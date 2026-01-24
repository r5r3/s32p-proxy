use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use http::{Request, StatusCode};
use http::request::Parts;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::os::unix::io::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::Semaphore;

use crate::buffer::BufPool;
use crate::uring_io::UringIO;
use crate::streaming::{
    copy_file_to_file,
    direct_io_ok_for_aligned_range,
    write_object_body,
    StreamCfg,
    WriteObjectDest,
};
use crate::fs_helpers::{
    bucket_exists_dir,
    bucket_root_path,
    join_object_path,
    ftruncate_file,
    open_file,
    OpenDirect,
    OpenMode
};

type Resp = s3pm_support::s3resp::HttpResponse;

static UPLOAD_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
enum UploadState {
    Active,
    Completing,
    Completed,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct UploadMeta {
    v: u8,
    bucket: String,
    key: String,
    upload_id: String,
    initiated: String, // ISO8601 Z
    state: UploadState,

    // Set as soon as we have 2 parts with the same size.
    assumed_part_size: Option<u64>,

    // part_number -> info
    parts: BTreeMap<u32, PartMeta>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PartMeta {
    size: u64,
    etag: String,          // include quotes
    last_modified: String, // ISO8601 Z
    stored: PartStored,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PartStored {
    Direct { off: u64 },
    File { name: String },
}

fn bucket_mpu_root(bucket_root: &Path, mpu_dir_name: &str) -> PathBuf {
    bucket_root.join(mpu_dir_name)
}

fn uploads_root(bucket_root: &Path, mpu_dir_name: &str) -> PathBuf {
    bucket_mpu_root(bucket_root, mpu_dir_name).join("uploads")
}

fn upload_dir(bucket_root: &Path, mpu_dir_name: &str, upload_id: &str) -> PathBuf {
    uploads_root(bucket_root, mpu_dir_name).join(upload_id)
}

fn upload_meta_path(dir: &Path) -> PathBuf {
    dir.join("meta.json")
}

fn upload_lock_path(dir: &Path) -> PathBuf {
    dir.join("lock")
}

fn upload_parts_dir(dir: &Path) -> PathBuf {
    dir.join("parts")
}

fn upload_direct_path(dir: &Path) -> PathBuf {
    dir.join("direct.bin")
}

fn sanitize_upload_id(upload_id: &str) -> Result<()> {
    if upload_id.is_empty() {
        return Err(anyhow!("empty uploadId"));
    }
    if upload_id.contains('/') || upload_id.contains('\\') {
        return Err(anyhow!("invalid uploadId"));
    }
    if upload_id.as_bytes().contains(&0) {
        return Err(anyhow!("invalid uploadId"));
    }
    Ok(())
}

fn gen_upload_id() -> String {
    let mut buf = [0u8; 20];

    #[cfg(target_os = "linux")]
    {
        let rc = unsafe {
            libc::getrandom(
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if rc == buf.len() as isize {
            return URL_SAFE_NO_PAD.encode(buf);
        }
    }

    let n = UPLOAD_COUNTER.fetch_add(1, Ordering::SeqCst);
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let mut fallback = [0u8; 32];
    fallback[..8].copy_from_slice(&now.as_secs().to_le_bytes());
    fallback[8..16].copy_from_slice(&now.subsec_nanos().to_le_bytes());
    fallback[16..24].copy_from_slice(&n.to_le_bytes());
    fallback[24..32].copy_from_slice(&(std::process::id() as u64).to_le_bytes());
    URL_SAFE_NO_PAD.encode(fallback)
}

fn lock_exclusive(path: &Path) -> Result<std::fs::File> {
    let (f, _used_direct) = open_file(
        path,
        OpenMode::ReadWriteCreate,
        OpenDirect::Buffered,
    )
    .with_context(|| format!("open lock {}", path.display()))?;

    let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) };
    if rc != 0 {
        return Err(anyhow!(
            "flock failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(f)
}

fn read_meta(dir: &Path) -> Result<UploadMeta> {
    let p = upload_meta_path(dir);
    let b = fs::read(&p).with_context(|| format!("read {}", p.display()))?;
    serde_json::from_slice(&b).context("parse meta.json")
}

fn write_meta_atomic(dir: &Path, meta: &UploadMeta) -> Result<()> {
    let p = upload_meta_path(dir);
    let tmp = dir.join("meta.json.tmp");

    let data = serde_json::to_vec_pretty(meta).context("serialize meta")?;
    fs::write(&tmp, data).with_context(|| format!("write {}", tmp.display()))?;

    fs::rename(&tmp, &p).with_context(|| format!("rename {} -> {}", tmp.display(), p.display()))?;
    Ok(())
}

// Recompute assumed_part_size if we have >=2 parts with the same size.
fn recompute_assumed_part_size(meta: &mut UploadMeta) {
    if meta.assumed_part_size.is_some() {
        return;
    }
    let mut counts: HashMap<u64, u32> = HashMap::new();
    for p in meta.parts.values() {
        *counts.entry(p.size).or_insert(0) += 1;
    }
    if let Some((sz, _)) = counts.into_iter().find(|(_k, v)| *v >= 2) {
        meta.assumed_part_size = Some(sz);
    }
}

fn compute_sequential_direct_offset(meta: &UploadMeta, part_number: u32) -> Option<u64> {
    if part_number <= 1 {
        return Some(0);
    }
    let mut off: u64 = 0;
    for pn in 1..part_number {
        let p = meta.parts.get(&pn)?;
        match p.stored {
            PartStored::Direct { off: o } if o == off => {
                off = off.saturating_add(p.size);
            }
            _ => return None,
        }
    }
    Some(off)
}

fn part_file_name(part_number: u32) -> String {
    format!("part-{:05}.bin", part_number)
}

fn is_cross_device(src_dir: &Path, dst_path: &Path) -> bool {
    let Ok(src_md) = fs::metadata(src_dir) else { return false };
    let Some(dst_parent) = dst_path.parent() else { return false };
    let Ok(dst_md) = fs::metadata(dst_parent) else { return false };
    src_md.dev() != dst_md.dev()
}

fn dst_tmp_path(dst_path: &Path, upload_id: &str) -> Result<PathBuf> {
    let parent = dst_path
        .parent()
        .ok_or_else(|| anyhow!("dst_path has no parent: {}", dst_path.display()))?;
    Ok(parent.join(format!(".s3pm-mpu-tmp-{upload_id}")))
}

fn is_exdev(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(libc::EXDEV)
}

/// Copy a byte range [0..len) from src file (starting at src_off0) into dst file (starting at dst_off0)
/// using the existing io_uring infrastructure and buffer pool.
async fn copy_range_to_range(
    src: Arc<std::fs::File>,
    src_off0: u64,
    dst: Arc<std::fs::File>,
    dst_off0: u64,
    len: u64,
    cfg: StreamCfg,
    uring: Arc<UringIO>,
    pool: Arc<BufPool>,
) -> Result<()> {
    if len == 0 {
        return Ok(());
    }

    let chunk = cfg.chunk_size;
    let inflight_cfg = cfg.inflight.max(1);

    let needed_chunks = ((len + chunk as u64 - 1) / chunk as u64) as usize;
    let allowed = std::cmp::min(inflight_cfg, needed_chunks.max(1));
    let stream_sem = Arc::new(Semaphore::new(allowed.max(1)));

    let src_sender = uring.sender(src.clone());
    let dst_sender = uring.sender(dst.clone());

    let mut pos: u64 = 0;
    while pos < len {
        let want = std::cmp::min(chunk as u64, len - pos) as usize;

        let pooled = pool
            .acquire_for_stream(&stream_sem)
            .await
            .map_err(|_| anyhow!("buffer pool closed"))?;

        let (n, pooled) = src_sender
            .read(src_off0 + pos, want, pooled)
            .await
            .with_context(|| format!("read copy src_off={}", src_off0 + pos))?;

        if n != want {
            return Err(anyhow!(
                "short read while copying: got {n}, want {want} at src_off={}",
                src_off0 + pos
            ));
        }

        dst_sender
            .write(dst_off0 + pos, n, pooled)
            .await
            .with_context(|| format!("write copy dst_off={}", dst_off0 + pos))?;

        pos += want as u64;
    }

    dst_sender.close();
    dst_sender.wait().await?;
    Ok(())
}

fn build_location(parts: &Parts, scheme: &str) -> String {
    let host = parts
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");

    // path-style gateway: uri.path() already includes "/{bucket}/{key}"
    format!("{scheme}://{host}{}", parts.uri.path())
}

fn no_such_upload(resource: Option<&str>) -> Resp {
    s3pm_support::s3resp::s3_error(
        StatusCode::NOT_FOUND,
        s3pm_support::s3xml::error_code::NO_SUCH_UPLOAD,
        "upload not found",
        resource,
        None,
    )
}

pub async fn handle(req: Request<Incoming>, app: Arc<crate::App>, class: &s3pm_support::classifier::S3RequestClass) -> Resp {
    let bucket = class.bucket.as_deref().unwrap_or("");
    let key = class.key.as_deref().unwrap_or("");

    match &class.op {
        s3pm_support::classifier::S3Op::Multipart(op) => match op {
            s3pm_support::classifier::MultipartOp::CreateMultipartUpload => {
                handle_create_mpu(req, app, bucket, key).await
            }
            s3pm_support::classifier::MultipartOp::UploadPart { upload_id, part_number } => {
                handle_upload_part(req, app, bucket, key, upload_id, *part_number).await
            }
            s3pm_support::classifier::MultipartOp::ListParts { upload_id } => {
                handle_list_parts(req, app, bucket, key, upload_id).await
            }
            s3pm_support::classifier::MultipartOp::CompleteMultipartUpload { upload_id } => {
                handle_complete(req, app, bucket, key, upload_id).await
            }
            s3pm_support::classifier::MultipartOp::AbortMultipartUpload { upload_id } => {
                handle_abort(req, app, bucket, key, upload_id).await
            }
            s3pm_support::classifier::MultipartOp::ListMultipartUploads => {
                handle_list_uploads(req, app, bucket).await
            }
            s3pm_support::classifier::MultipartOp::Unknown => {
                s3pm_support::s3resp::not_implemented("unknown multipart request", Some(req.uri().path()))
            }
        },
        _ => s3pm_support::s3resp::not_implemented("not a multipart request", Some(req.uri().path())),
    }
}

async fn handle_create_mpu(
    req: Request<Incoming>,
    app: Arc<crate::App>,
    bucket: &str,
    key: &str,
) -> Resp {
    let cfg = app.cfg.clone();

    if bucket.is_empty() || key.is_empty() {
        return s3pm_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s3pm_support::s3xml::error_code::INVALID_REQUEST,
            "missing bucket or key",
            Some(req.uri().path()),
            None,
        );
    }

    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => {}
        Ok(false) => return s3pm_support::s3resp::no_such_bucket("bucket not found", Some(req.uri().path())),
        Err(e) => return s3pm_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path())),
    }

    let bucket_root = match bucket_root_path(&cfg.posix_root, bucket) {
        Ok(p) => p,
        Err(e) => return s3pm_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path())),
    };

    let upload_id = gen_upload_id();
    let dir = upload_dir(&bucket_root, &cfg.mpu_dir_name, &upload_id);

    if let Err(e) = fs::create_dir_all(upload_parts_dir(&dir)) {
        return s3pm_support::s3resp::internal_error(&e.to_string(), Some(req.uri().path()), None);
    }

    let initiated = s3pm_support::s3xml::format_s3_time_system(SystemTime::now());

    let meta = UploadMeta {
        v: 1,
        bucket: bucket.to_string(),
        key: key.to_string(),
        upload_id: upload_id.clone(),
        initiated,
        state: UploadState::Active,
        assumed_part_size: None,
        parts: BTreeMap::new(),
    };

    // Write meta under lock
    let lock_path = upload_lock_path(&dir);
    match lock_exclusive(&lock_path) {
        Ok(_lk) => {
            if let Err(e) = write_meta_atomic(&dir, &meta) {
                return s3pm_support::s3resp::internal_error(&e.to_string(), Some(req.uri().path()), None);
            }
        }
        Err(e) => return s3pm_support::s3resp::internal_error(&e.to_string(), Some(req.uri().path()), None),
    }

    s3pm_support::s3resp::create_multipart_upload_ok(bucket, key, &upload_id)
}

async fn handle_list_uploads(
    req: Request<Incoming>,
    app: Arc<crate::App>,
    bucket: &str,
) -> Resp {
    let cfg = app.cfg.clone();

    if bucket.is_empty() {
        return s3pm_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s3pm_support::s3xml::error_code::INVALID_REQUEST,
            "missing bucket",
            Some(req.uri().path()),
            None,
        );
    }

    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => {}
        Ok(false) => return s3pm_support::s3resp::no_such_bucket("bucket not found", Some(req.uri().path())),
        Err(e) => return s3pm_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path())),
    }

    let bucket_root = match bucket_root_path(&cfg.posix_root, bucket) {
        Ok(p) => p,
        Err(e) => return s3pm_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path())),
    };

    let root = uploads_root(&bucket_root, &cfg.mpu_dir_name);
    let mut out: Vec<s3pm_support::s3xml::MultipartUploadInfo> = Vec::new();

    let rd = match fs::read_dir(&root) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return s3pm_support::s3resp::list_multipart_uploads_ok(bucket, &out);
        }
        Err(e) => return s3pm_support::s3resp::internal_error(&e.to_string(), Some(req.uri().path()), None),
    };

    for ent in rd.flatten() {
        if !ent.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let dir = ent.path();
        let meta = match read_meta(&dir) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !matches!(meta.state, UploadState::Active) {
            continue;
        }
        out.push(s3pm_support::s3xml::MultipartUploadInfo {
            key: meta.key,
            upload_id: meta.upload_id,
            initiated: meta.initiated,
        });
    }

    s3pm_support::s3resp::list_multipart_uploads_ok(bucket, &out)
}

async fn handle_list_parts(
    req: Request<Incoming>,
    app: Arc<crate::App>,
    bucket: &str,
    key: &str,
    upload_id: &str,
) -> Resp {
    let cfg = app.cfg.clone();

    if bucket.is_empty() || key.is_empty() {
        return s3pm_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s3pm_support::s3xml::error_code::INVALID_REQUEST,
            "missing bucket or key",
            Some(req.uri().path()),
            None,
        );
    }

    if let Err(e) = sanitize_upload_id(upload_id) {
        return s3pm_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s3pm_support::s3xml::error_code::INVALID_REQUEST,
            &e.to_string(),
            Some(req.uri().path()),
            None,
        );
    }

    let bucket_root = match bucket_root_path(&cfg.posix_root, bucket) {
        Ok(p) => p,
        Err(e) => return s3pm_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path())),
    };

    let dir = upload_dir(&bucket_root, &cfg.mpu_dir_name, upload_id);
    if !dir.exists() {
        return no_such_upload(Some(req.uri().path()));
    }

    let _lk = match lock_exclusive(&upload_lock_path(&dir)) {
        Ok(lk) => lk,
        Err(e) => return s3pm_support::s3resp::internal_error(&e.to_string(), Some(req.uri().path()), None),
    };

    let meta = match read_meta(&dir) {
        Ok(m) => m,
        Err(_) => return no_such_upload(Some(req.uri().path())),
    };

    if meta.bucket != bucket || meta.key != key {
        return no_such_upload(Some(req.uri().path()));
    }

    let mut parts: Vec<s3pm_support::s3xml::MultipartPartInfo> = Vec::new();
    for (pn, p) in meta.parts.iter() {
        parts.push(s3pm_support::s3xml::MultipartPartInfo {
            part_number: *pn,
            last_modified: p.last_modified.clone(),
            etag: p.etag.clone(),
            size: p.size,
        });
    }

    s3pm_support::s3resp::list_parts_ok(bucket, key, upload_id, &parts)
}

async fn handle_abort(
    req: Request<Incoming>,
    app: Arc<crate::App>,
    bucket: &str,
    key: &str,
    upload_id: &str,
) -> Resp {
    let cfg = app.cfg.clone();

    if bucket.is_empty() || key.is_empty() {
        return s3pm_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s3pm_support::s3xml::error_code::INVALID_REQUEST,
            "missing bucket or key",
            Some(req.uri().path()),
            None,
        );
    }

    if let Err(e) = sanitize_upload_id(upload_id) {
        return s3pm_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s3pm_support::s3xml::error_code::INVALID_REQUEST,
            &e.to_string(),
            Some(req.uri().path()),
            None,
        );
    }

    let bucket_root = match bucket_root_path(&cfg.posix_root, bucket) {
        Ok(p) => p,
        Err(e) => return s3pm_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path())),
    };

    let dir = upload_dir(&bucket_root, &cfg.mpu_dir_name, upload_id);
    if !dir.exists() {
        // S3 treats abort as idempotent-ish; but commonly NoSuchUpload.
        return no_such_upload(Some(req.uri().path()));
    }

    // best-effort delete
    let _ = fs::remove_dir_all(&dir);

    s3pm_support::s3resp::abort_multipart_upload_no_content()
}

async fn handle_upload_part(
    req: Request<Incoming>,
    app: Arc<crate::App>,
    bucket: &str,
    key: &str,
    upload_id: &str,
    part_number: u32,
) -> Resp {
    let cfg = app.cfg.clone();

    if bucket.is_empty() || key.is_empty() {
        return s3pm_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s3pm_support::s3xml::error_code::INVALID_REQUEST,
            "missing bucket or key",
            Some(req.uri().path()),
            None,
        );
    }
    if part_number == 0 {
        return s3pm_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s3pm_support::s3xml::error_code::INVALID_REQUEST,
            "invalid partNumber",
            Some(req.uri().path()),
            None,
        );
    }

    if let Err(e) = sanitize_upload_id(upload_id) {
        return s3pm_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s3pm_support::s3xml::error_code::INVALID_REQUEST,
            &e.to_string(),
            Some(req.uri().path()),
            None,
        );
    }

    // Need Content-Length at HTTP layer (consistent with PutObject)
    if req.headers().get(http::header::CONTENT_LENGTH).is_none() {
        return s3pm_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s3pm_support::s3xml::error_code::INVALID_REQUEST,
            "missing Content-Length",
            Some(req.uri().path()),
            None,
        );
    }

    let (is_streaming_sigv4, logical_len) = match crate::compute_logical_len(req.headers()) {
        Ok(v) => v,
        Err(e) => {
            return s3pm_support::s3resp::s3_error(
                StatusCode::BAD_REQUEST,
                s3pm_support::s3xml::error_code::INVALID_REQUEST,
                &e.to_string(),
                Some(req.uri().path()),
                None,
            )
        }
    };

    let bucket_root = match bucket_root_path(&cfg.posix_root, bucket) {
        Ok(p) => p,
        Err(e) => return s3pm_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path())),
    };
    let dir = upload_dir(&bucket_root, &cfg.mpu_dir_name, upload_id);
    if !dir.exists() {
        return no_such_upload(Some(req.uri().path()));
    }

    // Phase 1: lock + read meta (plan placement)
    let _lk = match lock_exclusive(&upload_lock_path(&dir)) {
        Ok(lk) => lk,
        Err(e) => return s3pm_support::s3resp::internal_error(&e.to_string(), Some(req.uri().path()), None),
    };

    let mut meta = match read_meta(&dir) {
        Ok(m) => m,
        Err(_) => return no_such_upload(Some(req.uri().path())),
    };

    if meta.bucket != bucket || meta.key != key {
        return no_such_upload(Some(req.uri().path()));
    }
    if !matches!(meta.state, UploadState::Active) {
        return s3pm_support::s3resp::s3_error(
            StatusCode::CONFLICT,
            s3pm_support::s3xml::error_code::INVALID_REQUEST,
            "upload is not active",
            Some(req.uri().path()),
            None,
        );
    }

    // Decide where to store, but first possibly "promote" assumed_part_size
    // based on just the headers (logical_len + part_number).
    //
    // New behavior:
    // - If part 1 arrives and assumed_part_size is None: set assumed_part_size = logical_len immediately.
    // - If assumed_part_size is None and this part's size matches any existing part size: set assumed_part_size = logical_len.
    // - Only do this early meta write when assumed_part_size is currently None.
    // - If assumed_part_size is already set: do NOT write meta here (no two-phase part entry).
    if meta.assumed_part_size.is_none() {
        let should_set_assumed = if part_number == 1 {
            true
        } else {
            // If any already-uploaded part has exactly this size, then after accepting this part
            // we'll have >=2 parts with the same size -> promote immediately.
            meta.parts.values().any(|p| p.size == logical_len)
        };

        if should_set_assumed {
            meta.assumed_part_size = Some(logical_len);

            // Persist assumed_part_size before writing bytes.
            // This reduces the window where multiple concurrent part uploads all think assumed is None.
            if let Err(e) = write_meta_atomic(&dir, &meta) {
                return s3pm_support::s3resp::internal_error(&e.to_string(), Some(req.uri().path()), None);
            }
        }
    }

    // Compute placement based on (possibly updated) assumed_part_size.
    //
    // IMPORTANT SAFETY GUARD:
    // - If assumed is set, only place into direct.bin if logical_len <= assumed.
    //   (If logical_len > assumed and we wrote it at (pn-1)*assumed we'd risk overlap/corruption.)
    let direct_off = if let Some(s) = meta.assumed_part_size {
        if logical_len <= s {
            Some((part_number as u64 - 1) * s)
        } else {
            None
        }
    } else {
        // As before: only place sequentially into direct if previous parts are direct + contiguous.
        compute_sequential_direct_offset(&meta, part_number)
    };

    // Drop lock ASAP (don’t hold during upload write)
    drop(_lk);

    let (parts, body) = req.into_parts();
    let now = s3pm_support::s3xml::format_s3_time_system(SystemTime::now());

    // We use a stable, client-visible ETag. (We do not validate ETags on complete.)
    let etag = format!("\"p{}-{}\"", part_number, logical_len);

    if let Some(off) = direct_off {
        // Decide direct IO for THIS part+offset (multipart writes MUST NOT pad, so only use O_DIRECT when fully aligned).
        let mut part_cfg = StreamCfg {
            chunk_size: cfg.chunk_size,
            inflight: cfg.inflight,
            direct_io: cfg.direct_io,
        };

        let mut use_direct = direct_io_ok_for_aligned_range(off, logical_len, &part_cfg);

        // Open direct.bin; if direct is requested but not supported, fall back to buffered.
        let direct_path = upload_direct_path(&dir);

        let file = {
            let (f, used_direct) = match open_file(
                &direct_path,
                OpenMode::ReadWriteCreate,
                if use_direct { OpenDirect::TryDirect } else { OpenDirect::Buffered },
            ) {
                Ok(v) => v,
                Err(e) => {
                    return s3pm_support::s3resp::internal_error(
                        &e.to_string(),
                        Some(parts.uri.path()),
                        None,
                    );
                }
            };

            if use_direct && !used_direct {
                tracing::warn!("open direct.bin with O_DIRECT failed (falling back)");
            }

            use_direct = used_direct;
            Arc::new(f)
        };

        // IMPORTANT: align the function behavior with how we opened the file.
        part_cfg.direct_io = use_direct;

        if let Err(e) = write_object_body(
            body,
            WriteObjectDest::File { file: file.clone(), start_off: off },
            logical_len,
            is_streaming_sigv4,
            part_cfg,
            app.uring.clone(),
            app.pool.clone(),
        )
        .await
        {
            return s3pm_support::s3resp::internal_error(&e.to_string(), Some(parts.uri.path()), None);
        }

        // Phase 3: lock + re-read + update meta (merge-safe)
        let _lk2 = match lock_exclusive(&upload_lock_path(&dir)) {
            Ok(lk) => lk,
            Err(e) => return s3pm_support::s3resp::internal_error(&e.to_string(), Some(parts.uri.path()), None),
        };

        let mut meta2 = match read_meta(&dir) {
            Ok(m) => m,
            Err(_) => return no_such_upload(Some(parts.uri.path())),
        };

        if !matches!(meta2.state, UploadState::Active) {
            return s3pm_support::s3resp::s3_error(
                StatusCode::CONFLICT,
                s3pm_support::s3xml::error_code::INVALID_REQUEST,
                "upload is not active",
                Some(parts.uri.path()),
                None,
            );
        }

        meta2.parts.insert(part_number, PartMeta {
            size: logical_len,
            etag: etag.clone(),
            last_modified: now,
            stored: PartStored::Direct { off },
        });
        recompute_assumed_part_size(&mut meta2);

        if let Err(e) = write_meta_atomic(&dir, &meta2) {
            return s3pm_support::s3resp::internal_error(&e.to_string(), Some(parts.uri.path()), None);
        }

        s3pm_support::s3resp::upload_part_ok(&etag)

    } else {

        // Store as individual part file
        let parts_dir = upload_parts_dir(&dir);
        let name = part_file_name(part_number);
        let final_path = parts_dir.join(&name);
        let tmp_path = parts_dir.join(format!("{name}.tmp"));

        if let Err(e) = write_object_body(
            body,
            WriteObjectDest::Path { path: tmp_path.clone() },
            logical_len,
            is_streaming_sigv4,
            StreamCfg {
                chunk_size: cfg.chunk_size,
                inflight: cfg.inflight,
                direct_io: cfg.direct_io,
            },
            app.uring.clone(),
            app.pool.clone(),
        )
        .await
        {
            let _ = fs::remove_file(&tmp_path);
            return s3pm_support::s3resp::internal_error(&e.to_string(), Some(parts.uri.path()), None);
        }

        if let Err(e) = fs::rename(&tmp_path, &final_path) {
            let _ = fs::remove_file(&tmp_path);
            return s3pm_support::s3resp::internal_error(&e.to_string(), Some(parts.uri.path()), None);
        }

        // Phase 3: lock + re-read + update meta (merge-safe)
        let _lk2 = match lock_exclusive(&upload_lock_path(&dir)) {
            Ok(lk) => lk,
            Err(e) => return s3pm_support::s3resp::internal_error(&e.to_string(), Some(parts.uri.path()), None),
        };

        let mut meta2 = match read_meta(&dir) {
            Ok(m) => m,
            Err(_) => return no_such_upload(Some(parts.uri.path())),
        };

        if !matches!(meta2.state, UploadState::Active) {
            return s3pm_support::s3resp::s3_error(
                StatusCode::CONFLICT,
                s3pm_support::s3xml::error_code::INVALID_REQUEST,
                "upload is not active",
                Some(parts.uri.path()),
                None,
            );
        }

        meta2.parts.insert(part_number, PartMeta {
            size: logical_len,
            etag: etag.clone(),
            last_modified: now,
            stored: PartStored::File { name },
        });
        recompute_assumed_part_size(&mut meta2);

        if let Err(e) = write_meta_atomic(&dir, &meta2) {
            return s3pm_support::s3resp::internal_error(&e.to_string(), Some(parts.uri.path()), None);
        }

        s3pm_support::s3resp::upload_part_ok(&etag)
    }
}

async fn handle_complete(
    req: Request<Incoming>,
    app: Arc<crate::App>,
    bucket: &str,
    key: &str,
    upload_id: &str,
) -> Resp {
    let cfg = app.cfg.clone();

    if bucket.is_empty() || key.is_empty() {
        return s3pm_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s3pm_support::s3xml::error_code::INVALID_REQUEST,
            "missing bucket or key",
            Some(req.uri().path()),
            None,
        );
    }
    if let Err(e) = sanitize_upload_id(upload_id) {
        return s3pm_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s3pm_support::s3xml::error_code::INVALID_REQUEST,
            &e.to_string(),
            Some(req.uri().path()),
            None,
        );
    }

    let bucket_root = match bucket_root_path(&cfg.posix_root, bucket) {
        Ok(p) => p,
        Err(e) => return s3pm_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path())),
    };

    let dir = upload_dir(&bucket_root, &cfg.mpu_dir_name, upload_id);
    if !dir.exists() {
        return no_such_upload(Some(req.uri().path()));
    }

    // Read and parse complete body
    let (parts, body) = req.into_parts();
    let collected = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            return s3pm_support::s3resp::s3_error(
                StatusCode::BAD_REQUEST,
                s3pm_support::s3xml::error_code::INVALID_REQUEST,
                &format!("failed to read body: {e}"),
                Some(parts.uri.path()),
                None,
            );
        }
    };

    let requested_parts = match s3pm_support::s3xml::parse_complete_parts(&collected) {
        Ok(v) => v,
        Err(e) => {
            return s3pm_support::s3resp::s3_error(
                StatusCode::BAD_REQUEST,
                s3pm_support::s3xml::error_code::INVALID_REQUEST,
                &e.to_string(),
                Some(parts.uri.path()),
                None,
            );
        }
    };

    let location = build_location(&parts, &cfg.public_scheme);

    // Lock for the whole completion (prevents new part uploads + makes direct/rename deterministic)
    let _lk = match lock_exclusive(&upload_lock_path(&dir)) {
        Ok(lk) => lk,
        Err(e) => return s3pm_support::s3resp::internal_error(&e.to_string(), Some(parts.uri.path()), None),
    };

    let mut meta = match read_meta(&dir) {
        Ok(m) => m,
        Err(_) => return no_such_upload(Some(parts.uri.path())),
    };

    if meta.bucket != bucket || meta.key != key {
        return no_such_upload(Some(parts.uri.path()));
    }
    if !matches!(meta.state, UploadState::Active) {
        return s3pm_support::s3resp::s3_error(
            StatusCode::CONFLICT,
            s3pm_support::s3xml::error_code::INVALID_REQUEST,
            "upload is not active",
            Some(parts.uri.path()),
            None,
        );
    }

    meta.state = UploadState::Completing;
    let _ = write_meta_atomic(&dir, &meta);

    // Validate parts exist
    let last_pn = *requested_parts.last().unwrap();
    // Require contiguous 1..last_pn (typical S3 expectation; simplifies direct layout).
    if requested_parts.len() != last_pn as usize || requested_parts[0] != 1 {
        return s3pm_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s3pm_support::s3xml::error_code::INVALID_REQUEST,
            "parts must be contiguous starting at 1",
            Some(parts.uri.path()),
            None,
        );
    }

    for pn in 1..=last_pn {
        if !meta.parts.contains_key(&pn) {
            return s3pm_support::s3resp::s3_error(
                StatusCode::BAD_REQUEST,
                s3pm_support::s3xml::error_code::INVALID_REQUEST,
                &format!("missing uploaded part {pn}"),
                Some(parts.uri.path()),
                None,
            );
        }
    }

    // Lustre: best-effort async prefetch for all part files before we start copying.
    #[cfg(feature = "lustre")]
    {
        for pn in 1..=last_pn {
            if let Some(part) = meta.parts.get(&pn) {
                if let PartStored::File { name } = &part.stored {
                    let src_path = upload_parts_dir(&dir).join(name);
                    if let Ok((f, _)) = open_file(&src_path, OpenMode::Read, OpenDirect::Buffered) {
                        crate::lustre::advise_willread(f.as_raw_fd(), 0, part.size);
                    }
                }
            }
        }
    }

    // Fast path condition:
    //  - assumed_part_size is known
    //  - parts 1..last-1 exactly assumed size
    //  - direct.bin can represent layout by offsets (pn-1)*assumed (direct parts must already match)
    let mut can_fast = false;
    let mut assumed = 0u64;
    let mut final_size = 0u64;

    if let Some(s) = meta.assumed_part_size {
        let mut ok = true;
        for pn in 1..last_pn {
            let p = meta.parts.get(&pn).unwrap();
            if p.size != s {
                ok = false;
                break;
            }
            if let PartStored::Direct { off } = p.stored {
                if off != (pn as u64 - 1) * s {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            let last = meta.parts.get(&last_pn).unwrap();
            // If last is already in direct, it must also be at (last-1)*s.
            if let PartStored::Direct { off } = last.stored {
                if off != (last_pn as u64 - 1) * s {
                    ok = false;
                }
            }
        }

        if ok {
            assumed = s;
            let last = meta.parts.get(&last_pn).unwrap();
            final_size = (last_pn as u64 - 1) * s + last.size;
            can_fast = true;
        }
    }

    let dst_path = match join_object_path(&cfg.posix_root, bucket, key) {
        Ok(p) => p,
        Err(e) => return s3pm_support::s3resp::access_denied(&e.to_string(), Some(parts.uri.path())),
    };

    if let Some(parent) = dst_path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            return s3pm_support::s3resp::internal_error(&e.to_string(), Some(parts.uri.path()), None);
        }
    }

    // Ensure any missing parts are copied INTO direct.bin (not direct->final), then rename direct.bin to final.
    let mut direct_file_opt: Option<Arc<std::fs::File>> = None;
    let direct_path = upload_direct_path(&dir);
    if can_fast {
        match open_file(&direct_path, OpenMode::ReadWriteCreate, OpenDirect::Buffered) {
            Ok((f, _used_direct)) => {
                direct_file_opt = Some(Arc::new(f));
            }
            Err(e) => {
                can_fast = false;
                tracing::warn!("fast path disabled: open direct.bin failed: {e}");
            }
        }
    }

    if can_fast {
        let direct_file = direct_file_opt.expect("direct_file must be present when can_fast");

        // For every part stored as file, copy into direct at expected offset.
        for pn in 1..=last_pn {
            let expected_off = (pn as u64 - 1) * assumed;
            let part = meta.parts.get(&pn).unwrap().clone();

            match part.stored {
                PartStored::Direct { off } => {
                    if off != expected_off {
                        can_fast = false;
                        break;
                    }
                }
                PartStored::File { name } => {
                    let src_path = upload_parts_dir(&dir).join(&name);
                    let src_file = match open_file(
                        &src_path,
                        OpenMode::Read,
                        OpenDirect::Buffered,
                    ) {
                        Ok((f, _used_direct)) => Arc::new(f),
                        Err(e) => {
                            can_fast = false;
                            tracing::warn!("fast path disabled: open part file failed: {e}");
                            break;
                        }
                    };

                    if let Err(e) = copy_range_to_range(
                        src_file,
                        0,
                        direct_file.clone(),
                        expected_off,
                        part.size,
                        StreamCfg { chunk_size: cfg.chunk_size, inflight: cfg.inflight, direct_io: false },
                        app.uring.clone(),
                        app.pool.clone(),
                    ).await {
                        can_fast = false;
                        tracing::warn!("fast path disabled: copy part->direct failed: {e}");
                        break;
                    }

                    // Update meta in-memory (we’ll write it at the end)
                    meta.parts.insert(pn, PartMeta {
                        size: part.size,
                        etag: part.etag,
                        last_modified: part.last_modified,
                        stored: PartStored::Direct { off: expected_off },
                    });

                    // best-effort delete source file to save space
                    let _ = fs::remove_file(&src_path);
                }
            }
        }

        if can_fast {
            // Truncate direct to final size and rename into place (no direct->final copy)
            if let Err(e) = ftruncate_file(&direct_file, final_size) {
                tracing::warn!("fast path disabled: truncate failed: {e}");
            } else {
                // Remove existing dst if needed (portable)
                if let Err(e) = fs::rename(&direct_path, &dst_path) {
                    // Cross-device? do a single copy direct.bin -> dst_tmp, then rename tmp -> dst.
                    if is_exdev(&e) {
                        let dst_tmp = match dst_tmp_path(&dst_path, upload_id) {
                            Ok(p) => p,
                            Err(err) => {
                                can_fast = false;
                                tracing::warn!("fast path disabled: cannot build dst tmp path: {err}");
                                // fall through to fallback
                                // (no break/return)
                                PathBuf::new()
                            }
                        };

                        if can_fast {
                            let _ = fs::remove_file(&dst_tmp);

                            // Copy the already-assembled direct.bin into destination tmp (avoid re-assembly).
                            let copy_cfg = StreamCfg { chunk_size: cfg.chunk_size, inflight: cfg.inflight, direct_io: false };
                            match copy_file_to_file(
                                direct_path.clone(),
                                dst_tmp.clone(),
                                final_size,
                                copy_cfg,
                                app.uring.clone(),
                                app.pool.clone(),
                            ).await {
                                Ok(()) => {
                                    if dst_path.exists() {
                                        let _ = fs::remove_file(&dst_path);
                                    }
                                    if let Err(e2) = fs::rename(&dst_tmp, &dst_path) {
                                        tracing::warn!("fast path disabled: rename tmp->dst failed: {e2}");
                                        let _ = fs::remove_file(&dst_tmp);
                                    } else {
                                        meta.state = UploadState::Completed;
                                        let _ = write_meta_atomic(&dir, &meta);
                                        let _ = fs::remove_dir_all(&dir);

                                        let m = match fs::metadata(&dst_path) {
                                            Ok(m) => m,
                                            Err(e) => return s3pm_support::s3resp::internal_error(&e.to_string(), Some(parts.uri.path()), None),
                                        };
                                        let etag = format!("\"{}\"", m.ino());
                                        return s3pm_support::s3resp::complete_multipart_upload_ok(&location, bucket, key, &etag);
                                    }
                                }
                                Err(err) => {
                                    tracing::warn!("fast path disabled: copy direct->dst_tmp failed: {err}");
                                    let _ = fs::remove_file(&dst_tmp);
                                }
                            }
                        }
                    } else {
                        tracing::warn!("fast path disabled: rename direct->dst failed: {e}");
                    }
                } else {
                    meta.state = UploadState::Completed;
                    let _ = write_meta_atomic(&dir, &meta);
                    let _ = fs::remove_dir_all(&dir);

                    let m = match fs::metadata(&dst_path) {
                        Ok(m) => m,
                        Err(e) => return s3pm_support::s3resp::internal_error(&e.to_string(), Some(parts.uri.path()), None),
                    };
                    let etag = format!("\"{}\"", m.ino());
                    return s3pm_support::s3resp::complete_multipart_upload_ok(&location, bucket, key, &etag);
                }
            }
        }
    }

    // Fallback: assemble into a staging file.
    // If dst is on a different filesystem than the upload dir, assemble directly into a tmp file
    // located next to the final destination (avoids an extra copy).
    let cross_dev = is_cross_device(&dir, &dst_path);

    let mut staged_in_dst = false;
    let mut staged_out: PathBuf = dir.join("complete.bin");

    if cross_dev {
        match dst_tmp_path(&dst_path, upload_id) {
            Ok(p) => {
                staged_out = p;
                staged_in_dst = true;
            }
            Err(e) => {
                tracing::warn!("cannot compute dst tmp path (falling back to upload staging): {e}");
                staged_in_dst = false;
            }
        }
    }

    // Best-effort cleanup of previous temp/stage file.
    let _ = fs::remove_file(&staged_out);

    // Open staging output. If staging in dst fails, fall back to upload dir staging.
    let out_file: Arc<std::fs::File> = match open_file(
        &staged_out,
        OpenMode::WriteCreateTruncate,
        OpenDirect::Buffered,
    ) {
        Ok((f, _used_direct)) => Arc::new(f),

        Err(e) if staged_in_dst => {
            tracing::warn!(
                "cannot open dst tmp for assembly (falling back to upload staging): {e}"
            );
            staged_in_dst = false;

            staged_out = dir.join("complete.bin");
            let _ = fs::remove_file(&staged_out);

            match open_file(
                &staged_out,
                OpenMode::WriteCreateTruncate,
                OpenDirect::Buffered,
            ) {
                Ok((f2, _used_direct2)) => Arc::new(f2),
                Err(e2) => {
                    return s3pm_support::s3resp::internal_error(
                        &e2.to_string(),
                        Some(parts.uri.path()),
                        None,
                    );
                }
            }
        }

        Err(e) => {
            return s3pm_support::s3resp::internal_error(
                &e.to_string(),
                Some(parts.uri.path()),
                None,
            );
        }
    };

    let direct_path = upload_direct_path(&dir);
    let direct_file = match open_file(&direct_path, OpenMode::Read, OpenDirect::Buffered) {
        Ok((f, _used_direct)) => Some(Arc::new(f)),
        Err(e) => {
            tracing::warn!("cannot open direct.bin {}: {e}", direct_path.display());
            None
        }
    };

    let mut out_off: u64 = 0;
    for pn in 1..=last_pn {
        let part = meta.parts.get(&pn).unwrap().clone();
        match part.stored {
            PartStored::Direct { off } => {
                let Some(df) = direct_file.clone() else {
                    return s3pm_support::s3resp::internal_error("direct.bin missing", Some(parts.uri.path()), None);
                };
                if let Err(e) = copy_range_to_range(
                    df,
                    off,
                    out_file.clone(),
                    out_off,
                    part.size,
                    StreamCfg { chunk_size: cfg.chunk_size, inflight: cfg.inflight, direct_io: false },
                    app.uring.clone(),
                    app.pool.clone(),
                ).await {
                    return s3pm_support::s3resp::internal_error(&e.to_string(), Some(parts.uri.path()), None);
                }
            }
            PartStored::File { name } => {
                let src_path = upload_parts_dir(&dir).join(&name);
                let src_file = match open_file(&src_path, OpenMode::Read, OpenDirect::Buffered) {
                    Ok((f, _used_direct)) => Arc::new(f),
                    Err(e) => {
                        return s3pm_support::s3resp::internal_error(
                            &e.to_string(),
                            Some(parts.uri.path()),
                            None,
                        );
                    }
                };
                if let Err(e) = copy_range_to_range(
                    src_file,
                    0,
                    out_file.clone(),
                    out_off,
                    part.size,
                    StreamCfg { chunk_size: cfg.chunk_size, inflight: cfg.inflight, direct_io: false },
                    app.uring.clone(),
                    app.pool.clone(),
                ).await {
                    return s3pm_support::s3resp::internal_error(&e.to_string(), Some(parts.uri.path()), None);
                }
            }
        }
        out_off = out_off.saturating_add(part.size);
    }

    // Ensure exact size (in case of sparse extension)
    if let Err(e) = ftruncate_file(&out_file, out_off) {
        let _ = fs::remove_file(&staged_out);
        return s3pm_support::s3resp::internal_error(&e.to_string(), Some(parts.uri.path()), None);
    }

    // Close before rename on some FS implementations
    drop(out_file);

    // Commit staged output into final destination
    if dst_path.exists() {
        let _ = fs::remove_file(&dst_path);
    }

    if staged_in_dst {
        // Same filesystem as destination => atomic rename, no extra copy.
        if let Err(e) = fs::rename(&staged_out, &dst_path) {
            let _ = fs::remove_file(&staged_out);
            return s3pm_support::s3resp::internal_error(&e.to_string(), Some(parts.uri.path()), None);
        }
    } else {
        // Old behavior: rename if possible, else EXDEV => copy to dst tmp then rename.
        match fs::rename(&staged_out, &dst_path) {
            Ok(()) => {}
            Err(e) if is_exdev(&e) => {
                let dst_tmp = match dst_tmp_path(&dst_path, upload_id) {
                    Ok(p) => p,
                    Err(err) => return s3pm_support::s3resp::internal_error(&err.to_string(), Some(parts.uri.path()), None),
                };
                let _ = fs::remove_file(&dst_tmp);

                let copy_cfg = StreamCfg { chunk_size: cfg.chunk_size, inflight: cfg.inflight, direct_io: false };
                if let Err(err) = copy_file_to_file(
                    staged_out.clone(),
                    dst_tmp.clone(),
                    out_off,
                    copy_cfg,
                    app.uring.clone(),
                    app.pool.clone(),
                ).await {
                    let _ = fs::remove_file(&dst_tmp);
                    return s3pm_support::s3resp::internal_error(&err.to_string(), Some(parts.uri.path()), None);
                }

                if dst_path.exists() {
                    let _ = fs::remove_file(&dst_path);
                }
                if let Err(e2) = fs::rename(&dst_tmp, &dst_path) {
                    let _ = fs::remove_file(&dst_tmp);
                    return s3pm_support::s3resp::internal_error(&e2.to_string(), Some(parts.uri.path()), None);
                }

                // best-effort remove original staged_out after successful cross-dev copy
                let _ = fs::remove_file(&staged_out);
            }
            Err(e) => {
                return s3pm_support::s3resp::internal_error(&e.to_string(), Some(parts.uri.path()), None);
            }
        }
    }

    meta.state = UploadState::Completed;
    let _ = write_meta_atomic(&dir, &meta);
    let _ = fs::remove_dir_all(&dir);

    let m = match fs::metadata(&dst_path) {
        Ok(m) => m,
        Err(e) => return s3pm_support::s3resp::internal_error(&e.to_string(), Some(parts.uri.path()), None),
    };
    let etag = format!("\"{}\"", m.ino());

    s3pm_support::s3resp::complete_multipart_upload_ok(&location, bucket, key, &etag)
}

