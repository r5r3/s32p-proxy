use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

mod buffer;
mod streaming;
mod uring_io;

use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use httpdate::fmt_http_date;
use hyper::body::Incoming;
use hyper::HeaderMap;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::fs;
use std::fs::OpenOptions;
use std::ffi::CString;
use std::os::unix::fs::MetadataExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::Semaphore;

use crate::buffer::{BufPool, PooledBuf, SliceOwner};
use crate::uring_io::UringIO;
use crate::streaming::{
    parse_range_header, stream_range_body, write_object_body_to_file,
    ByteRange, StreamCfg,
};
use s3pm_support;

type Resp = s3pm_support::s3resp::HttpResponse;

// ---- config ----

#[derive(Clone)]
struct Cfg {
    bind_addr: String,
    bind_uds: Option<PathBuf>,
    posix_root: PathBuf,
    access_key: String,
    secret_key: String,
    public_scheme: String,
    region: String,
    chunk_size: usize,
    inflight: usize,
    pool_size: usize,
    direct_io: bool,
}

fn env_bool(k: &str, default: bool) -> bool {
    match std::env::var(k).ok().as_deref() {
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES") => true,
        Some("0") | Some("false") | Some("FALSE") | Some("no") | Some("NO") => false,
        Some(_) => default,
        None => default,
    }
}

fn env_usize(k: &str, default: usize) -> usize {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn load_cfg() -> Result<Cfg> {
    let bind_addr = std::env::var("S3PM_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:0".to_string());
    let bind_uds = std::env::var("S3PM_BIND_UDS").ok().map(PathBuf::from);
    let posix_root = PathBuf::from(std::env::var("S3PM_POSIX_ROOT").context("S3PM_POSIX_ROOT missing")?);

    let access_key = std::env::var("AWS_ACCESS_KEY_ID").context("AWS_ACCESS_KEY_ID missing")?;
    let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY").context("AWS_SECRET_ACCESS_KEY missing")?;

    let public_scheme = std::env::var("S3PM_PUBLIC_SCHEME").unwrap_or_else(|_| "http".to_string());
    let region = std::env::var("S3PM_REGION").unwrap_or_else(|_| "us-east-1".to_string());

    let chunk_size = env_usize("S3PM_CHUNK_SIZE_MB", 4) * 1024 * 1024;
    let inflight = env_usize("S3PM_INFLIGHT", 16).max(1);

    let pool_size_default = inflight.saturating_mul(8).max(1);
    let pool_size = env_usize("S3PM_POOL_SIZE", pool_size_default).max(1);

    let direct_io = env_bool("S3PM_DIRECT_IO", false);

    Ok(Cfg {
        bind_addr,
        bind_uds,
        posix_root,
        access_key,
        secret_key,
        public_scheme,
        region,
        chunk_size,
        inflight,
        pool_size,
        direct_io,
    })
}

// ---- path mapping and other helpers ----

fn join_object_path(root: &Path, bucket: &str, key: &str) -> Result<PathBuf> {
    if bucket.is_empty() || bucket.contains('/') || bucket == "." || bucket == ".." {
        return Err(anyhow!("invalid bucket"));
    }

    let mut out = root.join(bucket);
    for part in key.split('/') {
        if part.is_empty() {
            continue;
        }
        if part == "." || part == ".." {
            return Err(anyhow!("invalid key segment"));
        }
        if part.as_bytes().contains(&0) {
            return Err(anyhow!("NUL in key segment"));
        }
        out.push(part);
    }
    Ok(out)
}

fn bucket_root_path(root: &Path, bucket: &str) -> Result<PathBuf> {
    join_object_path(root, bucket, "")
}

fn bucket_exists_dir(root: &Path, bucket: &str) -> Result<bool> {
    let p = bucket_root_path(root, bucket)?;
    Ok(p.exists() && p.is_dir())
}

#[derive(Debug, Clone, Copy)]
struct StatxInfo {
    ino: u64,
    size: u64,
    uid: u32,
    mtime: SystemTime,
}

fn system_time_from_unix(sec: i64, nsec: u32) -> SystemTime {
    use std::time::Duration;
    if sec >= 0 {
        SystemTime::UNIX_EPOCH + Duration::new(sec as u64, nsec)
    } else {
        let d = Duration::new((-sec) as u64, nsec);
        SystemTime::UNIX_EPOCH - d
    }
}

#[cfg(target_os = "linux")]
fn statx_info(path: &Path) -> Option<StatxInfo> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.contains(&0) {
        return None;
    }
    let c_path = CString::new(bytes).ok()?;

    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    let mask: libc::c_uint =
        (libc::STATX_INO | libc::STATX_SIZE | libc::STATX_MTIME | libc::STATX_UID) as libc::c_uint;

    let rc = unsafe {
        libc::statx(
            libc::AT_FDCWD,
            c_path.as_ptr(),
            libc::AT_STATX_DONT_SYNC,
            mask,
            &mut stx as *mut libc::statx,
        )
    };

    if rc != 0 {
        return None;
    }

    let mtime = system_time_from_unix(stx.stx_mtime.tv_sec as i64, stx.stx_mtime.tv_nsec as u32);

    Some(StatxInfo {
        ino: stx.stx_ino as u64,
        size: stx.stx_size as u64,
        uid: stx.stx_uid as u32,
        mtime,
    })
}

#[cfg(not(target_os = "linux"))]
fn statx_info(path: &Path) -> Option<StatxInfo> {
    let meta = std::fs::metadata(path).ok()?;
    let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);

    #[cfg(unix)]
    {
        Some(StatxInfo {
            ino: meta.ino(),
            size: meta.len(),
            uid: meta.uid(),
            mtime,
        })
    }

    #[cfg(not(unix))]
    {
        Some(StatxInfo { ino: 0, size: meta.len(), uid: 0, mtime })
    }
}

// ---- request handler ----

struct App {
    cfg: Arc<Cfg>,
    pool: Arc<BufPool>,
    io_sem: Arc<Semaphore>,
    io_total: usize,
    uring: Arc<UringIO>,
}

async fn read_small(
    file: Arc<std::fs::File>,
    pool: Arc<BufPool>,
    off: u64,
    len: usize,
) -> Result<Bytes> {
    let buf = pool.take();
    let pooled = PooledBuf::new(pool, buf);

    let (n, pooled) = tokio::task::spawn_blocking(move || -> anyhow::Result<(usize, PooledBuf)> {
        let mut pooled = pooled;
        let dst = &mut pooled.as_mut_bytes()[..len];
        let n = file
            .read_at(dst, off)
            .map_err(|e| anyhow!("read_at failed at off={off}: {e}"))?;
        Ok((n, pooled))
    })
    .await
    .map_err(|e| anyhow!("read task join error: {e}"))??;

    if n == 0 {
        return Err(anyhow!("unexpected EOF"));
    }

    Ok(Bytes::from_owner(SliceOwner::new(pooled, 0, n)))
}

async fn handle(req: Request<Incoming>, app: Arc<App>) -> Result<Resp, Infallible> {
    let class = s3pm_support::classifier::classify(req.method().as_str(), req.uri());

    let resp = match &class.op {
        s3pm_support::classifier::S3Op::Read(s3pm_support::classifier::ReadOp::GetBucketLocation) => {
            handle_get_bucket_location(req, app, &class).await
        }
        s3pm_support::classifier::S3Op::Read(s3pm_support::classifier::ReadOp::HeadBucket) => {
            handle_head_bucket(req, app, &class).await
        }
        s3pm_support::classifier::S3Op::Read(s3pm_support::classifier::ReadOp::GetObject)
        | s3pm_support::classifier::S3Op::Read(s3pm_support::classifier::ReadOp::HeadObject) => {
            handle_get_object(req, app, &class).await
        }
        s3pm_support::classifier::S3Op::Read(s3pm_support::classifier::ReadOp::ListObjectsV2) => {
            handle_list_objects_v2(req, app, &class).await
        }
        s3pm_support::classifier::S3Op::Write(s3pm_support::classifier::WriteOp::PutObject) => {
            handle_put_object(req, app, &class).await
        }
        s3pm_support::classifier::S3Op::Multipart(_) => handle_multipart(req, app, &class).await,
        s3pm_support::classifier::S3Op::Versioning(_) => handle_versioning(req, app, &class).await,
        _ => handle_other(req, app, &class).await,
    };

    Ok(resp)
}

fn require_sigv4(req: &Request<Incoming>, cfg: &Cfg) -> std::result::Result<(), Resp> {
    let auth = match s3pm_support::parse_authorization(req.headers()) {
        Ok(a) => a,
        Err(e) => {
            return Err(s3pm_support::s3resp::access_denied(
                &format!("bad Authorization: {e}"),
                None,
            ))
        }
    };

    if auth.access_key != cfg.access_key {
        return Err(s3pm_support::s3resp::access_denied("unknown access key", None));
    }

    if let Err(e) = s3pm_support::verify_sigv4_header_only(
        req.method().as_str(),
        req.uri(),
        req.headers(),
        &auth,
        &cfg.secret_key,
        &cfg.public_scheme,
    ) {
        return Err(s3pm_support::s3resp::signature_does_not_match(&e.to_string(), None));
    }

    Ok(())
}

fn query_is_only_location(req: &Request<Incoming>) -> bool {
    req.method() == http::Method::GET
        && req.uri().query().is_some_and(|q| {
            let mut parts = q.split('&').filter(|p| !p.is_empty());
            let first = parts.next().unwrap_or("");
            parts.next().is_none() && (first == "location" || first.starts_with("location="))
        })
}

async fn handle_get_bucket_location(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s3pm_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    // Require SigV4 even for local responses
    if let Err(resp) = require_sigv4(&req, &cfg) {
        return resp;
    }

    // Only allow ?location (classifier should already ensure this, but keep it defensive)
    if req.uri().query().is_some() && !query_is_only_location(&req) {
        return s3pm_support::s3resp::not_implemented("query parameters are not implemented", None);
    }

    let bucket = class.bucket.as_deref().unwrap_or("");
    if bucket.is_empty() {
        return s3pm_support::s3resp::not_implemented("missing bucket", Some(req.uri().path()));
    }

    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => s3pm_support::s3resp::get_bucket_location(&cfg.region),
        Ok(false) => s3pm_support::s3resp::no_such_bucket("bucket not found", Some(req.uri().path())),
        Err(e) => s3pm_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path())),
    }
}

async fn handle_head_bucket(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s3pm_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    // Require SigV4 even for local responses
    if let Err(resp) = require_sigv4(&req, &cfg) {
        return resp;
    }

    // Defensive: HeadBucket should not have query params in our implementation.
    if req.uri().query().is_some() {
        return s3pm_support::s3resp::not_implemented("query parameters are not implemented", None);
    }

    let bucket = class.bucket.as_deref().unwrap_or("");
    if bucket.is_empty() {
        return s3pm_support::s3resp::not_implemented("missing bucket", Some(req.uri().path()));
    }

    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => s3pm_support::s3resp::head_bucket_ok(&cfg.region),
        Ok(false) => s3pm_support::s3resp::no_such_bucket("bucket not found", Some(req.uri().path())),
        Err(e) => s3pm_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path())),
    }
}

async fn handle_multipart(req: Request<Incoming>, app: Arc<App>, _class: &s3pm_support::classifier::S3RequestClass) -> Resp {
    let cfg = app.cfg.clone();

    if let Err(resp) = require_sigv4(&req, &cfg) {
        return resp;
    }

    s3pm_support::s3resp::not_implemented("multipart uploads are not implemented", None)
}

async fn handle_versioning(req: Request<Incoming>, app: Arc<App>, _class: &s3pm_support::classifier::S3RequestClass) -> Resp {
    let cfg = app.cfg.clone();

    if let Err(resp) = require_sigv4(&req, &cfg) {
        return resp;
    }

    s3pm_support::s3resp::not_implemented("versioning is not implemented", None)
}

async fn handle_other(req: Request<Incoming>, app: Arc<App>, _class: &s3pm_support::classifier::S3RequestClass) -> Resp {
    let cfg = app.cfg.clone();

    if let Err(resp) = require_sigv4(&req, &cfg) {
        return resp;
    }

    // Preserve the previous general message
    s3pm_support::s3resp::not_implemented("only GET/HEAD /{bucket}/{key} is implemented", None)
}

async fn handle_get_object(req: Request<Incoming>, app: Arc<App>, class: &s3pm_support::classifier::S3RequestClass) -> Resp {
    let cfg = app.cfg.clone();

    // Reject query params (including presigned URLs) for object reads.
    if req.uri().query().is_some() {
        return s3pm_support::s3resp::not_implemented("query parameters are not implemented", None);
    }

    // SigV4: parse + verify (every request)
    if let Err(resp) = require_sigv4(&req, &cfg) {
        return resp;
    }

    let is_head_object = matches!(
        &class.op,
        s3pm_support::classifier::S3Op::Read(s3pm_support::classifier::ReadOp::HeadObject)
    );

    let bucket = class.bucket.as_deref().unwrap_or("");
    let key = class.key.as_deref().unwrap_or("");

    // If the bucket is missing, S3 expects NoSuchBucket (not NoSuchKey).
    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => {}
        Ok(false) => return s3pm_support::s3resp::no_such_bucket("bucket not found", Some(req.uri().path())),
        Err(e) => return s3pm_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path())),
    }

    let obj_path = match join_object_path(&cfg.posix_root, bucket, key) {
        Ok(p) => p,
        Err(e) => return s3pm_support::s3resp::access_denied(&e.to_string(), None),
    };

    // open once (buffered) to stat + inode + size
    let std_file = match OpenOptions::new().read(true).open(&obj_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return s3pm_support::s3resp::no_such_key("not found", None)
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return s3pm_support::s3resp::access_denied("permission denied", None)
        }
        Err(e) => {
            return s3pm_support::s3resp::internal_error(
                &e.to_string(),
                Some(req.uri().path()),
                None,
            );
        }
    };

    let meta = match std_file.metadata() {
        Ok(m) => m,
        Err(e) => {
            return s3pm_support::s3resp::internal_error(
                &e.to_string(),
                Some(req.uri().path()),
                None,
            );
        }
    };

    let size = meta.len();

    // IMPORTANT: real mtime in RFC1123 / HTTP-date format (required by many S3 clients).
    // If metadata.modified() fails, fall back to UNIX_EPOCH (still a valid HTTP date).
    let last_modified = meta
        .modified()
        .ok()
        .map(fmt_http_date)
        .unwrap_or_else(|| fmt_http_date(SystemTime::UNIX_EPOCH));

    // inode-based ETag
    let etag = format!("\"{}\"", meta.ino());

    // Empty object: 200 + Content-Length: 0 (+ common headers)
    if size == 0 {
        return s3pm_support::s3resp::object_response(
            StatusCode::OK,
            s3pm_support::s3resp::empty_body(),
            "application/octet-stream",
            0,
            &etag,
            &last_modified,
            None,
        );
    }

    // Range parsing (single-range only)
    let range_present = req.headers().get("range").is_some();
    let range = match req.headers().get("range") {
        None => None,
        Some(v) => match v.to_str() {
            Ok(s) => match parse_range_header(s, size) {
                Ok(r) => r,
                Err(e) => return s3pm_support::s3resp::invalid_range(&e.to_string(), None),
            },
            Err(_) => return s3pm_support::s3resp::invalid_range("bad Range header", None),
        },
    };

    let want = range.unwrap_or(ByteRange { start: 0, end_excl: size });
    let want_len = want.end_excl - want.start;

    // HeadObject: same headers as GetObject, but no body
    if is_head_object {
        let (status, content_length, content_range) = if range_present {
            (
                StatusCode::PARTIAL_CONTENT,
                want_len,
                Some(s3pm_support::s3resp::object_content_range(
                    want.start,
                    want.end_excl - 1,
                    size,
                )),
            )
        } else {
            (StatusCode::OK, size, None)
        };

        return s3pm_support::s3resp::object_response(
            status,
            s3pm_support::s3resp::empty_body(),
            "application/octet-stream",
            content_length,
            &etag,
            &last_modified,
            content_range.as_deref(),
        );
    }

    // Small body fast-path (<= one chunk): acquire ONE permit for this file/request.
    if (want_len as usize) <= cfg.chunk_size {
        let _permit = match app.io_sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                return s3pm_support::s3resp::internal_error(
                    "io permit semaphore closed",
                    Some(req.uri().path()),
                    None,
                )
            }
        };

        let file = Arc::new(std_file);
        let bytes = match read_small(file, app.pool.clone(), want.start, want_len as usize).await {
            Ok(b) => b,
            Err(e) => {
                return s3pm_support::s3resp::internal_error(
                    &e.to_string(),
                    Some(req.uri().path()),
                    None,
                );
            }
        };

        // For range responses, compute end from what we actually read (robust to truncation races).
        let (status, content_length, content_range) = if range_present {
            let end_incl = want.start + (bytes.len().saturating_sub(1) as u64);
            (
                StatusCode::PARTIAL_CONTENT,
                bytes.len() as u64,
                Some(s3pm_support::s3resp::object_content_range(want.start, end_incl, size)),
            )
        } else {
            (StatusCode::OK, size, None)
        };

        return s3pm_support::s3resp::object_response(
            status,
            s3pm_support::s3resp::body_bytes(bytes),
            "application/octet-stream",
            content_length,
            &etag,
            &last_modified,
            content_range.as_deref(),
        );
    }

    // Unified read path: always stream via UringIO (no small-file special case).
    let body = match stream_range_body(
        obj_path.clone(),
        size,
        want,
        StreamCfg {
            chunk_size: cfg.chunk_size,
            inflight: cfg.inflight,
            direct_io: cfg.direct_io,
        },
        app.uring.clone(),
        app.pool.clone(),
        app.io_sem.clone(),
        app.io_total,
    )
    .await
    {
        Ok(b) => b.boxed(),
        Err(e) => {
            return s3pm_support::s3resp::internal_error(
                &e.to_string(),
                Some(req.uri().path()),
                None,
            );
        }
    };


    let (status, content_length, content_range) = if range_present {
        (
            StatusCode::PARTIAL_CONTENT,
            want_len,
            Some(s3pm_support::s3resp::object_content_range(
                want.start,
                want.end_excl - 1,
                size,
            )),
        )
    } else {
        (StatusCode::OK, size, None)
    };

    s3pm_support::s3resp::object_response(
        status,
        body,
        "application/octet-stream",
        content_length,
        &etag,
        &last_modified,
        content_range.as_deref(),
    )
}

// -------------------------
// ListObjectsV2 (stateless traversal stack token)
// -------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ListV2Token {
    v: u8,
    bucket: String,
    prefix: String,              // original request prefix (possibly empty)
    delimiter: Option<String>,   // Some("/") or None (recursive)
    stack: Vec<ListV2Frame>,     // root..deepest
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ListV2Frame {
    dir: String,   // key prefix for this directory frame ("" or ends with "/")
    after: String, // sort-key cursor within this dir ("" means start)
}

fn encode_token(tok: &ListV2Token) -> Result<String> {
    let js = serde_json::to_vec(tok)?;
    Ok(URL_SAFE_NO_PAD.encode(js))
}

fn decode_token(s: &str) -> Result<ListV2Token> {
    let raw = URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(|e| anyhow!("bad continuation-token: {e}"))?;
    let tok: ListV2Token = serde_json::from_slice(&raw)
        .map_err(|e| anyhow!("bad continuation-token json: {e}"))?;
    Ok(tok)
}

// Split prefix into (dir_prefix, leaf_filter).
// If prefix ends with '/', it's a pure directory prefix.
// Otherwise, list starts from the parent dir, and filters first-level names by leaf_filter.
fn split_prefix(prefix: &str) -> (String, Option<String>) {
    if prefix.is_empty() || prefix.ends_with('/') {
        return (prefix.to_string(), None);
    }
    if let Some((a, b)) = prefix.rsplit_once('/') {
        let mut dir = a.to_string();
        if !dir.is_empty() {
            dir.push('/');
        }
        return (dir, Some(b.to_string()));
    }
    ("".to_string(), Some(prefix.to_string()))
}

// Build a traversal stack that resumes "after" a last-emitted key.
// Used for StartAfter (when no ContinuationToken is provided).
fn build_stack_from_last(dir_prefix: &str, last_key: &str, recursive: bool) -> Vec<ListV2Frame> {
    let mut frames = Vec::new();
    frames.push(ListV2Frame { dir: dir_prefix.to_string(), after: "".to_string() });

    if !last_key.starts_with(dir_prefix) {
        return frames;
    }
    let rel = &last_key[dir_prefix.len()..];
    let rel = rel.trim_start_matches('/');
    if rel.is_empty() {
        return frames;
    }

    if !recursive {
        // Non-recursive: cursor is just the "immediate child" sort-key
        // (file name or "dir/").
        let first = rel.split('/').next().unwrap_or(rel);
        let after = if last_key.ends_with('/') { format!("{first}/") } else { first.to_string() };
        frames[0].after = after;
        return frames;
    }

    let parts: Vec<&str> = rel.split('/').filter(|p| !p.is_empty()).collect();
    if parts.is_empty() {
        return frames;
    }
    if parts.len() == 1 {
        frames[0].after = parts[0].to_string();
        return frames;
    }

    // Descend directories for all but last segment.
    let mut cur_dir = dir_prefix.to_string();
    for (i, seg) in parts.iter().enumerate() {
        if i == parts.len() - 1 {
            // last segment is file name
            if let Some(last) = frames.last_mut() {
                last.after = (*seg).to_string();
            }
            break;
        }

        // ancestor frame "after" is "seg/"
        if let Some(last) = frames.last_mut() {
            last.after = format!("{seg}/");
        }
        // push child frame
        cur_dir.push_str(seg);
        cur_dir.push('/');
        frames.push(ListV2Frame { dir: cur_dir.clone(), after: "".to_string() });
    }

    frames
}

#[derive(Clone)]
struct DirItem {
    name: String,
    sort_key: String, // name or name + "/"
    is_dir: bool,
    path: PathBuf,
}

struct RuntimeFrame {
    dir_key: String,     // key prefix for this directory ("" or ends_with "/")
    dir_fs: PathBuf,     // filesystem path of this directory
    after: String,       // cursor sort_key
    entries: Vec<DirItem>,
    idx: usize,
    is_root: bool,
}

fn read_dir_sorted(dir_fs: &Path) -> Result<Vec<DirItem>> {
    let mut out = Vec::new();
    let rd = match fs::read_dir(dir_fs) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return Err(anyhow!("permission denied")),
        Err(e) => return Err(anyhow!("read_dir failed: {e}")),
    };

    for ent in rd {
        let ent = match ent {
            Ok(e) => e,
            Err(_) => continue,
        };
        let ft = match ent.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };

        // S3 keys are UTF-8; lossy conversion is pragmatic here.
        let name = ent.file_name().to_string_lossy().to_string();
        if name.is_empty() || name == "." || name == ".." {
            continue;
        }

        let is_dir = ft.is_dir();
        let sort_key = if is_dir { format!("{name}/") } else { name.clone() };
        out.push(DirItem {
            name,
            sort_key,
            is_dir,
            path: ent.path(),
        });
    }

    // Sort by key-order: files "name" vs dirs "name/" (important for correct lexicographic order).
    out.sort_by(|a, b| a.sort_key.cmp(&b.sort_key));
    Ok(out)
}

fn first_index_after(entries: &[DirItem], after: &str) -> usize {
    if after.is_empty() {
        return 0;
    }
    // linear scan is fine for typical dir sizes; replace with binary search if needed.
    for (i, it) in entries.iter().enumerate() {
        if it.sort_key.as_str() > after {
            return i;
        }
    }
    entries.len()
}

fn lookup_username(uid: u32) -> Option<String> {
    unsafe {
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut result: *mut libc::passwd = std::ptr::null_mut();

        let mut buf_len = 16 * 1024;
        for _ in 0..3 {
            let mut buf = vec![0u8; buf_len];
            let rc = libc::getpwuid_r(
                uid as libc::uid_t,
                &mut pwd,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            );
            if rc == 0 && !result.is_null() && !pwd.pw_name.is_null() {
                return Some(std::ffi::CStr::from_ptr(pwd.pw_name).to_string_lossy().to_string());
            }
            if rc == libc::ERANGE {
                buf_len *= 2;
                continue;
            }
            return None;
        }
        None
    }
}

fn owner_info(uid: u32) -> s3pm_support::s3xml::ListOwnerInfo {
    let id = uid.to_string();
    let display_name = lookup_username(uid).unwrap_or_else(|| id.clone());
    s3pm_support::s3xml::ListOwnerInfo { id, display_name }
}

async fn handle_list_objects_v2(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s3pm_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    if let Err(resp) = require_sigv4(&req, &cfg) {
        return resp;
    }

    let bucket = class.bucket.as_deref().unwrap_or("");
    if bucket.is_empty() {
        return s3pm_support::s3resp::not_implemented("missing bucket", Some(req.uri().path()));
    }

    // list-type=2 is already checked by classifier, keep defensive.
    if class.query.first("list-type") != Some("2") {
        return s3pm_support::s3resp::not_implemented("missing list-type=2", None);
    }

    // If bucket doesn't exist, return NoSuchBucket (S3 semantics).
    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => {}
        Ok(false) => return s3pm_support::s3resp::no_such_bucket("bucket not found", Some(req.uri().path())),
        Err(e) => return s3pm_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path())),
    }

    let prefix = class.query.first("prefix").unwrap_or("").to_string();

    // delimiter: only "/" is supported; if absent => recursive.
    let delimiter_q = class
        .query
        .first("delimiter")
        .and_then(|d| if d.is_empty() { None } else { Some(d) });

    let recursive = match delimiter_q {
        None => true,
        Some("/") => false,
        Some(_) => {
            return s3pm_support::s3resp::not_implemented("only delimiter=/ is supported", None);
        }
    };

    let max_keys = class
        .query
        .first("max-keys")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(1000)
        .min(1000);

    let fetch_owner = match class.query.first("fetch-owner") {
        Some(v) if v == "true" || v == "1" || v.eq_ignore_ascii_case("true") => true,
        Some(_) => true, // if present, treat as "requested"
        None => false,
    };

    let continuation_token_in = class.query.first("continuation-token").map(|s| s.to_string());
    let start_after = class.query.first("start-after").map(|s| s.to_string());

    let (dir_prefix, leaf_filter) = split_prefix(&prefix);

    // Filesystem start dir is bucket + dir_prefix
    let start_dir_fs = match join_object_path(&cfg.posix_root, bucket, &dir_prefix) {
        Ok(p) => p,
        Err(e) => return s3pm_support::s3resp::access_denied(&e.to_string(), None),
    };

    // If the *prefix directory* doesn't exist (but bucket exists), return an empty listing.
    if !start_dir_fs.exists() || !start_dir_fs.is_dir() {
        return s3pm_support::s3resp::list_objects_v2(
            bucket,
            Some(&prefix),
            if recursive { None } else { Some("/") },
            0,
            max_keys,
            false,
            continuation_token_in.as_deref(),
            None,
            start_after.as_deref(),
            &[],
            &[],
        );
    }

    // Build initial stack (from ContinuationToken or StartAfter)
    let mut token_stack: Vec<ListV2Frame> = if let Some(ct) = &continuation_token_in {
        match decode_token(ct) {
            Ok(tok) => {
                // Validate token belongs to the same listing shape
                if tok.bucket != bucket || tok.prefix != prefix || tok.delimiter.as_deref() != delimiter_q {
                    let mut parts = Vec::new();
                    if tok.bucket != bucket {
                        parts.push(format!("request-bucket {bucket} != token-bucket {}", tok.bucket));
                    }
                    if tok.prefix != prefix {
                        parts.push(format!("request-prefix {prefix} != token-prefix {}", tok.prefix));
                    }
                    if tok.delimiter.as_deref() != delimiter_q {
                        parts.push(format!(
                            "request-delimiter {:?} != token-delimiter {:?}",
                            delimiter_q,
                            tok.delimiter.as_deref()
                        ));
                    }

                    return s3pm_support::s3resp::s3_error(
                        StatusCode::BAD_REQUEST,
                        s3pm_support::s3xml::error_code::INVALID_REQUEST,
                        &format!(
                            "continuation-token does not match request parameters: {}",
                            parts.join(", ")
                        ),
                        Some(req.uri().path()),
                        None,
                    );
                }
                tok.stack
            }
            Err(e) => {
                return s3pm_support::s3resp::s3_error(
                    StatusCode::BAD_REQUEST,
                    s3pm_support::s3xml::error_code::INVALID_REQUEST,
                    &e.to_string(),
                    Some(req.uri().path()),
                    None,
                );
            }
        }
    } else if let Some(sa) = &start_after {
        build_stack_from_last(&dir_prefix, sa, recursive)
    } else {
        vec![ListV2Frame { dir: dir_prefix.clone(), after: "".to_string() }]
    };

    if token_stack.is_empty() {
        token_stack.push(ListV2Frame { dir: dir_prefix.clone(), after: "".to_string() });
    }

    // Build runtime frames from token stack
    let mut stack: Vec<RuntimeFrame> = Vec::new();
    for (i, fr) in token_stack.iter().enumerate() {
        let dir_fs = match join_object_path(&cfg.posix_root, bucket, &fr.dir) {
            Ok(p) => p,
            Err(_) => start_dir_fs.clone(),
        };
        let mut entries = read_dir_sorted(&dir_fs).unwrap_or_default();

        // Apply leaf_filter only at root frame (the directory where prefix “starts”).
        let is_root = i == 0;
        if is_root {
            if let Some(lf) = leaf_filter.as_deref() {
                entries.retain(|it| it.sort_key.starts_with(lf));
            }
        }

        let idx = first_index_after(&entries, &fr.after);

        stack.push(RuntimeFrame {
            dir_key: fr.dir.clone(),
            dir_fs,
            after: fr.after.clone(),
            entries,
            idx,
            is_root,
        });
    }

    let mut contents: Vec<s3pm_support::s3xml::ListObjectInfo> = Vec::new();
    let mut common_prefixes: Vec<String> = Vec::new();

    // Produce up to max_keys “results”; in delimiter mode keycount includes common prefixes
    while (contents.len() as u32 + common_prefixes.len() as u32) < max_keys {
        let Some(top) = stack.last_mut() else { break; };

        if top.idx >= top.entries.len() {
            stack.pop();
            continue;
        }

        let it = top.entries[top.idx].clone();
        top.idx += 1;
        top.after = it.sort_key.clone();

        if it.is_dir {
            if !recursive {
                // delimiter=/ mode: emit CommonPrefix, don't descend
                let cp = format!("{}{}{}", top.dir_key, it.name, "/");
                common_prefixes.push(cp);
                continue;
            }

            // recursive: descend
            let child_key = format!("{}{}{}", top.dir_key, it.name, "/");
            let child_fs = it.path.clone();

            let child_entries = read_dir_sorted(&child_fs).unwrap_or_default();
            stack.push(RuntimeFrame {
                dir_key: child_key,
                dir_fs: child_fs,
                after: "".to_string(),
                entries: child_entries,
                idx: 0,
                is_root: false,
            });
            continue;
        }

        // file: emit Contents using statx (AT_STATX_DONT_SYNC) for Lustre LSOM friendliness
        let stx = match statx_info(&it.path) {
            Some(s) => s,
            None => continue,
        };

        let key = format!("{}{}", top.dir_key, it.name);
        // Extra safety: only emit keys matching original prefix
        if !key.starts_with(&prefix) {
            continue;
        }

        let last_modified = s3pm_support::s3xml::format_s3_time_system(stx.mtime);
        let etag = format!("\"{}\"", stx.ino);
        let size = stx.size;

        let owner = if fetch_owner {
            Some(owner_info(stx.uid))
        } else {
            None
        };

        contents.push(s3pm_support::s3xml::ListObjectInfo {
            key,
            last_modified,
            etag,
            size,
            owner,
        });
    }

    let key_count = (contents.len() + common_prefixes.len()) as u32;
    let is_truncated = key_count >= max_keys && !stack.is_empty();

    let next_token = if is_truncated && key_count > 0 {
        // Build token from current runtime stack
        let tok = ListV2Token {
            v: 1,
            bucket: bucket.to_string(),
            prefix: prefix.clone(),
            delimiter: if recursive { None } else { Some("/".to_string()) },
            stack: stack
                .iter()
                .map(|rf| ListV2Frame {
                    dir: rf.dir_key.clone(),
                    after: rf.after.clone(),
                })
                .collect(),
        };
        encode_token(&tok).ok()
    } else {
        None
    };

    s3pm_support::s3resp::list_objects_v2(
        bucket,
        Some(&prefix),
        if recursive { None } else { Some("/") },
        key_count,
        max_keys,
        is_truncated && next_token.is_some(),
        continuation_token_in.as_deref(),
        next_token.as_deref(),
        start_after.as_deref(),
        &contents,
        &common_prefixes,
    )
}

// -------------------------
// PutObject and other write operations
// -------------------------

fn header_eq(headers: &HeaderMap, name: &str, expected: &str) -> bool {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|v| v == expected)
        .unwrap_or(false)
}

fn parse_u64_header(headers: &HeaderMap, name: &str) -> Result<u64> {
    let v = headers
        .get(name)
        .ok_or_else(|| anyhow!("missing header {name}"))?
        .to_str()
        .map_err(|_| anyhow!("invalid utf8 in header {name}"))?;
    v.parse::<u64>()
        .map_err(|_| anyhow!("invalid integer in header {name}: {v}"))
}

/// Returns (is_streaming_sigv4, logical_len)
fn compute_logical_len(headers: &HeaderMap) -> Result<(bool, u64)> {
    let is_streaming = header_eq(
        headers,
        "x-amz-content-sha256",
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
    );

    let logical_len = if is_streaming {
        parse_u64_header(headers, "x-amz-decoded-content-length")?
    } else {
        parse_u64_header(headers, "content-length")?
    };

    Ok((is_streaming, logical_len))
}

async fn handle_put_object(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s3pm_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    // Reject query params for PutObject for now (presigned etc.)
    if req.uri().query().is_some() {
        return s3pm_support::s3resp::not_implemented("query parameters are not implemented", None);
    }

    // SigV4: parse + verify (every request)
    if let Err(resp) = require_sigv4(&req, &cfg) {
        return resp;
    }

    let bucket = class.bucket.as_deref().unwrap_or("");
    let key = class.key.as_deref().unwrap_or("");

    if bucket.is_empty() || key.is_empty() {
        return s3pm_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s3pm_support::s3xml::error_code::INVALID_REQUEST,
            "missing bucket or key",
            Some(req.uri().path()),
            None,
        );
    }

    // S3 semantics: if bucket doesn't exist => NoSuchBucket
    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => {}
        Ok(false) => return s3pm_support::s3resp::no_such_bucket("bucket not found", Some(req.uri().path())),
        Err(e) => return s3pm_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path())),
    }

    let obj_path = match join_object_path(&cfg.posix_root, bucket, key) {
        Ok(p) => p,
        Err(e) => return s3pm_support::s3resp::access_denied(&e.to_string(), None),
    };

    // pick decoded length for streaming payloads
    let (is_streaming_sigv4, logical_len) = match compute_logical_len(req.headers()) {
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

    // Still require Content-Length at HTTP layer
    if req.headers().get(http::header::CONTENT_LENGTH).is_none() {
        return s3pm_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s3pm_support::s3xml::error_code::INVALID_REQUEST,
            "missing Content-Length",
            Some(req.uri().path()),
            None,
        );
    }

    let (parts, body) = req.into_parts();

    // Stream-write
    if let Err(e) = write_object_body_to_file(
        body,
        obj_path.clone(),
        logical_len,
        is_streaming_sigv4,
        StreamCfg {
            chunk_size: cfg.chunk_size,
            inflight: cfg.inflight,
            direct_io: cfg.direct_io,
        },
        app.uring.clone(),
        app.pool.clone(),
        app.io_sem.clone(),
        app.io_total,
    )
    .await
    {
        return s3pm_support::s3resp::internal_error(&e.to_string(), Some(parts.uri.path()), None);
    }

    // Build ETag (consistent with reads: inode-based ETag)
    let meta = match std::fs::metadata(&obj_path) {
        Ok(m) => m,
        Err(e) => return s3pm_support::s3resp::internal_error(&e.to_string(), Some(parts.uri.path()), None),
    };

    let etag = format!("\"{}\"", meta.ino());
    s3pm_support::s3resp::put_object_ok(&etag)
}

// ---- main ----

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    let cfg = Arc::new(load_cfg()?);

    let pool = Arc::new(BufPool::new(cfg.chunk_size, cfg.pool_size));
    pool.warm(cfg.pool_size);

    let io_total = cfg.pool_size.max(1);
    let io_sem = Arc::new(Semaphore::new(io_total));

    // Single global io_uring writer sized to the whole buffer pool.
    let uring = Arc::new(UringIO::spawn(io_total)?);

    let app = Arc::new(App {
        cfg: cfg.clone(),
        pool,
        io_sem,
        io_total,
        uring,
    });

    if let Some(sock_path) = cfg.bind_uds.clone() {
        let _ = std::fs::remove_file(&sock_path);

        if let Some(parent) = sock_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create UDS dir {}", parent.display()))?;
        }

        let listener = UnixListener::bind(&sock_path)
            .with_context(|| format!("bind uds {}", sock_path.display()))?;

        tracing::info!(
            "s3pm-gateway listening on uds {} (chunk_size={} inflight={} pool_size={})",
            sock_path.display(),
            cfg.chunk_size,
            cfg.inflight,
            cfg.pool_size
        );

        loop {
            let (stream, _addr) = listener.accept().await?;
            let app2 = app.clone();

            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req| handle(req, app2.clone()));
                if let Err(e) = http1::Builder::new()
                    .max_buf_size(8 * 1024 * 1024)
                    .writev(true)
                    .serve_connection(io, svc)
                    .await
                {
                    tracing::debug!(error = %e, "connection error");
                }
            });
        }
    } else {
        let listener = TcpListener::bind(&cfg.bind_addr)
            .await
            .with_context(|| format!("bind {}", cfg.bind_addr))?;

        tracing::info!(
            "s3pm-gateway listening on {} (chunk_size={} inflight={} pool_size={})",
            cfg.bind_addr,
            cfg.chunk_size,
            cfg.inflight,
            cfg.pool_size
        );

        loop {
            let (stream, _peer) = listener.accept().await?;
            stream.set_nodelay(true)?;
            let app2 = app.clone();

            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req| handle(req, app2.clone()));
                if let Err(e) = http1::Builder::new()
                    .max_buf_size(8 * 1024 * 1024)
                    .writev(true)
                    .serve_connection(io, svc)
                    .await
                {
                    tracing::debug!(error = %e, "connection error");
                }
            });
        }
    }
}
