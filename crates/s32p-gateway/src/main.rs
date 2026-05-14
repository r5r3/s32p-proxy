use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

pub mod buffer;
mod fs_helpers;
mod multipart;
pub mod streaming;
mod uring_io;

#[cfg(feature = "lustre")]
mod lustre;

use std::{
    convert::Infallible,
    fs,
    os::unix::fs::{FileExt, MetadataExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};

use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use httpdate::fmt_http_date;
use hyper::{HeaderMap, body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use s32p_support::{
    self,
    preconditions::{
        PreconditionOutcome, evaluate_copy_source_preconditions, evaluate_read_preconditions,
        evaluate_write_preconditions, parse_conditional_headers,
    },
    utils::{ByteRange, parse_range_header},
};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, UnixListener};

/// Direct connection peer captured at accept time. Used to (a) decide whether
/// to trust the `X-Forwarded-For` stamped by s32p-proxy (only when the peer is
/// loopback or UDS) and (b) provide a usable client identity in standalone
/// deployments where no proxy fronts the gateway.
#[derive(Debug, Clone)]
enum PeerAddr {
    Tcp(std::net::SocketAddr),
    Unix,
}

impl PeerAddr {
    fn is_local(&self) -> bool {
        match self {
            PeerAddr::Tcp(sa) => sa.ip().is_loopback(),
            PeerAddr::Unix => true,
        }
    }
    fn client_label(&self) -> String {
        match self {
            PeerAddr::Tcp(sa) => sa.ip().to_string(),
            PeerAddr::Unix => "unix".to_string(),
        }
    }
}

#[cfg(feature = "lustre")]
use crate::fs_helpers::stripe_count_for_size;
use crate::{
    buffer::{BufPool, PooledBuf, SliceOwner},
    fs_helpers::{
        LustreStriping, OpenDirect, OpenMode, bucket_exists_dir, bucket_root_path,
        join_object_path, open_file, statx_info,
    },
    streaming::{
        StreamCfg, WriteObjectDest, copy_file_to_file, stream_range_body, write_object_body,
    },
    uring_io::UringIO,
};

type Resp = s32p_support::s3resp::HttpResponse;

// ---- config ----

#[derive(Clone)]
struct Cfg {
    bind_addr:               String,
    bind_uds:                Option<PathBuf>,
    posix_root:              PathBuf,
    access_key:              String,
    secret_key:              String,
    public_scheme:           String,
    region:                  String,
    chunk_size:              usize,
    inflight:                usize,
    pool_size:               usize,
    direct_io:               bool,
    copy_max_size:           u64,
    mpu_dir_name:            String,
    #[cfg(feature = "lustre")]
    lustre_max_stripe_count: u32,
    virtual_hosted_suffixes: Vec<String>,
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
    let bind_addr = std::env::var("S32P_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:0".to_string());
    let bind_uds = std::env::var("S32P_BIND_UDS").ok().map(PathBuf::from);
    let posix_root =
        PathBuf::from(std::env::var("S32P_POSIX_ROOT").context("S32P_POSIX_ROOT missing")?);

    let access_key = std::env::var("AWS_ACCESS_KEY_ID").context("AWS_ACCESS_KEY_ID missing")?;
    let secret_key =
        std::env::var("AWS_SECRET_ACCESS_KEY").context("AWS_SECRET_ACCESS_KEY missing")?;

    let public_scheme = std::env::var("S32P_PUBLIC_SCHEME").unwrap_or_else(|_| "http".to_string());
    let region = std::env::var("S32P_REGION").unwrap_or_else(|_| "us-east-1".to_string());

    let chunk_size = env_usize("S32P_CHUNK_SIZE_MB", 4) * 1024 * 1024;
    let inflight = env_usize("S32P_INFLIGHT", 16).max(1);

    let pool_size_default = inflight.saturating_mul(8).max(1);
    let pool_size = env_usize("S32P_POOL_SIZE", pool_size_default).max(1);

    let direct_io = env_bool("S32P_DIRECT_IO", false);

    // CopyObject single-request size limit (AWS default is 5GB; larger requires multipart copy).
    let copy_max_size_gb = env_usize("S32P_COPY_MAX_SIZE_GB", 5).max(1);
    let copy_max_size = (copy_max_size_gb as u64).saturating_mul(1024u64 * 1024u64 * 1024u64);

    // upload directory for multipart uploads
    let mpu_dir_name = std::env::var("S32P_MPU_DIR").unwrap_or_else(|_| ".s32p-mpu".to_string());
    if mpu_dir_name.is_empty()
        || mpu_dir_name == "."
        || mpu_dir_name == ".."
        || mpu_dir_name.contains('/')
        || mpu_dir_name.contains('\\')
    {
        return Err(anyhow!(
            "invalid S32P_MPU_DIR={mpu_dir_name:?} (must be a single path component)"
        ));
    }

    // Maximum Lustre stripe count (only effective with --features lustre)
    #[allow(unused_variables)]
    let lustre_max_stripe_count = env_usize("S32P_LUSTRE_MAX_STRIPE_COUNT", 4).max(1) as u32;

    // Load virtual hosted suffixes from environment variable.
    // An unset OR empty env var, or a value of only commas/whitespace, must yield an empty Vec —
    // a bare "".split(',') returns vec![""], and an empty suffix matches every host
    // (host.ends_with("") is always true), which would mis-classify all path-style requests.
    let virtual_hosted_suffixes: Vec<String> = std::env::var("S32P_VIRTUAL_HOSTED_SUFFIXES")
        .ok()
        .map(|s| s.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();

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
        copy_max_size,
        mpu_dir_name,
        #[cfg(feature = "lustre")]
        lustre_max_stripe_count,
        virtual_hosted_suffixes,
    })
}

// ---- request handler ----

struct App {
    cfg:                     Arc<Cfg>,
    pool:                    Arc<BufPool>,
    uring:                   Arc<UringIO>,
    virtual_hosted_suffixes: Vec<String>,
}

fn is_reserved_first_segment(key_or_prefix: &str, mpu_dir_name: &str) -> bool {
    // We reserve keys whose FIRST path segment is exactly mpu_dir_name.
    // Examples that match:
    //   ".s32p-mpu"
    //   ".s32p-mpu/"
    //   ".s32p-mpu/anything"
    // Examples that do NOT match:
    //   "foo/.s32p-mpu/bar"
    let key_or_prefix = key_or_prefix.trim_end_matches('/');

    if key_or_prefix == mpu_dir_name {
        return true;
    }
    key_or_prefix
        .strip_prefix(mpu_dir_name)
        .is_some_and(|rest| rest.starts_with('/'))
}

async fn read_small(
    file: Arc<std::fs::File>,
    pool: Arc<BufPool>,
    off: u64,
    len: usize,
) -> Result<Bytes> {
    let pooled = pool.acquire().await.map_err(|_| anyhow!("buffer pool closed"))?;

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

async fn handle(
    req: Request<Incoming>,
    app: Arc<App>,
    peer: Option<PeerAddr>,
) -> Result<Resp, Infallible> {
    let method = req.method().clone();
    let uri_log = req.uri().to_string();
    let host_log = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("<missing>")
        .to_string();
    // Pick the "client IP" to log:
    //   - direct peer is loopback (or UDS) → trust X-Forwarded-For from the
    //     fronting s32p-proxy, fall back to the peer label if it's missing
    //   - direct peer is a real network address → use the peer; ignore XFF
    //     (a direct client could otherwise spoof their source)
    let xff = req.headers().get("x-forwarded-for").and_then(|v| v.to_str().ok());
    let client_log = match peer.as_ref() {
        Some(p) if p.is_local() => xff.map(str::to_string).unwrap_or_else(|| p.client_label()),
        Some(p) => p.client_label(),
        None => xff.unwrap_or("<unknown>").to_string(),
    };

    let class = s32p_support::classifier::classify_with_headers(
        req.method().as_str(),
        req.uri(),
        Some(req.headers()),
        &app.virtual_hosted_suffixes,
    );

    tracing::debug!(
        client = %client_log,
        method = %method,
        uri = %uri_log,
        host = %host_log,
        op = ?class.op,
        bucket = ?class.bucket,
        key = ?class.key,
        "incoming request"
    );

    // All actions require authentication
    let cfg = app.cfg.clone();
    if let Err(rej) = require_sigv4(&req, &cfg) {
        tracing::debug!(
            client = %client_log,
            method = %method,
            uri = %uri_log,
            host = %host_log,
            status = rej.response.status().as_u16(),
            reason = %rej.reason,
            "sigv4 verification failed"
        );
        return Ok(rej.response);
    }

    let resp = match &class.op {
        s32p_support::classifier::S3Op::Read(s32p_support::classifier::ReadOp::ListBuckets) => {
            handle_list_buckets(req, app, &class).await
        }
        s32p_support::classifier::S3Op::Read(
            s32p_support::classifier::ReadOp::GetBucketLocation,
        ) => handle_get_bucket_location(req, app, &class).await,
        s32p_support::classifier::S3Op::Read(s32p_support::classifier::ReadOp::HeadBucket) => {
            handle_head_bucket(req, app, &class).await
        }
        s32p_support::classifier::S3Op::Read(s32p_support::classifier::ReadOp::GetObject)
        | s32p_support::classifier::S3Op::Read(s32p_support::classifier::ReadOp::HeadObject) => {
            handle_get_object(req, app, &class).await
        }
        s32p_support::classifier::S3Op::Read(s32p_support::classifier::ReadOp::ListObjectsV2) => {
            handle_list_objects_v2(req, app, &class).await
        }
        s32p_support::classifier::S3Op::Read(s32p_support::classifier::ReadOp::ListObjectsV1) => {
            handle_list_objects_v1(req, app, &class).await
        }
        s32p_support::classifier::S3Op::Read(s32p_support::classifier::ReadOp::GetObjectAcl) => {
            handle_get_object_acl(req, app, &class).await
        }
        s32p_support::classifier::S3Op::Read(s32p_support::classifier::ReadOp::GetBucketAcl) => {
            handle_get_bucket_acl(req, app, &class).await
        }
        s32p_support::classifier::S3Op::Write(s32p_support::classifier::WriteOp::PutObjectAcl) => {
            handle_put_object_acl(req, app, &class).await
        }
        s32p_support::classifier::S3Op::Write(s32p_support::classifier::WriteOp::PutBucketAcl) => {
            handle_put_bucket_acl(req, app, &class).await
        }
        s32p_support::classifier::S3Op::Write(s32p_support::classifier::WriteOp::PutObject) => {
            handle_put_object(req, app, &class).await
        }
        s32p_support::classifier::S3Op::Write(s32p_support::classifier::WriteOp::RenameObject) => {
            handle_rename_object(req, app, &class).await
        }
        s32p_support::classifier::S3Op::Write(s32p_support::classifier::WriteOp::CopyObject) => {
            handle_copy_object(req, app, &class).await
        }
        s32p_support::classifier::S3Op::Write(s32p_support::classifier::WriteOp::DeleteObject) => {
            handle_delete_object(req, app, &class).await
        }
        s32p_support::classifier::S3Op::Write(s32p_support::classifier::WriteOp::DeleteObjects) => {
            handle_delete_objects(req, app, &class).await
        }
        s32p_support::classifier::S3Op::Multipart(_) => handle_multipart(req, app, &class).await,
        s32p_support::classifier::S3Op::Versioning(_) => handle_versioning(req, app, &class).await,
        _ => handle_other(req, app, &class).await,
    };

    tracing::debug!(
        client = %client_log,
        method = %method,
        uri = %uri_log,
        status = resp.status().as_u16(),
        "request completed"
    );

    Ok(resp)
}

fn require_sigv4(
    req: &Request<Incoming>,
    cfg: &Cfg,
) -> std::result::Result<(), s32p_support::SigV4Rejection> {
    s32p_support::verify_sigv4_request_any(
        req.method().as_str(),
        req.uri(),
        req.headers(),
        Some(&cfg.access_key),
        &cfg.secret_key,
        Some(req.uri().path()),
    )
}

fn query_is_only_location(req: &Request<Incoming>) -> bool {
    req.method() == http::Method::GET
        && s32p_support::classifier::QueryParams::from_uri(req.uri()).is_only_effective("location")
}

fn has_effective_query(req: &Request<Incoming>) -> bool {
    !s32p_support::classifier::QueryParams::from_uri(req.uri()).is_empty_effective()
}

// -------------------------
// ListBuckets (pagination)
// -------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ListBucketsToken {
    v:             u8,
    bucket_region: Option<String>,
    prefix:        Option<String>,
    after:         String,
}

fn encode_list_buckets_token(tok: &ListBucketsToken) -> Result<String> {
    let js = serde_json::to_vec(tok)?;
    Ok(URL_SAFE_NO_PAD.encode(js))
}

fn decode_list_buckets_token(s: &str) -> Result<ListBucketsToken> {
    let raw = URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(|e| anyhow!("bad continuation-token: {e}"))?;
    let tok: ListBucketsToken =
        serde_json::from_slice(&raw).map_err(|e| anyhow!("bad continuation-token json: {e}"))?;
    Ok(tok)
}

async fn handle_list_buckets(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    // Optional params
    let bucket_region_q = if class.query.has("bucket-region") {
        Some(class.query.first("bucket-region").unwrap_or("").to_string())
    } else {
        None
    };

    // AWS requires that the request is made to the regional endpoint that matches bucket-region.
    if let Some(br) = bucket_region_q.as_deref() {
        if !br.is_empty() && br != cfg.region.as_str() {
            return s32p_support::s3resp::s3_error(
                StatusCode::BAD_REQUEST,
                s32p_support::s3xml::error_code::INVALID_REQUEST,
                "bucket-region does not match this endpoint region",
                Some(req.uri().path()),
                None,
            );
        }
    }

    let prefix_q = if class.query.has("prefix") {
        Some(class.query.first("prefix").unwrap_or("").to_string())
    } else {
        None
    };

    let continuation_in = class
        .query
        .first("continuation-token")
        .and_then(|s| if s.is_empty() { None } else { Some(s.to_string()) });

    let max_buckets_in = match class.query.first("max-buckets") {
        None => None,
        Some(s) => match s.parse::<u32>() {
            Ok(v) => Some(v),
            Err(_) => {
                return s32p_support::s3resp::s3_error(
                    StatusCode::BAD_REQUEST,
                    s32p_support::s3xml::error_code::INVALID_REQUEST,
                    "invalid max-buckets",
                    Some(req.uri().path()),
                    None,
                );
            }
        },
    };

    if let Some(m) = max_buckets_in {
        if m < 1 || m > 10_000 {
            return s32p_support::s3resp::s3_error(
                StatusCode::BAD_REQUEST,
                s32p_support::s3xml::error_code::INVALID_REQUEST,
                "max-buckets must be between 1 and 10000",
                Some(req.uri().path()),
                None,
            );
        }
    }

    let paginated = max_buckets_in.is_some()
        || class.query.has("bucket-region")
        || class.query.has("prefix")
        || class.query.has("continuation-token");

    // Per AWS docs: if bucket-region/prefix/continuation-token are specified without max-buckets,
    // apply a default page size of 10,000.
    let page_size = if let Some(m) = max_buckets_in {
        Some(m)
    } else if paginated {
        Some(10_000)
    } else {
        None
    };

    // Load buckets from the POSIX root (top-level directories).
    let mut buckets: Vec<(String, SystemTime)> = Vec::new();
    let rd = match fs::read_dir(&cfg.posix_root) {
        Ok(rd) => rd,
        Err(e) => {
            return s32p_support::s3resp::access_denied(
                &format!("read_dir failed: {e}"),
                Some(req.uri().path()),
            );
        }
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
        let (is_dir, created) = if ft.is_symlink() {
            let link_path = ent.path();
            let target = match fs::read_link(&link_path) {
                Ok(t) => t,
                Err(_) => continue,
            };
            let target = if target.is_relative() {
                match link_path.parent() {
                    Some(p) => p.join(target),
                    None => continue,
                }
            } else {
                target
            };
            match fs::metadata(&target) {
                Ok(m) => (m.is_dir(), m.modified().ok().unwrap_or(SystemTime::UNIX_EPOCH)),
                Err(_) => continue,
            }
        } else {
            let m = match ent.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            (ft.is_dir(), m.modified().ok().unwrap_or(SystemTime::UNIX_EPOCH))
        };

        if !is_dir {
            continue;
        }

        let name = ent.file_name().to_string_lossy().to_string();
        if name.is_empty() || name == "." || name == ".." {
            continue;
        }

        buckets.push((name, created));
    }

    // Sort lexicographically by bucket name.
    buckets.sort_by(|a, b| a.0.cmp(&b.0));

    // Apply prefix filter.
    if let Some(pfx) = prefix_q.as_deref() {
        buckets.retain(|(name, _)| name.starts_with(pfx));
    }

    // Apply continuation token.
    let mut start_after = String::new();
    if let Some(ct) = &continuation_in {
        match decode_list_buckets_token(ct) {
            Ok(tok) => {
                // Validate token matches request filters.
                if tok.v != 1 {
                    return s32p_support::s3resp::s3_error(
                        StatusCode::BAD_REQUEST,
                        s32p_support::s3xml::error_code::INVALID_REQUEST,
                        "unsupported continuation-token version",
                        Some(req.uri().path()),
                        None,
                    );
                }
                if tok.prefix != prefix_q || tok.bucket_region != bucket_region_q {
                    return s32p_support::s3resp::s3_error(
                        StatusCode::BAD_REQUEST,
                        s32p_support::s3xml::error_code::INVALID_REQUEST,
                        "continuation-token does not match request parameters",
                        Some(req.uri().path()),
                        None,
                    );
                }
                start_after = tok.after;
            }
            Err(e) => {
                return s32p_support::s3resp::s3_error(
                    StatusCode::BAD_REQUEST,
                    s32p_support::s3xml::error_code::INVALID_REQUEST,
                    &e.to_string(),
                    Some(req.uri().path()),
                    None,
                );
            }
        }
    }

    if !start_after.is_empty() {
        buckets.retain(|(name, _)| name.as_str() > start_after.as_str());
    }

    let mut next_token_out: Option<String> = None;
    let mut page: Vec<(String, SystemTime)> = buckets;

    if let Some(ps) = page_size {
        let ps = ps as usize;
        if page.len() > ps {
            let last_name = page[ps - 1].0.clone();
            page.truncate(ps);

            let tok = ListBucketsToken {
                v:             1,
                bucket_region: bucket_region_q.clone(),
                prefix:        prefix_q.clone(),
                after:         last_name,
            };
            match encode_list_buckets_token(&tok) {
                Ok(s) => next_token_out = Some(s),
                Err(e) => {
                    return s32p_support::s3resp::internal_error(
                        &e.to_string(),
                        Some(req.uri().path()),
                        None,
                    );
                }
            }
        }
    }

    let include_bucket_region = paginated;
    let out: Vec<s32p_support::s3xml::BucketInfo> = page
        .into_iter()
        .map(|(name, creation_date)| s32p_support::s3xml::BucketInfo {
            name,
            bucket_region: include_bucket_region.then(|| cfg.region.clone()),
            bucket_arn: None,
            creation_date,
        })
        .collect();

    s32p_support::s3resp::list_buckets_paginated(
        &cfg.access_key,
        &cfg.access_key,
        &out,
        prefix_q.as_deref(),
        next_token_out.as_deref(),
    )
}

async fn handle_get_bucket_location(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    // Only allow ?location (classifier should already ensure this, but keep it defensive)
    if req.uri().query().is_some() && !query_is_only_location(&req) {
        return s32p_support::s3resp::not_implemented("query parameters are not implemented", None);
    }

    let bucket = class.bucket.as_deref().unwrap_or("");
    if bucket.is_empty() {
        return s32p_support::s3resp::not_implemented("missing bucket", Some(req.uri().path()));
    }

    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => s32p_support::s3resp::get_bucket_location(&cfg.region),
        Ok(false) => {
            s32p_support::s3resp::no_such_bucket("bucket not found", Some(req.uri().path()))
        }
        Err(e) => s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path())),
    }
}

async fn handle_get_object_acl(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    let bucket = class.bucket.as_deref().unwrap_or("");
    let key = class.key.as_deref().unwrap_or("");
    if bucket.is_empty() || key.is_empty() {
        return s32p_support::s3resp::not_implemented(
            "missing bucket or key",
            Some(req.uri().path()),
        );
    }
    if is_reserved_first_segment(key, &cfg.mpu_dir_name) {
        return s32p_support::s3resp::access_denied("reserved key prefix", Some(req.uri().path()));
    }

    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => {}
        Ok(false) => {
            return s32p_support::s3resp::no_such_bucket(
                "bucket not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    }

    let obj_path = match join_object_path(&cfg.posix_root, bucket, key) {
        Ok(p) => p,
        Err(e) => return s32p_support::s3resp::access_denied(&e.to_string(), None),
    };

    // statx the object (follow symlinks like GetObject does, then fall back to
    // NOFOLLOW via the helper) to get uid + mode bits.
    let m = match std::fs::metadata(&obj_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return s32p_support::s3resp::no_such_key(
                "object not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    };
    let uid = std::os::unix::fs::MetadataExt::uid(&m);
    let mode = std::os::unix::fs::PermissionsExt::mode(&m.permissions());
    let owner = owner_info(uid);

    s32p_support::s3resp::get_acl(&owner.id, &owner.display_name, (mode & 0o004) != 0)
}

async fn handle_get_bucket_acl(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    let bucket = class.bucket.as_deref().unwrap_or("");
    if bucket.is_empty() {
        return s32p_support::s3resp::not_implemented("missing bucket", Some(req.uri().path()));
    }

    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => {}
        Ok(false) => {
            return s32p_support::s3resp::no_such_bucket(
                "bucket not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    }

    let bucket_root = match bucket_root_path(&cfg.posix_root, bucket) {
        Ok(p) => p,
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    };
    let m = match std::fs::metadata(&bucket_root) {
        Ok(m) => m,
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    };
    let uid = std::os::unix::fs::MetadataExt::uid(&m);
    let mode = std::os::unix::fs::PermissionsExt::mode(&m.permissions());
    let owner = owner_info(uid);

    s32p_support::s3resp::get_acl(&owner.id, &owner.display_name, (mode & 0o004) != 0)
}

/// Determine whether the requested ACL grants public read access (POSIX
/// `o+r`). Mirrors the get-side logic: only the `Group: AllUsers` grant with
/// `READ` / `FULL_CONTROL` maps to a real bit; everything else is treated as
/// "no public read".
///
/// Precedence: `x-amz-acl` canned header → individual `x-amz-grant-*`
/// headers → XML body. AWS rejects combinations; for a no-op check we
/// honor whichever was specified first and ignore the rest.
fn acl_request_world_readable_intent(
    headers: &http::HeaderMap,
    body: &[u8],
) -> std::result::Result<bool, String> {
    if let Some(canned) = headers.get("x-amz-acl").and_then(|v| v.to_str().ok()) {
        let v = canned.trim().to_ascii_lowercase();
        return match v.as_str() {
            "private"
            | "bucket-owner-read"
            | "bucket-owner-full-control"
            | "aws-exec-read"
            | "log-delivery-write"
            | "authenticated-read" => Ok(false),
            "public-read" | "public-read-write" => Ok(true),
            other => Err(format!("unknown canned ACL: {other}")),
        };
    }

    let grant_headers = [
        "x-amz-grant-read",
        "x-amz-grant-write",
        "x-amz-grant-read-acp",
        "x-amz-grant-write-acp",
        "x-amz-grant-full-control",
    ];
    let any_grant_header = grant_headers.iter().any(|h| headers.contains_key(*h));
    if any_grant_header {
        let mentions_all_users = |hname: &str| {
            headers
                .get(hname)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|s| s.contains("AllUsers"))
        };
        return Ok(mentions_all_users("x-amz-grant-read")
            || mentions_all_users("x-amz-grant-full-control"));
    }

    s32p_support::s3xml::parse_put_acl_request_world_readable(body).map_err(|e| e.to_string())
}

async fn handle_put_object_acl(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    let bucket = class.bucket.as_deref().unwrap_or("");
    let key = class.key.as_deref().unwrap_or("");
    if bucket.is_empty() || key.is_empty() {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_REQUEST,
            "missing bucket or key",
            Some(req.uri().path()),
            None,
        );
    }
    if is_reserved_first_segment(key, &cfg.mpu_dir_name) {
        return s32p_support::s3resp::access_denied("reserved key prefix", Some(req.uri().path()));
    }

    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => {}
        Ok(false) => {
            return s32p_support::s3resp::no_such_bucket(
                "bucket not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    }

    let obj_path = match join_object_path(&cfg.posix_root, bucket, key) {
        Ok(p) => p,
        Err(e) => return s32p_support::s3resp::access_denied(&e.to_string(), None),
    };

    let m = match std::fs::metadata(&obj_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return s32p_support::s3resp::no_such_key(
                "object not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    };
    let current = (std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o004) != 0;

    let (parts, body) = req.into_parts();
    let collected = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            return s32p_support::s3resp::invalid_request(
                &format!("failed to read body: {e}"),
                Some(parts.uri.path()),
            );
        }
    };

    let requested = match acl_request_world_readable_intent(&parts.headers, &collected) {
        Ok(b) => b,
        Err(reason) => {
            tracing::debug!("PutObjectAcl invalid: {reason}");
            return s32p_support::s3resp::invalid_request(
                "invalid ACL request",
                Some(parts.uri.path()),
            );
        }
    };

    if requested == current {
        s32p_support::s3resp::put_acl_ok()
    } else {
        tracing::debug!(
            requested_world_readable = requested,
            current_world_readable = current,
            "PutObjectAcl rejected: would change effective access"
        );
        s32p_support::s3resp::not_implemented(
            "PutObjectAcl is accepted only when it matches the current effective access",
            Some(parts.uri.path()),
        )
    }
}

async fn handle_put_bucket_acl(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    let bucket = class.bucket.as_deref().unwrap_or("");
    if bucket.is_empty() {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_REQUEST,
            "missing bucket",
            Some(req.uri().path()),
            None,
        );
    }

    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => {}
        Ok(false) => {
            return s32p_support::s3resp::no_such_bucket(
                "bucket not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    }

    let bucket_root = match bucket_root_path(&cfg.posix_root, bucket) {
        Ok(p) => p,
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    };
    let m = match std::fs::metadata(&bucket_root) {
        Ok(m) => m,
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    };
    let current = (std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o004) != 0;

    let (parts, body) = req.into_parts();
    let collected = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            return s32p_support::s3resp::invalid_request(
                &format!("failed to read body: {e}"),
                Some(parts.uri.path()),
            );
        }
    };

    let requested = match acl_request_world_readable_intent(&parts.headers, &collected) {
        Ok(b) => b,
        Err(reason) => {
            tracing::debug!("PutBucketAcl invalid: {reason}");
            return s32p_support::s3resp::invalid_request(
                "invalid ACL request",
                Some(parts.uri.path()),
            );
        }
    };

    if requested == current {
        s32p_support::s3resp::put_acl_ok()
    } else {
        tracing::debug!(
            requested_world_readable = requested,
            current_world_readable = current,
            "PutBucketAcl rejected: would change effective access"
        );
        s32p_support::s3resp::not_implemented(
            "PutBucketAcl is accepted only when it matches the current effective access",
            Some(parts.uri.path()),
        )
    }
}

async fn handle_head_bucket(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    // Defensive: HeadBucket should not have query params in our implementation.
    if has_effective_query(&req) {
        return s32p_support::s3resp::not_implemented("query parameters are not implemented", None);
    }

    let bucket = class.bucket.as_deref().unwrap_or("");
    if bucket.is_empty() {
        return s32p_support::s3resp::not_implemented("missing bucket", Some(req.uri().path()));
    }

    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => s32p_support::s3resp::head_bucket_ok(&cfg.region),
        Ok(false) => {
            s32p_support::s3resp::no_such_bucket("bucket not found", Some(req.uri().path()))
        }
        Err(e) => s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path())),
    }
}

async fn handle_multipart(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    crate::multipart::handle(req, app, class).await
}

async fn handle_versioning(
    _req: Request<Incoming>,
    _app: Arc<App>,
    _class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    s32p_support::s3resp::not_implemented("versioning is not implemented", None)
}

async fn handle_other(
    _req: Request<Incoming>,
    _app: Arc<App>,
    _class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    // Preserve the previous general message
    s32p_support::s3resp::not_implemented("only GET/HEAD /{bucket}/{key} is implemented", None)
}

// Build a HEAD response from `lstat(2)` metadata. Used when `open(2)` returns
// ENOENT for a path that is itself a (broken) symlink, so HEAD agrees with the
// listing view of the same key. Mirrors the precondition handling of the main
// HEAD/GET path; the symlink's own inode/mtime/size feed ETag/Last-Modified/
// Content-Length.
fn head_response_from_lstat(req: &Request<Incoming>, lmeta: &std::fs::Metadata) -> Resp {
    let size = lmeta.len();
    let lm_st = lmeta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let last_modified = fmt_http_date(lm_st);
    let etag_unquoted = lmeta.ino().to_string();
    let etag = format!("\"{}\"", etag_unquoted);

    let cond = match parse_conditional_headers(req.headers()) {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("invalid conditional headers: {e}");
            return s32p_support::s3resp::invalid_request(&msg, Some(req.uri().path()));
        }
    };
    match evaluate_read_preconditions(&cond, &etag_unquoted, lm_st) {
        PreconditionOutcome::Proceed => {}
        PreconditionOutcome::NotModified => {
            return s32p_support::s3resp::not_modified(Some(&etag), Some(&last_modified));
        }
        PreconditionOutcome::PreconditionFailed => {
            return s32p_support::s3resp::precondition_failed(
                "GET/HEAD precondition failed",
                Some(req.uri().path()),
            );
        }
    }

    s32p_support::s3resp::object_response(
        StatusCode::OK,
        s32p_support::s3resp::empty_body(),
        "application/octet-stream",
        size,
        &etag,
        &last_modified,
        None,
    )
}

async fn handle_get_object(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    // Allow SigV4 presign query params; reject only effective (non-presign) query params.
    if has_effective_query(&req) {
        return s32p_support::s3resp::not_implemented("query parameters are not implemented", None);
    }

    let is_head_object = matches!(
        &class.op,
        s32p_support::classifier::S3Op::Read(s32p_support::classifier::ReadOp::HeadObject)
    );

    let bucket = class.bucket.as_deref().unwrap_or("");
    let key = class.key.as_deref().unwrap_or("");

    // hide multipart upload dir
    if is_reserved_first_segment(key, &cfg.mpu_dir_name) {
        return s32p_support::s3resp::no_such_key("not found", None);
    }

    // If the bucket is missing, S3 expects NoSuchBucket (not NoSuchKey).
    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => {}
        Ok(false) => {
            return s32p_support::s3resp::no_such_bucket(
                "bucket not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    }

    let obj_path = match join_object_path(&cfg.posix_root, bucket, key) {
        Ok(p) => p,
        Err(e) => return s32p_support::s3resp::access_denied(&e.to_string(), None),
    };

    // open once (buffered) to stat + inode + size
    let (std_file, _used_direct) =
        match open_file(&obj_path, OpenMode::Read, OpenDirect::Buffered, None) {
            Ok(v) => v,
            Err(e) => {
                let ioe = e.downcast_ref::<std::io::Error>();
                match ioe.map(|x| x.kind()) {
                    Some(std::io::ErrorKind::NotFound) => {
                        // Broken symlink: open() follows the link and fails with
                        // ENOENT. Listings still surface the entry via lstat
                        // fallback (statx_info), so HEAD must too — otherwise
                        // LIST advertises a key that HEAD then denies. GET is
                        // unchanged: there is no readable content, so 404 is
                        // the only honest answer.
                        if is_head_object {
                            if let Ok(lmeta) = std::fs::symlink_metadata(&obj_path) {
                                if lmeta.file_type().is_symlink() {
                                    return head_response_from_lstat(&req, &lmeta);
                                }
                            }
                        }
                        return s32p_support::s3resp::no_such_key("not found", None);
                    }
                    Some(std::io::ErrorKind::PermissionDenied) => {
                        return s32p_support::s3resp::access_denied("permission denied", None);
                    }
                    _ => {
                        return s32p_support::s3resp::internal_error(
                            &e.to_string(),
                            Some(req.uri().path()),
                            None,
                        );
                    }
                }
            }
        };

    let meta = match std_file.metadata() {
        Ok(m) => m,
        Err(e) => {
            return s32p_support::s3resp::internal_error(
                &e.to_string(),
                Some(req.uri().path()),
                None,
            );
        }
    };

    let size = meta.len();

    // IMPORTANT: real mtime in RFC1123 / HTTP-date format (required by many S3 clients).
    // If metadata.modified() fails, fall back to UNIX_EPOCH (still a valid HTTP date).
    let lm_st = meta.modified().unwrap_or_else(|_| SystemTime::UNIX_EPOCH);
    let last_modified = fmt_http_date(lm_st);

    // inode-based ETag
    let etag_unquoted = meta.ino().to_string();
    let etag = format!("\"{}\"", etag_unquoted);

    // are preconditions matched?
    let cond = match parse_conditional_headers(req.headers()) {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("invalid conditional headers: {e}");
            return s32p_support::s3resp::invalid_request(&msg, Some(req.uri().path()));
        }
    };

    match evaluate_read_preconditions(&cond, &etag_unquoted, lm_st) {
        PreconditionOutcome::Proceed => {}
        PreconditionOutcome::NotModified => {
            tracing::debug!("Read preconditions: NotModified (304) for {}", obj_path.display());
            return s32p_support::s3resp::not_modified(Some(&etag), Some(&last_modified));
        }
        PreconditionOutcome::PreconditionFailed => {
            tracing::debug!("Read preconditions failed (412) for {}", obj_path.display());
            return s32p_support::s3resp::precondition_failed(
                "GET/HEAD precondition failed",
                Some(req.uri().path()),
            );
        }
    }

    // Empty object: 200 + Content-Length: 0 (+ common headers)
    if size == 0 {
        return s32p_support::s3resp::object_response(
            StatusCode::OK,
            s32p_support::s3resp::empty_body(),
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
                Err(e) => return s32p_support::s3resp::invalid_range(&e.to_string(), None),
            },
            Err(_) => return s32p_support::s3resp::invalid_range("bad Range header", None),
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
                Some(s32p_support::s3resp::object_content_range(
                    want.start,
                    want.end_excl - 1,
                    size,
                )),
            )
        } else {
            (StatusCode::OK, size, None)
        };

        return s32p_support::s3resp::object_response(
            status,
            s32p_support::s3resp::empty_body(),
            "application/octet-stream",
            content_length,
            &etag,
            &last_modified,
            content_range.as_deref(),
        );
    }

    // Small body fast-path (<= one chunk): acquire ONE permit for this file/request.
    if (want_len as usize) <= cfg.chunk_size {
        let file = Arc::new(std_file);
        let bytes = match read_small(file, app.pool.clone(), want.start, want_len as usize).await {
            Ok(b) => b,
            Err(e) => {
                return s32p_support::s3resp::internal_error(
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
                Some(s32p_support::s3resp::object_content_range(want.start, end_incl, size)),
            )
        } else {
            (StatusCode::OK, size, None)
        };

        return s32p_support::s3resp::object_response(
            status,
            s32p_support::s3resp::body_bytes(bytes),
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
            inflight:   cfg.inflight,
            direct_io:  cfg.direct_io,
        },
        app.uring.clone(),
        app.pool.clone(),
    )
    .await
    {
        Ok(b) => b.boxed(),
        Err(e) => {
            return s32p_support::s3resp::internal_error(
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
            Some(s32p_support::s3resp::object_content_range(want.start, want.end_excl - 1, size)),
        )
    } else {
        (StatusCode::OK, size, None)
    };

    s32p_support::s3resp::object_response(
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
    v:         u8,
    bucket:    String,
    prefix:    String,           // original request prefix (possibly empty)
    delimiter: Option<String>,   // Some("/") or None (recursive)
    stack:     Vec<ListV2Frame>, // root..deepest
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ListV2Frame {
    dir:   String, // key prefix for this directory frame ("" or ends with "/")
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
    let tok: ListV2Token =
        serde_json::from_slice(&raw).map_err(|e| anyhow!("bad continuation-token json: {e}"))?;
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
    name:     String,
    sort_key: String, // name or name + "/"
    is_dir:   bool,
    path:     PathBuf,
}

struct RuntimeFrame {
    dir_key: String,               // key prefix for this directory ("" or ends_with "/")
    after:   String,               // cursor sort_key
    entries: Option<Vec<DirItem>>, // None = not loaded yet, Some = loaded (possibly empty)
    idx:     usize,
}

fn read_dir_sorted(dir_fs: &Path) -> Result<Vec<DirItem>> {
    let mut out = Vec::new();
    let rd = match fs::read_dir(dir_fs) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(anyhow!("permission denied"));
        }
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

        // For symlinks, follow to determine whether the target is a directory
        // so they list as folders (CommonPrefixes / trailing-slash key) rather
        // than as plain files. Broken/unreachable links fall back to file so
        // they still appear in the listing — `aws s3 rm --recursive` (and
        // similar) need to see them to issue a DELETE. Mirrors the
        // follow-then-fall-back pattern used by statx_info().
        let is_dir = if ft.is_symlink() {
            fs::metadata(ent.path()).map(|m| m.is_dir()).unwrap_or(false)
        } else {
            ft.is_dir()
        };
        let sort_key = if is_dir { format!("{name}/") } else { name.clone() };
        out.push(DirItem { name, sort_key, is_dir, path: ent.path() });
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

/// Load directory entries for a frame if not already loaded
fn ensure_frame_loaded(
    frame: &mut RuntimeFrame,
    cfg: &Cfg,
    bucket: &str,
    leaf_filter: Option<&str>,
    is_root: bool,
) -> Result<()> {
    if frame.entries.is_some() {
        return Ok(()); // Already loaded
    }

    let dir_fs = match join_object_path(&cfg.posix_root, bucket, &frame.dir_key) {
        Ok(p) => p,
        Err(e) => return Err(anyhow!("failed to compute dir path: {e}")),
    };

    let mut entries = read_dir_sorted(&dir_fs)?;

    // Apply leaf_filter only at root frame (the directory where prefix "starts").
    if is_root {
        if let Some(lf) = leaf_filter {
            entries.retain(|it| it.sort_key.starts_with(lf));
        }
    }

    // Find starting index
    frame.idx = first_index_after(&entries, &frame.after);
    frame.entries = Some(entries);

    Ok(())
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

fn owner_info(uid: u32) -> s32p_support::s3xml::ListOwnerInfo {
    let id = uid.to_string();
    let display_name = lookup_username(uid).unwrap_or_else(|| id.clone());
    s32p_support::s3xml::ListOwnerInfo { id, display_name }
}

async fn handle_list_objects_v2(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    let bucket = class.bucket.as_deref().unwrap_or("");
    if bucket.is_empty() {
        return s32p_support::s3resp::not_implemented("missing bucket", Some(req.uri().path()));
    }

    // list-type=2 is already checked by classifier, keep defensive.
    if class.query.first("list-type") != Some("2") {
        return s32p_support::s3resp::not_implemented("missing list-type=2", None);
    }

    // If bucket doesn't exist, return NoSuchBucket (S3 semantics).
    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => {}
        Ok(false) => {
            return s32p_support::s3resp::no_such_bucket(
                "bucket not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
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
            return s32p_support::s3resp::not_implemented("only delimiter=/ is supported", None);
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

    // EncodingType=url support: when requested, percent-encode all key/prefix
    // strings in the response (Key, CommonPrefixes/Prefix, echoed Prefix,
    // Delimiter, StartAfter) per AWS S3 conventions.
    let url_encode = matches!(class.query.first("encoding-type"), Some("url"));
    let enc = |s: &str| -> String {
        if url_encode { s32p_support::uri_encoding::s3_url_encode(s) } else { s.to_string() }
    };
    let encoding_type_resp = if url_encode { Some("url") } else { None };

    // check the prefix, we don't list multipart upload dirs
    if !prefix.is_empty() && is_reserved_first_segment(&prefix, cfg.mpu_dir_name.as_str()) {
        // behave as if it doesn't exist
        let prefix_enc = enc(&prefix);
        let start_after_enc = start_after.as_deref().map(enc);
        return s32p_support::s3resp::list_objects_v2(
            bucket,
            Some(&prefix_enc),
            if recursive { None } else { Some("/") },
            0,
            max_keys,
            false,
            continuation_token_in.as_deref(),
            None,
            start_after_enc.as_deref(),
            encoding_type_resp,
            &[],
            &[],
        );
    }

    let (dir_prefix, leaf_filter) = split_prefix(&prefix);

    // Filesystem start dir is bucket + dir_prefix
    let start_dir_fs = match join_object_path(&cfg.posix_root, bucket, &dir_prefix) {
        Ok(p) => p,
        Err(e) => return s32p_support::s3resp::access_denied(&e.to_string(), None),
    };

    // If the *prefix directory* doesn't exist (but bucket exists), return an empty listing.
    if !start_dir_fs.exists() || !start_dir_fs.is_dir() {
        let prefix_enc = enc(&prefix);
        let start_after_enc = start_after.as_deref().map(enc);
        return s32p_support::s3resp::list_objects_v2(
            bucket,
            Some(&prefix_enc),
            if recursive { None } else { Some("/") },
            0,
            max_keys,
            false,
            continuation_token_in.as_deref(),
            None,
            start_after_enc.as_deref(),
            encoding_type_resp,
            &[],
            &[],
        );
    }

    // Build initial stack (from ContinuationToken or StartAfter)
    let mut token_stack: Vec<ListV2Frame> = if let Some(ct) = &continuation_token_in {
        match decode_token(ct) {
            Ok(tok) => {
                // Validate token belongs to the same listing shape
                if tok.bucket != bucket
                    || tok.prefix != prefix
                    || tok.delimiter.as_deref() != delimiter_q
                {
                    let mut parts = Vec::new();
                    if tok.bucket != bucket {
                        parts.push(format!(
                            "request-bucket {bucket} != token-bucket {}",
                            tok.bucket
                        ));
                    }
                    if tok.prefix != prefix {
                        parts.push(format!(
                            "request-prefix {prefix} != token-prefix {}",
                            tok.prefix
                        ));
                    }
                    if tok.delimiter.as_deref() != delimiter_q {
                        parts.push(format!(
                            "request-delimiter {:?} != token-delimiter {:?}",
                            delimiter_q,
                            tok.delimiter.as_deref()
                        ));
                    }

                    return s32p_support::s3resp::s3_error(
                        StatusCode::BAD_REQUEST,
                        s32p_support::s3xml::error_code::INVALID_REQUEST,
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
                return s32p_support::s3resp::s3_error(
                    StatusCode::BAD_REQUEST,
                    s32p_support::s3xml::error_code::INVALID_REQUEST,
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

    // Reject continuation tokens that descend into the reserved dir
    if token_stack
        .iter()
        .any(|fr| is_reserved_first_segment(&fr.dir, &cfg.mpu_dir_name))
    {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_REQUEST,
            "continuation-token points into a reserved prefix",
            Some(req.uri().path()),
            None,
        );
    }

    if token_stack.is_empty() {
        token_stack.push(ListV2Frame { dir: dir_prefix.clone(), after: "".to_string() });
    }

    // Build runtime frames from token stack
    let mut stack: Vec<RuntimeFrame> = Vec::new();
    for fr in token_stack {
        stack.push(RuntimeFrame {
            dir_key: fr.dir.clone(),
            after:   fr.after.clone(),
            entries: None, // Will be loaded lazily
            idx:     0,
        });
    }

    let mut contents: Vec<s32p_support::s3xml::ListObjectInfo> = Vec::new();
    let mut common_prefixes: Vec<String> = Vec::new();

    // Produce up to max_keys “results”; in delimiter mode keycount includes common prefixes
    while (contents.len() as u32 + common_prefixes.len() as u32) < max_keys {
        let stack_len = stack.len();
        let Some(top) = stack.last_mut() else {
            break;
        };

        // Lazy load entries if not already loaded
        if top.entries.is_none() {
            let is_root_frame = stack_len == 1;
            if let Err(e) =
                ensure_frame_loaded(top, &cfg, bucket, leaf_filter.as_deref(), is_root_frame)
            {
                tracing::warn!("Failed to load directory {}: {}", top.dir_key, e);
                stack.pop();
                continue;
            }
        }

        let entries = top.entries.as_ref().unwrap(); // Safe because we just ensured it's loaded

        if top.idx >= entries.len() {
            stack.pop();
            continue;
        }

        let it = entries[top.idx].clone();
        top.idx += 1;
        top.after = it.sort_key.clone();

        // Hide the internal MPU directory at bucket root (and never descend into it)
        if top.dir_key.is_empty() && it.is_dir && it.name == cfg.mpu_dir_name {
            continue;
        }

        if it.is_dir {
            if !recursive {
                // delimiter=/ mode: emit CommonPrefix, don't descend
                let cp = format!("{}{}{}", top.dir_key, it.name, "/");
                common_prefixes.push(cp);
                continue;
            }

            // Recursive mode: surface leaf-empty directories as 0-byte
            // directory-marker objects (key ends in '/'). Without this, a
            // recursive ListObjects walk descends into an empty dir and
            // produces no Contents, so clients that delete-by-listing
            // (iOS S3 apps, mc rm --recursive, aws s3 rm --recursive) can't
            // reach the dir to remove it. We only mark *leaf-empty* dirs;
            // for non-empty parents, prune_empty_parents collapses the
            // chain after the leaf marker is deleted.
            let dir_is_empty = std::fs::read_dir(&it.path)
                .map(|mut rd| rd.next().is_none())
                .unwrap_or(false);

            if dir_is_empty {
                if let Some(stx) = statx_info(&it.path) {
                    let key = format!("{}{}{}", top.dir_key, it.name, "/");
                    if key.starts_with(&prefix) {
                        contents.push(s32p_support::s3xml::ListObjectInfo {
                            key,
                            last_modified: s32p_support::s3xml::format_s3_time_system(stx.mtime),
                            etag: format!("\"{}\"", stx.ino),
                            size: 0,
                            owner: if fetch_owner { Some(owner_info(stx.uid)) } else { None },
                        });
                    }
                }
                continue;
            }

            // recursive: descend
            let child_key = format!("{}{}{}", top.dir_key, it.name, "/");
            stack.push(RuntimeFrame {
                dir_key: child_key,
                after:   "".to_string(),
                entries: None, // Will be loaded lazily
                idx:     0,
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

        let last_modified = s32p_support::s3xml::format_s3_time_system(stx.mtime);
        let etag = format!("\"{}\"", stx.ino);
        let size = stx.size;

        let owner = if fetch_owner { Some(owner_info(stx.uid)) } else { None };

        contents.push(s32p_support::s3xml::ListObjectInfo {
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
            v:         1,
            bucket:    bucket.to_string(),
            prefix:    prefix.clone(),
            delimiter: if recursive { None } else { Some("/".to_string()) },
            stack:     stack
                .iter()
                .map(|rf| ListV2Frame { dir: rf.dir_key.clone(), after: rf.after.clone() })
                .collect(),
        };
        encode_token(&tok).ok()
    } else {
        None
    };

    // Apply EncodingType=url to the response (echoed prefix/start-after, Contents.Key,
    // CommonPrefixes/Prefix). Continuation tokens are already URL-safe (base64url),
    // and `Delimiter` is always `/` here so it round-trips fine either way — we still
    // pass the raw `/` because `s3_url_encode("/")` would yield `%2F` which AWS's own
    // responses also produce when EncodingType=url, but matching v1 behavior we keep
    // the delimiter unencoded for compatibility with naive clients.
    let prefix_enc = enc(&prefix);
    let start_after_enc = start_after.as_deref().map(enc);
    let contents_enc: Vec<s32p_support::s3xml::ListObjectInfo> = if url_encode {
        contents
            .iter()
            .map(|c| s32p_support::s3xml::ListObjectInfo {
                key:           enc(&c.key),
                last_modified: c.last_modified.clone(),
                etag:          c.etag.clone(),
                size:          c.size,
                owner:         c.owner.clone(),
            })
            .collect()
    } else {
        contents
    };
    let common_prefixes_enc: Vec<String> =
        if url_encode { common_prefixes.iter().map(|p| enc(p)).collect() } else { common_prefixes };

    s32p_support::s3resp::list_objects_v2(
        bucket,
        Some(&prefix_enc),
        if recursive { None } else { Some("/") },
        key_count,
        max_keys,
        is_truncated && next_token.is_some(),
        continuation_token_in.as_deref(),
        next_token.as_deref(),
        start_after_enc.as_deref(),
        encoding_type_resp,
        &contents_enc,
        &common_prefixes_enc,
    )
}

// -------------------------
// ListObjectsV1
// -------------------------
//
// Reuses the v2 directory walk (RuntimeFrame stack, ensure_frame_loaded, split_prefix,
// build_stack_from_last) and only differs in:
//   - pagination uses `marker` (a key) instead of an opaque `continuation-token`
//   - on truncation we emit `NextMarker` (the last emitted key/common-prefix);
//     no continuation token machinery
//   - the response shape: see `s3resp::list_objects_v1`

async fn handle_list_objects_v1(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    let bucket = class.bucket.as_deref().unwrap_or("");
    if bucket.is_empty() {
        return s32p_support::s3resp::not_implemented("missing bucket", Some(req.uri().path()));
    }

    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => {}
        Ok(false) => {
            return s32p_support::s3resp::no_such_bucket(
                "bucket not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    }

    let prefix = class.query.first("prefix").unwrap_or("").to_string();
    let marker = class.query.first("marker").unwrap_or("").to_string();

    let delimiter_q = class
        .query
        .first("delimiter")
        .and_then(|d| if d.is_empty() { None } else { Some(d) });

    let recursive = match delimiter_q {
        None => true,
        Some("/") => false,
        Some(_) => {
            return s32p_support::s3resp::not_implemented("only delimiter=/ is supported", None);
        }
    };

    let max_keys = class
        .query
        .first("max-keys")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(1000)
        .min(1000);

    let url_encode = matches!(class.query.first("encoding-type"), Some("url"));
    let enc = |s: &str| -> String {
        if url_encode { s32p_support::uri_encoding::s3_url_encode(s) } else { s.to_string() }
    };
    let encoding_type_resp = if url_encode { Some("url") } else { None };

    if !prefix.is_empty() && is_reserved_first_segment(&prefix, cfg.mpu_dir_name.as_str()) {
        return s32p_support::s3resp::list_objects_v1(
            bucket,
            &enc(&prefix),
            if recursive { None } else { Some("/") },
            &enc(&marker),
            None,
            max_keys,
            false,
            encoding_type_resp,
            &[],
            &[],
        );
    }

    let (dir_prefix, leaf_filter) = split_prefix(&prefix);

    let start_dir_fs = match join_object_path(&cfg.posix_root, bucket, &dir_prefix) {
        Ok(p) => p,
        Err(e) => return s32p_support::s3resp::access_denied(&e.to_string(), None),
    };

    if !start_dir_fs.exists() || !start_dir_fs.is_dir() {
        return s32p_support::s3resp::list_objects_v1(
            bucket,
            &enc(&prefix),
            if recursive { None } else { Some("/") },
            &enc(&marker),
            None,
            max_keys,
            false,
            encoding_type_resp,
            &[],
            &[],
        );
    }

    // Initial frame stack: marker positions us "after" a previously emitted key.
    let token_stack: Vec<ListV2Frame> = if !marker.is_empty() {
        build_stack_from_last(&dir_prefix, &marker, recursive)
    } else {
        vec![ListV2Frame { dir: dir_prefix.clone(), after: "".to_string() }]
    };

    if token_stack
        .iter()
        .any(|fr| is_reserved_first_segment(&fr.dir, &cfg.mpu_dir_name))
    {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_REQUEST,
            "marker points into a reserved prefix",
            Some(req.uri().path()),
            None,
        );
    }

    let mut stack: Vec<RuntimeFrame> = Vec::new();
    for fr in token_stack {
        stack.push(RuntimeFrame {
            dir_key: fr.dir.clone(),
            after:   fr.after.clone(),
            entries: None,
            idx:     0,
        });
    }

    let mut contents: Vec<s32p_support::s3xml::ListObjectInfo> = Vec::new();
    let mut common_prefixes: Vec<String> = Vec::new();
    // For NextMarker: the last *thing* emitted (key or common-prefix) wins.
    let mut last_emitted: Option<String> = None;

    while (contents.len() as u32 + common_prefixes.len() as u32) < max_keys {
        let stack_len = stack.len();
        let Some(top) = stack.last_mut() else {
            break;
        };

        if top.entries.is_none() {
            let is_root_frame = stack_len == 1;
            if let Err(e) =
                ensure_frame_loaded(top, &cfg, bucket, leaf_filter.as_deref(), is_root_frame)
            {
                tracing::warn!("Failed to load directory {}: {}", top.dir_key, e);
                stack.pop();
                continue;
            }
        }

        let entries = top.entries.as_ref().unwrap();

        if top.idx >= entries.len() {
            stack.pop();
            continue;
        }

        let it = entries[top.idx].clone();
        top.idx += 1;
        top.after = it.sort_key.clone();

        if top.dir_key.is_empty() && it.is_dir && it.name == cfg.mpu_dir_name {
            continue;
        }

        if it.is_dir {
            if !recursive {
                let cp = format!("{}{}{}", top.dir_key, it.name, "/");
                last_emitted = Some(cp.clone());
                common_prefixes.push(cp);
                continue;
            }

            // Surface leaf-empty directories as 0-byte directory markers in
            // recursive listings — see the matching v2 handler for rationale.
            let dir_is_empty = std::fs::read_dir(&it.path)
                .map(|mut rd| rd.next().is_none())
                .unwrap_or(false);

            if dir_is_empty {
                if let Some(stx) = statx_info(&it.path) {
                    let key = format!("{}{}{}", top.dir_key, it.name, "/");
                    if key.starts_with(&prefix) {
                        last_emitted = Some(key.clone());
                        contents.push(s32p_support::s3xml::ListObjectInfo {
                            key,
                            last_modified: s32p_support::s3xml::format_s3_time_system(stx.mtime),
                            etag: format!("\"{}\"", stx.ino),
                            size: 0,
                            owner: Some(owner_info(stx.uid)),
                        });
                    }
                }
                continue;
            }

            let child_key = format!("{}{}{}", top.dir_key, it.name, "/");
            stack.push(RuntimeFrame {
                dir_key: child_key,
                after:   "".to_string(),
                entries: None,
                idx:     0,
            });
            continue;
        }

        let stx = match statx_info(&it.path) {
            Some(s) => s,
            None => continue,
        };

        let key = format!("{}{}", top.dir_key, it.name);
        if !key.starts_with(&prefix) {
            continue;
        }

        let last_modified = s32p_support::s3xml::format_s3_time_system(stx.mtime);
        let etag = format!("\"{}\"", stx.ino);
        let size = stx.size;

        // v1 always carries Owner in Contents.
        let owner = Some(owner_info(stx.uid));

        last_emitted = Some(key.clone());
        contents.push(s32p_support::s3xml::ListObjectInfo {
            key,
            last_modified,
            etag,
            size,
            owner,
        });
    }

    let total = (contents.len() + common_prefixes.len()) as u32;
    let is_truncated = total >= max_keys && !stack.is_empty();

    // S3 v1: NextMarker is REQUIRED in the response only when delimiter is set; otherwise
    // it's optional and clients fall back to using the last key in Contents as the next
    // marker. We always emit it on truncation for consistency.
    let next_marker = if is_truncated { last_emitted } else { None };

    let prefix_enc = enc(&prefix);
    let marker_enc = enc(&marker);
    let next_marker_enc = next_marker.as_deref().map(enc);
    let contents_enc: Vec<s32p_support::s3xml::ListObjectInfo> = if url_encode {
        contents
            .iter()
            .map(|c| s32p_support::s3xml::ListObjectInfo {
                key:           enc(&c.key),
                last_modified: c.last_modified.clone(),
                etag:          c.etag.clone(),
                size:          c.size,
                owner:         c.owner.clone(),
            })
            .collect()
    } else {
        contents
    };
    let common_prefixes_enc: Vec<String> =
        if url_encode { common_prefixes.iter().map(|p| enc(p)).collect() } else { common_prefixes };

    s32p_support::s3resp::list_objects_v1(
        bucket,
        &prefix_enc,
        if recursive { None } else { Some("/") },
        &marker_enc,
        next_marker_enc.as_deref(),
        max_keys,
        is_truncated,
        encoding_type_resp,
        &contents_enc,
        &common_prefixes_enc,
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
    v.parse::<u64>().map_err(|_| anyhow!("invalid integer in header {name}: {v}"))
}

fn parse_copy_source(headers: &HeaderMap) -> Result<(String, String)> {
    let raw = headers
        .get("x-amz-copy-source")
        .ok_or_else(|| anyhow!("missing x-amz-copy-source"))?
        .to_str()
        .map_err(|_| anyhow!("invalid x-amz-copy-source"))?
        .trim();

    // Strip any version/query component (we don't support versioned copies yet).
    let raw = raw.split_once('?').map(|(p, _)| p).unwrap_or(raw);
    let raw = raw.trim_start_matches('/');
    if raw.is_empty() {
        return Err(anyhow!("invalid x-amz-copy-source"));
    }

    let decoded = s32p_support::uri_encoding::percent_decode_path_segments_lossy(raw);
    let mut it = decoded.splitn(2, '/');
    let bucket = it.next().unwrap_or("").to_string();
    let key = it.next().unwrap_or("").to_string();
    if bucket.is_empty() || key.is_empty() {
        return Err(anyhow!("invalid x-amz-copy-source (expected /bucket/key)"));
    }
    Ok((bucket, key))
}

/// Returns (is_streaming_sigv4, logical_len)
fn compute_logical_len(headers: &HeaderMap) -> Result<(bool, u64)> {
    let is_streaming =
        header_eq(headers, "x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD");

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
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    // Allow SigV4 presign query params; reject only effective (non-presign) query params.
    if has_effective_query(&req) {
        return s32p_support::s3resp::not_implemented("query parameters are not implemented", None);
    }

    let bucket = class.bucket.as_deref().unwrap_or("");
    let key = class.key.as_deref().unwrap_or("");

    // don't allow to write into the multipart upload directory
    if is_reserved_first_segment(key, &cfg.mpu_dir_name) {
        return s32p_support::s3resp::access_denied("reserved key prefix", Some(req.uri().path()));
    }

    if bucket.is_empty() || key.is_empty() {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_REQUEST,
            "missing bucket or key",
            Some(req.uri().path()),
            None,
        );
    }

    // S3 semantics: if bucket doesn't exist => NoSuchBucket
    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => {}
        Ok(false) => {
            return s32p_support::s3resp::no_such_bucket(
                "bucket not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    }

    let obj_path = match join_object_path(&cfg.posix_root, bucket, key) {
        Ok(p) => p,
        Err(e) => return s32p_support::s3resp::access_denied(&e.to_string(), None),
    };

    // Directory-marker PUT: a key ending in '/' addresses a filesystem
    // directory (the same shape that listing emits for empty leaves and
    // that handle_delete_object rmdir-s). We mkdir_p and return success,
    // skipping the conditional-header / streaming machinery — clients
    // don't send If-Match on dir markers, and the precondition path below
    // assumes a regular file (etag-from-inode, etc.).
    if key.ends_with('/') {
        // Markers are 0-byte by S3 convention. Require an explicit
        // Content-Length: 0 and reject anything else rather than silently
        // dropping a body the client thought we'd store.
        let claimed_len = req
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());
        match claimed_len {
            Some(0) => {}
            Some(_) => {
                return s32p_support::s3resp::invalid_request(
                    "directory-marker PUT must have zero length",
                    Some(req.uri().path()),
                );
            }
            None => {
                return s32p_support::s3resp::s3_error(
                    StatusCode::BAD_REQUEST,
                    s32p_support::s3xml::error_code::INVALID_REQUEST,
                    "missing Content-Length",
                    Some(req.uri().path()),
                    None,
                );
            }
        }

        if let Err(e) = std::fs::create_dir_all(&obj_path) {
            tracing::warn!(
                "directory-marker PUT create_dir_all {} failed: {e}",
                obj_path.display()
            );
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                return s32p_support::s3resp::access_denied(
                    "permission denied",
                    Some(req.uri().path()),
                );
            }
            return s32p_support::s3resp::internal_error(
                "failed to create directory marker",
                Some(req.uri().path()),
                None,
            );
        }

        let meta = match std::fs::metadata(&obj_path) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(
                    "directory-marker PUT stat after create failed for {}: {e}",
                    obj_path.display()
                );
                return s32p_support::s3resp::internal_error(
                    "failed to stat directory marker",
                    Some(req.uri().path()),
                    None,
                );
            }
        };
        let etag = format!("\"{}\"", meta.ino());
        return s32p_support::s3resp::put_object_ok(&etag);
    }

    // pick decoded length for streaming payloads
    let (is_streaming_sigv4, logical_len) = match compute_logical_len(req.headers()) {
        Ok(v) => v,
        Err(e) => {
            return s32p_support::s3resp::s3_error(
                StatusCode::BAD_REQUEST,
                s32p_support::s3xml::error_code::INVALID_REQUEST,
                &e.to_string(),
                Some(req.uri().path()),
                None,
            );
        }
    };

    // check preconditions
    let cond = match parse_conditional_headers(req.headers()) {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("invalid conditional headers: {e}");
            return s32p_support::s3resp::invalid_request(&msg, Some(req.uri().path()));
        }
    };

    // Determine existing object state (etag + last_modified) if present
    let existing = match fs::metadata(&obj_path) {
        Ok(m) => {
            // reuse your existing etag computation logic; if it's inode-based, compute it here too.
            let etag_existing = format!("{}", m.ino()); // adapt to your actual etag logic
            let lm = m.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            Some((etag_existing, lm))
        }
        Err(_) => None,
    };

    let existing_ref = existing.as_ref().map(|(e, lm)| (e.as_str(), *lm));
    match evaluate_write_preconditions(&cond, existing_ref) {
        PreconditionOutcome::Proceed => {}
        PreconditionOutcome::NotModified => {} // not used for PUT
        PreconditionOutcome::PreconditionFailed => {
            tracing::debug!(
                "Write preconditions failed (412) for PUT operation on {}",
                obj_path.display()
            );
            return s32p_support::s3resp::precondition_failed(
                "PUT precondition failed",
                Some(req.uri().path()),
            );
        }
    }

    // Still require Content-Length at HTTP layer
    if req.headers().get(http::header::CONTENT_LENGTH).is_none() {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_REQUEST,
            "missing Content-Length",
            Some(req.uri().path()),
            None,
        );
    }

    let (parts, body) = req.into_parts();

    #[cfg(feature = "lustre")]
    let striping = Some(LustreStriping::new(
        cfg.chunk_size as u64,
        stripe_count_for_size(logical_len, cfg.chunk_size as u64, cfg.lustre_max_stripe_count),
    ));
    #[cfg(not(feature = "lustre"))]
    let striping: Option<LustreStriping> = None;

    // Stream-write
    if let Err(e) = write_object_body(
        body,
        WriteObjectDest::Path { path: obj_path.clone(), striping },
        logical_len,
        is_streaming_sigv4,
        StreamCfg {
            chunk_size: cfg.chunk_size,
            inflight:   cfg.inflight,
            direct_io:  cfg.direct_io,
        },
        app.uring.clone(),
        app.pool.clone(),
    )
    .await
    {
        return s32p_support::s3resp::internal_error(&e.to_string(), Some(parts.uri.path()), None);
    }

    // Build ETag (consistent with reads: inode-based ETag)
    let meta = match std::fs::metadata(&obj_path) {
        Ok(m) => m,
        Err(e) => {
            return s32p_support::s3resp::internal_error(
                &e.to_string(),
                Some(parts.uri.path()),
                None,
            );
        }
    };

    let etag = format!("\"{}\"", meta.ino());
    s32p_support::s3resp::put_object_ok(&etag)
}

async fn handle_copy_object(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    // Allow SigV4 presign query params; reject only effective (non-presign) query params.
    if has_effective_query(&req) {
        return s32p_support::s3resp::not_implemented("query parameters are not implemented", None);
    }

    let dst_bucket = class.bucket.as_deref().unwrap_or("");
    let dst_key = class.key.as_deref().unwrap_or("");
    if dst_bucket.is_empty() || dst_key.is_empty() {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_REQUEST,
            "missing bucket or key",
            Some(req.uri().path()),
            None,
        );
    }

    // destination bucket must exist
    match bucket_exists_dir(&cfg.posix_root, dst_bucket) {
        Ok(true) => {}
        Ok(false) => {
            return s32p_support::s3resp::no_such_bucket(
                "bucket not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    }

    let (src_bucket, src_key) = match parse_copy_source(req.headers()) {
        Ok(v) => v,
        Err(e) => {
            return s32p_support::s3resp::s3_error(
                StatusCode::BAD_REQUEST,
                s32p_support::s3xml::error_code::INVALID_REQUEST,
                &e.to_string(),
                Some(req.uri().path()),
                None,
            );
        }
    };

    // source and destination must not contain the multipart upload directory
    if is_reserved_first_segment(dst_key, &cfg.mpu_dir_name)
        || is_reserved_first_segment(&src_key, &cfg.mpu_dir_name)
    {
        return s32p_support::s3resp::access_denied("reserved key prefix", Some(req.uri().path()));
    }

    // source bucket must exist
    match bucket_exists_dir(&cfg.posix_root, &src_bucket) {
        Ok(true) => {}
        Ok(false) => {
            return s32p_support::s3resp::no_such_bucket(
                "bucket not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    }

    let src_path = match join_object_path(&cfg.posix_root, &src_bucket, &src_key) {
        Ok(p) => p,
        Err(e) => return s32p_support::s3resp::access_denied(&e.to_string(), None),
    };

    let dst_path = match join_object_path(&cfg.posix_root, dst_bucket, dst_key) {
        Ok(p) => p,
        Err(e) => return s32p_support::s3resp::access_denied(&e.to_string(), None),
    };

    let src_meta = match std::fs::metadata(&src_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return s32p_support::s3resp::no_such_key("not found", None);
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return s32p_support::s3resp::access_denied("permission denied", None);
        }
        Err(e) => {
            return s32p_support::s3resp::internal_error(
                &e.to_string(),
                Some(req.uri().path()),
                None,
            );
        }
    };

    if src_meta.is_dir() {
        // Directory-marker copy: only valid when both source and destination
        // are directory-style keys (ending with '/'). The iOS Files / S3
        // app uses this to "rename" a folder marker. We skip the conditional
        // / streaming machinery for the same reason DELETE does on markers.
        if src_key.ends_with('/') && dst_key.ends_with('/') {
            if let Err(e) = std::fs::create_dir_all(&dst_path) {
                tracing::warn!(
                    "CopyObject directory-marker create_dir_all {} failed: {e}",
                    dst_path.display()
                );
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    return s32p_support::s3resp::access_denied(
                        "permission denied",
                        Some(req.uri().path()),
                    );
                }
                return s32p_support::s3resp::internal_error(
                    "failed to create directory marker",
                    Some(req.uri().path()),
                    None,
                );
            }
            let dst_meta = match std::fs::metadata(&dst_path) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(
                        "CopyObject directory-marker stat after create failed for {}: {e}",
                        dst_path.display()
                    );
                    return s32p_support::s3resp::internal_error(
                        "failed to stat directory marker",
                        Some(req.uri().path()),
                        None,
                    );
                }
            };
            let etag = format!("\"{}\"", dst_meta.ino());
            let last_modified = s32p_support::s3xml::format_s3_time_system(
                dst_meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            );
            return s32p_support::s3resp::copy_object_ok(&etag, &last_modified);
        }
        return s32p_support::s3resp::no_such_key("not found", None);
    }

    // check preconditions for copy source
    let cond = match parse_conditional_headers(req.headers()) {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("invalid conditional headers: {e}");
            return s32p_support::s3resp::invalid_request(&msg, Some(req.uri().path()));
        }
    };

    // Source preconditions
    let src_etag_unquoted = format!("{}", src_meta.ino()); // adapt to your etag logic
    let src_last_modified = src_meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
    match evaluate_copy_source_preconditions(&cond, &src_etag_unquoted, src_last_modified) {
        PreconditionOutcome::Proceed => {}
        _ => {
            tracing::debug!(
                "Copy source preconditions failed (412) for source {}",
                src_path.display()
            );
            return s32p_support::s3resp::precondition_failed(
                "Copy source precondition failed",
                Some(req.uri().path()),
            );
        }
    }

    // Destination preconditions - check if destination already exists and evaluate write conditions
    let dst_exists = match std::fs::metadata(&dst_path) {
        Ok(m) => {
            if m.is_dir() {
                None // treat directories as non-existent for object operations
            } else {
                let etag_existing = format!("{}", m.ino());
                let lm = m.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                Some((etag_existing, lm))
            }
        }
        Err(_) => None,
    };

    let dst_exists_ref = dst_exists.as_ref().map(|(e, lm)| (e.as_str(), *lm));
    match evaluate_write_preconditions(&cond, dst_exists_ref) {
        PreconditionOutcome::Proceed => {}
        PreconditionOutcome::NotModified => {} // not used for copy
        PreconditionOutcome::PreconditionFailed => {
            tracing::debug!(
                "Copy destination preconditions failed (412) for destination {}",
                dst_path.display()
            );
            return s32p_support::s3resp::precondition_failed(
                "Copy destination precondition failed",
                Some(req.uri().path()),
            );
        }
    }

    let size = src_meta.len();

    #[cfg(feature = "lustre")]
    let dst_striping = Some(LustreStriping::new(
        cfg.chunk_size as u64,
        stripe_count_for_size(size, cfg.chunk_size as u64, cfg.lustre_max_stripe_count),
    ));
    #[cfg(not(feature = "lustre"))]
    let dst_striping: Option<LustreStriping> = None;

    if size > cfg.copy_max_size {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::ENTITY_TOO_LARGE,
            &format!(
                "CopyObject size {} exceeds configured single-copy limit {} bytes",
                size, cfg.copy_max_size
            ),
            Some(req.uri().path()),
            None,
        );
    }

    if let Err(e) = copy_file_to_file(
        src_path,
        dst_path.clone(),
        size,
        dst_striping,
        StreamCfg {
            chunk_size: cfg.chunk_size,
            inflight:   cfg.inflight,
            direct_io:  cfg.direct_io,
        },
        app.uring.clone(),
        app.pool.clone(),
    )
    .await
    {
        return s32p_support::s3resp::internal_error(&e.to_string(), Some(req.uri().path()), None);
    }

    let dst_meta = match std::fs::metadata(&dst_path) {
        Ok(m) => m,
        Err(e) => {
            return s32p_support::s3resp::internal_error(
                &e.to_string(),
                Some(req.uri().path()),
                None,
            );
        }
    };

    let etag = format!("\"{}\"", dst_meta.ino());
    let last_modified = s32p_support::s3xml::format_s3_time_system(
        dst_meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
    );

    s32p_support::s3resp::copy_object_ok(&etag, &last_modified)
}

// -------------------------
// RenameObject
// -------------------------

fn parse_rename_source(dst_bucket: &str, headers: &HeaderMap) -> Result<(String, String)> {
    let raw = headers
        .get("x-amz-rename-source")
        .ok_or_else(|| anyhow!("missing x-amz-rename-source"))?
        .to_str()
        .map_err(|_| anyhow!("invalid x-amz-rename-source"))?
        .trim();

    // Strip any query component.
    let raw = raw.split_once('?').map(|(p, _)| p).unwrap_or(raw);
    let raw = raw.trim_start_matches('/');
    if raw.is_empty() {
        return Err(anyhow!("invalid x-amz-rename-source"));
    }

    // Decode percent-escapes segment-by-segment (same behavior as CopyObject parsing).
    let decoded: String = s32p_support::uri_encoding::percent_decode_path_segments_lossy(raw);

    // Accept both:
    //  - "/key"           (same bucket as destination)
    //  - "/bucket/key"    (explicit bucket)
    let mut it = decoded.splitn(2, '/');
    let first: &str = it.next().unwrap_or("");
    let second: Option<&str> = it.next();

    if let Some(rest) = second {
        // "/bucket/key" form
        let bucket: String = first.to_string();
        let key: String = rest.to_string();
        if bucket.is_empty() || key.is_empty() {
            return Err(anyhow!("invalid x-amz-rename-source (expected /bucket/key or /key)"));
        }
        Ok((bucket, key))
    } else {
        // "/key" form
        let key: String = first.to_string();
        if key.is_empty() {
            return Err(anyhow!("invalid x-amz-rename-source (expected /bucket/key or /key)"));
        }
        Ok((dst_bucket.to_string(), key))
    }
}

async fn handle_rename_object(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    // Allow SigV4 presign query params; ignore everything except renameObject.
    if !(class.query.is_only_effective("renameobject")
        || (class.query.has("renameobject") && class.query.is_only_effective("x-id")))
    {
        return s32p_support::s3resp::not_implemented("query parameters are not implemented", None);
    }

    let dst_bucket = class.bucket.as_deref().unwrap_or("");
    let dst_key = class.key.as_deref().unwrap_or("");
    if dst_bucket.is_empty() || dst_key.is_empty() {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_REQUEST,
            "missing bucket or key",
            Some(req.uri().path()),
            None,
        );
    }

    // destination bucket must exist
    match bucket_exists_dir(&cfg.posix_root, dst_bucket) {
        Ok(true) => {}
        Ok(false) => {
            return s32p_support::s3resp::no_such_bucket(
                "bucket not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    }

    let (src_bucket, src_key) = match parse_rename_source(dst_bucket, req.headers()) {
        Ok(v) => v,
        Err(e) => {
            return s32p_support::s3resp::s3_error(
                StatusCode::BAD_REQUEST,
                s32p_support::s3xml::error_code::INVALID_REQUEST,
                &e.to_string(),
                Some(req.uri().path()),
                None,
            );
        }
    };

    // S3 RenameObject is within the same bucket; reject cross-bucket.
    if src_bucket != dst_bucket {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_REQUEST,
            "cross-bucket rename is not supported",
            Some(req.uri().path()),
            None,
        );
    }

    // Don't allow reserved multipart prefix in either source or destination.
    if is_reserved_first_segment(dst_key, &cfg.mpu_dir_name)
        || is_reserved_first_segment(&src_key, &cfg.mpu_dir_name)
    {
        return s32p_support::s3resp::access_denied("reserved key prefix", Some(req.uri().path()));
    }

    let src_path = match join_object_path(&cfg.posix_root, &src_bucket, &src_key) {
        Ok(p) => p,
        Err(e) => return s32p_support::s3resp::access_denied(&e.to_string(), None),
    };

    let dst_path = match join_object_path(&cfg.posix_root, dst_bucket, dst_key) {
        Ok(p) => p,
        Err(e) => return s32p_support::s3resp::access_denied(&e.to_string(), None),
    };

    // Ensure source exists (file or directory).
    match std::fs::metadata(&src_path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return s32p_support::s3resp::no_such_key("not found", None);
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return s32p_support::s3resp::access_denied("permission denied", None);
        }
        Err(e) => {
            return s32p_support::s3resp::internal_error(
                &e.to_string(),
                Some(req.uri().path()),
                None,
            );
        }
    };

    // Create destination parent directories.
    if let Some(parent) = dst_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return s32p_support::s3resp::access_denied(
                &format!("failed to create destination directories: {e}"),
                None,
            );
        }
    }

    match std::fs::rename(&src_path, &dst_path) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
            // Required by your spec: error on cross-device rename (EXDEV).
            return s32p_support::s3resp::s3_error(
                StatusCode::BAD_REQUEST,
                s32p_support::s3xml::error_code::INVALID_REQUEST,
                "cross-device rename is not supported",
                Some(req.uri().path()),
                None,
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return s32p_support::s3resp::no_such_key("not found", None);
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return s32p_support::s3resp::access_denied("permission denied", None);
        }
        Err(e) => {
            return s32p_support::s3resp::internal_error(
                &e.to_string(),
                Some(req.uri().path()),
                None,
            );
        }
    }

    // Best-effort cleanup of empty parent directories under the bucket root.
    if let Ok(bucket_root) = bucket_root_path(&cfg.posix_root, dst_bucket) {
        if let Some(src_parent) = src_path.parent() {
            prune_empty_parents(&bucket_root, src_parent.to_path_buf());
        }
    }

    // Success: 200 with empty body.
    s32p_support::s3resp::response_bytes(StatusCode::OK, "application/xml", Vec::new(), [])
}

// -------------------------
// DeleteObject / DeleteObjects
// -------------------------

fn prune_empty_parents(bucket_root: &Path, mut dir: PathBuf) {
    loop {
        if dir == *bucket_root {
            break;
        }

        match std::fs::remove_dir(&dir) {
            Ok(()) => {
                // removed successfully, keep walking upward
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => break,
            Err(_e) => {
                // NotEmpty / other -> stop pruning
                break;
            }
        }

        let Some(parent) = dir.parent() else {
            break;
        };
        dir = parent.to_path_buf();
    }
}

async fn handle_delete_object(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    // Allow SigV4 presign query params; reject only effective (non-presign) query params.
    if has_effective_query(&req) {
        return s32p_support::s3resp::not_implemented("query parameters are not implemented", None);
    }

    let bucket = class.bucket.as_deref().unwrap_or("");
    let key = class.key.as_deref().unwrap_or("");

    // don't delete file from multipart upload dir
    if is_reserved_first_segment(key, &cfg.mpu_dir_name) {
        return s32p_support::s3resp::access_denied("reserved key prefix", Some(req.uri().path()));
    }

    if bucket.is_empty() || key.is_empty() {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_REQUEST,
            "missing bucket or key",
            Some(req.uri().path()),
            None,
        );
    }

    // S3 semantics: if bucket doesn't exist => NoSuchBucket
    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => {}
        Ok(false) => {
            return s32p_support::s3resp::no_such_bucket(
                "bucket not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    }

    let obj_path = match join_object_path(&cfg.posix_root, bucket, key) {
        Ok(p) => p,
        Err(e) => return s32p_support::s3resp::access_denied(&e.to_string(), None),
    };

    // Directory-marker delete: a key ending in '/' addresses an (expected
    // leaf-empty) filesystem directory. We rmdir it and let prune_empty_parents
    // collapse the chain upward. We deliberately skip the conditional-header
    // machinery — clients don't send If-Match on dir markers, and the
    // precondition path below assumes a regular file (etag-from-inode, etc.).
    if key.ends_with('/') {
        match std::fs::remove_dir(&obj_path) {
            Ok(()) => {
                if let (Ok(bucket_root), Some(parent)) =
                    (bucket_root_path(&cfg.posix_root, bucket), obj_path.parent())
                {
                    prune_empty_parents(&bucket_root, parent.to_path_buf());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // S3 DELETE is idempotent: missing target is still success.
            }
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTEMPTY)) => {
                tracing::debug!(
                    "DELETE on directory marker {} rejected: directory not empty",
                    obj_path.display()
                );
                return s32p_support::s3resp::s3_error(
                    StatusCode::CONFLICT,
                    "BucketNotEmpty",
                    "directory not empty",
                    Some(req.uri().path()),
                    None,
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                return s32p_support::s3resp::access_denied(
                    "permission denied",
                    Some(req.uri().path()),
                );
            }
            Err(e) => {
                return s32p_support::s3resp::internal_error(
                    &e.to_string(),
                    Some(req.uri().path()),
                    None,
                );
            }
        }
        return s32p_support::s3resp::delete_object_no_content();
    }

    // check preconditions
    let cond = match parse_conditional_headers(req.headers()) {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("invalid conditional headers: {e}");
            return s32p_support::s3resp::invalid_request(&msg, Some(req.uri().path()));
        }
    };

    let existing = match fs::metadata(&obj_path) {
        Ok(m) => {
            let etag_existing = format!("{}", m.ino()); // adapt to your etag logic
            let lm = m.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            Some((etag_existing, lm, m.len()))
        }
        Err(_) => None,
    };

    if let Some((etag_existing, lm, size)) = existing.as_ref() {
        // Enforce If-Match / If-None-Match / If-(Un)Modified-Since like a “write”
        let existing_ref = Some((etag_existing.as_str(), *lm));
        if evaluate_write_preconditions(&cond, existing_ref)
            == PreconditionOutcome::PreconditionFailed
        {
            tracing::debug!(
                "Write preconditions failed (412) for DELETE operation on {}",
                obj_path.display()
            );
            return s32p_support::s3resp::precondition_failed(
                "DELETE precondition failed",
                Some(req.uri().path()),
            );
        }

        // Optional extra checks (x-amz-if-match-size / last-modified-time)
        if let Some(want_size) = cond.amz_if_match_size {
            if want_size != *size {
                tracing::debug!(
                    "DELETE x-amz-if-match-size mismatch for {} (want: {}, got: {})",
                    obj_path.display(),
                    want_size,
                    size
                );
                return s32p_support::s3resp::precondition_failed(
                    "x-amz-if-match-size mismatch",
                    Some(req.uri().path()),
                );
            }
        }
        if let Some(want_lm) = cond.amz_if_match_last_modified_time {
            if *lm != want_lm {
                tracing::debug!(
                    "DELETE x-amz-if-match-last-modified-time mismatch for {}",
                    obj_path.display()
                );
                return s32p_support::s3resp::precondition_failed(
                    "x-amz-if-match-last-modified-time mismatch",
                    Some(req.uri().path()),
                );
            }
        }
    } else {
        // If object missing and caller supplied If-Match => fail (common behavior)
        if cond.if_match.is_some() {
            tracing::debug!(
                "DELETE If-Match precondition failed - object does not exist: {}",
                obj_path.display()
            );
            return s32p_support::s3resp::precondition_failed(
                "DELETE If-Match but object does not exist",
                Some(req.uri().path()),
            );
        }
    }

    // DeleteObject is idempotent: NotFound is still success.
    match std::fs::remove_file(&obj_path) {
        Ok(()) => {
            // best-effort prune empty parent dirs under the bucket root
            if let (Ok(bucket_root), Some(parent)) =
                (bucket_root_path(&cfg.posix_root, bucket), obj_path.parent())
            {
                prune_empty_parents(&bucket_root, parent.to_path_buf());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // still success
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return s32p_support::s3resp::access_denied(
                "permission denied",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::internal_error(
                &e.to_string(),
                Some(req.uri().path()),
                None,
            );
        }
    }

    s32p_support::s3resp::delete_object_no_content()
}

async fn handle_delete_objects(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    // Must be ?delete (classifier already checked), keep defensive.
    if !class.query.has("delete") {
        return s32p_support::s3resp::not_implemented("missing ?delete", None);
    }

    let bucket = class.bucket.as_deref().unwrap_or("");
    if bucket.is_empty() {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_REQUEST,
            "missing bucket",
            Some(req.uri().path()),
            None,
        );
    }

    // S3 semantics: if bucket doesn't exist => NoSuchBucket
    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => {}
        Ok(false) => {
            return s32p_support::s3resp::no_such_bucket(
                "bucket not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    }

    let (parts, body) = req.into_parts();

    // Read entire XML body (DeleteObjects bodies are small; S3 limits to 1000 keys)
    let collected = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            return s32p_support::s3resp::s3_error(
                StatusCode::BAD_REQUEST,
                s32p_support::s3xml::error_code::INVALID_REQUEST,
                &format!("failed to read body: {e}"),
                Some(parts.uri.path()),
                None,
            );
        }
    };

    let (quiet, keys) = match s32p_support::s3xml::parse_delete_objects_request(&collected) {
        Ok(v) => v,
        Err(e) => {
            return s32p_support::s3resp::s3_error(
                StatusCode::BAD_REQUEST,
                s32p_support::s3xml::error_code::INVALID_REQUEST,
                &e.to_string(),
                Some(parts.uri.path()),
                None,
            );
        }
    };

    // S3 limit is 1000 objects per multi-delete request.
    if keys.len() > 1000 {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_REQUEST,
            "too many keys in DeleteObjects (max 1000)",
            Some(parts.uri.path()),
            None,
        );
    }

    let bucket_root = match bucket_root_path(&cfg.posix_root, bucket) {
        Ok(p) => p,
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(parts.uri.path()));
        }
    };

    let mut deleted: Vec<String> = Vec::new();
    let mut errors: Vec<s32p_support::s3xml::DeleteErrorInfo> = Vec::new();

    for key in keys {
        if key.is_empty() {
            errors.push(s32p_support::s3xml::DeleteErrorInfo {
                key,
                code: s32p_support::s3xml::error_code::INVALID_REQUEST.to_string(),
                message: "empty key".to_string(),
            });
            continue;
        }

        // do not delete file from multipart upload dir
        if is_reserved_first_segment(&key, &cfg.mpu_dir_name) {
            errors.push(s32p_support::s3xml::DeleteErrorInfo {
                key,
                code: s32p_support::s3xml::error_code::ACCESS_DENIED.to_string(),
                message: "reserved key prefix".to_string(),
            });
            continue;
        }

        let obj_path = match join_object_path(&cfg.posix_root, bucket, &key) {
            Ok(p) => p,
            Err(e) => {
                errors.push(s32p_support::s3xml::DeleteErrorInfo {
                    key,
                    code: s32p_support::s3xml::error_code::INVALID_REQUEST.to_string(),
                    message: e.to_string(),
                });
                continue;
            }
        };

        // Directory-marker delete: a key ending in '/' is rmdir-ed instead of
        // unlinked. Mirrors handle_delete_object's branch.
        let res = if key.ends_with('/') {
            std::fs::remove_dir(&obj_path)
        } else {
            std::fs::remove_file(&obj_path)
        };

        match res {
            Ok(()) => {
                if let Some(parent) = obj_path.parent() {
                    prune_empty_parents(&bucket_root, parent.to_path_buf());
                }
                if !quiet {
                    deleted.push(key);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // idempotent success
                if !quiet {
                    deleted.push(key);
                }
            }
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTEMPTY)) => {
                errors.push(s32p_support::s3xml::DeleteErrorInfo {
                    key,
                    code: "BucketNotEmpty".to_string(),
                    message: "directory not empty".to_string(),
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                errors.push(s32p_support::s3xml::DeleteErrorInfo {
                    key,
                    code: s32p_support::s3xml::error_code::ACCESS_DENIED.to_string(),
                    message: "permission denied".to_string(),
                });
            }
            Err(e) => {
                errors.push(s32p_support::s3xml::DeleteErrorInfo {
                    key,
                    code: s32p_support::s3xml::error_code::INTERNAL_ERROR.to_string(),
                    message: e.to_string(),
                });
            }
        }
    }

    s32p_support::s3resp::delete_objects_result(&deleted, &errors)
}

// ---- main ----

fn main() -> Result<()> {
    // Check for S32P_LOG_LEVEL first (from config), then RUST_LOG, then default to info
    let log_filter = std::env::var("S32P_LOG_LEVEL")
        .or_else(|_| std::env::var("RUST_LOG"))
        .unwrap_or_else(|_| "info".into());

    // Local-time formatter. Prefer the offset injected by the proxy via
    // S32P_LOG_UTC_OFFSET_SECS: when launched under landlock the gateway has
    // no access to /etc/localtime, so libc::localtime_r falls back to UTC.
    // For standalone runs (no env var) we still try libc.
    let offset = std::env::var("S32P_LOG_UTC_OFFSET_SECS")
        .ok()
        .and_then(|s| s.parse::<i32>().ok())
        .and_then(|s| time::UtcOffset::from_whole_seconds(s).ok())
        .unwrap_or_else(s32p_support::utils::local_utc_offset);
    let timer = tracing_subscriber::fmt::time::OffsetTime::new(
        offset,
        time::format_description::well_known::Rfc3339,
    );
    tracing_subscriber::fmt()
        .with_timer(timer)
        .with_env_filter(log_filter)
        .init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async_main())
}

async fn async_main() -> Result<()> {

    let cfg = Arc::new(load_cfg()?);

    let pool = Arc::new(BufPool::new(cfg.chunk_size, cfg.pool_size));
    pool.warm(cfg.pool_size);

    // Single global io_uring writer sized to the whole buffer pool.
    let uring = Arc::new(UringIO::spawn(cfg.pool_size.max(1))?);

    let app = Arc::new(App {
        cfg: cfg.clone(),
        pool,
        uring,
        virtual_hosted_suffixes: cfg.virtual_hosted_suffixes.clone(),
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
            "s32p-gateway listening on uds {} (chunk_size={} inflight={} pool_size={})",
            sock_path.display(),
            cfg.chunk_size,
            cfg.inflight,
            cfg.pool_size
        );

        loop {
            let (stream, _addr) = listener.accept().await?;
            let app2 = app.clone();
            let peer = PeerAddr::Unix;

            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc =
                    service_fn(move |req| handle(req, app2.clone(), Some(peer.clone())));
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
            "s32p-gateway listening on {} (chunk_size={} inflight={} pool_size={})",
            cfg.bind_addr,
            cfg.chunk_size,
            cfg.inflight,
            cfg.pool_size
        );

        loop {
            let (stream, peer_sa) = listener.accept().await?;
            stream.set_nodelay(true)?;
            let app2 = app.clone();
            let peer = PeerAddr::Tcp(peer_sa);

            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc =
                    service_fn(move |req| handle(req, app2.clone(), Some(peer.clone())));
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
