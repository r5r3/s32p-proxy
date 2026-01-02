use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

mod buffer;
mod streaming;

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use httpdate::fmt_http_date;
use hyper::body::Incoming;
use hyper::header::LAST_MODIFIED;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::fs::OpenOptions;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::net::{TcpListener, UnixListener};
use tokio_uring::buf::BoundedBuf;

use crate::buffer::{BufPool, PooledBuf, SliceOwner};
use crate::streaming::{parse_range_header, stream_range_body, ByteRange, StreamCfg};

use s3pm_support;

// Hyper response type we use everywhere in this binary.
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
    /// Size of the *process-wide* aligned buffer pool, in number of buffers.
    ///
    /// Memory impact is approximately: `pool_size * chunk_size` bytes (plus allocator overhead).
    /// Example: pool_size=128, chunk_size=1MiB => ~128MiB resident when warmed.
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

    let chunk_size = env_usize("S3PM_CHUNK_SIZE", 1024 * 1024);
    let inflight = env_usize("S3PM_INFLIGHT", 16).max(1);

    // Global buffer pool size (number of buffers).
    // Default: 8 * inflight (enough slack to absorb concurrent requests without reallocating).
    //
    // IMPORTANT: This pool is warmed at startup (buffers are allocated and zero-initialized once),
    // which improves latency by avoiding per-request buffer allocation / page-fault / memset work.
    // Pool buffers are returned on Drop (best-effort) and reused across requests.
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

// ---- path mapping ----

fn join_object_path(root: &Path, bucket: &str, key: &str) -> Result<PathBuf> {
    // avoid ".." traversal
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

// ---- request handler ----

struct App {
    cfg: Arc<Cfg>,
    pool: Arc<BufPool>,
}

async fn read_small(
    file: Arc<tokio_uring::fs::File>,
    pool: Arc<BufPool>,
    off: u64,
    len: usize,
) -> Result<Bytes> {
    let buf = pool.take().await;
    let pooled = PooledBuf::new(pool, buf);
    let slice = pooled.slice(..len);

    let (res, slice) = file.read_at(slice, off).await;
    let n = res.map_err(|e| anyhow!("read_at failed at off={off}: {e}"))?;
    if n == 0 {
        return Err(anyhow!("unexpected EOF"));
    }

    let mut bytes = Bytes::from_owner(SliceOwner(slice));
    bytes = bytes.slice(0..n);
    Ok(bytes)
}

async fn handle(req: Request<Incoming>, app: Arc<App>) -> Result<Resp, Infallible> {
    let cfg = app.cfg.clone();

    // Classify first (no body required).
    let class = s3pm_support::classifier::classify(req.method().as_str(), req.uri());

    // Reject query params (including presigned URLs), except GetBucketLocation (?location)
    let is_get_bucket_location = req.method() == http::Method::GET
        && req.uri().query().is_some_and(|q| {
            let mut parts = q.split('&').filter(|p| !p.is_empty());
            let first = parts.next().unwrap_or("");
            parts.next().is_none() && (first == "location" || first.starts_with("location="))
        });

    if req.uri().query().is_some() && !is_get_bucket_location {
        return Ok(s3pm_support::s3resp::not_implemented(
            "query parameters are not implemented",
            None,
        ));
    }

    // SigV4: parse + verify (every request)
    let auth = match s3pm_support::parse_authorization(req.headers()) {
        Ok(a) => a,
        Err(e) => {
            return Ok(s3pm_support::s3resp::access_denied(
                &format!("bad Authorization: {e}"),
                None,
            ))
        }
    };

    if auth.access_key != cfg.access_key {
        return Ok(s3pm_support::s3resp::access_denied("unknown access key", None));
    }

    if let Err(e) = s3pm_support::verify_sigv4_header_only(
        req.method().as_str(),
        req.uri(),
        req.headers(),
        &auth,
        &cfg.secret_key,
        &cfg.public_scheme,
    ) {
        return Ok(s3pm_support::s3resp::signature_does_not_match(
            &e.to_string(),
            None,
        ));
    }

    match &class.op {
        s3pm_support::classifier::S3Op::Read(s3pm_support::classifier::ReadOp::GetBucketLocation) => {
            return Ok(s3pm_support::s3resp::get_bucket_location(&cfg.region));
        }
        s3pm_support::classifier::S3Op::Read(s3pm_support::classifier::ReadOp::GetObject) => {}
        s3pm_support::classifier::S3Op::Multipart(_) => {
            return Ok(s3pm_support::s3resp::not_implemented(
                "multipart uploads are not implemented",
                None,
            ));
        }
        s3pm_support::classifier::S3Op::Versioning(_) => {
            return Ok(s3pm_support::s3resp::not_implemented(
                "versioning is not implemented",
                None,
            ));
        }
        _ => {
            return Ok(s3pm_support::s3resp::not_implemented(
                "only GET /{bucket}/{key} is implemented",
                None,
            ));
        }
    }

    let bucket = class.bucket.as_deref().unwrap();
    let key = class.key.as_deref().unwrap();

    let obj_path = match join_object_path(&cfg.posix_root, bucket, key) {
        Ok(p) => p,
        Err(e) => return Ok(s3pm_support::s3resp::access_denied(&e.to_string(), None)),
    };

    // open once (buffered) to stat + inode + size
    let std_file = match OpenOptions::new().read(true).open(&obj_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(s3pm_support::s3resp::no_such_key("not found", None))
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Ok(s3pm_support::s3resp::access_denied("permission denied", None))
        }
        Err(e) => {
            return Ok(s3pm_support::s3resp::internal_error(
                &e.to_string(),
                Some(req.uri().path()),
                None,
            ));
        }
    };

    let meta = match std_file.metadata() {
        Ok(m) => m,
        Err(e) => {
            return Ok(s3pm_support::s3resp::internal_error(
                &e.to_string(),
                Some(req.uri().path()),
                None,
            ));
        }
    };

    let size = meta.len();
    if size == 0 {
        // empty object OK; return 200 with Content-Length 0
        let mut resp = Response::new(Full::new(Bytes::new()).boxed());
        *resp.status_mut() = StatusCode::OK;
        resp.headers_mut().insert("content-length", "0".parse().unwrap());
        resp.headers_mut()
            .insert("content-type", "application/octet-stream".parse().unwrap());
        return Ok(resp);
    }

    // IMPORTANT: real mtime in RFC1123 / HTTP-date format (required by many S3 clients).
    // If metadata.modified() fails, fall back to UNIX_EPOCH (still a valid HTTP date).
    let last_modified = meta
        .modified()
        .ok()
        .map(fmt_http_date)
        .unwrap_or_else(|| fmt_http_date(SystemTime::UNIX_EPOCH));

    let range = match req.headers().get("range") {
        None => None,
        Some(v) => match v.to_str() {
            Ok(s) => match parse_range_header(s, size) {
                Ok(r) => r,
                Err(e) => return Ok(s3pm_support::s3resp::invalid_range(&e.to_string(), None)),
            },
            Err(_) => return Ok(s3pm_support::s3resp::invalid_range("bad Range header", None)),
        },
    };

    let want = range.unwrap_or(ByteRange { start: 0, end_excl: size });
    let want_len = want.end_excl - want.start;

    // inode-based ETag
    let ino = meta.ino();
    let etag = format!("\"{}\"", ino);

    // Small body fast-path (<= one chunk): single read_at into one pooled buffer and return Full.
    if (want_len as usize) <= cfg.chunk_size {
        let file = Arc::new(tokio_uring::fs::File::from_std(std_file));
        let bytes = match read_small(file, app.pool.clone(), want.start, want_len as usize).await {
            Ok(b) => b,
            Err(e) => {
                return Ok(s3pm_support::s3resp::internal_error(
                    &e.to_string(),
                    Some(req.uri().path()),
                    None,
                ));
            }
        };

        let mut resp = Response::new(Full::new(bytes.clone()).boxed());

        if range.is_some() {
            *resp.status_mut() = StatusCode::PARTIAL_CONTENT;
            let end_incl = want.start + (bytes.len().saturating_sub(1) as u64);
            let content_range = format!("bytes {}-{}/{}", want.start, end_incl, size);
            resp.headers_mut().insert("content-range", content_range.parse().unwrap());
            resp.headers_mut().insert("accept-ranges", "bytes".parse().unwrap());
            resp.headers_mut().insert("content-length", bytes.len().to_string().parse().unwrap());
        } else {
            *resp.status_mut() = StatusCode::OK;
            resp.headers_mut().insert("content-length", size.to_string().parse().unwrap());
            resp.headers_mut().insert("accept-ranges", "bytes".parse().unwrap());
        }

        resp.headers_mut().insert("etag", etag.parse().unwrap());
        resp.headers_mut().insert("content-type", "application/octet-stream".parse().unwrap());
        resp.headers_mut().insert(LAST_MODIFIED, last_modified.parse().unwrap());
        resp.headers_mut().insert("server", "s3pm-gateway".parse().unwrap());

        return Ok(resp);
    }

    // Streaming body via streaming module
    let body = match stream_range_body(
        obj_path.clone(),
        size,
        want,
        StreamCfg {
            chunk_size: cfg.chunk_size,
            inflight: cfg.inflight,
            direct_io: cfg.direct_io,
        },
        app.pool.clone(),
    )
    .await
    {
        Ok(b) => b.boxed(),
        Err(e) => {
            return Ok(s3pm_support::s3resp::internal_error(
                &e.to_string(),
                Some(req.uri().path()),
                None,
            ));
        }
    };

    let mut resp = Response::new(body);

    if range.is_some() {
        *resp.status_mut() = StatusCode::PARTIAL_CONTENT;
        let content_range = format!("bytes {}-{}/{}", want.start, want.end_excl - 1, size);
        resp.headers_mut().insert("content-range", content_range.parse().unwrap());
        resp.headers_mut().insert("accept-ranges", "bytes".parse().unwrap());
        resp.headers_mut().insert("content-length", want_len.to_string().parse().unwrap());
    } else {
        *resp.status_mut() = StatusCode::OK;
        resp.headers_mut().insert("content-length", size.to_string().parse().unwrap());
        resp.headers_mut().insert("accept-ranges", "bytes".parse().unwrap());
    }

    resp.headers_mut().insert("etag", etag.parse().unwrap());
    resp.headers_mut().insert("content-type", "application/octet-stream".parse().unwrap());
    resp.headers_mut().insert(LAST_MODIFIED, last_modified.parse().unwrap());
    resp.headers_mut().insert("server", "s3pm-gateway".parse().unwrap());

    Ok(resp)
}

// ---- main ----

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    let cfg = Arc::new(load_cfg()?);

    // Global aligned buffer pool (warmed at startup)
    let pool = Arc::new(BufPool::new(cfg.chunk_size, cfg.pool_size));
    pool.warm(cfg.pool_size);

    let app = Arc::new(App { cfg: cfg.clone(), pool });

    tokio_uring::start(async move {
        if let Some(sock_path) = cfg.bind_uds.clone() {
            // IMPORTANT: UDS bind fails if the path already exists.
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

                tokio_uring::spawn(async move {
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

                tokio_uring::spawn(async move {
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

        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    })
}

