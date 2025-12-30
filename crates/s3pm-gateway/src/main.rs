use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use futures_util::stream::{FuturesOrdered, StreamExt};
use http::{Request, Response, StatusCode};
use http_body_util::{combinators::BoxBody, BodyExt, Full, StreamBody};
use httpdate::fmt_http_date;
use hyper::body::{Body, Frame, Incoming};
use hyper::header::LAST_MODIFIED;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use libc::O_DIRECT;
use std::convert::Infallible;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tokio_uring::buf::BoundedBuf;
use aligned_buffer::UniqueAlignedBuffer;

use s3pm_support;

// ---- config ----

#[derive(Clone)]
struct Cfg {
    bind_addr: String,
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

// ---- S3 REST-XML error helpers (shared in s3pm-support) ----
//
// Historically, the gateway had its own tiny XML builder.
// This is now centralized in s3pm-support so the proxy and gateway emit
// consistent S3 REST-XML error responses and codes.

type Resp = Response<BoxBody<Bytes, Infallible>>;

fn into_http_resp(b: s3pm_support::s3resp::BuiltResponse) -> Resp {
    let mut resp = Response::new(Full::new(Bytes::from(b.body)).boxed());
    *resp.status_mut() = b.status;
    resp.headers_mut().insert("content-type", b.content_type.parse().unwrap());
    for (k, v) in b.headers {
        resp.headers_mut().insert(k, v.parse().unwrap());
    }
    resp
}

fn resp_not_implemented(msg: &str) -> Resp {
    into_http_resp(s3pm_support::s3resp::not_implemented(msg, None))
}

fn resp_access_denied(msg: &str) -> Resp {
    into_http_resp(s3pm_support::s3resp::access_denied(msg, None))
}

fn resp_sig_mismatch(msg: &str) -> Resp {
    into_http_resp(s3pm_support::s3resp::signature_does_not_match(msg, None))
}

fn resp_no_such_key(msg: &str) -> Resp {
    into_http_resp(s3pm_support::s3resp::no_such_key(msg, None))
}

fn resp_invalid_range(msg: &str) -> Resp {
    into_http_resp(s3pm_support::s3resp::invalid_range(msg, None))
}

fn resp_bucket_location(region: &str) -> Response<BoxBody<Bytes, Infallible>> {
    // S3 returns an empty LocationConstraint for the classic default region.
    let body = if region == "us-east-1" || region.trim().is_empty() {
        r#"<?xml version="1.0" encoding="UTF-8"?>
<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>"#
            .to_string()
    } else {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">{}</LocationConstraint>"#,
            region
        )
    };

    let mut resp = Response::new(Full::new(Bytes::from(body)).boxed());
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert("content-type", "application/xml".parse().unwrap());
    resp.headers_mut().insert("x-amz-bucket-region", region.parse().unwrap());
    resp
}

// ---- Range parsing ----

#[derive(Debug, Clone, Copy)]
struct ByteRange {
    start: u64,
    end_excl: u64, // [start, end_excl)
}

fn parse_range_header(h: &str, size: u64) -> Result<Option<ByteRange>> {
    let h = h.trim();
    if h.is_empty() {
        return Ok(None);
    }
    if !h.starts_with("bytes=") {
        return Err(anyhow!("unsupported Range unit"));
    }
    let spec = &h["bytes=".len()..];

    // Reject multi-range
    if spec.contains(',') {
        return Err(anyhow!("multiple ranges not supported"));
    }

    let (a, b) = spec.split_once('-').ok_or_else(|| anyhow!("bad Range syntax"))?;
    if a.is_empty() {
        // suffix: "-N"
        let suffix: u64 = b.parse().map_err(|_| anyhow!("bad Range suffix"))?;
        if suffix == 0 {
            return Err(anyhow!("bad Range suffix"));
        }
        let start = size.saturating_sub(suffix);
        return Ok(Some(ByteRange { start, end_excl: size }));
    }

    let start: u64 = a.parse().map_err(|_| anyhow!("bad Range start"))?;
    if start >= size {
        return Err(anyhow!("Range start beyond EOF"));
    }

    let end_incl = if b.is_empty() {
        size - 1
    } else {
        let mut e: u64 = b.parse().map_err(|_| anyhow!("bad Range end"))?;
        if e >= size {
            e = size - 1; // clamp
        }
        e
    };

    if end_incl < start {
        return Err(anyhow!("Range end < start"));
    }

    Ok(Some(ByteRange {
        start,
        end_excl: end_incl + 1,
    }))
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

// ---- io_uring streaming ----

// fixed alignment for now (good default for O_DIRECT)
const ALIGN: usize = 4096;

// pool buffer type: aligned to 4096
type ABuf = UniqueAlignedBuffer<ALIGN>;

/// A global pool of fixed-size aligned buffers.
///
/// Why a global pool?
/// - Previously we created `inflight` buffers per request and zero-filled them.
///   With chunk_size=1MiB and inflight=16, that touches ~16MiB of memory *per request*
///   before the first body byte can be produced, which hurts TTFB (especially visible via proxy).
/// - By warming a global pool at startup we pay the allocation + zeroing cost once.
///   Requests then mostly just reuse buffers, improving latency and reducing allocator pressure.
///
/// Memory model:
/// - Each buffer is `chunk_size` bytes long and fully initialized (zero-filled) so it is safe
///   to expose as `&[u8]` / `Bytes` even when reads return fewer bytes.
/// - On drop, buffers are returned to the pool via `try_send`. If the pool is full, we drop
///   the buffer (best-effort) to avoid blocking in Drop.
struct BufPool {
    chunk_size: usize,
    tx: mpsc::Sender<ABuf>,
    rx: Mutex<mpsc::Receiver<ABuf>>,
}

impl BufPool {
    fn new(chunk_size: usize, pool_size: usize) -> Self {
        let (tx, rx) = mpsc::channel(pool_size);
        Self {
            chunk_size,
            tx,
            rx: Mutex::new(rx),
        }
    }

    fn sender(&self) -> mpsc::Sender<ABuf> {
        self.tx.clone()
    }

    /// Warm the pool with `n` buffers. This touches memory once at startup (page faults + memset).
    fn warm(&self, n: usize) {
        for _ in 0..n {
            let mut b = ABuf::with_capacity(self.chunk_size);
            // initialize once; ensures safe exposure even if read < len
            b.resize(self.chunk_size, 0);
            let _ = self.tx.try_send(b);
        }
    }

    /// Get a buffer from the pool or allocate a new one if empty.
    async fn take(&self) -> ABuf {
        // Fast path: try without waiting
        {
            let mut rx = self.rx.lock().await;
            if let Ok(b) = rx.try_recv() {
                return b;
            }
        }

        // Slow path: allocate on demand (still initialized, but should be rare if pool is sized well).
        let mut b = ABuf::with_capacity(self.chunk_size);
        b.resize(self.chunk_size, 0);
        b
    }

    fn put_back(&self, b: ABuf) {
        // bounded pool: return buffer; if pool is full or receiver gone, just drop
        let _ = self.tx.try_send(b);
    }
}

// A pooled buffer wrapper that returns the ABuf to the pool on Drop.
struct PooledBuf {
    pool: Arc<BufPool>,
    buf: Option<ABuf>,
}

impl PooledBuf {
    fn new(pool: Arc<BufPool>, buf: ABuf) -> Self {
        Self { pool, buf: Some(buf) }
    }
}

impl Drop for PooledBuf {
    fn drop(&mut self) {
        if let Some(b) = self.buf.take() {
            self.pool.put_back(b);
        }
    }
}

// SAFETY: buffer memory is stable and initialized (we create with len=chunk_size filled with zeros once).
unsafe impl tokio_uring::buf::IoBuf for PooledBuf {
    fn stable_ptr(&self) -> *const u8 {
        self.buf.as_ref().unwrap().as_ptr()
    }
    fn bytes_init(&self) -> usize {
        self.buf.as_ref().unwrap().len()
    }
    fn bytes_total(&self) -> usize {
        self.buf.as_ref().unwrap().len()
    }
}

unsafe impl tokio_uring::buf::IoBufMut for PooledBuf {
    fn stable_mut_ptr(&mut self) -> *mut u8 {
        self.buf.as_mut().unwrap().as_mut_ptr()
    }
    unsafe fn set_init(&mut self, _pos: usize) {
        // no-op: we keep the entire buffer initialized always
    }
}

// Wrap a tokio-uring Slice so we can feed it into Bytes::from_owner without copying.
struct SliceOwner<T>(tokio_uring::buf::Slice<T>);

impl<T> AsRef<[u8]> for SliceOwner<T>
where
    tokio_uring::buf::Slice<T>: std::ops::Deref<Target = [u8]>,
{
    fn as_ref(&self) -> &[u8] {
        &*self.0
    }
}

fn align_down(x: u64, a: u64) -> u64 { (x / a) * a }
fn align_up(x: u64, a: u64) -> u64 { ((x + a - 1) / a) * a }

async fn stream_range(
    path: PathBuf,
    file_size: u64,
    want: ByteRange,
    cfg: Arc<Cfg>,
    pool: Arc<BufPool>,
) -> Result<impl Body<Data = Bytes, Error = Infallible>> {
    // Channel from reader -> hyper body
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(cfg.inflight * 2);

    // Clone config/pool for task
    let cfg2 = cfg.clone();
    let pool2 = pool.clone();

    tokio_uring::spawn(async move {
        if let Err(e) = stream_range_task(path, file_size, want, cfg2, pool2, tx).await {
            tracing::warn!(error = %e, "stream task failed");
            // dropping tx ends the body; hyper will treat it as truncated if not all bytes sent
        }
    });

    let stream = ReceiverStream::new(rx);
    Ok(StreamBody::new(stream))
}

async fn stream_range_task(
    path: PathBuf,
    file_size: u64,
    want: ByteRange,
    cfg: Arc<Cfg>,
    pool: Arc<BufPool>,
    mut out: mpsc::Sender<Result<Frame<Bytes>, Infallible>>,
) -> Result<()> {
    let chunk = cfg.chunk_size;
    let inflight = cfg.inflight;

    // Build per-request buffer pool
    // NOTE: This used to allocate and zero `inflight` buffers *per request* which hurt TTFB.
    // We now reuse a process-wide pool (see BufPool) to avoid per-request memory work.
    let _pool_tx = pool.sender();

    // Decide direct/buffered plan
    let a = ALIGN as u64;

    // If direct I/O is requested, enforce chunk alignment
    let mut use_direct = cfg.direct_io;
    if use_direct && (chunk % ALIGN != 0) {
        tracing::warn!(chunk, "direct_io enabled but chunk not aligned; disabling direct_io for this request");
        use_direct = false;
    }

    // We may split into:
    //  - direct segment: aligned and not past file_size_aligned
    //  - tail segment: buffered (handles final partial block)
    let file_size_aligned = align_down(file_size, a);

    let mut segments: Vec<(bool, u64, u64)> = Vec::new(); // (direct, seg_start, seg_end_excl)

    if use_direct && want.start < file_size_aligned {
        let seg_start = align_down(want.start, a);
        let seg_end = std::cmp::min(align_up(want.end_excl, a), file_size_aligned);
        if seg_end > seg_start {
            segments.push((true, seg_start, seg_end));
        }
        if want.end_excl > seg_end {
            segments.push((false, seg_end.max(want.start), want.end_excl));
        }
    } else {
        segments.push((false, want.start, want.end_excl));
    }

    for (direct, seg_start, seg_end) in segments {
        if seg_start >= seg_end {
            continue;
        }

        let std_file = open_std_file(&path, direct)?;
        let file = Arc::new(tokio_uring::fs::File::from_std(std_file));

        stream_segment(
            file.clone(),
            seg_start,
            seg_end,
            want.start,
            want.end_excl,
            chunk,
            inflight,
            pool.clone(),
            &mut out,
        )
        .await?;
    }

    // done
    Ok(())
}

fn open_std_file(path: &Path, direct: bool) -> Result<std::fs::File> {
    let mut oo = OpenOptions::new();
    oo.read(true);
    if direct {
        oo.custom_flags(O_DIRECT);
    }
    oo.open(path).map_err(|e| anyhow!("{e}"))
}

async fn read_one(
    file: Arc<tokio_uring::fs::File>,
    slice: tokio_uring::buf::Slice<PooledBuf>,
    off: u64,
    want_start: u64,
    want_end: u64,
) -> anyhow::Result<Option<Bytes>> {
    let (res, slice) = file.read_at(slice, off).await;
    let n = res.map_err(|e| anyhow::anyhow!("read_at failed at off={off}: {e}"))?;
    if n == 0 {
        return Ok(None);
    }

    let mut bytes = Bytes::from_owner(SliceOwner(slice));
    bytes = bytes.slice(0..n);

    let chunk_start = std::cmp::max(want_start, off);
    let chunk_end = std::cmp::min(want_end, off + n as u64);

    if chunk_start >= chunk_end {
        return Ok(Some(Bytes::new()));
    }

    let i0 = (chunk_start - off) as usize;
    let i1 = (chunk_end - off) as usize;
    Ok(Some(bytes.slice(i0..i1)))
}

async fn stream_segment(
    file: Arc<tokio_uring::fs::File>,
    seg_start: u64,
    seg_end: u64,
    want_start: u64,
    want_end: u64,
    chunk_size: usize,
    inflight: usize,
    pool: Arc<BufPool>,
    out: &mut mpsc::Sender<Result<Frame<Bytes>, Infallible>>,
) -> anyhow::Result<()> {
    // Bound inflight by how much we will actually read in this segment.
    // This prevents wasting work/buffers for small objects or small ranges.
    let chunks_total = ((seg_end - seg_start) + chunk_size as u64 - 1) / chunk_size as u64;
    let inflight = std::cmp::min(inflight.max(1), chunks_total.max(1) as usize);

    let mut futs: FuturesOrdered<_> = FuturesOrdered::new();
    let mut next_off = seg_start;

    // initial fill
    for _ in 0..inflight {
        if next_off >= seg_end {
            break;
        }
        let len = std::cmp::min(chunk_size as u64, seg_end - next_off) as usize;

        let buf = pool.take().await;
        let pooled = PooledBuf::new(pool.clone(), buf);
        let slice = pooled.slice(..len);

        let off = next_off;
        futs.push_back(read_one(file.clone(), slice, off, want_start, want_end));
        next_off += len as u64;
    }

    while let Some(res) = futs.next().await {
        let maybe = res?;
        let Some(bytes) = maybe else {
            break; // EOF / truncated
        };

        if !bytes.is_empty() {
            if out.send(Ok(Frame::data(bytes))).await.is_err() {
                return Ok(()); // client gone
            }
        }

        // schedule next
        if next_off < seg_end {
            let len = std::cmp::min(chunk_size as u64, seg_end - next_off) as usize;

            let buf = pool.take().await;
            let pooled = PooledBuf::new(pool.clone(), buf);
            let slice = pooled.slice(..len);

            let off = next_off;
            futs.push_back(read_one(file.clone(), slice, off, want_start, want_end));
            next_off += len as u64;
        }
    }

    Ok(())
}

// ---- request handler ----

struct App {
    cfg: Arc<Cfg>,
    pool: Arc<BufPool>,
}

async fn handle(req: Request<Incoming>, app: Arc<App>) -> Result<Resp, Infallible> {
    let cfg = app.cfg.clone();

    // Classify first (no body required). This parsing logic is shared with the proxy now.
    let class = s3pm_support::classifier::classify(req.method().as_str(), req.uri());

    // Reject query params (including presigned URLs), except GetBucketLocation (?location)
    let is_get_bucket_location = req.method() == http::Method::GET
        && req.uri().query().is_some_and(|q| {
            let mut parts = q.split('&').filter(|p| !p.is_empty());
            let first = parts.next().unwrap_or("");
            parts.next().is_none() && (first == "location" || first.starts_with("location="))
        });

    if req.uri().query().is_some() && !is_get_bucket_location {
        return Ok(resp_not_implemented("query parameters are not implemented"));
    }

    // SigV4: parse + verify (every request)
    let auth = match s3pm_support::parse_authorization(req.headers()) {
        Ok(a) => a,
        Err(e) => return Ok(resp_access_denied(&format!("bad Authorization: {e}"))),
    };

    if auth.access_key != cfg.access_key {
        return Ok(resp_access_denied("unknown access key"));
    }

    if let Err(e) = s3pm_support::verify_sigv4_header_only(
        req.method().as_str(),
        req.uri(),
        req.headers(),
        &auth,
        &cfg.secret_key,
        &cfg.public_scheme,
    ) {
        return Ok(resp_sig_mismatch(&e.to_string()));
    }

    // Only GetObject for now (and only the clean "no query params" form).
    match &class.op {
        s3pm_support::classifier::S3Op::Read(s3pm_support::classifier::ReadOp::GetBucketLocation) => {
            return Ok(resp_bucket_location(&cfg.region));
        }
        s3pm_support::classifier::S3Op::Read(s3pm_support::classifier::ReadOp::GetObject) => {}
        s3pm_support::classifier::S3Op::Multipart(_) => {
            return Ok(resp_not_implemented("multipart uploads are not implemented"));
        }
        s3pm_support::classifier::S3Op::Versioning(_) => {
            return Ok(resp_not_implemented("versioning is not implemented"));
        }
        _ => {
            return Ok(resp_not_implemented("only GET /{bucket}/{key} is implemented"));
        }
    }

    let bucket = class.bucket.as_deref().unwrap();
    let key = class.key.as_deref().unwrap();

    let obj_path = match join_object_path(&cfg.posix_root, bucket, key) {
        Ok(p) => p,
        Err(e) => return Ok(resp_access_denied(&e.to_string())),
    };

    // open once (buffered) to stat + inode + size
    let std_file = match OpenOptions::new().read(true).open(&obj_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(resp_no_such_key("not found")),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return Ok(resp_access_denied("permission denied")),
        Err(e) => {
            let b = s3pm_support::s3resp::s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                s3pm_support::s3xml::error_code::INTERNAL_ERROR,
                &e.to_string(),
                Some(req.uri().path()),
                None,
            ).unwrap_or_else(|_| s3pm_support::s3resp::BuiltResponse {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                content_type: "application/xml",
                body: b"<Error><Code>InternalError</Code><Message>internal error</Message></Error>".to_vec(),
                headers: vec![],
            });
            return Ok(into_http_resp(b));
        }
    };

    let meta = match std_file.metadata() {
        Ok(m) => m,
        Err(e) => {
            let b = s3pm_support::s3resp::s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                s3pm_support::s3xml::error_code::INTERNAL_ERROR,
                &e.to_string(),
                Some(req.uri().path()),
                None,
            ).unwrap_or_else(|_| s3pm_support::s3resp::BuiltResponse {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                content_type: "application/xml",
                body: b"<Error><Code>InternalError</Code><Message>internal error</Message></Error>".to_vec(),
                headers: vec![],
            });
            return Ok(into_http_resp(b));
        }
    };

    let size = meta.len();
    if size == 0 {
        // empty object OK; return 200 with Content-Length 0
        let mut resp = Response::new(Full::new(Bytes::new()).boxed());
        *resp.status_mut() = StatusCode::OK;
        resp.headers_mut().insert("content-length", "0".parse().unwrap());
        resp.headers_mut().insert("content-type", "application/octet-stream".parse().unwrap());
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
                Err(e) => return Ok(resp_invalid_range(&e.to_string())),
            },
            Err(_) => return Ok(resp_invalid_range("bad Range header")),
        },
    };

    let want = range.unwrap_or(ByteRange { start: 0, end_excl: size });
    let want_len = want.end_excl - want.start;

    // inode-based ETag
    use std::os::unix::fs::MetadataExt;
    let ino = meta.ino();
    let etag = format!("\"{}\"", ino);

    // Small body fast-path:
    // If the response body fits in a single chunk, read it into one pooled buffer and return Full.
    //
    // This avoids spawning a streaming task + channels + backpressure coordination for small responses,
    // which improves latency and reduces overhead for common small-object GETs and small Range GETs.
    if (want_len as usize) <= cfg.chunk_size {
        let file = Arc::new(tokio_uring::fs::File::from_std(std_file));

        let buf = app.pool.take().await;
        let pooled = PooledBuf::new(app.pool.clone(), buf);

        let read_len = want_len as usize;
        let slice = pooled.slice(..read_len);

        let maybe = match read_one(file, slice, want.start, want.start, want.end_excl).await {
            Ok(m) => m,
            Err(e) => {
                let b = s3pm_support::s3resp::s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    s3pm_support::s3xml::error_code::INTERNAL_ERROR,
                    &e.to_string(),
                    Some(req.uri().path()),
                    None,
                ).unwrap_or_else(|_| s3pm_support::s3resp::BuiltResponse {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    content_type: "application/xml",
                    body: b"<Error><Code>InternalError</Code><Message>internal error</Message></Error>".to_vec(),
                    headers: vec![],
                });
                return Ok(into_http_resp(b));
            }
        };

        let Some(bytes) = maybe else {
            // EOF / truncated unexpectedly
            let b = s3pm_support::s3resp::s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                s3pm_support::s3xml::error_code::INTERNAL_ERROR,
                "unexpected EOF",
                Some(req.uri().path()),
                None,
            ).unwrap_or_else(|_| s3pm_support::s3resp::BuiltResponse {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                content_type: "application/xml",
                body: b"<Error><Code>InternalError</Code><Message>unexpected EOF</Message></Error>".to_vec(),
                headers: vec![],
            });
            return Ok(into_http_resp(b));
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

    // Build streaming body
    let body = match stream_range(obj_path.clone(), size, want, cfg.clone(), app.pool.clone()).await {
        Ok(b) => b.boxed(),
        Err(e) => {
            let b = s3pm_support::s3resp::s3_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                s3pm_support::s3xml::error_code::INTERNAL_ERROR,
                &e.to_string(),
                Some(req.uri().path()),
                None,
            ).unwrap_or_else(|_| s3pm_support::s3resp::BuiltResponse {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                content_type: "application/xml",
                body: b"<Error><Code>InternalError</Code><Message>internal error</Message></Error>".to_vec(),
                headers: vec![],
            });
            return Ok(into_http_resp(b));
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

    // Create and warm a global aligned buffer pool.
    //
    // This is the key latency fix:
    // - We allocate + zero memory once at startup (pool_size * chunk_size).
    // - Requests reuse buffers and avoid per-request memset/page faults before TTFB.
    //
    // Tuning:
    // - `S3PM_POOL_SIZE` controls number of buffers in the pool (default 8 * inflight).
    // - Larger pool reduces on-demand allocations under concurrency at the cost of RAM.
    let pool = Arc::new(BufPool::new(cfg.chunk_size, cfg.pool_size));
    pool.warm(cfg.pool_size);

    let app = Arc::new(App { cfg: cfg.clone(), pool });

    tokio_uring::start(async move {
        let listener = TcpListener::bind(&cfg.bind_addr).await
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
                    .pipeline_flush(true)
                    .serve_connection(io, svc).await {
                        tracing::debug!(error = %e, "connection error");
                }
            });
        }

        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    })
}

