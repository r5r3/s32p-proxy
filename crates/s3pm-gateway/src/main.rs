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
use tokio::sync::mpsc;
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
    chunk_size: usize,
    inflight: usize,
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

    let chunk_size = env_usize("S3PM_CHUNK_SIZE", 1024 * 1024);
    let inflight = env_usize("S3PM_INFLIGHT", 16).max(1);
    let direct_io = env_bool("S3PM_DIRECT_IO", false);

    Ok(Cfg {
        bind_addr,
        posix_root,
        access_key,
        secret_key,
        public_scheme,
        chunk_size,
        inflight,
        direct_io,
    })
}

// ---- tiny S3 XML error helper (keep minimal) ----

fn s3_error(code: &str, message: &str) -> Bytes {
    // Minimal, not perfect. You can reuse your proxy XML builder later.
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<Error xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Code>{}</Code>
  <Message>{}</Message>
</Error>"#,
        code, message
    );
    Bytes::from(body)
}

fn resp_xml(status: StatusCode, body: Bytes) -> Response<BoxBody<Bytes, Infallible>> {
    let mut resp = Response::new(Full::new(body).boxed());
    *resp.status_mut() = status;
    resp.headers_mut().insert("content-type", "application/xml".parse().unwrap());
    resp
}

fn resp_not_implemented(msg: &str) -> Response<BoxBody<Bytes, Infallible>> {
    resp_xml(StatusCode::NOT_IMPLEMENTED, s3_error("NotImplemented", msg))
}

fn resp_access_denied(msg: &str) -> Response<BoxBody<Bytes, Infallible>> {
    resp_xml(StatusCode::FORBIDDEN, s3_error("AccessDenied", msg))
}

fn resp_sig_mismatch(msg: &str) -> Response<BoxBody<Bytes, Infallible>> {
    resp_xml(StatusCode::FORBIDDEN, s3_error("SignatureDoesNotMatch", msg))
}

fn resp_no_such_key(msg: &str) -> Response<BoxBody<Bytes, Infallible>> {
    resp_xml(StatusCode::NOT_FOUND, s3_error("NoSuchKey", msg))
}

fn resp_invalid_range(msg: &str) -> Response<BoxBody<Bytes, Infallible>> {
    // S3 typically uses 416 for invalid ranges; body code often InvalidRange
    resp_xml(StatusCode::RANGE_NOT_SATISFIABLE, s3_error("InvalidRange", msg))
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

fn parse_bucket_key(path: &str) -> Option<(&str, &str)> {
    // expects "/bucket/key..."
    let p = path.trim_start_matches('/');
    let (bucket, rest) = p.split_once('/')?;
    if bucket.is_empty() || rest.is_empty() {
        return None;
    }
    Some((bucket, rest))
}

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

// A pooled buffer wrapper that returns the ABuf to the pool on Drop.
struct PooledBuf {
    pool: mpsc::Sender<ABuf>,
    buf: Option<ABuf>,
}

impl PooledBuf {
    fn new(pool: mpsc::Sender<ABuf>, buf: ABuf) -> Self {
        Self { pool, buf: Some(buf) }
    }
}

impl Drop for PooledBuf {
    fn drop(&mut self) {
        if let Some(b) = self.buf.take() {
            // bounded pool: return buffer; if receiver gone, just drop
            let _ = self.pool.try_send(b);
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
) -> Result<impl Body<Data = Bytes, Error = Infallible>> {
    // Channel from reader -> hyper body
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(cfg.inflight * 2);

    // Clone config for task
    let cfg2 = cfg.clone();

    tokio_uring::spawn(async move {
        if let Err(e) = stream_range_task(path, file_size, want, cfg2, tx).await {
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
    mut out: mpsc::Sender<Result<Frame<Bytes>, Infallible>>,
) -> Result<()> {
    let chunk = cfg.chunk_size;
    let inflight = cfg.inflight;

    // Build per-request buffer pool
    let (pool_tx, mut pool_rx) = mpsc::channel::<ABuf>(inflight);

    for _ in 0..inflight {
        let mut b = ABuf::with_capacity(chunk);
        // initialize once; ensures safe exposure even if read < len
        b.resize(chunk, 0);
        pool_tx.try_send(b).ok();
    }

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
            &pool_tx,
            &mut pool_rx,
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
    pool_tx: &mpsc::Sender<ABuf>,
    pool_rx: &mut mpsc::Receiver<ABuf>,
    out: &mut mpsc::Sender<Result<Frame<Bytes>, Infallible>>,
) -> anyhow::Result<()> {
    let mut futs: FuturesOrdered<_> = FuturesOrdered::new();
    let mut next_off = seg_start;

    // initial fill
    for _ in 0..inflight {
        if next_off >= seg_end {
            break;
        }
        let len = std::cmp::min(chunk_size as u64, seg_end - next_off) as usize;

        let buf = pool_rx.recv().await.ok_or_else(|| anyhow::anyhow!("buffer pool closed"))?;
        let pooled = PooledBuf::new(pool_tx.clone(), buf);
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

            let buf = pool_rx.recv().await.ok_or_else(|| anyhow::anyhow!("buffer pool closed"))?;
            let pooled = PooledBuf::new(pool_tx.clone(), buf);
            let slice = pooled.slice(..len);

            let off = next_off;
            futs.push_back(read_one(file.clone(), slice, off, want_start, want_end));
            next_off += len as u64;
        }
    }

    Ok(())
}

// ---- request handler ----

type Resp = Response<BoxBody<Bytes, Infallible>>;

async fn handle(req: Request<Incoming>, cfg: Arc<Cfg>) -> Result<Resp, Infallible> {
    // Reject query params (including presigned URLs)
    if req.uri().query().is_some() {
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

    // Only GetObject for now
    if req.method() != http::Method::GET {
        return Ok(resp_not_implemented("only GET (GetObject) is implemented"));
    }

    let Some((bucket, key)) = parse_bucket_key(req.uri().path()) else {
        return Ok(resp_not_implemented("only GET /{bucket}/{key} is implemented"));
    };

    let obj_path = match join_object_path(&cfg.posix_root, bucket, key) {
        Ok(p) => p,
        Err(e) => return Ok(resp_access_denied(&e.to_string())),
    };

    // open once (buffered) to stat + inode + size
    let std_file = match OpenOptions::new().read(true).open(&obj_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(resp_no_such_key("not found")),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return Ok(resp_access_denied("permission denied")),
        Err(e) => return Ok(resp_xml(StatusCode::INTERNAL_SERVER_ERROR, s3_error("InternalError", &e.to_string()))),
    };

    let meta = match std_file.metadata() {
        Ok(m) => m,
        Err(e) => return Ok(resp_xml(StatusCode::INTERNAL_SERVER_ERROR, s3_error("InternalError", &e.to_string()))),
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

    // Build streaming body
    let body = match stream_range(obj_path.clone(), size, want, cfg.clone()).await {
        Ok(b) => b.boxed(),
        Err(e) => return Ok(resp_xml(StatusCode::INTERNAL_SERVER_ERROR, s3_error("InternalError", &e.to_string()))),
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

    tokio_uring::start(async move {
        let listener = TcpListener::bind(&cfg.bind_addr).await
            .with_context(|| format!("bind {}", cfg.bind_addr))?;

        tracing::info!("s3pm-gateway listening on {}", cfg.bind_addr);

        loop {
            let (stream, _peer) = listener.accept().await?;
            let cfg2 = cfg.clone();

            tokio_uring::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req| handle(req, cfg2.clone()));
                if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                    tracing::debug!(error = %e, "connection error");
                }
            });
        }

        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    })
}

