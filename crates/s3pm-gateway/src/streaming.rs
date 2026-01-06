use anyhow::{anyhow, Result};
use bytes::{Bytes, Buf};
use futures_util::Stream;
use futures_util::stream::{FuturesOrdered, FuturesUnordered, StreamExt, TryStreamExt};
use http_body_util::{StreamBody, BodyExt};
use hyper::body::{Body, Incoming, Frame};
use libc::O_DIRECT;
use std::convert::Infallible;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io;
use tokio::sync::{mpsc, Semaphore};
use tokio_stream::wrappers::ReceiverStream;
use tokio_uring::buf::BoundedBuf;
use crate::buffer::{BufPool, PooledBuf, SliceOwner, BytesBuf, ALIGN};

#[derive(Debug, Clone, Copy)]
pub struct ByteRange {
    pub start: u64,
    pub end_excl: u64, // [start, end_excl)
}

#[derive(Clone)]
pub struct StreamCfg {
    pub chunk_size: usize,
    pub inflight: usize,
    pub direct_io: bool,
}

fn align_down(x: u64, a: u64) -> u64 {
    (x / a) * a
}
fn align_up(x: u64, a: u64) -> u64 {
    let y = x.saturating_add(a - 1);
    (y / a) * a
}

pub fn parse_range_header(h: &str, size: u64) -> Result<Option<ByteRange>> {
    let h = h.trim();
    if h.is_empty() {
        return Ok(None);
    }
    if !h.starts_with("bytes=") {
        return Err(anyhow!("unsupported Range unit"));
    }
    let spec = &h["bytes=".len()..];

    if spec.contains(',') {
        return Err(anyhow!("multiple ranges not supported"));
    }

    let (a, b) = spec.split_once('-').ok_or_else(|| anyhow!("bad Range syntax"))?;
    if a.is_empty() {
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
            e = size - 1;
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

/// Stream a range from file as a Hyper body (using tokio-uring reader task).
pub async fn stream_range_body(
    path: PathBuf,
    file_size: u64,
    want: ByteRange,
    cfg: StreamCfg,
    pool: Arc<BufPool>,
    io_sem: Arc<Semaphore>,
    io_total: usize,
) -> Result<impl Body<Data = Bytes, Error = Infallible>> {
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(cfg.inflight * 2);

    tokio_uring::spawn(async move {
        if let Err(e) = stream_range_task(path, file_size, want, cfg, pool, io_sem, io_total, tx).await
        {
            tracing::warn!(error = %e, "stream task failed");
        }
    });

    Ok(StreamBody::new(ReceiverStream::new(rx)))
}

fn effective_end_for_scheduling(
    file_size: u64,
    seg_start: u64,
    seg_end: u64,
    chunk_size: usize,
    direct: bool,
) -> u64 {
    if !direct {
        return seg_end;
    }

    // In direct mode, seg_end may extend past EOF (aligned-up). We must not schedule reads
    // that start at/after EOF (off >= file_size), because they'd return 0 and would stop
    // the pipeline too early. So cap at "one block past the last valid aligned start".
    let a = ALIGN as u64;
    if file_size == 0 {
        return seg_start;
    }

    // work_end is aligned and >= file_size; reads starting < work_end are safe,
    // but we must ensure the *start offset* is < file_size.
    let work_end = align_down(file_size.saturating_sub(1), a) + a;

    // Also ensure we don't run backwards.
    let capped = std::cmp::min(seg_end, work_end);
    // chunk_size is assumed aligned when direct; caller enforces.
    if capped < seg_start {
        seg_start
    } else {
        capped
    }
}

fn chunks_needed(seg_start: u64, eff_end: u64, chunk_size: usize) -> usize {
    if eff_end <= seg_start {
        return 0;
    }
    let span = eff_end - seg_start;
    ((span + chunk_size as u64 - 1) / chunk_size as u64) as usize
}

/// Decide per-file concurrency based on global permits already out.
fn per_file_permits(base: usize, io_total: usize, io_available: usize) -> usize {
    if base <= 1 || io_total <= 1 {
        return base.max(1);
    }

    let io_out = io_total.saturating_sub(io_available);

    // If more than half are out, scale down proportionally to remaining permits.
    if io_out > io_total / 2 {
        // scale factor = 2*available/total in (0,1)
        // allowed = ceil(base * 2*available/total)
        let avail = io_available.max(1) as u64;
        let total = io_total as u64;
        let scaled = ((base as u64) * (2 * avail) + (total - 1)) / total;
        scaled as usize
    } else {
        base
    }
}

async fn stream_range_task(
    path: PathBuf,
    file_size: u64,
    want: ByteRange,
    cfg: StreamCfg,
    pool: Arc<BufPool>,
    io_sem: Arc<Semaphore>,
    io_total: usize,
    mut out: mpsc::Sender<Result<Frame<Bytes>, Infallible>>,
) -> Result<()> {
    let chunk = cfg.chunk_size;
    let inflight_cfg = cfg.inflight.max(1);

    let a = ALIGN as u64;

    // Use O_DIRECT for the entire request if enabled and chunk_size is aligned.
    let mut direct = cfg.direct_io;
    if direct && (chunk % ALIGN != 0) {
        tracing::warn!(
            chunk,
            "direct_io enabled but chunk not aligned; disabling direct_io for this request"
        );
        direct = false;
    }

    // Choose the segment to read:
    // - direct: expand to alignment boundaries (may extend past EOF); slice later
    // - buffered: exact request range
    let (seg_start, seg_end) = if direct {
        (align_down(want.start, a), align_up(want.end_excl, a))
    } else {
        (want.start, want.end_excl)
    };

    if seg_start >= seg_end {
        return Ok(());
    }

    // Compute how many chunks are actually needed (taking file size into account).
    let eff_end = effective_end_for_scheduling(file_size, seg_start, seg_end, chunk, direct);
    let needed = chunks_needed(seg_start, eff_end, chunk);

    if needed == 0 {
        return Ok(());
    }

    // Base per-file concurrency = min(cfg.inflight, needed)
    let base = std::cmp::min(inflight_cfg, needed);

    // Dynamic per-file cap based on global usage snapshot.
    let available = io_sem.available_permits();
    let mut allowed = per_file_permits(base, io_total.max(1), available);

    // Never exceed what we actually need.
    allowed = allowed.clamp(1, base);

    // Acquire permits ONCE per file/request and hold until streaming completes.
    let _permits = io_sem
        .clone()
        .acquire_many_owned(allowed as u32)
        .await
        .map_err(|_| anyhow!("io permit semaphore closed"))?;

    // Open exactly one fd for the whole request (direct OR buffered).
    let std_file = open_std_file(&path, direct)?;
    let file = Arc::new(tokio_uring::fs::File::from_std(std_file));

    stream_segment(
        file,
        file_size,
        seg_start,
        seg_end,
        want.start,
        want.end_excl,
        chunk,
        allowed, // per-file permitted inflight
        direct,
        pool,
        &mut out,
    )
    .await?;

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
) -> Result<Option<Bytes>> {
    let (res, slice) = file.read_at(slice, off).await;
    let n = res.map_err(|e| anyhow!("read_at failed at off={off}: {e}"))?;
    if n == 0 {
        // EOF
        return Ok(None);
    }

    let mut bytes = Bytes::from_owner(SliceOwner(slice));
    bytes = bytes.slice(0..n);

    // Slice down to the requested [want_start, want_end) within this read window.
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
    file_size: u64,
    seg_start: u64,
    seg_end: u64,
    want_start: u64,
    want_end: u64,
    chunk_size: usize,
    inflight: usize, // already capped by per-file permits
    direct: bool,
    pool: Arc<BufPool>,
    out: &mut mpsc::Sender<Result<Frame<Bytes>, Infallible>>,
) -> Result<()> {
    let a = ALIGN as u64;

    let mut next_off = seg_start;

    // For direct mode, avoid scheduling reads that start at/after EOF.
    // We cap the scheduling window similarly to effective_end_for_scheduling().
    let effective_end = if direct {
        if file_size == 0 {
            seg_start
        } else {
            let work_end = align_down(file_size.saturating_sub(1), a) + a;
            std::cmp::min(seg_end, work_end)
        }
    } else {
        seg_end
    };

    if next_off >= effective_end {
        return Ok(());
    }

    // How many chunks will we actually schedule?
    let chunks_total =
        ((effective_end - seg_start) + chunk_size as u64 - 1) / chunk_size as u64;
    let inflight = std::cmp::min(inflight.max(1), chunks_total.max(1) as usize);

    let mut futs: FuturesOrdered<_> = FuturesOrdered::new();

    // Compute submission length at offset.
    let submit_len = |off: u64| -> usize {
        let remain = effective_end.saturating_sub(off);
        let mut len = std::cmp::min(chunk_size as u64, remain) as usize;

        if direct {
            // Ensure ALIGN multiple for O_DIRECT submissions.
            let rem = (len as u64) % a;
            if rem != 0 {
                len = (len as u64 + (a - rem)) as usize;
            }
            if off.saturating_add(len as u64) > effective_end {
                len = (effective_end - off) as usize;
            }
        }

        len.max(1)
    };

    // Prime the pipeline up to inflight.
    for _ in 0..inflight {
        if next_off >= effective_end {
            break;
        }
        let len = submit_len(next_off);

        let buf = pool.take();
        let pooled = PooledBuf::new(pool.clone(), buf);
        let slice = pooled.slice(..len);

        let off = next_off;
        futs.push_back(read_one(file.clone(), slice, off, want_start, want_end));
        next_off = next_off.saturating_add(len as u64);
    }

    while let Some(res) = futs.next().await {
        let Some(bytes) = res? else {
            break;
        };

        if !bytes.is_empty() {
            if out.send(Ok(Frame::data(bytes))).await.is_err() {
                return Ok(());
            }
        }

        if next_off < effective_end {
            let len = submit_len(next_off);

            let buf = pool.take();
            let pooled = PooledBuf::new(pool.clone(), buf);
            let slice = pooled.slice(..len);

            let off = next_off;
            futs.push_back(read_one(file.clone(), slice, off, want_start, want_end));
            next_off = next_off.saturating_add(len as u64);
        }
    }

    Ok(())
}

struct PlainFrameReader<S> {
    stream: S,
    buf: Bytes,
    done: bool,
}

impl<S> PlainFrameReader<S>
where
    S: Stream<Item = io::Result<Bytes>> + Unpin,
{
    fn new(stream: S) -> Self {
        Self {
            stream,
            buf: Bytes::new(),
            done: false,
        }
    }

    async fn refill(&mut self) -> io::Result<()> {
        if self.done {
            return Ok(());
        }
        while self.buf.is_empty() && !self.done {
            match self.stream.next().await {
                None => self.done = true,
                Some(Ok(b)) => self.buf = b,
                Some(Err(e)) => return Err(e),
            }
        }
        Ok(())
    }

    async fn read_exact_payload(&mut self, mut dst: &mut [u8]) -> io::Result<()> {
        while !dst.is_empty() {
            self.refill().await?;
            if self.done && self.buf.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "body shorter than expected",
                ));
            }

            let n = dst.len().min(self.buf.len());
            dst[..n].copy_from_slice(&self.buf[..n]);
            dst = &mut dst[n..];
            self.buf.advance(n);
        }
        Ok(())
    }

    async fn next_bytes(&mut self) -> io::Result<Option<Bytes>> {
        self.refill().await?;
        if self.done && self.buf.is_empty() {
            return Ok(None);
        }
        if self.buf.is_empty() {
            return Ok(Some(Bytes::new()));
        }
        Ok(Some(std::mem::take(&mut self.buf)))
    }

    async fn ensure_eof(mut self) -> io::Result<()> {
        while let Some(item) = self.stream.next().await {
            let b = item?;
            if !b.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "body longer than expected",
                ));
            }
        }
        Ok(())
    }
}

async fn try_preallocate(file: &tokio_uring::fs::File, len: u64) -> Result<()> {
    if len == 0 {
        return Ok(());
    }

    match file.fallocate(0, len, 0).await {
        Ok(()) => Ok(()),
        Err(e) => {
            // Some FS / setups return "operation not supported" etc. Don’t fail the upload.
            let raw = e.raw_os_error().unwrap_or(0);
            if raw == libc::EOPNOTSUPP
                || raw == libc::ENOSYS
                || raw == libc::EINVAL
                || raw == libc::ENOTSUP
            {
                tracing::debug!(error = %e, "fallocate not supported; continuing without preallocation");
                Ok(())
            } else {
                Err(anyhow!("fallocate({len}) failed: {e}"))
            }
        }
    }
}

fn ftruncate_fd(fd: std::os::unix::io::RawFd, len: u64) -> Result<()> {
    let rc = unsafe { libc::ftruncate(fd, len as libc::off_t) };
    if rc != 0 {
        return Err(anyhow!(
            "ftruncate({}) failed: {}",
            len,
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

pub mod aws_chunked {
    use super::*;
    use futures_util::Stream;

    #[derive(Debug, Clone, Copy)]
    enum State {
        NeedHeader,
        NeedData,
        NeedCrlf,
        NeedTrailers,
        Done,
    }

    /// Decoder for `x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD`.
    ///
    /// - Consumes the *encoded* HTTP body as `Bytes` frames (no AsyncRead wrapper).
    /// - Produces *decoded payload bytes*.
    /// - Ignores `chunk-signature=...` (parses and discards extensions).
    pub struct Decoder<S> {
        stream: S,
        buf: Bytes,
        scratch: Vec<u8>, // for header/trailer lines crossing frame boundaries
        state: State,
        remaining_in_chunk: usize,
        eof: bool,
    }

    impl<S> Decoder<S>
    where
        S: Stream<Item = io::Result<Bytes>> + Unpin,
    {
        pub fn new(stream: S) -> Self {
            Self {
                stream,
                buf: Bytes::new(),
                scratch: Vec::with_capacity(256),
                state: State::NeedHeader,
                remaining_in_chunk: 0,
                eof: false,
            }
        }

        async fn refill(&mut self) -> io::Result<()> {
            while self.buf.is_empty() && !self.eof {
                match self.stream.next().await {
                    None => self.eof = true,
                    Some(Ok(b)) => self.buf = b,
                    Some(Err(e)) => return Err(e),
                }
            }
            Ok(())
        }

        async fn read_line(&mut self) -> io::Result<Bytes> {
            self.scratch.clear();

            loop {
                // Search in current buffer for '\n'
                if let Some(pos) = self.buf.iter().position(|&c| c == b'\n') {
                    let line = self.buf.split_to(pos + 1);

                    // If scratch is empty, return line directly.
                    if self.scratch.is_empty() {
                        return Ok(line);
                    }

                    // Otherwise append line to scratch and return combined as Bytes.
                    self.scratch.extend_from_slice(&line);
                    return Ok(Bytes::copy_from_slice(&self.scratch));
                }

                // No newline: move entire buf into scratch, then refill.
                if !self.buf.is_empty() {
                    self.scratch.extend_from_slice(&self.buf);
                    self.buf = Bytes::new();
                }

                self.refill().await?;
                if self.eof && self.buf.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "aws-chunked: unexpected EOF while reading line",
                    ));
                }
            }
        }

        fn parse_chunk_len_line(line: &[u8]) -> io::Result<usize> {
            // Expected: "<hex>;chunk-signature=<hex>\r\n" (extensions ignored)
            // Be tolerant: allow "<hex>\r\n".
            let line = line.strip_suffix(b"\n").unwrap_or(line);
            let line = line.strip_suffix(b"\r").unwrap_or(line);

            let hex_part = line.split(|&c| c == b';').next().unwrap_or(&[]);
            if hex_part.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "aws-chunked: empty chunk size",
                ));
            }

            let s = std::str::from_utf8(hex_part).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "aws-chunked: non-utf8 size")
            })?;

            usize::from_str_radix(s, 16).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("aws-chunked: invalid hex chunk size: {s}"),
                )
            })
        }

        async fn consume_exact(&mut self, mut need: &[u8]) -> io::Result<()> {
            while !need.is_empty() {
                self.refill().await?;
                if self.eof && self.buf.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "aws-chunked: unexpected EOF while consuming CRLF",
                    ));
                }

                let take = need.len().min(self.buf.len());
                if &self.buf[..take] != &need[..take] {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "aws-chunked: missing/invalid CRLF",
                    ));
                }

                self.buf.advance(take);
                need = &need[take..];
            }
            Ok(())
        }

        async fn read_trailers_until_blank(&mut self) -> io::Result<()> {
            loop {
                let line = self.read_line().await?;
                if line == b"\n"[..] || line == b"\r\n"[..] {
                    return Ok(());
                }
                // ignore trailer headers
            }
        }

        /// Returns the next decoded payload chunk (may be a slice of an input frame).
        /// Returns `Ok(None)` when the aws-chunked stream terminator/trailers are fully consumed.
        pub async fn next_payload(&mut self) -> io::Result<Option<Bytes>> {
            loop {
                match self.state {
                    State::Done => return Ok(None),

                    State::NeedHeader => {
                        let line = self.read_line().await?;
                        let n = Self::parse_chunk_len_line(&line)?;
                        if n == 0 {
                            self.state = State::NeedTrailers;
                        } else {
                            self.remaining_in_chunk = n;
                            self.state = State::NeedData;
                        }
                    }

                    State::NeedData => {
                        if self.remaining_in_chunk == 0 {
                            self.state = State::NeedCrlf;
                            continue;
                        }

                        self.refill().await?;
                        if self.eof && self.buf.is_empty() {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "aws-chunked: unexpected EOF in chunk data",
                            ));
                        }

                        let take = self.remaining_in_chunk.min(self.buf.len());
                        let out = self.buf.split_to(take);
                        self.remaining_in_chunk -= take;

                        if !out.is_empty() {
                            return Ok(Some(out));
                        }
                    }

                    State::NeedCrlf => {
                        self.consume_exact(b"\r\n").await?;
                        self.state = State::NeedHeader;
                    }

                    State::NeedTrailers => {
                        self.read_trailers_until_blank().await?;
                        self.state = State::Done;
                        return Ok(None);
                    }
                }
            }
        }

        /// Read exactly `dst.len()` decoded payload bytes into `dst`.
        pub async fn read_exact_payload(&mut self, mut dst: &mut [u8]) -> io::Result<()> {
            while !dst.is_empty() {
                match self.next_payload().await? {
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "aws-chunked: decoded payload shorter than expected",
                        ))
                    }
                    Some(mut b) => {
                        if b.is_empty() {
                            continue;
                        }
                        let n = dst.len().min(b.len());
                        dst[..n].copy_from_slice(&b[..n]);
                        dst = &mut dst[n..];
                        b.advance(n);

                        // If we didn't consume the whole `b`, put the remainder back into `self.buf`
                        // by prefixing it (rare; only if dst is smaller than produced slice).
                        if !b.is_empty() {
                            // Put remainder in front of existing buf with a tiny copy.
                            // This is fine because it only happens when dst is smaller than
                            // the chunk slice (i.e. direct-io chunk boundary).
                            let mut v = Vec::with_capacity(b.len() + self.buf.len());
                            v.extend_from_slice(&b);
                            v.extend_from_slice(&self.buf);
                            self.buf = Bytes::from(v);
                        }
                    }
                }
            }
            Ok(())
        }

        /// Ensure the underlying stream is fully consumed (for HTTP/1.1 keep-alive correctness).
        pub async fn drain_to_eof(mut self) -> io::Result<()> {
            while let Some(item) = self.stream.next().await {
                let _ = item?;
            }
            Ok(())
        }
    }
}

/// Stream-write an object body to `path`.
///
/// Requirements / behavior:
/// - Supports parallel in-flight chunk writes (same file) up to `cfg.inflight` (scaled by global permits).
/// - Files smaller than chunk_size are written without direct_io.
/// - If direct_io is enabled:
///   - requires `chunk_size % ALIGN == 0`
///   - pads the last chunk with zeros to an aligned write size
///   - truncates to the real size at the end
pub async fn write_object_body_to_file(
    body: Incoming,
    path: PathBuf,
    logical_len: u64,          // decoded length if streaming, otherwise Content-Length
    is_streaming_sigv4: bool,  // STREAMING-AWS4-HMAC-SHA256-PAYLOAD
    cfg: StreamCfg,
    pool: Arc<BufPool>,
    io_sem: Arc<Semaphore>,
    io_total: usize,
) -> Result<()> {
    let chunk = cfg.chunk_size;
    let inflight_cfg = cfg.inflight.max(1);
    let a = ALIGN as u64;

    // Decide direct I/O (must be aligned).
    let mut direct = cfg.direct_io && logical_len > chunk as u64;
    if direct && (chunk % ALIGN != 0) {
        tracing::warn!(
            chunk,
            "direct_io enabled but chunk not aligned; disabling direct_io for this upload"
        );
        direct = false;
    }

    // Ensure parent directories exist (S3 "folders" are implicit)
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow!("create_dir_all {}: {e}", parent.display()))?;
    }

    // Open file (single fd for whole upload)
    let std_file = {
        let mut oo = OpenOptions::new();
        oo.write(true).create(true).truncate(true);
        if direct {
            oo.custom_flags(O_DIRECT);
        }
        oo.open(&path).map_err(|e| anyhow!("open {}: {e}", path.display()))?
    };

    let file = Arc::new(tokio_uring::fs::File::from_std(std_file));

    // Preallocate (best-effort). For direct, allocate the aligned-on-disk size.
    let prealloc_len = if direct {
        align_up(logical_len, a)
    } else {
        logical_len
    };
    try_preallocate(&file, prealloc_len).await?;

    // Empty object: done.
    if logical_len == 0 {
        // Ensure size is exactly 0 even if fallocate extended it.
        ftruncate_fd(file.as_raw_fd(), 0)?;
        return Ok(());
    }

    // Permits: base on logical chunks.
    let needed_chunks = ((logical_len + chunk as u64 - 1) / chunk as u64) as usize;
    let base = std::cmp::min(inflight_cfg, needed_chunks.max(1));
    let available = io_sem.available_permits();
    let mut allowed = per_file_permits(base, io_total.max(1), available);
    allowed = allowed.clamp(1, base);

    // Hold permits for the whole upload (matches read-side idea)
    let _permits = io_sem
        .clone()
        .acquire_many_owned(allowed as u32)
        .await
        .map_err(|_| anyhow!("io permit semaphore closed"))?;

    // Hyper -> stream of Bytes frames (encoded body bytes).
    let data_stream = body.into_data_stream().map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("body read error: {e}"))
    });

    // -------------------------
    // Buffered (non-direct) path: write Bytes frames without copying using BytesBuf
    // -------------------------
    if !direct {
        enum Src<S> {
            Plain(PlainFrameReader<S>),
            Aws(aws_chunked::Decoder<S>),
        }

        impl<S> Src<S>
        where
            S: Stream<Item = io::Result<Bytes>> + Unpin,
        {
            async fn next_payload(&mut self) -> io::Result<Option<Bytes>> {
                match self {
                    Src::Plain(p) => p.next_bytes().await,
                    Src::Aws(d) => d.next_payload().await,
                }
            }

            async fn ensure_done(self) -> io::Result<()> {
                match self {
                    Src::Plain(p) => p.ensure_eof().await,
                    Src::Aws(d) => d.drain_to_eof().await,
                }
            }
        }

        let mut src = if is_streaming_sigv4 {
            Src::Aws(aws_chunked::Decoder::new(data_stream))
        } else {
            Src::Plain(PlainFrameReader::new(data_stream))
        };

        let mut written: u64 = 0;
        let mut futs: FuturesUnordered<_> = FuturesUnordered::new();

        while written < logical_len {
            while futs.len() >= allowed {
                let Some(done) = futs.next().await else { break };
                done?;
            }

            let Some(b) = src.next_payload().await? else {
                return Err(anyhow!(
                    "upload body ended early: got {} bytes, expected {}",
                    written,
                    logical_len
                ));
            };

            if b.is_empty() {
                continue;
            }

            let remaining = (logical_len - written) as usize;
            if b.len() > remaining {
                return Err(anyhow!(
                    "upload body longer than expected: next chunk={}, remaining={}",
                    b.len(),
                    remaining
                ));
            }

            let off = written;
            written += b.len() as u64;

            let file2 = file.clone();
            futs.push(async move {
                // Ensure full write.
                let (res, _buf) = file2.write_all_at(BytesBuf(b), off).await;
                res.map_err(|e| anyhow!("write_all_at failed at off={off}: {e}"))?;
                Ok::<(), anyhow::Error>(())
            });
        }

        while let Some(done) = futs.next().await {
            done?;
        }

        // Make sure there is no extra payload (and drain framing / EOF).
        // - Plain: enforce EOF (no extra bytes beyond Content-Length).
        // - Aws: drain the remainder of the encoded stream (safe keep-alive).
        src.ensure_done().await.map_err(|e| anyhow!("{e}"))?;

        // Ensure final file size is exactly logical_len (fallocate may have extended it).
        ftruncate_fd(file.as_raw_fd(), logical_len)?;
        return Ok(());
    }

    // -------------------------
    // Direct I/O path: read into aligned pooled buffers and pad last write.
    // -------------------------
    enum DirectSrc<S> {
        Plain(PlainFrameReader<S>),
        Aws(aws_chunked::Decoder<S>),
    }

    impl<S> DirectSrc<S>
    where
        S: Stream<Item = io::Result<Bytes>> + Unpin,
    {
        async fn read_exact_payload(&mut self, dst: &mut [u8]) -> io::Result<()> {
            match self {
                DirectSrc::Plain(p) => p.read_exact_payload(dst).await,
                DirectSrc::Aws(d) => d.read_exact_payload(dst).await,
            }
        }

        async fn drain(self) -> io::Result<()> {
            match self {
                DirectSrc::Plain(p) => p.ensure_eof().await,
                DirectSrc::Aws(d) => d.drain_to_eof().await,
            }
        }
    }

    let mut src = if is_streaming_sigv4 {
        DirectSrc::Aws(aws_chunked::Decoder::new(data_stream))
    } else {
        DirectSrc::Plain(PlainFrameReader::new(data_stream))
    };

    let mut off: u64 = 0;
    let mut futs: FuturesUnordered<_> = FuturesUnordered::new();

    while off < logical_len {
        // throttle
        while futs.len() >= allowed {
            let Some(done) = futs.next().await else { break };
            done?;
        }

        let remaining = (logical_len - off) as usize;
        let real_len = std::cmp::min(chunk, remaining);

        let write_len = align_up(real_len as u64, a) as usize;

        let buf = pool.take();
        let mut pooled = PooledBuf::new(pool.clone(), buf);

        // Read decoded payload bytes.
        src.read_exact_payload(&mut pooled.as_mut_bytes()[..real_len])
            .await
            .map_err(|e| anyhow!("read payload failed: {e}"))?;

        // Pad tail to aligned write size.
        if write_len > real_len {
            pooled.as_mut_bytes()[real_len..write_len].fill(0);
        }

        let slice = pooled.slice(..write_len);
        let file2 = file.clone();
        let off2 = off;

        futs.push(async move {
            let (res, _slice) = file2.write_all_at(slice, off2).await;
            res.map_err(|e| anyhow!("write_all_at failed at off={off2}: {e}"))?;
            Ok::<(), anyhow::Error>(())
        });

        off += real_len as u64;
    }

    while let Some(done) = futs.next().await {
        done?;
    }

    // Drain any remaining encoded bytes (e.g. aws-chunked terminator/trailers).
    src.drain().await.map_err(|e| anyhow!("{e}"))?;

    // Truncate away the padded tail.
    ftruncate_fd(file.as_raw_fd(), logical_len)?;
    Ok(())
}
