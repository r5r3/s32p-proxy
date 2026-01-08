use anyhow::{anyhow, Result};
use bytes::{Bytes, Buf};
use futures_util::Stream;
use futures_util::stream::{FuturesOrdered, FuturesUnordered, StreamExt, TryStreamExt};
use http_body_util::{StreamBody, BodyExt};
use hyper::body::{Body, Incoming, Frame};
use libc::O_DIRECT;
use std::convert::Infallible;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, FileExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io;
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;

use crate::buffer::{BufPool, PooledBuf, SliceOwner, ALIGN};

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

fn align_down(x: u64, a: u64) -> u64 { (x / a) * a }
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

    Ok(Some(ByteRange { start, end_excl: end_incl + 1 }))
}

/// Stream a range from file as a Hyper body (Tokio runtime + spawn_blocking pread).
pub async fn stream_range_body(
    path: PathBuf,
    file_size: u64,
    want: ByteRange,
    cfg: StreamCfg,
    pool: Arc<BufPool>,
    io_sem: Arc<Semaphore>,
    io_total: usize,
) -> Result<impl Body<Data = Bytes, Error = Infallible>> {
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(cfg.inflight.max(1) * 2);

    tokio::spawn(async move {
        if let Err(e) = stream_range_task(path, file_size, want, cfg, pool, io_sem, io_total, tx).await {
            tracing::warn!(error = %e, "stream task failed");
        }
    });

    Ok(StreamBody::new(ReceiverStream::new(rx)))
}

fn effective_end_for_scheduling(
    file_size: u64,
    seg_start: u64,
    seg_end: u64,
    _chunk_size: usize,
    direct: bool,
) -> u64 {
    if !direct {
        return seg_end;
    }

    let a = ALIGN as u64;
    if file_size == 0 {
        return seg_start;
    }

    let work_end = align_down(file_size.saturating_sub(1), a) + a;
    let capped = std::cmp::min(seg_end, work_end);
    if capped < seg_start { seg_start } else { capped }
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

    if io_out > io_total / 2 {
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

    let mut direct = cfg.direct_io;
    if direct && (chunk % ALIGN != 0) {
        tracing::warn!(chunk, "direct_io enabled but chunk not aligned; disabling direct_io for this request");
        direct = false;
    }

    let (seg_start, seg_end) = if direct {
        (align_down(want.start, a), align_up(want.end_excl, a))
    } else {
        (want.start, want.end_excl)
    };

    if seg_start >= seg_end {
        return Ok(());
    }

    let eff_end = effective_end_for_scheduling(file_size, seg_start, seg_end, chunk, direct);
    let needed = chunks_needed(seg_start, eff_end, chunk);
    if needed == 0 {
        return Ok(());
    }

    let base = std::cmp::min(inflight_cfg, needed);
    let available = io_sem.available_permits();
    let mut allowed = per_file_permits(base, io_total.max(1), available);
    allowed = allowed.clamp(1, base);

    let _permits = io_sem
        .clone()
        .acquire_many_owned(allowed as u32)
        .await
        .map_err(|_| anyhow!("io permit semaphore closed"))?;

    let std_file = open_std_file(&path, direct)?;
    let file = Arc::new(std_file);

    stream_segment(
        file,
        file_size,
        seg_start,
        seg_end,
        want.start,
        want.end_excl,
        chunk,
        allowed,
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
    file: Arc<std::fs::File>,
    pooled: PooledBuf,
    off: u64,
    len: usize,
    want_start: u64,
    want_end: u64,
) -> Result<Option<Bytes>> {
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
        return Ok(None);
    }

    let mut bytes = Bytes::from_owner(SliceOwner::new(pooled, 0, n));

    let chunk_start = std::cmp::max(want_start, off);
    let chunk_end = std::cmp::min(want_end, off + n as u64);

    if chunk_start >= chunk_end {
        return Ok(Some(Bytes::new()));
    }

    let i0 = (chunk_start - off) as usize;
    let i1 = (chunk_end - off) as usize;
    bytes = bytes.slice(i0..i1);
    Ok(Some(bytes))
}

async fn stream_segment(
    file: Arc<std::fs::File>,
    file_size: u64,
    seg_start: u64,
    seg_end: u64,
    want_start: u64,
    want_end: u64,
    chunk_size: usize,
    inflight: usize,
    direct: bool,
    pool: Arc<BufPool>,
    out: &mut mpsc::Sender<Result<Frame<Bytes>, Infallible>>,
) -> Result<()> {
    let a = ALIGN as u64;
    let mut next_off = seg_start;

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

    let chunks_total = ((effective_end - seg_start) + chunk_size as u64 - 1) / chunk_size as u64;
    let inflight = std::cmp::min(inflight.max(1), chunks_total.max(1) as usize);

    let mut futs: FuturesOrdered<_> = FuturesOrdered::new();

    let submit_len = |off: u64| -> usize {
        let remain = effective_end.saturating_sub(off);
        let mut len = std::cmp::min(chunk_size as u64, remain) as usize;

        if direct {
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

    for _ in 0..inflight {
        if next_off >= effective_end {
            break;
        }
        let len = submit_len(next_off);

        let buf = pool.take();
        let pooled = PooledBuf::new(pool.clone(), buf);

        let off = next_off;
        futs.push_back(read_one(file.clone(), pooled, off, len, want_start, want_end));
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

            let off = next_off;
            futs.push_back(read_one(file.clone(), pooled, off, len, want_start, want_end));
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
        Self { stream, buf: Bytes::new(), done: false }
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
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "body shorter than expected"));
            }

            let n = dst.len().min(self.buf.len());
            dst[..n].copy_from_slice(&self.buf[..n]);
            dst = &mut dst[n..];
            self.buf.advance(n);
        }
        Ok(())
    }

    async fn ensure_eof(mut self) -> io::Result<()> {
        while let Some(item) = self.stream.next().await {
            let b = item?;
            if !b.is_empty() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "body longer than expected"));
            }
        }
        Ok(())
    }
}

async fn try_preallocate(fd: std::os::unix::io::RawFd, len: u64) -> Result<()> {
    if len == 0 {
        return Ok(());
    }

    tokio::task::spawn_blocking(move || -> Result<()> {
        // Prefer posix_fallocate for portability; treat unsupported as non-fatal.
        let rc = unsafe { libc::posix_fallocate(fd, 0, len as libc::off_t) };
        if rc == 0 {
            return Ok(());
        }

        if rc == libc::EOPNOTSUPP
            || rc == libc::ENOSYS
            || rc == libc::EINVAL
            || rc == libc::ENOTSUP
            || rc == libc::EBADF
        {
            tracing::debug!(rc, "posix_fallocate not supported; continuing without preallocation");
            Ok(())
        } else {
            Err(anyhow!("posix_fallocate({len}) failed: {}", io::Error::from_raw_os_error(rc)))
        }
    })
    .await
    .map_err(|e| anyhow!("prealloc task join error: {e}"))?
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
    enum State { NeedHeader, NeedData, NeedCrlf, NeedTrailers, Done }

    pub struct Decoder<S> {
        stream: S,
        buf: Bytes,
        pending: Bytes,
        scratch: Vec<u8>,
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
                pending: Bytes::new(),
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
                if let Some(pos) = self.buf.iter().position(|&c| c == b'\n') {
                    let line = self.buf.split_to(pos + 1);
                    if self.scratch.is_empty() {
                        return Ok(line);
                    }
                    self.scratch.extend_from_slice(&line);
                    return Ok(Bytes::copy_from_slice(&self.scratch));
                }

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
            let line = line.strip_suffix(b"\n").unwrap_or(line);
            let line = line.strip_suffix(b"\r").unwrap_or(line);

            let hex_part = line.split(|&c| c == b';').next().unwrap_or(&[]);
            if hex_part.is_empty() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "aws-chunked: empty chunk size"));
            }

            let s = std::str::from_utf8(hex_part)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "aws-chunked: non-utf8 size"))?;

            usize::from_str_radix(s, 16).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, format!("aws-chunked: invalid hex chunk size: {s}"))
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
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "aws-chunked: missing/invalid CRLF"));
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
            }
        }

        async fn next_payload_raw(&mut self) -> io::Result<Option<Bytes>> {
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
                            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "aws-chunked: unexpected EOF in chunk data"));
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

        pub async fn read_exact_payload(&mut self, mut dst: &mut [u8]) -> io::Result<()> {
            while !dst.is_empty() {
                if !self.pending.is_empty() {
                    let n = dst.len().min(self.pending.len());
                    dst[..n].copy_from_slice(&self.pending[..n]);
                    dst = &mut dst[n..];
                    self.pending.advance(n);
                    continue;
                }

                match self.next_payload_raw().await? {
                    None => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "aws-chunked: decoded payload shorter than expected")),
                    Some(b) => {
                        if b.is_empty() { continue; }
                        let n = dst.len().min(b.len());
                        dst[..n].copy_from_slice(&b[..n]);
                        dst = &mut dst[n..];
                        if n < b.len() {
                            self.pending = b.slice(n..);
                        }
                    }
                }
            }
            Ok(())
        }

        pub async fn drain_to_eof(mut self) -> io::Result<()> {
            while let Some(item) = self.stream.next().await {
                let _ = item?;
            }
            Ok(())
        }
    }
}

pub async fn write_object_body_to_file(
    body: Incoming,
    path: PathBuf,
    logical_len: u64,
    is_streaming_sigv4: bool,
    cfg: StreamCfg,
    pool: Arc<BufPool>,
    io_sem: Arc<Semaphore>,
    io_total: usize,
) -> Result<()> {
    use io_uring::{opcode, types, IoUring};
    use std::collections::VecDeque;
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc as StdArc;
    use std::thread;
    use tokio::sync::{mpsc, oneshot};

    let chunk = cfg.chunk_size;
    let inflight_cfg = cfg.inflight.max(1);
    let a = ALIGN as u64;

    // Decide direct I/O
    let mut direct = cfg.direct_io && logical_len > chunk as u64;
    if direct && (chunk % ALIGN != 0) {
        tracing::warn!(
            chunk,
            "direct_io enabled but chunk not aligned; disabling direct_io for this upload"
        );
        direct = false;
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow!("create_dir_all {}: {e}", parent.display()))?;
    }

    let file = {
        let mut oo = OpenOptions::new();
        oo.write(true).create(true).truncate(true);
        if direct {
            oo.custom_flags(O_DIRECT);
        }
        oo.open(&path)
            .map_err(|e| anyhow!("open {}: {e}", path.display()))?
    };

    // Preallocate best-effort
    let prealloc_len = if direct { align_up(logical_len, a) } else { logical_len };
    try_preallocate(file.as_raw_fd(), prealloc_len).await?;

    if logical_len == 0 {
        ftruncate_fd(file.as_raw_fd(), 0)?;
        return Ok(());
    }

    // Per-file depth and permits
    let needed_chunks = ((logical_len + chunk as u64 - 1) / chunk as u64) as usize;
    let base = std::cmp::min(inflight_cfg, needed_chunks.max(1));
    let available = io_sem.available_permits();
    let mut allowed = per_file_permits(base, io_total.max(1), available);
    allowed = allowed.clamp(1, base);

    let _permits = io_sem
        .clone()
        .acquire_many_owned(allowed as u32)
        .await
        .map_err(|_| anyhow!("io permit semaphore closed"))?;

    // -------------------------
    // Producer -> Writer channel
    // -------------------------

    struct WorkItem {
        off: u64,
        write_len: usize, // direct: aligned tail; buffered: exact
        pooled: PooledBuf,
    }

    // Slack keeps SQ full and reduces producer/writer ping-pong
    let queue_cap = (allowed * 4).max(8);
    let (tx, mut rx) = mpsc::channel::<WorkItem>(queue_cap);

    let cancel = StdArc::new(AtomicBool::new(false));
    let cancel_w = cancel.clone();

    let (done_tx, done_rx) = oneshot::channel::<Result<()>>();
    let fd: RawFd = file.as_raw_fd();

    // io_uring depth cap
    let depth: usize = allowed.min(128).max(1);

    thread::spawn(move || {
        fn submit_item(
            ring: &mut IoUring,
            slots: &mut [Option<WorkItem>],
            inflight: &mut usize,
            fd: RawFd,
            id: usize,
            item: WorkItem,
        ) -> Result<()> {
            let WorkItem { off, write_len, pooled } = item;

            // Keep buffer alive until CQE
            let ptr = pooled.as_bytes().as_ptr();
            let len = write_len as u32;

            slots[id] = Some(WorkItem { off, write_len, pooled });

            let op = opcode::Write::new(types::Fd(fd), ptr, len)
                .offset(off)
                .build()
                .user_data(id as u64);

            unsafe {
                ring.submission()
                    .push(&op)
                    .map_err(|_| anyhow!("io_uring SQ full"))?;
            }

            *inflight += 1;
            Ok(())
        }

        fn reap_all(
            ring: &mut IoUring,
            slots: &mut [Option<WorkItem>],
            free: &mut VecDeque<usize>,
            inflight: &mut usize,
            first_err: &mut Option<anyhow::Error>,
            cancel: &AtomicBool,
        ) {
            let mut cq = ring.completion();
            while let Some(cqe) = cq.next() {
                let id = cqe.user_data() as usize;
                let res = cqe.result();

                let item = slots.get_mut(id).and_then(|s| s.take());
                free.push_back(id);
                *inflight = inflight.saturating_sub(1);

                if first_err.is_some() {
                    drop(item);
                    continue;
                }

                let Some(item) = item else {
                    *first_err = Some(anyhow!("io_uring completion for unknown id={id}"));
                    cancel.store(true, Ordering::Relaxed);
                    continue;
                };

                if res < 0 {
                    let errno = -res;
                    *first_err = Some(anyhow!(
                        "io_uring write failed at off={}: errno={errno}",
                        item.off
                    ));
                    cancel.store(true, Ordering::Relaxed);
                    continue;
                }

                let n = res as usize;
                if n != item.write_len {
                    *first_err = Some(anyhow!(
                        "short io_uring write at off={}: wrote {n}, expected {}",
                        item.off,
                        item.write_len
                    ));
                    cancel.store(true, Ordering::Relaxed);
                    continue;
                }

                drop(item);
            }
        }

        let mut ring = match IoUring::new(depth as u32) {
            Ok(r) => r,
            Err(e) => {
                cancel_w.store(true, Ordering::Relaxed);
                let _ = done_tx.send(Err(anyhow!("IoUring::new({depth}) failed: {e}")));
                return;
            }
        };

        let mut slots: Vec<Option<WorkItem>> = Vec::with_capacity(depth);
        slots.resize_with(depth, || None);

        let mut free: VecDeque<usize> = (0..depth).collect();
        let mut inflight: usize = 0;
        let mut rx_closed = false;
        let mut first_err: Option<anyhow::Error> = None;

        loop {
            // Always reap everything available first (non-blocking).
            reap_all(
                &mut ring,
                &mut slots,
                &mut free,
                &mut inflight,
                &mut first_err,
                &cancel_w,
            );

            // If failed: stop submitting, drain channel (to unblock producer), and drain inflight ops.
            if first_err.is_some() {
                // Drain queued work without submitting
                while !rx_closed {
                    match rx.try_recv() {
                        Ok(w) => drop(w),
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            rx_closed = true;
                            break;
                        }
                    }
                }

                // Need to drain in-flight writes to safely drop buffers.
                if inflight > 0 {
                    // Allowed here: "rx is closed and you need to drain" semantics applies
                    // (we also drain on error).
                    if let Err(e) = ring.submit_and_wait(1) {
                        // keep original error if present; otherwise record this
                        if first_err.is_none() {
                            first_err = Some(anyhow!("io_uring submit_and_wait failed: {e}"));
                        }
                        break;
                    }
                    continue; // next iteration will reap_all()
                }

                // No inflight. Wait for producer to close (so it doesn’t block) then exit.
                if rx_closed {
                    break;
                }
                match rx.blocking_recv() {
                    Some(w) => drop(w),
                    None => {
                        rx_closed = true;
                        break;
                    }
                }
                continue;
            }

            // Fill SQ up to depth using try_recv (non-blocking).
            let mut pushed: usize = 0;

            while inflight < depth {
                let Some(id) = free.pop_front() else { break; };

                let work = match rx.try_recv() {
                    Ok(w) => w,
                    Err(mpsc::error::TryRecvError::Empty) => {
                        free.push_front(id);
                        break;
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        rx_closed = true;
                        free.push_front(id);
                        break;
                    }
                };

                // Push SQE (no submit yet)
                match submit_item(&mut ring, &mut slots, &mut inflight, fd, id, work) {
                    Ok(()) => pushed += 1,
                    Err(_) => {
                        // SQ full unexpectedly; put id back and break.
                        free.push_front(id);
                        // We'll rely on draining condition below if saturated.
                        break;
                    }
                }
            }

            // If we queued anything, submit once (batch).
            if pushed > 0 {
                if let Err(e) = ring.submit() {
                    first_err = Some(anyhow!("io_uring submit failed: {e}"));
                    cancel_w.store(true, Ordering::Relaxed);
                    continue;
                }
                // Reap again immediately (non-blocking)
                reap_all(
                    &mut ring,
                    &mut slots,
                    &mut free,
                    &mut inflight,
                    &mut first_err,
                    &cancel_w,
                );
                if first_err.is_some() {
                    continue;
                }
            }

            // Exit when channel closed and no inflight writes.
            if rx_closed && inflight == 0 {
                break;
            }

            // Only submit_and_wait when:
            // - saturated (inflight == depth), or
            // - rx is closed and we need to drain remaining inflight.
            if inflight == depth || (rx_closed && inflight > 0) {
                if let Err(e) = ring.submit_and_wait(1) {
                    first_err = Some(anyhow!("io_uring submit_and_wait failed: {e}"));
                    cancel_w.store(true, Ordering::Relaxed);
                }
                // next loop will reap_all()
                continue;
            }

            // Not saturated and rx not closed: block for one item to avoid busy spinning.
            if !rx_closed {
                match rx.blocking_recv() {
                    None => {
                        rx_closed = true;
                    }
                    Some(work) => {
                        if let Some(id) = free.pop_front() {
                            if let Err(e) =
                                submit_item(&mut ring, &mut slots, &mut inflight, fd, id, work)
                            {
                                free.push_front(id);
                                first_err = Some(e);
                                cancel_w.store(true, Ordering::Relaxed);
                                continue;
                            }
                            if let Err(e) = ring.submit() {
                                first_err = Some(anyhow!("io_uring submit failed: {e}"));
                                cancel_w.store(true, Ordering::Relaxed);
                                continue;
                            }
                            // Reap any immediate completions
                            reap_all(
                                &mut ring,
                                &mut slots,
                                &mut free,
                                &mut inflight,
                                &mut first_err,
                                &cancel_w,
                            );
                        } else {
                            // Shouldn't happen when inflight < depth, but be defensive.
                            drop(work);
                        }
                    }
                }
            }
        }

        let res = match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        };
        let _ = done_tx.send(res);
    });

    // -------------------------
    // Producer (async): decode + enqueue
    // -------------------------

    let data_stream = body.into_data_stream().map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("body read error: {e}"))
    });

    enum Src<S> {
        Plain(PlainFrameReader<S>),
        Aws(aws_chunked::Decoder<S>),
    }

    impl<S> Src<S>
    where
        S: Stream<Item = io::Result<Bytes>> + Unpin,
    {
        async fn read_exact_payload(&mut self, dst: &mut [u8]) -> io::Result<()> {
            match self {
                Src::Plain(p) => p.read_exact_payload(dst).await,
                Src::Aws(d) => d.read_exact_payload(dst).await,
            }
        }

        async fn finish(self) -> io::Result<()> {
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

    let mut off: u64 = 0;
    let mut tx_dead = false;

    while off < logical_len {
        let remaining = (logical_len - off) as usize;
        let real_len = std::cmp::min(chunk, remaining);

        // Direct: aligned tail; Buffered: exact
        let write_len = if direct {
            if real_len == chunk {
                chunk
            } else {
                align_up(real_len as u64, a) as usize
            }
        } else {
            real_len
        };

        let buf = pool.take();
        let mut pooled = PooledBuf::new(pool.clone(), buf);

        src.read_exact_payload(&mut pooled.as_mut_bytes()[..real_len])
            .await
            .map_err(|e| anyhow!("read payload failed at off={off}: {e}"))?;

        if write_len > real_len {
            pooled.as_mut_bytes()[real_len..write_len].fill(0);
        }

        // Stop enqueueing on cancel or channel dead; but keep draining body.
        if !cancel.load(Ordering::Relaxed) && !tx_dead {
            let item = WorkItem { off, write_len, pooled };
            if tx.send(item).await.is_err() {
                tx_dead = true;
            }
        } else {
            drop(pooled);
        }

        off += real_len as u64;
    }

    drop(tx);

    // Drain/validate remaining HTTP framing (keep-alive correctness)
    src.finish().await.map_err(|e| anyhow!("{e}"))?;

    // Wait for writer
    match done_rx.await {
        Ok(r) => r?,
        Err(_) => return Err(anyhow!("io_uring writer thread terminated without status")),
    }

    // Truncate padded tail
    ftruncate_fd(file.as_raw_fd(), logical_len)?;
    Ok(())
}
