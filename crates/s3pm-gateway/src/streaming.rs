use anyhow::{anyhow, Result};
use bytes::{Bytes, Buf};
use futures_util::Stream;
use futures_util::stream::{FuturesOrdered, StreamExt, TryStreamExt};
use http_body_util::{StreamBody, BodyExt};
use hyper::body::{Body, Incoming, Frame};
use libc::O_DIRECT;
use std::convert::Infallible;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio_stream::wrappers::ReceiverStream;
use tokio::io;
use tokio::sync::{mpsc, Semaphore};

use crate::buffer::{BufPool, PooledBuf, SliceOwner, ALIGN};
use crate::uring_io::{UringIO, UringFileSender};

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

/// Stream a range from file as a Hyper body using the shared UringIO.
pub async fn stream_range_body(
    path: PathBuf,
    file_size: u64,
    want: ByteRange,
    cfg: StreamCfg,
    uring: Arc<UringIO>,
    pool: Arc<BufPool>,
) -> Result<impl Body<Data = Bytes, Error = Infallible>> {
    // the channel must bu able to hold the result of all inflight operations at once
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(cfg.inflight);

    tokio::spawn(async move {
        if let Err(e) = stream_range_task(path, file_size, want, cfg, uring, pool, tx).await {
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

async fn stream_range_task(
    path: PathBuf,
    file_size: u64,
    want: ByteRange,
    cfg: StreamCfg,
    uring: Arc<UringIO>,
    pool: Arc<BufPool>,
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

    // number of allowed IO operations inflight. we need enought buffers to 
    // directly submit the next batch.
    let allowed = std::cmp::min(inflight_cfg, needed);
    let stream_sem = Arc::new(Semaphore::new(allowed.max(1) + out.capacity().max(allowed)));

    let std_file = open_std_file(&path, direct)?;
    let file = Arc::new(std_file);

    let sender = uring.sender(file.clone());

    stream_segment(
        &sender,
        file_size,
        seg_start,
        seg_end,
        want.start,
        want.end_excl,
        chunk,
        allowed,
        direct,
        pool,
        stream_sem,
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
    sender: &UringFileSender,
    pooled: PooledBuf,
    off: u64,
    len: usize,
    want_start: u64,
    want_end: u64,
) -> Result<Option<Bytes>> {
    let (n, pooled) = sender.read(off, len, pooled).await?;

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
    sender: &UringFileSender,
    file_size: u64,
    seg_start: u64,
    seg_end: u64,
    want_start: u64,
    want_end: u64,
    chunk_size: usize,
    inflight: usize,
    direct: bool,
    pool: Arc<BufPool>,
    stream_sem: Arc<Semaphore>,
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

    // ---- Lustre WILLREAD: section-based, always one section ahead ----
    // Size of read ahead sections is always chunk_size * inflight
    #[cfg(feature = "lustre")]
    let section_bytes: u64 = (inflight as u64).saturating_mul(chunk_size as u64);

    #[cfg(feature = "lustre")]
    let mut next_section_to_advise: u64 = seg_start.saturating_add(section_bytes); // section #1

    #[cfg(feature = "lustre")]
    let mut advise_section = |start: u64| {
        if start >= effective_end {
            return;
        }
        let end = std::cmp::min(effective_end, start.saturating_add(section_bytes));
        let len = end.saturating_sub(start);
        if len > 0 {
            crate::lustre::advise_willread(sender.get_fd(), start, len);
        }
    };

    // Seed: advise the first section (section #0) once, so reads in section #0 are hinted.
    #[cfg(feature = "lustre")]
    advise_section(seg_start);


    // When we begin reading a section (i.e., submit its first read),
    // advise the *next* section (one section ahead).
    #[cfg(feature = "lustre")]
    let mut maybe_advise_next_section = |off: u64| {
        // We only trigger at section boundaries: seg_start + k*section_bytes
        if section_bytes == 0 {
            return;
        }
        let rel = off.saturating_sub(seg_start);
        if rel % section_bytes != 0 {
            return; // not a section boundary
        }

        // We are starting section k; advise section k+1 if that's the next pending section.
        let next_start = off.saturating_add(section_bytes);
        if next_start == next_section_to_advise && next_start < effective_end {
            advise_section(next_start);
            next_section_to_advise = next_section_to_advise.saturating_add(section_bytes);
        }
    };

    // Initial fill
    for _ in 0..inflight {
        if next_off >= effective_end {
            break;
        }

        #[cfg(feature = "lustre")]
        maybe_advise_next_section(next_off);

        let len = submit_len(next_off);

        let pooled = pool
            .acquire_for_stream(&stream_sem)
            .await
            .map_err(|_| anyhow!("buffer pool closed"))?;

        let off = next_off;
        futs.push_back(read_one(sender, pooled, off, len, want_start, want_end));

        next_off = next_off.saturating_add(len as u64);
    }

    while let Some(res) = futs.next().await {
        let Some(bytes) = res? else { break; };

        // Send CURRENT bytes
        if !bytes.is_empty() {
            if out.send(Ok(Frame::data(bytes))).await.is_err() {
                return Ok(());
            }
        }

        // Plan and submit NEXT read
        if next_off < effective_end {
            #[cfg(feature = "lustre")]
            maybe_advise_next_section(next_off);
            
            let len = submit_len(next_off);

            let pooled = pool
                .acquire_for_stream(&stream_sem)
                .await
                .map_err(|_| anyhow!("buffer pool closed"))?;

            let off = next_off;
            futs.push_back(read_one(sender, pooled, off, len, want_start, want_end));

            next_off = next_off.saturating_add(len as u64);
        }
    }

    Ok(())
}

// -------------------------
// Upload path (unchanged except UringIO type)
// -------------------------

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

fn try_preallocate(fd: RawFd, len: u64) -> Result<()> {
    if len == 0 {
        return Ok(());
    }

    let rc = unsafe { libc::fallocate(fd, 0, 0, len as libc::off_t) };
    if rc == 0 {
        return Ok(());
    }

    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if errno == libc::EOPNOTSUPP
        || errno == libc::ENOSYS
        || errno == libc::EINVAL
        || errno == libc::ENOTSUP
    {
        tracing::debug!(errno, "fallocate not supported; setting size with ftruncate.");

        // try to use ftruncate instead
        return ftruncate_fd(fd, len);
    } else {
        Err(anyhow!("posix_fallocate({len}) failed: {}", errno))
    }
}

fn ftruncate_fd(fd: RawFd, len: u64) -> Result<()> {
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
    uring: Arc<UringIO>,
    pool: Arc<BufPool>,
) -> Result<()> {
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
    let file = Arc::new(file);

    // Preallocate best-effort
    let prealloc_len = if direct { align_up(logical_len, a) } else { logical_len };
    try_preallocate(file.as_raw_fd(), prealloc_len)?;

    if logical_len == 0 {
        ftruncate_fd(file.as_raw_fd(), 0)?;
        return Ok(());
    }

    // Lustre: best-effort lockahead hint for the whole file range we expect to write.
    #[cfg(feature = "lustre")]
    {
        crate::lustre::advise_locknoexpand(file.as_raw_fd(), 0, prealloc_len);
        crate::lustre::advise_lockahead_write(file.as_raw_fd(), 0, prealloc_len);
    }

    // Per-file depth / permits
    let needed_chunks = ((logical_len + chunk as u64 - 1) / chunk as u64) as usize;
    let allowed = std::cmp::min(inflight_cfg, needed_chunks.max(1));
    let stream_sem = Arc::new(Semaphore::new(allowed.max(1)));

    // Per-request sender (no per-request ring/thread)
    let sender = uring.sender(file.clone());
    let cancel = sender.cancel_token().clone();

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

        let write_len = if direct {
            if real_len == chunk {
                chunk
            } else {
                align_up(real_len as u64, a) as usize
            }
        } else {
            real_len
        };

        let mut pooled = pool
            .acquire_for_stream(&stream_sem)
            .await
            .map_err(|_| anyhow!("buffer pool closed"))?;

        src.read_exact_payload(&mut pooled.as_mut_bytes()[..real_len])
            .await
            .map_err(|e| anyhow!("read payload failed at off={off}: {e}"))?;

        if write_len > real_len {
            tracing::debug!("zero-padding {} bytes at offset {}", write_len - real_len, off);
            pooled.as_mut_bytes()[real_len..write_len].fill(0);
        }

        // Even if cancelled, keep consuming body to keep the HTTP connection correct.
        // But stop enqueueing once writer has failed / channel closed.
        if tx_dead || cancel.is_cancelled() {
            drop(pooled);
        } else {
            // bounded async backpressure; also abort on cancellation
            tokio::select! {
                r = sender.write(off, write_len, pooled) => {
                    if r.is_err() { tx_dead = true; }
                }
                _ = cancel.cancelled() => {
                    // send future is dropped; WriteItem (and pooled) are dropped -> buffer returned to pool
                    tx_dead = true;
                }
            }
        }

        off += real_len as u64;
    }

    sender.close();

    // Drain/validate remaining HTTP framing for keep-alive correctness
    src.finish().await.map_err(|e| anyhow!("{e}"))?;

    // Wait for per-request completion
    sender.wait().await?;

    // Truncate padded tail
    ftruncate_fd(file.as_raw_fd(), logical_len)?;
    Ok(())
}
