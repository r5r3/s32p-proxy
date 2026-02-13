use std::{
    convert::Infallible,
    os::unix::{fs::FileExt, io::AsRawFd},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Result, anyhow};
use bytes::{Buf, Bytes};
use futures_util::{
    Stream,
    stream::{FuturesOrdered, StreamExt, TryStreamExt},
};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Body, Frame, Incoming};
use s32p_support::utils::ByteRange;
use tokio::{
    io,
    sync::{Semaphore, mpsc},
};
use tokio_stream::wrappers::ReceiverStream;

use crate::{
    buffer::{ALIGN, BufPool, PooledBuf, SliceOwner},
    fs_helpers::{
        LustreStriping, OpenDirect, OpenMode, align_down, align_up, ftruncate_file, open_file,
        try_preallocate_range,
    },
    uring_io::{UringFileSender, UringIO},
};

#[derive(Clone)]
pub struct StreamCfg {
    pub chunk_size: usize,
    pub inflight:   usize,
    pub direct_io:  bool,
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
        tracing::warn!(
            chunk,
            "direct_io enabled but chunk not aligned; disabling direct_io for this request"
        );
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

    // Largest aligned prefix we can safely read with O_DIRECT without crossing EOF.
    let aligned_size = align_down(file_size, a);

    // If direct, cap streaming end to aligned_size (NOT align_up(file_size)).
    let direct_end = if direct { std::cmp::min(seg_end, aligned_size) } else { seg_end };

    // If there is nothing to do in the direct segment, skip it.
    if direct_end > seg_start {
        let eff_end = direct_end;
        let needed = chunks_needed(seg_start, eff_end, chunk);
        if needed == 0 {
            return Ok(());
        }

        let allowed = std::cmp::min(inflight_cfg, needed);
        let stream_sem = Arc::new(Semaphore::new(allowed.max(1) + out.capacity().max(allowed)));

        let (std_file, _used_direct) =
            open_file(&path, OpenMode::Read, OpenDirect::Buffered, None)?;
        let file = Arc::new(std_file);
        let sender = uring.sender(file.clone());

        stream_segment(
            &sender,
            file_size,
            seg_start,
            direct_end, // <-- capped
            want.start,
            want.end_excl,
            chunk,
            allowed,
            direct,
            pool.clone(),
            stream_sem,
            &mut out,
        )
        .await?;
    }

    // Buffered tail (only if request actually needs bytes beyond direct_end).
    let tail_start = std::cmp::max(want.start, direct_end);
    let tail_end = std::cmp::min(want.end_excl, file_size);

    if tail_end > tail_start {
        let tail_len = (tail_end - tail_start) as usize;
        let b = read_tail_bytes(&path, pool.clone(), tail_start, tail_len).await?;

        if !b.is_empty() {
            let _ = out.send(Ok(Frame::data(b))).await;
        }
    }

    Ok(())
}

async fn read_tail_bytes(path: &Path, pool: Arc<BufPool>, off: u64, len: usize) -> Result<Bytes> {
    if len == 0 {
        return Ok(Bytes::new());
    }

    let (f, _used_direct) = open_file(path, OpenMode::Read, OpenDirect::Buffered, None)?;
    let file = Arc::new(f);

    let pooled = pool.acquire().await.map_err(|_| anyhow!("buffer pool closed"))?;

    let (n, pooled) = tokio::task::spawn_blocking(move || -> Result<(usize, PooledBuf)> {
        let mut pooled = pooled;
        let dst = &mut pooled.as_mut_bytes()[..len];
        let n = file
            .read_at(dst, off)
            .map_err(|e| anyhow!("tail read_at failed at off={off}: {e}"))?;
        Ok((n, pooled))
    })
    .await
    .map_err(|e| anyhow!("tail read join error: {e}"))??;

    if n == 0 {
        return Err(anyhow!("tail unexpected EOF at off={off}"));
    }

    tracing::debug!("tail read {} bytes", n);
    Ok(Bytes::from_owner(SliceOwner::new(pooled, 0, n)))
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

    // IMPORTANT: with O_DIRECT we must not issue reads that extend past EOF.
    // So only stream up to the *largest aligned prefix* of the file.
    // The remaining (non-aligned) tail must be handled separately (buffered, read_tail_bytes).
    let effective_end = if direct {
        let aligned_eof = align_down(file_size, a); // <= file_size, multiple of ALIGN
        std::cmp::min(seg_end, aligned_eof)
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
    let advise_section = |start: u64| {
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
        let Some(bytes) = res? else {
            break;
        };

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
    buf:    Bytes,
    done:   bool,
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

pub mod aws_chunked {
    use futures_util::Stream;

    use super::*;

    #[derive(Debug, Clone, Copy)]
    enum State {
        NeedHeader,
        NeedData,
        NeedCrlf,
        NeedTrailers,
        Done,
    }

    pub struct Decoder<S> {
        stream:             S,
        buf:                Bytes,
        pending:            Bytes,
        scratch:            Vec<u8>,
        state:              State,
        remaining_in_chunk: usize,
        eof:                bool,
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
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "aws-chunked: decoded payload shorter than expected",
                        ));
                    }
                    Some(b) => {
                        if b.is_empty() {
                            continue;
                        }
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

/// Destination for an upload write.
pub enum WriteObjectDest {
    /// Create/truncate and write the whole object starting at offset 0.
    Path { path: PathBuf, striping: Option<LustreStriping> },

    /// Write into an already-open file at a fixed start offset (no truncate).
    File { file: Arc<std::fs::File>, start_off: u64 },
}

/// For multipart (or any ranged write), we can only use O_DIRECT when:
/// - direct_io is enabled
/// - chunk_size is ALIGN-aligned
/// - start_off and len are ALIGN-aligned
/// - len >= chunk_size (avoid tiny O_DIRECT writes)
pub fn direct_io_ok_for_aligned_range(start_off: u64, len: u64, cfg: &StreamCfg) -> bool {
    let a = ALIGN as u64;

    if !cfg.direct_io {
        return false;
    }
    if cfg.chunk_size % ALIGN != 0 {
        return false;
    }
    if len < cfg.chunk_size as u64 {
        return false;
    }
    if (start_off % a) != 0 {
        return false;
    }
    if (len % a) != 0 {
        return false;
    }

    true
}

/// Combined upload writer:
/// - For `WriteObjectDest::Path`: creates/truncates file, may use O_DIRECT and padding, and truncates to `logical_len`.
/// - For `WriteObjectDest::File`: writes at `start_off` into an existing file, NEVER pads, and only uses O_DIRECT
///   when the offset+len are aligned and the caller opened the file accordingly.
pub async fn write_object_body(
    body: Incoming,
    dest: WriteObjectDest,
    logical_len: u64,
    is_streaming_sigv4: bool,
    cfg: StreamCfg,
    uring: Arc<UringIO>,
    pool: Arc<BufPool>,
) -> Result<()> {
    let chunk = cfg.chunk_size;
    let inflight_cfg = cfg.inflight.max(1);
    let a = ALIGN as u64;

    // Decide direct I/O (final decision used for scheduling/padding behavior).
    let mut direct = match &dest {
        WriteObjectDest::Path { .. } => cfg.direct_io && logical_len > chunk as u64,
        WriteObjectDest::File { start_off, .. } => {
            direct_io_ok_for_aligned_range(*start_off, logical_len, &cfg)
        }
    };

    if direct && (chunk % ALIGN != 0) {
        tracing::warn!(
            chunk,
            "direct_io enabled but chunk not aligned; disabling direct_io for this upload"
        );
        direct = false;
    }

    // Resolve file + start offset + whether we should truncate to logical_len at the end.
    let (file, start_off, truncate_to_logical) = match dest {
        WriteObjectDest::Path { path, striping } => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| anyhow!("create_dir_all {}: {e}", parent.display()))?;
            }

            let (std_file, _used_direct) = open_file(
                &path,
                OpenMode::WriteCreateTruncate,
                if direct { OpenDirect::Direct } else { OpenDirect::Buffered },
                striping,
            )
            .map_err(|e| anyhow!("open {}: {e}", path.display()))?;

            let file = Arc::new(std_file);

            // Preallocate best-effort. For O_DIRECT we may write an aligned tail,
            // so preallocate the aligned size.
            let prealloc_len = if direct { align_up(logical_len, a) } else { logical_len };
            try_preallocate_range(file.as_raw_fd(), 0, prealloc_len)?;

            (file, 0u64, true)
        }

        WriteObjectDest::File { file, start_off } => {
            // For existing-file writes, we NEVER pad. If direct is enabled, ensure we can
            (file, start_off, false)
        }
    };

    if logical_len == 0 {
        if truncate_to_logical {
            ftruncate_file(&file, 0)?;
        }
        return Ok(());
    }

    // Per-write depth / permits
    let needed_chunks = ((logical_len + chunk as u64 - 1) / chunk as u64) as usize;
    let allowed = std::cmp::min(inflight_cfg, needed_chunks.max(1));
    let stream_sem = Arc::new(Semaphore::new(allowed.max(1)));

    // Per-request sender (shared ring)
    let sender = uring.sender(file.clone());
    let cancel = sender.cancel_token().clone();

    // Source stream (plain or AWS-chunked SigV4 streaming)
    let data_stream = body
        .into_data_stream()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("body read error: {e}")));

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

    let mut off_in_obj: u64 = 0;
    let mut tx_dead = false;

    while off_in_obj < logical_len {
        let remaining = (logical_len - off_in_obj) as usize;
        let real_len = std::cmp::min(chunk, remaining);

        // For new-file + O_DIRECT we may need to pad the final (short) chunk.
        // For existing-file writes we MUST NOT pad (would corrupt layout).
        let write_len = if direct && truncate_to_logical {
            if real_len == chunk { chunk } else { align_up(real_len as u64, a) as usize }
        } else {
            // No padding path (includes multipart / existing-file writes).
            if direct {
                // Sanity: O_DIRECT requires aligned lengths/offsets.
                if (real_len as u64) % a != 0 {
                    return Err(anyhow!(
                        "direct_io requires aligned write length; got len={} at off={}",
                        real_len,
                        start_off + off_in_obj
                    ));
                }
            }
            real_len
        };

        let mut pooled = pool
            .acquire_for_stream(&stream_sem)
            .await
            .map_err(|_| anyhow!("buffer pool closed"))?;

        // Always read exactly the payload bytes (no padding in the HTTP read).
        src.read_exact_payload(&mut pooled.as_mut_bytes()[..real_len])
            .await
            .map_err(|e| anyhow!("read payload failed at off={}: {e}", start_off + off_in_obj))?;

        // Only pad for the new-file O_DIRECT tail case.
        if write_len > real_len {
            tracing::debug!(
                "zero-padding {} bytes at offset {}",
                write_len - real_len,
                start_off + off_in_obj
            );
            pooled.as_mut_bytes()[real_len..write_len].fill(0);
        }

        // Keep consuming the body even if cancelled; just stop enqueueing writes.
        if tx_dead || cancel.is_cancelled() {
            drop(pooled);
        } else {
            let dst_off = start_off.checked_add(off_in_obj).ok_or_else(|| {
                anyhow!("write offset overflow: start_off={start_off} off={off_in_obj}")
            })?;

            tokio::select! {
                r = sender.write(dst_off, write_len, pooled) => {
                    if r.is_err() { tx_dead = true; }
                }
                _ = cancel.cancelled() => {
                    tx_dead = true;
                }
            }
        }

        off_in_obj = off_in_obj.saturating_add(real_len as u64);
    }

    sender.close();

    // Drain/validate remaining HTTP framing for keep-alive correctness
    src.finish().await.map_err(|e| anyhow!("{e}"))?;

    // Wait for io_uring completion
    sender.wait().await?;

    // For new-file writes, ensure exact size (truncate away any O_DIRECT padding).
    if truncate_to_logical {
        ftruncate_file(&file, logical_len)?;
    }

    Ok(())
}

pub async fn copy_file_to_file(
    src_path: PathBuf,
    dst_path: PathBuf,
    file_size: u64,
    dst_striping: Option<LustreStriping>,
    cfg: StreamCfg,
    uring: Arc<UringIO>,
    pool: Arc<BufPool>,
) -> Result<()> {
    let chunk = cfg.chunk_size;
    let inflight_cfg = cfg.inflight.max(1);
    let a = ALIGN as u64;

    let mut direct = cfg.direct_io && file_size > chunk as u64;
    if direct && (chunk % ALIGN != 0) {
        tracing::warn!(
            chunk,
            "direct_io enabled but chunk not aligned; disabling direct_io for this copy"
        );
        direct = false;
    }

    if let Some(parent) = dst_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow!("create_dir_all {}: {e}", parent.display()))?;
    }

    // With O_DIRECT we must never issue reads past EOF. We'll copy only the aligned prefix via io_uring,
    // and handle any unaligned tail via read_tail_bytes (buffered) + one final padded O_DIRECT write.
    let aligned_size = if direct { align_down(file_size, a) } else { file_size };
    let needs_tail = direct && aligned_size < file_size;

    let (src_f, _src_used_direct) = open_file(
        &src_path,
        OpenMode::Read,
        if direct { OpenDirect::Direct } else { OpenDirect::Buffered },
        None,
    )?;
    let src_file = Arc::new(src_f);

    let (dst_f, _dst_used_direct) = open_file(
        &dst_path,
        OpenMode::WriteCreateTruncate,
        if direct { OpenDirect::Direct } else { OpenDirect::Buffered },
        dst_striping,
    )
    .map_err(|e| anyhow!("open {}: {e}", dst_path.display()))?;
    let dst_file = Arc::new(dst_f);

    let prealloc_len = if direct { align_up(file_size, a) } else { file_size };
    try_preallocate_range(dst_file.as_raw_fd(), 0, prealloc_len)?;

    if file_size == 0 {
        ftruncate_file(&dst_file, 0)?;
        return Ok(());
    }

    // Lustre: best-effort hints read for the full range.
    #[cfg(feature = "lustre")]
    crate::lustre::advise_willread(src_file.as_raw_fd(), 0, prealloc_len);

    // Only schedule aligned prefix through uring when direct I/O is active.
    let scheduled_size = aligned_size;

    let needed_chunks = if scheduled_size == 0 {
        0usize
    } else {
        ((scheduled_size + chunk as u64 - 1) / chunk as u64) as usize
    };
    let allowed = std::cmp::min(inflight_cfg, needed_chunks.max(1));
    let stream_sem = Arc::new(Semaphore::new(allowed.max(1)));

    let src_sender = uring.sender(src_file.clone());
    let dst_sender = uring.sender(dst_file.clone());

    let cancel_r = src_sender.cancel_token().clone();
    let cancel_w = dst_sender.cancel_token().clone();

    async fn read_for_copy(
        sender: &UringFileSender,
        pool: Arc<BufPool>,
        stream_sem: &Arc<Semaphore>,
        off: u64,
        read_len: usize,
        min_data_len: usize,
        write_len: usize,
    ) -> Result<(u64, usize, PooledBuf)> {
        let pooled = pool
            .acquire_for_stream(stream_sem)
            .await
            .map_err(|_| anyhow!("buffer pool closed"))?;

        let (n, mut pooled) = sender.read(off, read_len, pooled).await?;
        if n < min_data_len {
            return Err(anyhow!(
                "unexpected EOF while copying at off={off}: read {n}, need {min_data_len}"
            ));
        }

        if write_len > n {
            pooled.as_mut_bytes()[n..write_len].fill(0);
        }

        Ok((off, write_len, pooled))
    }

    let mut futs: FuturesOrdered<_> = FuturesOrdered::new();

    let mut next_off: u64 = 0;
    let mut had_err: Option<anyhow::Error> = None;

    let plan = |off: u64, end: u64, chunk: usize, direct: bool, a: u64| -> (usize, usize) {
        let remaining = (end - off) as usize;
        let real_len = std::cmp::min(chunk, remaining);
        let write_len = if direct {
            if real_len == chunk {
                chunk
            } else {
                // For the aligned prefix, remaining is always a multiple of ALIGN, so this is safe
                // and will not extend past `end`.
                align_up(real_len as u64, a) as usize
            }
        } else {
            real_len
        };
        (real_len, write_len)
    };

    // ---- Copy aligned prefix via io_uring (possibly empty) ----
    if scheduled_size > 0 {
        // Initial fill
        for _ in 0..allowed {
            if next_off >= scheduled_size {
                break;
            }
            let (real_len, write_len) = plan(next_off, scheduled_size, chunk, direct, a);
            futs.push_back(read_for_copy(
                &src_sender,
                pool.clone(),
                &stream_sem,
                next_off,
                write_len,
                real_len,
                write_len,
            ));
            next_off += real_len as u64;
        }

        while let Some(res) = futs.next().await {
            match res {
                Ok((off, write_len, pooled)) => {
                    if cancel_w.is_cancelled() || cancel_r.is_cancelled() {
                        drop(pooled);
                        had_err = had_err.or_else(|| Some(anyhow!("copy cancelled")));
                        break;
                    }

                    if let Err(e) = dst_sender.write(off, write_len, pooled).await {
                        had_err = Some(e);
                        cancel_w.cancel();
                        cancel_r.cancel();
                        break;
                    }
                }
                Err(e) => {
                    had_err = Some(e);
                    cancel_w.cancel();
                    cancel_r.cancel();
                    break;
                }
            }

            if next_off < scheduled_size && had_err.is_none() {
                let (real_len, write_len) = plan(next_off, scheduled_size, chunk, direct, a);
                futs.push_back(read_for_copy(
                    &src_sender,
                    pool.clone(),
                    &stream_sem,
                    next_off,
                    write_len,
                    real_len,
                    write_len,
                ));
                next_off += real_len as u64;
            }
        }
    }

    // ---- Tail handling for unaligned file sizes in direct I/O mode ----
    if had_err.is_none() && needs_tail {
        let tail_off = aligned_size;
        let tail_len = (file_size - tail_off) as usize;

        // Buffered read of the exact tail bytes (no O_DIRECT, no read past EOF).
        let tail = read_tail_bytes(&src_path, pool.clone(), tail_off, tail_len).await?;

        // Write tail into the direct destination as one final padded aligned write.
        // We will ftruncate() to file_size at the end to remove the padding.
        let write_len = align_up(tail_len as u64, a) as usize;

        let mut pooled = pool
            .acquire_for_stream(&stream_sem)
            .await
            .map_err(|_| anyhow!("buffer pool closed"))?;

        pooled.as_mut_bytes()[..tail_len].copy_from_slice(&tail);
        if write_len > tail_len {
            pooled.as_mut_bytes()[tail_len..write_len].fill(0);
        }

        if let Err(e) = dst_sender.write(tail_off, write_len, pooled).await {
            had_err = Some(e);
            cancel_w.cancel();
            cancel_r.cancel();
        }
    }

    // Ensure we stop submitting and wait for outstanding writes.
    dst_sender.close();
    let wait_res = dst_sender.wait().await;

    if let Some(e) = had_err {
        let _ = wait_res;
        return Err(e);
    }

    wait_res?;

    // Truncate padded tail (direct I/O) or enforce exact size.
    ftruncate_file(&dst_file, file_size)?;
    Ok(())
}
