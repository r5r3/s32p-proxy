use anyhow::{anyhow, Result};
use bytes::Bytes;
use futures_util::stream::{FuturesOrdered, StreamExt};
use http_body_util::StreamBody;
use hyper::body::{Body, Frame};
use libc::O_DIRECT;
use std::convert::Infallible;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_uring::buf::BoundedBuf;

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
fn align_up(x: u64, a: u64) -> u64 { ((x + a - 1) / a) * a }

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
) -> Result<impl Body<Data = Bytes, Error = Infallible>> {
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(cfg.inflight * 2);

    tokio_uring::spawn(async move {
        if let Err(e) = stream_range_task(path, file_size, want, cfg, pool, tx).await {
            tracing::warn!(error = %e, "stream task failed");
        }
    });

    Ok(StreamBody::new(ReceiverStream::new(rx)))
}

async fn stream_range_task(
    path: PathBuf,
    file_size: u64,
    want: ByteRange,
    cfg: StreamCfg,
    pool: Arc<BufPool>,
    mut out: mpsc::Sender<Result<Frame<Bytes>, Infallible>>,
) -> Result<()> {
    let chunk = cfg.chunk_size;
    let inflight = cfg.inflight.max(1);

    let a = ALIGN as u64;

    let mut use_direct = cfg.direct_io;
    if use_direct && (chunk % ALIGN != 0) {
        tracing::warn!(chunk, "direct_io enabled but chunk not aligned; disabling direct_io for this request");
        use_direct = false;
    }

    let file_size_aligned = align_down(file_size, a);
    let mut segments: Vec<(bool, u64, u64)> = Vec::new();

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
            file,
            seg_start,
            seg_end,
            want.start,
            want.end_excl,
            chunk,
            inflight,
            pool.clone(),
            &mut out,
        ).await?;
    }

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
) -> Result<()> {
    let chunks_total = ((seg_end - seg_start) + chunk_size as u64 - 1) / chunk_size as u64;
    let inflight = std::cmp::min(inflight, chunks_total.max(1) as usize);

    let mut futs: FuturesOrdered<_> = FuturesOrdered::new();
    let mut next_off = seg_start;

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
        let Some(bytes) = res? else { break };

        if !bytes.is_empty() {
            if out.send(Ok(Frame::data(bytes))).await.is_err() {
                return Ok(());
            }
        }

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

