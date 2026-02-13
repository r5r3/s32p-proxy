use std::sync::Arc;

use aligned_buffer::UniqueAlignedBuffer;
use crossbeam_queue::ArrayQueue;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Fixed alignment for now (good default for O_DIRECT)
pub const ALIGN: usize = 4096;

/// Pool buffer type (aligned)
pub type ABuf = UniqueAlignedBuffer<ALIGN>;

/// A global pool of fixed-size aligned buffers (bounded).
pub struct BufPool {
    chunk_size: usize,
    q:          Arc<ArrayQueue<ABuf>>,
    // One permit per buffer that exists in the pool.
    // acquire() blocks when there are no buffers available.
    sem:        Arc<Semaphore>,
}

impl BufPool {
    pub fn new(chunk_size: usize, pool_size: usize) -> Self {
        Self {
            chunk_size,
            q: Arc::new(ArrayQueue::new(pool_size.max(1))),
            sem: Arc::new(Semaphore::new(0)),
        }
    }

    /// Warm the pool with `n` buffers (touch memory once at startup).
    /// Also "publishes" `n` permits.
    pub fn warm(&self, n: usize) {
        for _ in 0..n {
            let mut b = ABuf::with_capacity(self.chunk_size);
            b.resize(self.chunk_size, 0);
            self.q.push(b).expect("pool warm overflow");
        }
        self.sem.add_permits(n);
    }

    /// Acquire one buffer from the global pool (awaits if pool is empty).
    pub async fn acquire(self: &Arc<Self>) -> Result<PooledBuf, tokio::sync::AcquireError> {
        let global = self.sem.clone().acquire_owned().await?;
        let b = self.q.pop().expect("permit acquired but no buffer in queue");
        Ok(PooledBuf { pool: self.clone(), buf: Some(b), _global: global, _stream: None })
    }

    /// Acquire one buffer but also attach a per-stream inflight permit.
    pub async fn acquire_for_stream(
        self: &Arc<Self>,
        stream_sem: &Arc<Semaphore>,
    ) -> Result<PooledBuf, tokio::sync::AcquireError> {
        let stream = stream_sem.clone().acquire_owned().await?;
        let mut p = self.acquire().await?;
        p._stream = Some(stream);
        Ok(p)
    }

    #[inline]
    fn put_back(&self, b: ABuf) {
        // With strict bounding, this should never fail.
        self.q.push(b).expect("pool put_back overflow");
        // Releasing happens by dropping the OwnedSemaphorePermit in PooledBuf.
    }
}

/// A pooled buffer wrapper that returns the ABuf to the pool on Drop.
/// Also holds global + (optional) per-stream inflight permits.
pub struct PooledBuf {
    pool: Arc<BufPool>,
    buf:  Option<ABuf>,

    // One permit per global buffer in use
    _global: OwnedSemaphorePermit,
    // Optional: one permit per stream inflight buffer in use
    _stream: Option<OwnedSemaphorePermit>,
}

impl PooledBuf {
    /// Mutable access to the underlying initialized bytes (always len == chunk_size).
    #[inline]
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        self.buf.as_mut().unwrap().as_mut()
    }

    /// Immutable access to the full buffer (len == chunk_size).
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.buf.as_ref().unwrap().as_ref()
    }
}

impl Drop for PooledBuf {
    fn drop(&mut self) {
        if let Some(b) = self.buf.take() {
            self.pool.put_back(b);
            // permits are released automatically when `_global` / `_stream` drop
        }
    }
}

/// Owner type used for zero-copy `Bytes::from_owner(...)`.
pub struct SliceOwner {
    pooled: PooledBuf,
    start:  usize,
    end:    usize,
}

impl SliceOwner {
    pub fn new(pooled: PooledBuf, start: usize, end: usize) -> Self {
        Self { pooled, start, end }
    }
}

impl AsRef<[u8]> for SliceOwner {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.pooled.as_bytes()[self.start..self.end]
    }
}
