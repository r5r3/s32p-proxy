use aligned_buffer::UniqueAlignedBuffer;
use crossbeam_queue::ArrayQueue;
use std::sync::Arc;

/// Fixed alignment for now (good default for O_DIRECT)
pub const ALIGN: usize = 4096;

/// Pool buffer type (aligned)
pub type ABuf = UniqueAlignedBuffer<ALIGN>;

/// A global pool of fixed-size aligned buffers (lock-free, sync API).
pub struct BufPool {
    chunk_size: usize,
    q: Arc<ArrayQueue<ABuf>>,
}

impl BufPool {
    pub fn new(chunk_size: usize, pool_size: usize) -> Self {
        Self {
            chunk_size,
            q: Arc::new(ArrayQueue::new(pool_size)),
        }
    }

    /// Warm the pool with `n` buffers (touch memory once at startup).
    pub fn warm(&self, n: usize) {
        for _ in 0..n {
            let mut b = ABuf::with_capacity(self.chunk_size);
            b.resize(self.chunk_size, 0);
            let _ = self.q.push(b);
        }
    }

    /// Get a buffer from the pool or allocate a new one if empty.
    #[inline]
    pub fn take(&self) -> ABuf {
        if let Some(b) = self.q.pop() {
            return b;
        }

        let mut b = ABuf::with_capacity(self.chunk_size);
        b.resize(self.chunk_size, 0);
        b
    }

    #[inline]
    pub fn put_back(&self, b: ABuf) {
        let _ = self.q.push(b);
    }
}

/// A pooled buffer wrapper that returns the ABuf to the pool on Drop.
pub struct PooledBuf {
    pool: Arc<BufPool>,
    buf: Option<ABuf>,
}

impl PooledBuf {
    pub fn new(pool: Arc<BufPool>, buf: ABuf) -> Self {
        Self {
            pool,
            buf: Some(buf),
        }
    }

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
        }
    }
}

/// Owner type used for zero-copy `Bytes::from_owner(...)`.
/// When the Bytes is dropped, the underlying `PooledBuf` is dropped and returned to the pool.
pub struct SliceOwner {
    pooled: PooledBuf,
    start: usize,
    end: usize,
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
