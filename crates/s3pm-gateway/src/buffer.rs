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

    /// Read-only access (sometimes useful for debugging).
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

// SAFETY: memory is stable and initialized (we always keep len == init bytes).
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

/// Wrap a tokio-uring Slice so we can feed it into Bytes::from_owner without copying.
pub struct SliceOwner<T>(pub tokio_uring::buf::Slice<T>);

impl<T> AsRef<[u8]> for SliceOwner<T>
where
    tokio_uring::buf::Slice<T>: std::ops::Deref<Target = [u8]>,
{
    fn as_ref(&self) -> &[u8] {
        &*self.0
    }
}

