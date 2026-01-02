use aligned_buffer::UniqueAlignedBuffer;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

/// Fixed alignment for now (good default for O_DIRECT)
pub const ALIGN: usize = 4096;

/// Pool buffer type (aligned)
pub type ABuf = UniqueAlignedBuffer<ALIGN>;

/// A global pool of fixed-size aligned buffers.
pub struct BufPool {
    chunk_size: usize,
    tx: mpsc::Sender<ABuf>,
    rx: Mutex<mpsc::Receiver<ABuf>>,
}

impl BufPool {
    pub fn new(chunk_size: usize, pool_size: usize) -> Self {
        let (tx, rx) = mpsc::channel(pool_size);
        Self {
            chunk_size,
            tx,
            rx: Mutex::new(rx),
        }
    }

    pub fn sender(&self) -> mpsc::Sender<ABuf> {
        self.tx.clone()
    }

    /// Warm the pool with `n` buffers (touch memory once at startup).
    pub fn warm(&self, n: usize) {
        for _ in 0..n {
            let mut b = ABuf::with_capacity(self.chunk_size);
            b.resize(self.chunk_size, 0);
            let _ = self.tx.try_send(b);
        }
    }

    /// Get a buffer from the pool or allocate a new one if empty.
    pub async fn take(&self) -> ABuf {
        {
            let mut rx = self.rx.lock().await;
            if let Ok(b) = rx.try_recv() {
                return b;
            }
        }

        let mut b = ABuf::with_capacity(self.chunk_size);
        b.resize(self.chunk_size, 0);
        b
    }

    pub fn put_back(&self, b: ABuf) {
        let _ = self.tx.try_send(b);
    }
}

/// A pooled buffer wrapper that returns the ABuf to the pool on Drop.
pub struct PooledBuf {
    pool: Arc<BufPool>,
    buf: Option<ABuf>,
}

impl PooledBuf {
    pub fn new(pool: Arc<BufPool>, buf: ABuf) -> Self {
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

