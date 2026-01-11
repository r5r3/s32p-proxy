use anyhow::{anyhow, Result};
use io_uring::{opcode, types, IoUring};
use std::collections::VecDeque;
use std::os::fd::AsRawFd;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::buffer::PooledBuf;

// -------------------------
// Shared session completion
// -------------------------

struct SessionInner {
    pending: AtomicUsize,
    closed: AtomicBool,
    err: Mutex<Option<anyhow::Error>>,
    done: Mutex<Option<oneshot::Sender<Result<()>>>>,
    cancel: CancellationToken,
}

impl SessionInner {
    fn new(cancel: CancellationToken) -> Self {
        Self {
            pending: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            err: Mutex::new(None),
            done: Mutex::new(None),
            cancel,
        }
    }

    fn set_done(&self, tx: oneshot::Sender<Result<()>>) {
        *self.done.lock().unwrap() = Some(tx);
    }

    fn on_submit(&self) {
        self.pending.fetch_add(1, Ordering::SeqCst);
    }

    fn on_complete(&self) {
        let prev = self.pending.fetch_sub(1, Ordering::SeqCst);
        if prev <= 1 {
            self.try_finish();
        }
    }

    fn on_dropped_without_cqe(&self) {
        // Used when we incremented pending but the item never makes it to the ring.
        self.on_complete();
    }

    fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.try_finish();
        } else {
            self.try_finish();
        }
    }

    fn set_error_once(&self, e: anyhow::Error) {
        let mut g = self.err.lock().unwrap();
        if g.is_none() {
            *g = Some(e);
            self.cancel.cancel();
        }
    }

    fn try_finish(&self) {
        if !self.closed.load(Ordering::SeqCst) {
            return;
        }
        if self.pending.load(Ordering::SeqCst) != 0 {
            return;
        }

        let tx_opt = self.done.lock().unwrap().take();
        let Some(tx) = tx_opt else { return; };

        let res = match self.err.lock().unwrap().take() {
            Some(e) => Err(e),
            None => Ok(()),
        };
        let _ = tx.send(res);
    }
}

// -------------------------
// Public API
// -------------------------

/// Single shared io_uring instance (one thread) for both reads and writes.
pub struct UringIO {
    depth: usize,
    tx: mpsc::Sender<Msg>,
    cancel: CancellationToken, // cancelled on fatal io_uring failure
}

/// Per-file/per-request sender that can submit both reads and writes.
/// Enforces a max in-flight cap across *both* read+write ops for this sender.
pub struct UringFileSender {
    tx: mpsc::Sender<Msg>,
    file: Arc<std::fs::File>,
    fd: RawFd,
    session: Arc<SessionInner>,
    cancel: CancellationToken,
    done_rx: Option<oneshot::Receiver<Result<()>>>,
}

impl UringIO {
    /// Spawn a single io_uring thread with `depth` slots.
    /// In your gateway, set this to your buffer pool size.
    pub fn spawn(depth: usize) -> Result<Self> {
        let depth = depth.max(1);
        let (tx, rx) = mpsc::channel::<Msg>(depth);
        let cancel = CancellationToken::new();
        let cancel_w = cancel.clone();

        // Startup handshake so spawn() can fail fast if IoUring::new fails.
        let (start_tx, start_rx) = std::sync::mpsc::channel::<Result<()>>();

        thread::spawn(move || {
            let mut ring = match IoUring::new(depth as u32) {
                Ok(r) => {
                    let _ = start_tx.send(Ok(()));
                    r
                }
                Err(e) => {
                    cancel_w.cancel();
                    let _ = start_tx.send(Err(anyhow!("IoUring::new({depth}) failed: {e}")));
                    return;
                }
            };

            io_thread(depth, &mut ring, rx, &cancel_w);
        });

        start_rx
            .recv()
            .map_err(|_| anyhow!("uring io thread failed to report startup"))??;

        Ok(Self { depth, tx, cancel })
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn cancel_token(&self) -> &CancellationToken {
        &self.cancel
    }

    /// Create a per-file sender
    pub fn sender(&self, file: Arc<std::fs::File>) -> UringFileSender {
        let session_cancel = self.cancel.child_token();
        let session = Arc::new(SessionInner::new(session_cancel.clone()));
        let (done_tx, done_rx) = oneshot::channel::<Result<()>>();
        session.set_done(done_tx);

        UringFileSender {
            tx: self.tx.clone(),
            fd: file.as_raw_fd(),
            file,
            session,
            cancel: session_cancel,
            done_rx: Some(done_rx),
        }
    }
}

impl UringFileSender {
    pub fn cancel_token(&self) -> &CancellationToken {
        &self.cancel
    }

    /// No more ops will be submitted for this sender.
    pub fn close(&self) {
        self.session.close();
    }

    /// get the fd for ladvise
    pub fn get_fd(&self) -> RawFd {
        self.fd
    }

    /// Submit a write at `off` for `write_len` bytes from `pooled`.
    pub async fn write(&self, off: u64, write_len: usize, pooled: PooledBuf) -> Result<()> {
        if self.cancel.is_cancelled() {
            return Err(anyhow!("uring sender cancelled"));
        }

        self.session.on_submit();

        let item = WriteItem {
            fd: self.fd,
            _file: self.file.clone(),
            off,
            len: write_len,
            pooled,
            session: self.session.clone(),
        };

        if self.tx.send(Msg::Submit(OpCode::Write(item))).await.is_err() {
            let e = anyhow!("uring io thread stopped");
            self.session.set_error_once(anyhow!("{e}"));
            self.session.on_dropped_without_cqe();
            return Err(e);
        }

        Ok(())
    }

    /// Submit a read at `off` for up to `read_len` bytes into `pooled`.
    /// Returns (nread, pooled) when CQE completes. `nread` may be 0 at EOF.
    pub async fn read(&self, off: u64, read_len: usize, pooled: PooledBuf) -> Result<(usize, PooledBuf)> {
        if self.cancel.is_cancelled() {
            return Err(anyhow!("uring sender cancelled"));
        }

        self.session.on_submit();

        let (done_tx, done_rx) = oneshot::channel::<Result<ReadDone>>();

        let item = ReadItem {
            fd: self.fd,
            _file: self.file.clone(),
            off,
            len: read_len,
            pooled,
            session: self.session.clone(),
            done: Some(done_tx),
        };

        if self.tx.send(Msg::Submit(OpCode::Read(item))).await.is_err() {
            let e = anyhow!("uring io thread stopped");
            self.session.set_error_once(anyhow!("{e}"));
            self.session.on_dropped_without_cqe();
            return Err(e);
        }

        tokio::select! {
            r = done_rx => {
                let done = r.map_err(|_| anyhow!("uring read completion channel closed"))??;
                Ok((done.n, done.pooled))
            }
            _ = self.cancel.cancelled() => {
                Err(anyhow!("uring sender cancelled"))
            }
        }
    }

    /// Wait for all submitted ops on this sender to complete (or error).
    /// (You typically use this for writes; reads usually await per-op.)
    pub async fn wait(mut self) -> Result<()> {
        self.session.close();

        let rx = self
            .done_rx
            .take()
            .ok_or_else(|| anyhow!("uring sender done receiver missing"))?;

        rx.await
            .map_err(|_| anyhow!("uring sender done channel closed"))?
    }
}

impl Drop for UringFileSender {
    fn drop(&mut self) {
        self.session.close();
    }
}

// -------------------------
// Internal op enum + items
// -------------------------

enum Msg {
    Submit(OpCode),
}

/// The single opcode enum used by the shared thread.
enum OpCode {
    Read(ReadItem),
    Write(WriteItem),
}

struct ReadItem {
    fd: RawFd,
    _file: Arc<std::fs::File>,
    off: u64,
    len: usize,
    pooled: PooledBuf,
    session: Arc<SessionInner>,
    done: Option<oneshot::Sender<Result<ReadDone>>>,
}

struct WriteItem {
    fd: RawFd,
    _file: Arc<std::fs::File>,
    off: u64,
    len: usize,
    pooled: PooledBuf,
    session: Arc<SessionInner>,
}

struct ReadDone {
    n: usize,
    pooled: PooledBuf,
}

// -------------------------
// Shared io_uring thread
// -------------------------

fn io_thread(
    depth: usize,
    ring: &mut IoUring,
    mut rx: mpsc::Receiver<Msg>,
    global_cancel: &CancellationToken,
) {
    fn submit_item(
        ring: &mut IoUring,
        slots: &mut [Option<OpCode>],
        inflight: &mut usize,
        id: usize,
        item: OpCode,
    ) -> Result<()> {
        // Compute SQE from the item (must keep backing memory alive in slots[id]).
        let sqe = match &item {
            OpCode::Write(w) => {
                tracing::debug!("submitting write {} at offset {}, inflight={}", w.len, w.off, *inflight+1);
                let ptr = w.pooled.as_bytes().as_ptr();
                let len = w.len as u32;
                opcode::Write::new(types::Fd(w.fd), ptr, len)
                    .offset(w.off)
                    .build()
                    .user_data(id as u64)
            }
            OpCode::Read(r) => {
                tracing::debug!("submitting read {} at offset {}, inflight={}", r.len, r.off, *inflight+1);
                // Cast to *mut u8 for read; buffer is exclusively owned.
                let ptr = r.pooled.as_bytes().as_ptr() as *mut u8;
                let len = r.len as u32;
                opcode::Read::new(types::Fd(r.fd), ptr, len)
                    .offset(r.off)
                    .build()
                    .user_data(id as u64)
            }
        };

        slots[id] = Some(item);

        unsafe {
            ring.submission()
                .push(&sqe)
                .map_err(|_| anyhow!("io_uring SQ full"))?;
        }

        *inflight += 1;
        Ok(())
    }

    fn reap_all(
        ring: &mut IoUring,
        slots: &mut [Option<OpCode>],
        free: &mut VecDeque<usize>,
        inflight: &mut usize,
        global_cancel: &CancellationToken,
        fatal_err: &mut Option<anyhow::Error>,
    ) {
        let mut cq = ring.completion();
        while let Some(cqe) = cq.next() {
            let id = cqe.user_data() as usize;
            let res = cqe.result();

            let item = slots.get_mut(id).and_then(|s| s.take());
            free.push_back(id);
            *inflight = inflight.saturating_sub(1);

            let Some(item) = item else {
                *fatal_err = Some(anyhow!("io_uring completion for unknown id={id}"));
                global_cancel.cancel();
                continue;
            };

            match item {
                OpCode::Write(w) => {
                    if res < 0 {
                        let errno = -res;
                        w.session.set_error_once(anyhow!(
                            "io_uring write failed at off={}: errno={errno}",
                            w.off
                        ));
                    } else {
                        let n = res as usize;
                        if n != w.len {
                            w.session.set_error_once(anyhow!(
                                "short io_uring write at off={}: wrote {n}, expected {}",
                                w.off,
                                w.len
                            ));
                        }
                    }
                    w.session.on_complete();
                    drop(w);
                }
                OpCode::Read(r) => {
                    // Move fields out so we never partially-move `r` and then use it again.
                    let ReadItem {
                        off,
                        len,
                        pooled,
                        session,
                        mut done,
                        // keep these to ensure lifetime/permits end when we return:
                        fd: _,
                        _file: _,
                    } = r;

                    if res < 0 {
                        let errno = -res;
                        let e = anyhow!("io_uring read failed at off={}: errno={errno}", off);
                        session.set_error_once(anyhow!("{e}"));
                        if let Some(tx) = done.take() {
                            let _ = tx.send(Err(e));
                        }
                        session.on_complete();
                        // pooled dropped here (returned to pool)
                    } else {
                        let n = res as usize;

                        if n > len {
                            let e = anyhow!(
                                "io_uring read returned n={} > requested {} at off={}",
                                n, len, off
                            );
                            session.set_error_once(anyhow!("{e}"));
                            if let Some(tx) = done.take() {
                                let _ = tx.send(Err(e));
                            }
                            session.on_complete();
                            global_cancel.cancel();
                        } else {
                            if let Some(tx) = done.take() {
                                let _ = tx.send(Ok(ReadDone { n, pooled }));
                                // pooled moved into ReadDone, so don't use it here
                            } else {
                                session.set_error_once(anyhow!("missing read completion sender"));
                                global_cancel.cancel();
                            }
                            session.on_complete();
                        }
                    }
                }
            }
        }
    }

    fn fail_item(item: OpCode, msg: &str) {
        match item {
            OpCode::Write(w) => {
                w.session.set_error_once(anyhow!("{msg}"));
                w.session.on_complete();
                drop(w);
            }
            OpCode::Read(mut r) => {
                r.session.set_error_once(anyhow!("{msg}"));
                if let Some(done) = r.done.take() {
                    let _ = done.send(Err(anyhow!("{msg}")));
                }
                r.session.on_complete();
                drop(r);
            }
        }
    }

    let mut slots: Vec<Option<OpCode>> = Vec::with_capacity(depth);
    slots.resize_with(depth, || None);
    let mut free: VecDeque<usize> = (0..depth).collect();
    let mut inflight: usize = 0;
    let mut backlog: VecDeque<OpCode> = VecDeque::new();
    let mut rx_closed = false;
    let mut fatal_err: Option<anyhow::Error> = None;

    loop {
        reap_all(ring, &mut slots, &mut free, &mut inflight, global_cancel, &mut fatal_err);

        if fatal_err.is_some() {
            global_cancel.cancel();
        }

        if global_cancel.is_cancelled() {
            let msg = fatal_err
                .as_ref()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "uring io cancelled".to_string());

            while let Some(item) = backlog.pop_front() {
                fail_item(item, &msg);
            }
            for slot in slots.iter_mut() {
                if let Some(item) = slot.take() {
                    fail_item(item, &msg);
                }
            }
            while let Ok(Msg::Submit(item)) = rx.try_recv() {
                fail_item(item, &msg);
            }
            break;
        }

        // Fill SQ
        let mut pushed = 0usize;
        while inflight < depth {
            let Some(id) = free.pop_front() else { break; };

            let item = if let Some(it) = backlog.pop_front() {
                it
            } else {
                match rx.try_recv() {
                    Ok(Msg::Submit(it)) => it,
                    Err(mpsc::error::TryRecvError::Empty) => {
                        free.push_front(id);
                        break;
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        rx_closed = true;
                        free.push_front(id);
                        break;
                    }
                }
            };

            if let Err(e) = submit_item(ring, &mut slots, &mut inflight, id, item) {
                // Could not push SQE right now; re-queue and cancel fatally.
                let item = slots[id].take().unwrap_or_else(|| unreachable!());
                backlog.push_front(item);
                free.push_front(id);
                fatal_err = Some(e);
                global_cancel.cancel();
                break;
            }

            pushed += 1;
        }

        if pushed > 0 {
            if let Err(e) = ring.submit() {
                fatal_err = Some(anyhow!("io_uring submit failed: {e}"));
                global_cancel.cancel();
                continue;
            }
        }

        reap_all(ring, &mut slots, &mut free, &mut inflight, global_cancel, &mut fatal_err);
        if fatal_err.is_some() {
            global_cancel.cancel();
            continue;
        }

        if rx_closed && inflight == 0 && backlog.is_empty() {
            break;
        }

        // Wait strategy
        if inflight > 0 {
            if let Err(e) = ring.submit_and_wait(1) {
                fatal_err = Some(anyhow!("io_uring submit_and_wait failed: {e}"));
                global_cancel.cancel();
            }
            continue;
        }

        // inflight == 0: block for one message
        if !rx_closed {
            match rx.blocking_recv() {
                Some(Msg::Submit(it)) => backlog.push_back(it),
                None => rx_closed = true,
            }
        }
    }
}
