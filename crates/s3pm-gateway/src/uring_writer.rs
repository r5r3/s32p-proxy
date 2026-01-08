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

/// Global io_uring writer (single instance for the whole gateway).
/// Create per-request `UringSender`s from it.
pub struct UringWriter {
    depth: usize,
    tx: mpsc::Sender<Msg>,
    cancel: CancellationToken, // cancelled on fatal writer failure
}

/// Per-request handle. Enforces max in-flight writes for this sender.
pub struct UringSender {
    tx: mpsc::Sender<Msg>,
    file: Arc<std::fs::File>,
    fd: RawFd,
    inflight: Arc<Semaphore>,
    session: Arc<SessionInner>,
    cancel: CancellationToken,
    done_rx: Option<oneshot::Receiver<Result<()>>>,
}

impl UringWriter {
    /// Spawn the single io_uring writer thread.
    /// `depth` should typically be your buffer pool size.
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

            writer_thread(depth, &mut ring, rx, &cancel_w);
        });

        // Wait for thread to initialize the ring.
        start_rx
            .recv()
            .map_err(|_| anyhow!("uring writer thread failed to report startup"))??;

        Ok(Self { depth, tx, cancel })
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn cancel_token(&self) -> &CancellationToken {
        &self.cancel
    }

    /// Create a per-request sender bound to a single file.
    /// The sender will allow at most `max_inflight` outstanding writes for that request.
    pub fn sender(&self, file: Arc<std::fs::File>, max_inflight: usize) -> UringSender {
        let max_inflight = max_inflight.max(1);
        let inflight = Arc::new(Semaphore::new(max_inflight));

        let session_cancel = self.cancel.child_token();
        let session = Arc::new(SessionInner::new(session_cancel.clone()));
        let (done_tx, done_rx) = oneshot::channel::<Result<()>>();
        session.set_done(done_tx);

        UringSender {
            tx: self.tx.clone(),
            fd: file.as_raw_fd(),
            file,
            inflight,
            session,
            cancel: session_cancel,
            done_rx: Some(done_rx),
        }
    }
}

impl UringSender {
    pub fn cancel_token(&self) -> &CancellationToken {
        &self.cancel
    }

    /// Mark this sender as closed (no more writes will be submitted).
    pub fn close(&self) {
        self.session.close();
    }

    /// Submit one write. This enforces the per-sender in-flight cap:
    /// the call awaits a permit, and the permit is released only when the CQE completes.
    pub async fn send(&self, off: u64, write_len: usize, pooled: PooledBuf) -> Result<()> {
        if self.cancel.is_cancelled() {
            return Err(anyhow!("uring sender cancelled"));
        }

        // Per-sender in-flight cap.
        let permit = self
            .inflight
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("sender inflight semaphore closed"))?;

        self.session.on_submit();

        let item = WriteItem {
            fd: self.fd,
            _file: self.file.clone(), // keep fd alive until CQE
            off,
            write_len,
            pooled,
            _permit: permit, // released on CQE by Drop
            session: self.session.clone(),
        };

        if self.tx.send(Msg::Write(item)).await.is_err() {
            // Writer is gone: undo submit, record error, cancel session.
            let e = anyhow!("uring writer thread stopped");
            self.session.set_error_once(anyhow!("{e}"));
            self.session.on_dropped_without_cqe();
            return Err(e);
        }

        Ok(())
    }

    /// Wait until all submitted writes for this sender complete (or an error occurs).
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

impl Drop for UringSender {
    fn drop(&mut self) {
        self.session.close();
    }
}

// ===== internal =====

enum Msg {
    Write(WriteItem),
}

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

struct WriteItem {
    fd: RawFd,
    _file: Arc<std::fs::File>,
    off: u64,
    write_len: usize,
    pooled: PooledBuf,
    _permit: OwnedSemaphorePermit,
    session: Arc<SessionInner>,
}

fn writer_thread(
    depth: usize,
    ring: &mut IoUring,
    mut rx: mpsc::Receiver<Msg>,
    global_cancel: &CancellationToken,
) {
    fn submit_item(
        ring: &mut IoUring,
        slots: &mut [Option<WriteItem>],
        inflight: &mut usize,
        id: usize,
        item: WriteItem,
    ) -> Result<()> {
        let ptr = item.pooled.as_bytes().as_ptr();
        let len = item.write_len as u32;

        slots[id] = Some(item);
        let item_ref = slots[id].as_ref().unwrap();

        let op = opcode::Write::new(types::Fd(item_ref.fd), ptr, len)
            .offset(item_ref.off)
            .build()
            .user_data(id as u64);

        unsafe {
            ring.submission()
                .push(&op)
                .map_err(|_| anyhow!("io_uring SQ full"))?;
        }

        *inflight += 1;
        tracing::debug!("submitting {} bytes at offset {}; inflight={}", len, item_ref.off, *inflight);
        Ok(())
    }

    fn reap_all(
        ring: &mut IoUring,
        slots: &mut [Option<WriteItem>],
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

            // Per-session error reporting.
            if res < 0 {
                let errno = -res;
                item.session
                    .set_error_once(anyhow!("io_uring write failed at off={}: errno={errno}", item.off));
            } else {
                let n = res as usize;
                if n != item.write_len {
                    item.session.set_error_once(anyhow!(
                        "short io_uring write at off={}: wrote {n}, expected {}",
                        item.off,
                        item.write_len
                    ));
                }
            }

            // mark completion (even on error)
            item.session.on_complete();
            drop(item);
        }
    }

    let mut slots: Vec<Option<WriteItem>> = Vec::with_capacity(depth);
    slots.resize_with(depth, || None);
    let mut free: VecDeque<usize> = (0..depth).collect();
    let mut inflight: usize = 0;
    let mut backlog: VecDeque<WriteItem> = VecDeque::new();
    let mut rx_closed = false;
    let mut fatal_err: Option<anyhow::Error> = None;

    loop {
        reap_all(ring, &mut slots, &mut free, &mut inflight, global_cancel, &mut fatal_err);

        if fatal_err.is_some() {
            global_cancel.cancel();
        }

        if global_cancel.is_cancelled() {
            // Drain everything we currently hold and fail sessions.
            let msg = fatal_err
                .as_ref()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "uring writer cancelled".to_string());

            while let Some(item) = backlog.pop_front() {
                item.session.set_error_once(anyhow!("{msg}"));
                item.session.on_complete();
                drop(item);
            }
            for slot in slots.iter_mut() {
                if let Some(item) = slot.take() {
                    item.session.set_error_once(anyhow!("{msg}"));
                    item.session.on_complete();
                    drop(item);
                }
            }
            // Drain receiver queue too.
            while let Ok(Msg::Write(item)) = rx.try_recv() {
                item.session.set_error_once(anyhow!("{msg}"));
                item.session.on_complete();
                drop(item);
            }
            break;
        }

        // Fill SQ as much as possible.
        let mut pushed = 0usize;
        while inflight < depth {
            let Some(id) = free.pop_front() else { break; };

            let item = if let Some(it) = backlog.pop_front() {
                it
            } else {
                match rx.try_recv() {
                    Ok(Msg::Write(it)) => it,
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
                // Could not push SQE right now; keep work and retry.
                backlog.push_front(slots[id].take().unwrap_or_else(|| unreachable!()));
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

        // Avoid spinning: if we have inflight ops, wait for at least one CQE.
        if inflight > 0 {
            if let Err(e) = ring.submit_and_wait(1) {
                fatal_err = Some(anyhow!("io_uring submit_and_wait failed: {e}"));
                global_cancel.cancel();
            }
            continue;
        }

        // inflight == 0: block for one message.
        if !rx_closed {
            match rx.blocking_recv() {
                Some(Msg::Write(it)) => backlog.push_back(it),
                None => rx_closed = true,
            }
        }
    }
}