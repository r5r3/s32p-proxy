use anyhow::{anyhow, Result};
use io_uring::{opcode, types, IoUring};
use std::collections::VecDeque;
use std::os::unix::io::RawFd;
use std::thread;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::buffer::PooledBuf;

/// A single write request. `pooled` is kept alive until the CQE completes.
pub struct WriteItem {
    pub off: u64,
    pub write_len: usize,
    pub pooled: PooledBuf, // returned to pool on Drop
}

/// Spawns a dedicated io_uring writer thread.
/// Returns:
/// - a bounded Sender for `WriteItem` (capacity = depth),
/// - a CancellationToken (cancelled on first writer error),
/// - a oneshot Receiver for the writer result.
pub fn spawn_uring_writer(
    depth: usize,
    fd: RawFd,
) -> (
    mpsc::Sender<WriteItem>,
    CancellationToken,
    oneshot::Receiver<Result<()>>,
) {
    let depth = depth.max(1);

    // Bounded async channel: producer send().await provides backpressure.
    let (tx, mut rx) = mpsc::channel::<WriteItem>(depth);

    let cancel = CancellationToken::new();
    let cancel_w = cancel.clone();

    let (done_tx, done_rx) = oneshot::channel::<Result<()>>();

    thread::spawn(move || {
        fn submit_item(
            ring: &mut IoUring,
            slots: &mut [Option<WriteItem>],
            inflight: &mut usize,
            fd: RawFd,
            id: usize,
            item: WriteItem,
        ) -> Result<()> {
            let WriteItem { off, write_len, pooled } = item;

            let ptr = pooled.as_bytes().as_ptr();
            let len = write_len as u32;

            // keep buffer alive until CQE
            slots[id] = Some(WriteItem { off, write_len, pooled });

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
            tracing::debug!(
                "submitting {} bytes at offset {}; inflight: {}",
                len,
                off,
                *inflight
            );
            Ok(())
        }

        fn reap_all(
            ring: &mut IoUring,
            slots: &mut [Option<WriteItem>],
            free: &mut VecDeque<usize>,
            inflight: &mut usize,
            first_err: &mut Option<anyhow::Error>,
            cancel: &CancellationToken,
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
                    cancel.cancel();
                    continue;
                };

                if res < 0 {
                    let errno = -res;
                    *first_err = Some(anyhow!(
                        "io_uring write failed at off={}: errno={errno}",
                        item.off
                    ));
                    cancel.cancel();
                    continue;
                }

                let n = res as usize;
                if n != item.write_len {
                    *first_err = Some(anyhow!(
                        "short io_uring write at off={}: wrote {n}, expected {}",
                        item.off,
                        item.write_len
                    ));
                    cancel.cancel();
                    continue;
                }

                drop(item);
            }
        }

        let mut ring = match IoUring::new(depth as u32) {
            Ok(r) => r,
            Err(e) => {
                cancel_w.cancel();
                let _ = done_tx.send(Err(anyhow!("IoUring::new({depth}) failed: {e}")));
                return;
            }
        };

        let mut slots: Vec<Option<WriteItem>> = Vec::with_capacity(depth);
        slots.resize_with(depth, || None);

        let mut free: VecDeque<usize> = (0..depth).collect();
        let mut inflight: usize = 0;
        let mut rx_closed = false;
        let mut first_err: Option<anyhow::Error> = None;

        loop {
            // 1) reap
            reap_all(
                &mut ring,
                &mut slots,
                &mut free,
                &mut inflight,
                &mut first_err,
                &cancel_w,
            );

            // On error: cancel and drain inflight completions
            if first_err.is_some() {
                cancel_w.cancel();
                if inflight > 0 {
                    let _ = ring.submit_and_wait(inflight);
                    continue;
                }
                break;
            }

            // 2) fill SQ up to depth using non-blocking try_recv
            let mut pushed = 0usize;
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

                if submit_item(&mut ring, &mut slots, &mut inflight, fd, id, work).is_err() {
                    free.push_front(id);
                    break;
                }
                pushed += 1;
            }

            // 3) submit once per batch
            if pushed > 0 {
                if let Err(e) = ring.submit() {
                    first_err = Some(anyhow!("io_uring submit failed: {e}"));
                    continue;
                }
            }

            // 4) reap again
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

            if rx_closed && inflight == 0 {
                break;
            }

            // 5) only wait when saturated or draining
            if inflight == depth || (rx_closed && inflight > 0) {
                if let Err(e) = ring.submit_and_wait(1) {
                    first_err = Some(anyhow!("io_uring submit_and_wait failed: {e}"));
                    cancel_w.cancel();
                }
                continue;
            }

            // 6) otherwise block for one item to avoid spin
            if !rx_closed {
                match rx.blocking_recv() {
                    Some(work) => {
                        if let Some(id) = free.pop_front() {
                            if let Err(e) =
                                submit_item(&mut ring, &mut slots, &mut inflight, fd, id, work)
                            {
                                first_err = Some(e);
                                continue;
                            }
                            if let Err(e) = ring.submit() {
                                first_err = Some(anyhow!("io_uring submit failed: {e}"));
                                continue;
                            }
                        } else {
                            drop(work);
                        }
                    }
                    None => {
                        rx_closed = true;
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

    (tx, cancel, done_rx)
}
