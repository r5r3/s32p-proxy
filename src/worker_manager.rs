use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use std::{
    net::{SocketAddr, TcpListener},
    process::Stdio,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::TcpStream,
    process::{Child, Command},
    sync::{Mutex, Notify},
    time,
};

use crate::user_db::UserRecord;

#[derive(Clone, Debug)]
pub struct WorkerManagerConfig {
    pub restricted_exec: String,
    pub versitygw: String,
    pub posix_root: String,
    pub extra_versity_args: Vec<String>,
    pub idle_timeout: Duration,
    pub sweep_interval: Duration,
}

pub struct WorkerManager {
    cfg: WorkerManagerConfig,
    slots: DashMap<u32, Arc<WorkerSlot>>, // keyed by uid
    sweeper_started: AtomicBool,
}

struct WorkerSlot {
    state: Mutex<SlotState>,
    notify: Notify,
}

enum SlotState {
    Stopped,
    Starting,
    Running(Arc<WorkerHandle>),
}

pub struct WorkerHandle {
    pub uid: u32,
    pub username: String,
    pub addr: SocketAddr,
    last_used_unix: AtomicU64,
    child: Mutex<Child>,
}

impl WorkerHandle {
    fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs()
    }

    pub fn touch(&self) {
        self.last_used_unix.store(Self::now_unix(), Ordering::Relaxed);
    }

    pub fn last_used_unix(&self) -> u64 {
        self.last_used_unix.load(Ordering::Relaxed)
    }

    pub async fn is_alive(&self) -> bool {
        let mut child = self.child.lock().await;
        match child.try_wait() {
            Ok(Some(_status)) => false,
            Ok(None) => true,
            Err(_) => false,
        }
    }

    pub async fn terminate(&self) {
        let mut child = self.child.lock().await;

        // Try a graceful stop first (SIGKILL fallback).
        // `kill()` on tokio Child is SIGKILL on Unix.
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
}

impl WorkerManager {
    pub fn new(cfg: WorkerManagerConfig) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            slots: DashMap::new(),
            sweeper_started: AtomicBool::new(false),
        })
    }

    /// Start a background sweeper exactly once (call from within an async context, e.g. first request).
    pub fn start_sweeper(self: &Arc<Self>) {
        if self
            .sweeper_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return; // already started
        }

        let mgr = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                time::sleep(mgr.cfg.sweep_interval).await;
                mgr.sweep_once().await;
            }
        });
    }

    /// Returns Some(handle) if the worker is running and alive; otherwise None.
    pub async fn get_running(&self, uid: u32) -> Option<Arc<WorkerHandle>> {
        let slot = self.slots.get(&uid)?;
        let maybe = {
            let state = slot.state.lock().await;
            match &*state {
                SlotState::Running(h) => Some(Arc::clone(h)),
                _ => None,
            }
        };

        if let Some(h) = maybe {
            if h.is_alive().await {
                return Some(h);
            }
        }

        // Worker died; remove slot.
        drop(slot);
        self.slots.remove(&uid);
        None
    }

    /// Ensure a worker exists. Uses singleflight per uid (concurrent callers wait).
    pub async fn ensure_running(&self, user: &UserRecord) -> Result<Arc<WorkerHandle>> {
        let slot = self
            .slots
            .entry(user.uid)
            .or_insert_with(|| {
                Arc::new(WorkerSlot {
                    state: Mutex::new(SlotState::Stopped),
                    notify: Notify::new(),
                })
            })
            .clone();

        loop {
            // Fast path: running
            {
                let state = slot.state.lock().await;
                if let SlotState::Running(h) = &*state {
                    if h.is_alive().await {
                        h.touch();
                        return Ok(Arc::clone(h));
                    }
                }
            }

            // Become the starter or wait
            let should_start = {
                let mut state = slot.state.lock().await;
                match &*state {
                    SlotState::Running(_) => false,
                    SlotState::Starting => false,
                    SlotState::Stopped => {
                        *state = SlotState::Starting;
                        true
                    }
                }
            };

            if !should_start {
                // Wait for whoever is starting to finish
                slot.notify.notified().await;
                continue;
            }

            // We are responsible for starting it
            let start_res = self.spawn_worker(user).await;

            let mut state = slot.state.lock().await;
            match start_res {
                Ok(h) => {
                    *state = SlotState::Running(Arc::clone(&h));
                    slot.notify.notify_waiters();
                    return Ok(h);
                }
                Err(e) => {
                    *state = SlotState::Stopped;
                    slot.notify.notify_waiters();
                    return Err(e);
                }
            }
        }
    }

    async fn spawn_worker(&self, user: &UserRecord) -> Result<Arc<WorkerHandle>> {
        // Pick a local port (best-effort). Race is acceptable for now.
        let port = pick_free_port().context("failed to pick a free local port")?;
        let addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .map_err(|e| anyhow!("bad addr: {e}"))?;

        let mut cmd = Command::new(&self.cfg.restricted_exec);
        //cmd.arg("--user")
        //    .arg(&user.username)
        cmd.arg("--")
            .arg(&self.cfg.versitygw)
            .arg("--port")
            .arg(format!("127.0.0.1:{port}"));

        // Shared config/root:
        // VersityGW quickstart uses: versitygw --port :10000 posix /path/to/root
        // We'll do: ... posix <posix_root>
        cmd.args(&self.cfg.extra_versity_args)
            .arg("posix")
            .arg(&self.cfg.posix_root);

        // Credentials for this per-user worker:
        cmd.env("ROOT_ACCESS_KEY", &user.access_key)
            .env("ROOT_SECRET_KEY", &user.secret_key);

        // Don't inherit stdin; capture stderr for debugging if needed.
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        let child = cmd.spawn().context("failed to spawn restricted-exec/versitygw")?;

        let handle = Arc::new(WorkerHandle {
            uid: user.uid,
            username: user.username.clone(),
            addr,
            last_used_unix: AtomicU64::new(WorkerHandle::now_unix()),
            child: Mutex::new(child),
        });

        // Wait until TCP accepts connections (small grace window)
        wait_until_ready(addr, Duration::from_secs(2)).await?;

        Ok(handle)
    }

    async fn sweep_once(self: &Arc<Self>) {
        let now = WorkerHandle::now_unix();
        let idle_secs = self.cfg.idle_timeout.as_secs();

        // Collect keys first to avoid holding iter borrows over awaits.
        let uids: Vec<u32> = self.slots.iter().map(|e| *e.key()).collect();

        for uid in uids {
            let Some(slot) = self.slots.get(&uid) else { continue };

            let handle = {
                let state = slot.state.lock().await;
                match &*state {
                    SlotState::Running(h) => Some(Arc::clone(h)),
                    _ => None,
                }
            };

            let Some(h) = handle else { continue };

            // Remove dead workers
            if !h.is_alive().await {
                drop(slot);
                self.slots.remove(&uid);
                continue;
            }

            // Idle timeout
            let last_used = h.last_used_unix();
            if now.saturating_sub(last_used) >= idle_secs {
                h.terminate().await;
                drop(slot);
                self.slots.remove(&uid);
            }
        }
    }
}

fn pick_free_port() -> Result<u16> {
    let l = TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}

async fn wait_until_ready(addr: SocketAddr, timeout: Duration) -> Result<()> {
    let start = time::Instant::now();
    loop {
        match TcpStream::connect(addr).await {
            Ok(_) => return Ok(()),
            Err(_) => {
                if start.elapsed() >= timeout {
                    return Err(anyhow!("worker did not become ready on {addr} within {timeout:?}"));
                }
                time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

