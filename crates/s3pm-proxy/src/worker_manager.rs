use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use std::{
    fs,
    net::{SocketAddr, TcpListener},
    os::unix::fs as unix_fs,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
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
use tempfile::TempDir;

use crate::config::{WorkerProfile, WorkersConfig};
use s3pm_directory::{UserDoc, BucketView};

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct WorkerKey {
    pub access_key: String,
    pub profile: String,
}

impl WorkerKey {
    pub fn new(access_key: &str, profile: &str) -> Self {
        Self {
            access_key: access_key.to_string(),
            profile: profile.to_string(),
        }
    }
}

pub struct WorkerManager {
    cfg: WorkersConfig,
    slots: DashMap<WorkerKey, Arc<WorkerSlot>>, // keyed by (uid, worker_profile)
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
    pub key: WorkerKey,
    pub username: String,
    pub addr: SocketAddr,
    pub posix_root: PathBuf,
    tempdir: Mutex<Option<TempDir>>,
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
        let _ = child.kill().await; // SIGKILL on Unix
        let _ = child.wait().await;
        drop(child);

        // Remove temp dir immediately (even if the handle lives longer via Arc)
        let mut td = self.tempdir.lock().await;
        if let Some(dir) = td.take() {
            let _ = dir.close(); // ignore error; best-effort cleanup
        }
    }
}

impl WorkerManager {
    pub fn new(cfg: WorkersConfig) -> Arc<Self> {
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
        let sweep_interval = Duration::from_secs(mgr.cfg.lifecycle.sweep_interval_secs);

        tokio::spawn(async move {
            loop {
                time::sleep(sweep_interval).await;
                mgr.sweep_once().await;
            }
        });
    }

    /// Returns Some(handle) if the worker is running and alive; otherwise None.
    pub async fn get_running(&self, access_key: &str, profile: &str) -> Option<Arc<WorkerHandle>> {
        let key = WorkerKey::new(access_key, profile);
        let slot = self.slots.get(&key)?;
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
        self.slots.remove(&key);
        None
    }

    /// Ensure a worker exists for (user, profile). Uses singleflight per key (concurrent callers wait).
    pub async fn ensure_running(&self, user: &UserDoc, buckets: &[BucketView], profile: &str) -> Result<Arc<WorkerHandle>> {
        let key = WorkerKey::new(user.access_key.as_str(), profile);

        let slot = self
            .slots
            .entry(key.clone())
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
            let start_res = self.spawn_worker(user, buckets, profile).await;

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

    async fn spawn_worker(&self, user: &UserDoc, buckets: &[BucketView], profile_name: &str) -> Result<Arc<WorkerHandle>> {
        let profile = self
            .cfg
            .profiles
            .get(profile_name)
            .ok_or_else(|| anyhow!("unknown worker profile '{profile_name}'"))?;

        let port = pick_free_port().context("failed to pick a free local port")?;
        let bind_addr = format!("127.0.0.1:{port}");
        let addr: SocketAddr = bind_addr
            .parse()
            .map_err(|e| anyhow!("bad bind addr '{bind_addr}': {e}"))?;

        let euid_is_root = unsafe { libc::geteuid() == 0 };

        // Create fresh staged root with bucket links
        let (tempdir, staged_root) = create_staged_posix_root(
            &self.cfg.posix_root,       // treating cfg.posix_root as "runtime_root" base
            user.uid,
            user.gid,
            &user.access_key,
            buckets,
        )?;
        let staged_root_str = staged_root
            .to_str()
            .ok_or_else(|| anyhow!("staged root is not valid UTF-8: {}", staged_root.display()))?;

        let mut cmd = Command::new(&self.cfg.launcher.path);

        if self.cfg.launcher.pass_user_flag_if_root && euid_is_root {
            tracing::debug!(
                uid = user.uid,
                username = user.username.as_str(),
                profile = profile_name,
                "running as root: passing --user to launcher"
            );
            cmd.arg("--user").arg(&user.username);
        } else {
            tracing::debug!(
                uid = user.uid,
                username = user.username.as_str(),
                profile = profile_name,
                "launching without --user (either not root or disabled in config)"
            );
        }

        let vars = TemplateVars {
            username: &user.username,
            uid: user.uid,
            gid: user.gid,
            access_key: &user.access_key,
            secret_key: &user.secret_key,
            posix_root: &staged_root_str,
            port,
            bind_addr: &bind_addr,
        };

        let rendered_args = render_args(&profile.args, &vars)
            .with_context(|| format!("failed to render args for profile '{profile_name}'"))?;
        let rendered_env = render_env(&profile.env, &vars)
            .with_context(|| format!("failed to render env for profile '{profile_name}'"))?;

        // launcher -- <exec> <args...>
        cmd.arg("--")
            .arg(&profile.exec)
            .args(rendered_args)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        for (k, v) in rendered_env {
            cmd.env(k, v);
        }

        let child = cmd.spawn().context("failed to spawn launcher/worker")?;

        let handle = Arc::new(WorkerHandle {
            key: WorkerKey::new(user.access_key.as_str(), profile_name),
            username: user.username.clone(),
            addr,
            posix_root: staged_root.clone(),
            tempdir: Mutex::new(Some(tempdir)),
            last_used_unix: AtomicU64::new(WorkerHandle::now_unix()),
            child: Mutex::new(child),
        });

        wait_until_ready(addr, Duration::from_secs(2)).await?;
        Ok(handle)
    }

    async fn sweep_once(self: &Arc<Self>) {
        let now = WorkerHandle::now_unix();
        let idle_secs = self.cfg.lifecycle.idle_timeout_secs;

        // Collect keys first to avoid holding iter borrows over awaits.
        let keys: Vec<WorkerKey> = self.slots.iter().map(|e| e.key().clone()).collect();

        for key in keys {
            let Some(slot) = self.slots.get(&key) else { continue };

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
                self.slots.remove(&key);
                continue;
            }

            // Idle timeout
            let last_used = h.last_used_unix();
            if now.saturating_sub(last_used) >= idle_secs {
                tracing::info!(
                    access_key = h.key.access_key.as_str(),
                    profile = h.key.profile.as_str(),
                    "idle timeout reached; terminating worker"
                );
                h.terminate().await;
                drop(slot);
                self.slots.remove(&key);
            }
        }
    }

    /// Optional helper: expose the configured posix root for other modules.
    pub fn posix_root(&self) -> &str {
        &self.cfg.posix_root
    }

    /// Optional helper: check if a profile exists (useful for routing validation at runtime).
    pub fn has_profile(&self, profile: &str) -> bool {
        self.cfg.profiles.contains_key(profile)
    }
}

/* ---------------- templating ---------------- */

struct TemplateVars<'a> {
    username: &'a str,
    uid: u32,
    gid: u32,
    access_key: &'a str,
    secret_key: &'a str,
    posix_root: &'a str,
    port: u16,
    bind_addr: &'a str,
}

fn render_args(args: &[String], vars: &TemplateVars<'_>) -> Result<Vec<String>> {
    args.iter().map(|a| render_template(a, vars)).collect()
}

fn render_env(env: &std::collections::BTreeMap<String, String>, vars: &TemplateVars<'_>) -> Result<Vec<(String, String)>> {
    let mut out = Vec::with_capacity(env.len());
    for (k, v) in env {
        out.push((k.clone(), render_template(v, vars)?));
    }
    Ok(out)
}

/// Strict, safe placeholder replacement.
/// Supports tokens like: {{username}}, {{uid}}, {{gid}}, {{access_key}}, {{secret_key}},
/// {{posix_root}}, {{port}}, {{bind_addr}}.
/// Unknown tokens cause an error.
fn render_template(input: &str, vars: &TemplateVars<'_>) -> Result<String> {
    let mut out = String::with_capacity(input.len());
    let mut i = 0;

    while let Some(start) = input[i..].find("{{") {
        let start = i + start;
        out.push_str(&input[i..start]);

        let after = start + 2;
        let Some(end_rel) = input[after..].find("}}") else {
            return Err(anyhow!("unterminated template token in '{input}'"));
        };
        let end = after + end_rel;
        let name = input[after..end].trim();

        let value = match name {
            "username" => vars.username.to_string(),
            "uid" => vars.uid.to_string(),
            "gid" => vars.gid.to_string(),
            "access_key" => vars.access_key.to_string(),
            "secret_key" => vars.secret_key.to_string(),
            "posix_root" => vars.posix_root.to_string(),
            "port" => vars.port.to_string(),
            "bind_addr" => vars.bind_addr.to_string(),
            other => return Err(anyhow!("unknown template token '{{{{{other}}}}}' in '{input}'")),
        };

        out.push_str(&value);
        i = end + 2;
    }

    out.push_str(&input[i..]);
    Ok(out)
}

/* ---------------- utils ---------------- */

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

fn validate_bucket_link_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow!("bucket name must not be empty"));
    }
    if name.contains('/') || name.contains('\0') {
        return Err(anyhow!("bucket name contains invalid characters: {name:?}"));
    }
    if name == "." || name == ".." {
        return Err(anyhow!("bucket name is not allowed: {name:?}"));
    }
    Ok(())
}

fn lchown_if_root(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let euid_is_root = unsafe { libc::geteuid() == 0 };
    if !euid_is_root {
        return Ok(());
    }
    use std::ffi::CString;
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| anyhow!("path contains NUL: {}", path.display()))?;
    let rc = unsafe { libc::lchown(c.as_ptr(), uid, gid) };
    if rc != 0 {
        return Err(anyhow!("lchown failed for {}: errno={}", path.display(), rc));
    }
    Ok(())
}

fn chown_if_root(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let euid_is_root = unsafe { libc::geteuid() == 0 };
    if !euid_is_root {
        return Ok(());
    }
    use std::ffi::CString;
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| anyhow!("path contains NUL: {}", path.display()))?;
    let rc = unsafe { libc::chown(c.as_ptr(), uid, gid) };
    if rc != 0 {
        return Err(anyhow!("chown failed for {}: errno={}", path.display(), rc));
    }
    Ok(())
}

/// Create a fresh temp dir under cfg.posix_root (used as "runtime root"),
/// chown it to the target user if running as root, and add symlinks:
///   <temp>/<bucket_name> -> <bucket.data_path>
fn create_staged_posix_root(
    runtime_root: &str,
    user_uid: u32,
    user_gid: u32,
    access_key: &str,
    buckets: &[BucketView],
) -> Result<(TempDir, PathBuf)> {
    // Ensure base exists
    fs::create_dir_all(runtime_root)
        .with_context(|| format!("failed to create runtime_root {runtime_root}"))?;

    // Fresh temp dir
    let td = tempfile::Builder::new()
        .prefix(&format!("s3pm-{}-", access_key))
        .tempdir_in(runtime_root)
        .with_context(|| format!("failed to create tempdir in {runtime_root}"))?;

    let root = td.path().to_path_buf();

    // IMPORTANT: tempfile creates 0700 owned by current user.
    // If proxy runs as root but worker runs as user, the worker won't be able to traverse unless we chown.
    chown_if_root(&root, user_uid, user_gid)?;

    // Create symlinks
    let mut seen = std::collections::HashSet::new();
    for b in buckets {
        validate_bucket_link_name(&b.bucket_name)?;

        if !seen.insert(&b.bucket_name) {
            return Err(anyhow!("duplicate bucket name in staging set: {}", b.bucket_name));
        }

        let target = Path::new(&b.data_path);
        if !target.is_absolute() {
            return Err(anyhow!(
                "bucket {} data_path must be absolute (got {})",
                b.bucket_name,
                b.data_path
            ));
        }

        let link_final = root.join(&b.bucket_name);
        let link_tmp = root.join(format!(".{}.tmp", b.bucket_name));

        // best effort cleanup if exists
        let _ = fs::remove_file(&link_tmp);
        let _ = fs::remove_file(&link_final);

        unix_fs::symlink(target, &link_tmp)
            .with_context(|| format!("failed to symlink {} -> {}", link_tmp.display(), target.display()))?;

        // If you care about link ownership (usually not required), lchown it when root.
        // Directory ownership is the important part.
        let _ = lchown_if_root(&link_tmp, user_uid, user_gid);

        fs::rename(&link_tmp, &link_final)
            .with_context(|| format!("failed to rename {} -> {}", link_tmp.display(), link_final.display()))?;
    }

    Ok((td, root))
}

