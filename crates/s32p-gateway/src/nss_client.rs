//! Gateway-side client for the proxy's NSS lookup service.
//!
//! Replaces the direct `getpwuid_r` call that used to live inline in the
//! listing/ACL code paths. The worker no longer has `/etc/passwd` in its
//! Landlock allow list, so the only way to resolve uid → username under the
//! proxy is to ask the proxy. The proxy publishes an abstract-namespace UDS
//! whose name is passed to the worker via `S32P_NSS_PROXY_SOCK`.
//!
//! Two backends:
//!
//! * **`Direct`** — when the env var is absent or empty. Calls
//!   `getpwuid_r` locally via `spawn_blocking`. Only useful when the
//!   gateway runs standalone (dev/test, no proxy, no Landlock); under a
//!   proxy with `--allow-nss` dropped this would return `None` for every
//!   uid since `/etc/passwd` access is denied.
//! * **`Socket`** — connect to the abstract (or filesystem) UDS path the
//!   proxy gave us; send a 4-byte uid; read a `[len][name]` framed reply.
//!   See [`s32p_support::nss_proto`].
//!
//! All lookups (regardless of backend) flow through an in-memory cache
//! keyed by uid with a 5-minute TTL. The cache holds both positive and
//! negative entries (negative = uid is known-unknown), so a single missing
//! uid doesn't generate one socket query per listed file.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::RwLock,
    time::{Duration, Instant},
};

use s32p_support::{nss_lookup, nss_proto};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    sync::Mutex,
};

/// Positive cache TTL — successful and known-negative lookups live this long
/// before being re-queried.
pub const CACHE_TTL: Duration = Duration::from_secs(5 * 60);

/// Shorter TTL applied when the socket backend errors out and we have to
/// fall back to direct lookup (or numeric). Keeps us from hammering a sick
/// proxy on every list entry while still recovering quickly once it
/// returns.
pub const ERROR_FALLBACK_TTL: Duration = Duration::from_secs(30);

/// Per-query timeout on the socket round-trip. NSS via SSSD can stall;
/// 50 ms is well above local UDS latency and prevents one slow request
/// from blocking every concurrent listing on the worker.
pub const QUERY_TIMEOUT: Duration = Duration::from_millis(50);

/// Statistics produced by one [`NssClient::sweep`] pass. Same shape as the
/// replay cache's `SweepStats` so logging stays consistent.
#[derive(Debug, Clone, Copy)]
pub struct SweepStats {
    pub before:  usize,
    pub after:   usize,
    pub removed: usize,
    pub elapsed: Duration,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    value:      Option<String>,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
enum Address {
    /// Linux abstract-namespace name (the empty-prefix bytes after the
    /// leading `@`).
    Abstract(String),
    /// Filesystem socket path.
    Path(PathBuf),
}

enum Backend {
    Direct,
    Socket { addr: Address, conn: Mutex<Option<UnixStream>> },
}

pub struct NssClient {
    cache:   RwLock<HashMap<u32, CacheEntry>>,
    ttl:     Duration,
    backend: Backend,
}

impl NssClient {
    /// Build a client from an `S32P_NSS_PROXY_SOCK` env value.
    ///
    /// * `None` or empty → `Direct`.
    /// * starts with `@` → abstract socket (rest of string is the name).
    /// * otherwise → filesystem socket path.
    pub fn from_env(env_value: Option<&str>) -> Self {
        let backend = match env_value.map(str::trim) {
            None | Some("") => Backend::Direct,
            Some(raw) if raw.starts_with(nss_proto::ABSTRACT_PREFIX) => {
                let name = raw[nss_proto::ABSTRACT_PREFIX.len_utf8()..].to_string();
                Backend::Socket { addr: Address::Abstract(name), conn: Mutex::new(None) }
            }
            Some(raw) => {
                Backend::Socket { addr: Address::Path(PathBuf::from(raw)), conn: Mutex::new(None) }
            }
        };
        Self { cache: RwLock::new(HashMap::new()), ttl: CACHE_TTL, backend }
    }

    /// Direct-only constructor for tests.
    #[cfg(test)]
    pub fn direct_for_test(ttl: Duration) -> Self {
        Self { cache: RwLock::new(HashMap::new()), ttl, backend: Backend::Direct }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// True if the client is in `Direct` mode (no proxy socket configured).
    pub fn is_direct(&self) -> bool {
        matches!(self.backend, Backend::Direct)
    }

    /// Number of currently-cached entries (including not-yet-swept expired).
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.cache.read().unwrap().len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.cache.read().unwrap().is_empty()
    }

    /// Resolve `uid` to a username, consulting the cache first.
    ///
    /// Returns `Some(name)` on success, `None` for unknown uid or repeated
    /// backend failure. Always non-fatal: the listing code substitutes the
    /// numeric uid string at the call site.
    pub async fn lookup(&self, uid: u32) -> Option<String> {
        if let Some(hit) = self.cache_get(uid) {
            return hit;
        }

        match &self.backend {
            Backend::Direct => {
                let name =
                    tokio::task::spawn_blocking(move || nss_lookup::lookup_username_blocking(uid))
                        .await
                        .ok()
                        .flatten();
                self.cache_insert(uid, name.clone(), self.ttl);
                name
            }
            Backend::Socket { addr, conn } => {
                match query_socket(addr, conn, uid).await {
                    Ok(name) => {
                        self.cache_insert(uid, name.clone(), self.ttl);
                        name
                    }
                    Err(e) => {
                        tracing::debug!(uid, error = %e, "nss-proxy lookup failed; caching error fallback");
                        // Short-TTL cache so we don't retry on every listed
                        // entry, but still recover within ~30s once the
                        // proxy is healthy again.
                        self.cache_insert(uid, None, ERROR_FALLBACK_TTL);
                        None
                    }
                }
            }
        }
    }

    fn cache_get(&self, uid: u32) -> Option<Option<String>> {
        let now = Instant::now();
        let guard = self.cache.read().unwrap();
        guard.get(&uid).filter(|e| e.expires_at > now).map(|e| e.value.clone())
    }

    fn cache_insert(&self, uid: u32, value: Option<String>, ttl: Duration) {
        let entry = CacheEntry { value, expires_at: Instant::now() + ttl };
        self.cache.write().unwrap().insert(uid, entry);
    }

    /// Drop expired entries; periodic call from a background sweeper task.
    pub fn sweep(&self) -> SweepStats {
        let start = Instant::now();
        let now = start;
        let mut guard = self.cache.write().unwrap();
        let before = guard.len();
        guard.retain(|_, e| e.expires_at > now);
        let after = guard.len();
        SweepStats {
            before,
            after,
            removed: before.saturating_sub(after),
            elapsed: start.elapsed(),
        }
    }
}

async fn query_socket(
    addr: &Address,
    conn: &Mutex<Option<UnixStream>>,
    uid: u32,
) -> Result<Option<String>, std::io::Error> {
    let mut guard = conn.lock().await;

    // Try the existing connection once. On any error, drop it and reconnect
    // for a single retry. Keeps the persistent connection warm in the
    // common path while surviving proxy restart / idle teardown.
    for attempt in 0..2 {
        if guard.is_none() {
            *guard = Some(connect(addr).await?);
        }
        let stream = guard.as_mut().expect("just inserted");
        match tokio::time::timeout(QUERY_TIMEOUT, one_query(stream, uid)).await {
            Ok(Ok(name)) => return Ok(name),
            Ok(Err(e)) => {
                *guard = None;
                if attempt == 1 {
                    return Err(e);
                }
                // fall through to retry
            }
            Err(_) => {
                *guard = None;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "nss-proxy query timed out",
                ));
            }
        }
    }
    unreachable!("loop body either returns or continues into the second iteration which returns")
}

async fn connect(addr: &Address) -> Result<UnixStream, std::io::Error> {
    match addr {
        Address::Path(p) => UnixStream::connect(p).await,
        Address::Abstract(name) => {
            use std::os::linux::net::SocketAddrExt;
            let std_addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
            let std_stream = std::os::unix::net::UnixStream::connect_addr(&std_addr)?;
            std_stream.set_nonblocking(true)?;
            UnixStream::from_std(std_stream)
        }
    }
}

async fn one_query(stream: &mut UnixStream, uid: u32) -> Result<Option<String>, std::io::Error> {
    let req = nss_proto::encode_request(uid);
    stream.write_all(&req).await?;
    let mut len_buf = [0u8; 1];
    stream.read_exact(&mut len_buf).await?;
    let len = len_buf[0] as usize;
    if len == 0 {
        return Ok(None);
    }
    let mut name = vec![0u8; len];
    stream.read_exact(&mut name).await?;
    String::from_utf8(name)
        .map(Some)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn direct_resolves_self_uid_and_caches() {
        let client = NssClient::direct_for_test(Duration::from_secs(60));
        let me = unsafe { libc::geteuid() } as u32;

        let first = client.lookup(me).await;
        assert!(first.is_some());
        assert_eq!(client.len(), 1);

        // Second lookup hits the cache (cannot directly assert, but cache size stays 1).
        let second = client.lookup(me).await;
        assert_eq!(first, second);
        assert_eq!(client.len(), 1);
    }

    #[tokio::test]
    async fn direct_unknown_uid_caches_negative() {
        let client = NssClient::direct_for_test(Duration::from_secs(60));
        let bogus = 4_000_000_000u32;

        assert_eq!(client.lookup(bogus).await, None);
        // Even None is cached so repeated lookups don't re-query.
        assert_eq!(client.len(), 1);
        assert_eq!(client.lookup(bogus).await, None);
        assert_eq!(client.len(), 1);
    }

    #[tokio::test]
    async fn cache_expires_after_ttl() {
        let client = NssClient::direct_for_test(Duration::from_millis(10));
        let me = unsafe { libc::geteuid() } as u32;
        client.lookup(me).await;
        assert_eq!(client.len(), 1);
        tokio::time::sleep(Duration::from_millis(25)).await;
        // Entry is still in the map, but cache_get filters by expiry.
        // A fresh lookup overwrites it.
        client.lookup(me).await;
        assert_eq!(client.len(), 1);
        // Sweep removes nothing because the entry was just refreshed.
        let stats = client.sweep();
        assert_eq!(stats.removed, 0);
    }

    #[tokio::test]
    async fn sweep_removes_only_expired() {
        let client = NssClient::direct_for_test(Duration::from_millis(10));
        let me = unsafe { libc::geteuid() } as u32;
        client.lookup(me).await;
        client.lookup(4_000_000_000).await;
        assert_eq!(client.len(), 2);
        tokio::time::sleep(Duration::from_millis(25)).await;
        let stats = client.sweep();
        assert_eq!(stats.before, 2);
        assert_eq!(stats.after, 0);
        assert_eq!(stats.removed, 2);
    }

    #[test]
    fn from_env_picks_direct_for_empty() {
        assert!(NssClient::from_env(None).is_direct());
        assert!(NssClient::from_env(Some("")).is_direct());
        assert!(NssClient::from_env(Some("   ")).is_direct());
    }

    #[test]
    fn from_env_recognizes_abstract_and_path() {
        let abst = NssClient::from_env(Some("@s32p-nss-12345"));
        assert!(!abst.is_direct());
        let path = NssClient::from_env(Some("/run/s32p/nss.sock"));
        assert!(!path.is_direct());
    }
}
