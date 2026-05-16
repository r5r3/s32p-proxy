//! In-memory store of S3 Express directory-bucket sessions.
//!
//! Acts as a per-process `(access_key → secret)` lookup layered in front of
//! the `Directory` trait. The proxy checks here first when validating SigV4
//! on incoming requests; if the access key isn't a session key, it falls
//! through to the long-term-credential path.
//!
//! AWS reference: <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateSession.html>
//!
//! Ephemeral material is generated from `OsRng` (not the thread RNG, which
//! is acceptable for non-secret randomness but inappropriate for IAM-shaped
//! secrets).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use dashmap::DashMap;
use rand::RngCore;
use rand::rngs::OsRng;
use tokio::time;

/// Length of the ephemeral access key in bytes before base32 encoding.
/// 13 bytes → ~21 base32 chars, comfortably in the 16–128 range AWS allows.
const ACCESS_KEY_RAND_BYTES: usize = 13;
/// Length of the ephemeral secret in raw bytes before URL-safe base64-no-pad.
/// 30 bytes → 40 chars, matching the AWS secret-shape.
const SECRET_KEY_RAND_BYTES: usize = 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionMode {
    ReadOnly,
    ReadWrite,
}

impl SessionMode {
    pub fn from_header(value: Option<&str>) -> Self {
        match value.map(|v| v.trim()) {
            Some(v) if v.eq_ignore_ascii_case("ReadOnly") => SessionMode::ReadOnly,
            // AWS default is ReadWrite if the header is absent or any other value.
            _ => SessionMode::ReadWrite,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SessionEntry {
    pub access_key:        String,
    pub secret_key:        String,
    pub session_token:     String,
    /// The long-term access key the session is bound to. Used to route
    /// session-validated requests to the right worker.
    pub real_access_key:   String,
    /// Bucket the session was minted for; cross-bucket use is rejected.
    pub bucket:            String,
    pub mode:              SessionMode,
    /// Monotonic clock — authoritative for sweep/lookup validity. Immune to
    /// wall-clock skew or jumps.
    pub expires_at_inst:   Instant,
    /// Wall clock — rendered in the XML response so clients refresh on time.
    pub expires_at_system: SystemTime,
}

pub struct SessionStore {
    inner:            DashMap<String, SessionEntry>,
    max_active:       usize,
    cleanup_interval: Duration,
    cleanup_started:  AtomicBool,
}

impl SessionStore {
    pub fn new(max_active: usize, cleanup_interval: Duration) -> Self {
        Self {
            inner: DashMap::new(),
            max_active,
            cleanup_interval,
            cleanup_started: AtomicBool::new(false),
        }
    }

    /// Mint a new session for `real_access_key` against `bucket`.
    /// Returns `None` when the active-session cap would be exceeded.
    pub fn create(
        &self,
        real_access_key: &str,
        bucket: &str,
        mode: SessionMode,
        ttl: Duration,
    ) -> Option<SessionEntry> {
        if self.inner.len() >= self.max_active {
            return None;
        }
        let now_inst = Instant::now();
        let now_sys = SystemTime::now();
        let entry = SessionEntry {
            access_key:        gen_access_key(),
            secret_key:        gen_secret_key(),
            session_token:     uuid::Uuid::new_v4().to_string(),
            real_access_key:   real_access_key.to_string(),
            bucket:            bucket.to_string(),
            mode,
            expires_at_inst:   now_inst + ttl,
            expires_at_system: now_sys + ttl,
        };
        self.inner.insert(entry.access_key.clone(), entry.clone());
        Some(entry)
    }

    /// Look up a session by its ephemeral access key. Returns `None` for
    /// unknown keys *or* expired entries — expired entries are also evicted
    /// from the map so a later call doesn't have to re-check.
    pub fn lookup(&self, access_key: &str) -> Option<SessionEntry> {
        let entry = self.inner.get(access_key)?.clone();
        if entry.expires_at_inst <= Instant::now() {
            self.inner.remove(access_key);
            return None;
        }
        Some(entry)
    }

    pub fn invalidate(&self, access_key: &str) {
        self.inner.remove(access_key);
    }

    pub fn active_count(&self) -> usize {
        self.inner.len()
    }

    /// Lazily spawn a background task that periodically removes expired
    /// entries. Safe to call multiple times: the first call wins and the
    /// rest are no-ops. Must be called from inside a tokio runtime — the
    /// proxy invokes this from `request_filter`, where the runtime is
    /// already up.
    ///
    /// Mirrors `WorkerManager::start_sweeper` for shape (same Arc-of-self
    /// pattern, single tokio task, fixed cadence). Lazy start is the same
    /// reason: pingora's `Server::bootstrap()` runs before the runtime
    /// exists.
    pub fn start_cleanup(self: &Arc<Self>) {
        if self
            .cleanup_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        let store = Arc::clone(self);
        let interval = self.cleanup_interval;
        tokio::spawn(async move {
            let mut tick = time::interval(interval);
            // First tick fires immediately; skip it so the first sweep
            // happens after one full interval.
            tick.tick().await;
            loop {
                tick.tick().await;
                let now = Instant::now();
                store.inner.retain(|_, entry| entry.expires_at_inst > now);
            }
        });
    }
}

/// AWS access keys start with `AKIA` / `ASIA`; we mirror the `ASIA` prefix
/// (used for temporary creds) so client logs / cached creds look familiar.
/// The suffix is base32 (Crockford-style A–Z, 2–7) of CSPRNG bytes.
fn gen_access_key() -> String {
    let mut buf = [0u8; ACCESS_KEY_RAND_BYTES];
    OsRng.fill_bytes(&mut buf);
    let mut out = String::from("ASIA");
    for byte in buf {
        // 2 chars per byte, each from a 32-char alphabet → ample entropy
        // without dragging in a full base32 crate.
        const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        out.push(ALPHA[(byte >> 3) as usize] as char);
        out.push(ALPHA[(byte & 0x1f) as usize] as char);
    }
    out
}

fn gen_secret_key() -> String {
    let mut buf = [0u8; SECRET_KEY_RAND_BYTES];
    OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_key_shape() {
        let k = gen_access_key();
        assert!(k.starts_with("ASIA"));
        assert_eq!(k.len(), 4 + ACCESS_KEY_RAND_BYTES * 2);
    }

    #[test]
    fn secret_key_shape() {
        let s = gen_secret_key();
        // 30 bytes URL-safe-no-pad base64 → 40 chars.
        assert_eq!(s.len(), 40);
    }

    #[test]
    fn lookup_returns_none_after_expiry() {
        let store = SessionStore::new(16, Duration::from_secs(60));
        let entry = store
            .create("AKIAREAL", "bkt", SessionMode::ReadWrite, Duration::from_millis(1))
            .expect("under cap");
        std::thread::sleep(Duration::from_millis(5));
        assert!(store.lookup(&entry.access_key).is_none());
        // expired entry was evicted on lookup
        assert_eq!(store.active_count(), 0);
    }

    #[test]
    fn max_active_cap_enforced() {
        let store = SessionStore::new(1, Duration::from_secs(60));
        assert!(
            store
                .create("AKIAREAL", "bkt", SessionMode::ReadWrite, Duration::from_secs(60))
                .is_some()
        );
        assert!(
            store
                .create("AKIAREAL", "bkt", SessionMode::ReadWrite, Duration::from_secs(60))
                .is_none()
        );
    }

    #[test]
    fn mode_header_defaults_to_readwrite() {
        assert_eq!(SessionMode::from_header(None), SessionMode::ReadWrite);
        assert_eq!(SessionMode::from_header(Some("")), SessionMode::ReadWrite);
        assert_eq!(SessionMode::from_header(Some("ReadWrite")), SessionMode::ReadWrite);
        assert_eq!(SessionMode::from_header(Some("readwrite")), SessionMode::ReadWrite);
        assert_eq!(SessionMode::from_header(Some("ReadOnly")), SessionMode::ReadOnly);
        assert_eq!(SessionMode::from_header(Some("readonly")), SessionMode::ReadOnly);
    }
}
