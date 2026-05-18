//! Per-worker idempotency cache for the `x-amz-client-token` header.
//!
//! mountpoint-s3 always emits a UUID `x-amz-client-token` on RenameObject
//! (auto-generated if the caller doesn't provide one — see
//! `mountpoint-s3-client/src/s3_crt_client/rename_object.rs:64-73` upstream).
//! On a retried request (TCP blip, stale-connection retry, …) the same
//! token must replay the original response instead of re-executing the
//! rename — otherwise the retry sees the source already moved and returns
//! `NoSuchKey 404`, which the client takes as a real failure.
//!
//! Design
//! ------
//! - One cache per gateway worker process. Tokens are scoped to one
//!   mount-s3 process by construction (fresh UUIDs), so cross-worker
//!   sharing buys nothing.
//! - Two-state entry: `Pending` (operation in flight; concurrent retries
//!   block on the inner mutex) and `Done` (cached `(status, body)`).
//!   Same-token concurrent retries serialize on the mutex so only the
//!   first actually executes — the second wakes to find the cached
//!   response and returns it.
//! - TTL-bounded; lazily-spawned sweeper task evicts `Done` entries past
//!   their TTL. `Pending` entries are never swept (a live caller still
//!   holds the guard).
//! - Bounded size: at the cap, new tokens execute uncached
//!   (`Lookup::BypassCacheFull`) rather than failing. Graceful
//!   degradation under a hostile or buggy client.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use dashmap::DashMap;
use http::StatusCode;
use tokio::{
    sync::{Mutex, OwnedMutexGuard},
    time,
};

/// Outcome of looking a `(token, fingerprint)` pair up in the cache.
///
/// Variants are mutually exclusive; the caller branches on which one fires:
///
/// - `Replay`: token already completed with the same fingerprint —
///   return the cached response.
/// - `Conflict`: token completed with a *different* fingerprint —
///   AWS-shape `IdempotentParameterMismatch`.
/// - `Pending`: caller holds the per-token mutex and must execute the
///   operation, then `commit` or `abandon` the guard.
/// - `BypassCacheFull`: cache at `max_entries` — caller proceeds
///   without idempotency support (still produces correct one-shot
///   response, just not deduplicated across retries).
pub enum Lookup {
    Replay { status: StatusCode, body: Vec<u8> },
    Conflict,
    Pending(EntryGuard),
    BypassCacheFull,
}

/// Held by the caller while executing the cached operation. Must end in
/// either `commit` (publishes the response so retries can replay) or
/// `abandon` (removes the entry so retries can try fresh).
pub struct EntryGuard {
    cache: Arc<IdempotencyCache>,
    token: String,
    /// `OwnedMutexGuard` over the entry's `Mutex<EntryState>`. Held until
    /// `commit` or `abandon` runs, blocking any concurrent retry with the
    /// same token until we publish a result.
    guard: OwnedMutexGuard<EntryState>,
}

impl EntryGuard {
    /// Publish the cached response. Future calls with the same
    /// `(token, fingerprint)` get `Lookup::Replay`; with a different
    /// fingerprint, `Lookup::Conflict`.
    pub fn commit(mut self, fingerprint: String, status: StatusCode, body: Vec<u8>) {
        *self.guard = EntryState::Done { completed_at: Instant::now(), fingerprint, status, body };
        // Dropping `self.guard` here releases the per-entry mutex so any
        // concurrent retry blocked on `enter` wakes and sees `Done`.
    }

    /// Drop the entry without caching. A subsequent retry of this token
    /// will see an empty slot and execute fresh. Use on failure paths
    /// where re-execution is preferable to caching a transient error.
    pub fn abandon(self) {
        // Drop the mutex guard before removing from the map — otherwise
        // a concurrent retry that's blocked on the mutex would briefly
        // see the (now-stale) entry, then race with the map removal.
        let token = self.token;
        let cache = self.cache;
        drop(self.guard);
        cache.inner.remove(&token);
    }
}

enum EntryState {
    Pending,
    Done {
        completed_at: Instant,
        fingerprint:  String,
        status:       StatusCode,
        body:         Vec<u8>,
    },
}

pub struct IdempotencyCache {
    inner:            DashMap<String, Arc<Mutex<EntryState>>>,
    ttl:              Duration,
    cleanup_interval: Duration,
    max_entries:      usize,
    cleanup_started:  AtomicBool,
}

impl IdempotencyCache {
    pub fn new(ttl: Duration, cleanup_interval: Duration, max_entries: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: DashMap::new(),
            ttl,
            cleanup_interval,
            max_entries,
            cleanup_started: AtomicBool::new(false),
        })
    }

    /// Acquire the slot for `token`. Concurrent retries with the same
    /// token block here until the in-flight one publishes a result via
    /// `commit` (or removes the entry via `abandon`).
    pub async fn enter(self: &Arc<Self>, token: &str, fingerprint: &str) -> Lookup {
        // Fast path: the cap. Approximate (DashMap::len is racy under
        // concurrent inserts) but adequate — at most a handful of
        // entries past the cap, which is fine.
        if !self.inner.contains_key(token) && self.inner.len() >= self.max_entries {
            return Lookup::BypassCacheFull;
        }

        // Acquire or create the per-token mutex. `entry().or_insert_with`
        // is atomic; only one of N concurrent racers actually inserts.
        let entry = self
            .inner
            .entry(token.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(EntryState::Pending)))
            .clone();

        let guard = entry.lock_owned().await;
        match &*guard {
            EntryState::Done { fingerprint: stored, status, body, .. } => {
                if stored == fingerprint {
                    Lookup::Replay { status: *status, body: body.clone() }
                } else {
                    Lookup::Conflict
                }
            }
            EntryState::Pending => {
                Lookup::Pending(EntryGuard { cache: self.clone(), token: token.to_string(), guard })
            }
        }
    }

    /// Lazily spawn the background sweeper. Idempotent across concurrent
    /// callers via `compare_exchange`. Must be called from inside the
    /// tokio runtime — the hyper server is already up before any request
    /// handler runs, so `handle()` is a safe place to call this from.
    /// Mirrors `s32p-proxy/src/session.rs::SessionStore::start_cleanup`.
    pub fn start_cleanup(self: &Arc<Self>) {
        if self
            .cleanup_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        let cache = Arc::clone(self);
        let interval = self.cleanup_interval;
        let ttl = self.ttl;
        tokio::spawn(async move {
            let mut tick = time::interval(interval);
            // Skip the immediate first tick — wait one full interval
            // before the first sweep.
            tick.tick().await;
            loop {
                tick.tick().await;
                let now = Instant::now();
                cache.inner.retain(|_, slot| {
                    // `try_lock`: if a request is currently holding the
                    // mutex (Pending), leave the entry alone. Done
                    // entries past TTL are evicted.
                    match slot.try_lock() {
                        Ok(g) => match &*g {
                            EntryState::Done { completed_at, .. } => {
                                now.duration_since(*completed_at) < ttl
                            }
                            EntryState::Pending => true,
                        },
                        Err(_) => true,
                    }
                });
            }
        });
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache_with(ttl: Duration, max: usize) -> Arc<IdempotencyCache> {
        IdempotencyCache::new(ttl, Duration::from_secs(60), max)
    }

    #[tokio::test]
    async fn fresh_token_returns_pending() {
        let cache = cache_with(Duration::from_secs(60), 16);
        let res = cache.enter("tok-1", "fp-1").await;
        assert!(matches!(res, Lookup::Pending(_)));
    }

    #[tokio::test]
    async fn commit_then_lookup_returns_replay() {
        let cache = cache_with(Duration::from_secs(60), 16);
        let guard = match cache.enter("tok-1", "fp-1").await {
            Lookup::Pending(g) => g,
            _ => panic!("expected Pending on first call"),
        };
        guard.commit("fp-1".to_string(), StatusCode::OK, b"<ok/>".to_vec());

        match cache.enter("tok-1", "fp-1").await {
            Lookup::Replay { status, body } => {
                assert_eq!(status, StatusCode::OK);
                assert_eq!(body, b"<ok/>");
            }
            other => panic!("expected Replay, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[tokio::test]
    async fn mismatched_fingerprint_returns_conflict() {
        let cache = cache_with(Duration::from_secs(60), 16);
        let guard = match cache.enter("tok-1", "fp-A").await {
            Lookup::Pending(g) => g,
            _ => unreachable!(),
        };
        guard.commit("fp-A".to_string(), StatusCode::OK, vec![]);

        match cache.enter("tok-1", "fp-B").await {
            Lookup::Conflict => {}
            _ => panic!("expected Conflict on fingerprint change"),
        }
    }

    #[tokio::test]
    async fn abandoned_entry_allows_retry() {
        let cache = cache_with(Duration::from_secs(60), 16);
        let guard = match cache.enter("tok-1", "fp-1").await {
            Lookup::Pending(g) => g,
            _ => unreachable!(),
        };
        guard.abandon();

        // After abandon, the entry must be gone — next caller gets a fresh Pending.
        assert!(matches!(cache.enter("tok-1", "fp-1").await, Lookup::Pending(_)));
    }

    #[tokio::test]
    async fn concurrent_same_token_serializes() {
        // Two simultaneous calls with the same token: one wins the Pending
        // slot, executes, commits; the other blocks on the mutex and wakes
        // to find Replay. Different fingerprints across the two callers
        // would have produced Conflict for the second — we use the same
        // fingerprint here because that's the realistic "TCP retry of the
        // same request" shape.
        let cache = cache_with(Duration::from_secs(60), 16);

        let cache_a = Arc::clone(&cache);
        let cache_b = Arc::clone(&cache);

        // Start A first; have it sleep briefly inside Pending so B is
        // queued on the mutex.
        let a = tokio::spawn(async move {
            let g = match cache_a.enter("tok-1", "fp-1").await {
                Lookup::Pending(g) => g,
                _ => panic!("A expected Pending"),
            };
            // Yield so B definitely enters and parks on the mutex.
            tokio::time::sleep(Duration::from_millis(20)).await;
            g.commit("fp-1".to_string(), StatusCode::OK, b"A-result".to_vec());
        });

        // Give A a head start so B enters second.
        tokio::time::sleep(Duration::from_millis(5)).await;

        let b = tokio::spawn(async move { cache_b.enter("tok-1", "fp-1").await });

        a.await.unwrap();
        match b.await.unwrap() {
            Lookup::Replay { status, body } => {
                assert_eq!(status, StatusCode::OK);
                assert_eq!(body, b"A-result");
            }
            _ => panic!("B expected Replay (queued behind A, sees committed result)"),
        }
    }

    #[tokio::test]
    async fn expired_entries_are_swept() {
        // Tight TTL + tight cleanup interval so the sweeper fires within
        // the test window. The cache only sweeps `Done` entries; `Pending`
        // would be preserved (a live caller still holds the guard).
        let cache = IdempotencyCache::new(Duration::from_millis(40), Duration::from_millis(20), 16);
        cache.start_cleanup();

        let g = match cache.enter("tok-1", "fp-1").await {
            Lookup::Pending(g) => g,
            _ => unreachable!(),
        };
        g.commit("fp-1".to_string(), StatusCode::OK, vec![]);
        assert_eq!(cache.len(), 1);

        // Sleep past TTL + at least one sweep tick (skip-first tick means
        // we need ~2× the interval to be safe).
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(cache.len(), 0, "expired Done entry should be swept");
    }

    #[tokio::test]
    async fn cap_returns_bypass() {
        let cache = cache_with(Duration::from_secs(60), 1);
        // Fill to capacity.
        let g = match cache.enter("tok-1", "fp-1").await {
            Lookup::Pending(g) => g,
            _ => unreachable!(),
        };
        g.commit("fp-1".to_string(), StatusCode::OK, vec![]);

        // A new token at the cap → BypassCacheFull. Same token (already
        // present) would still hit the existing entry — only *new* tokens
        // get bypassed.
        match cache.enter("tok-2", "fp-2").await {
            Lookup::BypassCacheFull => {}
            _ => panic!("expected BypassCacheFull when cache is at cap"),
        }
        // The existing token still works — bypass only fires for new tokens
        // when the map is at cap.
        assert!(matches!(cache.enter("tok-1", "fp-1").await, Lookup::Replay { .. }));
    }
}
