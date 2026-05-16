//! TTL cache decorator over the [`Directory`] trait.
//!
//! Wraps any `Arc<dyn Directory>` (or any concrete `Directory` impl)
//! and short-circuits repeated lookups within `cfg.user_ttl` /
//! `cfg.buckets_ttl`. Negative results (`Ok(None)` from
//! [`Directory::user_by_access_key`]) are cached for the shorter
//! `cfg.negative_ttl` so an invalid-access-key flood can't hammer the
//! backend (relevant for the OpenBao backend; YAML lookups are free).
//! Backend errors are never cached — transient failures must propagate
//! so callers see the next attempt's outcome.
//!
//! ACL state is also snapshotted into spawned workers via
//! `S32P_BUCKET_ACL` (see `s32p-proxy::worker_manager::format_bucket_acl`).
//! That snapshot is independent of this cache and stays frozen for a
//! worker's lifetime; this cache only controls how fresh the *next*
//! spawn's snapshot is. ACL changes therefore propagate at
//! `max(buckets_ttl, idle_timeout_secs)` worst-case.
//!
//! # Concurrency notes
//!
//! Cold-cache fan-out is deduplicated by per-key single-flight: when N
//! concurrent callers all miss, the first one acquires the per-key
//! flight lock and goes to the backend; the rest serialize on the same
//! lock and re-check the cache after acquiring it, so only one backend
//! call happens per (key, fetch-cycle).
//!
//! On a backend error, the slot is not poisoned — the next waiter
//! retries its own fetch (serialized via the same flight lock). This
//! keeps the cache-error path from amplifying load on a struggling
//! backend.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::{Mutex, RwLock};

use crate::{BucketView, Directory, UserDoc};

/// Cache parameters. Positive entries (user found, buckets list ready)
/// live for `user_ttl` / `buckets_ttl`; negative `user_by_access_key`
/// results live for the shorter `negative_ttl`. `max_entries` is a
/// soft cap per map — at the cap we prune expired entries on the next
/// insert, and if everything is fresh, evict the entry with the
/// soonest expiry.
#[derive(Clone, Debug)]
pub struct CacheConfig {
    pub user_ttl:     Duration,
    pub buckets_ttl:  Duration,
    pub negative_ttl: Duration,
    pub max_entries:  usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            user_ttl:     Duration::from_secs(30),
            buckets_ttl:  Duration::from_secs(30),
            negative_ttl: Duration::from_secs(5),
            max_entries:  4096,
        }
    }
}

struct Entry<V> {
    value:      V,
    expires_at: Instant,
}

/// Per-key flight lock: tasks racing on the same cold key all hold
/// their own clone of the same `Arc<Mutex<()>>` and serialize through
/// it. Empty unit value is sufficient — the lock itself is the signal.
type FlightSlots = Mutex<HashMap<String, Arc<Mutex<()>>>>;

pub struct CachingDirectory<D: ?Sized> {
    inner:            Arc<D>,
    cfg:              CacheConfig,
    users:            RwLock<HashMap<String, Entry<Option<UserDoc>>>>,
    buckets:          RwLock<HashMap<String, Entry<Vec<BucketView>>>>,
    users_inflight:   FlightSlots,
    buckets_inflight: FlightSlots,
}

impl<D: Directory + ?Sized> CachingDirectory<D> {
    pub fn new(inner: Arc<D>, cfg: CacheConfig) -> Self {
        Self {
            inner,
            cfg,
            users: RwLock::new(HashMap::new()),
            buckets: RwLock::new(HashMap::new()),
            users_inflight: Mutex::new(HashMap::new()),
            buckets_inflight: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl<D: Directory + ?Sized> Directory for CachingDirectory<D> {
    async fn user_by_access_key(&self, access_key: &str) -> Result<Option<UserDoc>> {
        if let Some(hit) = read_fresh(&self.users, access_key).await {
            // Hits are the hot path — keep them at trace level so a
            // typical `RUST_LOG=info` deployment doesn't pay for them.
            tracing::trace!(
                target: "s32p_directory::cache",
                access_key,
                map = "users",
                outcome = if hit.is_some() { "positive" } else { "negative" },
                "cache hit",
            );
            return Ok(hit);
        }

        // Single-flight: serialize concurrent cold misses on the same
        // key through a per-key lock. The follower path then re-checks
        // the cache and almost always sees the leader's populated entry.
        let key_lock = acquire_flight_slot(&self.users_inflight, access_key).await;
        let flight = key_lock.lock().await;

        if let Some(hit) = read_fresh(&self.users, access_key).await {
            tracing::trace!(
                target: "s32p_directory::cache",
                access_key,
                map = "users",
                outcome = if hit.is_some() { "positive" } else { "negative" },
                role = "follower",
                "single-flight cache hit",
            );
            drop(flight);
            drop(key_lock);
            release_flight_slot(&self.users_inflight, access_key).await;
            return Ok(hit);
        }

        let result = self.inner.user_by_access_key(access_key).await;
        if let Ok(value) = &result {
            let (ttl, outcome) = if value.is_some() {
                (self.cfg.user_ttl, "positive")
            } else {
                (self.cfg.negative_ttl, "negative")
            };
            // Misses are interesting for tuning — debug level so they
            // show up under `RUST_LOG=s32p_directory::cache=debug`.
            tracing::debug!(
                target: "s32p_directory::cache",
                access_key,
                map = "users",
                outcome,
                ttl_secs = ttl.as_secs(),
                "cache miss; populated from backend",
            );
            insert_with_cap(&self.users, access_key, value.clone(), ttl, self.cfg.max_entries)
                .await;
        } else {
            tracing::debug!(
                target: "s32p_directory::cache",
                access_key,
                map = "users",
                "cache miss; backend error, not cached",
            );
        }

        drop(flight);
        drop(key_lock);
        release_flight_slot(&self.users_inflight, access_key).await;
        result
    }

    async fn buckets_for_access_key(&self, access_key: &str) -> Result<Vec<BucketView>> {
        if let Some(hit) = read_fresh(&self.buckets, access_key).await {
            tracing::trace!(
                target: "s32p_directory::cache",
                access_key,
                map = "buckets",
                entries = hit.len(),
                "cache hit",
            );
            return Ok(hit);
        }

        let key_lock = acquire_flight_slot(&self.buckets_inflight, access_key).await;
        let flight = key_lock.lock().await;

        if let Some(hit) = read_fresh(&self.buckets, access_key).await {
            tracing::trace!(
                target: "s32p_directory::cache",
                access_key,
                map = "buckets",
                entries = hit.len(),
                role = "follower",
                "single-flight cache hit",
            );
            drop(flight);
            drop(key_lock);
            release_flight_slot(&self.buckets_inflight, access_key).await;
            return Ok(hit);
        }

        let result = self.inner.buckets_for_access_key(access_key).await;
        if let Ok(value) = &result {
            // No distinct negative TTL: an empty Vec is a valid positive
            // answer (e.g. a user with no granted buckets), and an
            // unknown access key already returns Ok(vec![]) in both
            // backends today.
            tracing::debug!(
                target: "s32p_directory::cache",
                access_key,
                map = "buckets",
                entries = value.len(),
                ttl_secs = self.cfg.buckets_ttl.as_secs(),
                "cache miss; populated from backend",
            );
            insert_with_cap(
                &self.buckets,
                access_key,
                value.clone(),
                self.cfg.buckets_ttl,
                self.cfg.max_entries,
            )
            .await;
        } else {
            tracing::debug!(
                target: "s32p_directory::cache",
                access_key,
                map = "buckets",
                "cache miss; backend error, not cached",
            );
        }

        drop(flight);
        drop(key_lock);
        release_flight_slot(&self.buckets_inflight, access_key).await;
        result
    }
}

/// Claim or join the per-key flight slot. The returned `Arc<Mutex<()>>`
/// must subsequently be `.lock().await`ed to serialize with any other
/// concurrent caller for the same key.
async fn acquire_flight_slot(slots: &FlightSlots, key: &str) -> Arc<Mutex<()>> {
    let mut map = slots.lock().await;
    Arc::clone(map.entry(key.to_string()).or_insert_with(|| Arc::new(Mutex::new(()))))
}

/// Drop the per-key flight slot if no other task still holds a
/// reference. Strong-count comparison is reliable here because every
/// joiner holds an `Arc` clone from `acquire_flight_slot`, so the slot
/// is only safe to remove when the map's entry is the sole remaining
/// reference. Call this only after dropping the local `Arc` returned by
/// `acquire_flight_slot` and the lock guard.
async fn release_flight_slot(slots: &FlightSlots, key: &str) {
    let mut map = slots.lock().await;
    if let Some(existing) = map.get(key)
        && Arc::strong_count(existing) == 1
    {
        map.remove(key);
    }
}

async fn read_fresh<V: Clone>(map: &RwLock<HashMap<String, Entry<V>>>, key: &str) -> Option<V> {
    let m = map.read().await;
    m.get(key).filter(|e| e.expires_at > Instant::now()).map(|e| e.value.clone())
}

async fn insert_with_cap<V>(
    map: &RwLock<HashMap<String, Entry<V>>>,
    key: &str,
    value: V,
    ttl: Duration,
    cap: usize,
) {
    let mut m = map.write().await;
    if m.len() >= cap {
        let before = m.len();
        let now = Instant::now();
        m.retain(|_, e| e.expires_at > now);
        let pruned = before - m.len();
        // Still at the cap with all-fresh entries: evict the entry
        // with the soonest expiry. Bounded O(n) work, only on
        // pathological insert pressure.
        if m.len() >= cap
            && let Some(victim) = m.iter().min_by_key(|(_, e)| e.expires_at).map(|(k, _)| k.clone())
        {
            tracing::debug!(
                target: "s32p_directory::cache",
                cap,
                pruned_expired = pruned,
                evicted = %victim,
                "cache at capacity; pruned expired and evicted soonest-expiring entry",
            );
            m.remove(&victim);
        } else if pruned > 0 {
            tracing::debug!(
                target: "s32p_directory::cache",
                cap,
                pruned_expired = pruned,
                "cache at capacity; pruned expired entries",
            );
        }
    }
    m.insert(key.to_string(), Entry { value, expires_at: Instant::now() + ttl });
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use anyhow::anyhow;

    use super::*;
    use crate::types::AccessLevel;

    /// Counts calls and serves canned responses keyed by access key.
    /// `users[key]` is the response shape for that lookup; missing keys
    /// answer `Ok(None)`. `error_once` flips back to `false` after the
    /// first call, so error-not-cached can be exercised cleanly.
    struct MockDirectory {
        users:                HashMap<String, Option<UserDoc>>,
        buckets:              HashMap<String, Vec<BucketView>>,
        user_calls:           AtomicUsize,
        buckets_calls:        AtomicUsize,
        user_error_once_left: AtomicUsize, // emit Err on this many remaining calls
    }

    impl MockDirectory {
        fn new() -> Self {
            Self {
                users:                HashMap::new(),
                buckets:              HashMap::new(),
                user_calls:           AtomicUsize::new(0),
                buckets_calls:        AtomicUsize::new(0),
                user_error_once_left: AtomicUsize::new(0),
            }
        }

        fn with_user(mut self, k: &str, doc: UserDoc) -> Self {
            self.users.insert(k.to_string(), Some(doc));
            self
        }

        fn with_missing_user(mut self, k: &str) -> Self {
            self.users.insert(k.to_string(), None);
            self
        }

        fn with_buckets(mut self, k: &str, bs: Vec<BucketView>) -> Self {
            self.buckets.insert(k.to_string(), bs);
            self
        }

        fn with_user_errors(self, n: usize) -> Self {
            self.user_error_once_left.store(n, Ordering::SeqCst);
            self
        }
    }

    #[async_trait]
    impl Directory for MockDirectory {
        async fn user_by_access_key(&self, k: &str) -> Result<Option<UserDoc>> {
            self.user_calls.fetch_add(1, Ordering::SeqCst);
            // Burn one error if any left.
            let left = self.user_error_once_left.load(Ordering::SeqCst);
            if left > 0 {
                self.user_error_once_left.store(left - 1, Ordering::SeqCst);
                return Err(anyhow!("simulated backend error"));
            }
            Ok(self.users.get(k).cloned().unwrap_or(None))
        }

        async fn buckets_for_access_key(&self, k: &str) -> Result<Vec<BucketView>> {
            self.buckets_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.buckets.get(k).cloned().unwrap_or_default())
        }
    }

    fn sample_user(access_key: &str) -> UserDoc {
        UserDoc {
            access_key: access_key.to_string(),
            secret_key: "secret".to_string(),
            username:   "alice".to_string(),
            uid:        1000,
            gid:        1000,
        }
    }

    fn sample_bucket(name: &str, access: AccessLevel) -> BucketView {
        BucketView {
            bucket_id: format!("bkt-{name}"),
            bucket_name: name.to_string(),
            data_path: format!("/srv/{name}"),
            access,
        }
    }

    fn fast_cfg() -> CacheConfig {
        // Short, real-time TTLs keep the suite fast without `pause()`.
        CacheConfig {
            user_ttl:     Duration::from_millis(120),
            buckets_ttl:  Duration::from_millis(120),
            negative_ttl: Duration::from_millis(40),
            max_entries:  4096,
        }
    }

    #[tokio::test]
    async fn hit_within_ttl_avoids_backend_call() {
        let mock = Arc::new(MockDirectory::new().with_user("k1", sample_user("k1")));
        let cache = CachingDirectory::new(mock.clone(), fast_cfg());

        let a = cache.user_by_access_key("k1").await.unwrap();
        let b = cache.user_by_access_key("k1").await.unwrap();
        assert!(a.is_some() && b.is_some());
        assert_eq!(mock.user_calls.load(Ordering::SeqCst), 1, "second call must hit cache");
    }

    #[tokio::test]
    async fn miss_after_ttl_refetches() {
        let mock = Arc::new(MockDirectory::new().with_user("k1", sample_user("k1")));
        let cache = CachingDirectory::new(mock.clone(), fast_cfg());

        cache.user_by_access_key("k1").await.unwrap();
        tokio::time::sleep(Duration::from_millis(180)).await;
        cache.user_by_access_key("k1").await.unwrap();
        assert_eq!(
            mock.user_calls.load(Ordering::SeqCst),
            2,
            "post-TTL call must refetch from the backend"
        );
    }

    #[tokio::test]
    async fn negative_result_uses_short_ttl() {
        let mock = Arc::new(MockDirectory::new().with_missing_user("ghost"));
        let cache = CachingDirectory::new(mock.clone(), fast_cfg());

        // First miss → backend (call 1), cached as None for negative_ttl=40ms.
        let r = cache.user_by_access_key("ghost").await.unwrap();
        assert!(r.is_none());
        // Within negative_ttl: cache hit, no extra call.
        let r = cache.user_by_access_key("ghost").await.unwrap();
        assert!(r.is_none());
        assert_eq!(mock.user_calls.load(Ordering::SeqCst), 1);

        // After negative_ttl (60ms) but before user_ttl (120ms): must refetch
        // because the negative TTL applies, not the positive one.
        tokio::time::sleep(Duration::from_millis(60)).await;
        cache.user_by_access_key("ghost").await.unwrap();
        assert_eq!(
            mock.user_calls.load(Ordering::SeqCst),
            2,
            "negative_ttl must expire independently of user_ttl"
        );
    }

    #[tokio::test]
    async fn error_is_not_cached() {
        // First call returns Err; second call returns the canned Some.
        let mock =
            Arc::new(MockDirectory::new().with_user("k1", sample_user("k1")).with_user_errors(1));
        let cache = CachingDirectory::new(mock.clone(), fast_cfg());

        assert!(cache.user_by_access_key("k1").await.is_err());
        // No sleep — error must not have populated the cache, so the
        // second call goes to the backend immediately and succeeds.
        let r = cache.user_by_access_key("k1").await.unwrap();
        assert!(r.is_some());
        assert_eq!(mock.user_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn buckets_cache_is_independent_of_users_cache() {
        let mock = Arc::new(
            MockDirectory::new()
                .with_user("k1", sample_user("k1"))
                .with_buckets("k1", vec![sample_bucket("photos", AccessLevel::ReadWrite)]),
        );
        let cache = CachingDirectory::new(mock.clone(), fast_cfg());

        // Caching user lookup must not satisfy buckets lookup.
        cache.user_by_access_key("k1").await.unwrap();
        assert_eq!(mock.user_calls.load(Ordering::SeqCst), 1);
        assert_eq!(mock.buckets_calls.load(Ordering::SeqCst), 0);

        cache.buckets_for_access_key("k1").await.unwrap();
        assert_eq!(mock.user_calls.load(Ordering::SeqCst), 1);
        assert_eq!(mock.buckets_calls.load(Ordering::SeqCst), 1);

        // Repeating both hits the respective caches.
        cache.user_by_access_key("k1").await.unwrap();
        cache.buckets_for_access_key("k1").await.unwrap();
        assert_eq!(mock.user_calls.load(Ordering::SeqCst), 1);
        assert_eq!(mock.buckets_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn bound_enforcement_keeps_size_capped() {
        let mut mock = MockDirectory::new();
        for i in 0..6 {
            let k = format!("k{i}");
            mock = mock.with_user(&k, sample_user(&k));
        }
        let mock = Arc::new(mock);
        let cfg = CacheConfig {
            user_ttl:     Duration::from_secs(60), // long → no expiry pruning fires
            buckets_ttl:  Duration::from_secs(60),
            negative_ttl: Duration::from_secs(60),
            max_entries:  4,
        };
        let cache = CachingDirectory::new(mock.clone(), cfg);

        for i in 0..6 {
            cache.user_by_access_key(&format!("k{i}")).await.unwrap();
        }
        // After exceeding the cap with all-fresh entries, the soonest-
        // expiry eviction kicks in.
        let len = cache.users.read().await.len();
        assert!(len <= 4, "users map size {len} must be <= cap of 4");
    }

    /// Slow mock whose backend call sleeps, widening the cold-burst race
    /// window so single-flight has something to deduplicate.
    struct SlowMock {
        user:          Option<UserDoc>,
        user_calls:    AtomicUsize,
        buckets:       Vec<BucketView>,
        buckets_calls: AtomicUsize,
        delay:         Duration,
    }

    #[async_trait]
    impl Directory for SlowMock {
        async fn user_by_access_key(&self, _k: &str) -> Result<Option<UserDoc>> {
            self.user_calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            Ok(self.user.clone())
        }

        async fn buckets_for_access_key(&self, _k: &str) -> Result<Vec<BucketView>> {
            self.buckets_calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            Ok(self.buckets.clone())
        }
    }

    #[tokio::test]
    async fn singleflight_collapses_cold_burst_to_one_backend_call() {
        let mock = Arc::new(SlowMock {
            user:          Some(sample_user("k1")),
            user_calls:    AtomicUsize::new(0),
            buckets:       vec![sample_bucket("photos", AccessLevel::ReadWrite)],
            buckets_calls: AtomicUsize::new(0),
            delay:         Duration::from_millis(40),
        });
        let cache = Arc::new(CachingDirectory::new(mock.clone(), fast_cfg()));

        // 10 concurrent users + 10 concurrent buckets lookups on the
        // same cold key. Without single-flight this fans out to 20
        // backend calls; with it, exactly 2 (one per map).
        let mut handles = Vec::new();
        for _ in 0..10 {
            let c = Arc::clone(&cache);
            handles.push(tokio::spawn(async move {
                c.user_by_access_key("k1").await.unwrap();
            }));
            let c = Arc::clone(&cache);
            handles.push(tokio::spawn(async move {
                c.buckets_for_access_key("k1").await.unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        assert_eq!(
            mock.user_calls.load(Ordering::SeqCst),
            1,
            "10 concurrent cold users lookups must collapse to 1 backend call"
        );
        assert_eq!(
            mock.buckets_calls.load(Ordering::SeqCst),
            1,
            "10 concurrent cold buckets lookups must collapse to 1 backend call"
        );
    }

    #[tokio::test]
    async fn singleflight_slot_is_cleaned_up_after_completion() {
        let mock = Arc::new(MockDirectory::new().with_user("k1", sample_user("k1")));
        let cache = CachingDirectory::new(mock.clone(), fast_cfg());

        cache.user_by_access_key("k1").await.unwrap();
        cache.buckets_for_access_key("k1").await.unwrap();

        assert!(
            cache.users_inflight.lock().await.is_empty(),
            "users flight slot must be released after fetch completes"
        );
        assert!(
            cache.buckets_inflight.lock().await.is_empty(),
            "buckets flight slot must be released after fetch completes"
        );
    }

    #[tokio::test]
    async fn singleflight_error_does_not_prevent_subsequent_success() {
        // Leader's fetch errors; the next caller must be able to retry
        // and succeed without being blocked by a poisoned flight slot.
        let mock =
            Arc::new(MockDirectory::new().with_user("k1", sample_user("k1")).with_user_errors(1));
        let cache = CachingDirectory::new(mock.clone(), fast_cfg());

        assert!(cache.user_by_access_key("k1").await.is_err());
        let r = cache.user_by_access_key("k1").await.unwrap();
        assert!(r.is_some());
        assert_eq!(mock.user_calls.load(Ordering::SeqCst), 2);
        assert!(
            cache.users_inflight.lock().await.is_empty(),
            "flight slot must not be left dangling after an errored fetch"
        );
    }

    #[tokio::test]
    async fn yaml_passthrough_smoke() {
        // Builds a real YamlDirectory off a tempfile-backed directory.yaml
        // and confirms it's wrappable by the cache without any boxing /
        // ?Sized mistakes. Catches regressions that wouldn't show up on
        // the inline mock (which is Sized).
        use std::io::Write as _;

        use crate::yaml::YamlDirectory;

        let yaml = r#"
version: 1
users:
  - access_key: "akey"
    secret_key: "skey"
    username: "alice"
    uid: 1000
    gid: 1000
buckets: []
"#;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(yaml.as_bytes()).unwrap();
        let path = tmp.path().to_str().unwrap();
        let yd: Arc<dyn Directory> = Arc::new(YamlDirectory::from_path(path).unwrap());
        let cache = CachingDirectory::new(yd, fast_cfg());

        let u = cache.user_by_access_key("akey").await.unwrap();
        assert!(u.is_some());
        assert_eq!(u.as_ref().unwrap().username, "alice");

        let bs = cache.buckets_for_access_key("akey").await.unwrap();
        assert!(bs.is_empty());
    }
}
