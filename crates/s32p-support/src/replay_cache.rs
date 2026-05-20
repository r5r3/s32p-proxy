//! In-memory cache of recently-seen SigV4 signatures.
//!
//! Records the 32-byte HMAC-SHA256 signature of every successfully verified
//! request and rejects subsequent requests carrying the same signature
//! within its protection window. Only signatures that already passed
//! verification are inserted, so an attacker without valid credentials
//! cannot grind the cache.
//!
//! Per-entry expiry (header-signed)
//! --------------------------------
//! [`ReplayCache::check_and_record_until`] lets the caller specify
//! exactly when the entry expires. For header-signed requests the caller
//! passes `x_amz_date + HEADER_SIGV4_MAX_SKEW + 1s` — the latest server
//! time the signature could still verify. This closes a clock-skew gap
//! that a fixed `now + TTL` opens: if the server clock is *behind* the
//! client at insert time, a fixed TTL evicts the entry before the
//! signature stops being verifiable. Anchoring the expiry on the
//! client's `x-amz-date` eliminates that gap regardless of skew
//! direction. Worst-case entry lifetime is `max_entry_lifetime()` =
//! `2 × HEADER_SIGV4_MAX_SKEW + 1` (~30 min). The proxy's startup
//! invariant requires `workers.lifecycle.idle_timeout_secs >=
//! max_entry_lifetime()` so a worker is never recycled while one of its
//! cache entries is still inside its protection window.
//!
//! Fallback fixed TTL (presigned)
//! -------------------------------
//! [`ReplayCache::check_and_record`] uses `now + ttl()`. This is the
//! presigned-URL path. `X-Amz-Expires` may extend far beyond what is
//! reasonable to keep in memory (up to 7 days), so replay protection for
//! presigned URLs is deliberately bounded to "the first `ttl()` seconds
//! after receipt". A captured presigned URL replayed past that window
//! will be re-accepted by the cache — that gap is a documented
//! trade-off, not a bug.

use std::time::{Duration, Instant};

use dashmap::{DashMap, mapref::entry::Entry};

use crate::HEADER_SIGV4_MAX_SKEW;

/// Bounded TTL set of recently-seen SigV4 signature bytes.
pub struct ReplayCache {
    seen: DashMap<[u8; 32], Instant>, // value = expiry instant
    ttl:  Duration,
}

/// Returned by [`ReplayCache::check_and_record`] when the signature has been
/// seen within the cache TTL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayHit;

/// Statistics produced by one [`ReplayCache::sweep`] pass. Callers can
/// log these at debug level to observe the cache's working-set size and
/// the per-sweep eviction rate without coupling `s32p-support` to a
/// logging crate.
#[derive(Debug, Clone, Copy)]
pub struct SweepStats {
    /// Entry count before sweep.
    pub before:  usize,
    /// Entry count after sweep.
    pub after:   usize,
    /// Entries evicted (= `before - after`).
    pub removed: usize,
    /// Wall-clock time spent inside `sweep`.
    pub elapsed: Duration,
}

impl ReplayCache {
    /// Construct with TTL = `HEADER_SIGV4_MAX_SKEW + 1` second.
    pub fn new() -> Self {
        Self::with_ttl(HEADER_SIGV4_MAX_SKEW + Duration::from_secs(1))
    }

    /// Construct with an explicit TTL. Tests use this to exercise expiry
    /// without sleeping for the full skew window.
    pub fn with_ttl(ttl: Duration) -> Self {
        Self { seen: DashMap::new(), ttl }
    }

    /// Fallback TTL applied when [`Self::check_and_record`] is called
    /// without an explicit expiry. Used on the presigned-URL path; see
    /// the module-level docs for the trade-off.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Upper bound on how long any single entry can live in the cache,
    /// including header-signed entries anchored at the far edge of the
    /// SigV4 skew window. The proxy startup sanity check requires
    /// `idle_timeout_secs >= max_entry_lifetime` so a worker is never
    /// torn down while it still has a cache entry inside its protection
    /// window.
    pub fn max_entry_lifetime(&self) -> Duration {
        // Worst case: legit request arrives at server time `T₀ - skew`
        // (server clock behind client by the full skew amount). The
        // header-signed entry is anchored at `T₀ + skew + 1s`. Lifetime
        // = `2 × skew + 1`. Presigned entries live `ttl <= 2 × skew + 1`
        // by construction, so this is the tightest single bound that
        // covers both paths.
        2 * HEADER_SIGV4_MAX_SKEW + Duration::from_secs(1)
    }

    /// Number of currently-tracked signatures. May include expired entries
    /// that have not yet been swept; call [`Self::sweep`] to flush.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// If `signature` has not been seen recently, record it with expiry
    /// `now + ttl()` and return `Ok(())`. Otherwise return
    /// `Err(ReplayHit)` and leave the existing entry's expiry
    /// unchanged — a replayed signature does not extend its own lockout
    /// window. Used by the presigned-URL path; see module docs.
    pub fn check_and_record(&self, signature: [u8; 32]) -> Result<(), ReplayHit> {
        self.check_and_record_until(signature, Instant::now() + self.ttl)
    }

    /// Same as [`Self::check_and_record`] but with an explicit expiry
    /// instant. Used by the header-signed path to anchor expiry on
    /// `x-amz-date + HEADER_SIGV4_MAX_SKEW + 1s`, closing the clock-skew
    /// gap that a fixed `now + ttl` would leave open.
    pub fn check_and_record_until(
        &self,
        signature: [u8; 32],
        expires_at: Instant,
    ) -> Result<(), ReplayHit> {
        let now = Instant::now();
        match self.seen.entry(signature) {
            Entry::Occupied(mut e) => {
                if now < *e.get() {
                    return Err(ReplayHit);
                }
                // Prior entry has expired — overwrite with a fresh window.
                e.insert(expires_at);
                Ok(())
            }
            Entry::Vacant(e) => {
                e.insert(expires_at);
                Ok(())
            }
        }
    }

    /// Drop expired entries. Call periodically from a background task to
    /// bound steady-state memory; lazy eviction in `check_and_record`
    /// only covers keys that are looked up again. Each binary spawns its
    /// own sweeper task — `s32p-support` is intentionally tokio-free.
    ///
    /// Returns [`SweepStats`] so callers can emit a debug log without
    /// having to re-walk the map.
    pub fn sweep(&self) -> SweepStats {
        let start = Instant::now();
        let now = start;
        let before = self.seen.len();
        self.seen.retain(|_, expires_at| *expires_at > now);
        let after = self.seen.len();
        SweepStats {
            before,
            after,
            removed: before.saturating_sub(after),
            elapsed: start.elapsed(),
        }
    }
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Decode a 64-character hex string into a 32-byte array. Accepts upper- and
/// lower-case hex (SigV4 signatures are conventionally lowercase but being
/// lenient costs nothing). Returns `None` on wrong length or non-hex input.
pub fn decode_signature_hex(s: &str) -> Option<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = (hex_nibble(bytes[i * 2])? << 4) | hex_nibble(bytes[i * 2 + 1])?;
    }
    Some(out)
}

#[inline]
fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_record_succeeds_second_is_rejected() {
        let cache = ReplayCache::new();
        let sig = [42u8; 32];
        assert!(cache.check_and_record(sig).is_ok());
        assert_eq!(cache.check_and_record(sig), Err(ReplayHit));
    }

    #[test]
    fn distinct_signatures_do_not_collide() {
        let cache = ReplayCache::new();
        cache.check_and_record([1u8; 32]).unwrap();
        cache.check_and_record([2u8; 32]).unwrap();
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn expired_entry_is_replaced() {
        let cache = ReplayCache::with_ttl(Duration::from_millis(10));
        let sig = [1u8; 32];
        cache.check_and_record(sig).unwrap();
        std::thread::sleep(Duration::from_millis(25));
        // Same signature must be accepted again after TTL.
        cache.check_and_record(sig).unwrap();
    }

    #[test]
    fn replay_within_window_does_not_extend_expiry() {
        // If a replayed sig refreshed its own expiry, a hostile loop could
        // keep an entry pinned forever and DoS the cache. Verify the
        // rejection path does not insert/refresh.
        let cache = ReplayCache::with_ttl(Duration::from_millis(20));
        let sig = [7u8; 32];
        cache.check_and_record(sig).unwrap();
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(cache.check_and_record(sig), Err(ReplayHit)); // mid-window
        std::thread::sleep(Duration::from_millis(15)); // total elapsed > 20ms
        cache.check_and_record(sig).unwrap(); // accepted; expiry was not pushed
    }

    #[test]
    fn sweep_removes_expired() {
        let cache = ReplayCache::with_ttl(Duration::from_millis(5));
        cache.check_and_record([1u8; 32]).unwrap();
        cache.check_and_record([2u8; 32]).unwrap();
        assert_eq!(cache.len(), 2);
        std::thread::sleep(Duration::from_millis(20));
        cache.sweep();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn ttl_defaults_to_header_skew_plus_one() {
        let cache = ReplayCache::new();
        assert_eq!(cache.ttl(), HEADER_SIGV4_MAX_SKEW + Duration::from_secs(1));
    }

    #[test]
    fn max_entry_lifetime_is_two_skew_plus_one() {
        let cache = ReplayCache::new();
        assert_eq!(
            cache.max_entry_lifetime(),
            2 * HEADER_SIGV4_MAX_SKEW + Duration::from_secs(1),
        );
    }

    #[test]
    fn check_and_record_until_honors_explicit_expiry() {
        // Insert with a 10ms expiry, then verify the entry is gone after
        // 20ms regardless of the cache's default ttl (which is the
        // ~15-minute production default).
        let cache = ReplayCache::new();
        let sig = [99u8; 32];
        let expires_at = Instant::now() + Duration::from_millis(10);
        cache.check_and_record_until(sig, expires_at).unwrap();
        assert_eq!(cache.check_and_record_until(sig, expires_at), Err(ReplayHit));
        std::thread::sleep(Duration::from_millis(25));
        // Past the explicit expiry, even though the cache's default ttl
        // is much longer.
        cache.check_and_record_until(sig, Instant::now() + Duration::from_millis(5)).unwrap();
    }

    #[test]
    fn check_and_record_until_can_outlive_default_ttl() {
        // The header-signed path passes an expiry derived from
        // `x-amz-date + skew`, which can be up to `2 × ttl` from now
        // when the server clock lags. Verify the cache honours expiries
        // longer than the default ttl rather than capping them.
        let cache = ReplayCache::with_ttl(Duration::from_millis(5));
        let sig = [123u8; 32];
        let expires_at = Instant::now() + Duration::from_millis(50);
        cache.check_and_record_until(sig, expires_at).unwrap();
        std::thread::sleep(Duration::from_millis(20)); // past default ttl, well before explicit
        assert_eq!(cache.check_and_record_until(sig, expires_at), Err(ReplayHit));
    }

    #[test]
    fn decode_signature_hex_roundtrip() {
        let bytes: [u8; 32] = [
            0x00, 0x11, 0xff, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
            0xf0, 0xaa, 0xbb, 0xcc,
        ];
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(decode_signature_hex(&hex), Some(bytes));
        assert_eq!(decode_signature_hex(&hex.to_uppercase()), Some(bytes));
    }

    #[test]
    fn decode_signature_hex_rejects_bad_input() {
        assert!(decode_signature_hex("").is_none());
        assert!(decode_signature_hex(&"a".repeat(63)).is_none());
        assert!(decode_signature_hex(&"a".repeat(65)).is_none());
        assert!(decode_signature_hex(&"x".repeat(64)).is_none());
    }
}
