//! Per-source-IP concurrent-request limiter + keep-alive idle override.
//!
//! Closes two attack surfaces that are reachable from the public internet
//! without any credentials:
//!
//! 1. **FD exhaustion via dormant keep-alive.** Pingora's HTTP/1.1 server
//!    ships `KeepaliveStatus::Infinite` by default
//!    (`pingora-core/.../protocols/http/v1/server.rs:647` →
//!    `set_keepalive(Some(0))`, where `Some(0)` is the infinite sentinel).
//!    Any client who completes one request can then sit on the connection
//!    forever, holding an FD. The proxy overrides this in
//!    `early_request_filter` by calling `session.set_keepalive(Some(60))`.
//! 2. **Per-IP request floods.** A single source IP can drive arbitrary
//!    concurrency through the proxy — every in-flight request consumes a
//!    Pingora task slot and (for unauthenticated traffic) ~6 HMAC-SHA256
//!    operations in the SigV4 path. This module caps concurrent in-flight
//!    requests per source IP; on overflow the proxy returns `429 SlowDown`
//!    with `Retry-After: 1`.
//!
//! Loopback peers (`127.0.0.0/8`, `::1`) bypass the per-IP cap when
//! `trusted_loopback_bypass` is enabled (the default). This is purely for
//! ops convenience: an attacker who can talk to the proxy from loopback
//! has already breached the host.
//!
//! See `audit.md` H3 for the threat-model derivation.

use std::{
    net::IpAddr,
    sync::atomic::{AtomicU64, Ordering},
};

use dashmap::DashMap;

use crate::config::ConnectionLimitsConfig;

/// Per-source-IP concurrency tracker. Owns the in-flight counters and the
/// configuration knobs derived from `server.connection_limits`.
pub struct ConnectionLimiter {
    /// Cap on concurrent in-flight requests per source IP. `0` disables the
    /// cap entirely (escape hatch for operators who layer their own
    /// admission control in front of the proxy).
    per_ip:                  u64,
    /// When true, loopback peers (`127.0.0.0/8`, `::1`) skip the cap.
    loopback_bypass:         bool,
    /// Keep-alive idle timeout in seconds, applied via
    /// `Session::set_keepalive` in the proxy's `early_request_filter`.
    pub keepalive_idle_secs: u64,
    /// Per-IP in-flight counters. Keys are never removed — the IP set is
    /// bounded by realistic source-IP diversity, and the lock-contention
    /// cost of periodic cleanup isn't worth it for typical traffic.
    inflight:                DashMap<IpAddr, AtomicU64>,
}

/// Outcome of [`ConnectionLimiter::acquire`].
pub enum AcquireOutcome {
    /// Slot taken; caller must call [`ConnectionLimiter::release`] when the
    /// request completes. Carries the IP so the release path doesn't need
    /// to re-derive it from the session.
    Acquired(IpAddr),
    /// No cap applies (loopback bypass, non-Inet peer such as UDS, or
    /// `per_ip == 0` disable). Caller must NOT call `release`.
    Bypassed,
    /// The per-IP cap was exceeded. The caller should respond `429 SlowDown`
    /// and not call `release`. Carries the IP for log detail.
    Throttled(IpAddr),
}

impl ConnectionLimiter {
    pub fn new(cfg: &ConnectionLimitsConfig) -> Self {
        Self {
            per_ip:              cfg.max_concurrent_requests_per_ip,
            loopback_bypass:     cfg.trusted_loopback_bypass,
            keepalive_idle_secs: cfg.keepalive_idle_secs,
            inflight:            DashMap::new(),
        }
    }

    /// Attempt to reserve a per-IP slot for the request. See [`AcquireOutcome`].
    /// `ip` is the source IP as resolved from the Pingora session (callers
    /// should pass `session.client_addr().and_then(|a| a.as_inet()).map(|a|
    /// a.ip())` here).
    pub fn acquire(&self, ip: Option<IpAddr>) -> AcquireOutcome {
        let Some(ip) = ip else {
            // Non-Inet peer (UDS or unknown). Nothing to throttle on; let it
            // through. UDS into the proxy means a local component that has
            // already passed OS-level admission.
            return AcquireOutcome::Bypassed;
        };
        if self.per_ip == 0 {
            return AcquireOutcome::Bypassed;
        }
        if self.loopback_bypass && ip.is_loopback() {
            return AcquireOutcome::Bypassed;
        }

        let counter = self
            .inflight
            .entry(ip)
            .or_insert_with(|| AtomicU64::new(0));
        let prev = counter.fetch_add(1, Ordering::Relaxed);
        if prev >= self.per_ip {
            counter.fetch_sub(1, Ordering::Relaxed);
            AcquireOutcome::Throttled(ip)
        } else {
            AcquireOutcome::Acquired(ip)
        }
    }

    /// Drop a previously acquired slot. Must be called exactly once for each
    /// `Acquired(ip)` returned by [`acquire`]. Safe to call on an IP with
    /// no entry (treated as a no-op) so the release path doesn't need
    /// to defend against stale state.
    pub fn release(&self, ip: IpAddr) {
        if let Some(counter) = self.inflight.get(&ip) {
            counter.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(per_ip: u64, loopback_bypass: bool) -> ConnectionLimitsConfig {
        ConnectionLimitsConfig {
            max_concurrent_requests_per_ip: per_ip,
            keepalive_idle_secs:            60,
            trusted_loopback_bypass:        loopback_bypass,
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn acquires_up_to_cap_then_throttles() {
        let l = ConnectionLimiter::new(&cfg(2, false));
        assert!(matches!(l.acquire(Some(ip("1.2.3.4"))), AcquireOutcome::Acquired(_)));
        assert!(matches!(l.acquire(Some(ip("1.2.3.4"))), AcquireOutcome::Acquired(_)));
        // Third hit must throttle even though only this IP is using slots.
        assert!(matches!(l.acquire(Some(ip("1.2.3.4"))), AcquireOutcome::Throttled(_)));
    }

    #[test]
    fn release_frees_a_slot() {
        let l = ConnectionLimiter::new(&cfg(1, false));
        let a = l.acquire(Some(ip("9.9.9.9")));
        assert!(matches!(a, AcquireOutcome::Acquired(_)));
        // Second is throttled.
        assert!(matches!(l.acquire(Some(ip("9.9.9.9"))), AcquireOutcome::Throttled(_)));
        // After release, a fresh slot is available.
        l.release(ip("9.9.9.9"));
        assert!(matches!(l.acquire(Some(ip("9.9.9.9"))), AcquireOutcome::Acquired(_)));
    }

    #[test]
    fn different_ips_have_independent_buckets() {
        let l = ConnectionLimiter::new(&cfg(1, false));
        assert!(matches!(l.acquire(Some(ip("1.1.1.1"))), AcquireOutcome::Acquired(_)));
        // Different IP — gets its own slot.
        assert!(matches!(l.acquire(Some(ip("2.2.2.2"))), AcquireOutcome::Acquired(_)));
        // Each IP's second hit is its own throttle.
        assert!(matches!(l.acquire(Some(ip("1.1.1.1"))), AcquireOutcome::Throttled(_)));
        assert!(matches!(l.acquire(Some(ip("2.2.2.2"))), AcquireOutcome::Throttled(_)));
    }

    #[test]
    fn loopback_bypass_skips_cap() {
        let l = ConnectionLimiter::new(&cfg(1, true));
        for _ in 0..10 {
            assert!(matches!(l.acquire(Some(ip("127.0.0.1"))), AcquireOutcome::Bypassed));
        }
        for _ in 0..10 {
            assert!(matches!(l.acquire(Some(ip("::1"))), AcquireOutcome::Bypassed));
        }
    }

    #[test]
    fn loopback_bypass_disabled_still_caps_localhost() {
        let l = ConnectionLimiter::new(&cfg(1, false));
        assert!(matches!(l.acquire(Some(ip("127.0.0.1"))), AcquireOutcome::Acquired(_)));
        assert!(matches!(l.acquire(Some(ip("127.0.0.1"))), AcquireOutcome::Throttled(_)));
    }

    #[test]
    fn non_inet_peer_bypasses() {
        let l = ConnectionLimiter::new(&cfg(1, false));
        // `None` represents a non-Inet peer (UDS or unknown). Always bypassed.
        for _ in 0..10 {
            assert!(matches!(l.acquire(None), AcquireOutcome::Bypassed));
        }
    }

    #[test]
    fn zero_per_ip_disables_the_cap() {
        let l = ConnectionLimiter::new(&cfg(0, false));
        for _ in 0..1000 {
            assert!(matches!(l.acquire(Some(ip("5.5.5.5"))), AcquireOutcome::Bypassed));
        }
    }

    #[test]
    fn release_on_unknown_ip_is_noop() {
        let l = ConnectionLimiter::new(&cfg(2, false));
        // Should not panic or corrupt state.
        l.release(ip("8.8.8.8"));
        // Acquiring the same IP afterwards still gets a fresh slot.
        assert!(matches!(l.acquire(Some(ip("8.8.8.8"))), AcquireOutcome::Acquired(_)));
    }
}
