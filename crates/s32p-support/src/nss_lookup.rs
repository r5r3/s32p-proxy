//! Blocking `getpwuid_r` wrapper shared by the proxy's NSS listener and the
//! gateway's standalone fallback path.
//!
//! Used by:
//!   * [`crate::nss_proto`]'s server side (the proxy `nss_listener`), which
//!     calls this via `tokio::task::spawn_blocking` because glibc/SSSD can
//!     stall on the underlying NSS query.
//!   * the gateway's `NssClient` when no `S32P_NSS_PROXY_SOCK` env var is set
//!     (standalone runs without the proxy and without Landlock — dev/test).

/// Resolve a Unix uid to a username via libc's `getpwuid_r`. Returns `None`
/// on any failure (unknown uid, NSS backend error, denied filesystem access
/// to `/etc/passwd` under Landlock, …) — callers are expected to fall back
/// to a numeric string in that case.
pub fn lookup_username_blocking(uid: u32) -> Option<String> {
    unsafe {
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut result: *mut libc::passwd = std::ptr::null_mut();

        let mut buf_len = 16 * 1024;
        for _ in 0..3 {
            let mut buf = vec![0u8; buf_len];
            let rc = libc::getpwuid_r(
                uid as libc::uid_t,
                &mut pwd,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            );
            if rc == 0 && !result.is_null() && !pwd.pw_name.is_null() {
                return Some(std::ffi::CStr::from_ptr(pwd.pw_name).to_string_lossy().to_string());
            }
            if rc == libc::ERANGE {
                buf_len *= 2;
                continue;
            }
            return None;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_uid_returns_none() {
        // 4 billion is well outside any plausible passwd range and not
        // expected to resolve on any realistic test host.
        assert_eq!(lookup_username_blocking(4_000_000_000), None);
    }

    #[test]
    fn current_uid_resolves() {
        // The process's own uid should resolve to something non-empty
        // on any sane test environment.
        let me = unsafe { libc::geteuid() } as u32;
        let name = lookup_username_blocking(me);
        assert!(name.is_some() && !name.as_ref().unwrap().is_empty());
    }
}
