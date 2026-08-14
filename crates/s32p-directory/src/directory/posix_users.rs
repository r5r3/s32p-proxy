use std::{
    ffi::{CStr, CString},
    ptr,
};

use anyhow::{Result, anyhow};
use libc::{c_char, uid_t};

/// The numeric identity of a passwd entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PosixIds {
    pub uid: u32,
    pub gid: u32,
}

/// Resolve a Unix user name from a uid via `getpwuid_r`.
///
/// Returns `Ok(None)` if no passwd entry exists for the uid (common case after
/// `getpwuid_r` returns 0 with a NULL result pointer).
pub fn username_for_uid(uid: u32) -> Result<Option<String>> {
    let mut buf_size: usize = 4096;

    loop {
        unsafe {
            let mut pwd: libc::passwd = std::mem::zeroed();
            let mut result: *mut libc::passwd = ptr::null_mut();
            let mut buf = vec![0u8; buf_size];

            let rc = libc::getpwuid_r(
                uid as uid_t,
                &mut pwd,
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &mut result,
            );

            if rc == 0 {
                if result.is_null() || pwd.pw_name.is_null() {
                    return Ok(None);
                }
                let cstr = CStr::from_ptr(pwd.pw_name);
                return Ok(Some(cstr.to_string_lossy().into_owned()));
            }

            if rc == libc::ERANGE && buf_size < (1 << 20) {
                buf_size *= 2;
                continue;
            }

            return Err(anyhow!("getpwuid_r failed for uid {uid}: errno={rc}"));
        }
    }
}

/// Resolve the uid/gid of a Unix user name via `getpwnam_r` — the inverse of
/// [`username_for_uid`], used when an operator names a POSIX user and the
/// numeric ids should be derived from the host's passwd database rather than
/// typed in by hand.
///
/// Returns `Ok(None)` if no passwd entry exists for the name (`getpwnam_r`
/// returns 0 with a NULL result pointer).
pub fn ids_for_username(username: &str) -> Result<Option<PosixIds>> {
    let c_name = CString::new(username)
        .map_err(|_| anyhow!("invalid user name {username:?}: contains an interior NUL byte"))?;
    let mut buf_size: usize = 4096;

    loop {
        unsafe {
            let mut pwd: libc::passwd = std::mem::zeroed();
            let mut result: *mut libc::passwd = ptr::null_mut();
            let mut buf = vec![0u8; buf_size];

            let rc = libc::getpwnam_r(
                c_name.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &mut result,
            );

            if rc == 0 {
                if result.is_null() {
                    return Ok(None);
                }
                return Ok(Some(PosixIds { uid: pwd.pw_uid as u32, gid: pwd.pw_gid as u32 }));
            }

            if rc == libc::ERANGE && buf_size < (1 << 20) {
                buf_size *= 2;
                continue;
            }

            return Err(anyhow!("getpwnam_r failed for user {username}: errno={rc}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two lookups must agree: the name `getpwuid_r` reports for the
    /// current uid has to resolve back to that same uid via `getpwnam_r`.
    /// Uses the test process's own identity, so it needs no fixture account.
    #[test]
    fn name_and_id_lookups_round_trip() {
        let uid = unsafe { libc::getuid() } as u32;
        let Some(name) = username_for_uid(uid).expect("getpwuid_r") else {
            // No passwd entry for the test runner (container / nss-less build
            // host) — nothing to round-trip against.
            return;
        };

        let ids = ids_for_username(&name).expect("getpwnam_r").expect("name resolves back");
        assert_eq!(ids.uid, uid);
    }

    #[test]
    fn unknown_user_is_none_not_error() {
        let ids = ids_for_username("s32p-definitely-no-such-user").expect("getpwnam_r");
        assert_eq!(ids, None);
    }

    #[test]
    fn interior_nul_is_rejected() {
        assert!(ids_for_username("alice\0bob").is_err());
    }
}
