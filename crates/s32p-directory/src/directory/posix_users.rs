use std::{
    ffi::CStr,
    ptr,
};

use anyhow::{Result, anyhow};
use libc::{c_char, uid_t};

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
