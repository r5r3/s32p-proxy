use std::{
    ffi::{CStr, CString},
    ptr,
};

use anyhow::{Context, Result, anyhow};
use libc::{c_char, gid_t};

pub fn groups_for_user(username: &str, primary_gid: u32) -> Result<Vec<String>> {
    let c_user = CString::new(username).context("username contains NUL")?;

    // 1) First call with ngroups=0 to get required size
    let mut ngroups: i32 = 0;
    unsafe {
        libc::getgrouplist(c_user.as_ptr(), primary_gid as gid_t, ptr::null_mut(), &mut ngroups);
    }
    if ngroups <= 0 {
        // Still include primary group name (best effort).
        return Ok(vec![]);
    }

    // 2) Call again with allocated buffer
    let mut groups: Vec<gid_t> = vec![0; ngroups as usize];
    let mut ngroups2 = ngroups;
    let rc = unsafe {
        libc::getgrouplist(
            c_user.as_ptr(),
            primary_gid as gid_t,
            groups.as_mut_ptr(),
            &mut ngroups2,
        )
    };
    if rc < 0 {
        return Err(anyhow!("getgrouplist failed for user {}", username));
    }
    groups.truncate(ngroups2 as usize);

    // 3) Map gids to group names
    let mut names = Vec::with_capacity(groups.len());
    for gid in groups {
        if let Some(name) = group_name_from_gid(gid)? {
            names.push(name);
        }
    }

    // Dedup
    names.sort();
    names.dedup();
    Ok(names)
}

fn group_name_from_gid(gid: gid_t) -> Result<Option<String>> {
    // Use getgrgid_r
    unsafe {
        let mut grp: libc::group = std::mem::zeroed();
        let mut result: *mut libc::group = ptr::null_mut();

        // buffer for strings
        let mut buf = vec![0u8; 4096];
        let rc = libc::getgrgid_r(
            gid,
            &mut grp,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut result,
        );

        if rc != 0 {
            // If buffer too small, you could retry with larger buffer; 4k is usually enough.
            return Ok(None);
        }
        if result.is_null() || grp.gr_name.is_null() {
            return Ok(None);
        }

        let cstr = CStr::from_ptr(grp.gr_name);
        Ok(Some(cstr.to_string_lossy().to_string()))
    }
}
