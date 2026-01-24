use anyhow::{anyhow, Result};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Align `x` down to multiple of `a` (a > 0).
#[inline]
pub fn align_down(x: u64, a: u64) -> u64 {
    (x / a) * a
}

/// Align `x` up to multiple of `a` (a > 0).
#[inline]
pub fn align_up(x: u64, a: u64) -> u64 {
    let y = x.saturating_add(a - 1);
    (y / a) * a
}

/* -------------------------
 * POSIX path helpers
 * ------------------------- */

pub fn join_object_path(root: &Path, bucket: &str, key: &str) -> Result<PathBuf> {
    if bucket.is_empty() || bucket.contains('/') || bucket == "." || bucket == ".." {
        return Err(anyhow!("invalid bucket"));
    }

    let mut out = root.join(bucket);
    for part in key.split('/') {
        if part.is_empty() {
            continue;
        }
        if part == "." || part == ".." {
            return Err(anyhow!("invalid key segment"));
        }
        if part.as_bytes().contains(&0) {
            return Err(anyhow!("NUL in key segment"));
        }
        out.push(part);
    }
    Ok(out)
}

pub fn bucket_root_path(root: &Path, bucket: &str) -> Result<PathBuf> {
    join_object_path(root, bucket, "")
}

pub fn bucket_exists_dir(root: &Path, bucket: &str) -> Result<bool> {
    let p = bucket_root_path(root, bucket)?;
    Ok(p.exists() && p.is_dir())
}

/* -------------------------
 * File open helpers (Linux)
 * ------------------------- */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    Read,
    /// write-only, create + truncate
    WriteCreateTruncate,
    /// read+write, create if missing
    ReadWriteCreate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenDirect {
    /// Normal buffered I/O
    Buffered,
    /// Require O_DIRECT (fail if unsupported)
    Direct,
    /// Try O_DIRECT, fall back to buffered if unsupported
    TryDirect,
}

fn is_direct_io_not_supported(e: &io::Error) -> bool {
    let Some(errno) = e.raw_os_error() else { return false };
    errno == libc::EINVAL
        || errno == libc::EOPNOTSUPP
        || errno == libc::ENOTSUP
        || errno == libc::ENOSYS
}

fn open_file_io(path: &Path, mode: OpenMode, direct: bool) -> io::Result<File> {
    let mut oo = OpenOptions::new();

    match mode {
        OpenMode::Read => {
            oo.read(true);
        }
        OpenMode::WriteCreateTruncate => {
            oo.write(true).create(true).truncate(true);
        }
        OpenMode::ReadWriteCreate => {
            oo.read(true).write(true).create(true);
        }
    }

    if direct {
        oo.custom_flags(libc::O_DIRECT);
    }

    oo.open(path)
}

/// Open a file with the requested mode and direct I/O behavior.
/// Returns (file, used_direct).
pub fn open_file(path: &Path, mode: OpenMode, direct: OpenDirect) -> Result<(File, bool)> {
    match direct {
        OpenDirect::Buffered => Ok((open_file_io(path, mode, false).map_err(anyhow::Error::from)?, false)),
        OpenDirect::Direct => Ok((open_file_io(path, mode, true).map_err(anyhow::Error::from)?, true)),
        OpenDirect::TryDirect => match open_file_io(path, mode, true) {
            Ok(f) => Ok((f, true)),
            Err(e) if is_direct_io_not_supported(&e) => {
                Ok((open_file_io(path, mode, false).map_err(anyhow::Error::from)?, false))
            }
            Err(e) => Err(anyhow!(e)),
        },
    }
}

/* -------------------------
 * Preallocation / truncate
 * ------------------------- */

pub fn ftruncate_fd(fd: RawFd, len: u64) -> Result<()> {
    let rc = unsafe { libc::ftruncate(fd, len as libc::off_t) };
    if rc != 0 {
        return Err(anyhow!(
            "ftruncate({}) failed: {}",
            len,
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

pub fn ftruncate_file(file: &File, len: u64) -> Result<()> {
    ftruncate_fd(file.as_raw_fd(), len)
}

/// Best-effort preallocation for [start, start+len). Falls back to ftruncate(end) if fallocate(range) is unsupported.
pub fn try_preallocate_range(fd: RawFd, start: u64, len: u64) -> Result<()> {
    if len == 0 {
        return Ok(());
    }

    let end = start
        .checked_add(len)
        .ok_or_else(|| anyhow!("preallocate range overflow: start={start} len={len}"))?;

    let rc = unsafe { libc::fallocate(fd, 0, start as libc::off_t, len as libc::off_t) };
    if rc == 0 {
        return Ok(());
    }

    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if errno == libc::EOPNOTSUPP
        || errno == libc::ENOSYS
        || errno == libc::EINVAL
        || errno == libc::ENOTSUP
    {
        return ftruncate_fd(fd, end);
    }

    Err(anyhow!("fallocate(start={start}, len={len}) failed: errno={errno}"))
}

/* -------------------------
 * statx (Linux only)
 * ------------------------- */

#[derive(Debug, Clone, Copy)]
pub struct StatxInfo {
    pub ino: u64,
    pub size: u64,
    pub uid: u32,
    pub mtime: SystemTime,
}

fn system_time_from_unix(sec: i64, nsec: u32) -> SystemTime {
    if sec >= 0 {
        SystemTime::UNIX_EPOCH + Duration::new(sec as u64, nsec)
    } else {
        let d = Duration::new((-sec) as u64, nsec);
        SystemTime::UNIX_EPOCH - d
    }
}

pub fn statx_info(path: &Path) -> Option<StatxInfo> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.contains(&0) {
        return None;
    }
    let c_path = CString::new(bytes).ok()?;

    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    let mask: libc::c_uint =
        (libc::STATX_INO | libc::STATX_SIZE | libc::STATX_MTIME | libc::STATX_UID) as libc::c_uint;

    let rc = unsafe {
        libc::statx(
            libc::AT_FDCWD,
            c_path.as_ptr(),
            libc::AT_STATX_DONT_SYNC,
            mask,
            &mut stx as *mut libc::statx,
        )
    };
    if rc != 0 {
        return None;
    }

    let mtime = system_time_from_unix(stx.stx_mtime.tv_sec as i64, stx.stx_mtime.tv_nsec as u32);

    Some(StatxInfo {
        ino: stx.stx_ino as u64,
        size: stx.stx_size as u64,
        uid: stx.stx_uid as u32,
        mtime,
    })
}

