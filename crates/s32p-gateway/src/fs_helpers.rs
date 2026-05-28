use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io,
    os::unix::{
        ffi::OsStrExt,
        fs::OpenOptionsExt,
        io::{AsRawFd, RawFd},
    },
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use anyhow::{Result, anyhow};

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
 * Atomic rename helpers (Linux)
 * ------------------------- */

/// Atomically rename `src` to `dst` but fail if `dst` already exists.
///
/// On Linux this uses renameat2(RENAME_NOREPLACE).
/// - If dst exists: returns io::ErrorKind::AlreadyExists (EEXIST)
/// - If across devices: returns EXDEV (caller may fall back to copy+rename inside dst FS)
///
/// If renameat2 is not available (ENOSYS/EINVAL), this falls back to a best-effort
/// "exists check + rename" (not race-free, but only used on kernels without renameat2).
pub fn rename_noreplace(src: &Path, dst: &Path) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let src_bytes = src.as_os_str().as_bytes();
        let dst_bytes = dst.as_os_str().as_bytes();
        if src_bytes.is_empty()
            || src_bytes.contains(&0)
            || dst_bytes.is_empty()
            || dst_bytes.contains(&0)
        {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "NUL/empty path"));
        }

        let c_src = CString::new(src_bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in src path"))?;
        let c_dst = CString::new(dst_bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in dst path"))?;

        let rc = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                c_src.as_ptr(),
                libc::AT_FDCWD,
                c_dst.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };

        if rc == 0 {
            return Ok(());
        }

        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(errno) if errno == libc::EEXIST => {
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, err));
            }
            Some(errno) if errno == libc::ENOSYS || errno == libc::EINVAL => {
                // Kernel/libc doesn't support renameat2(RENAME_NOREPLACE).
                // Best-effort fallback (not race-free).
                if dst.exists() {
                    return Err(io::Error::new(io::ErrorKind::AlreadyExists, "destination exists"));
                }
                return std::fs::rename(src, dst);
            }
            _ => return Err(err),
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        if dst.exists() {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "destination exists"));
        }
        std::fs::rename(src, dst)
    }
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
    /// write-only, must already exist, no truncate; for appendable PUT.
    WriteExistingNoTrunc,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LustreStriping {
    /// Stripe size in bytes.
    pub stripe_size:    u64,
    /// Stripe count (number of OSTs). Must be >= 1.
    pub stripe_count:   i32,
    /// Stripe offset (starting OST index). Use -1 for default.
    pub stripe_offset:  i32,
    /// Stripe pattern. Use 0 (LOV_PATTERN_RAID0) for normal striping.
    pub stripe_pattern: u32,
}

impl LustreStriping {
    pub fn new(stripe_size: u64, stripe_count: u32) -> Self {
        Self {
            stripe_size,
            stripe_count: stripe_count.max(1) as i32,
            stripe_offset: -1,
            stripe_pattern: 0,
        }
    }
}

/// Compute a stripe count matching file size (ceil(file_size / stripe_size)),
/// capped by `max_stripe_count` (and always >= 1).
#[cfg(feature = "lustre")]
pub fn stripe_count_for_size(file_size: u64, stripe_size: u64, max_stripe_count: u32) -> u32 {
    if stripe_size == 0 {
        return 1;
    }
    let mut n = ((file_size + stripe_size - 1) / stripe_size) as u32;
    if n < 1 {
        n = 1;
    }
    if max_stripe_count > 0 && n > max_stripe_count {
        n = max_stripe_count;
    }
    n
}

fn is_direct_io_not_supported(e: &io::Error) -> bool {
    let Some(errno) = e.raw_os_error() else {
        return false;
    };
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
        OpenMode::WriteExistingNoTrunc => {
            oo.write(true).create(false).truncate(false);
        }
    }

    if direct {
        oo.custom_flags(libc::O_DIRECT);
    }

    oo.open(path)
}

/// Open a file with the requested mode and direct I/O behavior.
/// Returns (file, used_direct).
///
/// When the `lustre` feature is enabled, the caller may request Lustre striping for newly
/// created files via `striping`.
pub fn open_file(
    path: &Path,
    mode: OpenMode,
    direct: OpenDirect,
    #[allow(unused_variables)] striping: Option<LustreStriping>,
) -> Result<(File, bool)> {
    // Lustre striping must be set at file creation time.
    #[cfg(all(feature = "lustre", target_os = "linux"))]
    {
        if let Some(s) = striping {
            let should_create = match mode {
                OpenMode::Read | OpenMode::WriteExistingNoTrunc => false,
                OpenMode::WriteCreateTruncate => true,
                OpenMode::ReadWriteCreate => !path.exists(),
            };

            if should_create {
                // llapi_file_create() fails with EEXIST. For truncate-writes, remove the old file first.
                if matches!(mode, OpenMode::WriteCreateTruncate) {
                    match std::fs::remove_file(path) {
                        Ok(_) => {}
                        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                        Err(e) => {
                            return Err(anyhow!(
                                "remove_file {} failed before llapi_file_create: {e}",
                                path.display()
                            ));
                        }
                    }
                }

                // Best-effort create with striping. If a racing creator wins (EEXIST), just open.
                match crate::lustre::file_create(
                    path,
                    s.stripe_size,
                    s.stripe_offset,
                    s.stripe_count,
                    s.stripe_pattern,
                ) {
                    Ok(()) => {}
                    Err(e) => {
                        let is_eexist = e
                            .downcast_ref::<io::Error>()
                            .and_then(|ioe| ioe.raw_os_error())
                            .is_some_and(|errno| errno == libc::EEXIST);

                        if !is_eexist {
                            return Err(e);
                        }
                    }
                }
            }
        }
    }

    match direct {
        OpenDirect::Buffered => {
            Ok((open_file_io(path, mode, false).map_err(anyhow::Error::from)?, false))
        }
        OpenDirect::Direct => {
            Ok((open_file_io(path, mode, true).map_err(anyhow::Error::from)?, true))
        }
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
        return Err(anyhow!("ftruncate({}) failed: {}", len, std::io::Error::last_os_error()));
    }
    Ok(())
}

pub fn ftruncate_file(file: &File, len: u64) -> Result<()> {
    ftruncate_fd(file.as_raw_fd(), len)
}

/// Take an exclusive advisory lock (`flock(LOCK_EX)`) on the given file.
/// The lock is released automatically when the file descriptor is closed.
///
/// Used by the appendable-PUT path to serialize the
/// "stat current size → write at offset" window between concurrent
/// appends to the same key. Same idiom as multipart's `meta.json` lock.
pub fn flock_exclusive(file: &File) -> io::Result<()> {
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
    pub ino:   u64,
    pub size:  u64,
    pub uid:   u32,
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

    // Two-stage stat for symlink-friendly listings:
    //   1. follow the link (default) — gives the target's size/mtime, which is
    //      the data clients care about when the symlink resolves.
    //   2. if that fails (target unreachable from the gateway worker, broken
    //      link, etc.), retry with AT_SYMLINK_NOFOLLOW so the entry still
    //      appears in `ListObjectsV1/V2`. Otherwise the symlink would vanish
    //      from listings and `aws s3 rm --recursive` (and similar) would never
    //      issue a DELETE for it. GetObject still follows via open();
    //      DeleteObject still calls unlink(2), which targets the symlink
    //      itself, never the resolved file.
    let mut do_statx = |flags: libc::c_int| -> i32 {
        unsafe {
            libc::statx(libc::AT_FDCWD, c_path.as_ptr(), flags, mask, &mut stx as *mut libc::statx)
        }
    };
    let mut rc = do_statx(libc::AT_STATX_DONT_SYNC);
    if rc != 0 {
        rc = do_statx(libc::AT_STATX_DONT_SYNC | libc::AT_SYMLINK_NOFOLLOW);
    }
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

/* -------------------------
 * Object tagging xattrs
 *
 * Tags live in a single xattr `user.s32p.tags` whose value is the URL-form
 * encoding of the tag set (`team=a&stage=raw`) — the same wire shape as the
 * `x-amz-tagging` header. One attr matches S3's whole-set atomic semantics
 * (Put replaces, Delete clears, Get reads). Absent xattr means "no tags".
 * ------------------------- */

pub const TAGGING_XATTR: &str = "user.s32p.tags";

/// Read the tag set xattr from `path`. Returns the empty string when the
/// attribute is absent or the underlying filesystem doesn't support
/// `user.*` xattrs (treated as "no tags" — same as a freshly POSIX-created
/// file).
pub fn read_tags(path: &Path) -> io::Result<String> {
    match xattr::get(path, TAGGING_XATTR) {
        Ok(Some(bytes)) => Ok(String::from_utf8_lossy(&bytes).into_owned()),
        Ok(None) => Ok(String::new()),
        Err(e) if e.raw_os_error() == Some(libc::ENOTSUP) => Ok(String::new()),
        Err(e) => Err(e),
    }
}

/// Replace (or remove, if `tags_urlform` is empty) the tag set xattr on
/// `path`. Empty input maps to `removexattr` so the on-disk state matches
/// what a freshly POSIX-created file would have — no orphan attribute.
pub fn write_tags(path: &Path, tags_urlform: &str) -> io::Result<()> {
    if tags_urlform.is_empty() {
        return remove_tags(path);
    }
    xattr::set(path, TAGGING_XATTR, tags_urlform.as_bytes())
}

/// Remove the tag set xattr from `path`. Idempotent — absent attribute or
/// no-xattr-support filesystem are not errors.
pub fn remove_tags(path: &Path) -> io::Result<()> {
    match xattr::remove(path, TAGGING_XATTR) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::ENODATA) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::ENOTSUP) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Probe whether the filesystem backing `path` supports `user.*` extended
/// attributes. Uses `listxattr` (via `xattr::list_deref`) — a read-only
/// operation that requires no write permission and does not mutate any
/// inode state. Returns `false` only for the canonical "no xattr support"
/// errnos (`ENOTSUP` / `EOPNOTSUPP`); other errors propagate so callers
/// don't infer "unsupported" from permission or quota issues.
///
/// The deref variant matters because the staged `posix_root` layout
/// exposes each bucket as a symlink to `bucket.data_path`. Probing the
/// symlink with `llistxattr` would test the staging area's filesystem,
/// not the bucket data filesystem — so we explicitly follow the final
/// symlink to land on the same filesystem where `setxattr` will run.
///
/// `user.*` xattr support is a property of the mount, so callers should
/// cache by device id (see `MetadataExt::dev()`).
pub fn probe_user_xattrs_supported(path: &Path) -> io::Result<bool> {
    // Linux: ENOTSUP == EOPNOTSUPP (same errno value), so a single match
    // arm is sufficient. The xattr crate also surfaces other errnos
    // (e.g. EACCES) as is — propagate so callers don't infer "unsupported"
    // from permission/quota issues.
    match xattr::list_deref(path) {
        Ok(_) => Ok(true),
        Err(e) if e.raw_os_error() == Some(libc::ENOTSUP) => Ok(false),
        Err(e) => Err(e),
    }
}

/* -------------------------
 * Object metadata xattrs
 *
 * User-defined metadata (`x-amz-meta-*`) lives in a single xattr
 * `user.s32p.meta` whose value is the URL-form encoding of the pair set
 * (`author=alice&purpose=demo`). Content-Type lives in `user.s32p.content_type`.
 * Both are absent for POSIX-created files, in which case the gateway falls back
 * to derived values (empty user metadata, ladder-resolved Content-Type).
 *
 * Read-only POSIX-interop: `user.mime_type` is the freedesktop standard
 * xattr populated by file managers (GNOME/KDE) and `gio set`. The gateway
 * consults it as a Content-Type fallback but never writes it, leaving the
 * desktop xattr under POSIX users' control.
 * ------------------------- */

pub const USER_META_XATTR: &str = "user.s32p.meta";
pub const CONTENT_TYPE_XATTR: &str = "user.s32p.content_type";
pub const FREEDESKTOP_MIME_XATTR: &str = "user.mime_type";

/// Read the user-metadata xattr from `path`. Returns the empty string when
/// the attribute is absent or the backing filesystem doesn't support
/// `user.*` xattrs.
pub fn read_user_meta(path: &Path) -> io::Result<String> {
    match xattr::get(path, USER_META_XATTR) {
        Ok(Some(bytes)) => Ok(String::from_utf8_lossy(&bytes).into_owned()),
        Ok(None) => Ok(String::new()),
        Err(e) if e.raw_os_error() == Some(libc::ENOTSUP) => Ok(String::new()),
        Err(e) => Err(e),
    }
}

/// Replace (or remove, if `meta_urlform` is empty) the user-metadata xattr.
pub fn write_user_meta(path: &Path, meta_urlform: &str) -> io::Result<()> {
    if meta_urlform.is_empty() {
        return remove_user_meta(path);
    }
    xattr::set(path, USER_META_XATTR, meta_urlform.as_bytes())
}

/// Remove the user-metadata xattr from `path`. Idempotent.
pub fn remove_user_meta(path: &Path) -> io::Result<()> {
    match xattr::remove(path, USER_META_XATTR) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::ENODATA) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::ENOTSUP) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Resolve a stored Content-Type. Prefers `user.s32p.content_type` (set by
/// PutObject), falls back to `user.mime_type` (freedesktop standard, set by
/// POSIX desktop tooling). Returns `None` when neither is set or the
/// filesystem doesn't support `user.*` xattrs — callers then continue
/// down the resolution ladder (extension map, then default octet-stream).
pub fn read_content_type(path: &Path) -> io::Result<Option<String>> {
    if let Some(v) = read_xattr_string(path, CONTENT_TYPE_XATTR)? {
        return Ok(Some(v));
    }
    read_xattr_string(path, FREEDESKTOP_MIME_XATTR)
}

/// Write the explicit Content-Type xattr (or remove it when `ct` is empty).
/// Only ever touches `user.s32p.content_type` — never `user.mime_type`, so
/// the freedesktop xattr stays under POSIX users' control.
pub fn write_content_type(path: &Path, ct: &str) -> io::Result<()> {
    if ct.is_empty() {
        return remove_content_type(path);
    }
    xattr::set(path, CONTENT_TYPE_XATTR, ct.as_bytes())
}

/// Remove the explicit Content-Type xattr. Idempotent. Does not touch
/// `user.mime_type`.
pub fn remove_content_type(path: &Path) -> io::Result<()> {
    match xattr::remove(path, CONTENT_TYPE_XATTR) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::ENODATA) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::ENOTSUP) => Ok(()),
        Err(e) => Err(e),
    }
}

fn read_xattr_string(path: &Path, name: &str) -> io::Result<Option<String>> {
    match xattr::get(path, name) {
        Ok(Some(bytes)) => Ok(Some(String::from_utf8_lossy(&bytes).into_owned())),
        Ok(None) => Ok(None),
        Err(e) if e.raw_os_error() == Some(libc::ENOTSUP) => Ok(None),
        Err(e) => Err(e),
    }
}
