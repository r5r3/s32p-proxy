//! Startup-time validation for secret-bearing files.
//!
//! The proxy reads several files at startup whose contents are credentials:
//! the YAML directory, OpenBao AppRole role-id/secret-id, the TLS private key.
//! If any of these is left group- or world-readable, every local user on the
//! host can recover the contents directly — bypassing Landlock, SigV4, and
//! the `LimitCORE=0` heap-residue defense.
//!
//! [`stat_or_reject`] enforces a strict invariant on each such file:
//! - regular file
//! - owned by the proxy's effective uid
//! - mode masked with `0o077` is zero (no group or other bits at all)
//!
//! Callers invoke it before any `fs::read_to_string` or library handoff
//! (Pingora's `TlsSettings::intermediate`, `YamlDirectory::from_path`).

use std::{fs::OpenOptions, os::unix::fs::MetadataExt, path::Path};

use anyhow::{Context, Result, anyhow};

/// Reject the file if it isn't a regular file owned by the current
/// effective uid with mode `0o600` or stricter.
///
/// Opens the file (following symlinks — operators commonly symlink secret
/// files into `/etc/s32p`), then `fstat`s the *opened fd* rather than the
/// path. This closes the obvious TOCTOU between check and use; the caller
/// still does its own `read_to_string` separately, leaving a tiny residual
/// window. That's accepted at startup time: an attacker who can swap
/// files in `/etc/s32p` during proxy boot has already won.
pub fn stat_or_reject(path: &Path) -> Result<()> {
    let f = OpenOptions::new()
        .read(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let md = f.metadata().with_context(|| format!("fstat {}", path.display()))?;

    if !md.is_file() {
        return Err(anyhow!("{} is not a regular file (mode={:#o})", path.display(), md.mode()));
    }

    let owner = md.uid();
    let euid = unsafe { libc::geteuid() };
    if owner != euid {
        return Err(anyhow!(
            "{} is owned by uid {} but the proxy runs as uid {}; \
             expected owner == proxy uid",
            path.display(),
            owner,
            euid
        ));
    }

    let mode = md.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(anyhow!(
            "{} has mode {:o} (group/other bits set); \
             expected 0600 or stricter (owner-only)",
            path.display(),
            mode
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File, Permissions},
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// RAII guard: tempfile under /tmp, removed on drop. Avoids pulling in
    /// `tempfile` as a dev-dep (s32p-support has none today).
    struct Tmp(PathBuf);
    impl Tmp {
        fn new(name: &str) -> Self {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let p = std::env::temp_dir().join(format!("s32p-h6-{pid}-{n}-{name}"));
            Self(p)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            // Best-effort cleanup; ignore errors.
            let _ = fs::remove_file(&self.0);
            let _ = fs::remove_dir(&self.0);
        }
    }

    fn create_with_mode(path: &Path, mode: u32) {
        File::create(path).expect("create tempfile");
        fs::set_permissions(path, Permissions::from_mode(mode)).expect("chmod tempfile");
    }

    #[test]
    fn mode_0600_owner_match_accepted() {
        let t = Tmp::new("ok-0600");
        create_with_mode(t.path(), 0o600);
        stat_or_reject(t.path()).expect("0600 owner-match should be accepted");
    }

    #[test]
    fn mode_0640_rejected() {
        let t = Tmp::new("bad-0640");
        create_with_mode(t.path(), 0o640);
        let err = stat_or_reject(t.path()).expect_err("g+r must reject");
        let msg = err.to_string();
        assert!(msg.contains("640"), "error should name the observed mode: {msg}");
    }

    #[test]
    fn mode_0604_rejected() {
        let t = Tmp::new("bad-0604");
        create_with_mode(t.path(), 0o604);
        let err = stat_or_reject(t.path()).expect_err("o+r must reject");
        let msg = err.to_string();
        assert!(msg.contains("604"), "error should name the observed mode: {msg}");
    }

    #[test]
    fn mode_0660_rejected() {
        let t = Tmp::new("bad-0660");
        create_with_mode(t.path(), 0o660);
        let err = stat_or_reject(t.path()).expect_err("g+w must reject");
        let msg = err.to_string();
        assert!(msg.contains("660"), "error should name the observed mode: {msg}");
    }

    #[test]
    fn wrong_owner_rejected() {
        // chown requires CAP_CHOWN. Skip cleanly when not root so the test
        // is green on a normal dev box; CI can run it under sudo.
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            eprintln!("skipping wrong_owner_rejected: not running as root (euid={euid})");
            return;
        }
        let t = Tmp::new("wrong-owner");
        create_with_mode(t.path(), 0o600);
        // Change owner to uid 1 (bin) — present on every Linux system.
        let path_c = std::ffi::CString::new(t.path().as_os_str().as_encoded_bytes())
            .expect("path -> CString");
        let rc = unsafe { libc::chown(path_c.as_ptr(), 1, libc::gid_t::MAX) };
        assert_eq!(rc, 0, "chown failed errno={}", std::io::Error::last_os_error());
        let err = stat_or_reject(t.path()).expect_err("wrong owner must reject");
        let msg = err.to_string();
        assert!(msg.contains("owned by uid 1"), "should name observed owner: {msg}");
    }

    #[test]
    fn directory_rejected() {
        let t = Tmp::new("a-dir");
        fs::create_dir(t.path()).expect("mkdir tempdir");
        fs::set_permissions(t.path(), Permissions::from_mode(0o700)).expect("chmod tempdir");
        let err = stat_or_reject(t.path()).expect_err("directory must reject");
        let msg = err.to_string();
        assert!(msg.contains("not a regular file"), "should name the type problem: {msg}");
    }
}
