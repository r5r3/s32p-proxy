"""Spawn `rclone mount` against the proxy and yield the mount point.

`rclone` is our second FUSE mount client (alongside `mount-s3`). It uses
rclone's generic S3 backend in path-style mode against the proxy — i.e.
exactly the shape a user pointing rclone at MinIO/Ceph/our proxy would
use. That makes it complementary to mount-s3, which exercises the
directory-bucket (s3express) personality. The two together cover both
sides of the personality split.

Workflow:

    with RcloneMountSession(endpoint, bucket=name, mode="rw") as mount:
        (mount.path / "hello.txt").write_text("...")

The context manager:

  * writes a self-contained `rclone.conf` into a temp dir (so the test
    runner's `~/.config/rclone` is not consulted)
  * starts `rclone mount remote:bucket /mountpoint` in the foreground
  * waits for the mount to be visible via `os.path.ismount`
  * on exit, sends SIGTERM (rclone unmounts cleanly on SIGTERM/SIGINT)
    and falls back to fusermount on timeout

Caching notes:

  * `--vfs-cache-mode writes` is required — without it, opening a file
    for write fails with EROFS. Reads still go directly to S3.
  * `--dir-cache-time 1s` and `--poll-interval 0` make backend-side
    writes visible through the mount within a second. S3 has no native
    change notification, so without a short dir-cache the test for
    "POSIX writes file → mount sees it" would hit the 5-minute default
    and time out.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Literal
from urllib.parse import urlparse

_MOUNT_READY_TIMEOUT_S = 15.0
_UMOUNT_TIMEOUT_S = 10.0

# Name of the remote inside our generated rclone.conf. Arbitrary — only
# referenced as `s32p:<bucket>` on the mount command line.
_REMOTE_NAME = "s32p"


def is_available() -> bool:
    """True iff `rclone` is on PATH and `/dev/fuse` is accessible.

    Doesn't try to mount anything — just probes the prerequisites. Callers
    use this to decide whether to `pytest.skip` rclone-backed tests on
    systems that can't run FUSE.
    """
    if shutil.which("rclone") is None:
        return False
    if not Path("/dev/fuse").exists():
        return False
    return True


Mode = Literal["ro", "rw"]


@dataclass
class RcloneMountSession:
    """One `rclone mount` lifetime, tied to one bucket + one mountpoint.

    Generic S3 (`provider = Other`) in path-style — the proxy is reached
    as `<endpoint>/<bucket>/<key>`, signed with plain SigV4 against the
    `s3` service. No s3express / CreateSession handshake.
    """

    endpoint_url: str
    region: str
    access_key: str
    secret_key: str
    bucket: str
    mount_root: Path
    """Parent directory under which `mount_dir` is created. Tests should
    pass a `tmp_path` so the harness cleans up after itself."""

    mode: Mode = "rw"
    extra_args: tuple[str, ...] = ()
    log_level: str = "INFO"

    # Derived in __post_init__
    mount_dir: Path = field(init=False)
    log_path: Path = field(init=False)
    config_path: Path = field(init=False)
    cache_dir: Path = field(init=False)
    _proc: subprocess.Popen | None = field(default=None, init=False, repr=False)
    _log_fh: IO[bytes] | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.mount_root = self.mount_root.resolve()
        self.mount_root.mkdir(parents=True, exist_ok=True)
        self.mount_dir = self.mount_root / f"mnt-{self.bucket}-{os.getpid()}"
        self.mount_dir.mkdir(exist_ok=True)
        self.log_path = self.mount_root / f"rclone-{self.bucket}.log"
        self.config_path = self.mount_root / "rclone.conf"
        self.cache_dir = self.mount_root / "rclone-cache"
        self.cache_dir.mkdir(exist_ok=True)

    # ---------- helpers ----------

    def _write_config(self) -> None:
        """Render a minimal rclone.conf at `config_path`.

        Secret is written in plain text (rclone's `obscure` step is just
        base64 — not security, only "no shoulder-surfing"). For a test
        config in a tmpdir, plain text is fine.
        """
        body = (
            f"[{_REMOTE_NAME}]\n"
            "type = s3\n"
            "provider = Other\n"
            f"access_key_id = {self.access_key}\n"
            f"secret_access_key = {self.secret_key}\n"
            f"endpoint = {self.endpoint_url}\n"
            f"region = {self.region}\n"
            # Path-style is the safe default against a proxy that may not
            # have a wildcard-DNS virtual-hosted suffix configured for the
            # current run. The harness picks endpoint URL accordingly.
            "force_path_style = true\n"
        )
        self.config_path.write_text(body)
        self.config_path.chmod(0o600)

    def _build_argv(self) -> list[str]:
        argv: list[str] = [
            "rclone",
            "mount",
            f"{_REMOTE_NAME}:{self.bucket}",
            str(self.mount_dir),
            "--config", str(self.config_path),
            "--log-file", str(self.log_path),
            "--log-level", self.log_level,
            # Keep the directory cache short so a backend-side write
            # becomes visible through the mount within a test's
            # patience. S3 has no notify API, so longer caches would
            # require either explicit `rclone rc vfs/refresh` calls or
            # a multi-minute wait.
            "--dir-cache-time", "1s",
            "--poll-interval", "0",
            # Required for writes through the mount. Without it, opening
            # a file for write fails with EROFS. Cache is scoped to a
            # per-session tempdir so concurrent tests don't collide.
            "--vfs-cache-mode", "writes",
            "--cache-dir", str(self.cache_dir),
            # rclone defaults to a 5s post-close coalescing window before
            # uploading a dirty file. The mount tests assert that a
            # backend-side file appears within a few seconds, so a 5s
            # delay would race the assertion's timeout for no benefit
            # here (tests write each file exactly once). 0 means "upload
            # as soon as the file is closed".
            "--vfs-write-back", "0s",
            # Don't fork; we want a single subprocess we can signal.
            # rclone defaults to foreground without --daemon, but being
            # explicit avoids surprises if a future default flips.
        ]
        if self.mode == "ro":
            argv.append("--read-only")
        argv.extend(self.extra_args)
        return argv

    def _spawn_env(self) -> dict[str, str]:
        env = os.environ.copy()
        # Scrub AWS_* so a test runner's real credentials can't leak
        # past our explicit rclone.conf. rclone's S3 backend prefers
        # config-file values over env, but defensive cleanup makes the
        # contract obvious.
        for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
                  "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_REGION"):
            env.pop(k, None)
        # Some rclone code paths consult HOME for ~/.config; point it
        # at the mount_root so a misbehaving plugin can't read the
        # test runner's home dir.
        env["HOME"] = str(self.mount_root)
        return env

    # ---------- lifecycle ----------

    def start(self) -> None:
        if self._proc is not None:
            raise RuntimeError("RcloneMountSession.start() called twice")
        self._write_config()
        argv = self._build_argv()
        # rclone writes its own log to --log-file; the subprocess stdout
        # is normally empty. We still capture it so a panic before
        # logging is initialized doesn't vanish.
        self._log_fh = self.log_path.open("ab", buffering=0)
        self._proc = subprocess.Popen(
            argv,
            stdout=self._log_fh,
            stderr=subprocess.STDOUT,
            env=self._spawn_env(),
            start_new_session=True,
        )

        deadline = time.monotonic() + _MOUNT_READY_TIMEOUT_S
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                rc = self._proc.returncode
                self._tear_down()
                self._fail(f"rclone mount exited early (rc={rc})")
            if os.path.ismount(self.mount_dir):
                return
            time.sleep(0.05)
        self._tear_down()
        self._fail(
            f"rclone did not become a mountpoint at {self.mount_dir} "
            f"within {_MOUNT_READY_TIMEOUT_S}s"
        )

    def stop(self) -> None:
        proc = self._proc
        if proc is None:
            return
        try:
            if proc.poll() is None:
                # SIGTERM is rclone's clean-shutdown signal: it flushes
                # vfs writeback, runs fusermount, and exits. SIGKILL
                # would orphan the FUSE mount.
                proc.terminate()
                try:
                    proc.wait(_UMOUNT_TIMEOUT_S)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                    self._force_unmount()
        finally:
            self._tear_down()

    def _force_unmount(self) -> None:
        """Best-effort fusermount fallback after a hung rclone."""
        for cmd in (
            ["fusermount3", "-u", str(self.mount_dir)],
            ["fusermount", "-u", str(self.mount_dir)],
            ["umount", str(self.mount_dir)],
        ):
            try:
                subprocess.run(cmd, timeout=5.0, check=False)
                if not os.path.ismount(self.mount_dir):
                    return
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue

    def _tear_down(self) -> None:
        if self._log_fh is not None:
            self._log_fh.close()
            self._log_fh = None
        self._proc = None

    def __enter__(self) -> "RcloneMountSession":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    # ---------- diagnostics ----------

    @property
    def path(self) -> Path:
        """The mountpoint directory. Read/write here drives S3 ops via FUSE."""
        return self.mount_dir

    def log_tail(self, n: int = 8192) -> str:
        try:
            data = self.log_path.read_bytes()[-n:]
        except OSError:
            return "(log unreadable)"
        return data.decode("utf-8", "replace")

    def _fail(self, msg: str) -> None:
        raise RuntimeError(f"{msg}\n--- rclone log tail ---\n{self.log_tail()}")


def endpoint_url_for_rclone(base_url: str) -> str:
    """rclone's S3 backend wants the endpoint without a trailing slash and
    without any path component. The harness `endpoint.base_url` is
    already in that shape, but normalize defensively in case a future
    base_url grows a path."""
    p = urlparse(base_url)
    if not p.scheme or not p.netloc:
        raise ValueError(f"endpoint URL must be absolute: {base_url!r}")
    return f"{p.scheme}://{p.netloc}"
