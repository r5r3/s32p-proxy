"""Spawn `mount-s3` against the proxy and yield the mount point.

`mount-s3` is the only directory-bucket-aware client we drive end-to-end:
with `--bucket-type directory` it calls `GET /{bucket}?session` first and
signs all subsequent traffic with `service=s3express`. That makes it the
reference client for the proxy's CreateSession path.

Workflow:

    with MountpointSession(endpoint, bucket=name, mode="rw") as mount:
        (mount.path / "hello.txt").write_text("...")

The context manager:

  * starts `mount-s3 --foreground` as a subprocess with `--auto-unmount`
  * writes credentials into a temporary `--profile` config (env-var creds
    would also work, but `--profile` keeps the test runner's real
    `AWS_*` env from leaking in)
  * waits for the FUSE mount to be visible via `os.path.ismount`
  * on exit, kills the process (auto-unmount handles `umount`) and joins

FUSE requires `/dev/fuse` and either CAP_SYS_ADMIN or membership in the
`fuse` group on most distros. `is_available()` probes for the device and
exits cleanly so the tests can `pytest.skip` on systems that can't run
FUSE (CI without `--privileged`, etc.).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Literal

# Hard caps so a runaway mount can't sit forever inside a test.
_MOUNT_READY_TIMEOUT_S = 15.0
_UMOUNT_TIMEOUT_S = 10.0


def is_available() -> bool:
    """True iff `mount-s3` is on PATH and `/dev/fuse` is accessible.

    Doesn't try to mount anything — just probes the prerequisites. Callers
    use this to decide whether to `pytest.skip` the whole mountpoint
    family of tests on systems that can't run FUSE (containers without
    `--privileged`, kernels with no fuse module, etc.).
    """
    if shutil.which("mount-s3") is None:
        return False
    if not Path("/dev/fuse").exists():
        return False
    # The character device is usually 0666 so any uid can open it for
    # read, but the kernel only grants the mount if we have CAP_SYS_ADMIN
    # *or* mount via fusermount3 (which mount-s3 does). Trying to open
    # the device gives a false negative on user-mode FUSE setups, so we
    # don't.
    return True


Mode = Literal["ro", "rw"]


@dataclass
class MountpointSession:
    """One `mount-s3` lifetime, tied to one bucket + one mountpoint.

    `bucket_type` defaults to `directory`, which forces the CreateSession
    handshake regardless of the bucket name. Override to `general-purpose`
    to test the same proxy against a long-term-creds client — useful for
    A/B verification when a test fails only in directory-bucket mode.
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
    bucket_type: Literal["directory", "general-purpose"] = "directory"
    force_path_style: bool = True
    extra_args: tuple[str, ...] = ()
    debug: bool = True

    # Derived in __post_init__
    mount_dir: Path = field(init=False)
    log_path: Path = field(init=False)
    profile_path: Path = field(init=False)
    _proc: subprocess.Popen | None = field(default=None, init=False, repr=False)
    _log_fh: IO[bytes] | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.mount_root = self.mount_root.resolve()
        self.mount_root.mkdir(parents=True, exist_ok=True)
        # Pick a name that survives multiple mounts in one test run.
        self.mount_dir = self.mount_root / f"mnt-{self.bucket}-{os.getpid()}"
        self.mount_dir.mkdir(exist_ok=True)
        self.log_path = self.mount_root / f"mount-s3-{self.bucket}.log"
        self.profile_path = self.mount_root / "aws-creds"

    # ---------- helpers ----------

    def _write_aws_profile(self) -> None:
        """Render a minimal AWS credentials file at `profile_path`.

        `mount-s3 --profile s32p-test` reads from `$AWS_SHARED_CREDENTIALS_FILE`
        if set, otherwise `~/.aws/credentials`. We point at our temp file
        via the env var so the test runner's real creds (if any) stay out
        of the picture.
        """
        body = (
            "[s32p-test]\n"
            f"aws_access_key_id = {self.access_key}\n"
            f"aws_secret_access_key = {self.secret_key}\n"
        )
        self.profile_path.write_text(body)
        # 0600 — the AWS SDKs warn (or refuse, depending on version) on
        # world-readable credential files.
        self.profile_path.chmod(0o600)

    def _build_argv(self) -> list[str]:
        argv: list[str] = [
            "mount-s3",
            "--foreground",
            "--auto-unmount",
            "--endpoint-url", self.endpoint_url,
            "--region", self.region,
            "--bucket-type", self.bucket_type,
            "--profile", "s32p-test",
            self.bucket,
            str(self.mount_dir),
        ]
        if self.force_path_style:
            argv.append("--force-path-style")
        if self.mode == "rw":
            # mount-s3 is read-only by default. `--allow-delete` and
            # `--allow-overwrite` are the two flags that flip it to a
            # standard rw POSIX-style mount.
            argv.extend(["--allow-delete", "--allow-overwrite"])
        else:
            argv.append("--read-only")
        if self.debug:
            argv.append("--debug")
        argv.extend(self.extra_args)
        return argv

    def _spawn_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["AWS_SHARED_CREDENTIALS_FILE"] = str(self.profile_path)
        # Defensive: scrub any AWS_* env that mount-s3 might prefer over
        # the profile. The CRT credential chain is "env vars beat profile",
        # so leaving these in would silently use the test runner's creds.
        for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE"):
            env.pop(k, None)
        # Set AWS_REGION too so the auto-detect path doesn't try to query
        # IMDS or the AWS API.
        env["AWS_REGION"] = self.region
        return env

    # ---------- lifecycle ----------

    def start(self) -> None:
        if self._proc is not None:
            raise RuntimeError("MountpointSession.start() called twice")
        self._write_aws_profile()
        argv = self._build_argv()
        self._log_fh = self.log_path.open("ab", buffering=0)
        self._proc = subprocess.Popen(
            argv,
            stdout=self._log_fh,
            stderr=subprocess.STDOUT,
            env=self._spawn_env(),
            # Start in its own process group so a runaway test that
            # forgets to call stop() gets cleaned up by signal-the-group
            # on teardown.
            start_new_session=True,
        )

        deadline = time.monotonic() + _MOUNT_READY_TIMEOUT_S
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                rc = self._proc.returncode
                self._tear_down()
                self._fail(f"mount-s3 exited early (rc={rc})")
            if os.path.ismount(self.mount_dir):
                return
            time.sleep(0.05)
        self._tear_down()
        self._fail(
            f"mount-s3 did not become a mountpoint at {self.mount_dir} "
            f"within {_MOUNT_READY_TIMEOUT_S}s"
        )

    def stop(self) -> None:
        proc = self._proc
        if proc is None:
            return
        try:
            if proc.poll() is None:
                # SIGTERM → --auto-unmount runs `fusermount3 -u`. SIGKILL
                # would orphan the mount, which is the worst kind of test
                # bleed.
                proc.terminate()
                try:
                    proc.wait(_UMOUNT_TIMEOUT_S)
                except subprocess.TimeoutExpired:
                    # Last-resort kill. Try to unmount the dir directly so
                    # the next test doesn't trip over an EIO on the stale
                    # mount.
                    proc.kill()
                    proc.wait()
                    self._force_unmount()
        finally:
            self._tear_down()

    def _force_unmount(self) -> None:
        """Best-effort `fusermount3 -u` to recover from a hung mount-s3."""
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

    def __enter__(self) -> "MountpointSession":
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
        raise RuntimeError(f"{msg}\n--- mount-s3 log tail ---\n{self.log_tail()}")
