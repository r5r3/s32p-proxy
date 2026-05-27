"""Drive the `restic` backup tool against the proxy's S3 backend.

`restic` (https://restic.net) is a real-world backup application, not an
S3 SDK. Like the FUSE mount clients (`mount-s3`, `rclone`) it exercises
the proxy as an *application would* rather than issuing hand-shaped S3
calls — so it lives here as a session helper driven via subprocess, not
as an `S3Client` adapter.

What restic puts the proxy through, end to end:

  * `init`     — HEAD bucket, GET/LIST probes, then PUT of the repo
                 `config` + key objects. (No CreateBucket: the bucket is
                 pre-declared by the harness and HEAD succeeds, so
                 restic's minio-go client never calls MakeBucket.)
  * `backup`   — writes pack files under `data/`, plus `index/` and
                 `snapshots/` objects. Large packs go up as multipart
                 uploads; small repos stay single-PUT. Lots of small-object
                 PUT + LIST traffic either way.
  * `snapshots`— ListObjectsV2 over `snapshots/`.
  * `restore`  — GET of every referenced pack + index object, with HEAD
                 probes; reconstructs the tree to a target dir.
  * `check`    — reads the full index and verifies every referenced pack
                 object exists (HEAD/GET), the strongest read-side probe.

The S3 repository URL form restic wants is
`s3:<endpoint>/<bucket>[/<prefix>]` — minio-go reads the scheme from the
endpoint (`http://` → insecure) and uses path-style addressing for a bare
host/IP endpoint, which is exactly what the proxy serves.

Credentials and the repo-encryption password are passed via environment
(`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `RESTIC_PASSWORD`); the
test runner's own `AWS_*` are scrubbed so they can't leak past the
explicit creds.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# restic operations against a loopback proxy are fast, but `check` and
# `restore` read the whole repo; give them headroom so a slow CI host
# doesn't flake.
_CMD_TIMEOUT_S = 120.0

# Fixed repo-encryption password. Not a secret in a test context — the
# repo lives in a per-session tempdir bucket and is thrown away.
DEFAULT_PASSWORD = "test-restic-password"  # noqa: S105


def is_available() -> bool:
    """True iff `restic` is on PATH.

    Unlike the FUSE clients, restic needs no kernel feature — it's a plain
    S3 client — so this is just a binary-presence check. Callers use it to
    `pytest.skip` when restic isn't installed.
    """
    return shutil.which("restic") is not None


def endpoint_url_for_restic(base_url: str) -> str:
    """Normalize the harness endpoint to the `scheme://host[:port]` form
    restic's S3 backend expects — no trailing slash, no path component.
    The harness `base_url` is already in that shape; normalize defensively
    in case it ever grows a path."""
    p = urlparse(base_url)
    if not p.scheme or not p.netloc:
        raise ValueError(f"endpoint URL must be absolute: {base_url!r}")
    return f"{p.scheme}://{p.netloc}"


@dataclass
class ResticRepo:
    """A restic repository hosted on one proxy bucket (optionally under a
    key prefix), plus the small set of operations the tests drive.

    All commands run with `--no-cache` so restic talks to the backend on
    every operation instead of short-circuiting through a local cache —
    the point of the suite is to exercise the proxy, not restic's cache.
    """

    endpoint_url: str
    region: str
    access_key: str
    secret_key: str
    bucket: str
    work_root: Path
    """Per-test scratch dir (pass a `tmp_path`). Holds the restic log and
    anything restore writes; cleaned up by pytest."""

    prefix: str = ""
    password: str = DEFAULT_PASSWORD

    log_path: Path = field(init=False)

    def __post_init__(self) -> None:
        self.work_root = self.work_root.resolve()
        self.work_root.mkdir(parents=True, exist_ok=True)
        self.log_path = self.work_root / f"restic-{self.bucket}.log"

    # ---------- config ----------

    @property
    def repo_url(self) -> str:
        endpoint = endpoint_url_for_restic(self.endpoint_url)
        path = self.bucket if not self.prefix else f"{self.bucket}/{self.prefix.strip('/')}"
        return f"s3:{endpoint}/{path}"

    def _env(self) -> dict[str, str]:
        env = os.environ.copy()
        # Scrub the runner's AWS_* so they can't shadow our explicit creds.
        for k in (
            "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
            "AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION",
        ):
            env.pop(k, None)
        env["AWS_ACCESS_KEY_ID"] = self.access_key
        env["AWS_SECRET_ACCESS_KEY"] = self.secret_key
        # minio-go needs a region; the proxy is region-agnostic but a
        # mismatch makes the client retry against a "redirect" endpoint.
        env["AWS_DEFAULT_REGION"] = self.region
        env["RESTIC_REPOSITORY"] = self.repo_url
        env["RESTIC_PASSWORD"] = self.password
        # Point HOME at the scratch dir so restic's default cache location
        # (~/.cache/restic) can't touch the runner's home even if a code
        # path ignores --no-cache.
        env["HOME"] = str(self.work_root)
        return env

    # ---------- command runner ----------

    def run(self, *args: str, check: bool = True, timeout: float = _CMD_TIMEOUT_S) -> subprocess.CompletedProcess:
        """Run `restic <args>` against this repo. Appends stdout+stderr to
        the per-repo log. With `check=True` (default), a non-zero exit
        raises `RuntimeError` carrying the log tail."""
        argv = ["restic", "--no-cache", *args]
        proc = subprocess.run(
            argv,
            env=self._env(),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        with self.log_path.open("a") as fh:
            fh.write(f"$ {' '.join(argv)}\n")
            fh.write(proc.stdout)
            fh.write(proc.stderr)
            fh.write(f"[exit {proc.returncode}]\n\n")
        if check and proc.returncode != 0:
            raise RuntimeError(
                f"restic {args[0] if args else ''} failed (rc={proc.returncode})\n"
                f"--- restic log tail ---\n{self.log_tail()}"
            )
        return proc

    # ---------- operations ----------

    def init(self) -> None:
        self.run("init")

    def backup(self, source: Path, *extra: str) -> str:
        """Back up `source` and return the created snapshot's short id."""
        proc = self.run("backup", "--json", str(source), *extra)
        snap_id = ""
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("message_type") == "summary":
                snap_id = msg.get("snapshot_id", "")
        return snap_id

    def snapshots(self) -> list[dict[str, Any]]:
        proc = self.run("snapshots", "--json")
        return json.loads(proc.stdout or "[]")

    def restore(self, snapshot: str, target: Path) -> None:
        target.mkdir(parents=True, exist_ok=True)
        self.run("restore", snapshot, "--target", str(target))

    def check(self, *extra: str) -> None:
        """Verify repository integrity. `--read-data` reads every pack
        (heaviest GET path); without it, check only verifies structure."""
        self.run("check", *extra)

    # ---------- diagnostics ----------

    def log_tail(self, n: int = 8192) -> str:
        try:
            return self.log_path.read_bytes()[-n:].decode("utf-8", "replace")
        except OSError:
            return "(log unreadable)"
