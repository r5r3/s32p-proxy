"""Spawn an ephemeral OpenBao dev server for the integration suite.

`bao server -dev` runs entirely in-memory and starts already unsealed with
a KV v2 secrets engine mounted at `secret/` — exactly what the s32p
OpenBao backend expects. We pin a known root token and an auto-picked
loopback port so several test sessions (or xdist workers) don't collide.

Used only by `tests/test_openbao.py`, which skips when the `bao` binary is
not on PATH. Nothing here is wired into the default suite.
"""

from __future__ import annotations

import os
import socket
import subprocess
import time
from contextlib import closing
from pathlib import Path
from typing import IO

import requests


def _alloc_port(host: str = "127.0.0.1") -> int:
    """Bind to port 0 to learn an available port. Caller races until ready."""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


# Health-check status codes that mean "up and usable". A dev server is
# unsealed + initialized immediately, so 200 is the normal answer; the
# others are accepted defensively to avoid racing the very first poll.
_READY_STATUSES = frozenset({200, 429, 472, 473, 501, 503})


class OpenBaoServer:
    """Lifecycle of a `bao server -dev` process.

    start() blocks until /v1/sys/health answers (or the process dies); the
    server is reachable at `address` with `root_token`. stop() terminates
    it. The in-memory store is discarded on exit — no state survives.
    """

    def __init__(
        self,
        bao_bin: str,
        work_dir: Path,
        *,
        listen_host: str = "127.0.0.1",
        root_token: str = "root-test-token",
    ):
        self.bao_bin = bao_bin
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.listen_host = listen_host
        self.root_token = root_token
        self.port = _alloc_port(listen_host)
        self.log_path = self.work_dir / "openbao.log"
        self._proc: subprocess.Popen | None = None
        self._log_fh: IO[bytes] | None = None

    @property
    def address(self) -> str:
        return f"http://{self.listen_host}:{self.port}"

    def start(self, timeout: float = 15.0) -> None:
        if self._proc is not None:
            raise RuntimeError("OpenBaoServer.start() called twice")
        self._log_fh = self.log_path.open("ab", buffering=0)
        # HOME is redirected into work_dir as a second guard against the
        # token helper writing ~/.vault-token; -dev-no-store-token is the
        # primary one.
        env = dict(os.environ, HOME=str(self.work_dir))
        self._proc = subprocess.Popen(
            [
                self.bao_bin, "server", "-dev",
                "-dev-root-token-id", self.root_token,
                "-dev-listen-address", f"{self.listen_host}:{self.port}",
                "-dev-no-store-token",
            ],
            stdout=self._log_fh,
            stderr=subprocess.STDOUT,
            cwd=str(self.work_dir),
            env=env,
        )

        health = f"{self.address}/v1/sys/health"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                rc = self._proc.returncode
                self._close_log()
                raise RuntimeError(
                    f"openbao dev server exited early (rc={rc})\n"
                    f"--- log tail ---\n{self._log_tail()}"
                )
            try:
                if requests.get(health, timeout=0.5).status_code in _READY_STATUSES:
                    return
            except requests.RequestException:
                pass
            time.sleep(0.05)
        self.stop()
        raise RuntimeError(
            f"openbao dev server did not become healthy within {timeout}s\n"
            f"--- log tail ---\n{self._log_tail()}"
        )

    def stop(self, timeout: float = 5.0) -> None:
        if self._proc is not None:
            if self._proc.poll() is None:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
                    self._proc.wait()
            self._proc = None
        self._close_log()

    def _close_log(self) -> None:
        if self._log_fh is not None:
            self._log_fh.close()
            self._log_fh = None

    def _log_tail(self, n: int = 4096) -> str:
        try:
            return self.log_path.read_bytes()[-n:].decode("utf-8", "replace")
        except OSError:
            return "(log unreadable)"

    def __enter__(self) -> "OpenBaoServer":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()
