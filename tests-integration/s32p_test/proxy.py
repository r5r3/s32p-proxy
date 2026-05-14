"""Spawn a real `s32p-proxy` for tests.

Workflow:
    harness = ProxyHarness(session_dir)
    harness.directory.add_user(User(...))
    harness.directory.add_bucket(Bucket(...))
    harness.start()                  # blocks until the listen port accepts
    ...                              # tests run against harness.base_url
    harness.stop()

Or as a context manager:
    with ProxyHarness(session_dir) as harness:
        ...

The directory file is built before start() because the YAML backend reads
it once at startup (no hot reload). For tests that need to add buckets
mid-suite, run a separate harness or restart this one.

Single-uid only for now: workers run as the test runner's uid because
`launcher.pass_user_flag_if_root = False`. Multi-uid mode (workers as
distinct test users) needs the proxy to run as root and is gated behind
the `--mode=multi-uid` pytest option.
"""

from __future__ import annotations

import socket
import subprocess
import time
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO

import yaml

from .directory import YamlDirectory
from .paths import gateway_binary, proxy_binary, restricted_exec_binary


def _alloc_port(host: str = "127.0.0.1") -> int:
    """Bind to port 0 to learn an available port. Caller races until start()."""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def _port_open(host: str, port: int, timeout: float = 0.25) -> bool:
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            return True
    except OSError:
        return False


@dataclass
class ProxyHarness:
    """Owns: a session tempdir, the proxy config, the directory file, the
    UDS run dir, and the proxy process. Does not own any S3 client state."""

    session_dir: Path
    listen_host: str = "127.0.0.1"
    listen_port: int = 0  # 0 = auto-pick
    region: str = "us-east-1"
    public_scheme: str = "http"
    log_level: str = (
        "s32p_proxy=info,s32p_gateway=info,pingora=warn,pingora_proxy=warn"
    )
    virtual_hosted_suffixes: tuple[str, ...] = ()
    idle_timeout_secs: int = 60
    sweep_interval_secs: int = 5
    profile_name: str = "gateway"

    # Derived in __post_init__
    posix_root: Path = field(init=False)
    uds_run_dir: Path = field(init=False)
    config_path: Path = field(init=False)
    directory_path: Path = field(init=False)
    log_path: Path = field(init=False)
    directory: YamlDirectory = field(init=False)

    _proc: subprocess.Popen | None = field(default=None, init=False, repr=False)
    _log_fh: IO[bytes] | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.session_dir = self.session_dir.resolve()
        self.session_dir.mkdir(parents=True, exist_ok=True)

        self.posix_root = self.session_dir / "posix-root"
        self.posix_root.mkdir(exist_ok=True)
        self.uds_run_dir = self.session_dir / "uds"
        self.uds_run_dir.mkdir(exist_ok=True)
        self.config_path = self.session_dir / "s32p-proxy.yaml"
        self.directory_path = self.session_dir / "directory.yaml"
        self.log_path = self.session_dir / "proxy.log"

        if self.listen_port == 0:
            self.listen_port = _alloc_port(self.listen_host)

        self.directory = YamlDirectory(self.directory_path)

    @property
    def base_url(self) -> str:
        return f"{self.public_scheme}://{self.listen_host}:{self.listen_port}"

    # ----- config -----

    def _build_config(self) -> dict:
        gateway_env = {
            "S32P_BIND_UDS": "{{bind_uds}}",
            "S32P_POSIX_ROOT": "{{posix_root}}",
            "AWS_ACCESS_KEY_ID": "{{access_key}}",
            "AWS_SECRET_ACCESS_KEY": "{{secret_key}}",
            "S32P_PUBLIC_SCHEME": self.public_scheme,
            "S32P_REGION": "{{region}}",
            "S32P_VIRTUAL_HOSTED_SUFFIXES": "{{virtual_hosted_suffixes}}",
            "S32P_LOG_LEVEL": "{{log_level}}",
        }

        return {
            "version": 1,
            "server": {
                "listen": f"{self.listen_host}:{self.listen_port}",
                "public_scheme": self.public_scheme,
                "region": self.region,
                "log_level": self.log_level,
                "shutdown_grace_period_secs": 5,
                "virtual_hosted_suffixes": list(self.virtual_hosted_suffixes),
            },
            "auth": {
                "backend": "yaml",
                "yaml": {"path": str(self.directory_path)},
            },
            "workers": {
                "posix_root": str(self.posix_root),
                "launcher": {
                    "path": str(restricted_exec_binary()),
                    "pass_user_flag_if_root": False,
                    "landlock": False,  # disabled for the test harness; flip per-suite later
                },
                "lifecycle": {
                    "idle_timeout_secs": self.idle_timeout_secs,
                    "sweep_interval_secs": self.sweep_interval_secs,
                },
                "profiles": {
                    self.profile_name: {
                        "exec": str(gateway_binary()),
                        "args": [],
                        "env": gateway_env,
                        "upstream": {
                            "kind": "uds",
                            "uds_run_dir": str(self.uds_run_dir),
                        },
                    },
                },
            },
            "routing": {
                "class_map": {
                    "read":         {"action": "proxy", "worker_profile": self.profile_name},
                    "write":        {"action": "proxy", "worker_profile": self.profile_name},
                    "multipart":    {"action": "proxy", "worker_profile": self.profile_name},
                    "other":        {"action": "proxy", "worker_profile": self.profile_name},
                    "versioning":   {"action": "not_implemented", "message": "versioning not implemented"},
                    "object_lock":  {"action": "not_implemented", "message": "object lock not implemented"},
                    "bucket_admin": {"action": "not_implemented", "message": "bucket admin via s32p-ctl only"},
                },
            },
        }

    def write_config(self) -> None:
        self.config_path.write_text(yaml.safe_dump(self._build_config(), sort_keys=False))

    # ----- lifecycle -----

    def start(self, timeout: float = 15.0) -> None:
        if self._proc is not None:
            raise RuntimeError("ProxyHarness.start() called twice")
        self.write_config()

        self._log_fh = self.log_path.open("ab", buffering=0)
        self._proc = subprocess.Popen(
            [str(proxy_binary()), "--config", str(self.config_path)],
            stdout=self._log_fh,
            stderr=subprocess.STDOUT,
            cwd=str(self.session_dir),
        )

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                self._fail(f"proxy exited early (rc={self._proc.returncode})")
            if _port_open(self.listen_host, self.listen_port):
                return
            time.sleep(0.05)
        self._fail(f"proxy did not start listening on {self.listen_host}:{self.listen_port} within {timeout}s")

    def stop(self, timeout: float = 5.0) -> None:
        if self._proc is None:
            return
        if self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
        if self._log_fh is not None:
            self._log_fh.close()
            self._log_fh = None
        self._proc = None

    def __enter__(self) -> "ProxyHarness":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    # ----- diagnostics -----

    def _fail(self, msg: str) -> None:
        """Stop the proxy (if running) and raise with a log tail attached."""
        try:
            tail = self.log_path.read_bytes()[-8192:].decode("utf-8", "replace")
        except OSError:
            tail = "(log file unreadable)"
        self.stop()
        raise RuntimeError(f"{msg}\n--- proxy log tail ---\n{tail}")
