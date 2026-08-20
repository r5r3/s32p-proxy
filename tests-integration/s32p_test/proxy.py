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
    # TLS material for the public listener. The proxy requires both when
    # `public_scheme` is "https" (config.rs rejects the config otherwise),
    # and it runs the key through the same secret-file check as the
    # directory file: mode 0600 or stricter, owned by the proxy uid.
    tls_cert_path: Path | None = None
    tls_key_path: Path | None = None
    log_level: str = (
        "s32p_proxy=info,s32p_gateway=info,pingora=warn,pingora_proxy=warn"
    )
    virtual_hosted_suffixes: tuple[str, ...] = ()
    idle_timeout_secs: int = 600
    sweep_interval_secs: int = 5
    profile_name: str = "gateway"
    # CreateSession TTL. Kept short by default so expiry tests don't
    # bottleneck the suite; tests that need longer can override.
    session_ttl_secs: int = 60
    # Landlock matches the production deployment policy. The proxy's
    # `--allow-nss` flag is dropped (workers resolve uid → username via
    # the proxy's abstract NSS socket); allow-list is `--rw staged_root`,
    # per-bucket `--ro/--rw data_path`, `--rw uds-parent`, `--resolve-libs`.
    # `S32P_LOG_UTC_OFFSET_SECS` injection bypasses the
    # `/etc/localtime` read that would otherwise fail.
    landlock_enabled: bool = True
    # `server.connection_limits` knobs. Defaults match the production
    # ones in `etc/s32p-proxy.yaml`. The loopback bypass is on by
    # default because the test runner is `127.0.0.1` — without it,
    # bursty positive tests would intermittently false-trip the cap.
    # Tests that *do* want to exercise the cap (test_dos.py) spin up
    # their own harness with `trusted_loopback_bypass=False` and a low
    # `max_concurrent_requests_per_ip`.
    max_concurrent_requests_per_ip: int = 256
    keepalive_idle_secs: int = 60
    trusted_loopback_bypass: bool = True
    # Override for the generated `auth:` block. None → the default YAML
    # backend (and a `self.directory` YamlDirectory is created). Set it to
    # an `{"backend": "openbao", "openbao": {...}}` dict to point the proxy
    # at an OpenBao instead; in that case the caller owns directory seeding
    # (via OpenBaoDirectory) and `self.directory` is None.
    auth_config: dict | None = None

    # Derived in __post_init__
    posix_root: Path = field(init=False)
    uds_run_dir: Path = field(init=False)
    config_path: Path = field(init=False)
    directory_path: Path = field(init=False)
    log_path: Path = field(init=False)
    directory: YamlDirectory | None = field(init=False)

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

        # YAML backend owns a directory file the harness seeds directly;
        # OpenBao callers seed via their own OpenBaoDirectory wrapper.
        self.directory = (
            YamlDirectory(self.directory_path) if self.auth_config is None else None
        )

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
            # NOTE: S32P_WORKER_TOKEN is auto-injected by the proxy at
            # spawn time; not exposed as a YAML placeholder.
        }

        server: dict = {
            "listen": f"{self.listen_host}:{self.listen_port}",
            "public_scheme": self.public_scheme,
            "region": self.region,
            "log_level": self.log_level,
            "shutdown_grace_period_secs": 5,
            "virtual_hosted_suffixes": list(self.virtual_hosted_suffixes),
            "connection_limits": {
                "max_concurrent_requests_per_ip": self.max_concurrent_requests_per_ip,
                "keepalive_idle_secs": self.keepalive_idle_secs,
                "trusted_loopback_bypass": self.trusted_loopback_bypass,
            },
        }
        if self.public_scheme == "https":
            if self.tls_cert_path is None or self.tls_key_path is None:
                raise ValueError(
                    "public_scheme='https' needs tls_cert_path and tls_key_path"
                )
            server["tls_cert_path"] = str(self.tls_cert_path)
            server["tls_key_path"] = str(self.tls_key_path)

        return {
            "version": 1,
            "server": server,
            "auth": self.auth_config or {
                "backend": "yaml",
                "yaml": {"path": str(self.directory_path)},
            },
            "workers": {
                "posix_root": str(self.posix_root),
                "launcher": {
                    "path": str(restricted_exec_binary()),
                    "pass_user_flag_if_root": False,
                    "landlock": self.landlock_enabled,
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
                    "versioning":   {"action": "aws_compat"},
                    "object_lock":  {"action": "aws_compat"},
                    "service":      {"action": "aws_compat"},
                    "bucket_admin": {"action": "not_implemented", "message": "bucket admin via s32p-ctl only"},
                    "session":      {"action": "create_session"},
                },
            },
            "session": {
                "ttl_secs": self.session_ttl_secs,
                "cleanup_interval_secs": 5,
                "max_active": 1000,
            },
        }

    def write_config(self) -> None:
        self.config_path.write_text(yaml.safe_dump(self._build_config(), sort_keys=False))

    # ----- lifecycle -----

    def start(self, timeout: float = 15.0, max_attempts: int = 3) -> None:
        """Spawn the proxy; on early-exit (typical port-reuse race under
        xdist), pick a new port and retry up to `max_attempts` times."""
        if self._proc is not None:
            raise RuntimeError("ProxyHarness.start() called twice")

        last_reason = ""
        for attempt in range(1, max_attempts + 1):
            outcome = self._spawn_attempt(timeout)
            if outcome is None:
                return  # success
            last_reason = outcome
            if attempt < max_attempts:
                self.listen_port = _alloc_port(self.listen_host)
        self._fail(
            f"proxy did not start after {max_attempts} attempts; last: {last_reason}"
        )

    def _spawn_attempt(self, timeout: float) -> str | None:
        """One spawn attempt. Returns None on success, an error reason
        string on failure (caller decides whether to retry)."""
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
                rc = self._proc.returncode
                self._tear_down_attempt()
                return f"proxy exited early (rc={rc})"
            if _port_open(self.listen_host, self.listen_port):
                return None
            time.sleep(0.05)
        # Deadline expired without the port opening — kill, return reason.
        self._tear_down_attempt()
        return (
            f"proxy did not start listening on "
            f"{self.listen_host}:{self.listen_port} within {timeout}s"
        )

    def _tear_down_attempt(self) -> None:
        """Clean up an attempt that didn't reach 'listening' state, so
        start() can retry on a fresh port without leaking the process."""
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(2.0)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
        self._proc = None
        if self._log_fh is not None:
            self._log_fh.close()
            self._log_fh = None

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
