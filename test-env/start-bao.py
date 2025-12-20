#!/usr/bin/env python3
"""
Starts OpenBao in dev mode and seeds it with 5 test IAM users for versitygw's Vault IAM backend
(while writing the user data directly via the OpenBao/Vault HTTP API, NOT via versitygw admin).

Default layout seeded (matches versitygw IAM-Vault wiki example):
  mount:   kv-v2/   (KV v2 engine)
  prefix:  versitygw/
  secret:  versitygw/<access>
  data:    { "<access>": {access, secret, role, userID, groupID, projectID} }

Usage:
  python3 start-bao.py

Requirements:
  - OpenBao CLI installed and on PATH as `bao` (or set --bao-bin).
  - Python 3.8+.

Notes:
  - This is for local testing only (dev mode is intentionally insecure).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


@dataclass(frozen=True)
class UserAccount:
    access: str
    secret: str
    role: str       # "admin" | "user" | "userplus"
    userID: int
    groupID: int
    projectID: int

    def as_versitygw_account_obj(self) -> Dict[str, Any]:
        return {
            "access": self.access,
            "secret": self.secret,
            "role": self.role,
            "userID": self.userID,
            "groupID": self.groupID,
            "projectID": self.projectID,
        }


def http_json(
    base_url: str,
    method: str,
    path: str,
    token: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
    timeout_s: float = 3.0,
) -> Tuple[int, Dict[str, Any]]:
    url = base_url.rstrip("/") + path
    data = None
    headers = {"Accept": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read()
            if not raw:
                return resp.status, {}
            try:
                return resp.status, json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                return resp.status, {}
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            j = json.loads(raw.decode("utf-8")) if raw else {}
        except json.JSONDecodeError:
            j = {}
        return e.code, j
    except urllib.error.URLError as e:
        raise RuntimeError(f"Failed to connect to {url}: {e}") from e


def wait_for_ready(base_url: str, timeout_s: float = 20.0) -> None:
    deadline = time.time() + timeout_s
    last_err: Optional[str] = None
    while time.time() < deadline:
        try:
            status, _ = http_json(base_url, "GET", "/v1/sys/health", token=None, payload=None, timeout_s=1.5)
            if status in (200, 429, 472, 473, 501, 503):
                return
        except Exception as e:
            last_err = str(e)
        time.sleep(0.25)
    raise RuntimeError(f"OpenBao did not become ready at {base_url} within {timeout_s}s. Last error: {last_err}")


def ensure_kv_v2_mount(base_url: str, token: str, mount: str) -> None:
    mount = mount.strip("/")
    status, mounts = http_json(base_url, "GET", "/v1/sys/mounts", token=token)
    if status != 200:
        raise RuntimeError(f"Failed to read mounts: HTTP {status} {mounts}")

    if (mount + "/") in mounts:
        return

    payload = {"type": "kv", "options": {"version": "2"}, "description": "KV v2 for versitygw IAM test users"}
    status, resp = http_json(base_url, "POST", f"/v1/sys/mounts/{mount}", token=token, payload=payload)
    if status not in (200, 204):
        raise RuntimeError(f"Failed to mount kv-v2 at {mount}/: HTTP {status} {resp}")


def write_versitygw_user(base_url: str, token: str, mount: str, storage_prefix: str, user: UserAccount) -> None:
    mount = mount.strip("/")
    storage_prefix = storage_prefix.strip("/")
    secret_path = f"{storage_prefix}/{user.access}"
    api_path = f"/v1/{mount}/data/{secret_path}"
    payload = {"data": {user.access: user.as_versitygw_account_obj()}}

    status, resp = http_json(base_url, "POST", api_path, token=token, payload=payload)
    if status not in (200, 204):
        raise RuntimeError(f"Failed to write user {user.access}: HTTP {status} {resp}")


def make_temp_openbao_config(log_level: str, log_requests_level: str, enable_audit_stdout: bool) -> str:
    """
    Create a temp HCL config file. We delete it after the server is up.
    """
    hcl_parts = [
        f'log_level = "{log_level}"',
        f'log_requests_level = "{log_requests_level}"',
    ]

    # Declarative audit device to stdout (Linux/macOS): /dev/stdout
    # (On Windows, you'd likely want a file audit path instead.)
    if enable_audit_stdout:
        hcl_parts.append(
            """
audit "file" "to-stdout" {
  description = "Dev audit log to stdout."
  options {
    file_path = "/dev/stdout"
    log_raw   = "true"
  }
}
""".strip()
        )

    hcl = "\n\n".join(hcl_parts) + "\n"

    fd, path = tempfile.mkstemp(prefix="openbao-dev-", suffix=".hcl")
    try:
        os.write(fd, hcl.encode("utf-8"))
    finally:
        os.close(fd)

    # Tighten perms (best-effort)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass

    return path


def start_openbao_dev(bao_bin: str, listen_addr: str, root_token: str, config_path: str) -> subprocess.Popen:
    cmd = [
        bao_bin,
        "server",
        f"-config={config_path}",
        "-dev",
        f"-dev-root-token-id={root_token}",
        f"-dev-listen-address={listen_addr}",
    ]

    if os.name == "nt":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
        return subprocess.Popen(cmd, creationflags=creationflags)
    else:
        return subprocess.Popen(cmd, preexec_fn=os.setsid)


def stop_process(proc: subprocess.Popen, grace_s: float = 3.0) -> None:
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            proc.send_signal(signal.CTRL_BREAK_EVENT)  # type: ignore[attr-defined]
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass

    deadline = time.time() + grace_s
    while time.time() < deadline:
        if proc.poll() is not None:
            return
        time.sleep(0.1)

    try:
        if os.name == "nt":
            proc.kill()
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def safe_unlink(path: str) -> None:
    try:
        if path and os.path.exists(path):
            os.unlink(path)
    except Exception:
        pass


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--bao-bin", default="bao", help="Path to the `bao` binary (default: bao)")
    p.add_argument("--listen", default="127.0.0.1:8200", help="Dev listen address (default: 127.0.0.1:8200)")
    p.add_argument("--url", default=None, help="Base URL (default: http://<listen>)")
    p.add_argument("--root-token", default="root", help="Dev root token (default: root)")
    p.add_argument("--mount", default="secret", help="KV v2 mount path for versitygw (default: kv-v2)")
    p.add_argument("--storage-prefix", default="versitygw", help="Secret storage prefix (default: versitygw)")
    p.add_argument("--log-level", default="info", help="OpenBao log_level (default: info)")
    p.add_argument("--log-requests-level", default="info", help="OpenBao log_requests_level (default: info)")
    p.add_argument("--no-audit-stdout", action="store_true", help="Disable declarative audit to stdout")
    args = p.parse_args()

    if shutil.which(args.bao_bin) is None:
        print(f"ERROR: '{args.bao_bin}' not found on PATH. Install OpenBao and ensure `bao` is available.", file=sys.stderr)
        return 2

    base_url = args.url or f"http://{args.listen}"

    users = [
        UserAccount("testadmin", "testadmin-secret", "admin", 1, 0, 0),
        UserAccount("testuser1", "testuser1-secret", "user", 2, 0, 0),
        UserAccount("testuser2", "testuser2-secret", "user", 3, 0, 0),
        UserAccount("testuser3", "testuser3-secret", "userplus", 4, 0, 0),
        UserAccount("testuser4", "testuser4-secret", "user", 5, 0, 0),
    ]

    config_path = make_temp_openbao_config(
        log_level=args.log_level,
        log_requests_level=args.log_requests_level,
        enable_audit_stdout=(not args.no_audit_stdout),
    )

    proc: Optional[subprocess.Popen] = None
    try:
        proc = start_openbao_dev(args.bao_bin, args.listen, args.root_token, config_path)

        # Keep config until the server is actually responding, then delete it (“deleted on access”).
        wait_for_ready(base_url, timeout_s=20.0)
        safe_unlink(config_path)

        ensure_kv_v2_mount(base_url, args.root_token, args.mount)
        for u in users:
            write_versitygw_user(base_url, args.root_token, args.mount, args.storage_prefix, u)

        print("\nOpenBao dev server is running and seeded for versitygw.\n")
        print(f"OpenBao URL:        {base_url}")
        print(f"Root token:         {args.root_token}")
        print(f"KV v2 mount:        {args.mount}/")
        print(f"Storage prefix:     {args.storage_prefix}/")
        print(f"Request logs:       log_requests_level={args.log_requests_level} (see stdout)")
        print(f"Audit to stdout:    {'no' if args.no_audit_stdout else 'yes'}")
        print("\nSeeded IAM users (access / secret / role):")
        for u in users:
            print(f"  - {u.access} / {u.secret} / {u.role}")

        print("\nCtrl+C to stop.\n")

        while True:
            rc = proc.poll()
            if rc is not None:
                print(f"\nOpenBao exited with code {rc}")
                return rc
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\nStopping OpenBao...")
        if proc is not None:
            stop_process(proc)
        return 0
    except Exception as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        if proc is not None:
            stop_process(proc)
        return 1
    finally:
        # If startup failed before we deleted it, clean up the temp config.
        safe_unlink(config_path)


if __name__ == "__main__":
    raise SystemExit(main())

