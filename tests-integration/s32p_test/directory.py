"""Directory state for tests, driven through the real `s32p-ctl` binary.

Tests construct typed Python values (User, Bucket, Grant) and this module
translates them to `s32p-ctl --backend <yaml|openbao> …` invocations. Two
reasons for going through the CLI rather than writing the backing store
directly: it avoids duplicating the schema across two languages, and every
test setup ends up exercising the operator code path for free.

Two backends share the same command surface via `_CtlDirectory`:
`YamlDirectory` (the default for the bulk of the suite) and
`OpenBaoDirectory` (used by `tests/test_openbao.py` to cover the Vault/KV
read+write paths). They differ only in the backend-selection flags and in
how `setup` bootstraps; the user/bucket/ACL commands are identical.

For deliberately-malformed-directory negative tests, bypass this wrapper
and write the YAML by hand — call that out in a comment so it's clear the
bypass is intentional.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .paths import s32p_ctl_binary

AccessLevel = Literal["read_only", "read_write"]
PrincipalType = Literal["ak", "group"]


@dataclass(slots=True, frozen=True)
class User:
    access_key: str
    secret_key: str
    username: str
    uid: int
    gid: int


@dataclass(slots=True, frozen=True)
class Grant:
    """A `--grant` value for s32p-ctl. Canonical form `ak:KEY:read_write` /
    `group:NAME:read_only`."""
    principal_type: PrincipalType
    principal: str
    access: AccessLevel

    def __str__(self) -> str:
        return f"{self.principal_type}:{self.principal}:{self.access}"


@dataclass(slots=True, frozen=True)
class Bucket:
    name: str
    data_path: Path
    grants: tuple[Grant, ...] = ()
    bucket_id: str | None = None  # auto-generated UUID if None


class CtlError(RuntimeError):
    """Raised when s32p-ctl exits non-zero. Carries the captured stderr."""

    def __init__(self, args: list[str], rc: int, stderr: str):
        super().__init__(
            f"s32p-ctl {' '.join(args)} failed (rc={rc}): {stderr.strip()}"
        )
        self.args = args
        self.rc = rc
        self.stderr = stderr


class _CtlDirectory:
    """Backend-agnostic `s32p-ctl` command surface.

    Subclasses supply `_backend_args()` (the `--backend …` selection flags
    that precede every subcommand) and their own `setup()` bootstrap. The
    user/bucket/ACL commands below are identical across backends.
    """

    # ----- backend selection (subclass responsibility) -----

    def _backend_args(self) -> list[str]:
        raise NotImplementedError

    # ----- raw CLI access -----

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        cmd = [
            str(s32p_ctl_binary()),
            *self._backend_args(),
            *args,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise CtlError(list(args), result.returncode, result.stderr)
        return result

    # ----- users -----

    def add_user(self, user: User) -> User:
        self._run(
            "user", "add",
            "--access-key", user.access_key,
            "--secret-key", user.secret_key,
            "--username", user.username,
            "--uid", str(user.uid),
            "--gid", str(user.gid),
        )
        return user

    def rm_user(self, access_key: str, *, cleanup_acls: bool = True) -> None:
        self._run(
            "user", "rm",
            "--access-key", access_key,
            "--cleanup-acls", "true" if cleanup_acls else "false",
        )

    def list_users(self) -> str:
        """Returns the raw `user ls` output. Tests usually don't need this;
        prefer asserting via the Directory API or via S3 ListBuckets."""
        return self._run("user", "ls").stdout

    # ----- buckets -----

    def add_bucket(self, bucket: Bucket) -> Bucket:
        bucket.data_path.mkdir(parents=True, exist_ok=True)
        args = [
            "bucket", "add",
            "--name", bucket.name,
            "--data-path", str(bucket.data_path),
        ]
        if bucket.bucket_id is not None:
            args += ["--bucket-id", bucket.bucket_id]
        for g in bucket.grants:
            args += ["--grant", str(g)]
        self._run(*args)
        return bucket

    def rm_bucket(self, bucket_id: str) -> None:
        self._run("bucket", "rm", "--bucket-id", bucket_id)

    def acl_set(self, bucket_id: str, grants: list[Grant]) -> None:
        args = ["bucket", "acl-set", "--bucket-id", bucket_id]
        for g in grants:
            args += ["--grant", str(g)]
        self._run(*args)

    def list_buckets(self) -> str:
        return self._run("bucket", "ls").stdout


class YamlDirectory(_CtlDirectory):
    """Wrapper around `s32p-ctl --backend yaml --yaml-path <path>`.

    The backing file is created lazily on construction via `setup`;
    explicit `setup()` calls are also fine and idempotent.
    """

    def __init__(self, path: Path):
        self.path = path
        if not path.exists():
            self.setup()

    def _backend_args(self) -> list[str]:
        return ["--backend", "yaml", "--yaml-path", str(self.path)]

    def setup(self) -> None:
        """Create an empty directory file if missing."""
        self._run("setup")


class OpenBaoDirectory(_CtlDirectory):
    """Wrapper around `s32p-ctl --backend openbao …`.

    Authenticates either with a root/admin `token` or with an AppRole
    `role_id_file`/`secret_id_file` pair (mutually exclusive — token wins
    if both are given, mirroring `s32p-ctl`'s own precedence). The KV mount
    and prefix default to the same values the proxy and `s32p-ctl` use, so
    a dev OpenBao plus `openbao_setup()` is all that's needed.

    Unlike the YAML backend there is no per-instance file to create, so
    `setup()` is a no-op here: AppRole/policy bootstrap is a one-shot
    root-token operation handled by `openbao_setup()` before any directory
    wrapper is built.
    """

    def __init__(
        self,
        address: str,
        *,
        token: str | None = None,
        role_id_file: Path | None = None,
        secret_id_file: Path | None = None,
        kv_mount: str = "secret",
        prefix: str = "s32p",
        approle_mount: str = "approle",
    ):
        if token is None and (role_id_file is None or secret_id_file is None):
            raise ValueError(
                "OpenBaoDirectory needs either token= or "
                "both role_id_file= and secret_id_file="
            )
        self.address = address
        self.token = token
        self.role_id_file = role_id_file
        self.secret_id_file = secret_id_file
        self.kv_mount = kv_mount
        self.prefix = prefix
        self.approle_mount = approle_mount

    def _backend_args(self) -> list[str]:
        args = [
            "--backend", "openbao",
            "--address", self.address,
            "--kv-mount", self.kv_mount,
            "--prefix", self.prefix,
        ]
        if self.token is not None:
            args += ["--token", self.token]
        else:
            args += [
                "--approle-mount", self.approle_mount,
                "--role-id-file", str(self.role_id_file),
                "--secret-id-file", str(self.secret_id_file),
            ]
        return args

    def setup(self) -> None:
        """No-op: OpenBao bootstrap is done once via `openbao_setup()`."""


def openbao_setup(
    *,
    address: str,
    token: str,
    proxy_role_id_file: Path,
    proxy_secret_id_file: Path,
    admin_role_id_file: Path,
    admin_secret_id_file: Path,
    kv_mount: str = "secret",
    prefix: str = "s32p",
    approle_mount: str = "approle",
) -> None:
    """Run `s32p-ctl --backend openbao … setup` against a dev OpenBao.

    Creates the proxy/admin AppRoles + policies and writes their role_id /
    secret_id to the four files (mode 0600, created by s32p-ctl). The proxy
    consumes the proxy_* pair; the admin_* pair authenticates the
    `OpenBaoDirectory` used to seed users/buckets. Requires a root/admin
    `token` (the dev server's `-dev-root-token-id`).
    """
    for p in (proxy_role_id_file, proxy_secret_id_file,
              admin_role_id_file, admin_secret_id_file):
        p.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        str(s32p_ctl_binary()),
        "--backend", "openbao",
        "--address", address,
        "--token", token,
        "--kv-mount", kv_mount,
        "--prefix", prefix,
        "--approle-mount", approle_mount,
        "setup",
        "--proxy-role-id-file", str(proxy_role_id_file),
        "--proxy-secret-id-file", str(proxy_secret_id_file),
        "--admin-role-id-file", str(admin_role_id_file),
        "--admin-secret-id-file", str(admin_secret_id_file),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise CtlError(["setup"], result.returncode, result.stderr)
