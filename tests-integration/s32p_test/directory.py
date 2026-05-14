"""Directory state for tests, driven through the real `s32p-ctl` binary.

Tests construct typed Python values (User, Bucket, Grant) and this module
translates them to `s32p-ctl --backend yaml --yaml-path <path> …`
invocations. Two reasons for going through the CLI rather than emitting
YAML directly: it avoids duplicating the schema across two languages, and
every test setup ends up exercising the operator code path for free.

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


class YamlDirectory:
    """Wrapper around `s32p-ctl --backend yaml --yaml-path <path>`.

    The backing file is created lazily on first invocation via `setup`;
    explicit `setup()` calls are also fine and idempotent.
    """

    def __init__(self, path: Path):
        self.path = path
        if not path.exists():
            self.setup()

    # ----- raw CLI access -----

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        cmd = [
            str(s32p_ctl_binary()),
            "--backend", "yaml",
            "--yaml-path", str(self.path),
            *args,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise CtlError(list(args), result.returncode, result.stderr)
        return result

    # ----- lifecycle -----

    def setup(self) -> None:
        """Create an empty directory file if missing."""
        self._run("setup")

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
