"""End-to-end tests against `mount-s3` (Mountpoint for Amazon S3).

The directory-bucket compatibility goal is "a real mountpoint-s3 deployment
talks to the proxy without modification." mount-s3 was picked over
boto3/aws-cli for this suite because it's the only client we drive that
selects the *directory-bucket personality* on its own — `--bucket-type
directory` makes it sign with `service=s3express`, use the
`s3.endpoint_resolution_us` metric path, etc. The whole AWS-CRT-based
data plane goes through code paths that boto3 in general-purpose mode
never touches.

What this suite proves
----------------------
- mount-s3 with `--bucket-type directory` activates the
  `ExpressOneZone` personality (visible in its own log).
- All data-plane ops the personality emits (ListObjectsV2, HeadObject,
  CreateMultipartUpload/UploadPart/CompleteMultipartUpload, DeleteObject)
  reach the proxy, route to the worker, and produce the expected bytes
  on disk.
- A `--read-only` mount enforces no-write at the FUSE layer.

What this suite does NOT prove
------------------------------
- `CreateSession` is not exercised by mount-s3 when `--endpoint-url` is
  set: the AWS CRT's s3-express auth scheme bypasses the handshake for
  custom endpoints, even in directory-bucket mode. The CreateSession
  wire contract is covered by `tests/test_session.py` (raw SigV4).
- Conditional rename headers (`x-amz-rename-source-if-*`,
  `x-amz-client-token`). mount-s3's `cached_rename_support` latch trips
  on the first rename that needs them. Currently we don't drive renames
  through the mount; the gateway-side `RenameObject` is covered by
  `tests/test_rename.py`.

Skipped automatically when `mount-s3` isn't installed or `/dev/fuse`
isn't usable (CI without `--privileged`, kernels with no fuse module).
"""

from __future__ import annotations

import os
import time

import pytest

from s32p_test.mountpoint import MountpointSession, is_available


pytestmark = pytest.mark.skipif(
    not is_available(),
    reason="mount-s3 not installed or /dev/fuse not available",
)


# Bound on how long we wait for an MPU-complete to materialize on disk.
# mount-s3 returns from the user-space write before the upstream
# CompleteMultipartUpload finishes (the rename + ftruncate in the
# gateway), so a direct `bucket_fs.exists(...)` right after `write_bytes`
# can race. Three seconds is generous — the mount path is local
# loopback, so the real latency is tens of milliseconds.
_FS_VISIBLE_TIMEOUT_S = 3.0
_FS_POLL_S = 0.05


# ----------------------------------------------------------------- fixtures


@pytest.fixture
def mount(tmp_path, endpoint, bucket):
    """Mount the per-test `bucket` via mount-s3 in directory-bucket mode.

    `tmp_path` scopes the mount directory + log + creds file to the test,
    so a failure leaves disposable debris instead of polluting the
    session tempdir. The fixture handles `mount.stop()` even when the
    test raises; auto-unmount inside mount-s3 covers the SIGTERM path
    and `_force_unmount` covers the SIGKILL fallback.
    """
    session = MountpointSession(
        endpoint_url=endpoint.base_url,
        region=endpoint.region,
        access_key=endpoint.access_key,
        secret_key=endpoint.secret_key,
        bucket=bucket,
        mount_root=tmp_path,
        mode="rw",
    )
    session.start()
    try:
        yield session
    finally:
        session.stop()


@pytest.fixture
def mount_ro(tmp_path, endpoint, bucket, bucket_fs):
    """Read-only mount of the per-test bucket. Pre-seeds one file so the
    test has something to read without needing rw access."""
    bucket_fs.write("seed.bin", b"readable\n")
    session = MountpointSession(
        endpoint_url=endpoint.base_url,
        region=endpoint.region,
        access_key=endpoint.access_key,
        secret_key=endpoint.secret_key,
        bucket=bucket,
        mount_root=tmp_path,
        mode="ro",
    )
    session.start()
    try:
        yield session
    finally:
        session.stop()


# ----------------------------------------------------------------- helpers


def _wait_for_backend_file(bucket_fs, key: str, timeout: float = _FS_VISIBLE_TIMEOUT_S) -> bool:
    """Poll bucket_fs for `key` to appear. mount-s3's user-space write
    returns before CompleteMultipartUpload finishes propagating to the
    backend, so this small bounded wait absorbs the gap."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if bucket_fs.exists(key):
            return True
        time.sleep(_FS_POLL_S)
    return False


def _wait_for_mount_path(target, timeout: float = _FS_VISIBLE_TIMEOUT_S) -> bool:
    """Poll a mount-side path for visibility. mount-s3 caches negative
    lookups at minimal TTL, but there's still a beat between a backend
    write and the corresponding mount-side stat returning success."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if target.exists():
            return True
        time.sleep(_FS_POLL_S)
    return False


# ----------------------------------------------------------------- personality


def test_mount_selects_directory_bucket_personality(mount):
    """`--bucket-type directory` must make mount-s3 pick the
    ExpressOneZone personality. The marker is the only externally
    visible signal that mount-s3 considers this a directory bucket: it
    appears in mount-s3's own debug log at startup.

    Without this assertion, a future regression that mis-detects the
    bucket as general-purpose would still pass the data-plane tests
    below (they don't care which signing service was used) — this test
    is the one that locks in directory-bucket mode."""
    log = mount.log_tail(n=64 * 1024)
    assert "personality ExpressOneZone" in log, log


# ----------------------------------------------------------------- data plane


def test_write_via_mount_lands_on_backend(mount, bucket, bucket_fs):
    """Writing through the FUSE mount must land at the bucket's POSIX
    backing path with byte-identical content. mount-s3 always issues an
    MPU for writes (CreateMultipartUpload + UploadPart +
    CompleteMultipartUpload), so this exercises the gateway's MPU
    assembly path under the directory-bucket personality."""
    target = mount.path / "hello-mountpoint.txt"
    body = b"written through mount-s3\n"
    target.write_bytes(body)

    # The MPU-complete is async w.r.t. the user-space write — wait briefly
    # for the rename-into-place to happen on disk.
    assert _wait_for_backend_file(bucket_fs, "hello-mountpoint.txt"), (
        f"expected hello-mountpoint.txt on backend of {bucket}\n"
        f"--- mount-s3 log tail ---\n{mount.log_tail()}"
    )
    assert bucket_fs.read("hello-mountpoint.txt") == body


def test_read_via_mount_sees_backend_files(mount, bucket_fs):
    """An object placed via POSIX must be readable through the mount.
    With `test_write_via_mount_lands_on_backend` above, this proves the
    bidirectional interop contract for the directory-bucket
    personality."""
    bucket_fs.write("pre-existing.bin", b"placed via POSIX, read via FUSE\n")

    target = mount.path / "pre-existing.bin"
    assert _wait_for_mount_path(target), mount.log_tail()
    assert target.read_bytes() == b"placed via POSIX, read via FUSE\n"


def test_list_via_mount_reflects_backend(mount, bucket_fs):
    """`os.listdir(mount.path)` reflects the bucket's top-level keys —
    same set the backend lists. Doesn't assert ordering (mount-s3 caches
    pages from ListObjectsV2; the order is not load-bearing)."""
    for name in ("a.txt", "b.txt", "c.bin"):
        bucket_fs.write(name, b"x")

    deadline = time.monotonic() + _FS_VISIBLE_TIMEOUT_S
    seen: set[str] = set()
    while time.monotonic() < deadline:
        seen = set(os.listdir(mount.path))
        if {"a.txt", "b.txt", "c.bin"}.issubset(seen):
            break
        time.sleep(_FS_POLL_S)
    assert {"a.txt", "b.txt", "c.bin"}.issubset(seen), (
        f"mount listing {seen} missing entries; log:\n{mount.log_tail()}"
    )


def test_delete_via_mount_removes_backend_file(mount, bucket_fs):
    """`os.unlink` through the mount must remove the backend file. Needs
    `--allow-delete` (which our `mode='rw'` mount enables)."""
    bucket_fs.write("doomed.bin", b"goodbye\n")
    target = mount.path / "doomed.bin"
    assert _wait_for_mount_path(target), mount.log_tail()

    os.unlink(target)

    # Deletion is synchronous on the wire (DELETE returns 204 before
    # mount-s3 returns from unlink), but the negative-cache + readdir
    # interaction can briefly let the backend race; bound the check.
    deadline = time.monotonic() + _FS_VISIBLE_TIMEOUT_S
    while time.monotonic() < deadline and bucket_fs.exists("doomed.bin"):
        time.sleep(_FS_POLL_S)
    assert not bucket_fs.exists("doomed.bin"), mount.log_tail()


def test_roundtrip_via_mount(mount):
    """Pure FUSE roundtrip: write, read back, byte-identity. Doesn't
    touch the backend at all — both sides are the mount. Catches any
    mid-flight corruption that wouldn't show up in the POSIX-asserts
    tests (which all bypass mount-s3's read cache by checking the
    backend directly)."""
    target = mount.path / "roundtrip.bin"
    body = bytes(range(256)) * 16  # 4 KiB of varied bytes
    target.write_bytes(body)

    # mount-s3 might serve from its own read buffer; that's fine — the
    # test is "what I wrote is what I read", not "what's on disk".
    assert _wait_for_mount_path(target), mount.log_tail()
    assert target.read_bytes() == body


# ----------------------------------------------------------------- read-only


def test_readonly_mount_reads_succeed(mount_ro):
    """A `--read-only` mount must serve GETs unimpeded — read-only is a
    FUSE-level flag, not a session-mode flag, so it shouldn't interact
    with the proxy's ReadOnly session enforcement at all."""
    target = mount_ro.path / "seed.bin"
    assert _wait_for_mount_path(target), mount_ro.log_tail()
    assert target.read_bytes() == b"readable\n"


def test_readonly_mount_rejects_writes(mount_ro):
    """Writes through a `--read-only` mount must fail at the FUSE layer
    (EROFS), before any request reaches the proxy. Enforced by mount-s3,
    not by us — the test exists to catch a regression where a future
    config change accidentally drops `--read-only`."""
    with pytest.raises(OSError) as exc:
        (mount_ro.path / "should-fail.txt").write_bytes(b"x")
    # EROFS (30) or EACCES (13) depending on kernel/mountpoint version.
    assert exc.value.errno in (13, 30), exc.value
