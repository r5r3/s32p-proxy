"""End-to-end tests against FUSE mount clients (mount-s3 + rclone).

We drive two FUSE mount clients against the proxy:

  * `mount-s3` (Mountpoint for Amazon S3) — exercises the directory-bucket
    `ExpressOneZone` personality (`--bucket-type directory`, s3express
    signing, CRT data plane).
  * `rclone` — exercises generic SigV4 S3-compat path-style traffic, the
    shape every "rclone against MinIO/Ceph/our proxy" user runs.

The generic data-plane tests (`test_write_via_mount_lands_on_backend`,
`test_read_via_mount_sees_backend_files`, listing, delete, roundtrip,
read-only) are parametrized over both backends via the `mount_backend`
fixture — the same assertion runs once per client, ensuring both code
paths land bytes correctly on the POSIX backend. Client-specific tests
(personality marker, `If-None-Match` collision, `--incremental-upload`,
the directory-rename FUSE refusal, mount-s3's `RenameObject` path) stay
mount-s3 only via `@pytest.mark.parametrize("mount_backend",
["mount-s3"], indirect=True)`.

What this suite proves
----------------------
- mount-s3 with `--bucket-type directory` activates the
  `ExpressOneZone` personality (visible in its own log).
- Both clients' data-plane ops (ListObjectsV2, HeadObject, the various
  PUT/upload paths, DeleteObject) reach the proxy, route to the worker,
  and produce the expected bytes on disk.
- A `--read-only` mount enforces no-write at the FUSE layer (both
  clients).

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

Per-backend availability is checked inside the `mount` fixture: a test
parametrized over a backend whose binary isn't installed (or whose
`/dev/fuse` isn't usable) is skipped rather than failing.
"""

from __future__ import annotations

import os
import time

import pytest

from s32p_test.mountpoint import MountpointSession
from s32p_test.mountpoint import is_available as mountpoint_is_available
from s32p_test.rclone import RcloneMountSession, endpoint_url_for_rclone
from s32p_test.rclone import is_available as rclone_is_available


# Module-level guard: if neither backend is available there is nothing
# this file can do. Per-backend availability is re-checked inside the
# `mount` fixture so a one-backend-missing system still runs the
# tests for the other.
pytestmark = pytest.mark.skipif(
    not (mountpoint_is_available() or rclone_is_available()),
    reason="neither mount-s3 nor rclone is available (or /dev/fuse is missing)",
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


# Backends the generic mount tests run against. The fixture is parametrized
# here once; tests that need a specific backend override with
# `@pytest.mark.parametrize("mount_backend", ["mount-s3"], indirect=True)`.
_MOUNT_BACKENDS = ("mount-s3", "rclone")


@pytest.fixture(params=_MOUNT_BACKENDS)
def mount_backend(request) -> str:
    """Parametrized over `mount-s3` and `rclone`. A test that depends on
    `mount` (or `mount_ro`) without overriding this fixture runs once per
    backend. Backends whose binary is not installed cause the individual
    parametrization to be skipped — see `_make_mount_session`."""
    return request.param


def _make_mount_session(
    backend: str, *, tmp_path, endpoint, bucket, mode: str,
):
    """Construct (but don't start) a mount session for `backend`.

    Skips the test when the requested backend isn't usable on this host
    (binary missing, `/dev/fuse` absent). Per-backend skipping — not
    per-module — lets a one-backend-missing system still run the other
    half of the matrix.
    """
    if backend == "mount-s3":
        if not mountpoint_is_available():
            pytest.skip("mount-s3 not installed or /dev/fuse not available")
        return MountpointSession(
            endpoint_url=endpoint.base_url,
            region=endpoint.region,
            access_key=endpoint.access_key,
            secret_key=endpoint.secret_key,
            bucket=bucket,
            mount_root=tmp_path,
            mode=mode,
        )
    if backend == "rclone":
        if not rclone_is_available():
            pytest.skip("rclone not installed or /dev/fuse not available")
        return RcloneMountSession(
            endpoint_url=endpoint_url_for_rclone(endpoint.base_url),
            region=endpoint.region,
            access_key=endpoint.access_key,
            secret_key=endpoint.secret_key,
            bucket=bucket,
            mount_root=tmp_path,
            mode=mode,
        )
    raise ValueError(f"unknown mount backend: {backend!r}")


@pytest.fixture
def mount(tmp_path, endpoint, bucket, mount_backend):
    """Mount the per-test `bucket` via the parametrized backend.

    `tmp_path` scopes the mount directory + log + creds file to the test,
    so a failure leaves disposable debris instead of polluting the
    session tempdir. The fixture handles `stop()` even when the test
    raises; mount-s3's auto-unmount and rclone's SIGTERM handler cover
    the clean path, with a fusermount fallback for the SIGKILL case.
    """
    session = _make_mount_session(
        mount_backend, tmp_path=tmp_path, endpoint=endpoint,
        bucket=bucket, mode="rw",
    )
    session.start()
    try:
        yield session
    finally:
        session.stop()


@pytest.fixture
def mount_ro(tmp_path, endpoint, bucket, bucket_fs, mount_backend):
    """Read-only mount of the per-test bucket. Pre-seeds one file so the
    test has something to read without needing rw access."""
    bucket_fs.write("seed.bin", b"readable\n")
    session = _make_mount_session(
        mount_backend, tmp_path=tmp_path, endpoint=endpoint,
        bucket=bucket, mode="ro",
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


@pytest.mark.parametrize("mount_backend", ["mount-s3"], indirect=True)
def test_mount_selects_directory_bucket_personality(mount):
    """`--bucket-type directory` must make mount-s3 pick the
    ExpressOneZone personality. The marker is the only externally
    visible signal that mount-s3 considers this a directory bucket: it
    appears in mount-s3's own debug log at startup.

    Without this assertion, a future regression that mis-detects the
    bucket as general-purpose would still pass the data-plane tests
    below (they don't care which signing service was used) — this test
    is the one that locks in directory-bucket mode. mount-s3-only —
    rclone has no equivalent personality split."""
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


# ----------------------------------------------------------------- rename


# mountpoint-s3 1.x added support for the S3 Express `RenameObject` op
# (directory-bucket flavor of `mv`). On `--bucket-type directory` it
# will issue `PUT /{bucket}/{newkey}?renameObject` with the
# `x-amz-rename-source` header — exactly the surface the gateway
# implements (`tests/test_rename.py` covers it standalone). These
# tests prove the round-trip through FUSE → mount-s3 → proxy → gateway.
#
# Directory rename: AWS S3 Express doesn't have a "rename prefix" op,
# so mount-s3 either rejects it (EINVAL/EPERM) or walks the prefix and
# renames each key. We test it to document what happens, not to
# guarantee any particular outcome — if a future mount-s3 version
# changes the strategy the test makes that visible.


@pytest.mark.parametrize("mount_backend", ["mount-s3"], indirect=True)
def test_rename_file_via_mount(mount, bucket_fs):
    """`os.rename(a, b)` on a file inside the mount must produce the
    same backend state as a server-side `RenameObject`: new path
    contains the bytes, old path is gone. mount-s3-only because the
    assertion is specifically about its `RenameObject` path; rclone
    implements rename as CopyObject + DeleteObject and would exercise
    a different code path on the gateway side."""
    bucket_fs.write("orig.txt", b"rename me\n")
    src = mount.path / "orig.txt"
    dst = mount.path / "renamed.txt"

    assert _wait_for_mount_path(src), mount.log_tail()
    os.rename(src, dst)

    # Backend reflects the rename.
    deadline = time.monotonic() + _FS_VISIBLE_TIMEOUT_S
    while time.monotonic() < deadline:
        if bucket_fs.exists("renamed.txt") and not bucket_fs.exists("orig.txt"):
            break
        time.sleep(_FS_POLL_S)
    assert bucket_fs.exists("renamed.txt"), mount.log_tail()
    assert bucket_fs.read("renamed.txt") == b"rename me\n"
    assert not bucket_fs.exists("orig.txt"), mount.log_tail()


@pytest.mark.parametrize("mount_backend", ["mount-s3"], indirect=True)
def test_rename_file_across_dirs_via_mount(mount, bucket_fs):
    """Renaming across directories must work the same way. Tests both
    that the target parent directory is created on the backend (S3 has
    no real directories — the gateway must just place the object) and
    that the source parent is pruned afterwards (existing gateway
    behavior). mount-s3-only — same rationale as
    `test_rename_file_via_mount`."""
    bucket_fs.write("src-dir/orig.txt", b"crossing dirs\n")
    src = mount.path / "src-dir" / "orig.txt"
    dst_dir = mount.path / "dst-dir"
    dst = dst_dir / "renamed.txt"

    assert _wait_for_mount_path(src), mount.log_tail()
    # mount-s3 needs the target dir to exist as a FUSE node; in S3 land
    # this is a no-op (directories are virtual), but FUSE doesn't know
    # that. `exist_ok=True` because mount-s3 may already have created an
    # implicit dir node for the empty bucket.
    dst_dir.mkdir(exist_ok=True)

    os.rename(src, dst)

    deadline = time.monotonic() + _FS_VISIBLE_TIMEOUT_S
    while time.monotonic() < deadline:
        if bucket_fs.exists("dst-dir/renamed.txt") and not bucket_fs.exists("src-dir/orig.txt"):
            break
        time.sleep(_FS_POLL_S)
    assert bucket_fs.exists("dst-dir/renamed.txt"), mount.log_tail()
    assert bucket_fs.read("dst-dir/renamed.txt") == b"crossing dirs\n"
    assert not bucket_fs.exists("src-dir/orig.txt"), mount.log_tail()


@pytest.mark.parametrize("mount_backend", ["mount-s3"], indirect=True)
def test_directory_rename_refused_at_fuse_layer(mount, bucket_fs):
    """mount-s3 refuses to rename a directory (= shared key prefix) at
    the FUSE layer with `EPERM`. The refusal happens *before* any S3
    request — mount-s3 issues a HEAD + ListObjectsV2 on the source,
    sees the `<name>/` prefix shape, and rejects with "inode is a
    directory and cannot be renamed".

    AWS S3 Express has no atomic prefix-rename, so refusing is the
    only correct behavior at the SDK level — pretending to support it
    would mean an unsafe walk-and-rename loop that can leave half-moved
    state on partial failure. We assert the refusal so a future
    mount-s3 version that introduces a walk-rename mode shows up as a
    test failure (good — we'd then want to decide whether to mirror it
    server-side). mount-s3-only — rclone does walk-and-rename, which is
    a different (legitimate) policy choice.
    """
    bucket_fs.write("old-dir/a.txt", b"AAA\n")
    bucket_fs.write("old-dir/b.txt", b"BBB\n")
    src = mount.path / "old-dir"
    dst = mount.path / "new-dir"

    deadline = time.monotonic() + _FS_VISIBLE_TIMEOUT_S
    while time.monotonic() < deadline and not src.exists():
        time.sleep(_FS_POLL_S)
    assert src.exists(), mount.log_tail()

    with pytest.raises(OSError) as exc:
        os.rename(src, dst)
    # mount-s3 1.21 returns EPERM (1); accept the related "not
    # permitted/supported" family so a minor mount-s3 version bump that
    # picks a different (still-refusing) errno doesn't flake the test.
    assert exc.value.errno in (
        1,    # EPERM:   operation not permitted (mount-s3 1.21's choice)
        22,   # EINVAL:  invalid argument
        38,   # ENOSYS:  rename op not implemented
        95,   # ENOTSUP: operation not supported
    ), exc.value

    # Defense in depth: the backend must be untouched.
    assert bucket_fs.exists("old-dir/a.txt"), mount.log_tail()
    assert bucket_fs.exists("old-dir/b.txt"), mount.log_tail()
    assert not bucket_fs.exists("new-dir/a.txt"), mount.log_tail()


# ----------------------------------------------------------------- read-only


# ----------------------------------------------------------------- no-overwrite rename


@pytest.fixture
def mount_no_overwrite(tmp_path, endpoint, bucket):
    """Read-write mount **without** `--allow-overwrite`. This is the
    mountpoint-s3 default and the shape that surfaces the
    `If-None-Match: *` precondition on every rename. Used by the
    rename-collision test. mount-s3-only — rclone has no equivalent
    of `--allow-overwrite`, the header behavior is mount-s3-specific."""
    if not mountpoint_is_available():
        pytest.skip("mount-s3 not installed or /dev/fuse not available")
    session = MountpointSession(
        endpoint_url=endpoint.base_url,
        region=endpoint.region,
        access_key=endpoint.access_key,
        secret_key=endpoint.secret_key,
        bucket=bucket,
        mount_root=tmp_path,
        mode="rw",
        allow_overwrite=False,
    )
    session.start()
    try:
        yield session
    finally:
        session.stop()


def test_rename_into_existing_destination_blocked_without_overwrite(
    mount_no_overwrite, bucket_fs
):
    """End-to-end coverage of the `If-None-Match: *` path: a default-mode
    mountpoint-s3 mount issues that header on every rename. With the
    destination already populated, the gateway must return 412
    PreconditionFailed and mountpoint must surface it as a FUSE error —
    not silently overwrite. The data-loss footgun this defends against:
    `mv new old` clobbers `old` without the user realizing."""
    mount = mount_no_overwrite
    bucket_fs.write("src.bin", b"new bytes\n")
    bucket_fs.write("dst.bin", b"original bytes\n")

    src = mount.path / "src.bin"
    dst = mount.path / "dst.bin"

    deadline = time.monotonic() + _FS_VISIBLE_TIMEOUT_S
    while time.monotonic() < deadline and not (src.exists() and dst.exists()):
        time.sleep(_FS_POLL_S)
    assert src.exists() and dst.exists(), mount.log_tail()

    with pytest.raises(OSError) as exc:
        os.rename(src, dst)
    # mountpoint-s3 1.21 surfaces `RenameDestinationExists` as EEXIST.
    # Accept a small family in case a minor version picks a different
    # POSIX errno for the same logical condition.
    assert exc.value.errno in (
        17,  # EEXIST   — "File exists" (mountpoint-s3 1.21's choice)
        1,   # EPERM    — "Operation not permitted"
        13,  # EACCES   — "Permission denied"
    ), exc.value

    # Backend untouched: dst still has its original bytes, src still has new.
    assert bucket_fs.read("dst.bin") == b"original bytes\n"
    assert bucket_fs.read("src.bin") == b"new bytes\n"


# ----------------------------------------------------------------- incremental upload


@pytest.fixture
def mount_incremental(tmp_path, endpoint, bucket):
    """Read-write mount with `--incremental-upload`. Writes through this
    mount turn into a chain of `PUT … x-amz-write-offset-bytes` requests
    (S3 Express directory-bucket append) instead of a buffered single PUT
    or multipart upload. Used to exercise the gateway's
    `handle_put_object_append` end-to-end. mount-s3-only — rclone has no
    equivalent of the `--incremental-upload` mode."""
    if not mountpoint_is_available():
        pytest.skip("mount-s3 not installed or /dev/fuse not available")
    session = MountpointSession(
        endpoint_url=endpoint.base_url,
        region=endpoint.region,
        access_key=endpoint.access_key,
        secret_key=endpoint.secret_key,
        bucket=bucket,
        mount_root=tmp_path,
        mode="rw",
        incremental_upload=True,
    )
    session.start()
    try:
        yield session
    finally:
        session.stop()


def test_mount_incremental_large_write_chains_appends(mount_incremental, bucket_fs):
    """Write > 8 MiB through the mount in one go. Mountpoint-s3's default
    write-part-size is 8 MiB, so a single ~17 MiB write fans out into
    three chained appends (offset 0, 8 MiB, 16 MiB). The test fails if
    any chunk lands at the wrong offset, or if the inode-based ETag
    chain breaks between chunks. Readback compares the full bytes —
    a mid-chunk corruption is visible in the assertion.

    Deterministic pattern (xor of two prime-period sequences) so a
    failure report points at a specific offset rather than "binaries
    differ"."""
    mount = mount_incremental

    # 17 MiB. Big enough to span 3 default 8 MiB chunks; small enough to
    # write in well under a second on a loopback mount.
    size = 17 * 1024 * 1024
    payload = bytearray(size)
    for i in range(size):
        payload[i] = ((i * 13) ^ (i * 7 >> 8)) & 0xFF
    payload = bytes(payload)

    target = mount.path / "big.bin"
    target.write_bytes(payload)

    assert _wait_for_backend_file(bucket_fs, "big.bin"), mount.log_tail()
    got = bucket_fs.read("big.bin")
    assert len(got) == size, (len(got), size, mount.log_tail())
    if got != payload:
        # Locate the first byte that differs so the failure points at a
        # concrete offset (and lets us infer which chunk was corrupted).
        for i in range(size):
            if got[i] != payload[i]:
                raise AssertionError(
                    f"byte {i} differs: backend=0x{got[i]:02x} expected=0x{payload[i]:02x}\n"
                    f"--- mount-s3 log ---\n{mount.log_tail()}"
                )


# ----------------------------------------------------------------- read-only


def test_readonly_mount_rejects_writes(mount_ro):
    """Writes through a `--read-only` mount must fail at the FUSE layer
    (EROFS), before any request reaches the proxy. Enforced by mount-s3,
    not by us — the test exists to catch a regression where a future
    config change accidentally drops `--read-only`."""
    with pytest.raises(OSError) as exc:
        (mount_ro.path / "should-fail.txt").write_bytes(b"x")
    # EROFS (30) or EACCES (13) depending on kernel/mountpoint version.
    assert exc.value.errno in (13, 30), exc.value
