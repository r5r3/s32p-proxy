"""End-to-end tests driving the `restic` backup tool against the proxy.

restic (https://restic.net) is a real-world backup application that uses
S3 as a storage backend. Unlike the boto3/aws-cli matrix (which issues
hand-shaped S3 ops) it puts the proxy through a complete
application-level workflow: initialize an encrypted repository, back up a
directory tree, list snapshots, restore to a fresh target, and verify
integrity. That makes it complementary to the FUSE mount clients —
another "point a real tool at the proxy and see if it works" probe, this
one heavy on small-object PUT/LIST plus full-repo read-back.

What this suite proves
----------------------
- restic's minio-go S3 client initializes a repo against the proxy
  without tripping over CreateBucket (the bucket is pre-declared; HEAD
  succeeds, so MakeBucket is never attempted).
- A backup's objects land on the bucket's POSIX backend under the
  expected restic layout (`config`, `data/`, `index/`, `keys/`,
  `snapshots/`) — the interop contract this whole suite exists for.
- A restore reconstructs the source tree byte-for-byte (GET path).
- `restic check` passes — the repo the proxy stored is internally
  consistent, exercising the full index + pack read path.
- Incremental backup produces a second, distinct snapshot.

Skipped when `restic` is not on PATH.
"""

from __future__ import annotations

import pytest

from s32p_test.restic import ResticRepo
from s32p_test.restic import is_available as restic_is_available

pytestmark = [
    pytest.mark.skipif(
        not restic_is_available(),
        reason="restic is not installed (not on PATH)",
    ),
    # init + backup + restore + check is well over the 5s slow bar.
    pytest.mark.slow,
]


# ----------------------------------------------------------------- fixtures


@pytest.fixture
def source_tree(tmp_path):
    """A small directory tree to back up. Mixed file sizes and a nested
    subdir so the snapshot has real structure (not a single flat file)."""
    root = tmp_path / "src"
    (root / "sub").mkdir(parents=True)
    (root / "hello.txt").write_bytes(b"hello restic\n")
    (root / "empty.bin").write_bytes(b"")
    (root / "sub" / "nested.txt").write_text("nested content\n")
    # A few hundred KiB of varied bytes so the repo holds a non-trivial
    # pack, not just metadata.
    (root / "blob.bin").write_bytes(bytes((i * 31) & 0xFF for i in range(400 * 1024)))
    return root


@pytest.fixture
def restic_repo(tmp_path, endpoint, bucket) -> ResticRepo:
    """An initialized restic repository on the per-test bucket."""
    repo = ResticRepo(
        endpoint_url=endpoint.base_url,
        region=endpoint.region,
        access_key=endpoint.access_key,
        secret_key=endpoint.secret_key,
        bucket=bucket,
        work_root=tmp_path,
    )
    repo.init()
    return repo


# ----------------------------------------------------------------- tests


def test_init_lands_repo_layout_on_backend(restic_repo, bucket_fs):
    """`restic init` must create the encrypted-repo skeleton on the
    bucket's POSIX backend. `config` (the repo descriptor) and a key
    under `keys/` are written by init itself; the `data/`, `index/`,
    `snapshots/` dirs appear once a backup runs. We assert the two that
    init is responsible for — proof that restic's PUTs reached the worker
    and landed as real files."""
    assert bucket_fs.exists("config"), restic_repo.log_tail()
    keys = bucket_fs.listdir("keys")
    assert keys, f"expected a key object under keys/; log:\n{restic_repo.log_tail()}"


def test_backup_restore_roundtrip(restic_repo, source_tree, tmp_path):
    """The core contract: back up a tree, restore it, and get the bytes
    back. restore writes the source under its absolute path inside the
    target dir, so we walk both trees and compare."""
    snap_id = restic_repo.backup(source_tree)
    assert snap_id, f"backup produced no snapshot id; log:\n{restic_repo.log_tail()}"

    target = tmp_path / "restored"
    restic_repo.restore(snap_id, target)

    # restic restores each path at <target>/<absolute-source-path>.
    restored_root = target / source_tree.relative_to(source_tree.anchor)
    for src_file in sorted(p for p in source_tree.rglob("*") if p.is_file()):
        rel = src_file.relative_to(source_tree)
        got = (restored_root / rel).read_bytes()
        assert got == src_file.read_bytes(), (
            f"restored {rel} differs from source\n--- restic log ---\n{restic_repo.log_tail()}"
        )


def test_backup_objects_land_on_backend(restic_repo, source_tree, bucket_fs):
    """After a backup, the restic repo layout must be visible as real
    files/dirs on the bucket backend: at least one pack under `data/`,
    an `index/` entry, and a `snapshots/` entry. This is the
    POSIX<->S3 interop assertion — the proxy stored exactly what restic
    sent."""
    restic_repo.backup(source_tree)

    for top in ("data", "index", "snapshots"):
        assert bucket_fs.exists(top), (
            f"expected restic '{top}/' on backend of {restic_repo.bucket}\n"
            f"--- restic log ---\n{restic_repo.log_tail()}"
        )
    # `data/` is sharded into 256 hex subdirs; at least one must hold a pack.
    data_packs = [
        entry
        for shard in bucket_fs.listdir("data")
        for entry in bucket_fs.listdir(f"data/{shard}")
    ]
    assert data_packs, f"no pack files under data/; log:\n{restic_repo.log_tail()}"


def test_check_passes(restic_repo, source_tree):
    """`restic check --read-data` re-reads every pack and verifies the
    index against it — the strongest assertion that what the proxy stored
    is byte-faithful and internally consistent. A truncated PUT or a
    mangled GET would surface here as a check failure."""
    restic_repo.backup(source_tree)
    restic_repo.check("--read-data")


def test_incremental_backup_creates_second_snapshot(restic_repo, source_tree):
    """A second backup after modifying the tree must yield a distinct
    second snapshot. Exercises restic's "load existing index, append new
    packs" path — more LIST + conditional traffic than the first backup."""
    first = restic_repo.backup(source_tree)

    (source_tree / "added.txt").write_text("added after first backup\n")
    second = restic_repo.backup(source_tree)

    assert second and second != first, restic_repo.log_tail()
    snaps = restic_repo.snapshots()
    assert len(snaps) == 2, (
        f"expected 2 snapshots, got {len(snaps)}\n--- restic log ---\n{restic_repo.log_tail()}"
    )
