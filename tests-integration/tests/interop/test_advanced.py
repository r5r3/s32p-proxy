"""More interop scenarios: reserved paths, listing purity, permissions,
and that S3 copies are real independent files on the backend.
"""

from __future__ import annotations

import pytest

from s32p_test.clients.base import S3Error
from s32p_test.clients.capabilities import Capability


def test_reserved_mpu_dir_hidden_from_s3(client, bucket, bucket_fs):
    """A POSIX-created file whose first path segment is .s32p-mpu must be
    invisible to S3 (hidden from LIST, 404 on HEAD/GET). The same
    component name deeper in the tree is NOT hidden."""
    bucket_fs.write(".s32p-mpu/secret.txt", b"top-level mpu - must hide")
    bucket_fs.write("foo/.s32p-mpu/visible.txt", b"deeper mpu - must show")

    listing = client.list_objects(bucket)
    listed = {o.key for o in listing.objects}
    assert not any(k.startswith(".s32p-mpu") for k in listed), (
        f".s32p-mpu/* leaked into listing: {[k for k in listed if k.startswith('.s32p-mpu')]}"
    )
    assert "foo/.s32p-mpu/visible.txt" in listed

    with pytest.raises(S3Error) as exc:
        client.head_object(bucket, ".s32p-mpu/secret.txt")
    assert exc.value.status == 404


def test_empty_posix_dir_survives_s3_listing(client, bucket, bucket_fs):
    """LIST must not garbage-collect empty directories from the backend.
    POSIX users can use the filesystem directly and reads must stay pure
    (memory: feedback_list_time_gc)."""
    bucket_fs.mkdir("empty-dir")

    listing = client.list_objects(bucket, delimiter="/")
    assert "empty-dir/" in set(listing.common_prefixes), (
        "empty backend dir not exposed as common prefix"
    )

    # The critical assertion: LIST did NOT prune the empty dir.
    assert bucket_fs.exists("empty-dir"), "LIST garbage-collected an empty dir"


def test_chmod_blocks_s3_read(client, bucket, bucket_fs):
    """chmod 0o000 on a backend file makes the worker unable to read it,
    which the gateway must surface as AccessDenied (403). This proves the
    POSIX permission boundary is real, not bypassed."""
    key = "no-read.txt"
    client.put_object(bucket, key, b"will become unreadable")
    bucket_fs.chmod(key, 0o000)

    try:
        with pytest.raises(S3Error) as exc:
            client.get_object(bucket, key)
        assert exc.value.status == 403, f"expected 403, got {exc.value!r}"
    finally:
        # Restore mode so the bucket-fixture wipe of the next test doesn't
        # have to wrestle with this — unlink only needs write on the parent
        # dir, but being kind to debug sessions costs nothing.
        bucket_fs.chmod(key, 0o644)


@pytest.mark.requires_capability(Capability.COPY_OBJECT)
def test_s3_copy_creates_independent_posix_file(client, bucket, bucket_fs):
    """CopyObject must produce a real, independent file on the backend —
    not a hardlink and not a symlink. Mutating the source via POSIX after
    the copy must not change the destination."""
    src_key = "copy-src.txt"
    dst_key = "copy-dst.txt"
    original = b"original content\n"
    mutated = b"source was changed after copy\n"

    client.put_object(bucket, src_key, original)
    client.copy_object(bucket, src_key, bucket, dst_key)

    # Now mutate the source on disk.
    bucket_fs.write(src_key, mutated)

    # Destination must still hold the original content.
    got = client.get_object(bucket, dst_key)
    assert got.body == original, "copy was not independent (hardlink/symlink?)"

    # And the on-disk dst file must not be a symlink.
    dst_stat = bucket_fs.stat(dst_key, follow=False)
    assert not dst_stat.st_mode & 0o170000 == 0o120000, "dst is a symlink, copy semantics broken"
    src_stat = bucket_fs.stat(src_key)
    assert dst_stat.st_ino != src_stat.st_ino, "dst shares inode with src (hardlink)"
