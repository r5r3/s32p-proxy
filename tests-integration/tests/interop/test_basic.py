"""Bidirectional POSIX <-> S3 interop.

This is the unique value of this suite: the same byte sequence must be
visible from both sides regardless of which side wrote it. If any of
these tests fail, the POSIX-interop design contract is broken.
"""

from __future__ import annotations

import pytest

from s32p_test.clients.base import S3Error


def test_posix_write_then_s3_get(client, bucket, bucket_fs):
    """A file created directly under bucket.data_path must be GET-able via S3
    with byte-identical content."""
    key = "interop/posix-then-s3.txt"
    body = b"created via POSIX, read via S3\n"

    bucket_fs.write(key, body)

    got = client.get_object(bucket, key)
    assert got.body == body
    assert got.content_length == len(body)


def test_s3_put_then_posix_read(client, bucket, bucket_fs):
    """An object PUT via S3 must land at the expected POSIX path with
    byte-identical content (no transformation, no sidecar wrapping)."""
    key = "interop/s3-then-posix.bin"
    body = b"\x00\xff" * 64

    client.put_object(bucket, key, body)

    assert bucket_fs.exists(key)
    assert bucket_fs.read(key) == body


def test_posix_unlink_makes_s3_404(client, bucket, bucket_fs):
    """`os.unlink` on the backend must immediately make the object 404 on S3
    (no S3-side cache, no metadata layer to re-sync)."""
    key = "interop/will-be-unlinked.txt"
    client.put_object(bucket, key, b"present")
    assert bucket_fs.exists(key)

    bucket_fs.rm(key)

    with pytest.raises(S3Error) as exc:
        client.head_object(bucket, key)
    assert exc.value.status == 404


def test_posix_rename_visible_via_s3(client, bucket, bucket_fs):
    """Renaming the backend file via os.rename must change which key answers
    on S3 (old key 404, new key 200) without going through the gateway."""
    old_key = "interop/orig.txt"
    new_key = "interop/renamed.txt"
    body = b"identity travels with the inode\n"

    client.put_object(bucket, old_key, body)
    bucket_fs.rename(old_key, new_key)

    with pytest.raises(S3Error) as exc:
        client.head_object(bucket, old_key)
    assert exc.value.status == 404

    got = client.get_object(bucket, new_key)
    assert got.body == body


def test_posix_files_appear_in_s3_listing(client, bucket, bucket_fs):
    """Multiple files written via POSIX (across subdirs) all appear in a
    flat S3 ListObjectsV2."""
    keys = [
        "a.txt",
        "sub/b.txt",
        "sub/deeper/c.txt",
        "other/d.txt",
    ]
    for k in keys:
        bucket_fs.write(k, k.encode())

    listing = client.list_objects(bucket)
    listed = {o.key for o in listing.objects}
    assert listed >= set(keys), f"missing: {set(keys) - listed}"


def test_posix_dir_appears_as_common_prefix(client, bucket, bucket_fs):
    """A backend directory must show up as a CommonPrefix when the S3
    client lists with delimiter='/'. This is the primary way directory-y
    structure is exposed to S3 clients that aren't recursing."""
    bucket_fs.mkdir("subdir")
    bucket_fs.write("subdir/inside.txt", b"x")
    bucket_fs.write("top-level.txt", b"y")

    listing = client.list_objects(bucket, delimiter="/")
    keys = {o.key for o in listing.objects}
    prefixes = set(listing.common_prefixes)

    assert "top-level.txt" in keys
    assert "subdir/" in prefixes
    assert "subdir/inside.txt" not in keys  # delimiter rolls it up
