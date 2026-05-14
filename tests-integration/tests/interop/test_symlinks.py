"""Symlink behavior at the POSIX <-> S3 boundary.

Two documented contracts are pinned here:

1. Listing follows symlinks first, falls back to lstat on failure, never
   drops the entry (memory: feedback_symlink_listing_metadata).
2. HEAD on a broken symlink succeeds via the lstat fallback so a
   LIST-then-HEAD sequence stays consistent; GET on the same key returns
   404 because there is no readable content (gateway main.rs:1152-1159).
"""

from __future__ import annotations

import pytest

from s32p_test.clients.base import S3Error


def test_symlink_to_file_resolves_in_listing_and_get(client, bucket, bucket_fs):
    """A symlink pointing at a real file is listed (with the target's size)
    and GET returns the target's bytes — the symlink is transparent."""
    target_body = b"the real bytes\n"
    bucket_fs.write("target.txt", target_body)
    bucket_fs.symlink("target.txt", "link.txt")  # relative, same dir

    listing = client.list_objects(bucket)
    by_key = {o.key: o for o in listing.objects}
    assert "target.txt" in by_key
    assert "link.txt" in by_key
    # Listing follows the symlink, so the size matches the target's content.
    assert by_key["link.txt"].size == len(target_body)

    got = client.get_object(bucket, "link.txt")
    assert got.body == target_body


def test_broken_symlink_listed_head_succeeds_get_404s(client, bucket, bucket_fs):
    """Broken symlink: listing must still surface the entry (lstat
    fallback), HEAD must return the lstat info (so LIST→HEAD is
    consistent), and GET must return 404 (no readable content)."""
    bucket_fs.symlink("/definitely/does/not/exist", "broken.txt")

    listing = client.list_objects(bucket)
    listed = {o.key for o in listing.objects}
    assert "broken.txt" in listed, "broken symlink dropped from listing"

    # HEAD must succeed because LIST advertised the key.
    head = client.head_object(bucket, "broken.txt")
    # Symlink size is the length of the target path string (POSIX semantics).
    assert head.content_length == len("/definitely/does/not/exist")

    # GET has no honest answer — must 404.
    with pytest.raises(S3Error) as exc:
        client.get_object(bucket, "broken.txt")
    assert exc.value.status == 404
