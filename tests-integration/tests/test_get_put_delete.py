"""Sanity round-trip: PUT → HEAD → GET → DELETE → HEAD (404).

This is the smallest test that proves a client adapter can drive every basic
verb. It runs once per (client, addressing) combination via the matrix in
conftest.py, so adding a new client gives you this test for free.
"""

from __future__ import annotations

import pytest

from s32p_test.clients.base import S3Error
from s32p_test.clients.capabilities import Capability


def test_put_get_head_delete_roundtrip(client, bucket):
    key = "smoke/hello.txt"
    body = b"hello, s3\n"

    put = client.put_object(bucket, key, body, content_type="text/plain")
    assert put.etag, "PUT must return an ETag"

    head = client.head_object(bucket, key)
    assert head.content_length == len(body)
    assert head.etag == put.etag
    assert head.body == b""

    got = client.get_object(bucket, key)
    assert got.body == body
    assert got.etag == put.etag
    assert got.content_length == len(body)

    client.delete_object(bucket, key)

    with pytest.raises(S3Error) as exc:
        client.head_object(bucket, key)
    assert exc.value.status == 404, f"expected 404 after delete, got {exc.value!r}"


@pytest.mark.requires_capability(Capability.METADATA)
def test_user_metadata_roundtrip(client, bucket):
    """x-amz-meta-* round-trip. Stored as a single `user.s32p.meta` xattr
    on the object file; absent xattr means no metadata, which is still a
    valid S3 object."""
    key = "smoke/with-meta.bin"
    body = b"\x00" * 16
    meta = {"author": "alice", "purpose": "interop-test"}

    client.put_object(bucket, key, body, metadata=meta)
    head = client.head_object(bucket, key)

    # boto3 lowercases user-metadata keys; assert case-insensitively.
    got_meta = {k.lower(): v for k, v in head.metadata.items()}
    for k, v in meta.items():
        assert got_meta.get(k.lower()) == v, f"missing/wrong meta {k!r}: {head.metadata!r}"

    client.delete_object(bucket, key)


def test_directory_is_not_an_object(client, bucket):
    """A directory on disk is reachable only as the `dir/` marker (0 bytes),
    never as the bare name `dir`. If HEAD `dir` answered 200, file-provider
    clients would see a file and a folder with
    the same name and show one of them as "dir 2"."""
    client.put_object(bucket, "dirs/sub/file.txt", b"payload")

    for key in ("dirs/sub", "dirs/sub/file.txt/", "dirs/sub/file.txt/x"):
        with pytest.raises(S3Error) as exc:
            client.head_object(bucket, key)
        assert exc.value.status == 404, f"HEAD {key!r}: {exc.value!r}"
        with pytest.raises(S3Error) as exc:
            client.get_object(bucket, key)
        assert exc.value.status == 404, f"GET {key!r}: {exc.value!r}"

    head = client.head_object(bucket, "dirs/sub/")
    assert head.content_length == 0
    got = client.get_object(bucket, "dirs/sub/")
    assert got.body == b""
    assert got.etag == head.etag

    client.delete_object(bucket, "dirs/sub/file.txt")
