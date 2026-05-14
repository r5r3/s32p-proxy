"""ListObjects coverage: pagination, prefix scoping, empty bucket, V1.

Most of the listing semantics that matter for interop are already pinned
by `tests/interop/test_basic.py` (delimiter behavior, POSIX-created
files surface). This file focuses on the S3-API-side details: cursor
arithmetic, prefix filtering, and the V1 vs V2 entrypoints.
"""

from __future__ import annotations

from s32p_test.clients.capabilities import Capability

import pytest


def test_list_objects_v2_pagination(client, bucket):
    """Page through 5 objects 2 at a time. Each non-final page is
    truncated and yields a continuation token; following it returns the
    rest in lexical order."""
    keys = [f"item-{i:03d}.txt" for i in range(5)]
    for k in keys:
        client.put_object(bucket, k, k.encode())

    page1 = client.list_objects(bucket, max_keys=2)
    assert len(page1.objects) == 2
    assert page1.is_truncated
    assert page1.next_continuation_token

    page2 = client.list_objects(bucket, max_keys=2, continuation_token=page1.next_continuation_token)
    assert len(page2.objects) == 2
    assert page2.is_truncated
    assert page2.next_continuation_token

    page3 = client.list_objects(bucket, max_keys=2, continuation_token=page2.next_continuation_token)
    assert len(page3.objects) == 1
    assert not page3.is_truncated

    seen = [o.key for o in (page1.objects + page2.objects + page3.objects)]
    assert seen == sorted(keys), (
        f"pagination didn't preserve lexical order: {seen}"
    )


def test_list_objects_with_prefix(client, bucket):
    """`prefix` scopes the listing; objects outside the prefix are excluded."""
    for k in ["a/x", "a/y", "b/z", "top.txt"]:
        client.put_object(bucket, k, b".")

    listing = client.list_objects(bucket, prefix="a/")
    assert {o.key for o in listing.objects} == {"a/x", "a/y"}


def test_list_empty_bucket(client, bucket):
    """Listing an empty bucket returns no objects, no prefixes, not
    truncated — *not* an error."""
    listing = client.list_objects(bucket)
    assert listing.objects == []
    assert listing.common_prefixes == []
    assert not listing.is_truncated


@pytest.mark.requires_capability(Capability.LIST_V1)
def test_list_objects_v1_returns_all_objects(client, bucket):
    """V1 (`GET /{bucket}` legacy form, no `?list-type=2`) sees the same
    objects as V2 — the gateway has separate code paths for each."""
    keys = ["a", "b", "c"]
    for k in keys:
        client.put_object(bucket, k, b".")

    listing = client.list_objects(bucket, v1=True)
    assert {o.key for o in listing.objects} == set(keys)
