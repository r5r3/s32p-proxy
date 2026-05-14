"""Conditional GET/HEAD/PUT coverage.

The gateway implements RFC 7232 preconditions in
`crates/s32p-support/src/preconditions.rs` and applies them on the
read path (`evaluate_read_preconditions`), the write path
(`evaluate_write_preconditions`), and the copy-source path
(`evaluate_copy_source_preconditions`). These tests pin the externally
observable subset:

- Read failures return either 304 NotModified (If-None-Match match,
  If-Modified-Since not modified) or 412 PreconditionFailed.
- Write failures return 412 PreconditionFailed.
- The "create only" idiom (`PUT … If-None-Match: *`) is exercised in
  both directions (creates when absent, 412 when present).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from s32p_test.clients.base import Conditions, CopyConditions, S3Error
from s32p_test.clients.capabilities import Capability


pytestmark = pytest.mark.requires_capability(Capability.CONDITIONAL_REQUESTS)


# ---------------------------------------------------------------- GET / If-Match


def test_get_if_match_matching_returns_content(client, bucket):
    """If-Match with the current ETag must succeed and return the body."""
    body = b"original content"
    put = client.put_object(bucket, "obj", body)

    got = client.get_object(bucket, "obj", conditions=Conditions(if_match=put.etag))
    assert got.body == body


def test_get_if_match_mismatching_returns_412(client, bucket):
    """If-Match with a different ETag must return 412 PreconditionFailed."""
    client.put_object(bucket, "obj", b"original")

    with pytest.raises(S3Error) as exc:
        client.get_object(
            bucket, "obj", conditions=Conditions(if_match="ffffffffffffffff")
        )
    assert exc.value.status == 412, f"expected 412, got {exc.value!r}"


# ---------------------------------------------------------------- GET / If-None-Match


def test_get_if_none_match_matching_returns_304(client, bucket):
    """If-None-Match=current_etag means "give me only if changed" — and
    nothing has changed, so the server returns 304. Some clients surface
    304 as a successful empty body; others raise. Accept either."""
    put = client.put_object(bucket, "obj", b"v1")

    try:
        got = client.get_object(
            bucket, "obj", conditions=Conditions(if_none_match=put.etag)
        )
        assert got.body == b"", (
            f"304 must have empty body when surfaced as success, got {got.body!r}"
        )
    except S3Error as e:
        assert e.status == 304, f"expected 304, got {e!r}"


def test_get_if_none_match_mismatching_returns_content(client, bucket):
    """If-None-Match with a different ETag means "give me, since you're
    different" — server returns the full body."""
    body = b"v1"
    client.put_object(bucket, "obj", body)

    got = client.get_object(
        bucket, "obj", conditions=Conditions(if_none_match="ffffffffffffffff")
    )
    assert got.body == body


# ---------------------------------------------------------------- PUT / If-Match


def test_put_if_match_matching_overwrites(client, bucket):
    """The "compare-and-swap" idiom: read ETag, PUT with If-Match=etag.
    If nobody else updated in between, we win and the new bytes land."""
    put1 = client.put_object(bucket, "obj", b"v1")
    client.put_object(bucket, "obj", b"v2", conditions=Conditions(if_match=put1.etag))

    got = client.get_object(bucket, "obj")
    assert got.body == b"v2"


def test_put_if_match_mismatching_returns_412(client, bucket):
    """If somebody else updated in between (we have a stale ETag), the
    conditional PUT must fail with 412."""
    client.put_object(bucket, "obj", b"v1")

    with pytest.raises(S3Error) as exc:
        client.put_object(
            bucket, "obj", b"v2", conditions=Conditions(if_match="ffffffffffffffff")
        )
    assert exc.value.status == 412, f"expected 412, got {exc.value!r}"


# ---------------------------------------------------------------- PUT / If-None-Match=*


def test_put_if_none_match_star_creates_when_absent(client, bucket):
    """The "create-only" idiom: PUT with If-None-Match=* succeeds if and
    only if no object exists at the key."""
    client.put_object(
        bucket, "newkey", b"new", conditions=Conditions(if_none_match="*")
    )

    got = client.get_object(bucket, "newkey")
    assert got.body == b"new"


def test_put_if_none_match_star_returns_412_when_present(client, bucket):
    """When the object already exists, conditional create must fail with 412."""
    client.put_object(bucket, "obj", b"existing")

    with pytest.raises(S3Error) as exc:
        client.put_object(
            bucket, "obj", b"new", conditions=Conditions(if_none_match="*")
        )
    assert exc.value.status == 412, f"expected 412, got {exc.value!r}"

    # Original content must be untouched.
    assert client.get_object(bucket, "obj").body == b"existing"


# ---------------------------------------------------------------- date-based


def test_get_if_unmodified_since_in_past_returns_412(client, bucket):
    """If-Unmodified-Since with a date well in the past must reject any
    object created now (it has been modified since then)."""
    client.put_object(bucket, "obj", b"hello")
    long_ago = datetime(2020, 1, 1, tzinfo=UTC)

    with pytest.raises(S3Error) as exc:
        client.get_object(
            bucket, "obj", conditions=Conditions(if_unmodified_since=long_ago)
        )
    assert exc.value.status == 412, f"expected 412, got {exc.value!r}"


# ---------------------------------------------------------------- COPY / source preconditions
#
# Backed by `evaluate_copy_source_preconditions` in preconditions.rs and
# wired in `handle_copy_object` (main.rs:2700-2716). These check the
# *source* object's ETag/timestamp; on the wire they're the
# `x-amz-copy-source-if-*` headers, distinct from PUT-style `If-*`.


@pytest.mark.requires_capability(Capability.COPY_OBJECT)
def test_copy_source_if_match_matching_succeeds(client, bucket):
    """CopySourceIfMatch=src_etag must allow the copy when the source's
    ETag matches."""
    src = client.put_object(bucket, "src", b"data")

    client.copy_object(
        bucket, "src", bucket, "dst",
        conditions=CopyConditions(source=Conditions(if_match=src.etag)),
    )
    assert client.get_object(bucket, "dst").body == b"data"


@pytest.mark.requires_capability(Capability.COPY_OBJECT)
def test_copy_source_if_match_mismatching_returns_412(client, bucket):
    """CopySourceIfMatch=wrong-etag must fail with 412 — source doesn't
    match what the caller expected."""
    client.put_object(bucket, "src", b"data")

    with pytest.raises(S3Error) as exc:
        client.copy_object(
            bucket, "src", bucket, "dst",
            conditions=CopyConditions(source=Conditions(if_match="ffffffffffffffff")),
        )
    assert exc.value.status == 412, f"expected 412, got {exc.value!r}"


@pytest.mark.requires_capability(Capability.COPY_OBJECT)
def test_copy_source_if_none_match_matching_returns_412(client, bucket):
    """CopySourceIfNoneMatch=src_etag must fail with 412 — the source
    DOES match the etag we said it shouldn't."""
    src = client.put_object(bucket, "src", b"data")

    with pytest.raises(S3Error) as exc:
        client.copy_object(
            bucket, "src", bucket, "dst",
            conditions=CopyConditions(source=Conditions(if_none_match=src.etag)),
        )
    assert exc.value.status == 412, f"expected 412, got {exc.value!r}"


@pytest.mark.requires_capability(Capability.COPY_OBJECT)
def test_copy_source_if_none_match_mismatching_succeeds(client, bucket):
    """CopySourceIfNoneMatch=other-etag must succeed when the source
    doesn't match the given etag."""
    client.put_object(bucket, "src", b"data")

    client.copy_object(
        bucket, "src", bucket, "dst",
        conditions=CopyConditions(source=Conditions(if_none_match="ffffffffffffffff")),
    )
    assert client.get_object(bucket, "dst").body == b"data"


@pytest.mark.requires_capability(Capability.COPY_OBJECT)
def test_copy_source_if_unmodified_since_in_past_returns_412(client, bucket):
    """CopySourceIfUnmodifiedSince=long-ago — source was created now, so
    it has been modified since then; copy must 412."""
    client.put_object(bucket, "src", b"data")
    long_ago = datetime(2020, 1, 1, tzinfo=UTC)

    with pytest.raises(S3Error) as exc:
        client.copy_object(
            bucket, "src", bucket, "dst",
            conditions=CopyConditions(
                source=Conditions(if_unmodified_since=long_ago)
            ),
        )
    assert exc.value.status == 412, f"expected 412, got {exc.value!r}"


# ---------------------------------------------------------------- COPY / destination preconditions
#
# Backed by `evaluate_write_preconditions` (same path as PUT), invoked at
# main.rs:2741. Common idiom: `If-None-Match: *` for "copy only if
# destination doesn't exist."


@pytest.mark.requires_capability(Capability.COPY_OBJECT)
def test_copy_destination_if_none_match_star_when_present_returns_412(client, bucket):
    """Conditional copy with destination If-None-Match=* must reject
    when the destination already exists, and leave it untouched."""
    client.put_object(bucket, "src", b"new content")
    client.put_object(bucket, "dst", b"existing")

    with pytest.raises(S3Error) as exc:
        client.copy_object(
            bucket, "src", bucket, "dst",
            conditions=CopyConditions(
                destination=Conditions(if_none_match="*")
            ),
        )
    assert exc.value.status == 412, f"expected 412, got {exc.value!r}"

    # The destination must still hold the original content.
    assert client.get_object(bucket, "dst").body == b"existing"


@pytest.mark.requires_capability(Capability.COPY_OBJECT)
def test_copy_destination_if_none_match_star_when_absent_succeeds(client, bucket):
    """Conditional copy with destination If-None-Match=* must succeed
    when no object exists at the destination key."""
    client.put_object(bucket, "src", b"copied")

    client.copy_object(
        bucket, "src", bucket, "dst",
        conditions=CopyConditions(destination=Conditions(if_none_match="*")),
    )
    assert client.get_object(bucket, "dst").body == b"copied"
