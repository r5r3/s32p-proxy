"""RenameObject (S3 Express directory-bucket extension).

Tested via raw SigV4 because no general-purpose S3 SDK exposes rename:
boto3's `S3.Client.rename_object()` is gated to directory-bucket name
patterns and routes through `s3express` service signing + a prior
`CreateSession` call. Driving the wire directly is cheaper than emulating
that data plane for one verb.

Wire format: PUT /{bucket}/{dst_key}?renameObject with
`x-amz-rename-source: {src_key}` (URL-encoded, optional leading `/`).
The bucket is always the destination bucket — RenameObject is
same-bucket only by spec. Success: 200 with empty body.

Handler:    crates/s32p-gateway/src/main.rs::handle_rename_object
Classifier: crates/s32p-support/src/classifier.rs → WriteOp::RenameObject
            (class `write`; the proxy enforces ACL writability before
            spawning the worker).
"""

from __future__ import annotations

import time
from urllib.parse import quote

import botocore.auth
import botocore.awsrequest
import botocore.credentials
import requests


def _rename_raw(
    endpoint,
    *,
    bucket: str,
    dst_key: str,
    src_key: str | None,
    if_match: str | None = None,
    if_none_match: str | None = None,
    if_source_match: str | None = None,
    client_token: str | None = None,
) -> requests.Response:
    """Issue a SigV4-signed `PUT /{bucket}/{dst_key}?renameObject`.

    `x-amz-rename-source` is the URL-encoded source key (same bucket
    as the destination — that's the only shape AWS S3 Express defines).

    The four conditional/idempotency knobs mirror what mountpoint-s3 and
    the AWS SDKs emit. They're all optional — pass `None` to omit the
    header. `src_key=None` omits the rename-source header (negative test).
    """
    url = f"{endpoint.base_url}/{bucket}/{quote(dst_key, safe='/')}?renameObject"
    headers: dict[str, str] = {"x-amz-content-sha256": "UNSIGNED-PAYLOAD"}
    if src_key is not None:
        headers["x-amz-rename-source"] = quote(src_key, safe="/")
    if if_match is not None:
        headers["If-Match"] = if_match
    if if_none_match is not None:
        headers["If-None-Match"] = if_none_match
    if if_source_match is not None:
        headers["x-amz-rename-source-if-match"] = if_source_match
    if client_token is not None:
        headers["x-amz-client-token"] = client_token

    creds = botocore.credentials.Credentials(
        endpoint.access_key, endpoint.secret_key
    )
    req = botocore.awsrequest.AWSRequest(
        method="PUT", url=url, data=b"", headers=headers
    )
    botocore.auth.SigV4Auth(creds, "s3", endpoint.region).add_auth(req)
    return requests.put(
        url, data=b"", headers=dict(req.headers.items()), timeout=10
    )


def _head_etag(endpoint, bucket: str, key: str) -> str:
    """HEAD object and return its quoted ETag (as the gateway emits it).

    Conditional rename tests need a real ETag to round-trip through
    `If-Match`/`If-None-Match`/`x-amz-rename-source-if-match`. The
    gateway's ETag is inode-based (`format!("\\\"{}\\\"", meta.ino())`),
    so we can't predict it offline — read it from the wire instead.
    """
    url = f"{endpoint.base_url}/{bucket}/{quote(key, safe='/')}"
    headers = {"x-amz-content-sha256": "UNSIGNED-PAYLOAD"}
    creds = botocore.credentials.Credentials(endpoint.access_key, endpoint.secret_key)
    req = botocore.awsrequest.AWSRequest(method="HEAD", url=url, data=b"", headers=headers)
    botocore.auth.SigV4Auth(creds, "s3", endpoint.region).add_auth(req)
    resp = requests.head(url, headers=dict(req.headers.items()), timeout=10)
    assert resp.status_code == 200, f"HEAD {key}: {resp.status_code} {resp.text}"
    etag = resp.headers.get("ETag")
    assert etag is not None and etag != "", f"missing ETag on HEAD {key}"
    return etag


# ----------------------------------------------------------------- success cases


def test_rename_basic_roundtrip(endpoint, bucket, bucket_fs):
    """PUT-via-fs a source, rename it, assert the file moved on disk. The
    smallest proof that the wire format reaches the handler and ends with
    rename(2)."""
    bucket_fs.write("src/hello.txt", b"hello, rename\n")

    resp = _rename_raw(
        endpoint, bucket=bucket, dst_key="dst/hello.txt", src_key="src/hello.txt",
    )

    assert resp.status_code == 200, resp.text
    assert not bucket_fs.exists("src/hello.txt"), (
        "source should be gone after rename"
    )
    assert bucket_fs.read("dst/hello.txt") == b"hello, rename\n"


def test_rename_creates_destination_parents(endpoint, bucket, bucket_fs):
    """Rename to a deeper prefix that doesn't exist yet on disk. The handler
    calls create_dir_all on the destination parent; without it, rename(2)
    would ENOENT."""
    bucket_fs.write("flat.bin", b"x")

    resp = _rename_raw(
        endpoint, bucket=bucket,
        dst_key="deeply/nested/new-parent/flat.bin",
        src_key="flat.bin",
    )

    assert resp.status_code == 200, resp.text
    assert bucket_fs.read("deeply/nested/new-parent/flat.bin") == b"x"


def test_rename_overwrites_existing_destination(endpoint, bucket, bucket_fs):
    """rename(2) replaces an existing destination atomically — the handler
    doesn't pre-check or refuse. After the call, dst holds src's contents
    and src is gone."""
    bucket_fs.write("a", b"new\n")
    bucket_fs.write("b", b"old\n")

    resp = _rename_raw(endpoint, bucket=bucket, dst_key="b", src_key="a")

    assert resp.status_code == 200, resp.text
    assert not bucket_fs.exists("a")
    assert bucket_fs.read("b") == b"new\n"


# ----------------------------------------------------------------- error cases


def test_rename_missing_source_returns_404(endpoint, bucket, bucket_fs):
    """Source doesn't exist → 404 NoSuchKey. The handler stats the source
    before attempting rename, so this short-circuits before any FS work."""
    assert not bucket_fs.exists("missing.bin")

    resp = _rename_raw(
        endpoint, bucket=bucket, dst_key="anywhere.bin", src_key="missing.bin",
    )

    assert resp.status_code == 404, resp.text
    assert "<Code>NoSuchKey</Code>" in resp.text, resp.text


def test_rename_unknown_source_returns_404(endpoint, bucket, bucket_fs):
    """RenameObject is same-bucket by spec — `x-amz-rename-source` is a
    key, not `bucket/key`. A source key that doesn't resolve to a real
    file inside the destination bucket must return `NoSuchKey` 404
    (filesystem `metadata` miss), not 400. This pins the spec-strict
    parser behavior (an earlier parser interpreted a leading
    slash-segment as a bucket name and emitted InvalidRequest)."""
    bucket_fs.write("real.bin", b"x")

    resp = _rename_raw(
        endpoint, bucket=bucket,
        dst_key="dst.bin", src_key="not-there.bin",
    )

    assert resp.status_code == 404, resp.text
    assert "<Code>NoSuchKey</Code>" in resp.text, resp.text
    assert bucket_fs.exists("real.bin"), "unrelated source must not be touched"


def test_rename_missing_header_falls_through_to_other(endpoint, bucket):
    """The classifier requires `x-amz-rename-source` to be present before
    classifying as RenameObject; without it, the request misses every
    operation match and lands in the `other` op → `handle_other`, which
    returns 501 NotImplemented. Defense in depth: the handler's parser
    error path is unreachable from real clients."""
    resp = _rename_raw(
        endpoint, bucket=bucket, dst_key="dst.bin", src_key=None,
    )

    assert resp.status_code == 501, resp.text
    assert "<Code>NotImplemented</Code>" in resp.text, resp.text
    assert "PUT" in resp.text and "renameObject" in resp.text, (
        "message should echo the method and request-target so the caller "
        f"sees which shape was rejected: {resp.text}"
    )


def test_rename_reserved_prefix_as_source_blocked(endpoint, bucket):
    """Source under the multipart reserved dir (default `.s32p-mpu`) is
    rejected with 403 AccessDenied. The check fires before the
    source-exists stat, so no disk state is needed."""
    resp = _rename_raw(
        endpoint, bucket=bucket,
        dst_key="ok.bin", src_key=".s32p-mpu/some-upload/file",
    )

    assert resp.status_code == 403, resp.text
    assert "<Code>AccessDenied</Code>" in resp.text, resp.text


def test_rename_reserved_prefix_as_destination_blocked(endpoint, bucket, bucket_fs):
    """Destination under the reserved dir is also rejected with 403. The
    source must survive the rejected request."""
    bucket_fs.write("survivor.bin", b"y")

    resp = _rename_raw(
        endpoint, bucket=bucket,
        dst_key=".s32p-mpu/sneaky/file", src_key="survivor.bin",
    )

    assert resp.status_code == 403, resp.text
    assert "<Code>AccessDenied</Code>" in resp.text, resp.text
    assert bucket_fs.read("survivor.bin") == b"y"


def test_rename_blocked_by_readonly_acl(endpoint, acl_bucket):
    """A read_only-granted bucket must reject RenameObject at the proxy
    layer (`needs_write` is true for WriteOp::RenameObject) — the worker
    is never reached, and the pre-populated source survives on disk."""
    bucket, fs = acl_bucket("readonly")
    fs.write("ro-src.bin", b"survives\n")

    resp = _rename_raw(
        endpoint, bucket=bucket,
        dst_key="ro-dst.bin", src_key="ro-src.bin",
    )

    assert resp.status_code == 403, resp.text
    assert fs.read("ro-src.bin") == b"survives\n"
    assert not fs.exists("ro-dst.bin")


# ----------------------------------------------------------------- If-None-Match


def test_rename_if_none_match_star_rejects_existing_dest_with_412(endpoint, bucket, bucket_fs):
    """mountpoint-s3 sends `If-None-Match: *` when mounted without
    `--allow-overwrite`. The gateway must atomically refuse the rename
    if the destination already exists, returning 412 PreconditionFailed
    and leaving both files untouched. Atomicity comes from
    `renameat2(RENAME_NOREPLACE)` in `fs_helpers::rename_noreplace` —
    no TOCTOU window between the check and the rename."""
    bucket_fs.write("src.bin", b"new contents\n")
    bucket_fs.write("dst.bin", b"old contents\n")

    resp = _rename_raw(
        endpoint, bucket=bucket,
        dst_key="dst.bin", src_key="src.bin",
        if_none_match="*",
    )

    assert resp.status_code == 412, resp.text
    assert "<Code>PreconditionFailed</Code>" in resp.text, resp.text
    # Neither file moved.
    assert bucket_fs.read("src.bin") == b"new contents\n"
    assert bucket_fs.read("dst.bin") == b"old contents\n"


def test_rename_if_none_match_star_succeeds_when_dest_absent(endpoint, bucket, bucket_fs):
    """`If-None-Match: *` against a non-existent destination is a no-op
    precondition — rename proceeds normally. This is the path mountpoint-s3
    takes for a normal `mv new-file existing-name`."""
    bucket_fs.write("src.bin", b"contents\n")
    assert not bucket_fs.exists("dst.bin")

    resp = _rename_raw(
        endpoint, bucket=bucket,
        dst_key="dst.bin", src_key="src.bin",
        if_none_match="*",
    )

    assert resp.status_code == 200, resp.text
    assert bucket_fs.read("dst.bin") == b"contents\n"
    assert not bucket_fs.exists("src.bin")


def test_rename_if_none_match_specific_etag_matches_dest_returns_412(endpoint, bucket, bucket_fs):
    """`If-None-Match: "<etag>"` means "fail if destination has this
    exact ETag." Probe the dest's real ETag via HEAD, replay it,
    expect 412."""
    bucket_fs.write("src.bin", b"new\n")
    bucket_fs.write("dst.bin", b"old\n")
    dst_etag = _head_etag(endpoint, bucket, "dst.bin")

    resp = _rename_raw(
        endpoint, bucket=bucket,
        dst_key="dst.bin", src_key="src.bin",
        if_none_match=dst_etag,
    )

    assert resp.status_code == 412, resp.text
    assert "<Code>PreconditionFailed</Code>" in resp.text, resp.text
    assert bucket_fs.read("dst.bin") == b"old\n"


def test_rename_if_none_match_specific_etag_mismatches_dest_succeeds(endpoint, bucket, bucket_fs):
    """Same header, a wrong ETag value: precondition holds (dest's ETag
    *doesn't* match), rename proceeds and overwrites."""
    bucket_fs.write("src.bin", b"new\n")
    bucket_fs.write("dst.bin", b"old\n")

    resp = _rename_raw(
        endpoint, bucket=bucket,
        dst_key="dst.bin", src_key="src.bin",
        if_none_match='"this-etag-does-not-exist-9999"',
    )

    assert resp.status_code == 200, resp.text
    assert bucket_fs.read("dst.bin") == b"new\n"


# ----------------------------------------------------------------- If-Match


def test_rename_if_match_matching_dest_succeeds(endpoint, bucket, bucket_fs):
    """`If-Match: "<etag>"` means "destination must exist with this exact
    ETag." Matching value → rename proceeds and overwrites."""
    bucket_fs.write("src.bin", b"new\n")
    bucket_fs.write("dst.bin", b"old\n")
    dst_etag = _head_etag(endpoint, bucket, "dst.bin")

    resp = _rename_raw(
        endpoint, bucket=bucket,
        dst_key="dst.bin", src_key="src.bin",
        if_match=dst_etag,
    )

    assert resp.status_code == 200, resp.text
    assert bucket_fs.read("dst.bin") == b"new\n"


def test_rename_if_match_mismatching_dest_returns_412(endpoint, bucket, bucket_fs):
    """`If-Match` value that doesn't match the destination's ETag → 412,
    both files untouched."""
    bucket_fs.write("src.bin", b"new\n")
    bucket_fs.write("dst.bin", b"old\n")

    resp = _rename_raw(
        endpoint, bucket=bucket,
        dst_key="dst.bin", src_key="src.bin",
        if_match='"wrong-etag-42"',
    )

    assert resp.status_code == 412, resp.text
    assert "<Code>PreconditionFailed</Code>" in resp.text, resp.text
    assert bucket_fs.read("src.bin") == b"new\n"
    assert bucket_fs.read("dst.bin") == b"old\n"


def test_rename_if_match_absent_dest_returns_412(endpoint, bucket, bucket_fs):
    """`If-Match` against an absent destination must fail — "destination
    matches this ETag" can't be true of a non-existent resource. AWS
    semantics."""
    bucket_fs.write("src.bin", b"x\n")

    resp = _rename_raw(
        endpoint, bucket=bucket,
        dst_key="dst.bin", src_key="src.bin",
        if_match='"any-etag"',
    )

    assert resp.status_code == 412, resp.text
    assert "<Code>PreconditionFailed</Code>" in resp.text, resp.text
    assert bucket_fs.read("src.bin") == b"x\n"


# ----------------------------------------------------------------- x-amz-rename-source-if-match


def test_rename_source_if_match_matching_succeeds(endpoint, bucket, bucket_fs):
    """`x-amz-rename-source-if-match: "<etag>"` means "source must have
    this ETag." Matching value → rename proceeds."""
    bucket_fs.write("src.bin", b"contents\n")
    src_etag = _head_etag(endpoint, bucket, "src.bin")

    resp = _rename_raw(
        endpoint, bucket=bucket,
        dst_key="dst.bin", src_key="src.bin",
        if_source_match=src_etag,
    )

    assert resp.status_code == 200, resp.text
    assert bucket_fs.read("dst.bin") == b"contents\n"


def test_rename_source_if_match_mismatching_returns_412(endpoint, bucket, bucket_fs):
    """Wrong source ETag → 412. Source survives."""
    bucket_fs.write("src.bin", b"contents\n")

    resp = _rename_raw(
        endpoint, bucket=bucket,
        dst_key="dst.bin", src_key="src.bin",
        if_source_match='"wrong-source-etag"',
    )

    assert resp.status_code == 412, resp.text
    assert "<Code>PreconditionFailed</Code>" in resp.text, resp.text
    assert bucket_fs.read("src.bin") == b"contents\n"


def test_rename_etag_tolerates_unquoted(endpoint, bucket, bucket_fs):
    """Wire-spec ETags are quoted (`"123"`), but some clients omit the
    quotes. The handler accepts both shapes — same precondition either
    way. Important so a HEAD that stripped quotes can still be replayed
    into an `If-Match` and round-trip correctly."""
    bucket_fs.write("src.bin", b"x\n")
    bucket_fs.write("dst.bin", b"y\n")
    dst_etag_quoted = _head_etag(endpoint, bucket, "dst.bin")
    dst_etag_unquoted = dst_etag_quoted.strip('"')

    resp = _rename_raw(
        endpoint, bucket=bucket,
        dst_key="dst.bin", src_key="src.bin",
        if_match=dst_etag_unquoted,
    )

    assert resp.status_code == 200, resp.text
    assert bucket_fs.read("dst.bin") == b"x\n"


# ----------------------------------------------------------------- x-amz-client-token


def test_rename_client_token_replay_returns_cached_response(endpoint, bucket, bucket_fs):
    """Same `x-amz-client-token` + same request shape twice: first does
    the rename, second returns the cached 200 even though the source has
    moved (would normally NoSuchKey 404). This is the idempotency contract
    mountpoint-s3 needs for safe TCP-retry of a successful rename."""
    bucket_fs.write("src.bin", b"contents\n")
    token = "fixed-token-for-replay"

    first = _rename_raw(
        endpoint, bucket=bucket,
        dst_key="dst.bin", src_key="src.bin",
        client_token=token,
    )
    assert first.status_code == 200, first.text
    assert not bucket_fs.exists("src.bin")
    assert bucket_fs.read("dst.bin") == b"contents\n"

    # Force a fresh `x-amz-date` on the second call. SigV4 timestamps are
    # second-resolution; without this sleep, both calls in the same second
    # produce byte-identical signed requests and the SigV4 replay cache
    # rejects the second before the idempotency cache (the thing under
    # test) gets a chance to short-circuit. Real SDK retries pause
    # longer than this for unrelated reasons (TCP backoff).
    time.sleep(1.05)

    # Second call with same token, src now missing. Without idempotency
    # this would be NoSuchKey 404; with it, we get the cached 200.
    second = _rename_raw(
        endpoint, bucket=bucket,
        dst_key="dst.bin", src_key="src.bin",
        client_token=token,
    )
    assert second.status_code == 200, second.text


def test_rename_client_token_mismatched_fingerprint_returns_409(endpoint, bucket, bucket_fs):
    """Re-using a token for a different operation (different src/dst)
    must return 409 IdempotentParameterMismatch — the protocol error AWS
    surfaces for this case. The second rename does NOT execute."""
    bucket_fs.write("src1.bin", b"one\n")
    bucket_fs.write("src2.bin", b"two\n")
    token = "shared-token-different-payload"

    first = _rename_raw(
        endpoint, bucket=bucket,
        dst_key="dst1.bin", src_key="src1.bin",
        client_token=token,
    )
    assert first.status_code == 200, first.text

    second = _rename_raw(
        endpoint, bucket=bucket,
        dst_key="dst2.bin", src_key="src2.bin",
        client_token=token,
    )
    assert second.status_code == 409, second.text
    assert "<Code>IdempotentParameterMismatch</Code>" in second.text, second.text
    # Second operation must NOT have executed.
    assert bucket_fs.exists("src2.bin")
    assert not bucket_fs.exists("dst2.bin")


def test_rename_client_token_omitted_does_not_block_retry(endpoint, bucket, bucket_fs):
    """Sanity: with no `x-amz-client-token`, retry of a successful rename
    naturally fails with NoSuchKey (source is gone). This pins that the
    idempotency cache is opt-in via the header — it doesn't accidentally
    coalesce unrelated requests."""
    bucket_fs.write("src.bin", b"x\n")

    first = _rename_raw(endpoint, bucket=bucket, dst_key="dst.bin", src_key="src.bin")
    assert first.status_code == 200, first.text

    # See comment in test_rename_client_token_replay_returns_cached_response:
    # second-resolution x-amz-date means same-second calls produce identical
    # signatures and trip the SigV4 replay cache.
    time.sleep(1.05)

    second = _rename_raw(endpoint, bucket=bucket, dst_key="dst.bin", src_key="src.bin")
    assert second.status_code == 404, second.text
    assert "<Code>NoSuchKey</Code>" in second.text, second.text


def test_rename_client_token_failed_request_is_not_cached(endpoint, bucket, bucket_fs):
    """A request that fails (here: source doesn't exist → 404) must NOT be
    cached against its token — a subsequent retry where conditions have
    changed (source now exists) must execute fresh and succeed."""
    token = "token-for-failed-then-recovered"
    assert not bucket_fs.exists("late.bin")

    first = _rename_raw(
        endpoint, bucket=bucket,
        dst_key="dst.bin", src_key="late.bin",
        client_token=token,
    )
    assert first.status_code == 404, first.text

    bucket_fs.write("late.bin", b"now exists\n")

    # See comment in test_rename_client_token_replay_returns_cached_response:
    # second-resolution x-amz-date means same-second calls produce identical
    # signatures and trip the SigV4 replay cache.
    time.sleep(1.05)

    second = _rename_raw(
        endpoint, bucket=bucket,
        dst_key="dst.bin", src_key="late.bin",
        client_token=token,
    )
    # The cache abandoned the entry on the first failure, so the retry
    # re-executes and succeeds.
    assert second.status_code == 200, second.text
    assert bucket_fs.read("dst.bin") == b"now exists\n"
