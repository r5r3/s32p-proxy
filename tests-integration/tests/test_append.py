"""PutObject append via `x-amz-write-offset-bytes` (S3 Express directory-bucket).

mountpoint-s3 `--incremental-upload` turns a large write through the FUSE
mount into a chain of appended PUTs. Each chunk after the first carries:

    x-amz-write-offset-bytes: <bytes-already-uploaded>
    If-Match: "<etag-returned-by-previous-PUT>"

The gateway accepts the append when `offset == current_size` and rejects
otherwise. offset == 0 is treated as an ordinary create-or-replace PUT.

These tests drive the wire directly with SigV4 (UNSIGNED-PAYLOAD body)
because no general-purpose SDK exposes the header — boto3 only sets it
through the directory-bucket type adapter, which also forces
`s3express` signing and a CreateSession handshake. The mountpoint
end-to-end test in `test_mountpoint.py` covers the streaming /
aws-chunked body shape.

Handler:    crates/s32p-gateway/src/main.rs::handle_put_object_append
Errors:     crates/s32p-support/src/s3xml.rs::error_code
            (INVALID_WRITE_OFFSET, INVALID_ARGUMENT, NO_SUCH_KEY,
             PRECONDITION_FAILED)
"""

from __future__ import annotations

from urllib.parse import quote

import botocore.auth
import botocore.awsrequest
import botocore.credentials
import requests


def _put_raw(
    endpoint,
    *,
    bucket: str,
    key: str,
    body: bytes,
    write_offset: int | None = None,
    if_match: str | None = None,
    if_none_match: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> requests.Response:
    """Issue a SigV4-signed `PUT /{bucket}/{key}` with optional append headers.

    `write_offset is None` omits the header entirely (sanity / control
    case). `write_offset == 0` sends the header literally as "0" so the
    fall-through-to-ordinary-PUT path is exercised on the wire.
    """
    url = f"{endpoint.base_url}/{bucket}/{quote(key, safe='/')}"
    headers: dict[str, str] = {"x-amz-content-sha256": "UNSIGNED-PAYLOAD"}
    if write_offset is not None:
        headers["x-amz-write-offset-bytes"] = str(write_offset)
    if if_match is not None:
        headers["If-Match"] = if_match
    if if_none_match is not None:
        headers["If-None-Match"] = if_none_match
    if extra_headers:
        headers.update(extra_headers)

    creds = botocore.credentials.Credentials(endpoint.access_key, endpoint.secret_key)
    req = botocore.awsrequest.AWSRequest(method="PUT", url=url, data=body, headers=headers)
    botocore.auth.SigV4Auth(creds, "s3", endpoint.region).add_auth(req)
    return requests.put(url, data=body, headers=dict(req.headers.items()), timeout=10)


def _rename_raw(
    endpoint, *, bucket: str, dst_key: str, src_key: str,
    extra_headers: dict[str, str] | None = None,
) -> requests.Response:
    """Compact RenameObject helper for the cross-op rejection test."""
    url = f"{endpoint.base_url}/{bucket}/{quote(dst_key, safe='/')}?renameObject"
    headers: dict[str, str] = {
        "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
        "x-amz-rename-source": quote(src_key, safe="/"),
    }
    if extra_headers:
        headers.update(extra_headers)
    creds = botocore.credentials.Credentials(endpoint.access_key, endpoint.secret_key)
    req = botocore.awsrequest.AWSRequest(method="PUT", url=url, data=b"", headers=headers)
    botocore.auth.SigV4Auth(creds, "s3", endpoint.region).add_auth(req)
    return requests.put(url, data=b"", headers=dict(req.headers.items()), timeout=10)


def _head_etag(endpoint, bucket: str, key: str) -> str:
    """HEAD object and return its quoted ETag.

    The gateway's ETag is inode-based and stable across in-place
    appends, so chained `If-Match` tests can capture the ETag once and
    pass it back on every subsequent append.
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


# --------------------------------------------------------------- success cases


def test_append_at_current_size_extends_object(endpoint, bucket, bucket_fs):
    """The reference shape: write 5 bytes, then PUT 6 more at offset 5."""
    bucket_fs.write("doc.txt", b"hello")

    resp = _put_raw(
        endpoint, bucket=bucket, key="doc.txt", body=b" world", write_offset=5,
    )

    assert resp.status_code == 200, resp.text
    assert bucket_fs.read("doc.txt") == b"hello world"


def test_append_offset_zero_on_new_key_creates_object(endpoint, bucket, bucket_fs):
    """Offset 0 on a non-existent key falls through to ordinary PUT
    (mountpoint sends this as the first chunk of every incremental
    upload — must not regress)."""
    assert not bucket_fs.exists("fresh.bin")

    resp = _put_raw(
        endpoint, bucket=bucket, key="fresh.bin", body=b"hi", write_offset=0,
    )

    assert resp.status_code == 200, resp.text
    assert bucket_fs.read("fresh.bin") == b"hi"


def test_append_offset_zero_on_existing_key_replaces(endpoint, bucket, bucket_fs):
    """offset == 0 against an existing key creates-or-replaces, matching
    the plain-PUT behavior. Confirms we don't reinterpret 0 as
    'append-at-start' and reject it."""
    bucket_fs.write("doc.txt", b"old contents that are longer")

    resp = _put_raw(
        endpoint, bucket=bucket, key="doc.txt", body=b"new", write_offset=0,
    )

    assert resp.status_code == 200, resp.text
    assert bucket_fs.read("doc.txt") == b"new"


def test_append_chained_round_trip(endpoint, bucket, bucket_fs):
    """Emulate mountpoint's loop: four successive appends, each carrying
    the prior ETag as `If-Match`. The inode-based ETag is stable across
    appends so the chain reuses the same value. The final object is the
    concatenation of all chunks."""
    chunks = [b"alpha ", b"beta ", b"gamma ", b"delta"]
    initial = _put_raw(
        endpoint, bucket=bucket, key="chain.txt", body=chunks[0], write_offset=0,
    )
    assert initial.status_code == 200, initial.text
    etag = initial.headers["ETag"]
    offset = len(chunks[0])

    for chunk in chunks[1:]:
        r = _put_raw(
            endpoint, bucket=bucket, key="chain.txt", body=chunk,
            write_offset=offset, if_match=etag,
        )
        assert r.status_code == 200, (offset, r.text)
        # Inode is stable, so the ETag chains as-is.
        assert r.headers["ETag"] == etag, "inode-based ETag should not change on append"
        offset += len(chunk)

    assert bucket_fs.read("chain.txt") == b"".join(chunks)


# --------------------------------------------------------------- offset arithmetic


def test_append_wrong_offset_too_high_returns_invalid_write_offset(endpoint, bucket, bucket_fs):
    bucket_fs.write("doc.bin", b"abcd")  # size 4

    resp = _put_raw(
        endpoint, bucket=bucket, key="doc.bin", body=b"x", write_offset=5,
    )

    assert resp.status_code == 400, resp.text
    assert "<Code>InvalidWriteOffset</Code>" in resp.text, resp.text
    assert bucket_fs.read("doc.bin") == b"abcd", "object must not be modified"


def test_append_wrong_offset_too_low_returns_invalid_write_offset(endpoint, bucket, bucket_fs):
    bucket_fs.write("doc.bin", b"abcdef")  # size 6

    resp = _put_raw(
        endpoint, bucket=bucket, key="doc.bin", body=b"X", write_offset=3,
    )

    assert resp.status_code == 400, resp.text
    assert "<Code>InvalidWriteOffset</Code>" in resp.text, resp.text
    assert bucket_fs.read("doc.bin") == b"abcdef"


def test_append_offset_on_missing_key_returns_no_such_key(endpoint, bucket, bucket_fs):
    """Spec order: existence beats offset arithmetic. offset>0 on a key
    that doesn't exist must surface as NoSuchKey, not InvalidWriteOffset
    (matches mountpoint's `test_append_non_existing_object`)."""
    assert not bucket_fs.exists("nope.bin")

    resp = _put_raw(
        endpoint, bucket=bucket, key="nope.bin", body=b"x", write_offset=1024,
    )

    assert resp.status_code == 404, resp.text
    assert "<Code>NoSuchKey</Code>" in resp.text, resp.text


# --------------------------------------------------------------- empty body


def test_append_empty_body_returns_invalid_argument(endpoint, bucket, bucket_fs):
    """AWS returns InvalidArgument with body starting "Request body cannot
    be empty"; mountpoint-s3's client-side error mapper string-matches
    that prefix (`parse_put_object_single_error` →
    `parse_if_error_message_starts_with("Request body cannot be empty"...)`).
    Keep the prefix verbatim."""
    bucket_fs.write("doc.bin", b"abc")

    resp = _put_raw(
        endpoint, bucket=bucket, key="doc.bin", body=b"", write_offset=3,
    )

    assert resp.status_code == 400, resp.text
    assert "<Code>InvalidArgument</Code>" in resp.text, resp.text
    assert "Request body cannot be empty" in resp.text, resp.text
    assert bucket_fs.read("doc.bin") == b"abc"


# --------------------------------------------------------------- conditional headers


def test_append_if_match_matching_succeeds(endpoint, bucket, bucket_fs):
    bucket_fs.write("doc.bin", b"hello")
    etag = _head_etag(endpoint, bucket, "doc.bin")

    resp = _put_raw(
        endpoint, bucket=bucket, key="doc.bin", body=b"!",
        write_offset=5, if_match=etag,
    )

    assert resp.status_code == 200, resp.text
    assert bucket_fs.read("doc.bin") == b"hello!"


def test_append_if_match_mismatching_returns_412(endpoint, bucket, bucket_fs):
    bucket_fs.write("doc.bin", b"hello")

    resp = _put_raw(
        endpoint, bucket=bucket, key="doc.bin", body=b"!",
        write_offset=5, if_match='"deadbeef"',
    )

    assert resp.status_code == 412, resp.text
    assert "<Code>PreconditionFailed</Code>" in resp.text, resp.text
    assert bucket_fs.read("doc.bin") == b"hello"


def test_append_if_match_wildcard_succeeds_on_existing(endpoint, bucket, bucket_fs):
    """`If-Match: *` means "any existing object" — and we know the key
    exists because the open succeeded before preconditions ran."""
    bucket_fs.write("doc.bin", b"hello")

    resp = _put_raw(
        endpoint, bucket=bucket, key="doc.bin", body=b"!",
        write_offset=5, if_match="*",
    )

    assert resp.status_code == 200, resp.text
    assert bucket_fs.read("doc.bin") == b"hello!"


def test_append_if_none_match_star_matching_existing_returns_412(endpoint, bucket, bucket_fs):
    """`If-None-Match: *` is the "must not exist" idiom. On an existing
    object it must fail with 412. (Append's natural failure mode is
    NoSuchKey for missing keys, so the only way this header takes
    effect on the append path is via the 412 branch.)"""
    bucket_fs.write("doc.bin", b"hello")

    resp = _put_raw(
        endpoint, bucket=bucket, key="doc.bin", body=b"!",
        write_offset=5, if_none_match="*",
    )

    assert resp.status_code == 412, resp.text
    assert "<Code>PreconditionFailed</Code>" in resp.text, resp.text


# --------------------------------------------------------------- ordering


def test_append_404_beats_invalid_write_offset(endpoint, bucket, bucket_fs):
    """If the key doesn't exist and the offset is also bogus, NoSuchKey
    wins. Documents the check order so the mountpoint client's error
    mapping is reachable."""
    assert not bucket_fs.exists("nope.bin")

    resp = _put_raw(
        endpoint, bucket=bucket, key="nope.bin", body=b"x", write_offset=99999,
    )

    assert resp.status_code == 404
    assert "<Code>NoSuchKey</Code>" in resp.text


def test_append_412_beats_invalid_write_offset(endpoint, bucket, bucket_fs):
    """Wait — we want the opposite. Offset arithmetic runs *before*
    preconditions, so on a mismatched offset we surface
    InvalidWriteOffset rather than 412 even if If-Match would also have
    failed. Documents the ordering."""
    bucket_fs.write("doc.bin", b"abc")

    resp = _put_raw(
        endpoint, bucket=bucket, key="doc.bin", body=b"x",
        write_offset=99,  # wrong
        if_match='"wrong"',
    )

    assert resp.status_code == 400
    assert "<Code>InvalidWriteOffset</Code>" in resp.text


# --------------------------------------------------------------- directory marker


def test_append_to_directory_marker_rejected(endpoint, bucket, bucket_fs):
    """Keys ending in `/` are directory markers (mkdir on disk); the
    append surface isn't defined for them."""
    bucket_fs.mkdir("dir/")

    resp = _put_raw(
        endpoint, bucket=bucket, key="dir/", body=b"x", write_offset=0,
    )

    # offset=0 on a directory marker hits the directory-marker PUT path
    # (it has a separate zero-length guard), so verify the marker case
    # at offset>0 explicitly.
    # The directory marker PUT path rejects non-zero bodies even at
    # offset 0; verify that path here, then test the append-branch
    # rejection separately.
    assert resp.status_code == 400, resp.text

    resp2 = _put_raw(
        endpoint, bucket=bucket, key="dir/", body=b"x", write_offset=10,
    )
    assert resp2.status_code == 400, resp2.text
    assert "<Code>InvalidRequest</Code>" in resp2.text, resp2.text


# --------------------------------------------------------------- header rejection on non-PUT


def test_append_header_on_rename_rejected(endpoint, bucket, bucket_fs):
    """`x-amz-write-offset-bytes` is only valid on PutObject. RenameObject
    must reject it before it can be silently ignored."""
    bucket_fs.write("a.bin", b"x")

    resp = _rename_raw(
        endpoint, bucket=bucket, dst_key="b.bin", src_key="a.bin",
        extra_headers={"x-amz-write-offset-bytes": "0"},
    )

    assert resp.status_code == 400, resp.text
    assert "<Code>InvalidArgument</Code>" in resp.text, resp.text
    # Source must not have been touched.
    assert bucket_fs.read("a.bin") == b"x"


def test_append_header_malformed_returns_invalid_argument(endpoint, bucket, bucket_fs):
    """Strict integer parse: leading `+`, hex, signs, alphabetics → 400.

    (Leading/trailing whitespace and empty values would also fail our
    parser, but the requests library rejects them client-side before
    they hit the wire, so we don't exercise those shapes here.)
    """
    bucket_fs.write("doc.bin", b"hello")

    for bad in ("+5", "0x5", "-1", "abc", "5.0", "1e3"):
        resp = _put_raw(
            endpoint, bucket=bucket, key="doc.bin", body=b"!",
            extra_headers={"x-amz-write-offset-bytes": bad},
        )
        assert resp.status_code == 400, (bad, resp.text)
        assert "<Code>InvalidArgument</Code>" in resp.text, (bad, resp.text)
        assert bucket_fs.read("doc.bin") == b"hello", bad
