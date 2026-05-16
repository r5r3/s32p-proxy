"""RenameObject (S3 Express directory-bucket extension).

Tested via raw SigV4 because no general-purpose S3 SDK exposes rename:
boto3's `S3.Client.rename_object()` is gated to directory-bucket name
patterns and routes through `s3express` service signing + a prior
`CreateSession` call. Driving the wire directly is cheaper than emulating
that data plane for one verb.

Wire format: PUT /{bucket}/{dst_key}?renameObject with
`x-amz-rename-source: /{bucket}/{src_key}` (or `/{src_key}` for the
same-bucket shorthand). Success: 200 with empty body.

Handler:    crates/s32p-gateway/src/main.rs::handle_rename_object
Classifier: crates/s32p-support/src/classifier.rs → WriteOp::RenameObject
            (class `write`; the proxy enforces ACL writability before
            spawning the worker).
"""

from __future__ import annotations

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
    src_bucket: str | None = None,
) -> requests.Response:
    """Issue a SigV4-signed `PUT /{bucket}/{dst_key}?renameObject`.

    The helper always emits the explicit `/bucket/key` form of
    `x-amz-rename-source`. The gateway's parser also accepts a `/key`
    shorthand, but only when the key contains no `/` (anything past the
    first separator is parsed as the bucket) — not worth a public knob.

    - `src_key=None` omits the `x-amz-rename-source` header (negative test).
    - `src_bucket=None` defaults to `bucket`; pass a different name for
      the cross-bucket rejection test.
    """
    url = f"{endpoint.base_url}/{bucket}/{quote(dst_key, safe='/')}?renameObject"
    headers: dict[str, str] = {"x-amz-content-sha256": "UNSIGNED-PAYLOAD"}
    if src_key is not None:
        sb = src_bucket if src_bucket is not None else bucket
        headers["x-amz-rename-source"] = "/" + sb + "/" + quote(src_key, safe="/")

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


def test_rename_cross_bucket_returns_400(endpoint, bucket, bucket_fs):
    """S3 RenameObject is same-bucket only. The handler rejects with
    InvalidRequest as soon as the parsed source bucket differs from the
    destination — before looking at the filesystem."""
    bucket_fs.write("src.bin", b"x")

    resp = _rename_raw(
        endpoint, bucket=bucket,
        dst_key="dst.bin", src_key="src.bin",
        src_bucket="some-other-bucket",
    )

    assert resp.status_code == 400, resp.text
    assert "<Code>InvalidRequest</Code>" in resp.text, resp.text
    assert bucket_fs.exists("src.bin"), "source must not be touched"


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
