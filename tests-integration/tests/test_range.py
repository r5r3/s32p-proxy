"""Range request coverage.

Single-range `Range: bytes=...` returns `206 Partial Content`; invalid
ranges return `416 InvalidRange`. Multiple ranges return `206` with a
`multipart/byteranges` body (RFC 7233), one part per range — capped at 50
ranges, and any unsatisfiable range fails the whole request with `416`.

The single-range tests go through the `S3Client` matrix, which models
closed inclusive ranges (`range_=(start, end)`) — open-ended (`bytes=10-`)
and suffix (`bytes=-100`) forms would need adapter support and are out of
scope there. The multi-range tests can't use the matrix abstraction (it
takes one range), so they drive raw SigV4 requests directly and parse the
`multipart/byteranges` response.
"""

from __future__ import annotations

import botocore.auth
import botocore.awsrequest
import botocore.credentials
import pytest
import requests

from s32p_test.clients.base import S3Error
from s32p_test.clients.capabilities import Capability


# The single-range tests below run through the S3Client matrix and need the
# RANGE_REQUESTS capability. The marker is consulted by the `client` fixture,
# so it is inert for the raw multi-range tests (which take `endpoint` /
# `bucket` / `bucket_fs`, never `client`).
pytestmark = pytest.mark.requires_capability(Capability.RANGE_REQUESTS)


def _distinct_body(n: int) -> bytes:
    """Body where byte i = i % 256 — every byte position is identifiable
    by value so off-by-ones in slicing are visible."""
    return bytes(i % 256 for i in range(n))


def test_range_returns_exact_slice(client, bucket):
    """`Range: bytes=10-19` returns exactly bytes [10..19] inclusive
    (10 bytes total). Easy to misread as exclusive — pin it."""
    body = _distinct_body(1024)
    client.put_object(bucket, "rng.bin", body)

    got = client.get_object(bucket, "rng.bin", range_=(10, 19))
    assert got.body == body[10:20]
    assert got.content_length == 10


def test_range_at_end_of_file(client, bucket):
    """A range whose end is exactly the last byte index works (no
    off-by-one against EOF)."""
    body = _distinct_body(100)
    client.put_object(bucket, "rng.bin", body)

    got = client.get_object(bucket, "rng.bin", range_=(50, 99))
    assert got.body == body[50:100]
    assert got.content_length == 50


def test_invalid_range_returns_416(client, bucket):
    """A range that starts past EOF must produce 416 InvalidRange. The
    object is small (5 bytes); the request asks for bytes 100-200."""
    client.put_object(bucket, "rng.bin", b"short")

    with pytest.raises(S3Error) as exc:
        client.get_object(bucket, "rng.bin", range_=(100, 200))
    assert exc.value.status == 416, f"expected 416, got {exc.value!r}"


# ----------------------------------------------------------------- multi-range (raw)
#
# The S3Client matrix models a single range, so multi-range coverage drives
# the wire directly: write the object via the POSIX backend (bucket_fs), then
# GET it through the proxy with a raw SigV4-signed request carrying a
# multi-range header, and parse the multipart/byteranges body.


def _sign_get(endpoint, url, headers):
    """SigV4-sign a GET. Returns the header dict to send. Mirrors the raw
    signing helper in test_session.py / test_rename.py."""
    creds = botocore.credentials.Credentials(endpoint.access_key, endpoint.secret_key)
    req = botocore.awsrequest.AWSRequest(method="GET", url=url, data=b"", headers=dict(headers))
    botocore.auth.SigV4Auth(creds, "s3", endpoint.region).add_auth(req)
    return dict(req.headers.items())


def _get_raw(endpoint, bucket, key, range_header):
    """Issue a raw signed GET with the given `Range` header value."""
    url = f"{endpoint.base_url}/{bucket}/{key}"
    headers = _sign_get(
        endpoint,
        url,
        {"Range": range_header, "x-amz-content-sha256": "UNSIGNED-PAYLOAD"},
    )
    return requests.get(url, headers=headers, timeout=10)


def _boundary_from_content_type(content_type: str) -> str:
    """Extract the boundary token from a `multipart/byteranges; boundary=…`
    Content-Type value."""
    marker = "boundary="
    idx = content_type.find(marker)
    assert idx != -1, f"no boundary in Content-Type: {content_type!r}"
    return content_type[idx + len(marker):].strip().strip('"')


def _parse_byteranges(content: bytes, boundary: str):
    """Binary-safe parse of a multipart/byteranges body. Returns a list of
    (headers_dict, body_bytes). We control the exact serialization, so a
    manual split is more reliable than the stdlib email parser (which mangles
    binary payloads via line-ending normalization)."""
    delim = b"--" + boundary.encode("ascii")
    parts = []
    for seg in content.split(delim):
        if seg in (b"", b"\r\n") or seg.startswith(b"--"):
            # Preamble (empty) or the closing "--\r\n" delimiter.
            continue
        seg = seg[2:] if seg.startswith(b"\r\n") else seg  # drop CRLF after delimiter
        head, body = seg.split(b"\r\n\r\n", 1)
        body = body[:-2]  # drop the trailing CRLF before the next delimiter
        headers = {}
        for line in head.split(b"\r\n"):
            if not line:
                continue
            k, _, v = line.partition(b": ")
            headers[k.decode("ascii").lower()] = v.decode("ascii")
        parts.append((headers, body))
    return parts


def test_multirange_returns_multipart(endpoint, bucket, bucket_fs):
    """`Range: bytes=0-9,20-29` must yield a 206 multipart/byteranges body
    with two parts carrying the right Content-Range and exact bytes, and a
    Content-Length matching the body length."""
    body = _distinct_body(1024)
    bucket_fs.write("multi.bin", body)

    resp = _get_raw(endpoint, bucket, "multi.bin", "bytes=0-9,20-29")
    assert resp.status_code == 206, resp.text
    ctype = resp.headers["Content-Type"]
    assert ctype.startswith("multipart/byteranges"), ctype
    assert int(resp.headers["Content-Length"]) == len(resp.content), (
        f"Content-Length {resp.headers['Content-Length']} != body {len(resp.content)}"
    )

    boundary = _boundary_from_content_type(ctype)
    parts = _parse_byteranges(resp.content, boundary)
    assert len(parts) == 2, parts

    expected = [(0, 9), (20, 29)]
    for (headers, part_body), (start, end) in zip(parts, expected, strict=True):
        assert headers.get("content-range") == f"bytes {start}-{end}/1024", headers
        assert part_body == body[start:end + 1]


def test_multirange_over_cap_returns_416(endpoint, bucket, bucket_fs):
    """More than MAX_RANGES (50) ranges → 416, even though each individual
    range is satisfiable. 51 single-byte ranges over a 1 KiB object."""
    bucket_fs.write("multi.bin", _distinct_body(1024))
    spec = "bytes=" + ",".join(f"{i}-{i}" for i in range(51))

    resp = _get_raw(endpoint, bucket, "multi.bin", spec)
    assert resp.status_code == 416, f"expected 416, got {resp.status_code}: {resp.text}"


def test_multirange_partial_unsatisfiable_returns_416(endpoint, bucket, bucket_fs):
    """One satisfiable range plus one starting past EOF must fail the whole
    request with 416 (no partial/best-effort response)."""
    bucket_fs.write("multi.bin", _distinct_body(1024))

    resp = _get_raw(endpoint, bucket, "multi.bin", "bytes=0-9,100000-100001")
    assert resp.status_code == 416, f"expected 416, got {resp.status_code}: {resp.text}"
