"""SigV4 verification.

Two-stage verification:
- The proxy validates SigV4 (header or presigned) *before* spawning a worker
  (`s32p-proxy/src/main.rs::validate_sigv4_header_only_or_reject` →
  `s32p-support/src/lib.rs::verify_sigv4_request_any`). This is the
  anti-DoS gate: an unauthenticated caller cannot induce a worker spawn.
- Once a worker exists, the proxy forwards without re-validating. The
  worker (`s32p-gateway`) validates on every request.

This file covers the externally observable variants:

Positive
  - Presigned GET / PUT round-trips (signature in query).
  - Header SigV4 with `x-amz-content-sha256: UNSIGNED-PAYLOAD`
    (`s32p-support/src/lib.rs::verify_sigv4_header_only` honors it).

Negative — every one must reach the client as 403 / 400 with no object
side-effect:
  - Expired presigned URL.
  - Tampered presigned URL (extra/changed query param).
  - Unknown access key.
  - Header SigV4 with the Authorization signature mangled.
  - Request with neither header nor presign credentials.
"""

from __future__ import annotations

import time
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import botocore.auth
import botocore.awsrequest
import botocore.credentials
import pytest
import requests

from s32p_test.clients.capabilities import Capability


# ----------------------------------------------------------------- raw signing


def _sign_request(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes,
    *,
    access_key: str,
    secret_key: str,
    region: str,
) -> dict[str, str]:
    """Sign an HTTP request with SigV4 using botocore's signer.

    Returns the full header set that `requests` should send. Idempotent —
    callers may post-process the result before issuing the request, which
    is how the negative tests build malformed-but-otherwise-plausible
    requests.
    """
    creds = botocore.credentials.Credentials(access_key, secret_key)
    req = botocore.awsrequest.AWSRequest(
        method=method, url=url, data=body, headers=dict(headers)
    )
    botocore.auth.SigV4Auth(creds, "s3", region).add_auth(req)
    return dict(req.headers.items())


# ----------------------------------------------------------------- positive: presign


@pytest.mark.requires_capability(Capability.PRESIGN_GET)
def test_presigned_get_succeeds(client, bucket, bucket_fs):
    """Generate a presigned GET URL, fetch it with a plain HTTP client.
    Body must come back unchanged."""
    body = b"presigned hello\n"
    bucket_fs.write("presign-get.bin", body)

    url = client.presign_get(bucket, "presign-get.bin", expires=60)
    resp = requests.get(url, timeout=10)
    assert resp.status_code == 200, resp.text
    assert resp.content == body


@pytest.mark.requires_capability(Capability.PRESIGN_PUT)
def test_presigned_put_succeeds(client, bucket, bucket_fs):
    """Generate a presigned PUT URL, upload via plain HTTP. Object must
    land on disk byte-identical."""
    body = b"presigned put\n"
    url = client.presign_put(bucket, "presign-put.bin", expires=60)

    resp = requests.put(url, data=body, timeout=10)
    assert resp.status_code == 200, resp.text
    assert bucket_fs.read("presign-put.bin") == body


# ----------------------------------------------------------------- positive: unsigned payload


@pytest.mark.requires_capability(Capability.UNSIGNED_PAYLOAD)
def test_unsigned_payload_header_put_succeeds(endpoint, bucket, bucket_fs):
    """Header SigV4 with `x-amz-content-sha256: UNSIGNED-PAYLOAD`. The
    signature covers everything *but* the body — that's why the proxy
    can validate header-only before forwarding without ever reading the
    body. Server must accept the resulting PUT."""
    body = b"unsigned payload contents\n"
    url = f"{endpoint.base_url}/{bucket}/unsigned.bin"

    headers = {
        "host": _host_from(url),
        "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
        "x-amz-date": _now_amz_date(),
        "content-length": str(len(body)),
    }
    signed = _sign_request(
        "PUT", url, headers, body,
        access_key=endpoint.access_key,
        secret_key=endpoint.secret_key,
        region=endpoint.region,
    )

    resp = requests.put(url, data=body, headers=signed, timeout=10)
    assert resp.status_code == 200, resp.text
    assert bucket_fs.read("unsigned.bin") == body


# ----------------------------------------------------------------- negative: presigned URL tampering


@pytest.mark.requires_capability(Capability.PRESIGN_GET)
def test_presigned_get_after_expiry_rejected(client, bucket, bucket_fs):
    """Presigned URL must be rejected once X-Amz-Expires has elapsed.

    The before/after pattern is deliberate: a single post-expiry 403
    could be hiding an unrelated failure (signing bug, missing object,
    proxy misconfig). Asserting the URL works *before* expiry and fails
    *after* makes the test specific to the expiry mechanism.
    """
    body = b"expires-soon"
    bucket_fs.write("expires.bin", body)

    url = client.presign_get(bucket, "expires.bin", expires=1)

    # Pre-expiry: must work. Anything else points at a setup bug, not expiry.
    pre = requests.get(url, timeout=10)
    assert pre.status_code == 200, (
        f"sanity: URL must be valid before expiry, got {pre.status_code}: {pre.text}"
    )
    assert pre.content == body

    # Sleep past expiry. 1.5s gives margin without slowing the suite much.
    time.sleep(1.5)

    post = requests.get(url, timeout=10)
    assert post.status_code == 403, (
        f"expected 403 after expiry, got {post.status_code}: {post.text}"
    )
    # Tightening: the response must specifically signal expiry, not just
    # any 403. AWS returns AccessDenied with "Request has expired" for
    # expired presigned URLs (vs SignatureDoesNotMatch for bad sigs);
    # clients use the distinction to decide whether to refresh the URL
    # or re-sign.
    body_lc = post.text.lower()
    assert "<code>accessdenied</code>" in body_lc, (
        f"expected AccessDenied code, got: {post.text[:400]}"
    )
    assert "expired" in body_lc, (
        f"expected 'expired' in error body, got: {post.text[:400]}"
    )


@pytest.mark.requires_capability(Capability.PRESIGN_GET)
def test_presigned_get_extra_query_param_rejected(client, bucket, bucket_fs):
    """Adding any query param after signing changes the canonical request
    and must invalidate the signature. Must NOT reach the worker."""
    bucket_fs.write("tamper.bin", b"x")

    url = client.presign_get(bucket, "tamper.bin", expires=60)
    tampered = _add_query_param(url, "injected", "param")

    resp = requests.get(tampered, timeout=10)
    assert resp.status_code == 403, (
        f"expected 403 on extra query param, got {resp.status_code}: {resp.text}"
    )


@pytest.mark.requires_capability(Capability.PRESIGN_GET)
def test_presigned_get_modified_signature_rejected(client, bucket, bucket_fs):
    """Flipping a character in X-Amz-Signature is the textbook tamper
    case — server must reject with 403."""
    bucket_fs.write("sig-flip.bin", b"x")

    url = client.presign_get(bucket, "sig-flip.bin", expires=60)
    mangled = _mangle_query_param(url, "X-Amz-Signature")

    resp = requests.get(mangled, timeout=10)
    assert resp.status_code == 403, (
        f"expected 403 on bad signature, got {resp.status_code}: {resp.text}"
    )


# ----------------------------------------------------------------- negative: header SigV4


def test_unknown_access_key_rejected(endpoint, bucket):
    """A correctly-formed SigV4 with a non-existent access key must be
    rejected before any worker is spawned. The error code is
    InvalidAccessKeyId — slightly different from 'bad signature' so the
    client can distinguish."""
    url = f"{endpoint.base_url}/{bucket}/whatever"
    body = b""
    headers = {
        "host": _host_from(url),
        "x-amz-content-sha256": _empty_sha256(),
        "x-amz-date": _now_amz_date(),
    }
    signed = _sign_request(
        "GET", url, headers, body,
        access_key="AKIAUNKNOWNKEYDOESNOTEXIST",
        secret_key="anything",  # noqa: S106 (test fixture)
        region=endpoint.region,
    )

    resp = requests.get(url, headers=signed, timeout=10)
    assert resp.status_code == 403, (
        f"expected 403 for unknown access key, got {resp.status_code}: {resp.text}"
    )
    # Per s3 error code "InvalidAccessKeyId" — body is XML; just probe.
    assert "InvalidAccessKeyId" in resp.text, (
        f"expected InvalidAccessKeyId code in body, got: {resp.text[:300]}"
    )


def test_mangled_header_signature_rejected(endpoint, bucket):
    """Sign normally, then flip a byte in the Authorization signature.
    Server must respond 403 SignatureDoesNotMatch."""
    url = f"{endpoint.base_url}/{bucket}/whatever"
    body = b""
    headers = {
        "host": _host_from(url),
        "x-amz-content-sha256": _empty_sha256(),
        "x-amz-date": _now_amz_date(),
    }
    signed = _sign_request(
        "GET", url, headers, body,
        access_key=endpoint.access_key,
        secret_key=endpoint.secret_key,
        region=endpoint.region,
    )
    signed["Authorization"] = _mangle_signature_in_auth_header(signed["Authorization"])

    resp = requests.get(url, headers=signed, timeout=10)
    assert resp.status_code == 403, (
        f"expected 403 on mangled signature, got {resp.status_code}: {resp.text}"
    )


def test_missing_authorization_rejected(endpoint, bucket):
    """Request with neither Authorization header nor presign params must
    be rejected (no access key → no routing)."""
    url = f"{endpoint.base_url}/{bucket}/whatever"
    resp = requests.get(url, timeout=10)
    # Either 403 (AccessDenied / can't extract creds) or 400
    # (InvalidArgument) — both are pre-spawn rejections.
    assert resp.status_code in (400, 403), (
        f"expected 4xx pre-spawn rejection, got {resp.status_code}: {resp.text}"
    )


# ----------------------------------------------------------------- helpers


def _host_from(url: str) -> str:
    p = urlparse(url)
    return p.netloc  # boto3 signs `host` including non-default port


def _now_amz_date() -> str:
    """ISO basic format used by SigV4: YYYYMMDDTHHMMSSZ."""
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def _empty_sha256() -> str:
    # SHA-256 of the empty byte string, the canonical hash for body-less GETs.
    return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _add_query_param(url: str, key: str, value: str) -> str:
    p = urlparse(url)
    q = list(parse_qsl(p.query, keep_blank_values=True))
    q.append((key, value))
    return urlunparse(p._replace(query=urlencode(q, safe="/")))


def _mangle_query_param(url: str, key: str) -> str:
    """Flip the first char of the named query value to make it invalid
    without losing its general shape."""
    p = urlparse(url)
    q = list(parse_qsl(p.query, keep_blank_values=True))
    out = []
    for k, v in q:
        if k == key and v:
            v = _flip_first_alnum(v)
        out.append((k, v))
    return urlunparse(p._replace(query=urlencode(out, safe="/")))


def _mangle_signature_in_auth_header(auth: str) -> str:
    """Flip a char inside `Signature=…` to invalidate a header SigV4."""
    marker = "Signature="
    idx = auth.find(marker)
    assert idx >= 0, f"no Signature= in Authorization header: {auth!r}"
    head, tail = auth[: idx + len(marker)], auth[idx + len(marker):]
    return head + _flip_first_alnum(tail)


def _flip_first_alnum(s: str) -> str:
    for i, c in enumerate(s):
        if c.isalnum():
            flipped = "0" if c != "0" else "1"
            return s[:i] + flipped + s[i + 1:]
    return s  # nothing to flip (caller's problem)
