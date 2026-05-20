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
  - Replay of a previously-accepted signature (header or presigned),
    rejected by the in-memory replay cache in both proxy and gateway
    (`s32p-support/src/replay_cache.rs`).
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


@pytest.mark.requires_capability(Capability.PRESIGN_HEAD)
def test_presigned_head_succeeds(client, bucket, bucket_fs):
    """Presigned HEAD: same code path as GET on the proxy, exercised with
    a different verb. Body comes back empty; Content-Length header
    reflects the object size."""
    body = b"head me" * 100
    bucket_fs.write("presign-head.bin", body)

    url = client.presign_head(bucket, "presign-head.bin", expires=60)
    resp = requests.head(url, timeout=10)
    assert resp.status_code == 200, resp.text
    assert int(resp.headers["Content-Length"]) == len(body)
    assert resp.content == b""


@pytest.mark.requires_capability(Capability.PRESIGN_DELETE)
def test_presigned_delete_succeeds(client, bucket, bucket_fs):
    """Presigned DELETE: object must be gone from disk after the request."""
    bucket_fs.write("presign-delete.bin", b"transient")
    assert bucket_fs.exists("presign-delete.bin")

    url = client.presign_delete(bucket, "presign-delete.bin", expires=60)
    resp = requests.delete(url, timeout=10)
    assert resp.status_code in (200, 204), resp.text
    assert not bucket_fs.exists("presign-delete.bin"), (
        "DELETE returned success but file still on disk"
    )


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

    # Warm the worker before signing. The first proxy request triggers a
    # worker spawn (~4s under landlock + restricted-exec on this machine);
    # if that happens between signing and the pre-expiry GET reaching the
    # gateway, a short-expiry URL can age out in flight and the test fails
    # for the wrong reason (URL valid when signed, expired when served).
    # Any authenticated round-trip through the proxy will do — HeadBucket
    # is the cheapest.
    client.head_bucket(bucket)

    url = client.presign_get(bucket, "expires.bin", expires=2)

    # Pre-expiry: must work. Anything else points at a setup bug, not expiry.
    pre = requests.get(url, timeout=10)
    assert pre.status_code == 200, (
        f"sanity: URL must be valid before expiry, got {pre.status_code}: {pre.text}"
    )
    assert pre.content == body

    # Sleep past expiry. 2.5s = expires + 0.5s margin.
    time.sleep(2.5)

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


@pytest.mark.requires_capability(Capability.PRESIGN_PUT)
def test_presigned_put_after_expiry_rejected(client, bucket, bucket_fs):
    """Mirror of the GET expiry test, on the write side. Same
    before/after pattern: pre-expiry PUT must succeed; post-expiry must
    fail with AccessDenied / 'Request has expired' so the client knows
    to refresh the URL rather than re-sign."""
    # Warm the worker before signing — see comment on the GET sibling.
    client.head_bucket(bucket)

    url = client.presign_put(bucket, "put-expires.bin", expires=2)

    pre = requests.put(url, data=b"in-window", timeout=10)
    assert pre.status_code == 200, (
        f"sanity: presigned PUT must work before expiry, "
        f"got {pre.status_code}: {pre.text}"
    )

    time.sleep(2.5)

    post = requests.put(url, data=b"too-late", timeout=10)
    assert post.status_code == 403, (
        f"expected 403 after expiry, got {post.status_code}: {post.text}"
    )
    body_lc = post.text.lower()
    assert "<code>accessdenied</code>" in body_lc, post.text[:400]
    assert "expired" in body_lc, post.text[:400]
    # Filesystem must hold the pre-expiry write but not the post-expiry one.
    assert bucket_fs.read("put-expires.bin") == b"in-window"


@pytest.mark.requires_capability(Capability.PRESIGN_PUT)
def test_presigned_put_modified_signature_rejected(client, bucket, bucket_fs):
    """Tampering with X-Amz-Signature on a presigned PUT must reject
    BEFORE the body is written to the bucket."""
    url = client.presign_put(bucket, "put-sig-flip.bin", expires=60)
    mangled = _mangle_query_param(url, "X-Amz-Signature")

    resp = requests.put(mangled, data=b"should-not-land", timeout=10)
    assert resp.status_code == 403, (
        f"expected 403 on bad signature, got {resp.status_code}: {resp.text}"
    )
    assert not bucket_fs.exists("put-sig-flip.bin"), (
        "tampered presigned PUT was rejected but the body still landed"
    )


# ---------- presigned URL: cross-method / cross-path / cross-host swap ----------
#
# All three are forms of "the request that arrived doesn't match the request
# that was signed". The signature covers the method, the canonical URI (path),
# and a fixed list of headers (always including 'host'). Any of these
# differing must invalidate the signature.


@pytest.mark.requires_capability(Capability.PRESIGN_GET)
def test_presigned_get_method_swapped_to_put_rejected(client, bucket, bucket_fs):
    """Sign for GET, send PUT. The HTTP method is part of the canonical
    request, so the signatures must not match. A server that didn't
    include the method in canonicalization would let this through —
    catastrophic for a presigned-URL world where GET URLs are routinely
    shared as 'read-only' tokens."""
    bucket_fs.write("method-swap.bin", b"original")

    url = client.presign_get(bucket, "method-swap.bin", expires=60)
    resp = requests.put(url, data=b"hijacked", timeout=10)
    assert resp.status_code == 403, (
        f"GET-signed URL accepted as PUT (status {resp.status_code}): "
        f"{resp.text[:300]}"
    )
    # Original file content must be untouched.
    assert bucket_fs.read("method-swap.bin") == b"original"


@pytest.mark.requires_capability(Capability.PRESIGN_GET)
def test_presigned_get_path_modified_rejected(client, bucket, bucket_fs):
    """Sign for /a, send to /b. The canonical URI is signed, so swapping
    keys on a presigned URL must fail. Common attacker shape: harvest a
    presigned URL from a log, retarget to a sibling object."""
    bucket_fs.write("intended.bin", b"intended")
    bucket_fs.write("sibling.bin", b"sibling-untouched")

    url = client.presign_get(bucket, "intended.bin", expires=60)
    swapped = _replace_path_segment(url, "intended.bin", "sibling.bin")

    resp = requests.get(swapped, timeout=10)
    assert resp.status_code == 403, (
        f"path-swapped presigned URL not rejected (status {resp.status_code}): "
        f"{resp.text[:300]}"
    )


@pytest.mark.requires_capability(Capability.PRESIGN_GET)
def test_presigned_get_host_modified_rejected(client, bucket, bucket_fs):
    """The Host header is always in SignedHeaders; sending the request
    with a different Host than was signed must reject with 403."""
    bucket_fs.write("host-swap.bin", b"x")

    url = client.presign_get(bucket, "host-swap.bin", expires=60)
    # We connect to the proxy normally (URL.host = 127.0.0.1) but send a
    # different Host header. boto3 included `host: 127.0.0.1:<port>` in
    # the canonical request, so the proxy's recomputed signature won't
    # match what we sent.
    resp = requests.get(
        url,
        headers={"Host": "evil.example.com"},
        timeout=10,
    )
    assert resp.status_code == 403, (
        f"host-swapped presigned URL not rejected (status {resp.status_code}): "
        f"{resp.text[:300]}"
    )


# ----------------------------------------------------------------- negative: signature replay
#
# The proxy and gateway each keep an in-memory cache of recently-verified
# SigV4 signatures (TTL = HEADER_SIGV4_MAX_SKEW + 1s, see
# `s32p-support/src/replay_cache.rs`). Every successful verification
# records the signature; a subsequent request carrying the same signature
# inside the window is rejected with SignatureDoesNotMatch — the same
# client-facing code a bad signature produces, so the cache is not usable
# as an oracle. These tests exercise the end-to-end behavior; whether the
# rejection came from the proxy cache (spawn-gate path) or the gateway
# cache (fast-path) is not distinguished, only that the replay is denied.


def test_header_signed_put_replay_rejected(endpoint, bucket, bucket_fs):
    """Sign a header-SigV4 PUT once, send it twice. The first must succeed;
    the second must be rejected with SignatureDoesNotMatch. The byte-
    identical replay simulates a captured request being re-sent from a
    log scraper / proxied connection / mirror — exactly what the replay
    cache is there to stop."""
    body = b"first-and-only\n"
    url = f"{endpoint.base_url}/{bucket}/replay-header.bin"

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

    first = requests.put(url, data=body, headers=signed, timeout=10)
    assert first.status_code == 200, (
        f"sanity: signed PUT must succeed once, got {first.status_code}: {first.text}"
    )
    assert bucket_fs.read("replay-header.bin") == body

    # Byte-identical replay. Same headers (same x-amz-date, same Authorization),
    # same body. The signature is one we've already accepted.
    second = requests.put(url, data=body, headers=signed, timeout=10)
    assert second.status_code == 403, (
        f"expected 403 on replay, got {second.status_code}: {second.text}"
    )
    body_lc = second.text.lower()
    assert "<code>signaturedoesnotmatch</code>" in body_lc, (
        f"replay should surface as SignatureDoesNotMatch (not a different 403), "
        f"got: {second.text[:400]}"
    )


@pytest.mark.requires_capability(Capability.PRESIGN_GET)
def test_presigned_get_replay_rejected(client, bucket, bucket_fs):
    """Fetch a presigned URL twice. First must work; second must reject
    with SignatureDoesNotMatch. Replay protection is the main reason the
    cache exists for presigned URLs — they survive long enough to be
    captured from a log and resent."""
    body = b"presigned-replay\n"
    bucket_fs.write("replay-presign.bin", body)

    url = client.presign_get(bucket, "replay-presign.bin", expires=60)

    first = requests.get(url, timeout=10)
    assert first.status_code == 200, (
        f"sanity: presigned GET must work first, got {first.status_code}: {first.text}"
    )
    assert first.content == body

    second = requests.get(url, timeout=10)
    assert second.status_code == 403, (
        f"expected 403 on presigned replay, got {second.status_code}: {second.text}"
    )
    body_lc = second.text.lower()
    assert "<code>signaturedoesnotmatch</code>" in body_lc, (
        f"presigned replay should surface as SignatureDoesNotMatch, "
        f"got: {second.text[:400]}"
    )


def test_distinct_signatures_not_falsely_blocked(endpoint, bucket, bucket_fs):
    """Negative-of-negative: two *different* signed requests issued in
    rapid succession must both succeed. Guards against a regression where
    the cache key is too coarse (e.g. keyed on access-key instead of the
    signature) and starts dropping legitimate traffic."""
    body_a = b"alpha\n"
    body_b = b"beta\n"
    url_a = f"{endpoint.base_url}/{bucket}/distinct-a.bin"
    url_b = f"{endpoint.base_url}/{bucket}/distinct-b.bin"

    def _sign_put(url: str, body: bytes) -> dict[str, str]:
        return _sign_request(
            "PUT",
            url,
            {
                "host": _host_from(url),
                "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
                "x-amz-date": _now_amz_date(),
                "content-length": str(len(body)),
            },
            body,
            access_key=endpoint.access_key,
            secret_key=endpoint.secret_key,
            region=endpoint.region,
        )

    # Distinct paths → distinct canonical requests → distinct signatures.
    signed_a = _sign_put(url_a, body_a)
    signed_b = _sign_put(url_b, body_b)
    assert signed_a["Authorization"] != signed_b["Authorization"], (
        "test setup: distinct paths should produce distinct Authorization headers"
    )

    resp_a = requests.put(url_a, data=body_a, headers=signed_a, timeout=10)
    resp_b = requests.put(url_b, data=body_b, headers=signed_b, timeout=10)

    assert resp_a.status_code == 200, (
        f"first signed PUT was rejected as if a replay: {resp_a.status_code}: {resp_a.text}"
    )
    assert resp_b.status_code == 200, (
        f"second (distinct) signed PUT was rejected: {resp_b.status_code}: {resp_b.text}"
    )
    assert bucket_fs.read("distinct-a.bin") == body_a
    assert bucket_fs.read("distinct-b.bin") == body_b


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


def _replace_path_segment(url: str, old: str, new: str) -> str:
    """Swap a literal segment of the URL path (leaving query untouched).
    Used by the path-swap tamper test — preserves the X-Amz-* signature
    block so the only difference vs the signed request is the resource."""
    p = urlparse(url)
    if old not in p.path:
        raise AssertionError(f"path {p.path!r} does not contain {old!r}")
    return urlunparse(p._replace(path=p.path.replace(old, new, 1)))


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
