"""CreateSession (S3 Express directory-bucket auth flow).

The proxy exposes `GET /{bucket}?session` as a local handler that mints
ephemeral SigV4 credentials (AWS-style: AccessKeyId + SecretAccessKey +
SessionToken + Expiration) and stores them in an in-memory session store.
Subsequent data-plane requests can be signed with those credentials
against the `s3express` service name; the proxy validates them and
forwards to the worker with a trusted internal header.

These tests drive the wire with raw SigV4 (no general-purpose S3 SDK
implements CreateSession against a non-directory-bucket endpoint
without endpoint-resolver gymnastics).

Handler:     crates/s32p-proxy/src/main.rs (RouteAction::CreateSession)
Store:       crates/s32p-proxy/src/session.rs (SessionStore)
Trust path:  crates/s32p-gateway/src/main.rs require_sigv4 short-circuit
Classifier:  crates/s32p-support/src/classifier.rs → S3Op::Session(CreateSession)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import quote

import botocore.auth
import botocore.awsrequest
import botocore.credentials
import pytest
import requests


@dataclass(slots=True, frozen=True)
class SessionCreds:
    access_key:    str
    secret_key:    str
    session_token: str
    expiration:    str


# ----------------------------------------------------------------- helpers


def _sign(method, url, headers, body, *, access_key, secret_key, region, service):
    """SigV4-sign one request. Returns the header dict requests should send."""
    creds = botocore.credentials.Credentials(access_key, secret_key)
    req = botocore.awsrequest.AWSRequest(method=method, url=url, data=body, headers=dict(headers))
    botocore.auth.SigV4Auth(creds, service, region).add_auth(req)
    return dict(req.headers.items())


def _create_session_raw(
    endpoint,
    bucket: str,
    *,
    mode: str | None = None,
    access_key: str | None = None,
    secret_key: str | None = None,
    session_token: str | None = None,
) -> requests.Response:
    """Send a SigV4-signed `GET /{bucket}?session`. Optional `mode` is
    `ReadOnly` | `ReadWrite`; AWS defaults to ReadWrite when absent.

    `session_token` is used by the "sessions can't beget sessions" test to
    pass the proxy's token gate so the request reaches the action-level
    rejection — a real long-term-cred CreateSession never carries this
    header.
    """
    url = f"{endpoint.base_url}/{bucket}?session"
    headers: dict[str, str] = {"x-amz-content-sha256": "UNSIGNED-PAYLOAD"}
    if mode is not None:
        headers["x-amz-create-session-mode"] = mode
    if session_token is not None:
        headers["x-amz-s3session-token"] = session_token
    signed = _sign(
        "GET",
        url,
        headers,
        b"",
        access_key=access_key or endpoint.access_key,
        secret_key=secret_key or endpoint.secret_key,
        region=endpoint.region,
        service="s3",
    )
    return requests.get(url, headers=signed, timeout=10)


_XML_CRED_RE = re.compile(
    r"<AccessKeyId>(?P<ak>[^<]+)</AccessKeyId>\s*"
    r"<SecretAccessKey>(?P<sk>[^<]+)</SecretAccessKey>\s*"
    r"<SessionToken>(?P<st>[^<]+)</SessionToken>\s*"
    r"<Expiration>(?P<exp>[^<]+)</Expiration>",
    re.DOTALL,
)


def _parse_session(body: str) -> SessionCreds:
    """Parse the four `<Credentials>` fields from a `<CreateSessionResult>` body.

    Regex is cheap and avoids pulling in an XML lib at the test level; the
    response shape is fixed (we control the serializer). Test fails loudly
    if any field is missing.
    """
    m = _XML_CRED_RE.search(body)
    if m is None:
        raise AssertionError(f"could not parse <Credentials> from body: {body!r}")
    return SessionCreds(
        access_key=m.group("ak"),
        secret_key=m.group("sk"),
        session_token=m.group("st"),
        expiration=m.group("exp"),
    )


def _put_with_session(
    endpoint,
    bucket: str,
    key: str,
    body: bytes,
    creds: SessionCreds,
    *,
    token_override: str | None = None,
    omit_token: bool = False,
) -> requests.Response:
    """PUT signed with session credentials (service=s3express).

    The proxy enforces `x-amz-s3session-token` matches what CreateSession
    minted. `token_override` lets a test send a wrong value; `omit_token`
    lets a test drop the header entirely.
    """
    url = f"{endpoint.base_url}/{bucket}/{quote(key, safe='/')}"
    headers = {"x-amz-content-sha256": "UNSIGNED-PAYLOAD"}
    if not omit_token:
        headers["x-amz-s3session-token"] = token_override if token_override is not None else creds.session_token
    signed = _sign(
        "PUT", url, headers, body,
        access_key=creds.access_key,
        secret_key=creds.secret_key,
        region=endpoint.region,
        service="s3express",
    )
    return requests.put(url, data=body, headers=signed, timeout=10)


def _get_with_session(
    endpoint,
    bucket: str,
    key: str,
    creds: SessionCreds,
    *,
    token_override: str | None = None,
    omit_token: bool = False,
) -> requests.Response:
    url = f"{endpoint.base_url}/{bucket}/{quote(key, safe='/')}"
    headers = {"x-amz-content-sha256": "UNSIGNED-PAYLOAD"}
    if not omit_token:
        headers["x-amz-s3session-token"] = token_override if token_override is not None else creds.session_token
    signed = _sign(
        "GET", url, headers, b"",
        access_key=creds.access_key,
        secret_key=creds.secret_key,
        region=endpoint.region,
        service="s3express",
    )
    return requests.get(url, headers=signed, timeout=10)


# ----------------------------------------------------------------- happy path


def test_create_session_returns_credentials(endpoint, bucket):
    """CreateSession against a granted bucket returns a 200 + XML body
    with all four credential fields populated, an ISO-8601-Z `Expiration`,
    and credentials that *don't* echo the caller's long-term secret."""
    resp = _create_session_raw(endpoint, bucket)

    assert resp.status_code == 200, resp.text
    assert resp.headers.get("content-type", "").startswith("application/xml"), resp.headers

    creds = _parse_session(resp.text)
    assert creds.access_key, "AccessKeyId must be non-empty"
    assert creds.secret_key, "SecretAccessKey must be non-empty"
    assert creds.session_token, "SessionToken must be non-empty"
    # AWS-shaped temporary key prefix; mostly diagnostic, not strictly required.
    assert creds.access_key.startswith("ASIA"), creds.access_key
    # The session's secret must never equal the caller's long-term secret —
    # leaking the long-term secret in the session response is the failure
    # mode the OsRng-minted ephemeral guards against.
    assert creds.secret_key != endpoint.secret_key, (
        "session secret must be ephemeral, not the caller's long-term key"
    )
    # Expiration is "<YYYY>-<MM>-<DD>T...Z" via format_s3_time_system.
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", creds.expiration), creds.expiration


def test_session_credentials_drive_put_get(endpoint, bucket, bucket_fs):
    """Mint a ReadWrite session, then PUT + GET an object using session
    credentials. Asserts byte-identity on disk via bucket_fs and confirms
    the session signing path (service=`s3express`) reaches the worker."""
    creds = _parse_session(_create_session_raw(endpoint, bucket).text)

    body = b"session-driven payload\n"
    put = _put_with_session(endpoint, bucket, "via-session.bin", body, creds)
    assert put.status_code == 200, put.text

    # On disk: bytes match exactly.
    assert bucket_fs.read("via-session.bin") == body

    got = _get_with_session(endpoint, bucket, "via-session.bin", creds)
    assert got.status_code == 200, got.text
    assert got.content == body


def test_readonly_session_allows_get(endpoint, bucket, bucket_fs):
    """ReadOnly session must permit GETs on objects placed via POSIX."""
    bucket_fs.write("ro-obj.bin", b"ro payload\n")
    creds = _parse_session(_create_session_raw(endpoint, bucket, mode="ReadOnly").text)

    got = _get_with_session(endpoint, bucket, "ro-obj.bin", creds)
    assert got.status_code == 200, got.text
    assert got.content == b"ro payload\n"


def test_readonly_session_rejects_put(endpoint, bucket, bucket_fs):
    """ReadOnly session must reject PUT at the proxy with 403 AccessDenied
    *before* anything lands on disk."""
    creds = _parse_session(_create_session_raw(endpoint, bucket, mode="ReadOnly").text)

    resp = _put_with_session(endpoint, bucket, "should-not-land.bin", b"x", creds)
    assert resp.status_code == 403, resp.text
    assert "<Code>AccessDenied</Code>" in resp.text, resp.text
    assert not bucket_fs.exists("should-not-land.bin")


# ----------------------------------------------------------------- error paths


def test_cross_bucket_session_use_rejected(endpoint, proxy_harness):
    """A session minted for bucket A must not work against bucket B —
    even when the caller has grants on both. The check happens at the
    proxy before reaching the worker."""
    # Lease two pool buckets without going through the per-test `bucket`
    # fixture (we want both at once). They both have read_write grants for
    # the primary user, so the only thing keeping the request out is the
    # session-scope check.
    bucket_a = "test-bucket-000"
    bucket_b = "test-bucket-001"
    # Make sure both data dirs exist (the harness pre-creates them).
    assert (proxy_harness.session_dir / "buckets" / bucket_a).exists()
    assert (proxy_harness.session_dir / "buckets" / bucket_b).exists()

    creds = _parse_session(_create_session_raw(endpoint, bucket_a).text)

    # GET against the *wrong* bucket → 403 from proxy.
    url = f"{endpoint.base_url}/{bucket_b}/whatever"
    headers = {
        "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
        "x-amz-s3session-token": creds.session_token,
    }
    signed = _sign(
        "GET", url, headers, b"",
        access_key=creds.access_key,
        secret_key=creds.secret_key,
        region=endpoint.region,
        service="s3express",
    )
    resp = requests.get(url, headers=signed, timeout=10)
    assert resp.status_code == 403, resp.text
    assert "<Code>AccessDenied</Code>" in resp.text, resp.text


def test_create_session_with_session_creds_rejected(endpoint, bucket):
    """Sessions cannot beget sessions — CreateSession itself requires the
    caller's long-term IAM credentials. A session-signed CreateSession
    request that *also* carries the correct session-token (so it gets past
    the access-control gate) must 400 InvalidRequest at the action-level
    check."""
    creds = _parse_session(_create_session_raw(endpoint, bucket).text)

    resp = _create_session_raw(
        endpoint, bucket,
        access_key=creds.access_key,
        secret_key=creds.secret_key,
        session_token=creds.session_token,
    )
    assert resp.status_code == 400, resp.text
    assert "<Code>InvalidRequest</Code>" in resp.text, resp.text


def test_session_request_without_token_rejected(endpoint, bucket, bucket_fs):
    """Session-signed request that omits `x-amz-s3session-token` must be
    rejected at the proxy with a generic 403. The token is the second factor
    (the first is the ephemeral secret); a leaked access key alone is not
    enough to use the session."""
    creds = _parse_session(_create_session_raw(endpoint, bucket).text)

    resp = _put_with_session(endpoint, bucket, "no-token.bin", b"x", creds, omit_token=True)
    assert resp.status_code == 403, resp.text
    assert "<Code>AccessDenied</Code>" in resp.text, resp.text
    assert not bucket_fs.exists("no-token.bin")


def test_session_request_with_wrong_token_rejected(endpoint, bucket, bucket_fs):
    """Session-signed request that carries the wrong token value (e.g. a
    token from a different session or an attacker's guess) must be rejected.
    The same-length variant exercises the constant-time compare path."""
    creds = _parse_session(_create_session_raw(endpoint, bucket).text)
    # Same length, different value — exercises the byte-compare, not just
    # the length-prefilter.
    wrong_same_len = "0" * len(creds.session_token)
    assert wrong_same_len != creds.session_token

    resp = _put_with_session(
        endpoint, bucket, "wrong-token.bin", b"x", creds, token_override=wrong_same_len
    )
    assert resp.status_code == 403, resp.text
    assert "<Code>AccessDenied</Code>" in resp.text, resp.text
    assert not bucket_fs.exists("wrong-token.bin")


def test_unknown_session_access_key_rejected(endpoint, bucket):
    """An ASIA-shaped access key that was never minted falls through to
    the Directory lookup, which returns InvalidAccessKeyId."""
    fake = SessionCreds(
        access_key="ASIA" + "X" * 16,
        secret_key="X" * 40,
        session_token="00000000-0000-0000-0000-000000000000",
        expiration="2099-01-01T00:00:00Z",
    )
    resp = _put_with_session(endpoint, bucket, "ghost.bin", b"x", fake)
    assert resp.status_code == 403, resp.text
    # Either InvalidAccessKeyId (Directory miss) or SignatureDoesNotMatch
    # (long-term-secret-mismatch) — both are valid 403 codes for "we don't
    # know this key". Reject anything else.
    assert any(
        code in resp.text for code in ("InvalidAccessKeyId", "SignatureDoesNotMatch")
    ), resp.text


# ----------------------------------------------------------------- security


def test_spoofed_validated_header_stripped_by_proxy(endpoint, bucket, bucket_fs):
    """A client may try to inject `X-S32P-Validated` on a normal request
    to bypass auth. The proxy must strip the header at ingress so the
    worker never sees it; the legitimately-signed PUT must succeed
    end-to-end. The realistic attacker shape is to sign normally and
    *then* add the spoof header — signing the spoof header in would
    require knowing the long-term secret already, which makes the spoof
    pointless."""
    body = b"normal request\n"
    key = "normal-put.bin"
    url = f"{endpoint.base_url}/{bucket}/{key}"
    headers = {"x-amz-content-sha256": "UNSIGNED-PAYLOAD"}
    signed = _sign(
        "PUT", url, headers, body,
        access_key=endpoint.access_key,
        secret_key=endpoint.secret_key,
        region=endpoint.region,
        service="s3",
    )
    # Inject post-signing — the SignedHeaders list in `Authorization`
    # does not include this header, so SigV4 verification ignores it.
    signed["X-S32P-Validated"] = "if-this-were-trusted-everything-breaks"

    resp = requests.put(url, data=body, headers=signed, timeout=10)
    # If the proxy stripped the header *before* forwarding, our normal
    # long-term signature still verifies and the PUT succeeds. If the
    # proxy didn't strip, the gateway would either accept the spoof
    # (catastrophic) or 403 with a token-mismatch error.
    assert resp.status_code == 200, resp.text
    assert bucket_fs.read(key) == body


def test_session_response_does_not_leak_internal_headers(endpoint, bucket):
    """The CreateSession response is the only thing the client sees from
    the session subsystem. It must not carry any internal trust material
    (the per-worker token, internal validation headers, etc.) — those
    flow only on the proxy↔worker channel."""
    resp = _create_session_raw(endpoint, bucket)
    assert resp.status_code == 200, resp.text

    # No internal header should be reflected back.
    for hdr in resp.headers:
        assert not hdr.lower().startswith("x-s32p-"), (
            f"internal header leaked to client: {hdr}={resp.headers[hdr]!r}"
        )
    # And no internal-looking strings in the body either.
    body_lc = resp.text.lower()
    assert "x-s32p-" not in body_lc, resp.text
    assert "worker_token" not in body_lc, resp.text


# ----------------------------------------------------------------- TTL note
#
# Expiry semantics (the `expires_at_inst` sweep and the lookup-time
# expiration check) are verified directly in
# `crates/s32p-proxy/src/session.rs::tests::lookup_returns_none_after_expiry`.
# An integration-level expiry test would require either a sub-2s TTL on
# the session-scoped harness (too short to share with other tests in the
# run) or a re-spawned per-test harness (substantial extra runtime).
# Skipping the integration variant deliberately; the unit test covers it.

@pytest.mark.skip(reason="covered by session.rs unit test; integration TTL would re-spawn the harness")
def test_expired_session_rejected():  # pragma: no cover
    pass
