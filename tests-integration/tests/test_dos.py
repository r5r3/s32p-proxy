"""DoS-class admission control on the proxy listener.

Covers the per-IP concurrent-request cap returning
`429 SlowDown` once a single source IP exceeds
`server.connection_limits.max_concurrent_requests_per_ip`.

The session-scoped proxy used by the rest of the suite ships with
`trusted_loopback_bypass: true` so it doesn't false-trip bursty positive
tests issued from `127.0.0.1`. This test spins up its own short-lived
`ProxyHarness` with `trusted_loopback_bypass=false` and a very small cap
so we can actually exercise the rejection path.

The requests sent here intentionally bypass SigV4 (no Authorization
header) — the limiter runs *before* signature verification in
`request_filter`, so any request shape suffices to drive the counter.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import os
import pwd
import threading
from pathlib import Path
from urllib.parse import urlparse

import botocore.auth
import botocore.awsrequest
import botocore.credentials
import pytest
import requests

from s32p_test.directory import Bucket, Grant, User
from s32p_test.proxy import ProxyHarness


DOS_ACCESS_KEY = "DOS_TEST_KEY"
DOS_SECRET_KEY = "DOS_TEST_SECRET"  # noqa: S105 (test fixture)
DOS_BUCKET = "test-dos-bucket"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


@pytest.fixture
def restricted_proxy(tmp_path_factory) -> ProxyHarness:
    """Function-scoped proxy with the per-IP cap set very low and the
    loopback bypass disabled. Pre-populates one user and one bucket
    so the test can drive *signed* requests that actually reach the
    worker — that's necessary to hold the per-IP slot long enough for
    parallel requests to overlap (an unsigned 403 path completes in
    well under a millisecond, faster than threads can stack up).
    """
    session_dir: Path = tmp_path_factory.mktemp("s32p-dos")
    me = pwd.getpwuid(os.getuid())
    bucket_data_path = session_dir / "buckets" / DOS_BUCKET

    harness = ProxyHarness(
        session_dir=session_dir,
        max_concurrent_requests_per_ip=4,
        trusted_loopback_bypass=False,
        # Keep idle keepalive at the production default; irrelevant
        # for this test but documents the setting still applies.
        keepalive_idle_secs=60,
    )
    harness.directory.add_user(User(
        access_key=DOS_ACCESS_KEY,
        secret_key=DOS_SECRET_KEY,
        username=me.pw_name,
        uid=me.pw_uid,
        gid=me.pw_gid,
    ))
    harness.directory.add_bucket(Bucket(
        name=DOS_BUCKET,
        data_path=bucket_data_path,
        grants=(Grant("ak", DOS_ACCESS_KEY, "read_write"),),
        bucket_id=f"bkt-{DOS_BUCKET}",
    ))
    bucket_data_path.mkdir(parents=True, exist_ok=True)
    harness.start()
    try:
        yield harness
    finally:
        harness.stop()


def _sign_get(url: str, region: str) -> dict[str, str]:
    """Build SigV4-signed headers for a GET against `url`.

    Plain `botocore.auth.SigV4Auth` doesn't auto-add `x-amz-content-sha256`
    (that's the S3-specific signer's job); the proxy requires it on
    header-signed requests. We compute it explicitly for an empty body
    and pre-stage host/date/content-sha256 before signing, matching the
    pattern in `tests/test_sigv4.py::_sign_request` callers.
    """
    parsed = urlparse(url)
    host = parsed.netloc
    amz_date = _dt.datetime.now(_dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    pre = {
        "host":                 host,
        "x-amz-content-sha256": EMPTY_SHA256,
        "x-amz-date":           amz_date,
    }
    creds = botocore.credentials.Credentials(DOS_ACCESS_KEY, DOS_SECRET_KEY)
    req = botocore.awsrequest.AWSRequest(
        method="GET", url=url, data=b"", headers=dict(pre)
    )
    botocore.auth.SigV4Auth(creds, "s3", region).add_auth(req)
    return dict(req.headers.items())


def test_per_ip_concurrent_request_cap_returns_429(restricted_proxy):
    """With cap=4 and loopback bypass off, firing many parallel signed
    GETs must produce at least one `429 SlowDown`.

    Why signed requests? An unsigned 403 path completes in well under a
    millisecond — the limiter slot is released before the next thread's
    request can stack on the counter, so the cap is never hit even with
    16+ parallel sockets. A signed GET reaches the worker (worker spawn
    + filesystem stat + response on the first request takes ~tens of
    ms), so multiple in-flight requests reliably overlap.

    The 8 `conn_limit::tests` unit tests already cover the limiter's
    logic; this integration test proves the end-to-end wiring through
    `early_request_filter` / `request_filter` / `logging()` plus the
    YAML config plumbing and the 429 response shape.
    """
    n_parallel = 16    # 4× the cap of 4
    base = restricted_proxy.base_url
    region = restricted_proxy.region

    # GET on a key that doesn't exist — the worker will produce a
    # NoSuchKey 404, but the request still consumes a slot for the
    # entire pass-through duration (worker spawn on first hit, then
    # stat() + response). That's the window we need to stack on.
    url = f"{base}/{DOS_BUCKET}/no-such-key.bin"

    results: list[int] = []
    results_lock = threading.Lock()

    def fire() -> None:
        try:
            # Sign per-thread so each request has its own valid signature.
            headers = _sign_get(url, region)
            resp = requests.get(url, headers=headers, timeout=15)
            code = resp.status_code
        except requests.RequestException:
            # Pingora closes the connection on 429 (Retry-After + close).
            # Surface as -1 so the assertions only weigh HTTP outcomes.
            code = -1
        with results_lock:
            results.append(code)

    threads = [threading.Thread(target=fire) for _ in range(n_parallel)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20.0)

    assert 429 in results, (
        f"expected ≥1 429 SlowDown with cap=4 / {n_parallel} parallel "
        f"signed GETs, got distribution: "
        f"{dict((c, results.count(c)) for c in set(results))}"
    )


def test_per_ip_cap_releases_slot_after_request_completes(restricted_proxy):
    """Sanity: serial signed requests under the cap never trip the limiter.

    Each request must release its slot in `logging()` so the counter
    returns to zero and the next request gets a fresh slot. Without
    proper release this test would 429 on request #5.
    """
    base = restricted_proxy.base_url
    region = restricted_proxy.region
    url = f"{base}/{DOS_BUCKET}/no-such-key.bin"
    for _ in range(12):
        headers = _sign_get(url, region)
        resp = requests.get(url, headers=headers, timeout=10)
        assert resp.status_code != 429, (
            "serial requests under the cap must never 429; "
            f"got {resp.status_code}"
        )
