"""HTTP/2 at the proxy edge.

`s32p-proxy` advertises h2 by ALPN on its TLS listener
(`tls_settings.enable_h2()`), then reverse-proxies HTTP/1.1 to the worker.
Nothing in the client matrix can exercise that: boto3/urllib3 and the CRT
behind mount-s3 are HTTP/1.1-only. curl negotiates h2 over TLS and reports
which version it actually got, so it is the probe used here.

The second test covers what h2 makes possible and HTTP/1.1 does not. An
h2 body is framed by DATA frames terminated with END_STREAM, so
`Content-Length` is genuinely optional — a client can PUT a plain
(non-aws-chunked) body of unannounced size. The gateway's write path needs
a known length up front, so this must be a clean client-visible error
rather than a hang or a truncated object.

Edge:     crates/s32p-proxy/src/main.rs (`enable_h2`)
Handler:  crates/s32p-gateway/src/main.rs::handle_put_object
"""

from __future__ import annotations

import os
import subprocess

import botocore.auth
import botocore.awsrequest
import botocore.credentials
import pytest


def _sigv4_headers(endpoint, method: str, url: str) -> dict[str, str]:
    """SigV4 headers for `url`, signed over an unsigned payload.

    Only the headers we pass to curl are signed; curl adds Host itself
    (as `:authority` over h2) from the same URL, so it matches what
    botocore canonicalized.
    """
    creds = botocore.credentials.Credentials(endpoint.access_key, endpoint.secret_key)
    req = botocore.awsrequest.AWSRequest(
        method=method,
        url=url,
        data=b"",
        headers={"x-amz-content-sha256": "UNSIGNED-PAYLOAD"},
    )
    botocore.auth.SigV4Auth(creds, "s3", endpoint.region).add_auth(req)
    return dict(req.headers.items())


def _curl(endpoint, url: str, *args: str, stdin: bytes | None = None):
    """Run curl over h2 against the TLS harness, reporting version + status.

    `-w` is used instead of parsing `-v` output: `%{http_version}` reports
    the negotiated version directly ("2" when ALPN settled on h2).
    """
    header_args: list[str] = []
    for k, v in _sigv4_headers(endpoint, "PUT", url).items():
        header_args += ["-H", f"{k}: {v}"]
    # curl would otherwise add `Expect: 100-continue` for larger bodies,
    # which is HTTP/1.1 semantics and just noise here.
    header_args += ["-H", "Expect:"]

    return subprocess.run(
        [
            "curl", "--silent", "--show-error",
            "--http2",
            "--cacert", endpoint.ca_bundle,
            "-w", "%{http_version} %{http_code}",
            *header_args,
            *args,
            url,
        ],
        input=stdin,
        capture_output=True,
        timeout=30,
    )


def test_curl_negotiates_h2_and_puts_object(
    tls_endpoint, tls_bucket, tls_bucket_fs, tmp_path
):
    """A length-announced PUT over HTTP/2 stores the object."""
    key = "h2/probe.dat"
    body = os.urandom(1024)
    src = tmp_path / "probe.dat"
    src.write_bytes(body)

    url = f"{tls_endpoint.base_url}/{tls_bucket}/{key}"
    proc = _curl(tls_endpoint, url, "-T", str(src), "-o", "/dev/null")

    assert proc.returncode == 0, proc.stderr.decode()
    version, code = proc.stdout.decode().split()
    assert version == "2", f"expected h2 via ALPN, got HTTP/{version}"
    assert code == "200", proc.stdout.decode()
    assert tls_bucket_fs.read(key) == body


def test_curl_h2_put_without_content_length_is_rejected(
    tls_endpoint, tls_bucket, tls_bucket_fs, tmp_path
):
    """An h2 PUT of unannounced size is refused, not hung or truncated.

    Reading the body from stdin leaves curl unable to state a length; over
    HTTP/1.1 it would fall back to `Transfer-Encoding: chunked`, but over
    h2 the request simply carries no length at all.
    """
    key = "h2/nolen.dat"
    body = os.urandom(1024)
    out = tmp_path / "resp.xml"

    url = f"{tls_endpoint.base_url}/{tls_bucket}/{key}"
    proc = _curl(tls_endpoint, url, "-T", "-", "-o", str(out), stdin=body)

    assert proc.returncode == 0, proc.stderr.decode()
    version, code = proc.stdout.decode().split()
    assert version == "2", f"expected h2 via ALPN, got HTTP/{version}"
    # 411 Length Required / MissingContentLength is what AWS S3 answers a
    # PutObject that declares no body length.
    assert code == "411", f"{code}: {out.read_text()}"
    # Pin the reason, not just the status. The refusal comes from
    # compute_logical_len, which resolves the body length before any
    # handler-level check and has nothing to read for a plain h2 body.
    text = out.read_text()
    assert "MissingContentLength" in text, text
    assert "missing header content-length" in text, text
    # Nothing may be left behind on a refused write.
    assert not tls_bucket_fs.exists(key)
