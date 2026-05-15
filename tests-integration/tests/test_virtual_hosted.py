"""Virtual-hosted-style addressing.

The proxy parses bucket-name-from-Host when the Host header ends with one
of `server.virtual_hosted_suffixes` (see `parse_bucket_key_auto` in
classifier.rs:670). For tests, we rely on nip.io wildcard DNS so a host
like `mybucket.127.0.0.1.nip.io` resolves to 127.0.0.1 — boto3 connects
to loopback while sending the bucket name in the host label, exercising
the proxy's virtual-hosted parsing end-to-end.

These tests only run when `--addressing=virtual` (or `=both`) and the
DNS probe in conftest succeeded; otherwise the matrix never produces a
parametrized variant for them.
"""

from __future__ import annotations

import pytest

from s32p_test.clients.capabilities import Capability


pytestmark = pytest.mark.requires_capability(Capability.VIRTUAL_HOSTED)


def _skip_unless_virtual(client):
    if client.addressing != "virtual":
        pytest.skip("only meaningful in virtual addressing mode")


def test_virtual_hosted_put_get_roundtrip(client, bucket):
    """PUT then GET via virtual-hosted host. Failure here means either
    boto3 isn't using virtual style (check Endpoint.url_for_addressing)
    or the proxy isn't matching the suffix (check virtual_hosted_suffixes
    in the rendered config)."""
    _skip_unless_virtual(client)
    body = b"hello via vhost\n"
    client.put_object(bucket, "vhost/key", body)
    got = client.get_object(bucket, "vhost/key")
    assert got.body == body


def test_virtual_hosted_endpoint_url_uses_suffix(client, bucket):
    """Sanity check on the harness wiring: with virtual addressing,
    the client's endpoint URL must point at the suffix host (so the SDK
    can prepend the bucket label) and not at loopback. Adapter-specific
    introspection — gated by name."""
    _skip_unless_virtual(client)
    if client.name == "boto3":
        endpoint_url = client._s3.meta.endpoint_url
    elif client.name == "aws-cli":
        endpoint_url = client._endpoint_url
    else:
        pytest.skip(f"endpoint introspection not implemented for {client.name}")
    assert "127.0.0.1.nip.io" in endpoint_url, (
        f"expected suffix in endpoint_url for virtual mode, got {endpoint_url!r}"
    )
