"""Smoke coverage for the OpenBao directory backend.

The bulk of the suite runs against the YAML backend; these tests cover the
parts that only execute when `auth.backend: openbao` is in play:

  * `s32p-ctl --backend openbao` write path — AppRole login, KV v2 writes,
    and index-doc maintenance (exercised by `setup` + seeding below).
  * The proxy's runtime `OpenBaoDirectory` read path — AppRole login plus
    user/secret and buckets-for-access-key lookups on every request.

We don't re-run the whole client matrix here (that's the YAML backend's
job); a focused set of boto3 ops is enough to prove both code paths work
end to end. The whole module is gated behind `requires_openbao` and skips
when the `bao` binary isn't installed.

OpenBao provisioning: a single `bao server -dev` is spawned per session
(in-memory, discarded on exit). `openbao_setup()` bootstraps the
proxy/admin AppRoles; the proxy authenticates with the proxy pair, and
seeding goes through the *admin* AppRole so its policy is exercised too
(rather than the all-powerful root token).
"""

from __future__ import annotations

import os
import pwd
import shutil
import uuid

import boto3
import pytest
from botocore.client import Config
from botocore.exceptions import ClientError

from s32p_test.directory import Bucket, Grant, OpenBaoDirectory, User, openbao_setup
from s32p_test.openbao import OpenBaoServer
from s32p_test.proxy import ProxyHarness

pytestmark = pytest.mark.requires_openbao

# Fixed test credentials, distinct from the YAML suite's so a shared dev
# OpenBao (if ever reused) wouldn't collide.
OB_ACCESS_KEY = "OBACCESSKEY123"
OB_SECRET_KEY = "OBSECRETKEY456"  # noqa: S105 (test fixture, not a real secret)
OB_BUCKET = "openbao-bucket"


@pytest.fixture(scope="session")
def openbao_server(tmp_path_factory):
    bao = shutil.which(os.environ.get("S32P_BAO_BIN", "bao"))
    if bao is None:
        pytest.skip(
            "openbao backend tests need the `bao` binary on PATH "
            "(set S32P_BAO_BIN to override); none found"
        )
    work = tmp_path_factory.mktemp("openbao")
    srv = OpenBaoServer(bao_bin=bao, work_dir=work)
    srv.start()
    try:
        yield srv
    finally:
        srv.stop()


@pytest.fixture(scope="session")
def openbao_harness(openbao_server, tmp_path_factory) -> ProxyHarness:
    """A proxy backed by OpenBao, seeded with one user + one bucket.

    Single-uid: the seeded user is the test runner, so workers spawn as us
    (the harness keeps `pass_user_flag_if_root=False`).
    """
    session_dir = tmp_path_factory.mktemp("s32p-openbao")
    me = pwd.getpwuid(os.getuid())

    # Bootstrap AppRoles + policies with the dev root token; capture the
    # four credential files s32p-ctl writes (mode 0600).
    creds = session_dir / "openbao-creds"
    proxy_role_id = creds / "proxy-role-id"
    proxy_secret_id = creds / "proxy-secret-id"
    admin_role_id = creds / "admin-role-id"
    admin_secret_id = creds / "admin-secret-id"
    openbao_setup(
        address=openbao_server.address,
        token=openbao_server.root_token,
        proxy_role_id_file=proxy_role_id,
        proxy_secret_id_file=proxy_secret_id,
        admin_role_id_file=admin_role_id,
        admin_secret_id_file=admin_secret_id,
    )

    # Seed via the admin AppRole — exercises its policy + s32p-ctl's
    # AppRole login, not just the root token.
    directory = OpenBaoDirectory(
        address=openbao_server.address,
        role_id_file=admin_role_id,
        secret_id_file=admin_secret_id,
    )
    directory.add_user(User(
        access_key=OB_ACCESS_KEY,
        secret_key=OB_SECRET_KEY,
        username=me.pw_name,
        uid=me.pw_uid,
        gid=me.pw_gid,
    ))
    directory.add_bucket(Bucket(
        name=OB_BUCKET,
        data_path=session_dir / "buckets" / OB_BUCKET,
        grants=(Grant("ak", OB_ACCESS_KEY, "read_write"),),
        bucket_id="bkt-openbao",
    ))

    # Proxy reads via the proxy AppRole pair.
    auth_config = {
        "backend": "openbao",
        "openbao": {
            "address": openbao_server.address,
            "approle_mount": "approle",
            "role_id_file": str(proxy_role_id),
            "secret_id_file": str(proxy_secret_id),
            "kv_mount": "secret",
            "prefix": "s32p",
        },
    }
    harness = ProxyHarness(session_dir=session_dir, auth_config=auth_config)
    harness.start()
    try:
        yield harness
    finally:
        harness.stop()


def _s3(harness: ProxyHarness, *, access_key=OB_ACCESS_KEY, secret_key=OB_SECRET_KEY):
    """Path-style boto3 client with one-shot retries (so an auth failure
    surfaces immediately as a ClientError rather than looping)."""
    return boto3.client(
        "s3",
        endpoint_url=harness.base_url,
        region_name=harness.region,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            retries={"max_attempts": 1, "mode": "standard"},
        ),
    )


def test_list_buckets_reflects_openbao_grant(openbao_harness):
    """ListBuckets resolves the caller and their buckets-for-access-key
    index entirely through the OpenBao read path."""
    s3 = _s3(openbao_harness)
    names = [b["Name"] for b in s3.list_buckets()["Buckets"]]
    assert OB_BUCKET in names


def test_put_get_roundtrip(openbao_harness):
    """A full object round-trip: proves the proxy authorizes + spawns a
    worker off OpenBao-resolved identity."""
    s3 = _s3(openbao_harness)
    key = f"roundtrip-{uuid.uuid4().hex}.txt"
    body = b"openbao backend smoke test"
    s3.put_object(Bucket=OB_BUCKET, Key=key, Body=body)
    got = s3.get_object(Bucket=OB_BUCKET, Key=key)["Body"].read()
    assert got == body


def test_list_objects(openbao_harness):
    s3 = _s3(openbao_harness)
    prefix = f"list-{uuid.uuid4().hex}/"
    keys = {f"{prefix}a", f"{prefix}b", f"{prefix}c"}
    for k in keys:
        s3.put_object(Bucket=OB_BUCKET, Key=k, Body=b"x")
    listed = {
        o["Key"]
        for o in s3.list_objects_v2(Bucket=OB_BUCKET, Prefix=prefix).get("Contents", [])
    }
    assert keys <= listed


def test_wrong_secret_rejected(openbao_harness):
    """SigV4 verification uses the secret fetched from OpenBao; a wrong
    secret for a known access key must be rejected."""
    s3 = _s3(openbao_harness, secret_key="WRONGSECRET000")  # noqa: S106
    with pytest.raises(ClientError) as ei:
        s3.list_buckets()
    assert ei.value.response["ResponseMetadata"]["HTTPStatusCode"] == 403


def test_unknown_access_key_rejected(openbao_harness):
    """An access key with no OpenBao record is rejected (directory miss)."""
    s3 = _s3(openbao_harness, access_key="NOSUCHKEY999", secret_key="NOSUCHSECRET")  # noqa: S106
    with pytest.raises(ClientError) as ei:
        s3.list_buckets()
    assert ei.value.response["ResponseMetadata"]["HTTPStatusCode"] == 403
