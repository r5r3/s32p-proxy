"""End-to-end coverage of the `aws_compat` routing target.

For ops the proxy doesn't implement, the `aws_compat` action returns
the response real AWS would emit when the relevant feature isn't
configured on the bucket — `200` with an empty `<VersioningConfiguration/>`
for `GetBucketVersioning`, `404 ObjectLockConfigurationNotFoundError`
for `GetBucketObjectLockConfiguration`, `400 InvalidRequest` for
`Put-Retention` / `Put-LegalHold`, `404 NoSuchObjectLockConfiguration`
for `Get-Retention` / `Get-LegalHold`. Ops within the routed class
without an AWS feature-disabled shape (e.g. `PutBucketVersioning`)
fall back to `501 NotImplemented` — that fallback is covered by
`test_not_implemented.py::test_put_bucket_versioning_falls_back_to_501`,
plus the explicit `test_aws_compat_unmapped_op_falls_back_to_501`
case here so a regression in either half of the dispatcher fails
loudly.

Why this matters: the default proxy config maps `versioning` and
`object_lock` to `aws_compat`, so probes from boto3's high-level
resources (e.g. `bucket.Versioning().status`) and AWS-doc idioms
(`except client.exceptions.X:`) Just Work without per-op client
patching. The Rust unit tests in `responses::tests::*` cover the
in-process dispatcher; this file pins the end-to-end wire shape
through the real proxy + SigV4.
"""

from __future__ import annotations

import pytest
from botocore.exceptions import ClientError


# ---------------------------------------------------------------- versioning


def test_get_bucket_versioning_returns_empty_config_200(boto3_raw, bucket):
    """AWS returns 200 with `<VersioningConfiguration xmlns="…"/>` —
    no `<Status>` child means "Unversioned". boto3 parses this into a
    response dict with no `Status` / `MFADelete` keys (just
    `ResponseMetadata`)."""
    response = boto3_raw.get_bucket_versioning(Bucket=bucket)
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    # Absence of Status is the AWS signal for "Unversioned"; pin both
    # the absence and the explicit boto3 sentinel so a future
    # regression that synthesizes a 'Status': 'Suspended' is caught.
    assert "Status" not in response, response
    assert "MFADelete" not in response, response


# ---------------------------------------------------------------- object lock — get


def test_get_object_lock_configuration_returns_404_feature_not_found(boto3_raw, bucket):
    """AWS returns 404 with `ObjectLockConfigurationNotFoundError` when
    the bucket was never created with Object Lock enabled. This is the
    code AWS-doc-recommended probe patterns catch — so users can write
    `try: get_object_lock_configuration(); except ClientError as e: if
    e.response['Error']['Code'] == 'ObjectLockConfigurationNotFoundError': ...`
    against our proxy unmodified."""
    with pytest.raises(ClientError) as exc:
        boto3_raw.get_object_lock_configuration(Bucket=bucket)
    err = exc.value.response
    assert err["ResponseMetadata"]["HTTPStatusCode"] == 404
    assert err["Error"]["Code"] == "ObjectLockConfigurationNotFoundError", err


def test_get_object_retention_returns_404_no_such_object_lock_config(boto3_raw, bucket):
    """AWS returns 404 `NoSuchObjectLockConfiguration` when the object
    has no retention setting (true here because the *bucket* has no
    Object Lock at all)."""
    boto3_raw.put_object(Bucket=bucket, Key="retention-probe", Body=b"x")
    with pytest.raises(ClientError) as exc:
        boto3_raw.get_object_retention(Bucket=bucket, Key="retention-probe")
    err = exc.value.response
    assert err["ResponseMetadata"]["HTTPStatusCode"] == 404
    assert err["Error"]["Code"] == "NoSuchObjectLockConfiguration", err


def test_get_object_legal_hold_returns_404_no_such_object_lock_config(boto3_raw, bucket):
    """Same shape as GetObjectRetention — AWS uses the same code for
    both gets when no per-object lock state exists."""
    boto3_raw.put_object(Bucket=bucket, Key="legal-hold-probe", Body=b"x")
    with pytest.raises(ClientError) as exc:
        boto3_raw.get_object_legal_hold(Bucket=bucket, Key="legal-hold-probe")
    err = exc.value.response
    assert err["ResponseMetadata"]["HTTPStatusCode"] == 404
    assert err["Error"]["Code"] == "NoSuchObjectLockConfiguration", err


# ---------------------------------------------------------------- object lock — put


def test_put_object_retention_returns_400_invalid_request(boto3_raw, bucket):
    """AWS returns 400 `InvalidRequest` with the exact message
    "Bucket is missing Object Lock Configuration" when setting
    retention on an object whose bucket has no Object Lock. boto3
    surfaces this as `client.exceptions.InvalidRequest` (modeled), so
    user code can use that typed exception."""
    from datetime import datetime, timedelta, timezone
    boto3_raw.put_object(Bucket=bucket, Key="retention-target", Body=b"x")
    with pytest.raises(ClientError) as exc:
        boto3_raw.put_object_retention(
            Bucket=bucket,
            Key="retention-target",
            Retention={
                "Mode": "GOVERNANCE",
                "RetainUntilDate": datetime.now(tz=timezone.utc) + timedelta(days=1),
            },
        )
    err = exc.value.response
    assert err["ResponseMetadata"]["HTTPStatusCode"] == 400
    assert err["Error"]["Code"] == "InvalidRequest", err
    assert "Object Lock" in err["Error"].get("Message", ""), err


def test_put_object_legal_hold_returns_400_invalid_request(boto3_raw, bucket):
    """Same 400 InvalidRequest shape as Put-Retention."""
    boto3_raw.put_object(Bucket=bucket, Key="legal-hold-target", Body=b"x")
    with pytest.raises(ClientError) as exc:
        boto3_raw.put_object_legal_hold(
            Bucket=bucket,
            Key="legal-hold-target",
            LegalHold={"Status": "ON"},
        )
    err = exc.value.response
    assert err["ResponseMetadata"]["HTTPStatusCode"] == 400
    assert err["Error"]["Code"] == "InvalidRequest", err


# ---------------------------------------------------------------- fallback


def test_aws_compat_unmapped_op_falls_back_to_501(boto3_raw, bucket):
    """Ops in an `aws_compat`-routed class without an AWS feature-disabled
    response (here: `PutObjectLockConfiguration`) must hit the dispatcher's
    fallback arm and return 501 NotImplemented. This complements the
    Rust-side `responses::tests::*falls_back_to_501` tests with an
    end-to-end wire assertion — catches a regression where the YAML
    routing accidentally bypasses the dispatcher (e.g. flipped back to
    a `proxy` action that returns a different error)."""
    with pytest.raises(ClientError) as exc:
        boto3_raw.put_object_lock_configuration(
            Bucket=bucket,
            ObjectLockConfiguration={"ObjectLockEnabled": "Enabled"},
        )
    err = exc.value.response
    assert err["ResponseMetadata"]["HTTPStatusCode"] == 501
    assert err["Error"]["Code"] == "NotImplemented", err
