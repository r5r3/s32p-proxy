"""Proxy routing: classes that the test config maps to `not_implemented`
must return 501 NotImplemented to the client.

This file uses boto3 directly (not the matrix) because:
  - It tests *proxy routing*, not client behavior. The request URL/verb
    is identical across SDKs, so a second client adds no signal.
  - The abstract `S3Client` doesn't expose put-bucket-versioning,
    get-object-lock, or create-bucket — and shouldn't, since these are
    permanently unsupported (see project_bucket_admin_via_ctl, README).
  - aws-cli equivalents are trivial to add later if anyone wants matrix
    coverage of the routing — same ops, same response.
"""

from __future__ import annotations

import boto3
import pytest
from botocore.client import Config
from botocore.exceptions import ClientError


@pytest.fixture
def boto3_raw(endpoint):
    """Raw boto3 S3 client for ops that intentionally aren't in the
    `S3Client` abstraction."""
    return boto3.client(
        "s3",
        endpoint_url=endpoint.base_url,
        region_name=endpoint.region,
        aws_access_key_id=endpoint.access_key,
        aws_secret_access_key=endpoint.secret_key,
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            retries={"max_attempts": 1, "mode": "standard"},
        ),
    )


def _assert_not_implemented(exc_info: pytest.ExceptionInfo[ClientError]) -> None:
    response = exc_info.value.response
    err = response.get("Error", {})
    status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert status == 501, (
        f"expected HTTP 501, got {status} ({err.get('Code')!r}: {err.get('Message')!r})"
    )
    assert err.get("Code") == "NotImplemented", (
        f"expected Code=NotImplemented, got {err.get('Code')!r}"
    )


def test_versioning_routes_to_not_implemented(boto3_raw, bucket):
    """`PutBucketVersioning` is in the `versioning` class → not_implemented."""
    with pytest.raises(ClientError) as exc:
        boto3_raw.put_bucket_versioning(
            Bucket=bucket,
            VersioningConfiguration={"Status": "Enabled"},
        )
    _assert_not_implemented(exc)


def test_object_lock_routes_to_not_implemented(boto3_raw, bucket):
    """`GetObjectLockConfiguration` is in the `object_lock` class → not_implemented."""
    with pytest.raises(ClientError) as exc:
        boto3_raw.get_object_lock_configuration(Bucket=bucket)
    _assert_not_implemented(exc)


def test_create_bucket_routes_to_not_implemented(boto3_raw):
    """CreateBucket is operator-only via `s32p-ctl bucket add`; the S3
    surface returns NotImplemented permanently (project memory:
    bucket_admin_via_ctl). Doesn't need an existing bucket."""
    with pytest.raises(ClientError) as exc:
        boto3_raw.create_bucket(Bucket="should-never-be-created")
    _assert_not_implemented(exc)
