"""Proxy routing: classes/ops that still return 501 NotImplemented.

Covers two distinct sources of 501:

  1. The `bucket_admin` class is routed to `not_implemented` in the
     default config — every op in that class (`CreateBucket`,
     `DeleteBucket`) returns 501 unconditionally. That's a deliberate
     policy boundary, not a missing feature (bucket admin happens via
     `s32p-ctl`).
  2. The `versioning` class is routed to `aws_compat`, but ops within
     that class without an AWS feature-disabled equivalent
     (`PutBucketVersioning` — AWS always implements it) fall through
     the `aws_compat` dispatcher to the same 501 NotImplemented response.

The `aws_compat` ops that *do* get AWS-shaped responses (200, 404,
400) are covered separately in `test_aws_compat.py`.

This file uses boto3 directly (not the matrix) because:
  - It tests *proxy routing*, not client behavior. The request URL/verb
    is identical across SDKs, so a second client adds no signal.
  - The abstract `S3Client` doesn't expose put-bucket-versioning or
    create-bucket — and shouldn't, since these are permanently
    unsupported (see project_bucket_admin_via_ctl, README).
  - aws-cli equivalents are trivial to add later if anyone wants matrix
    coverage of the routing — same ops, same response.
"""

from __future__ import annotations

import pytest
from botocore.exceptions import ClientError


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


def test_put_bucket_versioning_falls_back_to_501(boto3_raw, bucket):
    """`PutBucketVersioning` is in the `versioning` class (routed to
    `aws_compat`), but AWS has no "feature disabled" response for this
    op — it always implements PutBucketVersioning unconditionally. The
    `aws_compat` dispatcher's fallback arm must therefore return 501
    NotImplemented. See `responses::aws_compat_response` for the table."""
    with pytest.raises(ClientError) as exc:
        boto3_raw.put_bucket_versioning(
            Bucket=bucket,
            VersioningConfiguration={"Status": "Enabled"},
        )
    _assert_not_implemented(exc)


def test_create_bucket_routes_to_not_implemented(boto3_raw):
    """CreateBucket is operator-only via `s32p-ctl bucket add`; the S3
    surface returns NotImplemented permanently (project memory:
    bucket_admin_via_ctl). Doesn't need an existing bucket."""
    with pytest.raises(ClientError) as exc:
        boto3_raw.create_bucket(Bucket="should-never-be-created")
    _assert_not_implemented(exc)
