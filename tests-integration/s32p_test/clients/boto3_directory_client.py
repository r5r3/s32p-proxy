"""boto3 configured for S3 Express directory-bucket mode.

boto3 doesn't have a `Config(directory_bucket=True)` knob — the
directory-bucket personality activates *per call* based on the
bucket name. When the bucket name ends in `--x-s3`, botocore's
endpoint ruleset routes the request through the `S3Express` backend,
which:

  1. issues `CreateSession` lazily before the first data-plane call,
     signed with `service=s3`, against `GET /{bucket}?session`,
  2. caches the response credentials (per-bucket LRU),
  3. signs subsequent data-plane requests with `service=s3express`
     using the cached session token.

The proxy already handles all three (CreateSession in
`crates/s32p-proxy/src/session.rs`, `s3express`-scope verification
in `crates/s32p-support/src/lib.rs`). What this adapter exists to
test is whether the full boto3 stack — endpoint resolver, signer
selection, response-model parsing, lazy session bootstrap — actually
works end-to-end against our endpoint.

Differences from `Boto3Client`:
  - No `PATH_STYLE`: AWS directory buckets are virtual-hosted only;
    boto3's endpoint resolver silently coerces away from path-style
    for `--x-s3` names regardless of `Config(addressing_style="path")`.
  - No `LIST_V1`: AWS forbids ListObjectsV1 on directory buckets.
  - No `OBJECT_ACL` / `BUCKET_ACL`: AWS doesn't support ACLs here;
    boto3 will refuse to issue them.
  - No `METADATA`: same posture as the plain boto3 adapter — gateway
    is a no-op already, existing `test_user_metadata_roundtrip` xfails
    document this.

The dual bucket pool in `tests-integration/conftest.py` hands this
adapter `--x-s3`-suffixed bucket names (e.g.
`test-dirbucket-000--use1-az4--x-s3`), so every call exercises the
directory-bucket data plane.
"""

from __future__ import annotations

import boto3
from botocore.client import Config

from .base import Endpoint, S3Client
from .boto3_client import Boto3Client
from .capabilities import Capability


class Boto3DirectoryClient(Boto3Client):
    name = "boto3-directory"
    capabilities = {
        Capability.DIRECTORY_BUCKET,
        Capability.VIRTUAL_HOSTED,
        Capability.RANGE_REQUESTS,
        Capability.LIST_V2,
        Capability.COPY_OBJECT,
        Capability.DELETE_OBJECTS,
        Capability.MULTIPART,
        # No PRESIGN_*: in directory-bucket mode every presigned URL is
        # generated with the ephemeral session credentials minted by
        # CreateSession (scope `…/s3express/aws4_request` + an
        # `X-Amz-S3session-Token` query param). The proxy doesn't yet
        # look up sessions for presigned URLs — `uid=0 username=<unknown>`
        # in the proxy log on the 403. Tracked as a follow-up gap in
        # `directory-bucket-support.md`.
        Capability.UNSIGNED_PAYLOAD,
        Capability.CONDITIONAL_REQUESTS,
    }

    def __init__(self, endpoint: Endpoint, *, addressing: str = "virtual"):
        # Skip `Boto3Client.__init__` and build the SDK client ourselves
        # because the parent pins `signature_version="s3v4"`, and that
        # pin breaks S3 Express signer selection. Why:
        #
        # `botocore.regions.EndpointRulesetResolver.auth_schemes_to_signing_ctx`
        # (regions.py:719-735) returns an empty signing context when a
        # user-supplied `signature_version` doesn't match the ruleset's
        # auth scheme. For `--x-s3` buckets, the ruleset emits
        # `sigv4-s3express`; `s3v4` doesn't satisfy
        # `_does_botocore_authname_match_ruleset_authname`, so the
        # context is wiped to `{}`. With no `signing_name='s3express'`
        # in the context, `S3ExpressIdentityResolver` (utils.py:1722)
        # skips identity injection and CreateSession is never issued.
        #
        # Leaving `signature_version` unset lets botocore pick
        # `v4-s3express` directly from the ruleset's auth scheme and
        # populates the context correctly.
        S3Client.__init__(self, endpoint, addressing=addressing)
        self._s3 = boto3.client(
            "s3",
            endpoint_url=endpoint.url_for_addressing(addressing),
            region_name=endpoint.region,
            aws_access_key_id=endpoint.access_key,
            aws_secret_access_key=endpoint.secret_key,
            config=Config(
                s3={"addressing_style": "virtual"},
                retries={"max_attempts": 1, "mode": "standard"},
            ),
        )
