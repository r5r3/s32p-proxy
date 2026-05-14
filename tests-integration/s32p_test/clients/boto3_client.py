"""boto3 implementation of the S3Client matrix interface."""

from __future__ import annotations

from typing import TYPE_CHECKING

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError

from .base import (
    Endpoint,
    GetResult,
    ListResult,
    PutResult,
    S3Client,
    S3Error,
    S3Object,
)
from .capabilities import Capability

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client as Boto3S3


class Boto3Client(S3Client):
    name = "boto3"
    capabilities = {
        Capability.PATH_STYLE,
        Capability.VIRTUAL_HOSTED,
        Capability.RANGE_REQUESTS,
        Capability.LIST_V1,
        Capability.LIST_V2,
        Capability.COPY_OBJECT,
        Capability.DELETE_OBJECTS,
        Capability.METADATA,
        Capability.MULTIPART,
        Capability.OBJECT_ACL,
        Capability.BUCKET_ACL,
        Capability.PRESIGN_GET,
        Capability.PRESIGN_PUT,
        Capability.UNSIGNED_PAYLOAD,
        # RENAME_OBJECT intentionally not advertised: boto3's S3Control client
        # has it for directory buckets but not for general S3; tests that want
        # rename should use the raw HTTP path or a future adapter.
    }

    def __init__(self, endpoint: Endpoint, *, addressing: str = "path"):
        super().__init__(endpoint, addressing=addressing)
        self._s3: Boto3S3 = boto3.client(
            "s3",
            endpoint_url=endpoint.base_url,
            region_name=endpoint.region,
            aws_access_key_id=endpoint.access_key,
            aws_secret_access_key=endpoint.secret_key,
            config=Config(
                signature_version="s3v4",
                s3={"addressing_style": "path" if addressing == "path" else "virtual"},
                retries={"max_attempts": 1, "mode": "standard"},
            ),
        )

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _wrap(call):
        """Translate botocore ClientError → S3Error."""
        try:
            return call()
        except ClientError as e:
            err = e.response.get("Error", {})
            meta = e.response.get("ResponseMetadata", {})
            raise S3Error(
                code=err.get("Code", "Unknown"),
                status=int(meta.get("HTTPStatusCode", 0)),
                message=err.get("Message", ""),
            ) from e

    # ------------------------------------------------------------------ buckets

    def list_buckets(self) -> list[str]:
        resp = self._wrap(lambda: self._s3.list_buckets())
        return [b["Name"] for b in resp.get("Buckets", [])]

    def head_bucket(self, bucket: str) -> bool:
        try:
            self._wrap(lambda: self._s3.head_bucket(Bucket=bucket))
            return True
        except S3Error as e:
            if e.status == 404:
                return False
            raise

    # ------------------------------------------------------------------ objects

    def put_object(
        self,
        bucket: str,
        key: str,
        body: bytes,
        *,
        content_type: str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> PutResult:
        kw: dict = {"Bucket": bucket, "Key": key, "Body": body}
        if content_type is not None:
            kw["ContentType"] = content_type
        if metadata:
            kw["Metadata"] = metadata
        resp = self._wrap(lambda: self._s3.put_object(**kw))
        return PutResult(etag=resp["ETag"].strip('"'))

    def get_object(
        self,
        bucket: str,
        key: str,
        *,
        range_: tuple[int, int] | None = None,
    ) -> GetResult:
        kw: dict = {"Bucket": bucket, "Key": key}
        if range_ is not None:
            kw["Range"] = f"bytes={range_[0]}-{range_[1]}"
        resp = self._wrap(lambda: self._s3.get_object(**kw))
        body = resp["Body"].read()
        return GetResult(
            body=body,
            etag=resp["ETag"].strip('"'),
            content_length=int(resp.get("ContentLength", len(body))),
            content_type=resp.get("ContentType"),
            metadata=dict(resp.get("Metadata", {})),
        )

    def head_object(self, bucket: str, key: str) -> GetResult:
        resp = self._wrap(lambda: self._s3.head_object(Bucket=bucket, Key=key))
        return GetResult(
            body=b"",
            etag=resp["ETag"].strip('"'),
            content_length=int(resp.get("ContentLength", 0)),
            content_type=resp.get("ContentType"),
            metadata=dict(resp.get("Metadata", {})),
        )

    def delete_object(self, bucket: str, key: str) -> None:
        self._wrap(lambda: self._s3.delete_object(Bucket=bucket, Key=key))

    def list_objects(
        self,
        bucket: str,
        *,
        prefix: str = "",
        delimiter: str | None = None,
        max_keys: int | None = None,
        continuation_token: str | None = None,
        v1: bool = False,
    ) -> ListResult:
        if v1:
            kw: dict = {"Bucket": bucket, "Prefix": prefix}
            if delimiter is not None:
                kw["Delimiter"] = delimiter
            if max_keys is not None:
                kw["MaxKeys"] = max_keys
            if continuation_token is not None:
                kw["Marker"] = continuation_token
            resp = self._wrap(lambda: self._s3.list_objects(**kw))
            return ListResult(
                objects=[_obj_from_v1(o) for o in resp.get("Contents", [])],
                common_prefixes=[p["Prefix"] for p in resp.get("CommonPrefixes", [])],
                is_truncated=bool(resp.get("IsTruncated", False)),
                next_continuation_token=resp.get("NextMarker"),
            )

        kw = {"Bucket": bucket, "Prefix": prefix}
        if delimiter is not None:
            kw["Delimiter"] = delimiter
        if max_keys is not None:
            kw["MaxKeys"] = max_keys
        if continuation_token is not None:
            kw["ContinuationToken"] = continuation_token
        resp = self._wrap(lambda: self._s3.list_objects_v2(**kw))
        return ListResult(
            objects=[_obj_from_v2(o) for o in resp.get("Contents", [])],
            common_prefixes=[p["Prefix"] for p in resp.get("CommonPrefixes", [])],
            is_truncated=bool(resp.get("IsTruncated", False)),
            next_continuation_token=resp.get("NextContinuationToken"),
        )

    def copy_object(self, src_bucket, src_key, dst_bucket, dst_key) -> PutResult:
        resp = self._wrap(
            lambda: self._s3.copy_object(
                Bucket=dst_bucket,
                Key=dst_key,
                CopySource={"Bucket": src_bucket, "Key": src_key},
            )
        )
        return PutResult(etag=resp["CopyObjectResult"]["ETag"].strip('"'))

    def delete_objects(self, bucket: str, keys: list[str]) -> list[str]:
        resp = self._wrap(
            lambda: self._s3.delete_objects(
                Bucket=bucket,
                Delete={"Objects": [{"Key": k} for k in keys], "Quiet": False},
            )
        )
        return [d["Key"] for d in resp.get("Deleted", [])]

    def presign_get(self, bucket: str, key: str, *, expires: int = 60) -> str:
        return self._s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket, "Key": key},
            ExpiresIn=expires,
        )


def _obj_from_v1(o: dict) -> S3Object:
    return S3Object(
        key=o["Key"],
        size=int(o["Size"]),
        etag=o["ETag"].strip('"'),
        last_modified=o["LastModified"].isoformat(),
    )


def _obj_from_v2(o: dict) -> S3Object:
    return S3Object(
        key=o["Key"],
        size=int(o["Size"]),
        etag=o["ETag"].strip('"'),
        last_modified=o["LastModified"].isoformat(),
    )
