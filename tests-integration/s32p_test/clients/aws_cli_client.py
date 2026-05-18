"""aws-cli (v2) implementation of the S3Client matrix interface.

Each operation shells out to `aws s3api <op> --endpoint-url <base>`. We use
s3api (not s3) because s3api maps 1:1 to the underlying S3 operations and
returns parseable JSON. Path-style addressing is the default when
--endpoint-url is given, so no extra configuration is needed.

Body bytes are passed via a temp file (--body <path>); responses bodies
land in another temp file (last positional arg). Both are unlinked after
the call.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, ClassVar

from .base import (
    Conditions,
    CopyConditions,
    Endpoint,
    GetResult,
    ListResult,
    PutResult,
    S3Client,
    S3Error,
    S3Object,
)
from .capabilities import Capability


# AWS short codes → typical HTTP status. aws-cli's stderr emits the short
# code for body-bearing responses but a bare numeric for HEAD ops.
_STATUS_FROM_CODE: dict[str, int] = {
    "NoSuchKey": 404,
    "NoSuchBucket": 404,
    "NoSuchUpload": 404,
    "AccessDenied": 403,
    "SignatureDoesNotMatch": 403,
    "InvalidAccessKeyId": 403,
    "NotImplemented": 501,
    "InvalidRequest": 400,
    "InvalidArgument": 400,
    "MalformedXML": 400,
    "BucketAlreadyExists": 409,
    "BucketNotEmpty": 409,
    "InvalidRange": 416,
    "PreconditionFailed": 412,
    "EntityTooLarge": 413,
    "InvalidPart": 400,
    "InvalidPartOrder": 400,
}

_ERROR_RE = re.compile(
    r"An error occurred \(([^)]+)\) when calling the (\w+) operation:?\s*(.*)"
)


class AwsCliClient(S3Client):
    name = "aws-cli"
    capabilities = {
        Capability.PATH_STYLE,
        Capability.VIRTUAL_HOSTED,
        Capability.RANGE_REQUESTS,
        Capability.LIST_V1,
        Capability.LIST_V2,
        Capability.COPY_OBJECT,
        Capability.DELETE_OBJECTS,
        Capability.METADATA,
        Capability.UNSIGNED_PAYLOAD,
        Capability.MULTIPART,
        Capability.UPLOAD_PART_COPY,
        Capability.CONDITIONAL_REQUESTS,
        Capability.PRESIGN_GET,
        # Skipped for now (each is a follow-up):
        # - OBJECT_ACL/BUCKET_ACL  can be added once we have a representative ACL doc shape
        # - PRESIGN_PUT      `aws s3 presign` produces GET URLs only; PUT presign
        #                    is not exposed by the CLI without manual signing.
    }

    # `aws s3api` has no per-command addressing-style flag — the only knob
    # is `s3.addressing_style` in the AWS config file. We write a temp INI
    # once and point AWS_CONFIG_FILE at it for every virtual-mode call.
    # Class-level cache: contents are constant so every instance shares
    # one file. Leaked at process exit (tiny; /tmp will rotate it).
    _virtual_config_path: ClassVar[str | None] = None

    @classmethod
    def _ensure_virtual_config(cls) -> str:
        if cls._virtual_config_path is None:
            fd, path = tempfile.mkstemp(prefix="s32p-aws-cfg-", suffix=".ini")
            with os.fdopen(fd, "w") as fh:
                fh.write("[default]\ns3 =\n    addressing_style = virtual\n")
            cls._virtual_config_path = path
        return cls._virtual_config_path

    def __init__(self, endpoint: Endpoint, *, addressing: str = "path"):
        super().__init__(endpoint, addressing=addressing)
        self._endpoint_url = endpoint.url_for_addressing(addressing)
        self._config_path: str | None = (
            self._ensure_virtual_config() if addressing == "virtual" else None
        )

    # ----------------------------------------------------------------- helpers

    def _env(self) -> dict[str, str]:
        env = dict(os.environ)
        env["AWS_ACCESS_KEY_ID"] = self.endpoint.access_key
        env["AWS_SECRET_ACCESS_KEY"] = self.endpoint.secret_key
        env["AWS_DEFAULT_REGION"] = self.endpoint.region
        # Drop session token if the host env happens to have one — would
        # confuse SigV4.
        env.pop("AWS_SESSION_TOKEN", None)
        if self._config_path is not None:
            env["AWS_CONFIG_FILE"] = self._config_path
        return env

    def _run(
        self,
        *args: str,
        timeout: float = 30.0,
    ) -> dict[str, Any] | None:
        """Run `aws s3api <args>` and return parsed JSON (or None on empty stdout)."""
        cmd = [
            "aws", "s3api", *args,
            "--endpoint-url", self._endpoint_url,
            "--no-paginate",
            "--output", "json",
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            env=self._env(),
            timeout=timeout,
        )
        if result.returncode != 0:
            raise self._parse_error(result.stderr.decode("utf-8", "replace"))
        out = result.stdout.strip()
        return json.loads(out) if out else None

    @staticmethod
    def _parse_error(stderr: str) -> S3Error:
        m = _ERROR_RE.search(stderr)
        if not m:
            return S3Error(code="Unknown", status=0, message=stderr.strip())
        code, _op, msg = m.group(1), m.group(2), m.group(3).strip()
        if code.isdigit():
            return S3Error(code=code, status=int(code), message=msg)
        return S3Error(code=code, status=_STATUS_FROM_CODE.get(code, 0), message=msg)

    @staticmethod
    @contextmanager
    def _tempfile_with(data: bytes | None = None):
        """Yield a path to a fresh temp file (optionally pre-filled), then unlink."""
        fd, path_str = tempfile.mkstemp(prefix="s32p-awscli-")
        try:
            with os.fdopen(fd, "wb") as fh:
                if data is not None:
                    fh.write(data)
            yield Path(path_str)
        finally:
            try:
                os.unlink(path_str)
            except FileNotFoundError:
                pass

    # ----------------------------------------------------------------- buckets

    def list_buckets(self) -> list[str]:
        result = self._run("list-buckets") or {}
        return [b["Name"] for b in result.get("Buckets", [])]

    def head_bucket(self, bucket: str) -> bool:
        try:
            self._run("head-bucket", "--bucket", bucket)
            return True
        except S3Error as e:
            if e.status == 404:
                return False
            raise

    # ----------------------------------------------------------------- objects

    def put_object(
        self,
        bucket: str,
        key: str,
        body: bytes,
        *,
        content_type: str | None = None,
        metadata: dict[str, str] | None = None,
        conditions: Conditions | None = None,
    ) -> PutResult:
        with self._tempfile_with(body) as body_path:
            args = [
                "put-object",
                "--bucket", bucket,
                "--key", key,
                "--body", str(body_path),
            ]
            if content_type is not None:
                args += ["--content-type", content_type]
            if metadata:
                # aws-cli shorthand: Key1=Value1,Key2=Value2 (no commas/equals
                # in values; tests control the input so this is fine).
                args += ["--metadata", ",".join(f"{k}={v}" for k, v in metadata.items())]
            args += _conditional_args(conditions)
            result = self._run(*args) or {}
        return PutResult(etag=result["ETag"].strip('"'))

    def get_object(
        self,
        bucket: str,
        key: str,
        *,
        range_: tuple[int, int] | None = None,
        conditions: Conditions | None = None,
    ) -> GetResult:
        with self._tempfile_with() as out_path:
            args = ["get-object", "--bucket", bucket, "--key", key]
            if range_ is not None:
                args += ["--range", f"bytes={range_[0]}-{range_[1]}"]
            args += _conditional_args(conditions)
            args.append(str(out_path))
            result = self._run(*args) or {}
            body = out_path.read_bytes()
        return GetResult(
            body=body,
            etag=result["ETag"].strip('"'),
            content_length=int(result.get("ContentLength", len(body))),
            content_type=result.get("ContentType"),
            metadata=dict(result.get("Metadata", {})),
        )

    def head_object(
        self,
        bucket: str,
        key: str,
        *,
        conditions: Conditions | None = None,
    ) -> GetResult:
        args = ["head-object", "--bucket", bucket, "--key", key]
        args += _conditional_args(conditions)
        result = self._run(*args) or {}
        return GetResult(
            body=b"",
            etag=result["ETag"].strip('"'),
            content_length=int(result.get("ContentLength", 0)),
            content_type=result.get("ContentType"),
            metadata=dict(result.get("Metadata", {})),
        )

    def delete_object(self, bucket: str, key: str) -> None:
        self._run("delete-object", "--bucket", bucket, "--key", key)

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
        op = "list-objects" if v1 else "list-objects-v2"
        args = [op, "--bucket", bucket]
        if prefix:
            args += ["--prefix", prefix]
        if delimiter is not None:
            args += ["--delimiter", delimiter]
        if max_keys is not None:
            # aws-cli's --max-keys IS the S3 MaxKeys (one API call's cap).
            # --max-items is CLI-side pagination — not what the matrix wants.
            args += ["--max-keys", str(max_keys)]
        if continuation_token is not None:
            args += ["--marker" if v1 else "--continuation-token", continuation_token]
        result = self._run(*args) or {}

        objects = [_object_from_aws(o) for o in result.get("Contents", [])]
        common = [p["Prefix"] for p in result.get("CommonPrefixes", [])]
        if v1:
            return ListResult(
                objects=objects,
                common_prefixes=common,
                is_truncated=bool(result.get("IsTruncated", False)),
                next_continuation_token=result.get("NextMarker"),
            )
        return ListResult(
            objects=objects,
            common_prefixes=common,
            is_truncated=bool(result.get("IsTruncated", False)),
            next_continuation_token=result.get("NextContinuationToken"),
        )

    def copy_object(
        self,
        src_bucket: str,
        src_key: str,
        dst_bucket: str,
        dst_key: str,
        *,
        conditions: CopyConditions | None = None,
    ) -> PutResult:
        args = [
            "copy-object",
            "--bucket", dst_bucket,
            "--key", dst_key,
            "--copy-source", f"{src_bucket}/{src_key}",
        ]
        if conditions is not None:
            if conditions.source is not None:
                args += _copy_source_conditional_args(conditions.source)
            if conditions.destination is not None:
                args += _conditional_args(conditions.destination)
        result = self._run(*args) or {}
        return PutResult(etag=result["CopyObjectResult"]["ETag"].strip('"'))

    def delete_objects(self, bucket: str, keys: list[str]) -> list[str]:
        delete_doc = json.dumps({"Objects": [{"Key": k} for k in keys], "Quiet": False})
        result = self._run(
            "delete-objects",
            "--bucket", bucket,
            "--delete", delete_doc,
        ) or {}
        return [d["Key"] for d in result.get("Deleted", [])]

    # ----- multipart -----

    def create_multipart(self, bucket: str, key: str) -> str:
        result = self._run(
            "create-multipart-upload", "--bucket", bucket, "--key", key
        ) or {}
        return result["UploadId"]

    def upload_part(
        self, bucket: str, key: str, upload_id: str, part_number: int, body: bytes
    ) -> str:
        with self._tempfile_with(body) as body_path:
            result = self._run(
                "upload-part",
                "--bucket", bucket,
                "--key", key,
                "--upload-id", upload_id,
                "--part-number", str(part_number),
                "--body", str(body_path),
            ) or {}
        return result["ETag"].strip('"')

    def upload_part_copy(
        self,
        dst_bucket: str,
        dst_key: str,
        upload_id: str,
        part_number: int,
        src_bucket: str,
        src_key: str,
        *,
        copy_source_range: tuple[int, int] | None = None,
        conditions: CopyConditions | None = None,
    ) -> str:
        args = [
            "upload-part-copy",
            "--bucket", dst_bucket,
            "--key", dst_key,
            "--upload-id", upload_id,
            "--part-number", str(part_number),
            "--copy-source", f"{src_bucket}/{src_key}",
        ]
        if copy_source_range is not None:
            start, end_inclusive = copy_source_range
            args += ["--copy-source-range", f"bytes={start}-{end_inclusive}"]
        if conditions is not None and conditions.source is not None:
            args += _copy_source_conditional_args(conditions.source)
        result = self._run(*args) or {}
        return result["CopyPartResult"]["ETag"].strip('"')

    def complete_multipart(
        self, bucket: str, key: str, upload_id: str, parts: list[tuple[int, str]]
    ) -> PutResult:
        parts_doc = json.dumps({
            "Parts": [
                {"PartNumber": n, "ETag": f'"{e.strip(chr(34))}"'}
                for n, e in sorted(parts)
            ]
        })
        result = self._run(
            "complete-multipart-upload",
            "--bucket", bucket,
            "--key", key,
            "--upload-id", upload_id,
            "--multipart-upload", parts_doc,
        ) or {}
        return PutResult(etag=result["ETag"].strip('"'))

    def abort_multipart(self, bucket: str, key: str, upload_id: str) -> None:
        self._run(
            "abort-multipart-upload",
            "--bucket", bucket,
            "--key", key,
            "--upload-id", upload_id,
        )

    # ----- presign -----

    def presign_get(self, bucket: str, key: str, *, expires: int = 60) -> str:
        """Uses `aws s3 presign` (NOT s3api). The CLI emits the URL on
        stdout; no JSON wrapping. Goes through a different command tree
        than _run, so it shells out directly."""
        cmd = [
            "aws", "s3", "presign",
            f"s3://{bucket}/{key}",
            "--endpoint-url", self._endpoint_url,
            "--expires-in", str(expires),
        ]
        result = subprocess.run(
            cmd, capture_output=True, env=self._env(), timeout=30,
        )
        if result.returncode != 0:
            raise self._parse_error(result.stderr.decode("utf-8", "replace"))
        return result.stdout.decode("utf-8").strip()


def _quote_etag(value: str) -> str:
    """S3 wants ETags quoted in conditional headers; '*' is special and
    must NOT be quoted. Idempotent."""
    if value == "*":
        return value
    if value.startswith('"') and value.endswith('"'):
        return value
    return f'"{value}"'


def _conditional_args(conditions: Conditions | None) -> list[str]:
    if conditions is None:
        return []
    out: list[str] = []
    if conditions.if_match is not None:
        out += ["--if-match", _quote_etag(conditions.if_match)]
    if conditions.if_none_match is not None:
        out += ["--if-none-match", _quote_etag(conditions.if_none_match)]
    if conditions.if_modified_since is not None:
        out += ["--if-modified-since", conditions.if_modified_since.isoformat()]
    if conditions.if_unmodified_since is not None:
        out += ["--if-unmodified-since", conditions.if_unmodified_since.isoformat()]
    return out


def _copy_source_conditional_args(conditions: Conditions) -> list[str]:
    """Source-side conditional flags for `aws s3api copy-object` — these
    map to the `x-amz-copy-source-if-*` headers."""
    out: list[str] = []
    if conditions.if_match is not None:
        out += ["--copy-source-if-match", _quote_etag(conditions.if_match)]
    if conditions.if_none_match is not None:
        out += ["--copy-source-if-none-match", _quote_etag(conditions.if_none_match)]
    if conditions.if_modified_since is not None:
        out += ["--copy-source-if-modified-since", conditions.if_modified_since.isoformat()]
    if conditions.if_unmodified_since is not None:
        out += ["--copy-source-if-unmodified-since", conditions.if_unmodified_since.isoformat()]
    return out


def _object_from_aws(o: dict) -> S3Object:
    return S3Object(
        key=o["Key"],
        size=int(o["Size"]),
        etag=o["ETag"].strip('"'),
        last_modified=o["LastModified"],  # aws-cli emits ISO-8601 string already
    )
