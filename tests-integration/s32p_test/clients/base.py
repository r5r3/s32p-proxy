"""S3 client matrix base class.

Every client adapter (boto3, aws-cli, mcli, ...) subclasses S3Client and
implements the abstract operations against its native SDK or binary. Tests
take the abstract `client` fixture and never reach into the native SDK
unless they explicitly want client-specific behavior.

Design notes:
- Operations return normalized dataclasses, not SDK-native types. Clients
  that surface less detail (e.g. mcli prints to stdout) fill in what they
  can and leave the rest at defaults.
- Errors are raised as `S3Error` carrying the AWS short code + HTTP status.
  Each adapter is responsible for mapping its native exceptions onto this.
- Capability-gated operations have default implementations that raise
  NotImplementedError, so a test using them on a non-supporting client gets
  skipped via the matrix fixture rather than crashing.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import ClassVar

from .capabilities import Capability


# ---------------------------------------------------------------- response types


@dataclass(slots=True)
class S3Object:
    key: str
    size: int
    etag: str
    last_modified: str  # ISO-8601, normalized by the adapter


@dataclass(slots=True)
class ListResult:
    objects: list[S3Object] = field(default_factory=list)
    common_prefixes: list[str] = field(default_factory=list)
    is_truncated: bool = False
    next_continuation_token: str | None = None


@dataclass(slots=True)
class GetResult:
    body: bytes
    etag: str
    content_length: int
    content_type: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class PutResult:
    etag: str


# ---------------------------------------------------------------- error type


class S3Error(Exception):
    """Normalized S3 error.

    `code` is the AWS short code (e.g. "NoSuchKey", "AccessDenied",
    "NotImplemented"). `status` is the HTTP status. `message` is the
    server-supplied error message (may be empty for clients that don't
    expose it).
    """

    def __init__(self, code: str, status: int, message: str = ""):
        super().__init__(f"{code} ({status}): {message}")
        self.code = code
        self.status = status
        self.message = message


# ---------------------------------------------------------------- endpoint config


@dataclass(slots=True)
class Endpoint:
    base_url: str          # e.g. "http://127.0.0.1:9000"
    region: str
    access_key: str
    secret_key: str
    # If set, virtual-hosted-style addressing is available; the adapter
    # rewrites the request URL when `addressing="virtual"`.
    virtual_hosted_suffix: str | None = None


# ---------------------------------------------------------------- ABC


class S3Client(ABC):
    """Abstract S3 client. One subclass per backing tool/SDK."""

    #: Stable name used for parametrize ids and --clients filtering.
    name: ClassVar[str] = "<override>"

    #: Capability set; tests check via the matrix fixture.
    capabilities: ClassVar[set[Capability]] = set()

    #: Filled by __init_subclass__; maps name -> class.
    registry: ClassVar[dict[str, type["S3Client"]]] = {}

    def __init_subclass__(cls, **kw):
        super().__init_subclass__(**kw)
        if cls.name == "<override>":
            raise TypeError(f"{cls.__name__} must set `name` class attr")
        if cls.name in S3Client.registry:
            raise RuntimeError(
                f"duplicate client name '{cls.name}' "
                f"({cls.__module__} vs {S3Client.registry[cls.name].__module__})"
            )
        S3Client.registry[cls.name] = cls

    def __init__(self, endpoint: Endpoint, *, addressing: str = "path"):
        if addressing not in ("path", "virtual"):
            raise ValueError(f"addressing must be path|virtual, got {addressing!r}")
        if addressing == "virtual" and endpoint.virtual_hosted_suffix is None:
            raise ValueError("virtual addressing requires endpoint.virtual_hosted_suffix")
        self.endpoint = endpoint
        self.addressing = addressing

    def supports(self, cap: Capability) -> bool:
        return cap in self.capabilities

    # ----- buckets -----

    @abstractmethod
    def list_buckets(self) -> list[str]: ...

    @abstractmethod
    def head_bucket(self, bucket: str) -> bool:
        """Returns True if the bucket exists and the caller can access it."""

    # ----- objects -----

    @abstractmethod
    def put_object(
        self,
        bucket: str,
        key: str,
        body: bytes,
        *,
        content_type: str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> PutResult: ...

    @abstractmethod
    def get_object(
        self,
        bucket: str,
        key: str,
        *,
        range_: tuple[int, int] | None = None,  # inclusive byte range
    ) -> GetResult: ...

    @abstractmethod
    def head_object(self, bucket: str, key: str) -> GetResult:
        """Like get_object() but body is b''."""

    @abstractmethod
    def delete_object(self, bucket: str, key: str) -> None: ...

    @abstractmethod
    def list_objects(
        self,
        bucket: str,
        *,
        prefix: str = "",
        delimiter: str | None = None,
        max_keys: int | None = None,
        continuation_token: str | None = None,
        v1: bool = False,
    ) -> ListResult: ...

    # ----- capability-gated; default impls raise so the matrix fixture skips -----

    def copy_object(self, src_bucket, src_key, dst_bucket, dst_key) -> PutResult:
        raise NotImplementedError(f"{self.name}: COPY_OBJECT not implemented")

    def delete_objects(self, bucket: str, keys: list[str]) -> list[str]:
        raise NotImplementedError(f"{self.name}: DELETE_OBJECTS not implemented")

    def create_multipart(self, bucket: str, key: str) -> str:
        raise NotImplementedError(f"{self.name}: MULTIPART not implemented")

    def upload_part(
        self, bucket: str, key: str, upload_id: str, part_number: int, body: bytes
    ) -> str:
        """Returns the part ETag."""
        raise NotImplementedError(f"{self.name}: MULTIPART not implemented")

    def complete_multipart(
        self, bucket: str, key: str, upload_id: str, parts: list[tuple[int, str]]
    ) -> PutResult:
        raise NotImplementedError(f"{self.name}: MULTIPART not implemented")

    def abort_multipart(self, bucket: str, key: str, upload_id: str) -> None:
        raise NotImplementedError(f"{self.name}: MULTIPART not implemented")

    def rename_object(self, bucket: str, src_key: str, dst_key: str) -> None:
        raise NotImplementedError(f"{self.name}: RENAME_OBJECT not implemented")

    def presign_get(self, bucket: str, key: str, *, expires: int = 60) -> str:
        raise NotImplementedError(f"{self.name}: PRESIGN_GET not implemented")
