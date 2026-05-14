"""Capability flags advertised by each client adapter.

Tests that need a capability declare it via `pytest.mark.requires_capability(X)`
and the matrix fixture skips clients that lack it. Keeping this in its own
module so the set is grep-able and adding a new capability is one diff.
"""

from __future__ import annotations

from enum import Enum, auto


class Capability(Enum):
    # Core
    PATH_STYLE = auto()
    VIRTUAL_HOSTED = auto()
    RANGE_REQUESTS = auto()
    LIST_V1 = auto()
    LIST_V2 = auto()
    COPY_OBJECT = auto()
    DELETE_OBJECTS = auto()  # POST /?delete bulk delete
    METADATA = auto()        # x-amz-meta-* round-trip

    # Multipart
    MULTIPART = auto()

    # ACL (s32p maps these onto POSIX state; many clients can drive them)
    OBJECT_ACL = auto()
    BUCKET_ACL = auto()

    # s32p extension
    RENAME_OBJECT = auto()

    # Signing
    PRESIGN_GET = auto()
    PRESIGN_PUT = auto()
    UNSIGNED_PAYLOAD = auto()
