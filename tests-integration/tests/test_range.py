"""Range request coverage.

README contract: "Supports single-range `Range: bytes=...` (returns
`206 Partial Content`; invalid ranges return `416 InvalidRange`)."

The S3Client abstraction only models closed inclusive ranges
(`range_=(start, end)`). Open-ended ranges (`bytes=10-`) and suffix
ranges (`bytes=-100`) would need adapter support — out of scope here.
"""

from __future__ import annotations

import pytest

from s32p_test.clients.base import S3Error
from s32p_test.clients.capabilities import Capability


pytestmark = pytest.mark.requires_capability(Capability.RANGE_REQUESTS)


def _distinct_body(n: int) -> bytes:
    """Body where byte i = i % 256 — every byte position is identifiable
    by value so off-by-ones in slicing are visible."""
    return bytes(i % 256 for i in range(n))


def test_range_returns_exact_slice(client, bucket):
    """`Range: bytes=10-19` returns exactly bytes [10..19] inclusive
    (10 bytes total). Easy to misread as exclusive — pin it."""
    body = _distinct_body(1024)
    client.put_object(bucket, "rng.bin", body)

    got = client.get_object(bucket, "rng.bin", range_=(10, 19))
    assert got.body == body[10:20]
    assert got.content_length == 10


def test_range_at_end_of_file(client, bucket):
    """A range whose end is exactly the last byte index works (no
    off-by-one against EOF)."""
    body = _distinct_body(100)
    client.put_object(bucket, "rng.bin", body)

    got = client.get_object(bucket, "rng.bin", range_=(50, 99))
    assert got.body == body[50:100]
    assert got.content_length == 50


def test_invalid_range_returns_416(client, bucket):
    """A range that starts past EOF must produce 416 InvalidRange. The
    object is small (5 bytes); the request asks for bytes 100-200."""
    client.put_object(bucket, "rng.bin", b"short")

    with pytest.raises(S3Error) as exc:
        client.get_object(bucket, "rng.bin", range_=(100, 200))
    assert exc.value.status == 416, f"expected 416, got {exc.value!r}"
