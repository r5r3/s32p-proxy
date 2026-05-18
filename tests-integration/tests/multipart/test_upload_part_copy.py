"""UploadPartCopy coverage.

UploadPartCopy is the S3 primitive SDKs reach for whenever a server-side
copy doesn't fit in a single CopyObject — most commonly for sources above
the 5 GiB CopyObject ceiling, but SDKs also use it as the default copy
path for sources well below that. Wire shape is identical to UploadPart
at the URL level; the `x-amz-copy-source` header is the only signal that
distinguishes the two (see `crates/s32p-gateway/src/multipart.rs`).

The gateway records a `total_size_hint` on the upload's meta.json when the
first part is an UploadPartCopy with no `copy-source-range` (the
single-source whole-file copy pattern). The hint feeds Lustre stripe-count
selection at `direct.bin` create. Several tests below assert the hint's
presence / first-write-wins semantics by reading meta.json directly.
"""

from __future__ import annotations

import json

import pytest

from s32p_test.clients.base import Conditions, CopyConditions, S3Error
from s32p_test.clients.capabilities import Capability

pytestmark = [
    pytest.mark.requires_capability(Capability.MULTIPART),
    pytest.mark.requires_capability(Capability.UPLOAD_PART_COPY),
]

# Small fixture sizes keep tests fast. The gateway has no enforced minimum
# part size for non-last parts.
SRC_SIZE_SMALL = 4 * 1024
SRC_SIZE_LARGE = 24 * 1024


def _payload(n: int, size: int) -> bytes:
    """Distinguishable repeating pattern; makes mismatch diagnostics readable."""
    return bytes([n & 0xFF]) * size


def _read_meta(bucket_fs, upload_id: str) -> dict:
    path = f".s32p-mpu/uploads/{upload_id}/meta.json"
    return json.loads(bucket_fs.read(path))


def test_upload_part_copy_basic_roundtrip(client, bucket):
    """One UploadPartCopy covering the whole source ⇒ destination object
    bytes identical to source."""
    src_data = _payload(0xAA, SRC_SIZE_SMALL)
    client.put_object(bucket, "src.bin", src_data)

    dst_key = "mpu/copy-basic.bin"
    upload_id = client.create_multipart(bucket, dst_key)

    part_etag = client.upload_part_copy(
        bucket, dst_key, upload_id, 1, bucket, "src.bin",
    )
    assert part_etag

    client.complete_multipart(bucket, dst_key, upload_id, [(1, part_etag)])

    got = client.get_object(bucket, dst_key)
    assert got.content_length == SRC_SIZE_SMALL
    assert got.body == src_data


def test_upload_part_copy_multi_part_with_range(client, bucket):
    """Split a single source object into three equal-sized parts via
    `copy-source-range`. Final destination concatenates back to the source."""
    src_data = _payload(0x5C, SRC_SIZE_LARGE)
    client.put_object(bucket, "src-large.bin", src_data)

    chunk = SRC_SIZE_LARGE // 3
    assert chunk * 3 == SRC_SIZE_LARGE, "test arithmetic"

    dst_key = "mpu/copy-multi.bin"
    upload_id = client.create_multipart(bucket, dst_key)

    parts: list[tuple[int, str]] = []
    for n in range(1, 4):
        start = (n - 1) * chunk
        end_inclusive = start + chunk - 1
        etag = client.upload_part_copy(
            bucket, dst_key, upload_id, n, bucket, "src-large.bin",
            copy_source_range=(start, end_inclusive),
        )
        parts.append((n, etag))

    client.complete_multipart(bucket, dst_key, upload_id, parts)

    got = client.get_object(bucket, dst_key)
    assert got.content_length == SRC_SIZE_LARGE
    assert got.body == src_data


def test_upload_part_copy_partial_range(client, bucket):
    """Slice copy: take bytes 100..199 of the source as the only part."""
    src_data = bytes(range(256)) * 4  # 1024 bytes of recognisable content
    client.put_object(bucket, "src-slice.bin", src_data)

    dst_key = "mpu/copy-slice.bin"
    upload_id = client.create_multipart(bucket, dst_key)

    part_etag = client.upload_part_copy(
        bucket, dst_key, upload_id, 1, bucket, "src-slice.bin",
        copy_source_range=(100, 199),
    )
    client.complete_multipart(bucket, dst_key, upload_id, [(1, part_etag)])

    got = client.get_object(bucket, dst_key)
    assert got.content_length == 100
    assert got.body == src_data[100:200]


def test_upload_part_copy_mixed_with_upload_part(client, bucket):
    """Part 1 via UploadPartCopy (whole source), part 2 via UploadPart
    (body upload). Final object is part1 || part2."""
    part1_data = _payload(0xAB, SRC_SIZE_SMALL)
    part2_data = _payload(0xCD, SRC_SIZE_SMALL)
    client.put_object(bucket, "src-mixed.bin", part1_data)

    dst_key = "mpu/copy-mixed.bin"
    upload_id = client.create_multipart(bucket, dst_key)

    etag1 = client.upload_part_copy(
        bucket, dst_key, upload_id, 1, bucket, "src-mixed.bin",
    )
    etag2 = client.upload_part(bucket, dst_key, upload_id, 2, part2_data)

    client.complete_multipart(
        bucket, dst_key, upload_id, [(1, etag1), (2, etag2)],
    )

    got = client.get_object(bucket, dst_key)
    assert got.content_length == 2 * SRC_SIZE_SMALL
    assert got.body == part1_data + part2_data


def test_upload_part_copy_source_if_match_success(client, bucket):
    """copy-source-if-match with the actual source ETag must succeed."""
    src_data = _payload(0x11, SRC_SIZE_SMALL)
    src_result = client.put_object(bucket, "src-cond.bin", src_data)

    dst_key = "mpu/copy-if-match.bin"
    upload_id = client.create_multipart(bucket, dst_key)
    etag = client.upload_part_copy(
        bucket, dst_key, upload_id, 1, bucket, "src-cond.bin",
        conditions=CopyConditions(source=Conditions(if_match=src_result.etag)),
    )
    client.complete_multipart(bucket, dst_key, upload_id, [(1, etag)])

    got = client.get_object(bucket, dst_key)
    assert got.body == src_data


def test_upload_part_copy_source_if_match_fail(client, bucket):
    """copy-source-if-match with a wrong ETag must return 412."""
    client.put_object(bucket, "src-cond-bad.bin", _payload(0x22, SRC_SIZE_SMALL))

    dst_key = "mpu/copy-if-match-bad.bin"
    upload_id = client.create_multipart(bucket, dst_key)
    try:
        with pytest.raises(S3Error) as exc:
            client.upload_part_copy(
                bucket, dst_key, upload_id, 1, bucket, "src-cond-bad.bin",
                conditions=CopyConditions(
                    source=Conditions(if_match="deadbeef-not-an-etag"),
                ),
            )
        assert exc.value.status == 412
    finally:
        try:
            client.abort_multipart(bucket, dst_key, upload_id)
        except S3Error as e:
            if e.status != 404:
                raise


def test_upload_part_copy_source_if_none_match_fail(client, bucket):
    """copy-source-if-none-match=* after the source exists must return 412."""
    client.put_object(bucket, "src-inm.bin", _payload(0x33, SRC_SIZE_SMALL))

    dst_key = "mpu/copy-if-none-match.bin"
    upload_id = client.create_multipart(bucket, dst_key)
    try:
        with pytest.raises(S3Error) as exc:
            client.upload_part_copy(
                bucket, dst_key, upload_id, 1, bucket, "src-inm.bin",
                conditions=CopyConditions(source=Conditions(if_none_match="*")),
            )
        assert exc.value.status == 412
    finally:
        try:
            client.abort_multipart(bucket, dst_key, upload_id)
        except S3Error as e:
            if e.status != 404:
                raise


def test_upload_part_copy_source_not_found(client, bucket):
    """UPC from a nonexistent source must return 404 (NoSuchKey)."""
    dst_key = "mpu/copy-missing-src.bin"
    upload_id = client.create_multipart(bucket, dst_key)
    try:
        with pytest.raises(S3Error) as exc:
            client.upload_part_copy(
                bucket, dst_key, upload_id, 1, bucket, "does-not-exist.bin",
            )
        assert exc.value.status == 404
    finally:
        try:
            client.abort_multipart(bucket, dst_key, upload_id)
        except S3Error as e:
            if e.status != 404:
                raise


def test_upload_part_copy_sets_total_size_hint_on_first_part(
    client, bucket, bucket_fs
):
    """First-part UPC with no `copy-source-range` ⇒ meta.json carries
    `total_size_hint == src_size`. This is the signal that drives Lustre
    stripe-count selection at direct.bin create."""
    src_data = _payload(0x44, SRC_SIZE_SMALL)
    client.put_object(bucket, "src-hint.bin", src_data)

    dst_key = "mpu/copy-hint.bin"
    upload_id = client.create_multipart(bucket, dst_key)
    client.upload_part_copy(
        bucket, dst_key, upload_id, 1, bucket, "src-hint.bin",
    )

    meta = _read_meta(bucket_fs, upload_id)
    assert meta.get("total_size_hint") == SRC_SIZE_SMALL, meta

    client.abort_multipart(bucket, dst_key, upload_id)


def test_upload_part_copy_no_hint_when_range_present(
    client, bucket, bucket_fs
):
    """If the first UPC carries a `copy-source-range`, the hint must NOT
    be set — a range copy doesn't tell us the destination's total size."""
    client.put_object(bucket, "src-range-only.bin", _payload(0x55, SRC_SIZE_LARGE))

    dst_key = "mpu/copy-range-no-hint.bin"
    upload_id = client.create_multipart(bucket, dst_key)
    client.upload_part_copy(
        bucket, dst_key, upload_id, 1, bucket, "src-range-only.bin",
        copy_source_range=(0, 99),
    )

    meta = _read_meta(bucket_fs, upload_id)
    assert meta.get("total_size_hint") is None, meta

    client.abort_multipart(bucket, dst_key, upload_id)


def test_upload_part_copy_hint_is_first_write_wins(
    client, bucket, bucket_fs
):
    """Once `total_size_hint` is set by part 1, a later UPC from a
    differently-sized source must NOT overwrite it. Striping is permanent
    at file create; second-thought updates buy nothing."""
    small = _payload(0x66, SRC_SIZE_SMALL)
    large = _payload(0x77, SRC_SIZE_LARGE)
    client.put_object(bucket, "src-first.bin", small)
    client.put_object(bucket, "src-second.bin", large)

    dst_key = "mpu/copy-stable-hint.bin"
    upload_id = client.create_multipart(bucket, dst_key)

    client.upload_part_copy(
        bucket, dst_key, upload_id, 1, bucket, "src-first.bin",
    )
    # Second-part UPC — different (larger) source, no range. The heuristic
    # is gated on `meta.parts.is_empty()` so this should never alter the
    # hint set by part 1.
    client.upload_part_copy(
        bucket, dst_key, upload_id, 2, bucket, "src-second.bin",
    )

    meta = _read_meta(bucket_fs, upload_id)
    assert meta.get("total_size_hint") == SRC_SIZE_SMALL, meta

    client.abort_multipart(bucket, dst_key, upload_id)
