"""Multipart upload coverage.

The gateway's multipart code (`crates/s32p-gateway/src/multipart.rs`) is
the most complex code path in the project — it has a fast path that
writes parts directly into a single `direct.bin` at computed offsets and
a fallback path that streams parts in order into a staging file.
Documented constraints (README):

- Parts must be contiguous from 1 at completion (`multipart.rs:1098-1106`).
- ETags are upload-time and not validated at completion.
- Direct placement requires part size <= assumed_part_size; assumed is
  pinned by part #1 OR by seeing two parts of equal size.
- Aborted/completed uploads must remove their `.s32p-mpu/uploads/<id>/` dir.

These tests pin the externally observable subset of those contracts. For
white-box assertions on which path was taken, look at gateway logs or the
`.s32p-mpu` state mid-upload.
"""

from __future__ import annotations

import pytest

from s32p_test.clients.base import S3Error
from s32p_test.clients.capabilities import Capability

# Small parts keep tests fast. The gateway doesn't enforce S3's 5 MiB minimum
# on non-last parts; if it ever starts to, these tests will tell us.
PART_SIZE = 256 * 1024


def _make_part(part_number: int, size: int = PART_SIZE) -> bytes:
    """Distinguishable byte pattern per part — failing assertions are
    readable ('part 2 corrupted at offset 0') rather than 'bytes diff'."""
    return bytes([part_number & 0xFF]) * size


pytestmark = pytest.mark.requires_capability(Capability.MULTIPART)


def test_basic_multipart_roundtrip(client, bucket):
    """Initiate, upload 3 uniform parts, complete, GET back, assert exact
    content. Uniform sizes hit the direct-placement fast path."""
    key = "mpu/uniform.bin"
    parts_data = [_make_part(i) for i in range(1, 4)]
    expected = b"".join(parts_data)

    upload_id = client.create_multipart(bucket, key)
    part_etags = [
        (i + 1, client.upload_part(bucket, key, upload_id, i + 1, data))
        for i, data in enumerate(parts_data)
    ]
    result = client.complete_multipart(bucket, key, upload_id, part_etags)
    assert result.etag

    got = client.get_object(bucket, key)
    assert got.content_length == len(expected)
    assert got.body == expected


def test_multipart_with_varying_part_sizes(client, bucket):
    """Parts with different sizes can't go through the direct-placement
    fast path (assumed_part_size never gets pinned), so this exercises
    the fallback assembly path. Final content must still be exact."""
    key = "mpu/varying.bin"
    sizes = [PART_SIZE, PART_SIZE // 2, PART_SIZE // 4]
    parts_data = [_make_part(i + 1, size=s) for i, s in enumerate(sizes)]
    expected = b"".join(parts_data)

    upload_id = client.create_multipart(bucket, key)
    part_etags = [
        (i + 1, client.upload_part(bucket, key, upload_id, i + 1, data))
        for i, data in enumerate(parts_data)
    ]
    client.complete_multipart(bucket, key, upload_id, part_etags)

    got = client.get_object(bucket, key)
    assert got.content_length == sum(sizes)
    assert got.body == expected


def test_abort_multipart_leaves_no_object(client, bucket):
    """After abort, HEAD on the would-be key must 404. The point: an
    in-progress multipart upload doesn't expose a partially-assembled
    object on the S3 surface."""
    key = "mpu/aborted.bin"
    upload_id = client.create_multipart(bucket, key)
    client.upload_part(bucket, key, upload_id, 1, _make_part(1))

    client.abort_multipart(bucket, key, upload_id)

    with pytest.raises(S3Error) as exc:
        client.head_object(bucket, key)
    assert exc.value.status == 404


def test_abort_multipart_clears_backend_upload_dir(client, bucket, bucket_fs):
    """Interop check: abort must remove the upload's working directory
    under .s32p-mpu/uploads/<upload_id>/. Otherwise aborted uploads
    accumulate as backend cruft visible to POSIX users."""
    key = "mpu/abort-cleanup.bin"
    upload_id = client.create_multipart(bucket, key)
    client.upload_part(bucket, key, upload_id, 1, _make_part(1))

    upload_dir = f".s32p-mpu/uploads/{upload_id}"
    assert bucket_fs.exists(upload_dir), (
        f"upload dir {upload_dir} not created on backend; "
        f"backend layout: {bucket_fs.listdir('.s32p-mpu/uploads') if bucket_fs.exists('.s32p-mpu/uploads') else 'no .s32p-mpu/uploads'}"
    )

    client.abort_multipart(bucket, key, upload_id)

    assert not bucket_fs.exists(upload_dir), (
        f"abort did not remove {upload_dir}"
    )


def test_complete_with_part_gap_fails(client, bucket):
    """Parts must be contiguous from 1 (multipart.rs:1098-1106).
    Uploading parts 1 and 3 (skipping 2) and then completing must fail;
    the partial upload is left behind for the client to abort."""
    key = "mpu/gappy.bin"
    upload_id = client.create_multipart(bucket, key)
    etag1 = client.upload_part(bucket, key, upload_id, 1, _make_part(1))
    etag3 = client.upload_part(bucket, key, upload_id, 3, _make_part(3))

    try:
        with pytest.raises(S3Error) as exc:
            client.complete_multipart(
                bucket, key, upload_id, [(1, etag1), (3, etag3)]
            )
        # Don't assert on the exact code/status — different gateway revisions
        # may pick InvalidRequest, InvalidPartOrder, etc. The contract is
        # "completion does not silently succeed with a gap."
        assert exc.value.status >= 400, (
            f"expected client/server error, got {exc.value!r}"
        )
    finally:
        # Don't leave the partial upload around — the bucket fixture wipes
        # data dirs but doesn't clean up multipart state through s3api.
        client.abort_multipart(bucket, key, upload_id)
