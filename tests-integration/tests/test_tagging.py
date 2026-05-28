"""Object tagging end-to-end.

Tags are stored as the `user.s32p.tags` xattr on the object file (one
xattr, URL-form-encoded — the same shape as the `x-amz-tagging` header).
A freshly POSIX-created file has no xattr → empty `TagSet`. This file
pins both the wire shape (boto3 round-trip) and the storage model
(POSIX-created file shows up with no tags).

Bucket-level `?tagging` is out of scope and intentionally falls through
to the `other` route; not exercised here.
"""

from __future__ import annotations

import pytest
from botocore.exceptions import ClientError


# ---------------------------------------------------------------- round-trip


def test_put_then_get_tagging_roundtrip(boto3_raw, bucket):
    key = "tagging/rt-basic"
    boto3_raw.put_object(Bucket=bucket, Key=key, Body=b"x")
    boto3_raw.put_object_tagging(
        Bucket=bucket,
        Key=key,
        Tagging={"TagSet": [{"Key": "team", "Value": "a"}, {"Key": "stage", "Value": "raw"}]},
    )

    got = boto3_raw.get_object_tagging(Bucket=bucket, Key=key)
    pairs = {t["Key"]: t["Value"] for t in got["TagSet"]}
    assert pairs == {"team": "a", "stage": "raw"}


def test_put_object_with_x_amz_tagging_header(boto3_raw, bucket):
    """`x-amz-tagging` on PutObject populates the tag set at creation
    time. boto3 maps the `Tagging=` kwarg to the URL-form header."""
    key = "tagging/with-header"
    boto3_raw.put_object(Bucket=bucket, Key=key, Body=b"x", Tagging="team=a&stage=raw")

    got = boto3_raw.get_object_tagging(Bucket=bucket, Key=key)
    pairs = {t["Key"]: t["Value"] for t in got["TagSet"]}
    assert pairs == {"team": "a", "stage": "raw"}


def test_get_tagging_returns_empty_when_unset(boto3_raw, bucket):
    """A regular PUT (no tagging header) yields an empty tag set."""
    key = "tagging/no-tags"
    boto3_raw.put_object(Bucket=bucket, Key=key, Body=b"x")

    got = boto3_raw.get_object_tagging(Bucket=bucket, Key=key)
    assert got["TagSet"] == []


def test_delete_tagging_clears(boto3_raw, bucket):
    key = "tagging/clear-via-delete"
    boto3_raw.put_object(Bucket=bucket, Key=key, Body=b"x", Tagging="k=v")
    boto3_raw.delete_object_tagging(Bucket=bucket, Key=key)

    got = boto3_raw.get_object_tagging(Bucket=bucket, Key=key)
    assert got["TagSet"] == []


def test_empty_tagset_clears(boto3_raw, bucket):
    """PutObjectTagging with an empty `<TagSet/>` is equivalent to
    DeleteObjectTagging. The gateway maps "no pairs" to `removexattr`."""
    key = "tagging/clear-via-empty-put"
    boto3_raw.put_object(Bucket=bucket, Key=key, Body=b"x", Tagging="k=v")
    boto3_raw.put_object_tagging(Bucket=bucket, Key=key, Tagging={"TagSet": []})

    got = boto3_raw.get_object_tagging(Bucket=bucket, Key=key)
    assert got["TagSet"] == []


def test_put_tagging_replaces_existing(boto3_raw, bucket):
    """PutObjectTagging is whole-set atomic: the new set fully replaces
    the previous set (it doesn't merge)."""
    key = "tagging/replace"
    boto3_raw.put_object(Bucket=bucket, Key=key, Body=b"x", Tagging="a=1&b=2")
    boto3_raw.put_object_tagging(
        Bucket=bucket,
        Key=key,
        Tagging={"TagSet": [{"Key": "c", "Value": "3"}]},
    )

    pairs = {t["Key"]: t["Value"] for t in boto3_raw.get_object_tagging(Bucket=bucket, Key=key)["TagSet"]}
    assert pairs == {"c": "3"}, f"old keys leaked: {pairs!r}"


# ---------------------------------------------------------------- CopyObject directive


def test_copy_object_default_directive_mirrors_source_tags(boto3_raw, bucket):
    """Default directive is COPY: destination inherits source tags
    without any `x-amz-tagging-directive` header on the request."""
    src_key = "tagging/copy-src"
    dst_key = "tagging/copy-dst-default"
    boto3_raw.put_object(Bucket=bucket, Key=src_key, Body=b"src", Tagging="stage=raw")
    boto3_raw.copy_object(
        Bucket=bucket,
        Key=dst_key,
        CopySource={"Bucket": bucket, "Key": src_key},
    )

    pairs = {t["Key"]: t["Value"] for t in boto3_raw.get_object_tagging(Bucket=bucket, Key=dst_key)["TagSet"]}
    assert pairs == {"stage": "raw"}


def test_copy_object_replace_with_header_sets_new_tags(boto3_raw, bucket):
    src_key = "tagging/copy-src-replace"
    dst_key = "tagging/copy-dst-replace"
    boto3_raw.put_object(Bucket=bucket, Key=src_key, Body=b"src", Tagging="stage=raw")
    boto3_raw.copy_object(
        Bucket=bucket,
        Key=dst_key,
        CopySource={"Bucket": bucket, "Key": src_key},
        TaggingDirective="REPLACE",
        Tagging="stage=done",
    )

    pairs = {t["Key"]: t["Value"] for t in boto3_raw.get_object_tagging(Bucket=bucket, Key=dst_key)["TagSet"]}
    assert pairs == {"stage": "done"}, f"REPLACE did not apply new tags: {pairs!r}"


def test_copy_object_replace_no_header_clears_tags(boto3_raw, bucket):
    """`TaggingDirective=REPLACE` without an `x-amz-tagging` header
    explicitly clears the destination's tags — even when the source
    had tags."""
    src_key = "tagging/copy-src-replace-clear"
    dst_key = "tagging/copy-dst-replace-clear"
    boto3_raw.put_object(Bucket=bucket, Key=src_key, Body=b"src", Tagging="stage=raw")
    boto3_raw.copy_object(
        Bucket=bucket,
        Key=dst_key,
        CopySource={"Bucket": bucket, "Key": src_key},
        TaggingDirective="REPLACE",
    )

    got = boto3_raw.get_object_tagging(Bucket=bucket, Key=dst_key)
    assert got["TagSet"] == [], f"REPLACE with no header should clear, got {got['TagSet']!r}"


# ---------------------------------------------------------------- POSIX interop


def test_posix_created_file_returns_empty_tagset(boto3_raw, bucket, bucket_fs):
    """A file dropped into the bucket directly via POSIX has no xattr
    on it — `GetObjectTagging` must return an empty set (not 500, not
    NoSuchKey). This is the load-bearing invariant: POSIX-created files
    are still valid S3 objects, just tagless."""
    bucket_fs.write("posix-only", b"hello from posix\n")

    got = boto3_raw.get_object_tagging(Bucket=bucket, Key="posix-only")
    assert got["TagSet"] == []


# ---------------------------------------------------------------- validation


def test_too_many_tags_rejected(boto3_raw, bucket):
    """S3 caps the tag set at 10 pairs; the gateway uses the AWS code
    `InvalidTag` for all shape violations (not `TooManyTags`)."""
    key = "tagging/too-many"
    boto3_raw.put_object(Bucket=bucket, Key=key, Body=b"x")
    too_many = {"TagSet": [{"Key": f"k{i}", "Value": str(i)} for i in range(11)]}

    with pytest.raises(ClientError) as exc:
        boto3_raw.put_object_tagging(Bucket=bucket, Key=key, Tagging=too_many)
    assert exc.value.response["Error"]["Code"] == "InvalidTag"
    assert exc.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400


def test_key_too_long_rejected(boto3_raw, bucket):
    """Tag key longer than 128 chars → InvalidTag."""
    key = "tagging/key-too-long"
    boto3_raw.put_object(Bucket=bucket, Key=key, Body=b"x")
    bad = {"TagSet": [{"Key": "k" * 129, "Value": "v"}]}

    with pytest.raises(ClientError) as exc:
        boto3_raw.put_object_tagging(Bucket=bucket, Key=key, Tagging=bad)
    assert exc.value.response["Error"]["Code"] == "InvalidTag"


def test_invalid_tagging_header_on_put_rejected(boto3_raw, bucket):
    """`x-amz-tagging` header containing too many pairs is rejected
    before the object is materialized."""
    too_many = "&".join(f"k{i}={i}" for i in range(11))

    with pytest.raises(ClientError) as exc:
        boto3_raw.put_object(
            Bucket=bucket,
            Key="tagging/header-too-many",
            Body=b"x",
            Tagging=too_many,
        )
    assert exc.value.response["Error"]["Code"] == "InvalidTag"

    # Object must not exist after the rejected PUT.
    with pytest.raises(ClientError) as exc2:
        boto3_raw.head_object(Bucket=bucket, Key="tagging/header-too-many")
    assert exc2.value.response["ResponseMetadata"]["HTTPStatusCode"] == 404


# ---------------------------------------------------------------- LastModified


def test_tag_put_does_not_change_lastmodified(boto3_raw, bucket):
    """AWS S3 does not bump `LastModified` on tag mutations. On Linux,
    `setxattr` updates ctime only (not mtime), so we get this for free
    — but pin the invariant so a future implementation change can't
    silently regress."""
    key = "tagging/lastmod"
    boto3_raw.put_object(Bucket=bucket, Key=key, Body=b"x")
    before = boto3_raw.head_object(Bucket=bucket, Key=key)["LastModified"]

    boto3_raw.put_object_tagging(
        Bucket=bucket,
        Key=key,
        Tagging={"TagSet": [{"Key": "k", "Value": "v"}]},
    )
    after = boto3_raw.head_object(Bucket=bucket, Key=key)["LastModified"]

    assert before == after, f"LastModified shifted across tag PUT: {before} -> {after}"
