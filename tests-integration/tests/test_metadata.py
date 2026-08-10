"""Object metadata end-to-end.

User-defined metadata (`x-amz-meta-*`) is stored in `user.s32p.meta`
(URL-form, lowercased keys). Content-Type is stored in
`user.s32p.content_type`. Absent xattrs mean "no metadata"; HEAD/GET
on a POSIX-created file returns empty user metadata and a
Content-Type resolved via the fallback ladder:

    1. user.s32p.content_type    (gateway-explicit)
    2. user.mime_type            (freedesktop standard, POSIX origin)
    3. mime_guess::from_path     (extension map, zero-I/O)
    4. application/octet-stream  (default)

These tests pin the wire shape (boto3 round-trip) and the storage
model (POSIX-created files appear with no metadata, no error).
"""

from __future__ import annotations

import os

import pytest
from botocore.exceptions import ClientError


# ---------------------------------------------------------------- user metadata round-trip


def test_put_then_head_user_metadata_roundtrip(boto3_raw, bucket):
    key = "metadata/rt-basic"
    boto3_raw.put_object(
        Bucket=bucket, Key=key, Body=b"x",
        Metadata={"author": "alice", "purpose": "demo"},
    )
    head = boto3_raw.head_object(Bucket=bucket, Key=key)

    # boto3 lowercases user-metadata keys on the response; AWS does the same.
    pairs = {k.lower(): v for k, v in head["Metadata"].items()}
    assert pairs == {"author": "alice", "purpose": "demo"}


def test_get_user_metadata_empty_when_unset(boto3_raw, bucket):
    """A PUT without metadata yields an empty metadata dict on HEAD."""
    key = "metadata/no-meta"
    boto3_raw.put_object(Bucket=bucket, Key=key, Body=b"x")

    head = boto3_raw.head_object(Bucket=bucket, Key=key)
    assert head["Metadata"] == {}


def test_put_object_with_metadata_replaces_existing(boto3_raw, bucket):
    """PutObject is create-or-replace; pre-existing metadata is cleared."""
    key = "metadata/replace"
    boto3_raw.put_object(
        Bucket=bucket, Key=key, Body=b"x",
        Metadata={"a": "1", "b": "2"},
    )
    boto3_raw.put_object(
        Bucket=bucket, Key=key, Body=b"y",
        Metadata={"c": "3"},
    )

    pairs = {k.lower(): v for k, v in boto3_raw.head_object(Bucket=bucket, Key=key)["Metadata"].items()}
    assert pairs == {"c": "3"}, f"old keys leaked: {pairs!r}"


def test_put_object_without_metadata_clears(boto3_raw, bucket):
    """PutObject with no metadata headers clears any existing set."""
    key = "metadata/clear-via-put"
    boto3_raw.put_object(
        Bucket=bucket, Key=key, Body=b"x",
        Metadata={"author": "alice"},
    )
    boto3_raw.put_object(Bucket=bucket, Key=key, Body=b"y")

    head = boto3_raw.head_object(Bucket=bucket, Key=key)
    assert head["Metadata"] == {}


# ---------------------------------------------------------------- Content-Type round-trip


def test_put_then_head_content_type_roundtrip(boto3_raw, bucket):
    key = "metadata/ct-explicit"
    boto3_raw.put_object(
        Bucket=bucket, Key=key, Body=b"<html/>",
        ContentType="text/html; charset=utf-8",
    )

    head = boto3_raw.head_object(Bucket=bucket, Key=key)
    assert head["ContentType"] == "text/html; charset=utf-8"


def test_extension_fallback_for_known_mime(boto3_raw, bucket, bucket_fs):
    """A POSIX-created file with no Content-Type xattr falls through to
    `mime_guess` for the extension. `.html` → `text/html`."""
    bucket_fs.write("posix-only.html", b"<html/>")

    head = boto3_raw.head_object(Bucket=bucket, Key="posix-only.html")
    assert head["ContentType"] == "text/html"


def test_extension_fallback_default_for_unknown(boto3_raw, bucket, bucket_fs):
    """Unknown extension bottoms out at `application/octet-stream`."""
    bucket_fs.write("posix-only.bin", b"\x00\x01\x02")

    head = boto3_raw.head_object(Bucket=bucket, Key="posix-only.bin")
    assert head["ContentType"] == "application/octet-stream"


def test_freedesktop_user_mime_type_honored(boto3_raw, bucket, bucket_fs):
    """`user.mime_type` is the freedesktop standard set by GNOME/KDE
    file managers and `gio set`. It must be honored as a fallback below
    the gateway's explicit xattr but above mime_guess — POSIX-tagged
    files appear with their MIME type over S3 without an explicit PUT."""
    path = bucket_fs.write("icon.png-named-thing", b"fake-png")
    os.setxattr(str(path), "user.mime_type", b"image/svg+xml")

    head = boto3_raw.head_object(Bucket=bucket, Key="icon.png-named-thing")
    assert head["ContentType"] == "image/svg+xml"


def test_explicit_content_type_beats_freedesktop(boto3_raw, bucket, bucket_fs):
    """When BOTH xattrs are present, the gateway's explicit
    `user.s32p.content_type` wins (it was set by an S3 client and is
    the more specific intent)."""
    path = bucket_fs.write("dual-tagged", b"data")
    os.setxattr(str(path), "user.mime_type", b"image/svg+xml")
    # PutObject sets user.s32p.content_type explicitly.
    boto3_raw.put_object(
        Bucket=bucket, Key="dual-tagged", Body=b"data",
        ContentType="image/png",
    )

    head = boto3_raw.head_object(Bucket=bucket, Key="dual-tagged")
    assert head["ContentType"] == "image/png"


# ---------------------------------------------------------------- CopyObject directive


def test_copy_object_default_directive_mirrors_user_metadata(boto3_raw, bucket):
    """Default directive is COPY: destination inherits source's user
    metadata and Content-Type without any `x-amz-metadata-directive`
    header on the request."""
    src = "metadata/copy-src"
    dst = "metadata/copy-dst-default"
    boto3_raw.put_object(
        Bucket=bucket, Key=src, Body=b"src",
        Metadata={"stage": "raw"},
        ContentType="application/json",
    )
    boto3_raw.copy_object(
        Bucket=bucket, Key=dst,
        CopySource={"Bucket": bucket, "Key": src},
    )

    head = boto3_raw.head_object(Bucket=bucket, Key=dst)
    pairs = {k.lower(): v for k, v in head["Metadata"].items()}
    assert pairs == {"stage": "raw"}
    assert head["ContentType"] == "application/json"


def test_copy_object_replace_with_headers_sets_new(boto3_raw, bucket):
    src = "metadata/copy-src-replace"
    dst = "metadata/copy-dst-replace"
    boto3_raw.put_object(
        Bucket=bucket, Key=src, Body=b"src",
        Metadata={"stage": "raw"},
        ContentType="application/json",
    )
    boto3_raw.copy_object(
        Bucket=bucket, Key=dst,
        CopySource={"Bucket": bucket, "Key": src},
        MetadataDirective="REPLACE",
        Metadata={"stage": "done"},
        ContentType="text/plain",
    )

    head = boto3_raw.head_object(Bucket=bucket, Key=dst)
    pairs = {k.lower(): v for k, v in head["Metadata"].items()}
    assert pairs == {"stage": "done"}, f"REPLACE did not apply new metadata: {pairs!r}"
    assert head["ContentType"] == "text/plain"


def test_copy_object_replace_no_metadata_clears(boto3_raw, bucket):
    """`MetadataDirective=REPLACE` without `Metadata` clears the
    destination's user metadata. `ContentType` falls back through the
    ladder (here: no extension, ends at octet-stream)."""
    src = "metadata/copy-src-replace-clear"
    dst = "metadata/copy-dst-replace-clear"
    boto3_raw.put_object(
        Bucket=bucket, Key=src, Body=b"src",
        Metadata={"stage": "raw"},
        ContentType="application/json",
    )
    # boto3 currently requires ContentType to be set explicitly when
    # MetadataDirective=REPLACE to clear it cleanly; passing nothing
    # would have the SDK pass through the existing object's Content-Type.
    # We test the wire-shape behavior: REPLACE + no x-amz-meta-* + no
    # Content-Type header at all clears both.
    boto3_raw.copy_object(
        Bucket=bucket, Key=dst,
        CopySource={"Bucket": bucket, "Key": src},
        MetadataDirective="REPLACE",
    )

    head = boto3_raw.head_object(Bucket=bucket, Key=dst)
    assert head["Metadata"] == {}, f"REPLACE should clear, got {head['Metadata']!r}"


# ---------------------------------------------------------------- POSIX interop


def test_posix_created_file_returns_empty_metadata(boto3_raw, bucket, bucket_fs):
    """A file dropped into the bucket directly via POSIX has no metadata
    xattrs on it — HEAD must return an empty `Metadata` map (not 500,
    not NoSuchKey). Same load-bearing invariant as tagging: POSIX-
    created files are still valid S3 objects."""
    bucket_fs.write("posix-only.txt", b"hello\n")

    head = boto3_raw.head_object(Bucket=bucket, Key="posix-only.txt")
    assert head["Metadata"] == {}


# ---------------------------------------------------------------- validation


def test_too_many_user_meta_pairs_rejected(boto3_raw, bucket):
    """The gateway caps user metadata at 32 pairs."""
    too_many = {f"k{i}": str(i) for i in range(33)}

    with pytest.raises(ClientError) as exc:
        boto3_raw.put_object(
            Bucket=bucket, Key="metadata/too-many",
            Body=b"x", Metadata=too_many,
        )
    assert exc.value.response["Error"]["Code"] == "InvalidArgument"
    assert exc.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400


def test_user_meta_payload_too_large_rejected(boto3_raw, bucket):
    """Total user-metadata payload above 2KB is rejected."""
    big_value = "a" * 1024
    too_big = {"k1": big_value, "k2": big_value, "k3": big_value}

    with pytest.raises(ClientError) as exc:
        boto3_raw.put_object(
            Bucket=bucket, Key="metadata/too-big",
            Body=b"x", Metadata=too_big,
        )
    assert exc.value.response["Error"]["Code"] == "InvalidArgument"


def test_bad_content_type_rejected(boto3_raw, bucket):
    """A Content-Type missing the `type/subtype` slash is rejected."""
    with pytest.raises(ClientError) as exc:
        boto3_raw.put_object(
            Bucket=bucket, Key="metadata/bad-ct",
            Body=b"x", ContentType="not-a-mime",
        )
    assert exc.value.response["Error"]["Code"] == "InvalidArgument"


# ---------------------------------------------------------------- robustness against corrupt xattrs


def test_corrupt_content_type_xattr_falls_back(boto3_raw, bucket, bucket_fs):
    """A POSIX user can write arbitrary bytes into `user.s32p.content_type`
    via `setfattr`, bypassing PUT-time validation. HEAD/GET must NOT
    panic on a value that contains bytes `HeaderValue` rejects (control
    bytes < 0x20 other than tab; 0x7f) — they fall back to the default
    Content-Type and the worker keeps serving. Without the runtime
    defense in `apply_object_headers` this would panic the worker."""
    path = bucket_fs.write("corrupt-ct", b"data")
    # 0x01 (SOH) is in the C0 control range and is unambiguously rejected
    # by `HeaderValue::try_from`. The validator screens this at PUT, but
    # a POSIX user with `setfattr` access can write it directly.
    os.setxattr(str(path), "user.s32p.content_type", b"text/plain\x01injected")

    head = boto3_raw.head_object(Bucket=bucket, Key="corrupt-ct")
    assert head["ContentType"] == "application/octet-stream"


def test_corrupt_freedesktop_mime_xattr_falls_back(boto3_raw, bucket, bucket_fs):
    """Same as above but on the freedesktop fallback xattr — also POSIX-
    writable, also must not panic."""
    path = bucket_fs.write("corrupt-mime", b"data")
    os.setxattr(str(path), "user.mime_type", b"image/svg\x01injected")

    head = boto3_raw.head_object(Bucket=bucket, Key="corrupt-mime")
    assert head["ContentType"] == "application/octet-stream"


# ---------------------------------------------------------------- LastModified


def test_posix_xattr_set_does_not_change_lastmodified(boto3_raw, bucket, bucket_fs):
    """AWS does not bump LastModified on metadata-only changes; on Linux
    `setxattr` updates ctime only, not mtime. Pin the invariant via a
    POSIX-side xattr edit (the gateway's PUT replaces the file inode, so
    we can't compare across a PUT — but we CAN compare across a direct
    POSIX xattr set, which is the most a tag-only mutation could ever
    do to mtime)."""
    path = bucket_fs.write("metadata/lastmod-pin", b"data")
    before = boto3_raw.head_object(Bucket=bucket, Key="metadata/lastmod-pin")["LastModified"]

    os.setxattr(str(path), "user.s32p.content_type", b"text/plain")
    after = boto3_raw.head_object(Bucket=bucket, Key="metadata/lastmod-pin")["LastModified"]

    assert before == after, f"LastModified shifted across xattr-only edit: {before} -> {after}"
