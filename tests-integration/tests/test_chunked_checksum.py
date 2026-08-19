"""aws-chunked uploads that carry no `Content-Length`.

Since botocore 1.36 the AWS SDKs default `request_checksum_calculation`
to `when_supported`, attaching a CRC32 to every upload. Where that
checksum travels depends on the endpoint scheme
(`botocore/httpchecksum.py::resolve_request_checksum_algorithm`): for an
operation with streaming input over **https** it is not a header but a
trailer, and `_apply_request_trailer_checksum` then rewrites the request
to

    Content-Encoding: aws-chunked
    Transfer-Encoding: chunked
    X-Amz-Trailer: x-amz-checksum-crc32
    X-Amz-Decoded-Content-Length: <logical size>
    X-Amz-Content-SHA256: STREAMING-UNSIGNED-PAYLOAD-TRAILER

*deleting* `Content-Length` in the process. The logical body size then
lives only in `x-amz-decoded-content-length` — which is exactly what
`compute_logical_len` already reads for `STREAMING-*` payloads.

The harness drives the proxy over plain HTTP, where botocore keeps the
checksum in a header and `Content-Length` survives, so no stock client in
the matrix can produce this shape. These tests build it explicitly. The
framing comes from botocore's own `AwsChunkedWrapper` (byte-exact with
what a real SDK emits, terminator and trailer included) and the request
is signed as `STREAMING-UNSIGNED-PAYLOAD-TRAILER`, which `SigV4Auth`
selects when the request context marks the checksum as trailer-located
(`botocore/auth.py::_is_streaming_checksum_payload`).

Handlers:  crates/s32p-gateway/src/main.rs::handle_put_object
           crates/s32p-gateway/src/multipart.rs::handle_upload_part
Length:    crates/s32p-gateway/src/main.rs::compute_logical_len
Framing:   crates/s32p-gateway/src/streaming.rs::aws_chunked
"""

from __future__ import annotations

import io
import os
import stat
from urllib.parse import quote

import botocore.auth
import botocore.awsrequest
import botocore.credentials
import requests
from botocore.httpchecksum import AwsChunkedWrapper, Crc32Checksum

# The trailer botocore appends for the default CRC32 algorithm.
CHECKSUM_TRAILER = "x-amz-checksum-crc32"

# Read granularity when pumping the encoder into the request body. Small
# enough that a multi-MiB part spans several aws-chunked chunks, so the
# decoder's chunk-boundary handling is exercised too.
_READ_SIZE = 64 * 1024


def _chunked_stream(data: bytes):
    """Yield `data` in botocore's aws-chunked framing.

    Handing `requests` a generator is what forces `Transfer-Encoding:
    chunked` with no `Content-Length` on the wire — the same shape
    botocore produces after it deletes the header.
    """
    wrapper = AwsChunkedWrapper(
        io.BytesIO(data),
        checksum_cls=Crc32Checksum,
        checksum_name=CHECKSUM_TRAILER,
    )
    while True:
        chunk = wrapper.read(_READ_SIZE)
        if not chunk:
            return
        yield chunk


def _put_chunked(
    endpoint,
    *,
    bucket: str,
    key: str,
    body: bytes,
    query: str = "",
) -> requests.Response:
    """SigV4-signed `PUT` of `body` as an aws-chunked, trailer-checksummed,
    `Content-Length`-less request."""
    url = f"{endpoint.base_url}/{bucket}/{quote(key, safe='/')}{query}"
    headers = {
        "x-amz-content-sha256": "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
        "content-encoding": "aws-chunked",
        "x-amz-trailer": CHECKSUM_TRAILER,
        "x-amz-decoded-content-length": str(len(body)),
        "x-amz-sdk-checksum-algorithm": "CRC32",
    }

    creds = botocore.credentials.Credentials(endpoint.access_key, endpoint.secret_key)
    # Signing over an empty body is correct here: the trailer marker
    # replaces the payload hash, so the body bytes never enter the
    # canonical request.
    req = botocore.awsrequest.AWSRequest(method="PUT", url=url, data=b"", headers=headers)
    req.context["checksum"] = {"request_algorithm": {"in": "trailer"}}
    botocore.auth.SigV4Auth(creds, "s3", endpoint.region).add_auth(req)

    return requests.put(
        url,
        data=_chunked_stream(body),
        headers=dict(req.headers.items()),
        timeout=30,
    )


def test_put_object_aws_chunked_without_content_length(endpoint, bucket, bucket_fs):
    """The reported failure: a default-configured boto3 client against an
    https endpoint sends exactly this and gets `InvalidRequest`."""
    key = "chunked/probe.dat"
    body = os.urandom(1024)

    resp = _put_chunked(endpoint, bucket=bucket, key=key, body=body)

    assert resp.status_code == 200, f"PUT {key}: {resp.status_code} {resp.text}"
    assert bucket_fs.read(key) == body


def test_put_directory_marker_aws_chunked_without_content_length(
    endpoint, bucket, bucket_fs
):
    """Directory markers take their own branch that demands an explicit
    `Content-Length: 0`; a zero-length aws-chunked body has none."""
    key = "chunked-dir/"

    resp = _put_chunked(endpoint, bucket=bucket, key=key, body=b"")

    assert resp.status_code == 200, f"PUT {key}: {resp.status_code} {resp.text}"
    assert stat.S_ISDIR(bucket_fs.stat("chunked-dir").st_mode)


def test_upload_part_aws_chunked_without_content_length(
    endpoint, bucket, bucket_fs, boto3_raw
):
    """UploadPart carries the same requirement independently of PutObject."""
    key = "chunked/mpu.dat"
    body = os.urandom(1024 * 1024)

    upload_id = boto3_raw.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
    resp = _put_chunked(
        endpoint,
        bucket=bucket,
        key=key,
        body=body,
        query=f"?partNumber=1&uploadId={quote(upload_id, safe='')}",
    )

    assert resp.status_code == 200, f"UploadPart {key}: {resp.status_code} {resp.text}"

    boto3_raw.complete_multipart_upload(
        Bucket=bucket,
        Key=key,
        UploadId=upload_id,
        MultipartUpload={"Parts": [{"ETag": resp.headers["ETag"], "PartNumber": 1}]},
    )
    assert bucket_fs.read(key) == body
