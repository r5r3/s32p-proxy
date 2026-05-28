use std::convert::Infallible;

use bytes::Bytes;
use http::{
    Response, StatusCode,
    header::{ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, LAST_MODIFIED},
};
use http_body_util::{BodyExt, Full, combinators::BoxBody};

use crate::s3xml;

/// Body type we use for small/complete responses.
/// Hyper can use `http::Response<impl http_body::Body>` directly, and `BoxBody` works everywhere.
pub type RespBody = BoxBody<Bytes, Infallible>;

/// Hyper-ready response type (also usable in other http-based stacks).
pub type HttpResponse = Response<RespBody>;

fn boxed_full(body: Vec<u8>) -> RespBody {
    Full::new(Bytes::from(body)).boxed()
}

/// Build a complete HTTP response with a full in-memory body.
/// Ensures `Content-Type` and `Content-Length` are set.
pub fn response_bytes(
    status: StatusCode,
    content_type: &'static str,
    body: Vec<u8>,
    headers: impl IntoIterator<Item = (&'static str, String)>,
) -> HttpResponse {
    let len = body.len();

    let mut resp = Response::new(boxed_full(body));
    *resp.status_mut() = status;

    resp.headers_mut().insert(CONTENT_TYPE, content_type.parse().unwrap());
    resp.headers_mut().insert(CONTENT_LENGTH, len.to_string().parse().unwrap());

    for (k, v) in headers {
        // All our generated header values are ASCII-ish; if parse fails, skip (best-effort).
        if let Ok(hv) = v.parse() {
            resp.headers_mut().insert(k, hv);
        }
    }

    resp
}

/* -------------------------
 * S3 REST-XML helpers
 * ------------------------- */

/// Build a standard S3 REST-XML error response (body + headers).
///
/// This never fails: XML build failures fall back to a minimal static body.
pub fn s3_error(
    status: StatusCode,
    code: &str,
    message: &str,
    resource: Option<&str>,
    request_id: Option<&str>,
) -> HttpResponse {
    let body =
        s3xml::s3_error_body(code, message, resource, request_id, None).unwrap_or_else(|_| {
            format!("<Error><Code>{}</Code><Message>{}</Message></Error>", code, message)
                .into_bytes()
        });

    let mut headers = Vec::new();
    if let Some(rid) = request_id {
        headers.push(("x-amz-request-id", rid.to_string()));
    }

    response_bytes(status, "application/xml", body, headers)
}

/// Convenience: Not Modified (304).
///
/// Used for GET/HEAD when If-None-Match / If-Modified-Since indicate the cached value is still valid.
/// We keep the body empty; optionally include ETag/Last-Modified so clients can keep metadata in sync.
pub fn not_modified(etag: Option<&str>, last_modified: Option<&str>) -> HttpResponse {
    let mut resp = Response::new(empty_body());
    *resp.status_mut() = StatusCode::NOT_MODIFIED;

    // Many clients are fine either way; setting 0 is safe and consistent.
    resp.headers_mut().insert(CONTENT_LENGTH, "0".parse().unwrap());

    if let Some(etag) = etag {
        resp.headers_mut().insert(ETAG, etag.parse().unwrap());
    }
    if let Some(lm) = last_modified {
        resp.headers_mut().insert(LAST_MODIFIED, lm.parse().unwrap());
    }

    resp.headers_mut().insert("server", "s32p-gateway".parse().unwrap());

    resp
}

/// Convenience: NotImplemented (501).
pub fn not_implemented(message: &str, resource: Option<&str>) -> HttpResponse {
    s3_error(
        StatusCode::NOT_IMPLEMENTED,
        s3xml::error_code::NOT_IMPLEMENTED,
        message,
        resource,
        None,
    )
}

/// 200 OK with an empty `<VersioningConfiguration xmlns="…"/>` body.
/// Matches what AWS S3 returns for `GetBucketVersioning` on a bucket
/// that was never versioned — absence of the `<Status>` element is the
/// "Unversioned" signal. Used by the `aws_compat` routing target.
pub fn versioning_not_configured() -> HttpResponse {
    let body = s3xml::versioning_configuration_empty_body().unwrap_or_else(|_| {
        format!("<VersioningConfiguration xmlns=\"{}\"/>", s3xml::S3_XMLNS).into_bytes()
    });
    response_bytes(StatusCode::OK, "application/xml", body, [])
}

/// 400 InvalidRequest for requests that carry any server-side encryption
/// headers — SSE-C (customer-provided keys), SSE-S3 (server-managed
/// AES256), SSE-KMS (server-managed via AWS KMS), or SSE-KMS-DSSE
/// (dual-layer). The gateway has no encryption path at all, so silently
/// dropping these headers would store the body in plaintext while the
/// client believes it sent an encrypted PUT — a data-confidentiality
/// footgun across every variant. Reject at the proxy with an AWS-shaped
/// 400 + InvalidRequest so the failure surfaces immediately, before any
/// worker is spawned.
///
/// The message names the specific variant so a user reading the response
/// knows exactly which SDK option to remove.
pub fn sse_not_supported(kind: crate::utils::DetectedSse, resource: Option<&str>) -> HttpResponse {
    use crate::utils::DetectedSse;
    let message = match kind {
        DetectedSse::CustomerKey => {
            "Server-side encryption with customer-provided keys (SSE-C) \
             is not supported by this proxy"
        }
        DetectedSse::ServerS3 => {
            "Server-side encryption (SSE-S3, x-amz-server-side-encryption: AES256) \
             is not supported by this proxy"
        }
        DetectedSse::ServerKms => {
            "Server-side encryption with AWS KMS (SSE-KMS) is not supported by this proxy"
        }
        DetectedSse::ServerKmsDsse => {
            "Server-side encryption with AWS KMS dual-layer (SSE-KMS-DSSE) is not \
             supported by this proxy"
        }
        DetectedSse::Unknown => {
            "The requested server-side encryption algorithm is not supported by this proxy"
        }
    };
    invalid_request(message, resource)
}

/// Convenience: InvalidRequest (400).
pub fn invalid_request(message: &str, resource: Option<&str>) -> HttpResponse {
    s3_error(StatusCode::BAD_REQUEST, s3xml::error_code::INVALID_REQUEST, message, resource, None)
}

/// Convenience: AccessDenied (403).
pub fn access_denied(message: &str, resource: Option<&str>) -> HttpResponse {
    s3_error(StatusCode::FORBIDDEN, s3xml::error_code::ACCESS_DENIED, message, resource, None)
}

/// Convenience: SignatureDoesNotMatch (403).
pub fn signature_does_not_match(message: &str, resource: Option<&str>) -> HttpResponse {
    s3_error(
        StatusCode::FORBIDDEN,
        s3xml::error_code::SIGNATURE_DOES_NOT_MATCH,
        message,
        resource,
        None,
    )
}

/// Convenience: RequestTimeTooSkewed (403). Returned for header-style
/// SigV4 requests whose `x-amz-date` falls outside the configured
/// clock-skew window. AWS S3 uses this code (separate from
/// SignatureDoesNotMatch) so clients know to re-sync their clock and
/// re-sign rather than treat the request as unauthorized.
pub fn request_time_too_skewed(message: &str, resource: Option<&str>) -> HttpResponse {
    s3_error(
        StatusCode::FORBIDDEN,
        s3xml::error_code::REQUEST_TIME_TOO_SKEWED,
        message,
        resource,
        None,
    )
}

/// Convenience: MethodNotAllowed (405) with an `Allow:` header.
///
/// Used for HTTP methods that aren't defined on the requested resource —
/// the canonical case is `HEAD /` (service-level HEAD; AWS only documents
/// `GET /` for ListBuckets). The `Allow:` value is the comma-separated
/// list of methods the caller could have used on the same resource (for
/// service-level `/`, that's just `GET`).
pub fn method_not_allowed(message: &str, resource: Option<&str>, allow: &str) -> HttpResponse {
    let body =
        s3xml::s3_error_body(s3xml::error_code::METHOD_NOT_ALLOWED, message, resource, None, None)
            .unwrap_or_else(|_| {
                format!(
                    "<Error><Code>{}</Code><Message>{}</Message></Error>",
                    s3xml::error_code::METHOD_NOT_ALLOWED,
                    message
                )
                .into_bytes()
            });
    response_bytes(
        StatusCode::METHOD_NOT_ALLOWED,
        "application/xml",
        body,
        [("Allow", allow.to_string())],
    )
}

/// Convenience: SlowDown (429). Emitted by the proxy when one source IP
/// exceeds its concurrent-request cap. AWS's documented response for
/// "retry, with backoff" — clients that respect the AWS SDK retry conventions
/// already know to back off on this code. `retry_after_secs` is sent as the
/// HTTP `Retry-After` header.
pub fn slow_down(message: &str, resource: Option<&str>, retry_after_secs: u64) -> HttpResponse {
    let body = s3xml::s3_error_body(s3xml::error_code::SLOW_DOWN, message, resource, None, None)
        .unwrap_or_else(|_| {
            format!(
                "<Error><Code>{}</Code><Message>{}</Message></Error>",
                s3xml::error_code::SLOW_DOWN,
                message
            )
            .into_bytes()
        });
    response_bytes(
        StatusCode::TOO_MANY_REQUESTS,
        "application/xml",
        body,
        [("Retry-After", retry_after_secs.to_string())],
    )
}

/// Convenience: InvalidAccessKeyId (403).
pub fn invalid_access_key_id(message: &str, resource: Option<&str>) -> HttpResponse {
    s3_error(
        StatusCode::FORBIDDEN,
        s3xml::error_code::INVALID_ACCESS_KEY_ID,
        message,
        resource,
        None,
    )
}

/// Convenience: NoSuchBucket (404).
pub fn no_such_bucket(message: &str, resource: Option<&str>) -> HttpResponse {
    s3_error(StatusCode::NOT_FOUND, s3xml::error_code::NO_SUCH_BUCKET, message, resource, None)
}

/// Convenience: NoSuchKey (404).
pub fn no_such_key(message: &str, resource: Option<&str>) -> HttpResponse {
    s3_error(StatusCode::NOT_FOUND, s3xml::error_code::NO_SUCH_KEY, message, resource, None)
}

/// Convenience: PreconditionFailed (412).
pub fn precondition_failed(message: &str, resource: Option<&str>) -> HttpResponse {
    s3_error(
        StatusCode::PRECONDITION_FAILED,
        s3xml::error_code::PRECONDITION_FAILED,
        message,
        resource,
        None,
    )
}

/// Convenience: InvalidRange (416).
pub fn invalid_range(message: &str, resource: Option<&str>) -> HttpResponse {
    s3_error(
        StatusCode::RANGE_NOT_SATISFIABLE,
        s3xml::error_code::INVALID_RANGE,
        message,
        resource,
        None,
    )
}

/// Convenience: InternalError (500).
pub fn internal_error(
    message: &str,
    resource: Option<&str>,
    request_id: Option<&str>,
) -> HttpResponse {
    s3_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        s3xml::error_code::INTERNAL_ERROR,
        message,
        resource,
        request_id,
    )
}

/// Convenience: ServiceUnavailable (503).
pub fn service_unavailable(
    message: &str,
    resource: Option<&str>,
    request_id: Option<&str>,
) -> HttpResponse {
    s3_error(
        StatusCode::SERVICE_UNAVAILABLE,
        s3xml::error_code::SERVICE_UNAVAILABLE,
        message,
        resource,
        request_id,
    )
}

/// Convenience: ListBuckets success (200).
pub fn list_buckets(
    owner_id: &str,
    owner_display_name: &str,
    buckets: &[s3xml::BucketInfo],
) -> HttpResponse {
    list_buckets_paginated(owner_id, owner_display_name, buckets, None, None)
}

/// Convenience: ListBuckets success (200), with optional pagination/filter fields.
///
/// `prefix` is echoed back in the response only when provided.
/// `next_continuation_token` is included only when there are more buckets to list.
pub fn list_buckets_paginated(
    owner_id: &str,
    owner_display_name: &str,
    buckets: &[s3xml::BucketInfo],
    prefix: Option<&str>,
    next_continuation_token: Option<&str>,
) -> HttpResponse {
    let body = s3xml::list_buckets_body_paginated(
        owner_id,
        owner_display_name,
        buckets,
        prefix,
        next_continuation_token,
    )
    .unwrap_or_else(|_| {
        b"<Error><Code>InternalError</Code><Message>xml build failed</Message></Error>".to_vec()
    });

    response_bytes(StatusCode::OK, "application/xml", body, [])
}

/// Convenience: GetObjectAcl / GetBucketAcl success (200) with synthetic ACL body.
/// See `s3xml::get_acl_body` for body shape; we mirror AWS's
/// "bucket-owner-enforced" response and optionally tack on an `AllUsers/READ`
/// grant when the file is world-readable in POSIX.
pub fn get_acl(owner_id: &str, owner_display_name: &str, world_readable: bool) -> HttpResponse {
    let body =
        s3xml::get_acl_body(owner_id, owner_display_name, world_readable).unwrap_or_else(|_| {
            // Minimal fallback (still valid for clients): owner-only FULL_CONTROL.
            format!(
                "<AccessControlPolicy xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                <Owner><ID>{owner_id}</ID><DisplayName>{owner_display_name}</DisplayName></Owner>\
                <AccessControlList><Grant>\
                <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" \
                xsi:type=\"CanonicalUser\"><ID>{owner_id}</ID>\
                <DisplayName>{owner_display_name}</DisplayName></Grantee>\
                <Permission>FULL_CONTROL</Permission>\
                </Grant></AccessControlList></AccessControlPolicy>"
            )
            .into_bytes()
        });
    response_bytes(StatusCode::OK, "application/xml", body, [])
}

/// Convenience: PutObjectAcl / PutBucketAcl success (200, empty body).
/// s32p does not store S3 ACL state — this response is only returned when
/// the requested ACL matches the effective POSIX state (no-op accept).
pub fn put_acl_ok() -> HttpResponse {
    let mut resp = response_bytes(StatusCode::OK, "application/xml", Vec::new(), []);
    resp.headers_mut().insert("server", "s32p-gateway".parse().unwrap());
    resp
}

/// GetObjectTagging success (200, `<Tagging><TagSet>…</TagSet></Tagging>` body).
/// `tags_urlform` is the stored URL-form payload (`team=a&stage=raw`);
/// empty input produces an empty `<TagSet/>`.
pub fn get_object_tagging(tags_urlform: &str) -> HttpResponse {
    let body = s3xml::get_object_tagging_body(tags_urlform).unwrap_or_else(|_| {
        b"<Tagging xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><TagSet/></Tagging>".to_vec()
    });
    response_bytes(StatusCode::OK, "application/xml", body, [])
}

/// PutObjectTagging success (200, empty body — AWS responds with no payload).
pub fn put_object_tagging_ok() -> HttpResponse {
    response_bytes(StatusCode::OK, "application/xml", Vec::new(), [])
}

/// DeleteObjectTagging success (204 No Content).
pub fn delete_object_tagging_ok() -> HttpResponse {
    response_bytes(StatusCode::NO_CONTENT, "application/xml", Vec::new(), [])
}

/// Convenience: GetBucketLocation success (200).
pub fn get_bucket_location(region: &str) -> HttpResponse {
    let body = s3xml::get_bucket_location_body(region).unwrap_or_else(|_| {
        // Minimal fallback (still valid-ish for clients)
        b"<LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></LocationConstraint>"
            .to_vec()
    });

    response_bytes(
        StatusCode::OK,
        "application/xml",
        body,
        [("x-amz-bucket-region", region.to_string())],
    )
}

/// Convenience: HeadBucket success (200, empty body).
/// Many clients expect `x-amz-bucket-region` to be present.
pub fn head_bucket_ok(region: &str) -> HttpResponse {
    response_bytes(
        StatusCode::OK,
        "application/xml",
        Vec::new(),
        [("x-amz-bucket-region", region.to_string())],
    )
}

/* -------------------------
 * S3 object (GetObject / HeadObject) response helpers
 * ------------------------- */

/// Box an empty body (useful for HEAD responses).
pub fn empty_body() -> RespBody {
    Full::new(Bytes::new()).boxed()
}

/// Box a full in-memory body from `Bytes`.
pub fn body_bytes(bytes: Bytes) -> RespBody {
    Full::new(bytes).boxed()
}

/// Format a Content-Range header value for a single range.
pub fn object_content_range(start: u64, end_incl: u64, total: u64) -> String {
    format!("bytes {}-{}/{}", start, end_incl, total)
}

/* -------------------------
 * Multi-range (RFC 7233 `multipart/byteranges`) response helpers
 *
 * These are the single source of truth for the on-the-wire byte layout of a
 * multi-range GET body. Both the `Content-Length` computation
 * (`multirange_content_length`) and the streaming emitter call the same
 * `multirange_part_header` / `multirange_closing`, so the advertised length
 * can never diverge from the bytes actually sent.
 *
 * The gateway stores no per-object content type (POSIX-interop design), so
 * every part advertises the gateway's constant media type.
 * ------------------------- */

/// Media type advertised for each part of a `multipart/byteranges` body, and
/// the gateway's content type for object responses generally.
pub const OBJECT_CONTENT_TYPE: &str = "application/octet-stream";

/// Generate a boundary string for a `multipart/byteranges` response.
///
/// Uniqueness — not secrecy — is what matters: a boundary that happens to
/// appear in the body would corrupt framing, the standard negligible RFC 7233
/// risk. Uses OS randomness (`getrandom`) with a time + process-local counter
/// fallback so it never blocks or fails.
pub fn multirange_boundary() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};

    let mut buf = [0u8; 16];
    let rc = unsafe { libc::getrandom(buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
    if rc != buf.len() as isize {
        static CTR: AtomicU64 = AtomicU64::new(0);
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        buf[..8].copy_from_slice(&t.to_le_bytes());
        buf[8..].copy_from_slice(&n.to_le_bytes());
    }

    let mut s = String::with_capacity(buf.len() * 2);
    for b in buf {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

/// The MIME part-header block that precedes one range's bytes:
/// `--{boundary}\r\nContent-Type: …\r\nContent-Range: bytes A-B/TOTAL\r\n\r\n`.
pub fn multirange_part_header(boundary: &str, start: u64, end_incl: u64, total: u64) -> Vec<u8> {
    format!(
        "--{boundary}\r\n\
         Content-Type: {OBJECT_CONTENT_TYPE}\r\n\
         Content-Range: bytes {start}-{end_incl}/{total}\r\n\r\n"
    )
    .into_bytes()
}

/// The closing delimiter of a `multipart/byteranges` body: `--{boundary}--\r\n`.
pub fn multirange_closing(boundary: &str) -> Vec<u8> {
    format!("--{boundary}--\r\n").into_bytes()
}

/// The `Content-Type` header value for a multi-range response.
pub fn multirange_content_type(boundary: &str) -> String {
    format!("multipart/byteranges; boundary={boundary}")
}

/// Exact `Content-Length` of the `multipart/byteranges` body for `ranges`.
///
/// Each range contributes its part header, its bytes, and a trailing `\r\n`;
/// the body ends with the closing delimiter. Mirrors exactly what the
/// streaming emitter sends.
pub fn multirange_content_length(
    boundary: &str,
    ranges: &[crate::utils::ByteRange],
    total: u64,
) -> u64 {
    let mut len: u64 = 0;
    for r in ranges {
        let end_incl = r.end_excl.saturating_sub(1);
        len += multirange_part_header(boundary, r.start, end_incl, total).len() as u64;
        len += r.end_excl - r.start; // body bytes
        len += 2; // trailing CRLF after the body
    }
    len += multirange_closing(boundary).len() as u64;
    len
}

fn apply_object_headers(
    headers: &mut http::HeaderMap,
    content_type: &str,
    content_length: u64,
    etag: &str,
    last_modified: &str,
    content_range: Option<&str>,
) {
    // Required / expected by most S3 clients
    headers.insert(CONTENT_TYPE, content_type.parse().unwrap());
    headers.insert(CONTENT_LENGTH, content_length.to_string().parse().unwrap());
    headers.insert(ACCEPT_RANGES, "bytes".parse().unwrap());
    headers.insert(ETAG, etag.parse().unwrap());
    headers.insert(LAST_MODIFIED, last_modified.parse().unwrap());

    if let Some(cr) = content_range {
        headers.insert(CONTENT_RANGE, cr.parse().unwrap());
    }

    // Keep consistent across all object responses from the gateway.
    // (Header name is lowercase string to avoid relying on `http::header::SERVER` existence across versions.)
    headers.insert("server", "s32p-gateway".parse().unwrap());
}

/// Build a GetObject/HeadObject response with consistent headers across:
/// - empty objects
/// - full 200 responses
/// - 206 single-range responses
/// - HEAD responses (empty body but correct Content-Length / Content-Range)
pub fn object_response(
    status: StatusCode,
    body: RespBody,
    content_type: &str,
    content_length: u64,
    etag: &str,
    last_modified: &str,
    content_range: Option<&str>,
) -> HttpResponse {
    let mut resp = Response::new(body);
    *resp.status_mut() = status;

    apply_object_headers(
        resp.headers_mut(),
        content_type,
        content_length,
        etag,
        last_modified,
        content_range,
    );

    resp
}

/// Convenience: ListObjectsV1 success (200).
pub fn list_objects_v1(
    bucket_name: &str,
    prefix: &str,
    delimiter: Option<&str>,
    marker: &str,
    next_marker: Option<&str>,
    max_keys: u32,
    is_truncated: bool,
    encoding_type: Option<&str>,
    contents: &[s3xml::ListObjectInfo],
    common_prefixes: &[String],
) -> HttpResponse {
    let body = s3xml::list_objects_v1_body(
        bucket_name,
        prefix,
        delimiter,
        marker,
        next_marker,
        max_keys,
        is_truncated,
        encoding_type,
        contents,
        common_prefixes,
    )
    .unwrap_or_else(|_| {
        b"<Error><Code>InternalError</Code><Message>xml build failed</Message></Error>".to_vec()
    });

    response_bytes(StatusCode::OK, "application/xml", body, [])
}

/// Convenience: ListObjectsV2 success (200).
pub fn list_objects_v2(
    bucket_name: &str,
    prefix: Option<&str>,
    delimiter: Option<&str>,
    key_count: u32,
    max_keys: u32,
    is_truncated: bool,
    continuation_token: Option<&str>,
    next_continuation_token: Option<&str>,
    start_after: Option<&str>,
    encoding_type: Option<&str>,
    contents: &[s3xml::ListObjectInfo],
    common_prefixes: &[String],
) -> HttpResponse {
    let body = s3xml::list_objects_v2_body(
        bucket_name,
        prefix,
        delimiter,
        key_count,
        max_keys,
        is_truncated,
        continuation_token,
        next_continuation_token,
        start_after,
        encoding_type,
        contents,
        common_prefixes,
    )
    .unwrap_or_else(|_| {
        b"<Error><Code>InternalError</Code><Message>xml build failed</Message></Error>".to_vec()
    });

    response_bytes(StatusCode::OK, "application/xml", body, [])
}

/// Convenience: PutObject success (200, empty body).
/// We return an ETag and keep the "server" header consistent with gateway responses.
pub fn put_object_ok(etag: &str) -> HttpResponse {
    // Empty body, but still include Content-Length and Content-Type (many clients are picky).
    let mut resp =
        response_bytes(StatusCode::OK, "application/xml", Vec::new(), [("etag", etag.to_string())]);

    resp.headers_mut().insert("server", "s32p-gateway".parse().unwrap());
    resp
}

/// Convenience: CopyObject success (200, REST-XML CopyObjectResult).
/// Includes ETag header and keeps the "server" header consistent with gateway responses.
pub fn copy_object_ok(etag: &str, last_modified: &str) -> HttpResponse {
    let body = s3xml::copy_object_result_body(last_modified, etag).unwrap_or_else(|_| {
        b"<Error><Code>InternalError</Code><Message>xml build failed</Message></Error>".to_vec()
    });

    let mut resp =
        response_bytes(StatusCode::OK, "application/xml", body, [("etag", etag.to_string())]);
    resp.headers_mut().insert("server", "s32p-gateway".parse().unwrap());
    resp
}

/// Convenience: DeleteObject success (204, empty body).
/// DeleteObject is idempotent; missing keys still return success.
pub fn delete_object_no_content() -> HttpResponse {
    let mut resp = response_bytes(StatusCode::NO_CONTENT, "application/xml", Vec::new(), []);
    resp.headers_mut().insert("server", "s32p-gateway".parse().unwrap());
    resp
}

/// Convenience: DeleteObjects success (200, REST-XML DeleteResult).
pub fn delete_objects_result(
    deleted_keys: &[String],
    errors: &[s3xml::DeleteErrorInfo],
) -> HttpResponse {
    let body = s3xml::delete_objects_result_body(deleted_keys, errors).unwrap_or_else(|_| {
        b"<Error><Code>InternalError</Code><Message>xml build failed</Message></Error>".to_vec()
    });

    let mut resp = response_bytes(StatusCode::OK, "application/xml", body, []);
    resp.headers_mut().insert("server", "s32p-gateway".parse().unwrap());
    resp
}

/* -------------------------
 * Multipart helpers
 * ------------------------- */

pub fn create_multipart_upload_ok(bucket: &str, key: &str, upload_id: &str) -> HttpResponse {
    let body =
        s3xml::initiate_multipart_upload_result_body(bucket, key, upload_id).unwrap_or_else(|_| {
            b"<Error><Code>InternalError</Code><Message>xml build failed</Message></Error>".to_vec()
        });

    let mut resp = response_bytes(StatusCode::OK, "application/xml", body, []);
    resp.headers_mut().insert("server", "s32p-gateway".parse().unwrap());
    resp
}

pub fn upload_part_ok(etag: &str) -> HttpResponse {
    let mut resp =
        response_bytes(StatusCode::OK, "application/xml", Vec::new(), [("etag", etag.to_string())]);
    resp.headers_mut().insert("server", "s32p-gateway".parse().unwrap());
    resp
}

/// UploadPartCopy success — 200 with `<CopyPartResult>` body carrying part ETag
/// and last-modified. Mirror of `copy_object_ok` for the multipart-copy path.
pub fn upload_part_copy_ok(etag: &str, last_modified: &str) -> HttpResponse {
    let body = s3xml::copy_part_result_body(last_modified, etag).unwrap_or_else(|_| {
        b"<Error><Code>InternalError</Code><Message>xml build failed</Message></Error>".to_vec()
    });

    let mut resp =
        response_bytes(StatusCode::OK, "application/xml", body, [("etag", etag.to_string())]);
    resp.headers_mut().insert("server", "s32p-gateway".parse().unwrap());
    resp
}

pub fn list_multipart_uploads_ok(
    bucket: &str,
    uploads: &[s3xml::MultipartUploadInfo],
) -> HttpResponse {
    let body = s3xml::list_multipart_uploads_body(bucket, uploads).unwrap_or_else(|_| {
        b"<Error><Code>InternalError</Code><Message>xml build failed</Message></Error>".to_vec()
    });

    let mut resp = response_bytes(StatusCode::OK, "application/xml", body, []);
    resp.headers_mut().insert("server", "s32p-gateway".parse().unwrap());
    resp
}

pub fn list_parts_ok(
    bucket: &str,
    key: &str,
    upload_id: &str,
    parts: &[s3xml::MultipartPartInfo],
) -> HttpResponse {
    let body = s3xml::list_parts_body(bucket, key, upload_id, parts).unwrap_or_else(|_| {
        b"<Error><Code>InternalError</Code><Message>xml build failed</Message></Error>".to_vec()
    });

    let mut resp = response_bytes(StatusCode::OK, "application/xml", body, []);
    resp.headers_mut().insert("server", "s32p-gateway".parse().unwrap());
    resp
}

pub fn complete_multipart_upload_ok(
    location: &str,
    bucket: &str,
    key: &str,
    etag: &str,
) -> HttpResponse {
    let body = s3xml::complete_multipart_upload_result_body(location, bucket, key, etag)
        .unwrap_or_else(|_| {
            b"<Error><Code>InternalError</Code><Message>xml build failed</Message></Error>".to_vec()
        });

    let mut resp =
        response_bytes(StatusCode::OK, "application/xml", body, [("etag", etag.to_string())]);
    resp.headers_mut().insert("server", "s32p-gateway".parse().unwrap());
    resp
}

pub fn abort_multipart_upload_no_content() -> HttpResponse {
    let mut resp = response_bytes(StatusCode::NO_CONTENT, "application/xml", Vec::new(), []);
    resp.headers_mut().insert("server", "s32p-gateway".parse().unwrap());
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::ByteRange;

    /// The assembled body must be exactly `multirange_content_length` bytes —
    /// this guards against the part-header serialization and the length math
    /// drifting apart.
    #[test]
    fn multirange_length_matches_assembled_body() {
        let total = 200u64;
        let ranges = vec![
            ByteRange { start: 0, end_excl: 10 },
            ByteRange { start: 20, end_excl: 30 },
            ByteRange { start: 199, end_excl: 200 },
        ];
        let boundary = "TESTBOUNDARY0123456789abcdef";

        let mut body: Vec<u8> = Vec::new();
        for r in &ranges {
            body.extend_from_slice(&multirange_part_header(
                boundary,
                r.start,
                r.end_excl - 1,
                total,
            ));
            body.extend(std::iter::repeat_n(b'x', (r.end_excl - r.start) as usize));
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(&multirange_closing(boundary));

        assert_eq!(body.len() as u64, multirange_content_length(boundary, &ranges, total));
    }
}
