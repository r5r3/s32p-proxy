use crate::s3xml;

use bytes::Bytes;
use http::header::{ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, LAST_MODIFIED};
use http::{Response, StatusCode};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use std::convert::Infallible;

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

    resp.headers_mut()
        .insert(CONTENT_TYPE, content_type.parse().unwrap());
    resp.headers_mut()
        .insert(CONTENT_LENGTH, len.to_string().parse().unwrap());

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
    let body = s3xml::s3_error_body(code, message, resource, request_id, None).unwrap_or_else(|_| {
        format!(
            "<Error><Code>{}</Code><Message>{}</Message></Error>",
            code, message
        )
        .into_bytes()
    });

    let mut headers = Vec::new();
    if let Some(rid) = request_id {
        headers.push(("x-amz-request-id", rid.to_string()));
    }

    response_bytes(status, "application/xml", body, headers)
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

/// Convenience: AccessDenied (403).
pub fn access_denied(message: &str, resource: Option<&str>) -> HttpResponse {
    s3_error(
        StatusCode::FORBIDDEN,
        s3xml::error_code::ACCESS_DENIED,
        message,
        resource,
        None,
    )
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
    s3_error(
        StatusCode::NOT_FOUND,
        s3xml::error_code::NO_SUCH_BUCKET,
        message,
        resource,
        None,
    )
}

/// Convenience: NoSuchKey (404).
pub fn no_such_key(message: &str, resource: Option<&str>) -> HttpResponse {
    s3_error(
        StatusCode::NOT_FOUND,
        s3xml::error_code::NO_SUCH_KEY,
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
pub fn internal_error(message: &str, resource: Option<&str>, request_id: Option<&str>) -> HttpResponse {
    s3_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        s3xml::error_code::INTERNAL_ERROR,
        message,
        resource,
        request_id,
    )
}

/// Convenience: ServiceUnavailable (503).
pub fn service_unavailable(message: &str, resource: Option<&str>, request_id: Option<&str>) -> HttpResponse {
    s3_error(
        StatusCode::SERVICE_UNAVAILABLE,
        s3xml::error_code::SERVICE_UNAVAILABLE,
        message,
        resource,
        request_id,
    )
}

/// Convenience: ListBuckets success (200).
pub fn list_buckets(owner_id: &str, owner_display_name: &str, buckets: &[s3xml::BucketInfo]) -> HttpResponse {
    let body = s3xml::list_buckets_body(owner_id, owner_display_name, buckets).unwrap_or_else(|_| {
        b"<Error><Code>InternalError</Code><Message>xml build failed</Message></Error>".to_vec()
    });

    response_bytes(StatusCode::OK, "application/xml", body, [])
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

fn apply_object_headers(
    headers: &mut http::HeaderMap,
    content_type: &'static str,
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
    headers.insert("server", "s3pm-gateway".parse().unwrap());
}

/// Build a GetObject/HeadObject response with consistent headers across:
/// - empty objects
/// - full 200 responses
/// - 206 single-range responses
/// - HEAD responses (empty body but correct Content-Length / Content-Range)
pub fn object_response(
    status: StatusCode,
    body: RespBody,
    content_type: &'static str,
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
    let mut resp = response_bytes(StatusCode::OK, "application/xml", Vec::new(), [
        ("etag", etag.to_string()),
    ]);

    resp.headers_mut().insert("server", "s3pm-gateway".parse().unwrap());
    resp
}

