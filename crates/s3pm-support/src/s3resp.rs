use anyhow::Result;
use http::StatusCode;

use crate::s3xml;

/// A framework-agnostic response builder output.
/// Proxy wraps it into Pingora response-writing; Gateway wraps it into Hyper responses.
pub struct BuiltResponse {
    pub status: StatusCode,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    pub headers: Vec<(&'static str, String)>,
}

/// Build a standard S3 REST-XML error response body (and common headers).
pub fn s3_error(
    status: StatusCode,
    code: &str,
    message: &str,
    resource: Option<&str>,
    request_id: Option<&str>,
) -> Result<BuiltResponse> {
    let body = s3xml::s3_error_body(code, message, resource, request_id, None)?;
    let mut headers = Vec::new();

    // Many clients don’t require these headers, but they’re handy for debugging.
    if let Some(rid) = request_id {
        headers.push(("x-amz-request-id", rid.to_string()));
    }

    Ok(BuiltResponse {
        status,
        content_type: "application/xml",
        body,
        headers,
    })
}

/// Convenience: NotImplemented (501).
pub fn not_implemented(message: &str, resource: Option<&str>) -> BuiltResponse {
    s3_error(
        StatusCode::NOT_IMPLEMENTED,
        s3xml::error_code::NOT_IMPLEMENTED,
        message,
        resource,
        None,
    )
    .unwrap_or_else(|_| BuiltResponse {
        status: StatusCode::NOT_IMPLEMENTED,
        content_type: "application/xml",
        body: b"<Error><Code>NotImplemented</Code><Message>xml build failed</Message></Error>".to_vec(),
        headers: vec![],
    })
}

/// Convenience: AccessDenied (403).
pub fn access_denied(message: &str, resource: Option<&str>) -> BuiltResponse {
    s3_error(
        StatusCode::FORBIDDEN,
        s3xml::error_code::ACCESS_DENIED,
        message,
        resource,
        None,
    )
    .unwrap_or_else(|_| BuiltResponse {
        status: StatusCode::FORBIDDEN,
        content_type: "application/xml",
        body: b"<Error><Code>AccessDenied</Code><Message>xml build failed</Message></Error>".to_vec(),
        headers: vec![],
    })
}

/// Convenience: SignatureDoesNotMatch (403).
pub fn signature_does_not_match(message: &str, resource: Option<&str>) -> BuiltResponse {
    s3_error(
        StatusCode::FORBIDDEN,
        s3xml::error_code::SIGNATURE_DOES_NOT_MATCH,
        message,
        resource,
        None,
    )
    .unwrap_or_else(|_| BuiltResponse {
        status: StatusCode::FORBIDDEN,
        content_type: "application/xml",
        body: b"<Error><Code>SignatureDoesNotMatch</Code><Message>xml build failed</Message></Error>".to_vec(),
        headers: vec![],
    })
}

/// Convenience: NoSuchKey (404).
pub fn no_such_key(message: &str, resource: Option<&str>) -> BuiltResponse {
    s3_error(
        StatusCode::NOT_FOUND,
        s3xml::error_code::NO_SUCH_KEY,
        message,
        resource,
        None,
    )
    .unwrap_or_else(|_| BuiltResponse {
        status: StatusCode::NOT_FOUND,
        content_type: "application/xml",
        body: b"<Error><Code>NoSuchKey</Code><Message>xml build failed</Message></Error>".to_vec(),
        headers: vec![],
    })
}

/// Convenience: InvalidRange (416).
pub fn invalid_range(message: &str, resource: Option<&str>) -> BuiltResponse {
    s3_error(
        StatusCode::RANGE_NOT_SATISFIABLE,
        s3xml::error_code::INVALID_RANGE,
        message,
        resource,
        None,
    )
    .unwrap_or_else(|_| BuiltResponse {
        status: StatusCode::RANGE_NOT_SATISFIABLE,
        content_type: "application/xml",
        body: b"<Error><Code>InvalidRange</Code><Message>xml build failed</Message></Error>".to_vec(),
        headers: vec![],
    })
}

/// Convenience: GetBucketLocation success (200).
pub fn get_bucket_location(region: &str) -> Result<BuiltResponse> {
    let body = crate::s3xml::get_bucket_location_body(region)?;
    Ok(BuiltResponse {
        status: StatusCode::OK,
        content_type: "application/xml",
        body,
        headers: vec![
            // S3 clients commonly expect this header
            ("x-amz-bucket-region", region.to_string()),
        ],
    })
}

