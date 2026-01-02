use bytes::Bytes;
use http::header::CONTENT_LENGTH;
use http::Response as HttpResponse;
use http_body_util::BodyExt;
use pingora::http::{ResponseHeader, StatusCode};
use pingora::proxy::Session;
use std::convert::Infallible;

use s3pm_support::s3resp;

// Re-export shared error codes + shared bucket info type to keep call-sites unchanged.
pub use s3pm_support::s3xml::error_code;
pub use s3pm_support::s3xml::BucketInfo;

/* -------------------------
 * Hyper -> Pingora adapter
 * ------------------------- */

/// Convert a Hyper-ready `http::Response` into a Pingora downstream response.
///
/// This is intended for **small/complete** responses (our shared s3resp builders always use full bodies).
/// If you later want true streaming to downstream (large bodies), implement a streaming adapter instead.
pub async fn respond_hyper(session: &mut Session, resp: s3pm_support::s3resp::HttpResponse, close: bool) -> pingora::Result<()> {
    if close {
        session.set_keepalive(None);
        session.set_close_on_response_before_downstream_finish(true);
    }

    let (parts, body) = resp.into_parts();

    // BoxBody has Error=Infallible, so this can't fail, but keep it explicit.
    let collected = body.collect().await.unwrap_or_default();
    let bytes = collected.to_bytes();

    // Build Pingora response header.
    let mut rh = ResponseHeader::build(parts.status, Some(parts.headers.len() + 4))?;

    // Copy headers (best effort for non-utf8 values).
    for (k, v) in parts.headers.iter() {
        if let Ok(vs) = v.to_str() {
            // IMPORTANT: clone the header name to avoid borrowing from parts.headers
            rh.insert_header(k.clone(), vs)?;
        }
    }

    // Ensure Content-Length matches what we actually write.
    rh.insert_header("Content-Length", bytes.len().to_string().as_str())?;

    session.write_response_header(Box::new(rh), false).await?;
    session.write_response_body(Some(bytes), true).await?;
    session.finish_body().await?;
    Ok(())
}

/* -------------------------
 * Higher-level helpers (used by proxy main)
 * ------------------------- */

/// Write a complete S3 REST-XML error (and short-circuit).
pub async fn respond_s3_error(
    session: &mut Session,
    status: StatusCode,
    code: &str,
    message: &str,
    resource: Option<&str>,
    request_id: Option<&str>,
) -> pingora::Result<()> {
    let resp = s3resp::s3_error(status, code, message, resource, request_id);
    respond_hyper(session, resp, /* close = */ true).await
}

/// Convenience: NotImplemented (501).
pub async fn respond_not_implemented(
    session: &mut Session,
    message: &str,
    resource: Option<&str>,
    _request_id: Option<&str>,
) -> pingora::Result<()> {
    let resp = s3resp::not_implemented(message, resource);
    respond_hyper(session, resp, /* close = */ true).await
}

/// Convenience: ListBuckets success (200).
pub async fn respond_list_buckets(
    session: &mut Session,
    owner_id: &str,
    owner_display_name: &str,
    buckets: &[BucketInfo],
) -> pingora::Result<()> {
    let resp = s3resp::list_buckets(owner_id, owner_display_name, buckets);

    // GET / has no request body; safe to keepalive
    respond_hyper(session, resp, /* close = */ false).await
}

/// Convenience: GetBucketLocation success (200).
pub async fn respond_get_bucket_location(
    session: &mut Session,
    region: &str,
    _resource: Option<&str>,
    _request_id: Option<&str>,
) -> pingora::Result<()> {
    let resp = s3resp::get_bucket_location(region);

    // GET has no request body; safe to keepalive
    respond_hyper(session, resp, /* close = */ false).await
}

