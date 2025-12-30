use anyhow::Result;
use pingora::http::{ResponseHeader, StatusCode};
use pingora::proxy::Session;

use s3pm_support::s3xml;

// Re-export shared error codes + shared bucket info type to keep call-sites unchanged.
pub use s3pm_support::s3xml::error_code;
pub use s3pm_support::s3xml::BucketInfo;

/* -------------------------
 * Pingora downstream writers
 * ------------------------- */

/// Write a complete response to the downstream *without proxying*.
///
/// Default behavior is to disable keepalive for safety. If you want to keep the
/// connection reusable, set `close = false` and optionally drain request body.
pub async fn respond_bytes(
    session: &mut Session,
    status: StatusCode,
    content_type: &str,
    body: Vec<u8>,
    extra_headers: &[(&'static str, String)],
    close: bool,
) -> pingora::Result<()> {
    // Safety: if we respond before request body is done, keepalive reuse can break for HTTP/1.1.
    // The simplest safe choice is to close keepalive for such early responses. :contentReference[oaicite:3]{index=3}
    if close {
        session.set_keepalive(None);
        session.set_close_on_response_before_downstream_finish(true);
    }

    // If you ever want keepalive even when a body might exist, you can drain it:
    // session.set_total_drain_timeout(Some(Duration::from_millis(200)));
    // let _ = session.drain_request_body().await;
    //
    // (Draining is useful to make H1 connections reusable.) :contentReference[oaicite:4]{index=4}

    let mut resp = ResponseHeader::build(status, Some(8))?;
    resp.insert_header("Content-Type", content_type)?;
    resp.insert_header("Content-Length", body.len().to_string())?;

    for (k, v) in extra_headers {
        resp.insert_header(*k, v.as_str())?;
    }

    session.write_response_header(Box::new(resp), false).await?;
    session.write_response_body(Some(body.into()), true).await?;

    // For Content-Length this is effectively a no-op, but safe to call. :contentReference[oaicite:5]{index=5}
    session.finish_body().await?;
    Ok(())
}

/// Convenience: write an S3 REST-XML error (and short-circuit).
pub async fn respond_s3_error(
    session: &mut Session,
    status: StatusCode,
    code: &str,
    message: &str,
    resource: Option<&str>,
    request_id: Option<&str>,
) -> pingora::Result<()> {
    // XML body generation is shared in s3pm-support now,
    // so proxy and gateway emit consistent S3 REST-XML.
    let body = s3xml::s3_error_body(code, message, resource, request_id, None)
        .unwrap_or_else(|_| b"<Error><Code>InternalError</Code><Message>xml build failed</Message></Error>".to_vec());

    // Many clients don’t require these headers, but they’re handy for debugging.
    let mut extra = Vec::new();
    if let Some(rid) = request_id {
        extra.push(("x-amz-request-id", rid.to_string()));
    }

    respond_bytes(
        session,
        status,
        "application/xml",
        body,
        &extra,
        /* close = */ true,
    )
    .await
}

/// Convenience: NotImplemented (501).
pub async fn respond_not_implemented(
    session: &mut Session,
    message: &str,
    resource: Option<&str>,
    request_id: Option<&str>,
) -> pingora::Result<()> {
    respond_s3_error(
        session,
        StatusCode::NOT_IMPLEMENTED,
        error_code::NOT_IMPLEMENTED,
        message,
        resource,
        request_id,
    )
    .await
}

/// Convenience: ListBuckets success (200).
pub async fn respond_list_buckets(
    session: &mut Session,
    owner_id: &str,
    owner_display_name: &str,
    buckets: &[BucketInfo],
) -> pingora::Result<()> {
    // ListBuckets XML generation is shared in s3pm-support now.
    let body = s3xml::list_buckets_body(owner_id, owner_display_name, buckets)
        .unwrap_or_else(|_| b"<Error><Code>InternalError</Code><Message>xml build failed</Message></Error>".to_vec());

    respond_bytes(
        session,
        StatusCode::OK,
        "application/xml",
        body,
        &[],
        /* close = */ false, // GET / has no request body; safe to keepalive
    )
    .await
}

/// Convenience: GetBucketLocation success (200).
pub async fn respond_get_bucket_location(
    session: &mut Session,
    region: &str,
    _resource: Option<&str>,
    _request_id: Option<&str>,
) -> pingora::Result<()> {
    let body = s3xml::get_bucket_location_body(region)
        .unwrap_or_else(|_| b"<LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></LocationConstraint>".to_vec());

    respond_bytes(
        session,
        StatusCode::OK,
        "application/xml",
        body,
        &[],
        /* close = */ false, // GET has no request body; safe to keepalive
    )
    .await
}

