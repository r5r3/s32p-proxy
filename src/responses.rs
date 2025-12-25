use anyhow::{anyhow, Result};
use pingora::http::{ResponseHeader, StatusCode};
use pingora::proxy::Session;

use quick_xml::se::to_string as to_xml_string;
use serde::Serialize;

use time::{macros::format_description, OffsetDateTime, UtcOffset};

pub const S3_XMLNS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

/// Common S3 error codes you’ll likely return locally.
pub mod error_code {
    pub const ACCESS_DENIED: &str = "AccessDenied";
    pub const SIGNATURE_DOES_NOT_MATCH: &str = "SignatureDoesNotMatch";
    pub const INVALID_ACCESS_KEY_ID: &str = "InvalidAccessKeyId";
    pub const NOT_IMPLEMENTED: &str = "NotImplemented";
    pub const INVALID_REQUEST: &str = "InvalidRequest";
    pub const INTERNAL_ERROR: &str = "InternalError";
    pub const SERVICE_UNAVAILABLE: &str = "ServiceUnavailable";
}

/// Minimal bucket info used by ListBuckets.
#[derive(Clone, Debug)]
pub struct BucketInfo {
    pub name: String,
    pub creation_date: OffsetDateTime,
}

/* -------------------------
 * Body builders (pure)
 * ------------------------- */

pub fn s3_error_body(
    code: &str,
    message: &str,
    resource: Option<&str>,
    request_id: Option<&str>,
    host_id: Option<&str>,
) -> Result<Vec<u8>> {
    let doc = ErrorDocument {
        code: code.to_string(),
        message: message.to_string(),
        resource: resource.map(|s| s.to_string()),
        request_id: request_id.map(|s| s.to_string()),
        host_id: host_id.map(|s| s.to_string()),
    };

    let xml = to_xml_string(&doc).map_err(|e| anyhow!("xml serialize error: {e}"))?;
    Ok(xml.into_bytes())
}

pub fn list_buckets_body(
    owner_id: &str,
    owner_display_name: &str,
    buckets: &[BucketInfo],
) -> Result<Vec<u8>> {
    let doc = ListAllMyBucketsResult {
        xmlns: S3_XMLNS,
        owner: Owner {
            id: owner_id.to_string(),
            display_name: owner_display_name.to_string(),
        },
        buckets: Buckets {
            bucket: buckets
                .iter()
                .map(|b| Bucket {
                    name: b.name.clone(),
                    creation_date: format_s3_time_utc_z(b.creation_date),
                })
                .collect(),
        },
    };

    let xml = to_xml_string(&doc).map_err(|e| anyhow!("xml serialize error: {e}"))?;
    Ok(xml.into_bytes())
}

fn format_s3_time_utc_z(dt: OffsetDateTime) -> String {
    let utc = dt.to_offset(UtcOffset::UTC);
    let fmt = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    utc.format(&fmt)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

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
    let body = s3_error_body(code, message, resource, request_id, None)
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
    let body = list_buckets_body(owner_id, owner_display_name, buckets)
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

/* -------------------------
 * XML DTOs
 * ------------------------- */

#[derive(Debug, Serialize)]
#[serde(rename = "Error")]
struct ErrorDocument {
    #[serde(rename = "Code")]
    code: String,
    #[serde(rename = "Message")]
    message: String,

    #[serde(rename = "Resource", skip_serializing_if = "Option::is_none")]
    resource: Option<String>,
    #[serde(rename = "RequestId", skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    #[serde(rename = "HostId", skip_serializing_if = "Option::is_none")]
    host_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename = "ListAllMyBucketsResult")]
struct ListAllMyBucketsResult {
    #[serde(rename = "@xmlns")]
    xmlns: &'static str,

    #[serde(rename = "Owner")]
    owner: Owner,

    #[serde(rename = "Buckets")]
    buckets: Buckets,
}

#[derive(Debug, Serialize)]
struct Owner {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "DisplayName")]
    display_name: String,
}

#[derive(Debug, Serialize)]
struct Buckets {
    #[serde(rename = "Bucket")]
    bucket: Vec<Bucket>,
}

#[derive(Debug, Serialize)]
struct Bucket {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "CreationDate")]
    creation_date: String,
}

