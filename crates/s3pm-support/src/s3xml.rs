use anyhow::{anyhow, Result};
use quick_xml::se::to_string as to_xml_string;
use serde::Serialize;

use time::{macros::format_description, OffsetDateTime, UtcOffset};

/// XML namespace used by S3 REST-XML error + list bucket responses.
pub const S3_XMLNS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

/// Common S3 error codes you’ll likely return locally.
/// Shared so proxy and gateway don’t drift.
pub mod error_code {
    pub const ACCESS_DENIED: &str = "AccessDenied";
    pub const SIGNATURE_DOES_NOT_MATCH: &str = "SignatureDoesNotMatch";
    pub const INVALID_ACCESS_KEY_ID: &str = "InvalidAccessKeyId";
    pub const NOT_IMPLEMENTED: &str = "NotImplemented";
    pub const INVALID_REQUEST: &str = "InvalidRequest";
    pub const INTERNAL_ERROR: &str = "InternalError";
    pub const SERVICE_UNAVAILABLE: &str = "ServiceUnavailable";

    // Used by gateway for object retrieval errors.
    pub const NO_SUCH_KEY: &str = "NoSuchKey";
    pub const INVALID_RANGE: &str = "InvalidRange";
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

/// Build XML body for GetBucketLocation.
/// AWS returns an *empty* LocationConstraint for us-east-1.
/// Many clients accept either empty text or a self-closing tag; we emit empty text via Option::None.
pub fn get_bucket_location_body(region: &str) -> Result<Vec<u8>> {
    let value = if region == "us-east-1" { None } else { Some(region.to_string()) };
    let doc = LocationConstraintDoc { xmlns: S3_XMLNS, value };
    let xml = to_xml_string(&doc)?;
    Ok(xml.into_bytes())
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

#[derive(Debug, Serialize)]
#[serde(rename = "LocationConstraint")]
struct LocationConstraintDoc {
    #[serde(rename = "@xmlns")]
    xmlns: &'static str,

    // quick-xml/serde text node
    #[serde(rename = "$text", skip_serializing_if = "Option::is_none")]
    value: Option<String>,
}


