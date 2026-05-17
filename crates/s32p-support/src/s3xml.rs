use std::time::SystemTime;

use anyhow::{Result, anyhow};
use quick_xml::{Reader, XmlVersion, events::Event, se::to_string as to_xml_string};
use serde::Serialize;
use time::{OffsetDateTime, UtcOffset, macros::format_description};

/// XML namespace used by S3 REST-XML error + list bucket responses.
pub const S3_XMLNS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

/// Common S3 error codes you’ll likely return locally.
/// Shared so proxy and gateway don’t drift.
pub mod error_code {
    pub const ACCESS_DENIED: &str = "AccessDenied";
    pub const SIGNATURE_DOES_NOT_MATCH: &str = "SignatureDoesNotMatch";
    pub const REQUEST_TIME_TOO_SKEWED: &str = "RequestTimeTooSkewed";
    pub const INVALID_ACCESS_KEY_ID: &str = "InvalidAccessKeyId";
    pub const NOT_IMPLEMENTED: &str = "NotImplemented";
    pub const INVALID_REQUEST: &str = "InvalidRequest";
    pub const INTERNAL_ERROR: &str = "InternalError";
    pub const SERVICE_UNAVAILABLE: &str = "ServiceUnavailable";
    pub const ENTITY_TOO_LARGE: &str = "EntityTooLarge";

    // Used by gateway for object retrieval errors.
    pub const NO_SUCH_KEY: &str = "NoSuchKey";
    pub const INVALID_RANGE: &str = "InvalidRange";

    // Used by gateway for bucket-level operations.
    pub const NO_SUCH_BUCKET: &str = "NoSuchBucket";

    // Used for multipart uploads
    pub const NO_SUCH_UPLOAD: &str = "NoSuchUpload";

    // for precondition checks
    pub const PRECONDITION_FAILED: &str = "PreconditionFailed";

    /// A retry of an idempotent operation (`x-amz-client-token`) reused
    /// the same token for a *different* request payload. AWS surfaces
    /// this as 409 with this code in services that support idempotency
    /// tokens. mountpoint-s3 doesn't currently produce a token mismatch
    /// (it generates a fresh UUID per call), but other SDKs may.
    pub const IDEMPOTENT_PARAMETER_MISMATCH: &str = "IdempotentParameterMismatch";

    /// Generic "bad request argument" used by S3. mountpoint-s3's
    /// `PutObjectError::EmptyBody` is keyed on this code together with
    /// the literal message prefix "Request body cannot be empty".
    pub const INVALID_ARGUMENT: &str = "InvalidArgument";

    /// `x-amz-write-offset-bytes` did not equal the current object size.
    /// AWS S3 Express directory-bucket append surface.
    pub const INVALID_WRITE_OFFSET: &str = "InvalidWriteOffset";
}

/// Minimal bucket info used by ListBuckets.
#[derive(Clone, Debug)]
pub struct BucketInfo {
    pub name:          String,
    /// Optional bucket region (used by paginated ListBuckets responses).
    pub bucket_region: Option<String>,
    /// Optional bucket ARN.
    pub bucket_arn:    Option<String>,
    pub creation_date: SystemTime,
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
        code:       code.to_string(),
        message:    message.to_string(),
        resource:   resource.map(|s| s.to_string()),
        request_id: request_id.map(|s| s.to_string()),
        host_id:    host_id.map(|s| s.to_string()),
    };

    let xml = to_xml_string(&doc).map_err(|e| anyhow!("xml serialize error: {e}"))?;
    Ok(xml.into_bytes())
}

pub fn list_buckets_body(
    owner_id: &str,
    owner_display_name: &str,
    buckets: &[BucketInfo],
) -> Result<Vec<u8>> {
    list_buckets_body_paginated(owner_id, owner_display_name, buckets, None, None)
}

/// Build XML body for ListBuckets (optionally paginated/filter-aware).
///
/// `next_continuation_token` is included only when there are more buckets to list.
/// `prefix` is echoed in the response only when it was provided in the request.
pub fn list_buckets_body_paginated(
    owner_id: &str,
    owner_display_name: &str,
    buckets: &[BucketInfo],
    prefix: Option<&str>,
    next_continuation_token: Option<&str>,
) -> Result<Vec<u8>> {
    let doc = ListAllMyBucketsResult {
        xmlns:              S3_XMLNS,
        buckets:            Buckets {
            bucket: buckets
                .iter()
                .map(|b| Bucket {
                    bucket_arn:    b.bucket_arn.clone(),
                    bucket_region: b.bucket_region.clone(),
                    creation_date: format_s3_time_system(b.creation_date),
                    name:          b.name.clone(),
                })
                .collect(),
        },
        owner:              Owner {
            id:           owner_id.to_string(),
            display_name: owner_display_name.to_string(),
        },
        continuation_token: next_continuation_token.map(|s| s.to_string()),
        prefix:             prefix.map(|s| s.to_string()),
    };

    let xml = to_xml_string(&doc).map_err(|e| anyhow!("xml serialize error: {e}"))?;
    Ok(xml.into_bytes())
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

/// Build XML body for GetObjectAcl / GetBucketAcl.
///
/// Mirrors the response AWS S3 emits in `bucket-owner-enforced` ownership mode
/// (ACLs disabled): a single `FULL_CONTROL` grant for the owner. Real
/// authorization in s32p comes from the proxy's directory ACL plus POSIX
/// permissions, not from S3 ACL state, so this is informational metadata only.
///
/// When `world_readable` is true, an additional `READ` grant for the canonical
/// `Group: AllUsers` URI is appended — this is the one POSIX-mode bit (`o+r`)
/// that translates losslessly into a standard S3 ACL grantee, so clients that
/// inspect ACLs see a truthful "this object is publicly readable" signal.
/// Group-readable POSIX bits have no S3 equivalent and are intentionally
/// dropped on the floor.
pub fn get_acl_body(
    owner_id: &str,
    owner_display_name: &str,
    world_readable: bool,
) -> Result<Vec<u8>> {
    const XSI_NS: &str = "http://www.w3.org/2001/XMLSchema-instance";
    const ALL_USERS_URI: &str = "http://acs.amazonaws.com/groups/global/AllUsers";

    let mut grants = vec![Grant {
        grantee:    Grantee {
            xmlns_xsi:    XSI_NS,
            xsi_type:     "CanonicalUser",
            id:           Some(owner_id.to_string()),
            display_name: Some(owner_display_name.to_string()),
            uri:          None,
        },
        permission: "FULL_CONTROL",
    }];

    if world_readable {
        grants.push(Grant {
            grantee:    Grantee {
                xmlns_xsi:    XSI_NS,
                xsi_type:     "Group",
                id:           None,
                display_name: None,
                uri:          Some(ALL_USERS_URI.to_string()),
            },
            permission: "READ",
        });
    }

    let doc = AccessControlPolicyDoc {
        xmlns:               S3_XMLNS,
        owner:               AclOwner {
            id:           owner_id.to_string(),
            display_name: owner_display_name.to_string(),
        },
        access_control_list: AccessControlList { grant: grants },
    };

    let xml = to_xml_string(&doc).map_err(|e| anyhow!("xml serialize error: {e}"))?;
    Ok(xml.into_bytes())
}

/// Build XML body for CreateSession (S3 Express directory-bucket session
/// establishment). Mirrors AWS's `<CreateSessionResult>` wire format so SDKs
/// in directory-bucket mode (boto3, AWS CLI, mountpoint-s3) can parse it.
///
/// The credentials passed here are the *ephemeral* triple minted by the
/// proxy's session store — never the caller's long-term IAM secret.
pub fn create_session_result_body(
    access_key: &str,
    secret_key: &str,
    session_token: &str,
    expiration: SystemTime,
) -> Result<Vec<u8>> {
    let doc = CreateSessionResultDoc {
        credentials: SessionCredentials {
            access_key_id:     access_key.to_string(),
            secret_access_key: secret_key.to_string(),
            session_token:     session_token.to_string(),
            expiration:        format_s3_time_system(expiration),
        },
    };
    let xml = to_xml_string(&doc).map_err(|e| anyhow!("xml serialize error: {e}"))?;
    Ok(xml.into_bytes())
}

/// Format SystemTime into S3 list time format (UTC with trailing Z).
pub fn format_s3_time_system(st: SystemTime) -> String {
    let dt = match OffsetDateTime::from(st) {
        dt => dt.to_offset(UtcOffset::UTC),
    };
    let fmt =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z");
    dt.format(&fmt).unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// Build XML body for ListObjectsV2 (GET ?list-type=2).
pub fn list_objects_v2_body(
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
    contents: &[ListObjectInfo],
    common_prefixes: &[String],
) -> Result<Vec<u8>> {
    let doc = ListBucketResultV2 {
        xmlns: S3_XMLNS,
        name: bucket_name.to_string(),
        prefix: prefix.filter(|s| !s.is_empty()).map(|s| s.to_string()),
        delimiter: delimiter.filter(|s| !s.is_empty()).map(|s| s.to_string()),
        key_count,
        max_keys,
        is_truncated,
        continuation_token: continuation_token.map(|s| s.to_string()),
        next_continuation_token: next_continuation_token.map(|s| s.to_string()),
        start_after: start_after.map(|s| s.to_string()),
        encoding_type: encoding_type.filter(|s| !s.is_empty()).map(|s| s.to_string()),
        contents: contents
            .iter()
            .map(|o| ContentsV2 {
                key:           o.key.clone(),
                last_modified: o.last_modified.clone(),
                etag:          o.etag.clone(),
                size:          o.size,
                storage_class: "STANDARD".to_string(),
                owner:         o.owner.as_ref().map(|ow| OwnerV2 {
                    id:           ow.id.clone(),
                    display_name: ow.display_name.clone(),
                }),
            })
            .collect(),
        common_prefixes: common_prefixes
            .iter()
            .map(|p| CommonPrefixesV2 { prefix: p.clone() })
            .collect(),
    };

    let xml = to_xml_string(&doc).map_err(|e| anyhow!("xml serialize error: {e}"))?;
    Ok(xml.into_bytes())
}

/// Build XML body for ListObjectsV1 (`GET /{bucket}` legacy form).
/// Differences vs. v2: pagination uses `Marker`/`NextMarker` (a key, not an opaque
/// token), `Owner` is always included in `Contents`, and there's no `KeyCount`.
pub fn list_objects_v1_body(
    bucket_name: &str,
    prefix: &str,
    delimiter: Option<&str>,
    marker: &str,
    next_marker: Option<&str>,
    max_keys: u32,
    is_truncated: bool,
    encoding_type: Option<&str>,
    contents: &[ListObjectInfo],
    common_prefixes: &[String],
) -> Result<Vec<u8>> {
    let doc = ListBucketResultV1 {
        xmlns: S3_XMLNS,
        name: bucket_name.to_string(),
        prefix: prefix.to_string(),
        marker: marker.to_string(),
        next_marker: next_marker.map(|s| s.to_string()),
        delimiter: delimiter.filter(|s| !s.is_empty()).map(|s| s.to_string()),
        max_keys,
        is_truncated,
        encoding_type: encoding_type.filter(|s| !s.is_empty()).map(|s| s.to_string()),
        contents: contents
            .iter()
            .map(|o| {
                let owner = o.owner.clone().unwrap_or_else(|| ListOwnerInfo {
                    id:           String::new(),
                    display_name: String::new(),
                });
                ContentsV1 {
                    key:           o.key.clone(),
                    last_modified: o.last_modified.clone(),
                    etag:          o.etag.clone(),
                    size:          o.size,
                    storage_class: "STANDARD".to_string(),
                    owner:         OwnerV1 {
                        id:           owner.id,
                        display_name: owner.display_name,
                    },
                }
            })
            .collect(),
        common_prefixes: common_prefixes
            .iter()
            .map(|p| CommonPrefixesV1 { prefix: p.clone() })
            .collect(),
    };

    let xml = to_xml_string(&doc).map_err(|e| anyhow!("xml serialize error: {e}"))?;
    Ok(xml.into_bytes())
}

/* -------------------------
 * CopyObject response
 * ------------------------- */

/// Build XML body for CopyObject (PUT with x-amz-copy-source).
/// Includes all optional checksum fields as empty tags (we don't compute checksums during copy).
pub fn copy_object_result_body(last_modified: &str, etag: &str) -> Result<Vec<u8>> {
    let doc = CopyObjectResultDoc {
        xmlns:           S3_XMLNS,
        last_modified:   last_modified.to_string(),
        etag:            etag.to_string(),
        checksum_crc32:  Some(String::new()),
        checksum_crc32c: Some(String::new()),
        checksum_sha1:   Some(String::new()),
        checksum_sha256: Some(String::new()),
    };

    let xml = to_xml_string(&doc).map_err(|e| anyhow!("xml serialize error: {e}"))?;
    Ok(xml.into_bytes())
}

/* -------------------------
 * DeleteObjects (multi-delete) response
 * ------------------------- */

#[derive(Clone, Debug)]
pub struct DeleteErrorInfo {
    pub key:     String,
    pub code:    String,
    pub message: String,
}

/// Build XML body for DeleteObjects (POST ?delete).
pub fn delete_objects_result_body(
    deleted_keys: &[String],
    errors: &[DeleteErrorInfo],
) -> Result<Vec<u8>> {
    let doc = DeleteResultDoc {
        xmlns:   S3_XMLNS,
        deleted: deleted_keys.iter().map(|k| DeletedEntry { key: k.clone() }).collect(),
        errors:  errors
            .iter()
            .map(|e| DeleteErrorEntry {
                key:     e.key.clone(),
                code:    e.code.clone(),
                message: e.message.clone(),
            })
            .collect(),
    };

    let xml = to_xml_string(&doc).map_err(|e| anyhow!("xml serialize error: {e}"))?;
    Ok(xml.into_bytes())
}

/* -------------------------
 * Multipart Upload responses
 * ------------------------- */

#[derive(Clone, Debug)]
pub struct MultipartUploadInfo {
    pub key:       String,
    pub upload_id: String,
    pub initiated: String, // ISO8601 Z
}

#[derive(Clone, Debug)]
pub struct MultipartPartInfo {
    pub part_number:   u32,
    pub last_modified: String, // ISO8601 Z
    pub etag:          String, // include quotes
    pub size:          u64,
}

pub fn initiate_multipart_upload_result_body(
    bucket: &str,
    key: &str,
    upload_id: &str,
) -> Result<Vec<u8>> {
    let doc = InitiateMultipartUploadResultDoc {
        xmlns:     S3_XMLNS,
        bucket:    bucket.to_string(),
        key:       key.to_string(),
        upload_id: upload_id.to_string(),
    };
    let xml = to_xml_string(&doc).map_err(|e| anyhow!("xml serialize error: {e}"))?;
    Ok(xml.into_bytes())
}

pub fn list_multipart_uploads_body(
    bucket: &str,
    uploads: &[MultipartUploadInfo],
) -> Result<Vec<u8>> {
    let doc = ListMultipartUploadsResultDoc {
        xmlns:   S3_XMLNS,
        bucket:  bucket.to_string(),
        uploads: uploads
            .iter()
            .map(|u| UploadEntry {
                key:       u.key.clone(),
                upload_id: u.upload_id.clone(),
                initiated: u.initiated.clone(),
            })
            .collect(),
    };
    let xml = to_xml_string(&doc).map_err(|e| anyhow!("xml serialize error: {e}"))?;
    Ok(xml.into_bytes())
}

pub fn list_parts_body(
    bucket: &str,
    key: &str,
    upload_id: &str,
    parts: &[MultipartPartInfo],
) -> Result<Vec<u8>> {
    let doc = ListPartsResultDoc {
        xmlns:     S3_XMLNS,
        bucket:    bucket.to_string(),
        key:       key.to_string(),
        upload_id: upload_id.to_string(),
        parts:     parts
            .iter()
            .map(|p| PartEntry {
                part_number:   p.part_number,
                last_modified: p.last_modified.clone(),
                etag:          p.etag.clone(),
                size:          p.size,
            })
            .collect(),
    };
    let xml = to_xml_string(&doc).map_err(|e| anyhow!("xml serialize error: {e}"))?;
    Ok(xml.into_bytes())
}

pub fn complete_multipart_upload_result_body(
    location: &str,
    bucket: &str,
    key: &str,
    etag: &str,
) -> Result<Vec<u8>> {
    let doc = CompleteMultipartUploadResultDoc {
        xmlns:    S3_XMLNS,
        location: location.to_string(),
        bucket:   bucket.to_string(),
        key:      key.to_string(),
        etag:     etag.to_string(),
    };
    let xml = to_xml_string(&doc).map_err(|e| anyhow!("xml serialize error: {e}"))?;
    Ok(xml.into_bytes())
}

#[derive(Debug, Serialize)]
#[serde(rename = "InitiateMultipartUploadResult")]
struct InitiateMultipartUploadResultDoc {
    #[serde(rename = "@xmlns")]
    xmlns: &'static str,

    #[serde(rename = "Bucket")]
    bucket:    String,
    #[serde(rename = "Key")]
    key:       String,
    #[serde(rename = "UploadId")]
    upload_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename = "ListMultipartUploadsResult")]
struct ListMultipartUploadsResultDoc {
    #[serde(rename = "@xmlns")]
    xmlns: &'static str,

    #[serde(rename = "Bucket")]
    bucket: String,

    #[serde(rename = "Upload", default, skip_serializing_if = "Vec::is_empty")]
    uploads: Vec<UploadEntry>,
}

#[derive(Debug, Serialize)]
struct UploadEntry {
    #[serde(rename = "Key")]
    key:       String,
    #[serde(rename = "UploadId")]
    upload_id: String,
    #[serde(rename = "Initiated")]
    initiated: String,
}

#[derive(Debug, Serialize)]
#[serde(rename = "ListPartsResult")]
struct ListPartsResultDoc {
    #[serde(rename = "@xmlns")]
    xmlns: &'static str,

    #[serde(rename = "Bucket")]
    bucket:    String,
    #[serde(rename = "Key")]
    key:       String,
    #[serde(rename = "UploadId")]
    upload_id: String,

    #[serde(rename = "Part", default, skip_serializing_if = "Vec::is_empty")]
    parts: Vec<PartEntry>,
}

#[derive(Debug, Serialize)]
struct PartEntry {
    #[serde(rename = "PartNumber")]
    part_number:   u32,
    #[serde(rename = "LastModified")]
    last_modified: String,
    #[serde(rename = "ETag")]
    etag:          String,
    #[serde(rename = "Size")]
    size:          u64,
}

#[derive(Debug, Serialize)]
#[serde(rename = "CompleteMultipartUploadResult")]
struct CompleteMultipartUploadResultDoc {
    #[serde(rename = "@xmlns")]
    xmlns: &'static str,

    #[serde(rename = "Location")]
    location: String,
    #[serde(rename = "Bucket")]
    bucket:   String,
    #[serde(rename = "Key")]
    key:      String,
    #[serde(rename = "ETag")]
    etag:     String,
}

/* -------------------------
 * XML DTOs
 * ------------------------- */

#[derive(Debug, Serialize)]
#[serde(rename = "Error")]
struct ErrorDocument {
    #[serde(rename = "Code")]
    code:    String,
    #[serde(rename = "Message")]
    message: String,

    #[serde(rename = "Resource", skip_serializing_if = "Option::is_none")]
    resource:   Option<String>,
    #[serde(rename = "RequestId", skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    #[serde(rename = "HostId", skip_serializing_if = "Option::is_none")]
    host_id:    Option<String>,
}

// --- public DTOs for ListBuckets ---

#[derive(Debug, Serialize)]
#[serde(rename = "ListAllMyBucketsResult")]
struct ListAllMyBucketsResult {
    #[serde(rename = "@xmlns")]
    xmlns: &'static str,

    #[serde(rename = "Buckets")]
    buckets: Buckets,

    #[serde(rename = "Owner")]
    owner: Owner,

    #[serde(rename = "ContinuationToken", skip_serializing_if = "Option::is_none")]
    continuation_token: Option<String>,

    #[serde(rename = "Prefix", skip_serializing_if = "Option::is_none")]
    prefix: Option<String>,
}

#[derive(Debug, Serialize)]
struct Owner {
    #[serde(rename = "ID")]
    id:           String,
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
    #[serde(rename = "BucketArn", skip_serializing_if = "Option::is_none")]
    bucket_arn: Option<String>,

    #[serde(rename = "BucketRegion", skip_serializing_if = "Option::is_none")]
    bucket_region: Option<String>,

    #[serde(rename = "Name")]
    name:          String,
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

// --- internal DTOs for GetObjectAcl / GetBucketAcl ---

#[derive(Debug, Serialize)]
#[serde(rename = "AccessControlPolicy")]
struct AccessControlPolicyDoc {
    #[serde(rename = "@xmlns")]
    xmlns:               &'static str,
    #[serde(rename = "Owner")]
    owner:               AclOwner,
    #[serde(rename = "AccessControlList")]
    access_control_list: AccessControlList,
}

#[derive(Debug, Serialize)]
struct AclOwner {
    #[serde(rename = "ID")]
    id:           String,
    #[serde(rename = "DisplayName")]
    display_name: String,
}

#[derive(Debug, Serialize)]
struct AccessControlList {
    #[serde(rename = "Grant")]
    grant: Vec<Grant>,
}

#[derive(Debug, Serialize)]
struct Grant {
    #[serde(rename = "Grantee")]
    grantee:    Grantee,
    #[serde(rename = "Permission")]
    permission: &'static str,
}

#[derive(Debug, Serialize)]
struct Grantee {
    #[serde(rename = "@xmlns:xsi")]
    xmlns_xsi:    &'static str,
    #[serde(rename = "@xsi:type")]
    xsi_type:     &'static str,
    #[serde(rename = "ID", skip_serializing_if = "Option::is_none")]
    id:           Option<String>,
    #[serde(rename = "DisplayName", skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(rename = "URI", skip_serializing_if = "Option::is_none")]
    uri:          Option<String>,
}

// --- public DTOs for ListObjectsV2 ---

#[derive(Clone, Debug)]
pub struct ListOwnerInfo {
    pub id:           String,
    pub display_name: String,
}

#[derive(Clone, Debug)]
pub struct ListObjectInfo {
    pub key:           String,
    pub last_modified: String, // ISO8601 UTC "YYYY-MM-DDTHH:MM:SSZ"
    pub etag:          String, // include quotes, e.g. "\"123\""
    pub size:          u64,
    pub owner:         Option<ListOwnerInfo>,
}

#[derive(Debug, Serialize)]
#[serde(rename = "ListBucketResult")]
struct ListBucketResultV2 {
    #[serde(rename = "@xmlns")]
    xmlns: &'static str,

    #[serde(rename = "Name")]
    name: String,

    #[serde(rename = "Prefix", skip_serializing_if = "Option::is_none")]
    prefix: Option<String>,

    #[serde(rename = "Delimiter", skip_serializing_if = "Option::is_none")]
    delimiter: Option<String>,

    #[serde(rename = "KeyCount")]
    key_count: u32,

    #[serde(rename = "MaxKeys")]
    max_keys: u32,

    #[serde(rename = "IsTruncated")]
    is_truncated: bool,

    #[serde(rename = "ContinuationToken", skip_serializing_if = "Option::is_none")]
    continuation_token: Option<String>,

    #[serde(rename = "NextContinuationToken", skip_serializing_if = "Option::is_none")]
    next_continuation_token: Option<String>,

    #[serde(rename = "StartAfter", skip_serializing_if = "Option::is_none")]
    start_after: Option<String>,

    #[serde(rename = "EncodingType", skip_serializing_if = "Option::is_none")]
    encoding_type: Option<String>,

    #[serde(rename = "Contents", default, skip_serializing_if = "Vec::is_empty")]
    contents: Vec<ContentsV2>,

    #[serde(rename = "CommonPrefixes", default, skip_serializing_if = "Vec::is_empty")]
    common_prefixes: Vec<CommonPrefixesV2>,
}

#[derive(Debug, Serialize)]
struct ContentsV2 {
    #[serde(rename = "Key")]
    key:           String,
    #[serde(rename = "LastModified")]
    last_modified: String,
    #[serde(rename = "ETag")]
    etag:          String,
    #[serde(rename = "Size")]
    size:          u64,
    #[serde(rename = "StorageClass")]
    storage_class: String,

    #[serde(rename = "Owner", skip_serializing_if = "Option::is_none")]
    owner: Option<OwnerV2>,
}

#[derive(Debug, Serialize)]
struct OwnerV2 {
    #[serde(rename = "ID")]
    id:           String,
    #[serde(rename = "DisplayName")]
    display_name: String,
}

#[derive(Debug, Serialize)]
struct CommonPrefixesV2 {
    #[serde(rename = "Prefix")]
    prefix: String,
}

// --- internal DTOs for ListObjectsV1 ---

#[derive(Debug, Serialize)]
#[serde(rename = "ListBucketResult")]
struct ListBucketResultV1 {
    #[serde(rename = "@xmlns")]
    xmlns: &'static str,

    #[serde(rename = "Name")]
    name: String,

    #[serde(rename = "Prefix")]
    prefix: String, // empty string if absent — v1 spec always emits this element

    #[serde(rename = "Marker")]
    marker: String, // empty string if absent — v1 spec always emits this element

    #[serde(rename = "NextMarker", skip_serializing_if = "Option::is_none")]
    next_marker: Option<String>,

    #[serde(rename = "Delimiter", skip_serializing_if = "Option::is_none")]
    delimiter: Option<String>,

    #[serde(rename = "MaxKeys")]
    max_keys: u32,

    #[serde(rename = "IsTruncated")]
    is_truncated: bool,

    #[serde(rename = "EncodingType", skip_serializing_if = "Option::is_none")]
    encoding_type: Option<String>,

    #[serde(rename = "Contents", default, skip_serializing_if = "Vec::is_empty")]
    contents: Vec<ContentsV1>,

    #[serde(rename = "CommonPrefixes", default, skip_serializing_if = "Vec::is_empty")]
    common_prefixes: Vec<CommonPrefixesV1>,
}

#[derive(Debug, Serialize)]
struct ContentsV1 {
    #[serde(rename = "Key")]
    key:           String,
    #[serde(rename = "LastModified")]
    last_modified: String,
    #[serde(rename = "ETag")]
    etag:          String,
    #[serde(rename = "Size")]
    size:          u64,
    #[serde(rename = "StorageClass")]
    storage_class: String,
    // v1 Contents always carries Owner (unlike v2 where it's optional via fetch-owner).
    #[serde(rename = "Owner")]
    owner:         OwnerV1,
}

#[derive(Debug, Serialize)]
struct OwnerV1 {
    #[serde(rename = "ID")]
    id:           String,
    #[serde(rename = "DisplayName")]
    display_name: String,
}

#[derive(Debug, Serialize)]
struct CommonPrefixesV1 {
    #[serde(rename = "Prefix")]
    prefix: String,
}

// --- internal DTOs for CreateSession response ---

#[derive(Debug, Serialize)]
#[serde(rename = "CreateSessionResult")]
struct CreateSessionResultDoc {
    #[serde(rename = "Credentials")]
    credentials: SessionCredentials,
}

#[derive(Debug, Serialize)]
struct SessionCredentials {
    #[serde(rename = "AccessKeyId")]
    access_key_id:     String,
    #[serde(rename = "SecretAccessKey")]
    secret_access_key: String,
    #[serde(rename = "SessionToken")]
    session_token:     String,
    #[serde(rename = "Expiration")]
    expiration:        String,
}

// --- internal DTOs for CopyObject response ---

#[derive(Debug, Serialize)]
#[serde(rename = "CopyObjectResult")]
struct CopyObjectResultDoc {
    #[serde(rename = "@xmlns")]
    xmlns: &'static str,

    #[serde(rename = "LastModified")]
    last_modified: String,

    #[serde(rename = "ETag")]
    etag: String,

    #[serde(rename = "ChecksumCRC32", skip_serializing_if = "Option::is_none")]
    checksum_crc32:  Option<String>,
    #[serde(rename = "ChecksumCRC32C", skip_serializing_if = "Option::is_none")]
    checksum_crc32c: Option<String>,
    #[serde(rename = "ChecksumSHA1", skip_serializing_if = "Option::is_none")]
    checksum_sha1:   Option<String>,
    #[serde(rename = "ChecksumSHA256", skip_serializing_if = "Option::is_none")]
    checksum_sha256: Option<String>,
}

// --- internal DTOs for DeleteObjects response ---

#[derive(Debug, Serialize)]
#[serde(rename = "DeleteResult")]
struct DeleteResultDoc {
    #[serde(rename = "@xmlns")]
    xmlns: &'static str,

    #[serde(rename = "Deleted", default, skip_serializing_if = "Vec::is_empty")]
    deleted: Vec<DeletedEntry>,

    #[serde(rename = "Error", default, skip_serializing_if = "Vec::is_empty")]
    errors: Vec<DeleteErrorEntry>,
}

#[derive(Debug, Serialize)]
struct DeletedEntry {
    #[serde(rename = "Key")]
    key: String,
}

#[derive(Debug, Serialize)]
struct DeleteErrorEntry {
    #[serde(rename = "Key")]
    key:     String,
    #[serde(rename = "Code")]
    code:    String,
    #[serde(rename = "Message")]
    message: String,
}

/* -------------------------
 * XML request parsers (gateway)
 * ------------------------- */

fn local_name(name: &[u8]) -> &[u8] {
    match name.iter().rposition(|&b| b == b':') {
        Some(i) => &name[i + 1..],
        None => name,
    }
}

/// Minimal parser for DeleteObjects request:
/// <Delete><Quiet>true</Quiet><Object><Key>k</Key></Object>...</Delete>
pub fn parse_delete_objects_request(xml: &[u8]) -> Result<(bool, Vec<String>)> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut keys: Vec<String> = Vec::new();
    let mut quiet = false;

    let mut in_key = false;
    let mut in_quiet = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = e.name();
                let n = local_name(name.as_ref());
                if n == b"Key" {
                    in_key = true;
                } else if n == b"Quiet" {
                    in_quiet = true;
                }
            }
            Ok(Event::End(e)) => {
                let name = e.name();
                let n = local_name(name.as_ref());
                if n == b"Key" {
                    in_key = false;
                } else if n == b"Quiet" {
                    in_quiet = false;
                }
            }
            Ok(Event::Text(t)) => {
                let s = t
                    .xml_content(XmlVersion::Implicit1_0)
                    .map_err(|e| anyhow!("xml text decode error: {e}"))?
                    .into_owned();
                if in_key {
                    if !s.is_empty() {
                        keys.push(s);
                    }
                } else if in_quiet {
                    let v = s.trim();
                    quiet = v.eq_ignore_ascii_case("true") || v == "1";
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(anyhow!("bad DeleteObjects XML: {e}")),
            _ => {}
        }
        buf.clear();
    }

    Ok((quiet, keys))
}

/// Parse CompleteMultipartUpload body and return sorted unique PartNumber list.
pub fn parse_complete_parts(xml: &[u8]) -> Result<Vec<u32>> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut parts: Vec<u32> = Vec::new();
    let mut in_part_number = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = e.name();
                let local = local_name(name.as_ref());
                if local == b"PartNumber" {
                    in_part_number = true;
                }
            }
            Ok(Event::End(e)) => {
                let name = e.name();
                let local = local_name(name.as_ref());
                if local == b"PartNumber" {
                    in_part_number = false;
                }
            }
            Ok(Event::Text(t)) => {
                if in_part_number {
                    let s = t
                        .xml_content(XmlVersion::Implicit1_0)
                        .map_err(|e| anyhow!("xml text decode error: {e}"))?
                        .into_owned();
                    let pn: u32 =
                        s.trim().parse().map_err(|_| anyhow!("invalid PartNumber: {s}"))?;
                    parts.push(pn);
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(anyhow!("bad CompleteMultipartUpload XML: {e}")),
            _ => {}
        }
        buf.clear();
    }

    if parts.is_empty() {
        return Err(anyhow!("no parts in CompleteMultipartUpload"));
    }

    parts.sort_unstable();
    parts.dedup();
    Ok(parts)
}

/// Parse the body of a PutObjectAcl / PutBucketAcl request and determine
/// whether it grants public read access (a `Group: AllUsers` grantee with
/// `READ` or `FULL_CONTROL`). This is the only ACL bit s32p tracks (POSIX
/// `o+r`); all other grants are dropped on the floor in `get_acl_body` and
/// are likewise ignored here.
///
/// An empty body yields `false` (private). A body that fails to parse is an
/// error so the caller can reject the request.
pub fn parse_put_acl_request_world_readable(xml: &[u8]) -> Result<bool> {
    if xml.iter().all(u8::is_ascii_whitespace) {
        return Ok(false);
    }

    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut in_grantee = false;
    let mut in_uri = false;
    let mut in_permission = false;

    let mut current_uri: Option<String> = None;
    let mut current_permission: Option<String> = None;
    let mut world_readable = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = e.name();
                let local = local_name(name.as_ref());
                if local == b"Grantee" {
                    in_grantee = true;
                    current_uri = None;
                } else if in_grantee && local == b"URI" {
                    in_uri = true;
                } else if local == b"Grant" {
                    current_permission = None;
                } else if local == b"Permission" {
                    in_permission = true;
                }
            }
            Ok(Event::End(e)) => {
                let name = e.name();
                let local = local_name(name.as_ref());
                if local == b"Grantee" {
                    in_grantee = false;
                } else if local == b"URI" {
                    in_uri = false;
                } else if local == b"Permission" {
                    in_permission = false;
                } else if local == b"Grant" {
                    let public = current_uri.as_deref().is_some_and(|u| u.contains("AllUsers"));
                    let perm = current_permission.as_deref().unwrap_or("");
                    if public
                        && (perm.eq_ignore_ascii_case("READ")
                            || perm.eq_ignore_ascii_case("FULL_CONTROL"))
                    {
                        world_readable = true;
                    }
                    current_uri = None;
                    current_permission = None;
                }
            }
            Ok(Event::Text(t)) => {
                let s = t
                    .xml_content(XmlVersion::Implicit1_0)
                    .map_err(|e| anyhow!("xml text decode error: {e}"))?
                    .into_owned();
                if in_uri {
                    current_uri = Some(s);
                } else if in_permission {
                    current_permission = Some(s);
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(anyhow!("bad PutAcl XML: {e}")),
            _ => {}
        }
        buf.clear();
    }

    Ok(world_readable)
}
