use std::collections::HashMap;

use http::{HeaderMap, Uri};

use super::utils::parse_u32;

/// High-level classification for S3 REST requests.
/// Shared by proxy and gateway to avoid duplicated request parsing logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3RequestClass {
    /// Bucket name if present (path-style parsing for now).
    pub bucket: Option<String>,
    /// Object key if present (everything after bucket/).
    pub key:    Option<String>,
    /// Parsed query parameters (lowercased keys).
    pub query:  QueryParams,
    /// Classified operation bucket.
    pub op:     S3Op,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S3Op {
    /// Multipart upload related operation.
    Multipart(MultipartOp),
    /// Versioning related operation.
    Versioning(VersioningOp),
    /// Object Lock / retention / legal-hold related operation.
    ObjectLock(ObjectLockOp),
    /// Basic read operations (we’ll add more here later).
    Read(ReadOp),
    /// Basic write operations.
    Write(WriteOp),
    /// Bucket administration operations.
    BucketAdmin(BucketAdminOp),
    /// Session / authorization operations (S3 Express directory-bucket flow).
    Session(SessionOp),
    /// Service-level (no bucket, no key) probe. The only documented S3
    /// op at the service endpoint is `GET /` (ListBuckets) — `HEAD /` is
    /// the connectivity probe that clients like Cyberduck / MountainDuck,
    /// mc, and similar issue before doing real work. AWS returns 405
    /// Method Not Allowed; we mirror that under the `aws_compat` action.
    HeadService,
    /// Anything else (for now).
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultipartOp {
    /// POST /{bucket}/{key}?uploads
    CreateMultipartUpload,
    /// PUT /{bucket}/{key}?partNumber=N&uploadId=...
    UploadPart { upload_id: String, part_number: u32 },
    /// GET /{bucket}/{key}?uploadId=...
    ListParts { upload_id: String },
    /// POST /{bucket}/{key}?uploadId=...
    CompleteMultipartUpload { upload_id: String },
    /// DELETE /{bucket}/{key}?uploadId=...
    AbortMultipartUpload { upload_id: String },
    /// GET /{bucket}?uploads
    ListMultipartUploads,
    /// Some multipart-ish request we recognized as multipart but couldn't fully parse.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersioningOp {
    /// GET /{bucket}?versioning
    GetBucketVersioning,
    /// PUT /{bucket}?versioning
    PutBucketVersioning,
    /// GET /{bucket}?versions
    ListObjectVersions,
    /// Any object-level request with ?versionId=...
    ObjectWithVersionId { version_id: String },
    /// Some versioning-ish request we recognized as versioning but couldn't fully parse.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectLockOp {
    /// GET /{bucket}?object-lock
    GetBucketObjectLockConfiguration,
    /// PUT /{bucket}?object-lock
    PutBucketObjectLockConfiguration,

    /// GET /{bucket}/{key}?retention
    GetObjectRetention,
    /// PUT /{bucket}/{key}?retention
    PutObjectRetention,

    /// GET /{bucket}/{key}?legal-hold
    GetObjectLegalHold,
    /// PUT /{bucket}/{key}?legal-hold
    PutObjectLegalHold,

    /// Some object-lock-ish request we recognized but couldn't fully parse.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadOp {
    /// GET / (ListBuckets)
    ListBuckets,
    /// GET /{bucket}/{key} (no query params)
    GetObject,
    /// HEAD /{bucket}/{key} (no query params)
    HeadObject,
    /// HEAD /{bucket} (no query params)
    HeadBucket,
    /// GET /{bucket}?location or GET /{bucket}/?location
    GetBucketLocation,
    /// GET /{bucket}?list-type=2 (ListObjectsV2)
    ListObjectsV2,
    /// GET /{bucket} (ListObjectsV1, the legacy form). Matches a plain bucket-level
    /// GET that isn't any other recognized op (`?location`, `?versioning`, multipart,
    /// object lock, V2 listing). v1 query params (`prefix`, `delimiter`, `marker`,
    /// `max-keys`, `encoding-type`) are all optional.
    ListObjectsV1,
    /// GET /{bucket}/{key}?acl
    GetObjectAcl,
    /// GET /{bucket}?acl
    GetBucketAcl,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteOp {
    /// PUT /{bucket}/{key} (no query params)
    PutObject,
    /// PUT /{bucket}/{key} with x-amz-copy-source
    CopyObject,
    /// PUT /{bucket}/{key}?renameObject with x-amz-rename-source
    RenameObject,
    /// DELETE /{bucket}/{key} (no query params)
    DeleteObject,
    /// POST /{bucket}?delete
    DeleteObjects,
    /// PUT /{bucket}/{key}?acl
    PutObjectAcl,
    /// PUT /{bucket}?acl
    PutBucketAcl,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BucketAdminOp {
    /// PUT /{bucket}
    CreateBucket,
    /// DELETE /{bucket}
    DeleteBucket,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionOp {
    /// GET /{bucket}?session — S3 Express directory-bucket session establishment.
    CreateSession,
}

/// Parse/validate conditional headers.

/// Parsed query params with lowercased keys.
/// Values are percent-decoded (via url::form_urlencoded), which is correct for routing.
/// Presence-only parameters are stored as empty string value (e.g. "?uploads" -> ("uploads","")).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueryParams {
    // key -> list of values; presence-only parameters are stored as empty string value.
    inner: HashMap<String, Vec<String>>,
}

impl QueryParams {
    pub fn from_uri(uri: &Uri) -> Self {
        let mut out = QueryParams::default();
        let q = match uri.query() {
            Some(q) if !q.is_empty() => q,
            _ => return out,
        };

        for (k, v) in url::form_urlencoded::parse(q.as_bytes()) {
            let key = k.trim().to_ascii_lowercase();
            if key.is_empty() {
                continue;
            }
            out.inner.entry(key).or_default().push(v.into_owned());
        }

        out
    }

    pub fn has(&self, key: &str) -> bool {
        self.inner.contains_key(&key.to_ascii_lowercase())
    }

    pub fn first(&self, key: &str) -> Option<&str> {
        self.inner
            .get(&key.to_ascii_lowercase())
            .and_then(|v| v.first())
            .map(|s| s.as_str())
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn is_only(&self, key: &str) -> bool {
        self.inner.len() == 1 && self.has(key)
    }

    /// SigV4 presign query keys that should be ignored for routing/classification decisions.
    /// (We still keep them in `query` for handlers that need them.)
    fn is_sigv4_presign_key(key_lc: &str) -> bool {
        matches!(
            key_lc,
            "x-amz-algorithm"
                | "x-amz-credential"
                | "x-amz-date"
                | "x-amz-expires"
                | "x-amz-signedheaders"
                | "x-amz-signature"
                | "x-amz-security-token"
                // `x-amz-s3session-token` is the S3 Express equivalent of
                // `x-amz-security-token`: it carries the ephemeral session
                // token in presigned URLs minted from a CreateSession
                // response. Same routing posture — ignore for
                // classification, but the proxy reads it for session
                // lookup (see `presign_session_token_from_query` in
                // `s32p-proxy/src/main.rs`).
                | "x-amz-s3session-token"
        )
    }

    /// Non-effective query keys that should be ignored for routing/classification decisions
    /// but are not SigV4 presign parameters. These can be validated but don't affect operation routing.
    fn is_non_effective_key(key_lc: &str) -> bool {
        matches!(
            key_lc,
            "x-id"
                | "content-type"
                | "cache-control"
                | "content-encoding"
                | "content-disposition"
                | "expires"
                | "x-amz-storage-class"
        )
    }

    /// Validate x-id if present - returns true if x-id is absent or matches the expected operation name
    pub fn validate_xid(&self, expected_op_name: &str) -> bool {
        match self.first("x-id") {
            Some(xid_value) => xid_value == expected_op_name,
            None => true, // x-id not present is always valid
        }
    }

    /// True if there are no *effective* query params except SigV4-presign params and non-effective keys.
    pub fn is_empty_effective(&self) -> bool {
        self.inner.keys().all(|k| {
            Self::is_sigv4_presign_key(k.as_str()) || Self::is_non_effective_key(k.as_str())
        })
    }

    /// True if the only *effective* (non-presign, non-non-effective) query param key is `key`.
    pub fn is_only_effective(&self, key: &str) -> bool {
        let key_lc = key.to_ascii_lowercase();

        let mut non_effective_keys = 0usize;
        let mut has_key = false;

        for k in self.inner.keys() {
            if Self::is_sigv4_presign_key(k.as_str()) || Self::is_non_effective_key(k.as_str()) {
                continue;
            }
            non_effective_keys += 1;
            if *k == key_lc {
                has_key = true;
            }
        }

        non_effective_keys == 1 && has_key
    }
}

impl S3Op {
    /// True for ops that mutate bucket or object state.
    ///
    /// Used by both proxy and gateway to decide whether ACL access-level
    /// applies (a `read_only` grant must reject writes). More precise than
    /// dispatching on the HTTP method alone — `Multipart::ListParts` and
    /// `Multipart::ListMultipartUploads` are GET-style reads even though
    /// they live under the `Multipart` family, and `S3Op::Other` may be a
    /// PUT/POST/DELETE we don't classify.
    ///
    /// `Unknown` sub-variants and `Other` are treated as writes so a
    /// `read_only` caller cannot slip an unrecognized op through.
    pub fn needs_write(&self) -> bool {
        match self {
            S3Op::Read(_) => false,
            S3Op::Write(_) => true,
            S3Op::Multipart(op) => match op {
                MultipartOp::ListParts { .. } | MultipartOp::ListMultipartUploads => false,
                MultipartOp::CreateMultipartUpload
                | MultipartOp::UploadPart { .. }
                | MultipartOp::CompleteMultipartUpload { .. }
                | MultipartOp::AbortMultipartUpload { .. }
                | MultipartOp::Unknown => true,
            },
            S3Op::Versioning(op) => match op {
                VersioningOp::GetBucketVersioning
                | VersioningOp::ListObjectVersions
                | VersioningOp::ObjectWithVersionId { .. } => false,
                VersioningOp::PutBucketVersioning | VersioningOp::Unknown => true,
            },
            S3Op::ObjectLock(op) => match op {
                ObjectLockOp::GetBucketObjectLockConfiguration
                | ObjectLockOp::GetObjectRetention
                | ObjectLockOp::GetObjectLegalHold => false,
                ObjectLockOp::PutBucketObjectLockConfiguration
                | ObjectLockOp::PutObjectRetention
                | ObjectLockOp::PutObjectLegalHold
                | ObjectLockOp::Unknown => true,
            },
            S3Op::BucketAdmin(_) => true,
            S3Op::Session(_) => false,
            // HeadService is a pure liveness probe — no state involved.
            S3Op::HeadService => false,
            S3Op::Other => true,
        }
    }
}

/// Convert a parsed class into a stable routing key used by config/routing.
/// This keeps the routing table simple (multipart/versioning/getobject/other).
pub fn class_key(class: &S3RequestClass) -> &'static str {
    match &class.op {
        S3Op::Multipart(_) => "multipart",
        S3Op::Versioning(_) => "versioning",
        S3Op::ObjectLock(_) => "object_lock",
        S3Op::Read(_) => "read",
        S3Op::Write(_) => "write",
        S3Op::BucketAdmin(_) => "bucket_admin",
        S3Op::Session(_) => "session",
        S3Op::HeadService => "service",
        S3Op::Other => "other",
    }
}

/// Classify an incoming request into S3 operation buckets, using headers when needed.
/// (CopyObject is distinguished from PutObject via x-amz-copy-source.)
///
/// This function automatically detects virtual-hosted-style vs path-style requests
/// based on the Host header and virtual_hosted_suffixes configuration.
pub fn classify_with_headers(
    method: &str,
    uri: &Uri,
    headers: Option<&HeaderMap>,
    virtual_hosted_suffixes: &[String],
) -> S3RequestClass {
    let (bucket, key, _is_virtual_hosted) =
        parse_bucket_key_auto(method, uri, headers, virtual_hosted_suffixes);
    let query = QueryParams::from_uri(uri);

    // Rest of the classification logic...

    // ListBuckets: GET / (may include pagination/filter query params, allow x-id)
    if method == "GET" && bucket.is_none() && key.is_none() && query.validate_xid("ListBuckets") {
        return S3RequestClass { bucket, key, query, op: S3Op::Read(ReadOp::ListBuckets) };
    }

    // HeadService: HEAD / with no bucket/key/query. Service-level HEAD is
    // not a documented S3 operation; AWS returns 405 Method Not Allowed.
    // Clients like Cyberduck / MountainDuck and `mc` issue this as a
    // connectivity probe before doing real work — recognising it here
    // (instead of falling through to `Other` → operator-configured proxy
    // worker) lets the proxy answer 405 directly via `aws_compat`,
    // skipping SigV4 / worker spawn for what should be a liveness check.
    if method == "HEAD" && bucket.is_none() && key.is_none() && query.is_empty_effective() {
        return S3RequestClass { bucket, key, query, op: S3Op::HeadService };
    }

    // Detect multipart first (uploadId can coexist with versionId in theory,
    // but multipart routing is usually clearer).
    if let Some(op) = classify_multipart(method, &bucket, &key, &query) {
        return S3RequestClass { bucket, key, query, op: S3Op::Multipart(op) };
    }

    // ACL sub-resource (`?acl`) takes precedence over versioning detection so
    // a request like `?acl&versionId=...` is recognized as GetObjectAcl rather
    // than getting hijacked by `classify_versioning` (which would map any
    // request with versionId to the Versioning class — currently routed to
    // not_implemented). We ignore versionId because versioning isn't supported.
    if method == "GET" && bucket.is_some() && query.has("acl") {
        if key.is_some() && query.validate_xid("GetObjectAcl") {
            return S3RequestClass { bucket, key, query, op: S3Op::Read(ReadOp::GetObjectAcl) };
        }
        if key.is_none() && query.validate_xid("GetBucketAcl") {
            return S3RequestClass { bucket, key, query, op: S3Op::Read(ReadOp::GetBucketAcl) };
        }
    }

    // PUT ?acl: clients issuing a rename/copy often follow up with a
    // PutObjectAcl that mirrors the source's ACL. Classifying it as Write
    // (instead of falling through to Other → versitygw → 501) lets the
    // gateway accept it as a no-op when the requested ACL matches the
    // current POSIX state.
    if method == "PUT" && bucket.is_some() && query.has("acl") {
        if key.is_some() && query.validate_xid("PutObjectAcl") {
            return S3RequestClass { bucket, key, query, op: S3Op::Write(WriteOp::PutObjectAcl) };
        }
        if key.is_none() && query.validate_xid("PutBucketAcl") {
            return S3RequestClass { bucket, key, query, op: S3Op::Write(WriteOp::PutBucketAcl) };
        }
    }

    if let Some(op) = classify_versioning(method, &bucket, &key, &query) {
        return S3RequestClass { bucket, key, query, op: S3Op::Versioning(op) };
    }

    // Object lock / retention / legal-hold (query sub-resources).
    // This must come before versioning so "?retention&versionId=..." is treated as object-lock.
    if let Some(op) = classify_object_lock(method, &bucket, &key, &query) {
        return S3RequestClass { bucket, key, query, op: S3Op::ObjectLock(op) };
    }

    // GetBucketLocation: GET /{bucket}?location (or /{bucket}/?location), and ONLY that param (allow x-id)
    if method == "GET"
        && bucket.is_some()
        && key.is_none()
        && query.is_only_effective("location")
        && query.validate_xid("GetBucketLocation")
    {
        return S3RequestClass { bucket, key, query, op: S3Op::Read(ReadOp::GetBucketLocation) };
    }

    // CreateSession (S3 Express directory-bucket): GET /{bucket}?session, that param only.
    // Must come before ListObjectsV1 so it doesn't get swallowed by the V1 fallback.
    if method == "GET"
        && bucket.is_some()
        && key.is_none()
        && query.is_only_effective("session")
        && query.validate_xid("CreateSession")
    {
        return S3RequestClass { bucket, key, query, op: S3Op::Session(SessionOp::CreateSession) };
    }

    // HeadBucket: HEAD /{bucket} (or /{bucket}/) with *no* query params (allow x-id)
    if method == "HEAD"
        && bucket.is_some()
        && key.is_none()
        && query.is_empty_effective()
        && query.validate_xid("HeadBucket")
    {
        return S3RequestClass { bucket, key, query, op: S3Op::Read(ReadOp::HeadBucket) };
    }

    // CreateBucket: PUT /{bucket} (or /{bucket}/) with *no* query params (allow x-id)
    if method == "PUT"
        && bucket.is_some()
        && key.is_none()
        && query.is_empty_effective()
        && query.validate_xid("CreateBucket")
    {
        return S3RequestClass {
            bucket,
            key,
            query,
            op: S3Op::BucketAdmin(BucketAdminOp::CreateBucket),
        };
    }

    // DeleteBucket: DELETE /{bucket} (or /{bucket}/) with *no* query params (allow x-id)
    if method == "DELETE"
        && bucket.is_some()
        && key.is_none()
        && query.is_empty_effective()
        && query.validate_xid("DeleteBucket")
    {
        return S3RequestClass {
            bucket,
            key,
            query,
            op: S3Op::BucketAdmin(BucketAdminOp::DeleteBucket),
        };
    }

    // GetObject: GET /{bucket}/{key} with *no* query params (allow x-id)
    if method == "GET"
        && bucket.is_some()
        && key.is_some()
        && query.is_empty_effective()
        && query.validate_xid("GetObject")
    {
        return S3RequestClass { bucket, key, query, op: S3Op::Read(ReadOp::GetObject) };
    }

    // HeadObject: HEAD /{bucket}/{key} with *no* query params (allow x-id)
    if method == "HEAD"
        && bucket.is_some()
        && key.is_some()
        && query.is_empty_effective()
        && query.validate_xid("HeadObject")
    {
        return S3RequestClass { bucket, key, query, op: S3Op::Read(ReadOp::HeadObject) };
    }

    // ListObjectsV2: GET /{bucket}?list-type=2 (may have other params, allow x-id)
    if method == "GET"
        && bucket.is_some()
        && key.is_none()
        && query.first("list-type") == Some("2")
        && query.validate_xid("ListObjectsV2")
    {
        return S3RequestClass { bucket, key, query, op: S3Op::Read(ReadOp::ListObjectsV2) };
    }

    // ListObjectsV1: GET /{bucket} that didn't match any earlier read shape.
    // No special query marker — v1 is the default behavior of a bucket GET in S3.
    // We get here only after multipart/versioning/object-lock/location/HeadBucket/V2
    // have all been ruled out, so accepting any remaining bucket-level GET is safe.
    if method == "GET" && bucket.is_some() && key.is_none() && query.validate_xid("ListObjects") {
        return S3RequestClass { bucket, key, query, op: S3Op::Read(ReadOp::ListObjectsV1) };
    }

    // CopyObject: PUT /{bucket}/{key} with *no* query params and x-amz-copy-source (allow x-id)
    if method == "PUT"
        && bucket.is_some()
        && key.is_some()
        && query.is_empty_effective()
        && headers.is_some_and(|h| h.get("x-amz-copy-source").is_some())
        && query.validate_xid("CopyObject")
    {
        return S3RequestClass { bucket, key, query, op: S3Op::Write(WriteOp::CopyObject) };
    }

    // RenameObject: PUT /{bucket}/{key}?renameObject with x-amz-rename-source (allow x-id)
    if method == "PUT"
        && bucket.is_some()
        && key.is_some()
        && query.has("renameobject")
        && headers.is_some_and(|h| h.get("x-amz-rename-source").is_some())
        && query.validate_xid("RenameObject")
    {
        return S3RequestClass { bucket, key, query, op: S3Op::Write(WriteOp::RenameObject) };
    }

    // PutObject: PUT /{bucket}/{key} with *no* query params (allow x-id)
    if method == "PUT"
        && bucket.is_some()
        && key.is_some()
        && query.is_empty_effective()
        && query.validate_xid("PutObject")
    {
        return S3RequestClass { bucket, key, query, op: S3Op::Write(WriteOp::PutObject) };
    }

    // DeleteObjects (multi-delete): POST /{bucket}?delete (may also include x-id=DeleteObjects etc.)
    if method == "POST"
        && bucket.is_some()
        && key.is_none()
        && query.has("delete")
        && query.validate_xid("DeleteObjects")
    {
        return S3RequestClass { bucket, key, query, op: S3Op::Write(WriteOp::DeleteObjects) };
    }

    // DeleteObject: DELETE /{bucket}/{key} with *no* query params (allow x-id)
    if method == "DELETE"
        && bucket.is_some()
        && key.is_some()
        && query.is_empty_effective()
        && query.validate_xid("DeleteObject")
    {
        return S3RequestClass { bucket, key, query, op: S3Op::Write(WriteOp::DeleteObject) };
    }

    S3RequestClass { bucket, key, query, op: S3Op::Other }
}

/// If this request should be rejected as "NotImplemented" (for now), return a message.
/// (Both proxy and gateway can use this consistently.)
pub fn not_implemented_reason(class: &S3RequestClass) -> Option<&'static str> {
    match &class.op {
        S3Op::Multipart(_) => Some("multipart uploads are not implemented"),
        S3Op::Versioning(_) => Some("versioning is not implemented"),
        S3Op::ObjectLock(_) => Some("object locking is not implemented"),
        S3Op::Read(_) => None, // handled by routing/gateway
        S3Op::Write(_) => None,
        S3Op::BucketAdmin(_) => Some("bucket administration is not implemented"),
        S3Op::Session(_) => None, // handled locally at the proxy
        // HeadService is handled by the `aws_compat` arm (405 Method Not Allowed).
        // Returning None here lets routing decide; under the default routing
        // ("service": aws_compat) the proxy emits 405 without touching a worker.
        S3Op::HeadService => None,
        S3Op::Other => None,
    }
}

fn classify_multipart(
    method: &str,
    bucket: &Option<String>,
    key: &Option<String>,
    query: &QueryParams,
) -> Option<MultipartOp> {
    // ListMultipartUploads: GET /{bucket}?uploads (allow x-id)
    if method == "GET"
        && bucket.is_some()
        && key.is_none()
        && query.has("uploads")
        && query.validate_xid("ListMultipartUploads")
    {
        return Some(MultipartOp::ListMultipartUploads);
    }

    // CreateMultipartUpload: POST /{bucket}/{key}?uploads (allow x-id)
    if method == "POST"
        && bucket.is_some()
        && key.is_some()
        && query.has("uploads")
        && query.validate_xid("CreateMultipartUpload")
    {
        return Some(MultipartOp::CreateMultipartUpload);
    }

    // uploadId is the strong signal for object multipart sub-resources (allow x-id)
    if let Some(upload_id) = query.first("uploadid").map(|s| s.to_string()) {
        // UploadPart: PUT ?partNumber=N&uploadId=...
        if method == "PUT" && query.validate_xid("UploadPart") {
            if let Some(pn) = query.first("partnumber").and_then(parse_u32) {
                return Some(MultipartOp::UploadPart { upload_id, part_number: pn });
            }
            return Some(MultipartOp::Unknown);
        }

        // ListParts: GET ?uploadId=...
        if method == "GET" && query.validate_xid("ListParts") {
            return Some(MultipartOp::ListParts { upload_id });
        }

        // CompleteMultipartUpload: POST ?uploadId=...
        if method == "POST" && query.validate_xid("CompleteMultipartUpload") {
            return Some(MultipartOp::CompleteMultipartUpload { upload_id });
        }

        // AbortMultipartUpload: DELETE ?uploadId=...
        if method == "DELETE" && query.validate_xid("AbortMultipartUpload") {
            return Some(MultipartOp::AbortMultipartUpload { upload_id });
        }

        return Some(MultipartOp::Unknown);
    }

    None
}

fn classify_versioning(
    method: &str,
    bucket: &Option<String>,
    key: &Option<String>,
    query: &QueryParams,
) -> Option<VersioningOp> {
    // Bucket versioning configuration: GET/PUT /{bucket}?versioning (allow x-id)
    if bucket.is_some() && key.is_none() && query.has("versioning") {
        return match method {
            "GET" if query.validate_xid("GetBucketVersioning") => {
                Some(VersioningOp::GetBucketVersioning)
            }
            "PUT" if query.validate_xid("PutBucketVersioning") => {
                Some(VersioningOp::PutBucketVersioning)
            }
            _ => Some(VersioningOp::Unknown),
        };
    }

    // List object versions: GET /{bucket}?versions (allow x-id)
    if method == "GET"
        && bucket.is_some()
        && key.is_none()
        && query.has("versions")
        && query.validate_xid("ListObjectVersions")
    {
        return Some(VersioningOp::ListObjectVersions);
    }

    // Any object request that specifies versionId (allow x-id)
    if key.is_some() {
        if let Some(vid) = query.first("versionid") {
            if query.validate_xid("ObjectWithVersionId") {
                return Some(VersioningOp::ObjectWithVersionId { version_id: vid.to_string() });
            }
        }
    }

    None
}

fn classify_object_lock(
    method: &str,
    bucket: &Option<String>,
    key: &Option<String>,
    query: &QueryParams,
) -> Option<ObjectLockOp> {
    // Bucket Object Lock configuration: GET/PUT /{bucket}?object-lock (allow x-id)
    if bucket.is_some() && key.is_none() && query.has("object-lock") {
        return match method {
            "GET" if query.validate_xid("GetBucketObjectLockConfiguration") => {
                Some(ObjectLockOp::GetBucketObjectLockConfiguration)
            }
            "PUT" if query.validate_xid("PutBucketObjectLockConfiguration") => {
                Some(ObjectLockOp::PutBucketObjectLockConfiguration)
            }
            _ => Some(ObjectLockOp::Unknown),
        };
    }

    // Object retention: GET/PUT /{bucket}/{key}?retention (allow x-id)
    if bucket.is_some() && key.is_some() && query.has("retention") {
        return match method {
            "GET" if query.validate_xid("GetObjectRetention") => {
                Some(ObjectLockOp::GetObjectRetention)
            }
            "PUT" if query.validate_xid("PutObjectRetention") => {
                Some(ObjectLockOp::PutObjectRetention)
            }
            _ => Some(ObjectLockOp::Unknown),
        };
    }

    // Object legal hold: GET/PUT /{bucket}/{key}?legal-hold (allow x-id)
    if bucket.is_some() && key.is_some() && query.has("legal-hold") {
        return match method {
            "GET" if query.validate_xid("GetObjectLegalHold") => {
                Some(ObjectLockOp::GetObjectLegalHold)
            }
            "PUT" if query.validate_xid("PutObjectLegalHold") => {
                Some(ObjectLockOp::PutObjectLegalHold)
            }
            _ => Some(ObjectLockOp::Unknown),
        };
    }

    None
}

fn parse_bucket_key_path_style(path: &str) -> (Option<String>, Option<String>) {
    // path-style:
    //   "/"                 => no bucket
    //   "/bucket"           => bucket
    //   "/bucket/"          => bucket, empty key (treat as None)
    //   "/bucket/key/a/b"   => bucket + key "key/a/b"
    let p = path.trim_start_matches('/');
    if p.is_empty() {
        return (None, None);
    }

    let mut it = p.splitn(2, '/');
    let bucket = it.next().map(|s| s.to_string());

    let key = it.next().and_then(|rest| {
        // Important: remove only the single separator slash between bucket and key.
        // Do NOT trim all leading slashes, because additional slashes are part of the key.
        let rest = rest.strip_prefix('/').unwrap_or(rest);
        if rest.is_empty() {
            None
        } else {
            Some(crate::uri_encoding::percent_decode_path_segments_lossy(rest))
        }
    });

    (bucket, key)
}

/// Detect request style and parse bucket/key accordingly
/// Returns (bucket, key, is_virtual_hosted_style)
fn parse_bucket_key_auto(
    method: &str,
    uri: &Uri,
    headers: Option<&HeaderMap>,
    virtual_hosted_suffixes: &[String],
) -> (Option<String>, Option<String>, bool) {
    // Virtual-hosted-style detection:
    // - Host header format: bucket.suffix (where suffix is in virtual_hosted_suffixes)
    // - Path contains only the key (no bucket)
    //
    // We check virtual-hosted *before* the GET / shortcut: ListObjects on a
    // virtual host is `GET /` plus query params, and that must yield the
    // bucket-from-host, not get short-circuited to ListBuckets.

    if let Some(host) = headers.and_then(|h| h.get("host").and_then(|v| v.to_str().ok())) {
        // Remove port number if present (e.g., "bucket.suffix:9000" -> "bucket.suffix")
        let host_without_port = host.split(':').next().unwrap_or(host);

        // Check if host ends with any of the configured suffixes
        for suffix in virtual_hosted_suffixes {
            // Skip empty suffix: ends_with("") is always true and would mis-classify every host.
            if suffix.is_empty() {
                continue;
            }
            if host_without_port.ends_with(suffix) {
                // Extract the part before the suffix
                let prefix = host_without_port.trim_end_matches(suffix);
                // Remove the trailing dot if present
                let prefix = prefix.trim_end_matches('.');

                // If there's exactly one component before the suffix, it's likely a bucket name
                if !prefix.is_empty() {
                    // This is virtual-hosted-style: bucket in host, key in path
                    let path = uri.path().trim_start_matches('/');
                    let key = if path.is_empty() {
                        None
                    } else {
                        Some(crate::uri_encoding::percent_decode_path_segments_lossy(path))
                    };
                    return (Some(prefix.to_string()), key, true);
                }
            }
        }
    }

    // No virtual-hosted match — fall through to path-style.
    if method == "GET" && uri.path() == "/" {
        // ListBuckets: no bucket in the request, listing is over all
        // buckets visible to the caller.
        return (None, None, false);
    }

    let (bucket, key) = parse_bucket_key_path_style(uri.path());
    (bucket, key, false)
}

#[cfg(test)]
mod needs_write_tests {
    use super::*;

    #[test]
    fn read_ops_are_not_writes() {
        for op in [
            ReadOp::ListBuckets,
            ReadOp::GetObject,
            ReadOp::HeadObject,
            ReadOp::HeadBucket,
            ReadOp::GetBucketLocation,
            ReadOp::ListObjectsV2,
            ReadOp::ListObjectsV1,
            ReadOp::GetObjectAcl,
            ReadOp::GetBucketAcl,
        ] {
            assert!(!S3Op::Read(op.clone()).needs_write(), "Read({op:?}) should not be write");
        }
    }

    #[test]
    fn write_ops_are_writes() {
        for op in [
            WriteOp::PutObject,
            WriteOp::CopyObject,
            WriteOp::RenameObject,
            WriteOp::DeleteObject,
            WriteOp::DeleteObjects,
            WriteOp::PutObjectAcl,
            WriteOp::PutBucketAcl,
        ] {
            assert!(S3Op::Write(op.clone()).needs_write(), "Write({op:?}) should be write");
        }
    }

    #[test]
    fn multipart_list_ops_are_reads_others_are_writes() {
        let upload_id = "u".to_string();
        // reads
        for op in [
            MultipartOp::ListParts { upload_id: upload_id.clone() },
            MultipartOp::ListMultipartUploads,
        ] {
            assert!(!S3Op::Multipart(op.clone()).needs_write(), "Multipart({op:?}) should be read");
        }
        // writes
        for op in [
            MultipartOp::CreateMultipartUpload,
            MultipartOp::UploadPart { upload_id: upload_id.clone(), part_number: 1 },
            MultipartOp::CompleteMultipartUpload { upload_id: upload_id.clone() },
            MultipartOp::AbortMultipartUpload { upload_id: upload_id.clone() },
            // Unknown is conservatively a write so a read_only caller can't slip
            // an unrecognized multipart op through.
            MultipartOp::Unknown,
        ] {
            assert!(S3Op::Multipart(op.clone()).needs_write(), "Multipart({op:?}) should be write");
        }
    }

    #[test]
    fn versioning_get_ops_are_reads_put_and_unknown_are_writes() {
        for op in [
            VersioningOp::GetBucketVersioning,
            VersioningOp::ListObjectVersions,
            VersioningOp::ObjectWithVersionId { version_id: "v1".to_string() },
        ] {
            assert!(
                !S3Op::Versioning(op.clone()).needs_write(),
                "Versioning({op:?}) should be read"
            );
        }
        for op in [VersioningOp::PutBucketVersioning, VersioningOp::Unknown] {
            assert!(
                S3Op::Versioning(op.clone()).needs_write(),
                "Versioning({op:?}) should be write"
            );
        }
    }

    #[test]
    fn object_lock_get_ops_are_reads_put_and_unknown_are_writes() {
        for op in [
            ObjectLockOp::GetBucketObjectLockConfiguration,
            ObjectLockOp::GetObjectRetention,
            ObjectLockOp::GetObjectLegalHold,
        ] {
            assert!(
                !S3Op::ObjectLock(op.clone()).needs_write(),
                "ObjectLock({op:?}) should be read"
            );
        }
        for op in [
            ObjectLockOp::PutBucketObjectLockConfiguration,
            ObjectLockOp::PutObjectRetention,
            ObjectLockOp::PutObjectLegalHold,
            ObjectLockOp::Unknown,
        ] {
            assert!(
                S3Op::ObjectLock(op.clone()).needs_write(),
                "ObjectLock({op:?}) should be write"
            );
        }
    }

    #[test]
    fn bucket_admin_ops_are_writes() {
        for op in [BucketAdminOp::CreateBucket, BucketAdminOp::DeleteBucket] {
            assert!(
                S3Op::BucketAdmin(op.clone()).needs_write(),
                "BucketAdmin({op:?}) should be write"
            );
        }
    }

    #[test]
    fn other_is_conservatively_a_write() {
        assert!(S3Op::Other.needs_write());
    }
}
