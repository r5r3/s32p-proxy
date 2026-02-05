use http::{HeaderMap, Uri};
use std::collections::HashMap;

/// High-level classification for S3 REST requests.
/// Shared by proxy and gateway to avoid duplicated request parsing logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3RequestClass {
    /// Bucket name if present (path-style parsing for now).
    pub bucket: Option<String>,
    /// Object key if present (everything after bucket/).
    pub key: Option<String>,
    /// Parsed query parameters (lowercased keys).
    pub query: QueryParams,
    /// Classified operation bucket.
    pub op: S3Op,
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
    /// Anything else (for now).
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultipartOp {
    /// POST /{bucket}/{key}?uploads
    CreateMultipartUpload,
    /// PUT /{bucket}/{key}?partNumber=N&uploadId=...
    UploadPart {
        upload_id: String,
        part_number: u32,
    },
    /// GET /{bucket}/{key}?uploadId=...
    ListParts {
        upload_id: String,
    },
    /// POST /{bucket}/{key}?uploadId=...
    CompleteMultipartUpload {
        upload_id: String,
    },
    /// DELETE /{bucket}/{key}?uploadId=...
    AbortMultipartUpload {
        upload_id: String,
    },
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteOp {
    /// PUT /{bucket}/{key} (no query params)
    PutObject,
    /// PUT /{bucket}/{key} with x-amz-copy-source
    CopyObject,
    /// DELETE /{bucket}/{key} (no query params)
    DeleteObject,
    /// POST /{bucket}?delete
    DeleteObjects,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BucketAdminOp {
    /// PUT /{bucket}
    CreateBucket,
    /// DELETE /{bucket}
    DeleteBucket,
}

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
        )
    }

    /// True if there are no *effective* query params except SigV4-presign params.
    pub fn is_empty_effective(&self) -> bool {
        self.inner
            .keys()
            .all(|k| Self::is_sigv4_presign_key(k.as_str()))
    }

    /// True if the only *effective* (non-presign) query param key is `key`.
    pub fn is_only_effective(&self, key: &str) -> bool {
        let key_lc = key.to_ascii_lowercase();

        let mut non_presign_keys = 0usize;
        let mut has_key = false;

        for k in self.inner.keys() {
            if Self::is_sigv4_presign_key(k.as_str()) {
                continue;
            }
            non_presign_keys += 1;
            if *k == key_lc {
                has_key = true;
            }
        }

        non_presign_keys == 1 && has_key
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
        S3Op::Other => "other",
    }
}

/// Classify an incoming request into S3 operation buckets, using headers when needed.
/// (CopyObject is distinguished from PutObject via x-amz-copy-source.)
pub fn classify_with_headers(method: &str, uri: &Uri, headers: Option<&HeaderMap>) -> S3RequestClass {
    let (bucket, key) = parse_bucket_key_path_style(uri.path());
    let query = QueryParams::from_uri(uri);

    // ListBuckets: GET / (may include pagination/filter query params)
    if method == "GET" && bucket.is_none() && key.is_none() {
        return S3RequestClass {
            bucket,
            key,
            query,
            op: S3Op::Read(ReadOp::ListBuckets),
        };
    }

    // Detect multipart first (uploadId can coexist with versionId in theory,
    // but multipart routing is usually clearer).
    if let Some(op) = classify_multipart(method, &bucket, &key, &query) {
        return S3RequestClass {
            bucket,
            key,
            query,
            op: S3Op::Multipart(op),
        };
    }

    if let Some(op) = classify_versioning(method, &bucket, &key, &query) {
        return S3RequestClass {
            bucket,
            key,
            query,
            op: S3Op::Versioning(op),
        };
    }

    // Object lock / retention / legal-hold (query sub-resources).
    // This must come before versioning so "?retention&versionId=..." is treated as object-lock.
    if let Some(op) = classify_object_lock(method, &bucket, &key, &query) {
        return S3RequestClass {
            bucket,
            key,
            query,
            op: S3Op::ObjectLock(op),
        };
    }

    // GetBucketLocation: GET /{bucket}?location (or /{bucket}/?location), and ONLY that param
    if method == "GET" && bucket.is_some() && key.is_none() && query.is_only_effective("location") {
        return S3RequestClass {
            bucket,
            key,
            query,
            op: S3Op::Read(ReadOp::GetBucketLocation),
        };
    }

    // HeadBucket: HEAD /{bucket} (or /{bucket}/) with *no* query params
    if method == "HEAD" && bucket.is_some() && key.is_none() && query.is_empty_effective() {
        return S3RequestClass {
            bucket,
            key,
            query,
            op: S3Op::Read(ReadOp::HeadBucket),
        };
    }

    // CreateBucket: PUT /{bucket} (or /{bucket}/) with *no* query params (allow x-id)
    if method == "PUT"
        && bucket.is_some()
        && key.is_none()
        && (query.is_empty_effective() || query.is_only_effective("x-id"))
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
        && (query.is_empty_effective() || query.is_only_effective("x-id"))
    {
        return S3RequestClass {
            bucket,
            key,
            query,
            op: S3Op::BucketAdmin(BucketAdminOp::DeleteBucket),
        };
    }


    // GetObject: GET /{bucket}/{key} with *no* query params
    if method == "GET" && bucket.is_some() && key.is_some() && query.is_empty_effective() {
        return S3RequestClass {
            bucket,
            key,
            query,
            op: S3Op::Read(ReadOp::GetObject),
        };
    }

    // HeadObject: HEAD /{bucket}/{key} with *no* query params
    if method == "HEAD" && bucket.is_some() && key.is_some() && query.is_empty_effective() {
        return S3RequestClass {
            bucket,
            key,
            query,
            op: S3Op::Read(ReadOp::HeadObject),
        };
    }

    // ListObjectsV2: GET /{bucket}?list-type=2 (may have other params)
    if method == "GET"
        && bucket.is_some()
        && key.is_none()
        && query.first("list-type") == Some("2")
    {
        return S3RequestClass {
            bucket,
            key,
            query,
            op: S3Op::Read(ReadOp::ListObjectsV2),
        };
    }

    // CopyObject: PUT /{bucket}/{key} with *no* query params and x-amz-copy-source
    if method == "PUT"
        && bucket.is_some()
        && key.is_some()
        && query.is_empty_effective()
        && headers.is_some_and(|h| h.get("x-amz-copy-source").is_some())
    {
        return S3RequestClass {
            bucket,
            key,
            query,
            op: S3Op::Write(WriteOp::CopyObject),
        };
    }

    // PutObject: PUT /{bucket}/{key} with *no* query params
    if method == "PUT" && bucket.is_some() && key.is_some() && query.is_empty_effective() {
        return S3RequestClass {
            bucket,
            key,
            query,
            op: S3Op::Write(WriteOp::PutObject),
        };
    }

    // DeleteObjects (multi-delete): POST /{bucket}?delete (may also include x-id=DeleteObjects etc.)
    if method == "POST" && bucket.is_some() && key.is_none() && query.has("delete") {
        return S3RequestClass {
            bucket,
            key,
            query,
            op: S3Op::Write(WriteOp::DeleteObjects),
        };
    }

    // DeleteObject: DELETE /{bucket}/{key} with *no* query params
    if method == "DELETE" && bucket.is_some() && key.is_some() && query.is_empty_effective() {
        return S3RequestClass {
            bucket,
            key,
            query,
            op: S3Op::Write(WriteOp::DeleteObject),
        };
    }

    S3RequestClass {
        bucket,
        key,
        query,
        op: S3Op::Other,
    }
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
        S3Op::Other => None,
    }
}

fn classify_multipart(
    method: &str,
    bucket: &Option<String>,
    key: &Option<String>,
    query: &QueryParams,
) -> Option<MultipartOp> {
    // ListMultipartUploads: GET /{bucket}?uploads
    if method == "GET" && bucket.is_some() && key.is_none() && query.has("uploads") {
        return Some(MultipartOp::ListMultipartUploads);
    }

    // CreateMultipartUpload: POST /{bucket}/{key}?uploads
    if method == "POST" && bucket.is_some() && key.is_some() && query.has("uploads") {
        return Some(MultipartOp::CreateMultipartUpload);
    }

    // uploadId is the strong signal for object multipart sub-resources
    if let Some(upload_id) = query.first("uploadid").map(|s| s.to_string()) {
        // UploadPart: PUT ?partNumber=N&uploadId=...
        if method == "PUT" {
            if let Some(pn) = query.first("partnumber").and_then(parse_u32) {
                return Some(MultipartOp::UploadPart {
                    upload_id,
                    part_number: pn,
                });
            }
            return Some(MultipartOp::Unknown);
        }

        // ListParts: GET ?uploadId=...
        if method == "GET" {
            return Some(MultipartOp::ListParts { upload_id });
        }

        // CompleteMultipartUpload: POST ?uploadId=...
        if method == "POST" {
            return Some(MultipartOp::CompleteMultipartUpload { upload_id });
        }

        // AbortMultipartUpload: DELETE ?uploadId=...
        if method == "DELETE" {
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
    // Bucket versioning configuration: GET/PUT /{bucket}?versioning
    if bucket.is_some() && key.is_none() && query.has("versioning") {
        return match method {
            "GET" => Some(VersioningOp::GetBucketVersioning),
            "PUT" => Some(VersioningOp::PutBucketVersioning),
            _ => Some(VersioningOp::Unknown),
        };
    }

    // List object versions: GET /{bucket}?versions
    if method == "GET" && bucket.is_some() && key.is_none() && query.has("versions") {
        return Some(VersioningOp::ListObjectVersions);
    }

    // Any object request that specifies versionId
    if key.is_some() {
        if let Some(vid) = query.first("versionid") {
            return Some(VersioningOp::ObjectWithVersionId {
                version_id: vid.to_string(),
            });
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
    // Bucket Object Lock configuration: GET/PUT /{bucket}?object-lock
    if bucket.is_some() && key.is_none() && query.has("object-lock") {
        return match method {
            "GET" => Some(ObjectLockOp::GetBucketObjectLockConfiguration),
            "PUT" => Some(ObjectLockOp::PutBucketObjectLockConfiguration),
            _ => Some(ObjectLockOp::Unknown),
        };
    }

    // Object retention: GET/PUT /{bucket}/{key}?retention
    if bucket.is_some() && key.is_some() && query.has("retention") {
        return match method {
            "GET" => Some(ObjectLockOp::GetObjectRetention),
            "PUT" => Some(ObjectLockOp::PutObjectRetention),
            _ => Some(ObjectLockOp::Unknown),
        };
    }

    // Object legal hold: GET/PUT /{bucket}/{key}?legal-hold
    if bucket.is_some() && key.is_some() && query.has("legal-hold") {
        return match method {
            "GET" => Some(ObjectLockOp::GetObjectLegalHold),
            "PUT" => Some(ObjectLockOp::PutObjectLegalHold),
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
        let rest = rest.trim_start_matches('/');
        if rest.is_empty() {
            None
        } else {
            Some(rest.to_string())
        }
    });

    (bucket, key)
}

fn parse_u32(s: &str) -> Option<u32> {
    s.parse::<u32>().ok()
}

