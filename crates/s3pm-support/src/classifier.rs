use http::Uri;
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
    /// Basic read operations (we’ll add more here later).
    Read(ReadOp),
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
pub enum ReadOp {
    /// GET /{bucket}/{key} (no query params)
    GetObject,
    /// HEAD /{bucket}/{key} (no query params)
    HeadObject,
    /// GET /{bucket}?location or GET /{bucket}/?location
    GetBucketLocation,
    /// GET /{bucket}?list-type=2 (ListObjectsV2)
    ListObjectsV2,
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
}

/// Convert a parsed class into a stable routing key used by config/routing.
/// This keeps the routing table simple (multipart/versioning/getobject/other).
pub fn class_key(class: &S3RequestClass) -> &'static str {
    match &class.op {
        S3Op::Multipart(_) => "multipart",
        S3Op::Versioning(_) => "versioning",
        S3Op::Read(_) => "read", // grouped "basic read" ops (GetObject, GetBucketLocation, ...)
        S3Op::Other => "other",
    }
}

/// Classify an incoming request into S3 operation buckets.
/// Currently focuses on versioning + multipart uploads (to reject as NotImplemented).
pub fn classify(method: &str, uri: &Uri) -> S3RequestClass {
    let (bucket, key) = parse_bucket_key_path_style(uri.path());
    let query = QueryParams::from_uri(uri);

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

    // GetBucketLocation: GET /{bucket}?location (or /{bucket}/?location), and ONLY that param
    if method == "GET" && bucket.is_some() && key.is_none() && query.is_only("location") {
        return S3RequestClass {
            bucket,
            key,
            query,
            op: S3Op::Read(ReadOp::GetBucketLocation),
        };
    }

    // GetObject: GET /{bucket}/{key} with *no* query params
    if method == "GET" && bucket.is_some() && key.is_some() && query.is_empty() {
        return S3RequestClass {
            bucket,
            key,
            query,
            op: S3Op::Read(ReadOp::GetObject),
        };
    }

    // HeadObject: HEAD /{bucket}/{key} with *no* query params
    if method == "HEAD" && bucket.is_some() && key.is_some() && query.is_empty() {
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
        S3Op::Read(_) => None, // handled by routing/gateway
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

