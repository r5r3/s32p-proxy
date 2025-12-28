use pingora::http::RequestHeader;
use std::collections::HashMap;

/// High-level classification for S3 REST requests.
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

/// Parsed query params with lowercased keys.
/// Values are kept raw (no percent decoding), which is fine for routing/versioning/multipart keys.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueryParams {
    // key -> list of values; presence-only parameters are stored as empty string value.
    inner: HashMap<String, Vec<String>>,
}

impl QueryParams {
    pub fn from_req(req: &RequestHeader) -> Self {
        let mut out = QueryParams::default();
        let q = match req.uri.query() {
            Some(q) if !q.is_empty() => q,
            _ => return out,
        };

        // Parses application/x-www-form-urlencoded style, percent-decodes.
        // For presence-only flags like "?uploads", form_urlencoded yields ("uploads", "").
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
}

/// Classify an incoming request into S3 operation buckets.
/// Currently focuses on versioning + multipart uploads (to reject as NotImplemented).
pub fn classify(req: &RequestHeader) -> S3RequestClass {
    let (bucket, key) = parse_bucket_key_path_style(req.uri.path());
    let query = QueryParams::from_req(req);

    // Detect multipart first (uploadId can coexist with versionId in theory, but multipart routing is usually clearer).
    if let Some(op) = classify_multipart(req, &bucket, &key, &query) {
        return S3RequestClass {
            bucket,
            key,
            query,
            op: S3Op::Multipart(op),
        };
    }

    if let Some(op) = classify_versioning(req, &bucket, &key, &query) {
        return S3RequestClass {
            bucket,
            key,
            query,
            op: S3Op::Versioning(op),
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
pub fn not_implemented_reason(class: &S3RequestClass) -> Option<&'static str> {
    match &class.op {
        S3Op::Multipart(_) => Some("multipart uploads are not implemented"),
        S3Op::Versioning(_) => Some("versioning is not implemented"),
        S3Op::Other => None,
    }
}

fn classify_multipart(
    req: &RequestHeader,
    bucket: &Option<String>,
    key: &Option<String>,
    query: &QueryParams,
) -> Option<MultipartOp> {
    let method = req.method.as_str();

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
    req: &RequestHeader,
    bucket: &Option<String>,
    key: &Option<String>,
    query: &QueryParams,
) -> Option<VersioningOp> {
    let method = req.method.as_str();

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
