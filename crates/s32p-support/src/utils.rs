//! Utility functions for string manipulation and other common operations.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};

/// Determine the local UTC offset via libc's `localtime_r`.
///
/// `time::UtcOffset::current_local_offset()` refuses to answer once any
/// background thread has been spawned (the global allocator can do this
/// before `main`), so logging falls back to UTC. `localtime_r` is the
/// thread-safe variant and has no such restriction — `tm_gmtoff` carries
/// the offset directly. Falls back to UTC only if the libc call itself fails.
pub fn local_utc_offset() -> time::UtcOffset {
    use std::mem::MaybeUninit;
    // SAFETY: time(NULL) returns the current epoch seconds; localtime_r
    // writes the broken-down local time into the provided buffer.
    let now = unsafe { libc::time(std::ptr::null_mut()) };
    let mut tm = MaybeUninit::<libc::tm>::uninit();
    let res = unsafe { libc::localtime_r(&now, tm.as_mut_ptr()) };
    if res.is_null() {
        return time::UtcOffset::UTC;
    }
    let tm = unsafe { tm.assume_init() };
    time::UtcOffset::from_whole_seconds(tm.tm_gmtoff as i32).unwrap_or(time::UtcOffset::UTC)
}

/// A byte range for HTTP range requests.
/// Represents a range [start, end_excl) where end_excl is exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    /// Start of the range (inclusive)
    pub start:    u64,
    /// End of the range (exclusive)
    pub end_excl: u64,
}

impl ByteRange {
    /// Create a new ByteRange
    pub fn new(start: u64, end_excl: u64) -> Self {
        Self { start, end_excl }
    }

    /// Get the length of the range
    pub fn len(&self) -> u64 {
        self.end_excl.saturating_sub(self.start)
    }

    /// Check if the range is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Trim leading and trailing slashes from a string.
/// This is useful for normalizing paths and URLs.
///
/// # Examples
/// ```
/// use s32p_support::utils::trim_slashes;
///
/// assert_eq!(trim_slashes("/hello/"), "hello");
/// assert_eq!(trim_slashes("hello"), "hello");
/// assert_eq!(trim_slashes("/hello"), "hello");
/// assert_eq!(trim_slashes("hello/"), "hello");
/// assert_eq!(trim_slashes(""), "");
/// ```
pub fn trim_slashes(s: &str) -> String {
    s.trim().trim_matches('/').to_string()
}

/// Parse a string into a u32, returning None if parsing fails.
///
/// # Examples
/// ```
/// use s32p_support::utils::parse_u32;
///
/// assert_eq!(parse_u32("42"), Some(42));
/// assert_eq!(parse_u32("not_a_number"), None);
/// assert_eq!(parse_u32("1234567890"), Some(1234567890));
/// ```
pub fn parse_u32(s: &str) -> Option<u32> {
    s.parse::<u32>().ok()
}

/// Parse a string into a u64, returning an error if parsing fails or the string is empty.
pub fn parse_u64_strict(s: &str, what: &str) -> Result<u64> {
    let v = s.trim();
    if v.is_empty() {
        return Err(anyhow!("empty {what}"));
    }
    v.parse::<u64>().map_err(|_| anyhow!("invalid {what}: {s:?}"))
}

/// Parse an HTTP date (IMF-fixdate, RFC 7231) into SystemTime.
pub fn parse_http_date(s: &str) -> Result<SystemTime> {
    httpdate::parse_http_date(s.trim()).map_err(|_| anyhow!("invalid HTTP-date value: {s:?}"))
}

/// Parse x-amz-if-match-last-modified-time value.
/// Tries to parse as epoch timestamp first, falls back to HTTP-date.
pub fn parse_amz_last_modified_match(v: &str) -> Result<SystemTime> {
    let s = v.trim();
    if let Ok(secs) = s.parse::<u64>() {
        return Ok(UNIX_EPOCH + Duration::from_secs(secs));
    }
    parse_http_date(s)
}

/// ETag condition parsed from If-Match / If-None-Match style headers.
#[derive(Debug, Clone)]
pub enum ETagCondition {
    Any,                // "*"
    OneOf(Vec<String>), // normalized, unquoted tags
}

impl ETagCondition {
    pub fn matches(&self, current_etag_unquoted: &str) -> bool {
        match self {
            ETagCondition::Any => true,
            ETagCondition::OneOf(list) => list.iter().any(|t| t == current_etag_unquoted),
        }
    }
}

/// Normalize a single ETag token: strip whitespace, optional weak prefix, optional quotes.
/// Returns None if empty/unusable.
pub fn normalize_etag_token(tok: &str) -> Option<String> {
    let t = tok.trim();
    if t.is_empty() {
        return None;
    }
    if t == "*" {
        return Some("*".to_string());
    }

    // allow weak: W/"abc" or W/abc
    let t = t.strip_prefix("W/").unwrap_or(t).trim();

    // strip surrounding quotes if present
    let t = t.strip_prefix('"').unwrap_or(t);
    let t = t.strip_suffix('"').unwrap_or(t);

    let t = t.trim();
    if t.is_empty() { None } else { Some(t.to_string()) }
}

/// Parse If-Match / If-None-Match value (comma-separated).
/// Returns Err if header is present but contains no usable tokens.
pub fn parse_etag_condition(value: &str) -> Result<ETagCondition> {
    let raw = value.trim();
    if raw.is_empty() {
        return Err(anyhow!("empty ETag precondition value"));
    }

    // Accept "*" (optionally quoted)
    if raw == "*" || raw == "\"*\"" {
        return Ok(ETagCondition::Any);
    }

    let mut out: Vec<String> = Vec::new();
    for part in raw.split(',') {
        if let Some(tok) = normalize_etag_token(part) {
            if tok == "*" {
                return Ok(ETagCondition::Any);
            }
            out.push(tok);
        }
    }

    if out.is_empty() {
        return Err(anyhow!("ETag precondition header present but contains no usable ETag tokens"));
    }

    out.sort();
    out.dedup();
    Ok(ETagCondition::OneOf(out))
}

/// Parse an HTTP Range header according to RFC 7233.
///
/// Supports:
/// - `bytes=0-499` (first 500 bytes)
/// - `bytes=500-999` (bytes 500-999 inclusive)
/// - `bytes=-500` (last 500 bytes)
/// - `bytes=500-` (from byte 500 to end)
///
/// Does NOT support:
/// - Multiple ranges (e.g., `bytes=0-499,500-999`)
/// - Other units besides `bytes`
///
/// # Examples
/// ```
/// use s32p_support::utils::{ByteRange, parse_range_header};
///
/// let range = parse_range_header("bytes=0-99", 200).unwrap();
/// assert_eq!(range, Some(ByteRange { start: 0, end_excl: 100 }));
///
/// let range = parse_range_header("bytes=-50", 200).unwrap();
/// assert_eq!(range, Some(ByteRange { start: 150, end_excl: 200 }));
///
/// let range = parse_range_header("bytes=100-", 200).unwrap();
/// assert_eq!(range, Some(ByteRange { start: 100, end_excl: 200 }));
/// ```
pub fn parse_range_header(h: &str, size: u64) -> Result<Option<ByteRange>> {
    let h = h.trim();
    if h.is_empty() {
        return Ok(None);
    }
    if !h.starts_with("bytes=") {
        return Err(anyhow!("unsupported Range unit"));
    }
    let spec = &h["bytes=".len()..];

    if spec.contains(',') {
        return Err(anyhow!("multiple ranges not supported"));
    }

    let (a, b) = spec.split_once('-').ok_or_else(|| anyhow!("bad Range syntax"))?;
    if a.is_empty() {
        // Suffix case: bytes=-500
        let suffix: u64 = b.parse().map_err(|_| anyhow!("bad Range suffix"))?;
        if suffix == 0 {
            return Err(anyhow!("bad Range suffix"));
        }
        let start = size.saturating_sub(suffix);
        return Ok(Some(ByteRange { start, end_excl: size }));
    }

    let start: u64 = a.parse().map_err(|_| anyhow!("bad Range start"))?;
    if start >= size {
        return Err(anyhow!("Range start beyond EOF"));
    }

    let end_incl = if b.is_empty() {
        // Open-ended case: bytes=500-
        size - 1
    } else {
        // Normal case: bytes=500-999
        let mut e: u64 = b.parse().map_err(|_| anyhow!("bad Range end"))?;
        if e >= size {
            e = size - 1;
        }
        e
    };

    if end_incl < start {
        return Err(anyhow!("Range end < start"));
    }

    Ok(Some(ByteRange { start, end_excl: end_incl + 1 }))
}

/// Header names that signal a request is using SSE-C (server-side encryption
/// with customer-provided keys). Six headers in total: three for the *target*
/// object (PUT/GET/HEAD/UploadPart/CreateMultipartUpload), three for the
/// *source* object on CopyObject / UploadPartCopy when the source itself was
/// uploaded with SSE-C. Listed in the canonical AWS casing for grep-ability
/// against AWS docs; `http::HeaderMap` lookups are case-insensitive.
pub const SSE_C_HEADER_NAMES: &[&str] = &[
    "x-amz-server-side-encryption-customer-algorithm",
    "x-amz-server-side-encryption-customer-key",
    "x-amz-server-side-encryption-customer-key-md5",
    "x-amz-copy-source-server-side-encryption-customer-algorithm",
    "x-amz-copy-source-server-side-encryption-customer-key",
    "x-amz-copy-source-server-side-encryption-customer-key-md5",
];

/// The primary header that selects server-managed SSE (SSE-S3 / SSE-KMS).
/// Value is one of `AES256`, `aws:kms`, or `aws:kms:dsse`.
pub const SSE_ALGORITHM_HEADER: &str = "x-amz-server-side-encryption";

/// Additional headers that imply SSE-KMS without the primary algorithm
/// header. Some SDK paths set only these (the algorithm header gets added
/// later by the SDK middleware); we still want to reject so the request
/// can't slip through with the algorithm header materializing inside the
/// worker.
pub const SSE_KMS_AUX_HEADER_NAMES: &[&str] = &[
    "x-amz-server-side-encryption-aws-kms-key-id",
    "x-amz-server-side-encryption-context",
    "x-amz-server-side-encryption-bucket-key-enabled",
];

/// Which SSE flavor we detected in an incoming request. Returned by
/// [`detect_unsupported_sse`] so the response helper can craft a
/// per-variant message — all four are equally unsupported by the
/// gateway, but distinguishing them in the error makes the failure
/// easier to debug.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedSse {
    /// SSE-C — customer-provided AES256 key, supplied in the request
    /// headers. Most dangerous to silently drop because the client
    /// believes it controls the key.
    CustomerKey,
    /// SSE-S3 — `x-amz-server-side-encryption: AES256`. Server-managed
    /// key, server-side-only encryption.
    ServerS3,
    /// SSE-KMS — `x-amz-server-side-encryption: aws:kms` plus optional
    /// `*-aws-kms-key-id` / `*-context` headers.
    ServerKms,
    /// SSE-KMS dual-layer — `x-amz-server-side-encryption: aws:kms:dsse`.
    /// Same kind as ServerKms semantically; tracked separately so the
    /// error message can name the right algorithm.
    ServerKmsDsse,
    /// Unknown `x-amz-server-side-encryption` value — client asked for
    /// some flavor of SSE we don't recognize. Treat as unsupported.
    Unknown,
}

/// Detect any unsupported server-side-encryption request shape. Returns
/// `None` if the request carries no SSE intent. Used to short-circuit at
/// the proxy: forwarding an SSE-bearing request to the gateway would
/// silently store *plaintext* while the client believes its body was
/// encrypted at rest — a data-confidentiality footgun.
///
/// Detection precedence: SSE-C wins over SSE-S3/KMS (a request setting
/// both is malformed, but SSE-C is the more dangerous case to mis-attribute
/// since it involves the caller's key material). The
/// `x-amz-server-side-encryption` algorithm value is matched
/// case-sensitively in the canonical AWS casing — that's what every SDK
/// produces; deviations are folded into [`DetectedSse::Unknown`].
pub fn detect_unsupported_sse(headers: &http::HeaderMap) -> Option<DetectedSse> {
    // SSE-C: any of the customer-key headers, target or copy-source.
    if SSE_C_HEADER_NAMES.iter().any(|name| headers.contains_key(*name)) {
        return Some(DetectedSse::CustomerKey);
    }

    // SSE-S3 / SSE-KMS / SSE-KMS-DSSE: the algorithm header.
    if let Some(value) = headers.get(SSE_ALGORITHM_HEADER) {
        if let Ok(v) = value.to_str() {
            return Some(match v.trim() {
                "AES256" => DetectedSse::ServerS3,
                "aws:kms" => DetectedSse::ServerKms,
                "aws:kms:dsse" => DetectedSse::ServerKmsDsse,
                _ => DetectedSse::Unknown,
            });
        }
        // Non-UTF8 header value — pathological, but still SSE intent.
        return Some(DetectedSse::Unknown);
    }

    // KMS-only headers without the primary algorithm header. Some
    // middleware paths set these first; the algorithm header would
    // materialize downstream. Reject early.
    if SSE_KMS_AUX_HEADER_NAMES.iter().any(|name| headers.contains_key(*name)) {
        return Some(DetectedSse::ServerKms);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trim_slashes() {
        assert_eq!(trim_slashes("/hello/"), "hello");
        assert_eq!(trim_slashes("hello"), "hello");
        assert_eq!(trim_slashes("/hello"), "hello");
        assert_eq!(trim_slashes("hello/"), "hello");
        assert_eq!(trim_slashes(""), "");
        assert_eq!(trim_slashes("  /hello/  "), "hello");
        assert_eq!(trim_slashes("///hello///"), "hello");
    }

    #[test]
    fn test_parse_u32() {
        assert_eq!(parse_u32("42"), Some(42));
        assert_eq!(parse_u32("0"), Some(0));
        assert_eq!(parse_u32("1234567890"), Some(1234567890));
        assert_eq!(parse_u32("not_a_number"), None);
        assert_eq!(parse_u32(""), None);
        assert_eq!(parse_u32("-1"), None); // Negative numbers
        assert_eq!(parse_u32("4294967296"), None); // Too large for u32
    }

    #[test]
    fn test_byte_range() {
        let range = ByteRange { start: 0, end_excl: 100 };
        assert_eq!(range.len(), 100);
        assert!(!range.is_empty());

        let empty_range = ByteRange { start: 50, end_excl: 50 };
        assert_eq!(empty_range.len(), 0);
        assert!(empty_range.is_empty());
    }

    #[test]
    fn test_parse_range_header() {
        // Normal range
        let range = parse_range_header("bytes=0-99", 200).unwrap();
        assert_eq!(range, Some(ByteRange { start: 0, end_excl: 100 }));

        // Suffix range
        let range = parse_range_header("bytes=-50", 200).unwrap();
        assert_eq!(range, Some(ByteRange { start: 150, end_excl: 200 }));

        // Open-ended range
        let range = parse_range_header("bytes=100-", 200).unwrap();
        assert_eq!(range, Some(ByteRange { start: 100, end_excl: 200 }));

        // Empty header
        let range = parse_range_header("", 200).unwrap();
        assert_eq!(range, None);

        // Invalid unit
        assert!(parse_range_header("items=0-99", 200).is_err());

        // Multiple ranges (not supported)
        assert!(parse_range_header("bytes=0-49,50-99", 200).is_err());

        // Bad syntax
        assert!(parse_range_header("bytes=0", 200).is_err());

        // Range beyond EOF
        assert!(parse_range_header("bytes=300-400", 200).is_err());

        // Zero suffix
        assert!(parse_range_header("bytes=-0", 200).is_err());

        // Invalid end < start
        assert!(parse_range_header("bytes=100-50", 200).is_err());
    }

    #[test]
    fn detect_sse_empty_map() {
        let h = http::HeaderMap::new();
        assert_eq!(detect_unsupported_sse(&h), None);
    }

    #[test]
    fn detect_sse_unrelated_headers_only() {
        let mut h = http::HeaderMap::new();
        h.insert("host", "example.com".parse().unwrap());
        h.insert("x-amz-date", "20250101T000000Z".parse().unwrap());
        h.insert("content-type", "text/plain".parse().unwrap());
        assert_eq!(detect_unsupported_sse(&h), None);
    }

    #[test]
    fn detect_sse_c_target_algorithm() {
        let mut h = http::HeaderMap::new();
        h.insert("x-amz-server-side-encryption-customer-algorithm", "AES256".parse().unwrap());
        assert_eq!(detect_unsupported_sse(&h), Some(DetectedSse::CustomerKey));
    }

    #[test]
    fn detect_sse_c_target_key_only() {
        // Some clients only set the key+md5 (the algorithm comes via the
        // SDK as a default header); the proxy must reject as long as *any*
        // SSE-C header is present.
        let mut h = http::HeaderMap::new();
        h.insert("x-amz-server-side-encryption-customer-key", "AAAA".parse().unwrap());
        assert_eq!(detect_unsupported_sse(&h), Some(DetectedSse::CustomerKey));
    }

    #[test]
    fn detect_sse_c_copy_source_variant() {
        let mut h = http::HeaderMap::new();
        h.insert(
            "x-amz-copy-source-server-side-encryption-customer-algorithm",
            "AES256".parse().unwrap(),
        );
        assert_eq!(detect_unsupported_sse(&h), Some(DetectedSse::CustomerKey));
    }

    #[test]
    fn detect_sse_c_case_insensitive_via_headermap() {
        // http::HeaderMap normalizes names; insert with mixed case still
        // resolves to lowercase, so the lookup matches our constants.
        let mut h = http::HeaderMap::new();
        h.insert("X-Amz-Server-Side-Encryption-Customer-Key", "AAAA".parse().unwrap());
        assert_eq!(detect_unsupported_sse(&h), Some(DetectedSse::CustomerKey));
    }

    #[test]
    fn detect_sse_s3_aes256() {
        let mut h = http::HeaderMap::new();
        h.insert("x-amz-server-side-encryption", "AES256".parse().unwrap());
        assert_eq!(detect_unsupported_sse(&h), Some(DetectedSse::ServerS3));
    }

    #[test]
    fn detect_sse_kms() {
        let mut h = http::HeaderMap::new();
        h.insert("x-amz-server-side-encryption", "aws:kms".parse().unwrap());
        assert_eq!(detect_unsupported_sse(&h), Some(DetectedSse::ServerKms));
    }

    #[test]
    fn detect_sse_kms_dsse() {
        let mut h = http::HeaderMap::new();
        h.insert("x-amz-server-side-encryption", "aws:kms:dsse".parse().unwrap());
        assert_eq!(detect_unsupported_sse(&h), Some(DetectedSse::ServerKmsDsse));
    }

    #[test]
    fn detect_sse_unknown_algorithm() {
        let mut h = http::HeaderMap::new();
        h.insert("x-amz-server-side-encryption", "ROT13".parse().unwrap());
        assert_eq!(detect_unsupported_sse(&h), Some(DetectedSse::Unknown));
    }

    #[test]
    fn detect_sse_kms_key_id_only() {
        // Aux header without the primary algorithm header still trips
        // the gate — middleware paths sometimes set kms-key-id first and
        // let the SDK add the algorithm header later.
        let mut h = http::HeaderMap::new();
        h.insert(
            "x-amz-server-side-encryption-aws-kms-key-id",
            "alias/some-key".parse().unwrap(),
        );
        assert_eq!(detect_unsupported_sse(&h), Some(DetectedSse::ServerKms));
    }

    #[test]
    fn detect_sse_c_wins_over_sse_kms_when_both_present() {
        // Pathological request — but if both are set, SSE-C is the more
        // dangerous to mis-attribute (caller's key material involved).
        let mut h = http::HeaderMap::new();
        h.insert("x-amz-server-side-encryption", "aws:kms".parse().unwrap());
        h.insert("x-amz-server-side-encryption-customer-key", "AAAA".parse().unwrap());
        assert_eq!(detect_unsupported_sse(&h), Some(DetectedSse::CustomerKey));
    }
}
