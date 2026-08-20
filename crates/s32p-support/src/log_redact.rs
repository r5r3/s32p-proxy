//! Log-safe redaction of SigV4 credentials in URIs.
//!
//! Presigned-URL SigV4 puts the signature into the query string. Logging
//! a URI verbatim leaves that signature in log files; for the lifetime
//! of `X-Amz-Expires` (up to 7 days) anyone who reads the log can replay
//! the request. This module rewrites those query params to a short
//! prefix that is cryptographically useless but still useful for
//! debug correlation: 8 hex chars of a 64-hex signature leaves 224 bits
//! unknown, which is not online-brute-forceable even by an attacker who
//! has the rest of the canonical request.
//!
//! Redacted params (case-insensitive match on the key):
//! - `X-Amz-Signature` — the HMAC-SHA256 output
//! - `X-Amz-Security-Token` — STS session token
//!
//! Other `X-Amz-*` params (`X-Amz-Algorithm`, `X-Amz-Credential`,
//! `X-Amz-Date`, `X-Amz-Expires`, `X-Amz-SignedHeaders`) pass through
//! verbatim. The access-key portion of `X-Amz-Credential` is already
//! emitted as a structured `access_key=` field on every authenticated
//! log entry, so leaving it in the URI is no incremental disclosure.
//!
//! The implementation walks the raw query bytes without
//! percent-decoding so the logged URI byte-for-byte matches the wire
//! form (modulo the truncated value). Truncation operates on chars and
//! appends a single `…` (U+2026) marker so the redaction is visually
//! obvious to a log reader.

/// How many leading chars of each redacted value to keep.
const PREFIX_CHARS: usize = 8;

/// Visual marker appended after the truncated value.
const ELLIPSIS: char = '…';

/// Redact SigV4 credentials in `uri`'s query for log output, rendering
/// `path[?query]`.
///
/// Scheme and authority are deliberately dropped. An HTTP/1.1 request
/// arrives in origin-form (`/bucket/key`), while HTTP/2 carries `:scheme`
/// and `:authority` as pseudo-headers and reconstructs an absolute URI
/// (`https://host:port/bucket/key`) — logging the URI verbatim would make
/// every access-log line depend on the protocol version the client
/// happened to negotiate. The host is emitted as its own field on the
/// same log entry, so nothing is lost.
pub fn redact_uri_for_log(uri: &http::Uri) -> String {
    let Some(q) = uri.query() else {
        return uri.path().to_string();
    };
    let redacted = redact_query_for_log(q);

    let mut out = String::with_capacity(uri.path().len() + redacted.len() + 1);
    out.push_str(uri.path());
    out.push('?');
    out.push_str(&redacted);
    out
}

/// Same as [`redact_uri_for_log`] but operates on a bare query string
/// (the substring after `?`, with no leading delimiter). Useful for
/// callers that already split the URI.
pub fn redact_query_for_log(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity(query.len());
    for (i, kv) in query.split('&').enumerate() {
        if i > 0 {
            out.push('&');
        }
        let Some((key, val)) = kv.split_once('=') else {
            // Param with no value (e.g. `?session`) — pass through.
            out.push_str(kv);
            continue;
        };
        out.push_str(key);
        out.push('=');
        if is_sensitive_param(key) {
            out.push_str(&truncate(val));
        } else {
            out.push_str(val);
        }
    }
    out
}

fn is_sensitive_param(key: &str) -> bool {
    key.eq_ignore_ascii_case("X-Amz-Signature") || key.eq_ignore_ascii_case("X-Amz-Security-Token")
}

/// Keep the first [`PREFIX_CHARS`] chars; append `…` if anything was
/// truncated. Empty input stays empty (no ellipsis added).
fn truncate(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    let mut byte_idx = 0usize;
    let mut taken = 0usize;
    for (i, _) in value.char_indices() {
        if taken == PREFIX_CHARS {
            byte_idx = i;
            break;
        }
        taken += 1;
        byte_idx = value.len(); // default: everything if we run out
    }
    if taken < PREFIX_CHARS || byte_idx >= value.len() {
        return value.to_string();
    }
    let mut out = String::with_capacity(byte_idx + ELLIPSIS.len_utf8());
    out.push_str(&value[..byte_idx]);
    out.push(ELLIPSIS);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(s: &str) -> http::Uri {
        s.parse().expect("test URI must parse")
    }

    #[test]
    fn presigned_get_signature_truncated() {
        let u = uri("/bucket/key?X-Amz-Algorithm=AWS4-HMAC-SHA256\
             &X-Amz-Credential=AKIA123/20260521/us-east-1/s3/aws4_request\
             &X-Amz-Date=20260521T120000Z\
             &X-Amz-Expires=60\
             &X-Amz-SignedHeaders=host\
             &X-Amz-Signature=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        let got = redact_uri_for_log(&u);
        assert!(got.contains("X-Amz-Signature=01234567…"), "got: {got}");
        // Other params untouched.
        assert!(got.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
        assert!(got.contains("X-Amz-Credential=AKIA123/20260521/us-east-1/s3/aws4_request"));
        assert!(got.contains("X-Amz-Date=20260521T120000Z"));
        assert!(got.contains("X-Amz-SignedHeaders=host"));
        // Path preserved.
        assert!(got.starts_with("/bucket/key?"));
    }

    #[test]
    fn no_query_returns_unchanged() {
        let u = uri("/bucket/key");
        assert_eq!(redact_uri_for_log(&u), "/bucket/key");
    }

    #[test]
    fn empty_query_is_empty() {
        assert_eq!(redact_query_for_log(""), "");
    }

    #[test]
    fn case_insensitive_key_match() {
        // AWS canonicalizes header names lowercase but query keys vary in
        // the wild. Match case-insensitively so SDKs that emit mixed case
        // (`X-Amz-SIGNATURE`, `x-amz-signature`) still get redacted.
        let q = "X-AMZ-SIGNATURE=0123456789abcdef0123456789abcdef\
                 0123456789abcdef0123456789abcdef";
        let got = redact_query_for_log(q);
        assert!(got.starts_with("X-AMZ-SIGNATURE=01234567…"), "got: {got}");
        let q = "x-amz-signature=0123456789abcdef0123456789abcdef\
                 0123456789abcdef0123456789abcdef";
        let got = redact_query_for_log(q);
        assert!(got.starts_with("x-amz-signature=01234567…"), "got: {got}");
    }

    #[test]
    fn security_token_redacted() {
        // Base64-ish value with `+`, `/`, `=`. The truncate function only
        // sees the raw bytes — no decoding needed; the log is for human
        // eyes and the wire form is preserved.
        let q = "X-Amz-Security-Token=FwoGZXIvYXdzEC8aDExampleTokenValueWithPaddinG=";
        let got = redact_query_for_log(q);
        assert_eq!(got, "X-Amz-Security-Token=FwoGZXIv…");
    }

    #[test]
    fn signature_shorter_than_prefix_kept_intact() {
        // Synthetic / malformed value of exactly 8 chars: no ellipsis
        // because nothing was truncated.
        let q = "X-Amz-Signature=01234567";
        assert_eq!(redact_query_for_log(q), "X-Amz-Signature=01234567");
        // Shorter still.
        let q = "X-Amz-Signature=abc";
        assert_eq!(redact_query_for_log(q), "X-Amz-Signature=abc");
    }

    #[test]
    fn signature_exactly_prefix_plus_one_truncates() {
        let q = "X-Amz-Signature=012345678";
        assert_eq!(redact_query_for_log(q), "X-Amz-Signature=01234567…");
    }

    #[test]
    fn percent_encoded_credential_passes_through() {
        // AWS wire format puts `/` chars in X-Amz-Credential as %2F.
        // Logger must preserve that — anyone who copies the URL out of
        // the log expects wire-shape encoding.
        let q = "X-Amz-Credential=AKIA%2F20260521%2Fus-east-1%2Fs3%2Faws4_request\
                 &X-Amz-Signature=0123456789abcdef0123456789abcdef\
                 0123456789abcdef0123456789abcdef";
        let got = redact_query_for_log(q);
        assert!(got.contains("X-Amz-Credential=AKIA%2F20260521%2Fus-east-1%2Fs3%2Faws4_request"));
        assert!(got.contains("X-Amz-Signature=01234567…"));
    }

    #[test]
    fn param_without_equals_passes_through() {
        // CreateSession uses `?session` (bare key, no value).
        let q = "session";
        assert_eq!(redact_query_for_log(q), "session");
        // Mixed with regular params.
        let q = "session&X-Amz-Signature=0123456789abcdef0123456789abcdef\
                 0123456789abcdef0123456789abcdef";
        let got = redact_query_for_log(q);
        assert_eq!(got, "session&X-Amz-Signature=01234567…");
    }

    #[test]
    fn redact_uri_drops_authority_and_scheme() {
        // An absolute URI is what an HTTP/2 request looks like after the
        // :scheme / :authority pseudo-headers are folded in. The log line
        // must match the origin-form an HTTP/1.1 client produces, so that
        // access logs don't vary with the negotiated protocol version.
        let u: http::Uri = "http://example.com:9000/bucket/key?X-Amz-Signature=\
            0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .parse()
            .unwrap();
        let got = redact_uri_for_log(&u);
        assert!(got.starts_with("/bucket/key?"), "got: {got}");
        assert!(!got.contains("example.com"), "got: {got}");
        assert!(got.contains("X-Amz-Signature=01234567…"));
    }

    #[test]
    fn redact_uri_drops_authority_when_there_is_no_query() {
        let u: http::Uri = "https://example.com:9000/bucket/key".parse().unwrap();
        assert_eq!(redact_uri_for_log(&u), "/bucket/key");
    }

    #[test]
    fn distinct_signatures_keep_distinct_prefixes() {
        // Correlation use case: two log lines for two different
        // signatures must remain visually distinguishable. (8 hex chars
        // = 32 bits = ~4B distinct prefixes; collisions in any sane
        // log volume are vanishingly rare.)
        let q1 = "X-Amz-Signature=deadbeef00000000000000000000000000\
                  00000000000000000000000000000000";
        let q2 = "X-Amz-Signature=cafebabe00000000000000000000000000\
                  00000000000000000000000000000000";
        let r1 = redact_query_for_log(q1);
        let r2 = redact_query_for_log(q2);
        assert_ne!(r1, r2);
        assert!(r1.contains("deadbeef…"));
        assert!(r2.contains("cafebabe…"));
    }
}
