//! Unit-style coverage for the user-metadata and Content-Type validators
//! in `s3xml.rs`. The integration suite exercises them end-to-end through
//! the gateway; these tests pin the validator boundary so charset changes
//! don't silently drift.

use s32p_support::s3xml::{validate_content_type, validate_user_metadata_urlform};

// ----- validate_user_metadata_urlform -----------------------------------

#[test]
fn user_meta_accepts_simple_pair() {
    assert!(validate_user_metadata_urlform("author=alice").is_ok());
}

#[test]
fn user_meta_accepts_empty_payload() {
    assert!(validate_user_metadata_urlform("").is_ok());
}

#[test]
fn user_meta_rejects_high_bit_byte_in_value() {
    // AWS documents user metadata as ASCII-only; SDKs URL-encode non-ASCII
    // before sending. Mirroring that server-side keeps the contract coherent
    // — `HeaderValue` would accept obs-text and round-trip the bytes, but
    // most HTTP clients reinterpret them as latin-1 and would surface
    // mojibake to the caller.
    let bad = format!("author=alic{}", "\u{00e4}");
    assert!(validate_user_metadata_urlform(&bad).is_err());
}

#[test]
fn user_meta_rejects_control_byte_in_value() {
    // Control bytes that `HeaderValue` rejects would silently disappear from
    // HEAD/GET responses (the user_meta loop in `apply_object_headers` skips
    // pairs that fail `HeaderValue::try_from`). Reject at PUT.
    let bad = "author=alic\x01e";
    assert!(validate_user_metadata_urlform(bad).is_err());
}

#[test]
fn user_meta_allows_tab_cr_lf_in_value() {
    // Common whitespace remains allowed — matches the prior behavior; HTTP
    // header line folding has been deprecated but `\t` is still valid in
    // header values.
    assert!(validate_user_metadata_urlform("k=a\tb").is_ok());
}

#[test]
fn user_meta_rejects_too_many_pairs() {
    let pairs: Vec<String> = (0..33).map(|i| format!("k{i}=v")).collect();
    assert!(validate_user_metadata_urlform(&pairs.join("&")).is_err());
}

#[test]
fn user_meta_rejects_oversized_payload() {
    let big = "a".repeat(2049);
    let payload = format!("k={big}");
    assert!(validate_user_metadata_urlform(&payload).is_err());
}

// ----- validate_content_type --------------------------------------------

#[test]
fn content_type_accepts_simple() {
    assert!(validate_content_type("text/plain").is_ok());
}

#[test]
fn content_type_accepts_with_params() {
    assert!(validate_content_type("text/html; charset=utf-8").is_ok());
}

#[test]
fn content_type_rejects_missing_slash() {
    assert!(validate_content_type("not-a-mime").is_err());
}

#[test]
fn content_type_rejects_high_bit_byte_in_params() {
    // Regression: the prior validator only screened the type/subtype
    // tokens and let high-bit bytes pass through in the params section.
    // MIME types are ASCII per RFC 6838, and any obs-text would round-
    // trip as mojibake through most HTTP clients — restrict the entire
    // string to printable ASCII to keep the contract coherent.
    let bad = "text/html; charset=\u{00e4}";
    assert!(validate_content_type(bad).is_err());
}

#[test]
fn content_type_rejects_control_byte() {
    assert!(validate_content_type("text/plain\x01").is_err());
}

#[test]
fn content_type_rejects_empty() {
    assert!(validate_content_type("").is_err());
}

#[test]
fn content_type_rejects_oversized() {
    let big = format!("text/{}", "x".repeat(252));
    assert!(validate_content_type(&big).is_err());
}
