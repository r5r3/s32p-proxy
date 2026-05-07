use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};

/// Percent-encode set used when an S3 list response has `encoding-type=url`.
/// Encodes every byte except the RFC 3986 unreserved set (`A-Za-z0-9-._~`).
/// In particular `/` IS encoded (`%2F`), matching AWS S3's actual behavior for
/// `EncodingType=url` responses. Clients percent-decode end-to-end, so the
/// round-trip is lossless for all UTF-8 keys.
pub const S3_URL_ENCODE_SET: &AsciiSet =
    &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');

/// Percent-encode a string for an S3 list response's `EncodingType=url`.
/// Use on `Key`, `Prefix` (echoed and in CommonPrefixes), `Marker`, `NextMarker`,
/// `StartAfter`, and `Delimiter` when the client requested url-encoding.
pub fn s3_url_encode(input: &str) -> String {
    utf8_percent_encode(input, S3_URL_ENCODE_SET).to_string()
}

/// Percent-decode a path-like string **segment-by-segment** (splitting on '/'),
/// while preserving '/' as a delimiter.
///
/// Used for:
/// - S3 path-style object keys (everything after "/{bucket}/")
/// - `x-amz-copy-source`
///
/// Behavior:
/// - Decodes each segment individually, then joins segments back with '/'.
/// - Preserves empty segments (e.g. "a//b").
/// - Malformed percent-escapes or invalid UTF-8 are handled *lossily* by keeping the original
///   (still percent-encoded) segment.
pub fn percent_decode_path_segments_lossy(input: &str) -> String {
    // Fast path: nothing to decode
    if !input.as_bytes().contains(&b'%') {
        return input.to_string();
    }

    let mut out = String::with_capacity(input.len());
    for (i, seg) in input.split('/').enumerate() {
        if i > 0 {
            out.push('/');
        }

        match percent_decode_str(seg).decode_utf8() {
            Ok(decoded) => out.push_str(&decoded),
            Err(_) => out.push_str(seg),
        }
    }

    out
}
