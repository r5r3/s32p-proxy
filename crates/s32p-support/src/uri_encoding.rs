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

/// Canonicalize a URI path for AWS SigV4 verification.
///
/// Returns the path with all bytes outside the unreserved set (`A-Za-z0-9-._~`)
/// and `/` percent-encoded, while leaving existing well-formed `%XX` sequences
/// intact (and upper-casing their hex digits).
///
/// Why this exists: with `PercentEncodingMode::Single`, aws-sigv4 uses the wire
/// URI path verbatim as the canonical URI. But several SDKs (boto3, aws-cli,
/// AWS Java SDK, minio-go in some paths) leave sub-delim characters like
/// `(`, `)`, `*`, `'`, `!`, `:`, `@` unencoded on the wire while still
/// percent-encoding them when computing the SigV4 canonical request, per the
/// AWS spec ("URI encode every byte except the unreserved characters"). The
/// resulting wire-vs-canonical divergence breaks signature verification unless
/// we re-encode the wire path the same way the client did.
pub fn canonicalize_uri_path_for_sigv4(path: &str) -> String {
    fn is_unreserved_or_slash(b: u8) -> bool {
        b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'/')
    }
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let bytes = path.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            out.push('%');
            out.push(bytes[i + 1].to_ascii_uppercase() as char);
            out.push(bytes[i + 2].to_ascii_uppercase() as char);
            i += 3;
            continue;
        }
        if is_unreserved_or_slash(b) {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0F) as usize] as char);
        }
        i += 1;
    }
    out
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
