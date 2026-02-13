use percent_encoding::percent_decode_str;

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
