//! Utility functions for string manipulation and other common operations.

use anyhow::{anyhow, Result};

/// A byte range for HTTP range requests.
/// Represents a range [start, end_excl) where end_excl is exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    /// Start of the range (inclusive)
    pub start: u64,
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
/// use s32p_support::utils::{parse_range_header, ByteRange};
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
}