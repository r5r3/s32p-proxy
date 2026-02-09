//! Utility functions for string manipulation and other common operations.

/// Trim leading and trailing slashes from a string.
/// This is useful for normalizing paths and URLs.
///
/// # Examples
/// ```
/// use s3pm_support::utils::trim_slashes;
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
}