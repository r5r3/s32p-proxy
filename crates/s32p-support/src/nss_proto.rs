//! Wire protocol for the NSS lookup proxy.
//!
//! The proxy runs an NSS lookup listener (`getpwuid_r`) that workers query
//! over a Linux abstract-namespace Unix domain socket. Stripping `--allow-nss`
//! from the worker's Landlock policy means the worker cannot read
//! `/etc/passwd` directly; this protocol is the worker's only path to a
//! uid → username string.
//!
//! ```text
//! Request:  4 bytes — uid as u32 little-endian
//! Response: 1 byte  — name length N (0 = unknown uid)
//!           N bytes — UTF-8 username
//! ```
//!
//! `LOGIN_NAME_MAX` is 256 on Linux; usernames are in practice ≤32 chars, so a
//! 1-byte length field is sufficient. Each connection is a stream of
//! independent request/response pairs.
//!
//! This module is intentionally sync / tokio-free. Async wire I/O lives in
//! the proxy and gateway crates, which already depend on tokio.

/// Prefix that distinguishes a Linux abstract-namespace socket name from a
/// filesystem path in the `S32P_NSS_PROXY_SOCK` env var.
pub const ABSTRACT_PREFIX: char = '@';

/// Wire length of the request frame in bytes.
pub const REQUEST_LEN: usize = 4;

/// Maximum encodable username length (constrained by the 1-byte length field).
pub const MAX_NAME_LEN: usize = 255;

/// Encode a uid as the wire request bytes.
pub fn encode_request(uid: u32) -> [u8; REQUEST_LEN] {
    uid.to_le_bytes()
}

/// Decode the request bytes back into a uid.
pub fn decode_request(buf: [u8; REQUEST_LEN]) -> u32 {
    u32::from_le_bytes(buf)
}

/// Build the wire bytes for a response. `None` is the unknown-uid marker
/// (single 0 byte). Returns `Err(())` if the name exceeds [`MAX_NAME_LEN`].
pub fn encode_response(name: Option<&str>) -> Result<Vec<u8>, NameTooLong> {
    let bytes = name.map(str::as_bytes).unwrap_or(&[]);
    if bytes.len() > MAX_NAME_LEN {
        return Err(NameTooLong);
    }
    let mut out = Vec::with_capacity(1 + bytes.len());
    out.push(bytes.len() as u8);
    out.extend_from_slice(bytes);
    Ok(out)
}

/// Returned by [`encode_response`] when the name exceeds the wire limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NameTooLong;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip() {
        let uid: u32 = 1234567;
        let buf = encode_request(uid);
        assert_eq!(decode_request(buf), uid);
    }

    #[test]
    fn encode_response_some() {
        let bytes = encode_response(Some("alice")).unwrap();
        assert_eq!(bytes, vec![5, b'a', b'l', b'i', b'c', b'e']);
    }

    #[test]
    fn encode_response_none() {
        let bytes = encode_response(None).unwrap();
        assert_eq!(bytes, vec![0]);
    }

    #[test]
    fn encode_response_empty_string_is_none_on_wire() {
        // Length 0 with no bytes — same wire representation as None.
        let bytes = encode_response(Some("")).unwrap();
        assert_eq!(bytes, vec![0]);
    }

    #[test]
    fn encode_response_rejects_oversize() {
        let big = "x".repeat(MAX_NAME_LEN + 1);
        assert_eq!(encode_response(Some(&big)), Err(NameTooLong));
    }

    #[test]
    fn encode_response_accepts_max_size() {
        let big = "x".repeat(MAX_NAME_LEN);
        let bytes = encode_response(Some(&big)).unwrap();
        assert_eq!(bytes.len(), 1 + MAX_NAME_LEN);
        assert_eq!(bytes[0] as usize, MAX_NAME_LEN);
    }
}
