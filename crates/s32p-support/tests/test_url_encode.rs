// EncodingType=url support: verify per-byte percent-encoding rules and that
// list-response XML carries `<EncodingType>url</EncodingType>` plus encoded
// Key/Prefix values when requested.

use s32p_support::{s3xml, uri_encoding::s3_url_encode};

#[test]
fn unreserved_chars_pass_through_unchanged() {
    // RFC 3986 unreserved set: A-Z a-z 0-9 - . _ ~
    let s = "AZaz09-._~";
    assert_eq!(s3_url_encode(s), s);
}

#[test]
fn slash_is_encoded() {
    // AWS S3's EncodingType=url DOES encode `/` (`%2F`). Clients percent-decode
    // end-to-end, so the round-trip is lossless.
    assert_eq!(s3_url_encode("foo/bar"), "foo%2Fbar");
    assert_eq!(s3_url_encode("/"), "%2F");
}

#[test]
fn space_and_special_ascii_are_encoded() {
    assert_eq!(s3_url_encode("hello world"), "hello%20world");
    assert_eq!(s3_url_encode("a+b"), "a%2Bb");
    assert_eq!(s3_url_encode("a&b=c"), "a%26b%3Dc");
    assert_eq!(s3_url_encode("[brackets]"), "%5Bbrackets%5D");
    assert_eq!(s3_url_encode("#fragment?query"), "%23fragment%3Fquery");
}

#[test]
fn already_encoded_percent_gets_double_encoded() {
    // If a key literally contains `%2F` (i.e. five literal characters), it must
    // be encoded again so the round-trip yields the original.
    assert_eq!(s3_url_encode("%2F"), "%252F");
}

#[test]
fn multibyte_utf8_is_encoded_byte_by_byte() {
    // German umlaut: ü = 0xC3 0xBC in UTF-8
    assert_eq!(s3_url_encode("für"), "f%C3%BCr");
    // Emoji: 🦀 = F0 9F A6 80
    assert_eq!(s3_url_encode("🦀"), "%F0%9F%A6%80");
}

#[test]
fn round_trip_through_percent_decode() {
    let originals = [
        "foo/bar baz.txt",
        "weird:name?with#stuff",
        "ünicödé/key",
        "🦀/safe",
        "back\\slash",
        "a&b=c+d%e",
    ];

    for orig in originals {
        let enc = s3_url_encode(orig);
        let dec = percent_encoding::percent_decode_str(&enc).decode_utf8().unwrap();
        assert_eq!(dec.as_ref(), orig, "round-trip failed for {orig:?} → {enc} → {dec}");
    }
}

#[test]
fn list_objects_v1_xml_carries_encoding_type_when_requested() {
    let contents = vec![s3xml::ListObjectInfo {
        key:           s3_url_encode("space file.txt"),
        last_modified: "2026-01-01T00:00:00Z".to_string(),
        etag:          "\"abc\"".to_string(),
        size:          1,
        owner:         Some(s3xml::ListOwnerInfo {
            id:           "0".to_string(),
            display_name: "n".to_string(),
        }),
    }];
    let prefixes = vec![s3_url_encode("foo bar/")];

    let bytes = s3xml::list_objects_v1_body(
        "bucket",
        &s3_url_encode(""),
        Some("/"),
        &s3_url_encode(""),
        None,
        1000,
        false,
        Some("url"),
        &contents,
        &prefixes,
    )
    .unwrap();
    let s = std::str::from_utf8(&bytes).unwrap();

    assert!(s.contains("<EncodingType>url</EncodingType>"), "missing EncodingType: {s}");
    assert!(s.contains("space%20file.txt"), "key not encoded: {s}");
    assert!(s.contains("foo%20bar%2F"), "common prefix not encoded: {s}");
}

#[test]
fn list_objects_v2_xml_carries_encoding_type_when_requested() {
    let contents = vec![s3xml::ListObjectInfo {
        key:           s3_url_encode("a/b/c with spaces.txt"),
        last_modified: "2026-01-01T00:00:00Z".to_string(),
        etag:          "\"abc\"".to_string(),
        size:          1,
        owner:         None,
    }];

    let bytes = s3xml::list_objects_v2_body(
        "bucket",
        Some(&s3_url_encode("a/b/")),
        Some("/"),
        1,
        1000,
        false,
        None,
        None,
        None,
        Some("url"),
        &contents,
        &[],
    )
    .unwrap();
    let s = std::str::from_utf8(&bytes).unwrap();

    assert!(s.contains("<EncodingType>url</EncodingType>"), "missing EncodingType: {s}");
    assert!(s.contains("a%2Fb%2Fc%20with%20spaces.txt"), "key not fully encoded: {s}");
    assert!(s.contains("<Prefix>a%2Fb%2F</Prefix>"), "prefix not encoded: {s}");
}

#[test]
fn list_objects_xml_without_encoding_type_omits_element() {
    // When encoding-type isn't requested, the EncodingType element must not appear.
    let bytes =
        s3xml::list_objects_v1_body("bucket", "", None, "", None, 1000, false, None, &[], &[])
            .unwrap();
    let s = std::str::from_utf8(&bytes).unwrap();
    assert!(!s.contains("EncodingType"), "EncodingType element leaked when not requested: {s}");

    let bytes = s3xml::list_objects_v2_body(
        "bucket",
        None,
        None,
        0,
        1000,
        false,
        None,
        None,
        None,
        None,
        &[],
        &[],
    )
    .unwrap();
    let s = std::str::from_utf8(&bytes).unwrap();
    assert!(!s.contains("EncodingType"), "EncodingType element leaked in v2: {s}");
}
