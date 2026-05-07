use http::{HeaderMap, HeaderValue, Uri};
use s32p_support::classifier::{classify_with_headers, ReadOp, S3Op};

#[test]
fn get_bucket_location_with_trailing_slash_and_remote_host() {
    let uri: Uri = "/s3test/?location=".parse().unwrap();
    let mut h = HeaderMap::new();
    h.insert("host", HeaderValue::from_static("s3.example.com"));
    let suffixes = vec!["127.0.0.1.nip.io".to_string(), "localhost".to_string()];

    let cls = classify_with_headers("GET", &uri, Some(&h), &suffixes);

    println!("classified as: {:?}", cls);
    assert!(
        matches!(cls.op, S3Op::Read(ReadOp::GetBucketLocation)),
        "expected Read(GetBucketLocation), got {:?}",
        cls.op
    );
}

#[test]
fn empty_string_suffix_must_not_trigger_virtual_hosted() {
    // This reproduces what the gateway sees when S32P_VIRTUAL_HOSTED_SUFFIXES="" is
    // parsed via "".split(',').collect() — yielding a vec with a single empty string.
    let uri: Uri = "/s3test/?location=".parse().unwrap();
    let mut h = HeaderMap::new();
    h.insert("host", HeaderValue::from_static("s3.example.com"));
    let suffixes = vec!["".to_string()];

    let cls = classify_with_headers("GET", &uri, Some(&h), &suffixes);

    println!("classified as: {:?}", cls);
    assert!(
        matches!(cls.op, S3Op::Read(ReadOp::GetBucketLocation)),
        "expected Read(GetBucketLocation), got {:?}",
        cls.op
    );
}
