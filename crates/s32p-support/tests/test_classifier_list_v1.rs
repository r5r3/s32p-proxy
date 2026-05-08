use http::{HeaderMap, HeaderValue, Uri};
use s32p_support::classifier::{ReadOp, S3Op, classify_with_headers};

fn classify(method: &str, path_and_query: &str) -> S3Op {
    let uri: Uri = path_and_query.parse().unwrap();
    let mut h = HeaderMap::new();
    h.insert("host", HeaderValue::from_static("s3.example.com"));
    classify_with_headers(method, &uri, Some(&h), &[]).op
}

#[test]
fn list_objects_v1_plain_get_bucket() {
    // mcli `aws s3api list-objects` flavor with no params at all.
    assert!(matches!(classify("GET", "/s3test"), S3Op::Read(ReadOp::ListObjectsV1)));
    assert!(matches!(classify("GET", "/s3test/"), S3Op::Read(ReadOp::ListObjectsV1)));
}

#[test]
fn list_objects_v1_mountain_duck_query_shape() {
    // Mountain Duck:
    //   GET /s3test/?encoding-type=url&max-keys=1000&prefix=&delimiter=%2F
    let op = classify("GET", "/s3test/?encoding-type=url&max-keys=1000&prefix=&delimiter=%2F");
    assert!(matches!(op, S3Op::Read(ReadOp::ListObjectsV1)), "expected ListObjectsV1, got {op:?}");
}

#[test]
fn list_objects_v1_with_marker_and_prefix() {
    let op = classify("GET", "/s3test/?prefix=foo/&marker=foo/baz&max-keys=42");
    assert!(matches!(op, S3Op::Read(ReadOp::ListObjectsV1)));
}

#[test]
fn list_objects_v2_still_takes_precedence() {
    // V1 fallback must NOT swallow V2 — list-type=2 still routes to V2.
    let op = classify("GET", "/s3test/?list-type=2&prefix=foo&continuation-token=abc");
    assert!(matches!(op, S3Op::Read(ReadOp::ListObjectsV2)));
}

#[test]
fn get_bucket_location_still_takes_precedence() {
    // ?location must still route to GetBucketLocation, not be misclassified as V1.
    let op = classify("GET", "/s3test/?location=");
    assert!(matches!(op, S3Op::Read(ReadOp::GetBucketLocation)));
}

#[test]
fn list_buckets_at_root_unchanged() {
    // GET / (no bucket) is ListBuckets, not ListObjectsV1.
    let op = classify("GET", "/");
    assert!(matches!(op, S3Op::Read(ReadOp::ListBuckets)));
}
