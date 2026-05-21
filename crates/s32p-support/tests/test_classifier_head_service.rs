//! HeadService classification.
//!
//! `HEAD /` is not a documented S3 operation — only `GET /` (ListBuckets)
//! is. Clients like Cyberduck / MountainDuck and `mc` issue `HEAD /` as a
//! connectivity probe before doing real work; AWS S3 returns 405 Method
//! Not Allowed. The classifier must emit `S3Op::HeadService` so the
//! proxy can route it to `aws_compat` and short-circuit the 405 without
//! touching a worker.

use http::{HeaderMap, HeaderValue, Uri};
use s32p_support::classifier::{S3Op, class_key, classify_with_headers};

fn classify(method: &str, path_and_query: &str) -> S3Op {
    let uri: Uri = path_and_query.parse().unwrap();
    let mut h = HeaderMap::new();
    h.insert("host", HeaderValue::from_static("s3.example.com"));
    classify_with_headers(method, &uri, Some(&h), &[]).op
}

#[test]
fn head_root_is_head_service() {
    assert!(matches!(classify("HEAD", "/"), S3Op::HeadService));
}

#[test]
fn head_root_with_xid_still_head_service() {
    // `x-id` is the AWS SDK's diagnostic query param; the classifier is
    // explicitly tolerant of it everywhere (see is_empty_effective and
    // validate_xid). HEAD / with x-id must still classify as HeadService.
    assert!(matches!(
        classify("HEAD", "/?x-id=HeadService"),
        S3Op::HeadService
    ));
}

#[test]
fn head_root_with_other_query_is_other_not_head_service() {
    // A HEAD with a substantive query param isn't a probe; falling back
    // to Other is correct (the classifier doesn't pretend to know what
    // such a request would mean).
    let op = classify("HEAD", "/?foo=bar");
    assert!(matches!(op, S3Op::Other), "expected Other, got {op:?}");
}

#[test]
fn get_root_remains_list_buckets() {
    // Regression guard: adding HeadService must not have shifted the
    // ListBuckets branch.
    use s32p_support::classifier::ReadOp;
    assert!(matches!(
        classify("GET", "/"),
        S3Op::Read(ReadOp::ListBuckets)
    ));
}

#[test]
fn head_bucket_remains_head_bucket() {
    // Regression guard: HEAD /{bucket} is HeadBucket, not HeadService.
    // Specifically the HeadService branch only fires when bucket is None.
    use s32p_support::classifier::ReadOp;
    let op = classify("HEAD", "/some-bucket");
    assert!(matches!(op, S3Op::Read(ReadOp::HeadBucket)), "got {op:?}");
}

#[test]
fn head_service_class_key_is_service() {
    // The class key is the contract between the classifier and the
    // operator's `routing.class_map`. "service" is the entry that maps
    // HeadService to its action.
    let uri: Uri = "/".parse().unwrap();
    let mut h = HeaderMap::new();
    h.insert("host", HeaderValue::from_static("s3.example.com"));
    let class = classify_with_headers("HEAD", &uri, Some(&h), &[]);
    assert_eq!(class_key(&class), "service");
}

#[test]
fn head_service_does_not_need_write() {
    // ACL evaluation: a read_only caller must be allowed to probe.
    let op = S3Op::HeadService;
    assert!(!op.needs_write());
}
