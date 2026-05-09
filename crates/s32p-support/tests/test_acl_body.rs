// Verifies the GetObjectAcl / GetBucketAcl XML response shape.
//
// The body mirrors AWS's `bucket-owner-enforced` response: a single
// FULL_CONTROL grant for the owner, plus an optional READ grant for
// `Group: AllUsers` when the underlying file is world-readable.

use http::Uri;
use s32p_support::{
    classifier::{ReadOp, S3Op, classify_with_headers},
    s3xml::get_acl_body,
};

#[test]
fn owner_only_full_control() {
    let xml_bytes = get_acl_body("1000", "alice", false).unwrap();
    let xml = std::str::from_utf8(&xml_bytes).unwrap();

    assert!(
        xml.starts_with("<AccessControlPolicy"),
        "unexpected root element: {xml}"
    );
    assert!(xml.contains("xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\""));

    // Owner block
    assert!(xml.contains("<Owner><ID>1000</ID><DisplayName>alice</DisplayName></Owner>"));

    // Single canonical-user grant with FULL_CONTROL
    assert!(xml.contains("xsi:type=\"CanonicalUser\""));
    assert!(xml.contains("xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""));
    assert!(xml.contains("<Permission>FULL_CONTROL</Permission>"));

    // No public-read grant when not world-readable
    assert!(!xml.contains("AllUsers"), "should not emit AllUsers grant: {xml}");
}

#[test]
fn world_readable_adds_all_users_read_grant() {
    let xml_bytes = get_acl_body("1000", "alice", true).unwrap();
    let xml = std::str::from_utf8(&xml_bytes).unwrap();

    // Still has the owner FULL_CONTROL grant
    assert!(xml.contains("<Permission>FULL_CONTROL</Permission>"));

    // Plus a Group/AllUsers READ grant
    assert!(xml.contains("xsi:type=\"Group\""));
    assert!(xml.contains("<URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>"));
    assert!(xml.contains("<Permission>READ</Permission>"));
}

#[test]
fn classifier_routes_get_object_acl() {
    let uri: Uri = "/bucket/path/to/file.txt?acl".parse().unwrap();
    let class = classify_with_headers("GET", &uri, None, &[]);
    assert!(matches!(class.op, S3Op::Read(ReadOp::GetObjectAcl)));
    assert_eq!(class.bucket.as_deref(), Some("bucket"));
    assert_eq!(class.key.as_deref(), Some("path/to/file.txt"));
}

#[test]
fn classifier_routes_get_bucket_acl() {
    let uri: Uri = "/bucket?acl".parse().unwrap();
    let class = classify_with_headers("GET", &uri, None, &[]);
    assert!(matches!(class.op, S3Op::Read(ReadOp::GetBucketAcl)));
    assert_eq!(class.bucket.as_deref(), Some("bucket"));
    assert_eq!(class.key, None);
}

#[test]
fn classifier_acl_with_versionid_still_routes_to_acl() {
    // boto3 / aws-cli sometimes append versionId; we ignore versioning but
    // must still recognize the request as GetObjectAcl rather than falling
    // through to S3Op::Other (which would route to versitygw and 501).
    let uri: Uri = "/bucket/key.txt?acl&versionId=null".parse().unwrap();
    let class = classify_with_headers("GET", &uri, None, &[]);
    assert!(
        matches!(class.op, S3Op::Read(ReadOp::GetObjectAcl)),
        "expected GetObjectAcl, got {:?}",
        class.op
    );
}

#[test]
fn classifier_get_object_without_acl_unchanged() {
    // Sanity: making sure the new branch didn't steal plain GETs.
    let uri: Uri = "/bucket/file.txt".parse().unwrap();
    let class = classify_with_headers("GET", &uri, None, &[]);
    assert!(matches!(class.op, S3Op::Read(ReadOp::GetObject)));
}
