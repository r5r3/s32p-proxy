use s32p_support::classifier::{classify_with_headers, QueryParams};
use http::Uri;
use std::str::FromStr;

#[test]
fn test_xid_validation_logic() {
    // Test the validate_xid function directly
    
    // Test 1: No x-id should always be valid
    let query = QueryParams::from_uri(&Uri::from_str("/bucket/key").unwrap());
    assert!(query.validate_xid("GetObject"), "Empty query should be valid for any operation");
    
    // Test 2: Matching x-id should be valid
    let query = QueryParams::from_uri(&Uri::from_str("/bucket/key?x-id=GetObject").unwrap());
    assert!(query.validate_xid("GetObject"), "Matching x-id should be valid");
    
    // Test 3: Non-matching x-id should be invalid
    let query = QueryParams::from_uri(&Uri::from_str("/bucket/key?x-id=PutObject").unwrap());
    assert!(!query.validate_xid("GetObject"), "Non-matching x-id should be invalid");
    
    // Test 4: x-id with other params should still validate
    let query = QueryParams::from_uri(&Uri::from_str("/bucket/key?x-id=GetObject&other=param").unwrap());
    assert!(query.validate_xid("GetObject"), "x-id should validate even with other params");
}

#[test]
fn test_xid_classification_integration() {
    // Test that x-id is properly handled in classification
    
    // Test 1: GetObject with matching x-id should work
    let uri = Uri::from_str("/bucket/key?x-id=GetObject").unwrap();
    let class = classify_with_headers("GET", &uri, None, &[]);
    assert!(matches!(class.op, s32p_support::classifier::S3Op::Read(
        s32p_support::classifier::ReadOp::GetObject
    )));
    
    // Test 2: GetObject with wrong x-id should not match
    let uri = Uri::from_str("/bucket/key?x-id=PutObject").unwrap();
    let class = classify_with_headers("GET", &uri, None, &[]);
    assert!(!matches!(class.op, s32p_support::classifier::S3Op::Read(
        s32p_support::classifier::ReadOp::GetObject
    )));
    
    // Test 3: GetObject without x-id should work
    let uri = Uri::from_str("/bucket/key").unwrap();
    let class = classify_with_headers("GET", &uri, None, &[]);
    assert!(matches!(class.op, s32p_support::classifier::S3Op::Read(
        s32p_support::classifier::ReadOp::GetObject
    )));
}

#[test]
fn test_xid_with_different_operations() {
    // Test x-id validation with different operation types
    
    // Test PutObject
    let uri = Uri::from_str("/bucket/key?x-id=PutObject").unwrap();
    let class = classify_with_headers("PUT", &uri, None, &[]);
    assert!(matches!(class.op, s32p_support::classifier::S3Op::Write(
        s32p_support::classifier::WriteOp::PutObject
    )));
    
    // Test DeleteObject
    let uri = Uri::from_str("/bucket/key?x-id=DeleteObject").unwrap();
    let class = classify_with_headers("DELETE", &uri, None, &[]);
    assert!(matches!(class.op, s32p_support::classifier::S3Op::Write(
        s32p_support::classifier::WriteOp::DeleteObject
    )));
    
    // Test ListBuckets
    let uri = Uri::from_str("/?x-id=ListBuckets").unwrap();
    let class = classify_with_headers("GET", &uri, None, &[]);
    assert!(matches!(class.op, s32p_support::classifier::S3Op::Read(
        s32p_support::classifier::ReadOp::ListBuckets
    )));
}

#[test]
fn test_xid_with_multipart_operations() {
    // Test x-id with multipart operations
    
    // Test CreateMultipartUpload
    let uri = Uri::from_str("/bucket/key?uploads&x-id=CreateMultipartUpload").unwrap();
    let class = classify_with_headers("POST", &uri, None, &[]);
    assert!(matches!(class.op, s32p_support::classifier::S3Op::Multipart(
        s32p_support::classifier::MultipartOp::CreateMultipartUpload
    )));
    
    // Test ListMultipartUploads
    let uri = Uri::from_str("/bucket?uploads&x-id=ListMultipartUploads").unwrap();
    let class = classify_with_headers("GET", &uri, None, &[]);
    assert!(matches!(class.op, s32p_support::classifier::S3Op::Multipart(
        s32p_support::classifier::MultipartOp::ListMultipartUploads
    )));
}

#[test]
fn test_xid_with_versioning_operations() {
    // Test x-id with versioning operations
    
    // Test GetBucketVersioning
    let uri = Uri::from_str("/bucket?versioning&x-id=GetBucketVersioning").unwrap();
    let class = classify_with_headers("GET", &uri, None, &[]);
    assert!(matches!(class.op, s32p_support::classifier::S3Op::Versioning(
        s32p_support::classifier::VersioningOp::GetBucketVersioning
    )));
}

#[test]
fn test_xid_with_bucket_admin_operations() {
    // Test x-id with bucket admin operations
    
    // Test CreateBucket
    let uri = Uri::from_str("/bucket?x-id=CreateBucket").unwrap();
    let class = classify_with_headers("PUT", &uri, None, &[]);
    assert!(matches!(class.op, s32p_support::classifier::S3Op::BucketAdmin(
        s32p_support::classifier::BucketAdminOp::CreateBucket
    )));
    
    // Test DeleteBucket
    let uri = Uri::from_str("/bucket?x-id=DeleteBucket").unwrap();
    let class = classify_with_headers("DELETE", &uri, None, &[]);
    assert!(matches!(class.op, s32p_support::classifier::S3Op::BucketAdmin(
        s32p_support::classifier::BucketAdminOp::DeleteBucket
    )));
}

#[test]
fn test_non_effective_attributes() {
    // Test that standard HTTP headers are treated as non-effective attributes
    
    // Test GetObject with various non-effective attributes
    let uri = Uri::from_str("/bucket/key?content-type=text/plain&cache-control=max-age=3600").unwrap();
    let class = classify_with_headers("GET", &uri, None, &[]);
    assert!(matches!(class.op, s32p_support::classifier::S3Op::Read(
        s32p_support::classifier::ReadOp::GetObject
    )));
    
    // Test PutObject with content-disposition
    let uri = Uri::from_str("/bucket/key?content-disposition=attachment").unwrap();
    let class = classify_with_headers("PUT", &uri, None, &[]);
    assert!(matches!(class.op, s32p_support::classifier::S3Op::Write(
        s32p_support::classifier::WriteOp::PutObject
    )));
    
    // Test with expires parameter
    let uri = Uri::from_str("/bucket/key?expires=1234567890").unwrap();
    let class = classify_with_headers("GET", &uri, None, &[]);
    assert!(matches!(class.op, s32p_support::classifier::S3Op::Read(
        s32p_support::classifier::ReadOp::GetObject
    )));
    
    // Test with content-encoding
    let uri = Uri::from_str("/bucket/key?content-encoding=gzip").unwrap();
    let class = classify_with_headers("GET", &uri, None, &[]);
    assert!(matches!(class.op, s32p_support::classifier::S3Op::Read(
        s32p_support::classifier::ReadOp::GetObject
    )));
    
    // Test with multiple non-effective attributes
    let uri = Uri::from_str("/bucket/key?content-type=text/plain&cache-control=no-cache&content-disposition=inline").unwrap();
    let class = classify_with_headers("GET", &uri, None, &[]);
    assert!(matches!(class.op, s32p_support::classifier::S3Op::Read(
        s32p_support::classifier::ReadOp::GetObject
    )));
    
    // Test with x-amz-storage-class
    let uri = Uri::from_str("/bucket/key?x-amz-storage-class=STANDARD").unwrap();
    let class = classify_with_headers("PUT", &uri, None, &[]);
    assert!(matches!(class.op, s32p_support::classifier::S3Op::Write(
        s32p_support::classifier::WriteOp::PutObject
    )));
    
    // Test with x-amz-storage-class and other non-effective attributes
    let uri = Uri::from_str("/bucket/key?x-amz-storage-class=REDUCED_REDUNDANCY&content-type=application/json&cache-control=public").unwrap();
    let class = classify_with_headers("PUT", &uri, None, &[]);
    assert!(matches!(class.op, s32p_support::classifier::S3Op::Write(
        s32p_support::classifier::WriteOp::PutObject
    )));
}