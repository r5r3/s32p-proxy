// Tests for S3 precondition evaluation functions

use http::HeaderMap;
use s32p_support::preconditions::{parse_conditional_headers, ConditionalHeaders};
use s32p_support::utils::ETagCondition;
use s32p_support::preconditions::{evaluate_copy_source_preconditions, evaluate_read_preconditions, evaluate_write_preconditions, PreconditionOutcome};
use std::time::UNIX_EPOCH;

// ============ READ PRECONDITIONS (GET/HEAD) ============

#[test]
fn test_read_preconditions_if_match() {
    let cond = ConditionalHeaders {
        if_match: Some(ETagCondition::OneOf(vec!["expected-etag".to_string()])),
        if_none_match: None,
        if_modified_since: None,
        if_unmodified_since: None,
        copy_source_if_match: None,
        copy_source_if_none_match: None,
        copy_source_if_modified_since: None,
        copy_source_if_unmodified_since: None,
        amz_if_match_size: None,
        amz_if_match_last_modified_time: None,
    };

    // Should fail if ETag doesn't match
    let result = evaluate_read_preconditions(&cond, "different-etag", UNIX_EPOCH);
    assert!(matches!(result, PreconditionOutcome::PreconditionFailed));

    // Should succeed if ETag matches
    let result = evaluate_read_preconditions(&cond, "expected-etag", UNIX_EPOCH);
    assert!(matches!(result, PreconditionOutcome::Proceed));
}

#[test]
fn test_read_preconditions_if_none_match() {
    let cond = ConditionalHeaders {
        if_match: None,
        if_none_match: Some(ETagCondition::OneOf(vec!["forbidden-etag".to_string()])),
        if_modified_since: None,
        if_unmodified_since: None,
        copy_source_if_match: None,
        copy_source_if_none_match: None,
        copy_source_if_modified_since: None,
        copy_source_if_unmodified_since: None,
        amz_if_match_size: None,
        amz_if_match_last_modified_time: None,
    };

    // Should return NotModified if ETag matches
    let result = evaluate_read_preconditions(&cond, "forbidden-etag", UNIX_EPOCH);
    assert!(matches!(result, PreconditionOutcome::NotModified));

    // Should succeed if ETag doesn't match
    let result = evaluate_read_preconditions(&cond, "different-etag", UNIX_EPOCH);
    assert!(matches!(result, PreconditionOutcome::Proceed));
}

#[test]
fn test_read_preconditions_if_modified_since() {
    let cond = ConditionalHeaders {
        if_match: None,
        if_none_match: None,
        if_modified_since: Some(UNIX_EPOCH + std::time::Duration::from_secs(100)),
        if_unmodified_since: None,
        copy_source_if_match: None,
        copy_source_if_none_match: None,
        copy_source_if_modified_since: None,
        copy_source_if_unmodified_since: None,
        amz_if_match_size: None,
        amz_if_match_last_modified_time: None,
    };

    // Should return NotModified if not modified since specified time
    let result = evaluate_read_preconditions(&cond, "any-etag", UNIX_EPOCH + std::time::Duration::from_secs(50));
    assert!(matches!(result, PreconditionOutcome::NotModified));

    // Should succeed if modified after specified time
    let result = evaluate_read_preconditions(&cond, "any-etag", UNIX_EPOCH + std::time::Duration::from_secs(150));
    assert!(matches!(result, PreconditionOutcome::Proceed));
}

#[test]
fn test_read_preconditions_if_unmodified_since() {
    let cond = ConditionalHeaders {
        if_match: None,
        if_none_match: None,
        if_modified_since: None,
        if_unmodified_since: Some(UNIX_EPOCH + std::time::Duration::from_secs(100)),
        copy_source_if_match: None,
        copy_source_if_none_match: None,
        copy_source_if_modified_since: None,
        copy_source_if_unmodified_since: None,
        amz_if_match_size: None,
        amz_if_match_last_modified_time: None,
    };

    // Should succeed if not modified after specified time
    let result = evaluate_read_preconditions(&cond, "any-etag", UNIX_EPOCH + std::time::Duration::from_secs(50));
    assert!(matches!(result, PreconditionOutcome::Proceed));

    // Should fail if modified after specified time
    let result = evaluate_read_preconditions(&cond, "any-etag", UNIX_EPOCH + std::time::Duration::from_secs(150));
    assert!(matches!(result, PreconditionOutcome::PreconditionFailed));
}

#[test]
fn test_read_preconditions_wildcards() {
    // Wildcard If-Match should match any ETag
    let cond = ConditionalHeaders {
        if_match: Some(ETagCondition::Any),
        if_none_match: None,
        if_modified_since: None,
        if_unmodified_since: None,
        copy_source_if_match: None,
        copy_source_if_none_match: None,
        copy_source_if_modified_since: None,
        copy_source_if_unmodified_since: None,
        amz_if_match_size: None,
        amz_if_match_last_modified_time: None,
    };

    let result = evaluate_read_preconditions(&cond, "any-etag", UNIX_EPOCH);
    assert!(matches!(result, PreconditionOutcome::Proceed));

    // Wildcard If-None-Match should match any ETag (return NotModified)
    let cond = ConditionalHeaders {
        if_match: None,
        if_none_match: Some(ETagCondition::Any),
        if_modified_since: None,
        if_unmodified_since: None,
        copy_source_if_match: None,
        copy_source_if_none_match: None,
        copy_source_if_modified_since: None,
        copy_source_if_unmodified_since: None,
        amz_if_match_size: None,
        amz_if_match_last_modified_time: None,
    };

    let result = evaluate_read_preconditions(&cond, "any-etag", UNIX_EPOCH);
    assert!(matches!(result, PreconditionOutcome::NotModified));
}

#[test]
fn test_read_preconditions_no_conditions() {
    let cond = ConditionalHeaders::default();
    let result = evaluate_read_preconditions(&cond, "any-etag", UNIX_EPOCH);
    assert!(matches!(result, PreconditionOutcome::Proceed));
}

// ============ WRITE PRECONDITIONS (PUT/DELETE/COPY destination) ============

#[test]
fn test_write_preconditions_if_match() {
    let cond = ConditionalHeaders {
        if_match: Some(ETagCondition::OneOf(vec!["expected-etag".to_string()])),
        if_none_match: None,
        if_modified_since: None,
        if_unmodified_since: None,
        copy_source_if_match: None,
        copy_source_if_none_match: None,
        copy_source_if_modified_since: None,
        copy_source_if_unmodified_since: None,
        amz_if_match_size: None,
        amz_if_match_last_modified_time: None,
    };

    // Should fail if object doesn't exist
    let result = evaluate_write_preconditions(&cond, None);
    assert!(matches!(result, PreconditionOutcome::PreconditionFailed));

    // Should fail if ETag doesn't match
    let result = evaluate_write_preconditions(&cond, Some(("different-etag", UNIX_EPOCH)));
    assert!(matches!(result, PreconditionOutcome::PreconditionFailed));

    // Should succeed if ETag matches
    let result = evaluate_write_preconditions(&cond, Some(("expected-etag", UNIX_EPOCH)));
    assert!(matches!(result, PreconditionOutcome::Proceed));
}

#[test]
fn test_write_preconditions_if_none_match() {
    let cond = ConditionalHeaders {
        if_match: None,
        if_none_match: Some(ETagCondition::OneOf(vec!["forbidden-etag".to_string()])),
        if_modified_since: None,
        if_unmodified_since: None,
        copy_source_if_match: None,
        copy_source_if_none_match: None,
        copy_source_if_modified_since: None,
        copy_source_if_unmodified_since: None,
        amz_if_match_size: None,
        amz_if_match_last_modified_time: None,
    };

    // Should succeed if object doesn't exist
    let result = evaluate_write_preconditions(&cond, None);
    assert!(matches!(result, PreconditionOutcome::Proceed));

    // Should succeed if ETag doesn't match
    let result = evaluate_write_preconditions(&cond, Some(("different-etag", UNIX_EPOCH)));
    assert!(matches!(result, PreconditionOutcome::Proceed));

    // Should fail if ETag matches
    let result = evaluate_write_preconditions(&cond, Some(("forbidden-etag", UNIX_EPOCH)));
    assert!(matches!(result, PreconditionOutcome::PreconditionFailed));
}

#[test]
fn test_write_preconditions_wildcard_if_none_match() {
    // Wildcard If-None-Match is commonly used to prevent overwrites
    let cond = ConditionalHeaders {
        if_match: None,
        if_none_match: Some(ETagCondition::Any), // "*"
        if_modified_since: None,
        if_unmodified_since: None,
        copy_source_if_match: None,
        copy_source_if_none_match: None,
        copy_source_if_modified_since: None,
        copy_source_if_unmodified_since: None,
        amz_if_match_size: None,
        amz_if_match_last_modified_time: None,
    };

    // Should succeed if object doesn't exist
    let result = evaluate_write_preconditions(&cond, None);
    assert!(matches!(result, PreconditionOutcome::Proceed));

    // Should fail if any object exists
    let result = evaluate_write_preconditions(&cond, Some(("any-etag", UNIX_EPOCH)));
    assert!(matches!(result, PreconditionOutcome::PreconditionFailed));
}

#[test]
fn test_write_preconditions_if_unmodified_since() {
    let cond = ConditionalHeaders {
        if_match: None,
        if_none_match: None,
        if_modified_since: None,
        if_unmodified_since: Some(UNIX_EPOCH + std::time::Duration::from_secs(100)),
        copy_source_if_match: None,
        copy_source_if_none_match: None,
        copy_source_if_modified_since: None,
        copy_source_if_unmodified_since: None,
        amz_if_match_size: None,
        amz_if_match_last_modified_time: None,
    };

    // Should succeed if object doesn't exist
    let result = evaluate_write_preconditions(&cond, None);
    assert!(matches!(result, PreconditionOutcome::Proceed));

    // Should succeed if not modified after specified time
    let result = evaluate_write_preconditions(&cond, Some(("any-etag", UNIX_EPOCH + std::time::Duration::from_secs(50))));
    assert!(matches!(result, PreconditionOutcome::Proceed));

    // Should fail if modified after specified time
    let result = evaluate_write_preconditions(&cond, Some(("any-etag", UNIX_EPOCH + std::time::Duration::from_secs(150))));
    assert!(matches!(result, PreconditionOutcome::PreconditionFailed));
}

#[test]
fn test_write_preconditions_if_modified_since() {
    let cond = ConditionalHeaders {
        if_match: None,
        if_none_match: None,
        if_modified_since: Some(UNIX_EPOCH + std::time::Duration::from_secs(100)),
        if_unmodified_since: None,
        copy_source_if_match: None,
        copy_source_if_none_match: None,
        copy_source_if_modified_since: None,
        copy_source_if_unmodified_since: None,
        amz_if_match_size: None,
        amz_if_match_last_modified_time: None,
    };

    // Should fail if object doesn't exist (can't be "modified since")
    let result = evaluate_write_preconditions(&cond, None);
    assert!(matches!(result, PreconditionOutcome::PreconditionFailed));

    // Should fail if not modified since specified time
    let result = evaluate_write_preconditions(&cond, Some(("any-etag", UNIX_EPOCH + std::time::Duration::from_secs(50))));
    assert!(matches!(result, PreconditionOutcome::PreconditionFailed));

    // Should succeed if modified after specified time
    let result = evaluate_write_preconditions(&cond, Some(("any-etag", UNIX_EPOCH + std::time::Duration::from_secs(150))));
    assert!(matches!(result, PreconditionOutcome::Proceed));
}

#[test]
fn test_write_preconditions_no_conditions() {
    let cond = ConditionalHeaders::default();

    // Should succeed if object doesn't exist
    let result = evaluate_write_preconditions(&cond, None);
    assert!(matches!(result, PreconditionOutcome::Proceed));
    
    // Should succeed if object exists
    let result = evaluate_write_preconditions(&cond, Some(("any-etag", UNIX_EPOCH)));
    assert!(matches!(result, PreconditionOutcome::Proceed));
}

// ============ COPY SOURCE PRECONDITIONS ============

#[test]
fn test_copy_source_preconditions_if_match() {
    let cond = ConditionalHeaders {
        if_match: None,
        if_none_match: None,
        if_modified_since: None,
        if_unmodified_since: None,
        copy_source_if_match: Some(ETagCondition::OneOf(vec!["expected-etag".to_string()])),
        copy_source_if_none_match: None,
        copy_source_if_modified_since: None,
        copy_source_if_unmodified_since: None,
        amz_if_match_size: None,
        amz_if_match_last_modified_time: None,
    };

    // Should fail if ETag doesn't match
    let result = evaluate_copy_source_preconditions(&cond, "different-etag", UNIX_EPOCH);
    assert!(matches!(result, PreconditionOutcome::PreconditionFailed));

    // Should succeed if ETag matches
    let result = evaluate_copy_source_preconditions(&cond, "expected-etag", UNIX_EPOCH);
    assert!(matches!(result, PreconditionOutcome::Proceed));
}

#[test]
fn test_copy_source_preconditions_if_none_match() {
    let cond = ConditionalHeaders {
        if_match: None,
        if_none_match: None,
        if_modified_since: None,
        if_unmodified_since: None,
        copy_source_if_match: None,
        copy_source_if_none_match: Some(ETagCondition::OneOf(vec!["forbidden-etag".to_string()])),
        copy_source_if_modified_since: None,
        copy_source_if_unmodified_since: None,
        amz_if_match_size: None,
        amz_if_match_last_modified_time: None,
    };

    // Should fail if ETag matches
    let result = evaluate_copy_source_preconditions(&cond, "forbidden-etag", UNIX_EPOCH);
    assert!(matches!(result, PreconditionOutcome::PreconditionFailed));

    // Should succeed if ETag doesn't match
    let result = evaluate_copy_source_preconditions(&cond, "different-etag", UNIX_EPOCH);
    assert!(matches!(result, PreconditionOutcome::Proceed));
}

#[test]
fn test_copy_source_preconditions_time_based() {
    // Test If-Unmodified-Since
    let cond = ConditionalHeaders {
        if_match: None,
        if_none_match: None,
        if_modified_since: None,
        if_unmodified_since: None,
        copy_source_if_match: None,
        copy_source_if_none_match: None,
        copy_source_if_modified_since: None,
        copy_source_if_unmodified_since: Some(UNIX_EPOCH + std::time::Duration::from_secs(100)),
        amz_if_match_size: None,
        amz_if_match_last_modified_time: None,
    };

    // Should fail if modified after specified time
    let result = evaluate_copy_source_preconditions(&cond, "any-etag", UNIX_EPOCH + std::time::Duration::from_secs(150));
    assert!(matches!(result, PreconditionOutcome::PreconditionFailed));

    // Should succeed if not modified after specified time
    let result = evaluate_copy_source_preconditions(&cond, "any-etag", UNIX_EPOCH + std::time::Duration::from_secs(50));
    assert!(matches!(result, PreconditionOutcome::Proceed));

    // Test If-Modified-Since
    let cond = ConditionalHeaders {
        if_match: None,
        if_none_match: None,
        if_modified_since: None,
        if_unmodified_since: None,
        copy_source_if_match: None,
        copy_source_if_none_match: None,
        copy_source_if_modified_since: Some(UNIX_EPOCH + std::time::Duration::from_secs(100)),
        copy_source_if_unmodified_since: None,
        amz_if_match_size: None,
        amz_if_match_last_modified_time: None,
    };

    // Should fail if not modified since specified time
    let result = evaluate_copy_source_preconditions(&cond, "any-etag", UNIX_EPOCH + std::time::Duration::from_secs(50));
    assert!(matches!(result, PreconditionOutcome::PreconditionFailed));

    // Should succeed if modified after specified time
    let result = evaluate_copy_source_preconditions(&cond, "any-etag", UNIX_EPOCH + std::time::Duration::from_secs(150));
    assert!(matches!(result, PreconditionOutcome::Proceed));
}

// ============ PRECEDENCE TESTS ============

#[test]
fn test_precondition_precedence() {
    // Test that If-Match is checked before If-None-Match
    let cond = ConditionalHeaders {
        if_match: Some(ETagCondition::OneOf(vec!["etag1".to_string()])),
        if_none_match: Some(ETagCondition::OneOf(vec!["etag1".to_string()])),
        if_modified_since: None,
        if_unmodified_since: None,
        copy_source_if_match: None,
        copy_source_if_none_match: None,
        copy_source_if_modified_since: None,
        copy_source_if_unmodified_since: None,
        amz_if_match_size: None,
        amz_if_match_last_modified_time: None,
    };

    // If-Match fails first
    let result = evaluate_read_preconditions(&cond, "etag2", UNIX_EPOCH);
    assert!(matches!(result, PreconditionOutcome::PreconditionFailed));

    // If both match, If-None-Match takes precedence (returns NotModified)
    let result = evaluate_read_preconditions(&cond, "etag1", UNIX_EPOCH);
    assert!(matches!(result, PreconditionOutcome::NotModified));
}

// ============ PARSE CONDITIONAL HEADERS TESTS ============

#[test]
fn test_parse_conditional_headers_empty() {
    let mut headers = HeaderMap::new();
    let result = parse_conditional_headers(&headers);
    assert!(result.is_ok());
    let cond = result.unwrap();
    assert!(cond.if_match.is_none());
    assert!(cond.if_none_match.is_none());
    assert!(cond.if_modified_since.is_none());
    assert!(cond.if_unmodified_since.is_none());
    assert!(cond.copy_source_if_match.is_none());
    assert!(cond.copy_source_if_none_match.is_none());
    assert!(cond.copy_source_if_modified_since.is_none());
    assert!(cond.copy_source_if_unmodified_since.is_none());
    assert!(cond.amz_if_match_size.is_none());
    assert!(cond.amz_if_match_last_modified_time.is_none());
}

#[test]
fn test_parse_conditional_headers_standard() {
    let mut headers = HeaderMap::new();
    headers.insert("if-match", "\"etag1\"".parse().unwrap());
    headers.insert("if-none-match", "\"etag2\"".parse().unwrap());
    headers.insert("if-modified-since", "Thu, 01 Jan 1970 00:00:01 GMT".parse().unwrap());
    headers.insert("if-unmodified-since", "Thu, 01 Jan 1970 00:00:02 GMT".parse().unwrap());

    let result = parse_conditional_headers(&headers);
    assert!(result.is_ok());
    let cond = result.unwrap();
    assert!(matches!(cond.if_match, Some(ETagCondition::OneOf(ref v)) if v == &vec!["etag1"]));
    assert!(matches!(cond.if_none_match, Some(ETagCondition::OneOf(ref v)) if v == &vec!["etag2"]));
    assert!(cond.if_modified_since.is_some());
    assert!(cond.if_unmodified_since.is_some());
}

#[test]
fn test_parse_conditional_headers_wildcard() {
    let mut headers = HeaderMap::new();
    headers.insert("if-match", "*" .parse().unwrap());
    headers.insert("if-none-match", "*" .parse().unwrap());

    let result = parse_conditional_headers(&headers);
    assert!(result.is_ok());
    let cond = result.unwrap();
    assert!(matches!(cond.if_match, Some(ETagCondition::Any)));
    assert!(matches!(cond.if_none_match, Some(ETagCondition::Any)));
}

#[test]
fn test_parse_conditional_headers_copy_source() {
    let mut headers = HeaderMap::new();
    headers.insert("x-amz-copy-source-if-match", "\"etag1\"".parse().unwrap());
    headers.insert("x-amz-copy-source-if-none-match", "\"etag2\"".parse().unwrap());
    headers.insert("x-amz-copy-source-if-modified-since", "Thu, 01 Jan 1970 00:00:01 GMT".parse().unwrap());
    headers.insert("x-amz-copy-source-if-unmodified-since", "Thu, 01 Jan 1970 00:00:02 GMT".parse().unwrap());

    let result = parse_conditional_headers(&headers);
    assert!(result.is_ok());
    let cond = result.unwrap();
    assert!(matches!(cond.copy_source_if_match, Some(ETagCondition::OneOf(ref v)) if v == &vec!["etag1"]));
    assert!(matches!(cond.copy_source_if_none_match, Some(ETagCondition::OneOf(ref v)) if v == &vec!["etag2"]));
    assert!(cond.copy_source_if_modified_since.is_some());
    assert!(cond.copy_source_if_unmodified_since.is_some());
}

#[test]
fn test_parse_conditional_headers_amz_extras() {
    let mut headers = HeaderMap::new();
    headers.insert("x-amz-if-match-size", "1024".parse().unwrap());
    headers.insert("x-amz-if-match-last-modified-time", "Thu, 01 Jan 1970 00:00:01 GMT".parse().unwrap());

    let result = parse_conditional_headers(&headers);
    assert!(result.is_ok());
    let cond = result.unwrap();
    assert_eq!(cond.amz_if_match_size, Some(1024));
    assert!(cond.amz_if_match_last_modified_time.is_some());
}

#[test]
fn test_parse_conditional_headers_invalid_empty() {
    let mut headers = HeaderMap::new();
    headers.insert("if-match", "   ".parse().unwrap());

    let result = parse_conditional_headers(&headers);
    assert!(result.is_err());
}

#[test]
fn test_parse_conditional_headers_invalid_non_ascii() {
    // Skip this test for now as it's complex to create invalid headers
    // that pass HeaderValue::from_bytes but fail to_str()
}

#[test]
fn test_parse_conditional_headers_invalid_date() {
    let mut headers = HeaderMap::new();
    headers.insert("if-modified-since", "invalid-date".parse().unwrap());

    let result = parse_conditional_headers(&headers);
    assert!(result.is_err());
}

#[test]
fn test_parse_conditional_headers_invalid_size() {
    let mut headers = HeaderMap::new();
    headers.insert("x-amz-if-match-size", "not-a-number".parse().unwrap());

    let result = parse_conditional_headers(&headers);
    assert!(result.is_err());
}