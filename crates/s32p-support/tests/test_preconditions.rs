// Tests for S3 precondition evaluation functions

use s32p_support::classifier::ConditionalHeaders;
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
