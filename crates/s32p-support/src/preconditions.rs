use crate::classifier::ConditionalHeaders;
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreconditionOutcome {
    Proceed,
    NotModified,         // for GET/HEAD
    PreconditionFailed,  // 412
}

/// Evaluate preconditions for read operations (GET/HEAD)
#[allow(dead_code)]
pub fn evaluate_read_preconditions(
    cond: &ConditionalHeaders,
    current_etag_unquoted: &str,
    last_modified: SystemTime,
) -> PreconditionOutcome {
    // Order loosely follows RFC 7232 precedence: If-Match, If-Unmodified-Since, If-None-Match, If-Modified-Since.

    if let Some(ifm) = &cond.if_match {
        if !ifm.matches(current_etag_unquoted) {
            return PreconditionOutcome::PreconditionFailed;
        }
    }

    if let Some(ius) = cond.if_unmodified_since {
        // If resource has been modified after ius => fail
        if last_modified > ius {
            return PreconditionOutcome::PreconditionFailed;
        }
    }

    if let Some(inm) = &cond.if_none_match {
        if inm.matches(current_etag_unquoted) {
            return PreconditionOutcome::NotModified;
        }
    }

    if let Some(ims) = cond.if_modified_since {
        // If not modified since ims => not modified
        if last_modified <= ims {
            return PreconditionOutcome::NotModified;
        }
    }

    PreconditionOutcome::Proceed
}

/// Evaluate preconditions for write operations (PUT, COPY destination)
pub fn evaluate_write_preconditions(
    cond: &ConditionalHeaders,
    existing: Option<(&str, SystemTime)>, // (etag_unquoted, last_modified)
) -> PreconditionOutcome {
    // For writes: any "not modified" concept becomes either proceed or 412.
    // - If-Match: require existing and matching.
    // - If-None-Match: if matches => fail (commonly "*" to require non-existence).
    // - If-Unmodified-Since: if modified after => fail.
    // - If-Modified-Since: rarely used for writes; treat as fail if not modified.

    if let Some(ifm) = &cond.if_match {
        match existing {
            Some((etag, _lm)) if ifm.matches(etag) => {},
            _ => return PreconditionOutcome::PreconditionFailed,
        }
    }

    if let Some(inm) = &cond.if_none_match {
        match existing {
            Some((etag, _lm)) if inm.matches(etag) => return PreconditionOutcome::PreconditionFailed,
            Some((_etag, _lm)) => {} // does not match => ok
            None => {}              // no existing => ok
        }
    }

    if let Some(ius) = cond.if_unmodified_since {
        if let Some((_etag, lm)) = existing {
            if lm > ius {
                return PreconditionOutcome::PreconditionFailed;
            }
        }
    }

    if let Some(ims) = cond.if_modified_since {
        if let Some((_etag, lm)) = existing {
            if lm <= ims {
                return PreconditionOutcome::PreconditionFailed;
            }
        } else {
            // "not modified since" is not meaningful if it doesn't exist
            return PreconditionOutcome::PreconditionFailed;
        }
    }

    PreconditionOutcome::Proceed
}

/// Evaluate preconditions for CopyObject source
pub fn evaluate_copy_source_preconditions(
    cond: &ConditionalHeaders,
    current_etag_unquoted: &str,
    last_modified: SystemTime,
) -> PreconditionOutcome {
    if let Some(ifm) = &cond.copy_source_if_match {
        if !ifm.matches(current_etag_unquoted) {
            return PreconditionOutcome::PreconditionFailed;
        }
    }

    if let Some(ius) = cond.copy_source_if_unmodified_since {
        if last_modified > ius {
            return PreconditionOutcome::PreconditionFailed;
        }
    }

    if let Some(inm) = &cond.copy_source_if_none_match {
        if inm.matches(current_etag_unquoted) {
            return PreconditionOutcome::PreconditionFailed;
        }
    }

    if let Some(ims) = cond.copy_source_if_modified_since {
        if last_modified <= ims {
            return PreconditionOutcome::PreconditionFailed;
        }
    }

    PreconditionOutcome::Proceed
}