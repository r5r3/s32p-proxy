use anyhow::{anyhow, Result};
use http::HeaderMap;
use std::time::SystemTime;

#[derive(Debug, Clone, Default)]
pub struct ConditionalHeaders {
    pub if_match: Option<crate::utils::ETagCondition>,
    pub if_none_match: Option<crate::utils::ETagCondition>,
    pub if_modified_since: Option<SystemTime>,
    pub if_unmodified_since: Option<SystemTime>,

    // CopyObject source preconditions
    pub copy_source_if_match: Option<crate::utils::ETagCondition>,
    pub copy_source_if_none_match: Option<crate::utils::ETagCondition>,
    pub copy_source_if_modified_since: Option<SystemTime>,
    pub copy_source_if_unmodified_since: Option<SystemTime>,

    // DeleteObject "directory bucket" extras (safe to parse even if you don't enforce everywhere)
    pub amz_if_match_size: Option<u64>,
    pub amz_if_match_last_modified_time: Option<SystemTime>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreconditionOutcome {
    Proceed,
    NotModified,         // for GET/HEAD
    PreconditionFailed,  // 412
}

/// Parse/validate conditional headers.
///
/// "useful" checks:
/// - Empty values are rejected
/// - ETag headers must contain "*" or at least one token
/// - Date headers must parse as HTTP-date
pub fn parse_conditional_headers(headers: &HeaderMap) -> Result<ConditionalHeaders> {
    fn header_to_str<'a>(headers: &'a HeaderMap, name: &http::header::HeaderName) -> Result<Option<&'a str>> {
        match headers.get(name) {
            None => Ok(None),
            Some(v) => {
                let s = v
                    .to_str()
                    .map_err(|_| anyhow!("header {} is not valid ASCII", name))?;
                let s = s.trim();
                if s.is_empty() {
                    return Err(anyhow!("empty header value for {}", name));
                }
                Ok(Some(s))
            }
        }
    }

    // Standard If-* headers
    let if_match = match header_to_str(headers, &http::header::IF_MATCH)? {
        Some(v) => Some(crate::utils::parse_etag_condition(v)?),
        None => None,
    };

    let if_none_match = match header_to_str(headers, &http::header::IF_NONE_MATCH)? {
        Some(v) => Some(crate::utils::parse_etag_condition(v)?),
        None => None,
    };

    let if_modified_since = match header_to_str(headers, &http::header::IF_MODIFIED_SINCE)? {
        Some(v) => Some(crate::utils::parse_http_date(v)?),
        None => None,
    };

    let if_unmodified_since = match header_to_str(headers, &http::header::IF_UNMODIFIED_SINCE)? {
        Some(v) => Some(crate::utils::parse_http_date(v)?),
        None => None,
    };

    // CopyObject source conditionals
    let h_copy_if_match: http::header::HeaderName = http::header::HeaderName::from_static("x-amz-copy-source-if-match");
    let h_copy_if_none_match: http::header::HeaderName = http::header::HeaderName::from_static("x-amz-copy-source-if-none-match");
    let h_copy_if_modified_since: http::header::HeaderName =
        http::header::HeaderName::from_static("x-amz-copy-source-if-modified-since");
    let h_copy_if_unmodified_since: http::header::HeaderName =
        http::header::HeaderName::from_static("x-amz-copy-source-if-unmodified-since");

    let copy_source_if_match = match header_to_str(headers, &h_copy_if_match)? {
        Some(v) => Some(crate::utils::parse_etag_condition(v)?),
        None => None,
    };

    let copy_source_if_none_match = match header_to_str(headers, &h_copy_if_none_match)? {
        Some(v) => Some(crate::utils::parse_etag_condition(v)?),
        None => None,
    };

    let copy_source_if_modified_since = match header_to_str(headers, &h_copy_if_modified_since)? {
        Some(v) => Some(crate::utils::parse_http_date(v)?),
        None => None,
    };

    let copy_source_if_unmodified_since = match header_to_str(headers, &h_copy_if_unmodified_since)? {
        Some(v) => Some(crate::utils::parse_http_date(v)?),
        None => None,
    };

    // DeleteObject extras
    let h_if_match_size: http::header::HeaderName = http::header::HeaderName::from_static("x-amz-if-match-size");
    let h_if_match_lmt: http::header::HeaderName = http::header::HeaderName::from_static("x-amz-if-match-last-modified-time");

    let amz_if_match_size = match header_to_str(headers, &h_if_match_size)? {
        Some(v) => Some(crate::utils::parse_u64_strict(v, "x-amz-if-match-size")?),
        None => None,
    };

    // We treat this as HTTP-date for consistency & usefulness.
    let amz_if_match_last_modified_time = match header_to_str(headers, &h_if_match_lmt)? {
        Some(v) => Some(crate::utils::parse_http_date(v)?),
        None => None,
    };

    Ok(ConditionalHeaders {
        if_match,
        if_none_match,
        if_modified_since,
        if_unmodified_since,
        copy_source_if_match,
        copy_source_if_none_match,
        copy_source_if_modified_since,
        copy_source_if_unmodified_since,
        amz_if_match_size,
        amz_if_match_last_modified_time,
    })
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