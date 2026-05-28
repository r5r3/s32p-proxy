use http_body_util::BodyExt;
use pingora::{
    http::{ResponseHeader, StatusCode},
    proxy::Session,
};
// Re-export shared error codes + shared bucket info type to keep call-sites unchanged.
pub use s32p_support::s3xml::error_code;
use s32p_support::{
    classifier::{ObjectLockOp, S3Op, VersioningOp},
    s3resp, s3xml,
};

/* -------------------------
 * Hyper -> Pingora adapter
 * ------------------------- */

/// Convert a Hyper-ready `http::Response` into a Pingora downstream response.
///
/// This is intended for **small/complete** responses (our shared s3resp builders always use full bodies).
/// If you later want true streaming to downstream (large bodies), implement a streaming adapter instead.
pub async fn respond_hyper(
    session: &mut Session,
    resp: s32p_support::s3resp::HttpResponse,
    close: bool,
) -> pingora::Result<()> {
    if close {
        session.set_keepalive(None);
        session.set_close_on_response_before_downstream_finish(true);
    }

    let (parts, body) = resp.into_parts();

    // BoxBody has Error=Infallible, so this can't fail, but keep it explicit.
    let collected = body.collect().await.unwrap_or_default();
    let bytes = collected.to_bytes();

    // Build Pingora response header.
    let mut rh = ResponseHeader::build(parts.status, Some(parts.headers.len() + 4))?;

    // Copy headers (best effort for non-utf8 values).
    for (k, v) in parts.headers.iter() {
        if let Ok(vs) = v.to_str() {
            // IMPORTANT: clone the header name to avoid borrowing from parts.headers
            rh.insert_header(k.clone(), vs)?;
        }
    }

    // Ensure Content-Length matches what we actually write.
    rh.insert_header("Content-Length", bytes.len().to_string().as_str())?;

    session.write_response_header(Box::new(rh), false).await?;
    session.write_response_body(Some(bytes), true).await?;
    session.finish_body().await?;
    Ok(())
}

/* -------------------------
 * Higher-level helpers (used by proxy main)
 * ------------------------- */

/// Write a complete S3 REST-XML error (and short-circuit).
pub async fn respond_s3_error(
    session: &mut Session,
    status: StatusCode,
    code: &str,
    message: &str,
    resource: Option<&str>,
    request_id: Option<&str>,
) -> pingora::Result<()> {
    let resp = s3resp::s3_error(status, code, message, resource, request_id);
    respond_hyper(session, resp, /* close = */ true).await
}

/// Convenience: NotImplemented (501).
pub async fn respond_not_implemented(
    session: &mut Session,
    message: &str,
    resource: Option<&str>,
    _request_id: Option<&str>,
) -> pingora::Result<()> {
    let resp = s3resp::not_implemented(message, resource);
    respond_hyper(session, resp, /* close = */ true).await
}

/// Convenience: SlowDown (429) with `Retry-After`. Closes the connection
/// (`close = true`) so a throttled client doesn't keep an FD pinned in
/// keep-alive after being told to back off.
pub async fn respond_slow_down(
    session: &mut Session,
    message: &str,
    resource: Option<&str>,
    retry_after_secs: u64,
) -> pingora::Result<()> {
    let resp = s3resp::slow_down(message, resource, retry_after_secs);
    respond_hyper(session, resp, /* close = */ true).await
}

/* -------------------------
 * aws_compat dispatch
 * ------------------------- */

/// Per-op AWS-compat response. Returns the response AWS would emit for
/// the same op on a bucket where the underlying feature isn't enabled
/// (`GetBucketVersioning` on an unversioned bucket → 200 with empty
/// config; `GetBucketObjectLockConfiguration` on a non-Object-Lock
/// bucket → 404 `ObjectLockConfigurationNotFoundError`; etc.). Ops in
/// the routed class without an AWS feature-disabled equivalent fall
/// back to 501 NotImplemented with a generic message.
///
/// Pure function: split from the async sender so it can be unit-tested
/// without a Pingora `Session`.
pub fn aws_compat_response(op: &S3Op, resource: Option<&str>) -> s3resp::HttpResponse {
    match op {
        // GetBucketVersioning on an unversioned bucket: AWS returns
        // 200 with `<VersioningConfiguration xmlns="…"/>` (no <Status>).
        S3Op::Versioning(VersioningOp::GetBucketVersioning) => s3resp::versioning_not_configured(),

        // GetBucketObjectLockConfiguration on a bucket that wasn't
        // created with Object Lock enabled.
        S3Op::ObjectLock(ObjectLockOp::GetBucketObjectLockConfiguration) => s3resp::s3_error(
            StatusCode::NOT_FOUND,
            s3xml::error_code::OBJECT_LOCK_CONFIGURATION_NOT_FOUND_ERROR,
            "Object Lock configuration does not exist for this bucket",
            resource,
            None,
        ),

        // GetObjectRetention / GetObjectLegalHold on an object whose
        // bucket has no Object Lock — AWS uses NoSuchObjectLockConfiguration.
        S3Op::ObjectLock(ObjectLockOp::GetObjectRetention | ObjectLockOp::GetObjectLegalHold) => {
            s3resp::s3_error(
                StatusCode::NOT_FOUND,
                s3xml::error_code::NO_SUCH_OBJECT_LOCK_CONFIGURATION,
                "The specified object does not have an ObjectLock configuration",
                resource,
                None,
            )
        }

        // Put-Retention / Put-LegalHold on a non-Object-Lock bucket:
        // AWS returns 400 InvalidRequest with this exact message string
        // (clients sometimes match on it).
        S3Op::ObjectLock(ObjectLockOp::PutObjectRetention | ObjectLockOp::PutObjectLegalHold) => {
            s3resp::invalid_request("Bucket is missing Object Lock Configuration", resource)
        }

        // HeadService: `HEAD /` is not a documented S3 op (only `GET /` for
        // ListBuckets is). AWS returns 405 Method Not Allowed; clients like
        // Cyberduck / MountainDuck issue HEAD / as a connectivity probe and
        // treat 405 as "server is alive, can't HEAD that resource" — they
        // proceed with real S3 work afterwards. The `Allow: GET` header
        // points polite clients at the right verb.
        S3Op::HeadService => s3resp::method_not_allowed(
            "The specified method is not allowed against this resource.",
            resource,
            "GET",
        ),

        // Anything else within an aws_compat-routed class — AWS either
        // doesn't have a feature-disabled response (it implements the
        // op unconditionally, e.g. PutBucketVersioning) or the wire
        // shape is too complex to synthesize here (ListObjectVersions).
        // Falling back to 501 is honest and forward-compatible.
        _ => s3resp::not_implemented("operation is not implemented by this proxy", resource),
    }
}

/// Send the AWS-compat response for `op`. Thin async wrapper around
/// `aws_compat_response` + `respond_hyper`. Used by the `aws_compat`
/// dispatch arm in `main.rs`.
pub async fn respond_aws_compat(
    session: &mut Session,
    op: &S3Op,
    resource: Option<&str>,
) -> pingora::Result<()> {
    respond_hyper(session, aws_compat_response(op, resource), /* close = */ true).await
}

#[cfg(test)]
mod tests {
    use s32p_support::classifier::BucketAdminOp;

    use super::*;

    /// Drain the HttpResponse body for inspection. Returns (status, body bytes).
    /// Async because BodyExt::collect is — but BoxBody<_, Infallible> never
    /// pends, so the call returns immediately under any executor.
    async fn body_bytes(resp: s3resp::HttpResponse) -> (StatusCode, Vec<u8>) {
        let (parts, body) = resp.into_parts();
        let collected = body.collect().await.unwrap_or_default();
        (parts.status, collected.to_bytes().to_vec())
    }

    fn assert_xml_contains(body: &[u8], needle: &str) {
        let s = String::from_utf8_lossy(body);
        assert!(s.contains(needle), "body did not contain {:?}: {}", needle, s);
    }

    #[tokio::test]
    async fn get_bucket_versioning_returns_200_empty_config() {
        let op = S3Op::Versioning(VersioningOp::GetBucketVersioning);
        let (status, body) = body_bytes(aws_compat_response(&op, None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_xml_contains(&body, "<VersioningConfiguration");
        assert_xml_contains(&body, "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"");
        // No <Status> child — that's how AWS signals "Unversioned".
        let s = String::from_utf8_lossy(&body);
        assert!(!s.contains("<Status>"), "unexpected <Status> in empty config: {s}");
    }

    #[tokio::test]
    async fn get_bucket_object_lock_config_returns_404_feature_not_found() {
        let op = S3Op::ObjectLock(ObjectLockOp::GetBucketObjectLockConfiguration);
        let (status, body) = body_bytes(aws_compat_response(&op, Some("/bkt"))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_xml_contains(&body, "<Code>ObjectLockConfigurationNotFoundError</Code>");
    }

    #[tokio::test]
    async fn get_object_retention_returns_404_no_such_object_lock_config() {
        let op = S3Op::ObjectLock(ObjectLockOp::GetObjectRetention);
        let (status, body) = body_bytes(aws_compat_response(&op, Some("/bkt/key"))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_xml_contains(&body, "<Code>NoSuchObjectLockConfiguration</Code>");
    }

    #[tokio::test]
    async fn get_object_legal_hold_returns_404_no_such_object_lock_config() {
        let op = S3Op::ObjectLock(ObjectLockOp::GetObjectLegalHold);
        let (status, body) = body_bytes(aws_compat_response(&op, Some("/bkt/key"))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_xml_contains(&body, "<Code>NoSuchObjectLockConfiguration</Code>");
    }

    #[tokio::test]
    async fn put_object_retention_returns_400_invalid_request() {
        let op = S3Op::ObjectLock(ObjectLockOp::PutObjectRetention);
        let (status, body) = body_bytes(aws_compat_response(&op, Some("/bkt/key"))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_xml_contains(&body, "<Code>InvalidRequest</Code>");
        assert_xml_contains(&body, "Bucket is missing Object Lock Configuration");
    }

    #[tokio::test]
    async fn put_object_legal_hold_returns_400_invalid_request() {
        let op = S3Op::ObjectLock(ObjectLockOp::PutObjectLegalHold);
        let (status, body) = body_bytes(aws_compat_response(&op, Some("/bkt/key"))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_xml_contains(&body, "<Code>InvalidRequest</Code>");
    }

    #[tokio::test]
    async fn put_bucket_versioning_falls_back_to_501() {
        // PutBucketVersioning has no AWS "feature disabled" response
        // (AWS always implements it). It must hit the fallback arm.
        let op = S3Op::Versioning(VersioningOp::PutBucketVersioning);
        let (status, body) = body_bytes(aws_compat_response(&op, None)).await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        assert_xml_contains(&body, "<Code>NotImplemented</Code>");
    }

    #[tokio::test]
    async fn bucket_admin_op_falls_back_to_501() {
        // If an operator routes `bucket_admin` to aws_compat (not the
        // recommended config — the default keeps it as not_implemented),
        // the dispatch must still terminate at 501 cleanly.
        let op = S3Op::BucketAdmin(BucketAdminOp::CreateBucket);
        let (status, _) = body_bytes(aws_compat_response(&op, None)).await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn head_service_returns_405_with_allow_get() {
        // `HEAD /` on AWS S3 returns 405; the proxy mirrors that under
        // the `aws_compat` action so clients like Cyberduck / MountainDuck
        // see the spec-accurate response without a SigV4 round-trip or
        // worker involvement.
        let resp = aws_compat_response(&S3Op::HeadService, None);
        let allow = resp.headers().get("Allow").map(|v| v.to_str().unwrap().to_string());
        let (status, body) = body_bytes(resp).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(allow.as_deref(), Some("GET"));
        assert_xml_contains(&body, "<Code>MethodNotAllowed</Code>");
    }
}
