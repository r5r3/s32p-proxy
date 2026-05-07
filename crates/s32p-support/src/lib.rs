use std::{
    collections::HashMap,
    fmt::Write as _,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, anyhow};
use aws_credential_types::Credentials;
use aws_sigv4::{
    http_request::{
        PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SigningParams,
        SigningSettings, UriPathNormalizationMode,
    },
    sign::v4,
};
use aws_smithy_runtime_api::client::identity::Identity;
use constant_time_eq::constant_time_eq;
use http::{HeaderMap, Uri};
use time::{OffsetDateTime, PrimitiveDateTime, macros::format_description};
use url::form_urlencoded;

/// Shared S3 request classification (used by proxy and gateway).
pub mod classifier;

/// Shared S3 REST-XML body builders (pure XML, no framework specifics).
pub mod s3xml;

/// Shared “response building” layer producing status + content-type + bytes + headers.
/// Each binary (proxy/gateway) wraps this into its own response type (Pingora vs Hyper).
pub mod s3resp;

// Shared URI and percent-decoding helpers.
pub mod uri_encoding;

// Utility functions for string manipulation
pub mod utils;

/// Precondition evaluation functions for S3 operations
pub mod preconditions;

#[derive(Debug, Clone)]
pub struct SigV4Auth {
    pub access_key:     String,
    pub scope_date:     String, // YYYYMMDD from Credential scope
    pub region:         String,
    pub service:        String,
    pub signed_headers: String, // "host;x-amz-content-sha256;x-amz-date"
    pub signature:      String, // hex
}

#[derive(Debug, Clone)]
pub struct PresignedSigV4Auth {
    pub access_key:     String,
    pub scope_date:     String, // YYYYMMDD from Credential scope
    pub region:         String,
    pub service:        String,
    pub signed_headers: String, // "host;..."
    pub signature:      String, // hex
    pub amz_date:       String, // original X-Amz-Date (for error messages)
    pub expires:        u64,    // seconds
    pub security_token: Option<String>,
}

/// Verify either:
/// - standard SigV4 header Authorization, or
/// - SigV4 presigned URL (query params)
///
/// `expected_access_key`:
/// - If `Some`, the signer access key must match it.
/// - If `None`, no access-key match is enforced (useful if caller already selected credentials by key).
pub fn verify_sigv4_request_any(
    method: &str,
    uri: &Uri,
    headers: &HeaderMap,
    expected_access_key: Option<&str>,
    secret_key: &str,
    resource: Option<&str>,
) -> std::result::Result<(), SigV4Rejection> {
    // Header-style SigV4
    if headers.get("authorization").is_some() {
        let auth = match parse_authorization(headers) {
            Ok(a) => a,
            Err(e) => {
                let reason = format!("bad Authorization: {e}");
                return Err(SigV4Rejection {
                    response: crate::s3resp::access_denied(&reason, resource),
                    reason,
                });
            }
        };

        if let Some(exp) = expected_access_key {
            if auth.access_key != exp {
                let reason = "unknown access key".to_string();
                return Err(SigV4Rejection {
                    response: crate::s3resp::access_denied(&reason, resource),
                    reason,
                });
            }
        }

        if let Err(e) = verify_sigv4_header_only(method, uri, headers, &auth, secret_key) {
            let reason = e.to_string();
            return Err(SigV4Rejection {
                response: crate::s3resp::signature_does_not_match(&reason, resource),
                reason,
            });
        }

        return Ok(());
    }

    // Presigned URL SigV4 (query signature)
    let auth = match parse_presigned_query(uri) {
        Ok(Some(a)) => a,
        Ok(None) => {
            let reason = "missing Authorization and missing presign params".to_string();
            return Err(SigV4Rejection {
                response: crate::s3resp::access_denied(&reason, resource),
                reason,
            });
        }
        Err(e) => {
            let reason = format!("bad presign params: {e}");
            return Err(SigV4Rejection {
                response: crate::s3resp::access_denied(&reason, resource),
                reason,
            });
        }
    };

    if let Some(exp) = expected_access_key {
        if auth.access_key != exp {
            let reason = "unknown access key".to_string();
            return Err(SigV4Rejection {
                response: crate::s3resp::access_denied(&reason, resource),
                reason,
            });
        }
    }

    if let Err(e) = verify_sigv4_presigned_url(method, uri, headers, &auth, secret_key) {
        let reason = e.to_string();
        return Err(SigV4Rejection {
            response: crate::s3resp::signature_does_not_match(&reason, resource),
            reason,
        });
    }

    Ok(())
}

/// Why a SigV4 verification was rejected, paired with the S3-XML response to send back.
/// `reason` is the underlying error message (suitable for logging); `response` is what the
/// caller should write to the wire.
pub struct SigV4Rejection {
    pub response: crate::s3resp::HttpResponse,
    pub reason:   String,
}

/// Parse SigV4 presign params from the URI query string.
/// Returns `Ok(None)` if the request is not using presigned URLs.
pub fn parse_presigned_query(uri: &Uri) -> Result<Option<PresignedSigV4Auth>> {
    let q = match uri.query() {
        Some(q) if !q.is_empty() => q,
        _ => return Ok(None),
    };

    let mut algo: Option<String> = None;
    let mut credential: Option<String> = None;
    let mut amz_date: Option<String> = None;
    let mut expires: Option<u64> = None;
    let mut signed_headers: Option<String> = None;
    let mut signature: Option<String> = None;
    let mut security_token: Option<String> = None;

    for (k, v) in form_urlencoded::parse(q.as_bytes()) {
        let k_lc = k.trim().to_ascii_lowercase();
        match k_lc.as_str() {
            "x-amz-algorithm" => algo = Some(v.into_owned()),
            "x-amz-credential" => credential = Some(v.into_owned()),
            "x-amz-date" => amz_date = Some(v.into_owned()),
            "x-amz-expires" => {
                let s = v.trim();
                if !s.is_empty() {
                    expires = s.parse::<u64>().ok();
                }
            }
            "x-amz-signedheaders" => signed_headers = Some(v.into_owned()),
            "x-amz-signature" => signature = Some(v.into_owned()),
            "x-amz-security-token" => security_token = Some(v.into_owned()),
            _ => {}
        }
    }

    // Not a presigned URL if there's no algorithm marker.
    let algo = match algo {
        Some(a) => a,
        None => return Ok(None),
    };

    if algo.trim() != "AWS4-HMAC-SHA256" {
        return Err(anyhow!("unsupported presign algo: {algo}"));
    }

    let credential = credential.ok_or_else(|| anyhow!("missing X-Amz-Credential"))?;
    let amz_date = amz_date.ok_or_else(|| anyhow!("missing X-Amz-Date"))?;
    let expires = expires.ok_or_else(|| anyhow!("missing/invalid X-Amz-Expires"))?;
    let signed_headers = signed_headers.ok_or_else(|| anyhow!("missing X-Amz-SignedHeaders"))?;
    let signature = signature.ok_or_else(|| anyhow!("missing X-Amz-Signature"))?;

    // Credential = access_key/YYYYMMDD/region/service/aws4_request
    let mut it = credential.split('/');
    let access_key = it.next().ok_or_else(|| anyhow!("bad X-Amz-Credential"))?.to_string();
    let scope_date = it.next().ok_or_else(|| anyhow!("bad X-Amz-Credential date"))?.to_string();
    let region = it.next().ok_or_else(|| anyhow!("bad X-Amz-Credential region"))?.to_string();
    let service = it.next().ok_or_else(|| anyhow!("bad X-Amz-Credential service"))?.to_string();

    Ok(Some(PresignedSigV4Auth {
        access_key,
        scope_date,
        region,
        service,
        signed_headers,
        signature,
        amz_date,
        expires,
        security_token,
    }))
}

/// Extract access key from either Authorization header (standard SigV4)
/// or from presigned URL query (X-Amz-Credential).
pub fn extract_access_key_from_request(uri: &Uri, headers: &HeaderMap) -> Result<String> {
    if headers.get("authorization").is_some() {
        return extract_access_key(headers);
    }
    if let Some(p) = parse_presigned_query(uri)? {
        if p.access_key.is_empty() {
            return Err(anyhow!("empty access key in X-Amz-Credential"));
        }
        return Ok(p.access_key);
    }
    Err(anyhow!("missing Authorization and missing presign params"))
}

/// Verify SigV4 presigned URL (query signature), without reading the body.
pub fn verify_sigv4_presigned_url(
    method: &str,
    uri: &Uri,
    headers: &HeaderMap,
    auth: &PresignedSigV4Auth,
    secret_key: &str,
) -> Result<()> {
    // 1) Parse X-Amz-Date
    let (_dt, date_str, signing_time) = parse_amz_date(auth.amz_date.trim())?;

    // date in credential scope must match x-amz-date date
    if date_str != auth.scope_date {
        return Err(anyhow!("date mismatch: scope={} x-amz-date={}", auth.scope_date, date_str));
    }

    // 2) Basic expiry check (reject if already expired)
    let now = SystemTime::now();
    let exp_at = signing_time + Duration::from_secs(auth.expires);
    if now > exp_at {
        return Err(anyhow!("presigned URL expired"));
    }

    // 3) Build base URI with SigV4-presign params removed, but keep original encoding/order
    // (We remove x-amz-* params so the signer can regenerate them consistently.)
    let path = uri.path();

    let filtered_query = {
        let q = uri.query().unwrap_or("");
        if q.is_empty() {
            String::new()
        } else {
            let mut kept: Vec<&str> = Vec::new();
            for seg in q.split('&') {
                if seg.is_empty() {
                    continue;
                }
                let key_raw = seg.split_once('=').map(|(k, _)| k).unwrap_or(seg);

                // Decode only the key for comparison (without changing the original segment)
                let decoded_key = form_urlencoded::parse(format!("{key_raw}=").as_bytes())
                    .next()
                    .map(|(k, _)| k.into_owned())
                    .unwrap_or_else(|| key_raw.to_string());

                let key_lc = decoded_key.trim().to_ascii_lowercase();
                let is_sigv4 = matches!(
                    key_lc.as_str(),
                    "x-amz-algorithm"
                        | "x-amz-credential"
                        | "x-amz-date"
                        | "x-amz-expires"
                        | "x-amz-signedheaders"
                        | "x-amz-signature"
                        | "x-amz-security-token"
                );

                if !is_sigv4 {
                    kept.push(seg);
                }
            }
            kept.join("&")
        }
    };

    let unsigned_uri = if filtered_query.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{filtered_query}")
    };

    // 4) Build lowercased header map (same as header auth path)
    let mut header_map: HashMap<String, String> = HashMap::new();
    for (name, value) in headers.iter() {
        let n = name.as_str().to_ascii_lowercase();
        let v = value
            .to_str()
            .map_err(|_| anyhow!("non-utf8 header value for {n}"))?
            .trim()
            .to_string();
        header_map.insert(n, v);
    }

    // 5) Select only headers listed in X-Amz-SignedHeaders
    let mut header_storage: Vec<(String, String)> = Vec::new();
    for h in auth.signed_headers.split(';') {
        let h = h.trim().to_ascii_lowercase();
        if h.is_empty() {
            continue;
        }
        let v = header_map
            .get(&h)
            .ok_or_else(|| anyhow!("signed header '{h}' missing in request"))?;
        header_storage.push((h, v.clone()));
    }

    // 6) Presigned URLs are typically UNSIGNED-PAYLOAD
    let body = SignableBody::UnsignedPayload;

    // 7) Build signing params, forcing signature into query params
    let credentials = Credentials::new(
        auth.access_key.clone(),
        secret_key.to_string(),
        auth.security_token.clone(),
        None,
        "static",
    );
    let identity: Identity = credentials.into();

    let mut signing_settings = SigningSettings::default();
    signing_settings.percent_encoding_mode = PercentEncodingMode::Single;
    signing_settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
    signing_settings.expires_in = Some(Duration::from_secs(auth.expires));
    signing_settings.payload_checksum_kind = PayloadChecksumKind::NoHeader;
    signing_settings.signature_location = aws_sigv4::http_request::SignatureLocation::QueryParams;

    let signing_params: SigningParams = v4::SigningParams::builder()
        .identity(&identity)
        .region(&auth.region)
        .name(&auth.service)
        .time(signing_time)
        .settings(signing_settings)
        .build()
        .map_err(|e| anyhow!("failed building signing params: {e}"))?
        .into();

    // 8) Try the original headers first; on mismatch, retry with default-port toggles
    // on the `host` header (see verify_sigv4_header_only for rationale).
    let host_variants = host_header_variants(&header_storage);
    let mut tried: Vec<(String, String)> = Vec::new();

    for variant in &host_variants {
        let attempt = match variant {
            None => header_storage.clone(),
            Some(new_host) => {
                let mut hs = header_storage.clone();
                if let Some(slot) = hs.iter_mut().find(|(k, _)| k == "host") {
                    slot.1 = new_host.clone();
                }
                hs
            }
        };
        let attempted_host = attempt
            .iter()
            .find(|(k, _)| k == "host")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();

        let header_iter = attempt.iter().map(|(k, v)| (k.as_str(), v.as_str()));
        let signable = SignableRequest::new(method, &unsigned_uri, header_iter, body.clone())
            .map_err(|e| anyhow!("signable request error: {e}"))?;

        let our_sig = aws_sigv4::http_request::sign(signable, &signing_params)
            .map_err(|e| anyhow!("sigv4 sign error: {e}"))?
            .into_parts()
            .1;

        if constant_time_eq(our_sig.as_bytes(), auth.signature.as_bytes()) {
            return Ok(());
        }
        tried.push((attempted_host, our_sig.to_string()));
    }

    Err(anyhow!(
        "signature mismatch ({})",
        sigv4_mismatch_diagnostic(
            method,
            &unsigned_uri,
            &header_storage,
            &auth.signed_headers,
            &auth.signature,
            &tried,
        )
    ))
}

pub fn parse_authorization(headers: &HeaderMap) -> Result<SigV4Auth> {
    let auth = headers
        .get("authorization")
        .ok_or_else(|| anyhow!("missing Authorization"))?
        .to_str()
        .map_err(|_| anyhow!("bad Authorization"))?;

    // AWS4-HMAC-SHA256 Credential=... SignedHeaders=... Signature=...
    let (algo, rest) = auth.split_once(' ').ok_or_else(|| anyhow!("bad Authorization format"))?;
    if algo.trim() != "AWS4-HMAC-SHA256" {
        return Err(anyhow!("unsupported auth algo: {algo}"));
    }

    let mut credential = None::<String>;
    let mut signed_headers = None::<String>;
    let mut signature = None::<String>;

    for part in rest.split(',') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            match k.trim() {
                "Credential" => credential = Some(v.trim().to_string()),
                "SignedHeaders" => signed_headers = Some(v.trim().to_string()),
                "Signature" => signature = Some(v.trim().to_string()),
                _ => {}
            }
        }
    }

    let credential = credential.ok_or_else(|| anyhow!("missing Credential"))?;
    let signed_headers = signed_headers.ok_or_else(|| anyhow!("missing SignedHeaders"))?;
    let signature = signature.ok_or_else(|| anyhow!("missing Signature"))?;

    // Credential = access_key/YYYYMMDD/region/service/aws4_request
    let mut it = credential.split('/');
    let access_key = it.next().ok_or_else(|| anyhow!("bad Credential"))?.to_string();
    let scope_date = it.next().ok_or_else(|| anyhow!("bad Credential date"))?.to_string();
    let region = it.next().ok_or_else(|| anyhow!("bad Credential region"))?.to_string();
    let service = it.next().ok_or_else(|| anyhow!("bad Credential service"))?.to_string();

    Ok(SigV4Auth { access_key, scope_date, region, service, signed_headers, signature })
}

/// Cheap routing helper: extract only the access key from Authorization header.
/// (No SigV4 validation, no SignedHeaders parsing.)
pub fn extract_access_key(headers: &HeaderMap) -> Result<String> {
    let auth = headers
        .get("authorization")
        .ok_or_else(|| anyhow!("missing Authorization"))?
        .to_str()
        .map_err(|_| anyhow!("bad Authorization"))?;

    // Look for "Credential=.../YYYYMMDD/region/service/aws4_request"
    let cred_pos = auth
        .find("Credential=")
        .ok_or_else(|| anyhow!("missing Credential in Authorization"))?;
    let after = &auth[cred_pos + "Credential=".len()..];

    // Credential value ends at ',' or whitespace
    let end = after.find(|c: char| c == ',' || c.is_whitespace()).unwrap_or(after.len());
    let cred_val = &after[..end];

    // Access key is the first segment before '/'
    let access_key = cred_val.split('/').next().ok_or_else(|| anyhow!("bad Credential value"))?;

    if access_key.is_empty() {
        return Err(anyhow!("empty access key in Credential"));
    }

    Ok(access_key.to_string())
}

/// Verify SigV4 *without reading the body*, using client x-amz-content-sha256.
/// Use this ONLY to gate worker spawn (first request).
pub fn verify_sigv4_header_only(
    method: &str,
    uri: &Uri,
    headers: &HeaderMap,
    auth: &SigV4Auth,
    secret_key: &str,
) -> Result<()> {
    // 1) Parse X-Amz-Date into signing time (SystemTime) and YYYYMMDD
    let x_amz_date = headers
        .get("x-amz-date")
        .ok_or_else(|| anyhow!("missing x-amz-date"))?
        .to_str()
        .map_err(|_| anyhow!("bad x-amz-date"))?
        .trim();

    let (_dt, date_str, signing_time) = parse_amz_date(x_amz_date)?;

    // date in credential scope must match x-amz-date date
    if date_str != auth.scope_date {
        return Err(anyhow!("date mismatch: scope={} x-amz-date={}", auth.scope_date, date_str));
    }

    // 2) Determine payload hash mode from x-amz-content-sha256
    let payload_hash = headers
        .get("x-amz-content-sha256")
        .ok_or_else(|| anyhow!("missing x-amz-content-sha256"))?
        .to_str()
        .map_err(|_| anyhow!("bad x-amz-content-sha256"))?
        .trim()
        .to_string();

    // NOTE: Some clients may use streaming payload modes.
    // If you want to avoid spawning workers for those, reject here.
    // For now, we accept UNSIGNED-PAYLOAD and hex hashes.
    let body = if payload_hash == "UNSIGNED-PAYLOAD" {
        SignableBody::UnsignedPayload
    } else {
        SignableBody::Precomputed(payload_hash)
    };

    // 3) Build URI for signing, only path and query are used.
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    // 4) Build header map lowercased
    let mut header_map: HashMap<String, String> = HashMap::new();
    for (name, value) in headers.iter() {
        let n = name.as_str().to_ascii_lowercase();
        if n == "authorization" {
            continue;
        }
        let v = value
            .to_str()
            .map_err(|_| anyhow!("non-utf8 header value for {n}"))?
            .trim()
            .to_string();
        header_map.insert(n, v);
    }

    // 5) Select only headers listed in SignedHeaders
    let mut header_storage: Vec<(String, String)> = Vec::new();
    for h in auth.signed_headers.split(';') {
        let h = h.trim().to_ascii_lowercase();
        if h.is_empty() {
            continue;
        }
        let v = header_map
            .get(&h)
            .ok_or_else(|| anyhow!("signed header '{h}' missing in request"))?;
        header_storage.push((h, v.clone()));
    }

    // 6) Build signing params (shared across attempts)
    let credentials =
        Credentials::new(auth.access_key.clone(), secret_key.to_string(), None, None, "static");
    let identity: Identity = credentials.into();

    let mut signing_settings = SigningSettings::default();
    // S3 SigV4 quirks:
    // - do NOT normalize the URI path
    // - do NOT double-encode the URI path
    signing_settings.percent_encoding_mode = PercentEncodingMode::Single;
    signing_settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;

    let signing_params: SigningParams = v4::SigningParams::builder()
        .identity(&identity)
        .region(&auth.region)
        .name(&auth.service)
        .time(signing_time)
        .settings(signing_settings)
        .build()
        .map_err(|e| anyhow!("failed building signing params: {e}"))?
        .into();

    // 7) Try the original headers first; on mismatch, retry with a few host-header
    // variants. AWS SigV4 doesn't standardize whether the default port appears in
    // the canonical `host` value. Different clients disagree (Go's net/http strips
    // `:80`/`:443`; some Java/Cyberduck-derived clients keep it). Accept either.
    let host_variants = host_header_variants(&header_storage);
    let mut tried: Vec<(String, String)> = Vec::new(); // (host_value_used, our_sig)

    for variant in &host_variants {
        let attempt = match variant {
            None => header_storage.clone(),
            Some(new_host) => {
                let mut hs = header_storage.clone();
                if let Some(slot) = hs.iter_mut().find(|(k, _)| k == "host") {
                    slot.1 = new_host.clone();
                }
                hs
            }
        };
        let attempted_host = attempt
            .iter()
            .find(|(k, _)| k == "host")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();

        let header_iter = attempt.iter().map(|(k, v)| (k.as_str(), v.as_str()));
        let signable = SignableRequest::new(method, path_and_query, header_iter, body.clone())
            .map_err(|e| anyhow!("signable request error: {e}"))?;

        let our_sig = aws_sigv4::http_request::sign(signable, &signing_params)
            .map_err(|e| anyhow!("sigv4 sign error: {e}"))?
            .into_parts()
            .1;

        if constant_time_eq(our_sig.as_bytes(), auth.signature.as_bytes()) {
            return Ok(());
        }
        tried.push((attempted_host, our_sig.to_string()));
    }

    Err(anyhow!(
        "signature mismatch ({})",
        sigv4_mismatch_diagnostic(
            method,
            path_and_query,
            &header_storage,
            &auth.signed_headers,
            &auth.signature,
            &tried,
        )
    ))
}

/// Build a one-line diagnostic string describing inputs to SigV4 verification.
/// Emitted only on mismatch — keeps the happy path hot. Header values are quoted
/// with backslash escapes so trailing whitespace and embedded `;` survive logging.
fn sigv4_mismatch_diagnostic(
    method: &str,
    path_and_query: &str,
    headers: &[(String, String)],
    signed_headers: &str,
    client_signature: &str,
    tried: &[(String, String)],
) -> String {
    let mut out = String::new();
    let _ = write!(out, "method={method} path_and_query={path_and_query:?} signed_headers={signed_headers:?} headers=[");
    for (i, (k, v)) in headers.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "{k}={v:?}");
    }
    out.push_str("] client_sig=");
    // Show first 8 hex chars only — full signatures are sensitive enough to keep short.
    out.push_str(&truncate_sig(client_signature));
    out.push_str(" tried=[");
    for (i, (h, s)) in tried.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "host={h:?}->{}", truncate_sig(s));
    }
    out.push(']');
    out
}

fn truncate_sig(s: &str) -> String {
    let n = s.len().min(8);
    let mut out = String::with_capacity(n + 3);
    out.push_str(&s[..n]);
    if s.len() > n {
        out.push_str("...");
    }
    out
}

/// Produce the set of `host` header values to try when verifying SigV4.
/// Returns `None` for the original (unmodified) value, plus any port-toggled
/// alternatives. Order: original first, then variants.
fn host_header_variants(headers: &[(String, String)]) -> Vec<Option<String>> {
    let mut out = vec![None];

    let host_val = match headers.iter().find(|(k, _)| k == "host") {
        Some((_, v)) => v.as_str(),
        None => return out,
    };

    // Parse "name[:port]". IPv6 literals "[::1]:443" need bracket handling.
    let (name, port) = if let Some(rest) = host_val.strip_prefix('[') {
        match rest.split_once("]:") {
            Some((n, p)) => (format!("[{n}]"), Some(p.to_string())),
            None => (host_val.to_string(), None),
        }
    } else if let Some((n, p)) = host_val.rsplit_once(':') {
        // Avoid mistaking an IPv6 address with no brackets/no port for "name:port"
        if n.contains(':') {
            (host_val.to_string(), None)
        } else {
            (n.to_string(), Some(p.to_string()))
        }
    } else {
        (host_val.to_string(), None)
    };

    match port.as_deref() {
        Some("80") | Some("443") => {
            // Client kept default port; also try without it.
            out.push(Some(name));
        }
        Some(_) => {
            // Non-default port: signing must include it. No alternatives.
        }
        None => {
            // Client dropped the port; also try with default ports added.
            out.push(Some(format!("{name}:443")));
            out.push(Some(format!("{name}:80")));
        }
    }

    out
}

fn parse_amz_date(amz_date: &str) -> Result<(OffsetDateTime, String, SystemTime)> {
    // X-Amz-Date format:  YYYYMMDDTHHMMSSZ (UTC, literal 'Z')
    let fmt = format_description!("[year][month][day]T[hour][minute][second]Z");

    // 1) Parse into a PrimitiveDateTime (no offset info)
    let pdt =
        PrimitiveDateTime::parse(amz_date, &fmt).map_err(|e| anyhow!("bad X-Amz-Date: {e}"))?;

    // 2) Assume UTC (Z) to get an OffsetDateTime
    let dt: OffsetDateTime = pdt.assume_utc();

    // 3) Extract the date part as YYYYMMDD for the scope check
    let date_str = dt.format(&format_description!("[year][month][day]"))?;

    // 4) Convert to SystemTime for aws-sigv4
    let signing_time = offset_to_system_time(dt);

    Ok((dt, date_str, signing_time))
}

fn offset_to_system_time(dt: OffsetDateTime) -> SystemTime {
    let ts = dt.unix_timestamp();
    if ts >= 0 {
        UNIX_EPOCH + Duration::from_secs(ts as u64)
    } else {
        UNIX_EPOCH - Duration::from_secs((-ts) as u64)
    }
}
