use anyhow::{anyhow, Result};
use aws_credential_types::Credentials;
use aws_sigv4::http_request::{SignableBody, SignableRequest, SigningParams, SigningSettings};
use aws_sigv4::sign::v4;
use aws_smithy_runtime_api::client::identity::Identity;
use constant_time_eq::constant_time_eq;
use http::{HeaderMap, Uri};

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use time::{macros::format_description, OffsetDateTime, PrimitiveDateTime};

/// Shared S3 request classification (used by proxy and gateway).
pub mod classifier;

/// Shared S3 REST-XML body builders (pure XML, no framework specifics).
pub mod s3xml;

/// Shared “response building” layer producing status + content-type + bytes + headers.
/// Each binary (proxy/gateway) wraps this into its own response type (Pingora vs Hyper).
pub mod s3resp;

/// Linux filesystem helpers shared across crates.
pub mod fs_helpers;

#[derive(Debug, Clone)]
pub struct SigV4Auth {
    pub access_key: String,
    pub scope_date: String, // YYYYMMDD from Credential scope
    pub region: String,
    pub service: String,
    pub signed_headers: String, // "host;x-amz-content-sha256;x-amz-date"
    pub signature: String,      // hex
}

pub fn parse_authorization(headers: &HeaderMap) -> Result<SigV4Auth> {
    let auth = headers
        .get("authorization")
        .ok_or_else(|| anyhow!("missing Authorization"))?
        .to_str()
        .map_err(|_| anyhow!("bad Authorization"))?;

    // AWS4-HMAC-SHA256 Credential=... SignedHeaders=... Signature=...
    let (algo, rest) = auth
        .split_once(' ')
        .ok_or_else(|| anyhow!("bad Authorization format"))?;
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
    let scope_date = it
        .next()
        .ok_or_else(|| anyhow!("bad Credential date"))?
        .to_string();
    let region = it
        .next()
        .ok_or_else(|| anyhow!("bad Credential region"))?
        .to_string();
    let service = it
        .next()
        .ok_or_else(|| anyhow!("bad Credential service"))?
        .to_string();

    Ok(SigV4Auth {
        access_key,
        scope_date,
        region,
        service,
        signed_headers,
        signature,
    })
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
    let end = after
        .find(|c: char| c == ',' || c.is_whitespace())
        .unwrap_or(after.len());
    let cred_val = &after[..end];

    // Access key is the first segment before '/'
    let access_key = cred_val
        .split('/')
        .next()
        .ok_or_else(|| anyhow!("bad Credential value"))?;

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
    public_scheme: &str, // "http" or "https"
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
        return Err(anyhow!(
            "date mismatch: scope={} x-amz-date={}",
            auth.scope_date,
            date_str
        ));
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

    // 3) Build URI for signing
    let host = headers
        .get("host")
        .ok_or_else(|| anyhow!("missing Host"))?
        .to_str()
        .map_err(|_| anyhow!("bad Host"))?;

    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let uri = format!("{public_scheme}://{host}{path_and_query}");

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

    let header_iter = header_storage.iter().map(|(k, v)| (k.as_str(), v.as_str()));

    // 6) Build signable request
    let signable = SignableRequest::new(method, &uri, header_iter, body)
        .map_err(|e| anyhow!("signable request error: {e}"))?;

    // 7) Build signing params
    let credentials = Credentials::new(
        auth.access_key.clone(),
        secret_key.to_string(),
        None,
        None,
        "static",
    );
    let identity: Identity = credentials.into();

    let signing_settings = SigningSettings::default();
    let signing_params: SigningParams = v4::SigningParams::builder()
        .identity(&identity)
        .region(&auth.region)
        .name(&auth.service)
        .time(signing_time)
        .settings(signing_settings)
        .build()
        .map_err(|e| anyhow!("failed building signing params: {e}"))?
        .into();

    // 8) Compute signature and compare with client signature
    let (_instructions, our_sig) = aws_sigv4::http_request::sign(signable, &signing_params)
        .map_err(|e| anyhow!("sigv4 sign error: {e}"))?
        .into_parts();

    if !constant_time_eq(our_sig.as_bytes(), auth.signature.as_bytes()) {
        return Err(anyhow!("signature mismatch"));
    }

    Ok(())
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

