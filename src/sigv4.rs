use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use aws_credential_types::Credentials;
use aws_sigv4::http_request::{
    sign, SignableBody, SignableRequest, SigningParams, SigningSettings,
};
use aws_sigv4::sign::v4;
use aws_smithy_runtime_api::client::identity::Identity;
use constant_time_eq::constant_time_eq;
use http::header::AUTHORIZATION;
use pingora::protocols::http::ServerSession;
use time::{
    macros::format_description,
    OffsetDateTime,
    PrimitiveDateTime,
};


/// Simple representation of a “user” from your account DB
#[derive(Clone, Debug)]
pub struct AwsUser {
    pub access_key: String,
    pub secret_key: String,
    // later: uid/gid, etc.
}

/// In-memory dummy DB: access_key -> AwsUser
fn demo_user_db() -> HashMap<String, AwsUser> {
    let mut m = HashMap::new();
    m.insert(
        "TESTACCESSKEY123".to_string(),
        AwsUser {
            access_key: "TESTACCESSKEY123".to_string(),
            secret_key: "TESTSECRETKEY456".to_string(),
        },
    );
    m
}

/// Parsed parts of the Authorization header
struct SigV4Auth {
    algorithm: String,      // e.g. "AWS4-HMAC-SHA256"
    access_key: String,     // from Credential=...
    scope_date: String,     // YYYYMMDD from Credential
    region: String,         // e.g. "us-east-1"
    service: String,        // e.g. "s3"
    signed_headers: String, // e.g. "host;x-amz-content-sha256;x-amz-date"
    signature: String,      // hex
}

/// Top-level function used from main.rs.
/// Takes the Pingora ServerSession, returns a "user id" (for now: access key)
pub fn validate_sigv4(sess: &ServerSession) -> Result<String> {
    let req = sess.req_header();

    // DEBUG: raw incoming request
    tracing::info!("=== Incoming request ===");
    tracing::info!("METHOD: {}", req.method);
    tracing::info!("URI:    {}", req.uri);
    for (name, value) in req.headers.iter() {
        tracing::info!("HDR {}: {:?}", name, value);
    }
    tracing::info!("========================");

    // 1. Authorization header
    let auth_header = req
        .headers
        .get(AUTHORIZATION)
        .ok_or_else(|| anyhow!("missing Authorization header"))?;
    let auth_str = auth_header.to_str().map_err(|_| anyhow!("bad auth header"))?;

    let auth = parse_authorization(auth_str)?;

    if auth.algorithm != "AWS4-HMAC-SHA256" {
        return Err(anyhow!("unsupported SigV4 algorithm: {}", auth.algorithm));
    }

    // 2. Look up user by access key
    let db = demo_user_db();
    let user = db
        .get(&auth.access_key)
        .ok_or_else(|| anyhow!("unknown access key"))?;

    if auth.service != "s3" {
        return Err(anyhow!("expected service 's3', got {}", auth.service));
    }

    // 3. Parse X-Amz-Date (full timestamp, e.g. 20250101T123456Z)
    let amz_date_header = req
        .headers
        .get("x-amz-date")
        .ok_or_else(|| anyhow!("missing X-Amz-Date header"))?;
    let amz_date_str = amz_date_header
        .to_str()
        .map_err(|_| anyhow!("bad X-Amz-Date"))?;

    let (_amz_dt, x_date, signing_time) = parse_amz_date(amz_date_str)?;

    // Sanity check: date part in Credential scope must match X-Amz-Date date
    let scope_date = &auth.scope_date;
    if &x_date != scope_date {
        return Err(anyhow!(
            "date mismatch between Credential scope ({scope_date}) and X-Amz-Date ({x_date})"
        ));
    }

    // 4. Build identity and signing params
    let credentials = Credentials::new(
        &user.access_key,
        &user.secret_key,
        None,
        None,
        "s3-proxy-static",
    );
    let identity: Identity = credentials.into();

    let signing_settings = SigningSettings::default();
    let signing_params: SigningParams = v4::SigningParams::builder()
        .identity(&identity)
        .region(&auth.region)
        .name(&auth.service) // "s3"
        .time(signing_time)
        .settings(signing_settings)
        .build()
        .map_err(|e| anyhow!("failed building signing params: {e}"))?
        .into();

    // 5. Build SignableRequest from Pingora's RequestHeader
    let method = req.method.to_string();

    let host = req
        .headers
        .get("Host")
        .ok_or_else(|| anyhow!("missing Host header"))?
        .to_str()
        .map_err(|_| anyhow!("bad Host header"))?;

    let path_and_query = req
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    // Assume HTTPS at the edge; if you terminate TLS elsewhere, adjust this
    let uri = format!("http://{}{}", host, path_and_query);

    // Build a map from lowercase header name -> value (string) for quick lookup
    let mut header_map: HashMap<String, String> = HashMap::new();
    for (name, value) in req.headers.iter() {
        let name_str = name.as_str().to_ascii_lowercase();
        if name_str == "authorization" {
            continue;
        }
        let value_str = value
            .to_str()
            .map_err(|_| anyhow!("non-UTF8 header value for {}", name_str))?
            .trim()
            .to_string();
        header_map.insert(name_str, value_str);
    }

    // Now select only the headers listed in SignedHeaders
    let mut header_storage: Vec<(String, String)> = Vec::new();
    for h in auth.signed_headers.split(';') {
        let h = h.trim().to_ascii_lowercase();
        if h.is_empty() {
            continue;
        }
        if let Some(v) = header_map.get(&h) {
            header_storage.push((h.clone(), v.clone()));
        } else {
            return Err(anyhow!("signed header '{}' missing in request", h));
        }
    }

    let header_iter = header_storage
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()));

    // DEBUG: what we are going to sign
    tracing::info!("=== Our signable request ===");
    tracing::info!("method: {}", method);
    tracing::info!("uri:    {}", uri);
    for (k, v) in &header_storage {
        tracing::info!("sign hdr {}: {}", k, v);
    }


    // 6. Payload: support UNSIGNED-PAYLOAD and precomputed hashes
    let payload_header = req
        .headers
        .get("x-amz-content-sha256")
        .ok_or_else(|| anyhow!("missing x-amz-content-sha256"))?;
    let payload_hash = payload_header
        .to_str()
        .map_err(|_| anyhow!("bad x-amz-content-sha256"))?;

    let body = if payload_hash == "UNSIGNED-PAYLOAD" {
        // Streaming / unsigned body
        SignableBody::UnsignedPayload
    } else {
        // Client already sent the SHA256 hash (hex). We don't need the bytes,
        // just tell aws-sigv4 to use this precomputed checksum.
        SignableBody::Precomputed(payload_hash.to_string())
    };

    let signable_request =
        SignableRequest::new(&method, uri.as_str(), header_iter, body).map_err(|e| {
            anyhow!(
                "failed to construct SignableRequest (method={}, uri={}): {e}",
                method,
                uri
            )
        })?;

    // 7. Compute signature and compare
    let (_instructions, signature) =
        sign(signable_request, &signing_params)
            .map_err(|e| anyhow!("sigv4 sign error: {e}"))?
            .into_parts();

    // `signature` is already a hex string (e.g. "89c0a20e...").
    let our_sig: String = signature;

    tracing::info!("Our signature:    {}", our_sig);
    tracing::info!("Client signature: {}", auth.signature);

    if !constant_time_eq(our_sig.as_bytes(), auth.signature.as_bytes()) {
        return Err(anyhow!("signature mismatch"));
    }

    Ok(user.access_key.clone())
}


fn parse_authorization(header: &str) -> Result<SigV4Auth> {
    // Example:
    // AWS4-HMAC-SHA256 Credential=AKIA.../20250306/us-east-1/s3/aws4_request,
    // SignedHeaders=host;x-amz-content-sha256;x-amz-date,
    // Signature=abcdef123...

    // Split only on the first space:
    let (algorithm, params) = header
        .split_once(' ')
        .ok_or_else(|| anyhow!("invalid Authorization header"))?;
    let algorithm = algorithm.trim().to_string();

    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;

    // params is the whole string after the algorithm:
    // "Credential=..., SignedHeaders=..., Signature=..."
    for kv in params.split(',') {
        let kv = kv.trim();
        if kv.is_empty() {
            continue;
        }

        // Split only once on '='
        let (key, value) = kv
            .split_once('=')
            .ok_or_else(|| anyhow!("bad auth param {kv}"))?;
        let key = key.trim();
        let value = value.trim();

        match key {
            "Credential" => credential = Some(value.to_string()),
            "SignedHeaders" => signed_headers = Some(value.to_string()),
            "Signature" => signature = Some(value.to_string()),
            _ => {}
        }
    }

    let credential = credential.ok_or_else(|| anyhow!("missing Credential"))?;
    let signed_headers = signed_headers.ok_or_else(|| anyhow!("missing SignedHeaders"))?;
    let signature = signature.ok_or_else(|| anyhow!("missing Signature"))?;

    // Credential format: <access_key>/<yyyymmdd>/<region>/<service>/aws4_request
    let mut cred_parts = credential.split('/');
    let access_key = cred_parts
        .next()
        .ok_or_else(|| anyhow!("bad Credential"))?
        .to_string();
    let scope_date = cred_parts
        .next()
        .ok_or_else(|| anyhow!("bad Credential date"))?
        .to_string();
    let region = cred_parts
        .next()
        .ok_or_else(|| anyhow!("bad Credential region"))?
        .to_string();
    let service = cred_parts
        .next()
        .ok_or_else(|| anyhow!("bad Credential service"))?
        .to_string();
    // ignore the final "aws4_request"

    Ok(SigV4Auth {
        algorithm,
        access_key,
        scope_date,
        region,
        service,
        signed_headers,
        signature,
    })
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

