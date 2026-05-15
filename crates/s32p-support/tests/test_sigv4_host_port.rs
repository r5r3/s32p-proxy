// Verifies that SigV4 header-only verification accepts both forms of the `host`
// header w.r.t. the default port — i.e. a client that signs with `:443` is
// accepted by a server that received the request with the port stripped, and
// vice versa. This was triggered by Mountain Duck/Cyberduck-derived clients
// that keep `:443` in the canonical `host` value while mcli/Go strips it.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_credential_types::Credentials;
use aws_sigv4::{
    http_request::{
        PercentEncodingMode, SignableBody, SignableRequest, SigningParams, SigningSettings,
        UriPathNormalizationMode,
    },
    sign::v4,
};
use aws_smithy_runtime_api::client::identity::Identity;
use http::{HeaderMap, HeaderValue, Uri};
use s32p_support::{SigV4Auth, verify_sigv4_header_only};

const ACCESS_KEY: &str = "AKIATESTKEY";
const SECRET_KEY: &str = "topsecret";
const REGION: &str = "us-east-1";
const SERVICE: &str = "s3";
const FIXED_TIME_UNIX: u64 = 1_840_000_000; // 2028-04 — stable

fn fixed_time() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(FIXED_TIME_UNIX)
}

fn amz_date_str() -> String {
    use time::{OffsetDateTime, format_description::FormatItem, macros::format_description};
    const FMT: &[FormatItem<'_>] =
        format_description!("[year][month][day]T[hour][minute][second]Z");
    let dt = OffsetDateTime::from_unix_timestamp(FIXED_TIME_UNIX as i64).unwrap();
    dt.format(FMT).unwrap()
}

fn scope_date_str() -> String {
    use time::{OffsetDateTime, format_description::FormatItem, macros::format_description};
    const FMT: &[FormatItem<'_>] = format_description!("[year][month][day]");
    let dt = OffsetDateTime::from_unix_timestamp(FIXED_TIME_UNIX as i64).unwrap();
    dt.format(FMT).unwrap()
}

/// Sign a GET request with an arbitrary host value and return the resulting hex signature.
fn sign_with_host(host: &str, path_and_query: &str) -> String {
    let amz_date = amz_date_str();
    let payload = "UNSIGNED-PAYLOAD".to_string();

    let headers: Vec<(String, String)> = vec![
        ("host".to_string(), host.to_string()),
        ("x-amz-content-sha256".to_string(), payload.clone()),
        ("x-amz-date".to_string(), amz_date),
    ];
    let header_iter = headers.iter().map(|(k, v)| (k.as_str(), v.as_str()));

    let signable =
        SignableRequest::new("GET", path_and_query, header_iter, SignableBody::UnsignedPayload)
            .unwrap();

    let creds = Credentials::new(ACCESS_KEY, SECRET_KEY, None, None, "static");
    let identity: Identity = creds.into();

    let mut settings = SigningSettings::default();
    settings.percent_encoding_mode = PercentEncodingMode::Single;
    settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;

    let params: SigningParams = v4::SigningParams::builder()
        .identity(&identity)
        .region(REGION)
        .name(SERVICE)
        .time(fixed_time())
        .settings(settings)
        .build()
        .unwrap()
        .into();

    aws_sigv4::http_request::sign(signable, &params)
        .unwrap()
        .into_parts()
        .1
        .to_string()
}

fn build_auth(signature: String) -> SigV4Auth {
    SigV4Auth {
        access_key: ACCESS_KEY.to_string(),
        scope_date: scope_date_str(),
        region: REGION.to_string(),
        service: SERVICE.to_string(),
        signed_headers: "host;x-amz-content-sha256;x-amz-date".to_string(),
        signature,
    }
}

fn build_headers(host_received: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("host", HeaderValue::from_str(host_received).unwrap());
    h.insert("x-amz-content-sha256", HeaderValue::from_static("UNSIGNED-PAYLOAD"));
    h.insert("x-amz-date", HeaderValue::from_str(&amz_date_str()).unwrap());
    h
}

#[test]
fn client_signs_with_443_server_receives_without_port() {
    // Mountain Duck-style: signs `host: example.com:443`
    let sig = sign_with_host("example.com:443", "/");
    let auth = build_auth(sig);

    // But arrives at the server with the port stripped
    let headers = build_headers("example.com");
    let uri: Uri = "/".parse().unwrap();

    verify_sigv4_header_only("GET", &uri, &headers, &auth, SECRET_KEY, None)
        .expect("verification should accept :443-signed request received without :443");
}

#[test]
fn client_signs_without_port_server_receives_with_443() {
    // mcli/Go-style: signs `host: example.com`
    let sig = sign_with_host("example.com", "/");
    let auth = build_auth(sig);

    // But somehow arrives with `:443` (e.g. an intermediary added it)
    let headers = build_headers("example.com:443");
    let uri: Uri = "/".parse().unwrap();

    verify_sigv4_header_only("GET", &uri, &headers, &auth, SECRET_KEY, None)
        .expect("verification should accept port-stripped signature received with :443");
}

#[test]
fn client_signs_with_80_server_receives_without_port() {
    let sig = sign_with_host("example.com:80", "/");
    let auth = build_auth(sig);
    let headers = build_headers("example.com");
    let uri: Uri = "/".parse().unwrap();

    verify_sigv4_header_only("GET", &uri, &headers, &auth, SECRET_KEY, None)
        .expect("port 80 toggle should also be accepted");
}

#[test]
fn non_default_port_must_match_exactly() {
    // A non-default port is signed; the server must receive that exact value.
    let sig = sign_with_host("example.com:9000", "/");
    let auth = build_auth(sig);

    // Server receives a different port — must NOT match.
    let headers = build_headers("example.com:8080");
    let uri: Uri = "/".parse().unwrap();

    let res = verify_sigv4_header_only("GET", &uri, &headers, &auth, SECRET_KEY, None);
    assert!(
        res.is_err(),
        "non-default port mismatch must reject (got {:?})",
        res.as_ref().err().map(|e| e.to_string())
    );
}

#[test]
fn matching_signature_still_works() {
    // Sanity: identical host on both sides, no port — happy path is unaffected.
    let sig = sign_with_host("example.com", "/");
    let auth = build_auth(sig);
    let headers = build_headers("example.com");
    let uri: Uri = "/".parse().unwrap();

    verify_sigv4_header_only("GET", &uri, &headers, &auth, SECRET_KEY, None)
        .expect("identical host must verify on the first attempt");
}

#[test]
fn truly_bad_signature_is_still_rejected() {
    // Signature for a different secret/path → no host variant should rescue it.
    let bad_sig = sign_with_host("example.com:443", "/wrong-path");
    let auth = build_auth(bad_sig);
    let headers = build_headers("example.com");
    let uri: Uri = "/".parse().unwrap();

    let res = verify_sigv4_header_only("GET", &uri, &headers, &auth, SECRET_KEY, None);
    assert!(res.is_err(), "unrelated bad signature must remain rejected");
}
