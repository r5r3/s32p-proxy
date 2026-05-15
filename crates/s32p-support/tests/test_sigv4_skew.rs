// Verifies the header-SigV4 clock-skew gate. AWS S3 rejects header-signed
// requests whose `x-amz-date` differs from the server clock by more than
// 15 minutes; without the gate, a captured signed request stays
// indefinitely replayable. The presigned-URL path has its own
// `X-Amz-Expires`-based expiry and is not exercised here.
//
// All requests are signed *now* (rebuilt per-test) so the only difference
// across cases is the `x-amz-date` header value the server sees and the
// `max_skew` argument to the verifier — keeping the test independent of
// real wall-clock drift.

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
use s32p_support::{HEADER_SIGV4_MAX_SKEW, SigV4Auth, verify_sigv4_header_only};
use time::{OffsetDateTime, format_description::FormatItem, macros::format_description};

const ACCESS_KEY: &str = "AKIATESTKEY";
const SECRET_KEY: &str = "topsecret";
const REGION: &str = "us-east-1";
const SERVICE: &str = "s3";
const HOST: &str = "example.com";

const AMZ_DATE_FMT: &[FormatItem<'_>] =
    format_description!("[year][month][day]T[hour][minute][second]Z");
const SCOPE_DATE_FMT: &[FormatItem<'_>] = format_description!("[year][month][day]");

fn amz_date_str(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    OffsetDateTime::from_unix_timestamp(secs).unwrap().format(AMZ_DATE_FMT).unwrap()
}

fn scope_date_str(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    OffsetDateTime::from_unix_timestamp(secs)
        .unwrap()
        .format(SCOPE_DATE_FMT)
        .unwrap()
}

/// Sign a GET / request whose `x-amz-date` matches `signing_time` exactly.
fn sign_at(signing_time: SystemTime) -> (SigV4Auth, HeaderMap) {
    let amz_date = amz_date_str(signing_time);
    let payload = "UNSIGNED-PAYLOAD".to_string();

    let signed_headers = vec![
        ("host".to_string(), HOST.to_string()),
        ("x-amz-content-sha256".to_string(), payload.clone()),
        ("x-amz-date".to_string(), amz_date.clone()),
    ];
    let header_iter = signed_headers.iter().map(|(k, v)| (k.as_str(), v.as_str()));

    let signable =
        SignableRequest::new("GET", "/", header_iter, SignableBody::UnsignedPayload).unwrap();

    let creds = Credentials::new(ACCESS_KEY, SECRET_KEY, None, None, "static");
    let identity: Identity = creds.into();
    let mut settings = SigningSettings::default();
    settings.percent_encoding_mode = PercentEncodingMode::Single;
    settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
    let params: SigningParams = v4::SigningParams::builder()
        .identity(&identity)
        .region(REGION)
        .name(SERVICE)
        .time(signing_time)
        .settings(settings)
        .build()
        .unwrap()
        .into();

    let signature = aws_sigv4::http_request::sign(signable, &params)
        .unwrap()
        .into_parts()
        .1
        .to_string();

    let auth = SigV4Auth {
        access_key: ACCESS_KEY.to_string(),
        scope_date: scope_date_str(signing_time),
        region: REGION.to_string(),
        service: SERVICE.to_string(),
        signed_headers: "host;x-amz-content-sha256;x-amz-date".to_string(),
        signature,
    };

    let mut headers = HeaderMap::new();
    headers.insert("host", HeaderValue::from_static(HOST));
    headers.insert("x-amz-content-sha256", HeaderValue::from_static("UNSIGNED-PAYLOAD"));
    headers.insert("x-amz-date", HeaderValue::from_str(&amz_date).unwrap());

    (auth, headers)
}

#[test]
fn current_time_is_within_window() {
    // A request signed *now* must verify when the gate is on.
    let (auth, headers) = sign_at(SystemTime::now());
    let uri: Uri = "/".parse().unwrap();

    verify_sigv4_header_only("GET", &uri, &headers, &auth, SECRET_KEY, Some(HEADER_SIGV4_MAX_SKEW))
        .expect("a now-signed request must verify with the default max-skew");
}

#[test]
fn one_hour_in_the_past_is_rejected() {
    // Comfortably outside the 15-minute window.
    let signing_time = SystemTime::now() - Duration::from_secs(60 * 60);
    let (auth, headers) = sign_at(signing_time);
    let uri: Uri = "/".parse().unwrap();

    let res = verify_sigv4_header_only(
        "GET",
        &uri,
        &headers,
        &auth,
        SECRET_KEY,
        Some(HEADER_SIGV4_MAX_SKEW),
    );
    let err = res.expect_err("an hour-old signature must be rejected by the skew gate");
    assert!(
        err.to_string().contains("request time skewed"),
        "expected the skew marker in the error, got: {err}"
    );
}

#[test]
fn one_hour_in_the_future_is_rejected() {
    // Future-dated requests are also out-of-window. Use the same gate.
    let signing_time = SystemTime::now() + Duration::from_secs(60 * 60);
    let (auth, headers) = sign_at(signing_time);
    let uri: Uri = "/".parse().unwrap();

    let res = verify_sigv4_header_only(
        "GET",
        &uri,
        &headers,
        &auth,
        SECRET_KEY,
        Some(HEADER_SIGV4_MAX_SKEW),
    );
    let err = res.expect_err("a future-dated signature must be rejected by the skew gate");
    assert!(
        err.to_string().contains("request time skewed"),
        "expected the skew marker in the error, got: {err}"
    );
}

#[test]
fn skew_check_is_skipped_when_max_skew_is_none() {
    // Sanity-check the test escape hatch: with `None`, even a year-old
    // signature should pass the skew check (it'll fail the date-in-scope
    // check first because YYYYMMDD won't match, so it's enough to assert
    // the error *isn't* the skew error).
    let signing_time = SystemTime::now() - Duration::from_secs(365 * 24 * 60 * 60);
    let (auth, headers) = sign_at(signing_time);
    let uri: Uri = "/".parse().unwrap();

    // With None the function may still reject for a non-skew reason
    // (here it doesn't — same scope_date as the x-amz-date the verifier
    // sees, signature was computed at the same signing_time). So this
    // call must succeed.
    verify_sigv4_header_only("GET", &uri, &headers, &auth, SECRET_KEY, None)
        .expect("with max_skew=None, an old-but-internally-consistent request must verify");
}

#[test]
fn just_inside_window_passes() {
    // Right at the edge: 14 minutes ago. Must pass the 15-minute gate.
    let signing_time = SystemTime::now() - Duration::from_secs(14 * 60);
    let (auth, headers) = sign_at(signing_time);
    let uri: Uri = "/".parse().unwrap();

    verify_sigv4_header_only("GET", &uri, &headers, &auth, SECRET_KEY, Some(HEADER_SIGV4_MAX_SKEW))
        .expect("14m-old signature must still verify under the 15m gate");
}

#[test]
fn just_outside_window_is_rejected() {
    // 16 minutes ago. Must fail the 15-minute gate.
    let signing_time = SystemTime::now() - Duration::from_secs(16 * 60);
    let (auth, headers) = sign_at(signing_time);
    let uri: Uri = "/".parse().unwrap();

    let res = verify_sigv4_header_only(
        "GET",
        &uri,
        &headers,
        &auth,
        SECRET_KEY,
        Some(HEADER_SIGV4_MAX_SKEW),
    );
    let err = res.expect_err("16m-old signature must be rejected at the 15m gate");
    assert!(
        err.to_string().contains("request time skewed"),
        "expected the skew marker in the error, got: {err}"
    );
}
