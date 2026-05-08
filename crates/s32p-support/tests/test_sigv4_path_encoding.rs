// SigV4 path-encoding fallback: clients that follow the AWS SigV4 spec
// (boto3, aws-cli, AWS Java SDK) percent-encode every byte outside the RFC 3986
// unreserved set when building the canonical URI, even when the wire URI keeps
// sub-delim characters like `(`, `)`, `*`, `'`, `!` literal. This test signs a
// DELETE with the canonicalized canonical URI (`%28`/`%29`) and presents the
// wire URI with literal parens, mirroring the bug seen with object key
// "scalene/.../script (dev).tmpl".
//
// Without the path-canonicalization fallback in verify_sigv4_header_only, this
// test fails with "signature mismatch".

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
const FIXED_TIME_UNIX: u64 = 1_840_000_000;

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

fn sign_path(method: &str, host: &str, canonical_path: &str) -> String {
    let amz_date = amz_date_str();
    let payload = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string();
    let headers: Vec<(String, String)> = vec![
        ("host".to_string(), host.to_string()),
        ("x-amz-content-sha256".to_string(), payload.clone()),
        ("x-amz-date".to_string(), amz_date),
    ];
    let header_iter = headers.iter().map(|(k, v)| (k.as_str(), v.as_str()));

    let signable = SignableRequest::new(
        method,
        canonical_path,
        header_iter,
        SignableBody::Precomputed(payload),
    )
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
        access_key:     ACCESS_KEY.to_string(),
        scope_date:     scope_date_str(),
        region:         REGION.to_string(),
        service:        SERVICE.to_string(),
        signed_headers: "host;x-amz-content-sha256;x-amz-date".to_string(),
        signature,
    }
}

fn build_headers(host: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("host", HeaderValue::from_str(host).unwrap());
    h.insert(
        "x-amz-content-sha256",
        HeaderValue::from_static(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
    );
    h.insert("x-amz-date", HeaderValue::from_str(&amz_date_str()).unwrap());
    h
}

#[test]
fn parens_unencoded_on_wire_but_encoded_in_canonical_uri() {
    // Reproduces the user-reported case: DELETE on
    //   /tickets/.../script%20(dev).tmpl
    // The client (boto3-style) percent-encodes parens for its canonical URI
    // (matching the AWS SigV4 spec) but transmits literal `(`/`)` on the wire.
    let host = "z-sv-l2s3gw03.example.com";
    let canonical_path =
        "/tickets/scalene/venv/lib/python3.10/site-packages/setuptools/script%20%28dev%29.tmpl";
    let wire_path =
        "/tickets/scalene/venv/lib/python3.10/site-packages/setuptools/script%20(dev).tmpl";

    let sig = sign_path("DELETE", host, canonical_path);
    let auth = build_auth(sig);

    let headers = build_headers(host);
    let uri: Uri = wire_path.parse().unwrap();

    verify_sigv4_header_only("DELETE", &uri, &headers, &auth, SECRET_KEY).expect(
        "verification should accept boto3-style requests where the canonical URI \
         encodes sub-delim chars but the wire URI leaves them literal",
    );
}

#[test]
fn fully_unencoded_parens_on_wire_and_in_canonical_uri() {
    // The other valid case: a (non-conformant) client signs with literal parens
    // in the canonical URI and also sends them literal on the wire. We must
    // still accept this — that's the path that worked before the fix and the
    // fallback must not break it.
    let host = "example.com";
    let path = "/bucket/dir/script(x).tmpl";

    let sig = sign_path("DELETE", host, path);
    let auth = build_auth(sig);

    let headers = build_headers(host);
    let uri: Uri = path.parse().unwrap();

    verify_sigv4_header_only("DELETE", &uri, &headers, &auth, SECRET_KEY)
        .expect("signing and verifying with the same literal-paren path must succeed");
}

#[test]
fn extra_subdelim_chars_get_canonicalized() {
    // Spot-check more sub-delim chars: `*`, `'`, `!`, `:`, `@`, `,`, `+`.
    // boto3 and aws-cli encode all of these in the canonical URI.
    let host = "example.com";
    // Canonical: encode * ' ! : @ , +
    let canonical_path = "/bucket/a%2Ab%27c%21d%3Ae%40f%2Cg%2Bh.txt";
    let wire_path = "/bucket/a*b'c!d:e@f,g+h.txt";

    let sig = sign_path("GET", host, canonical_path);
    let auth = build_auth(sig);

    let headers = build_headers(host);
    let uri: Uri = wire_path.parse().unwrap();

    verify_sigv4_header_only("GET", &uri, &headers, &auth, SECRET_KEY).expect(
        "verification should accept literal sub-delim chars on the wire when \
         the client's canonical URI percent-encodes them",
    );
}

#[test]
fn rejects_genuinely_wrong_signature() {
    // Sanity check: the fallback only flips the path encoding, so a truly
    // tampered request must still be rejected.
    let host = "example.com";
    let wire_path = "/bucket/dir/file.txt";

    // Build a valid auth, then corrupt the signature.
    let mut sig = sign_path("DELETE", host, wire_path);
    sig.replace_range(0..1, if &sig[0..1] == "0" { "1" } else { "0" });
    let auth = build_auth(sig);

    let headers = build_headers(host);
    let uri: Uri = wire_path.parse().unwrap();

    let res = verify_sigv4_header_only("DELETE", &uri, &headers, &auth, SECRET_KEY);
    assert!(res.is_err(), "tampered signature must be rejected");
}
