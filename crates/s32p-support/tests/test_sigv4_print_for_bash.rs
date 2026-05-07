// Print one signature for a fixed input so we can cross-check the openssl
// reproduction in test-env/sigv4-cross-check.sh.

use aws_credential_types::Credentials;
use aws_sigv4::{
    http_request::{
        PercentEncodingMode, SignableBody, SignableRequest, SigningParams, SigningSettings,
        UriPathNormalizationMode,
    },
    sign::v4,
};
use aws_smithy_runtime_api::client::identity::Identity;
use std::time::{Duration, UNIX_EPOCH};
use time::macros::format_description;

#[test]
fn print_signature_for_bash_cross_check() {
    let secret = "topsecret";
    let region = "us-east-1";
    let service = "s3";

    // Match the bash script: 2028-04-20T10:00:00Z
    use time::OffsetDateTime;
    let unix = OffsetDateTime::parse(
        "2028-04-20T10:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap()
    .unix_timestamp() as u64;
    let signing_time = UNIX_EPOCH + Duration::from_secs(unix);

    let dt = OffsetDateTime::from_unix_timestamp(unix as i64).unwrap();
    let amz_date_str = dt
        .format(format_description!(
            "[year][month][day]T[hour][minute][second]Z"
        ))
        .unwrap();
    let date_str = dt.format(format_description!("[year][month][day]")).unwrap();
    println!("SCOPE_DATE={date_str}");
    println!("AMZ_DATE={amz_date_str}");

    let headers: Vec<(String, String)> = vec![
        ("host".to_string(), "example.com".to_string()),
        (
            "x-amz-content-sha256".to_string(),
            "UNSIGNED-PAYLOAD".to_string(),
        ),
        ("x-amz-date".to_string(), amz_date_str.clone()),
    ];

    let header_iter = headers.iter().map(|(k, v)| (k.as_str(), v.as_str()));
    let signable =
        SignableRequest::new("GET", "/", header_iter, SignableBody::UnsignedPayload).unwrap();

    let creds = Credentials::new("AKIATESTKEY", secret, None, None, "static");
    let identity: Identity = creds.into();

    let mut settings = SigningSettings::default();
    settings.percent_encoding_mode = PercentEncodingMode::Single;
    settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;

    let params: SigningParams = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name(service)
        .time(signing_time)
        .settings(settings)
        .build()
        .unwrap()
        .into();

    let sig = aws_sigv4::http_request::sign(signable, &params)
        .unwrap()
        .into_parts()
        .1
        .to_string();

    println!("aws_sigv4: {sig}");
}
