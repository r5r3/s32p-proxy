use bytes::Bytes;
use http::{Response};
use http_body_util::{combinators::BoxBody, Full, BodyExt};
use std::convert::Infallible;

use s3pm_support::s3resp::BuiltResponse;

pub type Resp = Response<BoxBody<Bytes, Infallible>>;

/// Convert a framework-agnostic BuiltResponse into a Hyper response.
pub fn into_hyper(b: BuiltResponse) -> Resp {
    let mut resp = Response::new(Full::new(Bytes::from(b.body)).boxed());
    *resp.status_mut() = b.status;

    resp.headers_mut()
        .insert("content-type", b.content_type.parse().unwrap());

    for (k, v) in b.headers {
        resp.headers_mut().insert(k, v.parse().unwrap());
    }

    resp
}

