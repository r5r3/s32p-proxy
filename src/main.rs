use anyhow::Result;
use async_trait::async_trait;
use http::{Response, StatusCode};

use pingora::apps::http_app::{HttpServer, ServeHttp};
use pingora::protocols::http::ServerSession;
use pingora::server::Server;
use pingora::services::listening::Service;

mod sigv4;

struct S3ProxyApp;

#[async_trait]
impl ServeHttp for S3ProxyApp {
    // IMPORTANT: This must return `Response<Vec<u8>>`, not a Result.
    async fn response(&self, sess: &mut ServerSession) -> Response<Vec<u8>> {
        match sigv4::validate_sigv4(sess) {
            Ok(user_id) => {
                // Simple routing:
                let req = sess.req_header();

                tracing::info!("Signed for user {user_id}");

                // --- Case 1: ListBuckets (GET /)
                if req.method == "GET" && req.uri.path() == "/" {
                    let body = r#"<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner>
    <ID>{user_id}</ID>
    <DisplayName>{user_id}</DisplayName>
  </Owner>
  <Buckets>
    <Bucket>
      <Name>dummy-bucket</Name>
      <CreationDate>2025-01-01T00:00:00.000Z</CreationDate>
    </Bucket>
  </Buckets>
</ListAllMyBucketsResult>"#;

                    let body_bytes = body.as_bytes().to_vec();
                    let len = body_bytes.len().to_string();

                    return Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/xml")
                        .header("Content-Length", len)
                        .body(body_bytes)
                        .unwrap();
                }

                // --- Default dummy response for now:
                let body = format!(
                    "<DummyResponse><User>{}</User><OK>true</OK></DummyResponse>\n",
                    user_id,
                );
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/xml")
                    .body(body.into_bytes())
                    .unwrap()
            }
            Err(err) => {
                // SigV4 failed
                tracing::warn!("SigV4 validation failed: {err:#}");

                let body = format!(
                    "<Error>\
                       <Code>AccessDenied</Code>\
                       <Message>{}</Message>\
                     </Error>\n",
                    err
                );

                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header("Content-Type", "application/xml")
                    .body(body.into_bytes())
                    .unwrap()
            }
        }
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    // Pingora server
    let mut server = Server::new(None)?;
    server.bootstrap();

    // Our HTTP application
    let http_app = HttpServer::new_app(S3ProxyApp);

    // Listening service on 0.0.0.0:9000
    let mut service = Service::new("s3-proxy-manager".to_string(), http_app);
    service.add_tcp("0.0.0.0:9000");

    server.add_service(service);
    server.run_forever();
}

