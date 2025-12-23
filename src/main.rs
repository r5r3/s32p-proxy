use anyhow::Result;
use async_trait::async_trait;
use http::{Response, StatusCode};

use pingora::apps::http_app::{HttpServer, ServeHttp};
use pingora::protocols::http::ServerSession;
use pingora::server::Server;
use pingora::services::listening::Service;

use std::time::Instant;

mod sigv4;
mod user_db;
mod worker_manager;

use user_db::UserDb;
use worker_manager::{WorkerManager, WorkerManagerConfig};

struct S3ProxyApp {
    user_db: UserDb,
    workers: std::sync::Arc<WorkerManager>,
    public_scheme: String, // "http" in dev; "https" behind TLS
}

#[async_trait]
impl ServeHttp for S3ProxyApp {
    async fn response(&self, sess: &mut ServerSession) -> Response<Vec<u8>> {
        // Start background sweeper lazily (we are now inside tokio)
        self.workers.start_sweeper();

        let start = Instant::now();
        let req = sess.req_header();

        let method = req.method.as_str();
        let path = req.uri.path();
        let query = req.uri.query().unwrap_or("");
        let host = req
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("<missing-host>");

        let ua = req
            .headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("<no-ua>");

        tracing::debug!(
            method = method,
            path = path,
            query = query,
            host = host,
            user_agent = ua,
            "incoming request"
        );

        // (Optional) log a few relevant SigV4 headers (avoid full Authorization)
        if let Some(v) = req.headers.get("x-amz-date").and_then(|v| v.to_str().ok()) {
            tracing::debug!(x_amz_date = v, "sigv4 header");
        }
        if let Some(v) = req
            .headers
            .get("x-amz-content-sha256")
            .and_then(|v| v.to_str().ok())
        {
            tracing::debug!(x_amz_content_sha256 = v, "sigv4 header");
        }

        // 1) Parse Authorization → access_key + signed headers + signature (for gating)
        let auth = match sigv4::parse_authorization(req) {
            Ok(a) => {
                tracing::debug!(
                    access_key = a.access_key.as_str(),
                    region = a.region.as_str(),
                    service = a.service.as_str(),
                    signed_headers = a.signed_headers.as_str(),
                    "parsed Authorization"
                );
                a
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to parse Authorization");
                return xml_err(StatusCode::FORBIDDEN, "AccessDenied", &e.to_string());
            }
        };

        // 2) Map access_key → user record
        let user = match self.user_db.get(&auth.access_key) {
            Some(u) => {
                tracing::debug!(
                    access_key = auth.access_key.as_str(),
                    username = u.username.as_str(),
                    uid = u.uid,
                    gid = u.gid,
                    "mapped access key to unix user"
                );
                u.clone()
            }
            None => {
                tracing::warn!(
                    access_key = auth.access_key.as_str(),
                    "unknown access key; rejecting without spawning worker"
                );
                return xml_err(
                    StatusCode::FORBIDDEN,
                    "InvalidAccessKeyId",
                    "unknown access key",
                );
            }
        };

        // 3) Check worker state
        let running = self.workers.get_running(user.uid).await;
        if let Some(h) = running {
            tracing::debug!(
                uid = user.uid,
                username = user.username.as_str(),
                addr = %h.addr,
                "worker already running; skip proxy-side signature verification"
            );
            h.touch();
        } else {
            tracing::debug!(
                uid = user.uid,
                username = user.username.as_str(),
                "worker not running; perform header-only SigV4 verification before spawn"
            );

            // Gate spawning with header-only verification (uses client supplied payload hash)
            if let Err(e) = sigv4::verify_sigv4_header_only(
                req,
                &auth,
                &user.secret_key,
                &self.public_scheme,
            ) {
                tracing::warn!(
                    uid = user.uid,
                    username = user.username.as_str(),
                    error = %e,
                    "SigV4 header-only verification failed; rejecting without spawning worker"
                );
                return xml_err(StatusCode::FORBIDDEN, "SignatureDoesNotMatch", &e.to_string());
            }

            tracing::debug!(
                uid = user.uid,
                username = user.username.as_str(),
                "SigV4 header-only verification OK; starting/ensuring worker"
            );

            match self.workers.ensure_running(&user).await {
                Ok(h) => {
                    tracing::info!(
                        uid = user.uid,
                        username = user.username.as_str(),
                        addr = %h.addr,
                        "worker is running"
                    );
                    h.touch();
                }
                Err(e) => {
                    tracing::error!(
                        uid = user.uid,
                        username = user.username.as_str(),
                        error = %e,
                        "failed to start worker"
                    );
                    return xml_err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "ServiceUnavailable",
                        &format!("failed to start worker: {e:#}"),
                    );
                }
            }
        }

        // 4) Placeholder response (until we switch to streaming proxy)
        let addr = self
            .workers
            .get_running(user.uid)
            .await
            .map(|h| h.addr.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let body = format!(
            r#"<S3ProxyManager>
  <User>{}</User>
  <UID>{}</UID>
  <WorkerAddr>{}</WorkerAddr>
</S3ProxyManager>"#,
            user.username, user.uid, addr
        );

        tracing::debug!(
            uid = user.uid,
            username = user.username.as_str(),
            elapsed_ms = start.elapsed().as_millis(),
            "responding (dummy handler)"
        );

        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/xml")
            .header("Content-Length", body.len().to_string())
            .body(body.into_bytes())
            .unwrap()
    }
}

fn xml_err(status: StatusCode, code: &str, message: &str) -> Response<Vec<u8>> {
    let body = format!(
        r#"<Error>
  <Code>{}</Code>
  <Message>{}</Message>
</Error>"#,
        code, message
    );
    Response::builder()
        .status(status)
        .header("Content-Type", "application/xml")
        .header("Content-Length", body.len().to_string())
        .body(body.into_bytes())
        .unwrap()
}

fn main() -> Result<()> {
    // Suggested: set RUST_LOG=s3_proxy_manager=debug or RUST_LOG=debug
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()),
        )
        .init();

    let user_db = UserDb::demo();

    let workers = WorkerManager::new(WorkerManagerConfig {
        restricted_exec: "../restricted-exec/target/debug/restricted-exec".to_string(),
        versitygw: "../versity-patched/versitygw".to_string(),
        posix_root: "/tmp/s3".to_string(),
        extra_versity_args: vec![],
        idle_timeout: std::time::Duration::from_secs(10 * 60),
        sweep_interval: std::time::Duration::from_secs(10),
    });

    let app = S3ProxyApp {
        user_db,
        workers,
        public_scheme: "http".to_string(),
    };

    let mut server = Server::new(None)?;
    server.bootstrap();

    let http_app = HttpServer::new_app(app);

    let mut svc = Service::new("s3-proxy-manager".into(), http_app);
    svc.add_tcp("0.0.0.0:9000");
    server.add_service(svc);

    tracing::info!("s3-proxy-manager listening on 0.0.0.0:9000");
    server.run_forever();
}
