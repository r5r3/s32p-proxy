use anyhow::Result;
use async_trait::async_trait;

use pingora::http::{RequestHeader, ResponseHeader, StatusCode};
use pingora::proxy::{http_proxy_service, ProxyHttp, Session};
use pingora::{Error, ErrorType, Result as PResult};
use pingora::server::Server;
use pingora::upstreams::peer::HttpPeer;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

mod responses;
mod sigv4;
mod user_db;
mod worker_manager;
mod classifier;
mod config;

use user_db::{UserDb, UserRecord};
use worker_manager::{WorkerHandle, WorkerManager};

struct S3ProxyApp {
    user_db: UserDb,
    workers: Arc<WorkerManager>,
    public_scheme: String, // "http" in dev; "https" behind TLS
}

#[derive(Clone, Default)]
struct ProxyCtx {
    uid: Option<u32>,
    username: Option<String>,
    // Preserve original host EXACTLY (important for SigV4 verification in worker)
    orig_host: Option<String>,
    // Selected upstream (per-user worker)
    upstream: Option<SocketAddr>,
    // Optional handle (for touch/logging)
    worker: Option<Arc<WorkerHandle>>,
}

impl ProxyCtx {
    fn set_user(&mut self, user: &UserRecord) {
        self.uid = Some(user.uid);
        self.username = Some(user.username.clone());
    }
}

#[async_trait]
impl ProxyHttp for S3ProxyApp {
    type CTX = ProxyCtx;

    fn new_ctx(&self) -> Self::CTX {
        ProxyCtx::default()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> PResult<bool> {
        // Start background sweeper lazily (we are now inside tokio)
        self.workers.start_sweeper();

        let start = Instant::now();

        // IMPORTANT: clone header so we don't hold an immutable borrow of `session`
        let req: RequestHeader = session.req_header().clone();

        // Classify each request (no body required)
        let class = classifier::classify(&req);
        if let Some(reason) = classifier::not_implemented_reason(&class) {
            tracing::debug!(?class, reason, "request classified as not implemented (will validate first)");
        } else {
            tracing::debug!(?class, "request classified");
        }

        let method = req.method.as_str();
        let path = req.uri.path();
        let query = req.uri.query().unwrap_or("");

        let host = req
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        ctx.orig_host = host.clone();

        tracing::debug!(
            method = method,
            path = path,
            query = query,
            host = host.as_deref().unwrap_or("<missing-host>"),
            "incoming request"
        );

        // 1) Extract access key cheaply (no SigV4 check yet)
        let access_key = match sigv4::extract_access_key(&req) {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(error = %e, "failed to extract access key");
                responses::respond_s3_error(
                    session,
                    StatusCode::FORBIDDEN,
                    responses::error_code::ACCESS_DENIED,
                    &e.to_string(),
                    Some(req.uri.path()),
                    None,
                )
                .await?;
                return Ok(true);
            }
        };

        // 2) Map access key -> unix user
        let user = match self.user_db.get(&access_key) {
            Some(u) => u.clone(),
            None => {
                tracing::warn!(access_key = access_key.as_str(), "unknown access key");
                responses::respond_s3_error(
                    session,
                    StatusCode::FORBIDDEN,
                    responses::error_code::INVALID_ACCESS_KEY_ID,
                    "unknown access key",
                    Some(req.uri.path()),
                    None,
                )
                .await?;
                return Ok(true);
            }
        };
        ctx.set_user(&user);

        // 2b) If this request is currently "NotImplemented": validate first, then reply NotImplemented.
        if let Some(reason) = classifier::not_implemented_reason(&class) {
            // Validate first. Only reply NotImplemented if request is valid.
            if validate_sigv4_header_only_or_reject(session, &req, &user, &self.public_scheme).await? {
                return Ok(true); // already responded with auth/signature error
            }

            responses::respond_not_implemented(session, reason, Some(req.uri.path()), None).await?;
            return Ok(true);
        }

        let profile = "versitygw-default"; // later: selected from routing config

        // 3) If worker already running: NO proxy-side SigV4 verify (just route)
        if let Some(h) = self.workers.get_running(user.uid, profile).await {
            h.touch();
            ctx.upstream = Some(h.addr);
            ctx.worker = Some(h);

            tracing::debug!(
                uid = user.uid,
                username = user.username.as_str(),
                addr = %ctx.upstream.unwrap(),
                elapsed_ms = start.elapsed().as_millis(),
                "worker already running; routing without proxy-side sigv4 verify"
            );
            return Ok(false);
        }

        // 4) Worker not running: parse full Authorization + verify header-only before spawn
        if validate_sigv4_header_only_or_reject(session, &req, &user, &self.public_scheme).await? {
            return Ok(true); // already responded with auth/signature error, no spawn
        }

        // 5) Start worker on demand
        let h = match self.workers.ensure_running(&user, profile).await {
            Ok(h) => h,
            Err(e) => {
                tracing::error!(
                    uid = user.uid,
                    username = user.username.as_str(),
                    error = %e,
                    "failed to start worker"
                );
                responses::respond_s3_error(
                    session,
                    StatusCode::SERVICE_UNAVAILABLE,
                    responses::error_code::SERVICE_UNAVAILABLE,
                    &format!("failed to start worker: {e:#}"),
                    Some(req.uri.path()),
                    None,
                )
                .await?;
                return Ok(true);
            }
        };

        h.touch();
        ctx.upstream = Some(h.addr);
        ctx.worker = Some(h);

        tracing::info!(
            uid = user.uid,
            username = user.username.as_str(),
            addr = %ctx.upstream.unwrap(),
            elapsed_ms = start.elapsed().as_millis(),
            "worker started; routing request"
        );

        Ok(false)
    }

    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Self::CTX) -> PResult<Box<HttpPeer>> {
        let addr = ctx.upstream.ok_or_else(|| {
            // Should never happen if request_filter set ctx.upstream
            Error::explain(ErrorType::InternalError, "no upstream selected")
        })?;

        // Plain HTTP to local worker
        let peer = Box::new(HttpPeer::new(addr, false, "localhost".to_string()));
        Ok(peer)
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> PResult<()>
    where
        Self::CTX: Send + Sync,
    {
        // IMPORTANT for SigV4: do NOT let Host change when proxying to 127.0.0.1:PORT
        if let Some(host) = ctx.orig_host.as_deref() {
            upstream_request.insert_header("Host", host)?;
        }

        // Remove hop-by-hop headers (safe: usually not in SignedHeaders)
        upstream_request.remove_header("connection");
        upstream_request.remove_header("proxy-connection");
        upstream_request.remove_header("keep-alive");
        upstream_request.remove_header("te");
        upstream_request.remove_header("upgrade");

        // (Optional) if you add any headers here, be careful:
        // adding/removing a header that appears in SignedHeaders will break SigV4 in versitygw.

        tracing::debug!(
            uid = ctx.uid.unwrap_or(0),
            upstream = %ctx.upstream.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap()),
            "sending request upstream"
        );

        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> PResult<()>
    where
        Self::CTX: Send + Sync,
    {
        // Example “future requirement”: modify headers here.
        // (This is safe and doesn’t affect SigV4: response isn’t signed.)
        upstream_response.insert_header("Server", "s3-proxy-manager")?;
        upstream_response.remove_header("alt-svc");

        Ok(())
    }

    async fn logging(&self, session: &mut Session, e: Option<&pingora::Error>, ctx: &mut Self::CTX) {
        let status = session
            .response_written()
            .map(|r| r.status.as_u16())
            .unwrap_or(0);

        if let Some(err) = e {
            tracing::warn!(
                uid = ctx.uid.unwrap_or(0),
                username = ctx.username.as_deref().unwrap_or("<unknown>"),
                status = status,
                error = %err,
                "{}",
                session.request_summary()
            );
        } else {
            tracing::info!(
                uid = ctx.uid.unwrap_or(0),
                username = ctx.username.as_deref().unwrap_or("<unknown>"),
                status = status,
                "{}",
                session.request_summary()
            );
        }
    }
}

async fn validate_sigv4_header_only_or_reject(
    session: &mut Session,
    req: &RequestHeader,
    user: &UserRecord,
    public_scheme: &str,
) -> PResult<bool> {
    // Parse full Authorization (for SignedHeaders/scope/region/service/signature)
    let auth = match sigv4::parse_authorization(req) {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(uid = user.uid, error = %e, "failed to parse Authorization");
            responses::respond_s3_error(
                session,
                StatusCode::FORBIDDEN,
                responses::error_code::ACCESS_DENIED,
                &e.to_string(),
                Some(req.uri.path()),
                None,
            )
            .await?;
            return Ok(true);
        }
    };

    // Validate header-only SigV4 using client x-amz-content-sha256
    if let Err(e) = sigv4::verify_sigv4_header_only(req, &auth, &user.secret_key, public_scheme) {
        tracing::warn!(
            uid = user.uid,
            username = user.username.as_str(),
            error = %e,
            "sigv4 header-only verification failed"
        );
        responses::respond_s3_error(
            session,
            StatusCode::FORBIDDEN,
            responses::error_code::SIGNATURE_DOES_NOT_MATCH,
            &e.to_string(),
            Some(req.uri.path()),
            None,
        )
        .await?;
        return Ok(true);
    }

    Ok(false) // valid
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()))
        .init();

    let user_db = UserDb::demo();

    let cfg = config::Config::from_path("etc/s3-proxy-manager.yaml")?;
    let workers = WorkerManager::new(cfg.workers.clone());

    let app = S3ProxyApp {
        user_db,
        workers,
        public_scheme: "http".to_string(),
    };

    let mut server = Server::new(None)?;
    server.bootstrap();

    let mut proxy = http_proxy_service(&server.configuration, app);
    proxy.add_tcp("0.0.0.0:9000");
    server.add_service(proxy);

    tracing::info!("s3-proxy-manager listening on 0.0.0.0:9000");
    server.run_forever();
}
