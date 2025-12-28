use anyhow::{Context, Result};
use async_trait::async_trait;

use pingora::http::{RequestHeader, ResponseHeader, StatusCode};
use pingora::proxy::{http_proxy_service, ProxyHttp, Session};
use pingora::{Error, ErrorType, Result as PResult};
use pingora::server::Server;
use pingora::upstreams::peer::HttpPeer;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use std::fs;

mod responses;
mod sigv4;
mod worker_manager;
mod classifier;
mod config;

use s3pm_directory::Directory;
use s3pm_directory::{UserDoc, BucketView};
use s3pm_directory::yaml::YamlDirectory;
use s3pm_directory::openbao::OpenBaoDirectory;

use worker_manager::{WorkerHandle, WorkerManager};

struct S3ProxyApp {
    directory: Arc<dyn Directory>,
    workers: Arc<WorkerManager>,
    public_scheme: String, // from config.server.public_scheme
    routing: config::RoutingConfig,
}

#[derive(Clone, Default)]
struct ProxyCtx {
    uid: Option<u32>,
    username: Option<String>,
    // Preserve original host EXACTLY (important for SigV4 verification in worker)
    orig_host: Option<String>,
    // Selected worker profile (used as part of worker key)
    worker_profile: Option<String>,
    // Selected upstream (per-user worker)
    upstream: Option<SocketAddr>,
    // Optional handle (for touch/logging)
    worker: Option<Arc<WorkerHandle>>,
}

impl ProxyCtx {
    fn set_user(&mut self, user: &UserDoc) {
        self.uid = Some(user.uid);
        self.username = Some(user.username.clone());
    }
}

fn class_key(class: &classifier::S3RequestClass) -> &'static str {
    match &class.op {
        classifier::S3Op::Multipart(_) => "multipart",
        classifier::S3Op::Versioning(_) => "versioning",
        classifier::S3Op::Other => "other",
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

        // Classify (no body required)
        let class = classifier::classify(&req);
        let key = class_key(&class);

        // Determine route action from config
        let action = self.routing.class_map.get(key).ok_or_else(|| {
            Error::explain(
                ErrorType::InternalError,
                format!("no routing configured for class '{key}'"),
            )
        })?;

        tracing::debug!(?class, class_key = key, ?action, "classified request and selected route action");

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
        let user = match self.directory.user_by_access_key(&access_key).await.map_err(|e| {
            Error::explain(ErrorType::InternalError, format!("directory error: {e:#}"))
        })? {
            Some(u) => u,
            None => {
                // InvalidAccessKeyId
                responses::respond_s3_error(
                    session,
                    StatusCode::FORBIDDEN,
                    responses::error_code::INVALID_ACCESS_KEY_ID,
                    "unknown access key",
                    Some(req.uri.path()),
                    None,
                ).await?;
                return Ok(true);
            }
        };
        ctx.set_user(&user);

        // 2b) If routing says NotImplemented: validate first, then reply NotImplemented.
        if let config::RouteAction::NotImplemented { message } = action {
            // Only send NotImplemented for VALID requests.
            if validate_sigv4_header_only_or_reject(session, &req, &user, &self.public_scheme).await? {
                return Ok(true); // already responded with auth/signature error
            }

            responses::respond_not_implemented(session, message, Some(req.uri.path()), None).await?;
            return Ok(true);
        }

        // 2c) Routing says Proxy: select worker profile
        let profile = match action {
            config::RouteAction::Proxy { worker_profile } => worker_profile.as_str(),
            config::RouteAction::NotImplemented { .. } => unreachable!(),
        };
        ctx.worker_profile = Some(profile.to_string());

        // 3) If worker already running: NO proxy-side SigV4 verify (just route)
        if let Some(h) = self.workers.get_running(user.access_key.as_str(), profile).await {
            h.touch();
            ctx.upstream = Some(h.addr);
            ctx.worker = Some(h);

            tracing::debug!(
                uid = user.uid,
                username = user.username.as_str(),
                profile = profile,
                addr = %ctx.upstream.unwrap(),
                elapsed_ms = start.elapsed().as_millis(),
                "worker already running; routing without proxy-side sigv4 verify"
            );
            return Ok(false);
        }

        // 4) Worker not running: verify header-only before spawn
        if validate_sigv4_header_only_or_reject(session, &req, &user, &self.public_scheme).await? {
            return Ok(true); // already responded with auth/signature error, no spawn
        }

        // 5) Start worker on demand (profile-specific)
        let buckets = self.directory.buckets_for_access_key(&access_key).await
            .map_err(|e| Error::explain(ErrorType::InternalError, format!("directory buckets error: {e:#}")))?;

        // Start worker with staged root
        let h = match self.workers.ensure_running(&user, &buckets, profile).await {
            Ok(h) => h,
            Err(e) => {
                tracing::error!(
                    uid = user.uid,
                    username = user.username.as_str(),
                    profile = profile,
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

        let posix_root = h.posix_root.display().to_string();
        h.touch();
        ctx.upstream = Some(h.addr);
        ctx.worker = Some(h);

        tracing::info!(
            uid = user.uid,
            username = user.username.as_str(),
            profile = profile,
            root = %posix_root,
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

        tracing::debug!(
            uid = ctx.uid.unwrap_or(0),
            profile = ctx.worker_profile.as_deref().unwrap_or("<none>"),
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
        // Response is not signed; safe to modify headers here.
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
                profile = ctx.worker_profile.as_deref().unwrap_or("<none>"),
                status = status,
                error = %err,
                "{}",
                session.request_summary()
            );
        } else {
            tracing::info!(
                uid = ctx.uid.unwrap_or(0),
                username = ctx.username.as_deref().unwrap_or("<unknown>"),
                profile = ctx.worker_profile.as_deref().unwrap_or("<none>"),
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
    user: &UserDoc,
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
    let cfg = config::Config::from_path("etc/s3-proxy-manager.yaml")?;

    // Build directory backend
    let directory: Arc<dyn Directory> = match cfg.auth.backend {
        config::AuthBackend::Yaml => {
            let y = cfg.auth.yaml.as_ref().context("auth.yaml missing")?;
            Arc::new(YamlDirectory::from_path(&y.path)?)
        }
        config::AuthBackend::OpenBao => {
            let o = cfg.auth.openbao.as_ref().context("auth.openbao missing")?;

            let role_id = fs::read_to_string(&o.role_id_file)
                .with_context(|| format!("failed to read role_id_file {}", o.role_id_file))?
                .trim()
                .to_string();

            let secret_id = fs::read_to_string(&o.secret_id_file)
                .with_context(|| format!("failed to read secret_id_file {}", o.secret_id_file))?
                .trim()
                .to_string();

            Arc::new(OpenBaoDirectory::new(
                o.address.clone(),
                o.approle_mount.clone(),
                role_id,
                secret_id,
                o.kv_mount.clone(),
                o.prefix.clone(),
            ))
        }
    };

    let listen = cfg.server.listen.clone();

    let workers = WorkerManager::new(cfg.workers.clone());

    let app = S3ProxyApp {
        directory,
        workers,
        public_scheme: cfg.server.public_scheme.clone(),
        routing: cfg.routing.clone(),
    };

    let mut server = Server::new(None)?;
    server.bootstrap();

    let mut proxy = http_proxy_service(&server.configuration, app);
    proxy.add_tcp(&listen);
    server.add_service(proxy);

    tracing::info!("s3-proxy-manager listening on {}", listen);
    server.run_forever();
}
