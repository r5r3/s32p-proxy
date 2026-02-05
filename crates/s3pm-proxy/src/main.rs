use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use anyhow::{Context, Result};
use async_trait::async_trait;

use pingora::http::{RequestHeader, ResponseHeader, StatusCode};
use pingora::proxy::{http_proxy_service, ProxyHttp, Session};
use pingora::{Error, ErrorType, Result as PResult};
use pingora::server::Server;
use pingora::upstreams::peer::{HttpPeer, PeerOptions};
use pingora::listeners::tls::TlsSettings;
use rustls::crypto::{aws_lc_rs, CryptoProvider};

use std::sync::Arc;
use std::time::Instant;
use std::fs;

mod responses;
mod worker_manager;
mod config;

use s3pm_directory::Directory;
use s3pm_directory::UserDoc;
use s3pm_directory::yaml::YamlDirectory;
use s3pm_directory::openbao::OpenBaoDirectory;

use s3pm_support;

use worker_manager::{WorkerHandle, WorkerManager, WorkerEndpoint};


struct S3ProxyApp {
    directory: Arc<dyn Directory>,
    workers: Arc<WorkerManager>,
    public_scheme: String, // from config.server.public_scheme
    routing: config::RoutingConfig,
    region: String, // from config.server.region (for GetBucketLocation)
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
    upstream: Option<WorkerEndpoint>,
    // Optional handle (for touch/logging)
    worker: Option<Arc<WorkerHandle>>,
}

impl ProxyCtx {
    fn set_user(&mut self, user: &UserDoc) {
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

        // Classify (no body required).
        // This logic is shared with the gateway now (in s3pm-support),
        // so routing decisions won't drift.
        let class = s3pm_support::classifier::classify_with_headers(req.method.as_str(), &req.uri, Some(&req.headers));
        let key = s3pm_support::classifier::class_key(&class);

        // Determine route action from config.
        // If routing for the specific class is not configured,
        // fall back to the "other" route.
        let (_selected_key, action) = match self.routing.class_map.get(key) {
            Some(a) => (key, a),
            None => match self.routing.class_map.get("other") {
                Some(a) => {
                    tracing::debug!(
                        requested_class = key,
                        fallback_class = "other",
                        "no routing configured for class; falling back to 'other'"
                    );
                    ("other", a)
                }
                None => {
                    return Err(Error::explain(
                        ErrorType::InternalError,
                        format!("no routing configured for class '{key}' and no fallback 'other' route"),
                    ));
                }
            },
        };

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
        let access_key = match s3pm_support::extract_access_key_from_request(&req.uri, &req.headers) {
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
            ctx.upstream = Some(h.endpoint.clone());
            ctx.worker = Some(h);

            tracing::debug!(
                uid = user.uid,
                username = user.username.as_str(),
                profile = profile,
                addr = %ctx.upstream.clone().unwrap(),
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
        ctx.upstream = Some(h.endpoint.clone());
        ctx.worker = Some(h);

        tracing::info!(
            uid = user.uid,
            username = user.username.as_str(),
            profile = profile,
            root = %posix_root,
            addr = %ctx.upstream.clone().unwrap(),
            elapsed_ms = start.elapsed().as_millis(),
            "worker started; routing request"
        );

        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> PResult<Box<HttpPeer>> {
        let ep = ctx.upstream.clone().ok_or_else(|| {
            Error::explain(ErrorType::InternalError, "no upstream selected")
        })?;

        let peer = match ep {
            WorkerEndpoint::Tcp(addr) => {
                let mut peer = HttpPeer::new(addr, false, "localhost".to_string());

                let mut opts = PeerOptions::new();
                opts.tcp_recv_buf = Some(8 * 1024 * 1024); // 8 MiB receive buffer on the upstream TCP socket
                peer.options = opts;

                peer
            }
            WorkerEndpoint::Uds(path) => {
                // HttpPeer::new_uds returns Result<...> so map it into Pingora's error type.
                let peer = HttpPeer::new_uds(path.to_string_lossy().as_ref(), false, "localhost".to_string())
                    .map_err(|e| Error::explain(ErrorType::InternalError, format!("new_uds failed: {e}")))?;

                // TCP-only socket options don't apply to UDS; leave options default.
                peer
            }
        };

        Ok(Box::new(peer))
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
            upstream = %ctx.upstream.as_ref().map(|ep| ep.to_string()).unwrap_or_else(|| "<none>".to_string()),
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
    let res = s3pm_support::verify_sigv4_request_any(
        req.method.as_str(),
        &req.uri,
        &req.headers,
        None, // proxy already selected `user` based on extracted access key
        &user.secret_key,
        public_scheme,
    );

    match res {
        Ok(()) => Ok(false),
        Err(e) => {
            let (status, code) = match e.kind {
                s3pm_support::SigV4VerifyErrorKind::AccessDenied => (
                    StatusCode::FORBIDDEN,
                    responses::error_code::ACCESS_DENIED,
                ),
                s3pm_support::SigV4VerifyErrorKind::SignatureDoesNotMatch => (
                    StatusCode::FORBIDDEN,
                    responses::error_code::SIGNATURE_DOES_NOT_MATCH,
                ),
            };

            responses::respond_s3_error(
                session,
                status,
                code,
                &e.message,
                Some(req.uri.path()),
                None,
            )
            .await?;

            Ok(true)
        }
    }
}

fn rustls_prefer_fast_cipher() -> Result<()> {
    // Prefer AES-128 first, then AES-256.
    //
    // NOTE: rustls uses the provider’s cipher_suites order as server preference.
    // We keep CHACHA as a fallback after AES.
    use rustls::crypto::aws_lc_rs::cipher_suite::*;

    let mut provider = aws_lc_rs::default_provider();
    provider.cipher_suites = vec![
        // TLS 1.3
        TLS13_AES_128_GCM_SHA256,
        //TLS13_AES_256_GCM_SHA384,
        //TLS13_CHACHA20_POLY1305_SHA256,

        // TLS 1.2 (ECDHE + AES-GCM), AES-128 first
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        //TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        //TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,

        // TLS 1.2 fallback
        //TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        //TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ];

    CryptoProvider::install_default(provider).expect("Failed to install aws-lc-rs as default TLS provider");
    Ok(())
}


fn main() -> Result<()> {
    // ensure, that aws-lc-rs is our crypto provider
    // aws_lc_rs::default_provider().install_default().expect("Failed to install aws-lc-rs as default TLS provider");
    rustls_prefer_fast_cipher().unwrap();

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

    let workers = WorkerManager::new(cfg.workers.clone(), cfg.server.clone());

    let app = S3ProxyApp {
        directory,
        workers,
        public_scheme: cfg.server.public_scheme.clone(),
        routing: cfg.routing.clone(),
        region: cfg.server.region.clone(),
    };

    let mut server = Server::new(None)?;
    server.bootstrap();

    let mut proxy = http_proxy_service(&server.configuration, app);

    if cfg.server.public_scheme == "https" {
        let mut tls_settings = TlsSettings::intermediate(
            cfg.server.tls_cert_path.as_ref().unwrap(),
            cfg.server.tls_key_path.as_ref().unwrap(),
        ).context("failed to load TLS settings (check certificate/key paths and format)")?;
        tls_settings.enable_h2();
        proxy.add_tls_with_settings(&cfg.server.listen, None, tls_settings);
        tracing::info!("TLS enabled, listening on {}", listen);
    } else {
        proxy.add_tcp(&listen);
        tracing::info!("TLS disabled, listening on {}", listen);
    }

    server.add_service(proxy);
    server.run_forever();
}
