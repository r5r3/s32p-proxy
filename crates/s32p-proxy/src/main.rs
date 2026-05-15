use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use std::{fs, path::PathBuf, sync::Arc, time::Instant};

use anyhow::{Context, Result};
use async_trait::async_trait;
use clap::Parser;
use pingora::{
    Error, ErrorType, Result as PResult,
    http::{RequestHeader, ResponseHeader, StatusCode},
    listeners::tls::TlsSettings,
    proxy::{ProxyHttp, Session, http_proxy_service},
    server::{Server, ShutdownWatch, configuration::ServerConf},
    services::background::{BackgroundService, background_service},
    upstreams::peer::{HttpPeer, PeerOptions},
};
use rustls::crypto::{CryptoProvider, aws_lc_rs};

mod config;
mod responses;
mod worker_manager;

use s32p_directory::{
    AccessLevel, Directory, UserDoc, openbao::OpenBaoDirectory, yaml::YamlDirectory,
};
use s32p_support;
use worker_manager::{WorkerEndpoint, WorkerHandle, WorkerManager};

#[derive(Parser, Debug)]
#[command(version, about = "S3 to POSIX proxy", long_about = None)]
struct Cli {
    #[arg(short, long, default_value = "etc/s32p-proxy.yaml")]
    config: PathBuf,
}

struct S3ProxyApp {
    directory:               Arc<dyn Directory>,
    workers:                 Arc<WorkerManager>,
    routing:                 config::RoutingConfig,
    virtual_hosted_suffixes: Vec<String>, // from config.server.virtual_hosted_suffixes
}

/// Pingora background service that terminates worker processes on graceful
/// shutdown. Pingora flips its `ShutdownWatch` to `true` when SIGTERM/SIGQUIT
/// arrives; we await that, kill every worker, and let the grace period run
/// down on the now-empty slot map. SIGINT (fast shutdown) doesn't broadcast,
/// so this future never wakes — `kill_on_drop(true)` on the spawn `Command`
/// is what catches that path during runtime teardown.
struct WorkerShutdownService {
    workers: Arc<WorkerManager>,
}

#[async_trait]
impl BackgroundService for WorkerShutdownService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        if shutdown.changed().await.is_err() {
            return;
        }
        tracing::info!("graceful shutdown received; terminating worker processes");
        self.workers.shutdown().await;
        tracing::info!("all worker processes terminated");
    }
}

#[derive(Clone, Default)]
struct ProxyCtx {
    uid:            Option<u32>,
    username:       Option<String>,
    // Preserve original host EXACTLY (important for SigV4 verification in worker)
    orig_host:      Option<String>,
    // Selected worker profile (used as part of worker key)
    worker_profile: Option<String>,
    // Selected upstream (per-user worker)
    upstream:       Option<WorkerEndpoint>,
    // Optional handle (for touch/logging)
    worker:         Option<Arc<WorkerHandle>>,
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

        // HTTP/2 sends authority in `:authority` instead of a `Host` header.
        // SigV4 always signs `host` (it's the canonical name for the authority),
        // so synthesize a `Host` header from `:authority` if missing — otherwise
        // verification fails with "signed header 'host' missing in request".
        if session.req_header().headers.get("host").is_none()
            && let Some(authority) = session.req_header().uri.authority()
        {
            let v = authority.as_str().to_string();
            session.req_header_mut().insert_header("host", &v)?;
        }

        // IMPORTANT: clone header so we don't hold an immutable borrow of `session`
        let req: RequestHeader = session.req_header().clone();

        // Classify (no body required).
        // This logic is shared with the gateway now (in s32p-support),
        // so routing decisions won't drift.
        let class = s32p_support::classifier::classify_with_headers(
            req.method.as_str(),
            &req.uri,
            Some(&req.headers),
            &self.virtual_hosted_suffixes,
        );
        let key = s32p_support::classifier::class_key(&class);

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
                        format!(
                            "no routing configured for class '{key}' and no fallback 'other' route"
                        ),
                    ));
                }
            },
        };

        tracing::debug!(
            ?class,
            class_key = key,
            ?action,
            "classified request and selected route action"
        );

        let method = req.method.as_str();
        let path = req.uri.path();
        let query = req.uri.query().unwrap_or("");

        let host = req.headers.get("host").and_then(|v| v.to_str().ok()).map(|s| s.to_string());

        ctx.orig_host = host.clone();

        tracing::debug!(
            method = method,
            path = path,
            query = query,
            host = host.as_deref().unwrap_or("<missing-host>"),
            "incoming request"
        );

        // 1) Extract access key cheaply (no SigV4 check yet)
        let access_key = match s32p_support::extract_access_key_from_request(&req.uri, &req.headers)
        {
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
                )
                .await?;
                return Ok(true);
            }
        };
        ctx.set_user(&user);

        // Track whether we've already SigV4-verified this request inside the
        // proxy. Multiple steps below (ACL pre-check, NotImplemented gate,
        // pre-spawn gate) used to verify independently — wasted work for
        // write requests that hit two of these paths. We verify at most
        // once per request now.
        let mut sigv4_validated = false;

        // 2a) ACL access-level enforcement.
        //
        // Look up the caller's effective access on the request's bucket and
        // reject early if the request needs write but the grant is read_only.
        // Doing this before SigV4 validation would leak ACL state to
        // unauthenticated callers, so it sits *after* user lookup but *before*
        // the SigV4 verify in 2b/4 — a read_only caller still has to present
        // a valid signature to learn the request was rejected for ACL reasons.
        //
        // ListBuckets has no bucket and is filtered by visibility downstream,
        // so it's exempt here. For any other request without a recognised
        // bucket (malformed URL, etc.) we let later layers produce the right
        // error.
        if needs_write(method)
            && let Some(bucket_name) = class.bucket.as_deref()
        {
            // First validate the signature so we don't tell unauthenticated
            // callers anything about the bucket's ACL.
            if validate_sigv4_header_only_or_reject(session, &req, &user).await? {
                return Ok(true);
            }
            sigv4_validated = true;
            let access = bucket_access_for_caller(
                self.directory.as_ref(),
                &access_key,
                bucket_name,
            )
            .await
            .map_err(|e| {
                Error::explain(
                    ErrorType::InternalError,
                    format!("acl lookup failed: {e:#}"),
                )
            })?;
            if matches!(access, Some(AccessLevel::ReadOnly)) {
                tracing::info!(
                    access_key = access_key.as_str(),
                    bucket = bucket_name,
                    method = method,
                    "rejecting write on read_only-granted bucket"
                );
                responses::respond_s3_error(
                    session,
                    StatusCode::FORBIDDEN,
                    responses::error_code::ACCESS_DENIED,
                    "access denied",
                    Some(req.uri.path()),
                    None,
                )
                .await?;
                return Ok(true);
            }
            // None (no grant) and Some(ReadWrite) both fall through.
            // No-grant is enforced downstream (the bucket isn't symlinked
            // into the worker's posix_root); leaving that path unchanged
            // keeps this commit narrowly scoped to read_only enforcement.
        }

        // 2b) If routing says NotImplemented: validate first, then reply NotImplemented.
        if let config::RouteAction::NotImplemented { message } = action {
            // Only send NotImplemented for VALID requests.
            if !sigv4_validated
                && validate_sigv4_header_only_or_reject(session, &req, &user).await?
            {
                return Ok(true); // already responded with auth/signature error
            }

            responses::respond_not_implemented(session, message, Some(req.uri.path()), None)
                .await?;
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

        // 4) Worker not running: verify header-only before spawn (unless
        //    the ACL pre-check in 2a already verified for this request).
        if !sigv4_validated
            && validate_sigv4_header_only_or_reject(session, &req, &user).await?
        {
            return Ok(true); // already responded with auth/signature error, no spawn
        }

        // 5) Start worker on demand (profile-specific)
        let buckets = self.directory.buckets_for_access_key(&access_key).await.map_err(|e| {
            Error::explain(ErrorType::InternalError, format!("directory buckets error: {e:#}"))
        })?;

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
        let ep = ctx
            .upstream
            .clone()
            .ok_or_else(|| Error::explain(ErrorType::InternalError, "no upstream selected"))?;

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
                let peer = HttpPeer::new_uds(
                    path.to_string_lossy().as_ref(),
                    false,
                    "localhost".to_string(),
                )
                .map_err(|e| {
                    Error::explain(ErrorType::InternalError, format!("new_uds failed: {e}"))
                })?;

                // TCP-only socket options don't apply to UDS; leave options default.
                peer
            }
        };

        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
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

        // Stamp client IP onto the upstream request so the gateway can log it.
        // We *replace* any client-supplied X-Forwarded-For — clients shouldn't
        // be sending it, and trusting it would let them spoof the peer. Safe
        // for SigV4: AWS SDKs don't include x-forwarded-for in SignedHeaders,
        // so the worker's re-validation is unaffected.
        if let Some(addr) = session.client_addr() {
            // SocketAddr's Display includes the port for Inet variants ("ip:port");
            // strip it so the header is just the IP. Pingora's wrapper covers
            // both inet and unix; for unix sockets we just record "unix".
            let ip = addr
                .as_inet()
                .map(|sa| sa.ip().to_string())
                .unwrap_or_else(|| "unix".to_string());
            upstream_request.insert_header("X-Forwarded-For", ip)?;
        } else {
            upstream_request.remove_header("x-forwarded-for");
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
        upstream_response.insert_header("Server", "s32p-proxy")?;
        upstream_response.remove_header("alt-svc");
        Ok(())
    }

    async fn logging(
        &self,
        session: &mut Session,
        e: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) {
        let status = session.response_written().map(|r| r.status.as_u16()).unwrap_or(0);
        let client = session
            .client_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "<unknown>".to_string());

        if let Some(err) = e {
            tracing::warn!(
                client = %client,
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
                client = %client,
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

/// True for HTTP methods that mutate state on S3.
///
/// PUT/POST/DELETE cover every write operation in the S3 surface s32p
/// implements. The one S3 op that's a POST-but-read is `SelectObjectContent`
/// (`POST /key?select`), which s32p doesn't classify or implement; if it's
/// added later, this predicate has to grow a query-param exception so a
/// read_only caller can still issue Select.
fn needs_write(method: &str) -> bool {
    matches!(method, "PUT" | "POST" | "DELETE")
}

/// Look up the caller's effective access level on a single bucket.
///
/// Walks the directory's `buckets_for_access_key` view, which already
/// folds together access-key + group grants and applies the documented
/// max-of-principals rule. Returns:
///   - `Some(level)` if the caller has any grant on the bucket
///   - `None` if the caller has no matching grant (and so the bucket
///     should be invisible to them)
async fn bucket_access_for_caller(
    directory: &dyn Directory,
    access_key: &str,
    bucket_name: &str,
) -> Result<Option<AccessLevel>> {
    let buckets = directory.buckets_for_access_key(access_key).await?;
    Ok(buckets
        .into_iter()
        .find(|b| b.bucket_name == bucket_name)
        .map(|b| b.access))
}

async fn validate_sigv4_header_only_or_reject(
    session: &mut Session,
    req: &RequestHeader,
    user: &UserDoc,
) -> PResult<bool> {
    match s32p_support::verify_sigv4_request_any(
        req.method.as_str(),
        &req.uri,
        &req.headers,
        None, // proxy already selected `user` based on extracted access key
        &user.secret_key,
        Some(req.uri.path()),
    ) {
        Ok(()) => Ok(false),
        Err(rej) => {
            let client = session
                .client_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|| "<unknown>".to_string());
            tracing::debug!(
                client = %client,
                method = req.method.as_str(),
                path = req.uri.path(),
                query = req.uri.query().unwrap_or(""),
                username = user.username.as_str(),
                status = rej.response.status().as_u16(),
                reason = %rej.reason,
                "proxy sigv4 verification rejected request (pre-spawn gate)"
            );
            responses::respond_hyper(session, rej.response, /* close = */ true).await?;
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

    CryptoProvider::install_default(provider)
        .expect("Failed to install aws-lc-rs as default TLS provider");
    Ok(())
}

fn main() -> Result<()> {
    // ensure, that aws-lc-rs is our crypto provider
    // aws_lc_rs::default_provider().install_default().expect("Failed to install aws-lc-rs as default TLS provider");
    rustls_prefer_fast_cipher().unwrap();

    let cli = Cli::parse();

    // Load config first to get log level from config file
    let mut cfg = config::Config::from_path(&cli.config)?;

    // Resolve placeholders in the config (e.g., {{install_bin_dir}})
    // Determine the install_bin_dir: use the directory of the current executable
    let install_bin_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "target/debug".to_string());
    cfg.resolve_placeholders(&install_bin_dir)?;

    // Determine log level: config file takes precedence, then RUST_LOG env var, then default
    let log_filter = if let Some(log_level) = &cfg.server.log_level {
        log_level.clone()
    } else {
        std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string())
    };

    // Local-time formatter; offset is taken from libc's localtime_r so it
    // works even if a background thread already exists (e.g. allocator).
    let timer = tracing_subscriber::fmt::time::OffsetTime::new(
        s32p_support::utils::local_utc_offset(),
        time::format_description::well_known::Rfc3339,
    );
    tracing_subscriber::fmt().with_timer(timer).with_env_filter(log_filter).init();

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
        workers: workers.clone(),
        routing: cfg.routing.clone(),
        virtual_hosted_suffixes: cfg.server.virtual_hosted_suffixes.clone(),
    };

    let pingora_conf = ServerConf {
        grace_period_seconds: Some(cfg.server.shutdown_grace_period_secs),
        ..ServerConf::default()
    };
    let mut server = Server::new_with_opt_and_conf(None, pingora_conf);
    server.bootstrap();

    let mut proxy = http_proxy_service(&server.configuration, app);

    if cfg.server.public_scheme == "https" {
        let mut tls_settings = TlsSettings::intermediate(
            cfg.server.tls_cert_path.as_ref().unwrap(),
            cfg.server.tls_key_path.as_ref().unwrap(),
        )
        .context("failed to load TLS settings (check certificate/key paths and format)")?;
        tls_settings.enable_h2();
        proxy.add_tls_with_settings(&cfg.server.listen, None, tls_settings);
        tracing::info!("TLS enabled, listening on {}", listen);
    } else {
        proxy.add_tcp(&listen);
        tracing::info!("TLS disabled, listening on {}", listen);
    }

    server.add_service(proxy);
    server.add_service(background_service("worker-shutdown", WorkerShutdownService { workers }));
    server.run_forever();
}
