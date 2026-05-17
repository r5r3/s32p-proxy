use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use std::{fs, path::PathBuf, sync::Arc, time::{Duration, Instant}};

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
mod session;
mod worker_manager;

use s32p_directory::{Directory, UserDoc, openbao::OpenBaoDirectory, yaml::YamlDirectory};
use s32p_support;
use session::{SessionMode, SessionStore};
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
    sessions:                Arc<SessionStore>,
    session_ttl:             Duration,
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
    uid:               Option<u32>,
    username:          Option<String>,
    // Preserve original host EXACTLY (important for SigV4 verification in worker)
    orig_host:         Option<String>,
    // Selected worker profile (used as part of worker key)
    worker_profile:    Option<String>,
    // Selected upstream (per-user worker)
    upstream:          Option<WorkerEndpoint>,
    // Optional handle (for touch/logging)
    worker:            Option<Arc<WorkerHandle>>,
    // True when the proxy validated this request using a session credential
    // (rather than long-term creds). `upstream_request_filter` uses this to
    // inject `X-S32P-Validated: <worker_token>` so the gateway short-circuits
    // its own SigV4 re-check.
    session_validated: bool,
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
        // Start background sweepers lazily (we are now inside tokio).
        self.workers.start_sweeper();
        self.sessions.start_cleanup();

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

        // SECURITY: strip any client-supplied trust header. Only the proxy
        // itself is allowed to inject this in `upstream_request_filter`; a
        // request arriving with it from the public listener is either
        // confused (proxy chain?) or hostile (spoof attempt).
        session.req_header_mut().remove_header("x-s32p-validated");

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

        // 2) Resolve access_key → user. Check the session store first: an
        // ephemeral session credential pre-empts the long-term Directory
        // lookup. SigV4 validation (with the ephemeral secret) happens here
        // too because the worker can't redo it later — workers don't have a
        // Directory and can't see the session store.
        let (user, session_validated) = if let Some(entry) = self.sessions.lookup(&access_key) {
            // Validate the session token bound at mint time. AWS S3 Express
            // sends it as `x-amz-s3session-token` on every data-plane request;
            // we require an exact, constant-time match against the value we
            // stored. This is the second factor on top of the ephemeral
            // secret: an attacker who scraped the access key from a log but
            // never saw the token cannot use the session.
            //
            // Checked before bucket/SigV4 so a probing caller cannot
            // distinguish "valid session, wrong everything else" from any
            // other 403 via the response — all session-bound rejections
            // share the same generic AccessDenied shape.
            let provided_token = req
                .headers
                .get("x-amz-s3session-token")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let token_ok = provided_token.len() == entry.session_token.len()
                && constant_time_eq::constant_time_eq(
                    provided_token.as_bytes(),
                    entry.session_token.as_bytes(),
                );
            if !token_ok {
                tracing::debug!(
                    real_access_key = entry.real_access_key.as_str(),
                    token_present = !provided_token.is_empty(),
                    "session-token validation failed; rejecting"
                );
                responses::respond_s3_error(
                    session,
                    StatusCode::FORBIDDEN,
                    responses::error_code::ACCESS_DENIED,
                    "Access Denied",
                    Some(req.uri.path()),
                    None,
                )
                .await?;
                return Ok(true);
            }

            // Cross-bucket scope. A session minted for bucket A must not be
            // accepted on bucket B. The response is a generic AccessDenied:
            // a probing caller must not be able to distinguish "valid session,
            // wrong bucket" from any other 403 via the message body.
            if class.bucket.as_deref() != Some(entry.bucket.as_str()) {
                tracing::debug!(
                    session_bucket = entry.bucket.as_str(),
                    request_bucket = class.bucket.as_deref().unwrap_or("<none>"),
                    real_access_key = entry.real_access_key.as_str(),
                    "session credentials replayed against a different bucket; rejecting"
                );
                responses::respond_s3_error(
                    session,
                    StatusCode::FORBIDDEN,
                    responses::error_code::ACCESS_DENIED,
                    "Access Denied",
                    Some(req.uri.path()),
                    None,
                )
                .await?;
                return Ok(true);
            }

            // ReadOnly session: reject writes (proxy-side enforcement; the
            // worker can't tell ReadOnly from ReadWrite — they have the same
            // SigV4 shape — so this check must live here).
            if matches!(entry.mode, SessionMode::ReadOnly) && class.op.needs_write() {
                responses::respond_s3_error(
                    session,
                    StatusCode::FORBIDDEN,
                    responses::error_code::ACCESS_DENIED,
                    "session is ReadOnly; write operations are not permitted",
                    Some(req.uri.path()),
                    None,
                )
                .await?;
                return Ok(true);
            }

            // Re-check the real user via Directory every request. If the
            // operator revoked the long-term identity since the session was
            // minted, the session must die with it.
            let real_user = match self
                .directory
                .user_by_access_key(&entry.real_access_key)
                .await
                .map_err(|e| {
                    Error::explain(ErrorType::InternalError, format!("directory error: {e:#}"))
                })? {
                Some(u) => u,
                None => {
                    self.sessions.invalidate(&access_key);
                    responses::respond_s3_error(
                        session,
                        StatusCode::FORBIDDEN,
                        responses::error_code::ACCESS_DENIED,
                        "session owner has been removed",
                        Some(req.uri.path()),
                        None,
                    )
                    .await?;
                    return Ok(true);
                }
            };

            // Validate SigV4 with the *ephemeral* secret bound to this
            // session. Same verifier as the long-term path; only the secret
            // differs.
            match s32p_support::verify_sigv4_request_any(
                req.method.as_str(),
                &req.uri,
                &req.headers,
                None,
                &entry.secret_key,
                Some(req.uri.path()),
            ) {
                Ok(()) => {}
                Err(rej) => {
                    tracing::debug!(
                        method = req.method.as_str(),
                        path = req.uri.path(),
                        reason = %rej.reason,
                        "session-signed request rejected at proxy SigV4 check"
                    );
                    responses::respond_hyper(session, rej.response, true).await?;
                    return Ok(true);
                }
            }

            (real_user, true)
        } else {
            // Long-term credentials: standard Directory lookup.
            match self.directory.user_by_access_key(&access_key).await.map_err(|e| {
                Error::explain(ErrorType::InternalError, format!("directory error: {e:#}"))
            })? {
                Some(u) => (u, false),
                None => {
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
            }
        };
        ctx.set_user(&user);
        ctx.session_validated = session_validated;

        // 2a) If routing says NotImplemented: validate SigV4 first (unless we
        // already validated via session), then reply with NotImplemented.
        // Validating up front prevents unauthenticated callers from probing
        // the routing table.
        if let config::RouteAction::NotImplemented { message } = action {
            if !session_validated
                && validate_sigv4_header_only_or_reject(session, &req, &user).await?
            {
                return Ok(true); // already responded with auth/signature error
            }

            responses::respond_not_implemented(session, message, Some(req.uri.path()), None)
                .await?;
            return Ok(true);
        }

        // 2a') CreateSession: mint an ephemeral session for the caller, return
        // the AWS-shaped XML credentials. Sessions can't beget sessions —
        // CreateSession must be driven with long-term IAM creds.
        if let config::RouteAction::CreateSession = action {
            if session_validated {
                responses::respond_s3_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    responses::error_code::INVALID_REQUEST,
                    "CreateSession requires long-term credentials",
                    Some(req.uri.path()),
                    None,
                )
                .await?;
                return Ok(true);
            }
            if validate_sigv4_header_only_or_reject(session, &req, &user).await? {
                return Ok(true);
            }

            let bucket = match class.bucket.as_deref() {
                Some(b) if !b.is_empty() => b.to_string(),
                _ => {
                    responses::respond_s3_error(
                        session,
                        StatusCode::BAD_REQUEST,
                        responses::error_code::INVALID_REQUEST,
                        "CreateSession requires a bucket",
                        Some(req.uri.path()),
                        None,
                    )
                    .await?;
                    return Ok(true);
                }
            };

            let mode = SessionMode::from_header(
                req.headers.get("x-amz-create-session-mode").and_then(|v| v.to_str().ok()),
            );

            let entry = match self
                .sessions
                .create(&user.access_key, &bucket, mode, self.session_ttl)
            {
                Some(e) => e,
                None => {
                    responses::respond_s3_error(
                        session,
                        StatusCode::SERVICE_UNAVAILABLE,
                        responses::error_code::SERVICE_UNAVAILABLE,
                        "session store is at capacity",
                        Some(req.uri.path()),
                        None,
                    )
                    .await?;
                    return Ok(true);
                }
            };

            let body = s32p_support::s3xml::create_session_result_body(
                &entry.access_key,
                &entry.secret_key,
                &entry.session_token,
                entry.expires_at_system,
            )
            .map_err(|e| Error::explain(ErrorType::InternalError, format!("xml: {e}")))?;

            let resp =
                s32p_support::s3resp::response_bytes(StatusCode::OK, "application/xml", body, []);
            responses::respond_hyper(session, resp, /* close = */ false).await?;
            return Ok(true);
        }

        // 2b) Routing says Proxy: select worker profile
        let profile = match action {
            config::RouteAction::Proxy { worker_profile } => worker_profile.as_str(),
            config::RouteAction::NotImplemented { .. } | config::RouteAction::CreateSession => {
                unreachable!()
            }
        };
        ctx.worker_profile = Some(profile.to_string());

        // 3) If worker already running: NO proxy-side SigV4 verify (just route).
        // Applies to both reads and writes: the worker re-validates SigV4 on
        // every request and now also enforces bucket-ACL access levels using
        // the snapshot the proxy stages into S32P_BUCKET_ACL at spawn (see
        // `worker_manager::format_bucket_acl`).
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

        // 4) Worker not running: verify header-only before spawn (anti-DoS gate).
        // Skip if we already validated via session credentials above; sessions
        // sign with `s3express` and a different secret, which the long-term
        // path would reject.
        if !session_validated && validate_sigv4_header_only_or_reject(session, &req, &user).await? {
            return Ok(true); // already responded with auth/signature error, no spawn
        }

        // 5) Start worker on demand (profile-specific)
        // For session-validated requests, `access_key` is the ephemeral key
        // (not in the Directory). Look up buckets via `user.access_key`,
        // which we resolved to the real long-term identity earlier.
        let buckets =
            self.directory.buckets_for_access_key(&user.access_key).await.map_err(|e| {
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

        // If this request authenticated via a session credential, hand the
        // worker its own per-spawn token so it can skip SigV4 re-validation.
        // The trust chain is: (a) connection is loopback/UDS, (b) header
        // present, (c) value matches the worker's env-loaded
        // `S32P_WORKER_TOKEN`. All three are checked in the gateway.
        if ctx.session_validated
            && let Some(handle) = ctx.worker.as_ref()
        {
            upstream_request.insert_header("X-S32P-Validated", handle.worker_token.as_str())?;
        }

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
    let inner_directory: Arc<dyn Directory> = match cfg.auth.backend {
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

    // Optional TTL cache in front of the directory backend.
    //
    // Default-on for OpenBao (every uncached request hits Vault); off for
    // YAML (lookups are an in-memory HashMap clone — caching just adds a
    // lock cost). The user can flip either default by setting
    // `auth.cache.enabled` explicitly in YAML.
    let cache_enabled = cfg
        .auth
        .cache
        .enabled
        .unwrap_or(matches!(cfg.auth.backend, config::AuthBackend::OpenBao));
    let directory: Arc<dyn Directory> = if cache_enabled {
        let cache_cfg = s32p_directory::CacheConfig {
            user_ttl:     std::time::Duration::from_secs(cfg.auth.cache.user_ttl_secs),
            buckets_ttl:  std::time::Duration::from_secs(cfg.auth.cache.buckets_ttl_secs),
            negative_ttl: std::time::Duration::from_secs(cfg.auth.cache.negative_ttl_secs),
            max_entries:  cfg.auth.cache.max_entries,
        };
        tracing::info!(
            backend = ?cfg.auth.backend,
            user_ttl_secs = cfg.auth.cache.user_ttl_secs,
            buckets_ttl_secs = cfg.auth.cache.buckets_ttl_secs,
            negative_ttl_secs = cfg.auth.cache.negative_ttl_secs,
            max_entries = cfg.auth.cache.max_entries,
            "directory cache enabled"
        );
        Arc::new(s32p_directory::CachingDirectory::new(inner_directory, cache_cfg))
    } else {
        tracing::info!(
            backend = ?cfg.auth.backend,
            "directory cache disabled"
        );
        inner_directory
    };

    let listen = cfg.server.listen.clone();

    let workers = WorkerManager::new(cfg.workers.clone(), cfg.server.clone());

    let sessions = Arc::new(SessionStore::new(
        cfg.session.max_active,
        Duration::from_secs(cfg.session.cleanup_interval_secs),
    ));
    // Cleanup task is started lazily from request_filter (same pattern as
    // WorkerManager::start_sweeper) — pingora's Server::bootstrap() runs
    // before the tokio runtime exists, so we can't spawn here.
    tracing::info!(
        ttl_secs = cfg.session.ttl_secs,
        cleanup_interval_secs = cfg.session.cleanup_interval_secs,
        max_active = cfg.session.max_active,
        "session store initialized"
    );

    let app = S3ProxyApp {
        directory,
        workers: workers.clone(),
        sessions,
        session_ttl: Duration::from_secs(cfg.session.ttl_secs),
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
