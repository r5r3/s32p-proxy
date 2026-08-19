use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

pub mod buffer;
mod fs_helpers;
mod idempotency;
mod multipart;
mod nss_client;
pub mod streaming;
mod uring_io;

#[cfg(feature = "lustre")]
mod lustre;

use std::{
    collections::HashMap,
    convert::Infallible,
    fs, io,
    os::unix::fs::{FileExt, MetadataExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};

use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use dashmap::DashMap;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use httpdate::fmt_http_date;
use hyper::{HeaderMap, body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use s32p_support::{
    self,
    preconditions::{
        PreconditionOutcome, evaluate_copy_source_preconditions, evaluate_read_preconditions,
        evaluate_write_preconditions, parse_conditional_headers,
    },
    utils::{ByteRange, parse_ranges_header},
};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, UnixListener};

/// Direct connection peer captured at accept time. Used to (a) decide whether
/// to trust the `X-Forwarded-For` stamped by s32p-proxy (only when the peer is
/// loopback or UDS) and (b) provide a usable client identity in standalone
/// deployments where no proxy fronts the gateway.
#[derive(Debug, Clone)]
enum PeerAddr {
    Tcp(std::net::SocketAddr),
    Unix,
}

impl PeerAddr {
    fn is_local(&self) -> bool {
        match self {
            PeerAddr::Tcp(sa) => sa.ip().is_loopback(),
            PeerAddr::Unix => true,
        }
    }

    fn client_label(&self) -> String {
        match self {
            PeerAddr::Tcp(sa) => sa.ip().to_string(),
            PeerAddr::Unix => "unix".to_string(),
        }
    }
}

#[cfg(feature = "lustre")]
use crate::fs_helpers::stripe_count_for_size;
use crate::{
    buffer::{BufPool, PooledBuf, SliceOwner},
    fs_helpers::{
        LustreStriping, OpenDirect, OpenMode, bucket_exists_dir, bucket_root_path, flock_exclusive,
        join_object_path, open_file, probe_user_xattrs_supported, read_content_type, read_tags,
        read_user_meta, remove_tags, statx_info, write_content_type, write_tags, write_user_meta,
    },
    streaming::{
        StreamCfg, WriteObjectDest, copy_file_to_file, stream_multirange_body, stream_range_body,
        write_object_body,
    },
    uring_io::UringIO,
};

type Resp = s32p_support::s3resp::HttpResponse;

// ---- config ----

/// Effective per-bucket access level snapshotted at worker spawn.
/// The proxy passes this in via `S32P_BUCKET_ACL`; buckets not listed
/// (and the env var being absent entirely) default to `ReadWrite`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AclLevel {
    ReadOnly,
    ReadWrite,
}

#[derive(Clone)]
struct Cfg {
    bind_addr:               String,
    bind_uds:                Option<PathBuf>,
    posix_root:              PathBuf,
    access_key:              String,
    secret_key:              String,
    public_scheme:           String,
    region:                  String,
    chunk_size:              usize,
    inflight:                usize,
    pool_size:               usize,
    direct_io:               bool,
    copy_max_size:           u64,
    mpu_dir_name:            String,
    #[cfg(feature = "lustre")]
    lustre_max_stripe_count: u32,
    virtual_hosted_suffixes: Vec<String>,
    /// Per-spawn secret shared with the proxy. The proxy attaches it as
    /// `X-S32P-Validated: <worker_token>` when forwarding a session-validated
    /// request; the worker uses the comparison to short-circuit SigV4
    /// re-validation (which is impossible against session-signed requests
    /// because the worker has no directory access to the ephemeral secret).
    /// Loaded from env `S32P_WORKER_TOKEN`; fatal at startup if missing.
    worker_token:            String,
    /// Snapshot of per-bucket access levels, supplied by the proxy via
    /// `S32P_BUCKET_ACL`. Entries are looked up by bucket name; absence
    /// (or absence of the env var entirely) means `ReadWrite` — that
    /// preserves the historical worker behavior when the proxy doesn't
    /// pre-stage ACL state.
    bucket_acl:              HashMap<String, AclLevel>,
}

fn env_bool(k: &str, default: bool) -> bool {
    match std::env::var(k).ok().as_deref() {
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES") => true,
        Some("0") | Some("false") | Some("FALSE") | Some("no") | Some("NO") => false,
        Some(_) => default,
        None => default,
    }
}

fn env_usize(k: &str, default: usize) -> usize {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// True iff `name` matches the S3 bucket-name charset (lowercase letters,
/// digits, `.`, `-`). This is *not* a full S3 bucket-name validator (no
/// length check, no rules about leading/trailing chars, no `..` rule) —
/// just a charset gate so a malformed `S32P_BUCKET_ACL` value can't smuggle
/// `,` or `:` into a name and silently shift the entry boundary.
fn is_s3_bucket_name_charset(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
}

/// Parse `S32P_BUCKET_ACL=foo:rw,bar:ro,baz:rw` into a name → level map.
///
/// Per-entry parse failures (missing `:`, unknown access value, name fails
/// the S3 charset check) are skipped with a warning log, leaving the
/// affected bucket to fall back to the default-rw rule. Empty input yields
/// an empty map. Bucket name is preserved verbatim (no case folding); S3
/// bucket names are required to be lowercase by spec, and the proxy emits
/// them as-is.
fn parse_bucket_acl(raw: &str) -> HashMap<String, AclLevel> {
    let mut out = HashMap::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some((name, level)) = entry.split_once(':') else {
            tracing::warn!(entry = %entry, "S32P_BUCKET_ACL: entry missing ':' separator, skipping");
            continue;
        };
        let name = name.trim();
        let level = level.trim();
        if !is_s3_bucket_name_charset(name) {
            tracing::warn!(entry = %entry, "S32P_BUCKET_ACL: bucket name fails S3 charset, skipping");
            continue;
        }
        let parsed = match level {
            "ro" => AclLevel::ReadOnly,
            "rw" => AclLevel::ReadWrite,
            other => {
                tracing::warn!(
                    entry = %entry, level = %other,
                    "S32P_BUCKET_ACL: unknown access level (expected ro|rw), skipping"
                );
                continue;
            }
        };
        out.insert(name.to_string(), parsed);
    }
    out
}

fn load_cfg() -> Result<Cfg> {
    let bind_addr = std::env::var("S32P_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:0".to_string());
    let bind_uds = std::env::var("S32P_BIND_UDS").ok().map(PathBuf::from);
    let posix_root =
        PathBuf::from(std::env::var("S32P_POSIX_ROOT").context("S32P_POSIX_ROOT missing")?);

    let access_key = std::env::var("AWS_ACCESS_KEY_ID").context("AWS_ACCESS_KEY_ID missing")?;
    let secret_key =
        std::env::var("AWS_SECRET_ACCESS_KEY").context("AWS_SECRET_ACCESS_KEY missing")?;

    let public_scheme = std::env::var("S32P_PUBLIC_SCHEME").unwrap_or_else(|_| "http".to_string());
    let region = std::env::var("S32P_REGION").unwrap_or_else(|_| "us-east-1".to_string());

    let chunk_size = env_usize("S32P_CHUNK_SIZE_MB", 4) * 1024 * 1024;
    let inflight = env_usize("S32P_INFLIGHT", 16).max(1);

    let pool_size_default = inflight.saturating_mul(8).max(1);
    let pool_size = env_usize("S32P_POOL_SIZE", pool_size_default).max(1);

    let direct_io = env_bool("S32P_DIRECT_IO", false);

    // CopyObject single-request size limit (AWS default is 5GB; larger requires multipart copy).
    let copy_max_size_gb = env_usize("S32P_COPY_MAX_SIZE_GB", 5).max(1);
    let copy_max_size = (copy_max_size_gb as u64).saturating_mul(1024u64 * 1024u64 * 1024u64);

    // upload directory for multipart uploads
    let mpu_dir_name = std::env::var("S32P_MPU_DIR").unwrap_or_else(|_| ".s32p-mpu".to_string());
    if mpu_dir_name.is_empty()
        || mpu_dir_name == "."
        || mpu_dir_name == ".."
        || mpu_dir_name.contains('/')
        || mpu_dir_name.contains('\\')
    {
        return Err(anyhow!(
            "invalid S32P_MPU_DIR={mpu_dir_name:?} (must be a single path component)"
        ));
    }

    // Maximum Lustre stripe count (only effective with --features lustre)
    #[allow(unused_variables)]
    let lustre_max_stripe_count = env_usize("S32P_LUSTRE_MAX_STRIPE_COUNT", 4).max(1) as u32;

    // Load virtual hosted suffixes from environment variable.
    // An unset OR empty env var, or a value of only commas/whitespace, must yield an empty Vec —
    // a bare "".split(',') returns vec![""], and an empty suffix matches every host
    // (host.ends_with("") is always true), which would mis-classify all path-style requests.
    let virtual_hosted_suffixes: Vec<String> = std::env::var("S32P_VIRTUAL_HOSTED_SUFFIXES")
        .ok()
        .map(|s| s.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();

    // Per-bucket ACL snapshot from the proxy. Absent/empty → empty map →
    // every bucket the worker sees is treated as read_write (legacy
    // behavior preserved when paired with an older proxy).
    let bucket_acl = std::env::var("S32P_BUCKET_ACL")
        .ok()
        .map(|s| parse_bucket_acl(&s))
        .unwrap_or_default();

    // Per-spawn token shared with the proxy. Optional: if absent or empty
    // (e.g. running under an older proxy, a manual invocation for
    // debugging, or a custom wrapper), the session short-circuit is
    // disabled entirely. `require_sigv4` ignores `X-S32P-Validated` in
    // that mode and falls through to standard SigV4 — sessions just won't
    // work end-to-end, but normal long-term-credential traffic does.
    let worker_token = std::env::var("S32P_WORKER_TOKEN").unwrap_or_default();

    Ok(Cfg {
        bind_addr,
        bind_uds,
        posix_root,
        access_key,
        secret_key,
        public_scheme,
        region,
        chunk_size,
        inflight,
        pool_size,
        direct_io,
        copy_max_size,
        mpu_dir_name,
        #[cfg(feature = "lustre")]
        lustre_max_stripe_count,
        virtual_hosted_suffixes,
        bucket_acl,
        worker_token,
    })
}

// ---- request handler ----

struct App {
    cfg:                     Arc<Cfg>,
    pool:                    Arc<BufPool>,
    uring:                   Arc<UringIO>,
    virtual_hosted_suffixes: Vec<String>,
    /// Per-worker idempotency cache for `x-amz-client-token` on
    /// RenameObject. See `idempotency.rs`.
    idempotency:             Arc<idempotency::IdempotencyCache>,
    /// Resolves uid → username for listing/ACL `DisplayName` fields.
    /// Connects to the proxy's abstract NSS lookup socket when the
    /// `S32P_NSS_PROXY_SOCK` env is set; otherwise falls back to a direct
    /// `getpwuid_r` call (only useful when running standalone without
    /// Landlock). See `nss_client.rs`.
    nss_client:              Arc<nss_client::NssClient>,
    /// Per-device cache of `user.*` xattr support, populated lazily on
    /// first tagging request that touches a given mount. Key is the
    /// device id from `MetadataExt::dev()`. Used to fail-fast on
    /// tagging writes (PutObjectTagging, x-amz-tagging on PutObject,
    /// etc.) when the backing filesystem doesn't support extended
    /// attributes — without that gate, a PutObject would stream the
    /// body, then discover `ENOTSUP` from setxattr after the object
    /// landed.
    xattr_support:           DashMap<u64, bool>,
}

/// Look up whether `path`'s filesystem supports `user.*` xattrs, using
/// the per-device cache on `App`. On cache miss, probes via
/// `probe_user_xattrs_supported` (a `listxattr` syscall — read-only,
/// no write permission required). Bubbles I/O errors other than the
/// canonical "no xattr support" errnos so callers don't mis-attribute
/// permission/quota failures as missing FS capability.
fn user_xattrs_supported_for(app: &App, probe_path: &Path) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let dev = std::fs::metadata(probe_path)?.dev();
    if let Some(v) = app.xattr_support.get(&dev) {
        return Ok(*v);
    }
    let supported = probe_user_xattrs_supported(probe_path)?;
    app.xattr_support.insert(dev, supported);
    Ok(supported)
}

/// Resolve the Content-Type and user metadata that HEAD/GET should report
/// for `obj_path`. Implements the documented fallback ladder:
///
/// 1. `user.s32p.content_type` xattr (explicit, set by PutObject).
/// 2. `user.mime_type` xattr (freedesktop standard, set by POSIX desktop
///    tooling — read-only POSIX-interop).
/// 3. `mime_guess::from_path(...).first_raw()` — extension map, zero-I/O.
/// 4. `application/octet-stream` (the existing default).
///
/// User metadata is read from `user.s32p.meta` and decoded into ordered
/// pairs. Both xattr reads gracefully degrade to "absent" on filesystems
/// without `user.*` support (matches the POSIX-created file case).
fn resolve_object_headers(obj_path: &Path) -> (String, Vec<(String, String)>) {
    let content_type = read_content_type(obj_path)
        .ok()
        .flatten()
        .or_else(|| mime_guess::from_path(obj_path).first_raw().map(str::to_string))
        .unwrap_or_else(|| s32p_support::s3resp::OBJECT_CONTENT_TYPE.to_string());
    let user_meta_urlform = read_user_meta(obj_path).unwrap_or_default();
    let user_meta: Vec<(String, String)> =
        url::form_urlencoded::parse(user_meta_urlform.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
    (content_type, user_meta)
}

pub(crate) fn is_reserved_first_segment(key_or_prefix: &str, mpu_dir_name: &str) -> bool {
    // We reserve keys whose FIRST path segment is exactly mpu_dir_name.
    // Examples that match:
    //   ".s32p-mpu"
    //   ".s32p-mpu/"
    //   ".s32p-mpu/anything"
    // Examples that do NOT match:
    //   "foo/.s32p-mpu/bar"
    let key_or_prefix = key_or_prefix.trim_end_matches('/');

    if key_or_prefix == mpu_dir_name {
        return true;
    }
    key_or_prefix
        .strip_prefix(mpu_dir_name)
        .is_some_and(|rest| rest.starts_with('/'))
}

async fn read_small(
    file: Arc<std::fs::File>,
    pool: Arc<BufPool>,
    off: u64,
    len: usize,
) -> Result<Bytes> {
    let pooled = pool.acquire().await.map_err(|_| anyhow!("buffer pool closed"))?;

    let (n, pooled) = tokio::task::spawn_blocking(move || -> anyhow::Result<(usize, PooledBuf)> {
        let mut pooled = pooled;
        let dst = &mut pooled.as_mut_bytes()[..len];
        let n = file
            .read_at(dst, off)
            .map_err(|e| anyhow!("read_at failed at off={off}: {e}"))?;
        Ok((n, pooled))
    })
    .await
    .map_err(|e| anyhow!("read task join error: {e}"))??;

    if n == 0 {
        return Err(anyhow!("unexpected EOF"));
    }

    Ok(Bytes::from_owner(SliceOwner::new(pooled, 0, n)))
}

async fn handle(
    req: Request<Incoming>,
    app: Arc<App>,
    peer: Option<PeerAddr>,
) -> Result<Resp, Infallible> {
    // Lazy-start background sweepers. `start_cleanup` no-ops after the
    // first call (compare_exchange). Doing it here means the tokio
    // runtime is up; the gateway's `main` runs before the runtime.
    app.idempotency.start_cleanup();

    let method = req.method().clone();
    // SigV4 signature and STS token are truncated to an 8-char prefix
    // (cryptographically useless, still useful for correlating log
    // lines). Other `X-Amz-*` params pass through verbatim.
    let uri_log = s32p_support::log_redact::redact_uri_for_log(req.uri());
    let host_log = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("<missing>")
        .to_string();
    let user_agent_log = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("<missing>")
        .to_string();
    // Pick the "client IP" to log:
    //   - direct peer is loopback (or UDS) → trust X-Forwarded-For from the
    //     fronting s32p-proxy, fall back to the peer label if it's missing
    //   - direct peer is a real network address → use the peer; ignore XFF
    //     (a direct client could otherwise spoof their source)
    let xff = req.headers().get("x-forwarded-for").and_then(|v| v.to_str().ok());
    let client_log = match peer.as_ref() {
        Some(p) if p.is_local() => xff.map(str::to_string).unwrap_or_else(|| p.client_label()),
        Some(p) => p.client_label(),
        None => xff.unwrap_or("<unknown>").to_string(),
    };

    let class = s32p_support::classifier::classify_with_headers(
        req.method().as_str(),
        req.uri(),
        Some(req.headers()),
        &app.virtual_hosted_suffixes,
    );

    tracing::debug!(
        client = %client_log,
        method = %method,
        uri = %uri_log,
        host = %host_log,
        user_agent = user_agent_log.as_str(),
        op = ?class.op,
        bucket = ?class.bucket,
        key = ?class.key,
        "incoming request"
    );

    // All actions require authentication
    let cfg = app.cfg.clone();
    if let Err(rej) = require_sigv4(&req, &cfg, peer.as_ref()) {
        tracing::debug!(
            client = %client_log,
            method = %method,
            uri = %uri_log,
            host = %host_log,
            user_agent = user_agent_log.as_str(),
            status = rej.response.status().as_u16(),
            reason = %rej.reason,
            "sigv4 verification failed"
        );
        return Ok(rej.response);
    }

    // ACL access-level enforcement. The proxy stages this access key's
    // bucket→level map into S32P_BUCKET_ACL at spawn; any bucket not in
    // the map (or an absent map entirely) defaults to read_write — that
    // keeps a fresh worker behaving exactly as before when the proxy
    // doesn't send the snapshot. ListBuckets has no bucket and is
    // exempted by `class.bucket.is_none()`. Visibility (no-grant) is
    // already enforced by the staged posix_root, so the only check left
    // here is "write against a known-read_only bucket".
    if class.op.needs_write()
        && let Some(bucket_name) = class.bucket.as_deref()
        && matches!(cfg.bucket_acl.get(bucket_name), Some(AclLevel::ReadOnly))
    {
        tracing::info!(
            client = %client_log,
            access_key = cfg.access_key.as_str(),
            bucket = bucket_name,
            method = %method,
            "rejecting write on read_only-granted bucket"
        );
        return Ok(s32p_support::s3resp::access_denied("access denied", Some(req.uri().path())));
    }

    // `x-amz-write-offset-bytes` is only valid on PutObject. Reject up
    // front on every other route so a stray header can't reach
    // CopyObject / UploadPart / DeleteObject / etc. and silently get
    // ignored.
    if req.headers().contains_key("x-amz-write-offset-bytes")
        && !matches!(
            class.op,
            s32p_support::classifier::S3Op::Write(s32p_support::classifier::WriteOp::PutObject)
        )
    {
        return Ok(s32p_support::s3resp::s3_error(
            http::StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_ARGUMENT,
            "x-amz-write-offset-bytes is only valid on PutObject",
            Some(req.uri().path()),
            None,
        ));
    }

    let resp = match &class.op {
        s32p_support::classifier::S3Op::Read(s32p_support::classifier::ReadOp::ListBuckets) => {
            handle_list_buckets(req, app, &class).await
        }
        s32p_support::classifier::S3Op::Read(
            s32p_support::classifier::ReadOp::GetBucketLocation,
        ) => handle_get_bucket_location(req, app, &class).await,
        s32p_support::classifier::S3Op::Read(s32p_support::classifier::ReadOp::HeadBucket) => {
            handle_head_bucket(req, app, &class).await
        }
        s32p_support::classifier::S3Op::Read(s32p_support::classifier::ReadOp::GetObject)
        | s32p_support::classifier::S3Op::Read(s32p_support::classifier::ReadOp::HeadObject) => {
            handle_get_object(req, app, &class).await
        }
        s32p_support::classifier::S3Op::Read(s32p_support::classifier::ReadOp::ListObjectsV2) => {
            handle_list_objects_v2(req, app, &class).await
        }
        s32p_support::classifier::S3Op::Read(s32p_support::classifier::ReadOp::ListObjectsV1) => {
            handle_list_objects_v1(req, app, &class).await
        }
        s32p_support::classifier::S3Op::Read(s32p_support::classifier::ReadOp::GetObjectAcl) => {
            handle_get_object_acl(req, app, &class).await
        }
        s32p_support::classifier::S3Op::Read(s32p_support::classifier::ReadOp::GetBucketAcl) => {
            handle_get_bucket_acl(req, app, &class).await
        }
        s32p_support::classifier::S3Op::Write(s32p_support::classifier::WriteOp::PutObjectAcl) => {
            handle_put_object_acl(req, app, &class).await
        }
        s32p_support::classifier::S3Op::Write(s32p_support::classifier::WriteOp::PutBucketAcl) => {
            handle_put_bucket_acl(req, app, &class).await
        }
        s32p_support::classifier::S3Op::Write(s32p_support::classifier::WriteOp::PutObject) => {
            handle_put_object(req, app, &class).await
        }
        s32p_support::classifier::S3Op::Write(s32p_support::classifier::WriteOp::RenameObject) => {
            handle_rename_object(req, app, &class).await
        }
        s32p_support::classifier::S3Op::Write(s32p_support::classifier::WriteOp::CopyObject) => {
            handle_copy_object(req, app, &class).await
        }
        s32p_support::classifier::S3Op::Write(s32p_support::classifier::WriteOp::DeleteObject) => {
            handle_delete_object(req, app, &class).await
        }
        s32p_support::classifier::S3Op::Write(s32p_support::classifier::WriteOp::DeleteObjects) => {
            handle_delete_objects(req, app, &class).await
        }
        s32p_support::classifier::S3Op::Read(
            s32p_support::classifier::ReadOp::GetObjectTagging,
        ) => handle_get_object_tagging(req, app, &class).await,
        s32p_support::classifier::S3Op::Write(
            s32p_support::classifier::WriteOp::PutObjectTagging,
        ) => handle_put_object_tagging(req, app, &class).await,
        s32p_support::classifier::S3Op::Write(
            s32p_support::classifier::WriteOp::DeleteObjectTagging,
        ) => handle_delete_object_tagging(req, app, &class).await,
        s32p_support::classifier::S3Op::Multipart(_) => handle_multipart(req, app, &class).await,
        s32p_support::classifier::S3Op::Versioning(_) => handle_versioning(req, app, &class).await,
        _ => handle_other(req, app, &class).await,
    };

    tracing::debug!(
        client = %client_log,
        method = %method,
        uri = %uri_log,
        status = resp.status().as_u16(),
        "request completed"
    );

    Ok(resp)
}

fn require_sigv4(
    req: &Request<Incoming>,
    cfg: &Cfg,
    peer: Option<&PeerAddr>,
) -> std::result::Result<(), s32p_support::SigV4Rejection> {
    // Session-validated short-circuit. The proxy validated SigV4 with the
    // session's ephemeral secret; we can't redo that here because we don't
    // know the secret (the session store lives in the proxy, not the
    // worker). Instead, three things must all hold:
    //
    //   1. cfg.worker_token configured — empty means the worker wasn't
    //      spawned by a session-aware proxy; the header (if any) is
    //      ignored entirely and we fall through to normal SigV4.
    //   2. peer.is_local()             — only proxy → worker traffic is
    //                                    loopback/UDS.
    //   3. header == cfg.worker_token  — proves the connection comes from
    //                                    the proxy that spawned us.
    //
    // Each failure mode logs distinctly so misconfigs (worker exposed
    // off-host, stale token after restart) are distinguishable from
    // active probes.
    if !cfg.worker_token.is_empty()
        && let Some(hv) = req.headers().get("x-s32p-validated")
    {
        let resource = Some(req.uri().path());
        let is_local = peer.map(PeerAddr::is_local).unwrap_or(false);
        if !is_local {
            tracing::warn!(
                peer = ?peer,
                "rejected X-S32P-Validated header from non-local peer"
            );
            return Err(s32p_support::SigV4Rejection {
                response: s32p_support::s3resp::access_denied(
                    "validation header rejected",
                    resource,
                ),
                reason:   "X-S32P-Validated from non-local peer".to_string(),
            });
        }
        let provided = hv.to_str().unwrap_or("");
        // Constant-time-ish comparison is overkill at this trust boundary
        // (the channel is loopback/UDS), but use a length-then-compare to
        // avoid early-exit on the first differing byte costing nothing.
        let token_match = provided.len() == cfg.worker_token.len() && provided == cfg.worker_token;
        if !token_match {
            tracing::warn!("X-S32P-Validated header token mismatch");
            return Err(s32p_support::SigV4Rejection {
                response: s32p_support::s3resp::access_denied(
                    "validation header rejected",
                    resource,
                ),
                reason:   "X-S32P-Validated token mismatch".to_string(),
            });
        }
        // All three checks passed — trust the proxy's prior validation.
        return Ok(());
    }

    s32p_support::verify_sigv4_request_any(
        req.method().as_str(),
        req.uri(),
        req.headers(),
        Some(&cfg.access_key),
        &cfg.secret_key,
        Some(req.uri().path()),
    )
}

fn query_is_only_location(req: &Request<Incoming>) -> bool {
    req.method() == http::Method::GET
        && s32p_support::classifier::QueryParams::from_uri(req.uri()).is_only_effective("location")
}

fn has_effective_query(req: &Request<Incoming>) -> bool {
    !s32p_support::classifier::QueryParams::from_uri(req.uri()).is_empty_effective()
}

// -------------------------
// ListBuckets (pagination)
// -------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ListBucketsToken {
    v:             u8,
    bucket_region: Option<String>,
    prefix:        Option<String>,
    after:         String,
}

fn encode_list_buckets_token(tok: &ListBucketsToken) -> Result<String> {
    let js = serde_json::to_vec(tok)?;
    Ok(URL_SAFE_NO_PAD.encode(js))
}

fn decode_list_buckets_token(s: &str) -> Result<ListBucketsToken> {
    let raw = URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(|e| anyhow!("bad continuation-token: {e}"))?;
    let tok: ListBucketsToken =
        serde_json::from_slice(&raw).map_err(|e| anyhow!("bad continuation-token json: {e}"))?;
    Ok(tok)
}

async fn handle_list_buckets(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    // Optional params
    let bucket_region_q = if class.query.has("bucket-region") {
        Some(class.query.first("bucket-region").unwrap_or("").to_string())
    } else {
        None
    };

    // AWS requires that the request is made to the regional endpoint that matches bucket-region.
    if let Some(br) = bucket_region_q.as_deref() {
        if !br.is_empty() && br != cfg.region.as_str() {
            return s32p_support::s3resp::s3_error(
                StatusCode::BAD_REQUEST,
                s32p_support::s3xml::error_code::INVALID_REQUEST,
                "bucket-region does not match this endpoint region",
                Some(req.uri().path()),
                None,
            );
        }
    }

    let prefix_q = if class.query.has("prefix") {
        Some(class.query.first("prefix").unwrap_or("").to_string())
    } else {
        None
    };

    let continuation_in = class
        .query
        .first("continuation-token")
        .and_then(|s| if s.is_empty() { None } else { Some(s.to_string()) });

    let max_buckets_in = match class.query.first("max-buckets") {
        None => None,
        Some(s) => match s.parse::<u32>() {
            Ok(v) => Some(v),
            Err(_) => {
                return s32p_support::s3resp::s3_error(
                    StatusCode::BAD_REQUEST,
                    s32p_support::s3xml::error_code::INVALID_REQUEST,
                    "invalid max-buckets",
                    Some(req.uri().path()),
                    None,
                );
            }
        },
    };

    if let Some(m) = max_buckets_in {
        if m < 1 || m > 10_000 {
            return s32p_support::s3resp::s3_error(
                StatusCode::BAD_REQUEST,
                s32p_support::s3xml::error_code::INVALID_REQUEST,
                "max-buckets must be between 1 and 10000",
                Some(req.uri().path()),
                None,
            );
        }
    }

    let paginated = max_buckets_in.is_some()
        || class.query.has("bucket-region")
        || class.query.has("prefix")
        || class.query.has("continuation-token");

    // Per AWS docs: if bucket-region/prefix/continuation-token are specified without max-buckets,
    // apply a default page size of 10,000.
    let page_size = if let Some(m) = max_buckets_in {
        Some(m)
    } else if paginated {
        Some(10_000)
    } else {
        None
    };

    // Load buckets from the POSIX root (top-level directories).
    let mut buckets: Vec<(String, SystemTime)> = Vec::new();
    let rd = match fs::read_dir(&cfg.posix_root) {
        Ok(rd) => rd,
        Err(e) => {
            return s32p_support::s3resp::access_denied(
                &format!("read_dir failed: {e}"),
                Some(req.uri().path()),
            );
        }
    };

    for ent in rd {
        let ent = match ent {
            Ok(e) => e,
            Err(_) => continue,
        };
        let ft = match ent.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        let (is_dir, created) = if ft.is_symlink() {
            let link_path = ent.path();
            let target = match fs::read_link(&link_path) {
                Ok(t) => t,
                Err(_) => continue,
            };
            let target = if target.is_relative() {
                match link_path.parent() {
                    Some(p) => p.join(target),
                    None => continue,
                }
            } else {
                target
            };
            match fs::metadata(&target) {
                Ok(m) => (m.is_dir(), m.modified().ok().unwrap_or(SystemTime::UNIX_EPOCH)),
                Err(_) => continue,
            }
        } else {
            let m = match ent.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            (ft.is_dir(), m.modified().ok().unwrap_or(SystemTime::UNIX_EPOCH))
        };

        if !is_dir {
            continue;
        }

        let name = ent.file_name().to_string_lossy().to_string();
        if name.is_empty() || name == "." || name == ".." {
            continue;
        }

        buckets.push((name, created));
    }

    // Sort lexicographically by bucket name.
    buckets.sort_by(|a, b| a.0.cmp(&b.0));

    // Apply prefix filter.
    if let Some(pfx) = prefix_q.as_deref() {
        buckets.retain(|(name, _)| name.starts_with(pfx));
    }

    // Apply continuation token.
    let mut start_after = String::new();
    if let Some(ct) = &continuation_in {
        match decode_list_buckets_token(ct) {
            Ok(tok) => {
                // Validate token matches request filters.
                if tok.v != 1 {
                    return s32p_support::s3resp::s3_error(
                        StatusCode::BAD_REQUEST,
                        s32p_support::s3xml::error_code::INVALID_REQUEST,
                        "unsupported continuation-token version",
                        Some(req.uri().path()),
                        None,
                    );
                }
                if tok.prefix != prefix_q || tok.bucket_region != bucket_region_q {
                    return s32p_support::s3resp::s3_error(
                        StatusCode::BAD_REQUEST,
                        s32p_support::s3xml::error_code::INVALID_REQUEST,
                        "continuation-token does not match request parameters",
                        Some(req.uri().path()),
                        None,
                    );
                }
                start_after = tok.after;
            }
            Err(e) => {
                return s32p_support::s3resp::s3_error(
                    StatusCode::BAD_REQUEST,
                    s32p_support::s3xml::error_code::INVALID_REQUEST,
                    &e.to_string(),
                    Some(req.uri().path()),
                    None,
                );
            }
        }
    }

    if !start_after.is_empty() {
        buckets.retain(|(name, _)| name.as_str() > start_after.as_str());
    }

    let mut next_token_out: Option<String> = None;
    let mut page: Vec<(String, SystemTime)> = buckets;

    if let Some(ps) = page_size {
        let ps = ps as usize;
        if page.len() > ps {
            let last_name = page[ps - 1].0.clone();
            page.truncate(ps);

            let tok = ListBucketsToken {
                v:             1,
                bucket_region: bucket_region_q.clone(),
                prefix:        prefix_q.clone(),
                after:         last_name,
            };
            match encode_list_buckets_token(&tok) {
                Ok(s) => next_token_out = Some(s),
                Err(e) => {
                    return s32p_support::s3resp::internal_error(
                        &e.to_string(),
                        Some(req.uri().path()),
                        None,
                    );
                }
            }
        }
    }

    let include_bucket_region = paginated;
    let out: Vec<s32p_support::s3xml::BucketInfo> = page
        .into_iter()
        .map(|(name, creation_date)| s32p_support::s3xml::BucketInfo {
            name,
            bucket_region: include_bucket_region.then(|| cfg.region.clone()),
            bucket_arn: None,
            creation_date,
        })
        .collect();

    s32p_support::s3resp::list_buckets_paginated(
        &cfg.access_key,
        &cfg.access_key,
        &out,
        prefix_q.as_deref(),
        next_token_out.as_deref(),
    )
}

async fn handle_get_bucket_location(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    // Only allow ?location (classifier should already ensure this, but keep it defensive)
    if req.uri().query().is_some() && !query_is_only_location(&req) {
        return s32p_support::s3resp::not_implemented("query parameters are not implemented", None);
    }

    let bucket = class.bucket.as_deref().unwrap_or("");
    if bucket.is_empty() {
        return s32p_support::s3resp::not_implemented("missing bucket", Some(req.uri().path()));
    }

    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => s32p_support::s3resp::get_bucket_location(&cfg.region),
        Ok(false) => {
            s32p_support::s3resp::no_such_bucket("bucket not found", Some(req.uri().path()))
        }
        Err(e) => s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path())),
    }
}

async fn handle_get_object_acl(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    let bucket = class.bucket.as_deref().unwrap_or("");
    let key = class.key.as_deref().unwrap_or("");
    if bucket.is_empty() || key.is_empty() {
        return s32p_support::s3resp::not_implemented(
            "missing bucket or key",
            Some(req.uri().path()),
        );
    }
    if is_reserved_first_segment(key, &cfg.mpu_dir_name) {
        return s32p_support::s3resp::access_denied("reserved key prefix", Some(req.uri().path()));
    }

    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => {}
        Ok(false) => {
            return s32p_support::s3resp::no_such_bucket(
                "bucket not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    }

    let obj_path = match join_object_path(&cfg.posix_root, bucket, key) {
        Ok(p) => p,
        Err(e) => return s32p_support::s3resp::access_denied(&e.to_string(), None),
    };

    // statx the object (follow symlinks like GetObject does, then fall back to
    // NOFOLLOW via the helper) to get uid + mode bits.
    let m = match std::fs::metadata(&obj_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return s32p_support::s3resp::no_such_key("object not found", Some(req.uri().path()));
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    };
    let uid = std::os::unix::fs::MetadataExt::uid(&m);
    let mode = std::os::unix::fs::PermissionsExt::mode(&m.permissions());
    let owner = owner_info(&app.nss_client, uid).await;

    s32p_support::s3resp::get_acl(&owner.id, &owner.display_name, (mode & 0o004) != 0)
}

async fn handle_get_bucket_acl(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    let bucket = class.bucket.as_deref().unwrap_or("");
    if bucket.is_empty() {
        return s32p_support::s3resp::not_implemented("missing bucket", Some(req.uri().path()));
    }

    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => {}
        Ok(false) => {
            return s32p_support::s3resp::no_such_bucket(
                "bucket not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    }

    let bucket_root = match bucket_root_path(&cfg.posix_root, bucket) {
        Ok(p) => p,
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    };
    let m = match std::fs::metadata(&bucket_root) {
        Ok(m) => m,
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    };
    let uid = std::os::unix::fs::MetadataExt::uid(&m);
    let mode = std::os::unix::fs::PermissionsExt::mode(&m.permissions());
    let owner = owner_info(&app.nss_client, uid).await;

    s32p_support::s3resp::get_acl(&owner.id, &owner.display_name, (mode & 0o004) != 0)
}

/// Determine whether the requested ACL grants public read access (POSIX
/// `o+r`). Mirrors the get-side logic: only the `Group: AllUsers` grant with
/// `READ` / `FULL_CONTROL` maps to a real bit; everything else is treated as
/// "no public read".
///
/// Precedence: `x-amz-acl` canned header → individual `x-amz-grant-*`
/// headers → XML body. AWS rejects combinations; for a no-op check we
/// honor whichever was specified first and ignore the rest.
fn acl_request_world_readable_intent(
    headers: &http::HeaderMap,
    body: &[u8],
) -> std::result::Result<bool, String> {
    if let Some(canned) = headers.get("x-amz-acl").and_then(|v| v.to_str().ok()) {
        let v = canned.trim().to_ascii_lowercase();
        return match v.as_str() {
            "private"
            | "bucket-owner-read"
            | "bucket-owner-full-control"
            | "aws-exec-read"
            | "log-delivery-write"
            | "authenticated-read" => Ok(false),
            "public-read" | "public-read-write" => Ok(true),
            other => Err(format!("unknown canned ACL: {other}")),
        };
    }

    let grant_headers = [
        "x-amz-grant-read",
        "x-amz-grant-write",
        "x-amz-grant-read-acp",
        "x-amz-grant-write-acp",
        "x-amz-grant-full-control",
    ];
    let any_grant_header = grant_headers.iter().any(|h| headers.contains_key(*h));
    if any_grant_header {
        let mentions_all_users = |hname: &str| {
            headers
                .get(hname)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|s| s.contains("AllUsers"))
        };
        return Ok(mentions_all_users("x-amz-grant-read")
            || mentions_all_users("x-amz-grant-full-control"));
    }

    s32p_support::s3xml::parse_put_acl_request_world_readable(body).map_err(|e| e.to_string())
}

/// Hard cap on XML-shaped S3 control-plane bodies (PutObjectAcl,
/// PutBucketAcl, DeleteObjects, CompleteMultipartUpload). The largest
/// realistic body is DeleteObjects at 1000 keys, which is ~256 KiB at
/// 256 B/key; 1 MiB gives generous headroom for unusual key lengths
/// without leaving room for memory-pressure abuse.
pub(crate) const XML_BODY_MAX_BYTES: usize = 1 * 1024 * 1024;

/// Cap on header count per request. Hyper's default is no cap, so a
/// hostile client can advertise tens of thousands of headers to inflate
/// per-connection memory. 64 headers comfortably fits any S3 client we
/// know of (boto3, aws-cli, rclone, mountpoint-s3, s5cmd all send <30).
///
/// Note: there is intentionally no `header_read_timeout` on the gateway
/// listener. Hyper's `header_read_timeout` is consulted at the start of
/// every header read — including the post-keepalive "waiting for next
/// request" read — so it doubles as a keep-alive idle timeout, which
/// would close idle proxy↔gateway connections and force pingora to
/// reconnect on the next request. The gateway is always behind the
/// proxy (UDS by default, local TCP otherwise), and the proxy already
/// reads the full request headers before forwarding, so slowloris from
/// the proxy isn't a credible threat. The public-internet slowloris
/// gate lives at the proxy listener (Pingora `set_keepalive(60s)` from
/// `early_request_filter`).
const MAX_REQUEST_HEADERS: usize = 64;

/// Outcome of [`collect_body_capped`].
pub(crate) enum BodyCapErr {
    /// Body advertised or streamed more than the cap. `advertised` carries
    /// the `Content-Length` value if that was the trigger (for log detail),
    /// `None` if it was a streaming overrun.
    TooLarge { advertised: Option<u64> },
    /// Underlying body read error (network, decoder, etc.).
    Read(String),
}

/// Collect an Incoming body into [`Bytes`], refusing bodies above `cap`.
///
/// Two-stage rejection:
/// - **Pre-read**: if `Content-Length` is present and exceeds `cap`, reject
///   without touching the body. Closes the "advertise 1 GiB, dribble" path.
/// - **Streaming**: wrap in [`http_body_util::Limited`] so a body without
///   `Content-Length` (or one that lies about it) is cut off as soon as the
///   running total crosses `cap`.
///
/// On success returns the collected bytes (at most `cap`).
/// Check `Content-Length` against `cap`. Returns the advertised value if it
/// would exceed the cap (caller should reject before reading the body), or
/// `None` if the header is absent / non-numeric / within budget. Factored out
/// so it's unit-testable without constructing a [`hyper::body::Incoming`].
fn content_length_over_cap(headers: &HeaderMap, cap: usize) -> Option<u64> {
    let advertised = headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())?;
    (advertised > cap as u64).then_some(advertised)
}

pub(crate) async fn collect_body_capped(
    headers: &HeaderMap,
    body: Incoming,
    cap: usize,
) -> Result<Bytes, BodyCapErr> {
    if let Some(advertised) = content_length_over_cap(headers, cap) {
        return Err(BodyCapErr::TooLarge { advertised: Some(advertised) });
    }

    let limited = http_body_util::Limited::new(body, cap);
    match limited.collect().await {
        Ok(c) => Ok(c.to_bytes()),
        Err(e) => {
            if e.downcast_ref::<http_body_util::LengthLimitError>().is_some() {
                Err(BodyCapErr::TooLarge { advertised: None })
            } else {
                Err(BodyCapErr::Read(e.to_string()))
            }
        }
    }
}

async fn handle_put_object_acl(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    let bucket = class.bucket.as_deref().unwrap_or("");
    let key = class.key.as_deref().unwrap_or("");
    if bucket.is_empty() || key.is_empty() {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_REQUEST,
            "missing bucket or key",
            Some(req.uri().path()),
            None,
        );
    }
    if is_reserved_first_segment(key, &cfg.mpu_dir_name) {
        return s32p_support::s3resp::access_denied("reserved key prefix", Some(req.uri().path()));
    }

    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => {}
        Ok(false) => {
            return s32p_support::s3resp::no_such_bucket(
                "bucket not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    }

    let obj_path = match join_object_path(&cfg.posix_root, bucket, key) {
        Ok(p) => p,
        Err(e) => return s32p_support::s3resp::access_denied(&e.to_string(), None),
    };

    let m = match std::fs::metadata(&obj_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return s32p_support::s3resp::no_such_key("object not found", Some(req.uri().path()));
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    };
    let current = (std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o004) != 0;

    let (parts, body) = req.into_parts();
    let collected = match collect_body_capped(&parts.headers, body, XML_BODY_MAX_BYTES).await {
        Ok(b) => b,
        Err(BodyCapErr::TooLarge { advertised }) => {
            tracing::debug!(
                op = "PutObjectAcl",
                advertised = ?advertised,
                cap = XML_BODY_MAX_BYTES,
                "request body exceeds XML body cap"
            );
            return s32p_support::s3resp::s3_error(
                StatusCode::BAD_REQUEST,
                s32p_support::s3xml::error_code::INVALID_REQUEST,
                "request body too large",
                Some(parts.uri.path()),
                None,
            );
        }
        Err(BodyCapErr::Read(e)) => {
            return s32p_support::s3resp::invalid_request(
                &format!("failed to read body: {e}"),
                Some(parts.uri.path()),
            );
        }
    };

    let requested = match acl_request_world_readable_intent(&parts.headers, &collected) {
        Ok(b) => b,
        Err(reason) => {
            tracing::debug!("PutObjectAcl invalid: {reason}");
            return s32p_support::s3resp::invalid_request(
                "invalid ACL request",
                Some(parts.uri.path()),
            );
        }
    };

    if requested == current {
        s32p_support::s3resp::put_acl_ok()
    } else {
        tracing::debug!(
            requested_world_readable = requested,
            current_world_readable = current,
            "PutObjectAcl rejected: would change effective access"
        );
        s32p_support::s3resp::not_implemented(
            "PutObjectAcl is accepted only when it matches the current effective access",
            Some(parts.uri.path()),
        )
    }
}

async fn handle_put_bucket_acl(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    let bucket = class.bucket.as_deref().unwrap_or("");
    if bucket.is_empty() {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_REQUEST,
            "missing bucket",
            Some(req.uri().path()),
            None,
        );
    }

    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => {}
        Ok(false) => {
            return s32p_support::s3resp::no_such_bucket(
                "bucket not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    }

    let bucket_root = match bucket_root_path(&cfg.posix_root, bucket) {
        Ok(p) => p,
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    };
    let m = match std::fs::metadata(&bucket_root) {
        Ok(m) => m,
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    };
    let current = (std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o004) != 0;

    let (parts, body) = req.into_parts();
    let collected = match collect_body_capped(&parts.headers, body, XML_BODY_MAX_BYTES).await {
        Ok(b) => b,
        Err(BodyCapErr::TooLarge { advertised }) => {
            tracing::debug!(
                op = "PutBucketAcl",
                advertised = ?advertised,
                cap = XML_BODY_MAX_BYTES,
                "request body exceeds XML body cap"
            );
            return s32p_support::s3resp::s3_error(
                StatusCode::BAD_REQUEST,
                s32p_support::s3xml::error_code::INVALID_REQUEST,
                "request body too large",
                Some(parts.uri.path()),
                None,
            );
        }
        Err(BodyCapErr::Read(e)) => {
            return s32p_support::s3resp::invalid_request(
                &format!("failed to read body: {e}"),
                Some(parts.uri.path()),
            );
        }
    };

    let requested = match acl_request_world_readable_intent(&parts.headers, &collected) {
        Ok(b) => b,
        Err(reason) => {
            tracing::debug!("PutBucketAcl invalid: {reason}");
            return s32p_support::s3resp::invalid_request(
                "invalid ACL request",
                Some(parts.uri.path()),
            );
        }
    };

    if requested == current {
        s32p_support::s3resp::put_acl_ok()
    } else {
        tracing::debug!(
            requested_world_readable = requested,
            current_world_readable = current,
            "PutBucketAcl rejected: would change effective access"
        );
        s32p_support::s3resp::not_implemented(
            "PutBucketAcl is accepted only when it matches the current effective access",
            Some(parts.uri.path()),
        )
    }
}

/* -------------------------
 * Object tagging
 *
 * Tags live in the `user.s32p.tags` xattr on the object file. The stored
 * payload is the URL-form encoding of the tag set (matches the
 * `x-amz-tagging` header wire shape). See `fs_helpers::read_tags` /
 * `write_tags` for the storage layer.
 * ------------------------- */

/// Fail-fast gate for tagging writes: probes the filesystem's `user.*`
/// xattr support (cached per device on `App`). Returns `Some(resp)`
/// when the caller should short-circuit — `501 NotImplemented` when
/// the backing FS doesn't support xattrs, or `500 InternalError` when
/// the probe itself failed (e.g. the bucket symlink target is missing).
/// `probe_path` should exist; the bucket root is a safe choice when an
/// object doesn't exist yet (e.g. PutObject creating a fresh key).
fn require_xattr_support(app: &App, probe_path: &Path, uri_path: &str) -> Option<Resp> {
    match user_xattrs_supported_for(app, probe_path) {
        Ok(true) => None,
        Ok(false) => {
            tracing::debug!(
                probe = %probe_path.display(),
                "tagging rejected: filesystem does not support user.* xattrs"
            );
            Some(s32p_support::s3resp::not_implemented(
                "object tagging not supported on this storage backend",
                Some(uri_path),
            ))
        }
        Err(e) => {
            tracing::warn!(
                probe = %probe_path.display(),
                error = %e,
                "tagging xattr-support probe failed"
            );
            Some(s32p_support::s3resp::internal_error(
                "failed to probe object tagging support",
                Some(uri_path),
                None,
            ))
        }
    }
}

async fn handle_get_object_tagging(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    let bucket = class.bucket.as_deref().unwrap_or("");
    let key = class.key.as_deref().unwrap_or("");
    if bucket.is_empty() || key.is_empty() {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_REQUEST,
            "missing bucket or key",
            Some(req.uri().path()),
            None,
        );
    }
    if is_reserved_first_segment(key, &cfg.mpu_dir_name) {
        return s32p_support::s3resp::access_denied("reserved key prefix", Some(req.uri().path()));
    }

    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => {}
        Ok(false) => {
            return s32p_support::s3resp::no_such_bucket(
                "bucket not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    }

    let obj_path = match join_object_path(&cfg.posix_root, bucket, key) {
        Ok(p) => p,
        Err(e) => return s32p_support::s3resp::access_denied(&e.to_string(), None),
    };

    match std::fs::metadata(&obj_path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return s32p_support::s3resp::no_such_key("object not found", Some(req.uri().path()));
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    };

    let tags = match read_tags(&obj_path) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(
                path = %obj_path.display(),
                error = %e,
                "GetObjectTagging: failed to read xattr"
            );
            return s32p_support::s3resp::internal_error(
                "failed to read object tags",
                Some(req.uri().path()),
                None,
            );
        }
    };

    s32p_support::s3resp::get_object_tagging(&tags)
}

async fn handle_put_object_tagging(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    let bucket = class.bucket.as_deref().unwrap_or("");
    let key = class.key.as_deref().unwrap_or("");
    if bucket.is_empty() || key.is_empty() {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_REQUEST,
            "missing bucket or key",
            Some(req.uri().path()),
            None,
        );
    }
    if is_reserved_first_segment(key, &cfg.mpu_dir_name) {
        return s32p_support::s3resp::access_denied("reserved key prefix", Some(req.uri().path()));
    }

    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => {}
        Ok(false) => {
            return s32p_support::s3resp::no_such_bucket(
                "bucket not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    }

    let obj_path = match join_object_path(&cfg.posix_root, bucket, key) {
        Ok(p) => p,
        Err(e) => return s32p_support::s3resp::access_denied(&e.to_string(), None),
    };

    match std::fs::metadata(&obj_path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return s32p_support::s3resp::no_such_key("object not found", Some(req.uri().path()));
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    };

    if let Some(resp) = require_xattr_support(&app, &obj_path, req.uri().path()) {
        return resp;
    }

    let (parts, body) = req.into_parts();
    let collected = match collect_body_capped(&parts.headers, body, XML_BODY_MAX_BYTES).await {
        Ok(b) => b,
        Err(BodyCapErr::TooLarge { advertised }) => {
            tracing::debug!(
                op = "PutObjectTagging",
                advertised = ?advertised,
                cap = XML_BODY_MAX_BYTES,
                "request body exceeds XML body cap"
            );
            return s32p_support::s3resp::s3_error(
                StatusCode::BAD_REQUEST,
                s32p_support::s3xml::error_code::INVALID_REQUEST,
                "request body too large",
                Some(parts.uri.path()),
                None,
            );
        }
        Err(BodyCapErr::Read(e)) => {
            return s32p_support::s3resp::invalid_request(
                &format!("failed to read body: {e}"),
                Some(parts.uri.path()),
            );
        }
    };

    let tags_urlform = match s32p_support::s3xml::parse_object_tagging_request(&collected) {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("PutObjectTagging malformed XML: {e}");
            return s32p_support::s3resp::s3_error(
                StatusCode::BAD_REQUEST,
                s32p_support::s3xml::error_code::MALFORMED_XML,
                "malformed Tagging XML",
                Some(parts.uri.path()),
                None,
            );
        }
    };

    if let Err(reason) = s32p_support::s3xml::validate_tagging_urlform(&tags_urlform) {
        tracing::debug!("PutObjectTagging invalid: {reason}");
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_TAG,
            "invalid tag set",
            Some(parts.uri.path()),
            None,
        );
    }

    if let Err(e) = write_tags(&obj_path, &tags_urlform) {
        tracing::warn!(
            path = %obj_path.display(),
            error = %e,
            "PutObjectTagging: failed to write xattr"
        );
        return s32p_support::s3resp::internal_error(
            "failed to write object tags",
            Some(parts.uri.path()),
            None,
        );
    }

    s32p_support::s3resp::put_object_tagging_ok()
}

async fn handle_delete_object_tagging(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    let bucket = class.bucket.as_deref().unwrap_or("");
    let key = class.key.as_deref().unwrap_or("");
    if bucket.is_empty() || key.is_empty() {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_REQUEST,
            "missing bucket or key",
            Some(req.uri().path()),
            None,
        );
    }
    if is_reserved_first_segment(key, &cfg.mpu_dir_name) {
        return s32p_support::s3resp::access_denied("reserved key prefix", Some(req.uri().path()));
    }

    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => {}
        Ok(false) => {
            return s32p_support::s3resp::no_such_bucket(
                "bucket not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    }

    let obj_path = match join_object_path(&cfg.posix_root, bucket, key) {
        Ok(p) => p,
        Err(e) => return s32p_support::s3resp::access_denied(&e.to_string(), None),
    };

    match std::fs::metadata(&obj_path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return s32p_support::s3resp::no_such_key("object not found", Some(req.uri().path()));
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    };

    if let Some(resp) = require_xattr_support(&app, &obj_path, req.uri().path()) {
        return resp;
    }

    if let Err(e) = remove_tags(&obj_path) {
        tracing::warn!(
            path = %obj_path.display(),
            error = %e,
            "DeleteObjectTagging: failed to remove xattr"
        );
        return s32p_support::s3resp::internal_error(
            "failed to remove object tags",
            Some(req.uri().path()),
            None,
        );
    }

    s32p_support::s3resp::delete_object_tagging_ok()
}

async fn handle_head_bucket(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    // Defensive: HeadBucket should not have query params in our implementation.
    if has_effective_query(&req) {
        return s32p_support::s3resp::not_implemented("query parameters are not implemented", None);
    }

    let bucket = class.bucket.as_deref().unwrap_or("");
    if bucket.is_empty() {
        return s32p_support::s3resp::not_implemented("missing bucket", Some(req.uri().path()));
    }

    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => s32p_support::s3resp::head_bucket_ok(&cfg.region),
        Ok(false) => {
            s32p_support::s3resp::no_such_bucket("bucket not found", Some(req.uri().path()))
        }
        Err(e) => s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path())),
    }
}

async fn handle_multipart(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    crate::multipart::handle(req, app, class).await
}

async fn handle_versioning(
    _req: Request<Incoming>,
    _app: Arc<App>,
    _class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    s32p_support::s3resp::not_implemented("versioning is not implemented", None)
}

async fn handle_other(
    req: Request<Incoming>,
    _app: Arc<App>,
    _class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    // Catch-all for requests the classifier couldn't match. Echo method
    // and request-target so the client sees which shape was rejected.
    let path_and_query =
        req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or(req.uri().path());
    let message = format!("unsupported request shape: {} {}", req.method(), path_and_query,);
    s32p_support::s3resp::not_implemented(&message, Some(req.uri().path()))
}

// Build a HEAD response from `lstat(2)` metadata. Used when `open(2)` returns
// ENOENT for a path that is itself a (broken) symlink, so HEAD agrees with the
// listing view of the same key. Mirrors the precondition handling of the main
// HEAD/GET path; the symlink's own inode/mtime/size feed ETag/Last-Modified/
// Content-Length.
fn head_response_from_lstat(req: &Request<Incoming>, lmeta: &std::fs::Metadata) -> Resp {
    let size = lmeta.len();
    let lm_st = lmeta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let last_modified = fmt_http_date(lm_st);
    let etag_unquoted = format_inode_etag_unquoted(lmeta.ino());
    let etag = format_inode_etag(lmeta.ino());

    let cond = match parse_conditional_headers(req.headers()) {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("invalid conditional headers: {e}");
            return s32p_support::s3resp::invalid_request(&msg, Some(req.uri().path()));
        }
    };
    match evaluate_read_preconditions(&cond, &etag_unquoted, lm_st) {
        PreconditionOutcome::Proceed => {}
        PreconditionOutcome::NotModified => {
            return s32p_support::s3resp::not_modified(Some(&etag), Some(&last_modified));
        }
        PreconditionOutcome::PreconditionFailed => {
            return s32p_support::s3resp::precondition_failed(
                "GET/HEAD precondition failed",
                Some(req.uri().path()),
            );
        }
    }

    // Broken-symlink HEAD: we have only `lstat()` on the symlink itself, no
    // resolved object path to read xattrs from. Fall back to the default
    // Content-Type and no user metadata — same as a regular file with no
    // metadata set. Listing already shows the symlink as a normal entry,
    // so this keeps HEAD consistent.
    s32p_support::s3resp::object_response(
        StatusCode::OK,
        s32p_support::s3resp::empty_body(),
        s32p_support::s3resp::OBJECT_CONTENT_TYPE,
        size,
        &etag,
        &last_modified,
        None,
        &[],
    )
}

async fn handle_get_object(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    // Allow SigV4 presign query params; reject only effective (non-presign) query params.
    if has_effective_query(&req) {
        return s32p_support::s3resp::not_implemented("query parameters are not implemented", None);
    }

    let is_head_object = matches!(
        &class.op,
        s32p_support::classifier::S3Op::Read(s32p_support::classifier::ReadOp::HeadObject)
    );

    let bucket = class.bucket.as_deref().unwrap_or("");
    let key = class.key.as_deref().unwrap_or("");

    // hide multipart upload dir
    if is_reserved_first_segment(key, &cfg.mpu_dir_name) {
        return s32p_support::s3resp::no_such_key("not found", None);
    }

    // If the bucket is missing, S3 expects NoSuchBucket (not NoSuchKey).
    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => {}
        Ok(false) => {
            return s32p_support::s3resp::no_such_bucket(
                "bucket not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    }

    let obj_path = match join_object_path(&cfg.posix_root, bucket, key) {
        Ok(p) => p,
        Err(e) => return s32p_support::s3resp::access_denied(&e.to_string(), None),
    };

    // open once (buffered) to stat + inode + size
    let (std_file, _used_direct) =
        match open_file(&obj_path, OpenMode::Read, OpenDirect::Buffered, None) {
            Ok(v) => v,
            Err(e) => {
                let ioe = e.downcast_ref::<std::io::Error>();
                match ioe.map(|x| x.kind()) {
                    Some(std::io::ErrorKind::NotFound) => {
                        // Broken symlink: open() follows the link and fails with
                        // ENOENT. Listings still surface the entry via lstat
                        // fallback (statx_info), so HEAD must too — otherwise
                        // LIST advertises a key that HEAD then denies. GET is
                        // unchanged: there is no readable content, so 404 is
                        // the only honest answer.
                        if is_head_object {
                            if let Ok(lmeta) = std::fs::symlink_metadata(&obj_path) {
                                if lmeta.file_type().is_symlink() {
                                    return head_response_from_lstat(&req, &lmeta);
                                }
                            }
                        }
                        return s32p_support::s3resp::no_such_key("not found", None);
                    }
                    Some(std::io::ErrorKind::PermissionDenied) => {
                        return s32p_support::s3resp::access_denied("permission denied", None);
                    }
                    _ => {
                        return s32p_support::s3resp::internal_error(
                            &e.to_string(),
                            Some(req.uri().path()),
                            None,
                        );
                    }
                }
            }
        };

    let meta = match std_file.metadata() {
        Ok(m) => m,
        Err(e) => {
            return s32p_support::s3resp::internal_error(
                &e.to_string(),
                Some(req.uri().path()),
                None,
            );
        }
    };

    let size = meta.len();

    // IMPORTANT: real mtime in RFC1123 / HTTP-date format (required by many S3 clients).
    // If metadata.modified() fails, fall back to UNIX_EPOCH (still a valid HTTP date).
    let lm_st = meta.modified().unwrap_or_else(|_| SystemTime::UNIX_EPOCH);
    let last_modified = fmt_http_date(lm_st);

    // inode-based ETag (see `format_inode_etag` for the `-1` suffix rationale).
    let etag_unquoted = format_inode_etag_unquoted(meta.ino());
    let etag = format_inode_etag(meta.ino());

    // are preconditions matched?
    let cond = match parse_conditional_headers(req.headers()) {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("invalid conditional headers: {e}");
            return s32p_support::s3resp::invalid_request(&msg, Some(req.uri().path()));
        }
    };

    match evaluate_read_preconditions(&cond, &etag_unquoted, lm_st) {
        PreconditionOutcome::Proceed => {}
        PreconditionOutcome::NotModified => {
            tracing::debug!("Read preconditions: NotModified (304) for {}", obj_path.display());
            return s32p_support::s3resp::not_modified(Some(&etag), Some(&last_modified));
        }
        PreconditionOutcome::PreconditionFailed => {
            tracing::debug!("Read preconditions failed (412) for {}", obj_path.display());
            return s32p_support::s3resp::precondition_failed(
                "GET/HEAD precondition failed",
                Some(req.uri().path()),
            );
        }
    }

    // Resolve stored Content-Type + user metadata once; reuse on every
    // response branch (empty, multi-range, HEAD, fast-path, streamed).
    // Multi-range responses still use `multirange_content_type` for the
    // outer response (RFC 7233 requires `multipart/byteranges`), but
    // x-amz-meta-* still echoes the stored set.
    let (stored_content_type, user_meta) = resolve_object_headers(&obj_path);

    // Empty object: 200 + Content-Length: 0 (+ common headers)
    if size == 0 {
        return s32p_support::s3resp::object_response(
            StatusCode::OK,
            s32p_support::s3resp::empty_body(),
            &stored_content_type,
            0,
            &etag,
            &last_modified,
            None,
            &user_meta,
        );
    }

    // Range parsing (RFC 7233). A single range keeps the plain 206 path; two
    // or more ranges produce a `multipart/byteranges` body (GET only). Any
    // unsatisfiable range or more than `MAX_RANGES` → 416 (in the parser).
    let ranges: Option<Vec<ByteRange>> = match req.headers().get("range") {
        None => None,
        Some(v) => match v.to_str() {
            Ok(s) => match parse_ranges_header(s, size) {
                Ok(r) => Some(r),
                Err(e) => return s32p_support::s3resp::invalid_range(&e.to_string(), None),
            },
            Err(_) => return s32p_support::s3resp::invalid_range("bad Range header", None),
        },
    };

    // Multi-range GET → multipart/byteranges. HEAD ignores multi-range (a
    // multipart body is meaningless without a body) and falls through to the
    // full-object 200 path below.
    if !is_head_object && ranges.as_ref().is_some_and(|r| r.len() >= 2) {
        let ranges = ranges.unwrap();
        let boundary = s32p_support::s3resp::multirange_boundary();
        let content_length =
            s32p_support::s3resp::multirange_content_length(&boundary, &ranges, size);
        let content_type = s32p_support::s3resp::multirange_content_type(&boundary);

        let body = match stream_multirange_body(
            obj_path.clone(),
            size,
            ranges,
            boundary,
            StreamCfg {
                chunk_size: cfg.chunk_size,
                inflight:   cfg.inflight,
                direct_io:  cfg.direct_io,
            },
            app.uring.clone(),
            app.pool.clone(),
        )
        .await
        {
            Ok(b) => b.boxed(),
            Err(e) => {
                return s32p_support::s3resp::internal_error(
                    &e.to_string(),
                    Some(req.uri().path()),
                    None,
                );
            }
        };

        return s32p_support::s3resp::object_response(
            StatusCode::PARTIAL_CONTENT,
            body,
            &content_type,
            content_length,
            &etag,
            &last_modified,
            None,
            &user_meta,
        );
    }

    // Single-range (or no-range) path. A multi-range HEAD lands here with the
    // Range deliberately ignored (range_present = false → full-object 200).
    let single_range = match &ranges {
        Some(r) if r.len() == 1 => Some(r[0]),
        _ => None,
    };
    let range_present = single_range.is_some();
    let want = single_range.unwrap_or(ByteRange { start: 0, end_excl: size });
    let want_len = want.end_excl - want.start;

    // HeadObject: same headers as GetObject, but no body
    if is_head_object {
        let (status, content_length, content_range) = if range_present {
            (
                StatusCode::PARTIAL_CONTENT,
                want_len,
                Some(s32p_support::s3resp::object_content_range(
                    want.start,
                    want.end_excl - 1,
                    size,
                )),
            )
        } else {
            (StatusCode::OK, size, None)
        };

        return s32p_support::s3resp::object_response(
            status,
            s32p_support::s3resp::empty_body(),
            &stored_content_type,
            content_length,
            &etag,
            &last_modified,
            content_range.as_deref(),
            &user_meta,
        );
    }

    // Small body fast-path (<= one chunk): acquire ONE permit for this file/request.
    if (want_len as usize) <= cfg.chunk_size {
        let file = Arc::new(std_file);
        let bytes = match read_small(file, app.pool.clone(), want.start, want_len as usize).await {
            Ok(b) => b,
            Err(e) => {
                return s32p_support::s3resp::internal_error(
                    &e.to_string(),
                    Some(req.uri().path()),
                    None,
                );
            }
        };

        // For range responses, compute end from what we actually read (robust to truncation races).
        let (status, content_length, content_range) = if range_present {
            let end_incl = want.start + (bytes.len().saturating_sub(1) as u64);
            (
                StatusCode::PARTIAL_CONTENT,
                bytes.len() as u64,
                Some(s32p_support::s3resp::object_content_range(want.start, end_incl, size)),
            )
        } else {
            (StatusCode::OK, size, None)
        };

        return s32p_support::s3resp::object_response(
            status,
            s32p_support::s3resp::body_bytes(bytes),
            &stored_content_type,
            content_length,
            &etag,
            &last_modified,
            content_range.as_deref(),
            &user_meta,
        );
    }

    // Unified read path: always stream via UringIO (no small-file special case).
    let body = match stream_range_body(
        obj_path.clone(),
        size,
        want,
        StreamCfg {
            chunk_size: cfg.chunk_size,
            inflight:   cfg.inflight,
            direct_io:  cfg.direct_io,
        },
        app.uring.clone(),
        app.pool.clone(),
    )
    .await
    {
        Ok(b) => b.boxed(),
        Err(e) => {
            return s32p_support::s3resp::internal_error(
                &e.to_string(),
                Some(req.uri().path()),
                None,
            );
        }
    };

    let (status, content_length, content_range) = if range_present {
        (
            StatusCode::PARTIAL_CONTENT,
            want_len,
            Some(s32p_support::s3resp::object_content_range(want.start, want.end_excl - 1, size)),
        )
    } else {
        (StatusCode::OK, size, None)
    };

    s32p_support::s3resp::object_response(
        status,
        body,
        &stored_content_type,
        content_length,
        &etag,
        &last_modified,
        content_range.as_deref(),
        &user_meta,
    )
}

// -------------------------
// ListObjectsV2 (stateless traversal stack token)
// -------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ListV2Token {
    v:         u8,
    bucket:    String,
    prefix:    String,           // original request prefix (possibly empty)
    delimiter: Option<String>,   // Some("/") or None (recursive)
    stack:     Vec<ListV2Frame>, // root..deepest
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ListV2Frame {
    dir:   String, // key prefix for this directory frame ("" or ends with "/")
    after: String, // sort-key cursor within this dir ("" means start)
}

fn encode_token(tok: &ListV2Token) -> Result<String> {
    let js = serde_json::to_vec(tok)?;
    Ok(URL_SAFE_NO_PAD.encode(js))
}

fn decode_token(s: &str) -> Result<ListV2Token> {
    let raw = URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(|e| anyhow!("bad continuation-token: {e}"))?;
    let tok: ListV2Token =
        serde_json::from_slice(&raw).map_err(|e| anyhow!("bad continuation-token json: {e}"))?;
    Ok(tok)
}

// Split prefix into (dir_prefix, leaf_filter).
// If prefix ends with '/', it's a pure directory prefix.
// Otherwise, list starts from the parent dir, and filters first-level names by leaf_filter.
fn split_prefix(prefix: &str) -> (String, Option<String>) {
    if prefix.is_empty() || prefix.ends_with('/') {
        return (prefix.to_string(), None);
    }
    if let Some((a, b)) = prefix.rsplit_once('/') {
        let mut dir = a.to_string();
        if !dir.is_empty() {
            dir.push('/');
        }
        return (dir, Some(b.to_string()));
    }
    ("".to_string(), Some(prefix.to_string()))
}

// Build a traversal stack that resumes "after" a last-emitted key.
// Used for StartAfter (when no ContinuationToken is provided).
fn build_stack_from_last(dir_prefix: &str, last_key: &str, recursive: bool) -> Vec<ListV2Frame> {
    let mut frames = Vec::new();
    frames.push(ListV2Frame { dir: dir_prefix.to_string(), after: "".to_string() });

    if !last_key.starts_with(dir_prefix) {
        return frames;
    }
    let rel = &last_key[dir_prefix.len()..];
    let rel = rel.trim_start_matches('/');
    if rel.is_empty() {
        return frames;
    }

    if !recursive {
        // Non-recursive: cursor is just the "immediate child" sort-key
        // (file name or "dir/").
        let first = rel.split('/').next().unwrap_or(rel);
        let after = if last_key.ends_with('/') { format!("{first}/") } else { first.to_string() };
        frames[0].after = after;
        return frames;
    }

    let parts: Vec<&str> = rel.split('/').filter(|p| !p.is_empty()).collect();
    if parts.is_empty() {
        return frames;
    }
    if parts.len() == 1 {
        frames[0].after = parts[0].to_string();
        return frames;
    }

    // Descend directories for all but last segment.
    let mut cur_dir = dir_prefix.to_string();
    for (i, seg) in parts.iter().enumerate() {
        if i == parts.len() - 1 {
            // last segment is file name
            if let Some(last) = frames.last_mut() {
                last.after = (*seg).to_string();
            }
            break;
        }

        // ancestor frame "after" is "seg/"
        if let Some(last) = frames.last_mut() {
            last.after = format!("{seg}/");
        }
        // push child frame
        cur_dir.push_str(seg);
        cur_dir.push('/');
        frames.push(ListV2Frame { dir: cur_dir.clone(), after: "".to_string() });
    }

    frames
}

#[derive(Clone)]
struct DirItem {
    name:     String,
    sort_key: String, // name or name + "/"
    is_dir:   bool,
    path:     PathBuf,
}

struct RuntimeFrame {
    dir_key: String,               // key prefix for this directory ("" or ends_with "/")
    after:   String,               // cursor sort_key
    entries: Option<Vec<DirItem>>, // None = not loaded yet, Some = loaded (possibly empty)
    idx:     usize,
}

fn read_dir_sorted(dir_fs: &Path) -> Result<Vec<DirItem>> {
    let mut out = Vec::new();
    let rd = match fs::read_dir(dir_fs) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(anyhow!("permission denied"));
        }
        Err(e) => return Err(anyhow!("read_dir failed: {e}")),
    };

    for ent in rd {
        let ent = match ent {
            Ok(e) => e,
            Err(_) => continue,
        };
        let ft = match ent.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };

        // S3 keys are UTF-8; lossy conversion is pragmatic here.
        let name = ent.file_name().to_string_lossy().to_string();
        if name.is_empty() || name == "." || name == ".." {
            continue;
        }

        // For symlinks, follow to determine whether the target is a directory
        // so they list as folders (CommonPrefixes / trailing-slash key) rather
        // than as plain files. Broken/unreachable links fall back to file so
        // they still appear in the listing — `aws s3 rm --recursive` (and
        // similar) need to see them to issue a DELETE. Mirrors the
        // follow-then-fall-back pattern used by statx_info().
        let is_dir = if ft.is_symlink() {
            fs::metadata(ent.path()).map(|m| m.is_dir()).unwrap_or(false)
        } else {
            ft.is_dir()
        };
        let sort_key = if is_dir { format!("{name}/") } else { name.clone() };
        out.push(DirItem { name, sort_key, is_dir, path: ent.path() });
    }

    // Sort by key-order: files "name" vs dirs "name/" (important for correct lexicographic order).
    out.sort_by(|a, b| a.sort_key.cmp(&b.sort_key));
    Ok(out)
}

fn first_index_after(entries: &[DirItem], after: &str) -> usize {
    if after.is_empty() {
        return 0;
    }
    // linear scan is fine for typical dir sizes; replace with binary search if needed.
    for (i, it) in entries.iter().enumerate() {
        if it.sort_key.as_str() > after {
            return i;
        }
    }
    entries.len()
}

/// Load directory entries for a frame if not already loaded
fn ensure_frame_loaded(
    frame: &mut RuntimeFrame,
    cfg: &Cfg,
    bucket: &str,
    leaf_filter: Option<&str>,
    is_root: bool,
) -> Result<()> {
    if frame.entries.is_some() {
        return Ok(()); // Already loaded
    }

    let dir_fs = match join_object_path(&cfg.posix_root, bucket, &frame.dir_key) {
        Ok(p) => p,
        Err(e) => return Err(anyhow!("failed to compute dir path: {e}")),
    };

    let mut entries = read_dir_sorted(&dir_fs)?;

    // Apply leaf_filter only at root frame (the directory where prefix "starts").
    if is_root {
        if let Some(lf) = leaf_filter {
            entries.retain(|it| it.sort_key.starts_with(lf));
        }
    }

    // Find starting index
    frame.idx = first_index_after(&entries, &frame.after);
    frame.entries = Some(entries);

    Ok(())
}

async fn owner_info(
    client: &nss_client::NssClient,
    uid: u32,
) -> s32p_support::s3xml::ListOwnerInfo {
    let id = uid.to_string();
    let display_name = client.lookup(uid).await.unwrap_or_else(|| id.clone());
    s32p_support::s3xml::ListOwnerInfo { id, display_name }
}

async fn handle_list_objects_v2(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    let bucket = class.bucket.as_deref().unwrap_or("");
    if bucket.is_empty() {
        return s32p_support::s3resp::not_implemented("missing bucket", Some(req.uri().path()));
    }

    // list-type=2 is already checked by classifier, keep defensive.
    if class.query.first("list-type") != Some("2") {
        return s32p_support::s3resp::not_implemented("missing list-type=2", None);
    }

    // If bucket doesn't exist, return NoSuchBucket (S3 semantics).
    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => {}
        Ok(false) => {
            return s32p_support::s3resp::no_such_bucket(
                "bucket not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    }

    let prefix = class.query.first("prefix").unwrap_or("").to_string();

    // delimiter: only "/" is supported; if absent => recursive.
    let delimiter_q = class
        .query
        .first("delimiter")
        .and_then(|d| if d.is_empty() { None } else { Some(d) });

    let recursive = match delimiter_q {
        None => true,
        Some("/") => false,
        Some(_) => {
            return s32p_support::s3resp::not_implemented("only delimiter=/ is supported", None);
        }
    };

    let max_keys = class
        .query
        .first("max-keys")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(1000)
        .min(1000);

    let fetch_owner = match class.query.first("fetch-owner") {
        Some(v) if v == "true" || v == "1" || v.eq_ignore_ascii_case("true") => true,
        Some(_) => true, // if present, treat as "requested"
        None => false,
    };

    let continuation_token_in = class.query.first("continuation-token").map(|s| s.to_string());
    let start_after = class.query.first("start-after").map(|s| s.to_string());

    // EncodingType=url support: when requested, percent-encode all key/prefix
    // strings in the response (Key, CommonPrefixes/Prefix, echoed Prefix,
    // Delimiter, StartAfter) per AWS S3 conventions.
    let url_encode = matches!(class.query.first("encoding-type"), Some("url"));
    let enc = |s: &str| -> String {
        if url_encode { s32p_support::uri_encoding::s3_url_encode(s) } else { s.to_string() }
    };
    let encoding_type_resp = if url_encode { Some("url") } else { None };

    // check the prefix, we don't list multipart upload dirs
    if !prefix.is_empty() && is_reserved_first_segment(&prefix, cfg.mpu_dir_name.as_str()) {
        // behave as if it doesn't exist
        let prefix_enc = enc(&prefix);
        let start_after_enc = start_after.as_deref().map(enc);
        return s32p_support::s3resp::list_objects_v2(
            bucket,
            Some(&prefix_enc),
            if recursive { None } else { Some("/") },
            0,
            max_keys,
            false,
            continuation_token_in.as_deref(),
            None,
            start_after_enc.as_deref(),
            encoding_type_resp,
            &[],
            &[],
        );
    }

    let (dir_prefix, leaf_filter) = split_prefix(&prefix);

    // Filesystem start dir is bucket + dir_prefix
    let start_dir_fs = match join_object_path(&cfg.posix_root, bucket, &dir_prefix) {
        Ok(p) => p,
        Err(e) => return s32p_support::s3resp::access_denied(&e.to_string(), None),
    };

    // If the *prefix directory* doesn't exist (but bucket exists), return an empty listing.
    if !start_dir_fs.exists() || !start_dir_fs.is_dir() {
        let prefix_enc = enc(&prefix);
        let start_after_enc = start_after.as_deref().map(enc);
        return s32p_support::s3resp::list_objects_v2(
            bucket,
            Some(&prefix_enc),
            if recursive { None } else { Some("/") },
            0,
            max_keys,
            false,
            continuation_token_in.as_deref(),
            None,
            start_after_enc.as_deref(),
            encoding_type_resp,
            &[],
            &[],
        );
    }

    // Build initial stack (from ContinuationToken or StartAfter)
    let mut token_stack: Vec<ListV2Frame> = if let Some(ct) = &continuation_token_in {
        match decode_token(ct) {
            Ok(tok) => {
                // Validate token belongs to the same listing shape
                if tok.bucket != bucket
                    || tok.prefix != prefix
                    || tok.delimiter.as_deref() != delimiter_q
                {
                    let mut parts = Vec::new();
                    if tok.bucket != bucket {
                        parts.push(format!(
                            "request-bucket {bucket} != token-bucket {}",
                            tok.bucket
                        ));
                    }
                    if tok.prefix != prefix {
                        parts.push(format!(
                            "request-prefix {prefix} != token-prefix {}",
                            tok.prefix
                        ));
                    }
                    if tok.delimiter.as_deref() != delimiter_q {
                        parts.push(format!(
                            "request-delimiter {:?} != token-delimiter {:?}",
                            delimiter_q,
                            tok.delimiter.as_deref()
                        ));
                    }

                    return s32p_support::s3resp::s3_error(
                        StatusCode::BAD_REQUEST,
                        s32p_support::s3xml::error_code::INVALID_REQUEST,
                        &format!(
                            "continuation-token does not match request parameters: {}",
                            parts.join(", ")
                        ),
                        Some(req.uri().path()),
                        None,
                    );
                }
                tok.stack
            }
            Err(e) => {
                return s32p_support::s3resp::s3_error(
                    StatusCode::BAD_REQUEST,
                    s32p_support::s3xml::error_code::INVALID_REQUEST,
                    &e.to_string(),
                    Some(req.uri().path()),
                    None,
                );
            }
        }
    } else if let Some(sa) = &start_after {
        build_stack_from_last(&dir_prefix, sa, recursive)
    } else {
        vec![ListV2Frame { dir: dir_prefix.clone(), after: "".to_string() }]
    };

    // Reject continuation tokens that descend into the reserved dir
    if token_stack
        .iter()
        .any(|fr| is_reserved_first_segment(&fr.dir, &cfg.mpu_dir_name))
    {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_REQUEST,
            "continuation-token points into a reserved prefix",
            Some(req.uri().path()),
            None,
        );
    }

    if token_stack.is_empty() {
        token_stack.push(ListV2Frame { dir: dir_prefix.clone(), after: "".to_string() });
    }

    // Build runtime frames from token stack
    let mut stack: Vec<RuntimeFrame> = Vec::new();
    for fr in token_stack {
        stack.push(RuntimeFrame {
            dir_key: fr.dir.clone(),
            after:   fr.after.clone(),
            entries: None, // Will be loaded lazily
            idx:     0,
        });
    }

    let mut contents: Vec<s32p_support::s3xml::ListObjectInfo> = Vec::new();
    let mut common_prefixes: Vec<String> = Vec::new();

    // Produce up to max_keys “results”; in delimiter mode keycount includes common prefixes
    while (contents.len() as u32 + common_prefixes.len() as u32) < max_keys {
        let stack_len = stack.len();
        let Some(top) = stack.last_mut() else {
            break;
        };

        // Lazy load entries if not already loaded
        if top.entries.is_none() {
            let is_root_frame = stack_len == 1;
            if let Err(e) =
                ensure_frame_loaded(top, &cfg, bucket, leaf_filter.as_deref(), is_root_frame)
            {
                tracing::warn!("Failed to load directory {}: {}", top.dir_key, e);
                stack.pop();
                continue;
            }
        }

        let entries = top.entries.as_ref().unwrap(); // Safe because we just ensured it's loaded

        if top.idx >= entries.len() {
            stack.pop();
            continue;
        }

        let it = entries[top.idx].clone();
        top.idx += 1;
        top.after = it.sort_key.clone();

        // Hide the internal MPU directory at bucket root (and never descend into it)
        if top.dir_key.is_empty() && it.is_dir && it.name == cfg.mpu_dir_name {
            continue;
        }

        if it.is_dir {
            if !recursive {
                // delimiter=/ mode: emit CommonPrefix, don't descend
                let cp = format!("{}{}{}", top.dir_key, it.name, "/");
                common_prefixes.push(cp);
                continue;
            }

            // Recursive mode: surface leaf-empty directories as 0-byte
            // directory-marker objects (key ends in '/'). Without this, a
            // recursive ListObjects walk descends into an empty dir and
            // produces no Contents, so clients that delete-by-listing
            // (iOS S3 apps, mc rm --recursive, aws s3 rm --recursive) can't
            // reach the dir to remove it. We only mark *leaf-empty* dirs;
            // for non-empty parents, prune_empty_parents collapses the
            // chain after the leaf marker is deleted.
            let dir_is_empty =
                std::fs::read_dir(&it.path).map(|mut rd| rd.next().is_none()).unwrap_or(false);

            if dir_is_empty {
                if let Some(stx) = statx_info(&it.path) {
                    let key = format!("{}{}{}", top.dir_key, it.name, "/");
                    if key.starts_with(&prefix) {
                        let owner = if fetch_owner {
                            Some(owner_info(&app.nss_client, stx.uid).await)
                        } else {
                            None
                        };
                        contents.push(s32p_support::s3xml::ListObjectInfo {
                            key,
                            last_modified: s32p_support::s3xml::format_s3_time_system(stx.mtime),
                            etag: format_inode_etag(stx.ino),
                            size: 0,
                            owner,
                        });
                    }
                }
                continue;
            }

            // recursive: descend
            let child_key = format!("{}{}{}", top.dir_key, it.name, "/");
            stack.push(RuntimeFrame {
                dir_key: child_key,
                after:   "".to_string(),
                entries: None, // Will be loaded lazily
                idx:     0,
            });
            continue;
        }

        // file: emit Contents using statx (AT_STATX_DONT_SYNC) for Lustre LSOM friendliness
        let stx = match statx_info(&it.path) {
            Some(s) => s,
            None => continue,
        };

        let key = format!("{}{}", top.dir_key, it.name);
        // Extra safety: only emit keys matching original prefix
        if !key.starts_with(&prefix) {
            continue;
        }

        let last_modified = s32p_support::s3xml::format_s3_time_system(stx.mtime);
        let etag = format_inode_etag(stx.ino);
        let size = stx.size;

        let owner =
            if fetch_owner { Some(owner_info(&app.nss_client, stx.uid).await) } else { None };

        contents.push(s32p_support::s3xml::ListObjectInfo {
            key,
            last_modified,
            etag,
            size,
            owner,
        });
    }

    let key_count = (contents.len() + common_prefixes.len()) as u32;
    let is_truncated = key_count >= max_keys && !stack.is_empty();

    let next_token = if is_truncated && key_count > 0 {
        // Build token from current runtime stack
        let tok = ListV2Token {
            v:         1,
            bucket:    bucket.to_string(),
            prefix:    prefix.clone(),
            delimiter: if recursive { None } else { Some("/".to_string()) },
            stack:     stack
                .iter()
                .map(|rf| ListV2Frame { dir: rf.dir_key.clone(), after: rf.after.clone() })
                .collect(),
        };
        encode_token(&tok).ok()
    } else {
        None
    };

    // Apply EncodingType=url to the response (echoed prefix/start-after, Contents.Key,
    // CommonPrefixes/Prefix). Continuation tokens are already URL-safe (base64url),
    // and `Delimiter` is always `/` here so it round-trips fine either way — we still
    // pass the raw `/` because `s3_url_encode("/")` would yield `%2F` which AWS's own
    // responses also produce when EncodingType=url, but matching v1 behavior we keep
    // the delimiter unencoded for compatibility with naive clients.
    let prefix_enc = enc(&prefix);
    let start_after_enc = start_after.as_deref().map(enc);
    let contents_enc: Vec<s32p_support::s3xml::ListObjectInfo> = if url_encode {
        contents
            .iter()
            .map(|c| s32p_support::s3xml::ListObjectInfo {
                key:           enc(&c.key),
                last_modified: c.last_modified.clone(),
                etag:          c.etag.clone(),
                size:          c.size,
                owner:         c.owner.clone(),
            })
            .collect()
    } else {
        contents
    };
    let common_prefixes_enc: Vec<String> =
        if url_encode { common_prefixes.iter().map(|p| enc(p)).collect() } else { common_prefixes };

    s32p_support::s3resp::list_objects_v2(
        bucket,
        Some(&prefix_enc),
        if recursive { None } else { Some("/") },
        key_count,
        max_keys,
        is_truncated && next_token.is_some(),
        continuation_token_in.as_deref(),
        next_token.as_deref(),
        start_after_enc.as_deref(),
        encoding_type_resp,
        &contents_enc,
        &common_prefixes_enc,
    )
}

// -------------------------
// ListObjectsV1
// -------------------------
//
// Reuses the v2 directory walk (RuntimeFrame stack, ensure_frame_loaded, split_prefix,
// build_stack_from_last) and only differs in:
//   - pagination uses `marker` (a key) instead of an opaque `continuation-token`
//   - on truncation we emit `NextMarker` (the last emitted key/common-prefix);
//     no continuation token machinery
//   - the response shape: see `s3resp::list_objects_v1`

async fn handle_list_objects_v1(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    let bucket = class.bucket.as_deref().unwrap_or("");
    if bucket.is_empty() {
        return s32p_support::s3resp::not_implemented("missing bucket", Some(req.uri().path()));
    }

    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => {}
        Ok(false) => {
            return s32p_support::s3resp::no_such_bucket(
                "bucket not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    }

    let prefix = class.query.first("prefix").unwrap_or("").to_string();
    let marker = class.query.first("marker").unwrap_or("").to_string();

    let delimiter_q = class
        .query
        .first("delimiter")
        .and_then(|d| if d.is_empty() { None } else { Some(d) });

    let recursive = match delimiter_q {
        None => true,
        Some("/") => false,
        Some(_) => {
            return s32p_support::s3resp::not_implemented("only delimiter=/ is supported", None);
        }
    };

    let max_keys = class
        .query
        .first("max-keys")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(1000)
        .min(1000);

    let url_encode = matches!(class.query.first("encoding-type"), Some("url"));
    let enc = |s: &str| -> String {
        if url_encode { s32p_support::uri_encoding::s3_url_encode(s) } else { s.to_string() }
    };
    let encoding_type_resp = if url_encode { Some("url") } else { None };

    if !prefix.is_empty() && is_reserved_first_segment(&prefix, cfg.mpu_dir_name.as_str()) {
        return s32p_support::s3resp::list_objects_v1(
            bucket,
            &enc(&prefix),
            if recursive { None } else { Some("/") },
            &enc(&marker),
            None,
            max_keys,
            false,
            encoding_type_resp,
            &[],
            &[],
        );
    }

    let (dir_prefix, leaf_filter) = split_prefix(&prefix);

    let start_dir_fs = match join_object_path(&cfg.posix_root, bucket, &dir_prefix) {
        Ok(p) => p,
        Err(e) => return s32p_support::s3resp::access_denied(&e.to_string(), None),
    };

    if !start_dir_fs.exists() || !start_dir_fs.is_dir() {
        return s32p_support::s3resp::list_objects_v1(
            bucket,
            &enc(&prefix),
            if recursive { None } else { Some("/") },
            &enc(&marker),
            None,
            max_keys,
            false,
            encoding_type_resp,
            &[],
            &[],
        );
    }

    // Initial frame stack: marker positions us "after" a previously emitted key.
    let token_stack: Vec<ListV2Frame> = if !marker.is_empty() {
        build_stack_from_last(&dir_prefix, &marker, recursive)
    } else {
        vec![ListV2Frame { dir: dir_prefix.clone(), after: "".to_string() }]
    };

    if token_stack
        .iter()
        .any(|fr| is_reserved_first_segment(&fr.dir, &cfg.mpu_dir_name))
    {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_REQUEST,
            "marker points into a reserved prefix",
            Some(req.uri().path()),
            None,
        );
    }

    let mut stack: Vec<RuntimeFrame> = Vec::new();
    for fr in token_stack {
        stack.push(RuntimeFrame {
            dir_key: fr.dir.clone(),
            after:   fr.after.clone(),
            entries: None,
            idx:     0,
        });
    }

    let mut contents: Vec<s32p_support::s3xml::ListObjectInfo> = Vec::new();
    let mut common_prefixes: Vec<String> = Vec::new();
    // For NextMarker: the last *thing* emitted (key or common-prefix) wins.
    let mut last_emitted: Option<String> = None;

    while (contents.len() as u32 + common_prefixes.len() as u32) < max_keys {
        let stack_len = stack.len();
        let Some(top) = stack.last_mut() else {
            break;
        };

        if top.entries.is_none() {
            let is_root_frame = stack_len == 1;
            if let Err(e) =
                ensure_frame_loaded(top, &cfg, bucket, leaf_filter.as_deref(), is_root_frame)
            {
                tracing::warn!("Failed to load directory {}: {}", top.dir_key, e);
                stack.pop();
                continue;
            }
        }

        let entries = top.entries.as_ref().unwrap();

        if top.idx >= entries.len() {
            stack.pop();
            continue;
        }

        let it = entries[top.idx].clone();
        top.idx += 1;
        top.after = it.sort_key.clone();

        if top.dir_key.is_empty() && it.is_dir && it.name == cfg.mpu_dir_name {
            continue;
        }

        if it.is_dir {
            if !recursive {
                let cp = format!("{}{}{}", top.dir_key, it.name, "/");
                last_emitted = Some(cp.clone());
                common_prefixes.push(cp);
                continue;
            }

            // Surface leaf-empty directories as 0-byte directory markers in
            // recursive listings — see the matching v2 handler for rationale.
            let dir_is_empty =
                std::fs::read_dir(&it.path).map(|mut rd| rd.next().is_none()).unwrap_or(false);

            if dir_is_empty {
                if let Some(stx) = statx_info(&it.path) {
                    let key = format!("{}{}{}", top.dir_key, it.name, "/");
                    if key.starts_with(&prefix) {
                        last_emitted = Some(key.clone());
                        let owner = Some(owner_info(&app.nss_client, stx.uid).await);
                        contents.push(s32p_support::s3xml::ListObjectInfo {
                            key,
                            last_modified: s32p_support::s3xml::format_s3_time_system(stx.mtime),
                            etag: format_inode_etag(stx.ino),
                            size: 0,
                            owner,
                        });
                    }
                }
                continue;
            }

            let child_key = format!("{}{}{}", top.dir_key, it.name, "/");
            stack.push(RuntimeFrame {
                dir_key: child_key,
                after:   "".to_string(),
                entries: None,
                idx:     0,
            });
            continue;
        }

        let stx = match statx_info(&it.path) {
            Some(s) => s,
            None => continue,
        };

        let key = format!("{}{}", top.dir_key, it.name);
        if !key.starts_with(&prefix) {
            continue;
        }

        let last_modified = s32p_support::s3xml::format_s3_time_system(stx.mtime);
        let etag = format_inode_etag(stx.ino);
        let size = stx.size;

        // v1 always carries Owner in Contents.
        let owner = Some(owner_info(&app.nss_client, stx.uid).await);

        last_emitted = Some(key.clone());
        contents.push(s32p_support::s3xml::ListObjectInfo {
            key,
            last_modified,
            etag,
            size,
            owner,
        });
    }

    let total = (contents.len() + common_prefixes.len()) as u32;
    let is_truncated = total >= max_keys && !stack.is_empty();

    // S3 v1: NextMarker is REQUIRED in the response only when delimiter is set; otherwise
    // it's optional and clients fall back to using the last key in Contents as the next
    // marker. We always emit it on truncation for consistency.
    let next_marker = if is_truncated { last_emitted } else { None };

    let prefix_enc = enc(&prefix);
    let marker_enc = enc(&marker);
    let next_marker_enc = next_marker.as_deref().map(enc);
    let contents_enc: Vec<s32p_support::s3xml::ListObjectInfo> = if url_encode {
        contents
            .iter()
            .map(|c| s32p_support::s3xml::ListObjectInfo {
                key:           enc(&c.key),
                last_modified: c.last_modified.clone(),
                etag:          c.etag.clone(),
                size:          c.size,
                owner:         c.owner.clone(),
            })
            .collect()
    } else {
        contents
    };
    let common_prefixes_enc: Vec<String> =
        if url_encode { common_prefixes.iter().map(|p| enc(p)).collect() } else { common_prefixes };

    s32p_support::s3resp::list_objects_v1(
        bucket,
        &prefix_enc,
        if recursive { None } else { Some("/") },
        &marker_enc,
        next_marker_enc.as_deref(),
        max_keys,
        is_truncated,
        encoding_type_resp,
        &contents_enc,
        &common_prefixes_enc,
    )
}

// -------------------------
// PutObject and other write operations
// -------------------------

fn parse_u64_header(headers: &HeaderMap, name: &str) -> Result<u64> {
    let v = headers
        .get(name)
        .ok_or_else(|| anyhow!("missing header {name}"))?
        .to_str()
        .map_err(|_| anyhow!("invalid utf8 in header {name}"))?;
    v.parse::<u64>().map_err(|_| anyhow!("invalid integer in header {name}: {v}"))
}

pub(crate) fn parse_copy_source(headers: &HeaderMap) -> Result<(String, String)> {
    let raw = headers
        .get("x-amz-copy-source")
        .ok_or_else(|| anyhow!("missing x-amz-copy-source"))?
        .to_str()
        .map_err(|_| anyhow!("invalid x-amz-copy-source"))?
        .trim();

    // Strip any version/query component (we don't support versioned copies yet).
    let raw = raw.split_once('?').map(|(p, _)| p).unwrap_or(raw);
    let raw = raw.trim_start_matches('/');
    if raw.is_empty() {
        return Err(anyhow!("invalid x-amz-copy-source"));
    }

    let decoded = s32p_support::uri_encoding::percent_decode_path_segments_lossy(raw);
    let mut it = decoded.splitn(2, '/');
    let bucket = it.next().unwrap_or("").to_string();
    let key = it.next().unwrap_or("").to_string();
    if bucket.is_empty() || key.is_empty() {
        return Err(anyhow!("invalid x-amz-copy-source (expected /bucket/key)"));
    }
    Ok((bucket, key))
}

/// Returns (is_streaming, logical_len).
///
/// "Streaming" here means the request body is `aws-chunked`-framed and the
/// decoder must strip framing before writing payload bytes. AWS uses four
/// `x-amz-content-sha256` tokens for this, all sharing the `STREAMING-`
/// prefix:
///
/// - `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`          (signed chunks, no trailer)
/// - `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`  (signed chunks + trailer)
/// - `STREAMING-UNSIGNED-PAYLOAD-TRAILER`          (no per-chunk sig, trailer with checksum)
/// - `STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD[-TRAILER]` (SigV4a equivalents)
///
/// They share one wire format: `<hex-size>[;chunk-signature=…]\r\n<payload>\r\n …
/// 0\r\n<trailers>\r\n\r\n`. The decoder in `streaming::aws_chunked` ignores
/// the optional `;chunk-signature=` extension and reads trailers-until-blank,
/// so the same code path covers all four. The wire-name is *only* used to
/// decide which length header to trust:
///
/// - streaming → `x-amz-decoded-content-length` (logical body)
/// - non-streaming (`UNSIGNED-PAYLOAD`, an explicit hex digest, …)
///   → `Content-Length`
///
/// Matching on the `STREAMING-` prefix (case-insensitive — AWS docs are
/// uppercase but the canonical-request layer is byte-exact, leaving the
/// header value the SDK chooses) covers the current taxonomy and any future
/// `STREAMING-*-TRAILER` variants without another code change.
fn compute_logical_len(headers: &HeaderMap) -> Result<(bool, u64)> {
    let is_streaming = headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("STREAMING-"));

    let logical_len = if is_streaming {
        parse_u64_header(headers, "x-amz-decoded-content-length")?
    } else {
        parse_u64_header(headers, "content-length")?
    };

    Ok((is_streaming, logical_len))
}

async fn handle_put_object(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    // Allow SigV4 presign query params; reject only effective (non-presign) query params.
    if has_effective_query(&req) {
        return s32p_support::s3resp::not_implemented("query parameters are not implemented", None);
    }

    let bucket = class.bucket.as_deref().unwrap_or("");
    let key = class.key.as_deref().unwrap_or("");

    // don't allow to write into the multipart upload directory
    if is_reserved_first_segment(key, &cfg.mpu_dir_name) {
        return s32p_support::s3resp::access_denied("reserved key prefix", Some(req.uri().path()));
    }

    if bucket.is_empty() || key.is_empty() {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_REQUEST,
            "missing bucket or key",
            Some(req.uri().path()),
            None,
        );
    }

    // S3 semantics: if bucket doesn't exist => NoSuchBucket
    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => {}
        Ok(false) => {
            return s32p_support::s3resp::no_such_bucket(
                "bucket not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    }

    let obj_path = match join_object_path(&cfg.posix_root, bucket, key) {
        Ok(p) => p,
        Err(e) => return s32p_support::s3resp::access_denied(&e.to_string(), None),
    };

    // Directory-marker PUT: a key ending in '/' addresses a filesystem
    // directory (the same shape that listing emits for empty leaves and
    // that handle_delete_object rmdir-s). We mkdir_p and return success,
    // skipping the conditional-header / streaming machinery — clients
    // don't send If-Match on dir markers, and the precondition path below
    // assumes a regular file (etag-from-inode, etc.).
    if key.ends_with('/') {
        // Markers are 0-byte by S3 convention. Require an explicit zero
        // length and reject anything else rather than silently dropping a
        // body the client thought we'd store. The size is read through
        // compute_logical_len because an aws-chunked body carries no
        // Content-Length at all — it announces its length in
        // `x-amz-decoded-content-length`.
        match compute_logical_len(req.headers()) {
            Ok((_, 0)) => {}
            Ok(_) => {
                return s32p_support::s3resp::invalid_request(
                    "directory-marker PUT must have zero length",
                    Some(req.uri().path()),
                );
            }
            Err(e) => {
                return s32p_support::s3resp::s3_error(
                    StatusCode::BAD_REQUEST,
                    s32p_support::s3xml::error_code::INVALID_REQUEST,
                    &e.to_string(),
                    Some(req.uri().path()),
                    None,
                );
            }
        }

        if let Err(e) = std::fs::create_dir_all(&obj_path) {
            tracing::warn!(
                "directory-marker PUT create_dir_all {} failed: {e}",
                obj_path.display()
            );
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                return s32p_support::s3resp::access_denied(
                    "permission denied",
                    Some(req.uri().path()),
                );
            }
            return s32p_support::s3resp::internal_error(
                "failed to create directory marker",
                Some(req.uri().path()),
                None,
            );
        }

        let meta = match std::fs::metadata(&obj_path) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(
                    "directory-marker PUT stat after create failed for {}: {e}",
                    obj_path.display()
                );
                return s32p_support::s3resp::internal_error(
                    "failed to stat directory marker",
                    Some(req.uri().path()),
                    None,
                );
            }
        };
        let etag = format_inode_etag(meta.ino());
        return s32p_support::s3resp::put_object_ok(&etag);
    }

    // pick decoded length for streaming payloads
    let (is_aws_chunked, logical_len) = match compute_logical_len(req.headers()) {
        Ok(v) => v,
        Err(e) => {
            return s32p_support::s3resp::s3_error(
                StatusCode::BAD_REQUEST,
                s32p_support::s3xml::error_code::INVALID_REQUEST,
                &e.to_string(),
                Some(req.uri().path()),
                None,
            );
        }
    };

    // S3 Express directory-bucket append (PutObject with
    // `x-amz-write-offset-bytes`). The header must equal the current
    // object size; the body is streamed at that offset without
    // truncating. Mountpoint-s3 in `--incremental-upload` mode drives
    // this path. offset == 0 is treated as a normal create-or-replace
    // PUT and falls through to the regular code path below.
    let write_offset = match parse_write_offset_header(req.headers()) {
        Ok(v) => v,
        Err(reason) => {
            return s32p_support::s3resp::s3_error(
                StatusCode::BAD_REQUEST,
                s32p_support::s3xml::error_code::INVALID_ARGUMENT,
                reason,
                Some(req.uri().path()),
                None,
            );
        }
    };

    if let Some(offset) = write_offset
        && offset > 0
    {
        return handle_put_object_append(
            req,
            app.clone(),
            obj_path,
            offset,
            logical_len,
            is_aws_chunked,
        )
        .await;
    }

    // check preconditions
    let cond = match parse_conditional_headers(req.headers()) {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("invalid conditional headers: {e}");
            return s32p_support::s3resp::invalid_request(&msg, Some(req.uri().path()));
        }
    };

    // Determine existing object state (etag + last_modified) if present.
    // Use the unquoted-etag helper so the precondition string round-trips
    // byte-equal against an `If-Match` header the client formed from a
    // prior HEAD/GET response.
    let existing = match fs::metadata(&obj_path) {
        Ok(m) => {
            let etag_existing = format_inode_etag_unquoted(m.ino());
            let lm = m.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            Some((etag_existing, lm))
        }
        Err(_) => None,
    };

    let existing_ref = existing.as_ref().map(|(e, lm)| (e.as_str(), *lm));
    match evaluate_write_preconditions(&cond, existing_ref) {
        PreconditionOutcome::Proceed => {}
        PreconditionOutcome::NotModified => {} // not used for PUT
        PreconditionOutcome::PreconditionFailed => {
            tracing::debug!(
                "Write preconditions failed (412) for PUT operation on {}",
                obj_path.display()
            );
            return s32p_support::s3resp::precondition_failed(
                "PUT precondition failed",
                Some(req.uri().path()),
            );
        }
    }

    // A plain body must announce its size in Content-Length — that is the
    // only length the write path can trust. An aws-chunked body announces
    // it in `x-amz-decoded-content-length` and rides `Transfer-Encoding:
    // chunked`, so it legitimately has no Content-Length; compute_logical_len
    // has already taken its size from the decoded header. AWS SDKs send
    // exactly that shape for an ordinary upload over https, where the
    // default CRC32 checksum moves into an aws-chunked trailer.
    if !is_aws_chunked && req.headers().get(http::header::CONTENT_LENGTH).is_none() {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_REQUEST,
            "missing Content-Length",
            Some(req.uri().path()),
            None,
        );
    }

    // Extract and validate the optional `x-amz-tagging` header up front.
    // The header value is already URL-form (`team=a&stage=raw`) — the wire
    // shape matches the on-disk xattr, so it stores verbatim. Validating
    // here means a malformed tag set is rejected before any I/O.
    let tagging_header: Option<String> =
        match req.headers().get("x-amz-tagging").map(|v| v.to_str()) {
            Some(Ok(s)) => Some(s.to_string()),
            Some(Err(_)) => {
                return s32p_support::s3resp::s3_error(
                    StatusCode::BAD_REQUEST,
                    s32p_support::s3xml::error_code::INVALID_TAG,
                    "invalid x-amz-tagging header encoding",
                    Some(req.uri().path()),
                    None,
                );
            }
            None => None,
        };
    if let Some(s) = &tagging_header
        && let Err(reason) = s32p_support::s3xml::validate_tagging_urlform(s)
    {
        tracing::debug!("PutObject x-amz-tagging invalid: {reason}");
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_TAG,
            "invalid x-amz-tagging header",
            Some(req.uri().path()),
            None,
        );
    }

    // Extract and validate the optional user metadata (`x-amz-meta-*`
    // headers) and explicit `Content-Type`. Both rejected up front so a
    // malformed value can't materialize a half-tagged object on disk.
    let user_meta_urlform: String =
        match s32p_support::s3resp::extract_user_meta_headers(req.headers()) {
            Ok(s) => s,
            Err(reason) => {
                tracing::debug!("PutObject x-amz-meta-* invalid: {reason}");
                return s32p_support::s3resp::s3_error(
                    StatusCode::BAD_REQUEST,
                    s32p_support::s3xml::error_code::INVALID_ARGUMENT,
                    "invalid x-amz-meta-* header",
                    Some(req.uri().path()),
                    None,
                );
            }
        };
    if let Err(reason) = s32p_support::s3xml::validate_user_metadata_urlform(&user_meta_urlform) {
        tracing::debug!("PutObject user metadata invalid: {reason}");
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_ARGUMENT,
            "invalid user metadata",
            Some(req.uri().path()),
            None,
        );
    }
    let content_type_header: Option<String> =
        match req.headers().get(http::header::CONTENT_TYPE).map(|v| v.to_str()) {
            Some(Ok(s)) => Some(s.to_string()),
            Some(Err(_)) => {
                return s32p_support::s3resp::s3_error(
                    StatusCode::BAD_REQUEST,
                    s32p_support::s3xml::error_code::INVALID_ARGUMENT,
                    "invalid Content-Type header encoding",
                    Some(req.uri().path()),
                    None,
                );
            }
            None => None,
        };
    if let Some(ct) = &content_type_header
        && let Err(reason) = s32p_support::s3xml::validate_content_type(ct)
    {
        tracing::debug!("PutObject Content-Type invalid: {reason}");
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_ARGUMENT,
            "invalid Content-Type header",
            Some(req.uri().path()),
            None,
        );
    }

    // When the client supplied tagging, user metadata, or an explicit
    // Content-Type at creation time, fail-fast before streaming the body
    // if the backing FS can't store xattrs. The bucket root is a symlink
    // to the real bucket data dir; the probe uses the deref variant so it
    // lands on the same filesystem where `setxattr` will run. Avoids
    // streaming the body, materializing the object, and then discovering
    // ENOTSUP from setxattr (which would leave an object on disk lacking
    // the metadata the client believed they wrote).
    let needs_xattr_probe =
        tagging_header.is_some() || !user_meta_urlform.is_empty() || content_type_header.is_some();
    if needs_xattr_probe {
        let bucket_root = match bucket_root_path(&cfg.posix_root, bucket) {
            Ok(p) => p,
            Err(e) => {
                return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
            }
        };
        if let Some(resp) = require_xattr_support(&app, &bucket_root, req.uri().path()) {
            return resp;
        }
    }

    let (parts, body) = req.into_parts();

    #[cfg(feature = "lustre")]
    let striping = Some(LustreStriping::new(
        cfg.chunk_size as u64,
        stripe_count_for_size(logical_len, cfg.chunk_size as u64, cfg.lustre_max_stripe_count),
    ));
    #[cfg(not(feature = "lustre"))]
    let striping: Option<LustreStriping> = None;

    // Stream-write
    if let Err(e) = write_object_body(
        body,
        WriteObjectDest::Path { path: obj_path.clone(), striping },
        logical_len,
        is_aws_chunked,
        StreamCfg {
            chunk_size: cfg.chunk_size,
            inflight:   cfg.inflight,
            direct_io:  cfg.direct_io,
        },
        app.uring.clone(),
        app.pool.clone(),
    )
    .await
    {
        return s32p_support::s3resp::internal_error(&e.to_string(), Some(parts.uri.path()), None);
    }

    // Build ETag (consistent with reads: inode-based ETag via the shared helper).
    let meta = match std::fs::metadata(&obj_path) {
        Ok(m) => m,
        Err(e) => {
            return s32p_support::s3resp::internal_error(
                &e.to_string(),
                Some(parts.uri.path()),
                None,
            );
        }
    };

    // Apply tagging xattr after the object is materialized. PutObject is
    // create-or-replace, so any pre-existing tagging on the same key/inode
    // is replaced by write_tags (or cleared if the header was absent).
    let to_write = tagging_header.as_deref().unwrap_or("");
    if let Err(e) = write_tags(&obj_path, to_write) {
        tracing::warn!(
            path = %obj_path.display(),
            error = %e,
            "PutObject: failed to write tagging xattr"
        );
        return s32p_support::s3resp::internal_error(
            "failed to write object tags",
            Some(parts.uri.path()),
            None,
        );
    }

    // Apply user metadata and Content-Type xattrs with the same
    // create-or-replace semantics. Empty payload removes the xattr so
    // PutObject of an existing key always lands on a clean slate.
    if let Err(e) = write_user_meta(&obj_path, &user_meta_urlform) {
        tracing::warn!(
            path = %obj_path.display(),
            error = %e,
            "PutObject: failed to write user metadata xattr"
        );
        return s32p_support::s3resp::internal_error(
            "failed to write user metadata",
            Some(parts.uri.path()),
            None,
        );
    }
    let ct_to_write = content_type_header.as_deref().unwrap_or("");
    if let Err(e) = write_content_type(&obj_path, ct_to_write) {
        tracing::warn!(
            path = %obj_path.display(),
            error = %e,
            "PutObject: failed to write Content-Type xattr"
        );
        return s32p_support::s3resp::internal_error(
            "failed to write Content-Type",
            Some(parts.uri.path()),
            None,
        );
    }

    let etag = format_inode_etag(meta.ino());
    s32p_support::s3resp::put_object_ok(&etag)
}

/// Parse the optional `x-amz-write-offset-bytes` header.
///
/// Returns `Ok(None)` if absent. Strict base-10 `u64`; rejects whitespace,
/// signs, hex, or multiple values. Error string is plain prose suitable
/// for the response body.
fn parse_write_offset_header(headers: &http::HeaderMap) -> Result<Option<u64>, &'static str> {
    let mut iter = headers.get_all("x-amz-write-offset-bytes").iter();
    let Some(v) = iter.next() else {
        return Ok(None);
    };
    if iter.next().is_some() {
        return Err("x-amz-write-offset-bytes specified more than once");
    }
    let s = v.to_str().map_err(|_| "x-amz-write-offset-bytes is not valid ASCII")?;
    // Require strict digits: no leading sign, no whitespace, no underscores.
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err("x-amz-write-offset-bytes must be a non-negative integer");
    }
    let n: u64 = s.parse().map_err(|_| "x-amz-write-offset-bytes is out of range")?;
    Ok(Some(n))
}

/// Streamed append PUT (`x-amz-write-offset-bytes > 0`).
///
/// Order of checks mirrors what mountpoint-s3's
/// `parse_put_object_single_error` expects:
///
///   1. directory-marker keys rejected (InvalidRequest 400)
///   2. open existing file — NotFound → NoSuchKey 404
///   3. flock(LOCK_EX) on the opened fd
///   4. stat under the lock; offset != size → InvalidWriteOffset 400
///   5. If-Match / If-None-Match etc. → PreconditionFailed 412
///   6. empty body → InvalidArgument 400 with the literal AWS prefix
///      "Request body cannot be empty" (mountpoint string-matches it)
///   7. stream-write at `offset`, no truncate, no padding
///
/// The inode-based ETag is stable across appends, so the response ETag
/// equals the pre-append ETag. Mountpoint's chained `If-Match` loop
/// works unchanged.
async fn handle_put_object_append(
    req: Request<Incoming>,
    app: Arc<App>,
    obj_path: PathBuf,
    offset: u64,
    logical_len: u64,
    is_aws_chunked: bool,
) -> Resp {
    let cfg = app.cfg.clone();
    let uri_path = req.uri().path().to_owned();

    // Directory-marker keys can't be appended to: they're directories on
    // disk, not regular files, and AWS rejects the combination too.
    if req.uri().path().ends_with('/') {
        return s32p_support::s3resp::invalid_request(
            "x-amz-write-offset-bytes is not valid on a directory marker",
            Some(&uri_path),
        );
    }

    // Parse preconditions up front so a malformed header still maps to
    // InvalidRequest (matches the non-append PUT branch).
    let cond = match parse_conditional_headers(req.headers()) {
        Ok(c) => c,
        Err(e) => {
            return s32p_support::s3resp::invalid_request(
                &format!("invalid conditional headers: {e}"),
                Some(&uri_path),
            );
        }
    };

    // Mirror the ordinary PUT check: Content-Length is required only for
    // a plain body. An aws-chunked one carries its length in
    // `x-amz-decoded-content-length` (already resolved into `logical_len`).
    if !is_aws_chunked && req.headers().get(http::header::CONTENT_LENGTH).is_none() {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_REQUEST,
            "missing Content-Length",
            Some(&uri_path),
            None,
        );
    }

    // Open the destination. `WriteExistingNoTrunc` => O_WRONLY without
    // O_CREAT / O_TRUNC, so a missing key surfaces as NotFound and we
    // emit NoSuchKey — matching mountpoint's
    // `test_append_non_existing_object` expectation. TryDirect lets the
    // streaming layer use O_DIRECT only when the offset+length happen to
    // be aligned (`direct_io_ok_for_aligned_range`); otherwise the open
    // falls back to buffered.
    let direct = if cfg.direct_io { OpenDirect::TryDirect } else { OpenDirect::Buffered };
    let (file, _used_direct) =
        match open_file(&obj_path, OpenMode::WriteExistingNoTrunc, direct, None) {
            Ok(t) => t,
            Err(e) => {
                // open_file wraps the underlying io::Error in anyhow; reach
                // through to classify by ErrorKind.
                let io_kind = e.downcast_ref::<std::io::Error>().map(|ie| ie.kind());
                return match io_kind {
                    Some(std::io::ErrorKind::NotFound) => {
                        s32p_support::s3resp::no_such_key("not found", Some(&uri_path))
                    }
                    Some(std::io::ErrorKind::PermissionDenied) => {
                        s32p_support::s3resp::access_denied("permission denied", Some(&uri_path))
                    }
                    _ => {
                        s32p_support::s3resp::internal_error(&e.to_string(), Some(&uri_path), None)
                    }
                };
            }
        };

    // Take an exclusive advisory lock on the opened fd. This serializes
    // against another in-flight append on the same inode and is released
    // when `file` drops at end of scope. The competing parallel-appender
    // wakes up, re-stats, and gets InvalidWriteOffset on its own pass.
    if let Err(e) = flock_exclusive(&file) {
        return s32p_support::s3resp::internal_error(
            &format!("flock failed: {e}"),
            Some(&uri_path),
            None,
        );
    }

    // Stat *under the lock* so the size check and the write share a
    // consistent view of the file.
    let cur_meta = match file.metadata() {
        Ok(m) => m,
        Err(e) => {
            return s32p_support::s3resp::internal_error(
                &format!("fstat after flock failed: {e}"),
                Some(&uri_path),
                None,
            );
        }
    };
    if cur_meta.is_dir() {
        // We opened in WriteExistingNoTrunc which can't succeed on a
        // directory under most kernels, but guard explicitly so the
        // failure mode is the documented one.
        return s32p_support::s3resp::invalid_request(
            "x-amz-write-offset-bytes target is a directory",
            Some(&uri_path),
        );
    }

    let cur_size = cur_meta.len();
    if offset != cur_size {
        tracing::debug!(
            offset,
            cur_size,
            path = %obj_path.display(),
            "append rejected: x-amz-write-offset-bytes != current size"
        );
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_WRITE_OFFSET,
            "the write offset does not match the current object size",
            Some(&uri_path),
            None,
        );
    }

    // Run write preconditions against the file we actually have open.
    // Inode-based, unquoted etag for consistency with the non-append
    // PUT path — must match `format_inode_etag_unquoted` so an `If-Match`
    // formed from a prior HEAD/GET round-trips.
    let existing_etag = format_inode_etag_unquoted(cur_meta.ino());
    let existing_lm = cur_meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
    match evaluate_write_preconditions(&cond, Some((existing_etag.as_str(), existing_lm))) {
        PreconditionOutcome::Proceed => {}
        PreconditionOutcome::NotModified => {} // not used for PUT
        PreconditionOutcome::PreconditionFailed => {
            tracing::debug!(
                path = %obj_path.display(),
                "append rejected: precondition failed"
            );
            return s32p_support::s3resp::precondition_failed(
                "PUT precondition failed",
                Some(&uri_path),
            );
        }
    }

    // Empty body is rejected with the literal AWS error message prefix
    // that mountpoint-s3's `parse_put_object_single_error` matches on
    // (see mountpoint-s3-client/src/s3_crt_client/put_object.rs:318-320).
    if logical_len == 0 {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_ARGUMENT,
            "Request body cannot be empty",
            Some(&uri_path),
            None,
        );
    }

    let (_parts, body) = req.into_parts();

    // Stream at fixed offset. WriteObjectDest::File never truncates and
    // never pads; the StreamCfg / O_DIRECT decisions happen inside
    // write_object_body based on alignment.
    let file = Arc::new(file);
    if let Err(e) = write_object_body(
        body,
        WriteObjectDest::File { file: file.clone(), start_off: offset },
        logical_len,
        is_aws_chunked,
        StreamCfg {
            chunk_size: cfg.chunk_size,
            inflight:   cfg.inflight,
            direct_io:  cfg.direct_io,
        },
        app.uring.clone(),
        app.pool.clone(),
    )
    .await
    {
        return s32p_support::s3resp::internal_error(&e.to_string(), Some(&uri_path), None);
    }

    // Inode is stable across in-place append, so the ETag is unchanged.
    // We still re-stat (under the lock) to source the response from a
    // single authoritative read.
    let meta = match file.metadata() {
        Ok(m) => m,
        Err(e) => {
            return s32p_support::s3resp::internal_error(
                &format!("fstat after append failed: {e}"),
                Some(&uri_path),
                None,
            );
        }
    };
    let etag = format_inode_etag(meta.ino());
    // `file` (and its flock) drop here.
    s32p_support::s3resp::put_object_ok(&etag)
}

async fn handle_copy_object(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    // Allow SigV4 presign query params; reject only effective (non-presign) query params.
    if has_effective_query(&req) {
        return s32p_support::s3resp::not_implemented("query parameters are not implemented", None);
    }

    let dst_bucket = class.bucket.as_deref().unwrap_or("");
    let dst_key = class.key.as_deref().unwrap_or("");
    if dst_bucket.is_empty() || dst_key.is_empty() {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_REQUEST,
            "missing bucket or key",
            Some(req.uri().path()),
            None,
        );
    }

    // destination bucket must exist
    match bucket_exists_dir(&cfg.posix_root, dst_bucket) {
        Ok(true) => {}
        Ok(false) => {
            return s32p_support::s3resp::no_such_bucket(
                "bucket not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    }

    let (src_bucket, src_key) = match parse_copy_source(req.headers()) {
        Ok(v) => v,
        Err(e) => {
            return s32p_support::s3resp::s3_error(
                StatusCode::BAD_REQUEST,
                s32p_support::s3xml::error_code::INVALID_REQUEST,
                &e.to_string(),
                Some(req.uri().path()),
                None,
            );
        }
    };

    // Resolve tagging directive and validate any REPLACE header up front.
    // Default directive is COPY (mirror source tags). REPLACE uses the
    // `x-amz-tagging` header value (or clears tags when the header is
    // absent). Validating here means a malformed header rejects the COPY
    // before any file I/O.
    let tagging_directive_replace = match req
        .headers()
        .get("x-amz-tagging-directive")
        .map(|v| v.to_str())
    {
        Some(Ok(s)) => match s.trim() {
            "COPY" | "" => false,
            "REPLACE" => true,
            other => {
                tracing::debug!(directive = %other, "CopyObject invalid x-amz-tagging-directive");
                return s32p_support::s3resp::s3_error(
                    StatusCode::BAD_REQUEST,
                    s32p_support::s3xml::error_code::INVALID_ARGUMENT,
                    "invalid x-amz-tagging-directive (expected COPY or REPLACE)",
                    Some(req.uri().path()),
                    None,
                );
            }
        },
        Some(Err(_)) => {
            return s32p_support::s3resp::s3_error(
                StatusCode::BAD_REQUEST,
                s32p_support::s3xml::error_code::INVALID_ARGUMENT,
                "invalid x-amz-tagging-directive encoding",
                Some(req.uri().path()),
                None,
            );
        }
        None => false,
    };
    let copy_replace_tags: Option<String> = if tagging_directive_replace {
        match req.headers().get("x-amz-tagging").map(|v| v.to_str()) {
            Some(Ok(s)) => {
                if let Err(reason) = s32p_support::s3xml::validate_tagging_urlform(s) {
                    tracing::debug!("CopyObject REPLACE x-amz-tagging invalid: {reason}");
                    return s32p_support::s3resp::s3_error(
                        StatusCode::BAD_REQUEST,
                        s32p_support::s3xml::error_code::INVALID_TAG,
                        "invalid x-amz-tagging header",
                        Some(req.uri().path()),
                        None,
                    );
                }
                Some(s.to_string())
            }
            Some(Err(_)) => {
                return s32p_support::s3resp::s3_error(
                    StatusCode::BAD_REQUEST,
                    s32p_support::s3xml::error_code::INVALID_TAG,
                    "invalid x-amz-tagging header encoding",
                    Some(req.uri().path()),
                    None,
                );
            }
            None => Some(String::new()),
        }
    } else {
        None
    };

    // Resolve metadata directive and validate any REPLACE inputs up front.
    // Parallel to the tagging directive block above. Default COPY mirrors
    // the source's user metadata + Content-Type; REPLACE uses request
    // headers (clears when none are supplied).
    let metadata_directive_replace = match req
        .headers()
        .get("x-amz-metadata-directive")
        .map(|v| v.to_str())
    {
        Some(Ok(s)) => match s.trim() {
            "COPY" | "" => false,
            "REPLACE" => true,
            other => {
                tracing::debug!(directive = %other, "CopyObject invalid x-amz-metadata-directive");
                return s32p_support::s3resp::s3_error(
                    StatusCode::BAD_REQUEST,
                    s32p_support::s3xml::error_code::INVALID_ARGUMENT,
                    "invalid x-amz-metadata-directive (expected COPY or REPLACE)",
                    Some(req.uri().path()),
                    None,
                );
            }
        },
        Some(Err(_)) => {
            return s32p_support::s3resp::s3_error(
                StatusCode::BAD_REQUEST,
                s32p_support::s3xml::error_code::INVALID_ARGUMENT,
                "invalid x-amz-metadata-directive encoding",
                Some(req.uri().path()),
                None,
            );
        }
        None => false,
    };
    let copy_replace_user_meta: Option<String> = if metadata_directive_replace {
        match s32p_support::s3resp::extract_user_meta_headers(req.headers()) {
            Ok(s) => {
                if let Err(reason) = s32p_support::s3xml::validate_user_metadata_urlform(&s) {
                    tracing::debug!("CopyObject REPLACE user metadata invalid: {reason}");
                    return s32p_support::s3resp::s3_error(
                        StatusCode::BAD_REQUEST,
                        s32p_support::s3xml::error_code::INVALID_ARGUMENT,
                        "invalid user metadata",
                        Some(req.uri().path()),
                        None,
                    );
                }
                Some(s)
            }
            Err(reason) => {
                tracing::debug!("CopyObject REPLACE x-amz-meta-* invalid: {reason}");
                return s32p_support::s3resp::s3_error(
                    StatusCode::BAD_REQUEST,
                    s32p_support::s3xml::error_code::INVALID_ARGUMENT,
                    "invalid x-amz-meta-* header",
                    Some(req.uri().path()),
                    None,
                );
            }
        }
    } else {
        None
    };
    let copy_replace_content_type: Option<String> = if metadata_directive_replace {
        match req.headers().get(http::header::CONTENT_TYPE).map(|v| v.to_str()) {
            Some(Ok(s)) => {
                if let Err(reason) = s32p_support::s3xml::validate_content_type(s) {
                    tracing::debug!("CopyObject REPLACE Content-Type invalid: {reason}");
                    return s32p_support::s3resp::s3_error(
                        StatusCode::BAD_REQUEST,
                        s32p_support::s3xml::error_code::INVALID_ARGUMENT,
                        "invalid Content-Type header",
                        Some(req.uri().path()),
                        None,
                    );
                }
                Some(s.to_string())
            }
            Some(Err(_)) => {
                return s32p_support::s3resp::s3_error(
                    StatusCode::BAD_REQUEST,
                    s32p_support::s3xml::error_code::INVALID_ARGUMENT,
                    "invalid Content-Type header encoding",
                    Some(req.uri().path()),
                    None,
                );
            }
            None => Some(String::new()),
        }
    } else {
        None
    };

    // source and destination must not contain the multipart upload directory
    if is_reserved_first_segment(dst_key, &cfg.mpu_dir_name)
        || is_reserved_first_segment(&src_key, &cfg.mpu_dir_name)
    {
        return s32p_support::s3resp::access_denied("reserved key prefix", Some(req.uri().path()));
    }

    // source bucket must exist
    match bucket_exists_dir(&cfg.posix_root, &src_bucket) {
        Ok(true) => {}
        Ok(false) => {
            return s32p_support::s3resp::no_such_bucket(
                "bucket not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    }

    let src_path = match join_object_path(&cfg.posix_root, &src_bucket, &src_key) {
        Ok(p) => p,
        Err(e) => return s32p_support::s3resp::access_denied(&e.to_string(), None),
    };

    let dst_path = match join_object_path(&cfg.posix_root, dst_bucket, dst_key) {
        Ok(p) => p,
        Err(e) => return s32p_support::s3resp::access_denied(&e.to_string(), None),
    };

    let src_meta = match std::fs::metadata(&src_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return s32p_support::s3resp::no_such_key("not found", None);
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return s32p_support::s3resp::access_denied("permission denied", None);
        }
        Err(e) => {
            return s32p_support::s3resp::internal_error(
                &e.to_string(),
                Some(req.uri().path()),
                None,
            );
        }
    };

    if src_meta.is_dir() {
        // Directory-marker copy: only valid when both source and destination
        // are directory-style keys (ending with '/'). The iOS Files / S3
        // app uses this to "rename" a folder marker. We skip the conditional
        // / streaming machinery for the same reason DELETE does on markers.
        if src_key.ends_with('/') && dst_key.ends_with('/') {
            if let Err(e) = std::fs::create_dir_all(&dst_path) {
                tracing::warn!(
                    "CopyObject directory-marker create_dir_all {} failed: {e}",
                    dst_path.display()
                );
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    return s32p_support::s3resp::access_denied(
                        "permission denied",
                        Some(req.uri().path()),
                    );
                }
                return s32p_support::s3resp::internal_error(
                    "failed to create directory marker",
                    Some(req.uri().path()),
                    None,
                );
            }
            let dst_meta = match std::fs::metadata(&dst_path) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(
                        "CopyObject directory-marker stat after create failed for {}: {e}",
                        dst_path.display()
                    );
                    return s32p_support::s3resp::internal_error(
                        "failed to stat directory marker",
                        Some(req.uri().path()),
                        None,
                    );
                }
            };
            let etag = format_inode_etag(dst_meta.ino());
            let last_modified = s32p_support::s3xml::format_s3_time_system(
                dst_meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            );
            return s32p_support::s3resp::copy_object_ok(&etag, &last_modified);
        }
        return s32p_support::s3resp::no_such_key("not found", None);
    }

    // check preconditions for copy source
    let cond = match parse_conditional_headers(req.headers()) {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("invalid conditional headers: {e}");
            return s32p_support::s3resp::invalid_request(&msg, Some(req.uri().path()));
        }
    };

    // Source preconditions (etag string must match what HEAD/GET on the source emits).
    let src_etag_unquoted = format_inode_etag_unquoted(src_meta.ino());
    let src_last_modified = src_meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
    match evaluate_copy_source_preconditions(&cond, &src_etag_unquoted, src_last_modified) {
        PreconditionOutcome::Proceed => {}
        _ => {
            tracing::debug!(
                "Copy source preconditions failed (412) for source {}",
                src_path.display()
            );
            return s32p_support::s3resp::precondition_failed(
                "Copy source precondition failed",
                Some(req.uri().path()),
            );
        }
    }

    // Destination preconditions - check if destination already exists and evaluate write conditions
    let dst_exists = match std::fs::metadata(&dst_path) {
        Ok(m) => {
            if m.is_dir() {
                None // treat directories as non-existent for object operations
            } else {
                let etag_existing = format_inode_etag_unquoted(m.ino());
                let lm = m.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                Some((etag_existing, lm))
            }
        }
        Err(_) => None,
    };

    let dst_exists_ref = dst_exists.as_ref().map(|(e, lm)| (e.as_str(), *lm));
    match evaluate_write_preconditions(&cond, dst_exists_ref) {
        PreconditionOutcome::Proceed => {}
        PreconditionOutcome::NotModified => {} // not used for copy
        PreconditionOutcome::PreconditionFailed => {
            tracing::debug!(
                "Copy destination preconditions failed (412) for destination {}",
                dst_path.display()
            );
            return s32p_support::s3resp::precondition_failed(
                "Copy destination precondition failed",
                Some(req.uri().path()),
            );
        }
    }

    let size = src_meta.len();

    #[cfg(feature = "lustre")]
    let dst_striping = Some(LustreStriping::new(
        cfg.chunk_size as u64,
        stripe_count_for_size(size, cfg.chunk_size as u64, cfg.lustre_max_stripe_count),
    ));
    #[cfg(not(feature = "lustre"))]
    let dst_striping: Option<LustreStriping> = None;

    if size > cfg.copy_max_size {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::ENTITY_TOO_LARGE,
            &format!(
                "CopyObject size {} exceeds configured single-copy limit {} bytes",
                size, cfg.copy_max_size
            ),
            Some(req.uri().path()),
            None,
        );
    }

    // Resolve the tag set the destination should end up with, validating
    // any source xattr now (strict COPY: a corrupt source tag set fails
    // the whole COPY rather than silently writing it through). Doing this
    // before `copy_file_to_file` means a validation error doesn't leave a
    // half-applied copy — the destination is never materialized when the
    // source xattr is malformed. REPLACE was already validated up top.
    let dst_tags: String = match &copy_replace_tags {
        Some(s) => s.clone(),
        None => match read_tags(&src_path) {
            Ok(s) => {
                if !s.is_empty()
                    && let Err(reason) = s32p_support::s3xml::validate_tagging_urlform(&s)
                {
                    tracing::debug!(
                        src = %src_path.display(),
                        reason,
                        "CopyObject: source xattr tag set fails validation"
                    );
                    return s32p_support::s3resp::s3_error(
                        StatusCode::BAD_REQUEST,
                        s32p_support::s3xml::error_code::INVALID_TAG,
                        "source object has invalid tag set",
                        Some(req.uri().path()),
                        None,
                    );
                }
                s
            }
            Err(e) => {
                tracing::warn!(
                    src = %src_path.display(),
                    error = %e,
                    "CopyObject: failed to read source tagging xattr"
                );
                return s32p_support::s3resp::internal_error(
                    "failed to read source object tags",
                    Some(req.uri().path()),
                    None,
                );
            }
        },
    };

    // Resolve destination user metadata and Content-Type — same strict-
    // validate-before-copy posture as tagging. REPLACE values were
    // validated above; COPY reads the source xattr now so a corrupt
    // source rejects the COPY before the file content is materialized.
    // Reading absent xattrs from the source yields the empty string,
    // which translates to "destination has no metadata" — same as a
    // fresh POSIX-created file.
    let dst_user_meta: String = match &copy_replace_user_meta {
        Some(s) => s.clone(),
        None => match read_user_meta(&src_path) {
            Ok(s) => {
                if !s.is_empty()
                    && let Err(reason) = s32p_support::s3xml::validate_user_metadata_urlform(&s)
                {
                    tracing::debug!(
                        src = %src_path.display(),
                        reason,
                        "CopyObject: source user metadata fails validation"
                    );
                    return s32p_support::s3resp::s3_error(
                        StatusCode::BAD_REQUEST,
                        s32p_support::s3xml::error_code::INVALID_ARGUMENT,
                        "source object has invalid user metadata",
                        Some(req.uri().path()),
                        None,
                    );
                }
                s
            }
            Err(e) => {
                tracing::warn!(
                    src = %src_path.display(),
                    error = %e,
                    "CopyObject: failed to read source user metadata xattr"
                );
                return s32p_support::s3resp::internal_error(
                    "failed to read source user metadata",
                    Some(req.uri().path()),
                    None,
                );
            }
        },
    };
    let dst_content_type: String = match &copy_replace_content_type {
        Some(s) => s.clone(),
        None => {
            // Default COPY: mirror what HEAD/GET on the source would have
            // reported — including the freedesktop `user.mime_type`
            // fallback. Writing the resolved value to the dst's explicit
            // `user.s32p.content_type` xattr keeps S3-visible state stable
            // across COPY (S3 client sees the same Content-Type as before).
            // The source's freedesktop xattr is unchanged.
            match read_content_type(&src_path) {
                Ok(Some(s)) => {
                    if let Err(reason) = s32p_support::s3xml::validate_content_type(&s) {
                        tracing::debug!(
                            src = %src_path.display(),
                            reason,
                            "CopyObject: source Content-Type fails validation"
                        );
                        return s32p_support::s3resp::s3_error(
                            StatusCode::BAD_REQUEST,
                            s32p_support::s3xml::error_code::INVALID_ARGUMENT,
                            "source object has invalid Content-Type",
                            Some(req.uri().path()),
                            None,
                        );
                    }
                    s
                }
                Ok(None) => String::new(),
                Err(e) => {
                    tracing::warn!(
                        src = %src_path.display(),
                        error = %e,
                        "CopyObject: failed to read source Content-Type xattr"
                    );
                    return s32p_support::s3resp::internal_error(
                        "failed to read source Content-Type",
                        Some(req.uri().path()),
                        None,
                    );
                }
            }
        }
    };

    // Fail-fast probe for the destination FS once the final tag / metadata
    // / Content-Type values are known. Covers both REPLACE-with-headers
    // (values come from request) and default-COPY (values come from
    // source xattrs) — without the probe a default COPY of a tagged or
    // metadata-bearing source onto an xattr-less dst would silently
    // succeed at `copy_file_to_file` and then 500 from `xattr::set`,
    // leaving a half-applied destination object on disk. Empty-payload
    // writes go through the `remove*` helpers, which already swallow
    // ENOTSUP gracefully, so the probe is only needed when something
    // would actually be set.
    let needs_xattr_probe =
        !dst_tags.is_empty() || !dst_user_meta.is_empty() || !dst_content_type.is_empty();
    if needs_xattr_probe {
        let dst_root = match bucket_root_path(&cfg.posix_root, dst_bucket) {
            Ok(p) => p,
            Err(e) => {
                return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
            }
        };
        if let Some(resp) = require_xattr_support(&app, &dst_root, req.uri().path()) {
            return resp;
        }
    }

    if let Err(e) = copy_file_to_file(
        src_path.clone(),
        dst_path.clone(),
        size,
        dst_striping,
        StreamCfg {
            chunk_size: cfg.chunk_size,
            inflight:   cfg.inflight,
            direct_io:  cfg.direct_io,
        },
        app.uring.clone(),
        app.pool.clone(),
    )
    .await
    {
        return s32p_support::s3resp::internal_error(&e.to_string(), Some(req.uri().path()), None);
    }

    if let Err(e) = write_tags(&dst_path, &dst_tags) {
        tracing::warn!(
            dst = %dst_path.display(),
            error = %e,
            "CopyObject: failed to write destination tagging xattr"
        );
        return s32p_support::s3resp::internal_error(
            "failed to write destination object tags",
            Some(req.uri().path()),
            None,
        );
    }

    if let Err(e) = write_user_meta(&dst_path, &dst_user_meta) {
        tracing::warn!(
            dst = %dst_path.display(),
            error = %e,
            "CopyObject: failed to write destination user metadata xattr"
        );
        return s32p_support::s3resp::internal_error(
            "failed to write destination user metadata",
            Some(req.uri().path()),
            None,
        );
    }
    if let Err(e) = write_content_type(&dst_path, &dst_content_type) {
        tracing::warn!(
            dst = %dst_path.display(),
            error = %e,
            "CopyObject: failed to write destination Content-Type xattr"
        );
        return s32p_support::s3resp::internal_error(
            "failed to write destination Content-Type",
            Some(req.uri().path()),
            None,
        );
    }

    let dst_meta = match std::fs::metadata(&dst_path) {
        Ok(m) => m,
        Err(e) => {
            return s32p_support::s3resp::internal_error(
                &e.to_string(),
                Some(req.uri().path()),
                None,
            );
        }
    };

    let etag = format_inode_etag(dst_meta.ino());
    let last_modified = s32p_support::s3xml::format_s3_time_system(
        dst_meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
    );

    s32p_support::s3resp::copy_object_ok(&etag, &last_modified)
}

// -------------------------
// RenameObject
// -------------------------

/// Parse `x-amz-rename-source` into the source object key.
///
/// AWS S3 Express `RenameObject` is always same-bucket; the header
/// carries the source key only — no bucket prefix, leading `/`
/// optional. That matches what mountpoint-s3 and the AWS SDKs send.
/// See <https://docs.aws.amazon.com/AmazonS3/latest/API/API_RenameObject.html>.
fn parse_rename_source(headers: &HeaderMap) -> Result<String> {
    let raw = headers
        .get("x-amz-rename-source")
        .ok_or_else(|| anyhow!("missing x-amz-rename-source"))?
        .to_str()
        .map_err(|_| anyhow!("invalid x-amz-rename-source"))?
        .trim();

    // Defensive: spec doesn't allow a query component, but strip one if
    // a buggy client adds it.
    let raw = raw.split_once('?').map(|(p, _)| p).unwrap_or(raw);
    let raw = raw.trim_start_matches('/');
    if raw.is_empty() {
        return Err(anyhow!("invalid x-amz-rename-source"));
    }

    let key = s32p_support::uri_encoding::percent_decode_path_segments_lossy(raw);
    if key.is_empty() {
        return Err(anyhow!("invalid x-amz-rename-source"));
    }
    Ok(key)
}

async fn handle_rename_object(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    // Allow SigV4 presign query params; ignore everything except renameObject.
    if !(class.query.is_only_effective("renameobject")
        || (class.query.has("renameobject") && class.query.is_only_effective("x-id")))
    {
        return s32p_support::s3resp::not_implemented("query parameters are not implemented", None);
    }

    let dst_bucket = class.bucket.as_deref().unwrap_or("");
    let dst_key = class.key.as_deref().unwrap_or("");
    if dst_bucket.is_empty() || dst_key.is_empty() {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_REQUEST,
            "missing bucket or key",
            Some(req.uri().path()),
            None,
        );
    }

    // destination bucket must exist
    match bucket_exists_dir(&cfg.posix_root, dst_bucket) {
        Ok(true) => {}
        Ok(false) => {
            return s32p_support::s3resp::no_such_bucket(
                "bucket not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    }

    let src_key = match parse_rename_source(req.headers()) {
        Ok(v) => v,
        Err(e) => {
            return s32p_support::s3resp::s3_error(
                StatusCode::BAD_REQUEST,
                s32p_support::s3xml::error_code::INVALID_REQUEST,
                &e.to_string(),
                Some(req.uri().path()),
                None,
            );
        }
    };

    // Conditional + idempotency headers. mountpoint-s3 emits
    // `x-amz-client-token` on every rename and `If-None-Match: *` when
    // mounted without `--allow-overwrite`. The other three are sent only
    // when the caller passes the corresponding `RenameObjectParams` field
    // (no current mount-s3 path does, but the params struct supports it).
    let if_match = header_str(req.headers(), "if-match");
    let if_none_match = header_str(req.headers(), "if-none-match");
    let if_source_match = header_str(req.headers(), "x-amz-rename-source-if-match");
    let client_token = header_str(req.headers(), "x-amz-client-token");

    // Idempotency check runs *before* any filesystem work so a replay
    // returns the cached response without re-stating the source (which
    // would now be missing post-rename and produce a spurious NoSuchKey).
    let fingerprint = rename_fingerprint(
        dst_bucket,
        &src_key,
        dst_key,
        &if_match,
        &if_none_match,
        &if_source_match,
    );
    let mut guard: Option<idempotency::EntryGuard> = match client_token.as_deref() {
        Some(token) => match app.idempotency.enter(token, &fingerprint).await {
            idempotency::Lookup::Replay { status, body } => {
                return s32p_support::s3resp::response_bytes(status, "application/xml", body, []);
            }
            idempotency::Lookup::Conflict => {
                return s32p_support::s3resp::s3_error(
                    StatusCode::CONFLICT,
                    s32p_support::s3xml::error_code::IDEMPOTENT_PARAMETER_MISMATCH,
                    "client token reused for a different request",
                    Some(req.uri().path()),
                    None,
                );
            }
            idempotency::Lookup::BypassCacheFull => {
                tracing::warn!("rename idempotency cache at capacity; running without dedup");
                None
            }
            idempotency::Lookup::Pending(g) => Some(g),
        },
        None => None,
    };

    // After this point, every early return must `abandon()` the guard so a
    // subsequent retry can execute. The `abort!` macro centralizes that.
    macro_rules! abort {
        ($resp:expr) => {{
            if let Some(g) = guard.take() {
                g.abandon();
            }
            return $resp;
        }};
    }

    // Don't allow reserved multipart prefix in either source or destination.
    if is_reserved_first_segment(dst_key, &cfg.mpu_dir_name)
        || is_reserved_first_segment(&src_key, &cfg.mpu_dir_name)
    {
        abort!(s32p_support::s3resp::access_denied("reserved key prefix", Some(req.uri().path())));
    }

    let src_path = match join_object_path(&cfg.posix_root, dst_bucket, &src_key) {
        Ok(p) => p,
        Err(e) => abort!(s32p_support::s3resp::access_denied(&e.to_string(), None)),
    };

    let dst_path = match join_object_path(&cfg.posix_root, dst_bucket, dst_key) {
        Ok(p) => p,
        Err(e) => abort!(s32p_support::s3resp::access_denied(&e.to_string(), None)),
    };

    // Source must exist (file or directory). Capture the inode for the
    // `x-amz-rename-source-if-match` comparison below.
    let src_meta = match std::fs::metadata(&src_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            abort!(s32p_support::s3resp::no_such_key("not found", None));
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            abort!(s32p_support::s3resp::access_denied("permission denied", None));
        }
        Err(e) => {
            abort!(s32p_support::s3resp::internal_error(
                &e.to_string(),
                Some(req.uri().path()),
                None,
            ));
        }
    };
    let src_etag = format_inode_etag(src_meta.ino());

    if let Some(want) = &if_source_match {
        if !etag_matches(&src_etag, want) {
            abort!(s32p_support::s3resp::precondition_failed(
                "x-amz-rename-source-if-match did not match source",
                Some(req.uri().path()),
            ));
        }
    }

    // Stat destination once for both `If-Match` and the
    // specific-ETag form of `If-None-Match`. `*` is handled atomically
    // below via `renameat2(RENAME_NOREPLACE)` so we don't depend on
    // this stat being race-free.
    let dst_etag_opt = std::fs::metadata(&dst_path).ok().map(|m| format_inode_etag(m.ino()));

    if let Some(want) = &if_match {
        match &dst_etag_opt {
            Some(have) if etag_matches(have, want) => {}
            _ => abort!(s32p_support::s3resp::precondition_failed(
                "If-Match did not match destination",
                Some(req.uri().path()),
            )),
        }
    }

    let use_noreplace = if_none_match.as_deref() == Some("*");
    if let (Some(want), Some(have)) = (&if_none_match, &dst_etag_opt) {
        // `*` reaches here only when the destination exists — fail. A
        // specific ETag fails iff it matches the current dst ETag.
        if want == "*" || etag_matches(have, want) {
            abort!(s32p_support::s3resp::precondition_failed(
                "If-None-Match precondition failed",
                Some(req.uri().path()),
            ));
        }
    }

    if let Some(parent) = dst_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            abort!(s32p_support::s3resp::access_denied(
                &format!("failed to create destination directories: {e}"),
                None,
            ));
        }
    }

    let rename_result = if use_noreplace {
        crate::fs_helpers::rename_noreplace(&src_path, &dst_path)
    } else {
        std::fs::rename(&src_path, &dst_path)
    };

    match rename_result {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Only reachable via the `rename_noreplace` path
            // (`If-None-Match: *`). This closes the TOCTOU between the
            // stat above and the rename — a destination that appeared in
            // the meantime still produces 412.
            abort!(s32p_support::s3resp::precondition_failed(
                "If-None-Match: destination already exists",
                Some(req.uri().path()),
            ));
        }
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
            abort!(s32p_support::s3resp::s3_error(
                StatusCode::BAD_REQUEST,
                s32p_support::s3xml::error_code::INVALID_REQUEST,
                "cross-device rename is not supported",
                Some(req.uri().path()),
                None,
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            abort!(s32p_support::s3resp::no_such_key("not found", None));
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            abort!(s32p_support::s3resp::access_denied("permission denied", None));
        }
        Err(e) => {
            abort!(s32p_support::s3resp::internal_error(
                &e.to_string(),
                Some(req.uri().path()),
                None,
            ));
        }
    }

    // Best-effort cleanup of empty parent directories under the bucket root.
    if let Ok(bucket_root) = bucket_root_path(&cfg.posix_root, dst_bucket) {
        if let Some(src_parent) = src_path.parent() {
            prune_empty_parents(&bucket_root, src_parent.to_path_buf());
        }
    }

    // Publish the successful response to the idempotency cache. A retry
    // with the same `x-amz-client-token` + same fingerprint now gets
    // `Lookup::Replay` and skips the filesystem path entirely.
    let body: Vec<u8> = Vec::new();
    if let Some(g) = guard.take() {
        g.commit(fingerprint, StatusCode::OK, body.clone());
    }
    s32p_support::s3resp::response_bytes(StatusCode::OK, "application/xml", body, [])
}

/// Read a header as a borrowed `String`. Returns `None` for missing or
/// non-ASCII values (the latter shouldn't happen for the headers we care
/// about; defensive against malformed clients).
fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_string)
}

/// Format the inode-derived ETag with a `-1` multipart-style suffix. The
/// suffix exists so AWS SDK for .NET (which treats any ETag containing
/// `-` as a multipart aggregate and skips its MD5-vs-ETag check on
/// PutObject/UploadPart responses and on GetObject stream wrapping)
/// doesn't reject our inode-based ETags as bad MD5s. The inode itself
/// stays load-bearing (Lustre/POSIX-interop story per README); the
/// suffix is purely a "skip integrity check" signal to strict clients.
/// All stat-derived ETag emissions and all precondition-comparison
/// strings in the gateway go through this helper (or its unquoted twin
/// `format_inode_etag_unquoted`) so the literal byte-string round-trips
/// consistently through `If-Match`.
pub(crate) fn format_inode_etag(ino: u64) -> String {
    format!("\"{}-1\"", ino)
}

/// Unquoted form of `format_inode_etag` for use as `current_etag_unquoted`
/// in the precondition evaluators (`evaluate_read_preconditions` /
/// `evaluate_write_preconditions` / `evaluate_copy_source_preconditions`).
/// Must stay in lockstep with `format_inode_etag` — same digits, same
/// suffix — so a client cached `If-Match: "<ino>-1"` matches.
pub(crate) fn format_inode_etag_unquoted(ino: u64) -> String {
    format!("{}-1", ino)
}

/// Compare two ETag-like values for equality, tolerating optional
/// surrounding double-quotes on either side. AWS specifies quoted ETags
/// on the wire, but some clients omit them; accepting both means a
/// client's stored ETag round-trips byte-identically into `If-Match`
/// regardless of how they captured it.
fn etag_matches(have: &str, want: &str) -> bool {
    fn unquote(s: &str) -> &str {
        s.strip_prefix('"').and_then(|s| s.strip_suffix('"')).unwrap_or(s)
    }
    unquote(have.trim()) == unquote(want.trim())
}

/// Fingerprint for the idempotency cache. Two requests with the same
/// `x-amz-client-token` are considered "the same operation" iff their
/// fingerprints are byte-equal; otherwise the second is a token reuse
/// and returns 409 `IdempotentParameterMismatch`.
///
/// Fields are NUL-separated so a stray slash or colon inside a key (S3
/// keys may contain any UTF-8) can't collide with a field boundary.
/// Bucket name is included even though our renames are always
/// same-bucket, so a future cross-process token shared across workers
/// (not currently possible — cache is per-worker) wouldn't accidentally
/// merge requests bound to different buckets.
fn rename_fingerprint(
    dst_bucket: &str,
    src_key: &str,
    dst_key: &str,
    if_match: &Option<String>,
    if_none_match: &Option<String>,
    if_source_match: &Option<String>,
) -> String {
    format!(
        "{}\0{}\0{}\0{}\0{}\0{}",
        dst_bucket,
        src_key,
        dst_key,
        if_match.as_deref().unwrap_or(""),
        if_none_match.as_deref().unwrap_or(""),
        if_source_match.as_deref().unwrap_or(""),
    )
}

// -------------------------
// DeleteObject / DeleteObjects
// -------------------------

fn prune_empty_parents(bucket_root: &Path, mut dir: PathBuf) {
    loop {
        if dir == *bucket_root {
            break;
        }

        match std::fs::remove_dir(&dir) {
            Ok(()) => {
                // removed successfully, keep walking upward
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => break,
            Err(_e) => {
                // NotEmpty / other -> stop pruning
                break;
            }
        }

        let Some(parent) = dir.parent() else {
            break;
        };
        dir = parent.to_path_buf();
    }
}

async fn handle_delete_object(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    // Allow SigV4 presign query params; reject only effective (non-presign) query params.
    if has_effective_query(&req) {
        return s32p_support::s3resp::not_implemented("query parameters are not implemented", None);
    }

    let bucket = class.bucket.as_deref().unwrap_or("");
    let key = class.key.as_deref().unwrap_or("");

    // don't delete file from multipart upload dir
    if is_reserved_first_segment(key, &cfg.mpu_dir_name) {
        return s32p_support::s3resp::access_denied("reserved key prefix", Some(req.uri().path()));
    }

    if bucket.is_empty() || key.is_empty() {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_REQUEST,
            "missing bucket or key",
            Some(req.uri().path()),
            None,
        );
    }

    // S3 semantics: if bucket doesn't exist => NoSuchBucket
    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => {}
        Ok(false) => {
            return s32p_support::s3resp::no_such_bucket(
                "bucket not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    }

    let obj_path = match join_object_path(&cfg.posix_root, bucket, key) {
        Ok(p) => p,
        Err(e) => return s32p_support::s3resp::access_denied(&e.to_string(), None),
    };

    // Directory-marker delete: a key ending in '/' addresses an (expected
    // leaf-empty) filesystem directory. We rmdir it and let prune_empty_parents
    // collapse the chain upward. We deliberately skip the conditional-header
    // machinery — clients don't send If-Match on dir markers, and the
    // precondition path below assumes a regular file (etag-from-inode, etc.).
    if key.ends_with('/') {
        match std::fs::remove_dir(&obj_path) {
            Ok(()) => {
                if let (Ok(bucket_root), Some(parent)) =
                    (bucket_root_path(&cfg.posix_root, bucket), obj_path.parent())
                {
                    prune_empty_parents(&bucket_root, parent.to_path_buf());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // S3 DELETE is idempotent: missing target is still success.
            }
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTEMPTY)) => {
                tracing::debug!(
                    "DELETE on directory marker {} rejected: directory not empty",
                    obj_path.display()
                );
                return s32p_support::s3resp::s3_error(
                    StatusCode::CONFLICT,
                    "BucketNotEmpty",
                    "directory not empty",
                    Some(req.uri().path()),
                    None,
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                return s32p_support::s3resp::access_denied(
                    "permission denied",
                    Some(req.uri().path()),
                );
            }
            Err(e) => {
                return s32p_support::s3resp::internal_error(
                    &e.to_string(),
                    Some(req.uri().path()),
                    None,
                );
            }
        }
        return s32p_support::s3resp::delete_object_no_content();
    }

    // check preconditions
    let cond = match parse_conditional_headers(req.headers()) {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("invalid conditional headers: {e}");
            return s32p_support::s3resp::invalid_request(&msg, Some(req.uri().path()));
        }
    };

    let existing = match fs::metadata(&obj_path) {
        Ok(m) => {
            let etag_existing = format_inode_etag_unquoted(m.ino());
            let lm = m.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            Some((etag_existing, lm, m.len()))
        }
        Err(_) => None,
    };

    if let Some((etag_existing, lm, size)) = existing.as_ref() {
        // Enforce If-Match / If-None-Match / If-(Un)Modified-Since like a “write”
        let existing_ref = Some((etag_existing.as_str(), *lm));
        if evaluate_write_preconditions(&cond, existing_ref)
            == PreconditionOutcome::PreconditionFailed
        {
            tracing::debug!(
                "Write preconditions failed (412) for DELETE operation on {}",
                obj_path.display()
            );
            return s32p_support::s3resp::precondition_failed(
                "DELETE precondition failed",
                Some(req.uri().path()),
            );
        }

        // Optional extra checks (x-amz-if-match-size / last-modified-time)
        if let Some(want_size) = cond.amz_if_match_size {
            if want_size != *size {
                tracing::debug!(
                    "DELETE x-amz-if-match-size mismatch for {} (want: {}, got: {})",
                    obj_path.display(),
                    want_size,
                    size
                );
                return s32p_support::s3resp::precondition_failed(
                    "x-amz-if-match-size mismatch",
                    Some(req.uri().path()),
                );
            }
        }
        if let Some(want_lm) = cond.amz_if_match_last_modified_time {
            if *lm != want_lm {
                tracing::debug!(
                    "DELETE x-amz-if-match-last-modified-time mismatch for {}",
                    obj_path.display()
                );
                return s32p_support::s3resp::precondition_failed(
                    "x-amz-if-match-last-modified-time mismatch",
                    Some(req.uri().path()),
                );
            }
        }
    } else {
        // If object missing and caller supplied If-Match => fail (common behavior)
        if cond.if_match.is_some() {
            tracing::debug!(
                "DELETE If-Match precondition failed - object does not exist: {}",
                obj_path.display()
            );
            return s32p_support::s3resp::precondition_failed(
                "DELETE If-Match but object does not exist",
                Some(req.uri().path()),
            );
        }
    }

    // DeleteObject is idempotent: NotFound is still success.
    match std::fs::remove_file(&obj_path) {
        Ok(()) => {
            // best-effort prune empty parent dirs under the bucket root
            if let (Ok(bucket_root), Some(parent)) =
                (bucket_root_path(&cfg.posix_root, bucket), obj_path.parent())
            {
                prune_empty_parents(&bucket_root, parent.to_path_buf());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // still success
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return s32p_support::s3resp::access_denied(
                "permission denied",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::internal_error(
                &e.to_string(),
                Some(req.uri().path()),
                None,
            );
        }
    }

    s32p_support::s3resp::delete_object_no_content()
}

async fn handle_delete_objects(
    req: Request<Incoming>,
    app: Arc<App>,
    class: &s32p_support::classifier::S3RequestClass,
) -> Resp {
    let cfg = app.cfg.clone();

    // Must be ?delete (classifier already checked), keep defensive.
    if !class.query.has("delete") {
        return s32p_support::s3resp::not_implemented("missing ?delete", None);
    }

    let bucket = class.bucket.as_deref().unwrap_or("");
    if bucket.is_empty() {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_REQUEST,
            "missing bucket",
            Some(req.uri().path()),
            None,
        );
    }

    // S3 semantics: if bucket doesn't exist => NoSuchBucket
    match bucket_exists_dir(&cfg.posix_root, bucket) {
        Ok(true) => {}
        Ok(false) => {
            return s32p_support::s3resp::no_such_bucket(
                "bucket not found",
                Some(req.uri().path()),
            );
        }
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(req.uri().path()));
        }
    }

    let (parts, body) = req.into_parts();

    // Read entire XML body. S3 limits DeleteObjects to 1000 keys; XML_BODY_MAX_BYTES
    // (1 MiB) caps the worst-case allocation before the body is touched.
    let collected = match collect_body_capped(&parts.headers, body, XML_BODY_MAX_BYTES).await {
        Ok(b) => b,
        Err(BodyCapErr::TooLarge { advertised }) => {
            tracing::debug!(
                op = "DeleteObjects",
                advertised = ?advertised,
                cap = XML_BODY_MAX_BYTES,
                "request body exceeds XML body cap"
            );
            return s32p_support::s3resp::s3_error(
                StatusCode::BAD_REQUEST,
                s32p_support::s3xml::error_code::INVALID_REQUEST,
                "request body too large",
                Some(parts.uri.path()),
                None,
            );
        }
        Err(BodyCapErr::Read(e)) => {
            return s32p_support::s3resp::s3_error(
                StatusCode::BAD_REQUEST,
                s32p_support::s3xml::error_code::INVALID_REQUEST,
                &format!("failed to read body: {e}"),
                Some(parts.uri.path()),
                None,
            );
        }
    };

    let (quiet, keys) = match s32p_support::s3xml::parse_delete_objects_request(&collected) {
        Ok(v) => v,
        Err(e) => {
            return s32p_support::s3resp::s3_error(
                StatusCode::BAD_REQUEST,
                s32p_support::s3xml::error_code::INVALID_REQUEST,
                &e.to_string(),
                Some(parts.uri.path()),
                None,
            );
        }
    };

    // S3 limit is 1000 objects per multi-delete request.
    if keys.len() > 1000 {
        return s32p_support::s3resp::s3_error(
            StatusCode::BAD_REQUEST,
            s32p_support::s3xml::error_code::INVALID_REQUEST,
            "too many keys in DeleteObjects (max 1000)",
            Some(parts.uri.path()),
            None,
        );
    }

    let bucket_root = match bucket_root_path(&cfg.posix_root, bucket) {
        Ok(p) => p,
        Err(e) => {
            return s32p_support::s3resp::access_denied(&e.to_string(), Some(parts.uri.path()));
        }
    };

    let mut deleted: Vec<String> = Vec::new();
    let mut errors: Vec<s32p_support::s3xml::DeleteErrorInfo> = Vec::new();

    for key in keys {
        if key.is_empty() {
            errors.push(s32p_support::s3xml::DeleteErrorInfo {
                key,
                code: s32p_support::s3xml::error_code::INVALID_REQUEST.to_string(),
                message: "empty key".to_string(),
            });
            continue;
        }

        // do not delete file from multipart upload dir
        if is_reserved_first_segment(&key, &cfg.mpu_dir_name) {
            errors.push(s32p_support::s3xml::DeleteErrorInfo {
                key,
                code: s32p_support::s3xml::error_code::ACCESS_DENIED.to_string(),
                message: "reserved key prefix".to_string(),
            });
            continue;
        }

        let obj_path = match join_object_path(&cfg.posix_root, bucket, &key) {
            Ok(p) => p,
            Err(e) => {
                errors.push(s32p_support::s3xml::DeleteErrorInfo {
                    key,
                    code: s32p_support::s3xml::error_code::INVALID_REQUEST.to_string(),
                    message: e.to_string(),
                });
                continue;
            }
        };

        // Directory-marker delete: a key ending in '/' is rmdir-ed instead of
        // unlinked. Mirrors handle_delete_object's branch.
        let res = if key.ends_with('/') {
            std::fs::remove_dir(&obj_path)
        } else {
            std::fs::remove_file(&obj_path)
        };

        match res {
            Ok(()) => {
                if let Some(parent) = obj_path.parent() {
                    prune_empty_parents(&bucket_root, parent.to_path_buf());
                }
                if !quiet {
                    deleted.push(key);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // idempotent success
                if !quiet {
                    deleted.push(key);
                }
            }
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTEMPTY)) => {
                errors.push(s32p_support::s3xml::DeleteErrorInfo {
                    key,
                    code: "BucketNotEmpty".to_string(),
                    message: "directory not empty".to_string(),
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                errors.push(s32p_support::s3xml::DeleteErrorInfo {
                    key,
                    code: s32p_support::s3xml::error_code::ACCESS_DENIED.to_string(),
                    message: "permission denied".to_string(),
                });
            }
            Err(e) => {
                errors.push(s32p_support::s3xml::DeleteErrorInfo {
                    key,
                    code: s32p_support::s3xml::error_code::INTERNAL_ERROR.to_string(),
                    message: e.to_string(),
                });
            }
        }
    }

    s32p_support::s3resp::delete_objects_result(&deleted, &errors)
}

// ---- main ----

fn main() -> Result<()> {
    // Check for S32P_LOG_LEVEL first (from config), then RUST_LOG, then default to info
    let log_filter = std::env::var("S32P_LOG_LEVEL")
        .or_else(|_| std::env::var("RUST_LOG"))
        .unwrap_or_else(|_| "info".into());

    // Local-time formatter. Prefer the offset injected by the proxy via
    // S32P_LOG_UTC_OFFSET_SECS: when launched under landlock the gateway has
    // no access to /etc/localtime, so libc::localtime_r falls back to UTC.
    // For standalone runs (no env var) we still try libc.
    let offset = std::env::var("S32P_LOG_UTC_OFFSET_SECS")
        .ok()
        .and_then(|s| s.parse::<i32>().ok())
        .and_then(|s| time::UtcOffset::from_whole_seconds(s).ok())
        .unwrap_or_else(s32p_support::utils::local_utc_offset);
    let timer = tracing_subscriber::fmt::time::OffsetTime::new(
        offset,
        time::format_description::well_known::Rfc3339,
    );
    let log_format = std::env::var("S32P_LOG_FORMAT").unwrap_or_else(|_| "text".into());
    let builder = tracing_subscriber::fmt().with_timer(timer).with_env_filter(log_filter);
    match log_format.as_str() {
        "json" => builder.json().init(),
        "text" => builder.init(),
        other => anyhow::bail!("S32P_LOG_FORMAT must be \"text\" or \"json\", got {other:?}"),
    }

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async_main())
}

async fn async_main() -> Result<()> {
    let cfg = Arc::new(load_cfg()?);

    let pool = Arc::new(BufPool::new(cfg.chunk_size, cfg.pool_size));
    pool.warm(cfg.pool_size);

    // Single global io_uring writer sized to the whole buffer pool.
    let uring = Arc::new(UringIO::spawn(cfg.pool_size.max(1))?);

    // Per-worker idempotency cache for `x-amz-client-token` on
    // RenameObject. Hardcoded defaults: 300s TTL matches AWS's typical
    // idempotency window for STS-shaped tokens; 60s sweep cadence keeps
    // memory from accumulating between requests; 4096-entry cap bounds
    // worst case (~1 MiB) under pathological clients.
    let idempotency = idempotency::IdempotencyCache::new(
        std::time::Duration::from_secs(300),
        std::time::Duration::from_secs(60),
        4096,
    );
    // Sweeper is started lazily from the first request handler — the
    // tokio runtime is up by then. Mirrors `SessionStore::start_cleanup`.

    // NSS lookup client. Connects to the proxy's abstract socket when
    // `S32P_NSS_PROXY_SOCK` is set; otherwise falls back to local
    // `getpwuid_r`. The proxy injects the env var at worker spawn time.
    let nss_sock_env = std::env::var("S32P_NSS_PROXY_SOCK").ok();
    let nss_client = Arc::new(nss_client::NssClient::from_env(nss_sock_env.as_deref()));
    tracing::info!(
        backend = if nss_client.is_direct() { "direct" } else { "proxy-socket" },
        ttl_secs = nss_client.ttl().as_secs(),
        "nss lookup client initialized"
    );
    // Sweep at half the TTL so expired entries survive at most one
    // half-window of stale memory. Same shape as the replay-cache sweeper.
    {
        let cache = Arc::clone(&nss_client);
        let interval = cache.ttl() / 2;
        tokio::spawn(async move {
            let mut t = tokio::time::interval(interval);
            t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                t.tick().await;
                let stats = cache.sweep();
                tracing::debug!(
                    before = stats.before,
                    after = stats.after,
                    removed = stats.removed,
                    elapsed_us = stats.elapsed.as_micros() as u64,
                    "nss-cache sweep"
                );
            }
        });
        tracing::info!(interval_secs = interval.as_secs(), "nss-cache sweeper started");
    }

    let app = Arc::new(App {
        cfg: cfg.clone(),
        pool,
        uring,
        virtual_hosted_suffixes: cfg.virtual_hosted_suffixes.clone(),
        idempotency,
        nss_client,
        xattr_support: DashMap::new(),
    });

    if let Some(sock_path) = cfg.bind_uds.clone() {
        let _ = std::fs::remove_file(&sock_path);

        if let Some(parent) = sock_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create UDS dir {}", parent.display()))?;
        }

        let listener = UnixListener::bind(&sock_path)
            .with_context(|| format!("bind uds {}", sock_path.display()))?;

        tracing::info!(
            "s32p-gateway listening on uds {} (chunk_size={} inflight={} pool_size={})",
            sock_path.display(),
            cfg.chunk_size,
            cfg.inflight,
            cfg.pool_size
        );

        loop {
            let (stream, _addr) = listener.accept().await?;
            let app2 = app.clone();
            let peer = PeerAddr::Unix;

            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req| handle(req, app2.clone(), Some(peer.clone())));
                if let Err(e) = http1::Builder::new()
                    .max_buf_size(8 * 1024 * 1024)
                    .writev(true)
                    .max_headers(MAX_REQUEST_HEADERS)
                    .serve_connection(io, svc)
                    .await
                {
                    tracing::debug!(error = %e, "connection error");
                }
            });
        }
    } else {
        let listener = TcpListener::bind(&cfg.bind_addr)
            .await
            .with_context(|| format!("bind {}", cfg.bind_addr))?;

        tracing::info!(
            "s32p-gateway listening on {} (chunk_size={} inflight={} pool_size={})",
            cfg.bind_addr,
            cfg.chunk_size,
            cfg.inflight,
            cfg.pool_size
        );

        loop {
            let (stream, peer_sa) = listener.accept().await?;
            stream.set_nodelay(true)?;
            let app2 = app.clone();
            let peer = PeerAddr::Tcp(peer_sa);

            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req| handle(req, app2.clone(), Some(peer.clone())));
                if let Err(e) = http1::Builder::new()
                    .max_buf_size(8 * 1024 * 1024)
                    .writev(true)
                    .max_headers(MAX_REQUEST_HEADERS)
                    .serve_connection(io, svc)
                    .await
                {
                    tracing::debug!(error = %e, "connection error");
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bucket_acl_empty_yields_empty_map() {
        assert!(parse_bucket_acl("").is_empty());
        assert!(parse_bucket_acl("   ").is_empty());
        assert!(parse_bucket_acl(",,").is_empty());
    }

    #[test]
    fn parse_bucket_acl_well_formed() {
        let m = parse_bucket_acl("alpha:rw,bravo:ro,charlie:rw");
        assert_eq!(m.get("alpha"), Some(&AclLevel::ReadWrite));
        assert_eq!(m.get("bravo"), Some(&AclLevel::ReadOnly));
        assert_eq!(m.get("charlie"), Some(&AclLevel::ReadWrite));
        assert_eq!(m.len(), 3);
    }

    #[test]
    fn parse_bucket_acl_tolerates_whitespace() {
        let m = parse_bucket_acl("  alpha : rw , bravo:ro");
        assert_eq!(m.get("alpha"), Some(&AclLevel::ReadWrite));
        assert_eq!(m.get("bravo"), Some(&AclLevel::ReadOnly));
    }

    #[test]
    fn parse_bucket_acl_skips_malformed_entries_keeping_good_ones() {
        // "noseparator" has no colon; "bad:xx" has unknown level;
        // "UPPER:rw" fails the S3 charset check; "good:ro" survives.
        let m = parse_bucket_acl("noseparator,bad:xx,UPPER:rw,good:ro");
        assert_eq!(m.get("good"), Some(&AclLevel::ReadOnly));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn parse_bucket_acl_rejects_non_s3_charset() {
        // The S3 bucket-name spec is `[a-z0-9.-]`. The charset gate
        // exists so a buggy or hostile proxy can't smuggle entries with
        // characters that S3 itself forbids — they're dropped, leaving
        // the affected bucket on the default-rw fallback.
        assert!(parse_bucket_acl("UPPER:rw").is_empty());
        assert!(parse_bucket_acl("with_underscore:rw").is_empty());
        assert!(parse_bucket_acl("with space:rw").is_empty());
        assert!(parse_bucket_acl(":rw").is_empty()); // empty name
    }

    #[test]
    fn parse_bucket_acl_accepts_dots_and_hyphens() {
        let m = parse_bucket_acl("my-bucket.0:ro");
        assert_eq!(m.get("my-bucket.0"), Some(&AclLevel::ReadOnly));
    }

    fn hdrs(content_sha256: &str, body_len: u64, decoded_len: Option<u64>) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-amz-content-sha256", content_sha256.parse().unwrap());
        h.insert("content-length", body_len.to_string().parse().unwrap());
        if let Some(d) = decoded_len {
            h.insert("x-amz-decoded-content-length", d.to_string().parse().unwrap());
        }
        h
    }

    /// All four AWS-defined `STREAMING-*` payload markers must route to the
    /// aws-chunked decoder. The test pins the contract: gateway compatibility
    /// with mountpoint-s3 (which sends `STREAMING-UNSIGNED-PAYLOAD-TRAILER`),
    /// the AWS CLI v2 (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`), and any
    /// SigV4a-signing future client (`STREAMING-AWS4-ECDSA-…`) is now part of
    /// the surface we promise.
    #[test]
    fn compute_logical_len_recognizes_all_streaming_variants() {
        for v in [
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
            "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
            "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD",
            "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER",
        ] {
            let h = hdrs(v, 1234, Some(1000));
            let (is_streaming, logical) = compute_logical_len(&h).unwrap();
            assert!(is_streaming, "{v} must classify as streaming");
            // Streaming bodies trust x-amz-decoded-content-length, not
            // the on-the-wire content-length.
            assert_eq!(logical, 1000, "{v} must use decoded-content-length");
        }
    }

    #[test]
    fn compute_logical_len_non_streaming_uses_content_length() {
        // Bare `UNSIGNED-PAYLOAD` is a raw body; `decoded-content-length`
        // is absent and `Content-Length` is the truth.
        let h = hdrs("UNSIGNED-PAYLOAD", 1234, None);
        let (is_streaming, logical) = compute_logical_len(&h).unwrap();
        assert!(!is_streaming);
        assert_eq!(logical, 1234);

        // A hex SHA-256 (signed-payload, non-streaming) is also raw on the wire.
        let sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let h = hdrs(sha, 5678, None);
        let (is_streaming, logical) = compute_logical_len(&h).unwrap();
        assert!(!is_streaming);
        assert_eq!(logical, 5678);
    }

    fn cl_headers(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(http::header::CONTENT_LENGTH, value.parse().unwrap());
        h
    }

    #[test]
    fn content_length_under_cap_returns_none() {
        let h = cl_headers("1024");
        assert_eq!(content_length_over_cap(&h, XML_BODY_MAX_BYTES), None);
    }

    #[test]
    fn content_length_equal_to_cap_returns_none() {
        // The cap is inclusive — a body of exactly XML_BODY_MAX_BYTES is
        // accepted. Documenting the boundary so a future "≤ vs <" change is
        // a deliberate, test-visible decision.
        let h = cl_headers(&XML_BODY_MAX_BYTES.to_string());
        assert_eq!(content_length_over_cap(&h, XML_BODY_MAX_BYTES), None);
    }

    #[test]
    fn content_length_one_over_cap_rejected() {
        let v = (XML_BODY_MAX_BYTES + 1).to_string();
        let h = cl_headers(&v);
        assert_eq!(
            content_length_over_cap(&h, XML_BODY_MAX_BYTES),
            Some(XML_BODY_MAX_BYTES as u64 + 1)
        );
    }

    #[test]
    fn content_length_huge_value_rejected() {
        // The realistic DoS path: client claims a gigabyte body.
        let h = cl_headers("1073741824");
        assert_eq!(content_length_over_cap(&h, XML_BODY_MAX_BYTES), Some(1_073_741_824));
    }

    #[test]
    fn content_length_absent_treated_as_unknown() {
        // No Content-Length is legal (chunked, etc.). Pre-check passes;
        // the streaming wrap in collect_body_capped catches over-cap bodies
        // during read.
        let h = HeaderMap::new();
        assert_eq!(content_length_over_cap(&h, XML_BODY_MAX_BYTES), None);
    }

    #[test]
    fn content_length_garbage_treated_as_absent() {
        // A non-numeric or negative Content-Length is malformed but we
        // don't reject on it here — hyper will reject the request earlier
        // in the parse path. The cap check just falls through to streaming.
        let h = cl_headers("not-a-number");
        assert_eq!(content_length_over_cap(&h, XML_BODY_MAX_BYTES), None);
    }
}
