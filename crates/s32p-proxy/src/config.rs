use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub version: u32,
    pub server:  ServerConfig,
    pub auth:    AuthConfig,
    pub workers: WorkersConfig,
    pub routing: RoutingConfig,
    #[serde(default)]
    pub session: SessionConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SessionConfig {
    /// Lifetime of a CreateSession credential in seconds. AWS uses 300 (5 min).
    #[serde(default = "default_session_ttl_secs")]
    pub ttl_secs:              u64,
    /// How often the proxy sweeps expired session entries from memory.
    #[serde(default = "default_session_cleanup_interval_secs")]
    pub cleanup_interval_secs: u64,
    /// Hard cap on simultaneously-active sessions; further `CreateSession`
    /// calls fail with `ServiceUnavailable` once exceeded.
    #[serde(default = "default_session_max_active")]
    pub max_active:            usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            ttl_secs:              default_session_ttl_secs(),
            cleanup_interval_secs: default_session_cleanup_interval_secs(),
            max_active:            default_session_max_active(),
        }
    }
}

fn default_session_ttl_secs() -> u64 {
    300
}
fn default_session_cleanup_interval_secs() -> u64 {
    60
}
fn default_session_max_active() -> usize {
    10_000
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// e.g. "0.0.0.0:9000"
    pub listen:                     String,
    /// "http" in dev, "https" behind TLS termination
    pub public_scheme:              String,
    /// Path to TLS certificate (full chain)
    pub tls_cert_path:              Option<String>,
    /// Path to TLS private key (in PEM format)
    pub tls_key_path:               Option<String>,
    /// Bucket region returned by GetBucketLocation (e.g. "eu-central-1"). Use "us-east-1" for the classic default.
    pub region:                     String,
    /// e.g. "info", "debug", or "s32p_proxy=debug"
    pub log_level:                  Option<String>,
    /// Log format: "text" (default, human-readable) or "json" (one JSON
    /// object per line, suitable for ingestion by Wazuh/Elastic/etc.).
    /// Forwarded to workers via the `{{log_format}}` template placeholder.
    pub log_format:                 Option<String>,
    /// Pingora's grace period on SIGTERM, in seconds. The proxy stops
    /// accepting new connections, broadcasts shutdown, then sleeps this
    /// long (uninterruptible) to let in-flight requests drain. Defaults
    /// to 10s; set higher if you have slow large-object PUTs.
    /// Pingora's own default is 300s, which is too long for `systemctl
    /// stop` (TimeoutStopSec=30s in the shipped unit).
    #[serde(default = "default_shutdown_grace_period_secs")]
    pub shutdown_grace_period_secs: u64,
    /// Host suffixes for virtual-hosted-style bucket detection.
    /// If a request's Host header ends with one of these suffixes and has exactly one additional component,
    /// it will be treated as virtual-hosted-style (bucket in host, key in path).
    /// Example: ["s3.example.com", "s3.internal.example.com"]
    #[serde(default)]
    pub virtual_hosted_suffixes:    Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    /// Which directory backend to use.
    #[serde(default)]
    pub backend: AuthBackend,

    /// YAML backend options
    pub yaml: Option<YamlAuthConfig>,

    /// OpenBao backend options (AppRole + KV v2 + indices)
    pub openbao: Option<OpenBaoAuthConfig>,

    /// Optional TTL cache in front of the directory backend. The
    /// `enabled` field is `Option<bool>` so the proxy can apply a
    /// backend-aware default in `main.rs`: cache is on by default for
    /// the OpenBao backend (every request would otherwise hit Vault),
    /// off by default for the YAML backend (lookups are already free
    /// in-memory).
    #[serde(default)]
    pub cache: CacheToggle,
}

/// User-facing cache controls. See `s32p_directory::CacheConfig` for the
/// runtime type the proxy constructs from these values.
#[derive(Debug, Clone, Deserialize)]
pub struct CacheToggle {
    /// `None` → use the per-backend default. `Some(true)` / `Some(false)`
    /// override it.
    pub enabled:           Option<bool>,
    #[serde(default = "default_user_ttl_secs")]
    pub user_ttl_secs:     u64,
    #[serde(default = "default_buckets_ttl_secs")]
    pub buckets_ttl_secs:  u64,
    #[serde(default = "default_negative_ttl_secs")]
    pub negative_ttl_secs: u64,
    #[serde(default = "default_max_entries")]
    pub max_entries:       usize,
}

// Hand-written so omitting the whole `auth.cache:` section yields the
// same values as omitting individual fields. `derive(Default)` here
// would zero everything (u64::default = 0, usize::default = 0), and
// `#[serde(default = "...")]` only fires when fields are missing
// inside a *present* struct — not when the parent's `serde(default)`
// triggers Default::default() for the whole struct.
impl Default for CacheToggle {
    fn default() -> Self {
        Self {
            enabled:           None,
            user_ttl_secs:     default_user_ttl_secs(),
            buckets_ttl_secs:  default_buckets_ttl_secs(),
            negative_ttl_secs: default_negative_ttl_secs(),
            max_entries:       default_max_entries(),
        }
    }
}

fn default_user_ttl_secs() -> u64 {
    30
}
fn default_buckets_ttl_secs() -> u64 {
    30
}
fn default_negative_ttl_secs() -> u64 {
    5
}
fn default_max_entries() -> usize {
    4096
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthBackend {
    Yaml,
    OpenBao,
}

impl Default for AuthBackend {
    fn default() -> Self {
        AuthBackend::Yaml
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct YamlAuthConfig {
    /// Path to the YAML directory file.
    pub path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OpenBaoAuthConfig {
    /// Base URL of OpenBao, e.g. "http://127.0.0.1:8200"
    pub address: String,

    /// Auth mount for AppRole, usually "approle"
    #[serde(default = "default_approle_mount")]
    pub approle_mount: String,

    /// Files containing role_id/secret_id (recommended over inline secrets in YAML)
    pub role_id_file:   String,
    pub secret_id_file: String,

    /// KV v2 mount name, e.g. "secret"
    pub kv_mount: String,

    /// Prefix under that mount, e.g. "s32p"
    pub prefix: String,
}

fn default_approle_mount() -> String {
    "approle".to_string()
}

fn default_shutdown_grace_period_secs() -> u64 {
    10
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig {
    /// "tcp" or "uds"
    pub kind: UpstreamKind,

    /// Base directory for per-uid UDS run dirs. Used when kind=uds.
    /// Sockets are created under: <uds_run_dir>/<uid>-<instance_id>/<profile>.sock
    /// where <instance_id> is a per-proxy-process random suffix so that multiple
    /// proxy instances on the same host (sharing a worker uid) don't collide.
    /// If unset, defaults to `/run/s32p` when the proxy runs as root
    /// (euid == 0), otherwise `$XDG_RUNTIME_DIR/s32p`.
    pub uds_run_dir: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamKind {
    Tcp,
    Uds,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self { kind: UpstreamKind::Tcp, uds_run_dir: None }
    }
}

/// Resolve the default base directory for UDS run dirs based on the
/// proxy's effective uid:
/// - euid == 0 (e.g. systemd service): `/run/s32p`
/// - euid != 0: `$XDG_RUNTIME_DIR/s32p`
fn default_uds_run_dir() -> Result<String> {
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        Ok("/run/s32p".to_string())
    } else {
        let xdg = std::env::var("XDG_RUNTIME_DIR").map_err(|_| {
            anyhow!(
                "XDG_RUNTIME_DIR is not set; either set it, run as root, or set \
                 workers.profiles.<name>.upstream.uds_run_dir explicitly"
            )
        })?;
        let xdg = xdg.trim_end_matches('/');
        if xdg.is_empty() {
            return Err(anyhow!(
                "XDG_RUNTIME_DIR is empty; either set it to a valid path, run as root, \
                 or set workers.profiles.<name>.upstream.uds_run_dir explicitly"
            ));
        }
        Ok(format!("{xdg}/s32p"))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkersConfig {
    /// Shared POSIX root directory passed to the worker template ({{posix_root}})
    pub posix_root: String,

    pub launcher:  LauncherConfig,
    pub lifecycle: LifecycleConfig,

    /// Named worker templates
    pub profiles: BTreeMap<String, WorkerProfile>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LauncherConfig {
    pub path:                   String,
    pub pass_user_flag_if_root: bool,
    #[serde(default = "default_true")]
    pub landlock:               bool,
    /// Pass `--landlock-strict` to the launcher: fail-closed when the kernel
    /// reports `PartiallyEnforced`. Defaults on; deployments on kernels with
    /// incomplete Landlock ABI support may need to disable this explicitly.
    #[serde(default = "default_true")]
    pub landlock_strict:        bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LifecycleConfig {
    pub idle_timeout_secs:   u64,
    pub sweep_interval_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkerProfile {
    /// Worker executable, e.g. "/usr/local/bin/versitygw"
    pub exec: String,

    /// Args are a list (no shell). Placeholders are left as-is for your templater later.
    pub args: Vec<String>,

    #[serde(default)]
    pub upstream: UpstreamConfig,

    /// Environment variables for the worker process.
    /// Values may include placeholders like "{{access_key}}".
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RoutingConfig {
    /// Maps classifier classes (e.g. "multipart", "versioning", "other")
    /// to an action.
    pub class_map: BTreeMap<String, RouteAction>,
    // Reserved for later:
    // #[serde(default)]
    // pub rules: Vec<RouteRule>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum RouteAction {
    /// Proxy to a worker profile (and thus spawn/route to that kind of worker).
    Proxy { worker_profile: String },

    /// Return S3 NotImplemented (but only after SigV4 validation, per your logic).
    NotImplemented { message: String },

    /// Handle locally as S3 Express CreateSession. Mints ephemeral
    /// credentials in the proxy's session store and returns the
    /// `<CreateSessionResult>` XML body.
    CreateSession,

    /// Reply locally with the closest AWS-shaped response per the
    /// specific `S3Op` (e.g. 200 + empty `<VersioningConfiguration/>`
    /// for `GetBucketVersioning`, 404 + `ObjectLockConfigurationNotFoundError`
    /// for `GetBucketObjectLockConfiguration`, 400 + `InvalidRequest` for
    /// Put-Retention / Put-LegalHold). Ops within the routed class that
    /// have no AWS feature-disabled equivalent fall back to 501
    /// NotImplemented with a generic message. See
    /// `responses::respond_aws_compat` for the per-op dispatch table.
    AwsCompat,
}

impl Config {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;
        Self::from_str(&text).with_context(|| format!("config parse failed for {}", path.display()))
    }

    pub fn from_str(yaml: &str) -> Result<Self> {
        let mut cfg: Config = serde_yaml::from_str(yaml).context("failed to parse YAML")?;
        cfg.normalize_defaults()?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Fill in runtime-derived defaults for fields the user may omit.
    fn normalize_defaults(&mut self) -> Result<()> {
        for (name, profile) in self.workers.profiles.iter_mut() {
            if !matches!(profile.upstream.kind, UpstreamKind::Uds) {
                continue;
            }
            let already_set = profile
                .upstream
                .uds_run_dir
                .as_deref()
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false);
            if already_set {
                continue;
            }
            profile.upstream.uds_run_dir = Some(default_uds_run_dir().with_context(|| {
                format!(
                    "workers.profiles.{name}.upstream.uds_run_dir is unset and no default \
                     could be derived"
                )
            })?);
        }
        Ok(())
    }

    /// Resolve placeholders in the launcher path.
    /// Currently supports: {{install_bin_dir}}
    pub fn resolve_placeholders(&mut self, install_bin_dir: &str) -> Result<()> {
        // Resolve {{install_bin_dir}} in launcher path
        if self.workers.launcher.path.contains("{{install_bin_dir}}") {
            self.workers.launcher.path =
                self.workers.launcher.path.replace("{{install_bin_dir}}", install_bin_dir);
        }

        // Resolve {{install_bin_dir}} in worker profiles
        for profile in self.workers.profiles.values_mut() {
            if profile.exec.contains("{{install_bin_dir}}") {
                profile.exec = profile.exec.replace("{{install_bin_dir}}", install_bin_dir);
            }
        }

        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(anyhow!("unsupported config version {} (expected 1)", self.version));
        }

        if self.server.listen.trim().is_empty() {
            return Err(anyhow!("server.listen must not be empty"));
        }

        match self.server.public_scheme.as_str() {
            "http" | "https" => {}
            other => {
                return Err(anyhow!(
                    "server.public_scheme must be 'http' or 'https' (got '{other}')"
                ));
            }
        }

        if self.server.public_scheme == "https" {
            if self.server.tls_cert_path.is_none() || self.server.tls_key_path.is_none() {
                return Err(anyhow!(
                    "TLS certificate and key paths are required when public_scheme is 'https'"
                ));
            }
            // Verify files exist and are readable
            if let (Some(cert_path), Some(key_path)) =
                (&self.server.tls_cert_path, &self.server.tls_key_path)
            {
                if !Path::new(cert_path).exists() || !Path::new(key_path).exists() {
                    return Err(anyhow!("TLS certificate or key file does not exist"));
                }
            }
        }

        if self.server.region.trim().is_empty() {
            return Err(anyhow!("server.region must not be empty"));
        }

        match self.auth.backend {
            AuthBackend::Yaml => {
                let y = self.auth.yaml.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("auth.backend is 'yaml' but auth.yaml is missing")
                })?;
                if y.path.trim().is_empty() {
                    return Err(anyhow::anyhow!("auth.yaml.path must not be empty"));
                }
            }
            AuthBackend::OpenBao => {
                let o = self.auth.openbao.as_ref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "auth.backend is 'open_bao'/'openbao' but auth.openbao is missing"
                    )
                })?;

                if o.address.trim().is_empty() {
                    return Err(anyhow::anyhow!("auth.openbao.address must not be empty"));
                }
                if o.approle_mount.trim().is_empty() {
                    return Err(anyhow::anyhow!("auth.openbao.approle_mount must not be empty"));
                }
                if o.role_id_file.trim().is_empty() {
                    return Err(anyhow::anyhow!("auth.openbao.role_id_file must not be empty"));
                }
                if o.secret_id_file.trim().is_empty() {
                    return Err(anyhow::anyhow!("auth.openbao.secret_id_file must not be empty"));
                }
                if o.kv_mount.trim().is_empty() {
                    return Err(anyhow::anyhow!("auth.openbao.kv_mount must not be empty"));
                }
                if o.prefix.trim().is_empty() {
                    return Err(anyhow::anyhow!("auth.openbao.prefix must not be empty"));
                }
            }
        }

        if self.workers.posix_root.trim().is_empty() {
            return Err(anyhow!("workers.posix_root must not be empty"));
        }

        if self.workers.launcher.path.trim().is_empty() {
            return Err(anyhow!("workers.launcher.path must not be empty"));
        }

        if self.workers.profiles.is_empty() {
            return Err(anyhow!("workers.profiles must contain at least one profile"));
        }

        for (_name, profile) in &self.workers.profiles {
            match profile.upstream.kind {
                UpstreamKind::Tcp => {}
                UpstreamKind::Uds => {
                    let dir = profile.upstream.uds_run_dir.as_deref().unwrap_or("").trim();
                    if dir.is_empty() {
                        return Err(anyhow!(
                            "workers.profile.upstream.uds_run_dir is empty after default \
                             resolution (this should not happen — please report)"
                        ));
                    }
                }
            }
        }

        // Validate routing targets exist
        for (class, action) in &self.routing.class_map {
            match action {
                RouteAction::Proxy { worker_profile } => {
                    if !self.workers.profiles.contains_key(worker_profile) {
                        return Err(anyhow!(
                            "routing.class_map.{class}: references unknown worker_profile '{worker_profile}'"
                        ));
                    }
                }
                RouteAction::NotImplemented { message } => {
                    if message.trim().is_empty() {
                        return Err(anyhow!(
                            "routing.class_map.{class}: not_implemented message must not be empty"
                        ));
                    }
                }
                RouteAction::CreateSession => {
                    // The classifier emits `session` only for `GET /{bucket}?session`.
                    // Operators can disable the feature by mapping it to `not_implemented`,
                    // but routing it to a worker would be a misconfig: the session store
                    // lives in the proxy, the worker can't mint credentials.
                    if class != "session" {
                        return Err(anyhow!(
                            "routing.class_map.{class}: action 'create_session' is only \
                             valid for the 'session' class (got '{class}')"
                        ));
                    }
                }
                RouteAction::AwsCompat => {
                    // No-op: the per-op AWS-shape dispatch lives in
                    // `responses::respond_aws_compat`, and any op without an
                    // explicit AWS feature-disabled response falls back to
                    // a 501 NotImplemented. Allowed on any class — operators
                    // can choose this for `versioning` / `object_lock` (the
                    // intended use) without us second-guessing them on
                    // other classes.
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: omitting the entire `auth.cache:` section must yield
    /// the same TTL/cap values as omitting individual fields. A bare
    /// `derive(Default)` on `CacheToggle` zeroes everything and the
    /// per-backend default-on (OpenBao) would silently build a cache
    /// with TTL=0 — useless. The hand-written `Default` keeps the
    /// two paths consistent.
    #[test]
    fn cache_toggle_default_matches_field_serde_defaults() {
        let from_default = CacheToggle::default();
        let from_empty_struct: CacheToggle =
            serde_yaml::from_str("{}").expect("empty struct must deserialize via field defaults");
        assert_eq!(from_default.enabled, from_empty_struct.enabled);
        assert_eq!(from_default.user_ttl_secs, from_empty_struct.user_ttl_secs);
        assert_eq!(from_default.buckets_ttl_secs, from_empty_struct.buckets_ttl_secs);
        assert_eq!(from_default.negative_ttl_secs, from_empty_struct.negative_ttl_secs);
        assert_eq!(from_default.max_entries, from_empty_struct.max_entries);
        // And the values must be the documented defaults, not zero.
        assert_eq!(from_default.user_ttl_secs, 30);
        assert_eq!(from_default.max_entries, 4096);
    }

    /// Sibling regression: when `auth:` carries no `cache:` key at all,
    /// the AuthConfig field's `#[serde(default)]` triggers
    /// `<CacheToggle as Default>::default()` — must yield the documented
    /// non-zero values, not a useless all-zero cache.
    #[test]
    fn auth_config_without_cache_section_uses_documented_defaults() {
        let yaml = r#"
backend: openbao
"#;
        let auth: AuthConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(auth.cache.enabled, None); // backend-aware default applies in main.rs
        assert_eq!(auth.cache.user_ttl_secs, 30);
        assert_eq!(auth.cache.buckets_ttl_secs, 30);
        assert_eq!(auth.cache.negative_ttl_secs, 5);
        assert_eq!(auth.cache.max_entries, 4096);
    }
}
