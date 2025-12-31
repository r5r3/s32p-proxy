use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::{collections::BTreeMap, fs, path::Path};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub version: u32,
    pub server: ServerConfig,
    pub auth: AuthConfig,
    pub workers: WorkersConfig,
    pub routing: RoutingConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// e.g. "0.0.0.0:9000"
    pub listen: String,
    /// "http" in dev, "https" behind TLS termination
    pub public_scheme: String,
    /// Bucket region returned by GetBucketLocation (e.g. "eu-central-1"). Use "us-east-1" for the classic default.
    pub region: String,
    /// e.g. "info", "debug", or "s3_proxy_manager=debug"
    pub log: Option<String>,
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
    pub role_id_file: String,
    pub secret_id_file: String,

    /// KV v2 mount name, e.g. "secret"
    pub kv_mount: String,

    /// Prefix under that mount, e.g. "s3pm"
    pub prefix: String,
}

fn default_approle_mount() -> String {
    "approle".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig {
    /// "tcp" or "uds"
    pub kind: UpstreamKind,

    /// Base directory for per-uid UDS run dirs. Required when kind=uds.
    /// Sockets will be created under: <uds_run_dir>/<uid>/<profile>.sock
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
        Self {
            kind: UpstreamKind::Tcp,
            uds_run_dir: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkersConfig {
    /// Shared POSIX root directory passed to the worker template ({{posix_root}})
    pub posix_root: String,

    pub launcher: LauncherConfig,
    pub lifecycle: LifecycleConfig,

    /// Named worker templates
    pub profiles: BTreeMap<String, WorkerProfile>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LauncherConfig {
    pub path: String,
    pub pass_user_flag_if_root: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LifecycleConfig {
    pub idle_timeout_secs: u64,
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
}

impl Config {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;
        Self::from_str(&text).with_context(|| format!("config parse failed for {}", path.display()))
    }

    pub fn from_str(yaml: &str) -> Result<Self> {
        let cfg: Config = serde_yaml::from_str(yaml).context("failed to parse YAML")?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(anyhow!(
                "unsupported config version {} (expected 1)",
                self.version
            ));
        }

        if self.server.listen.trim().is_empty() {
            return Err(anyhow!("server.listen must not be empty"));
        }

        match self.server.public_scheme.as_str() {
            "http" | "https" => {}
            other => {
                return Err(anyhow!(
                    "server.public_scheme must be 'http' or 'https' (got '{other}')"
                ))
            }
        }

        if self.server.region.trim().is_empty() {
            return Err(anyhow!("server.region must not be empty"));
        }

        match self.auth.backend {
            AuthBackend::Yaml => {
                let y = self.auth.yaml.as_ref().ok_or_else(|| anyhow::anyhow!(
                    "auth.backend is 'yaml' but auth.yaml is missing"
                ))?;
                if y.path.trim().is_empty() {
                    return Err(anyhow::anyhow!("auth.yaml.path must not be empty"));
                }
            }
            AuthBackend::OpenBao => {
                let o = self.auth.openbao.as_ref().ok_or_else(|| anyhow::anyhow!(
                    "auth.backend is 'open_bao'/'openbao' but auth.openbao is missing"
                ))?;

                if o.address.trim().is_empty() { return Err(anyhow::anyhow!("auth.openbao.address must not be empty")); }
                if o.approle_mount.trim().is_empty() { return Err(anyhow::anyhow!("auth.openbao.approle_mount must not be empty")); }
                if o.role_id_file.trim().is_empty() { return Err(anyhow::anyhow!("auth.openbao.role_id_file must not be empty")); }
                if o.secret_id_file.trim().is_empty() { return Err(anyhow::anyhow!("auth.openbao.secret_id_file must not be empty")); }
                if o.kv_mount.trim().is_empty() { return Err(anyhow::anyhow!("auth.openbao.kv_mount must not be empty")); }
                if o.prefix.trim().is_empty() { return Err(anyhow::anyhow!("auth.openbao.prefix must not be empty")); }
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

        for (name, profile) in &self.workers.profiles {
            match profile.upstream.kind {
                UpstreamKind::Tcp => {}
                UpstreamKind::Uds => {
                    let dir = profile.upstream.uds_run_dir.as_deref().unwrap_or("").trim();
                    if dir.is_empty() {
                        return Err(anyhow!("workers.profile.upstream.uds_run_dir must be set when kind=uds"));
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
            }
        }

        Ok(())
    }
}

