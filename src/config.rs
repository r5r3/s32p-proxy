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
    /// e.g. "info", "debug", or "s3_proxy_manager=debug"
    pub log: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AuthConfig {
    /// Path to a user database file (future); optional for now.
    pub users_file: Option<String>,
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

        if self.workers.posix_root.trim().is_empty() {
            return Err(anyhow!("workers.posix_root must not be empty"));
        }

        if self.workers.launcher.path.trim().is_empty() {
            return Err(anyhow!("workers.launcher.path must not be empty"));
        }

        if self.workers.profiles.is_empty() {
            return Err(anyhow!("workers.profiles must contain at least one profile"));
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

