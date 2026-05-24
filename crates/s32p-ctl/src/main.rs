use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use clap::{Args, Parser, Subcommand, ValueEnum};
use s32p_admin::{
    OpenBaoAdmin,
    yaml::{
        DirectoryFileV1, load_directory_yaml_file, parse_directory_yaml_str,
        render_directory_yaml_string, save_directory_yaml_file,
    },
};
use s32p_directory::directory::layout::normalize_acl; // ensure layout.rs is public
use s32p_directory::types::{AccessLevel, AclEntry, BucketDoc, Principal, UserDoc};
use serde::Deserialize;
use uuid::Uuid;

#[derive(ValueEnum, Debug, Clone, Copy)]
enum Backend {
    Openbao,
    Yaml,
}

#[derive(Parser, Debug)]
#[command(name = "s32p-ctl", version)]
struct Cli {
    /// Read auth/backend defaults from an s32p-proxy YAML config.
    /// Explicit flags still override; missing values fall back to built-in defaults.
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Backend to use: openbao or yaml. Default: openbao (or auth.backend from --config).
    #[arg(long, value_enum)]
    backend: Option<Backend>,

    /// YAML directory file path (required for --backend yaml).
    #[arg(long)]
    yaml_path: Option<PathBuf>,

    /// OpenBao/Vault connection settings (used for --backend openbao).
    #[command(flatten)]
    openbao: OpenBaoConnArgs,

    #[command(subcommand)]
    cmd: Cmd,
}

/* ------------------- subset of s32p-proxy YAML, for --config ------------------- */
//
// Mirrors the auth-relevant fields of s32p-proxy/src/config.rs. Unknown fields
// are ignored by serde, so the proxy's full config can be passed directly.

#[derive(Debug, Deserialize)]
struct ProxyYamlSubset {
    auth: ProxyAuth,
}

#[derive(Debug, Deserialize)]
struct ProxyAuth {
    #[serde(default)]
    backend: Option<ProxyBackend>,
    yaml:    Option<ProxyYamlBackend>,
    openbao: Option<ProxyOpenBao>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ProxyBackend {
    Yaml,
    OpenBao,
}

#[derive(Debug, Deserialize)]
struct ProxyYamlBackend {
    path: String,
}

#[derive(Debug, Deserialize)]
struct ProxyOpenBao {
    address:              Option<String>,
    approle_mount:        Option<String>,
    /// proxy's read-only AppRole credentials
    role_id_file:         Option<String>,
    secret_id_file:       Option<String>,
    /// admin AppRole credentials — preferred by s32p-ctl when present
    admin_role_id_file:   Option<String>,
    admin_secret_id_file: Option<String>,
    kv_mount:             Option<String>,
    prefix:               Option<String>,
}

fn apply_config_defaults(cli: &mut Cli) -> Result<()> {
    let Some(path) = cli.config.as_deref() else {
        return Ok(());
    };

    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read config file: {}", path.display()))?;
    let cfg: ProxyYamlSubset = serde_yaml::from_str(&text)
        .with_context(|| format!("parse config file: {}", path.display()))?;

    if cli.backend.is_none() {
        cli.backend = cfg.auth.backend.as_ref().map(|b| match b {
            ProxyBackend::Yaml => Backend::Yaml,
            ProxyBackend::OpenBao => Backend::Openbao,
        });
    }

    if cli.yaml_path.is_none() {
        if let Some(y) = &cfg.auth.yaml {
            cli.yaml_path = Some(PathBuf::from(&y.path));
        }
    }

    if let Some(o) = &cfg.auth.openbao {
        if cli.openbao.address.is_none() {
            cli.openbao.address = o.address.clone();
        }
        if cli.openbao.kv_mount.is_none() {
            cli.openbao.kv_mount = o.kv_mount.clone();
        }
        if cli.openbao.prefix.is_none() {
            cli.openbao.prefix = o.prefix.clone();
        }
        if cli.openbao.auth.approle_mount.is_none() {
            cli.openbao.auth.approle_mount = o.approle_mount.clone();
        }
        // Prefer admin_*_file over the proxy's read-only role/secret files.
        let role_id_file = o.admin_role_id_file.as_ref().or(o.role_id_file.as_ref());
        let secret_id_file = o.admin_secret_id_file.as_ref().or(o.secret_id_file.as_ref());
        if cli.openbao.auth.role_id.is_none() && cli.openbao.auth.role_id_file.is_none() {
            cli.openbao.auth.role_id_file = role_id_file.map(PathBuf::from);
        }
        if cli.openbao.auth.secret_id.is_none() && cli.openbao.auth.secret_id_file.is_none() {
            cli.openbao.auth.secret_id_file = secret_id_file.map(PathBuf::from);
        }
    }

    Ok(())
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Initialize backend structures.
    ///
    /// - openbao: enable approle + create policies + create roles s32p-proxy(ro) and s32p-admin(rw)
    /// - yaml: create an empty directory.yaml skeleton
    Setup(SetupArgs),

    #[command(subcommand)]
    /// Manage users (add, remove, list) with the selected backend.
    User(UserCmd),

    #[command(subcommand)]
    /// Manage buckets (add, remove, list, set-acl) with the selected backend.
    Bucket(BucketCmd),

    /// Import a directory.yaml into the backend.
    ImportYaml(ImportYamlArgs),

    /// Import users from a VersityGW IAM JSON file (`accessAccounts`).
    ///
    /// `username` is resolved at runtime via `getpwuid_r(userID)`.
    /// VG `role` is discarded; VG IAM has no bucket concept, so buckets/ACLs
    /// in the directory are not touched. Always merges (no `--replace`).
    ImportVersityIam(ImportVersityIamArgs),

    /// Export backend state to a directory.yaml.
    ExportYaml(ExportYamlArgs),
}

/* ------------------- OpenBao connection args (validated only if backend=openbao) ------------------- */

#[derive(Args, Debug, Clone, Default)]
struct OpenBaoConnArgs {
    /// OpenBao/Vault address, e.g. http://127.0.0.1:8200
    #[arg(long, env = "VAULT_ADDR")]
    address: Option<String>,

    /// KV v2 mount name. Default: "secret" (or auth.openbao.kv_mount from --config).
    #[arg(long)]
    kv_mount: Option<String>,

    /// Prefix within the KV store. Default: "s32p" (or auth.openbao.prefix from --config).
    #[arg(long)]
    prefix: Option<String>,

    #[command(flatten)]
    auth: OpenBaoAuthArgs,
}

#[derive(Args, Debug, Clone, Default)]
struct OpenBaoAuthArgs {
    /// root/admin token for bootstrap (VAULT_TOKEN).
    #[arg(long, env = "VAULT_TOKEN")]
    token: Option<String>,

    /// AppRole auth mount. Default: "approle" (or auth.openbao.approle_mount from --config).
    #[arg(long)]
    approle_mount: Option<String>,

    /// Role ID string (alternative to --role-id-file)
    #[arg(long)]
    role_id: Option<String>,

    /// Secret ID string (alternative to --secret-id-file)
    #[arg(long)]
    secret_id: Option<String>,

    /// Role ID file (recommended)
    #[arg(long)]
    role_id_file: Option<PathBuf>,

    /// Secret ID file (recommended)
    #[arg(long)]
    secret_id_file: Option<PathBuf>,
}

impl OpenBaoAuthArgs {
    fn read_trimmed(path: &Path) -> Result<String> {
        let s =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        Ok(s.trim().to_string())
    }
}

async fn openbao_admin(conn: &OpenBaoConnArgs) -> Result<OpenBaoAdmin> {
    let address = conn
        .address
        .as_ref()
        .ok_or_else(|| anyhow!("missing OpenBao address: provide --address or VAULT_ADDR"))?
        .trim()
        .to_string();

    let kv_mount = conn.kv_mount.clone().unwrap_or_else(|| "secret".to_string());
    let prefix = conn.prefix.clone().unwrap_or_else(|| "s32p".to_string());
    let approle_mount = conn.auth.approle_mount.clone().unwrap_or_else(|| "approle".to_string());

    // Token auth takes precedence
    if let Some(t) = &conn.auth.token {
        return OpenBaoAdmin::new_token(address, t.clone(), kv_mount, prefix);
    }

    // Otherwise AppRole auth
    let role_id = match (&conn.auth.role_id, &conn.auth.role_id_file) {
        (Some(v), _) => v.trim().to_string(),
        (None, Some(p)) => OpenBaoAuthArgs::read_trimmed(p)?,
        _ => return Err(anyhow!("missing auth: provide --token or --role-id/--role-id-file")),
    };

    let secret_id = match (&conn.auth.secret_id, &conn.auth.secret_id_file) {
        (Some(v), _) => v.trim().to_string(),
        (None, Some(p)) => OpenBaoAuthArgs::read_trimmed(p)?,
        _ => return Err(anyhow!("missing auth: provide --token or --secret-id/--secret-id-file")),
    };

    OpenBaoAdmin::new_approle(address, approle_mount, role_id, secret_id, kv_mount, prefix)
}

/* ------------------- setup ------------------- */

#[derive(Args, Debug)]
struct SetupArgs {
    /// For OpenBao: write proxy role_id to file
    #[arg(long)]
    proxy_role_id_file:   Option<PathBuf>,
    /// For OpenBao: write proxy secret_id to file
    #[arg(long)]
    proxy_secret_id_file: Option<PathBuf>,

    /// For OpenBao: write admin role_id to file
    #[arg(long)]
    admin_role_id_file:   Option<PathBuf>,
    /// For OpenBao: write admin secret_id to file
    #[arg(long)]
    admin_secret_id_file: Option<PathBuf>,
}

fn write_secret_file(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create dir {}", parent.display()))?;
    }
    std::fs::write(path, contents).with_context(|| format!("write {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perm = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perm)
            .with_context(|| format!("chmod 0600 {}", path.display()))?;
    }

    Ok(())
}

fn require_yaml_path(yaml_path: &Option<PathBuf>) -> Result<PathBuf> {
    yaml_path
        .clone()
        .ok_or_else(|| anyhow!("--yaml-path is required when --backend yaml"))
}

fn load_yaml_or_default(path: &Path) -> Result<DirectoryFileV1> {
    if path.exists() {
        load_directory_yaml_file(path.to_str().unwrap())
    } else {
        Ok(DirectoryFileV1 { version: 1, users: vec![], buckets: vec![] })
    }
}

/* ------------------- user commands ------------------- */

#[derive(Subcommand, Debug)]
enum UserCmd {
    Add(UserAddArgs),
    Rm(UserRmArgs),
    Ls,
}

#[derive(Args, Debug)]
struct UserAddArgs {
    #[arg(long)]
    access_key: String,
    #[arg(long)]
    secret_key: String,
    #[arg(long)]
    username:   String,
    #[arg(long)]
    uid:        u32,
    #[arg(long)]
    gid:        u32,
}

#[derive(Args, Debug)]
struct UserRmArgs {
    #[arg(long)]
    access_key: String,

    /// Remove this access_key from bucket ACLs (best-effort)
    #[arg(long, default_value_t = true)]
    cleanup_acls: bool,
}

/* ------------------- bucket commands ------------------- */

#[derive(Subcommand, Debug)]
enum BucketCmd {
    Add(BucketAddArgs),
    Rm(BucketRmArgs),
    Ls,
    AclSet(BucketAclSetArgs),
}

#[derive(Args, Debug)]
struct BucketAddArgs {
    /// Optional bucket id. If omitted, a UUID is generated.
    #[arg(long)]
    bucket_id: Option<String>,

    #[arg(long)]
    name:      String,
    #[arg(long)]
    data_path: String,

    /// Repeatable: "ak:<ACCESS_KEY>:read_only|read_write" or "group:<NAME>:read_only|read_write"
    #[arg(long = "grant")]
    grants: Vec<String>,
}

#[derive(Args, Debug)]
struct BucketRmArgs {
    #[arg(long)]
    bucket_id: String,
}

#[derive(Args, Debug)]
struct BucketAclSetArgs {
    #[arg(long)]
    bucket_id: String,

    /// Repeatable: "ak:<ACCESS_KEY>:read_only|read_write" or "group:<NAME>:read_only|read_write"
    #[arg(long = "grant")]
    grants: Vec<String>,
}

/* ------------------- import/export ------------------- */

#[derive(Args, Debug)]
struct ImportYamlArgs {
    #[arg(long)]
    yaml: PathBuf,

    /// Replace existing data (yaml: overwrite file; openbao: purge prefix subtrees)
    #[arg(long, default_value_t = true)]
    replace: bool,
}

#[derive(Args, Debug)]
struct ExportYamlArgs {
    #[arg(long)]
    yaml: PathBuf,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
enum OnMissingUserArg {
    /// Hard error and stop the import (default).
    Error,
    /// Use the VG access key string as the `username`.
    UseAccessKey,
    /// Log a warning and skip the entry.
    Skip,
}

impl From<OnMissingUserArg> for s32p_admin::versity_iam::OnMissingUser {
    fn from(v: OnMissingUserArg) -> Self {
        match v {
            OnMissingUserArg::Error => Self::Error,
            OnMissingUserArg::UseAccessKey => Self::UseAccessKey,
            OnMissingUserArg::Skip => Self::Skip,
        }
    }
}

#[derive(Args, Debug)]
struct ImportVersityIamArgs {
    /// Path to the VersityGW IAM JSON file.
    #[arg(long)]
    json: PathBuf,

    /// What to do when `getpwuid_r(userID)` returns no entry.
    #[arg(long, value_enum, default_value_t = OnMissingUserArg::Error)]
    on_missing_user: OnMissingUserArg,

    /// Only import these access keys (repeatable). Mutually exclusive with --exclude.
    #[arg(long = "include")]
    include: Vec<String>,

    /// Skip these access keys (repeatable). Mutually exclusive with --include.
    #[arg(long = "exclude", conflicts_with = "include")]
    exclude: Vec<String>,
}

/* ------------------- parsing helpers ------------------- */

fn parse_access_level(s: &str) -> Result<AccessLevel> {
    match s.trim().to_ascii_lowercase().as_str() {
        "ro" | "read" | "read_only" | "readonly" => Ok(AccessLevel::ReadOnly),
        "rw" | "write" | "read_write" | "readwrite" => Ok(AccessLevel::ReadWrite),
        _ => Err(anyhow!("invalid access level '{s}', expected read_only|read_write")),
    }
}

fn parse_grant(s: &str) -> Result<AclEntry> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 3 {
        return Err(anyhow!(
            "invalid grant '{s}'. expected 'ak:<ACCESS_KEY>:read_only|read_write' or 'group:<NAME>:read_only|read_write'"
        ));
    }

    let principal = match parts[0].trim().to_ascii_lowercase().as_str() {
        "ak" | "access_key" => Principal::AccessKey { access_key: parts[1].trim().to_string() },
        "group" | "group_name" => Principal::GroupName { name: parts[1].trim().to_string() },
        other => return Err(anyhow!("invalid grant principal type '{other}' in '{s}'")),
    };

    s32p_directory::validate_principal(&principal)?;

    let access = parse_access_level(parts[2])?;
    Ok(AclEntry { principal, access })
}

/* ------------------- YAML backend operations ------------------- */

fn yaml_user_upsert(doc: &mut DirectoryFileV1, user: UserDoc) {
    doc.users.retain(|u| u.access_key != user.access_key);
    doc.users.push(user);
    doc.users.sort_by(|a, b| a.access_key.cmp(&b.access_key));
}

fn yaml_user_delete(doc: &mut DirectoryFileV1, access_key: &str, cleanup_acls: bool) {
    doc.users.retain(|u| u.access_key != access_key);

    if cleanup_acls {
        for b in &mut doc.buckets {
            b.acl.retain(|e| match &e.principal {
                Principal::AccessKey { access_key: ak } => ak != access_key,
                _ => true,
            });
            b.acl = normalize_acl(std::mem::take(&mut b.acl));
        }
    }
}

fn yaml_bucket_upsert(doc: &mut DirectoryFileV1, mut bucket: BucketDoc) {
    bucket.acl = normalize_acl(bucket.acl);
    doc.buckets.retain(|b| b.id != bucket.id);
    doc.buckets.push(bucket);
    doc.buckets.sort_by(|a, b| a.id.cmp(&b.id));
}

fn yaml_bucket_delete(doc: &mut DirectoryFileV1, bucket_id: &str) {
    doc.buckets.retain(|b| b.id != bucket_id);
}

fn print_versity_report(r: &s32p_admin::versity_iam::ImportReport) {
    println!(
        "imported={} filtered={} missing-user-skipped={}",
        r.imported.len(),
        r.filtered.len(),
        r.missing_user_skipped.len()
    );
    if !r.filtered.is_empty() {
        println!("filtered: {}", r.filtered.join(", "));
    }
    if !r.missing_user_skipped.is_empty() {
        println!("missing-user skipped: {}", r.missing_user_skipped.join(", "));
    }
}

fn yaml_bucket_set_acl(
    doc: &mut DirectoryFileV1,
    bucket_id: &str,
    acl: Vec<AclEntry>,
) -> Result<()> {
    let b = doc
        .buckets
        .iter_mut()
        .find(|b| b.id == bucket_id)
        .ok_or_else(|| anyhow!("bucket not found: {bucket_id}"))?;
    b.acl = normalize_acl(acl);
    Ok(())
}

/* ------------------- main ------------------- */

fn main() -> Result<()> {
    // Capture the local UTC offset before tokio spawns its worker threads —
    // `time` refuses to determine it once other threads exist.
    let timer = tracing_subscriber::fmt::time::OffsetTime::local_rfc_3339().unwrap_or_else(|_| {
        tracing_subscriber::fmt::time::OffsetTime::new(
            time::UtcOffset::UTC,
            time::format_description::well_known::Rfc3339,
        )
    });
    tracing_subscriber::fmt()
        .with_timer(timer)
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()))
        .init();

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async_main())
}

async fn async_main() -> Result<()> {
    let mut cli = Cli::parse();
    apply_config_defaults(&mut cli)?;
    let backend = cli.backend.unwrap_or(Backend::Openbao);
    let yaml_path = cli.yaml_path.clone();
    let openbao = cli.openbao.clone();
    let cmd = cli.cmd;

    match cmd {
        Cmd::Setup(args) => match backend {
            Backend::Openbao => {
                let address = openbao
                    .address
                    .as_ref()
                    .ok_or_else(|| {
                        anyhow!("missing OpenBao address: provide --address or VAULT_ADDR")
                    })?
                    .clone();

                let root_token = openbao
                    .auth
                    .token
                    .clone()
                    .ok_or_else(|| anyhow!("setup(openbao) requires --token or VAULT_TOKEN"))?;

                let res = OpenBaoAdmin::setup(
                    address,
                    root_token,
                    openbao.auth.approle_mount.clone().unwrap_or_else(|| "approle".to_string()),
                    openbao.kv_mount.clone().unwrap_or_else(|| "secret".to_string()),
                    openbao.prefix.clone().unwrap_or_else(|| "s32p".to_string()),
                )
                .await?;

                println!("Created/updated AppRoles:");
                println!("- {} role_id={}", res.proxy.role_name, res.proxy.role_id);
                println!("- {} role_id={}", res.admin.role_name, res.admin.role_id);
                println!();
                println!("Secret IDs (store securely):");
                println!("- {} secret_id={}", res.proxy.role_name, res.proxy.secret_id);
                println!("- {} secret_id={}", res.admin.role_name, res.admin.secret_id);

                if let Some(p) = args.proxy_role_id_file.as_deref() {
                    write_secret_file(p, &res.proxy.role_id)?;
                }
                if let Some(p) = args.proxy_secret_id_file.as_deref() {
                    write_secret_file(p, &res.proxy.secret_id)?;
                }
                if let Some(p) = args.admin_role_id_file.as_deref() {
                    write_secret_file(p, &res.admin.role_id)?;
                }
                if let Some(p) = args.admin_secret_id_file.as_deref() {
                    write_secret_file(p, &res.admin.secret_id)?;
                }
            }
            Backend::Yaml => {
                let path = require_yaml_path(&yaml_path)?;
                let doc = DirectoryFileV1 { version: 1, users: vec![], buckets: vec![] };
                save_directory_yaml_file(path.to_str().unwrap(), &doc)?;
                println!("ok: wrote {}", path.display());
            }
        },

        Cmd::User(sub) => match sub {
            UserCmd::Add(args) => match backend {
                Backend::Openbao => {
                    let admin = openbao_admin(&openbao).await?;
                    let user = UserDoc {
                        access_key: args.access_key,
                        secret_key: args.secret_key,
                        username:   args.username,
                        uid:        args.uid,
                        gid:        args.gid,
                    };
                    admin.upsert_user(user).await?;
                    println!("ok");
                }
                Backend::Yaml => {
                    let path = require_yaml_path(&yaml_path)?;
                    let mut doc = load_yaml_or_default(&path)?;
                    let user = UserDoc {
                        access_key: args.access_key,
                        secret_key: args.secret_key,
                        username:   args.username,
                        uid:        args.uid,
                        gid:        args.gid,
                    };
                    yaml_user_upsert(&mut doc, user);
                    save_directory_yaml_file(path.to_str().unwrap(), &doc)?;
                    println!("ok");
                }
            },

            UserCmd::Rm(args) => match backend {
                Backend::Openbao => {
                    let admin = openbao_admin(&openbao).await?;
                    admin.delete_user(&args.access_key, args.cleanup_acls).await?;
                    println!("ok");
                }
                Backend::Yaml => {
                    let path = require_yaml_path(&yaml_path)?;
                    let mut doc = load_yaml_or_default(&path)?;
                    yaml_user_delete(&mut doc, args.access_key.trim(), args.cleanup_acls);
                    save_directory_yaml_file(path.to_str().unwrap(), &doc)?;
                    println!("ok");
                }
            },

            UserCmd::Ls => match backend {
                Backend::Openbao => {
                    let admin = openbao_admin(&openbao).await?;
                    let users = admin.list_users().await?;
                    for u in users {
                        println!("{}\t{}\tuid={}\tgid={}", u.access_key, u.username, u.uid, u.gid);
                    }
                }
                Backend::Yaml => {
                    let path = require_yaml_path(&yaml_path)?;
                    let doc = load_yaml_or_default(&path)?;
                    for u in doc.users {
                        println!("{}\t{}\tuid={}\tgid={}", u.access_key, u.username, u.uid, u.gid);
                    }
                }
            },
        },

        Cmd::Bucket(sub) => match sub {
            BucketCmd::Add(args) => match backend {
                Backend::Openbao => {
                    let admin = openbao_admin(&openbao).await?;
                    let mut acl = Vec::new();
                    for g in args.grants {
                        acl.push(parse_grant(&g)?);
                    }
                    if acl.is_empty() {
                        return Err(anyhow!("bucket must have at least one --grant"));
                    }

                    if let Some(id) = args.bucket_id {
                        let bucket =
                            BucketDoc { id, name: args.name, data_path: args.data_path, acl };
                        admin.upsert_bucket(bucket).await?;
                        println!("ok");
                    } else {
                        let bucket_id =
                            admin.create_bucket(&args.name, &args.data_path, acl).await?;
                        println!("{bucket_id}");
                    }
                }
                Backend::Yaml => {
                    let path = require_yaml_path(&yaml_path)?;
                    let mut doc = load_yaml_or_default(&path)?;
                    let mut acl = Vec::new();
                    for g in args.grants {
                        acl.push(parse_grant(&g)?);
                    }
                    if acl.is_empty() {
                        return Err(anyhow!("bucket must have at least one --grant"));
                    }

                    let id = args.bucket_id.unwrap_or_else(|| Uuid::new_v4().to_string());
                    let bucket = BucketDoc {
                        id: id.clone(),
                        name: args.name,
                        data_path: args.data_path,
                        acl,
                    };
                    yaml_bucket_upsert(&mut doc, bucket);
                    save_directory_yaml_file(path.to_str().unwrap(), &doc)?;
                    println!("{id}");
                }
            },

            BucketCmd::Rm(args) => match backend {
                Backend::Openbao => {
                    let admin = openbao_admin(&openbao).await?;
                    admin.delete_bucket(&args.bucket_id).await?;
                    println!("ok");
                }
                Backend::Yaml => {
                    let path = require_yaml_path(&yaml_path)?;
                    let mut doc = load_yaml_or_default(&path)?;
                    yaml_bucket_delete(&mut doc, args.bucket_id.trim());
                    save_directory_yaml_file(path.to_str().unwrap(), &doc)?;
                    println!("ok");
                }
            },

            BucketCmd::Ls => match backend {
                Backend::Openbao => {
                    let admin = openbao_admin(&openbao).await?;
                    let buckets = admin.list_buckets().await?;
                    for b in buckets {
                        println!("{}\t{}\t{}", b.id, b.name, b.data_path);
                    }
                }
                Backend::Yaml => {
                    let path = require_yaml_path(&yaml_path)?;
                    let doc = load_yaml_or_default(&path)?;
                    for b in doc.buckets {
                        println!("{}\t{}\t{}", b.id, b.name, b.data_path);
                    }
                }
            },

            BucketCmd::AclSet(args) => match backend {
                Backend::Openbao => {
                    let admin = openbao_admin(&openbao).await?;
                    let mut acl = Vec::new();
                    for g in args.grants {
                        acl.push(parse_grant(&g)?);
                    }
                    if acl.is_empty() {
                        return Err(anyhow!("acl-set requires at least one --grant"));
                    }
                    admin.set_bucket_acl(&args.bucket_id, acl).await?;
                    println!("ok");
                }
                Backend::Yaml => {
                    let path = require_yaml_path(&yaml_path)?;
                    let mut doc = load_yaml_or_default(&path)?;
                    let mut acl = Vec::new();
                    for g in args.grants {
                        acl.push(parse_grant(&g)?);
                    }
                    if acl.is_empty() {
                        return Err(anyhow!("acl-set requires at least one --grant"));
                    }
                    yaml_bucket_set_acl(&mut doc, args.bucket_id.trim(), acl)?;
                    save_directory_yaml_file(path.to_str().unwrap(), &doc)?;
                    println!("ok");
                }
            },
        },

        Cmd::ImportYaml(args) => match backend {
            Backend::Openbao => {
                let admin = openbao_admin(&openbao).await?;
                admin.import_yaml_file(args.yaml.to_str().unwrap(), args.replace).await?;
                println!("ok");
            }
            Backend::Yaml => {
                let dst = require_yaml_path(&yaml_path)?;
                let src_text = std::fs::read_to_string(&args.yaml)
                    .with_context(|| format!("read {}", args.yaml.display()))?;
                let imported = parse_directory_yaml_str(&src_text)?;

                if args.replace {
                    save_directory_yaml_file(dst.to_str().unwrap(), &imported)?;
                } else {
                    // merge: users by access_key, buckets by id
                    let mut cur = load_yaml_or_default(&dst)?;
                    for u in imported.users {
                        yaml_user_upsert(&mut cur, u);
                    }
                    for b in imported.buckets {
                        yaml_bucket_upsert(&mut cur, b);
                    }
                    save_directory_yaml_file(dst.to_str().unwrap(), &cur)?;
                }

                println!("ok");
            }
        },

        Cmd::ImportVersityIam(args) => {
            use s32p_admin::versity_iam::{
                ImportFilter, parse_versity_iam_file, versity_iam_to_user_docs,
            };

            let filter = ImportFilter {
                include: if args.include.is_empty() {
                    None
                } else {
                    Some(args.include.iter().cloned().collect())
                },
                exclude: if args.exclude.is_empty() {
                    None
                } else {
                    Some(args.exclude.iter().cloned().collect())
                },
            };
            let on_missing = args.on_missing_user.into();

            match backend {
                Backend::Openbao => {
                    let admin = openbao_admin(&openbao).await?;
                    let report = admin
                        .import_versity_iam_file(args.json.to_str().unwrap(), &filter, on_missing)
                        .await?;
                    print_versity_report(&report);
                }
                Backend::Yaml => {
                    let path = require_yaml_path(&yaml_path)?;
                    let mut doc = load_yaml_or_default(&path)?;
                    let file = parse_versity_iam_file(args.json.to_str().unwrap())?;
                    let (users, report) = versity_iam_to_user_docs(&file, &filter, on_missing)?;
                    for u in users {
                        yaml_user_upsert(&mut doc, u);
                    }
                    save_directory_yaml_file(path.to_str().unwrap(), &doc)?;
                    print_versity_report(&report);
                }
            }
        }

        Cmd::ExportYaml(args) => match backend {
            Backend::Openbao => {
                let admin = openbao_admin(&openbao).await?;
                admin.export_yaml_file(args.yaml.to_str().unwrap()).await?;
                println!("ok");
            }
            Backend::Yaml => {
                let src = require_yaml_path(&yaml_path)?;
                let doc = load_yaml_or_default(&src)?;
                let text = render_directory_yaml_string(&doc)?;
                write_secret_file(&args.yaml, &text)?;
                println!("ok");
            }
        },
    }

    Ok(())
}
