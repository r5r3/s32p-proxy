use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};
use s3pm_admin::{AccessLevel, AclEntry, OpenBaoAdmin, OpenBaoAuth, Principal, UserDoc, BucketDoc};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(name = "s3pmctl", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// OpenBao / Vault-backed directory management
    #[command(subcommand)]
    Openbao(OpenBaoCmd),
}

#[derive(Subcommand, Debug)]
enum OpenBaoCmd {
    /// Initialize OpenBao structures:
    /// - enable AppRole auth (if needed)
    /// - create policies + AppRoles: s3pm-proxy (ro) and s3pm-admin (rw)
    Setup(OpenBaoSetupArgs),

    #[command(subcommand)]
    User(UserCmd),

    #[command(subcommand)]
    Bucket(BucketCmd),

    /// Import directory.yaml into OpenBao (optionally replacing existing data).
    ImportYaml(ImportYamlArgs),

    /// Export OpenBao directory to directory.yaml
    ExportYaml(ExportYamlArgs),
}

/* ------------------- shared OpenBao connection args ------------------- */

#[derive(Args, Debug, Clone)]
struct OpenBaoConnArgs {
    /// OpenBao/Vault address, e.g. http://127.0.0.1:8200
    #[arg(long, env = "VAULT_ADDR")]
    address: String,

    /// KV v2 mount name, e.g. "secret"
    #[arg(long, default_value = "secret")]
    kv_mount: String,

    /// Prefix within the KV store, e.g. "s3pm"
    #[arg(long, default_value = "s3pm")]
    prefix: String,

    #[command(flatten)]
    auth: OpenBaoAuthArgs,
}

#[derive(Args, Debug, Clone)]
struct OpenBaoAuthArgs {
    /// Use a token (typically for setup or bootstrap).
    #[arg(long, env = "VAULT_TOKEN")]
    token: Option<String>,

    /// AppRole auth mount (default "approle")
    #[arg(long, default_value = "approle")]
    approle_mount: String,

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
        let s = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        Ok(s.trim().to_string())
    }

    fn build_auth(&self) -> Result<OpenBaoAuth> {
        if let Some(t) = &self.token {
            return Ok(OpenBaoAuth::Token(t.clone()));
        }

        let role_id = match (&self.role_id, &self.role_id_file) {
            (Some(v), _) => v.trim().to_string(),
            (None, Some(p)) => Self::read_trimmed(p)?,
            _ => return Err(anyhow!("missing auth: provide --token or --role-id/--role-id-file")),
        };

        let secret_id = match (&self.secret_id, &self.secret_id_file) {
            (Some(v), _) => v.trim().to_string(),
            (None, Some(p)) => Self::read_trimmed(p)?,
            _ => return Err(anyhow!("missing auth: provide --token or --secret-id/--secret-id-file")),
        };

        Ok(OpenBaoAuth::AppRole {
            mount: self.approle_mount.clone(),
            role_id,
            secret_id,
        })
    }
}

async fn openbao_admin(conn: &OpenBaoConnArgs) -> Result<OpenBaoAdmin> {
    let auth = conn.auth.build_auth()?;
    let admin = match auth {
        OpenBaoAuth::Token(t) => OpenBaoAdmin::new_token(conn.address.clone(), t, conn.kv_mount.clone(), conn.prefix.clone()),
        OpenBaoAuth::AppRole { mount, role_id, secret_id } => OpenBaoAdmin::new_approle(
            conn.address.clone(),
            mount,
            role_id,
            secret_id,
            conn.kv_mount.clone(),
            conn.prefix.clone(),
        ),
    };
    Ok(admin)
}

/* ------------------- setup ------------------- */

#[derive(Args, Debug)]
struct OpenBaoSetupArgs {
    /// OpenBao/Vault address (VAULT_ADDR)
    #[arg(long, env = "VAULT_ADDR")]
    address: String,

    /// Root/admin token for bootstrap (VAULT_TOKEN)
    #[arg(long, env = "VAULT_TOKEN")]
    token: String,

    /// AppRole auth mount to enable/use (default: approle)
    #[arg(long, default_value = "approle")]
    approle_mount: String,

    /// KV v2 mount name (default: secret)
    #[arg(long, default_value = "secret")]
    kv_mount: String,

    /// Prefix within KV store (default: s3pm)
    #[arg(long, default_value = "s3pm")]
    prefix: String,

    /// Write proxy role_id to file
    #[arg(long)]
    proxy_role_id_file: Option<PathBuf>,
    /// Write proxy secret_id to file
    #[arg(long)]
    proxy_secret_id_file: Option<PathBuf>,

    /// Write admin role_id to file
    #[arg(long)]
    admin_role_id_file: Option<PathBuf>,
    /// Write admin secret_id to file
    #[arg(long)]
    admin_secret_id_file: Option<PathBuf>,
}

fn write_secret_file(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create dir {}", parent.display()))?;
    }
    std::fs::write(path, contents).with_context(|| format!("write {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perm = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perm).with_context(|| format!("chmod 0600 {}", path.display()))?;
    }

    Ok(())
}

/* ------------------- user commands ------------------- */

#[derive(Subcommand, Debug)]
enum UserCmd {
    Add(UserAddArgs),
    Rm(UserRmArgs),
    Ls(OpenBaoConnArgs),
}

#[derive(Args, Debug)]
struct UserAddArgs {
    #[command(flatten)]
    conn: OpenBaoConnArgs,

    #[arg(long)]
    access_key: String,
    #[arg(long)]
    secret_key: String,
    #[arg(long)]
    username: String,
    #[arg(long)]
    uid: u32,
    #[arg(long)]
    gid: u32,
}

#[derive(Args, Debug)]
struct UserRmArgs {
    #[command(flatten)]
    conn: OpenBaoConnArgs,

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
    Ls(OpenBaoConnArgs),
    AclSet(BucketAclSetArgs),
}

#[derive(Args, Debug)]
struct BucketAddArgs {
    #[command(flatten)]
    conn: OpenBaoConnArgs,

    #[arg(long)]
    name: String,
    #[arg(long)]
    data_path: String,

    /// Repeatable: "ak:<ACCESS_KEY>:read_only|read_write" or "group:<NAME>:read_only|read_write"
    #[arg(long = "grant")]
    grants: Vec<String>,
}

#[derive(Args, Debug)]
struct BucketRmArgs {
    #[command(flatten)]
    conn: OpenBaoConnArgs,

    #[arg(long)]
    bucket_id: String,
}

#[derive(Args, Debug)]
struct BucketAclSetArgs {
    #[command(flatten)]
    conn: OpenBaoConnArgs,

    #[arg(long)]
    bucket_id: String,

    /// Repeatable: "ak:<ACCESS_KEY>:read_only|read_write" or "group:<NAME>:read_only|read_write"
    #[arg(long = "grant")]
    grants: Vec<String>,
}

/* ------------------- import/export ------------------- */

#[derive(Args, Debug)]
struct ImportYamlArgs {
    #[command(flatten)]
    conn: OpenBaoConnArgs,

    #[arg(long)]
    yaml: PathBuf,

    /// Replace existing s3pm data under prefix (users/buckets/index)
    #[arg(long, default_value_t = true)]
    replace: bool,
}

#[derive(Args, Debug)]
struct ExportYamlArgs {
    #[command(flatten)]
    conn: OpenBaoConnArgs,

    #[arg(long)]
    yaml: PathBuf,
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
        "ak" | "access_key" => Principal::AccessKey {
            access_key: parts[1].trim().to_string(),
        },
        "group" => Principal::GroupName {
            name: parts[1].trim().to_string(),
        },
        other => return Err(anyhow!("invalid grant principal type '{other}' in '{s}'")),
    };

    let access = parse_access_level(parts[2])?;
    Ok(AclEntry { principal, access })
}

/* ------------------- main ------------------- */

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()))
        .init();

    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Openbao(cmd) => match cmd {
            OpenBaoCmd::Setup(args) => {
                let res = OpenBaoAdmin::setup(
                    args.address.clone(),
                    args.token.clone(),
                    args.approle_mount.clone(),
                    args.kv_mount.clone(),
                    args.prefix.clone(),
                )
                .await?;

                println!("Created/updated AppRoles:");
                println!("- {} role_id={}", res.proxy.role_name, res.proxy.role_id);
                println!("- {} role_id={}", res.admin.role_name, res.admin.role_id);

                // Secret IDs should be treated as sensitive.
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

            OpenBaoCmd::User(sub) => match sub {
                UserCmd::Add(args) => {
                    let admin = openbao_admin(&args.conn).await?;
                    let user = UserDoc {
                        access_key: args.access_key,
                        secret_key: args.secret_key,
                        username: args.username,
                        uid: args.uid,
                        gid: args.gid,
                    };
                    admin.upsert_user(user).await?;
                    println!("ok");
                }
                UserCmd::Rm(args) => {
                    let admin = openbao_admin(&args.conn).await?;
                    admin.delete_user(&args.access_key, args.cleanup_acls).await?;
                    println!("ok");
                }
                UserCmd::Ls(conn) => {
                    let admin = openbao_admin(&conn).await?;
                    let users = admin.list_users().await?;
                    for u in users {
                        println!(
                            "{}\t{}\tuid={}\tgid={}",
                            u.access_key, u.username, u.uid, u.gid
                        );
                    }
                }
            },

            OpenBaoCmd::Bucket(sub) => match sub {
                BucketCmd::Add(args) => {
                    let admin = openbao_admin(&args.conn).await?;
                    let mut acl = Vec::new();
                    for g in args.grants {
                        acl.push(parse_grant(&g)?);
                    }
                    if acl.is_empty() {
                        return Err(anyhow!("bucket must have at least one --grant"));
                    }

                    let bucket_id = admin.create_bucket(&args.name, &args.data_path, acl).await?;
                    println!("{bucket_id}");
                }
                BucketCmd::Rm(args) => {
                    let admin = openbao_admin(&args.conn).await?;
                    admin.delete_bucket(&args.bucket_id).await?;
                    println!("ok");
                }
                BucketCmd::Ls(conn) => {
                    let admin = openbao_admin(&conn).await?;
                    let buckets = admin.list_buckets().await?;
                    for b in buckets {
                        println!("{}\t{}\t{}", b.id, b.name, b.data_path);
                    }
                }
                BucketCmd::AclSet(args) => {
                    let admin = openbao_admin(&args.conn).await?;
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
            },

            OpenBaoCmd::ImportYaml(args) => {
                let admin = openbao_admin(&args.conn).await?;
                admin
                    .import_yaml_file(args.yaml.to_str().unwrap(), args.replace)
                    .await?;
                println!("ok");
            }

            OpenBaoCmd::ExportYaml(args) => {
                let admin = openbao_admin(&args.conn).await?;
                admin.export_yaml_file(args.yaml.to_str().unwrap()).await?;
                println!("ok");
            }
        },
    }

    Ok(())
}

