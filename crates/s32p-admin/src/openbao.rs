use std::collections::HashSet;

use anyhow::{Context, Result, anyhow};
pub use s32p_directory::openbao_client::OpenBaoAuth;
use s32p_directory::{
    DirectoryFileV1,
    directory::layout::{DirectoryLayout, IndexDoc, normalize_acl, principal_key},
    openbao_client::{OpenBaoClient, build_openbao_http_client},
    parse_directory_yaml_str, render_directory_yaml_string,
    types::{AclEntry, BucketDoc, Principal, UserDoc},
};
use s32p_support::utils::trim_slashes;
use serde::{Serialize, de::DeserializeOwned};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct AppRoleCredentials {
    pub role_name: String,
    pub role_id:   String,
    pub secret_id: String,
}

#[derive(Clone, Debug)]
pub struct SetupResult {
    pub proxy: AppRoleCredentials,
    pub admin: AppRoleCredentials,
}

#[derive(Clone)]
pub struct OpenBaoAdmin {
    kv_mount: String,
    layout:   DirectoryLayout,
    client:   OpenBaoClient,
}

impl OpenBaoAdmin {
    pub fn new_token(
        address: impl Into<String>,
        token: impl Into<String>,
        kv_mount: impl Into<String>,
        prefix: impl Into<String>,
    ) -> Result<Self> {
        let http = build_openbao_http_client()?;
        Ok(Self {
            kv_mount: trim_slashes(&kv_mount.into()),
            layout:   DirectoryLayout::new(prefix.into()),
            client:   OpenBaoClient::new_token(address, token, http),
        })
    }

    pub fn new_approle(
        address: impl Into<String>,
        approle_mount: impl Into<String>,
        role_id: impl Into<String>,
        secret_id: impl Into<String>,
        kv_mount: impl Into<String>,
        prefix: impl Into<String>,
    ) -> Result<Self> {
        let http = build_openbao_http_client()?;
        Ok(Self {
            kv_mount: trim_slashes(&kv_mount.into()),
            layout:   DirectoryLayout::new(prefix.into()),
            client:   OpenBaoClient::new_approle(address, approle_mount, role_id, secret_id, http),
        })
    }

    pub fn kv_mount(&self) -> &str {
        &self.kv_mount
    }

    pub fn prefix(&self) -> &str {
        self.layout.prefix()
    }

    /* ----------------------------- Setup ----------------------------- */

    pub async fn setup(
        address: String,
        root_token: String,
        approle_mount: String,
        kv_mount: String,
        prefix: String,
    ) -> Result<SetupResult> {
        let http = build_openbao_http_client()?;
        let client = OpenBaoClient::new_token(address, root_token, http);

        let kv_mount = trim_slashes(&kv_mount);
        let prefix = trim_slashes(&prefix);

        client.ensure_kv_v2_mount(&kv_mount).await?;
        client.enable_auth_approle(&approle_mount).await?;

        let proxy_role = "s32p-proxy";
        let admin_role = "s32p-admin";

        let proxy_policy = format!(
            r#"
path "{kv_mount}/data/{prefix}/*" {{
  capabilities = ["read"]
}}

path "{kv_mount}/metadata/{prefix}/*" {{
  capabilities = ["list","read"]
}}
"#
        );

        let admin_policy = format!(
            r#"
path "{kv_mount}/data/{prefix}/*" {{
  capabilities = ["create","read","update","delete","list"]
}}

path "{kv_mount}/metadata/{prefix}/*" {{
  capabilities = ["create","read","update","delete","list"]
}}
"#
        );

        client.set_acl_policy(proxy_role, &proxy_policy).await?;
        client.set_acl_policy(admin_role, &admin_policy).await?;

        client
            .set_approle_role(&approle_mount, proxy_role, &[proxy_role.to_string()])
            .await?;
        client
            .set_approle_role(&approle_mount, admin_role, &[admin_role.to_string()])
            .await?;

        let proxy_role_id = client.read_approle_role_id(&approle_mount, proxy_role).await?;
        let proxy_secret_id = client.generate_approle_secret_id(&approle_mount, proxy_role).await?;

        let admin_role_id = client.read_approle_role_id(&approle_mount, admin_role).await?;
        let admin_secret_id = client.generate_approle_secret_id(&approle_mount, admin_role).await?;

        Ok(SetupResult {
            proxy: AppRoleCredentials {
                role_name: proxy_role.to_string(),
                role_id:   proxy_role_id,
                secret_id: proxy_secret_id,
            },
            admin: AppRoleCredentials {
                role_name: admin_role.to_string(),
                role_id:   admin_role_id,
                secret_id: admin_secret_id,
            },
        })
    }

    /* ----------------------------- KV helpers ----------------------------- */

    async fn kv_put<T: Serialize>(&self, rel_path: &str, doc: &T) -> Result<()> {
        self.client.kv2_write(&self.kv_mount, rel_path, doc).await
    }

    async fn kv_get_opt<T: DeserializeOwned + Send>(&self, rel_path: &str) -> Result<Option<T>> {
        self.client.kv2_read_opt(&self.kv_mount, rel_path).await
    }

    async fn kv_delete_metadata(&self, rel_path: &str) -> Result<()> {
        self.client.kv2_delete_metadata(&self.kv_mount, rel_path).await
    }

    async fn kv_list_opt(&self, rel_path: &str) -> Result<Option<Vec<String>>> {
        self.client.kv2_list_opt(&self.kv_mount, rel_path).await
    }

    /* ----------------------------- Index helpers ----------------------------- */

    async fn index_read(&self, rel_path: &str) -> Result<IndexDoc> {
        Ok(self.kv_get_opt::<IndexDoc>(rel_path).await?.unwrap_or_default())
    }

    async fn index_write(&self, rel_path: &str, idx: &IndexDoc) -> Result<()> {
        if idx.bucket_ids.is_empty() {
            self.kv_delete_metadata(rel_path).await?;
        } else {
            self.kv_put(rel_path, idx).await?;
        }
        Ok(())
    }

    async fn index_add_bucket(&self, rel_path: &str, bucket_id: &str) -> Result<()> {
        let mut idx = self.index_read(rel_path).await?;
        if !idx.bucket_ids.iter().any(|x| x == bucket_id) {
            idx.bucket_ids.push(bucket_id.to_string());
            idx.bucket_ids.sort();
            idx.bucket_ids.dedup();
            self.index_write(rel_path, &idx).await?;
        }
        Ok(())
    }

    async fn index_remove_bucket(&self, rel_path: &str, bucket_id: &str) -> Result<()> {
        let mut idx = self.index_read(rel_path).await?;
        let before = idx.bucket_ids.len();
        idx.bucket_ids.retain(|x| x != bucket_id);
        if idx.bucket_ids.len() != before {
            self.index_write(rel_path, &idx).await?;
        }
        Ok(())
    }

    async fn add_bucket_to_indices(&self, bucket_id: &str, acl: &[AclEntry]) -> Result<()> {
        for e in acl {
            match &e.principal {
                Principal::AccessKey { access_key } => {
                    self.index_add_bucket(&self.layout.idx_access_key(access_key), bucket_id)
                        .await?;
                }
                Principal::GroupName { name } => {
                    self.index_add_bucket(&self.layout.idx_group(name), bucket_id).await?;
                }
            }
        }
        Ok(())
    }

    async fn remove_bucket_from_indices(&self, bucket_id: &str, acl: &[AclEntry]) -> Result<()> {
        for e in acl {
            match &e.principal {
                Principal::AccessKey { access_key } => {
                    self.index_remove_bucket(&self.layout.idx_access_key(access_key), bucket_id)
                        .await?;
                }
                Principal::GroupName { name } => {
                    self.index_remove_bucket(&self.layout.idx_group(name), bucket_id).await?;
                }
            }
        }
        Ok(())
    }

    /* ----------------------------- Users ----------------------------- */

    pub async fn upsert_user(&self, mut user: UserDoc) -> Result<()> {
        if user.secret_key.trim().is_empty() {
            return Err(anyhow!("user.secret_key must not be empty"));
        }
        if user.username.trim().is_empty() {
            return Err(anyhow!("user.username must not be empty"));
        }

        user.access_key = user.access_key.trim().to_string();
        user.secret_key = user.secret_key.trim().to_string();
        user.username = user.username.trim().to_string();

        // Access key is stored as a KV path segment (`users/<access_key>`) and
        // must agree with the ACL access-key principal allowlist, so a created
        // user can always be named by a grant. Rejects empty too.
        s32p_directory::validate_access_key(&user.access_key)?;

        self.kv_put(&self.layout.user(&user.access_key), &user).await?;
        Ok(())
    }

    pub async fn delete_user(&self, access_key: &str, cleanup_acls: bool) -> Result<()> {
        let ak = access_key.trim();
        if ak.is_empty() {
            return Err(anyhow!("access_key must not be empty"));
        }

        if cleanup_acls {
            let idx = self.index_read(&self.layout.idx_access_key(ak)).await?;
            for bucket_id in idx.bucket_ids {
                if let Some(mut b) =
                    self.kv_get_opt::<BucketDoc>(&self.layout.bucket(&bucket_id)).await?
                {
                    let before = b.acl.len();
                    b.acl.retain(|e| match &e.principal {
                        Principal::AccessKey { access_key } => access_key != ak,
                        _ => true,
                    });
                    if b.acl.len() != before {
                        self.set_bucket_acl(&bucket_id, b.acl).await?;
                    }
                }
            }
        }

        self.kv_delete_metadata(&self.layout.user(ak)).await?;
        self.kv_delete_metadata(&self.layout.idx_access_key(ak)).await?;
        Ok(())
    }

    pub async fn list_users(&self) -> Result<Vec<UserDoc>> {
        let mut out = Vec::new();

        let Some(keys) = self.kv_list_opt(&self.layout.users_root()).await? else {
            return Ok(out);
        };

        for k in keys {
            let k = k.trim_end_matches('/');
            if k.is_empty() {
                continue;
            }
            if let Some(u) = self.kv_get_opt::<UserDoc>(&self.layout.user(k)).await? {
                out.push(u);
            }
        }

        out.sort_by(|a, b| a.access_key.cmp(&b.access_key));
        Ok(out)
    }

    /* ----------------------------- Buckets ----------------------------- */

    pub async fn create_bucket(
        &self,
        name: &str,
        data_path: &str,
        acl: Vec<AclEntry>,
    ) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let bucket = BucketDoc {
            id: id.clone(),
            name: name.to_string(),
            data_path: data_path.to_string(),
            acl,
        };
        self.upsert_bucket(bucket).await?;
        Ok(id)
    }

    pub async fn upsert_bucket(&self, mut bucket: BucketDoc) -> Result<()> {
        if bucket.id.trim().is_empty() {
            return Err(anyhow!("bucket.id must not be empty"));
        }
        if bucket.name.trim().is_empty() {
            return Err(anyhow!("bucket.name must not be empty (id={})", bucket.id));
        }
        if bucket.data_path.trim().is_empty() {
            return Err(anyhow!("bucket.data_path must not be empty (id={})", bucket.id));
        }

        bucket.id = bucket.id.trim().to_string();
        bucket.name = bucket.name.trim().to_string();
        bucket.data_path = bucket.data_path.trim().to_string();
        s32p_directory::validate_bucket_name(&bucket.name)
            .with_context(|| format!("bucket id {}", bucket.id))?;
        s32p_directory::validate_acl(&bucket.acl)
            .with_context(|| format!("bucket {} ({})", bucket.id, bucket.name))?;
        bucket.acl = normalize_acl(bucket.acl);

        let existing = self.kv_get_opt::<BucketDoc>(&self.layout.bucket(&bucket.id)).await?;
        if let Some(old) = existing {
            let old_acl = normalize_acl(old.acl);
            let new_acl = bucket.acl.clone();

            let old_set: HashSet<String> =
                old_acl.iter().map(|e| principal_key(&e.principal)).collect();
            let new_set: HashSet<String> =
                new_acl.iter().map(|e| principal_key(&e.principal)).collect();

            for pk in old_set.difference(&new_set) {
                if let Some((kind, value)) = pk.split_once(':') {
                    match kind {
                        "ak" => {
                            self.index_remove_bucket(&self.layout.idx_access_key(value), &bucket.id)
                                .await?
                        }
                        "group" => {
                            self.index_remove_bucket(&self.layout.idx_group(value), &bucket.id)
                                .await?
                        }
                        _ => {}
                    }
                }
            }
            for pk in new_set.difference(&old_set) {
                if let Some((kind, value)) = pk.split_once(':') {
                    match kind {
                        "ak" => {
                            self.index_add_bucket(&self.layout.idx_access_key(value), &bucket.id)
                                .await?
                        }
                        "group" => {
                            self.index_add_bucket(&self.layout.idx_group(value), &bucket.id).await?
                        }
                        _ => {}
                    }
                }
            }
        } else {
            self.add_bucket_to_indices(&bucket.id, &bucket.acl).await?;
        }

        self.kv_put(&self.layout.bucket(&bucket.id), &bucket).await?;
        Ok(())
    }

    pub async fn delete_bucket(&self, bucket_id: &str) -> Result<()> {
        let bid = bucket_id.trim();
        if bid.is_empty() {
            return Err(anyhow!("bucket_id must not be empty"));
        }

        let Some(bucket) = self.kv_get_opt::<BucketDoc>(&self.layout.bucket(bid)).await? else {
            return Ok(());
        };

        self.remove_bucket_from_indices(bid, &bucket.acl).await?;
        self.kv_delete_metadata(&self.layout.bucket(bid)).await?;
        Ok(())
    }

    pub async fn list_buckets(&self) -> Result<Vec<BucketDoc>> {
        let mut out = Vec::new();

        let Some(keys) = self.kv_list_opt(&self.layout.buckets_root()).await? else {
            return Ok(out);
        };

        for k in keys {
            let k = k.trim_end_matches('/');
            if k.is_empty() {
                continue;
            }
            if let Some(b) = self.kv_get_opt::<BucketDoc>(&self.layout.bucket(k)).await? {
                out.push(b);
            }
        }

        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    pub async fn set_bucket_acl(&self, bucket_id: &str, acl: Vec<AclEntry>) -> Result<()> {
        let bid = bucket_id.trim();
        if bid.is_empty() {
            return Err(anyhow!("bucket_id must not be empty"));
        }

        let Some(mut bucket) = self.kv_get_opt::<BucketDoc>(&self.layout.bucket(bid)).await? else {
            return Err(anyhow!("bucket not found: {bid}"));
        };

        bucket.acl = acl;
        self.upsert_bucket(bucket).await?;
        Ok(())
    }

    /* ----------------------------- Import / Export (unchanged) ----------------------------- */

    pub async fn export_yaml_string(&self) -> Result<String> {
        let users = self.list_users().await?;
        let buckets = self.list_buckets().await?;

        let root = DirectoryFileV1 { version: 1, users, buckets };

        render_directory_yaml_string(&root)
    }

    pub async fn export_yaml_file(&self, path: &str) -> Result<()> {
        use std::{
            fs::{self, OpenOptions, Permissions},
            io::Write,
            os::unix::fs::{OpenOptionsExt, PermissionsExt},
        };
        let s = self.export_yaml_string().await?;
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("open yaml file {path}"))?;
        f.write_all(s.as_bytes()).with_context(|| format!("write yaml file {path}"))?;
        fs::set_permissions(path, Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 yaml file {path}"))?;
        Ok(())
    }

    async fn purge_tree(&self, rel_path: &str) -> Result<()> {
        let mut stack: Vec<String> = vec![rel_path.trim_matches('/').to_string()];

        while let Some(cur_rel) = stack.pop() {
            let full = self.layout.join(&cur_rel);

            let Some(keys) = self.kv_list_opt(&full).await? else {
                continue;
            };

            for k in keys {
                if k.ends_with('/') {
                    let subdir = k.trim_end_matches('/');
                    let next_rel = if cur_rel.is_empty() {
                        subdir.to_string()
                    } else {
                        format!("{}/{}", cur_rel, subdir)
                    };
                    stack.push(next_rel);
                } else {
                    let leaf_rel =
                        if cur_rel.is_empty() { k.clone() } else { format!("{}/{}", cur_rel, k) };
                    let leaf_full = self.layout.join(&leaf_rel);
                    self.kv_delete_metadata(&leaf_full).await?;
                }
            }
        }

        Ok(())
    }

    pub async fn import_yaml_string(&self, yaml: &str, replace: bool) -> Result<()> {
        let root = parse_directory_yaml_str(yaml)?;

        if replace {
            self.purge_tree("users").await?;
            self.purge_tree("buckets").await?;
            self.purge_tree("index").await?;
        }

        for u in root.users {
            self.upsert_user(u).await?;
        }

        for mut b in root.buckets {
            b.acl = normalize_acl(b.acl);
            self.upsert_bucket(b).await?;
        }

        Ok(())
    }

    pub async fn import_yaml_file(&self, path: &str, replace: bool) -> Result<()> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("read yaml file {path}"))?;
        self.import_yaml_string(&text, replace).await
    }

    /* ----------------------------- VersityGW IAM JSON import ----------------------------- */

    /// Import users from a VersityGW IAM JSON string. Always merges (existing
    /// users with the same access_key are overwritten). Buckets/ACLs are not
    /// touched: VG IAM has no bucket concept.
    pub async fn import_versity_iam_string(
        &self,
        json: &str,
        filter: &crate::versity_iam::ImportFilter,
        on_missing: crate::versity_iam::OnMissingUser,
    ) -> Result<crate::versity_iam::ImportReport> {
        let file = crate::versity_iam::parse_versity_iam_str(json)?;
        let (users, report) =
            crate::versity_iam::versity_iam_to_user_docs(&file, filter, on_missing)?;
        for u in users {
            self.upsert_user(u).await?;
        }
        Ok(report)
    }

    pub async fn import_versity_iam_file(
        &self,
        path: &str,
        filter: &crate::versity_iam::ImportFilter,
        on_missing: crate::versity_iam::OnMissingUser,
    ) -> Result<crate::versity_iam::ImportReport> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read versity iam file {path}"))?;
        self.import_versity_iam_string(&text, filter, on_missing).await
    }
}
