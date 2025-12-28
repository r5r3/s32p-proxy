use anyhow::{anyhow, Context, Result};
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use uuid::Uuid;

use s3pm_directory::types::{AccessLevel, AclEntry, BucketDoc, Principal, UserDoc};

#[derive(Clone, Debug)]
pub enum OpenBaoAuth {
    Token(String),
    AppRole {
        mount: String,
        role_id: String,
        secret_id: String,
    },
}

#[derive(Clone, Debug)]
pub struct AppRoleCredentials {
    pub role_name: String,
    pub role_id: String,
    pub secret_id: String,
}

#[derive(Clone, Debug)]
pub struct SetupResult {
    pub proxy: AppRoleCredentials,
    pub admin: AppRoleCredentials,
}

#[derive(Clone)]
pub struct OpenBaoAdmin {
    address: String,
    kv_mount: String,
    prefix: String,
    auth: OpenBaoAuth,

    http: reqwest::Client,
    token_state: Arc<Mutex<TokenState>>,
}

#[derive(Debug)]
struct TokenState {
    token: Option<String>,
    expires_at: Option<Instant>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct IndexDoc {
    #[serde(default)]
    bucket_ids: Vec<String>,
}

/* ----------------------------- helpers ----------------------------- */

fn trim_slashes(s: &str) -> String {
    s.trim().trim_matches('/').to_string()
}

fn principal_key(p: &Principal) -> String {
    match p {
        Principal::AccessKey { access_key } => format!("ak:{access_key}"),
        Principal::GroupName { name } => format!("group:{name}"),
    }
}

fn normalize_acl(mut acl: Vec<AclEntry>) -> Vec<AclEntry> {
    // Merge duplicates by taking the max access level.
    let mut map: HashMap<String, (Principal, AccessLevel)> = HashMap::new();

    for e in acl.drain(..) {
        let k = principal_key(&e.principal);
        map.entry(k)
            .and_modify(|(_, cur)| {
                *cur = std::cmp::max(*cur, e.access);
            })
            .or_insert((e.principal, e.access));
    }

    let mut out: Vec<AclEntry> = map
        .into_values()
        .map(|(principal, access)| AclEntry { principal, access })
        .collect();

    // Stable ordering helps diffs
    out.sort_by(|a, b| principal_key(&a.principal).cmp(&principal_key(&b.principal)));
    out
}

impl OpenBaoAdmin {
    pub fn new_token(
        address: impl Into<String>,
        token: impl Into<String>,
        kv_mount: impl Into<String>,
        prefix: impl Into<String>,
    ) -> Self {
        let token = token.into();
        Self {
            address: address.into(),
            kv_mount: trim_slashes(&kv_mount.into()),
            prefix: trim_slashes(&prefix.into()),
            auth: OpenBaoAuth::Token(token.clone()),
            http: reqwest::Client::new(),
            token_state: Arc::new(Mutex::new(TokenState {
                token: Some(token),
                expires_at: None,
            })),
        }
    }

    pub fn new_approle(
        address: impl Into<String>,
        approle_mount: impl Into<String>,
        role_id: impl Into<String>,
        secret_id: impl Into<String>,
        kv_mount: impl Into<String>,
        prefix: impl Into<String>,
    ) -> Self {
        Self {
            address: address.into(),
            kv_mount: trim_slashes(&kv_mount.into()),
            prefix: trim_slashes(&prefix.into()),
            auth: OpenBaoAuth::AppRole {
                mount: trim_slashes(&approle_mount.into()),
                role_id: role_id.into(),
                secret_id: secret_id.into(),
            },
            http: reqwest::Client::new(),
            token_state: Arc::new(Mutex::new(TokenState {
                token: None,
                expires_at: None,
            })),
        }
    }

    pub fn kv_mount(&self) -> &str {
        &self.kv_mount
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    fn base_url(&self) -> String {
        self.address.trim_end_matches('/').to_string()
    }

    fn url(&self, api_path: &str) -> String {
        // api_path is like "sys/auth/approle" or "secret/data/foo"
        format!("{}/v1/{}", self.base_url(), api_path.trim_start_matches('/'))
    }

    fn p_user(&self, access_key: &str) -> String {
        format!("{}/users/{}", self.prefix, access_key)
    }
    fn p_bucket(&self, bucket_id: &str) -> String {
        format!("{}/buckets/{}", self.prefix, bucket_id)
    }
    fn p_idx_access_key(&self, access_key: &str) -> String {
        format!("{}/index/access_key/{}", self.prefix, access_key)
    }
    fn p_idx_group(&self, group: &str) -> String {
        format!("{}/index/group/{}", self.prefix, group)
    }

    async fn approle_login(&self, mount: &str, role_id: &str, secret_id: &str) -> Result<(String, u64)> {
        #[derive(Debug, Serialize)]
        struct Req<'a> {
            role_id: &'a str,
            secret_id: &'a str,
        }

        #[derive(Debug, Deserialize)]
        struct Resp {
            auth: Option<Auth>,
        }

        #[derive(Debug, Deserialize)]
        struct Auth {
            client_token: String,
            lease_duration: u64,
        }

        let path = format!("auth/{}/login", trim_slashes(mount));
        let resp = self
            .http
            .post(self.url(&path))
            .json(&Req { role_id, secret_id })
            .send()
            .await
            .context("approle login http send")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("approle login failed: {status} {body}"));
        }

        let r: Resp = resp.json().await.context("approle login json parse")?;
        let a = r.auth.ok_or_else(|| anyhow!("approle login: missing auth in response"))?;
        Ok((a.client_token, a.lease_duration))
    }

    async fn ensure_token(&self) -> Result<String> {
        // Token auth: return immediately.
        if let OpenBaoAuth::Token(t) = &self.auth {
            return Ok(t.clone());
        }

        // AppRole: cache and refresh near expiry.
        let mut st = self.token_state.lock().await;
        let needs_login = match (&st.token, &st.expires_at) {
            (Some(_), Some(exp)) => Instant::now() + Duration::from_secs(30) >= *exp,
            _ => true,
        };

        if !needs_login {
            return Ok(st.token.clone().unwrap());
        }

        let (mount, role_id, secret_id) = match &self.auth {
            OpenBaoAuth::AppRole {
                mount,
                role_id,
                secret_id,
            } => (mount.clone(), role_id.clone(), secret_id.clone()),
            OpenBaoAuth::Token(_) => unreachable!(),
        };

        let (token, ttl) = self.approle_login(&mount, &role_id, &secret_id).await?;
        st.token = Some(token.clone());
        st.expires_at = Some(Instant::now() + Duration::from_secs(ttl));
        Ok(token)
    }

    async fn request(&self, method: Method, api_path: &str) -> Result<reqwest::RequestBuilder> {
        let token = self.ensure_token().await?;
        Ok(self
            .http
            .request(method, self.url(api_path))
            .header("X-Vault-Token", token))
    }

    async fn send_ok(&self, rb: reqwest::RequestBuilder) -> Result<reqwest::Response> {
        let resp = rb.send().await.context("openbao http send")?;
        let status = resp.status();
        if status.is_success() {
            Ok(resp)
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(anyhow!("openbao api error: {status} {body}"))
        }
    }

    /* ----------------------------- OpenBao setup ----------------------------- */

    /// Setup OpenBao for s3pm:
    /// - ensures AppRole auth method is enabled
    /// - creates two policies: proxy (read-only) and admin (read-write)
    /// - creates two AppRoles: s3pm-proxy and s3pm-admin
    /// - returns role_id + secret_id for both
    pub async fn setup(
        address: String,
        root_token: String,
        approle_mount: String,
        kv_mount: String,
        prefix: String,
    ) -> Result<SetupResult> {
        // Use token auth for setup.
        let client = OpenBaoAdmin::new_token(address, root_token, kv_mount, prefix);

        client.enable_auth_approle(&approle_mount).await?;

        // Policies and roles are fixed names per requirement.
        let proxy_role = "s3pm-proxy";
        let admin_role = "s3pm-admin";

        // Policy rules must reference the kv mount AND the kv v2 paths data/ + metadata/.
        let kv_mount = client.kv_mount.clone();
        let prefix = client.prefix.clone();

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

        client.set_policy(proxy_role, &proxy_policy).await?;
        client.set_policy(admin_role, &admin_policy).await?;

        // Create/update AppRoles that hand out tokens with those policies.
        client
            .set_approle_role(&approle_mount, proxy_role, &[proxy_role.to_string()])
            .await?;
        client
            .set_approle_role(&approle_mount, admin_role, &[admin_role.to_string()])
            .await?;

        // Fetch role IDs and generate secret IDs.
        let proxy_role_id = client.read_role_id(&approle_mount, proxy_role).await?;
        let proxy_secret_id = client.generate_secret_id(&approle_mount, proxy_role).await?;

        let admin_role_id = client.read_role_id(&approle_mount, admin_role).await?;
        let admin_secret_id = client.generate_secret_id(&approle_mount, admin_role).await?;

        Ok(SetupResult {
            proxy: AppRoleCredentials {
                role_name: proxy_role.to_string(),
                role_id: proxy_role_id,
                secret_id: proxy_secret_id,
            },
            admin: AppRoleCredentials {
                role_name: admin_role.to_string(),
                role_id: admin_role_id,
                secret_id: admin_secret_id,
            },
        })
    }

    async fn enable_auth_approle(&self, approle_mount: &str) -> Result<()> {
        // POST /sys/auth/:path  { "type": "approle" }
        let m = trim_slashes(approle_mount);
        let api_path = format!("sys/auth/{m}");

        // Setup uses token auth, so token is already present.
        let rb = self
            .request(Method::POST, &api_path)
            .await?
            .json(&json!({ "type": "approle" }));

        let resp = rb.send().await.context("enable approle auth send")?;
        if resp.status().is_success() {
            return Ok(());
        }

        // If already enabled, Vault/OpenBao typically returns 400 with a message like "path is already in use".
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if status == StatusCode::BAD_REQUEST && body.to_ascii_lowercase().contains("path is already in use") {
            return Ok(());
        }

        Err(anyhow!("enable approle auth failed: {status} {body}"))
    }

    async fn set_policy(&self, policy_name: &str, policy_hcl: &str) -> Result<()> {
        // PUT /sys/policies/acl/:name  { "policy": "..." }
        let name = trim_slashes(policy_name);
        let api_path = format!("sys/policies/acl/{name}");

        self.send_ok(
            self.request(Method::PUT, &api_path)
                .await?
                .json(&json!({ "policy": policy_hcl })),
        )
        .await?;
        Ok(())
    }

    async fn set_approle_role(&self, approle_mount: &str, role_name: &str, token_policies: &[String]) -> Result<()> {
        // POST /auth/:mount/role/:role_name
        // Minimal payload; you can tune TTL/period later.
        let m = trim_slashes(approle_mount);
        let r = trim_slashes(role_name);
        let api_path = format!("auth/{m}/role/{r}");

        self.send_ok(
            self.request(Method::POST, &api_path)
                .await?
                .json(&json!({
                    "token_policies": token_policies,
                    "token_no_default_policy": true
                })),
        )
        .await?;
        Ok(())
    }

    async fn read_role_id(&self, approle_mount: &str, role_name: &str) -> Result<String> {
        #[derive(Debug, Deserialize)]
        struct Resp {
            data: Option<Data>,
        }
        #[derive(Debug, Deserialize)]
        struct Data {
            role_id: String,
        }

        let m = trim_slashes(approle_mount);
        let r = trim_slashes(role_name);
        let api_path = format!("auth/{m}/role/{r}/role-id");

        let resp = self.send_ok(self.request(Method::GET, &api_path).await?).await?;
        let r: Resp = resp.json().await.context("read role-id json parse")?;
        let role_id = r
            .data
            .ok_or_else(|| anyhow!("read role-id: missing data"))?
            .role_id;
        Ok(role_id)
    }

    async fn generate_secret_id(&self, approle_mount: &str, role_name: &str) -> Result<String> {
        #[derive(Debug, Deserialize)]
        struct Resp {
            data: Option<Data>,
        }
        #[derive(Debug, Deserialize)]
        struct Data {
            secret_id: String,
        }

        let m = trim_slashes(approle_mount);
        let r = trim_slashes(role_name);
        let api_path = format!("auth/{m}/role/{r}/secret-id");

        let resp = self
            .send_ok(self.request(Method::POST, &api_path).await?.json(&json!({})))
            .await?;
        let r: Resp = resp.json().await.context("generate secret-id json parse")?;
        let secret_id = r
            .data
            .ok_or_else(|| anyhow!("generate secret-id: missing data"))?
            .secret_id;
        Ok(secret_id)
    }

    /* ----------------------------- KV v2 helpers ----------------------------- */

    async fn kv_put<T: Serialize>(&self, rel_path: &str, doc: &T) -> Result<()> {
        // POST /<mount>/data/<rel_path>  { "data": { ... } }
        let rel_path = rel_path.trim_start_matches('/');
        let api_path = format!("{}/data/{}", self.kv_mount, rel_path);

        let data = serde_json::to_value(doc).context("serialize doc to json")?;
        self.send_ok(self.request(Method::POST, &api_path).await?.json(&json!({ "data": data })))
            .await?;
        Ok(())
    }

    async fn kv_get_opt<T: DeserializeOwned>(&self, rel_path: &str) -> Result<Option<T>> {
        // GET /<mount>/data/<rel_path>
        #[derive(Debug, Deserialize)]
        struct Resp<T> {
            data: Option<Data<T>>,
        }
        #[derive(Debug, Deserialize)]
        struct Data<T> {
            data: T,
        }

        let rel_path = rel_path.trim_start_matches('/');
        let api_path = format!("{}/data/{}", self.kv_mount, rel_path);

        let rb = self.request(Method::GET, &api_path).await?;
        let resp = rb.send().await.context("kv get send")?;

        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("kv get failed: {status} {body}"));
        }

        let r: Resp<T> = resp.json().await.context("kv get json parse")?;
        Ok(r.data.map(|d| d.data))
    }

    async fn kv_delete_metadata(&self, rel_path: &str) -> Result<()> {
        // DELETE /<mount>/metadata/<rel_path>
        let rel_path = rel_path.trim_start_matches('/');
        let api_path = format!("{}/metadata/{}", self.kv_mount, rel_path);

        let rb = self.request(Method::DELETE, &api_path).await?;
        let resp = rb.send().await.context("kv delete metadata send")?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(());
        }
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("kv delete metadata failed: {status} {body}"));
        }
        Ok(())
    }

    async fn kv_list_opt(&self, rel_path: &str) -> Result<Option<Vec<String>>> {
        // LIST /<mount>/metadata/<rel_path>
        #[derive(Debug, Deserialize)]
        struct Resp {
            data: Option<Data>,
        }
        #[derive(Debug, Deserialize)]
        struct Data {
            keys: Vec<String>,
        }

        let rel_path = rel_path.trim_start_matches('/');
        let api_path = format!("{}/metadata/{}", self.kv_mount, rel_path);

        let list_method = Method::from_bytes(b"LIST").context("construct LIST method")?;
        let rb = self.request(list_method, &api_path).await?;
        let resp = rb.send().await.context("kv list send")?;

        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("kv list failed: {status} {body}"));
        }

        let r: Resp = resp.json().await.context("kv list json parse")?;
        Ok(Some(r.data.map(|d| d.keys).unwrap_or_default()))
    }

    /* ----------------------------- Index helpers ----------------------------- */

    async fn index_read(&self, rel_path: &str) -> Result<IndexDoc> {
        Ok(self.kv_get_opt::<IndexDoc>(rel_path).await?.unwrap_or_default())
    }

    async fn index_write(&self, rel_path: &str, idx: &IndexDoc) -> Result<()> {
        if idx.bucket_ids.is_empty() {
            // keep storage clean, directory handles missing index as empty
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
                    self.index_add_bucket(&self.p_idx_access_key(access_key), bucket_id)
                        .await?;
                }
                Principal::GroupName { name } => {
                    self.index_add_bucket(&self.p_idx_group(name), bucket_id).await?;
                }
            }
        }
        Ok(())
    }

    async fn remove_bucket_from_indices(&self, bucket_id: &str, acl: &[AclEntry]) -> Result<()> {
        for e in acl {
            match &e.principal {
                Principal::AccessKey { access_key } => {
                    self.index_remove_bucket(&self.p_idx_access_key(access_key), bucket_id)
                        .await?;
                }
                Principal::GroupName { name } => {
                    self.index_remove_bucket(&self.p_idx_group(name), bucket_id).await?;
                }
            }
        }
        Ok(())
    }

    /* ----------------------------- Users ----------------------------- */

    pub async fn upsert_user(&self, mut user: UserDoc) -> Result<()> {
        if user.access_key.trim().is_empty() {
            return Err(anyhow!("user.access_key must not be empty"));
        }
        if user.secret_key.trim().is_empty() {
            return Err(anyhow!("user.secret_key must not be empty"));
        }
        if user.username.trim().is_empty() {
            return Err(anyhow!("user.username must not be empty"));
        }

        user.access_key = user.access_key.trim().to_string();
        user.secret_key = user.secret_key.trim().to_string();
        user.username = user.username.trim().to_string();

        self.kv_put(&self.p_user(&user.access_key), &user).await?;
        Ok(())
    }

    pub async fn delete_user(&self, access_key: &str, cleanup_acls: bool) -> Result<()> {
        let ak = access_key.trim();
        if ak.is_empty() {
            return Err(anyhow!("access_key must not be empty"));
        }

        if cleanup_acls {
            // Use the access_key index to find buckets to scrub.
            let idx = self.index_read(&self.p_idx_access_key(ak)).await?;
            for bucket_id in idx.bucket_ids {
                if let Some(mut b) = self.kv_get_opt::<BucketDoc>(&self.p_bucket(&bucket_id)).await? {
                    let before = b.acl.len();
                    b.acl.retain(|e| match &e.principal {
                        Principal::AccessKey { access_key } => access_key != ak,
                        _ => true,
                    });
                    if b.acl.len() != before {
                        // Use upsert_bucket logic by calling set_bucket_acl
                        self.set_bucket_acl(&bucket_id, b.acl).await?;
                    }
                }
            }
        }

        // Delete user doc and index doc.
        self.kv_delete_metadata(&self.p_user(ak)).await?;
        self.kv_delete_metadata(&self.p_idx_access_key(ak)).await?;
        Ok(())
    }

    pub async fn list_users(&self) -> Result<Vec<UserDoc>> {
        let mut out = Vec::new();

        let Some(keys) = self.kv_list_opt(&format!("{}/users", self.prefix)).await? else {
            return Ok(out);
        };

        for k in keys {
            let k = k.trim_end_matches('/'); // ignore directories
            if k.is_empty() {
                continue;
            }
            if let Some(u) = self.kv_get_opt::<UserDoc>(&self.p_user(k)).await? {
                out.push(u);
            }
        }

        out.sort_by(|a, b| a.access_key.cmp(&b.access_key));
        Ok(out)
    }

    /* ----------------------------- Buckets ----------------------------- */

    pub async fn create_bucket(&self, name: &str, data_path: &str, acl: Vec<AclEntry>) -> Result<String> {
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
        bucket.acl = normalize_acl(bucket.acl);

        // If bucket exists, update indices based on delta of principals.
        let existing = self.kv_get_opt::<BucketDoc>(&self.p_bucket(&bucket.id)).await?;
        if let Some(old) = existing {
            let old_acl = normalize_acl(old.acl);
            let new_acl = bucket.acl.clone();

            let old_set: HashSet<String> = old_acl.iter().map(|e| principal_key(&e.principal)).collect();
            let new_set: HashSet<String> = new_acl.iter().map(|e| principal_key(&e.principal)).collect();

            // Removed principals => remove from indices
            for pk in old_set.difference(&new_set) {
                if let Some((kind, value)) = pk.split_once(':') {
                    match kind {
                        "ak" => self.index_remove_bucket(&self.p_idx_access_key(value), &bucket.id).await?,
                        "group" => self.index_remove_bucket(&self.p_idx_group(value), &bucket.id).await?,
                        _ => {}
                    }
                }
            }
            // Added principals => add to indices
            for pk in new_set.difference(&old_set) {
                if let Some((kind, value)) = pk.split_once(':') {
                    match kind {
                        "ak" => self.index_add_bucket(&self.p_idx_access_key(value), &bucket.id).await?,
                        "group" => self.index_add_bucket(&self.p_idx_group(value), &bucket.id).await?,
                        _ => {}
                    }
                }
            }
        } else {
            // New bucket => add to all indices
            self.add_bucket_to_indices(&bucket.id, &bucket.acl).await?;
        }

        // Write bucket doc last (authoritative ACL)
        self.kv_put(&self.p_bucket(&bucket.id), &bucket).await?;
        Ok(())
    }

    pub async fn delete_bucket(&self, bucket_id: &str) -> Result<()> {
        let bid = bucket_id.trim();
        if bid.is_empty() {
            return Err(anyhow!("bucket_id must not be empty"));
        }

        let Some(bucket) = self.kv_get_opt::<BucketDoc>(&self.p_bucket(bid)).await? else {
            // already gone
            return Ok(());
        };

        // Remove indices first.
        self.remove_bucket_from_indices(bid, &bucket.acl).await?;

        // Delete bucket doc.
        self.kv_delete_metadata(&self.p_bucket(bid)).await?;
        Ok(())
    }

    pub async fn list_buckets(&self) -> Result<Vec<BucketDoc>> {
        let mut out = Vec::new();

        let Some(keys) = self.kv_list_opt(&format!("{}/buckets", self.prefix)).await? else {
            return Ok(out);
        };

        for k in keys {
            let k = k.trim_end_matches('/');
            if k.is_empty() {
                continue;
            }
            if let Some(b) = self.kv_get_opt::<BucketDoc>(&self.p_bucket(k)).await? {
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

        let Some(mut bucket) = self.kv_get_opt::<BucketDoc>(&self.p_bucket(bid)).await? else {
            return Err(anyhow!("bucket not found: {bid}"));
        };

        bucket.acl = acl;
        self.upsert_bucket(bucket).await?;
        Ok(())
    }

    /* ----------------------------- Import / Export ----------------------------- */

    pub async fn export_yaml_string(&self) -> Result<String> {
        let users = self.list_users().await?;
        let buckets = self.list_buckets().await?;

        let root = crate::yaml::YamlRoot {
            version: 1,
            users,
            buckets,
        };

        crate::yaml::render_yaml_string(&root)
    }

    pub async fn export_yaml_file(&self, path: &str) -> Result<()> {
        let s = self.export_yaml_string().await?;
        std::fs::write(path, s).with_context(|| format!("write yaml file {path}"))?;
        Ok(())
    }

    async fn purge_tree(&self, rel_path: &str) -> Result<()> {
        // rel_path is relative to prefix, e.g. "users" or "index"
        // We walk the KV v2 "metadata" tree using LIST requests, and delete leaf metadata.
        //
        // NOTE: KV v2 LIST returns directory entries with a trailing slash.
        // We do an explicit stack-based DFS to avoid async recursion (E0733).
        let mut stack: Vec<String> = vec![rel_path.trim_matches('/').to_string()];

        while let Some(cur_rel) = stack.pop() {
            let full = if cur_rel.is_empty() {
                self.prefix.clone()
            } else {
                format!("{}/{}", self.prefix, cur_rel)
            };

            let Some(keys) = self.kv_list_opt(&full).await? else {
                continue; // subtree not present
            };

            for k in keys {
                if k.ends_with('/') {
                    // directory: push subdir
                    let subdir = k.trim_end_matches('/');
                    let next_rel = if cur_rel.is_empty() {
                        subdir.to_string()
                    } else {
                        format!("{}/{}", cur_rel, subdir)
                    };
                    stack.push(next_rel);
                } else {
                    // leaf: delete metadata entry
                    let leaf_rel = if cur_rel.is_empty() {
                        k.clone()
                    } else {
                        format!("{}/{}", cur_rel, k)
                    };
                    let leaf_full = format!("{}/{}", self.prefix, leaf_rel);
                    self.kv_delete_metadata(&leaf_full).await?;
                }
            }
        }

        Ok(())
    }

    pub async fn import_yaml_string(&self, yaml: &str, replace: bool) -> Result<()> {
        let root = crate::yaml::parse_yaml_str(yaml)?;

        if replace {
            // wipe known subtrees under prefix
            self.purge_tree("users").await?;
            self.purge_tree("buckets").await?;
            self.purge_tree("index").await?;
        }

        // Write users first.
        for u in root.users {
            self.upsert_user(u).await?;
        }

        // Write buckets and build indices.
        // Note: upsert_bucket will create/update indices.
        for mut b in root.buckets {
            b.acl = normalize_acl(b.acl);
            self.upsert_bucket(b).await?;
        }

        Ok(())
    }

    pub async fn import_yaml_file(&self, path: &str, replace: bool) -> Result<()> {
        let text = std::fs::read_to_string(path).with_context(|| format!("read yaml file {path}"))?;
        self.import_yaml_string(&text, replace).await
    }
}

