use crate::directory::layout::{DirectoryLayout, IndexDoc};
use crate::directory::posix_groups::groups_for_user;
use crate::directory::{AccessLevel, BucketDoc, BucketView, Directory, Principal, UserDoc};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct OpenBaoDirectory {
    address: String,

    // AppRole auth
    approle_mount: String,
    role_id: String,
    secret_id: String,

    // KV v2 mount name, e.g. "secret"
    kv_mount: String,

    // KV path layout (prefix/users/..., prefix/buckets/..., prefix/index/...)
    layout: DirectoryLayout,

    http: reqwest::Client,
    state: Arc<Mutex<TokenState>>,
}

struct TokenState {
    token: Option<String>,
    expires_at: Option<Instant>,
}

impl OpenBaoDirectory {
    pub fn new(
        address: String,
        approle_mount: String,
        role_id: String,
        secret_id: String,
        kv_mount: String,
        prefix: String,
    ) -> Self {
        Self {
            address,
            approle_mount: trim_slashes(&approle_mount),
            role_id,
            secret_id,
            kv_mount: trim_slashes(&kv_mount),
            layout: DirectoryLayout::new(prefix),
            http: reqwest::Client::new(),
            state: Arc::new(Mutex::new(TokenState {
                token: None,
                expires_at: None,
            })),
        }
    }

    fn base_url(&self) -> String {
        self.address.trim_end_matches('/').to_string()
    }

    fn url(&self, api_path: &str) -> String {
        format!(
            "{}/v1/{}",
            self.base_url(),
            api_path.trim_start_matches('/')
        )
    }

    async fn approle_login(&self) -> Result<(String, u64)> {
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

        let api_path = format!("auth/{}/login", self.approle_mount);

        let resp = self
            .http
            .post(self.url(&api_path))
            .json(&Req {
                role_id: &self.role_id,
                secret_id: &self.secret_id,
            })
            .send()
            .await
            .context("openbao approle login send")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("openbao approle login failed: {status} {body}"));
        }

        let r: Resp = resp.json().await.context("openbao approle login json parse")?;
        let a = r
            .auth
            .ok_or_else(|| anyhow!("openbao approle login: missing auth in response"))?;
        Ok((a.client_token, a.lease_duration))
    }

    async fn ensure_token(&self) -> Result<String> {
        let mut st = self.state.lock().await;

        let needs_login = match (&st.token, &st.expires_at) {
            (Some(_), Some(exp)) => Instant::now() + Duration::from_secs(30) >= *exp,
            _ => true,
        };

        if !needs_login {
            return Ok(st.token.clone().unwrap());
        }

        let (token, ttl) = self.approle_login().await?;
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

    async fn kv_get_opt<T: DeserializeOwned>(&self, rel_path: &str) -> Result<Option<T>> {
        // KV v2 read: GET /v1/<kv_mount>/data/<rel_path>
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

        let resp = self
            .request(Method::GET, &api_path)
            .await?
            .send()
            .await
            .context("openbao kv get send")?;

        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("openbao kv get failed: {status} {body}"));
        }

        let r: Resp<T> = resp.json().await.context("openbao kv get json parse")?;
        Ok(r.data.map(|d| d.data))
    }

    fn effective_access(
        bucket: &BucketDoc,
        access_key: &str,
        group_names: &HashSet<String>,
    ) -> Option<AccessLevel> {
        let mut best: Option<AccessLevel> = None;

        for e in &bucket.acl {
            let matches = match &e.principal {
                Principal::AccessKey { access_key: ak } => ak == access_key,
                Principal::GroupName { name } => group_names.contains(name),
            };
            if matches {
                best = Some(match best {
                    None => e.access,
                    Some(cur) => std::cmp::max(cur, e.access),
                });
            }
        }

        best
    }
}

#[async_trait]
impl Directory for OpenBaoDirectory {
    async fn user_by_access_key(&self, access_key: &str) -> Result<Option<UserDoc>> {
        self.kv_get_opt::<UserDoc>(&self.layout.user(access_key)).await
    }

    async fn buckets_for_access_key(&self, access_key: &str) -> Result<Vec<BucketView>> {
        let Some(user) = self.user_by_access_key(access_key).await? else {
            return Ok(vec![]);
        };

        let groups = groups_for_user(&user.username, user.gid)?;
        let group_set: HashSet<String> = groups.into_iter().collect();

        // 1) Read index for access_key
        let mut ids: HashSet<String> = HashSet::new();
        if let Some(idx) = self
            .kv_get_opt::<IndexDoc>(&self.layout.idx_access_key(access_key))
            .await?
        {
            ids.extend(idx.bucket_ids);
        }

        // 2) Read indices for each group name
        for g in &group_set {
            if let Some(idx) = self.kv_get_opt::<IndexDoc>(&self.layout.idx_group(g)).await? {
                ids.extend(idx.bucket_ids);
            }
        }

        // 3) Fetch bucket docs and evaluate ACLs (authoritative)
        let mut out: Vec<BucketView> = Vec::new();
        let mut name_seen: HashSet<String> = HashSet::new();

        for id in ids {
            let Some(bucket) = self.kv_get_opt::<BucketDoc>(&self.layout.bucket(&id)).await? else {
                continue; // stale index
            };

            let Some(access) = Self::effective_access(&bucket, access_key, &group_set) else {
                continue; // stale provisioning
            };

            // enforce per-access_key bucket name uniqueness
            if !name_seen.insert(bucket.name.clone()) {
                return Err(anyhow!(
                    "access_key {} sees multiple buckets with the same name '{}' (ambiguous)",
                    access_key,
                    bucket.name
                ));
            }

            out.push(BucketView {
                bucket_id: bucket.id.clone(),
                bucket_name: bucket.name.clone(),
                data_path: bucket.data_path.clone(),
                access,
            });
        }

        out.sort_by(|a, b| a.bucket_name.cmp(&b.bucket_name));
        Ok(out)
    }
}

fn trim_slashes(s: &str) -> String {
    s.trim().trim_matches('/').to_string()
}

