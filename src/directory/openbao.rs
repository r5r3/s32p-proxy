use crate::directory::posix_groups::groups_for_user;
use crate::directory::{AccessLevel, BucketDoc, BucketView, Directory, Principal, UserDoc};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use vaultrs::auth::approle;
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use vaultrs::kv2;

#[derive(Clone)]
pub struct OpenBaoDirectory {
    address: String,

    // AppRole auth
    approle_mount: String,
    role_id: String,
    secret_id: String,

    // KV v2
    kv_mount: String,
    prefix: String,

    // cached client token
    state: Arc<Mutex<ClientState>>,
}

struct ClientState {
    client: Option<Arc<VaultClient>>,
    expires_at: Option<Instant>,
}

#[derive(Debug, Deserialize)]
struct IndexDoc {
    bucket_ids: Vec<String>,
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
            approle_mount,
            role_id,
            secret_id,
            kv_mount,
            prefix,
            state: Arc::new(Mutex::new(ClientState {
                client: None,
                expires_at: None,
            })),
        }
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
    fn p_idx_group(&self, group_name: &str) -> String {
        format!("{}/index/group/{}", self.prefix, group_name)
    }

    async fn ensure_client(&self) -> Result<Arc<VaultClient>> {
        let mut st = self.state.lock().await;
        let needs_login = match (&st.client, &st.expires_at) {
            (Some(_), Some(exp)) => Instant::now() + Duration::from_secs(30) >= *exp,
            _ => true,
        };
        if !needs_login {
            return Ok(Arc::clone(st.client.as_ref().unwrap()));
        }

        let anon = VaultClient::new(
            VaultClientSettingsBuilder::default()
                .address(self.address.clone())
                .build()
                .context("build openbao client (anon)")?,
        )
        .context("create openbao client (anon)")?;

        let auth = approle::login(&anon, &self.approle_mount, &self.role_id, &self.secret_id)
            .await
            .context("openbao approle login failed")?;

        let token = auth.client_token.clone();
        let ttl = auth.lease_duration as u64;

        let client = VaultClient::new(
            VaultClientSettingsBuilder::default()
                .address(self.address.clone())
                .token(token)
                .build()
                .context("build openbao client (token)")?,
        )
        .context("create openbao client (token)")?;

        st.expires_at = Some(Instant::now() + Duration::from_secs(ttl));
        st.client = Some(Arc::new(client));

        Ok(Arc::clone(st.client.as_ref().unwrap()))
    }

    async fn kv_read_opt<T: for<'de> Deserialize<'de> + Send>(&self, path: &str) -> Result<Option<T>> {
        let c = self.ensure_client().await?;
        match kv2::read::<T>(c.as_ref(), &self.kv_mount, path).await {
            Ok(v) => Ok(Some(v)),
            Err(_) => Ok(None), // you can tighten this later by matching "not found" vs real errors
        }
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
        self.kv_read_opt::<UserDoc>(&self.p_user(access_key)).await
    }

    async fn buckets_for_access_key(&self, access_key: &str) -> Result<Vec<BucketView>> {
        let Some(user) = self.user_by_access_key(access_key).await? else {
            return Ok(vec![]);
        };

        let groups = groups_for_user(&user.username, user.gid)?;
        let group_set: HashSet<String> = groups.into_iter().collect();

        // 1) Read index for access_key
        let mut ids: HashSet<String> = HashSet::new();
        if let Some(idx) = self.kv_read_opt::<IndexDoc>(&self.p_idx_access_key(access_key)).await? {
            ids.extend(idx.bucket_ids);
        }

        // 2) Read indices for each group name (efficient lookup)
        for g in &group_set {
            if let Some(idx) = self.kv_read_opt::<IndexDoc>(&self.p_idx_group(g)).await? {
                ids.extend(idx.bucket_ids);
            }
        }

        // 3) Fetch bucket docs and evaluate ACLs (authoritative)
        let mut out: Vec<BucketView> = Vec::new();
        let mut name_seen: HashSet<String> = HashSet::new();

        for id in ids {
            let Some(bucket) = self.kv_read_opt::<BucketDoc>(&self.p_bucket(&id)).await? else {
                // stale index => ignore (or error if you want strictness)
                continue;
            };

            let Some(access) = Self::effective_access(&bucket, access_key, &group_set) else {
                // index says visible but ACL does not match => stale provisioning => ignore or error
                continue;
            };

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

