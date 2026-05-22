use std::collections::HashSet;

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use s32p_support::utils::trim_slashes;

use crate::{
    directory::{
        AccessLevel, BucketDoc, BucketView, Directory, Principal, UserDoc,
        layout::{DirectoryLayout, IndexDoc},
        posix_groups::groups_for_user,
    },
    openbao_client::{OpenBaoClient, build_openbao_http_client},
};

#[derive(Clone)]
pub struct OpenBaoDirectory {
    kv_mount: String,
    layout:   DirectoryLayout,
    client:   OpenBaoClient,
}

impl OpenBaoDirectory {
    pub fn new(
        address: String,
        approle_mount: String,
        role_id: String,
        secret_id: String,
        kv_mount: String,
        prefix: String,
    ) -> Result<Self> {
        let http = build_openbao_http_client()?;
        Ok(Self {
            kv_mount: trim_slashes(&kv_mount),
            layout:   DirectoryLayout::new(prefix),
            client:   OpenBaoClient::new_approle(
                address,
                approle_mount,
                role_id,
                secret_id,
                http,
            ),
        })
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
        self.client
            .kv2_read_opt::<UserDoc>(&self.kv_mount, &self.layout.user(access_key))
            .await
    }

    async fn buckets_for_access_key(&self, access_key: &str) -> Result<Vec<BucketView>> {
        let Some(user) = self.user_by_access_key(access_key).await? else {
            return Ok(vec![]);
        };

        let groups = groups_for_user(&user.username, user.gid)?;
        let group_set: HashSet<String> = groups.into_iter().collect();

        // Candidate bucket ids from indices
        let mut ids: HashSet<String> = HashSet::new();

        if let Some(idx) = self
            .client
            .kv2_read_opt::<IndexDoc>(&self.kv_mount, &self.layout.idx_access_key(access_key))
            .await?
        {
            ids.extend(idx.bucket_ids);
        }

        for g in &group_set {
            if let Some(idx) = self
                .client
                .kv2_read_opt::<IndexDoc>(&self.kv_mount, &self.layout.idx_group(g))
                .await?
            {
                ids.extend(idx.bucket_ids);
            }
        }

        // Fetch bucket docs + evaluate ACL
        let mut out: Vec<BucketView> = Vec::new();
        let mut name_seen: HashSet<String> = HashSet::new();

        for id in ids {
            let Some(bucket) = self
                .client
                .kv2_read_opt::<BucketDoc>(&self.kv_mount, &self.layout.bucket(&id))
                .await?
            else {
                continue; // stale index
            };

            let Some(access) = Self::effective_access(&bucket, access_key, &group_set) else {
                continue; // stale provisioning
            };

            // avoid ambiguous routing: per access_key, bucket names must be unique
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
