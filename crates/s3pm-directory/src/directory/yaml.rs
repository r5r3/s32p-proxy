use crate::directory::file::{parse_directory_yaml_str, DirectoryFileV1};
use crate::directory::layout::normalize_acl;
use crate::directory::posix_groups::groups_for_user;
use crate::directory::{AccessLevel, BucketDoc, BucketView, Directory, Principal, UserDoc};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::fs;

#[derive(Clone)]
pub struct YamlDirectory {
    users: HashMap<String, UserDoc>,     // access_key -> user
    buckets: HashMap<String, BucketDoc>, // bucket_id -> bucket

    index_access_key: HashMap<String, Vec<String>>, // access_key -> bucket_ids
    index_group: HashMap<String, Vec<String>>,      // group_name -> bucket_ids
}

impl YamlDirectory {
    pub fn from_path(path: &str) -> Result<Self> {
        let text = fs::read_to_string(path).with_context(|| format!("read yaml directory: {path}"))?;
        Self::from_str(&text)
    }

    pub fn from_str(yaml: &str) -> Result<Self> {
        let doc: DirectoryFileV1 = parse_directory_yaml_str(yaml)?;
        Self::from_doc(doc)
    }

    pub fn from_doc(doc: DirectoryFileV1) -> Result<Self> {
        doc.validate()?;

        let mut users = HashMap::new();
        for u in doc.users {
            if u.access_key.trim().is_empty() {
                return Err(anyhow!("user access_key must not be empty"));
            }
            if users.insert(u.access_key.clone(), u).is_some() {
                return Err(anyhow!("duplicate user access_key in yaml"));
            }
        }

        let mut buckets = HashMap::new();
        for mut b in doc.buckets {
            if b.id.trim().is_empty() {
                return Err(anyhow!("bucket id must not be empty"));
            }
            if b.name.trim().is_empty() {
                return Err(anyhow!("bucket name must not be empty (id={})", b.id));
            }
            if b.data_path.trim().is_empty() {
                return Err(anyhow!("bucket data_path must not be empty (id={})", b.id));
            }

            b.acl = normalize_acl(b.acl);

            if buckets.insert(b.id.clone(), b).is_some() {
                return Err(anyhow!("duplicate bucket id in yaml"));
            }
        }

        let mut index_access_key: HashMap<String, Vec<String>> = HashMap::new();
        let mut index_group: HashMap<String, Vec<String>> = HashMap::new();

        for (bucket_id, bucket) in &buckets {
            for entry in &bucket.acl {
                match &entry.principal {
                    Principal::AccessKey { access_key } => {
                        index_access_key
                            .entry(access_key.clone())
                            .or_default()
                            .push(bucket_id.clone());
                    }
                    Principal::GroupName { name } => {
                        index_group.entry(name.clone()).or_default().push(bucket_id.clone());
                    }
                }
            }
        }

        for v in index_access_key.values_mut() {
            v.sort();
            v.dedup();
        }
        for v in index_group.values_mut() {
            v.sort();
            v.dedup();
        }

        Ok(Self {
            users,
            buckets,
            index_access_key,
            index_group,
        })
    }

    fn effective_access(
        &self,
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
impl Directory for YamlDirectory {
    async fn user_by_access_key(&self, access_key: &str) -> Result<Option<UserDoc>> {
        Ok(self.users.get(access_key).cloned())
    }

    async fn buckets_for_access_key(&self, access_key: &str) -> Result<Vec<BucketView>> {
        let Some(user) = self.users.get(access_key) else {
            return Ok(vec![]);
        };

        let groups = groups_for_user(&user.username, user.gid)?;
        let group_set: HashSet<String> = groups.into_iter().collect();

        let mut ids: HashSet<String> = HashSet::new();
        if let Some(v) = self.index_access_key.get(access_key) {
            ids.extend(v.iter().cloned());
        }
        for g in &group_set {
            if let Some(v) = self.index_group.get(g) {
                ids.extend(v.iter().cloned());
            }
        }

        let mut out: Vec<BucketView> = Vec::new();
        let mut name_seen: HashSet<String> = HashSet::new();

        for id in ids {
            let Some(bucket) = self.buckets.get(&id) else { continue };

            let Some(access) = self.effective_access(bucket, access_key, &group_set) else {
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

