use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::directory::types::{AccessLevel, AclEntry, Principal};

#[derive(Clone, Debug)]
pub struct DirectoryLayout {
    prefix: String,
}

impl DirectoryLayout {
    pub fn new(prefix: impl Into<String>) -> Self {
        let p = prefix.into();
        let p = p.trim().trim_matches('/').to_string();
        Self { prefix: p }
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Join a path relative to the directory prefix.
    /// Examples:
    ///  prefix="s32p", rel="users/AKIA..." -> "s32p/users/AKIA..."
    pub fn join(&self, rel: &str) -> String {
        let rel = rel.trim().trim_matches('/');
        if rel.is_empty() {
            return self.prefix.clone();
        }
        if self.prefix.is_empty() { rel.to_string() } else { format!("{}/{}", self.prefix, rel) }
    }

    pub fn users_root(&self) -> String {
        self.join("users")
    }

    pub fn buckets_root(&self) -> String {
        self.join("buckets")
    }

    pub fn index_root(&self) -> String {
        self.join("index")
    }

    pub fn user(&self, access_key: &str) -> String {
        self.join(&format!("users/{}", access_key))
    }

    pub fn bucket(&self, bucket_id: &str) -> String {
        self.join(&format!("buckets/{}", bucket_id))
    }

    pub fn idx_access_key(&self, access_key: &str) -> String {
        self.join(&format!("index/access_key/{}", access_key))
    }

    pub fn idx_group(&self, group_name: &str) -> String {
        self.join(&format!("index/group/{}", group_name))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IndexDoc {
    #[serde(default)]
    pub bucket_ids: Vec<String>,
}

/// Stable string key for principals, useful for sorting/merging.
pub fn principal_key(p: &Principal) -> String {
    match p {
        Principal::AccessKey { access_key } => format!("ak:{access_key}"),
        Principal::GroupName { name } => format!("group:{name}"),
    }
}

/// Merge duplicate principals by taking the maximum access level.
/// Also sorts entries for stable storage/diffs.
pub fn normalize_acl(acl: Vec<AclEntry>) -> Vec<AclEntry> {
    let mut map: HashMap<String, (Principal, AccessLevel)> = HashMap::new();

    for e in acl {
        let key = principal_key(&e.principal);
        map.entry(key)
            .and_modify(|(_, cur)| *cur = std::cmp::max(*cur, e.access))
            .or_insert((e.principal, e.access));
    }

    let mut out: Vec<AclEntry> = map
        .into_values()
        .map(|(principal, access)| AclEntry { principal, access })
        .collect();

    out.sort_by(|a, b| principal_key(&a.principal).cmp(&principal_key(&b.principal)));
    out
}
