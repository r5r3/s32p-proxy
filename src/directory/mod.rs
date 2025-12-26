use anyhow::Result;
use async_trait::async_trait;

pub mod openbao;
pub mod posix_groups;
pub mod types;
pub mod yaml;

pub use types::{
    AccessLevel, AclEntry, BucketDoc, BucketView, Principal, UserDoc,
};

#[async_trait]
pub trait Directory: Send + Sync {
    async fn user_by_access_key(&self, access_key: &str) -> Result<Option<UserDoc>>;

    /// Returns buckets visible to this access_key, with effective access resolved from ACLs.
    async fn buckets_for_access_key(&self, access_key: &str) -> Result<Vec<BucketView>>;
}

