use anyhow::Result;
use async_trait::async_trait;

pub mod file;
pub mod layout;
pub mod openbao;
pub mod posix_groups;
pub mod types;
pub mod yaml;

pub use file::{
    load_directory_yaml_file, parse_directory_yaml_str, render_directory_yaml_string,
    save_directory_yaml_file, DirectoryFileV1,
};
pub use layout::{DirectoryLayout, IndexDoc, normalize_acl, principal_key};
pub use types::{AccessLevel, AclEntry, BucketDoc, BucketView, Principal, UserDoc};

#[async_trait]
pub trait Directory: Send + Sync {
    async fn user_by_access_key(&self, access_key: &str) -> Result<Option<UserDoc>>;
    async fn buckets_for_access_key(&self, access_key: &str) -> Result<Vec<BucketView>>;
}
