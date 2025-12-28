use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserDoc {
    pub access_key: String,
    pub secret_key: String,
    pub username: String,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BucketDoc {
    pub id: String,
    pub name: String,
    pub data_path: String,
    #[serde(default)]
    pub acl: Vec<AclEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AclEntry {
    pub principal: Principal,
    pub access: AccessLevel,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Principal {
    AccessKey { access_key: String },
    GroupName { name: String },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AccessLevel {
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Debug)]
pub struct BucketView {
    pub bucket_id: String,
    pub bucket_name: String,
    pub data_path: String,
    pub access: AccessLevel,
}

