use std::{
    fs::{self, OpenOptions, Permissions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::directory::types::{BucketDoc, UserDoc};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryFileV1 {
    pub version: u32,
    #[serde(default)]
    pub users:   Vec<UserDoc>,
    #[serde(default)]
    pub buckets: Vec<BucketDoc>,
}

impl DirectoryFileV1 {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(anyhow!(
                "unsupported directory file version {} (expected 1)",
                self.version
            ));
        }
        for u in &self.users {
            // Access key doubles as a KV path segment and must match the ACL
            // access-key principal allowlist so every user can be named by a
            // grant. Rejects empty too.
            crate::directory::layout::validate_access_key(&u.access_key)
                .with_context(|| format!("user {}", u.username))?;
        }
        for b in &self.buckets {
            crate::directory::layout::validate_bucket_name(&b.name)
                .with_context(|| format!("bucket id {}", b.id))?;
            crate::directory::layout::validate_acl(&b.acl)
                .with_context(|| format!("bucket {} ({})", b.id, b.name))?;
        }
        Ok(())
    }
}

pub fn parse_directory_yaml_str(s: &str) -> Result<DirectoryFileV1> {
    let doc: DirectoryFileV1 = serde_yaml::from_str(s).context("parse directory yaml")?;
    doc.validate()?;
    Ok(doc)
}

pub fn render_directory_yaml_string(doc: &DirectoryFileV1) -> Result<String> {
    doc.validate()?;
    serde_yaml::to_string(doc).context("render directory yaml")
}

pub fn load_directory_yaml_file(path: &str) -> Result<DirectoryFileV1> {
    let s =
        fs::read_to_string(path).with_context(|| format!("read directory yaml file: {path}"))?;
    parse_directory_yaml_str(&s)
}

/// Write the directory file at mode 0600. New files are created with the
/// strict mode from the outset (no transient world-readable window);
/// existing files have their mode tightened after write.
///
/// The proxy rejects directory files with group/other bits at startup
/// (see `s32p_support::secret_file::stat_or_reject`),
/// so any operator path that creates or updates the file must land here.
pub fn save_directory_yaml_file(path: &str, doc: &DirectoryFileV1) -> Result<()> {
    let s = render_directory_yaml_string(doc)?;
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("open directory yaml file: {path}"))?;
    f.write_all(s.as_bytes())
        .with_context(|| format!("write directory yaml file: {path}"))?;
    fs::set_permissions(path, Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 directory yaml file: {path}"))?;
    Ok(())
}
