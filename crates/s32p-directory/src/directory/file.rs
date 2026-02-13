use std::fs;

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

pub fn save_directory_yaml_file(path: &str, doc: &DirectoryFileV1) -> Result<()> {
    let s = render_directory_yaml_string(doc)?;
    fs::write(path, s).with_context(|| format!("write directory yaml file: {path}"))
}
