use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;

use s3pm_directory::types::{BucketDoc, UserDoc};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct YamlRoot {
    pub version: u32,
    #[serde(default)]
    pub users: Vec<UserDoc>,
    #[serde(default)]
    pub buckets: Vec<BucketDoc>,
}

impl YamlRoot {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(anyhow!("unsupported directory.yaml version {} (expected 1)", self.version));
        }
        // Very light validation. The admin backend will validate deeper when writing.
        Ok(())
    }
}

pub fn parse_yaml_str(s: &str) -> Result<YamlRoot> {
    let root: YamlRoot = serde_yaml::from_str(s).context("parse directory yaml")?;
    root.validate()?;
    Ok(root)
}

pub fn render_yaml_string(root: &YamlRoot) -> Result<String> {
    root.validate()?;
    serde_yaml::to_string(root).context("render directory yaml")
}

pub fn load_yaml_file(path: &str) -> Result<YamlRoot> {
    let text = fs::read_to_string(path).with_context(|| format!("read yaml file {path}"))?;
    parse_yaml_str(&text)
}

pub fn save_yaml_file(path: &str, root: &YamlRoot) -> Result<()> {
    let text = render_yaml_string(root)?;
    fs::write(path, text).with_context(|| format!("write yaml file {path}"))
}

