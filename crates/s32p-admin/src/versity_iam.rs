use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result, anyhow};
use s32p_directory::{posix_users::username_for_uid, types::UserDoc};
use serde::Deserialize;

/// One account inside a VersityGW IAM JSON `accessAccounts` map.
///
/// Unknown fields (e.g. `projectID`) are ignored.
#[derive(Deserialize, Debug, Clone)]
pub struct VersityIamAccount {
    pub access:   String,
    pub secret:   String,
    #[serde(default)]
    pub role:     String,
    #[serde(rename = "userID")]
    pub user_id:  u32,
    #[serde(rename = "groupID")]
    pub group_id: u32,
}

/// Top-level VersityGW IAM JSON file shape:
/// `{"accessAccounts": {<key>: VersityIamAccount, ...}, ...}`.
///
/// Other top-level fields (e.g. `iamAccount`) are ignored.
#[derive(Deserialize, Debug, Default)]
pub struct VersityIamFile {
    #[serde(rename = "accessAccounts", default)]
    pub access_accounts: HashMap<String, VersityIamAccount>,
}

/// Behavior when `getpwuid_r` returns no entry for a `userID`.
#[derive(Debug, Clone, Copy)]
pub enum OnMissingUser {
    /// Hard error and stop the import.
    Error,
    /// Use the VG access key string as the `username`.
    UseAccessKey,
    /// Log a warning and skip the entry.
    Skip,
}

/// Optional include/exclude filter on access keys. Mutually exclusive.
#[derive(Debug, Default, Clone)]
pub struct ImportFilter {
    pub include: Option<HashSet<String>>,
    pub exclude: Option<HashSet<String>>,
}

#[derive(Debug, Default, Clone)]
pub struct ImportReport {
    pub imported:             Vec<String>,
    pub filtered:             Vec<String>,
    pub missing_user_skipped: Vec<String>,
}

pub fn parse_versity_iam_str(json: &str) -> Result<VersityIamFile> {
    serde_json::from_str::<VersityIamFile>(json).context("parse VersityGW IAM JSON")
}

pub fn parse_versity_iam_file(path: &str) -> Result<VersityIamFile> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("read versity iam file {path}"))?;
    parse_versity_iam_str(&text)
}

/// Convert a parsed VersityGW IAM file into `UserDoc`s ready to insert into a Directory.
///
/// - Discards the `role` field.
/// - Resolves `username` via `getpwuid_r(userID)`, falling back per `on_missing`.
/// - Filters by access key according to `filter` (include OR exclude, not both).
/// - Sorts the output by access key for deterministic insertion order.
pub fn versity_iam_to_user_docs(
    file: &VersityIamFile,
    filter: &ImportFilter,
    on_missing: OnMissingUser,
) -> Result<(Vec<UserDoc>, ImportReport)> {
    if filter.include.is_some() && filter.exclude.is_some() {
        return Err(anyhow!("--include and --exclude are mutually exclusive"));
    }

    // Resolve effective access_key per entry, warn on map-key vs inner mismatch.
    let mut entries: Vec<(String, &VersityIamAccount)> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for (outer_key, acct) in &file.access_accounts {
        let inner = acct.access.trim();
        let effective = if inner.is_empty() { outer_key.clone() } else { inner.to_string() };

        if !inner.is_empty() && inner != outer_key {
            tracing::warn!(
                outer = %outer_key,
                inner = %acct.access,
                "VG IAM map key differs from inner 'access' field; using inner"
            );
        }
        if !seen.insert(effective.clone()) {
            tracing::warn!(
                access_key = %effective,
                "duplicate access key in VG IAM file; later entry will overwrite earlier one"
            );
        }
        entries.push((effective, acct));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    // Warn about filter keys that don't appear in the input at all.
    let all_keys: HashSet<&str> = entries.iter().map(|(k, _)| k.as_str()).collect();
    if let Some(inc) = &filter.include {
        for k in inc {
            if !all_keys.contains(k.as_str()) {
                tracing::warn!(key = %k, "--include access key not found in VG IAM file");
            }
        }
    }
    if let Some(exc) = &filter.exclude {
        for k in exc {
            if !all_keys.contains(k.as_str()) {
                tracing::warn!(key = %k, "--exclude access key not found in VG IAM file");
            }
        }
    }

    let mut imported: Vec<UserDoc> = Vec::new();
    let mut report = ImportReport::default();

    for (access_key, acct) in entries {
        if let Some(inc) = &filter.include {
            if !inc.contains(&access_key) {
                report.filtered.push(access_key);
                continue;
            }
        } else if let Some(exc) = &filter.exclude {
            if exc.contains(&access_key) {
                report.filtered.push(access_key);
                continue;
            }
        }

        let secret = acct.secret.trim();
        if secret.is_empty() {
            return Err(anyhow!("VG IAM account '{access_key}' has empty secret"));
        }

        let username = match username_for_uid(acct.user_id)? {
            Some(name) => name,
            None => match on_missing {
                OnMissingUser::Error => {
                    return Err(anyhow!(
                        "no system user for uid {} (access_key {}); use --on-missing-user use-access-key|skip to override",
                        acct.user_id,
                        access_key
                    ));
                }
                OnMissingUser::UseAccessKey => access_key.clone(),
                OnMissingUser::Skip => {
                    tracing::warn!(
                        uid = acct.user_id,
                        access_key = %access_key,
                        "skipping VG IAM account: no system user for uid"
                    );
                    report.missing_user_skipped.push(access_key);
                    continue;
                }
            },
        };

        imported.push(UserDoc {
            access_key: access_key.clone(),
            secret_key: secret.to_string(),
            username,
            uid: acct.user_id,
            gid: acct.group_id,
        });
        report.imported.push(access_key);
    }

    Ok((imported, report))
}
