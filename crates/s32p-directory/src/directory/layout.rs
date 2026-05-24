use std::{collections::HashMap, sync::LazyLock};

use anyhow::{Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::directory::types::{AccessLevel, AclEntry, Principal};

/// Allowed access-key principal: 1–128 chars of `[A-Za-z0-9_-]`. Excludes
/// empty/whitespace/`/`/`.`/`*` so the value is safe as an OpenBao KV path
/// segment (`users/<access_key>`, `index/access_key/<access_key>`) and can
/// never be a path-traversal token or a "matches nothing" stray.
static ACCESS_KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]{1,128}$").expect("valid access_key regex"));

/// Allowed group-name principal: must start with `[A-Za-z0-9_]`, then up to 63
/// more of `[A-Za-z0-9_.-]`. Permits typical POSIX group names (e.g.
/// `s3-team`, `domain.users`) while excluding empty, leading separators, `/`,
/// whitespace, and `*`. Leading-char rule means the value can never be `.` or
/// `..`, keeping `index/group/<name>` traversal-safe.
static GROUP_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$").expect("valid group regex"));

/// S3 general-purpose bucket-name rule: 3–63 chars of `[a-z0-9.-]`, beginning
/// and ending with a letter or digit. (`{1,61}` interior + the two anchored
/// ends = length 3–63.) Adjacent dots are rejected by a separate check in
/// [`validate_bucket_name`].
static BUCKET_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$").expect("valid bucket regex"));

/// Validate a bucket name against the S3 general-purpose naming rule, enforced
/// at *creation* (not only when the name is later interpolated into a worker's
/// staging path). Mirrors the M2 access-key/principal validators: rejecting bad
/// names where an operator creates them, rather than only catching them at the
/// filesystem-path boundary.
///
/// Enforces: length 3–63, charset `[a-z0-9.-]`, begins/ends alphanumeric, and
/// no consecutive dots. Deliberately **not** enforced (out of scope, matching
/// the gateway's pragmatic level): the IPv4-address-format prohibition and the
/// reserved prefix/suffix rules (`xn--`, `-s3alias`, …). The proxy's
/// `validate_bucket_link_name` remains as an independent path-safety backstop
/// at the symlink-construction step, since the name's source (a hand-editable
/// directory backend) is a separate trust boundary.
pub fn validate_bucket_name(name: &str) -> Result<()> {
    if !BUCKET_NAME_RE.is_match(name) {
        bail!(
            "invalid bucket name {name:?}: must be 3–63 chars of [a-z0-9.-], \
             beginning and ending with a letter or digit"
        );
    }
    if name.contains("..") {
        bail!("invalid bucket name {name:?}: must not contain consecutive dots");
    }
    Ok(())
}

/// Validate an access-key identifier against [`ACCESS_KEY_RE`]. Shared by user
/// creation (`UserDoc.access_key`) and the ACL access-key principal so the two
/// can never disagree — an access key you can create must also be one you can
/// grant. Both store the value as an OpenBao KV path segment, so the
/// character-set bound is also a path-traversal guard.
pub fn validate_access_key(access_key: &str) -> Result<()> {
    if !ACCESS_KEY_RE.is_match(access_key) {
        bail!("invalid access_key {access_key:?}: must match {}", ACCESS_KEY_RE.as_str());
    }
    Ok(())
}

/// Reject ACL principals whose identifier is empty, a wildcard, or otherwise
/// outside the allowed character set. Under the exact-equality ACL matcher an
/// empty/`*` principal can never name a real caller, so it is always an
/// operator mistake (a silently dead entry); the character-set bound also
/// keeps both principal kinds safe as OpenBao KV path segments. Called at
/// every ingestion point (YAML parse/render, `s32p-ctl` grant parsing, and
/// the OpenBao admin write path) so neither backend can persist a bad entry.
pub fn validate_principal(p: &Principal) -> Result<()> {
    match p {
        Principal::AccessKey { access_key } => validate_access_key(access_key)?,
        Principal::GroupName { name } => {
            if !GROUP_NAME_RE.is_match(name) {
                bail!(
                    "invalid ACL principal group_name {name:?}: must match {}",
                    GROUP_NAME_RE.as_str()
                );
            }
        }
    }
    Ok(())
}

/// Validate every principal in an ACL. See [`validate_principal`].
pub fn validate_acl(acl: &[AclEntry]) -> Result<()> {
    for e in acl {
        validate_principal(&e.principal)?;
    }
    Ok(())
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn ak(s: &str) -> Principal {
        Principal::AccessKey { access_key: s.to_string() }
    }
    fn grp(s: &str) -> Principal {
        Principal::GroupName { name: s.to_string() }
    }

    #[test]
    fn valid_access_keys_accepted() {
        for s in ["TESTACCESSKEY123", "AKIA1234567890", "a", "user_1-2", &"k".repeat(128)] {
            assert!(validate_principal(&ak(s)).is_ok(), "should accept access_key {s:?}");
        }
    }

    #[test]
    fn invalid_access_keys_rejected() {
        // empty, whitespace, wildcard, path separator, dot/traversal, control,
        // and over-length all rejected.
        for s in ["", " ", "ab cd", "*", "a/b", "..", "a.b", "key\n", &"k".repeat(129)] {
            assert!(validate_principal(&ak(s)).is_err(), "should reject access_key {s:?}");
        }
    }

    #[test]
    fn valid_group_names_accepted() {
        for s in ["s3-team", "domain.users", "_internal", "g1", &"g".repeat(64)] {
            assert!(validate_principal(&grp(s)).is_ok(), "should accept group_name {s:?}");
        }
    }

    #[test]
    fn invalid_group_names_rejected() {
        // empty, wildcard, leading separator (can't become `.`/`..`), path
        // separator, whitespace, and over-length all rejected.
        for s in ["", "*", ".", "..", "-bad", ".hidden", "a/b", "team x", &"g".repeat(65)] {
            assert!(validate_principal(&grp(s)).is_err(), "should reject group_name {s:?}");
        }
    }

    #[test]
    fn validate_access_key_matches_principal_rule() {
        // User-creation validation must agree with the ACL access-key
        // principal rule, so a created user can always be named by a grant.
        for s in ["TESTACCESSKEY123", "user_1-2"] {
            assert!(validate_access_key(s).is_ok());
            assert!(validate_principal(&ak(s)).is_ok());
        }
        for s in ["", "*", "a/b", "..", "bad key"] {
            assert!(validate_access_key(s).is_err());
            assert!(validate_principal(&ak(s)).is_err());
        }
    }

    #[test]
    fn valid_bucket_names_accepted() {
        for s in [
            "test",
            "scratch",
            "boto3-directory",
            "test-bucket-000",
            "test-dirbucket-000--use1-az4--x-s3", // double hyphens are fine
            "a1b",
            "my.bucket.name",
            &"b".repeat(63),
        ] {
            assert!(validate_bucket_name(s).is_ok(), "should accept bucket name {s:?}");
        }
    }

    #[test]
    fn invalid_bucket_names_rejected() {
        for s in [
            "",
            "ab",                  // too short (<3)
            &"b".repeat(64),       // too long (>63)
            "UPPER",               // uppercase
            "under_score",         // underscore not in charset
            "-leading",            // must begin alphanumeric
            "trailing-",           // must end alphanumeric
            ".dot",                // must begin alphanumeric
            "dot.",                // must end alphanumeric
            "a..b",                // consecutive dots
            "has space",           // whitespace
            "bad/slash",           // path separator
        ] {
            assert!(validate_bucket_name(s).is_err(), "should reject bucket name {s:?}");
        }
    }

    #[test]
    fn validate_acl_reports_first_bad_entry() {
        let acl = vec![
            AclEntry { principal: ak("good"), access: AccessLevel::ReadOnly },
            AclEntry { principal: ak(""), access: AccessLevel::ReadWrite },
        ];
        let err = validate_acl(&acl).unwrap_err().to_string();
        assert!(err.contains("access_key"), "error should name the field: {err}");
    }
}
