//! Committed `keys.toml` trust-roster helpers.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::security::parse_signing_key;

/// A currently active registry signing key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterKey {
    pub id: String,
    /// Key in `registry:Ed25519:<base64>` form.
    pub key: String,
}

/// A planned retired key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokedKey {
    pub id: String,
    pub key: String,
    #[serde(default)]
    pub reason: Option<String>,
}

/// Trust roster stored as the committed tree file `keys.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeysToml {
    #[serde(default, rename = "keys")]
    pub active: Vec<RosterKey>,
    #[serde(default)]
    pub revoked: Vec<RevokedKey>,
}

/// Load and validate `keys.toml` from a checked-out registry tree.
///
/// # Errors
///
/// Returns an error if the file exists but cannot be parsed or contains a key
/// outside the expected `registry:Ed25519:<base64>` form.
pub fn load_keys_toml(root: &Path) -> Result<Option<KeysToml>> {
    let path = root.join("keys.toml");
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(&path)
        .with_context(|| format!("reading {}", path.display()))?;
    let roster: KeysToml = toml::from_str(&content)
        .with_context(|| format!("parsing {}", path.display()))?;
    validate_roster(&roster)?;
    Ok(Some(roster))
}

/// Write `keys.toml` after validating every key entry.
pub fn write_keys_toml(root: &Path, roster: &KeysToml) -> Result<()> {
    validate_roster(roster)?;
    let content = toml::to_string_pretty(roster).context("serializing keys.toml")?;
    fs::write(root.join("keys.toml"), content)
        .with_context(|| format!("writing {}", root.join("keys.toml").display()))?;
    Ok(())
}

/// Return the revoked ids that are effective when vouched by `vouching_key_id`.
///
/// A key cannot credibly revoke itself; self-vouched revocations are ignored.
pub fn effective_revocations(roster: &KeysToml, vouching_key_id: &str) -> Vec<String> {
    roster
        .revoked
        .iter()
        .filter(|entry| entry.id != vouching_key_id)
        .map(|entry| entry.id.clone())
        .collect()
}

fn validate_roster(roster: &KeysToml) -> Result<()> {
    for entry in &roster.active {
        parse_signing_key(&entry.key)
            .with_context(|| format!("invalid active key '{}'", entry.id))?;
    }
    for entry in &roster.revoked {
        parse_signing_key(&entry.key)
            .with_context(|| format!("invalid revoked key '{}'", entry.id))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const KEY1: &str = "aos-core:Ed25519:YWJjZA==";
    const KEY2: &str = "aos-core:Ed25519:ZWZnaA==";

    #[test]
    fn keys_toml_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let roster = KeysToml {
            active: vec![
                RosterKey { id: "old".into(), key: KEY1.into() },
                RosterKey { id: "new".into(), key: KEY2.into() },
            ],
            revoked: vec![RevokedKey {
                id: "retired".into(),
                key: KEY1.into(),
                reason: Some("planned retirement".into()),
            }],
        };
        write_keys_toml(tmp.path(), &roster).unwrap();
        let loaded = load_keys_toml(tmp.path()).unwrap().unwrap();
        assert_eq!(loaded, roster);
    }

    #[test]
    fn keys_toml_absent_returns_none() {
        let tmp = TempDir::new().unwrap();
        assert!(load_keys_toml(tmp.path()).unwrap().is_none());
    }

    #[test]
    fn keys_toml_rejects_bad_key_format() {
        let tmp = TempDir::new().unwrap();
        fs::write(
            tmp.path().join("keys.toml"),
            r#"
[[keys]]
id = "bad"
key = "not-a-key"
"#,
        )
        .unwrap();
        assert!(load_keys_toml(tmp.path()).is_err());
    }

    #[test]
    fn revocation_honoured_when_vouched_by_survivor() {
        let roster = KeysToml {
            active: vec![],
            revoked: vec![RevokedKey {
                id: "old".into(),
                key: KEY1.into(),
                reason: None,
            }],
        };
        assert_eq!(effective_revocations(&roster, "new"), vec!["old"]);
    }

    #[test]
    fn revocation_ignored_when_only_self_vouched() {
        let roster = KeysToml {
            active: vec![],
            revoked: vec![RevokedKey {
                id: "old".into(),
                key: KEY1.into(),
                reason: None,
            }],
        };
        assert!(effective_revocations(&roster, "old").is_empty());
    }
}
