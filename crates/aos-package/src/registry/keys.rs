//! Committed `keys.toml` trust-roster helpers.
//!
//! A registry commits its signing-key roster as a `keys.toml` file at the
//! repository root, enabling *in-band key rotation*: when a sync verifies a
//! head commit signed by a currently trusted key and delivered as a
//! fast-forward, the roster in that commit becomes the new trusted set (see
//! [`pin_rotated_keys`]). The file lists active keys and planned
//! revocations:
//!
//! ```toml
//! schema = 1
//!
//! [[keys]]
//! id = "release-2026"
//! key = "aos-core:Ed25519:base64..."
//!
//! [[revoked]]
//! id = "release-2024"
//! key = "aos-core:Ed25519:base64..."
//! provenance-before-sequence = 42
//! reason = "planned retirement"
//! ```
//!
//! Revocations are only honoured when vouched for by a *different* active
//! key ([`effective_revocations`]) so a compromised key cannot revoke the
//! keys that would supersede it.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::security::{KeySource, KeyStore, TrustedKey, key_fingerprint, parse_signing_key};

// The committed-roster schema (`KeysToml`, `RosterKey`, `RevokedKey`, and the
// `KEYS_TOML_SCHEMA` version) moved to the wasm-clean `aos-registry-surface`
// crate (RFC-0004 Phase 5) so the registry hub's indexer and the Cloudflare
// Worker can deserialize a committed roster — to extend the trusted key set
// during a verified walk — without pulling `aos-package` (native-only).
// Re-exported here so `aos_package::registry::keys::{KeysToml, RosterKey,
// RevokedKey, KEYS_TOML_SCHEMA}` paths are unchanged; the native load/validate/
// pin helpers below layer on top.
pub use aos_registry_surface::manifest::{KEYS_TOML_SCHEMA, KeysToml, RevokedKey, RosterKey};

/// Load and validate `keys.toml` from a checked-out registry tree.
///
/// Returns `Ok(None)` when the tree has no `keys.toml`.
///
/// # Errors
///
/// Returns an error if the file exists but cannot be read or parsed,
/// declares an unsupported schema, or contains a key outside the expected
/// `registry:Ed25519:<base64>` form.
pub fn load_keys_toml(root: &Path) -> Result<Option<KeysToml>> {
    let path = root.join("keys.toml");
    if !path.exists() {
        return Ok(None);
    }
    let content =
        fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let roster: KeysToml =
        toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
    validate_roster(&roster)?;
    Ok(Some(roster))
}

/// Load and validate `keys.toml` from a specific commit's tree.
///
/// Reads the file with `git show <commit>:keys.toml` so the roster comes
/// from the *verified* commit, not from any working-tree extraction.
/// Returns `Ok(None)` when the commit has no `keys.toml`.
///
/// # Errors
///
/// Returns an error if the git invocation fails for any reason other than
/// the file being absent, or if the roster fails validation.
pub fn load_keys_toml_at_commit(repo_dir: &Path, commit: &str) -> Result<Option<KeysToml>> {
    let Some(bytes) = crate::registry::repo::read_blob_at_blocking(repo_dir, commit, "keys.toml")
        .with_context(|| format!("reading {commit}:keys.toml"))?
    else {
        return Ok(None);
    };
    let content = String::from_utf8_lossy(&bytes);
    let roster: KeysToml =
        toml::from_str(&content).with_context(|| format!("parsing keys.toml at {commit}"))?;
    validate_roster(&roster)?;
    Ok(Some(roster))
}

/// Write `keys.toml` after validating every key entry.
///
/// # Errors
///
/// Returns an error if the roster fails validation or the file cannot be
/// serialized or written.
pub fn write_keys_toml(root: &Path, roster: &KeysToml) -> Result<()> {
    validate_roster(roster)?;
    let content = toml::to_string_pretty(roster).context("serializing keys.toml")?;
    fs::write(root.join("keys.toml"), content)
        .with_context(|| format!("writing {}", root.join("keys.toml").display()))?;
    Ok(())
}

/// Return the active roster key with the given id, if any.
pub fn active_key_by_id<'a>(roster: &'a KeysToml, id: &str) -> Option<&'a RosterKey> {
    roster.active.iter().find(|entry| entry.id == id)
}

/// Return `true` if the roster declares `id` revoked.
pub fn is_revoked(roster: &KeysToml, id: &str) -> bool {
    roster.revoked.iter().any(|entry| entry.id == id)
}

/// Pin a verified roster's active key set into the writable trusted-key
/// store.
///
/// This is the production path of in-band key rotation: after a roster
/// change has been verified (signed by a currently trusted key, delivered
/// as a fast-forward), the writable `trusted-keys.d` file is rewritten to
/// exactly the roster's active set. Previously pinned keys absent from the
/// roster are unpinned, and revoked keys still visible in read-only anchor
/// directories are masked with `# revoked:` exclusion lines (see
/// [`KeyStore::sync_registry_keys`]).
///
/// # Errors
///
/// Returns an error when the roster fails validation, an active key does
/// not belong to `registry`, or the writable store cannot be rewritten.
pub fn pin_rotated_keys(
    store: &KeyStore,
    registry: &str,
    roster: &KeysToml,
) -> Result<crate::security::KeySyncReport> {
    validate_roster(roster)?;
    let mut active = Vec::with_capacity(roster.active.len());
    for entry in &roster.active {
        let (entry_registry, algorithm, public_key) = parse_signing_key(&entry.key)
            .with_context(|| format!("invalid active key '{}'", entry.id))?;
        if entry_registry != registry {
            bail!(
                "active key '{}' belongs to registry '{}', expected '{}'",
                entry.id,
                entry_registry,
                registry,
            );
        }
        active.push(TrustedKey {
            registry: entry_registry,
            algorithm,
            fingerprint: key_fingerprint(&public_key),
            public_key,
            source: KeySource::Tofu,
        });
    }
    store.sync_registry_keys(registry, &active)
}

/// Return the revoked ids that are effective when vouched by `vouching_key_id`.
///
/// A key cannot credibly revoke itself; self-vouched revocations are ignored.
pub fn effective_revocations(roster: &KeysToml, vouching_key_id: &str) -> Vec<String> {
    if active_key_by_id(roster, vouching_key_id).is_none() || is_revoked(roster, vouching_key_id) {
        return Vec::new();
    }

    roster
        .revoked
        .iter()
        .filter(|entry| entry.id != vouching_key_id)
        .map(|entry| entry.id.clone())
        .collect()
}

/// Validate the schema version, every active key's format, and every
/// revoked entry's id.
fn validate_roster(roster: &KeysToml) -> Result<()> {
    if roster.schema != KEYS_TOML_SCHEMA {
        bail!(
            "unsupported keys.toml schema {}: expected {}",
            roster.schema,
            KEYS_TOML_SCHEMA,
        );
    }
    for entry in &roster.active {
        parse_signing_key(&entry.key)
            .with_context(|| format!("invalid active key '{}'", entry.id))?;
    }
    for entry in &roster.revoked {
        if entry.id.is_empty() {
            bail!("revoked key id is empty");
        }
        if entry.key.is_some() != entry.provenance_before_sequence.is_some() {
            bail!(
                "revoked key '{}' must declare key and provenance-before-sequence together",
                entry.id
            );
        }
        if let Some(key) = &entry.key {
            parse_signing_key(key)
                .with_context(|| format!("invalid revoked key '{}'", entry.id))?;
        }
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
                RosterKey {
                    id: "old".into(),
                    key: KEY1.into(),
                },
                RosterKey {
                    id: "new".into(),
                    key: KEY2.into(),
                },
            ],
            revoked: vec![RevokedKey {
                id: "retired".into(),
                key: Some(KEY1.into()),
                provenance_before_sequence: Some(17),
                reason: Some("planned retirement".into()),
            }],
            ..KeysToml::default()
        };
        write_keys_toml(tmp.path(), &roster).unwrap();
        let loaded = load_keys_toml(tmp.path()).unwrap().unwrap();
        assert_eq!(loaded, roster);
        let content = fs::read_to_string(tmp.path().join("keys.toml")).unwrap();
        assert!(content.contains("schema = 1"));
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
    fn keys_toml_rejects_unsupported_schema() {
        let tmp = TempDir::new().unwrap();
        fs::write(
            tmp.path().join("keys.toml"),
            r#"
schema = 2
"#,
        )
        .unwrap();
        let err = load_keys_toml(tmp.path()).unwrap_err();
        assert!(format!("{err:#}").contains("unsupported keys.toml schema 2"));
    }

    #[test]
    fn revocation_honoured_when_vouched_by_survivor() {
        let roster = KeysToml {
            active: vec![RosterKey {
                id: "new".into(),
                key: KEY2.into(),
            }],
            revoked: vec![RevokedKey {
                id: "old".into(),
                key: None,
                provenance_before_sequence: None,
                reason: None,
            }],
            ..KeysToml::default()
        };
        assert_eq!(effective_revocations(&roster, "new"), vec!["old"]);
    }

    #[test]
    fn revocation_ignored_when_only_self_vouched() {
        let roster = KeysToml {
            active: vec![RosterKey {
                id: "old".into(),
                key: KEY1.into(),
            }],
            revoked: vec![RevokedKey {
                id: "old".into(),
                key: None,
                provenance_before_sequence: None,
                reason: None,
            }],
            ..KeysToml::default()
        };
        assert!(effective_revocations(&roster, "old").is_empty());
    }

    #[test]
    fn revocation_ignored_when_voucher_not_active() {
        let roster = KeysToml {
            active: vec![RosterKey {
                id: "new".into(),
                key: KEY2.into(),
            }],
            revoked: vec![RevokedKey {
                id: "old".into(),
                key: None,
                provenance_before_sequence: None,
                reason: None,
            }],
            ..KeysToml::default()
        };
        assert!(effective_revocations(&roster, "unknown").is_empty());
    }

    #[test]
    fn rotation_pins_new_overlapping_key() {
        let tmp = TempDir::new().unwrap();
        let store = KeyStore::new(vec![tmp.path().join("trusted")]);
        let roster = KeysToml {
            active: vec![
                RosterKey {
                    id: "old".into(),
                    key: KEY1.into(),
                },
                RosterKey {
                    id: "new".into(),
                    key: KEY2.into(),
                },
            ],
            revoked: vec![],
            ..KeysToml::default()
        };

        let report = pin_rotated_keys(&store, "aos-core", &roster).unwrap();
        assert_eq!(report.pinned, 2);
        assert_eq!(report.unpinned, 0);
        assert_eq!(report.masked, 0);
        let pinned = store.lookup_all("aos-core");
        assert_eq!(pinned.len(), 2);
        assert!(pinned.iter().any(|key| key.public_key == "YWJjZA=="));
        assert!(pinned.iter().any(|key| key.public_key == "ZWZnaA=="));
    }

    #[test]
    fn rotation_rejects_key_for_other_registry() {
        let tmp = TempDir::new().unwrap();
        let store = KeyStore::new(vec![tmp.path().join("trusted")]);
        let roster = KeysToml {
            active: vec![RosterKey {
                id: "foreign".into(),
                key: "other:Ed25519:YWJjZA==".into(),
            }],
            revoked: vec![],
            ..KeysToml::default()
        };

        assert!(pin_rotated_keys(&store, "aos-core", &roster).is_err());
    }
}
