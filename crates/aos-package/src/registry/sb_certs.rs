//! Committed `sb-certs.toml` Secure Boot validation catalog.
//!
//! A registry commits the *active Secure Boot db-cert set* and the *SBAT
//! revocation floor* as an `sb-certs.toml` file at the repository root,
//! parallel to the signing-key roster in [`crate::registry::keys`]. Where
//! `keys.toml` governs *who may sign registry releases*, `sb-certs.toml`
//! records *which db certificates a published UKI is allowed to chain to*
//! and the *minimum SBAT generation per component* that the fleet will
//! install — turning a boot-time Secure Boot rejection into a download-time
//! refusal (RFC-0006 phase 4, `registry-catalog.md`).
//!
//! The registry never produces Secure Boot signatures; this file only
//! records facts that `apm` validates a downloaded image against before it
//! creates a new generation. Because the file lives in the signed git tree,
//! it is covered by the registry's existing release signature for free.
//!
//! ```toml
//! schema = 1
//!
//! # Active db certificates. A published image's signer leaf cert SHA-256
//! # must appear here (and not under [[revoked]]) for `apm` to install it.
//! [[active]]
//! id = "db-2026"
//! cert_sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
//!
//! # Retired db certificates. Vouched for by an active id, never honoured
//! # when self-vouched (a compromised cert cannot retire its successor).
//! [[revoked]]
//! id = "db-2024"
//! reason = "planned rotation"
//!
//! # SBAT revocation floor: the minimum acceptable generation per
//! # component. An image whose `.sbat` generation for a listed component is
//! # below the floor is refused at download time.
//! [[sbat_floor]]
//! component = "aos"
//! generation = 2
//! ```
//!
//! Revocations are only effective when vouched for by a *different* active
//! id ([`effective_cert_revocations`]), mirroring [`crate::registry::keys`].

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::types::SbatEntry;

/// The `sb-certs.toml` schema version this build reads and writes.
pub const SB_CERTS_TOML_SCHEMA: u32 = 1;

/// File name of the committed Secure Boot catalog at the registry tree root.
pub const SB_CERTS_TOML_FILE: &str = "sb-certs.toml";

/// A currently active Secure Boot db certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbCert {
    /// Human-chosen stable identifier used by revocation entries.
    pub id: String,
    /// Lowercase hex SHA-256 of the db certificate (DER), as recorded on a
    /// published image's [`crate::types::SysrootImageEntry::sb_signer_cert_sha256`].
    pub cert_sha256: String,
}

/// A retired Secure Boot db certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokedSbCert {
    /// Identifier of the [`SbCert`] being revoked.
    pub id: String,
    /// Optional human-readable revocation reason.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Secure Boot validation catalog stored as the committed tree file
/// `sb-certs.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbCertsToml {
    /// Schema version; must equal [`SB_CERTS_TOML_SCHEMA`].
    #[serde(default = "default_schema")]
    pub schema: u32,
    /// Currently active db certificates (`[[active]]` in the file).
    #[serde(default)]
    pub active: Vec<SbCert>,
    /// Certificates declared revoked (`[[revoked]]` in the file).
    #[serde(default)]
    pub revoked: Vec<RevokedSbCert>,
    /// Per-component minimum acceptable SBAT generation
    /// (`[[sbat_floor]]` in the file).
    #[serde(default)]
    pub sbat_floor: Vec<SbatEntry>,
}

impl Default for SbCertsToml {
    fn default() -> Self {
        Self {
            schema: SB_CERTS_TOML_SCHEMA,
            active: Vec::new(),
            revoked: Vec::new(),
            sbat_floor: Vec::new(),
        }
    }
}

impl SbCertsToml {
    /// Return `true` if `cert_sha256` is an active, non-revoked db cert.
    ///
    /// The comparison is case-insensitive on the hex digest.
    #[must_use]
    pub fn accepts_signer(&self, cert_sha256: &str) -> bool {
        let needle = cert_sha256.to_ascii_lowercase();
        let Some(entry) = self
            .active
            .iter()
            .find(|cert| cert.cert_sha256.eq_ignore_ascii_case(&needle))
        else {
            return false;
        };
        !self.revoked.iter().any(|rev| rev.id == entry.id)
    }

    /// Return the revocation floor as a `component -> minimum generation` map.
    #[must_use]
    pub fn floor_map(&self) -> HashMap<&str, u32> {
        self.sbat_floor
            .iter()
            .map(|entry| (entry.component.as_str(), entry.generation))
            .collect()
    }

    /// Find the first SBAT entry whose generation is below the floor.
    ///
    /// Returns `Some((component, image_generation, floor_generation))` for
    /// the first violation, or `None` when every component meets or exceeds
    /// its floor. Components absent from `sbat` are not consulted; a missing
    /// component cannot satisfy a floor, so callers that require presence
    /// should check `sbat` coverage separately.
    #[must_use]
    pub fn first_below_floor(&self, sbat: &[SbatEntry]) -> Option<(String, u32, u32)> {
        let floor = self.floor_map();
        for entry in sbat {
            if let Some(&minimum) = floor.get(entry.component.as_str())
                && entry.generation < minimum
            {
                return Some((entry.component.clone(), entry.generation, minimum));
            }
        }
        None
    }
}

/// Load and validate `sb-certs.toml` from a checked-out registry tree.
///
/// Returns `Ok(None)` when the tree has no `sb-certs.toml`, so unsigned/dev
/// registries that record no Secure Boot facts keep working.
///
/// # Errors
///
/// Returns an error if the file exists but cannot be read or parsed,
/// declares an unsupported schema, or fails validation (an empty cert id,
/// a non-hex/wrong-length digest, an empty SBAT-floor component, or a
/// revocation that names no active cert).
pub fn load_sb_certs_toml(root: &Path) -> Result<Option<SbCertsToml>> {
    let path = root.join(SB_CERTS_TOML_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let content =
        fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let catalog: SbCertsToml =
        toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
    validate_catalog(&catalog)?;
    Ok(Some(catalog))
}

/// Write `sb-certs.toml` after validating every entry.
///
/// # Errors
///
/// Returns an error if the catalog fails validation or the file cannot be
/// serialized or written.
pub fn write_sb_certs_toml(root: &Path, catalog: &SbCertsToml) -> Result<()> {
    validate_catalog(catalog)?;
    let content = toml::to_string_pretty(catalog).context("serializing sb-certs.toml")?;
    let path = root.join(SB_CERTS_TOML_FILE);
    fs::write(&path, content).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Return the revoked db-cert ids that are effective when vouched by
/// `vouching_cert_id`.
///
/// A cert cannot credibly revoke itself; self-vouched revocations are
/// ignored, and a voucher that is not itself active or is itself revoked
/// vouches for nothing.
#[must_use]
pub fn effective_cert_revocations(catalog: &SbCertsToml, vouching_cert_id: &str) -> Vec<String> {
    let voucher_active = catalog.active.iter().any(|c| c.id == vouching_cert_id);
    let voucher_revoked = catalog.revoked.iter().any(|r| r.id == vouching_cert_id);
    if !voucher_active || voucher_revoked {
        return Vec::new();
    }
    catalog
        .revoked
        .iter()
        .filter(|entry| entry.id != vouching_cert_id)
        .map(|entry| entry.id.clone())
        .collect()
}

/// Validate the schema version and every active/revoked/floor entry.
fn validate_catalog(catalog: &SbCertsToml) -> Result<()> {
    if catalog.schema != SB_CERTS_TOML_SCHEMA {
        bail!(
            "unsupported sb-certs.toml schema {}: expected {}",
            catalog.schema,
            SB_CERTS_TOML_SCHEMA,
        );
    }
    for cert in &catalog.active {
        if cert.id.is_empty() {
            bail!("active db cert has an empty id");
        }
        validate_sha256_hex(&cert.cert_sha256)
            .with_context(|| format!("active db cert '{}'", cert.id))?;
    }
    for rev in &catalog.revoked {
        if rev.id.is_empty() {
            bail!("revoked db cert id is empty");
        }
        if !catalog.active.iter().any(|cert| cert.id == rev.id) {
            bail!(
                "revoked db cert '{}' names no entry under [[active]]",
                rev.id
            );
        }
    }
    for entry in &catalog.sbat_floor {
        if entry.component.is_empty() {
            bail!("sbat_floor entry has an empty component");
        }
    }
    Ok(())
}

/// Validate a lowercase 64-char hex SHA-256 digest.
fn validate_sha256_hex(digest: &str) -> Result<()> {
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("cert_sha256 must be a 64-character hex SHA-256 digest, got '{digest}'");
    }
    Ok(())
}

fn default_schema() -> u32 {
    SB_CERTS_TOML_SCHEMA
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const CERT_A: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    const CERT_B: &str = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752";

    fn sbat(pairs: &[(&str, u32)]) -> Vec<SbatEntry> {
        pairs
            .iter()
            .map(|(c, g)| SbatEntry {
                component: (*c).into(),
                generation: *g,
            })
            .collect()
    }

    #[test]
    fn roundtrip_preserves_all_sections() {
        let tmp = TempDir::new().unwrap();
        let catalog = SbCertsToml {
            active: vec![SbCert {
                id: "db-2026".into(),
                cert_sha256: CERT_A.into(),
            }],
            revoked: vec![RevokedSbCert {
                id: "db-2024".into(),
                reason: Some("rotation".into()),
            }],
            sbat_floor: sbat(&[("aos", 2)]),
            ..SbCertsToml::default()
        };
        // The revoked id must reference an active entry to validate.
        let catalog = SbCertsToml {
            active: vec![
                catalog.active[0].clone(),
                SbCert {
                    id: "db-2024".into(),
                    cert_sha256: CERT_B.into(),
                },
            ],
            ..catalog
        };
        write_sb_certs_toml(tmp.path(), &catalog).unwrap();
        let loaded = load_sb_certs_toml(tmp.path()).unwrap().unwrap();
        assert_eq!(loaded, catalog);
        let content = fs::read_to_string(tmp.path().join(SB_CERTS_TOML_FILE)).unwrap();
        assert!(content.contains("schema = 1"));
    }

    #[test]
    fn absent_returns_none() {
        let tmp = TempDir::new().unwrap();
        assert!(load_sb_certs_toml(tmp.path()).unwrap().is_none());
    }

    #[test]
    fn accepts_active_signer_case_insensitively() {
        let catalog = SbCertsToml {
            active: vec![SbCert {
                id: "db".into(),
                cert_sha256: CERT_A.into(),
            }],
            ..SbCertsToml::default()
        };
        assert!(catalog.accepts_signer(&CERT_A.to_ascii_uppercase()));
        assert!(!catalog.accepts_signer(CERT_B));
    }

    #[test]
    fn rejects_revoked_signer() {
        let catalog = SbCertsToml {
            active: vec![SbCert {
                id: "db".into(),
                cert_sha256: CERT_A.into(),
            }],
            revoked: vec![RevokedSbCert {
                id: "db".into(),
                reason: None,
            }],
            ..SbCertsToml::default()
        };
        assert!(!catalog.accepts_signer(CERT_A));
    }

    #[test]
    fn floor_detects_below_and_passes_at_or_above() {
        let catalog = SbCertsToml {
            sbat_floor: sbat(&[("aos", 2), ("systemd", 1)]),
            ..SbCertsToml::default()
        };
        assert_eq!(
            catalog.first_below_floor(&sbat(&[("aos", 1), ("systemd", 1)])),
            Some(("aos".into(), 1, 2))
        );
        assert!(
            catalog
                .first_below_floor(&sbat(&[("aos", 2), ("systemd", 5)]))
                .is_none()
        );
        // Unlisted component imposes no floor.
        assert!(
            catalog
                .first_below_floor(&sbat(&[("aos", 2), ("grub", 1)]))
                .is_none()
        );
    }

    #[test]
    fn rejects_bad_digest() {
        let tmp = TempDir::new().unwrap();
        fs::write(
            tmp.path().join(SB_CERTS_TOML_FILE),
            "[[active]]\nid = \"db\"\ncert_sha256 = \"nothex\"\n",
        )
        .unwrap();
        assert!(load_sb_certs_toml(tmp.path()).is_err());
    }

    #[test]
    fn rejects_dangling_revocation() {
        let tmp = TempDir::new().unwrap();
        fs::write(
            tmp.path().join(SB_CERTS_TOML_FILE),
            "[[revoked]]\nid = \"ghost\"\n",
        )
        .unwrap();
        assert!(load_sb_certs_toml(tmp.path()).is_err());
    }

    #[test]
    fn revocation_ignored_when_only_self_vouched() {
        let catalog = SbCertsToml {
            active: vec![SbCert {
                id: "db".into(),
                cert_sha256: CERT_A.into(),
            }],
            revoked: vec![RevokedSbCert {
                id: "db".into(),
                reason: None,
            }],
            ..SbCertsToml::default()
        };
        assert!(effective_cert_revocations(&catalog, "db").is_empty());
    }

    #[test]
    fn revocation_honoured_when_vouched_by_survivor() {
        let catalog = SbCertsToml {
            active: vec![
                SbCert {
                    id: "new".into(),
                    cert_sha256: CERT_A.into(),
                },
                SbCert {
                    id: "old".into(),
                    cert_sha256: CERT_B.into(),
                },
            ],
            revoked: vec![RevokedSbCert {
                id: "old".into(),
                reason: None,
            }],
            ..SbCertsToml::default()
        };
        assert_eq!(effective_cert_revocations(&catalog, "new"), vec!["old"]);
    }
}
