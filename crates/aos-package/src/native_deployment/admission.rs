//! Byte-only validation of image-authenticated native artifact catalogs.
//!
//! A checked catalog proves document consistency. Its digest must separately
//! come from the caller's authenticated image metadata; it grants no authority
//! to arbitrary caller-supplied bytes.

use std::collections::BTreeMap;

use anyhow::{Result, ensure};
use aos_ability_plan::module_graph::GRAPH_LIMITS;
use aos_contract::Sha256Digest;
use serde::Deserialize;

/// Records the immutable identity of one admitted store object.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdmittedRoot {
    /// Names the canonical store root.
    pub store_path: String,
    /// Binds the object's canonical NAR bytes.
    pub nar_hash: String,
    /// Gives the exact uncompressed NAR size.
    pub nar_size: u64,
    /// Lists sorted, unique Nix store hash references.
    pub references: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema: String,
    roots: Vec<AdmittedRoot>,
}

/// Holds a bounded catalog whose records have passed structural validation.
#[derive(Debug)]
pub struct AdmissionCatalog {
    roots: BTreeMap<String, AdmittedRoot>,
}

impl AdmissionCatalog {
    /// Checks catalog bytes against an independently authenticated digest.
    ///
    /// # Errors
    /// Returns an error for a digest mismatch, malformed or oversized data,
    /// duplicate roots, invalid NAR identities, or noncanonical references.
    pub fn decode(bytes: &[u8], digest: Sha256Digest) -> Result<Self> {
        ensure!(
            Sha256Digest::of_bytes(bytes) == digest,
            "admission document digest differs"
        );
        let document: Document = GRAPH_LIMITS.decode(bytes, "image admission catalog")?;
        ensure!(
            document.schema == "aos.package.admission",
            "unsupported image admission catalog"
        );
        let mut roots = BTreeMap::new();
        for record in document.roots {
            super::check_root(&record.store_path)?;
            Sha256Digest::parse(&record.nar_hash)?;
            ensure!(record.nar_size > 0, "admitted NAR size must be positive");
            ensure!(
                record.references.windows(2).all(|pair| pair[0] < pair[1]),
                "admitted references must be sorted and unique"
            );
            for reference in &record.references {
                ensure!(
                    reference.len() == 32
                        && reference
                            .bytes()
                            .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte)),
                    "invalid admitted reference identity"
                );
            }
            ensure!(
                roots.insert(record.store_path.clone(), record).is_none(),
                "admission catalog repeats a store root"
            );
        }
        Ok(Self { roots })
    }

    /// Borrows the checked artifact records by canonical store path.
    pub fn roots(&self) -> &BTreeMap<String, AdmittedRoot> {
        &self.roots
    }

    /// Requires every supplied store root to be covered by the catalog.
    ///
    /// # Errors
    /// Returns an error for a noncanonical path or an absent root.
    pub fn require_roots<'a>(&self, roots: impl IntoIterator<Item = &'a str>) -> Result<()> {
        for root in roots {
            super::check_root(root)?;
            ensure!(
                self.roots.contains_key(root),
                "artifact lacks image admission: {root}"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn record() -> serde_json::Value {
        json!({"storePath":"/nix/store/00000000000000000000000000000000-source",
            "narHash":format!("sha256:{}", "a".repeat(64)), "narSize":1, "references":[]})
    }

    fn decode(records: Vec<serde_json::Value>) -> Result<AdmissionCatalog> {
        let bytes = serde_json::to_vec(&json!({"schema":"aos.package.admission", "roots":records}))
            .unwrap();
        AdmissionCatalog::decode(&bytes, Sha256Digest::of_bytes(&bytes))
    }

    #[test]
    fn rejects_duplicate_roots_and_noncanonical_references() {
        assert!(decode(vec![record(), record()]).is_err());
        let mut repeated = record();
        repeated["references"] = json!(["0".repeat(32), "0".repeat(32)]);
        assert!(decode(vec![repeated]).is_err());
        let mut invalid = record();
        invalid["references"] = json!(["z".repeat(31)]);
        assert!(decode(vec![invalid]).is_err());
    }

    #[test]
    fn checks_digest_and_exact_context_coverage() {
        let catalog = decode(vec![record()]).unwrap();
        catalog
            .require_roots([record()["storePath"].as_str().unwrap()])
            .unwrap();
        assert!(
            catalog
                .require_roots(["/nix/store/11111111111111111111111111111111-other"])
                .is_err()
        );
        assert!(AdmissionCatalog::decode(b"{}", Sha256Digest::of_bytes(b"different")).is_err());
    }
}
