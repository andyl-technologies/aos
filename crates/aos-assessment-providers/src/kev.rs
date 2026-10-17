//! CISA KEV catalog enrichment using exact CVE identifiers and source custody.
//!
//! Catalog absence never establishes that a vulnerability is unexploited.

use anyhow::{Result, bail};
use aos_contract::Sha256Digest;

use crate::json::parse;
use crate::osv::{array, required};

/// Identifies the admitted CISA KEV catalog normalization profile.
pub const ADAPTER_VERSION: &str = "aos-cisa-kev/v1";

/// Shared source-attributed exploitation assertion and exact CVE grammar.
pub use aos_assessment::advisory::{KnownExploit, is_cve_id};

/// Parses a complete catalog into a bounded sorted exploitation assertion set.
///
/// # Errors
///
/// Returns an error for invalid/duplicate CVE identities, malformed dates,
/// inconsistent record counts or excessive/ambiguous provider data.
pub fn catalog(bytes: &[u8]) -> Result<Vec<KnownExploit>> {
    let value = parse(bytes)?;
    let catalog_version = required(&value, "catalogVersion")?;
    if catalog_version.len() > 128 || catalog_version.chars().any(char::is_control) {
        bail!("invalid KEV catalog identity");
    }
    let entries = array(&value, "vulnerabilities")?;
    if entries.len() > 20_000
        || value.get("count").and_then(serde_json::Value::as_u64) != Some(entries.len() as u64)
    {
        bail!("KEV catalog count does not match retained records");
    }
    let mut records = Vec::new();
    for entry in entries {
        let cve_id = required(entry, "cveID")?;
        let date_added = required(entry, "dateAdded")?;
        if !is_cve_id(cve_id) || date_added.len() != 10 {
            bail!("invalid KEV CVE identity or addition date");
        }
        aos_assessment::time::Timestamp::parse(&format!("{date_added}T00:00:00Z"))?;
        records.push(KnownExploit {
            cve_id: cve_id.into(),
            catalog_version: catalog_version.into(),
            date_added: date_added.into(),
            source_digest: Sha256Digest::of_bytes(bytes),
        });
    }
    records.sort();
    if records
        .windows(2)
        .any(|pair| pair[0].cve_id == pair[1].cve_id)
    {
        bail!("KEV catalog contains a duplicate CVE assertion");
    }
    Ok(records)
}
