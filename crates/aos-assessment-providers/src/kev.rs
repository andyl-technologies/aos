//! CISA KEV catalog enrichment using exact CVE identifiers and source custody.
//!
//! Catalog absence never establishes that a vulnerability is unexploited.

use anyhow::{Result, bail};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::json::parse;
use crate::osv::{array, required};

/// Identifies the admitted CISA KEV catalog normalization profile.
pub const ADAPTER_VERSION: &str = "aos-cisa-kev/v1";

/// Retains one source-attributed known-exploitation assertion.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct KnownExploit {
    /// Exact uppercase CVE identifier.
    pub cve_id: String,
    /// Source catalog version containing this assertion.
    pub catalog_version: String,
    /// Exact source addition date.
    pub date_added: String,
    /// Exact raw catalog evidence.
    pub source_digest: Sha256Digest,
}

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

/// Checks the exact CVE identifier grammar without case/name heuristics.
#[must_use]
pub fn is_cve_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("CVE-") else {
        return false;
    };
    let Some((year, sequence)) = rest.split_once('-') else {
        return false;
    };
    year.len() == 4
        && year.bytes().all(|byte| byte.is_ascii_digit())
        && (4..=20).contains(&sequence.len())
        && sequence.bytes().all(|byte| byte.is_ascii_digit())
}
