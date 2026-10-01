//! Exact versioned conditional deletion commitments for external object turns.
//!
//! ```json
//! {"provider_version":"immutable-version","etag":"\"strong\"","bytes":"12","content_hash":"sha256:..."}
//! ```
//!
//! A provider version identifies the reviewed incarnation. A successful HEAD
//! or an identical ETag never substitutes for it. This commitment grants no
//! provider permission; dispatch additionally requires the configured delete
//! cohort, its epoch lease, and the permanent physical object's turn.

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

/// Retains the exact reviewed incarnation and its logical inventory evidence.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalDeletePrecondition {
    /// Actual immutable provider version, never a logical guard stamp.
    pub provider_version: String,
    /// Exact strong quoted entity tag from reviewed provider inventory.
    pub etag: String,
    /// Canonical decimal reviewed length, without JSON number rounding.
    pub bytes: String,
    /// Optional unchanged inventory hash declaration.
    pub content_hash: Option<String>,
}

impl ExternalDeletePrecondition {
    /// Checks the bounded exact-version commitment without granting dispatch.
    ///
    /// # Errors
    /// Returns an error for absent or malformed provider identity, entity tag,
    /// noncanonical length, excessive size, or an invalid hash declaration.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            crate::storage_work::valid_provider_version(&self.provider_version)
                && self.provider_version != "null",
            "external deletion requires a real provider version"
        );
        ensure!(
            crate::surface_write::strong_if_match_etag(&self.etag)? == self.etag,
            "noncanonical external delete ETag"
        );
        let bytes = self.bytes.parse::<u64>()?;
        ensure!(
            bytes.to_string() == self.bytes
                && bytes <= crate::storage_work::MAX_VERIFY_SOURCE_BYTES,
            "external delete length is invalid"
        );
        ensure!(
            self.content_hash.as_ref().is_none_or(|hash| {
                !hash.is_empty() && hash.len() <= 128 && !hash.chars().any(char::is_control)
            }),
            "external delete hash is invalid"
        );
        Ok(())
    }
}
