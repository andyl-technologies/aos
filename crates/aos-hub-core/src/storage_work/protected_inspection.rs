//! Exact permanent source evidence for guarded storage-local inspection.
//!
//! This is a projection of an existing positive receipt, never a read permit.
//! The executor loads it under the exact physical-key gate and retains that
//! gate while consuming source bytes. Native checks its current selected scope
//! separately from the authenticated result's intrinsic consistency.
//!
//! ```text
//! source = {version: 1, scope: StorageAuthorityObjectScope,
//!           closure: {guard_stamp, receipt_digest, sha256, bytes, etag?}}
//! ```

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use crate::storage_authority::{
    control::StorageAuthorityObjectScope, external_object::copy::source::CopySourceClosure,
};

use super::{StorageObjectIdentity, StorageWorkPlan};

/// Maximum encoded single-file documentation NAR admitted by the shared parser.
pub const MAX_DOCUMENT_NAR_BYTES: usize = aos_doc_model::MAX_DOCUMENT_BYTES + 512;

/// Projects an existing closure on one exact physical key without granting access.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedInspectionSource {
    /// Explicit evidence format, independent of the storage plan version.
    pub version: u32,
    /// Actual permanent physical key and authority selected by the executor.
    pub scope: StorageAuthorityObjectScope,
    /// Prior positive receipt and incarnation, never inferred from provider HEAD.
    pub closure: CopySourceClosure,
}

impl ProtectedInspectionSource {
    /// Checks intrinsic evidence shape without establishing receipt provenance.
    ///
    /// # Errors
    /// Refuses malformed scope, changed authority, zero incarnation or invalid
    /// receipt/hash/size/tag. Empty objects retain their genuine closed digest.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1,
            "protected inspection evidence version differs"
        );
        self.scope.guard_name()?;
        self.closure.validate()?;
        self.scope.validate_stamp(&self.closure.guard_stamp)?;
        ensure!(
            self.closure.guard_stamp.incarnation.as_str() != "0",
            "protected inspection lacks a positive incarnation"
        );
        Ok(())
    }

    /// Correlates a selected physical key with exact observed size and strong tag.
    ///
    /// # Errors
    /// Refuses another full key, size or retained completion tag. The caller
    /// derives the full key from independently selected current binding pins.
    pub fn validate_for(&self, full_key: &str, total: u64, etag: &str) -> Result<()> {
        self.validate()?;
        crate::surface_write::strong_if_match_etag(etag)?;
        ensure!(
            self.scope.full_key == full_key
                && self.closure.bytes.get() as u64 == total
                && self.closure.etag.as_ref().is_none_or(|value| value == etag),
            "protected inspection source differs from its closed receipt"
        );
        Ok(())
    }

    /// Checks the relative result key and exact independently selected binding prefix.
    ///
    /// # Errors
    /// Refuses a result outside its signed path or permanent physical scope.
    pub fn validate_identity(
        &self,
        plan: &StorageWorkPlan,
        path: &str,
        binding_prefix: &str,
        source: &StorageObjectIdentity,
    ) -> Result<()> {
        ensure!(
            source.key == plan.object_key(path)?,
            "protected result key differs"
        );
        let full_key = crate::keymap::r2_key(binding_prefix, &source.key);
        self.validate_for(&full_key, source.size, &source.etag)?;
        ensure!(
            source.provider_version.is_none(),
            "guard stamp is not a provider version"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests;
