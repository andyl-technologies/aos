//! Independent source and destination pins for cross-binding copies.
//!
//! These projections commit actual installed domains and accepted read bounds.
//! Their shape grants no lease, provider capability or current SQL permission.
//! Old originals omit the complete transfer projection.
//!
//! ```text
//! transfer = {source_binding, source_incarnation, destination_incarnation,
//!             destination_physical_authority_id, maximum_source_range_bytes}
//! source_binding = {binding_id, binding_stable_id, binding_resource_version,
//!                   snapshot_revision, profile_digest, binding_read_revision, read_generation,
//!                   physical_authority_id}
//! incarnation = provider_version | guarded_closure
//! ```

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use crate::direct_upload::MAX_DIRECT_PART_BYTES;
use crate::storage_authority::{PhysicalStorageAuthorityId, lease::LeaseInteger};

use super::{CopyPlacementPin, digest_string, identifier};

/// Selects an independently qualified object incarnation protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CopyIncarnationMode {
    /// Requires a genuine non-null immutable provider version.
    ProviderVersion,
    /// Requires a positive permanent guard closure and its retained receipt.
    GuardedClosure,
}

/// Pins the actual source Read domain independently of destination publication.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CopySourceBindingPin {
    /// Actual source binding row identity.
    pub binding_id: LeaseInteger,
    /// Immutable source binding stable identity.
    pub binding_stable_id: String,
    /// Exact current source binding resource version.
    pub binding_resource_version: LeaseInteger,
    /// Nonsecret acknowledged source snapshot revision.
    pub snapshot_revision: String,
    /// Independently installed source Read domain commitment.
    pub profile_digest: String,
    /// Association revision that actually selects the admitted Read cohort.
    pub binding_read_revision: LeaseInteger,
    /// Independently selected source Read credential generation.
    pub read_generation: LeaseInteger,
    /// Source permanent physical authority, never the destination authority.
    pub physical_authority_id: PhysicalStorageAuthorityId,
}

impl CopySourceBindingPin {
    /// Checks an exact source row projection without accepting Read permission.
    ///
    /// # Errors
    /// Refuses malformed identities, revisions or another placement's binding.
    pub fn validate(&self, source: &CopyPlacementPin) -> Result<()> {
        identifier(&self.binding_stable_id)?;
        ensure!(
            self.binding_id.get() > 0
                && self.binding_id == source.binding_id
                && self.binding_resource_version.get() > 0
                && self.binding_read_revision.get() > 0
                && self.read_generation.get() > 0
                && digest_string(&self.snapshot_revision)
                && digest_string(&self.profile_digest),
            "cross-binding source Read pins differ"
        );
        Ok(())
    }
}

/// Commits separate incarnation modes and an actually accepted source range bound.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CopyTransferPins {
    /// Exact current source Read binding and installed domain.
    pub source_binding: CopySourceBindingPin,
    /// Incarnation selected from the source's accepted provider contract.
    pub source_incarnation: CopyIncarnationMode,
    /// Completion identity selected from the destination's own contract.
    pub destination_incarnation: CopyIncarnationMode,
    /// Destination permanent physical authority for guarded completion.
    pub destination_physical_authority_id: PhysicalStorageAuthorityId,
    /// Actual independently accepted maximum source conditional range length.
    pub maximum_source_range_bytes: LeaseInteger,
}

impl CopyTransferPins {
    /// Checks dual-binding selectors and their explicit source Read geometry.
    ///
    /// Destination multipart geometry is checked against this bound by the
    /// immutable original. Source multipart writer geometry is unrelated.
    ///
    /// # Errors
    /// Refuses same-binding projections or an absent/excessive range bound.
    pub fn validate(
        &self,
        source: &CopyPlacementPin,
        destination: &CopyPlacementPin,
    ) -> Result<()> {
        self.source_binding.validate(source)?;
        ensure!(
            source.binding_id != destination.binding_id
                && self.maximum_source_range_bytes.get() > 0
                && self.maximum_source_range_bytes.get() as u64 <= MAX_DIRECT_PART_BYTES,
            "cross-binding domain or source range bound differs"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests;
