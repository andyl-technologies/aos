//! Classifies capability retention under the current closed local contract.
//!
//! Capability presence authorizes only checked new uses. The current strict
//! CapabilityRecord schema declares no administrative deletion-retention mode;
//! its lifetime, revocation generation, delegation, runtime binding and grants
//! do not retain a logical resource. Actual admitted executions, attachments and
//! physical holds remain independent dependencies. Expiry never deletes them.
//! Advanced explicit administrative-retention policies are unsupported by the
//! first-local profile; unknown record versions/fields refuse in the sole codec.

use aos_sandbox_core::CapabilityRecord;

/// Records the canonical registry's durable disposition as comparison DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityRegistryStateDataV2 {
    /// The canonical registry row permits separately checked current use.
    Active,
    /// The canonical registry row is a permanent revocation tombstone.
    Revoked,
}

/// Names the current schema's deletion-retention classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityDeleteRetentionDataV2 {
    /// No current capability field requires explicit administrative retention.
    NoAdministrativeRetention,
}

/// Classifies the complete current capability uniformly, including the caller.
///
/// This performs no revocation, expiry/current-use check or consumer release.
/// The complete record and durable state remain retained by the real census;
/// actual authorization must still reject use and new edges on tombstones.
#[must_use]
pub fn capability_delete_retention_data_v2(
    _capability: &CapabilityRecord, _state: CapabilityRegistryStateDataV2,
) -> CapabilityDeleteRetentionDataV2 {
    CapabilityDeleteRetentionDataV2::NoAdministrativeRetention
}
