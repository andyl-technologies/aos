//! Historical runtime provenance for capability issuance records.
//!
//! The record references the immutable holder decision and publication, not a
//! mutable current head. Kernel handles and clock fields are diagnostic audit
//! facts; decoding them cannot reconstruct a Host observation or live session.
//!
//! ```text
//! runtime = { binding_revision, binding_digest, publication_digest,
//!             assignment_digest, lease_generation, lease_digest,
//!             payload_scope_handle, boot_id, clock_provenance,
//!             observed_wall_seconds, observed_boottime_nanoseconds,
//!             expires_wall_seconds, deadline_boottime_nanoseconds }
//! ```

use aos_sandbox_core::{CapabilityRecord, ObjectDigest};
use serde::{Deserialize, Serialize};

use super::{IssuanceDecisionMetadataV1, PublisherAuthorityError};
use crate::Journal;
use crate::runtime_authority::{
    RuntimeAuthorityBindingV1, RuntimeAuthorityStateV1, binding_in_validated_namespace,
};

aos_sandbox_ledger_replay::define_provider_runtime_issuance_data_recipe_v1! {
    invalid_metadata: PublisherAuthorityError::InvalidIssuanceMetadata,
    crosslink: PublisherAuthorityError::IssuanceCrosslinkMismatch
}

#[cfg(test)]
mod tests;

impl RuntimeIssuanceEvidenceV1 {
    /// Returns the historical immutable holder-decision revision.
    #[must_use]
    pub const fn binding_revision(&self) -> u64 {
        self.binding_revision
    }

    /// Returns the exact historical holder-decision digest, not a currentness token.
    #[must_use]
    pub const fn binding_digest(&self) -> ObjectDigest {
        self.binding_digest
    }

    /// Returns the exact authority publication used for observation.
    #[must_use]
    pub const fn publication_digest(&self) -> ObjectDigest {
        self.publication_digest
    }

    /// Returns the complete canonical assignment commitment.
    #[must_use]
    pub const fn assignment_digest(&self) -> ObjectDigest {
        self.assignment_digest
    }

    /// Returns the signed lease generation used for observation.
    #[must_use]
    pub const fn lease_generation(&self) -> u64 {
        self.lease_generation
    }

    /// Returns the exact signed lease commitment.
    #[must_use]
    pub const fn lease_digest(&self) -> ObjectDigest {
        self.lease_digest
    }

    /// Returns the diagnostic Host pin handle without reconstructing kernel authority.
    #[must_use]
    pub const fn payload_scope_handle(&self) -> &[u8; 32] {
        &self.payload_scope_handle
    }

    /// Returns the boot identity shared by observation and issuance.
    #[must_use]
    pub const fn boot_id(&self) -> [u8; 16] {
        self.boot_id
    }

    /// Returns the protected clock-adapter identity shared by observation and issuance.
    #[must_use]
    pub const fn clock_provenance(&self) -> [u8; 16] {
        self.clock_provenance
    }

    /// Returns the paired wall-clock second at observation acquisition.
    #[must_use]
    pub const fn observed_wall_seconds(&self) -> i64 {
        self.observed_wall_seconds
    }

    /// Returns the paired BOOTTIME nanoseconds at observation acquisition.
    #[must_use]
    pub const fn observed_boottime_nanoseconds(&self) -> u64 {
        self.observed_boottime_nanoseconds
    }

    /// Returns the observation's exclusive wall-clock bound, not capability expiry.
    #[must_use]
    pub const fn expires_wall_seconds(&self) -> i64 {
        self.expires_wall_seconds
    }

    /// Returns the original observation deadline, not a restorable session lifetime.
    #[must_use]
    pub const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.deadline_boottime_nanoseconds
    }


    /// Checks references only after the caller validated the complete runtime namespace.
    pub(super) fn validate_provenance(
        &self,
        journal: &Journal,
        capability: &CapabilityRecord,
    ) -> Result<(), PublisherAuthorityError> {
        let claims = capability.claims();
        let sandbox = claims
            .sandbox
            .ok_or(PublisherAuthorityError::IssuanceCrosslinkMismatch)?;
        let binding = binding_in_validated_namespace(journal, sandbox, self.binding_revision)?;
        self.validate_binding(&binding, capability)
    }

    fn validate_binding(
        &self,
        binding: &RuntimeAuthorityBindingV1,
        capability: &CapabilityRecord,
    ) -> Result<(), PublisherAuthorityError> {
        self.validate_binding_data_v2(binding.data_v2(), capability)
    }

    pub(super) fn validate_binding_data_v2(
        &self,
        binding: &aos_sandbox_protocol::domain_ledger::runtime_authority_history::RuntimeAuthorityBindingV1,
        capability: &CapabilityRecord,
    ) -> Result<(), PublisherAuthorityError> {
        let claims = capability.claims();
        let manifest = binding.manifest().manifest();
        if binding.state() != RuntimeAuthorityStateV1::Bound
            || binding.holder() != Some(claims.holder)
            || binding.digest() != self.binding_digest
            || binding.publication_digest() != self.publication_digest
            || binding.assignment_digest() != self.assignment_digest
            || binding.lease_generation() != self.lease_generation
            || binding.lease_digest() != self.lease_digest
            || binding.revision() != self.binding_revision
            || claims.project != manifest.project()
            || claims.sandbox != Some(manifest.sandbox())
            || claims.incarnation != Some(manifest.incarnation())
            || claims.assignment_epoch != Some(manifest.epoch())
        {
            return Err(PublisherAuthorityError::IssuanceCrosslinkMismatch);
        }
        Ok(())
    }
}
