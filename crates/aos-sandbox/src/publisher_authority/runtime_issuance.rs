//! Historical runtime provenance for version-three capability issuance records.
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

use aos_sandbox_core::{CapabilityId, CapabilityRecord, ObjectDigest};
use serde::{Deserialize, Serialize};

use super::{
    BoundedWriter, DecodedCapabilityRecordV1, DurableCapabilityStateV1, IssuanceDecisionMetadataV1,
    PublisherAuthorityError, RECORD_VERSION_V3,
};
use crate::Journal;
use crate::runtime_authority::{
    RuntimeAuthorityBindingV1, RuntimeAuthorityStateV1, binding_in_validated_namespace,
};

#[cfg(test)]
mod tests;

/// Retains immutable runtime-observation audit facts behind a local capability.
///
/// This value is not a live proof, including when deserialization succeeds.
/// Registry replay checks its claims, timing, and protected historical binding;
/// online admission must separately acquire current runtime authority.
///
/// ```compile_fail
/// use aos_sandbox::publisher_authority::RuntimeIssuanceEvidenceV1;
/// use aos_sandbox::runtime_scope::CurrentRuntimeScope;
/// fn restore(evidence: RuntimeIssuanceEvidenceV1) -> CurrentRuntimeScope {
///     evidence.into()
/// }
/// ```
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeIssuanceEvidenceV1 {
    binding_revision: u64,
    binding_digest: ObjectDigest,
    publication_digest: ObjectDigest,
    assignment_digest: ObjectDigest,
    lease_generation: u64,
    lease_digest: ObjectDigest,
    payload_scope_handle: [u8; 32],
    boot_id: [u8; 16],
    clock_provenance: [u8; 16],
    observed_wall_seconds: i64,
    observed_boottime_nanoseconds: u64,
    expires_wall_seconds: i64,
    deadline_boottime_nanoseconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeCapabilityWireV3 {
    version: u16,
    state: u8,
    capability: CapabilityRecord,
    issuance: IssuanceDecisionMetadataV1,
    claims_digest: ObjectDigest,
    runtime: RuntimeIssuanceEvidenceV1,
}

#[derive(Serialize)]
struct RuntimeCapabilityRefV3<'a> {
    version: u16,
    state: u8,
    capability: &'a CapabilityRecord,
    issuance: &'a IssuanceDecisionMetadataV1,
    claims_digest: ObjectDigest,
    runtime: &'a RuntimeIssuanceEvidenceV1,
}

pub(super) fn decode_record_v3(
    key: CapabilityId,
    bytes: &[u8],
    maximum: usize,
) -> Result<DecodedCapabilityRecordV1, PublisherAuthorityError> {
    let decoded: RuntimeCapabilityWireV3 =
        serde_json::from_slice(bytes).map_err(|_| PublisherAuthorityError::MalformedRecord)?;
    let state = match decoded.state {
        0 => DurableCapabilityStateV1::Active,
        1 => DurableCapabilityStateV1::Revoked,
        _ => return Err(PublisherAuthorityError::MalformedRecord),
    };
    if decoded.version != RECORD_VERSION_V3 {
        return Err(PublisherAuthorityError::UnsupportedVersion(decoded.version));
    }
    if decoded.capability.id() != key {
        return Err(PublisherAuthorityError::CapabilityKeyMismatch);
    }
    if decoded.issuance.validate_for(&decoded.capability)? != decoded.claims_digest {
        return Err(PublisherAuthorityError::IssuanceCrosslinkMismatch);
    }
    decoded.runtime.validate_for(&decoded.issuance)?;
    let issuance = (decoded.issuance, decoded.claims_digest);
    if encode_record_v3(
        state,
        &decoded.capability,
        &issuance,
        &decoded.runtime,
        maximum,
    )? != bytes
    {
        return Err(PublisherAuthorityError::MalformedRecord);
    }
    Ok(DecodedCapabilityRecordV1 {
        state,
        capability: decoded.capability,
        issuance: Some(issuance),
        runtime: Some(decoded.runtime),
    })
}

pub(super) fn encode_record_v3(
    state: DurableCapabilityStateV1,
    capability: &CapabilityRecord,
    issuance: &(IssuanceDecisionMetadataV1, ObjectDigest),
    runtime: &RuntimeIssuanceEvidenceV1,
    maximum: usize,
) -> Result<Vec<u8>, PublisherAuthorityError> {
    let record = RuntimeCapabilityRefV3 {
        version: RECORD_VERSION_V3,
        state: state.wire_value(),
        capability,
        issuance: &issuance.0,
        claims_digest: issuance.1,
        runtime,
    };
    let mut writer = BoundedWriter::new(maximum);
    if serde_json::to_writer(&mut writer, &record).is_err() {
        return if writer.exceeded {
            Err(PublisherAuthorityError::LimitExceeded("record bytes"))
        } else {
            Err(PublisherAuthorityError::MalformedRecord)
        };
    }
    Ok(writer.bytes)
}

impl RuntimeIssuanceEvidenceV1 {
    #[cfg(target_os = "linux")]
    pub(crate) fn from_scope(scope: &crate::runtime_scope::CurrentRuntimeScope) -> Self {
        let binding = scope.binding();
        let clock = scope.observation_clock();
        Self {
            binding_revision: binding.revision(),
            binding_digest: binding.digest(),
            publication_digest: binding.publication_digest(),
            assignment_digest: binding.assignment_digest(),
            lease_generation: binding.lease_generation(),
            lease_digest: binding.lease_digest(),
            payload_scope_handle: *scope.observed().payload_scope_handle(),
            boot_id: clock.host_boot_id(),
            clock_provenance: clock.provenance().as_bytes(),
            observed_wall_seconds: clock.wall_seconds(),
            observed_boottime_nanoseconds: clock.boottime_nanoseconds(),
            expires_wall_seconds: scope.expires_wall_seconds(),
            deadline_boottime_nanoseconds: scope.deadline_boottime_nanoseconds(),
        }
    }

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

    pub(super) fn validate_for(
        &self,
        metadata: &IssuanceDecisionMetadataV1,
    ) -> Result<(), PublisherAuthorityError> {
        let duration = self
            .expires_wall_seconds
            .checked_sub(self.observed_wall_seconds)
            .and_then(|seconds| u64::try_from(seconds).ok())
            .filter(|seconds| (1..=30).contains(seconds))
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .ok_or(PublisherAuthorityError::InvalidIssuanceMetadata)?;
        if self.binding_revision == 0
            || self.lease_generation == 0
            || self.payload_scope_handle == [0; 32]
            || [
                self.binding_digest,
                self.publication_digest,
                self.assignment_digest,
                self.lease_digest,
            ]
            .iter()
            .any(|digest| digest.as_bytes() == &[0; 32])
            || self.boot_id == [0; 16]
            || self.clock_provenance == [0; 16]
            || self.boot_id != metadata.boot_id()
            || self.clock_provenance != metadata.clock_provenance()
            || self.observed_boottime_nanoseconds.checked_add(duration)
                != Some(self.deadline_boottime_nanoseconds)
            || metadata.observed_wall_seconds() < self.observed_wall_seconds
            || metadata.observed_wall_seconds() >= self.expires_wall_seconds
            || metadata.observed_boottime_nanoseconds() < self.observed_boottime_nanoseconds
            || metadata.observed_boottime_nanoseconds() >= self.deadline_boottime_nanoseconds
        {
            return Err(PublisherAuthorityError::IssuanceCrosslinkMismatch);
        }
        let wall_elapsed = metadata
            .observed_wall_seconds()
            .checked_sub(self.observed_wall_seconds)
            .and_then(|seconds| u64::try_from(seconds).ok())
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .ok_or(PublisherAuthorityError::IssuanceCrosslinkMismatch)?;
        let boot_elapsed =
            metadata.observed_boottime_nanoseconds() - self.observed_boottime_nanoseconds;
        if wall_elapsed.abs_diff(boot_elapsed)
            > aos_sandbox_core::ownership_lease::CLOCK_PAIR_TOLERANCE_NANOSECONDS
        {
            return Err(PublisherAuthorityError::IssuanceCrosslinkMismatch);
        }
        Ok(())
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
