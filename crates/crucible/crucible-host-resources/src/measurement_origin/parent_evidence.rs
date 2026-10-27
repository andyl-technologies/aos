//! Binds the same guest invocation to its externally retained parent admission.
//!
//! The parent pays the complete sixteen-GiB actor domain before fresh execution
//! and retains that payment until physical VM retirement. Metadata and staging
//! are subdivisions of that domain. This evidence transports identity and the
//! admitted contract, never Rust loans or the parent's clock coordinates.

mod record;

use super::{MeasurementInvocationOrigin, MeasurementOriginError, StaticMode};

/// Consumes one guest origin together with its closed parent admission evidence.
pub struct AuthenticatedParentInvocation {
    origin: MeasurementInvocationOrigin,
    evidence: CertifiedNativeRoleEvidence,
}

impl AuthenticatedParentInvocation {
    /// Receives the one parent-bound invocation from its actual root PID1 issuer.
    ///
    /// # Errors
    /// Refuses repeated entry, original expiry, wrong issuer, unsealed evidence,
    /// or an image, policy, incarnation or immutable role mismatch.
    pub fn receive_original() -> Result<Self, MeasurementOriginError> {
        record::receive(MeasurementInvocationOrigin::receive_original()?)
    }

    /// Returns the same guest origin and its once-issued actor evidence.
    ///
    /// # Errors
    /// Refuses a policy, mode or native-width mismatch, or original expiration.
    pub fn split_for_actor(
        self,
    ) -> Result<(MeasurementInvocationOrigin, CertifiedNativeRoleEvidence), MeasurementOriginError>
    {
        self.origin.remaining()?;
        let expected_mode = match self.origin.policy.mode {
            StaticMode::NativeOnly => CertifiedMeasurementMode::NativeOnly,
            StaticMode::KernelMeasurement => CertifiedMeasurementMode::KernelMeasurement,
        };
        if self.origin.policy_digest != self.evidence.operator_digest
            || self.origin.policy.native_count != u64::from(self.evidence.native_count)
            || expected_mode != self.evidence.mode
            || self.evidence.generation == 0
            || self.origin.policy.actor_task_limit != 4096
            || self.origin.policy.actor_descriptors != 1024
            || self.origin.policy.actor_cpu_slots != 10
            || self.origin.policy.actor_resident_bytes != 16 << 30
            || self.origin.policy.host_memory_bytes != 20 << 30
            || self.origin.policy.host_backing_bytes != 64 << 30
        {
            return Err(MeasurementOriginError::Authentication(
                "parent actor binding",
            ));
        }
        Ok((self.origin, self.evidence))
    }
}

/// Selects the immutable family admitted before the actor's first birth.
#[derive(Debug, PartialEq, Eq)]
pub enum CertifiedMeasurementMode {
    /// Uses ordinary resident native mappings.
    NativeOnly,
    /// Uses the separately admitted disposable kernel measurement family.
    KernelMeasurement,
}

/// Retains an image, policy and incarnation binding to a paid whole actor domain.
///
/// There is no scalar constructor, deserialization implementation or account
/// getter. Only the private parent transport may issue this value after original
/// admission and birth enforcement. Parsing image facts alone cannot issue it.
pub struct CertifiedNativeRoleEvidence {
    images: VerifiedImageInventory,
    operator_digest: [u8; 32],
    workflow_digest: [u8; 32],
    incarnation: [u8; 32],
    generation: u64,
    mode: CertifiedMeasurementMode,
    native_count: u8,
}

impl CertifiedNativeRoleEvidence {
    /// Borrows the installed image and corresponding-source identity.
    #[must_use]
    pub fn images(&self) -> &VerifiedImageInventory {
        &self.images
    }

    /// Borrows the original immutable operator policy digest.
    #[must_use]
    pub fn operator_digest(&self) -> &[u8; 32] {
        &self.operator_digest
    }

    /// Borrows the immutable versioned workflow, including service purposes.
    #[must_use]
    pub fn workflow_digest(&self) -> &[u8; 32] {
        &self.workflow_digest
    }

    /// Borrows the externally owned VM incarnation identity.
    #[must_use]
    pub fn incarnation(&self) -> &[u8; 32] {
        &self.incarnation
    }

    /// Returns the nonzero original issuance generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Borrows the family selected before admission and process birth.
    #[must_use]
    pub fn mode(&self) -> &CertifiedMeasurementMode {
        &self.mode
    }

    /// Returns the authenticated one-, two- or four-worker native width.
    #[must_use]
    pub fn native_count(&self) -> u64 {
        u64::from(self.native_count)
    }
}

/// Identifies the installed post-fixup image inventory and its retained source.
pub struct VerifiedImageInventory {
    digest: [u8; 32],
    source_digest: [u8; 32],
    // The sealed issuance remains pinned through every actor alias and debit.
    _record: std::fs::File,
}

impl VerifiedImageInventory {
    /// Borrows the exact inventory digest.
    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Borrows the matching compiler-source inventory digest.
    #[must_use]
    pub fn source_digest(&self) -> &[u8; 32] {
        &self.source_digest
    }
}
