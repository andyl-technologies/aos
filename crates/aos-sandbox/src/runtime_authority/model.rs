//! Keeps private Native record acceptance above the shared canonical DATA codec.
//!
//! Only the existing store/codec boundary can enclose replayed Binding/Pending
//! DATA. Neither a public portable record nor its canonical decoder constructs
//! these Native wrappers, a current Runtime scope or an effect permit.

use aos_sandbox_core::{
    CanonicalAssignmentManifestV1, ObjectDigest, OperationId, PrincipalId, SandboxId,
};
use aos_sandbox_protocol::domain_ledger::runtime_authority_history as data;

use super::RuntimeAuthorityError;

pub use data::RuntimeAuthorityStateV1;
pub(super) use data::RuntimeAuthorityHeadV1;

/// Carries a checked nonauthorizing Runtime holder intent.
#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(transparent)]
pub struct RuntimeAuthorityIntentV1 {
    pub(super) data: data::RuntimeAuthorityIntentV1,
}

impl std::fmt::Debug for RuntimeAuthorityIntentV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.data, f)
    }
}

impl RuntimeAuthorityIntentV1 {
    /// Requests a binding to an explicitly authenticated and authorized holder.
    ///
    /// `expected_revision` is `None` only when the sandbox has never had a
    /// runtime-authority head. The protected store enforces that comparison.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeAuthorityError::InvalidIntent`] for a zero holder or
    /// zero expected revision.
    pub fn bind_holder(
        holder: PrincipalId,
        expected_revision: Option<u64>,
    ) -> Result<Self, RuntimeAuthorityError> {
        data::RuntimeAuthorityIntentV1::bind_holder(holder, expected_revision)
            .map(|data| Self { data })
            .map_err(RuntimeAuthorityError::from)
    }

    /// Requests an ordered tombstone for the protected current holder mapping.
    ///
    /// Admission requires exactly one canonical Host Stop effect for the current
    /// assignment. The tombstone takes effect at ownership activation, before
    /// dispatch; it is not evidence that runtime shutdown has completed.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeAuthorityError::InvalidIntent`] for a zero expected
    /// revision. Revoking a sandbox without a current head is rejected during
    /// protected admission.
    pub fn revoke(expected_revision: Option<u64>) -> Result<Self, RuntimeAuthorityError> {
        data::RuntimeAuthorityIntentV1::revoke(expected_revision)
            .map(|data| Self { data })
            .map_err(RuntimeAuthorityError::from)
    }

    /// Returns the exact revision expected at protected admission.
    #[must_use]
    pub const fn expected_revision(&self) -> Option<u64> {
        self.data.expected_revision()
    }

    /// Returns whether this intent binds a holder or requests a tombstone.
    #[must_use]
    pub const fn state(&self) -> RuntimeAuthorityStateV1 {
        self.data.state()
    }

    /// Returns the domain-separated commitment stored with the operation.
    ///
    /// The digest commits only the caller-authorized intent. Assignment and
    /// publication facts are separately derived and retained by the protected
    /// pending record.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        self.data.digest()
    }
}

/// Preserves the unchanged checked Runtime replay bounds.
#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(transparent)]
pub struct RuntimeAuthorityLimits {
    pub(super) data: data::RuntimeAuthorityLimits,
}

impl std::fmt::Debug for RuntimeAuthorityLimits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.data, f)
    }
}

impl RuntimeAuthorityLimits {
    pub(crate) const fn data_v2(self) -> data::RuntimeAuthorityLimits {
        self.data
    }

    /// Constructs limits within the implementation's fixed ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeAuthorityError::InvalidLimits`] if any limit is zero or
    /// exceeds its hard ceiling.
    pub fn new(
        maximum_records: usize,
        maximum_record_bytes: usize,
        maximum_materialized_bytes: usize,
    ) -> Result<Self, RuntimeAuthorityError> {
        data::RuntimeAuthorityLimits::new(
            maximum_records,
            maximum_record_bytes,
            maximum_materialized_bytes,
        )
        .map(|data| Self { data })
        .map_err(RuntimeAuthorityError::from)
    }
}

impl Default for RuntimeAuthorityLimits {
    fn default() -> Self {
        Self {
            data: data::RuntimeAuthorityLimits::default(),
        }
    }
}

/// Retains one store-admitted nonauthorizing pending record.
#[derive(Clone, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct RuntimeAuthorityPendingV1 {
    pub(super) data: data::RuntimeAuthorityPendingV1,
}

impl std::fmt::Debug for RuntimeAuthorityPendingV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.data, f)
    }
}

impl RuntimeAuthorityPendingV1 {
    // This borrows comparison DATA only; private accepted construction stays here.
    pub(crate) const fn historical_data_v1(&self) -> &data::RuntimeAuthorityPendingV1 {
        &self.data
    }

    pub(crate) const fn operation(&self) -> OperationId {
        self.data.operation()
    }

    pub(crate) const fn request_digest(&self) -> &[u8; 32] {
        self.data.request_digest()
    }

    pub(crate) const fn state(&self) -> RuntimeAuthorityStateV1 {
        self.data.state()
    }

    pub(crate) const fn manifest(&self) -> &CanonicalAssignmentManifestV1 {
        self.data.manifest()
    }

    pub(crate) const fn sandbox(&self) -> SandboxId {
        self.data.sandbox()
    }

    pub(crate) const fn source_draft_digest(&self) -> ObjectDigest {
        self.data.source_draft_digest()
    }

    pub(crate) fn intent_digest(&self) -> ObjectDigest {
        self.data.intent_digest()
    }
}

/// Retains one privately replayed structural Runtime binding.
///
/// A decoded portable record cannot construct this Native wrapper, current
/// Runtime proof, process pin or publication effect permit.
///
/// ```compile_fail
/// use aos_sandbox::runtime_authority::RuntimeAuthorityBindingV1;
/// use aos_sandbox_protocol::domain_ledger::runtime_authority_history as data;
/// fn accept(record: data::RuntimeAuthorityBindingV1) -> RuntimeAuthorityBindingV1 {
///     record.into()
/// }
/// ```
#[derive(Clone, Eq, PartialEq)]
#[repr(transparent)]
pub struct RuntimeAuthorityBindingV1 {
    pub(super) data: data::RuntimeAuthorityBindingV1,
}

impl std::fmt::Debug for RuntimeAuthorityBindingV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.data, f)
    }
}

impl RuntimeAuthorityBindingV1 {
    pub(crate) const fn data_v2(&self) -> &data::RuntimeAuthorityBindingV1 {
        &self.data
    }

    // This borrows comparison DATA only; private accepted construction stays here.
    pub(crate) const fn historical_data_v1(&self) -> &data::RuntimeAuthorityBindingV1 {
        &self.data
    }

    /// Returns whether this revision binds a holder or revokes the mapping.
    #[must_use]
    pub const fn state(&self) -> RuntimeAuthorityStateV1 {
        self.data.state()
    }

    /// Returns the bound holder, or `None` for a revocation tombstone.
    #[must_use]
    pub const fn holder(&self) -> Option<PrincipalId> {
        self.data.holder()
    }

    /// Returns the contiguous sandbox-local binding revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.data.revision()
    }

    /// Returns the canonical assignment manifest from the admitted gate draft.
    #[must_use]
    pub const fn manifest(&self) -> &CanonicalAssignmentManifestV1 {
        self.data.manifest()
    }

    /// Returns the sandbox named by the canonical assignment.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.data.sandbox()
    }

    /// Returns the internally derived canonical assignment digest.
    #[must_use]
    pub const fn assignment_digest(&self) -> ObjectDigest {
        self.data.assignment_digest()
    }

    /// Returns the operation that activated this immutable revision.
    #[must_use]
    pub const fn operation(&self) -> OperationId {
        self.data.operation()
    }

    /// Returns the normalized request digest admitted with the operation.
    #[must_use]
    pub const fn request_digest(&self) -> &[u8; 32] {
        self.data.request_digest()
    }

    /// Returns the exact admitted authority-publication draft digest.
    #[must_use]
    pub const fn source_draft_digest(&self) -> ObjectDigest {
        self.data.source_draft_digest()
    }

    /// Returns the exact prepared authority-publication digest.
    #[must_use]
    pub const fn publication_digest(&self) -> ObjectDigest {
        self.data.publication_digest()
    }

    /// Returns the ownership-lease generation activated with this revision.
    #[must_use]
    pub const fn lease_generation(&self) -> u64 {
        self.data.lease_generation()
    }

    /// Returns the exact ownership-lease digest activated with this revision.
    #[must_use]
    pub const fn lease_digest(&self) -> ObjectDigest {
        self.data.lease_digest()
    }

    /// Returns the domain-separated digest of this complete immutable record.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.data.digest()
    }
}

