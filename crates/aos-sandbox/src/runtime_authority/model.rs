//! Typed values for protected runtime-assignment authority.
//!
//! Public intents are non-authorizing compiler inputs. Pending and binding
//! values can only be constructed by the crate-private store after it has
//! resolved a canonical authority-publication draft and protected current head.

use aos_sandbox_core::{
    CanonicalAssignmentManifestV1, ObjectDigest, OperationId, PrincipalId, SandboxId,
};
use sha2::{Digest as _, Sha256};

use super::{
    MAXIMUM_MATERIALIZED_BYTES, MAXIMUM_RECORD_BYTES, MAXIMUM_RECORDS, RuntimeAuthorityError,
};

/// Selects the durable result of one admitted runtime-authority intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeAuthorityStateV1 {
    /// Binds the current assignment to one controller-authorized holder.
    Bound,
    /// Revokes the current holder mapping while retaining an ordered tombstone.
    Revoked,
}

impl RuntimeAuthorityStateV1 {
    pub(super) const fn code(self) -> u8 {
        match self {
            Self::Bound => 1,
            Self::Revoked => 2,
        }
    }

    pub(super) fn from_code(code: u8) -> Result<Self, RuntimeAuthorityError> {
        match code {
            1 => Ok(Self::Bound),
            2 => Ok(Self::Revoked),
            _ => Err(RuntimeAuthorityError::CorruptState),
        }
    }
}

/// Carries a non-authorizing holder-binding or revocation request.
///
/// The intent contains neither assignment bytes nor a caller-selected current
/// state. Admission derives those facts from the ownership-gated publication
/// draft and the protected runtime-authority head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeAuthorityIntentV1 {
    pub(super) state: RuntimeAuthorityStateV1,
    pub(super) holder: Option<PrincipalId>,
    pub(super) expected_revision: Option<u64>,
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
        validate_expected_revision(expected_revision)?;
        if holder.as_bytes() == &[0; 16] {
            return Err(RuntimeAuthorityError::InvalidIntent);
        }
        Ok(Self {
            state: RuntimeAuthorityStateV1::Bound,
            holder: Some(holder),
            expected_revision,
        })
    }

    /// Requests an ordered tombstone for the protected current holder mapping.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeAuthorityError::InvalidIntent`] for a zero expected
    /// revision. Revoking a sandbox without a current head is rejected during
    /// protected admission.
    pub fn revoke(expected_revision: Option<u64>) -> Result<Self, RuntimeAuthorityError> {
        validate_expected_revision(expected_revision)?;
        Ok(Self {
            state: RuntimeAuthorityStateV1::Revoked,
            holder: None,
            expected_revision,
        })
    }

    /// Returns the exact revision expected at protected admission.
    #[must_use]
    pub const fn expected_revision(&self) -> Option<u64> {
        self.expected_revision
    }

    /// Returns whether this intent binds a holder or requests a tombstone.
    #[must_use]
    pub const fn state(&self) -> RuntimeAuthorityStateV1 {
        self.state
    }

    /// Returns the domain-separated commitment stored with the operation.
    ///
    /// The digest commits only the caller-authorized intent. Assignment and
    /// publication facts are separately derived and retained by the protected
    /// pending record.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        intent_digest(self.state, self.holder, self.expected_revision)
    }
}

fn validate_expected_revision(revision: Option<u64>) -> Result<(), RuntimeAuthorityError> {
    if revision == Some(0) {
        return Err(RuntimeAuthorityError::InvalidIntent);
    }
    Ok(())
}

/// Bounds complete namespace replay and mutation encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeAuthorityLimits {
    pub(super) maximum_records: usize,
    pub(super) maximum_record_bytes: usize,
    pub(super) maximum_materialized_bytes: usize,
}

impl RuntimeAuthorityLimits {
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
        if maximum_records == 0
            || maximum_records > MAXIMUM_RECORDS
            || maximum_record_bytes == 0
            || maximum_record_bytes > MAXIMUM_RECORD_BYTES
            || maximum_materialized_bytes == 0
            || maximum_materialized_bytes > MAXIMUM_MATERIALIZED_BYTES
        {
            return Err(RuntimeAuthorityError::InvalidLimits);
        }
        Ok(Self {
            maximum_records,
            maximum_record_bytes,
            maximum_materialized_bytes,
        })
    }
}

impl Default for RuntimeAuthorityLimits {
    fn default() -> Self {
        Self {
            maximum_records: MAXIMUM_RECORDS,
            maximum_record_bytes: MAXIMUM_RECORD_BYTES,
            maximum_materialized_bytes: MAXIMUM_MATERIALIZED_BYTES,
        }
    }
}

/// Retains one admitted, non-authorizing runtime-authority intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeAuthorityPendingV1 {
    pub(super) operation: OperationId,
    pub(super) request_digest: [u8; 32],
    pub(super) state: RuntimeAuthorityStateV1,
    pub(super) holder: Option<PrincipalId>,
    pub(super) expected_revision: Option<u64>,
    pub(super) revision: u64,
    pub(super) predecessor_digest: Option<ObjectDigest>,
    pub(super) manifest: CanonicalAssignmentManifestV1,
    pub(super) source_draft_digest: ObjectDigest,
}

impl RuntimeAuthorityPendingV1 {
    pub(crate) const fn operation(&self) -> OperationId {
        self.operation
    }

    pub(crate) const fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }

    pub(crate) const fn state(&self) -> RuntimeAuthorityStateV1 {
        self.state
    }

    pub(crate) const fn manifest(&self) -> &CanonicalAssignmentManifestV1 {
        &self.manifest
    }

    pub(crate) const fn sandbox(&self) -> SandboxId {
        self.manifest.manifest().sandbox()
    }

    pub(crate) const fn source_draft_digest(&self) -> ObjectDigest {
        self.source_draft_digest
    }

    pub(crate) fn intent_digest(&self) -> ObjectDigest {
        intent_digest(self.state, self.holder, self.expected_revision)
    }
}

/// Replays one immutable protected runtime-authority decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeAuthorityBindingV1 {
    pub(super) operation: OperationId,
    pub(super) request_digest: [u8; 32],
    pub(super) state: RuntimeAuthorityStateV1,
    pub(super) holder: Option<PrincipalId>,
    pub(super) revision: u64,
    pub(super) predecessor_digest: Option<ObjectDigest>,
    pub(super) manifest: CanonicalAssignmentManifestV1,
    pub(super) source_draft_digest: ObjectDigest,
    pub(super) publication_digest: ObjectDigest,
    pub(super) lease_generation: u64,
    pub(super) lease_digest: ObjectDigest,
    pub(super) digest: ObjectDigest,
}

impl RuntimeAuthorityBindingV1 {
    /// Returns whether this revision binds a holder or revokes the mapping.
    #[must_use]
    pub const fn state(&self) -> RuntimeAuthorityStateV1 {
        self.state
    }

    /// Returns the bound holder, or `None` for a revocation tombstone.
    #[must_use]
    pub const fn holder(&self) -> Option<PrincipalId> {
        self.holder
    }

    /// Returns the contiguous sandbox-local binding revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the canonical assignment manifest from the admitted gate draft.
    #[must_use]
    pub const fn manifest(&self) -> &CanonicalAssignmentManifestV1 {
        &self.manifest
    }

    /// Returns the sandbox named by the canonical assignment.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.manifest.manifest().sandbox()
    }

    /// Returns the internally derived canonical assignment digest.
    #[must_use]
    pub const fn assignment_digest(&self) -> ObjectDigest {
        self.manifest.digest()
    }

    /// Returns the operation that activated this immutable revision.
    #[must_use]
    pub const fn operation(&self) -> OperationId {
        self.operation
    }

    /// Returns the normalized request digest admitted with the operation.
    #[must_use]
    pub const fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }

    /// Returns the exact admitted authority-publication draft digest.
    #[must_use]
    pub const fn source_draft_digest(&self) -> ObjectDigest {
        self.source_draft_digest
    }

    /// Returns the exact prepared authority-publication digest.
    #[must_use]
    pub const fn publication_digest(&self) -> ObjectDigest {
        self.publication_digest
    }

    /// Returns the ownership-lease generation activated with this revision.
    #[must_use]
    pub const fn lease_generation(&self) -> u64 {
        self.lease_generation
    }

    /// Returns the exact ownership-lease digest activated with this revision.
    #[must_use]
    pub const fn lease_digest(&self) -> ObjectDigest {
        self.lease_digest
    }

    /// Returns the domain-separated digest of this complete immutable record.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RuntimeAuthorityHeadV1 {
    pub(super) sandbox: SandboxId,
    pub(super) revision: u64,
    pub(super) binding_digest: ObjectDigest,
}

fn intent_digest(
    state: RuntimeAuthorityStateV1,
    holder: Option<PrincipalId>,
    expected_revision: Option<u64>,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(super::INTENT_DIGEST_DOMAIN);
    digest.update([state.code()]);
    digest.update(
        holder
            .unwrap_or_else(|| PrincipalId::from_bytes([0; 16]))
            .as_bytes(),
    );
    digest.update([u8::from(expected_revision.is_some())]);
    digest.update(expected_revision.unwrap_or(0).to_be_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}
