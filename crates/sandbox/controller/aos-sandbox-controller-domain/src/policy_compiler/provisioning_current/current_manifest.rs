//! Selects current structural assignment DATA through the existing C stores.
//!
//! Callers retain a genuine full native C cut and pay the complete publication
//! and RuntimeAuthority decoder/index shape before this pure selection. The
//! returned records do not establish live Ownership or authorize a resource.

use aos_sandbox_model::{CanonicalAssignmentManifestV1, SandboxId};
use crate::publication::{AuthorityPublicationStore, CurrentAuthorityPublicationV1};
use crate::runtime_authority::{
    RuntimeAuthorityBindingV1, RuntimeAuthorityLimits, RuntimeAuthorityStateV1,
    RuntimeAuthorityStore,
};
use crate::{Journal, JournalError};

/// Preserves the concrete selector failure inside retained Journal custody.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CurrentProtectedAssignmentErrorV3 {
    #[error(transparent)]
    RuntimeAuthority(#[from] crate::runtime_authority::RuntimeAuthorityError),
    #[error(transparent)]
    Publication(#[from] crate::publication::AuthorityPublicationError),
    #[error(transparent)]
    Journal(#[from] JournalError),
}

/// Retains both actual protected records instead of adopting a supplied manifest.
pub(crate) struct CurrentProtectedAssignmentDataV2 {
    binding: RuntimeAuthorityBindingV1,
    publication: CurrentAuthorityPublicationV1,
}

impl CurrentProtectedAssignmentDataV2 {
    /// Borrows the actual binding selected with this same protected publication.
    pub(crate) fn binding_data_v2(&self) -> &RuntimeAuthorityBindingV1 {
        &self.binding
    }

    pub(crate) fn manifest_v2(&self) -> &CanonicalAssignmentManifestV1 {
        self.binding.manifest()
    }

    pub(crate) fn publication_v2(&self) -> &CurrentAuthorityPublicationV1 {
        &self.publication
    }
}

/// Selects the current bound manifest through the same complete store validators.
///
/// # Errors
/// Rejects an unhealthy or unprotected C, corrupt namespaces, absent/revoked
/// current binding, or different publication, canonical manifest or lease links.
pub(crate) fn current_protected_assignment_data_v2(
    controller: &mut Journal,
    sandbox: SandboxId,
) -> Result<CurrentProtectedAssignmentDataV2, CurrentProtectedAssignmentErrorV3> {
    let binding = RuntimeAuthorityStore::load(controller, RuntimeAuthorityLimits::default())?
        .current(sandbox)?.ok_or(JournalError::ProtectedBoundary)?;
    let publication = AuthorityPublicationStore::new(controller)
        .current(sandbox)?.ok_or(JournalError::ProtectedBoundary)?;

    require_current_assignment_records_v2(&binding, &publication)?;

    Ok(CurrentProtectedAssignmentDataV2 { binding, publication })
}

/// Compares actual validated current-record DATA without constructing a store.
///
/// The caller independently owns full namespace/schema/native validation. This
/// predicate cannot establish that a supplied pair is the actual current pair.
///
/// # Errors
/// Rejects revocation or differing publication, manifest and lease links.
pub(crate) fn require_current_assignment_records_v2(
    binding: &RuntimeAuthorityBindingV1,
    publication: &CurrentAuthorityPublicationV1,
) -> Result<(), JournalError> {
    require_current_assignment_links_v2(binding.state(), binding.publication_digest(),
        binding.manifest(), binding.lease_digest(), binding.lease_generation(),
        publication.history_data_v2())
}

/// Bounds only the additional current-record comparison and return carriers.
pub(crate) fn current_protected_assignment_carrier_receiving_bytes_v2() -> Option<usize> {
    std::mem::size_of::<CurrentProtectedAssignmentDataV2>().checked_mul(2)
}

/// Shares the sole binding/publication predicate with genuine readonly owners.
///
/// The complete supplied records are nonauthorizing DATA. A Root readonly
/// caller obtains them only through its own full canonical native C replay.
///
/// # Errors
/// Rejects revocation or differing publication, manifest and lease links.
pub(crate) fn require_current_assignment_history_v2(
    binding: &aos_sandbox_protocol::domain_ledger::runtime_authority_history::RuntimeAuthorityBindingV1,
    publication: &aos_sandbox_protocol::publication::PublicationHistoryV1,
) -> Result<(), JournalError> {
    require_current_assignment_links_v2(binding.state(), binding.publication_digest(),
        binding.manifest(), binding.lease_digest(), binding.lease_generation(), publication)
}

// The Native and passive records lend only their existing borrowed canonical
// identities. This private predicate creates no wrapper, currentness or grant.
fn require_current_assignment_links_v2(
    state: RuntimeAuthorityStateV1,
    publication_digest: aos_sandbox_model::ObjectDigest,
    manifest: &CanonicalAssignmentManifestV1,
    lease_digest: aos_sandbox_model::ObjectDigest,
    lease_generation: u64,
    publication: &aos_sandbox_protocol::publication::PublicationHistoryV1,
) -> Result<(), JournalError> {
    if state != RuntimeAuthorityStateV1::Bound
        || publication_digest != publication.digest()
        || manifest.canonical_bytes() != publication.manifest().canonical_bytes()
        || lease_digest != publication.lease_digest()
        || lease_generation != publication.lease_generation()
    {
        return Err(JournalError::ProtectedBoundary);
    }

    Ok(())
}
