//! Selects current structural assignment DATA through the existing C stores.
//!
//! Callers retain a genuine full native C cut and pay the complete publication
//! and RuntimeAuthority decoder/index shape before this pure selection. The
//! returned records do not establish live Ownership or authorize a resource.

use aos_sandbox_model::{CanonicalAssignmentManifestV1, SandboxId};
use crate::publication::CurrentAuthorityPublicationV1;
use crate::runtime_authority::{
    RuntimeAuthorityBindingV1, RuntimeAuthorityLimits,
};
use crate::JournalError;
use crate::journal::historical_observation::HistoricalObservationV1;

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
    controller: HistoricalObservationV1<'_>,
    sandbox: SandboxId,
) -> Result<CurrentProtectedAssignmentDataV2, CurrentProtectedAssignmentErrorV3> {
    let binding = crate::runtime_authority::current_observed_v2(
        controller, RuntimeAuthorityLimits::default(), sandbox,
    )?.ok_or(JournalError::ProtectedBoundary)?;
    let publication = crate::publication::current_observed_v2(controller, sandbox)?
        .ok_or(JournalError::ProtectedBoundary)?;

    aos_sandbox_protocol::domain_ledger::runtime_authority_history::current_assignment::
        require_current_assignment_history_data_v2(binding.historical_data_v1(), publication.history_data_v2())
        .map_err(|_| JournalError::ProtectedBoundary)?;

    Ok(CurrentProtectedAssignmentDataV2 { binding, publication })
}

/// Prices the actual retained pair and genuine-owner selector forwarding.
pub(crate) fn current_protected_assignment_carrier_receiving_bytes_v2() -> Option<usize> {
    use std::mem::size_of;

    size_of::<CurrentProtectedAssignmentDataV2>().checked_mul(2)?
        .checked_add(current_protected_assignment_observation_control_bytes_v2()?)
}

// Host compiler/final owners already price their complete inline Self, including
// the retained pair. Their later model quote adds only this new forwarding term.
pub(crate) fn current_protected_assignment_observation_control_bytes_v2() -> Option<usize> {
    use std::mem::size_of;

    size_of::<HistoricalObservationV1<'_>>().checked_mul(3)?
        .checked_add(crate::runtime_authority::current_observation_control_bytes_v2()?)?
        .checked_add(crate::publication::current_observation_control_bytes_v2()?)?
        .checked_add(aos_sandbox_protocol::domain_ledger::runtime_authority_history::current_assignment::
            current_assignment_links_control_bytes_v2()?)
}

// These actual old Journal callers construct the loan here, rather than
// borrowing the separately priced native FinalTarget getter result.
pub(crate) fn current_protected_assignment_journal_observation_control_bytes_v2() -> Option<usize> {
    current_protected_assignment_observation_control_bytes_v2()?
        .checked_add(HistoricalObservationV1::journal_receiving_control_bytes_v1()?)
}

pub(crate) fn current_protected_assignment_journal_carrier_receiving_bytes_v2() -> Option<usize> {
    std::mem::size_of::<CurrentProtectedAssignmentDataV2>().checked_mul(2)?
        .checked_add(current_protected_assignment_journal_observation_control_bytes_v2()?)
}
