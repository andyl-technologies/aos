//! Preserves the actual selected Source readback failure categories.

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1;
use aos_sandbox_ledger_replay::source_signer_data::{SourceHoldReadbackErrorV1,
    SourceSignerGenesisDataErrorV1};
use aos_sandbox_protocol::domain_ledger::DomainLedgerDataError;
use super::readonly_native::SourceReadonlyNativeErrorV1;

#[derive(Debug, thiserror::Error)]
pub(super) enum SourceReadbackGenesisErrorV1 {
    #[error("invalid Source genesis record or exact owner join")]
    NonCanonical,
    #[error("Source genesis project or flight conflicts with retained state")]
    Conflict,
    #[error("Source genesis owner or credential is not current")]
    Stale,
    #[error(transparent)]
    Journal(#[from] CanonicalJournalMechanicalErrorV1),
    #[error(transparent)]
    Hierarchy(#[from] DomainLedgerDataError),
    #[error(transparent)]
    Data(#[from] SourceSignerGenesisDataErrorV1),
}

#[derive(Debug, thiserror::Error)]
pub(super) enum SourceSignerReadbackErrorV1 {
    #[error("unsafe Source signer journal view")]
    View,
    #[error(transparent)]
    Journal(#[from] CanonicalJournalMechanicalErrorV1),
    #[error(transparent)]
    Native(#[from] SourceReadonlyNativeErrorV1),
    #[error("Source hold and typed hierarchy head are not current")]
    Stale,
    #[error(transparent)]
    Signing(#[from] SourceHoldReadbackErrorV1),
    #[error(transparent)]
    FirstSuccessor(#[from] SourceReadbackGenesisErrorV1),
}

impl From<SourceSignerGenesisDataErrorV1> for SourceSignerReadbackErrorV1 {
    fn from(cause: SourceSignerGenesisDataErrorV1) -> Self {
        Self::FirstSuccessor(SourceReadbackGenesisErrorV1::Data(cause))
    }
}
