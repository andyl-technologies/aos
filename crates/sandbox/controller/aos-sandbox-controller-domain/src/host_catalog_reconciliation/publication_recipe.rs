//! Binds the canonical Host pending/confirmation assemblies to the paid scope.
//!
//! A recipe is not a payer, operation grant, accepted child or native token.
//! Only the actual pending2/catalog6 scope may consume it through the existing
//! Core semantic/native append engine. Its constructors stay in this module's
//! canonical catalog parent, and its pre-state comparisons allocate nothing.

use super::*;

/// Selects the two distinct canonical catalog append destinations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostCatalogCommitPhaseV2 {
    Pending,
    Confirmation,
}

/// Borrows one exact canonical transaction and its original catalog binding.
pub(crate) struct HostCatalogCommitRecipeV2<'transaction> {
    transaction: &'transaction JournalTransaction,
    phase: HostCatalogCommitPhaseV2,
    generation: u64,
    digest: [u8; 32],
    prior_current: Option<Vec<u8>>,
    prior_pending: Option<Vec<u8>>,
}

impl<'transaction> HostCatalogCommitRecipeV2<'transaction> {
    // The caller has paid these actual co-live historical backing copies and
    // the canonical transaction before reaching this assembly point.
    pub(super) fn from_canonical_assembly_v2(
        journal: &Journal,
        transaction: &'transaction JournalTransaction,
        record: &CatalogRecord,
        phase: HostCatalogCommitPhaseV2,
    ) -> Result<Self, HostCatalogReconciliationError> {
        if record.state != CatalogRecordState::Pending {
            return Err(HostCatalogReconciliationError::CorruptState);
        }
        Ok(Self {
            transaction,
            phase,
            generation: record.catalog.generation(),
            digest: record.catalog_digest,
            prior_current: journal
                .get(RecordNamespace::HostCatalogReconciliation, CURRENT_KEY)
                .map(<[u8]>::to_vec),
            prior_pending: journal
                .get(RecordNamespace::HostCatalogReconciliation, PENDING_KEY)
                .map(<[u8]>::to_vec),
        })
    }

    /// Compares the whole exact transaction without decoding or allocation.
    pub(crate) fn require_transaction_v2(
        &self,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        if transaction != self.transaction {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Refuses changed current/pending history before the same native append.
    pub(crate) fn require_history_v2(&self, journal: &Journal) -> Result<(), JournalError> {
        if journal.get(RecordNamespace::HostCatalogReconciliation, CURRENT_KEY)
            != self.prior_current.as_deref()
            || journal.get(RecordNamespace::HostCatalogReconciliation, PENDING_KEY)
                != self.prior_pending.as_deref()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        match self.phase {
            HostCatalogCommitPhaseV2::Pending if self.prior_pending.is_some() => {
                Err(JournalError::ProtectedBoundary)
            }
            HostCatalogCommitPhaseV2::Confirmation if self.prior_pending.is_none() => {
                Err(JournalError::ProtectedBoundary)
            }
            _ => Ok(()),
        }
    }

    pub(crate) const fn phase_v2(&self) -> HostCatalogCommitPhaseV2 {
        self.phase
    }

    pub(crate) const fn catalog_generation_v2(&self) -> u64 {
        self.generation
    }

    pub(crate) const fn catalog_digest_v2(&self) -> [u8; 32] {
        self.digest
    }
}
