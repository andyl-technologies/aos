//! Selects only existing Network journal key families before semantic replay.
//!
//! This comparison does not move MAC validation earlier. The actual catalog
//! still authenticates its complete materialized model at the old frontier.

use std::collections::BTreeMap;

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Cause;
use aos_sandbox_model::RecordNamespace;
use aos_sandbox_ledger_replay::replay::{source_tree_genesis, source_tree_successor};
use aos_sandbox_protocol::domain_ledger::transaction::{JournalLimits, JournalTransaction};

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

#[derive(Clone, Copy)]
pub(super) enum Schema {
    Creation,
    Lifecycle,
    Preparation,
    Namespace,
    Worker,
    #[cfg(test)]
    Fixture,
}

impl Schema {
    pub(super) fn from_name(name: &str) -> Result<Self, Cause> {
        match name {
            "network-state.journal" => Ok(Self::Creation),
            "network-lifecycle-state.journal" => Ok(Self::Lifecycle),
            "network-preparations.journal" => Ok(Self::Preparation),
            "network-namespaces.journal" => Ok(Self::Namespace),
            "network-worker-replay.journal" => Ok(Self::Worker),
            _ => Err(Cause::ProtectedBoundary),
        }
    }

    fn permits_key(self, namespace: RecordNamespace, key: &[u8]) -> bool {
        match self {
            Self::Creation => crate::state::creation_journal_key_data_v1(namespace, key),
            Self::Lifecycle => match namespace {
                RecordNamespace::Operation
                | RecordNamespace::Effect
                | RecordNamespace::AuthorityPublication
                | RecordNamespace::DesiredState => key.len() == 16,
                RecordNamespace::NetworkResourceInventory => key.len() == 32,
                _ => false,
            },
            Self::Preparation => crate::preparation_catalog::journal_key_data_v1(namespace, key),
            Self::Namespace => crate::namespace_catalog::journal_key_data_v1(namespace, key),
            Self::Worker => namespace == RecordNamespace::Effect && key.len() == 16,
            #[cfg(test)]
            Self::Fixture => true,
        }
    }

    pub(super) fn require_transaction(self, transaction: &JournalTransaction) -> Result<(), Cause> {
        if transaction
            .records()
            .iter()
            .all(|record| self.permits_key(record.namespace(), record.key()))
        {
            Ok(())
        } else {
            Err(Cause::ForeignAuthorityNamespace)
        }
    }

    pub(super) fn require_state(self, state: &State) -> Result<(), Cause> {
        if state
            .keys()
            .all(|(namespace, key)| self.permits_key(*namespace, key))
        {
            Ok(())
        } else {
            Err(Cause::ForeignAuthorityNamespace)
        }
    }

    pub(super) fn before_logical(
        self,
        state: &State,
        transaction: &JournalTransaction,
        limits: JournalLimits,
    ) -> Result<(), Cause> {
        self.require_transaction(transaction)?;
        // A raw32 lifecycle handle can begin a reserved Source-family prefix.
        // Keep the existing canonical transition veto before native admission.
        // Other closed keys exclude every such selector; no MAC check moves.
        if self.needs_source_comparison() {
            let _ = source_tree_successor::validate_replayed_transaction::<
                Cause,
                aos_sandbox_protocol::domain_ledger::DomainLedgerDataError,
                aos_sandbox_ledger_replay::genesis::SourceGenesisReceiptDataErrorV1,
            >(state, transaction, limits)?;
        }
        Ok(())
    }

    pub(super) fn before_append(
        self,
        state: &State,
        transaction: &JournalTransaction,
    ) -> Result<(), Cause> {
        self.require_transaction(transaction)?;
        if self.needs_source_comparison() {
            // The ordinary append frontier independently vetoes genesis-family
            // mutations before the successor transition comparison.
            source_tree_genesis::require_no_mutation(
                state,
                transaction,
                source_tree_genesis::SourceGenesisTransitionV1::None,
            )?;
            let _ = source_tree_successor::require_transition::<
                Cause,
                aos_sandbox_protocol::domain_ledger::DomainLedgerDataError,
                aos_sandbox_ledger_replay::genesis::SourceGenesisReceiptDataErrorV1,
            >(state, transaction, None)?;
        }
        Ok(())
    }

    pub(super) fn finish_prefix(self, state: &State, compacted: bool) -> Result<(), Cause> {
        self.require_state(state)?;
        if self.needs_source_comparison() {
            source_tree_successor::validate_replayed_state::<
                Cause,
                aos_sandbox_protocol::domain_ledger::DomainLedgerDataError,
                aos_sandbox_ledger_replay::genesis::SourceGenesisReceiptDataErrorV1,
            >(state, compacted)?;
        }
        Ok(())
    }

    fn needs_source_comparison(self) -> bool {
        match self {
            Self::Lifecycle => true,
            #[cfg(test)]
            Self::Fixture => true,
            _ => false,
        }
    }
}
