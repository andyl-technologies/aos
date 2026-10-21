//! Keeps Cache's single-namespace claim and exact intrinsic writer snapshot.
//!
//! The five real Cache writers retain protected opening provenance and the
//! canonical legacy-capacity/namespace checks. Source, Root, Controller and
//! Mount purpose-specific claims have no constructor or implementation here.
//! Raw historical records remain DATA until this actual owner revalidates the
//! same native writer, namespace and sequence at its use boundary.

use aos_sandbox_broker::canonical_journal::CanonicalJournalInstanceDataV1;

use super::{CacheJournalInstanceV1, Journal, JournalError, RecordNamespace};

pub(crate) struct ProtectedJournalSnapshot {
    instance: CanonicalJournalInstanceDataV1<CacheJournalInstanceV1>,
    namespace: RecordNamespace,
    sequence: u64,
}

pub(crate) struct ProtectedJournalAuthority<'journal> {
    pub(super) journal: &'journal mut Journal,
    pub(super) namespace: RecordNamespace,
}

impl Journal {
    // Every real Cache raw-authority consumer claims DesiredState. Keeping
    // that closed selection here avoids importing Domain's unrelated scopes.
    pub(crate) fn claim_cache_authority_v1(
        &mut self,
    ) -> Result<ProtectedJournalAuthority<'_>, JournalError> {
        self.ensure_protected_authority()?;
        let namespace = RecordNamespace::DesiredState;
        self.require_cache_history_schema_v1()?;
        Ok(ProtectedJournalAuthority {
            journal: self,
            namespace,
        })
    }
}

impl ProtectedJournalAuthority<'_> {
    pub(crate) fn get(&self, key: &[u8]) -> Result<Option<&[u8]>, JournalError> {
        self.journal.ensure_protected_authority()?;
        Ok(self.journal.get(self.namespace, key))
    }

    pub(crate) fn records(&self) -> Result<impl Iterator<Item = (&[u8], &[u8])>, JournalError> {
        self.journal.ensure_protected_authority()?;
        Ok(self.journal.records(self.namespace))
    }

    pub(crate) fn snapshot(&self) -> Result<ProtectedJournalSnapshot, JournalError> {
        self.journal.ensure_protected_authority()?;
        let instance = self.journal.instance.clone();
        Ok(ProtectedJournalSnapshot {
            instance,
            namespace: self.namespace,
            sequence: self.journal.snapshot_sequence(),
        })
    }

    pub(crate) fn validate_snapshot_for_effect(
        &self,
        snapshot: &ProtectedJournalSnapshot,
    ) -> Result<(), JournalError> {
        self.journal.ensure_protected_authority()?;
        let instance = &self.journal.instance;
        if !instance.same_original_v1(&snapshot.instance)
            || snapshot.namespace != self.namespace
            || snapshot.sequence != self.journal.snapshot_sequence()
        {
            return Err(JournalError::Mechanical(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::StaleAuthoritySnapshot));
        }
        Ok(())
    }
}

/// Retains the exact actual writer cut and ordered preflighted transaction set.
pub(crate) struct ProtectedJournalPreflight {
    snapshot: ProtectedJournalSnapshot,
    transaction_digest: [u8; 32],
}

impl ProtectedJournalSnapshot {
    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }
}

impl ProtectedJournalAuthority<'_> {
    pub(crate) fn is_materialized_empty(&self) -> Result<bool, JournalError> {
        self.journal.ensure_protected_authority()?;
        Ok(self.journal.read_view().state().is_empty())
    }

    pub(crate) fn preflight_transactions(
        &self,
        transactions: &[super::JournalTransaction],
    ) -> Result<ProtectedJournalPreflight, JournalError> {
        self.preflight_with_cache_gate(transactions, super::CacheMutationGateV1::Ordinary)
    }

    pub(crate) fn preflight_with_retained_cache_gate_v1(
        &self,
        transactions: &[super::JournalTransaction],
        gate: &mut super::HeldCacheMutationGateV1,
    ) -> Result<ProtectedJournalPreflight, JournalError> {
        self.preflight_with_cache_gate(transactions, super::CacheMutationGateV1::Retained(gate))
    }

    pub(crate) fn preflight_with_cache_gate(
        &self,
        transactions: &[super::JournalTransaction],
        mut gate: super::CacheMutationGateV1<'_>,
    ) -> Result<ProtectedJournalPreflight, JournalError> {
        self.journal.ensure_protected_authority()?;
        self.validate_transaction_namespaces(transactions)?;
        gate.preflight(self.journal, transactions)?;
        Ok(ProtectedJournalPreflight {
            snapshot: self.snapshot()?,
            transaction_digest: super::authority_preflight_digest(transactions),
        })
    }

    pub(crate) fn validate_preflight_for_effect(
        &self,
        preflight: &ProtectedJournalPreflight,
        transactions: &[super::JournalTransaction],
    ) -> Result<(), JournalError> {
        self.journal.ensure_protected_authority()?;
        self.validate_transaction_namespaces(transactions)?;
        self.validate_snapshot_for_effect(&preflight.snapshot)?;
        if preflight.transaction_digest != super::authority_preflight_digest(transactions) {
            return Err(JournalError::preflight_mismatch());
        }
        Ok(())
    }

    pub(crate) fn commit(
        &mut self,
        transaction: &super::JournalTransaction,
    ) -> Result<super::CommitResult, JournalError> {
        self.journal.ensure_protected_authority()?;
        self.validate_transaction_namespaces(std::slice::from_ref(transaction))?;
        self.journal.commit(transaction)
    }

    pub(crate) fn commit_with_retained_cache_gate_v1(
        &mut self,
        preflight: &ProtectedJournalPreflight,
        transaction: &super::JournalTransaction,
        gate: &mut super::HeldCacheMutationGateV1,
    ) -> Result<super::CommitResult, JournalError> {
        self.validate_preflight_for_effect(preflight, std::slice::from_ref(transaction))?;
        self.journal.commit_with_retained_cache_gate_v1(transaction, gate)
    }

    pub(crate) fn commit_with_original_cache_gate_v1(
        &mut self,
        preflight: &ProtectedJournalPreflight,
        transaction: &super::JournalTransaction,
        mut gate: super::CacheMutationGateV1<'_>,
    ) -> Result<super::CommitResult, JournalError> {
        self.validate_preflight_for_effect(preflight, std::slice::from_ref(transaction))?;
        gate.commit(self.journal, transaction)
    }

    pub(crate) fn require_original_cache_gate_v1(
        &self,
        gate: &mut super::CacheMutationGateV1<'_>,
    ) -> Result<(), JournalError> {
        gate.check(self.journal)
    }

    pub(crate) fn require_retained_cache_gate_v1(
        &self,
        gate: &mut super::HeldCacheMutationGateV1,
    ) -> Result<(), JournalError> {
        gate.require_for_target(self.journal)
    }

    pub(crate) fn require_retained_cache_own_append_v1(
        &self,
        before: &ProtectedJournalSnapshot,
        transaction: &super::JournalTransaction,
        result: &super::CommitResult,
        gate: &mut super::HeldCacheMutationGateV1,
    ) -> Result<(), JournalError> {
        self.require_original_cache_own_append_v1(
            before, transaction, result, &mut super::CacheMutationGateV1::Retained(gate),
        )
    }

    pub(crate) fn require_original_cache_own_append_v1(
        &self,
        before: &ProtectedJournalSnapshot,
        transaction: &super::JournalTransaction,
        result: &super::CommitResult,
        gate: &mut super::CacheMutationGateV1<'_>,
    ) -> Result<(), JournalError> {
        self.journal.ensure_protected_authority()?;
        self.validate_transaction_namespaces(std::slice::from_ref(transaction))?;
        if !self.journal.instance.same_original_v1(&before.instance)
            || before.namespace != self.namespace
        {
            return Err(JournalError::Mechanical(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::StaleAuthoritySnapshot));
        }
        gate.require_own_append(self.journal, before.sequence, transaction, result)
    }

    fn validate_transaction_namespaces(
        &self,
        transactions: &[super::JournalTransaction],
    ) -> Result<(), JournalError> {
        for transaction in transactions {
            if transaction.records().iter().any(|record| record.namespace() != self.namespace) {
                return Err(JournalError::foreign_namespace());
            }
        }
        Ok(())
    }
}

impl Journal {
    pub(super) fn require_cache_history_schema_v1(&self) -> Result<(), JournalError> {
        self.ensure_protected_authority()?;
        let view = self.read_view();
        require_cache_history_schema_data_v1(view.state(), view.committed_namespaces())
    }
}

pub(super) fn require_cache_history_schema_data_v1(
    state: &super::policy::State,
    namespaces: &std::collections::BTreeSet<RecordNamespace>,
) -> Result<(), JournalError> {
    let namespace = RecordNamespace::DesiredState;
    aos_sandbox_protocol::domain_ledger::capacity_family::family::require_legacy_reservations(
        state,
    )
    .map_err(JournalError::from)?;
    let foreign_history = namespaces.iter().any(|actual| {
        *actual != namespace && *actual != RecordNamespace::GlobalCapacityReservation
    });
    let foreign_state = state.keys().any(|(actual, _)| {
        *actual != namespace && *actual != RecordNamespace::GlobalCapacityReservation
    });
    if foreign_history
        || foreign_state
        || !aos_sandbox_protocol::domain_ledger::capacity_family::all_reservations_owned_by(
            state,
            namespace,
        )
        .map_err(JournalError::from)?
    {
        return Err(JournalError::foreign_namespace());
    }
    Ok(())
}
