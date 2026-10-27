//! Preserves the real successor preview and its conservative remaining suffix.
//!
//! Only the actual ordinary Root session constructs these private borrowers.
//! The zero archive below measures capacity before a Source receipt exists; it
//! never enters the archive decoder, a semantic transition or native append.

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Mechanical;
use aos_sandbox_broker::domain_transaction_custody::pressure::{
    CapacityDeletionSelectorDataV1, validate_reserved_capacity_data_v1,
};
use aos_sandbox_model::RecordNamespace;
use aos_sandbox_journal::materialized::{self, RecordMutationRef};
use aos_sandbox_ledger_replay::replay::phase_records::RootFirstSourceSuccessorIntentV2;
use aos_sandbox_ledger_replay::replay::root_original_inventory::materialize;
use aos_sandbox_ledger_replay::replay::source_tree_successor::{
    FirstSourceSuccessorNativePhaseV2 as Phase, require_sequence_headroom, transaction_id,
};
use aos_sandbox_protocol::domain_ledger::transaction::{
    JournalRecord, JournalTransaction, encoded_transaction_append_bytes, validate_transaction,
};

use crate::native::{PolicyNativeJournalErrorV1 as NativeError, journal::RootPolicyJournalV1};

use super::super::names::{RootAuthorityNameRecipeV1, RootAuthorityNamesOriginalV1};
use super::RootSourceGenesisAuthorityV1;
use super::native_cut::RootGenesisNativeCrossingOriginalV1;

// This is an advisory borrower of actual native custody, not a saved phase
// token. Its sole constructor remains in the actual Root session below.
pub(in crate::native) struct RootSuccessorAdvisoryCutV1<'original> {
    context: &'original RootFirstSourceSuccessorIntentV2,
    transaction: &'original JournalTransaction,
    phase: Phase,
    native: &'original mut RootGenesisNativeCrossingOriginalV1,
}

impl RootSuccessorAdvisoryCutV1<'_> {
    pub(in crate::native) fn require_before_models_v1(
        &self,
        journal: &RootPolicyJournalV1,
        transactions: &[JournalTransaction],
    ) -> Result<(), NativeError> {
        if transactions != std::slice::from_ref(self.transaction)
            || !matches!(
                self.phase,
                Phase::RootPrepared
                    | Phase::RootAnchor
                    | Phase::MixedRootPrepared
                    | Phase::MixedRootAnchor
            )
            || self.transaction.id() != &transaction_id(self.context.approval(), self.phase)
        {
            return Err(NativeError::boundary());
        }
        journal.ensure_healthy()
    }

    pub(in crate::native) fn first_phase_data_v1(&self) -> Phase {
        self.phase
    }

    pub(in crate::native) fn require_family_owner_v1(
        &mut self,
        journal: &RootPolicyJournalV1,
    ) -> Result<(), NativeError> {
        self.native
            .family_owner
            .observe_transient_once_v1(journal, RootAuthorityNameRecipeV1::Owner)
            .map_err(|()| NativeError::boundary())
    }

    pub(in crate::native) fn require_source_transition_v1(
        &self,
        state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        transaction: &JournalTransaction,
    ) -> Result<Option<[u8; 32]>, NativeError> {
        aos_sandbox_ledger_replay::replay::source_tree_successor::require_transition::<
            Mechanical,
            aos_sandbox_protocol::domain_ledger::DomainLedgerDataError,
            aos_sandbox_ledger_replay::genesis::SourceGenesisReceiptDataErrorV1,
        >(state, transaction, Some(self.phase))
        .map_err(NativeError::from)
    }
}

impl RootSourceGenesisAuthorityV1 {
    pub(super) fn preflight_successor_v1(
        &self,
        transaction: &JournalTransaction,
        context: &RootFirstSourceSuccessorIntentV2,
        phase: Phase,
        native: &mut RootGenesisNativeCrossingOriginalV1,
    ) -> Result<(), NativeError> {
        let mut original = RootSuccessorAdvisoryCutV1 {
            context,
            transaction,
            phase,
            native,
        };
        self.authority
            .journal
            .preflight_genesis_successor_v1(std::slice::from_ref(transaction), &mut original)
    }

    pub(super) fn preflight_successor_shape_v1(
        &self,
        prepared: &JournalTransaction,
        intent: &RootFirstSourceSuccessorIntentV2,
        phase: Phase,
        before: &mut RootAuthorityNamesOriginalV1,
        advisory: &mut RootGenesisNativeCrossingOriginalV1,
        after: &mut RootAuthorityNamesOriginalV1,
    ) -> Result<(), NativeError> {
        before
            .observe_transient_once_v1(&self.authority.journal, RootAuthorityNameRecipeV1::Owner)
            .map_err(|()| NativeError::boundary())?;
        self.preflight_successor_v1(prepared, intent, phase, advisory)?;
        let [intent_record, reservation] = prepared.records() else {
            return Err(NativeError::boundary());
        };
        if intent_record.value() != Some(intent.as_bytes()) {
            return Err(Mechanical::AuthorityPreflightMismatch.into());
        }
        let (_, admission, capacity_id) = aos_sandbox_protocol::domain_ledger::capacity_family::decode_capacity_reservation_request_v1(reservation)
            .map_err(Mechanical::from)?;
        if &admission != prepared.id() {
            return Err(Mechanical::AuthorityPreflightMismatch.into());
        }
        let suffix = JournalTransaction::new(
            transaction_id(intent.approval(), Phase::RootAnchor),
            vec![
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    [
                        b"\0aos-root-first-source-successor-v2\0floor\0".as_slice(),
                        intent.project().as_bytes(),
                    ]
                    .concat(),
                    vec![0; 688 + intent.as_bytes().len()],
                ),
                JournalRecord::delete(RecordNamespace::DesiredState, intent_record.key().to_vec()),
                JournalRecord::delete(
                    RecordNamespace::GlobalCapacityReservation,
                    reservation.key().to_vec(),
                ),
            ],
        )
        .map_err(Mechanical::from)?;
        let journal = &self.authority.journal;
        let view = journal.read_view();
        let limits = journal.limits();
        validate_transaction(&suffix, limits).map_err(Mechanical::from)?;
        if suffix.id() == prepared.id() || view.transaction_ids().contains(suffix.id()) {
            return Err(Mechanical::DuplicateTransaction.into());
        }

        let after_prepared = materialize(view.state(), prepared);
        let prefix_bytes = materialized::validate_change(
            view.state(),
            view.materialized_bytes(),
            prepared.records().iter().map(RecordMutationRef::from),
            limits.maximum_materialized_bytes,
            limits.maximum_materialized_records,
        )
        .map_err(Mechanical::from)?;
        let terminal_bytes = materialized::validate_change(
            &after_prepared,
            prefix_bytes,
            suffix.records().iter().map(RecordMutationRef::from),
            limits.maximum_materialized_bytes,
            limits.maximum_materialized_records,
        )
        .map_err(Mechanical::from)?;
        let prefix_append_bytes =
            encoded_transaction_append_bytes(prepared).map_err(Mechanical::from)?;
        let suffix_append_bytes =
            encoded_transaction_append_bytes(&suffix).map_err(Mechanical::from)?;
        let journal_bytes = view
            .metadata()?
            .len()
            .checked_add(prefix_append_bytes)
            .and_then(|bytes| bytes.checked_add(suffix_append_bytes))
            .ok_or(Mechanical::JournalTooLarge)?;
        if journal_bytes > limits.maximum_journal_bytes {
            return Err(Mechanical::JournalTooLarge.into());
        }
        let transactions = view
            .committed_transactions()
            .checked_add(2)
            .ok_or(Mechanical::LimitExceeded("committed transaction count"))?;
        if transactions > limits.maximum_transactions {
            return Err(Mechanical::LimitExceeded("committed transaction count").into());
        }
        validate_reserved_capacity_data_v1(
            &after_prepared,
            terminal_bytes,
            suffix.records(),
            CapacityDeletionSelectorDataV1::Reservation(Some(capacity_id)),
            journal_bytes,
            transactions,
            limits,
        )
        .map_err(Mechanical::from)?;

        let prefix_frames = u64::try_from(prepared.records().len())
            .map_err(|_| Mechanical::SequenceExhausted)?
            .checked_add(2)
            .ok_or(Mechanical::SequenceExhausted)?;
        let terminal_frames = u64::try_from(suffix.records().len())
            .map_err(|_| Mechanical::SequenceExhausted)?
            .checked_add(2)
            .ok_or(Mechanical::SequenceExhausted)?;
        let next = view
            .next_sequence()
            .checked_add(prefix_frames)
            .and_then(|sequence| sequence.checked_add(terminal_frames))
            .ok_or(Mechanical::SequenceExhausted)?;
        let after_terminal = materialize(&after_prepared, &suffix);
        require_sequence_headroom(&after_terminal, next).map_err(NativeError::from)?;
        after
            .observe_transient_once_v1(journal, RootAuthorityNameRecipeV1::Owner)
            .map_err(|()| NativeError::boundary())
    }
}
