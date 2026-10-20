//! Projects the same completed fixed readonly prefix through canonical DATA folds.
//!
//! These queries borrow this owner and use the sole existing historical codecs
//! and family reducers. They perform no native IO and grant no mutation, peer
//! currentness or receiving permission. The Source connection retains its paid
//! original and independent native posts around every signing operation.

use aos_sandbox_core::{ProjectId, RecordNamespace};
use aos_sandbox_ledger_replay::replay::{source_tree_genesis, source_tree_successor};
use aos_sandbox_protocol::domain_ledger::{
    source_policy_hold::{SourceDomainPolicyHoldV1, SourceDomainPolicyV8PendingSettlementV1},
    source_project_history::{SourceProjectAdmissionChallengeV1,
        SourceProjectAdmissionReservationV1, SourceProjectAdmissionTerminalV1},
};

use super::{JournalError, SourceReadonlyNativeOriginalV1};

impl SourceReadonlyNativeOriginalV1 {
    pub(in crate::signer) fn get(&self, namespace: RecordNamespace, key: &[u8]) -> Option<&[u8]> {
        self.replay.state()?.get(&(namespace, key.to_vec())).map(Vec::as_slice)
    }

    pub(in crate::signer) fn all_records(&self)
        -> impl Iterator<Item = (RecordNamespace, &[u8], &[u8])>
    {
        self.replay.state().into_iter().flat_map(|state| state.iter())
            .map(|((namespace, key), value)| (*namespace, key.as_slice(), value.as_slice()))
    }

    pub(in crate::signer) fn source_domain_challenge_v1(&self)
        -> Result<Option<aos_sandbox_ledger_replay::source_domain_challenge::SourceDomainChallengeDataV1>, JournalError>
    {
        self.get(RecordNamespace::DesiredState,
            aos_sandbox_ledger_replay::source_domain_challenge::KEY)
            .map(|bytes| aos_sandbox_ledger_replay::source_domain_challenge::SourceDomainChallengeDataV1::decode(bytes)
                .map_err(|_| JournalError::ProtectedBoundary)).transpose()
    }

    pub(in crate::signer) fn source_domain_policy_hold_v1(&self)
        -> Result<Option<SourceDomainPolicyHoldV1>, JournalError>
    {
        aos_sandbox_ledger_replay::source_policy_hold::current(self.state()?)
            .map_err(|_| JournalError::ProtectedBoundary)
    }

    pub(in crate::signer) fn source_domain_policy_v8_pending_settlement_v1(&self)
        -> Result<Option<SourceDomainPolicyV8PendingSettlementV1>, JournalError>
    {
        aos_sandbox_ledger_replay::source_policy_hold::current_with_v8_pending(self.state()?)
            .map(|(_, pending)| pending).map_err(|_| JournalError::ProtectedBoundary)
    }

    pub(in crate::signer) fn source_tree_genesis_rows_v1(&self)
        -> Result<source_tree_genesis::SourceGenesisRowsV1, JournalError>
    {
        source_tree_genesis::current_rows(self.state()?)
    }

    pub(in crate::signer) fn source_first_successor_rows_v2(&self)
        -> Result<source_tree_successor::SourceFirstSuccessorRowsV2, JournalError>
    {
        source_tree_successor::current_rows(self.state()?)
    }

    pub(in crate::signer) fn source_project_continuation_rows_v3(&self, selected: Option<ProjectId>)
        -> Result<source_tree_successor::SourceFirstSuccessorRowsV2, JournalError>
    {
        source_tree_successor::current_project_rows_v3(self.state()?, selected)
    }

    pub(in crate::signer) fn source_project_genesis_data_v3(&self, selected: ProjectId)
        -> Result<source_tree_successor::SourceProjectFamilyDataV3, JournalError>
    {
        source_tree_successor::current_project_genesis_data_v3(self.state()?, selected)
    }

    pub(in crate::signer) fn source_project_admission_terminal_v1(&self)
        -> Result<Option<SourceProjectAdmissionTerminalV1>, JournalError>
    {
        aos_sandbox_ledger_replay::source_project_readback::current_rows(self.state()?)
            .map(|rows| rows.terminal()).map_err(|_| JournalError::ProtectedBoundary)
    }

    pub(in crate::signer) fn source_project_admission_reservation_status_v1(&self)
        -> Result<Option<(SourceProjectAdmissionReservationV1, bool)>, JournalError>
    {
        aos_sandbox_ledger_replay::source_project_readback::current_rows(self.state()?)
            .map(|rows| rows.reservation().map(|row| (row, rows.cancellation().is_some())))
            .map_err(|_| JournalError::ProtectedBoundary)
    }

    pub(in crate::signer) fn source_project_admission_reservation_v1(&self)
        -> Result<Option<SourceProjectAdmissionReservationV1>, JournalError>
    {
        aos_sandbox_ledger_replay::source_project_readback::current_rows(self.state()?)
            .map(|rows| rows.reservation()).map_err(|_| JournalError::ProtectedBoundary)
    }

    pub(in crate::signer) fn source_project_admission_status_v1(&self)
        -> Result<Option<(SourceProjectAdmissionChallengeV1, bool)>, JournalError>
    {
        aos_sandbox_ledger_replay::source_project_readback::current_rows(self.state()?)
            .map(|rows| rows.challenge().map(|row| (row, rows.settlement().is_some())))
            .map_err(|_| JournalError::ProtectedBoundary)
    }
}
