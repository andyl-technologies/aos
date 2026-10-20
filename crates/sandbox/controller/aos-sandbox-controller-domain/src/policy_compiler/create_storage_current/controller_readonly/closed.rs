//! Extends the exact previously read Controller suffix through committed U/C10.
//!
//! Expected transactions are comparison DATA reconstructed with the sole
//! codecs from actual captured state. The second full semantic/native pass
//! must observe these exact COMMITs and all preceding accepted history.

use sha2::{Digest as _, Sha256};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1, OwnerV1, KeyV1, PhaseV1, RecordEnvelopeV1,
    continuation::ContinuationKindV1,
    outcome::HandoffRetainedBodyDataV1,
};
use aos_sandbox_protocol::domain_ledger::resource_bank::{CreateStorageUseBindingV1, claim_bytes};
use crate::journal::{JournalTransaction, JournalError, RecordNamespace};
use super::super::{RootCreateStorageCurrentErrorV1 as Error,
    closed::input::RootReleaseInputV1, outcome::RootCurrentOutcomeStateV1,
    use_reserved::RootCurrentUseReservedStateV1};

type State = std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

#[derive(Default)]
pub(crate) struct RootControllerClosedSuffixDataV1 {
    commit: Option<Result<JournalTransaction, Box<dyn std::error::Error>>>,
    handoff: Option<Result<JournalTransaction, JournalError>>,
    positions: [(u64, u64); 3],
    committed_claim: Option<[u8; 32]>,
    primary: Option<Result<(), Box<dyn std::error::Error>>>,
    closed: bool,
}

impl RootControllerClosedSuffixDataV1 {
    pub(super) fn observe_once(&mut self, state: &State, lane: [u8; 16],
        reserved: &RootCurrentUseReservedStateV1, outcome: &RootCurrentOutcomeStateV1,
        input: &RootReleaseInputV1,
    ) -> Result<(), Error> {
        if self.primary.is_some() || self.closed { self.closed = true; return Err(Error::Original); }
        self.primary = Some(self.observe_inner(state, lane, reserved, outcome, input));
        self.require_complete_v1()
    }

    fn observe_inner(&mut self, state: &State, lane: [u8; 16],
        reserved: &RootCurrentUseReservedStateV1, outcome: &RootCurrentOutcomeStateV1,
        input: &RootReleaseInputV1,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let previous = outcome.completed_controller_v1()?.outcome_suffix_v1()?;
        let expected = previous.expected_v1()?;
        for transaction in expected {
            for record in transaction.records().iter().take(1) {
                if state.get(&(record.namespace(), record.key().to_vec())).map(Vec::as_slice) != record.value() {
                    return Err(Box::new(JournalError::ProtectedBoundary));
                }
            }
        }
        let original = reserved.received_original_v1()?.receipt_v1(lane)?;
        let body = original.body(lane)?;
        let binding = CreateStorageUseBindingV1::decode(body.binding)?;
        self.commit = Some(body.expected_commit_transaction_v1(state).map_err(|cause| Box::new(cause) as _));
        let commit = positive(&self.commit)?;
        self.positions[0] = previous.positions_v1()?[4];
        self.positions[1] = (self.positions[0].0.checked_add(4).ok_or(JournalError::SequenceExhausted)?,
            self.positions[0].1.checked_add(crate::journal::encoded_transaction_append_bytes(commit)?)
                .ok_or(JournalError::JournalTooLarge)?);
        let actual = input.controller_receipt_v1(lane)?;
        let record = actual.record_data(lane, ContinuationKindV1::HandoffRetained)?;
        let handoff = HandoffRetainedBodyDataV1::decode(record.body())?;
        let current_claim = claim_bytes(state, binding.claim_id()).ok_or(JournalError::ProtectedBoundary)?;
        let claim_digest: [u8; 32] = Sha256::digest(current_claim).into();
        if actual.names != original.names || handoff.bank_names != original.names
            || (handoff.bank_after_next, handoff.bank_after_end) != self.positions[1]
            || handoff.bank_commit != *commit.id() || handoff.bank_commit != binding.commit_transaction_id()?
            || handoff.use_binding != <[u8; 32]>::from(Sha256::digest(body.binding))
            || handoff.committed_use_claim != claim_digest
        { return Err(Box::new(JournalError::ProtectedBoundary)); }
        let c9 = expected[3].records().first().and_then(|record| record.value())
            .ok_or(JournalError::ProtectedBoundary)?;
        let c9 = RecordEnvelopeV1::decode(c9, KeyV1::new(lane, OwnerV1::Controller, 9)?,
            PhaseV1::new(OwnerV1::Controller, 8)?)?;
        if record.coordinates().predecessor != c9.checksum()
            || record.coordinates().correlation != c9.coordinates().correlation
        { return Err(Box::new(JournalError::ProtectedBoundary)); }
        self.handoff = Some(crate::journal::create_storage_history::prepare_readonly_history_pair_v1(
            KeyV1::new(lane, OwnerV1::Controller, 10)?, PhaseV1::new(OwnerV1::Controller, 9)?,
            actual.record, &actual.latest_head));
        let transaction = positive(&self.handoff)?;
        self.positions[2] = (self.positions[1].0.checked_add(4).ok_or(JournalError::SequenceExhausted)?,
            self.positions[1].1.checked_add(crate::journal::encoded_transaction_append_bytes(transaction)?)
                .ok_or(JournalError::JournalTooLarge)?);
        if self.positions[2] != (actual.after_next, actual.after_end) {
            return Err(Box::new(JournalError::ProtectedBoundary));
        }
        self.committed_claim = Some(claim_digest);
        Ok(())
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), Error> {
        if !self.closed && matches!(self.primary, Some(Ok(()))) && self.committed_claim.is_some()
            && matches!(self.commit, Some(Ok(_))) && matches!(self.handoff, Some(Ok(_))) { Ok(()) }
        else { Err(Error::History) }
    }

    pub(crate) fn expected_v1(&self) -> Result<[&JournalTransaction; 2], Error> {
        self.require_complete_v1()?;
        Ok([positive(&self.commit).map_err(|_| Error::History)?, positive(&self.handoff).map_err(|_| Error::History)?])
    }

    pub(crate) fn positions_v1(&self) -> Result<[(u64, u64); 3], Error> {
        self.require_complete_v1()?;
        Ok(self.positions)
    }

    pub(crate) fn committed_claim_v1(&self) -> Result<[u8; 32], Error> {
        self.require_complete_v1()?;
        self.committed_claim.ok_or(Error::History)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.commit.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause.as_ref())
            .or_else(|| self.handoff.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.primary.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
    }
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    value.as_ref().and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
}
