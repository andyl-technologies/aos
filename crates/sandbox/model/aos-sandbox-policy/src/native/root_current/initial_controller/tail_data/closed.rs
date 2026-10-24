//! Extends the exact previously read Controller suffix through committed U/C10.
//!
//! Expected transactions are comparison DATA reconstructed with the sole
//! codecs from actual captured state. The second full semantic/native pass
//! must observe these exact COMMITs and all preceding accepted history.

use super::super::body::prepare_readonly_pair as prepare_readonly_history_pair_v1;
use super::super::purpose::*;
use super::super::*;
use crate::native::readonly::RootReadonlyErrorV1 as JournalError;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1, KeyV1, OwnerV1, PhaseV1, RecordEnvelopeV1, continuation::ContinuationKindV1,
    outcome::HandoffRetainedBodyDataV1,
};
use aos_sandbox_protocol::domain_ledger::resource_bank::{CreateStorageUseBindingV1, claim_bytes};
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;
use sha2::{Digest as _, Sha256};
type State = std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

#[derive(Default)]
pub(in crate::native::root_current) struct RootControllerClosedSuffixDataV1 {
    commit: Option<Result<JournalTransaction, Box<dyn std::error::Error>>>,
    handoff: Option<Result<JournalTransaction, JournalError>>,
    positions: [(u64, u64); 3],
    committed_claim: Option<[u8; 32]>,
    primary: Option<Result<(), Box<dyn std::error::Error>>>,
    closed: bool,
}

impl RootControllerClosedSuffixDataV1 {
    pub(in crate::native::root_current) fn observe_once(
        &mut self,
        state: &State,
        lane: [u8; 16],
        reserved: &RootUseReservedOriginalV1,
        outcome: &RootUseOutcomeOriginalV1,
        input: &RootReleaseInputOriginalV1,
    ) -> Result<(), E> {
        if self.primary.is_some() || self.closed {
            self.closed = true;
            return Err(E::Incomplete);
        }
        self.primary = Some(self.observe_inner(state, lane, reserved, outcome, input));
        self.require_complete_v1()
    }

    fn observe_inner(
        &mut self,
        state: &State,
        lane: [u8; 16],
        reserved: &RootUseReservedOriginalV1,
        outcome: &RootUseOutcomeOriginalV1,
        input: &RootReleaseInputOriginalV1,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let previous = outcome.completed_controller_v1()?.outcome_suffix_v1()?;
        let expected = previous.expected_v1()?;
        for transaction in expected {
            for record in transaction.records().iter().take(1) {
                if state
                    .get(&(record.namespace(), record.key().to_vec()))
                    .map(Vec::as_slice)
                    != record.value()
                {
                    return Err(Box::new(JournalError::ProtectedBoundary));
                }
            }
        }
        let original = reserved.received_original_v1()?.receipt_v1(lane)?;
        let body = original.body(lane)?;
        let binding = CreateStorageUseBindingV1::decode(body.binding)?;
        self.commit = Some(
            body.expected_commit_transaction_v1(state)
                .map_err(|cause| Box::new(cause) as _),
        );
        let commit = positive(&self.commit)?;
        self.positions[0] = previous.positions_v1()?[4];
        self.positions[1] = (self.positions[0].0.checked_add(4).ok_or(JournalError::Mechanical(Mechanical::SequenceExhausted))?,
            self.positions[0].1.checked_add(aos_sandbox_protocol::domain_ledger::transaction::encoded_transaction_append_bytes(commit)?)
                .ok_or(JournalError::JournalTooLarge)?);
        let actual = input.controller_receipt_v1(lane)?;
        let record = actual.record_data(lane, ContinuationKindV1::HandoffRetained)?;
        let handoff = HandoffRetainedBodyDataV1::decode(record.body())?;
        let current_claim =
            claim_bytes(state, binding.claim_id()).ok_or(JournalError::ProtectedBoundary)?;
        let claim_digest: [u8; 32] = Sha256::digest(current_claim).into();
        if actual.names != original.names
            || handoff.bank_names != original.names
            || (handoff.bank_after_next, handoff.bank_after_end) != self.positions[1]
            || handoff.bank_commit != *commit.id()
            || handoff.bank_commit != binding.commit_transaction_id()?
            || handoff.use_binding != <[u8; 32]>::from(Sha256::digest(body.binding))
            || handoff.committed_use_claim != claim_digest
        {
            return Err(Box::new(JournalError::ProtectedBoundary));
        }
        let c9 = expected[3]
            .records()
            .first()
            .and_then(|record| record.value())
            .ok_or(JournalError::ProtectedBoundary)?;
        let c9 = RecordEnvelopeV1::decode(
            c9,
            KeyV1::new(lane, OwnerV1::Controller, 9)?,
            PhaseV1::new(OwnerV1::Controller, 8)?,
        )?;
        if record.coordinates().predecessor != c9.checksum()
            || record.coordinates().correlation != c9.coordinates().correlation
        {
            return Err(Box::new(JournalError::ProtectedBoundary));
        }
        self.handoff = Some(prepare_readonly_history_pair_v1(
            KeyV1::new(lane, OwnerV1::Controller, 10)?,
            PhaseV1::new(OwnerV1::Controller, 9)?,
            actual.record,
            &actual.latest_head,
        ));
        let transaction = positive(&self.handoff)?;
        self.positions[2] = (self.positions[1].0.checked_add(4).ok_or(JournalError::Mechanical(Mechanical::SequenceExhausted))?,
            self.positions[1].1.checked_add(aos_sandbox_protocol::domain_ledger::transaction::encoded_transaction_append_bytes(transaction)?)
                .ok_or(JournalError::JournalTooLarge)?);
        if self.positions[2] != (actual.after_next, actual.after_end) {
            return Err(Box::new(JournalError::ProtectedBoundary));
        }
        self.committed_claim = Some(claim_digest);
        Ok(())
    }

    pub(in crate::native::root_current) fn require_complete_v1(&self) -> Result<(), E> {
        if !self.closed
            && matches!(self.primary, Some(Ok(())))
            && self.committed_claim.is_some()
            && matches!(self.commit, Some(Ok(_)))
            && matches!(self.handoff, Some(Ok(_)))
        {
            Ok(())
        } else {
            Err(E::Incomplete)
        }
    }

    pub(in crate::native::root_current) fn expected_v1(
        &self,
    ) -> Result<[&JournalTransaction; 2], E> {
        self.require_complete_v1()?;
        Ok([
            positive(&self.commit).map_err(|_| E::Incomplete)?,
            positive(&self.handoff).map_err(|_| E::Incomplete)?,
        ])
    }

    pub(in crate::native::root_current) fn positions_v1(&self) -> Result<[(u64, u64); 3], E> {
        self.require_complete_v1()?;
        Ok(self.positions)
    }

    pub(in crate::native::root_current) fn committed_claim_v1(&self) -> Result<[u8; 32], E> {
        self.require_complete_v1()?;
        self.committed_claim.ok_or(E::Incomplete)
    }

    pub(in crate::native::root_current) fn failure(
        &self,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        self.commit
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .map(|cause| cause.as_ref())
            .or_else(|| {
                self.handoff
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.primary
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
    }
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    value
        .as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or(JournalError::ProtectedBoundary)
}
