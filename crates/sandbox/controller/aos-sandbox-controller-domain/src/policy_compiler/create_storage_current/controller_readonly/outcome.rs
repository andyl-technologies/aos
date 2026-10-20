//! Checks the actual native Controller continuation through C9 before Root5.
//!
//! The first canonical pass supplies these borrowed rows. Their exact expected
//! transactions then constrain the second same-file role replay at every native
//! COMMIT; a receipt alone never establishes the Controller suffix.

use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    KeyV1, OwnerV1, PhaseV1, RecordEnvelopeV1, LatestHeadV1,
    continuation::{ContinuationKindV1, ContinuationNativeReceiptDataV1,
        SignedPreparationBundleDataV1, UseAdmittedBodyDataV1},
    controller_use::{ControllerSignedBodyDataV1, ControllerDispatchBoundBodyDataV1,
        ControllerSessionReservedBodyDataV1},
    outcome::ControllerOutcomeBodyDataV1,
};
use crate::journal::{JournalError, JournalTransaction, RecordNamespace};
use crate::journal::create_storage_history::prepare_readonly_history_pair_v1;
use super::super::{RootCreateStorageCurrentErrorV1 as Error,
    signed_bound::RootCurrentSignedBoundStateV1, use_admitted::RootCurrentUseAdmittedStateV1,
    use_reserved::received::RootCurrentUseReservedReceivedV1};

pub(crate) struct RootControllerOutcomeSuffixDataV1 {
    expected: [Option<Result<JournalTransaction, JournalError>>; 4],
    positions: [(u64, u64); 5],
    session: Option<ControllerSessionReservedBodyDataV1>,
    outcome: Option<ControllerOutcomeBodyDataV1>,
    primary: Option<Result<(), Box<dyn std::error::Error>>>,
    closed: bool,
}

impl Default for RootControllerOutcomeSuffixDataV1 {
    fn default() -> Self {
        Self { expected: std::array::from_fn(|_| None), positions: [(0, 0); 5],
            session: None, outcome: None, primary: None, closed: false }
    }
}

impl RootControllerOutcomeSuffixDataV1 {
    pub(super) fn observe_once(&mut self,
        state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        lane: [u8; 16], signed: &RootCurrentSignedBoundStateV1,
        admitted: &RootCurrentUseAdmittedStateV1, reserved: &RootCurrentUseReservedReceivedV1,
        receipt: ContinuationNativeReceiptDataV1<'_>,
    ) -> Result<(), Error> {
        if self.primary.is_some() || self.closed { self.closed = true; return Err(Error::Original); }
        self.primary = Some(self.observe_inner(state, lane, signed, admitted, reserved, receipt));
        self.require_complete_v1()
    }

    fn observe_inner(&mut self,
        state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        lane: [u8; 16], root_signed: &RootCurrentSignedBoundStateV1,
        root_admitted: &RootCurrentUseAdmittedStateV1, reserved: &RootCurrentUseReservedReceivedV1,
        receipt: ContinuationNativeReceiptDataV1<'_>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let original_signed = root_signed.completed_bundle_v1()?;
        let original_admitted = root_admitted.completed_receipt_v1()?;
        let original_bound = root_signed.completed_receipt_v1()?;
        // C5 is the actual preceding suffix receipt, not RootValidated's C4.
        let prior = RecordEnvelopeV1::decode(reserved.receipt_v1(lane)?.record,
            KeyV1::new(lane, OwnerV1::Controller, 5)?, PhaseV1::new(OwnerV1::Controller, 4)?)?;
        let mut predecessor = prior.checksum();
        let reserved_receipt = reserved.receipt_v1(lane)?;
        self.positions[0] = (reserved_receipt.after_next, reserved_receipt.after_end);
        let mut c6_checksum = [0; 32];
        let mut c7_checksum = [0; 32];
        for ordinal in 0..4 {
            let revision = (ordinal + 6) as u64;
            let key = KeyV1::new(lane, OwnerV1::Controller, revision)?;
            let phase = PhaseV1::new(OwnerV1::Controller, (ordinal + 5) as u8)?;
            let raw = state.get(&(RecordNamespace::CreateStorageHistory, key.encode().to_vec()))
                .ok_or(JournalError::ProtectedBoundary)?;
            let record = RecordEnvelopeV1::decode(raw, key, phase)?;
            if record.coordinates().predecessor != predecessor
                || record.coordinates().correlation != prior.coordinates().correlation
            { return Err(Box::new(JournalError::ProtectedBoundary)); }
            match ordinal {
                0 => {
                    let signed = ControllerSignedBodyDataV1::decode(record.body(), lane,
                        original_signed.encoded_bytes()?)?;
                    require_receipt(signed.admitted, original_admitted)?;
                    let bundle = signed.bundle_data_v1(lane, original_signed.encoded_bytes()?)?;
                    require_bundle(bundle, original_signed)?;
                    c6_checksum = record.checksum();
                }
                1 => {
                    let dispatch = ControllerDispatchBoundBodyDataV1::decode(record.body(), lane)?;
                    if dispatch.signed != c6_checksum { return Err(Box::new(JournalError::ProtectedBoundary)); }
                    require_receipt(dispatch.bound, original_bound)?;
                    c7_checksum = record.checksum();
                }
                2 => {
                    let session = ControllerSessionReservedBodyDataV1::decode(record.body())?;
                    if session.dispatch_bound != c7_checksum
                        || session.request_id != root_signed.completed_request_id_v1()?
                    { return Err(Box::new(JournalError::ProtectedBoundary)); }
                    self.session = Some(session);
                }
                3 => {
                    if raw.as_slice() != receipt.record { return Err(Box::new(JournalError::ProtectedBoundary)); }
                    let outcome = ControllerOutcomeBodyDataV1::decode(record.body())?;
                    let admitted = original_admitted.record_data(lane, ContinuationKindV1::UseAdmitted)?;
                    let admitted_body = UseAdmittedBodyDataV1::decode(admitted.body())?;
                    if outcome.signed_bound != original_bound.record_data(lane, ContinuationKindV1::SignedBound)?.checksum()
                        || outcome.use_admitted != admitted.checksum()
                        || outcome.use_claim != admitted_body.use_claim
                        || outcome.request_id != root_signed.completed_request_id_v1()?
                    { return Err(Box::new(JournalError::ProtectedBoundary)); }
                    self.outcome = Some(outcome);
                }
                _ => return Err(Box::new(JournalError::ProtectedBoundary)),
            }
            let head = LatestHeadV1::new(revision, record.checksum())?.encode();
            self.expected[ordinal] = Some(prepare_readonly_history_pair_v1(key, phase, raw, &head));
            let transaction = positive(&self.expected[ordinal])?;
            let bytes = crate::journal::encoded_transaction_append_bytes(transaction)?;
            let before = self.positions[ordinal];
            self.positions[ordinal + 1] = (before.0.checked_add(4).ok_or(JournalError::SequenceExhausted)?,
                before.1.checked_add(bytes).ok_or(JournalError::JournalTooLarge)?);
            predecessor = record.checksum();
        }
        if self.positions[4] != (receipt.after_next, receipt.after_end)
            || receipt.names != reserved_receipt.names
        { return Err(Box::new(JournalError::ProtectedBoundary)); }
        let key = KeyV1::new(lane, OwnerV1::Controller, 0)?.encode();
        if state.get(&(RecordNamespace::CreateStorageHistory, key.to_vec())).map(Vec::as_slice)
            != Some(receipt.latest_head.as_slice())
        { return Err(Box::new(JournalError::ProtectedBoundary)); }
        Ok(())
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), Error> {
        if !self.closed && matches!(self.primary, Some(Ok(())))
            && self.expected.iter().all(|value| matches!(value, Some(Ok(_))))
            && self.session.is_some() && self.outcome.is_some() { Ok(()) }
        else { Err(Error::History) }
    }

    pub(crate) fn expected_v1(&self) -> Result<[&JournalTransaction; 4], Error> {
        self.require_complete_v1()?;
        Ok([positive(&self.expected[0]).map_err(|_| Error::History)?,
            positive(&self.expected[1]).map_err(|_| Error::History)?,
            positive(&self.expected[2]).map_err(|_| Error::History)?,
            positive(&self.expected[3]).map_err(|_| Error::History)?])
    }

    pub(crate) fn positions_v1(&self) -> Result<[(u64, u64); 5], Error> {
        self.require_complete_v1()?;
        Ok(self.positions)
    }

    pub(crate) fn session_v1(&self) -> Result<ControllerSessionReservedBodyDataV1, Error> {
        self.require_complete_v1()?;
        self.session.ok_or(Error::History)
    }

    pub(crate) fn outcome_v1(&self) -> Result<ControllerOutcomeBodyDataV1, Error> {
        self.require_complete_v1()?;
        self.outcome.ok_or(Error::History)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.expected.iter().find_map(|value| value.as_ref()?.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.primary.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
    }
}

fn require_receipt(left: ContinuationNativeReceiptDataV1<'_>, right: ContinuationNativeReceiptDataV1<'_>)
    -> Result<(), JournalError>
{
    if left.record != right.record || left.latest_head != right.latest_head || left.names != right.names
        || left.after_next != right.after_next || left.after_end != right.after_end
    { return Err(JournalError::ProtectedBoundary); }
    Ok(())
}

fn require_bundle(left: SignedPreparationBundleDataV1<'_>, right: SignedPreparationBundleDataV1<'_>)
    -> Result<(), JournalError>
{
    if left.plan != right.plan || left.signature != right.signature || left.request_body != right.request_body {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    value.as_ref().and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
}
