//! Derives Root4's exact C6 comparison transaction from its held originals.
//!
//! The expected bytes are DATA only. The enclosing reader independently opens
//! Controller's real journal and must replay this pair at the exact native
//! C5-to-C6 boundary before Root may append SignedBound.

use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1, KeyV1, LatestHeadV1, OwnerV1, PhaseV1, RecordCoordinatesV1,
    RecordEnvelopeV1, RECORD_OVERHEAD_BYTES,
    controller_use::ControllerSignedBodyDataV1,
};
use crate::journal::{JournalError, JournalTransaction};
use super::super::{
    RootCreateStorageCurrentErrorV1 as Error,
    signed_bound::input::RootSignedInputV1,
    use_admitted::RootCurrentUseAdmittedStateV1,
    use_reserved::received::RootCurrentUseReservedReceivedV1,
};

#[derive(Default)]
pub(super) struct RootControllerSignedSuffixDataV1 {
    expected: Option<Result<JournalTransaction, Box<dyn std::error::Error>>>,
    positions: [(u64, u64); 2],
    closed: bool,
}

impl RootControllerSignedSuffixDataV1 {
    pub(super) fn prepare_once(&mut self, lane: [u8; 16],
        reserved: &RootCurrentUseReservedReceivedV1,
        admitted: &RootCurrentUseAdmittedStateV1, input: &RootSignedInputV1,
    ) -> Result<(), Error> {
        if self.expected.is_some() || self.closed {
            self.closed = true;
            return Err(Error::Original);
        }
        self.expected = Some(self.prepare_inner(lane, reserved, admitted, input));
        self.expected_v1().map(|_| ())
    }

    fn prepare_inner(&mut self, lane: [u8; 16],
        reserved: &RootCurrentUseReservedReceivedV1,
        admitted: &RootCurrentUseAdmittedStateV1, input: &RootSignedInputV1,
    ) -> Result<JournalTransaction, Box<dyn std::error::Error>> {
        let original = reserved.receipt_v1(lane)?;
        let previous = RecordEnvelopeV1::decode(original.record,
            KeyV1::new(lane, OwnerV1::Controller, 5)?,
            PhaseV1::new(OwnerV1::Controller, 4)?)?;
        let body = ControllerSignedBodyDataV1 {
            admitted: admitted.completed_receipt_v1()?, bundle: input.completed_bytes_v1()?,
        };
        let width = input.completed_bundle_v1()?.encoded_bytes()?;
        let mut encoded = vec![0; body.encoded_bytes()?];
        body.encode_into(lane, width, &mut encoded)?;
        let key = KeyV1::new(lane, OwnerV1::Controller, 6)?;
        let phase = PhaseV1::new(OwnerV1::Controller, 5)?;
        let mut record = vec![0; RECORD_OVERHEAD_BYTES.checked_add(encoded.len())
            .ok_or(HistoryErrorV1::Extent)?];
        let checksum = RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
            key, phase, predecessor: previous.checksum(),
            correlation: previous.coordinates().correlation,
        }, &encoded, &mut record)?;
        let head = LatestHeadV1::new(6, checksum)?.encode();
        let transaction = crate::journal::create_storage_history::prepare_readonly_history_pair_v1(
            key, phase, &record, &head)?;
        let bytes = crate::journal::encoded_transaction_append_bytes(&transaction)?;
        self.positions = [(original.after_next, original.after_end),
            (original.after_next.checked_add(4).ok_or(JournalError::SequenceExhausted)?,
                original.after_end.checked_add(bytes).ok_or(JournalError::JournalTooLarge)?)];
        Ok(transaction)
    }

    pub(super) fn expected_v1(&self) -> Result<&JournalTransaction, Error> {
        if self.closed { return Err(Error::Original); }
        self.expected.as_ref().and_then(|value| value.as_ref().ok()).ok_or(Error::History)
    }

    pub(super) fn positions_v1(&self) -> Result<[(u64, u64); 2], Error> {
        self.expected_v1()?;
        Ok(self.positions)
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.expected.as_ref()?.as_ref().err().map(|cause| cause.as_ref())
    }
}
