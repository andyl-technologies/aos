//! Derives Root4's exact C6 comparison transaction from its held originals.
//!
//! The expected bytes are DATA only. The enclosing reader independently opens
//! Controller's real journal and must replay this pair at the exact native
//! C5-to-C6 boundary before Root may append SignedBound.

use super::super::body::prepare_readonly_pair as prepare_readonly_history_pair_v1;
use super::super::purpose::*;
use super::super::*;
use crate::native::readonly::RootReadonlyErrorV1 as JournalError;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1, KeyV1, LatestHeadV1, OwnerV1, PhaseV1, RECORD_OVERHEAD_BYTES,
    RecordCoordinatesV1, RecordEnvelopeV1, controller_use::ControllerSignedBodyDataV1,
};
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;
#[derive(Default)]
pub(in crate::native::root_current) struct RootControllerSignedSuffixDataV1 {
    expected: Option<Result<JournalTransaction, Box<dyn std::error::Error>>>,
    positions: [(u64, u64); 2],
    closed: bool,
}

impl RootControllerSignedSuffixDataV1 {
    pub(in crate::native::root_current) fn prepare_once(
        &mut self,
        lane: [u8; 16],
        reserved: &RootUseReservedReceivedOriginalV1,
        admitted: &RootUseAdmittedOriginalV1,
        input: &RootSignedInputOriginalV1,
    ) -> Result<(), E> {
        if self.expected.is_some() || self.closed {
            self.closed = true;
            return Err(E::Incomplete);
        }
        self.expected = Some(self.prepare_inner(lane, reserved, admitted, input));
        self.expected_v1().map(|_| ())
    }

    fn prepare_inner(
        &mut self,
        lane: [u8; 16],
        reserved: &RootUseReservedReceivedOriginalV1,
        admitted: &RootUseAdmittedOriginalV1,
        input: &RootSignedInputOriginalV1,
    ) -> Result<JournalTransaction, Box<dyn std::error::Error>> {
        let original = reserved.receipt_v1(lane)?;
        let previous = RecordEnvelopeV1::decode(
            original.record,
            KeyV1::new(lane, OwnerV1::Controller, 5)?,
            PhaseV1::new(OwnerV1::Controller, 4)?,
        )?;
        let body = ControllerSignedBodyDataV1 {
            admitted: admitted.completed_receipt_v1()?,
            bundle: input.received_bytes_v1()?,
        };
        let width = input.received_bundle_v1()?.encoded_bytes()?;
        let mut encoded = vec![0; body.encoded_bytes()?];
        body.encode_into(lane, width, &mut encoded)?;
        let key = KeyV1::new(lane, OwnerV1::Controller, 6)?;
        let phase = PhaseV1::new(OwnerV1::Controller, 5)?;
        let mut record = vec![
            0;
            RECORD_OVERHEAD_BYTES
                .checked_add(encoded.len())
                .ok_or(HistoryErrorV1::Extent)?
        ];
        let checksum = RecordEnvelopeV1::encode_into(
            RecordCoordinatesV1 {
                key,
                phase,
                predecessor: previous.checksum(),
                correlation: previous.coordinates().correlation,
            },
            &encoded,
            &mut record,
        )?;
        let head = LatestHeadV1::new(6, checksum)?.encode();
        let transaction = prepare_readonly_history_pair_v1(key, phase, &record, &head)?;
        let bytes =
            aos_sandbox_protocol::domain_ledger::transaction::encoded_transaction_append_bytes(
                &transaction,
            )?;
        self.positions = [
            (original.after_next, original.after_end),
            (
                original
                    .after_next
                    .checked_add(4)
                    .ok_or(JournalError::Mechanical(Mechanical::SequenceExhausted))?,
                original
                    .after_end
                    .checked_add(bytes)
                    .ok_or(JournalError::JournalTooLarge)?,
            ),
        ];
        Ok(transaction)
    }

    pub(in crate::native::root_current) fn expected_v1(&self) -> Result<&JournalTransaction, E> {
        if self.closed {
            return Err(E::Incomplete);
        }
        self.expected
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(E::Incomplete)
    }

    pub(in crate::native::root_current) fn positions_v1(&self) -> Result<[(u64, u64); 2], E> {
        self.expected_v1()?;
        Ok(self.positions)
    }

    pub(in crate::native::root_current) fn failure(
        &self,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        self.expected
            .as_ref()?
            .as_ref()
            .err()
            .map(|cause| cause.as_ref())
    }
}
