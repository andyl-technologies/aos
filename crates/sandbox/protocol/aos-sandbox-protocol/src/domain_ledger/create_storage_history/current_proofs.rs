//! Frames actual Controller and independent Cache current observations.
//!
//! ```text
//! AOSXCP01 | Controller-receipt-length:u32be=516 | actual-receipt[516] |
//! Cache-signed-packet-length:u32be | actual-Cache-signed-packet
//! ```
//!
//! This is the payload of frame kind4, after complete B. Source17 is an
//! independent Root-to-Source exchange and is not copied into this container.
//! The Cache bytes retain their independent signer-owned purpose and schema;
//! this framing cannot manufacture that signer or replace its Native producer.

mod challenge;
pub use challenge::{
    CurrentProofsChallengeDataV1, CURRENT_PROOFS_CHALLENGE_BODY_BYTES_V1,
    CURRENT_PROOFS_CHALLENGE_FRAME_BYTES_V1,
};

use super::{HistoryErrorV1, reader};
use super::ready::{InputsReadyNativeReceiptDataV1, INPUTS_READY_RECEIPT_BYTES_V1};

/// Borrows exact role observations without admitting either as current authority.
#[derive(Clone, Copy)]
pub struct CurrentProofsDataV1<'packets> {
    /// The actual Controller InputsReady return/readback, independently replayed by Root.
    pub controller: InputsReadyNativeReceiptDataV1<'packets>,
    /// The real independent Cache service's exact signed new-purpose response.
    pub cache_packet: &'packets [u8],
}

impl<'packets> CurrentProofsDataV1<'packets> {
    /// Checks the exact outer framing and fixed Controller receipt grammar.
    ///
    /// Cache schema/signature/currentness and Controller Native replay belong
    /// to their actual paid independent consumers, not this borrowed container.
    ///
    /// # Errors
    /// Rejects wrong magic, Controller extent, malformed receipt, empty Cache
    /// packet, truncated fields or trailing bytes.
    pub fn decode(bytes: &'packets [u8], lane: [u8; 16]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        if input.array::<8>()? != *b"AOSXCP01" {
            return Err(HistoryErrorV1::Malformed);
        }
        let controller_bytes = usize::try_from(input.u32()?).map_err(|_| HistoryErrorV1::Extent)?;
        if controller_bytes != INPUTS_READY_RECEIPT_BYTES_V1 {
            return Err(HistoryErrorV1::Extent);
        }
        let controller = InputsReadyNativeReceiptDataV1::decode(input.bytes(controller_bytes)?, lane)?;
        let cache_bytes = usize::try_from(input.u32()?).map_err(|_| HistoryErrorV1::Extent)?;
        let cache_packet = input.bytes(cache_bytes)?;
        input.finish()?;
        let value = Self { controller, cache_packet };
        value.encoded_bytes(lane)?;
        Ok(value)
    }

    /// Measures both exact original observations without introducing a global cap.
    ///
    /// # Errors
    /// Rejects malformed Controller data, empty Cache bytes or checked wire-width
    /// overflow. The actual receiver must fund the real signer-specific width
    /// before allocation; a declared length supplies no receiving budget.
    pub fn encoded_bytes(self, lane: [u8; 16]) -> Result<usize, HistoryErrorV1> {
        self.controller.body(lane)?;
        if self.cache_packet.is_empty() {
            return Err(HistoryErrorV1::Malformed);
        }
        u32::try_from(self.cache_packet.len()).map_err(|_| HistoryErrorV1::Extent)?;
        (16_usize + INPUTS_READY_RECEIPT_BYTES_V1).checked_add(self.cache_packet.len())
            .ok_or(HistoryErrorV1::Extent)
    }

    /// Writes the exact two original fields into prepaid caller-owned storage.
    ///
    /// # Errors
    /// Rejects invalid fields or a nonexact destination before writing bytes.
    pub fn encode_into(self, lane: [u8; 16], output: &mut [u8]) -> Result<(), HistoryErrorV1> {
        if output.len() != self.encoded_bytes(lane)? {
            return Err(HistoryErrorV1::Extent);
        }
        let controller = self.controller.encode(lane)?;
        output[..8].copy_from_slice(b"AOSXCP01");
        output[8..12].copy_from_slice(&(INPUTS_READY_RECEIPT_BYTES_V1 as u32).to_be_bytes());
        let end = 12 + INPUTS_READY_RECEIPT_BYTES_V1;
        output[12..end].copy_from_slice(&controller);
        let length = u32::try_from(self.cache_packet.len()).map_err(|_| HistoryErrorV1::Extent)?;
        output[end..end + 4].copy_from_slice(&length.to_be_bytes());
        output[end + 4..].copy_from_slice(self.cache_packet);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{KeyV1, LatestHeadV1, OwnerV1, PhaseV1, RecordCoordinatesV1, RecordEnvelopeV1};
    use super::super::association::AcceptedAssociationDataV1;
    use super::super::ready::{InputsReadyBodyDataV1, INPUTS_READY_RECORD_BYTES_V1};
    use super::super::super::protected_names::ProtectedJournalNamesV1;

    #[test]
    fn actual_receipt_framing_borrows_cache_bytes_and_rejects_foreign_lane_or_head() {
        let lane = [1; 16];
        let body = InputsReadyBodyDataV1 {
            association: AcceptedAssociationDataV1 {
                operation: [2; 16], project: [3; 16], sandbox: [4; 16],
                accepted_request: [5; 32], coissuance_binding: [6; 32], seed: [7; 32],
                controller_nonce: [8; 16], boot: [9; 16], started: 10, cutoff: 11,
            },
            assignment_planned: [12; 32], ready: [13; 32], bundle_bytes: 14,
        };
        let mut record = [0; INPUTS_READY_RECORD_BYTES_V1];
        let checksum = RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
            key: KeyV1::new(lane, OwnerV1::Controller, 3).unwrap(),
            phase: PhaseV1::new(OwnerV1::Controller, 2).unwrap(),
            predecessor: body.assignment_planned, correlation: body.association.seed,
        }, &body.encode().unwrap(), &mut record).unwrap();
        let receipt = InputsReadyNativeReceiptDataV1 {
            record: &record, latest_head: LatestHeadV1::new(3, checksum).unwrap().encode(),
            names: ProtectedJournalNamesV1::from_bytes(&[1; 48]).unwrap(),
            after_next: 15, after_end: 16,
        };
        // Opaque bytes intentionally do not model a Cache signature or owner.
        // This test qualifies only the shared outer framing and receipt codec.
        let data = CurrentProofsDataV1 { controller: receipt, cache_packet: b"Cache-original" };
        let mut bytes = vec![0; data.encoded_bytes(lane).unwrap()];
        data.encode_into(lane, &mut bytes).unwrap();

        let decoded = CurrentProofsDataV1::decode(&bytes, lane).unwrap();
        assert_eq!(decoded.controller.body(lane).unwrap(), body);
        assert_eq!(decoded.cache_packet, data.cache_packet);
        assert_eq!(decoded.cache_packet.as_ptr(), bytes[16 + INPUTS_READY_RECEIPT_BYTES_V1..].as_ptr());
        assert!(CurrentProofsDataV1::decode(&bytes, [17; 16]).is_err());
        let mut changed = bytes.clone();
        changed[12 + INPUTS_READY_RECORD_BYTES_V1 + 8] ^= 1;
        assert!(CurrentProofsDataV1::decode(&changed, lane).is_err());
        assert!(CurrentProofsDataV1::decode(&bytes[..bytes.len() - 1], lane).is_err());
    }
}
