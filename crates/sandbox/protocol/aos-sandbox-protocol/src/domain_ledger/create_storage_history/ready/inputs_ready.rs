//! Frames the actual completed B index in a first InputsReady history body.
//!
//! ```text
//! AOSXIR01 | accepted-association[192] | AssignmentPlanned-checksum[32] |
//! existing-Ready-commitment[32] | complete-encoded-B-length:u64be
//! ```
//!
//! Controller revision3/phase2 follows its actual revision2/phase12 assignment.
//! The complete original B stays in its producing flight. This fixed index
//! contains no future commit coordinates and cannot restore that live owner.

use super::{ReadyBundleDataV1, ready_commitment_v1};
use super::super::{
    HEAD_BYTES, HistoryErrorV1, KeyV1, LatestHeadV1, OwnerV1, PhaseV1,
    RECORD_OVERHEAD_BYTES, RecordEnvelopeV1, nonzero, reader,
};
use super::super::association::AcceptedAssociationDataV1;
use super::super::source_held::SourceHeldReceiptDataV1;
use super::super::super::protected_names::ProtectedJournalNamesV1;

/// Holds the exact fixed first InputsReady body width.
pub const INPUTS_READY_BODY_BYTES_V1: usize = 272;

/// Carries the complete B association as historical comparison data.
///
/// A decoded index grants no receiving budget, Root validation, use claim or
/// permission to reconstruct or discard the original producing flight.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputsReadyBodyDataV1 {
    /// The unchanged accepted Create association from the original Source Held.
    pub association: AcceptedAssociationDataV1,
    /// The checksum of the exact preceding AssignmentPlanned record.
    pub assignment_planned: [u8; 32],
    /// The existing V1 commitment of every exact byte of complete B.
    pub ready: [u8; 32],
    /// The complete original encoded B width, excluding this fixed index.
    pub bundle_bytes: u64,
}

impl InputsReadyBodyDataV1 {
    /// Derives the fixed index from one complete structurally valid original B.
    ///
    /// This operation borrows all existing codecs and performs no allocation,
    /// typed policy decode, signature validation, IO or authority construction.
    ///
    /// # Errors
    /// Rejects malformed B framing or historical association and size overflow.
    pub fn from_bundle(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let bundle = ReadyBundleDataV1::decode(bytes)?;
        let source = SourceHeldReceiptDataV1::decode(bundle.source_held, bundle.lane)?;
        let assignment = RecordEnvelopeV1::decode(bundle.assignment_planned,
            KeyV1::new(bundle.lane, OwnerV1::Controller, 2)?,
            PhaseV1::new(OwnerV1::Controller, 12)?)?;
        let value = Self {
            association: source.body(bundle.lane)?.association(),
            assignment_planned: assignment.checksum(),
            ready: ready_commitment_v1(bytes),
            bundle_bytes: u64::try_from(bytes.len()).map_err(|_| HistoryErrorV1::Extent)?,
        };
        value.validate()?;
        Ok(value)
    }

    /// Decodes exactly the fixed index without reconstructing its live B owner.
    ///
    /// # Errors
    /// Rejects wrong magic or extent, zero commitments or an empty B width.
    pub fn decode(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        if input.array::<8>()? != *b"AOSXIR01" {
            return Err(HistoryErrorV1::Malformed);
        }
        let value = Self {
            association: AcceptedAssociationDataV1::decode(input.bytes(192)?)?,
            assignment_planned: input.array()?,
            ready: input.array()?,
            bundle_bytes: input.u64()?,
        };
        input.finish()?;
        value.validate()?;
        Ok(value)
    }

    /// Encodes the complete fixed index without allocating.
    ///
    /// # Errors
    /// Rejects malformed association, zero commitments or an empty B width.
    pub fn encode(self) -> Result<[u8; INPUTS_READY_BODY_BYTES_V1], HistoryErrorV1> {
        self.validate()?;
        let mut bytes = [0; INPUTS_READY_BODY_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSXIR01");
        bytes[8..200].copy_from_slice(&self.association.encode()?);
        bytes[200..232].copy_from_slice(&self.assignment_planned);
        bytes[232..264].copy_from_slice(&self.ready);
        bytes[264..272].copy_from_slice(&self.bundle_bytes.to_be_bytes());
        Ok(bytes)
    }

    /// Compares every indexed field with the exact supplied complete B.
    ///
    /// # Errors
    /// Rejects malformed B or any association, assignment, digest or width change.
    pub fn require_bundle(self, bytes: &[u8]) -> Result<(), HistoryErrorV1> {
        if self != Self::from_bundle(bytes)? {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(())
    }

    fn validate(self) -> Result<(), HistoryErrorV1> {
        self.association.encode()?;
        nonzero(&self.assignment_planned)?;
        nonzero(&self.ready)?;
        if self.bundle_bytes == 0 {
            return Err(HistoryErrorV1::Extent);
        }
        Ok(())
    }
}

/// Holds the fixed complete InputsReady history record width.
pub const INPUTS_READY_RECORD_BYTES_V1: usize = RECORD_OVERHEAD_BYTES + INPUTS_READY_BODY_BYTES_V1;
/// Holds its exact atomic-head and returned native comparison receipt width.
pub const INPUTS_READY_RECEIPT_BYTES_V1: usize = INPUTS_READY_RECORD_BYTES_V1 + HEAD_BYTES + 64;

/// Borrows the actual InputsReady return as historical comparison data.
///
/// This receipt alone authenticates no Native append or current Controller.
/// Root must independently replay the fixed Controller location and compare
/// these exact records, names, NEXT and durable end under its own original.
#[derive(Clone, Copy)]
pub struct InputsReadyNativeReceiptDataV1<'record> {
    /// The exact phase2/revision3 record retained by the actual producer.
    pub record: &'record [u8; INPUTS_READY_RECORD_BYTES_V1],
    /// The latest head atomically appended with that record.
    pub latest_head: [u8; HEAD_BYTES],
    /// The actual unchanged Controller protected physical names.
    pub names: ProtectedJournalNamesV1,
    /// Its actual returned and independently read-back NEXT.
    pub after_next: u64,
    /// Its actual returned and independently read-back durable end.
    pub after_end: u64,
}

impl<'record> InputsReadyNativeReceiptDataV1<'record> {
    /// Checks the exact fixed receipt and record/head correlation.
    ///
    /// # Errors
    /// Rejects malformed extent, record, body, atomic head, seed, names or zero
    /// native coordinates. No native membership or currentness is established.
    pub fn decode(bytes: &'record [u8], lane: [u8; 16]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        let value = Self {
            record: input.bytes(INPUTS_READY_RECORD_BYTES_V1)?.try_into()
                .map_err(|_| HistoryErrorV1::Extent)?,
            latest_head: input.array()?,
            names: ProtectedJournalNamesV1::from_bytes(input.bytes(48)?)
                .map_err(|_| HistoryErrorV1::Malformed)?,
            after_next: input.u64()?, after_end: input.u64()?,
        };
        input.finish()?;
        value.body(lane)?;
        Ok(value)
    }

    /// Borrows the checked fixed index without reconstructing a live B owner.
    ///
    /// # Errors
    /// Rejects invalid phase/revision/head, seed or native coordinate grammar.
    pub fn body(self, lane: [u8; 16]) -> Result<InputsReadyBodyDataV1, HistoryErrorV1> {
        let key = KeyV1::new(lane, OwnerV1::Controller, 3)?;
        let record = RecordEnvelopeV1::decode(self.record, key,
            PhaseV1::new(OwnerV1::Controller, 2)?)?;
        let body = InputsReadyBodyDataV1::decode(record.body())?;
        let latest = KeyV1::new(lane, OwnerV1::Controller, 0)?;
        LatestHeadV1::decode(&self.latest_head, latest)?.check_record(latest, record)?;
        ProtectedJournalNamesV1::from_bytes(&self.names.to_bytes())
            .map_err(|_| HistoryErrorV1::Malformed)?;
        if record.coordinates().correlation != body.association.seed
            || record.coordinates().predecessor != body.assignment_planned
            || self.after_next == 0 || self.after_end == 0 {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(body)
    }

    /// Compares the exact original B and its included AssignmentPlanned predecessor.
    ///
    /// # Errors
    /// Rejects malformed B or a different lane, index, assignment or predecessor.
    pub fn require_bundle(self, bytes: &[u8]) -> Result<(), HistoryErrorV1> {
        let bundle = ReadyBundleDataV1::decode(bytes)?;
        self.body(bundle.lane)?.require_bundle(bytes)?;
        let intent = super::IntentNativeReceiptDataV1::decode(bundle.intent_native_receipt)?;
        if self.names != intent.names || self.after_next <= intent.after_next
            || self.after_end <= intent.after_end {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(())
    }

    /// Writes this complete checked fixed receipt without allocating.
    ///
    /// # Errors
    /// Rejects the same invalid record/head/native framing as [`Self::body`].
    pub fn encode(self, lane: [u8; 16]) -> Result<[u8; INPUTS_READY_RECEIPT_BYTES_V1], HistoryErrorV1> {
        self.body(lane)?;
        let mut bytes = [0; INPUTS_READY_RECEIPT_BYTES_V1];
        let record_end = INPUTS_READY_RECORD_BYTES_V1;
        bytes[..record_end].copy_from_slice(self.record);
        bytes[record_end..record_end + HEAD_BYTES].copy_from_slice(&self.latest_head);
        bytes[record_end + HEAD_BYTES..record_end + HEAD_BYTES + 48].copy_from_slice(&self.names.to_bytes());
        bytes[record_end + HEAD_BYTES + 48..record_end + HEAD_BYTES + 56]
            .copy_from_slice(&self.after_next.to_be_bytes());
        bytes[record_end + HEAD_BYTES + 56..].copy_from_slice(&self.after_end.to_be_bytes());
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_index_rejects_truncation_zero_width_and_non_bundle_reconstruction() {
        let value = InputsReadyBodyDataV1 {
            association: AcceptedAssociationDataV1 {
                operation: [1; 16], project: [2; 16], sandbox: [3; 16],
                accepted_request: [4; 32], coissuance_binding: [5; 32], seed: [6; 32],
                controller_nonce: [7; 16], boot: [8; 16], started: 9, cutoff: 10,
            },
            assignment_planned: [11; 32], ready: [12; 32], bundle_bytes: 13,
        };
        let bytes = value.encode().unwrap();

        assert_eq!(InputsReadyBodyDataV1::decode(&bytes).unwrap(), value);
        assert!(InputsReadyBodyDataV1::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut changed = bytes;
        changed[264..].fill(0);
        assert!(InputsReadyBodyDataV1::decode(&changed).is_err());
        assert!(value.require_bundle(b"not-an-original-B").is_err());
    }
}
