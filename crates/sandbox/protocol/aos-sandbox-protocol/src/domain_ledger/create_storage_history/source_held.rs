//! Encodes a new Source Held row and its exact native receipt as inert DATA.
//!
//! ```text
//! body = AOSXSH01 | operation[16] | project[16] | sandbox[16] |
//!        accepted-request[32] | coissuance-binding[32] | seed[32] |
//!        Controller-nonce[16] | boot[16] | started:u64be | cutoff:u64be |
//!        Source-names[48] | Source-before-NEXT:u64be | Source-before-end:u64be
//! receipt = Source-Held-record[404] | latest-head[40] | Source-names[48] |
//!           Source-after-NEXT:u64be | Source-after-end:u64be
//! ```
//!
//! The body cannot contain its own future commit coordinates. A Native producer
//! derives the receipt only after the exact record/head atomic append, returned
//! result, readback and independent posts under the same real Source writer.
//! Decoding these bytes proves neither that append nor any current owner,
//! signature, receiving budget, resource grant or complete Ready bundle.

use super::super::protected_names::ProtectedJournalNamesV1;
use super::association::AcceptedAssociationDataV1;
use super::{
    HEAD_BYTES, HistoryErrorV1, KeyV1, LatestHeadV1, OwnerV1, PhaseV1,
    RECORD_OVERHEAD_BYTES, RecordEnvelopeV1, reader,
};

/// Holds the exact new Source Held body width.
pub const SOURCE_HELD_BODY_BYTES_V1: usize = 264;
/// Holds the exact envelope width for the new Source Held body.
pub const SOURCE_HELD_RECORD_BYTES_V1: usize =
    RECORD_OVERHEAD_BYTES + SOURCE_HELD_BODY_BYTES_V1;
/// Holds the exact new Source Held native receipt width.
pub const SOURCE_HELD_RECEIPT_BYTES_V1: usize =
    SOURCE_HELD_RECORD_BYTES_V1 + HEAD_BYTES + 48 + 8 + 8;

/// Describes the new Source Held body's exact original association as DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceHeldBodyDataV1 {
    /// The actual accepted Create operation, distinct from Spec publication.
    pub operation: [u8; 16],
    /// The actual accepted Create project's identity.
    pub project: [u8; 16],
    /// The actual accepted Create sandbox projection's identity.
    pub sandbox: [u8; 16],
    /// The existing Controller scope's digest of the accepted canonical request.
    pub accepted_request: [u8; 32],
    /// The original retained native Q04 coissuance binding commitment.
    pub coissuance_binding: [u8; 32],
    /// The commitment of the complete actual Controller Intent association A.
    pub seed: [u8; 32],
    /// The once-generated Controller nonce persisted by that same Intent.
    pub controller_nonce: [u8; 16],
    /// The original continuation clock's actual host boot identity.
    pub boot: [u8; 16],
    /// The original continuation's paired BOOTTIME sample, in nanoseconds.
    pub started: u64,
    /// The same immutable original operation cutoff, never a renewed deadline.
    pub cutoff: u64,
    /// The actual held Source writer's preappend fixed physical names.
    pub source_names: ProtectedJournalNamesV1,
    /// The same Source writer's NEXT before the new Held append.
    pub source_before_next: u64,
    /// The same Source writer's durable end before the new Held append.
    pub source_before_end: u64,
}

impl SourceHeldBodyDataV1 {
    /// Decodes an exact body without allocating or admitting a live Source.
    ///
    /// # Errors
    /// Rejects nonexact extent, wrong magic, zero identities, malformed names,
    /// absent NEXT or a nonincreasing original cutoff.
    pub fn decode(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        if input.array::<8>()? != *b"AOSXSH01" {
            return Err(HistoryErrorV1::Malformed);
        }

        let association = AcceptedAssociationDataV1::read(&mut input)?;
        let value = Self {
            operation: association.operation,
            project: association.project,
            sandbox: association.sandbox,
            accepted_request: association.accepted_request,
            coissuance_binding: association.coissuance_binding,
            seed: association.seed,
            controller_nonce: association.controller_nonce,
            boot: association.boot,
            started: association.started,
            cutoff: association.cutoff,
            source_names: ProtectedJournalNamesV1::from_bytes(input.bytes(48)?)
                .map_err(|_| HistoryErrorV1::Malformed)?,
            source_before_next: input.u64()?,
            source_before_end: input.u64()?,
        };
        input.finish()?;
        value.validate()?;
        Ok(value)
    }

    /// Encodes the exact body into caller-owned fixed storage without allocation.
    ///
    /// # Errors
    /// Rejects malformed identities, names, NEXT or original cutoff.
    pub fn encode(self) -> Result<[u8; SOURCE_HELD_BODY_BYTES_V1], HistoryErrorV1> {
        self.validate()?;

        let mut bytes = [0; SOURCE_HELD_BODY_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSXSH01");
        bytes[8..200].copy_from_slice(&self.association().encode()?);
        bytes[200..248].copy_from_slice(&self.source_names.to_bytes());
        bytes[248..256].copy_from_slice(&self.source_before_next.to_be_bytes());
        bytes[256..264].copy_from_slice(&self.source_before_end.to_be_bytes());
        Ok(bytes)
    }

    /// Returns the fixed accepted association as passive comparison DATA.
    ///
    /// This does not authenticate the original intake, writer or cutoff.
    #[must_use]
    pub fn association(self) -> AcceptedAssociationDataV1 {
        AcceptedAssociationDataV1 {
            operation: self.operation, project: self.project, sandbox: self.sandbox,
            accepted_request: self.accepted_request, coissuance_binding: self.coissuance_binding,
            seed: self.seed, controller_nonce: self.controller_nonce, boot: self.boot,
            started: self.started, cutoff: self.cutoff,
        }
    }

    fn validate(self) -> Result<(), HistoryErrorV1> {
        self.association().validate_identities()?;
        ProtectedJournalNamesV1::from_bytes(&self.source_names.to_bytes())
            .map_err(|_| HistoryErrorV1::Malformed)?;
        if self.source_before_next == 0 || self.cutoff <= self.started {
            return Err(HistoryErrorV1::Malformed);
        }
        Ok(())
    }
}

/// Borrows the exact new Held record beside its native comparison coordinates.
///
/// These claimed coordinates are untrusted until independently compared with
/// the same actual Source writer and its complete exact allowed native suffix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceHeldReceiptDataV1<'record> {
    /// The complete checksum-covered new Source Held record, never old Q04.
    pub record: &'record [u8; SOURCE_HELD_RECORD_BYTES_V1],
    /// The exact head body atomically appended with this record.
    pub latest_head: [u8; HEAD_BYTES],
    /// The unchanged original Source physical names after the append.
    pub source_names: ProtectedJournalNamesV1,
    /// The actual returned/read-back Source NEXT after the append.
    pub source_after_next: u64,
    /// The actual returned/read-back Source durable end after the append.
    pub source_after_end: u64,
}

impl<'record> SourceHeldReceiptDataV1<'record> {
    /// Borrows and checks one exact receipt under the expected original lane.
    ///
    /// # Errors
    /// Rejects extent, envelope, body, head or lane/seed/name/position mismatch.
    /// No native commit, original writer or currentness is authenticated.
    pub fn decode(bytes: &'record [u8], lane: [u8; 16]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        let value = Self {
            record: input.bytes(SOURCE_HELD_RECORD_BYTES_V1)?.try_into()
                .map_err(|_| HistoryErrorV1::Extent)?,
            latest_head: input.array()?,
            source_names: ProtectedJournalNamesV1::from_bytes(input.bytes(48)?)
                .map_err(|_| HistoryErrorV1::Malformed)?,
            source_after_next: input.u64()?,
            source_after_end: input.u64()?,
        };
        input.finish()?;
        value.body(lane)?;
        Ok(value)
    }

    /// Returns the checked body while preserving the exact borrowed record.
    ///
    /// # Errors
    /// Rejects an inconsistent envelope, original association or receipt.
    pub fn body(self, lane: [u8; 16]) -> Result<SourceHeldBodyDataV1, HistoryErrorV1> {
        let record_key = KeyV1::new(lane, OwnerV1::Source, 1)?;
        let record = RecordEnvelopeV1::decode(self.record, record_key,
            PhaseV1::new(OwnerV1::Source, 1)?)?;
        let body = SourceHeldBodyDataV1::decode(record.body())?;
        let head_key = KeyV1::new(lane, OwnerV1::Source, 0)?;
        LatestHeadV1::decode(&self.latest_head, head_key)?.check_record(head_key, record)?;

        if record.coordinates().correlation != body.seed
            || self.source_names != body.source_names
            || self.source_after_next <= body.source_before_next
            || self.source_after_end <= body.source_before_end
        {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(body)
    }

    /// Encodes a checked receipt into fixed caller-owned storage without allocation.
    ///
    /// # Errors
    /// Rejects an inconsistent lane, envelope, body, head or native position.
    pub fn encode(self, lane: [u8; 16]) -> Result<[u8; SOURCE_HELD_RECEIPT_BYTES_V1], HistoryErrorV1> {
        self.body(lane)?;
        let mut bytes = [0; SOURCE_HELD_RECEIPT_BYTES_V1];
        let record_end = SOURCE_HELD_RECORD_BYTES_V1;
        let head_end = record_end + HEAD_BYTES;
        let names_end = head_end + 48;
        bytes[..record_end].copy_from_slice(self.record);
        bytes[record_end..head_end].copy_from_slice(&self.latest_head);
        bytes[head_end..names_end].copy_from_slice(&self.source_names.to_bytes());
        bytes[names_end..names_end + 8].copy_from_slice(&self.source_after_next.to_be_bytes());
        bytes[names_end + 8..].copy_from_slice(&self.source_after_end.to_be_bytes());
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::RecordCoordinatesV1;

    fn body() -> SourceHeldBodyDataV1 {
        SourceHeldBodyDataV1 {
            operation: [1; 16], project: [2; 16], sandbox: [3; 16],
            accepted_request: [4; 32], coissuance_binding: [5; 32],
            seed: [6; 32], controller_nonce: [7; 16], boot: [8; 16],
            started: 9, cutoff: 10,
            source_names: ProtectedJournalNamesV1::from_historical_fields(
                (1, 2), (3, 4), (5, 6),
            ),
            source_before_next: 11, source_before_end: 12,
        }
    }

    fn record(body: SourceHeldBodyDataV1, lane: [u8; 16])
        -> ([u8; SOURCE_HELD_RECORD_BYTES_V1], [u8; HEAD_BYTES])
    {
        let coordinates = RecordCoordinatesV1 {
            key: KeyV1::new(lane, OwnerV1::Source, 1).unwrap(),
            phase: PhaseV1::new(OwnerV1::Source, 1).unwrap(),
            predecessor: [0; 32], correlation: body.seed,
        };
        let mut record = [0; SOURCE_HELD_RECORD_BYTES_V1];
        let checksum = RecordEnvelopeV1::encode_into(
            coordinates, &body.encode().unwrap(), &mut record,
        ).unwrap();
        (record, LatestHeadV1::new(1, checksum).unwrap().encode())
    }

    #[test]
    fn body_keeps_accepted_identity_and_preappend_positions_distinct() {
        let original = body();
        let bytes = original.encode().unwrap();

        assert_eq!(bytes.len(), 264);
        assert_eq!(&bytes[8..24], &original.operation);
        assert_eq!(&bytes[56..88], &original.accepted_request);
        assert_eq!(&bytes[88..120], &original.coissuance_binding);
        assert_eq!(&bytes[248..256], &original.source_before_next.to_be_bytes());
        assert_eq!(&bytes[256..264], &original.source_before_end.to_be_bytes());
        assert_eq!(SourceHeldBodyDataV1::decode(&bytes).unwrap(), original);
        assert!(SourceHeldBodyDataV1::decode(&bytes[..263]).is_err());

        let mut changed = bytes;
        changed[192..200].copy_from_slice(&original.started.to_be_bytes());
        assert!(SourceHeldBodyDataV1::decode(&changed).is_err());
    }

    #[test]
    fn exact_receipt_rejects_foreign_lane_head_names_and_old_native_position() {
        let body = body();
        let lane = [13; 16];
        let (record, latest_head) = record(body, lane);
        let receipt = SourceHeldReceiptDataV1 {
            record: &record, latest_head, source_names: body.source_names,
            source_after_next: 15, source_after_end: 16,
        };
        let bytes = receipt.encode(lane).unwrap();

        assert_eq!(bytes.len(), 508);
        let decoded = SourceHeldReceiptDataV1::decode(&bytes, lane).unwrap();
        assert_eq!(decoded.body(lane).unwrap(), body);
        assert_eq!(decoded.record.as_ptr(), bytes.as_ptr());
        assert!(SourceHeldReceiptDataV1::decode(&bytes, [14; 16]).is_err());
        assert!(SourceHeldReceiptDataV1::decode(&bytes[..507], lane).is_err());

        let mut changed = bytes;
        changed[SOURCE_HELD_RECORD_BYTES_V1 + 8] ^= 1;
        assert!(SourceHeldReceiptDataV1::decode(&changed, lane).is_err());

        let mut changed = bytes;
        let names_start = SOURCE_HELD_RECORD_BYTES_V1 + HEAD_BYTES;
        changed[names_start..names_start + 48].copy_from_slice(
            &ProtectedJournalNamesV1::from_historical_fields((1, 2), (3, 7), (5, 6)).to_bytes(),
        );
        assert!(SourceHeldReceiptDataV1::decode(&changed, lane).is_err());

        let mut changed = bytes;
        let next_start = SOURCE_HELD_RECEIPT_BYTES_V1 - 16;
        changed[next_start..next_start + 8].copy_from_slice(&body.source_before_next.to_be_bytes());
        assert!(SourceHeldReceiptDataV1::decode(&changed, lane).is_err());
    }
}
