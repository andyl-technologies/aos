//! Frames Root's UseAuthorized row/native return as nonauthorizing DATA.
//!
//! ```text
//! body[616] = AOSXUA01 | accepted-association[192] | RootNonce[16] |
//! RootOpen[32] | Ready[32] | InputsReady[32] | CurrentProofs[32] |
//! Source17-packet[32] | assignment[32] | ownership-lease[32] | receiving[22*u64be]
//! record[756] = Root revision2 phase2, predecessor=actual RootOpen checksum
//! receipt[860] = record | head[40] | names[48] | afterNEXT[8] | afterEnd[8]
//! frame[972] = existing UseAuthorized-header[112] | receipt
//! sequence = 5 + actual Ready transfer index count
//! ```
//!
//! Parsed DATA cannot issue U15. Controller's genuine same-bank issuer must
//! hold the actual authenticated Root turn and independently derive/check its
//! required operation shape and ceiling. Root's own producer requires its full
//! live typed-B/current-cut owner before any positive native transition.

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use sha2::{Digest as _, Sha256};

use super::{HEAD_BYTES, RECORD_OVERHEAD_BYTES, HistoryErrorV1, KeyV1,
    LatestHeadV1, OwnerV1, PhaseV1, RecordEnvelopeV1, nonzero, reader};
use super::association::AcceptedAssociationDataV1;
use super::cache_held::current_proof::CACHE_CURRENT_PROOF_PACKET_BYTES_V1;
use super::ready::{INPUTS_READY_RECEIPT_BYTES_V1, InputsReadyNativeReceiptDataV1};
use super::root_open::RootHelloDataV1;
use super::source_current::SOURCE_CURRENT_PACKET_BYTES_V1;
use super::transport::FRAME_HEADER_BYTES;
use super::super::protected_names::ProtectedJournalNamesV1;

const _: [(); 22] = [(); D::COUNT];
/// Holds the exact fixed authorization body width.
pub const USE_AUTHORIZED_BODY_BYTES_V1: usize = 616;
/// Holds the exact Root revision2 phase2 record width.
pub const USE_AUTHORIZED_RECORD_BYTES_V1: usize = RECORD_OVERHEAD_BYTES + USE_AUTHORIZED_BODY_BYTES_V1;
/// Holds the exact native Root record/head/position return width.
pub const USE_AUTHORIZED_RECEIPT_BYTES_V1: usize = USE_AUTHORIZED_RECORD_BYTES_V1 + HEAD_BYTES + 64;
/// Holds the exact frame width, using the existing shared frame codec.
pub const USE_AUTHORIZED_FRAME_BYTES_V1: usize = FRAME_HEADER_BYTES + USE_AUTHORIZED_RECEIPT_BYTES_V1;
/// Holds the exact canonical CurrentProofs4 payload width.
pub const CURRENT_PROOFS_PAYLOAD_BYTES_V1: usize = 16 + INPUTS_READY_RECEIPT_BYTES_V1 + CACHE_CURRENT_PROOF_PACKET_BYTES_V1;

/// Commits exact sent canonical Phase4 payload bytes as comparison DATA.
///
/// This neither parses/authenticates roles nor prices receipt. Both actual
/// peers retain the same canonical bytes under their own current originals.
#[must_use]
pub fn current_proofs_commitment_v1(bytes: &[u8; CURRENT_PROOFS_PAYLOAD_BYTES_V1]) -> [u8; 32] {
    Sha256::new().chain_update(b"aos.sandbox.create-storage.current-proofs.v1\0")
        .chain_update(bytes).finalize().into()
}

/// Commits Root's independently verified signed Source17 packet as DATA.
///
/// These568 bytes exclude the outer8-byte selector. Controller preserves the
/// Root attestation; an unseen packet supplies no local Source authority.
#[must_use]
pub fn source_current_reply_commitment_v1(bytes: &[u8; SOURCE_CURRENT_PACKET_BYTES_V1]) -> [u8; 32] {
    Sha256::new().chain_update(b"aos.sandbox.create-storage.source-current-reply.v1\0")
        .chain_update(bytes).finalize().into()
}

/// Describes Root's selected request without granting a resource claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UseAuthorizedBodyDataV1 {
    /// The exact accepted association from Controller's actual InputsReady.
    pub association: AcceptedAssociationDataV1,
    /// The unchanged independent Root nonce from the original Hello.
    pub root_nonce: [u8; 16],
    /// The actual original RootOpen envelope checksum.
    pub root_open: [u8; 32],
    /// The exact complete B commitment from the original Hello.
    pub ready: [u8; 32],
    /// The actual Controller InputsReady envelope checksum.
    pub inputs_ready: [u8; 32],
    /// The named commitment of exact sent canonical CurrentProofs4 payload.
    pub current_proofs: [u8; 32],
    /// Root's commitment of its independently verified Source17 packet.
    pub source_current: [u8; 32],
    /// The existing Core canonical assignment digest checked independently by Root.
    pub assignment: [u8; 32],
    /// The independently verified Ownership lease's existing artifact digest.
    pub ownership_lease: [u8; 32],
    /// The proposed exact all22 receiving requirement; parsed DATA is no grant.
    pub receiving: ResourceVector,
}

impl UseAuthorizedBodyDataV1 {
    /// Decodes exact fixed fields without allocating, verifying or issuing U.
    ///
    /// # Errors
    /// Rejects magic/extent/identity/cutoff errors or a zero/unlimited vector.
    /// The dimension count is versioned at22, independent of declared lengths.
    pub fn decode(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        if input.array::<8>()? != *b"AOSXUA01" { return Err(HistoryErrorV1::Malformed); }
        let association = AcceptedAssociationDataV1::decode(input.bytes(192)?)?;
        let root_nonce = input.array()?;
        let root_open = input.array()?;
        let ready = input.array()?;
        let inputs_ready = input.array()?;
        let current_proofs = input.array()?;
        let source_current = input.array()?;
        let assignment = input.array()?;
        let ownership_lease = input.array()?;
        let mut receiving = ResourceVector::ZERO;
        for dimension in D::ALL { receiving = receiving.with(dimension, input.u64()?); }
        input.finish()?;
        let value = Self { association, root_nonce, root_open, ready, inputs_ready,
            current_proofs, source_current, assignment, ownership_lease, receiving };
        value.validate()?;
        Ok(value)
    }

    /// Encodes fixed comparison fields into an allocation-free array.
    ///
    /// # Errors
    /// Rejects invalid identities/cutoff or a zero/unlimited requirement.
    pub fn encode(self) -> Result<[u8; USE_AUTHORIZED_BODY_BYTES_V1], HistoryErrorV1> {
        self.validate()?;
        let mut bytes = [0; USE_AUTHORIZED_BODY_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSXUA01");
        bytes[8..200].copy_from_slice(&self.association.encode()?);
        bytes[200..216].copy_from_slice(&self.root_nonce);
        let mut offset = 216;
        for value in [self.root_open, self.ready, self.inputs_ready, self.current_proofs,
            self.source_current, self.assignment, self.ownership_lease] {
            bytes[offset..offset + 32].copy_from_slice(&value);
            offset += 32;
        }
        for dimension in D::ALL {
            bytes[offset..offset + 8].copy_from_slice(&self.receiving.get(dimension).to_be_bytes());
            offset += 8;
        }
        Ok(bytes)
    }

    fn validate(self) -> Result<(), HistoryErrorV1> {
        self.association.validate()?;
        nonzero(&self.root_nonce)?;
        for value in [&self.root_open, &self.ready, &self.inputs_ready, &self.current_proofs,
            &self.source_current, &self.assignment, &self.ownership_lease] { nonzero(value)?; }
        if self.receiving == ResourceVector::ZERO
            || D::ALL.into_iter().any(|dimension| self.receiving.get(dimension) == u64::MAX) {
            return Err(HistoryErrorV1::Malformed);
        }
        Ok(())
    }
}

/// Borrows Root's actual record/head/native return without recreating its owner.
#[derive(Clone, Copy)]
pub struct UseAuthorizedNativeReceiptDataV1<'record> {
    /// The exact actual Root revision2 phase2 record, never regenerated.
    pub record: &'record [u8; USE_AUTHORIZED_RECORD_BYTES_V1],
    /// The head atomically appended with that same record.
    pub latest_head: [u8; HEAD_BYTES],
    /// The retained Root authority writer's unchanged actual physical names.
    pub names: ProtectedJournalNamesV1,
    /// The actual returned/read-back NEXT after the atomic pair.
    pub after_next: u64,
    /// The exact actual returned/read-back durable end, preserved as DATA.
    pub after_end: u64,
}

impl<'record> UseAuthorizedNativeReceiptDataV1<'record> {
    /// Borrows exact receipt framing and checks its canonical row/head.
    ///
    /// # Errors
    /// Rejects extent, row/head/lane/correlation or absent position.
    pub fn decode(bytes: &'record [u8], lane: [u8; 16]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        let value = Self {
            record: input.bytes(USE_AUTHORIZED_RECORD_BYTES_V1)?.try_into().map_err(|_| HistoryErrorV1::Extent)?,
            latest_head: input.array()?,
            names: ProtectedJournalNamesV1::from_bytes(input.bytes(48)?).map_err(|_| HistoryErrorV1::Malformed)?,
            after_next: input.u64()?, after_end: input.u64()?,
        };
        input.finish()?;
        value.body(lane)?;
        Ok(value)
    }

    /// Returns the body after checking its exact chain, correlation and head.
    ///
    /// # Errors
    /// Rejects a foreign row/phase/head, predecessor, seed or absent position.
    pub fn body(self, lane: [u8; 16]) -> Result<UseAuthorizedBodyDataV1, HistoryErrorV1> {
        let record = RecordEnvelopeV1::decode(self.record,
            KeyV1::new(lane, OwnerV1::Root, 2)?, PhaseV1::new(OwnerV1::Root, 2)?)?;
        let body = UseAuthorizedBodyDataV1::decode(record.body())?;
        let head_key = KeyV1::new(lane, OwnerV1::Root, 0)?;
        LatestHeadV1::decode(&self.latest_head, head_key)?.check_record(head_key, record)?;
        if record.coordinates().predecessor != body.root_open
            || record.coordinates().correlation != body.association.seed
            || self.after_next == 0 || self.after_end == 0 {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(body)
    }

    /// Requires exact Hello/InputsReady fields, names and pre-Open NEXT+8.
    ///
    /// RootOpen and UseAuthorized each append one four-frame atomic pair.
    /// Hello omits durable end: no prior offset is invented here. Root's actual
    /// producer must compare returned/readback end exactly before sending; the
    /// Controller preserves that raw field under its genuine received owner.
    ///
    /// # Errors
    /// Rejects changed association/nonce/digests/names or any other NEXT.
    pub fn require_originals(self, hello: &RootHelloDataV1<'_>,
        inputs: InputsReadyNativeReceiptDataV1<'_>) -> Result<(), HistoryErrorV1> {
        let lane = hello.body.open.lane;
        let body = self.body(lane)?;
        let input = inputs.body(lane)?;
        let record = RecordEnvelopeV1::decode(inputs.record,
            KeyV1::new(lane, OwnerV1::Controller, 3)?, PhaseV1::new(OwnerV1::Controller, 2)?)?;
        if body.association != input.association || body.root_nonce != hello.body.root_nonce
            || body.root_open != hello.checksum || body.ready != hello.body.open.ready
            || body.ready != input.ready || body.inputs_ready != record.checksum()
            || body.association.controller_nonce != hello.body.open.controller_nonce
            || body.association.seed != hello.body.open.seed || body.association.boot != hello.body.boot
            || self.names != hello.body.authority_names
            || hello.body.authority_next.checked_add(8) != Some(self.after_next) {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(())
    }

    /// Encodes this exact original receipt into already-paid fixed storage.
    ///
    /// # Errors
    /// Rejects the same inconsistencies as the fixed body validator.
    pub fn encode(self, lane: [u8; 16]) -> Result<[u8; USE_AUTHORIZED_RECEIPT_BYTES_V1], HistoryErrorV1> {
        self.body(lane)?;
        let mut bytes = [0; USE_AUTHORIZED_RECEIPT_BYTES_V1];
        let end = USE_AUTHORIZED_RECORD_BYTES_V1;
        bytes[..end].copy_from_slice(self.record);
        bytes[end..end + HEAD_BYTES].copy_from_slice(&self.latest_head);
        bytes[end + HEAD_BYTES..end + HEAD_BYTES + 48].copy_from_slice(&self.names.to_bytes());
        bytes[end + HEAD_BYTES + 48..end + HEAD_BYTES + 56].copy_from_slice(&self.after_next.to_be_bytes());
        bytes[end + HEAD_BYTES + 56..].copy_from_slice(&self.after_end.to_be_bytes());
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{RecordCoordinatesV1, root_open::RootOpenBodyDataV1};
    use super::super::transport::{FrameCoordinatesV1, FrameKindV1, OpenQueryV1};
    use super::super::ready::{InputsReadyBodyDataV1, INPUTS_READY_RECORD_BYTES_V1};

    fn association() -> AcceptedAssociationDataV1 {
        AcceptedAssociationDataV1 {
            operation: [7; 16], project: [8; 16], sandbox: [9; 16],
            accepted_request: [10; 32], coissuance_binding: [11; 32], seed: [3; 32],
            controller_nonce: [1; 16], boot: [6; 16], started: 100, cutoff: 200,
        }
    }

    fn body() -> UseAuthorizedBodyDataV1 {
        UseAuthorizedBodyDataV1 {
            association: association(), root_nonce: [5; 16], root_open: [12; 32],
            ready: [4; 32], inputs_ready: [13; 32], current_proofs: [14; 32],
            source_current: [15; 32], assignment: [16; 32], ownership_lease: [17; 32],
            receiving: ResourceVector::ZERO.with(D::MemoryBytes, 4096),
        }
    }

    #[test]
    fn body_roundtrip_rejects_unlimited_or_absent_resource_request() {
        let value = body();
        let bytes = value.encode().unwrap();

        assert_eq!(UseAuthorizedBodyDataV1::decode(&bytes).unwrap(), value);
        assert!(UseAuthorizedBodyDataV1::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut changed = value;
        changed.receiving = ResourceVector::ZERO;
        assert!(changed.encode().is_err());
        for dimension in D::ALL {
            changed.receiving = value.receiving.with(dimension, u64::MAX);
            assert!(changed.encode().is_err());
        }
        let mut changed = bytes;
        changed[8 + 184..8 + 192].copy_from_slice(&100_u64.to_be_bytes());
        assert!(UseAuthorizedBodyDataV1::decode(&changed).is_err());
    }

    #[test]
    fn receipt_binds_actual_hello_inputs_head_and_exact_two_pair_next() {
        // These are canonical codec DATA fixtures. They create no genuine
        // native Root/J original, signed current cut or U authority.
        let names = ProtectedJournalNamesV1::from_historical_fields((1, 2), (3, 4), (5, 6));
        let root_body = RootOpenBodyDataV1 {
            open: OpenQueryV1 { controller_nonce: [1; 16], lane: [2; 16], seed: [3; 32], ready: [4; 32] },
            root_nonce: [5; 16], boot: [6; 16], started: 110, cutoff: 180,
            authority_names: names,
            policy_names: ProtectedJournalNamesV1::from_historical_fields((1, 2), (7, 8), (9, 10)),
            authority_next: 10, policy_next: 1, root_profile: [12; 32],
            root_recipient: [13; 16], root_producer: [14; 16], root_pid: 15,
            controller_pid: 16, controller_uid: 17, controller_gid: 18,
        };
        let lane = root_body.open.lane;
        let mut root_record = [0; 500];
        RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
            key: KeyV1::new(lane, OwnerV1::Root, 1).unwrap(),
            phase: PhaseV1::new(OwnerV1::Root, 1).unwrap(), predecessor: [0; 32], correlation: [3; 32],
        }, &root_body.encode().unwrap(), &mut root_record).unwrap();
        let header = FrameCoordinatesV1 { kind: FrameKindV1::Hello, lane, sequence: 1,
            root_nonce: [5; 16], controller_nonce: [1; 16] }.encode_header(&root_record).unwrap();
        let mut hello_bytes = Vec::from(header);
        hello_bytes.extend_from_slice(&root_record);
        let hello = RootHelloDataV1::decode(&hello_bytes, root_body.open).unwrap();

        let input_body = InputsReadyBodyDataV1 { association: association(),
            assignment_planned: [12; 32], ready: [4; 32], bundle_bytes: 15 };
        let mut input_record = [0; INPUTS_READY_RECORD_BYTES_V1];
        let input_checksum = RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
            key: KeyV1::new(lane, OwnerV1::Controller, 3).unwrap(),
            phase: PhaseV1::new(OwnerV1::Controller, 2).unwrap(),
            predecessor: [12; 32], correlation: [3; 32],
        }, &input_body.encode().unwrap(), &mut input_record).unwrap();
        let input = InputsReadyNativeReceiptDataV1 { record: &input_record,
            latest_head: LatestHeadV1::new(3, input_checksum).unwrap().encode(),
            names, after_next: 20, after_end: 1000 };
        let value = UseAuthorizedBodyDataV1 { root_open: hello.checksum,
            inputs_ready: input_checksum, ..body() };
        let mut record = [0; USE_AUTHORIZED_RECORD_BYTES_V1];
        let checksum = RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
            key: KeyV1::new(lane, OwnerV1::Root, 2).unwrap(),
            phase: PhaseV1::new(OwnerV1::Root, 2).unwrap(),
            predecessor: hello.checksum, correlation: [3; 32],
        }, &value.encode().unwrap(), &mut record).unwrap();
        let receipt = UseAuthorizedNativeReceiptDataV1 { record: &record,
            latest_head: LatestHeadV1::new(2, checksum).unwrap().encode(),
            names, after_next: 18, after_end: 10000 };
        let encoded = receipt.encode(lane).unwrap();

        let decoded = UseAuthorizedNativeReceiptDataV1::decode(&encoded, lane).unwrap();
        assert!(decoded.require_originals(&hello, input).is_ok());
        assert_eq!(decoded.after_end, 10000);
        assert_eq!(decoded.record.as_ptr(), encoded.as_ptr());
        assert!(UseAuthorizedNativeReceiptDataV1 { after_next: 17, ..receipt }
            .require_originals(&hello, input).is_err());
        let mut changed = encoded;
        changed[USE_AUTHORIZED_RECORD_BYTES_V1 + 8] ^= 1;
        assert!(UseAuthorizedNativeReceiptDataV1::decode(&changed, lane).is_err());
        assert!(UseAuthorizedNativeReceiptDataV1::decode(&encoded, [42; 16]).is_err());
    }
}
