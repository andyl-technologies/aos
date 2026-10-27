//! Frames actual Root validation and the genuine Controller U reservation.
//!
//! ```text
//! RootValidated body = AOSXRV01 | actual UseAuthorized native receipt[860]
//! UseReserved body = AOSXUR01 | RootValidated[32] | bank head[945] |
//!   bank claim[531] | immutable U binding[168] | bank transaction[16] |
//!   actual bank-after names[48] | NEXT[8] | end[8]
//! receipt = actual UseReserved record | latest head[40] | names[48] | NEXT[8] | end[8]
//! ```
//!
//! The bank return precedes the Controller UseReserved append. Its own returned
//! position belongs only to the outer receipt, never inside its preappend body.
//! All decoded fields are DATA; real Root/C owners independently replay their
//! full native histories and retain their same accepted financial originals.

use aos_sandbox_model::ResourceVector;
use aos_sandbox_journal::geometry::{RecordShape, encoded_transaction_append_bytes};
use sha2::{Digest as _, Sha256};

use super::{HEAD_BYTES, KEY_BYTES, RECORD_OVERHEAD_BYTES, HistoryErrorV1,
    KeyV1, LatestHeadV1, OwnerV1, PhaseV1, RecordEnvelopeV1, nonzero, reader};
use super::super::protected_names::ProtectedJournalNamesV1;
use super::super::resource_bank::{AccountHead, AccountKind, Claim, ClaimPurpose, ClaimState,
    CreateStorageUseBindingV1, ACCOUNT_HEAD_BYTES_V1, CLAIM_BYTES_V1,
    CREATE_STORAGE_USE_BINDING_BYTES_V1};
use super::use_authorized::{UseAuthorizedNativeReceiptDataV1, USE_AUTHORIZED_RECEIPT_BYTES_V1};
use super::cache_held::current_proof::CACHE_CURRENT_PROOF_PACKET_BYTES_V1;

/// Specifies the fixed Controller RootValidated phase3 body width.
pub const ROOT_VALIDATED_BODY_BYTES_V1: usize = 8 + USE_AUTHORIZED_RECEIPT_BYTES_V1;
/// Specifies the exact Controller revision4 RootValidated record width.
pub const ROOT_VALIDATED_RECORD_BYTES_V1: usize = RECORD_OVERHEAD_BYTES + ROOT_VALIDATED_BODY_BYTES_V1;
/// Specifies the exact Controller phase4 UseReserved body width.
pub const USE_RESERVED_BODY_BYTES_V1: usize = 8 + 32 + ACCOUNT_HEAD_BYTES_V1 + CLAIM_BYTES_V1
    + CREATE_STORAGE_USE_BINDING_BYTES_V1 + 16 + 64;
/// Specifies the Controller revision5 phase4 record width.
pub const USE_RESERVED_RECORD_BYTES_V1: usize = RECORD_OVERHEAD_BYTES + USE_RESERVED_BODY_BYTES_V1;
/// Specifies the actual Controller record/head/native position receipt width.
pub const USE_RESERVED_RECEIPT_BYTES_V1: usize = USE_RESERVED_RECORD_BYTES_V1 + HEAD_BYTES + 64;
/// Specifies the fresh use-proof container width, excluding its frame header.
pub const USE_CURRENT_PROOFS_BYTES_V1: usize = 16 + USE_RESERVED_RECEIPT_BYTES_V1 + CACHE_CURRENT_PROOF_PACKET_BYTES_V1;

/// Borrows the actual Root authorization inside the later Controller record.
#[derive(Clone, Copy)]
pub struct RootValidatedBodyDataV1<'held> {
    /// The completed authenticated Root turn's actual native receipt.
    pub authorization: UseAuthorizedNativeReceiptDataV1<'held>,
}

impl<'held> RootValidatedBodyDataV1<'held> {
    /// Decodes exact fixed correlation DATA without granting U.
    ///
    /// # Errors
    /// Rejects a wrong magic/width or malformed original Root receipt.
    pub fn decode(bytes: &'held [u8], lane: [u8; 16]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        if input.array::<8>()? != *b"AOSXRV01" { return Err(HistoryErrorV1::Malformed); }
        let authorization = UseAuthorizedNativeReceiptDataV1::decode(
            input.bytes(USE_AUTHORIZED_RECEIPT_BYTES_V1)?, lane)?;
        input.finish()?;
        Ok(Self { authorization })
    }

    /// Copies the exact original receipt into prepaid fixed body storage.
    ///
    /// # Errors
    /// Rejects an invalid original receipt or mismatched lane.
    pub fn encode(self, lane: [u8; 16]) -> Result<[u8; ROOT_VALIDATED_BODY_BYTES_V1], HistoryErrorV1> {
        let mut bytes = [0; ROOT_VALIDATED_BODY_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSXRV01");
        bytes[8..].copy_from_slice(&self.authorization.encode(lane)?);
        Ok(bytes)
    }
}

/// Borrows already-committed bank bytes and its original native position DATA.
#[derive(Clone, Copy)]
pub struct UseReservedBodyDataV1<'held> {
    /// The actual Controller RootValidated record checksum.
    pub root_validated: [u8; 32],
    /// The actual reserved Sandbox account head under its fixed protected key.
    pub head: &'held [u8; ACCOUNT_HEAD_BYTES_V1],
    /// The actual purpose15 reserved claim under its fixed protected key.
    pub claim: &'held [u8; CLAIM_BYTES_V1],
    /// The same actual immutable five-field use binding.
    pub binding: &'held [u8; CREATE_STORAGE_USE_BINDING_BYTES_V1],
    /// The original deterministic reserve transaction identity.
    pub transaction: [u8; 16],
    /// The actual bank reserve's original protected writer names.
    pub names: ProtectedJournalNamesV1,
    /// The actual returned/readback NEXT before the later UseReserved pair.
    pub after_next: u64,
    /// The actual returned/readback durable end before the later pair.
    pub after_end: u64,
}

impl<'held> UseReservedBodyDataV1<'held> {
    /// Decodes and compares exact passive bank fields without native authority.
    ///
    /// # Errors
    /// Rejects width, checksum, purpose/state, account, binding or position errors.
    pub fn decode(bytes: &'held [u8]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        if input.array::<8>()? != *b"AOSXUR01" { return Err(HistoryErrorV1::Malformed); }
        let value = Self { root_validated: input.array()?,
            head: input.bytes(ACCOUNT_HEAD_BYTES_V1)?.try_into().map_err(|_| HistoryErrorV1::Extent)?,
            claim: input.bytes(CLAIM_BYTES_V1)?.try_into().map_err(|_| HistoryErrorV1::Extent)?,
            binding: input.bytes(CREATE_STORAGE_USE_BINDING_BYTES_V1)?.try_into().map_err(|_| HistoryErrorV1::Extent)?,
            transaction: input.array()?,
            names: ProtectedJournalNamesV1::from_bytes(input.bytes(48)?)
                .map_err(|_| HistoryErrorV1::Malformed)?,
            after_next: input.u64()?, after_end: input.u64()?,
        };
        input.finish()?;
        value.validate()?;
        Ok(value)
    }

    /// Encodes the same already-committed fields into fixed preappend DATA.
    ///
    /// # Errors
    /// Rejects malformed or substituted bank/Root validation fields.
    pub fn encode(self) -> Result<[u8; USE_RESERVED_BODY_BYTES_V1], HistoryErrorV1> {
        self.validate()?;
        let mut bytes = [0; USE_RESERVED_BODY_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSXUR01");
        bytes[8..40].copy_from_slice(&self.root_validated);
        let mut offset = 40;
        for field in [self.head.as_slice(), self.claim.as_slice(), self.binding.as_slice()] {
            bytes[offset..offset + field.len()].copy_from_slice(field);
            offset += field.len();
        }
        bytes[offset..offset + 16].copy_from_slice(&self.transaction);
        offset += 16;
        bytes[offset..offset + 48].copy_from_slice(&self.names.to_bytes());
        bytes[offset + 48..offset + 56].copy_from_slice(&self.after_next.to_be_bytes());
        bytes[offset + 56..offset + 64].copy_from_slice(&self.after_end.to_be_bytes());
        Ok(bytes)
    }

    /// Encodes the exact reserve comparison transaction through the bank codec.
    ///
    /// This constructs DATA only. The actual independent physical observer
    /// still requires the genuine historical predecessor and native positions;
    /// no supplied account bytes establish a writer, grant or reservation.
    ///
    /// # Errors
    /// Rejects malformed fixed bank fields or canonical transaction encoding.
    pub fn expected_reserve_transaction_v1(self)
        -> Result<super::super::transaction::JournalTransaction,
            super::super::resource_bank::ResourceBankDataError>
    {
        use super::super::resource_bank::{AccountMutation, ResourceBankDataError};
        self.validate().map_err(|_| ResourceBankDataError::CorruptLedger)?;
        let head = AccountHead::decode(self.head)?;
        let claim = Claim::decode(self.claim)?;
        let binding = CreateStorageUseBindingV1::decode(self.binding)?;
        // The sole encoder reads only after/claim/binding here. Its unused
        // before argument confers no predecessor success or mutation admission.
        AccountMutation::new((&self.transaction, &head, &head, &claim,
            &None, &None, &None, &None)).with_create_storage_use_v1(&binding).transaction()
    }

    /// Encodes the exact actual committed U pair through the sole bank codec.
    ///
    /// This is comparison DATA. The caller must independently validate actual
    /// native COMMIT members, physical positions and the original role joins.
    ///
    /// # Errors
    /// Rejects a changed original reserved claim/binding or an incomplete or
    /// invalid actual committed replay before canonical transaction encoding.
    pub fn expected_commit_transaction_v1(self,
        state: &std::collections::BTreeMap<(aos_sandbox_model::RecordNamespace, Vec<u8>), Vec<u8>>)
        -> Result<super::super::transaction::JournalTransaction,
            super::super::resource_bank::ResourceBankDataError> {
        use super::super::resource_bank::{AccountMutation, Claim, CreateStorageUseBindingV1};
        self.validate().map_err(|_| super::super::resource_bank::ResourceBankDataError::CorruptLedger)?;
        let binding = CreateStorageUseBindingV1::decode(self.binding)?;
        let reserved = Claim::decode(self.claim)?;
        let (head, claim) = binding.committed_replayed_pair_v1(state, reserved)?;
        let transaction = binding.commit_transaction_id()?;
        AccountMutation::new((&transaction, &head, &head, &claim,
            &None, &None, &None, &None)).transaction()
    }

    /// Checks the same proposed amount and actual Root authorization checksum.
    ///
    /// This comparison grants no use. Its actual caller retains the completed
    /// Root turn and independently reads the exact protected Controller suffix.
    ///
    /// # Errors
    /// Rejects another Root receipt, original operation, Project or amount.
    /// Full accepted Sandbox/coissuance equality remains with the actual independent reader.
    pub fn require_authorization_v1(self, lane: [u8; 16],
        original: UseAuthorizedNativeReceiptDataV1<'_>) -> Result<(), HistoryErrorV1>
    {
        self.validate()?;
        let authorization = original.body(lane)?;
        let binding = CreateStorageUseBindingV1::decode(self.binding).map_err(|_| HistoryErrorV1::Correlation)?;
        let claim_model = Claim::decode(self.claim).map_err(|_| HistoryErrorV1::Correlation)?;
        let claim = claim_model.native_fields();
        let head = AccountHead::decode(self.head).map_err(|_| HistoryErrorV1::Correlation)?.native_fields();
        let record = RecordEnvelopeV1::decode(original.record,
            KeyV1::new(lane, OwnerV1::Root, 2)?, PhaseV1::new(OwnerV1::Root, 2)?)?;
        if binding.use_authorized_checksum() != record.checksum()
            || claim.amount != authorization.receiving
            || claim_model.operation() != authorization.association.operation
            || head.project != authorization.association.project {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(())
    }

    fn validate(self) -> Result<(), HistoryErrorV1> {
        nonzero(&self.root_validated)?;
        nonzero(&self.transaction)?;
        let head = AccountHead::decode(self.head).map_err(|_| HistoryErrorV1::Malformed)?.native_fields();
        let claim = Claim::decode(self.claim).map_err(|_| HistoryErrorV1::Malformed)?.native_fields();
        let binding = CreateStorageUseBindingV1::decode(self.binding).map_err(|_| HistoryErrorV1::Malformed)?;
        if head.kind != AccountKind::Sandbox || head.generation != 3
            || head.id != claim.account || head.enrollment != claim.enrollment
            || claim.purpose != ClaimPurpose::CreateStorageUse || claim.state != ClaimState::Reserved
            || claim.amount == ResourceVector::ZERO || binding.claim_id() != claim.id
            || binding.root_validated_checksum() != self.root_validated
            || binding.reserve_transaction_id().map_err(|_| HistoryErrorV1::Malformed)? != self.transaction
            || self.after_next == 0 || self.after_end == 0 {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(())
    }
}

/// Borrows the actual later Controller record/head/native return as DATA.
#[derive(Clone, Copy)]
pub struct UseReservedNativeReceiptDataV1<'held> {
    /// The completed Controller revision5 phase4 record.
    pub record: &'held [u8; USE_RESERVED_RECORD_BYTES_V1],
    /// Its actual readback latest head.
    pub latest_head: [u8; HEAD_BYTES],
    /// Its actual returned protected writer names.
    pub names: ProtectedJournalNamesV1,
    /// Its actual returned/readback NEXT.
    pub after_next: u64,
    /// Its actual returned/readback durable end.
    pub after_end: u64,
}

impl<'held> UseReservedNativeReceiptDataV1<'held> {
    /// Decodes a fixed receipt while leaving its original storage borrowed.
    ///
    /// # Errors
    /// Rejects substituted record/head/lane, malformed body or nonexact positions.
    pub fn decode(bytes: &'held [u8], lane: [u8; 16]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        let value = Self { record: input.bytes(USE_RESERVED_RECORD_BYTES_V1)?.try_into()
                .map_err(|_| HistoryErrorV1::Extent)?, latest_head: input.array()?,
            names: ProtectedJournalNamesV1::from_bytes(input.bytes(48)?)
                .map_err(|_| HistoryErrorV1::Malformed)?,
            after_next: input.u64()?, after_end: input.u64()?,
        };
        input.finish()?;
        value.body(lane)?;
        Ok(value)
    }

    /// Borrows the exact body after the shared envelope/head/position checks.
    ///
    /// # Errors
    /// Rejects a malformed or replaced receipt; this never authenticates a writer.
    pub fn body(self, lane: [u8; 16]) -> Result<UseReservedBodyDataV1<'held>, HistoryErrorV1> {
        let key = KeyV1::new(lane, OwnerV1::Controller, 5)?;
        let record = RecordEnvelopeV1::decode(self.record, key, PhaseV1::new(OwnerV1::Controller, 4)?)?;
        let latest = KeyV1::new(lane, OwnerV1::Controller, 0)?;
        LatestHeadV1::decode(&self.latest_head, latest)?.check_record(latest, record)?;
        let body = UseReservedBodyDataV1::decode(record.body())?;
        let append = encoded_transaction_append_bytes([
            RecordShape { key_bytes: KEY_BYTES, value_bytes: Some(USE_RESERVED_RECORD_BYTES_V1) },
            RecordShape { key_bytes: KEY_BYTES, value_bytes: Some(HEAD_BYTES) },
        ].into_iter()).map_err(|_| HistoryErrorV1::Extent)?;
        if record.coordinates().predecessor != body.root_validated || self.names != body.names
            || body.after_next.checked_add(4) != Some(self.after_next)
            || body.after_end.checked_add(append) != Some(self.after_end) {
            return Err(HistoryErrorV1::Correlation);
        }
        Ok(body)
    }

    /// Encodes the exact receipt into already-admitted fixed storage.
    ///
    /// # Errors
    /// Rejects an invalid receipt or substituted lane.
    pub fn encode(self, lane: [u8; 16]) -> Result<[u8; USE_RESERVED_RECEIPT_BYTES_V1], HistoryErrorV1> {
        self.body(lane)?;
        let mut bytes = [0; USE_RESERVED_RECEIPT_BYTES_V1];
        bytes[..USE_RESERVED_RECORD_BYTES_V1].copy_from_slice(self.record);
        let offset = USE_RESERVED_RECORD_BYTES_V1;
        bytes[offset..offset + HEAD_BYTES].copy_from_slice(&self.latest_head);
        let offset = offset + HEAD_BYTES;
        bytes[offset..offset + 48].copy_from_slice(&self.names.to_bytes());
        bytes[offset + 48..offset + 56].copy_from_slice(&self.after_next.to_be_bytes());
        bytes[offset + 56..offset + 64].copy_from_slice(&self.after_end.to_be_bytes());
        Ok(bytes)
    }
}

/// Commits exact fresh phase7 use-proof container bytes without granting U.
#[must_use]
pub fn use_current_proofs_commitment_v1(bytes: &[u8; USE_CURRENT_PROOFS_BYTES_V1]) -> [u8; 32] {
    Sha256::new().chain_update(b"aos.sandbox.create-storage.use-current-proofs.v1\0")
        .chain_update(bytes).finalize().into()
}

/// Borrows the distinct fresh use-stage Controller/Cache observations.
///
/// Source remains Root's independently contacted leg. This container creates
/// neither a fresh Cache signature nor a live Controller U borrower.
#[derive(Clone, Copy)]
pub struct UseCurrentProofsDataV1<'held> {
    /// The actual completed UseReserved record/head/position.
    pub controller: UseReservedNativeReceiptDataV1<'held>,
    /// The second actual independent Cache signed proof.
    pub cache_packet: &'held [u8; CACHE_CURRENT_PROOF_PACKET_BYTES_V1],
}

impl<'held> UseCurrentProofsDataV1<'held> {
    /// Decodes exact purpose7 framing while borrowing both original packets.
    ///
    /// # Errors
    /// Rejects wrong magic, lengths, lane, record/head or actual position DATA.
    pub fn decode(bytes: &'held [u8], lane: [u8; 16]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        if input.array::<8>()? != *b"AOSXUP01"
            || input.u32()? != USE_RESERVED_RECEIPT_BYTES_V1 as u32 {
            return Err(HistoryErrorV1::Malformed);
        }
        let controller = UseReservedNativeReceiptDataV1::decode(
            input.bytes(USE_RESERVED_RECEIPT_BYTES_V1)?, lane)?;
        if input.u32()? != CACHE_CURRENT_PROOF_PACKET_BYTES_V1 as u32 {
            return Err(HistoryErrorV1::Extent);
        }
        let cache_packet = input.bytes(CACHE_CURRENT_PROOF_PACKET_BYTES_V1)?
            .try_into().map_err(|_| HistoryErrorV1::Extent)?;
        input.finish()?;
        Ok(Self { controller, cache_packet })
    }

    /// Copies both actual observations to a prepaid fixed purpose7 container.
    ///
    /// # Errors
    /// Rejects malformed Controller receipt DATA before copying bytes.
    pub fn encode(self, lane: [u8; 16])
        -> Result<[u8; USE_CURRENT_PROOFS_BYTES_V1], HistoryErrorV1>
    {
        let controller = self.controller.encode(lane)?;
        let mut bytes = [0; USE_CURRENT_PROOFS_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSXUP01");
        bytes[8..12].copy_from_slice(&(USE_RESERVED_RECEIPT_BYTES_V1 as u32).to_be_bytes());
        let end = 12 + USE_RESERVED_RECEIPT_BYTES_V1;
        bytes[12..end].copy_from_slice(&controller);
        bytes[end..end + 4].copy_from_slice(&(CACHE_CURRENT_PROOF_PACKET_BYTES_V1 as u32).to_be_bytes());
        bytes[end + 4..].copy_from_slice(self.cache_packet);
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_model::ResourceDimension as D;
    use super::super::{RecordCoordinatesV1, association::AcceptedAssociationDataV1,
        use_authorized::{UseAuthorizedBodyDataV1, USE_AUTHORIZED_RECORD_BYTES_V1}};

    #[test]
    fn root_validated_preserves_the_exact_authorized_native_receipt() {
        let lane = [2; 16];
        let association = AcceptedAssociationDataV1 {
            operation: [3; 16], project: [4; 16], sandbox: [5; 16],
            accepted_request: [6; 32], coissuance_binding: [7; 32], seed: [8; 32],
            controller_nonce: [9; 16], boot: [10; 16], started: 100, cutoff: 200,
        };
        let body = UseAuthorizedBodyDataV1 {
            association, root_nonce: [11; 16], root_open: [12; 32], ready: [13; 32],
            inputs_ready: [14; 32], current_proofs: [15; 32], source_current: [16; 32],
            assignment: [17; 32], ownership_lease: [18; 32],
            receiving: ResourceVector::ZERO.with(D::MemoryBytes, 4096),
        };
        let mut record = [0; USE_AUTHORIZED_RECORD_BYTES_V1];
        let checksum = RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
            key: KeyV1::new(lane, OwnerV1::Root, 2).unwrap(),
            phase: PhaseV1::new(OwnerV1::Root, 2).unwrap(), predecessor: body.root_open,
            correlation: association.seed,
        }, &body.encode().unwrap(), &mut record).unwrap();
        let receipt = UseAuthorizedNativeReceiptDataV1 { record: &record,
            latest_head: LatestHeadV1::new(2, checksum).unwrap().encode(),
            names: ProtectedJournalNamesV1::from_historical_fields((1, 2), (3, 4), (5, 6)),
            after_next: 18, after_end: 10000 };

        let encoded = RootValidatedBodyDataV1 { authorization: receipt }.encode(lane).unwrap();
        let decoded = RootValidatedBodyDataV1::decode(&encoded, lane).unwrap();

        assert_eq!(&encoded[8..], receipt.encode(lane).unwrap().as_slice());
        assert_eq!(decoded.authorization.record.as_ptr(), encoded[8..].as_ptr());
        assert_eq!(decoded.authorization.body(lane).unwrap(), body);
        assert!(RootValidatedBodyDataV1::decode(&encoded, [42; 16]).is_err());
        let mut changed = encoded;
        changed[8 + USE_AUTHORIZED_RECORD_BYTES_V1 + 8] ^= 1;
        assert!(RootValidatedBodyDataV1::decode(&changed, lane).is_err());
    }

    #[test]
    fn fresh_use_proofs_have_a_distinct_commitment_and_exact_width() {
        let bytes = [0; USE_CURRENT_PROOFS_BYTES_V1];
        assert_eq!(ROOT_VALIDATED_RECORD_BYTES_V1, 1008);
        assert_eq!(USE_RESERVED_RECORD_BYTES_V1, 1904);
        assert_eq!(USE_RESERVED_RECEIPT_BYTES_V1, 2008);
        assert_eq!(USE_CURRENT_PROOFS_BYTES_V1, 3088);
        let raw: [u8; 32] = Sha256::digest(bytes).into();
        assert_ne!(use_current_proofs_commitment_v1(&bytes), raw);
        assert!(UseCurrentProofsDataV1::decode(&bytes, [2; 16]).is_err());
        let mut changed = bytes;
        changed[changed.len() - 1] = 1;
        assert_ne!(use_current_proofs_commitment_v1(&bytes), use_current_proofs_commitment_v1(&changed));
    }
}
