//! Frames one newly authorized metadata-finality comparison with the fixed Root.
//!
//! ```text
//! query[267] = AOSFRQ01 | nonce16 | admission-key67 | admission32 | lane16 |
//!              signed-Inventory18-packet32 | Inventory18-session32 |
//!              original-provenance16 | boot16 | original-wall:i64 |
//!              original-BOOTTIME:u64 | original-cutoff:u64 | wall-expiry:i64
//! ack[232] = AOSFRA01 | nonce16 | admission32 | old-Create16 |
//!            Source-terminal32 | signed-Inventory18-packet32 | exact-C-CAS32 |
//!            original-provenance16 | boot16 | actual-wall:i64 | actual-BOOTTIME:u64 |
//!            original-cutoff:u64 | current-wall-expiry:i64
//! ```
//!
//! These bytes do not authorize a mutation. Only the genuine purpose-bound
//! fixed Root peer, original new Recover owner, complete independent native
//! reads, exact response/EOF and every owed post can issue the opaque local
//! metadata-CAS lender. This grammar cannot represent a plan or effect grant.

use aos_sandbox_core::bounded_codec::BoundedReader;
use aos_sandbox_core::{RawClockProvenance, RawPairedClockSample};
use sha2::{Digest as _, Sha256};

use super::{
    CreateFinalityObservationAdmissionDataV1 as Admission, FinalityRecoverDataErrorV1 as Error,
    OBSERVATION_ADMISSION_KEY_BYTES_V1,
};

/// Gives the exact fixed newly authorized comparison request width.
pub const FINALITY_RECOVER_QUERY_BYTES_V1: usize = 200 + OBSERVATION_ADMISSION_KEY_BYTES_V1;
/// Gives the exact fixed metadata-only comparison acknowledgement width.
pub const FINALITY_RECOVER_ACKNOWLEDGEMENT_BYTES_V1: usize = 232;

/// Carries untrusted references to independently protected current evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalityRecoverQueryDataV1 {
    /// Binds this one entered comparison and its exact response.
    pub nonce: [u8; 16],
    /// Selects only the immutable newly authorized observation row.
    pub admission_key: [u8; OBSERVATION_ADMISSION_KEY_BYTES_V1],
    /// Commits every byte of that original protected row.
    pub admission: [u8; 32],
    /// Identifies the historical lane independently checked against actual Root6.
    pub lane: [u8; 16],
    /// Commits the complete actually received signed Inventory18 outcome packet.
    pub inventory: [u8; 32],
    /// Names its actual new Inventory-only negotiated Session binding.
    pub inventory_session: [u8; 32],
    /// Supplies only an early narrowing bound, later compared with the protected row.
    pub original: RawPairedClockSample,
    /// Supplies the unchanged original new Recover cutoff as untrusted DATA.
    pub cutoff: u64,
    /// Supplies the current new capability/policy expiry as untrusted DATA.
    pub wall_expiry: i64,
}

impl FinalityRecoverQueryDataV1 {
    /// Checks exact framing without opening a Journal or constructing authority.
    ///
    /// # Errors
    /// Refuses another family, sentinel evidence, changed width or suffix.
    pub fn decode_v1(bytes: &[u8]) -> Result<Self, Error> {
        let mut input = BoundedReader::new(bytes, |_| Error);
        if input.array::<8>()? != *b"AOSFRQ01" {
            return Err(Error);
        }
        let nonce = input.array()?;
        let admission_key = input.array()?;
        let admission = input.array()?;
        let lane = input.array()?;
        let inventory = input.array()?;
        let inventory_session = input.array()?;
        let provenance = RawClockProvenance::new_untrusted(input.array()?).map_err(|_| Error)?;
        let original = RawPairedClockSample::new_untrusted(
            provenance,
            input.array()?,
            input.i64()?,
            input.u64()?,
        )
        .map_err(|_| Error)?;
        let value = Self {
            nonce,
            admission_key,
            admission,
            lane,
            inventory,
            inventory_session,
            original,
            cutoff: input.u64()?,
            wall_expiry: input.i64()?,
        };
        input.finish()?;
        value.require_shape_v1()?;
        Ok(value)
    }

    /// Encodes into the fixed prepaid request destination.
    ///
    /// # Errors
    /// Refuses sentinel evidence or a non-admission key.
    pub fn encode_v1(self) -> Result<[u8; FINALITY_RECOVER_QUERY_BYTES_V1], Error> {
        self.require_shape_v1()?;
        let mut bytes = [0; FINALITY_RECOVER_QUERY_BYTES_V1];
        encode_fields_v1(
            &mut bytes,
            &[
                b"AOSFRQ01",
                &self.nonce,
                &self.admission_key,
                &self.admission,
                &self.lane,
                &self.inventory,
                &self.inventory_session,
                &self.original.provenance().as_bytes(),
                &self.original.host_boot_id(),
                &self.original.wall_seconds().to_be_bytes(),
                &self.original.boottime_nanoseconds().to_be_bytes(),
                &self.cutoff.to_be_bytes(),
                &self.wall_expiry.to_be_bytes(),
            ],
        )?;
        Ok(bytes)
    }

    fn require_shape_v1(self) -> Result<(), Error> {
        Admission::require_key_v1(&self.admission_key)?;
        if [self.nonce, self.lane].contains(&[0; 16])
            || [self.admission, self.inventory, self.inventory_session].contains(&[0; 32])
            || self.original.provenance().as_bytes() != *b"aos-cli-clock-v1"
            || self.original.boottime_nanoseconds() == 0
            || self.cutoff <= self.original.boottime_nanoseconds()
            || self.wall_expiry <= self.original.wall_seconds()
            || self
                .original
                .conservative_expiry_deadline_data_v1(self.wall_expiry)
                .is_none_or(|maximum| self.cutoff > maximum)
            || self
                .original
                .boottime_nanoseconds()
                .checked_add(65_000_000_000)
                .is_none_or(|maximum| self.cutoff > maximum)
        {
            return Err(Error);
        }
        Ok(())
    }
}

/// Describes only the independently checked metadata transaction and new horizon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalityRecoverAcknowledgementDataV1 {
    /// Echoes the actual newly entered request nonce.
    pub nonce: [u8; 16],
    /// Binds the exact newly authorized protected observation.
    pub admission: [u8; 32],
    /// Identifies the old Create whose public metadata alone may change.
    pub target: [u8; 16],
    /// Binds the independently captured canonical latest Source Terminal row.
    pub source_terminal: [u8; 32],
    /// Binds the actually signed fresh Inventory18 response packet.
    pub inventory: [u8; 32],
    /// Commits the exact sole permitted Controller metadata transaction.
    pub controller_transaction: [u8; 32],
    /// Records the actual Root sample under the new authorization's clock source.
    pub sample: RawPairedClockSample,
    /// Preserves or tightens the same new Recover cutoff; never an old Apply TTL.
    pub cutoff: u64,
    /// Preserves or tightens the current new capability/policy wall expiry.
    pub wall_expiry: i64,
}

impl FinalityRecoverAcknowledgementDataV1 {
    /// Measures the closed fixed response before the shared receiver grows.
    ///
    /// # Errors
    /// Refuses a partial header or another response purpose. The complete
    /// response is still strictly decoded after its exact extent is received.
    pub fn declared_encoded_bytes_v1(header: &[u8]) -> Result<usize, Error> {
        if header.len() != 20 || header.get(..8) != Some(b"AOSFRA01".as_slice()) {
            return Err(Error);
        }
        Ok(FINALITY_RECOVER_ACKNOWLEDGEMENT_BYTES_V1)
    }

    /// Decodes only exact metadata comparison DATA, without issuing an ACK loan.
    ///
    /// # Errors
    /// Refuses another family, sentinel fields, malformed clock or suffix.
    pub fn decode_v1(bytes: &[u8]) -> Result<Self, Error> {
        let mut input = BoundedReader::new(bytes, |_| Error);
        if input.array::<8>()? != *b"AOSFRA01" {
            return Err(Error);
        }
        let nonce = input.array()?;
        let admission = input.array()?;
        let target = input.array()?;
        let source_terminal = input.array()?;
        let inventory = input.array()?;
        let controller_transaction = input.array()?;
        let provenance = RawClockProvenance::new_untrusted(input.array()?).map_err(|_| Error)?;
        let sample = RawPairedClockSample::new_untrusted(
            provenance,
            input.array()?,
            input.i64()?,
            input.u64()?,
        )
        .map_err(|_| Error)?;
        let value = Self {
            nonce,
            admission,
            target,
            source_terminal,
            inventory,
            controller_transaction,
            sample,
            cutoff: input.u64()?,
            wall_expiry: input.i64()?,
        };
        input.finish()?;
        value.require_shape_v1()?;
        Ok(value)
    }

    /// Encodes into a fixed already paid response destination.
    ///
    /// # Errors
    /// Refuses sentinel evidence or a sample outside this new narrowed horizon.
    pub fn encode_v1(self) -> Result<[u8; FINALITY_RECOVER_ACKNOWLEDGEMENT_BYTES_V1], Error> {
        self.require_shape_v1()?;
        let mut bytes = [0; FINALITY_RECOVER_ACKNOWLEDGEMENT_BYTES_V1];
        encode_fields_v1(
            &mut bytes,
            &[
                b"AOSFRA01",
                &self.nonce,
                &self.admission,
                &self.target,
                &self.source_terminal,
                &self.inventory,
                &self.controller_transaction,
                &self.sample.provenance().as_bytes(),
                &self.sample.host_boot_id(),
                &self.sample.wall_seconds().to_be_bytes(),
                &self.sample.boottime_nanoseconds().to_be_bytes(),
                &self.cutoff.to_be_bytes(),
                &self.wall_expiry.to_be_bytes(),
            ],
        )?;
        Ok(bytes)
    }

    fn require_shape_v1(self) -> Result<(), Error> {
        if [self.nonce, self.target].contains(&[0; 16])
            || [
                self.admission,
                self.source_terminal,
                self.inventory,
                self.controller_transaction,
            ]
            .contains(&[0; 32])
            || self.sample.provenance().as_bytes() != *b"aos-cli-clock-v1"
            || self.sample.boottime_nanoseconds() == 0
            || self.cutoff <= self.sample.boottime_nanoseconds()
            || self.wall_expiry <= self.sample.wall_seconds()
            || self
                .sample
                .conservative_expiry_deadline_data_v1(self.wall_expiry)
                .is_none_or(|maximum| self.cutoff > maximum)
        {
            return Err(Error);
        }
        Ok(())
    }
}

/// Commits exact immutable new admission bytes without claiming their provenance.
#[must_use]
pub fn finality_admission_commitment_v1(bytes: &[u8]) -> [u8; 32] {
    commitment_v1(b"aos.sandbox.create-finality-recover.admission.v1\0", bytes)
}

/// Commits the complete signed fresh Inventory18 outcome, including its envelope.
#[must_use]
pub fn finality_inventory_commitment_v1(packet: &[u8]) -> [u8; 32] {
    commitment_v1(
        b"aos.sandbox.create-finality-recover.inventory.v1\0",
        packet,
    )
}

/// Commits exact acknowledgement bytes only as historical comparison DATA.
#[must_use]
pub fn finality_acknowledgement_commitment_v1(bytes: &[u8]) -> [u8; 32] {
    commitment_v1(
        b"aos.sandbox.create-finality-recover.acknowledgement.v1\0",
        bytes,
    )
}

/// Commits every ordered member of the exact metadata-only joint transaction.
///
/// This fixed-width hash recipe is comparison DATA. Only a genuine completed
/// Root exchange and same-payer native crossing can authorize its use.
///
/// # Errors
/// Refuses another row count, a deletion or an unrepresentable encoded width.
pub fn finality_controller_transaction_commitment_v1(
    transaction: &crate::domain_ledger::transaction::JournalTransaction,
) -> Result<[u8; 32], Error> {
    if transaction.records().len() != 4 {
        return Err(Error);
    }
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.create-finality-recover.controller-transaction.v1\0");
    digest.update(transaction.id());
    digest.update(4_u64.to_be_bytes());
    for record in transaction.records() {
        let value = record.value().ok_or(Error)?;
        digest.update([record.namespace() as u8]);
        digest.update(
            u64::try_from(record.key().len())
                .map_err(|_| Error)?
                .to_be_bytes(),
        );
        digest.update(record.key());
        digest.update(u64::try_from(value.len()).map_err(|_| Error)?.to_be_bytes());
        digest.update(value);
    }
    Ok(digest.finalize().into())
}

fn commitment_v1(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(domain)
        .chain_update(bytes)
        .finalize()
        .into()
}

fn encode_fields_v1(output: &mut [u8], fields: &[&[u8]]) -> Result<(), Error> {
    let mut offset = 0_usize;
    for field in fields {
        let end = offset.checked_add(field.len()).ok_or(Error)?;
        output
            .get_mut(offset..end)
            .ok_or(Error)?
            .copy_from_slice(field);
        offset = end;
    }
    if offset != output.len() {
        return Err(Error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_ledger::transaction::{JournalRecord, JournalTransaction};
    use aos_sandbox_core::RecordNamespace;

    fn sample() -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-cli-clock-v1").unwrap(),
            [9; 16],
            100,
            10_000_000_000,
        )
        .unwrap()
    }

    fn query() -> FinalityRecoverQueryDataV1 {
        FinalityRecoverQueryDataV1 {
            nonce: [1; 16],
            admission_key: Admission::key_from_original_v1([2; 16], [3; 32]),
            admission: [4; 32],
            lane: [5; 16],
            inventory: [6; 32],
            inventory_session: [7; 32],
            original: sample(),
            cutoff: 40_000_000_000,
            wall_expiry: 140,
        }
    }

    #[test]
    fn exact_wire_roundtrip_refuses_foreign_key_suffix_and_clock_origin() {
        let query = query();
        let encoded = query.encode_v1().unwrap();
        assert_eq!(encoded.len(), FINALITY_RECOVER_QUERY_BYTES_V1);
        assert_eq!(encoded.len(), 200 + query.admission_key.len());
        assert_eq!(
            FinalityRecoverQueryDataV1::decode_v1(&encoded).unwrap(),
            query
        );
        let mut extra = encoded.to_vec();
        extra.push(0);
        assert!(FinalityRecoverQueryDataV1::decode_v1(&extra).is_err());
        let mut changed = query;
        changed.admission_key[0] ^= 1;
        assert!(changed.encode_v1().is_err());
        changed = query;
        changed.original = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [9; 16],
            100,
            10_000_000_000,
        )
        .unwrap();
        assert!(changed.encode_v1().is_err());

        let acknowledgement = FinalityRecoverAcknowledgementDataV1 {
            nonce: query.nonce,
            admission: query.admission,
            target: [8; 16],
            source_terminal: [9; 32],
            inventory: query.inventory,
            controller_transaction: [10; 32],
            sample: sample(),
            cutoff: query.cutoff,
            wall_expiry: query.wall_expiry,
        };
        let encoded = acknowledgement.encode_v1().unwrap();
        assert_eq!(encoded.len(), FINALITY_RECOVER_ACKNOWLEDGEMENT_BYTES_V1);
        assert_eq!(FinalityRecoverAcknowledgementDataV1::declared_encoded_bytes_v1(&encoded[..20]).unwrap(), encoded.len());
        assert!(FinalityRecoverAcknowledgementDataV1::declared_encoded_bytes_v1(&encoded[..19]).is_err());
        let mut wrong_header = encoded[..20].to_vec();
        wrong_header[0] ^= 1;
        assert!(FinalityRecoverAcknowledgementDataV1::declared_encoded_bytes_v1(&wrong_header).is_err());
        assert_eq!(
            FinalityRecoverAcknowledgementDataV1::decode_v1(&encoded).unwrap(),
            acknowledgement
        );
        assert!(FinalityRecoverAcknowledgementDataV1 {
            wall_expiry: 100,
            ..acknowledgement
        }
        .encode_v1()
        .is_err());
    }

    #[test]
    fn acknowledgement_commitment_covers_all_four_members_not_only_joint_id() {
        let records = (1_u8..=4)
            .map(|value| {
                JournalRecord::put(
                    RecordNamespace::Operation,
                    vec![value; 16],
                    vec![value; 104],
                )
            })
            .collect();
        let original = JournalTransaction::new([1; 16], records).unwrap();
        let digest = finality_controller_transaction_commitment_v1(&original).unwrap();
        let mut changed = original.records().to_vec();
        changed[3] = JournalRecord::put(RecordNamespace::Operation, vec![4; 16], vec![5; 104]);
        let changed = JournalTransaction::new(*original.id(), changed).unwrap();
        assert_ne!(
            digest,
            finality_controller_transaction_commitment_v1(&changed).unwrap()
        );
        let truncated =
            JournalTransaction::new(*original.id(), original.records()[..3].to_vec()).unwrap();
        assert!(finality_controller_transaction_commitment_v1(&truncated).is_err());
    }
}
