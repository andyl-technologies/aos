//! Records one newly authorized metadata-finality observation, never an effect.
//!
//! ```text
//! key = "finality-admission/" | holder16 | idempotencyDigest32
//! value = AOSFAD02 | operation16 | requestScope32 | oldCreate16 | node16 | holder16 | project16 | capability16
//!       | channel32 | authorizationRevision32 | idempotencyDigest32
//!       | clockProvenance16 | boot16 | wall:i64 | BOOTTIME:u64
//!       | originalCutoff:u64 | wallExpiry:i64 | requestLength:u32 | request
//! ```
//!
//! The request is the exact canonical public Recover envelope. Its checked
//! version and evidence remain inside that original body. A Root consumer must
//! independently replay the actual C, recompute current authorization, validate
//! Source/Session finality and retain native posts before admitting metadata CAS.

use aos_sandbox_model::bounded_codec::BoundedReader;
use aos_sandbox_model::{RawClockProvenance, RawPairedClockSample};
use sha2::{Digest as _, Sha256};

const MAGIC: &[u8; 8] = b"AOSFAD02";
const PREFIX: &[u8] = b"finality-admission/";
const IDEMPOTENCY_DOMAIN: &[u8] = b"aos.sandbox.create-finality-recover.idempotency.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.create-finality-recover.admission-transaction.v1\0";

/// Holds only this admission's fixed encoded fields before its original request.
pub const OBSERVATION_ADMISSION_HEADER_BYTES_V1: usize = 300;
/// Holds the exact protected row key width.
pub const OBSERVATION_ADMISSION_KEY_BYTES_V1: usize = PREFIX.len() + 16 + 32;

/// Reports malformed or substituted observation-admission DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid Create finality observation admission data")]
pub struct FinalityRecoverDataErrorV1;

/// Borrows the actual authorization context of one new Recover observation.
///
/// All fields remain untrusted DATA until compared with genuine retained
/// originals or independently decoded protected state. This type admits no IO.
#[derive(Clone, Copy, Debug)]
pub struct CreateFinalityObservationAdmissionDataV1<'request> {
    /// The new public MetadataComplete operation, derived by the sole key recipe.
    pub operation: [u8; 16],
    /// The actual admitting Controller's request domain, not a caller override.
    pub request_scope: [u8; 32],
    /// The historical Create whose metadata alone may be reconciled.
    pub target: [u8; 16],
    /// The genuine new recipient's enrolled node.
    pub node: [u8; 16],
    /// The holder authenticated by the original public TLS/native admission.
    pub holder: [u8; 16],
    /// The same authenticated project and current capability scope.
    pub project: [u8; 16],
    /// The actual capability selected by protected holder-handle resolution.
    pub capability: [u8; 16],
    /// Its exact authenticated proof-of-possession channel binding.
    pub channel: [u8; 32],
    /// The canonical protected capability/policy/revocation/floor revision.
    pub authorization_revision: [u8; 32],
    /// The canonical idempotency commitment for the actual request.
    pub idempotency_digest: [u8; 32],
    /// The genuine new observation's original paired sample, as DATA only.
    pub original: RawPairedClockSample,
    /// The unchanged minimum new authorization cutoff, never an old Apply TTL.
    pub cutoff: u64,
    /// The new current capability/policy expiry; historical leases are separate.
    pub wall_expiry: i64,
    /// The exact original public mutation envelope, including version/evidence.
    pub canonical_request: &'request [u8],
}

impl<'request> CreateFinalityObservationAdmissionDataV1<'request> {
    /// Decodes exact borrowed framing without allocating or restoring authority.
    ///
    /// # Errors
    /// Refuses malformed fields, wrong method, stale/sentinel horizon or suffix.
    pub fn decode_v1(bytes: &'request [u8]) -> Result<Self, FinalityRecoverDataErrorV1> {
        let mut input = BoundedReader::new(bytes, |_| FinalityRecoverDataErrorV1);
        if input.array::<8>()? != *MAGIC {
            return Err(FinalityRecoverDataErrorV1);
        }
        let operation = input.array()?;
        let request_scope = input.array()?;
        let target = input.array()?;
        let node = input.array()?;
        let holder = input.array()?;
        let project = input.array()?;
        let capability = input.array()?;
        let channel = input.array()?;
        let authorization_revision = input.array()?;
        let idempotency_digest = input.array()?;
        let provenance = RawClockProvenance::new_untrusted(input.array()?)
            .map_err(|_| FinalityRecoverDataErrorV1)?;
        let original = RawPairedClockSample::new_untrusted(
            provenance,
            input.array()?,
            input.i64()?,
            input.u64()?,
        )
        .map_err(|_| FinalityRecoverDataErrorV1)?;
        let cutoff = input.u64()?;
        let wall_expiry = input.i64()?;
        let length = usize::try_from(input.u32()?).map_err(|_| FinalityRecoverDataErrorV1)?;
        let canonical_request = input.bytes(length)?;
        input.finish()?;
        let value = Self {
            operation,
            request_scope,
            target,
            node,
            holder,
            project,
            capability,
            channel,
            authorization_revision,
            idempotency_digest,
            original,
            cutoff,
            wall_expiry,
            canonical_request,
        };
        value.encoded_bytes_v1()?;
        Ok(value)
    }

    /// Measures the exact record before its genuine producer allocates it.
    ///
    /// # Errors
    /// Refuses non-Recover framing, sentinel fields or non-narrowing horizons.
    pub fn encoded_bytes_v1(self) -> Result<usize, FinalityRecoverDataErrorV1> {
        use crate::public_api::{
            method::PublicApiAuditMethodV1, mutation::PublicMutationEnvelopeDataV1,
        };
        let envelope = PublicMutationEnvelopeDataV1::decode_v1(self.canonical_request)
            .map_err(|_| FinalityRecoverDataErrorV1)?;
        if [
            self.operation,
            self.target,
            self.node,
            self.holder,
            self.project,
            self.capability,
        ]
        .contains(&[0; 16])
            || [
                self.request_scope,
                self.channel,
                self.authorization_revision,
                self.idempotency_digest,
            ]
            .contains(&[0; 32])
            || self.operation != Self::operation_id_v1(&self.key_v1())
            || self.operation == self.target
            || self.original.provenance().as_bytes() != *b"aos-cli-clock-v1"
            || self.original.boottime_nanoseconds() == 0
            || self.cutoff <= self.original.boottime_nanoseconds()
            || self.wall_expiry <= self.original.wall_seconds()
            || self
                .original
                .conservative_expiry_deadline_data_v1(self.wall_expiry)
                .is_none_or(|deadline| self.cutoff > deadline)
            || self
                .original
                .boottime_nanoseconds()
                .checked_add(65_000_000_000)
                .is_none_or(|deadline| self.cutoff > deadline)
            || envelope.method_v1() != PublicApiAuditMethodV1::OperatorRecover
        {
            return Err(FinalityRecoverDataErrorV1);
        }
        u32::try_from(self.canonical_request.len()).map_err(|_| FinalityRecoverDataErrorV1)?;
        OBSERVATION_ADMISSION_HEADER_BYTES_V1
            .checked_add(self.canonical_request.len())
            .ok_or(FinalityRecoverDataErrorV1)
    }

    /// Encodes into an already admitted exact destination without allocation.
    ///
    /// # Errors
    /// Refuses the same invalid fields or a destination of another width.
    pub fn encode_into_v1(self, output: &mut [u8]) -> Result<(), FinalityRecoverDataErrorV1> {
        if output.len() != self.encoded_bytes_v1()? {
            return Err(FinalityRecoverDataErrorV1);
        }
        let mut offset = 0_usize;
        let request_length =
            u32::try_from(self.canonical_request.len()).map_err(|_| FinalityRecoverDataErrorV1)?;
        for field in [
            MAGIC.as_slice(),
            &self.operation,
            &self.request_scope,
            &self.target,
            &self.node,
            &self.holder,
            &self.project,
            &self.capability,
            &self.channel,
            &self.authorization_revision,
            &self.idempotency_digest,
            &self.original.provenance().as_bytes(),
            &self.original.host_boot_id(),
            &self.original.wall_seconds().to_be_bytes(),
            &self.original.boottime_nanoseconds().to_be_bytes(),
            &self.cutoff.to_be_bytes(),
            &self.wall_expiry.to_be_bytes(),
            &request_length.to_be_bytes(),
            self.canonical_request,
        ] {
            let end = offset
                .checked_add(field.len())
                .ok_or(FinalityRecoverDataErrorV1)?;
            output
                .get_mut(offset..end)
                .ok_or(FinalityRecoverDataErrorV1)?
                .copy_from_slice(field);
            offset = end;
        }
        Ok(())
    }

    /// Builds the fixed row key without allocating or supplying a writer.
    #[must_use]
    pub fn key_v1(self) -> [u8; OBSERVATION_ADMISSION_KEY_BYTES_V1] {
        Self::key_from_original_v1(self.holder, self.idempotency_digest)
    }

    /// Builds the canonical row key from its two immutable original identities.
    #[must_use]
    pub fn key_from_original_v1(holder: [u8; 16], idempotency: [u8; 32])
        -> [u8; OBSERVATION_ADMISSION_KEY_BYTES_V1] {
        let mut key = [0; OBSERVATION_ADMISSION_KEY_BYTES_V1];
        key[..PREFIX.len()].copy_from_slice(PREFIX);
        key[PREFIX.len()..PREFIX.len() + 16].copy_from_slice(&holder);
        key[PREFIX.len() + 16..].copy_from_slice(&idempotency);
        key
    }

    /// Derives this new operation identity from the immutable admission key.
    ///
    /// This deterministic identity avoids an additional unpriced entropy call.
    /// The genuine append must still reject occupied Operation and request keys.
    #[must_use]
    pub fn operation_id_v1(key: &[u8]) -> [u8; 16] {
        let digest = Sha256::new()
            .chain_update(b"aos.sandbox.create-finality-recover.public-operation.v1\0")
            .chain_update(key).finalize();
        let mut id = [0; 16];
        id.copy_from_slice(&digest[..16]);
        id[0] |= 0x80;
        id
    }

    /// Recomputes the established public request commitment from original DATA.
    #[must_use]
    pub fn request_digest_v1(self) -> [u8; 32] {
        super::public_operation::public_controller_request_digest_v1(self.request_scope,
            self.holder, self.project, self.canonical_request)
    }

    /// Checks exact framing of a selected observation key without allocating.
    ///
    /// # Errors
    /// Refuses another family, width or sentinel holder/idempotency identity.
    pub fn require_key_v1(key: &[u8]) -> Result<(), FinalityRecoverDataErrorV1> {
        if key.len() != OBSERVATION_ADMISSION_KEY_BYTES_V1 || !key.starts_with(PREFIX)
            || key[PREFIX.len()..PREFIX.len() + 16] == [0; 16]
            || key[PREFIX.len() + 16..] == [0; 32] {
            return Err(FinalityRecoverDataErrorV1);
        }
        Ok(())
    }

    /// Commits the actual holder and original idempotency bytes as passive DATA.
    #[must_use]
    pub fn idempotency_digest_v1(holder: [u8; 16], idempotency: &[u8]) -> [u8; 32] {
        Sha256::new()
            .chain_update(IDEMPOTENCY_DOMAIN)
            .chain_update(holder)
            .chain_update((idempotency.len() as u64).to_be_bytes())
            .chain_update(idempotency)
            .finalize()
            .into()
    }

    /// Derives only native transaction DATA for this exact admitted row.
    #[must_use]
    pub fn transaction_id_v1(key: &[u8], encoded: &[u8]) -> [u8; 16] {
        let digest = Sha256::new()
            .chain_update(TRANSACTION_DOMAIN)
            .chain_update(key)
            .chain_update(encoded)
            .finalize();
        let mut id = [0; 16];
        id.copy_from_slice(&digest[..16]);
        id[0] |= 0x80;
        id
    }

    /// Recognizes only this finite row family for the full protected replay.
    #[must_use]
    pub fn is_admission_key_v1(key: &[u8]) -> bool {
        key.starts_with(PREFIX)
    }

    /// Checks the sole canonical key against the complete borrowed row.
    ///
    /// # Errors
    /// Refuses wrong key width, holder, idempotency binding or record framing.
    pub fn require_record_v1(
        key: &[u8],
        encoded: &'request [u8],
    ) -> Result<(), FinalityRecoverDataErrorV1> {
        let value = Self::decode_v1(encoded)?;
        Self::require_key_v1(key)?;
        if key != value.key_v1() {
            return Err(FinalityRecoverDataErrorV1);
        }
        Ok(())
    }

    /// Rejects mutation of an existing admission in the sole native reducer.
    ///
    /// # Errors
    /// Refuses overwrites, deletion or malformed rows in this exact family.
    /// Other recovery families retain their own unchanged validators.
    pub fn require_new_record_v1(
        key: &[u8],
        before: Option<&[u8]>,
        after: Option<&'request [u8]>,
    ) -> Result<(), FinalityRecoverDataErrorV1> {
        if !Self::is_admission_key_v1(key) {
            return Ok(());
        }
        if before.is_some() {
            return Err(FinalityRecoverDataErrorV1);
        }
        Self::require_record_v1(key, after.ok_or(FinalityRecoverDataErrorV1)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Vec<u8> {
        let mut bytes = b"AOSPMR01".to_vec();
        bytes.extend_from_slice(&26_u16.to_be_bytes());
        bytes.extend_from_slice(&2_u32.to_be_bytes());
        // This fixture tests borrowed envelope framing. The real producer and
        // Root consumer independently run the existing complete body validator.
        bytes.extend_from_slice(&[8, 1]);
        bytes
    }

    fn data(request: &[u8]) -> CreateFinalityObservationAdmissionDataV1<'_> {
        let mut key = [0; OBSERVATION_ADMISSION_KEY_BYTES_V1];
        key[..PREFIX.len()].copy_from_slice(PREFIX);
        key[PREFIX.len()..PREFIX.len() + 16].copy_from_slice(&[3; 16]);
        key[PREFIX.len() + 16..].copy_from_slice(&[8; 32]);
        CreateFinalityObservationAdmissionDataV1 {
            operation: CreateFinalityObservationAdmissionDataV1::operation_id_v1(&key),
            request_scope: [10; 32],
            target: [1; 16],
            node: [2; 16],
            holder: [3; 16],
            project: [4; 16],
            capability: [5; 16],
            channel: [6; 32],
            authorization_revision: [7; 32],
            idempotency_digest: [8; 32],
            original: RawPairedClockSample::new_untrusted(
                RawClockProvenance::new_untrusted(*b"aos-cli-clock-v1").unwrap(),
                [9; 16],
                100,
                10_000_000_000,
            )
            .unwrap(),
            cutoff: 40_000_000_000,
            wall_expiry: 140,
            canonical_request: request,
        }
    }

    #[test]
    fn exact_record_binds_the_original_request_holder_and_immutable_horizon() {
        let request = request();
        let original = data(&request);
        let mut encoded = vec![0; original.encoded_bytes_v1().unwrap()];
        original.encode_into_v1(&mut encoded).unwrap();
        let decoded = CreateFinalityObservationAdmissionDataV1::decode_v1(&encoded).unwrap();

        assert_eq!(decoded.canonical_request, request.as_slice());
        assert_eq!(decoded.original, original.original);
        assert_eq!(decoded.cutoff, original.cutoff);
        assert_eq!(decoded.key_v1(), original.key_v1());
        assert!(
            CreateFinalityObservationAdmissionDataV1::require_record_v1(
                &original.key_v1(),
                &encoded
            )
            .is_ok()
        );

        let mut wrong_key = original.key_v1();
        wrong_key[PREFIX.len()] ^= 1;
        assert!(
            CreateFinalityObservationAdmissionDataV1::require_record_v1(&wrong_key, &encoded)
                .is_err()
        );
        assert!(
            CreateFinalityObservationAdmissionDataV1 {
                cutoff: 76_000_000_000,
                ..original
            }
            .encoded_bytes_v1()
            .is_err()
        );
        assert!(
            CreateFinalityObservationAdmissionDataV1::decode_v1(&encoded[..encoded.len() - 1])
                .is_err()
        );
    }

    #[test]
    fn native_replay_refuses_even_exact_overwrite_and_deletion() {
        let request = request();
        let original = data(&request);
        let mut encoded = vec![0; original.encoded_bytes_v1().unwrap()];
        original.encode_into_v1(&mut encoded).unwrap();
        let key = original.key_v1();

        assert!(
            CreateFinalityObservationAdmissionDataV1::require_new_record_v1(
                &key,
                None,
                Some(&encoded)
            )
            .is_ok()
        );
        assert!(
            CreateFinalityObservationAdmissionDataV1::require_new_record_v1(
                &key,
                Some(&encoded),
                Some(&encoded)
            )
            .is_err()
        );
        assert!(
            CreateFinalityObservationAdmissionDataV1::require_new_record_v1(
                &key,
                Some(&encoded),
                None
            )
            .is_err()
        );
        assert!(
            CreateFinalityObservationAdmissionDataV1::require_new_record_v1(&key, None, None)
                .is_err()
        );
    }
}
