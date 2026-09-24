//! Canonical, non-authorizing `AOSCOB01` execution Observe reservation codec.
//!
//! The Controller execution owner records this binding after authenticated
//! Host Authorize. Decoding it does not grant Observe dispatch authority.
//!
//! ```text
//! AOSCOB01 || execution:16 || Create-operation:16 || Observe-operation:16
//!          || spec-digest:32 || source-operation-commitment:32
//!          || authorization-receipt:40 || record-digest:32
//! ```

use aos_sandbox_core::{ExecutionId, ObjectDigest, OperationId};
use sha2::{Digest as _, Sha256};

const MAGIC: &[u8; 8] = b"AOSCOB01";
const RECEIPT_MAGIC: &[u8; 8] = b"AOSEXE01";
const RECEIPT_BYTES: usize = 40;
const RECORD_BYTES: usize = 8 + 16 + 16 + 16 + 32 + 32 + RECEIPT_BYTES + 32;
const OPERATION_DOMAIN: &[u8] = b"aos.sandbox.controller.execution-observe-operation.v1\0";
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.controller.execution-observe-reservation.v1\0";

/// Reports a malformed or contradictory execution Observe reservation binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObserveReservationCodecErrorV1 {
    /// The authorization receipt has another byte length.
    ReceiptLength,
    /// The receipt or a required Create binding is absent or invalid.
    InvalidBinding,
    /// The derived Observe operation cannot be represented.
    InvalidOperation,
    /// The derived Observe operation equals Create or is zero.
    NotDistinct,
    /// The record framing, checksum, identity, or journal key is inconsistent.
    CorruptRecord,
}

/// Binds one derived Observe ID to exact retained Create and Host evidence.
///
/// This value is a reservation only. The owning Controller must separately
/// prove current source custody and reconcile an authorized child effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerExecutionObserveReservationV1 {
    execution: ExecutionId,
    create_operation: OperationId,
    observe_operation: OperationId,
    specification_digest: ObjectDigest,
    source_operation_commitment: [u8; 32],
    authorization_receipt: [u8; RECEIPT_BYTES],
}

impl ControllerExecutionObserveReservationV1 {
    /// Derives the one Observe ID from exact Create and Host receipt fields.
    ///
    /// # Errors
    ///
    /// Rejects a malformed receipt, a missing Create binding, or an Observe ID
    /// that is zero or equal to the Create operation ID.
    pub fn new(
        execution: ExecutionId,
        create_operation: OperationId,
        specification_digest: ObjectDigest,
        source_operation_commitment: [u8; 32],
        authorization_receipt: &[u8],
    ) -> Result<Self, ObserveReservationCodecErrorV1> {
        let receipt: [u8; RECEIPT_BYTES] = authorization_receipt
            .try_into()
            .map_err(|_| ObserveReservationCodecErrorV1::ReceiptLength)?;
        if receipt.get(..8) != Some(RECEIPT_MAGIC.as_slice())
            || receipt[8..] == [0; 32]
            || execution.as_bytes() == &[0; 16]
            || create_operation.as_bytes() == &[0; 16]
            || specification_digest.as_bytes() == &[0; 32]
            || source_operation_commitment == [0; 32]
        {
            return Err(ObserveReservationCodecErrorV1::InvalidBinding);
        }

        let digest: [u8; 32] = Sha256::new()
            .chain_update(OPERATION_DOMAIN)
            .chain_update(create_operation.as_bytes())
            .chain_update(execution.as_bytes())
            .chain_update(specification_digest.as_bytes())
            .chain_update(source_operation_commitment)
            .chain_update(receipt)
            .finalize()
            .into();
        let operation: [u8; 16] = digest[..16]
            .try_into()
            .map_err(|_| ObserveReservationCodecErrorV1::InvalidOperation)?;
        if operation == [0; 16] || operation == *create_operation.as_bytes() {
            return Err(ObserveReservationCodecErrorV1::NotDistinct);
        }

        Ok(Self {
            execution,
            create_operation,
            observe_operation: OperationId::from_bytes(operation),
            specification_digest,
            source_operation_commitment,
            authorization_receipt: receipt,
        })
    }

    /// Returns the execution identity used as the protected journal key.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the original public Create operation identity.
    #[must_use]
    pub const fn create_operation(&self) -> OperationId {
        self.create_operation
    }

    /// Returns the distinct deterministic Observe operation identity.
    #[must_use]
    pub const fn observe_operation(&self) -> OperationId {
        self.observe_operation
    }

    /// Returns the exact canonical Create specification digest.
    #[must_use]
    pub const fn specification_digest(&self) -> ObjectDigest {
        self.specification_digest
    }

    /// Returns the Create source operation commitment.
    #[must_use]
    pub const fn source_operation_commitment(&self) -> [u8; 32] {
        self.source_operation_commitment
    }

    /// Encodes the checksummed versioned reservation record.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RECORD_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(self.execution.as_bytes());
        bytes.extend_from_slice(self.create_operation.as_bytes());
        bytes.extend_from_slice(self.observe_operation.as_bytes());
        bytes.extend_from_slice(self.specification_digest.as_bytes());
        bytes.extend_from_slice(&self.source_operation_commitment);
        bytes.extend_from_slice(&self.authorization_receipt);
        bytes.extend_from_slice(
            &Sha256::new()
                .chain_update(RECORD_DOMAIN)
                .chain_update(&bytes)
                .finalize(),
        );
        bytes
    }

    /// Decodes a record and binds its execution identity to the journal key.
    ///
    /// # Errors
    ///
    /// Rejects invalid framing or checksum, a malformed receipt or Create
    /// binding, a changed derived Observe ID, or a foreign journal key.
    pub fn decode(key: &[u8], bytes: &[u8]) -> Result<Self, ObserveReservationCodecErrorV1> {
        if bytes.len() != RECORD_BYTES || bytes.get(..8) != Some(MAGIC.as_slice()) {
            return Err(ObserveReservationCodecErrorV1::CorruptRecord);
        }
        let checksum_at = RECORD_BYTES - 32;
        let checksum = Sha256::new()
            .chain_update(RECORD_DOMAIN)
            .chain_update(&bytes[..checksum_at])
            .finalize();
        if bytes[checksum_at..] != checksum[..] {
            return Err(ObserveReservationCodecErrorV1::CorruptRecord);
        }

        let mut cursor = MAGIC.len();
        let execution = ExecutionId::from_bytes(read_array::<16>(bytes, &mut cursor)?);
        let create_operation = OperationId::from_bytes(read_array::<16>(bytes, &mut cursor)?);
        let observe_operation = OperationId::from_bytes(read_array::<16>(bytes, &mut cursor)?);
        let specification_digest = ObjectDigest::from_bytes(read_array::<32>(bytes, &mut cursor)?);
        let source_operation_commitment = read_array::<32>(bytes, &mut cursor)?;
        let receipt = read_array::<RECEIPT_BYTES>(bytes, &mut cursor)?;
        if cursor != checksum_at {
            return Err(ObserveReservationCodecErrorV1::CorruptRecord);
        }
        let reconstructed = Self::new(
            execution,
            create_operation,
            specification_digest,
            source_operation_commitment,
            &receipt,
        )?;
        if reconstructed.observe_operation != observe_operation || key != execution.as_bytes() {
            return Err(ObserveReservationCodecErrorV1::CorruptRecord);
        }
        Ok(reconstructed)
    }
}

fn read_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], ObserveReservationCodecErrorV1> {
    let end = (*cursor)
        .checked_add(N)
        .ok_or(ObserveReservationCodecErrorV1::CorruptRecord)?;
    let value = bytes
        .get(*cursor..end)
        .and_then(|value| value.try_into().ok())
        .ok_or(ObserveReservationCodecErrorV1::CorruptRecord)?;
    *cursor = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reservation() -> ControllerExecutionObserveReservationV1 {
        let mut receipt = [5; RECEIPT_BYTES];
        receipt[..8].copy_from_slice(RECEIPT_MAGIC);
        ControllerExecutionObserveReservationV1::new(
            ExecutionId::from_bytes([1; 16]),
            OperationId::from_bytes([2; 16]),
            ObjectDigest::from_bytes([3; 32]),
            [4; 32],
            &receipt,
        )
        .unwrap()
    }

    #[test]
    fn record_requires_exact_key_checksum_and_derived_observe_identity() {
        let reservation = reservation();
        let execution = reservation.execution();
        let key = execution.as_bytes();
        let bytes = reservation.encode();
        assert_eq!(
            ControllerExecutionObserveReservationV1::decode(key, &bytes),
            Ok(reservation)
        );
        assert_eq!(
            ControllerExecutionObserveReservationV1::decode(&[9; 16], &bytes),
            Err(ObserveReservationCodecErrorV1::CorruptRecord)
        );

        let mut altered = bytes.clone();
        altered[40] ^= 1;
        altered.truncate(RECORD_BYTES - 32);
        altered.extend_from_slice(
            &Sha256::new()
                .chain_update(RECORD_DOMAIN)
                .chain_update(&altered)
                .finalize(),
        );
        assert_eq!(
            ControllerExecutionObserveReservationV1::decode(key, &altered),
            Err(ObserveReservationCodecErrorV1::CorruptRecord)
        );

        let mut corrupt = bytes;
        corrupt[159] ^= 1;
        assert_eq!(
            ControllerExecutionObserveReservationV1::decode(key, &corrupt),
            Err(ObserveReservationCodecErrorV1::CorruptRecord)
        );
    }

    #[test]
    fn constructor_rejects_untyped_or_zero_authorization_receipt() {
        let reservation = reservation();
        let args = (
            reservation.execution(),
            reservation.create_operation(),
            reservation.specification_digest(),
            reservation.source_operation_commitment(),
        );
        assert_eq!(
            ControllerExecutionObserveReservationV1::new(args.0, args.1, args.2, args.3, &[5; 39]),
            Err(ObserveReservationCodecErrorV1::ReceiptLength)
        );
        let mut zero = [0; RECEIPT_BYTES];
        zero[..8].copy_from_slice(RECEIPT_MAGIC);
        assert_eq!(
            ControllerExecutionObserveReservationV1::new(args.0, args.1, args.2, args.3, &zero),
            Err(ObserveReservationCodecErrorV1::InvalidBinding)
        );
    }
}
