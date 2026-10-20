//! Canonical historical Controller argument receipt DATA, without fresh authority.
//!
//! ```text
//! AOSCAF01 | execution16 | Create16 | attempt32 | requestSHA32 |
//! outcomeSHA32 | HostReceiptLen:u16BE | HostReceipt | checksum32
//! ```

use aos_sandbox_model::{ExecutionId, ObjectDigest, OperationId};
use sha2::{Digest as _, Sha256};
use crate::host_execution_argument::receipt::MAXIMUM_HOST_ARGUMENT_FRESH_RECEIPT_BYTES_V1;
const MAGIC: &[u8; 8] = b"AOSCAF01";
const DOMAIN: &[u8] = b"aos.sandbox.controller-argument-receipt.v1\0";
const FIXED_BYTES: usize = 8 + 16 + 16 + 32 + 32 + 32 + 2 + 32;
/// Bounds one complete original argument receipt record.
pub const MAXIMUM_RECORD_BYTES: usize = FIXED_BYTES + MAXIMUM_HOST_ARGUMENT_FRESH_RECEIPT_BYTES_V1;

/// Reports malformed or inconsistent historical receipt DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ControllerArgumentReceiptDataErrorV1 {
    /// Original framing, identity, checksum or canonical bytes disagree.
    #[error("invalid Controller argument receipt DATA")]
    Mismatch,
}

/// Contains original nonauthorizing Controller argument receipt fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerArgumentReceiptDataV1 {
    /// Exact execution identity.
    pub execution: ExecutionId,
    /// Original accepted Create identity.
    pub create_operation: OperationId,
    /// Exact protected argument attempt commitment.
    pub attempt_digest: ObjectDigest,
    /// SHA256 of the complete signed request packet.
    pub request_packet_digest: ObjectDigest,
    /// SHA256 of the complete signed outcome packet.
    pub outcome_packet_digest: ObjectDigest,
    /// Exact canonical Host-attested argument receipt DATA.
    pub exact_host_receipt: Vec<u8>,
    /// Domain-separated checksum of the complete record prefix.
    pub record_digest: ObjectDigest,
}

impl ControllerArgumentReceiptDataV1 {
    /// Encodes the original bounded Controller receipt DATA.
    ///
    /// # Errors
    /// Rejects an unrepresentable retained Host receipt length.
    pub fn encode(&self) -> Result<Vec<u8>, ControllerArgumentReceiptDataErrorV1> {
        let receipt_length = u16::try_from(self.exact_host_receipt.len())
            .map_err(|_| ControllerArgumentReceiptDataErrorV1::Mismatch)?;
        let mut bytes = Vec::with_capacity(FIXED_BYTES + self.exact_host_receipt.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(self.execution.as_bytes());
        bytes.extend_from_slice(self.create_operation.as_bytes());
        bytes.extend_from_slice(self.attempt_digest.as_bytes());
        bytes.extend_from_slice(self.request_packet_digest.as_bytes());
        bytes.extend_from_slice(self.outcome_packet_digest.as_bytes());
        bytes.extend_from_slice(&receipt_length.to_be_bytes());
        bytes.extend_from_slice(&self.exact_host_receipt);
        bytes.extend_from_slice(self.record_digest.as_bytes());
        Ok(bytes)
    }

    /// Decodes exact bounded receipt framing, checksums and identities.
    ///
    /// # Errors
    /// Rejects malformed framing, length, checksum or zero required fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, ControllerArgumentReceiptDataErrorV1> {
        if bytes.len() < FIXED_BYTES
            || bytes.len() > MAXIMUM_RECORD_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
        {
            return Err(ControllerArgumentReceiptDataErrorV1::Mismatch);
        }
        let read_16 =
            |start: usize| -> Result<[u8; 16], ControllerArgumentReceiptDataErrorV1> {
                bytes[start..start + 16]
                    .try_into()
                    .map_err(|_| ControllerArgumentReceiptDataErrorV1::Mismatch)
            };
        let read_32 =
            |start: usize| -> Result<ObjectDigest, ControllerArgumentReceiptDataErrorV1> {
                Ok(ObjectDigest::from_bytes(
                    bytes[start..start + 32]
                        .try_into()
                        .map_err(|_| ControllerArgumentReceiptDataErrorV1::Mismatch)?,
                ))
            };
        let receipt_length = usize::from(u16::from_be_bytes(
            bytes[136..138]
                .try_into()
                .map_err(|_| ControllerArgumentReceiptDataErrorV1::Mismatch)?,
        ));
        if receipt_length == 0 || bytes.len() != FIXED_BYTES + receipt_length {
            return Err(ControllerArgumentReceiptDataErrorV1::Mismatch);
        }
        let checksum_start = bytes.len() - 32;
        let record = Self {
            execution: ExecutionId::from_bytes(read_16(8)?),
            create_operation: OperationId::from_bytes(read_16(24)?),
            attempt_digest: read_32(40)?,
            request_packet_digest: read_32(72)?,
            outcome_packet_digest: read_32(104)?,
            exact_host_receipt: bytes[138..checksum_start].to_vec(),
            record_digest: read_32(checksum_start)?,
        };
        if !record.is_valid()
            || record.record_digest != digest_record(&bytes[..checksum_start])
            || record.encode()? != bytes
        {
            return Err(ControllerArgumentReceiptDataErrorV1::Mismatch);
        }
        Ok(record)
    }

    /// Checks the original required field and retained receipt byte bounds.
    ///
    /// This does not authenticate Host bytes or create a fresh observation.
    #[doc(hidden)]
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.execution.as_bytes() != &[0; 16]
            && self.create_operation.as_bytes() != &[0; 16]
            && self.attempt_digest.as_bytes() != &[0; 32]
            && self.request_packet_digest.as_bytes() != &[0; 32]
            && self.outcome_packet_digest.as_bytes() != &[0; 32]
            && !self.exact_host_receipt.is_empty()
            && self.exact_host_receipt.len() <= MAXIMUM_HOST_ARGUMENT_FRESH_RECEIPT_BYTES_V1
    }
}

/// Computes the original purpose-separated record-prefix checksum.
#[must_use]
pub fn digest_record(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}
