//! Versioned sealed admission content for the existing Host Apply method.
//!
//! The complete Controller attempt already contains the canonical spec. The
//! Storage response is historical selector DATA; Host must independently hold
//! the actual matching Storage writer while retaining its live argument owner.
//!
//! ```text
//! AOSHEC02 | attempt-length:u32be | Storage-response-length:u32be |
//! canonical-AOSCSI01 | canonical-StorageOutputRegistrationResponseV1 |
//! SHA256(domain || preceding)[32]
//! ```

use sha2::{Digest as _, Sha256};
use crate::execution_spec_attempt::{ExecutionSpecAttemptFieldsV1,
    MAXIMUM_RECORD_BYTES, ExecutionSpecAttemptDataErrorV1};
use crate::storage_output_reserve::continuation::decode_storage_output_registration_response_data_v1;
use crate::ProtocolValidationError;

const MAGIC: &[u8; 8] = b"AOSHEC02";
const DOMAIN: &[u8] = b"aos.sandbox.host.execution-admission-content.v2\0";
const PREFIX_BYTES: usize = 16;
const CHECKSUM_BYTES: usize = 32;
/// Bounds the same canonical Storage response accepted by its existing decoder.
pub(super) const MAXIMUM_STORAGE_RESPONSE_BYTES_V2: usize = 1024;
/// Preserves the complete maximum-size spec plus all exact admission framing.
pub(super) const MAXIMUM_ADMISSION_CONTENT_BYTES_V2: usize = PREFIX_BYTES + MAXIMUM_RECORD_BYTES
    + MAXIMUM_STORAGE_RESPONSE_BYTES_V2 + CHECKSUM_BYTES;

/// Borrows canonical historical input for a future closed Host admission.
#[derive(Clone, Copy, Debug)]
pub(super) struct AdmissionBaseDataV5<'content> {
    attempt: &'content [u8],
    storage_response: &'content [u8],
}

impl<'content> AdmissionBaseDataV5<'content> {
    /// Joins historical byte inputs without conferring authority.
    ///
    /// # Errors
    /// Rejects noncanonical attempts or Storage responses and mismatched claims.
    pub fn new(attempt: &'content [u8], storage_response: &'content [u8])
        -> Result<Self, ProtocolValidationError> {
        let fields = ExecutionSpecAttemptFieldsV1::decode(attempt).map_err(attempt_error)?;
        let specification = fields.decoded_specification().map_err(attempt_error)?;
        let storage = decode_storage_output_registration_response_data_v1(storage_response)?;
        let row = &storage.canonical_reservation;
        let marker = &storage.canonical_original_marker;
        if row[..8] != *b"AOSEOR03" || marker[..8] != *b"AOSEOS01"
            || row[8..24] != *fields.execution.as_bytes()
            || row[24..40] != *fields.create_operation.as_bytes()
            || row[40..72] != *fields.source_heads.assignment_digest.as_bytes()
            || row[72..104] != *fields.source_heads.output_claim.as_bytes()
            || u64::from_be_bytes(row[104..112].try_into().map_err(|_| invalid())?)
                != specification.resources().output_bytes().admitted_bytes()
            || row[128] != 1 || row[129..145] != [0; 16]
            || marker[8..24] == [0; 16] || marker[56..88] == [0; 32] || marker[88..120] == [0; 32]
            || marker[24..40] != row[8..24] || marker[40..56] != row[24..40]
            || &marker[120..152] != Sha256::digest(row).as_slice()
        {
            return Err(invalid());
        }
        Ok(Self { attempt, storage_response })
    }

    /// Decodes exact version-two content using the sole attempt/response codecs.
    ///
    /// # Errors
    /// Rejects framing overflow, wrong bounds, checksum or canonical DATA.
    pub fn decode(bytes: &'content [u8]) -> Result<Self, ProtocolValidationError> {
        if bytes.len() < PREFIX_BYTES + CHECKSUM_BYTES || bytes.len() > MAXIMUM_ADMISSION_CONTENT_BYTES_V2
            || bytes[..8] != *MAGIC {
            return Err(invalid());
        }
        let attempt_len = u32::from_be_bytes(bytes[8..12].try_into().map_err(|_| invalid())?) as usize;
        let storage_len = u32::from_be_bytes(bytes[12..16].try_into().map_err(|_| invalid())?) as usize;
        let end = PREFIX_BYTES.checked_add(attempt_len).and_then(|end| end.checked_add(storage_len))
            .ok_or_else(invalid)?;
        if attempt_len > MAXIMUM_RECORD_BYTES || storage_len > MAXIMUM_STORAGE_RESPONSE_BYTES_V2
            || end.checked_add(CHECKSUM_BYTES) != Some(bytes.len())
            || checksum(&bytes[..end]) != bytes[end..] {
            return Err(invalid());
        }
        Self::new(&bytes[PREFIX_BYTES..PREFIX_BYTES + attempt_len], &bytes[PREFIX_BYTES + attempt_len..end])
    }

    /// Encodes the complete historical content for one sealed descriptor.
    ///
    /// # Errors
    /// Rejects length conversion or noncanonical input before allocating.
    pub fn encode(self) -> Result<Vec<u8>, ProtocolValidationError> {
        Self::new(self.attempt, self.storage_response)?;
        let attempt_len = u32::try_from(self.attempt.len()).map_err(|_| invalid())?;
        let storage_len = u32::try_from(self.storage_response.len()).map_err(|_| invalid())?;
        let length = encoded_widths_v5(self.attempt.len(), self.storage_response.len())
            .ok_or_else(invalid)?;
        let mut bytes = Vec::with_capacity(length);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&attempt_len.to_be_bytes());
        bytes.extend_from_slice(&storage_len.to_be_bytes());
        bytes.extend_from_slice(self.attempt);
        bytes.extend_from_slice(self.storage_response);
        let digest = checksum(&bytes);
        bytes.extend_from_slice(&digest);
        Ok(bytes)
    }

    /// Borrows the complete canonical Controller historical attempt.
    pub const fn attempt_bytes(self) -> &'content [u8] { self.attempt }

    /// Borrows the canonical historical Storage row and original marker.
    pub const fn storage_response_bytes(self) -> &'content [u8] { self.storage_response }

    /// Borrows the canonical specification without reconstructing its source.
    ///
    /// # Errors
    /// Rejects invalid attempt DATA; no currentness or role is established.
    pub fn specification_bytes(self) -> Result<&'content [u8], ProtocolValidationError> {
        Ok(ExecutionSpecAttemptFieldsV1::decode(self.attempt).map_err(attempt_error)?.specification_bytes)
    }
}

// Both the actual encoder and the outer passive supplier share exact framing.
pub(super) fn encoded_widths_v5(attempt: usize, storage: usize) -> Option<usize> {
    if attempt > MAXIMUM_RECORD_BYTES || storage > MAXIMUM_STORAGE_RESPONSE_BYTES_V2 {
        return None;
    }
    PREFIX_BYTES.checked_add(attempt)?.checked_add(storage)?.checked_add(CHECKSUM_BYTES)
}

fn checksum(bytes: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(DOMAIN).chain_update(bytes).finalize().into()
}

fn invalid() -> ProtocolValidationError {
    ProtocolValidationError::InvalidField("Host execution admission content")
}

fn attempt_error(_: ExecutionSpecAttemptDataErrorV1) -> ProtocolValidationError { invalid() }
