//! Canonical sealed lifetime admission for the existing Host Apply transport.
//!
//! The current format tags Stream/PTY lifetime DATA separately from genuine
//! physical Capture source DATA. Host still joins its actual native59, signed
//! admission, original verified lease and the appropriate live Storage owner.
//!
//! ```text
//! AOSHEC05 | base-length:u32be | capture-response-length:u32be
//! | kind:u8 | zero[3] | source-length:u32be | canonical-base
//! | source[424 for Stream, 944 for Capture] | capture-response
//! | SHA256(domain || preceding)[32]
//! ```

mod base;

use aos_sandbox_model::{ExecutionOutputModeV1, ExecutionSpecV1, ObjectDigest};
use sha2::{Digest as _, Sha256};

use crate::execution_spec_attempt::ExecutionSpecAttemptFieldsV1;
use crate::storage_capture_grant::{StorageCaptureGrantSourceV1, StorageCaptureGrantSourceV2,
    ValidatedStorageCaptureAttemptV1, STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V2,
    MAXIMUM_RESPONSE_BODY_BYTES, decode_storage_capture_attempt_response_ongoing_v2};
use crate::storage_capture_lifetime::{StorageCaptureExecutionLifetimeDataV2,
    STORAGE_CAPTURE_EXECUTION_LIFETIME_BYTES_V2};
use crate::storage_output_reserve::continuation::decode_storage_output_registration_response_data_v1;
use crate::ProtocolValidationError;
use base::AdmissionBaseDataV5;

const MAGIC: &[u8; 8] = b"AOSHEC05";
const DOMAIN: &[u8] = b"aos.sandbox.host.execution-admission-content.v5\0";
const PREFIX_BYTES: usize = 24;
const CHECKSUM_BYTES: usize = 32;
const STREAM: u8 = 1;
const CAPTURE: u8 = 2;

/// Bounds the exact logical-registration response used by the current frame.
pub const MAXIMUM_LOGICAL_REGISTRATION_BYTES_V5: usize = base::MAXIMUM_STORAGE_RESPONSE_BYTES_V2;

/// Bounds the complete spec, logical registration and largest tagged source.
pub const MAXIMUM_ADMISSION_CONTENT_BYTES_V5: usize = PREFIX_BYTES
    + base::MAXIMUM_ADMISSION_CONTENT_BYTES_V2 + STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V2
    + MAXIMUM_RESPONSE_BODY_BYTES + CHECKSUM_BYTES;

/// Returns exact Stream/PTY framing bytes from its passive encoded input widths.
///
/// This supplies receiving geometry only; canonical decoding and the actual
/// owning lifetime/native admission remain mandatory before Guest issue.
#[must_use]
pub fn stream_encoded_widths_v5(attempt: usize, registration: usize) -> Option<usize> {
    encoded_widths_v5(base::encoded_widths_v5(attempt, registration)?, STREAM, 0)
}

/// Returns exact Capture framing bytes from its passive encoded input widths.
///
/// This prices the fixed real source width and response bytes, without creating
/// a source, pipe, native owner, grant or larger receiving declaration.
#[must_use]
pub fn capture_encoded_widths_v5(attempt: usize, registration: usize, response: usize) -> Option<usize> {
    encoded_widths_v5(base::encoded_widths_v5(attempt, registration)?, CAPTURE, response)
}

fn encoded_widths_v5(base: usize, kind: u8, response: usize) -> Option<usize> {
    let source = match kind {
        STREAM if response == 0 => STORAGE_CAPTURE_EXECUTION_LIFETIME_BYTES_V2,
        CAPTURE if response <= MAXIMUM_RESPONSE_BODY_BYTES => STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V2,
        _ => return None,
    };
    if base > base::MAXIMUM_ADMISSION_CONTENT_BYTES_V2 { return None; }
    PREFIX_BYTES.checked_add(base)?.checked_add(source)?
        .checked_add(response)?.checked_add(CHECKSUM_BYTES)
}

/// Carries the canonical tagged lifetime as comparison DATA only.
///
/// It supplies no native owner, admission, receiving allowance or completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifetimeSourceDataV5 {
    /// Carries the original Stream/PTY lifetime.
    Stream(StorageCaptureExecutionLifetimeDataV2),
    /// Carries the original physical Capture source.
    Capture(StorageCaptureGrantSourceV2),
}

impl LifetimeSourceDataV5 {
    fn kind(&self) -> u8 {
        match self { Self::Stream(_) => STREAM, Self::Capture(_) => CAPTURE }
    }

    fn bytes(&self) -> &[u8] {
        match self {
            Self::Stream(lifetime) => lifetime.canonical_bytes_v2(),
            Self::Capture(source) => source.canonical_bytes_v2(),
        }
    }

    fn lifetime(&self) -> &StorageCaptureExecutionLifetimeDataV2 {
        match self { Self::Stream(lifetime) => lifetime, Self::Capture(source) => source.lifetime_v2() }
    }
}

/// Borrows canonical admission selectors without granting native execution.
#[derive(Clone, Copy, Debug)]
pub struct HostExecutionAdmissionContentV5<'content> {
    base: AdmissionBaseDataV5<'content>,
    source: LifetimeSourceDataV5,
    capture_response: &'content [u8],
    capture_attempt: Option<ValidatedStorageCaptureAttemptV1>,
}

impl<'content> HostExecutionAdmissionContentV5<'content> {
    /// Joins an actual Stream or PTY specification with its original lifetime DATA.
    ///
    /// # Errors
    /// Rejects noncanonical input, a Capture specification, foreign accepted
    /// request/specification/assignment, or a changed original lifetime.
    pub fn new_stream_v5(
        attempt: &'content [u8], registration: &'content [u8],
        lifetime: &StorageCaptureExecutionLifetimeDataV2,
    ) -> Result<Self, ProtocolValidationError> {
        Self::new(AdmissionBaseDataV5::new(attempt, registration)?,
            LifetimeSourceDataV5::Stream(*lifetime), &[])
    }

    /// Joins a Capture specification with its genuine signed-source selectors.
    ///
    /// # Errors
    /// Rejects another specification mode, source/attempt, logical output,
    /// accepted request, assignment, output limits or original lifetime.
    pub fn new_capture_v5(
        attempt: &'content [u8], registration: &'content [u8],
        source: &StorageCaptureGrantSourceV2, capture_response: &'content [u8],
    ) -> Result<Self, ProtocolValidationError> {
        Self::new(AdmissionBaseDataV5::new(attempt, registration)?,
            LifetimeSourceDataV5::Capture(*source), capture_response)
    }

    fn new(base: AdmissionBaseDataV5<'content>, source: LifetimeSourceDataV5,
        capture_response: &'content [u8]) -> Result<Self, ProtocolValidationError> {
        let fields = ExecutionSpecAttemptFieldsV1::decode(base.attempt_bytes()).map_err(|_| invalid())?;
        let specification = fields.decoded_specification().map_err(|_| invalid())?;
        source.lifetime().require_specification_data_v2(&specification,
            fields.create_operation, fields.create_operation, fields.accepted_request_digest)?;
        let capture_attempt = match source {
            LifetimeSourceDataV5::Stream(_) => {
                if specification.io().output_mode() != ExecutionOutputModeV1::Stream || !capture_response.is_empty() {
                    return Err(invalid());
                }
                None
            }
            LifetimeSourceDataV5::Capture(source) => {
                require_capture_source_data_v5(base, source.original_source_v1())?;
                Some(decode_storage_capture_attempt_response_ongoing_v2(capture_response, &source, false)?)
            }
        };
        Ok(Self { base, source, capture_response, capture_attempt })
    }

    /// Decodes only the tagged current grammar through the sole canonical codecs.
    ///
    /// # Errors
    /// Rejects old standalone versions, invalid kind/width/reserved fields,
    /// overflow, checksum, canonical input or complete source associations.
    pub fn decode(bytes: &'content [u8]) -> Result<Self, ProtocolValidationError> {
        if bytes.len() < PREFIX_BYTES + CHECKSUM_BYTES || bytes.len() > MAXIMUM_ADMISSION_CONTENT_BYTES_V5
            || bytes[..8] != *MAGIC || bytes[17..20] != [0; 3]
        { return Err(invalid()); }
        let length = |start: usize| -> Result<usize, ProtocolValidationError> {
            Ok(u32::from_be_bytes(bytes[start..start + 4].try_into().map_err(|_| invalid())?) as usize)
        };
        let base_len = length(8)?;
        let response_len = length(12)?;
        let source_len = length(20)?;
        let expected_source_len = match bytes[16] {
            STREAM => STORAGE_CAPTURE_EXECUTION_LIFETIME_BYTES_V2,
            CAPTURE => STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V2,
            _ => return Err(invalid()),
        };
        let base_end = PREFIX_BYTES.checked_add(base_len).ok_or_else(invalid)?;
        let source_end = base_end.checked_add(source_len).ok_or_else(invalid)?;
        let end = source_end.checked_add(response_len).ok_or_else(invalid)?;
        if base_len > base::MAXIMUM_ADMISSION_CONTENT_BYTES_V2 || source_len != expected_source_len
            || response_len > MAXIMUM_RESPONSE_BODY_BYTES
            || end.checked_add(CHECKSUM_BYTES) != Some(bytes.len())
            || checksum(&bytes[..end]) != bytes[end..]
        { return Err(invalid()); }
        let source_bytes = &bytes[base_end..source_end];
        let source = match bytes[16] {
            STREAM => LifetimeSourceDataV5::Stream(StorageCaptureExecutionLifetimeDataV2::from_canonical_bytes_v2(source_bytes)?),
            CAPTURE => LifetimeSourceDataV5::Capture(StorageCaptureGrantSourceV2::from_canonical_bytes_v2(source_bytes)?),
            _ => return Err(invalid()),
        };
        Self::new(AdmissionBaseDataV5::decode(&bytes[PREFIX_BYTES..base_end])?,
            source, &bytes[source_end..end])
    }

    /// Encodes one exact current sealed admission without changing its lifetime.
    ///
    /// # Errors
    /// Rejects canonical input or arithmetic/encoded length bounds before growth.
    pub fn encode(self) -> Result<Vec<u8>, ProtocolValidationError> {
        Self::new(self.base, self.source, self.capture_response)?;
        let base = self.base.encode()?;
        let source = self.source.bytes();
        let total = encoded_widths_v5(base.len(), self.source.kind(), self.capture_response.len())
            .ok_or_else(invalid)?;
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&u32::try_from(base.len()).map_err(|_| invalid())?.to_be_bytes());
        bytes.extend_from_slice(&u32::try_from(self.capture_response.len()).map_err(|_| invalid())?.to_be_bytes());
        bytes.push(self.source.kind());
        bytes.extend_from_slice(&[0; 3]);
        bytes.extend_from_slice(&u32::try_from(source.len()).map_err(|_| invalid())?.to_be_bytes());
        bytes.extend_from_slice(&base);
        bytes.extend_from_slice(source);
        bytes.extend_from_slice(self.capture_response);
        let digest = checksum(&bytes);
        bytes.extend_from_slice(&digest);
        Ok(bytes)
    }

    /// Borrows the exact protected specification-attempt bytes.
    #[must_use]
    pub const fn attempt_bytes(self) -> &'content [u8] { self.base.attempt_bytes() }

    /// Borrows the exact authenticated logical registration response.
    #[must_use]
    pub const fn storage_response_bytes(self) -> &'content [u8] { self.base.storage_response_bytes() }

    /// Borrows the canonical specification without reconstructing its source.
    ///
    /// # Errors
    /// Rejects malformed specification-attempt DATA.
    pub fn specification_bytes(self) -> Result<&'content [u8], ProtocolValidationError> { self.base.specification_bytes() }

    /// Copies the source already validated by this exact content decoder.
    ///
    /// This comparison DATA grants no signed or native permission.
    #[must_use]
    pub const fn source_data_v5(&self) -> LifetimeSourceDataV5 { self.source }

    /// Borrows the same complete original lifetime for either execution mode.
    #[must_use]
    pub fn lifetime_v2(&self) -> &StorageCaptureExecutionLifetimeDataV2 { self.source.lifetime() }

    /// Borrows a physical source only for the actual Capture variant.
    #[must_use]
    pub fn capture_source_v2(&self) -> Option<&StorageCaptureGrantSourceV2> {
        match &self.source { LifetimeSourceDataV5::Capture(source) => Some(source), _ => None }
    }

    /// Copies a canonical Capture attempt only for the physical variant.
    #[must_use]
    pub const fn capture_attempt_v1(&self) -> Option<ValidatedStorageCaptureAttemptV1> { self.capture_attempt }

    /// Borrows the exact signed physical-attempt response, empty for Stream.
    #[must_use]
    pub const fn capture_response_bytes_v5(&self) -> &'content [u8] {
        self.capture_response
    }

    /// Returns the complete tagged-source commitment as comparison DATA.
    #[must_use]
    pub fn source_digest_v5(&self) -> ObjectDigest {
        match &self.source {
            LifetimeSourceDataV5::Stream(lifetime) => lifetime.digest_v2(),
            LifetimeSourceDataV5::Capture(source) => source.source_digest_v2(),
        }
    }
}

fn checksum(bytes: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(DOMAIN).chain_update(bytes).finalize().into()
}

fn invalid() -> ProtocolValidationError {
    ProtocolValidationError::InvalidField("Host version-five execution lifetime admission")
}

fn require_capture_source_data_v5<'content>(
    base: AdmissionBaseDataV5<'content>, source: &StorageCaptureGrantSourceV1,
) -> Result<(ExecutionSpecAttemptFieldsV1<'content>, ExecutionSpecV1), ProtocolValidationError> {
        let fields = ExecutionSpecAttemptFieldsV1::decode(base.attempt_bytes())
            .map_err(|_| invalid())?;
        let specification = fields.decoded_specification().map_err(|_| invalid())?;
        let ExecutionOutputModeV1::Capture { maximum_stdout_bytes, maximum_stderr_bytes }
            = specification.io().output_mode() else { return Err(invalid()) };
        let storage = decode_storage_output_registration_response_data_v1(
            base.storage_response_bytes())?;
        let target = specification.target();
        let assignment = source.assignment();
        let output_assignment = specification.resources().output_bytes().assignment()
            .broker_assignment().map_err(|_| invalid())?;
        if assignment != output_assignment
            || source.settlement().execution() != fields.execution
            || source.settlement().create_operation() != fields.create_operation
            || source.settlement().record_digest() != fields.source_heads.output_settlement
            || assignment.sandbox() != target.sandbox()
            || assignment.incarnation() != target.incarnation()
            || assignment.epoch() != target.assignment_epoch()
            || assignment.digest() != fields.source_heads.assignment_digest
            || assignment.epoch().get() != fields.source_heads.assignment_epoch
            || source.output_claim_digest() != fields.source_heads.output_claim
            || source.output_record_digest().as_bytes()
                != Sha256::digest(&storage.canonical_reservation).as_slice()
            || source.output_limits() != (specification.resources().output_bytes().admitted_bytes(),
                maximum_stdout_bytes, maximum_stderr_bytes)
        {
            return Err(invalid());
        }
        Ok((fields, specification))
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_standalone_and_unknown_source_versions_refuse_before_nested_decode() {
        for magic in [b"AOSHEC02", b"AOSHEC04", b"AOSHEC06"] {
            let mut bytes = vec![0; PREFIX_BYTES + CHECKSUM_BYTES];
            bytes[..8].copy_from_slice(magic);
            assert!(HostExecutionAdmissionContentV5::decode(&bytes).is_err());
        }
        for kind in [0, 3, 255] {
            let mut bytes = vec![0; PREFIX_BYTES + CHECKSUM_BYTES];
            bytes[..8].copy_from_slice(MAGIC);
            bytes[16] = kind;
            assert!(HostExecutionAdmissionContentV5::decode(&bytes).is_err());
        }
    }

    #[test]
    fn source_kind_requires_its_own_exact_width_and_zero_reserved_fields() {
        for (kind, width) in [(STREAM, STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V2),
            (CAPTURE, STORAGE_CAPTURE_EXECUTION_LIFETIME_BYTES_V2)]
        {
            let mut bytes = vec![0; PREFIX_BYTES + width + CHECKSUM_BYTES];
            bytes[..8].copy_from_slice(MAGIC);
            bytes[16] = kind;
            bytes[20..24].copy_from_slice(&(width as u32).to_be_bytes());
            let end = bytes.len() - CHECKSUM_BYTES;
            let digest = checksum(&bytes[..end]);
            bytes[end..].copy_from_slice(&digest);
            assert!(HostExecutionAdmissionContentV5::decode(&bytes).is_err());
        }
        let mut bytes = vec![0; PREFIX_BYTES + CHECKSUM_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[16] = STREAM;
        bytes[17] = 1;
        assert!(HostExecutionAdmissionContentV5::decode(&bytes).is_err());
    }
}
