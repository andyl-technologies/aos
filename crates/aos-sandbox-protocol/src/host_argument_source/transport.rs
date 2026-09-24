//! Authenticated request-body reference for one sealed AOSCAS01 descriptor.
//!
//! This validates transport exactness, not accepted-Create authority. The
//! signed Host-audience grant issuer and Host one-shot owner are not wired, so
//! production dispatch must reject even a structurally valid request before
//! sending on the retained Guest channel.

use aos_proto::aos::sandbox::local::v1::ObserveHostRuntimeArgumentRequestV1;
use aos_sandbox_core::{ExecutionId, ObjectDigest, OperationId, ProtocolId};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use super::{
    DecodedControllerExecutionArgumentSourceV1,
    MAXIMUM_CONTROLLER_EXECUTION_ARGUMENT_SOURCE_BYTES_V1,
    decode_controller_execution_argument_source_v1,
};
use crate::{
    PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedHeader, exact_nonzero,
    validate_request_header,
};

const MAXIMUM_REQUEST_BODY_BYTES: usize = 4 * 1024;
const SOURCE_TRANSFER_VERSION: u32 = 1;
const ATTEMPT_DOMAIN: &[u8] = b"aos.sandbox.host.argument-source-attempt.v1\0";

/// Binds exact sealed source bytes to one signed broker request attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostArgumentSourceContentFieldsV1 {
    bytes: u64,
    digest: [u8; 32],
    source_digest: ObjectDigest,
    attempt_commitment: [u8; 32],
}

impl HostArgumentSourceContentFieldsV1 {
    /// Returns the exact required sealed descriptor size.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.bytes
    }

    /// Returns raw SHA-256 of the complete sealed source bytes.
    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }

    /// Returns the structural source digest stored inside AOSCAS01.
    #[must_use]
    pub const fn source_digest(self) -> ObjectDigest {
        self.source_digest
    }

    /// Returns the signed transport-attempt commitment.
    #[must_use]
    pub const fn attempt_commitment(self) -> [u8; 32] {
        self.attempt_commitment
    }
}

/// Carries a canonical request without granting Guest observation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedHostRuntimeArgumentRequestV1 {
    header: ValidatedHeader,
    execution: ExecutionId,
    create_operation: OperationId,
    content: HostArgumentSourceContentFieldsV1,
}

impl ValidatedHostRuntimeArgumentRequestV1 {
    /// Returns the validated Host broker request header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the execution locator bound by the signed body.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the accepted Create operation locator bound by the signed body.
    #[must_use]
    pub const fn create_operation(&self) -> OperationId {
        self.create_operation
    }

    /// Returns the exact signed descriptor reference.
    #[must_use]
    pub const fn content_fields(&self) -> HostArgumentSourceContentFieldsV1 {
        self.content
    }

    /// Checks mapped sealed bytes against the signed attempt and boot deadline.
    ///
    /// This proves no accepted-Create grant, assignment currentness, or Guest
    /// session. The Host must reject dispatch until those separate owners are
    /// wired. The source and request deadlines are each checked independently.
    ///
    /// # Errors
    ///
    /// Rejects changed content, source/locator mismatch, a foreign Host boot,
    /// or expiry of either monotonic deadline.
    pub fn verify_source(
        &self,
        content: &[u8],
        host_boot_id: [u8; 16],
        now_boottime_nanoseconds: u64,
    ) -> Result<DecodedControllerExecutionArgumentSourceV1, ProtocolValidationError> {
        if self.header.deadline_boottime_nanoseconds() <= now_boottime_nanoseconds {
            return Err(ProtocolValidationError::DeadlineExpired);
        }
        let actual = host_argument_source_content_fields_v1(
            *self.header.request_id(),
            self.execution,
            self.create_operation,
            content,
        )?;
        if actual != self.content {
            return Err(ProtocolValidationError::InvalidField(
                "argument source content",
            ));
        }
        let source = decode_controller_execution_argument_source_v1(content)
            .map_err(|_| ProtocolValidationError::InvalidField("argument source content"))?;
        if source.host_boot_id() != host_boot_id {
            return Err(ProtocolValidationError::InvalidField(
                "argument source host boot",
            ));
        }
        if source.deadline_boottime_nanoseconds() <= now_boottime_nanoseconds {
            return Err(ProtocolValidationError::DeadlineExpired);
        }
        Ok(source)
    }
}

/// Derives the reference to one structurally canonical sealed AOSCAS01 value.
///
/// This is a transport helper, not a Controller issuer or Host authorization.
/// A future signed grant must cover every returned field and the exact body.
///
/// # Errors
///
/// Rejects empty, oversized, noncanonical, or different-locator source bytes.
pub fn host_argument_source_content_fields_v1(
    request_id: [u8; 16],
    execution: ExecutionId,
    create_operation: OperationId,
    content: &[u8],
) -> Result<HostArgumentSourceContentFieldsV1, ProtocolValidationError> {
    if content.is_empty() || content.len() > MAXIMUM_CONTROLLER_EXECUTION_ARGUMENT_SOURCE_BYTES_V1 {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let source = decode_controller_execution_argument_source_v1(content)
        .map_err(|_| ProtocolValidationError::InvalidField("argument source content"))?;
    if source.execution() != execution || source.create_operation() != create_operation {
        return Err(ProtocolValidationError::InvalidField(
            "argument source locator",
        ));
    }
    let bytes = content.len() as u64;
    let digest: [u8; 32] = Sha256::digest(content).into();
    let source_digest = source.source_digest();
    let attempt_commitment = attempt_commitment(
        request_id,
        execution,
        create_operation,
        bytes,
        digest,
        source_digest,
    );
    Ok(HostArgumentSourceContentFieldsV1 {
        bytes,
        digest,
        source_digest,
        attempt_commitment,
    })
}

/// Decodes the canonical authenticated Host argument-source request body.
///
/// The source itself is verified only after the pinned sealed descriptor is
/// mapped. No response success or Guest dispatch is authorized by this body.
///
/// # Errors
///
/// Rejects malformed, unknown-field, oversized, expired, or inconsistent
/// transport references and foreign broker headers.
pub fn decode_host_runtime_argument_request_v1(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedHostRuntimeArgumentRequestV1, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_REQUEST_BODY_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = ObserveHostRuntimeArgumentRequestV1::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != bytes {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let header = validate_request_header(
        request
            .header
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?,
        peer,
        policy,
        ProtocolId::HostBroker,
        now_boottime_nanoseconds,
    )?;
    if request.source_transfer_version != SOURCE_TRANSFER_VERSION
        || request.source_content_bytes == 0
        || request.source_content_bytes
            > MAXIMUM_CONTROLLER_EXECUTION_ARGUMENT_SOURCE_BYTES_V1 as u64
    {
        return Err(ProtocolValidationError::InvalidField(
            "argument source transfer",
        ));
    }

    let execution =
        ExecutionId::from_bytes(exact_nonzero::<16>(&request.execution_id, "execution_id")?);
    let create_operation = OperationId::from_bytes(exact_nonzero::<16>(
        &request.create_operation_id,
        "create_operation_id",
    )?);
    let digest = exact_nonzero::<32>(&request.source_content_digest, "source_content_digest")?;
    let source_digest = ObjectDigest::from_bytes(exact_nonzero::<32>(
        &request.source_digest,
        "source_digest",
    )?);
    let expected = attempt_commitment(
        *header.request_id(),
        execution,
        create_operation,
        request.source_content_bytes,
        digest,
        source_digest,
    );
    if exact_nonzero::<32>(
        &request.source_attempt_commitment,
        "source_attempt_commitment",
    )? != expected
    {
        return Err(ProtocolValidationError::InvalidField(
            "source_attempt_commitment",
        ));
    }
    Ok(ValidatedHostRuntimeArgumentRequestV1 {
        header,
        execution,
        create_operation,
        content: HostArgumentSourceContentFieldsV1 {
            bytes: request.source_content_bytes,
            digest,
            source_digest,
            attempt_commitment: expected,
        },
    })
}

fn attempt_commitment(
    request_id: [u8; 16],
    execution: ExecutionId,
    create_operation: OperationId,
    bytes: u64,
    digest: [u8; 32],
    source_digest: ObjectDigest,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(ATTEMPT_DOMAIN);
    hash.update(SOURCE_TRANSFER_VERSION.to_be_bytes());
    hash.update(request_id);
    hash.update(execution.as_bytes());
    hash.update(create_operation.as_bytes());
    hash.update(bytes.to_be_bytes());
    hash.update(digest);
    hash.update(source_digest.as_bytes());
    hash.finalize().into()
}
