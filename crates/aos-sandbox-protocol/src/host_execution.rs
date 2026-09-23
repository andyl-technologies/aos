//! Canonical controller-to-Host execution handoff and protected readback bodies.
//!
//! These decoders establish wire shape and cross-links. The authenticated
//! broker session proves the sender; the fixed Host execution owner supplies
//! currentness, admission, effect, and outcome authority.

use aos_proto::aos::sandbox::local::v1::{
    ApplyHostExecutionRequestV1, HostExecutionActionV1, HostExecutionCompletionStatusV1,
    HostExecutionOutcomeV1, HostExecutionPhaseV1, QueryHostExecutionRequestV1,
};
use aos_sandbox_core::runtime_backend::EffectOperationV1;
use aos_sandbox_core::{
    DecodeLimits, ExecutionId, ObjectDigest, ProtocolId, decode_execution_spec_v1,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::{
    PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedHeader, exact_nonzero,
    validate_request_header,
};

const MAXIMUM_HANDOFF_BODY_BYTES: usize = 64 * 1024;

/// Carries a validated intent without granting execution authority.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedHostExecutionApplyV1 {
    header: ValidatedHeader,
    operation_id: [u8; 16],
    execution_id: ExecutionId,
    source_commitment: ObjectDigest,
    action: EffectOperationV1,
    specification: Option<aos_sandbox_core::ExecutionSpecV1>,
}

impl ValidatedHostExecutionApplyV1 {
    /// Returns the validated broker request header.
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the stable controller operation identity.
    pub const fn operation_id(&self) -> [u8; 16] {
        self.operation_id
    }

    /// Returns the exact execution identity.
    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    /// Returns the controller's stable canonical operation commitment.
    pub const fn source_commitment(&self) -> ObjectDigest {
        self.source_commitment
    }

    /// Returns the closed guest control action.
    pub const fn action(&self) -> EffectOperationV1 {
        self.action
    }

    /// Borrows the canonical execution specification for authorization.
    pub const fn specification(&self) -> Option<&aos_sandbox_core::ExecutionSpecV1> {
        self.specification.as_ref()
    }
}

/// Carries a validated readback locator without granting an effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedHostExecutionQueryV1 {
    header: ValidatedHeader,
    operation_id: [u8; 16],
    execution_id: ExecutionId,
    source_commitment: ObjectDigest,
}

impl ValidatedHostExecutionQueryV1 {
    /// Returns the validated broker request header.
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the stable controller operation identity.
    pub const fn operation_id(&self) -> [u8; 16] {
        self.operation_id
    }

    /// Returns the exact execution identity.
    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    /// Returns the controller's stable canonical operation commitment.
    pub const fn source_commitment(&self) -> ObjectDigest {
        self.source_commitment
    }
}

/// Decodes one canonical authenticated Host execution intent.
///
/// # Errors
///
/// Rejects oversized, noncanonical, unknown-field, malformed, or semantically
/// inconsistent requests and expired or foreign broker headers.
pub fn decode_host_execution_apply_v1(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedHostExecutionApplyV1, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_HANDOFF_BODY_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = ApplyHostExecutionRequestV1::decode_from_slice(bytes)
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
    let operation_id = exact_nonzero::<16>(&request.operation_id, "operation_id")?;
    let execution_id =
        ExecutionId::from_bytes(exact_nonzero::<16>(&request.execution_id, "execution_id")?);
    let source_commitment = ObjectDigest::from_bytes(exact_nonzero::<32>(
        &request.source_operation_commitment,
        "source_operation_commitment",
    )?);

    let no_geometry = request.terminal_rows == 0 && request.terminal_columns == 0;
    let action = match request.action.as_known() {
        Some(HostExecutionActionV1::HOST_EXECUTION_ACTION_AUTHORIZE)
            if no_geometry
                && request.signal_number == 0
                && !request.canonical_execution_spec.is_empty() =>
        {
            EffectOperationV1::AuthorizeExecution
        }
        Some(HostExecutionActionV1::HOST_EXECUTION_ACTION_RESIZE)
            if request.signal_number == 0 && request.canonical_execution_spec.is_empty() =>
        {
            let rows = u16::try_from(request.terminal_rows)
                .ok()
                .filter(|value| *value != 0)
                .ok_or(ProtocolValidationError::InvalidField("terminal_rows"))?;
            let columns = u16::try_from(request.terminal_columns)
                .ok()
                .filter(|value| *value != 0)
                .ok_or(ProtocolValidationError::InvalidField("terminal_columns"))?;
            EffectOperationV1::ResizeTerminal { rows, columns }
        }
        Some(HostExecutionActionV1::HOST_EXECUTION_ACTION_SIGNAL)
            if no_geometry
                && request.canonical_execution_spec.is_empty()
                && (1..=64).contains(&request.signal_number) =>
        {
            EffectOperationV1::Signal {
                signal_code: request.signal_number as u8,
            }
        }
        Some(HostExecutionActionV1::HOST_EXECUTION_ACTION_CANCEL)
            if no_geometry
                && request.signal_number == 0
                && request.canonical_execution_spec.is_empty() =>
        {
            EffectOperationV1::Cancel
        }
        Some(HostExecutionActionV1::HOST_EXECUTION_ACTION_OBSERVE)
            if no_geometry
                && request.signal_number == 0
                && request.canonical_execution_spec.is_empty() =>
        {
            EffectOperationV1::Observe
        }
        _ => {
            return Err(ProtocolValidationError::InvalidField(
                "execution action fields",
            ));
        }
    };
    let specification = if matches!(action, EffectOperationV1::AuthorizeExecution) {
        let limits = DecodeLimits {
            maximum_bytes: MAXIMUM_HANDOFF_BODY_BYTES,
            ..DecodeLimits::default()
        };
        let specification = decode_execution_spec_v1(&request.canonical_execution_spec, limits)
            .map_err(|_| ProtocolValidationError::InvalidField("canonical_execution_spec"))?;
        if specification.execution() != execution_id {
            return Err(ProtocolValidationError::InvalidField("execution_id"));
        }
        Some(specification)
    } else {
        None
    };

    Ok(ValidatedHostExecutionApplyV1 {
        header,
        operation_id,
        execution_id,
        source_commitment,
        action,
        specification,
    })
}

/// Decodes one canonical protected-outcome readback locator.
///
/// # Errors
///
/// Rejects malformed, noncanonical, expired, or foreign requests.
pub fn decode_host_execution_query_v1(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedHostExecutionQueryV1, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_HANDOFF_BODY_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = QueryHostExecutionRequestV1::decode_from_slice(bytes)
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
    Ok(ValidatedHostExecutionQueryV1 {
        header,
        operation_id: exact_nonzero::<16>(&request.operation_id, "operation_id")?,
        execution_id: ExecutionId::from_bytes(exact_nonzero::<16>(
            &request.execution_id,
            "execution_id",
        )?),
        source_commitment: ObjectDigest::from_bytes(exact_nonzero::<32>(
            &request.source_operation_commitment,
            "source_operation_commitment",
        )?),
    })
}

/// Checks a Host result against an exact authenticated apply or query locator.
///
/// # Errors
///
/// Rejects foreign IDs, malformed phase-specific fields, and noncanonical wire.
pub fn decode_host_execution_outcome_v1(
    bytes: &[u8],
    operation_id: [u8; 16],
    execution_id: ExecutionId,
    source_commitment: ObjectDigest,
) -> Result<HostExecutionOutcomeV1, ProtocolValidationError> {
    let outcome = HostExecutionOutcomeV1::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !outcome.__buffa_unknown_fields.is_empty() || outcome.encode_to_vec() != bytes {
        return Err(ProtocolValidationError::UnknownFields);
    }
    if outcome.operation_id != operation_id
        || outcome.execution_id != execution_id.as_bytes()
        || outcome.source_operation_commitment != source_commitment.as_bytes()
    {
        return Err(ProtocolValidationError::InvalidField(
            "execution outcome identity",
        ));
    }
    match outcome.phase.as_known() {
        Some(HostExecutionPhaseV1::HOST_EXECUTION_PHASE_ABSENT)
            if outcome.effect_commitment.is_empty()
                && outcome.completion_digest.is_empty()
                && outcome.completion_bytes.is_empty()
                && outcome.completion_status.to_i32() == 0
                && outcome.observation_sequence == 0 => {}
        Some(HostExecutionPhaseV1::HOST_EXECUTION_PHASE_PENDING
            | HostExecutionPhaseV1::HOST_EXECUTION_PHASE_ISSUED
            | HostExecutionPhaseV1::HOST_EXECUTION_PHASE_INDETERMINATE)
            if exact_nonzero::<32>(&outcome.effect_commitment, "effect_commitment").is_ok()
                && outcome.completion_digest.is_empty()
                && outcome.completion_bytes.is_empty()
                && outcome.completion_status.to_i32() == 0
                && outcome.observation_sequence == 0 => {}
        Some(HostExecutionPhaseV1::HOST_EXECUTION_PHASE_COMPLETE)
            if exact_nonzero::<32>(&outcome.effect_commitment, "effect_commitment").is_ok()
                && exact_nonzero::<32>(&outcome.completion_digest, "completion_digest").is_ok()
                && !outcome.completion_bytes.is_empty()
                && outcome.completion_bytes.len() <= 15 * 1_048_576
                && outcome.completion_digest == execution_result_digest(&outcome.completion_bytes)
                && outcome.observation_sequence != 0
                && matches!(outcome.completion_status.as_known(),
                    Some(HostExecutionCompletionStatusV1::HOST_EXECUTION_COMPLETION_STATUS_SUCCEEDED
                        | HostExecutionCompletionStatusV1::HOST_EXECUTION_COMPLETION_STATUS_REJECTED_BEFORE_EFFECT
                        | HostExecutionCompletionStatusV1::HOST_EXECUTION_COMPLETION_STATUS_FAILED_PERMANENT)) => {}
        _ => return Err(ProtocolValidationError::InvalidField("execution outcome phase")),
    }
    Ok(outcome)
}

fn execution_result_digest(bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-execution-effect-result-v1\0");
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    digest.finalize().into()
}
