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
/// Largest canonical execution specification admitted by the runtime backend.
pub const MAXIMUM_HOST_EXECUTION_SPEC_BYTES: usize = 15 * 1_048_576;

/// Exact sealed content for an Apply control action without a specification.
pub const HOST_EXECUTION_CONTROL_CONTENT_V1: &[u8] = &[0];

const SPEC_ATTEMPT_DOMAIN: &[u8] = b"aos.sandbox.host.execution-spec-attempt.v1\0";

/// Binds one sealed content descriptor to an authenticated Apply attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostExecutionSpecContentFieldsV1 {
    bytes: u64,
    digest: [u8; 32],
    attempt_commitment: [u8; 32],
}

impl HostExecutionSpecContentFieldsV1 {
    /// Derives the stable content portion of a signed grant.
    #[must_use]
    pub fn for_grant(content: &[u8]) -> Self {
        Self {
            bytes: content.len() as u64,
            digest: Sha256::digest(content).into(),
            attempt_commitment: [0; 32],
        }
    }

    /// Binds stable content fields to one authenticated request attempt.
    #[must_use]
    pub fn bind_attempt(
        self,
        request_id: [u8; 16],
        operation_id: [u8; 16],
        execution_id: ExecutionId,
        source_commitment: ObjectDigest,
        action: EffectOperationV1,
    ) -> Self {
        Self {
            attempt_commitment: spec_attempt_commitment_v1(
                request_id,
                operation_id,
                execution_id,
                source_commitment,
                action,
                self.bytes,
                self.digest,
            ),
            ..self
        }
    }

    /// Returns the exact expected sealed descriptor size.
    pub const fn bytes(self) -> u64 {
        self.bytes
    }

    /// Returns SHA-256 of the exact sealed descriptor contents.
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }

    /// Returns the commitment to content and the authenticated request attempt.
    pub const fn attempt_commitment(self) -> [u8; 32] {
        self.attempt_commitment
    }

    /// Reports whether this reference is the exact control marker.
    #[must_use]
    pub fn is_control_marker(self) -> bool {
        self.bytes == HOST_EXECUTION_CONTROL_CONTENT_V1.len() as u64
            && self.digest == <[u8; 32]>::from(Sha256::digest(HOST_EXECUTION_CONTROL_CONTENT_V1))
    }
}

/// Derives the signed fields for a sealed Host execution-spec descriptor.
///
/// # Errors
///
/// Rejects empty or oversized content and a control marker that differs from
/// the fixed one-byte value. The caller supplies canonical specification bytes
/// for Authorize; Host independently decodes and reproduces them before effect.
#[allow(clippy::too_many_arguments)]
pub fn host_execution_spec_content_fields_v1(
    request_id: [u8; 16],
    operation_id: [u8; 16],
    execution_id: ExecutionId,
    source_commitment: ObjectDigest,
    action: EffectOperationV1,
    content: &[u8],
) -> Result<HostExecutionSpecContentFieldsV1, ProtocolValidationError> {
    if content.is_empty() || content.len() > MAXIMUM_HOST_EXECUTION_SPEC_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    if !matches!(action, EffectOperationV1::AuthorizeExecution)
        && content != HOST_EXECUTION_CONTROL_CONTENT_V1
    {
        return Err(ProtocolValidationError::InvalidField("spec content"));
    }
    let digest: [u8; 32] = Sha256::digest(content).into();
    let bytes = content.len() as u64;
    let attempt_commitment = spec_attempt_commitment_v1(
        request_id,
        operation_id,
        execution_id,
        source_commitment,
        action,
        bytes,
        digest,
    );
    Ok(HostExecutionSpecContentFieldsV1 {
        bytes,
        digest,
        attempt_commitment,
    })
}

fn spec_attempt_commitment_v1(
    request_id: [u8; 16],
    operation_id: [u8; 16],
    execution_id: ExecutionId,
    source_commitment: ObjectDigest,
    action: EffectOperationV1,
    bytes: u64,
    digest: [u8; 32],
) -> [u8; 32] {
    let mut attempt = Sha256::new();
    attempt.update(SPEC_ATTEMPT_DOMAIN);
    attempt.update(request_id);
    attempt.update(operation_id);
    attempt.update(execution_id.as_bytes());
    attempt.update(source_commitment.as_bytes());
    attempt.update([action.code()]);
    attempt.update(action.arguments());
    attempt.update(bytes.to_be_bytes());
    attempt.update(digest);
    attempt.finalize().into()
}

/// Carries a validated intent without granting execution authority.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedHostExecutionApplyV1 {
    header: ValidatedHeader,
    operation_id: [u8; 16],
    execution_id: ExecutionId,
    source_commitment: ObjectDigest,
    action: EffectOperationV1,
    specification: Option<aos_sandbox_core::ExecutionSpecV1>,
    content: Option<HostExecutionSpecContentFieldsV1>,
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

    /// Returns the exact sealed descriptor size for descriptor transport v1.
    pub const fn content_bytes(&self) -> Option<u64> {
        match self.content {
            Some(content) => Some(content.bytes()),
            None => None,
        }
    }

    /// Returns the signed content reference for grant matching.
    pub const fn content_fields(&self) -> Option<HostExecutionSpecContentFieldsV1> {
        self.content
    }

    /// Validates one pinned sealed descriptor against this exact Apply attempt.
    ///
    /// # Errors
    ///
    /// Rejects legacy inline transport, changed bytes, a noncanonical or
    /// mismatched specification, and a changed control marker.
    pub fn verify_content(&mut self, bytes: &[u8]) -> Result<(), ProtocolValidationError> {
        let expected = self.content.ok_or(ProtocolValidationError::InvalidField(
            "spec transfer version",
        ))?;
        let actual = host_execution_spec_content_fields_v1(
            *self.header.request_id(),
            self.operation_id,
            self.execution_id,
            self.source_commitment,
            self.action,
            bytes,
        )?;
        if actual != expected {
            return Err(ProtocolValidationError::InvalidField("spec content"));
        }
        if matches!(self.action, EffectOperationV1::AuthorizeExecution) {
            let limits = DecodeLimits {
                maximum_bytes: MAXIMUM_HOST_EXECUTION_SPEC_BYTES,
                ..DecodeLimits::default()
            };
            let specification = decode_execution_spec_v1(bytes, limits)
                .map_err(|_| ProtocolValidationError::InvalidField("spec content"))?;
            if specification.execution() != self.execution_id {
                return Err(ProtocolValidationError::InvalidField("execution_id"));
            }
            self.specification = Some(specification);
        }
        Ok(())
    }
}

/// Carries a validated readback locator without granting an effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedHostExecutionQueryV1 {
    header: ValidatedHeader,
    operation_id: [u8; 16],
    execution_id: ExecutionId,
    source_commitment: ObjectDigest,
    content: HostExecutionSpecContentFieldsV1,
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

    /// Returns the exact Apply content reference bound to this readback.
    pub const fn content_fields(&self) -> HostExecutionSpecContentFieldsV1 {
        self.content
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
            if no_geometry && request.signal_number == 0 =>
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
    let content = if request.spec_transfer_version == 1 {
        if !request.canonical_execution_spec.is_empty()
            || request.spec_content_bytes == 0
            || request.spec_content_bytes > MAXIMUM_HOST_EXECUTION_SPEC_BYTES as u64
        {
            return Err(ProtocolValidationError::InvalidField("spec content"));
        }
        let digest = exact_nonzero::<32>(&request.spec_content_digest, "spec_content_digest")?;
        let attempt_commitment =
            exact_nonzero::<32>(&request.spec_attempt_commitment, "spec_attempt_commitment")?;
        if !matches!(action, EffectOperationV1::AuthorizeExecution)
            && (request.spec_content_bytes != HOST_EXECUTION_CONTROL_CONTENT_V1.len() as u64
                || digest != <[u8; 32]>::from(Sha256::digest(HOST_EXECUTION_CONTROL_CONTENT_V1)))
        {
            return Err(ProtocolValidationError::InvalidField("spec content"));
        }
        if spec_attempt_commitment_v1(
            *header.request_id(),
            operation_id,
            execution_id,
            source_commitment,
            action,
            request.spec_content_bytes,
            digest,
        ) != attempt_commitment
        {
            return Err(ProtocolValidationError::InvalidField(
                "spec attempt commitment",
            ));
        }
        HostExecutionSpecContentFieldsV1 {
            bytes: request.spec_content_bytes,
            digest,
            attempt_commitment,
        }
    } else {
        return Err(ProtocolValidationError::InvalidField(
            "spec transfer version",
        ));
    };

    Ok(ValidatedHostExecutionApplyV1 {
        header,
        operation_id,
        execution_id,
        source_commitment,
        action,
        specification: None,
        content: Some(content),
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
    let content_bytes = request.spec_content_bytes;
    if content_bytes == 0 || content_bytes > MAXIMUM_HOST_EXECUTION_SPEC_BYTES as u64 {
        return Err(ProtocolValidationError::InvalidField("spec_content_bytes"));
    }
    let content_digest = exact_nonzero::<32>(&request.spec_content_digest, "spec_content_digest")?;
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
        content: HostExecutionSpecContentFieldsV1 {
            bytes: content_bytes,
            digest: content_digest,
            attempt_commitment: [0; 32],
        },
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

#[cfg(test)]
mod content_tests {
    use super::*;
    use aos_proto::aos::sandbox::local::v1::{Audience, RequestHeader};

    fn fields(request_id: [u8; 16], content: &[u8]) -> HostExecutionSpecContentFieldsV1 {
        host_execution_spec_content_fields_v1(
            request_id,
            [2; 16],
            ExecutionId::from_bytes([3; 16]),
            ObjectDigest::from_bytes([4; 32]),
            EffectOperationV1::AuthorizeExecution,
            content,
        )
        .unwrap()
    }

    #[test]
    fn sealed_content_reference_binds_the_exact_attempt_and_bytes() {
        let original = fields([1; 16], b"specification");

        assert_eq!(original.bytes(), 13);
        assert_ne!(
            original.digest(),
            fields([1; 16], b"specification!").digest()
        );
        assert_ne!(
            original.attempt_commitment(),
            fields([5; 16], b"specification").attempt_commitment()
        );
    }

    #[test]
    fn full_runtime_content_ceiling_is_admitted_without_inline_framing() {
        let largest = vec![7; MAXIMUM_HOST_EXECUTION_SPEC_BYTES];

        assert_eq!(fields([1; 16], &largest).bytes(), largest.len() as u64);
        let oversized = vec![7; MAXIMUM_HOST_EXECUTION_SPEC_BYTES + 1];
        assert!(
            host_execution_spec_content_fields_v1(
                [1; 16],
                [2; 16],
                ExecutionId::from_bytes([3; 16]),
                ObjectDigest::from_bytes([4; 32]),
                EffectOperationV1::AuthorizeExecution,
                &oversized,
            )
            .is_err()
        );
    }

    #[test]
    fn control_content_has_one_canonical_marker() {
        let accepted = host_execution_spec_content_fields_v1(
            [1; 16],
            [2; 16],
            ExecutionId::from_bytes([3; 16]),
            ObjectDigest::from_bytes([4; 32]),
            EffectOperationV1::Cancel,
            HOST_EXECUTION_CONTROL_CONTENT_V1,
        )
        .unwrap();

        assert!(accepted.is_control_marker());
        assert!(
            host_execution_spec_content_fields_v1(
                [1; 16],
                [2; 16],
                ExecutionId::from_bytes([3; 16]),
                ObjectDigest::from_bytes([4; 32]),
                EffectOperationV1::Cancel,
                b"other",
            )
            .is_err()
        );
    }

    #[test]
    fn legacy_inline_apply_is_rejected_by_the_host_decoder() {
        let request = ApplyHostExecutionRequestV1 {
            header: Some(RequestHeader {
                protocol_major: 1,
                request_id: vec![1; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: 10,
                maximum_response_bytes: 4_096,
                ..Default::default()
            })
            .into(),
            operation_id: vec![2; 16],
            execution_id: vec![3; 16],
            source_operation_commitment: vec![4; 32],
            action: HostExecutionActionV1::HOST_EXECUTION_ACTION_AUTHORIZE.into(),
            canonical_execution_spec: vec![5],
            ..Default::default()
        };
        let peer = PeerCredentials {
            uid: 100,
            gid: 200,
            pid: Some(300),
        };
        let policy = PeerPolicy {
            uid: 100,
            gid: Some(200),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        };

        assert!(matches!(
            decode_host_execution_apply_v1(&request.encode_to_vec(), peer, policy, 1),
            Err(ProtocolValidationError::InvalidField(
                "spec transfer version"
            ))
        ));
    }
}
