//! Dormant nonauthorizing adapter for existing GuestAgent protobuf messages.
//!
//! The legacy protobuf request lacks the canonical execution specification,
//! durable admission commitment, session binding, and operation sequence CAS
//! required by [`crate::AgentOperationRequestV1`]. Consequently this adapter
//! exposes only validated compatibility projections. No function in this
//! module can mint an agent handshake or execution authorization.

use aos_proto::aos::sandbox::local::v1::{
    AssignmentFence, Audience, Feature, GuestExecutionAction, GuestExecutionResult,
    GuestExecutionState, GuestHandshakeRequest, GuestHandshakeResponse, RequestHeader,
};
use aos_sandbox_core::{
    AssignmentEpoch, AuditId, DesiredGeneration, ExecutionId, IncarnationId, ObjectDigest,
    PrincipalId, SandboxId,
};

use crate::{
    AgentExecutionOutcomeV1, AgentExecutionPhaseV1, AgentFeatureV1, AgentHandshakeResponseV1,
};

const MAX_LEGACY_REASON_BYTES: usize = 128;

/// Carries structurally validated fields from a legacy handshake request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyHandshakeProjectionV1 {
    /// Nonzero request identity from the legacy header.
    pub request_id: [u8; 16],
    /// Exact sandbox identity.
    pub sandbox: SandboxId,
    /// Exact runtime incarnation.
    pub incarnation: IncarnationId,
    /// Exact assignment epoch.
    pub assignment_epoch: AssignmentEpoch,
    /// Exact desired generation.
    pub desired_generation: DesiredGeneration,
    /// Exact signed assignment digest.
    pub assignment_digest: ObjectDigest,
    /// Legacy handshake challenge bytes.
    pub challenge: [u8; 32],
}

/// Carries structurally validated legacy execution-control fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyExecutionProjectionV1 {
    /// Nonzero request identity.
    pub request_id: [u8; 16],
    /// Exact assignment fence projection.
    pub sandbox: SandboxId,
    /// Exact runtime incarnation.
    pub incarnation: IncarnationId,
    /// Exact assignment epoch.
    pub assignment_epoch: AssignmentEpoch,
    /// Exact desired generation.
    pub desired_generation: DesiredGeneration,
    /// Exact assignment digest.
    pub assignment_digest: ObjectDigest,
    /// Targeted durable execution.
    pub execution: ExecutionId,
    /// Legacy closed operation.
    pub action: LegacyExecutionActionV1,
    /// Forced-command commitment, not a complete specification.
    pub forced_command_digest: ObjectDigest,
    /// Authenticated principal claimed by the legacy carrier.
    pub principal: PrincipalId,
    /// Durable audit identity claimed by the legacy carrier.
    pub audit: AuditId,
}

/// Defines the legacy execution action after strict argument-shape validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyExecutionActionV1 {
    /// Legacy authorization remains nonauthorizing without the full spec/admission.
    Authorize,
    /// Changes terminal geometry.
    ResizeTerminal {
        /// Positive terminal row count.
        rows: u16,
        /// Positive terminal column count.
        columns: u16,
    },
    /// Delivers one portable signal code.
    Signal {
        /// Portable signal number in the closed range 1 through 64.
        signal_code: u8,
    },
    /// Cancels one execution.
    Cancel,
    /// Observes one execution.
    Observe,
}

/// Validates the bounded fixed-width portion of a legacy handshake request.
///
/// # Errors
///
/// Returns [`LegacyGuestAdapterError`] for an absent header/fence, wrong exact
/// protocol/audience shape, sentinel field, or challenge length mismatch.
pub fn project_legacy_handshake_request_v1(
    request: &GuestHandshakeRequest,
) -> Result<LegacyHandshakeProjectionV1, LegacyGuestAdapterError> {
    let header = request
        .header
        .as_option()
        .ok_or(LegacyGuestAdapterError::MissingField)?;
    validate_header(header)?;
    let request_id = exact_array(&header.request_id)?;
    if request_id == [0; 16] {
        return Err(LegacyGuestAdapterError::Sentinel);
    }
    let fence = request
        .fence
        .as_option()
        .ok_or(LegacyGuestAdapterError::MissingField)?;
    let projected = project_fence(fence)?;
    let challenge = exact_array(&request.challenge)?;
    if challenge == [0; 32] {
        return Err(LegacyGuestAdapterError::Sentinel);
    }
    Ok(LegacyHandshakeProjectionV1 {
        request_id,
        sandbox: projected.0,
        incarnation: projected.1,
        assignment_epoch: projected.2,
        desired_generation: projected.3,
        assignment_digest: projected.4,
        challenge,
    })
}

/// Validates one legacy execution request into a nonauthorizing projection.
///
/// # Errors
///
/// Returns [`LegacyGuestAdapterError`] for sentinel identity/digest fields,
/// absent header/fence, or action arguments outside their exact shape.
pub fn project_legacy_execution_request_v1(
    request: &aos_proto::aos::sandbox::local::v1::ApplyGuestExecutionRequest,
) -> Result<LegacyExecutionProjectionV1, LegacyGuestAdapterError> {
    let header = request
        .header
        .as_option()
        .ok_or(LegacyGuestAdapterError::MissingField)?;
    validate_header(header)?;
    let request_id = exact_array(&header.request_id)?;
    let fence = request
        .fence
        .as_option()
        .ok_or(LegacyGuestAdapterError::MissingField)?;
    let (sandbox, incarnation, assignment_epoch, desired_generation, assignment_digest) =
        project_fence(fence)?;
    let execution_bytes: [u8; 16] = exact_array(&request.execution_id)?;
    let forced_digest: [u8; 32] = exact_array(&request.forced_command_digest)?;
    let principal_bytes: [u8; 16] = exact_array(&request.principal_id)?;
    let audit_bytes: [u8; 16] = exact_array(&request.audit_id)?;
    if request_id == [0; 16]
        || execution_bytes == [0; 16]
        || forced_digest == [0; 32]
        || principal_bytes == [0; 16]
        || audit_bytes == [0; 16]
    {
        return Err(LegacyGuestAdapterError::Sentinel);
    }
    let action = match request
        .action
        .as_known()
        .ok_or(LegacyGuestAdapterError::UnknownAction)?
    {
        GuestExecutionAction::GUEST_EXECUTION_ACTION_AUTHORIZE
            if request.terminal_rows == 0
                && request.terminal_columns == 0
                && request.signal_number == 0 =>
        {
            LegacyExecutionActionV1::Authorize
        }
        GuestExecutionAction::GUEST_EXECUTION_ACTION_RESIZE_TERMINAL
            if request.terminal_rows > 0
                && request.terminal_rows <= u32::from(u16::MAX)
                && request.terminal_columns > 0
                && request.terminal_columns <= u32::from(u16::MAX)
                && request.signal_number == 0 =>
        {
            LegacyExecutionActionV1::ResizeTerminal {
                rows: request.terminal_rows as u16,
                columns: request.terminal_columns as u16,
            }
        }
        GuestExecutionAction::GUEST_EXECUTION_ACTION_SIGNAL
            if request.terminal_rows == 0
                && request.terminal_columns == 0
                && (1..=64).contains(&request.signal_number) =>
        {
            LegacyExecutionActionV1::Signal {
                signal_code: request.signal_number as u8,
            }
        }
        GuestExecutionAction::GUEST_EXECUTION_ACTION_CANCEL
            if request.terminal_rows == 0
                && request.terminal_columns == 0
                && request.signal_number == 0 =>
        {
            LegacyExecutionActionV1::Cancel
        }
        GuestExecutionAction::GUEST_EXECUTION_ACTION_OBSERVE
            if request.terminal_rows == 0
                && request.terminal_columns == 0
                && request.signal_number == 0 =>
        {
            LegacyExecutionActionV1::Observe
        }
        GuestExecutionAction::GUEST_EXECUTION_ACTION_UNSPECIFIED => {
            return Err(LegacyGuestAdapterError::UnknownAction);
        }
        _ => return Err(LegacyGuestAdapterError::InvalidActionArguments),
    };
    Ok(LegacyExecutionProjectionV1 {
        request_id,
        sandbox,
        incarnation,
        assignment_epoch,
        desired_generation,
        assignment_digest,
        execution: ExecutionId::from_bytes(execution_bytes),
        action,
        forced_command_digest: ObjectDigest::from_bytes(forced_digest),
        principal: PrincipalId::from_bytes(principal_bytes),
        audit: AuditId::from_bytes(audit_bytes),
    })
}

/// Projects an authenticated agent handshake into the existing protobuf response.
///
/// The active adapter must separately bind the protobuf request to the exact
/// canonical agent handshake. This function only preserves already verified
/// response values.
#[must_use]
pub fn legacy_handshake_response_v1(response: &AgentHandshakeResponseV1) -> GuestHandshakeResponse {
    GuestHandshakeResponse {
        challenge_signature: response.challenge_signature().to_vec(),
        agent_version: Some(Feature {
            namespace: "aos.sandbox.guest-agent".to_owned(),
            major: 1,
            minor: 0,
            ..Default::default()
        })
        .into(),
        features: response
            .features()
            .as_slice()
            .iter()
            .map(proto_feature)
            .collect(),
        ..Default::default()
    }
}

/// Projects one already committed agent outcome into the existing protobuf result.
///
/// # Errors
///
/// Returns [`LegacyGuestAdapterError::InvalidResult`] when exact canonical
/// result bytes cannot be represented by the legacy exit-code/reason shape.
pub fn legacy_execution_result_v1(
    execution: ExecutionId,
    outcome: &AgentExecutionOutcomeV1,
    exact_exit_code: Option<i32>,
) -> Result<GuestExecutionResult, LegacyGuestAdapterError> {
    if execution.as_bytes() == &[0; 16] {
        return Err(LegacyGuestAdapterError::Sentinel);
    }
    let (state, exit_code) = match outcome.phase() {
        AgentExecutionPhaseV1::Authorized | AgentExecutionPhaseV1::Starting => {
            (GuestExecutionState::GUEST_EXECUTION_STATE_AUTHORIZED, 0)
        }
        AgentExecutionPhaseV1::Running => (GuestExecutionState::GUEST_EXECUTION_STATE_RUNNING, 0),
        AgentExecutionPhaseV1::Exited => (
            GuestExecutionState::GUEST_EXECUTION_STATE_EXITED,
            exact_exit_code.ok_or(LegacyGuestAdapterError::InvalidResult)?,
        ),
        AgentExecutionPhaseV1::Canceled => (GuestExecutionState::GUEST_EXECUTION_STATE_CANCELED, 0),
        AgentExecutionPhaseV1::Failed | AgentExecutionPhaseV1::Lost => {
            (GuestExecutionState::GUEST_EXECUTION_STATE_FAILED, 0)
        }
        AgentExecutionPhaseV1::Quiesced | AgentExecutionPhaseV1::Ready => {
            return Err(LegacyGuestAdapterError::InvalidResult);
        }
    };
    if outcome.phase() != AgentExecutionPhaseV1::Exited && exact_exit_code.is_some() {
        return Err(LegacyGuestAdapterError::InvalidResult);
    }
    if outcome.result_bytes().len() > MAX_LEGACY_REASON_BYTES {
        return Err(LegacyGuestAdapterError::InvalidResult);
    }
    let termination_reason = std::str::from_utf8(outcome.result_bytes())
        .map_err(|_| LegacyGuestAdapterError::InvalidResult)?
        .to_owned();
    Ok(GuestExecutionResult {
        execution_id: execution.as_bytes().to_vec(),
        state: state.into(),
        exit_code,
        termination_reason,
        observation_sequence: outcome.sequence().get(),
        ..Default::default()
    })
}

fn proto_feature(feature: &AgentFeatureV1) -> Feature {
    let suffix = match feature {
        AgentFeatureV1::Readiness => "readiness",
        AgentFeatureV1::ExecutionHandoff => "execution-handoff",
        AgentFeatureV1::ExecutionObservation => "execution-observation",
        AgentFeatureV1::TerminalResize => "terminal-resize",
        AgentFeatureV1::ExecutionSignal => "execution-signal",
        AgentFeatureV1::Quiesce => "quiesce",
        AgentFeatureV1::RuntimeArgumentObservation => "runtime-argument-observation",
    };
    Feature {
        namespace: format!("aos.sandbox.guest-agent.{suffix}"),
        major: 1,
        minor: 0,
        ..Default::default()
    }
}

fn validate_header(header: &RequestHeader) -> Result<(), LegacyGuestAdapterError> {
    if header.protocol_major != 1
        || header.protocol_minor != 0
        || header.request_id.len() != 16
        || header.audience != Audience::AUDIENCE_GUEST_AGENT
        || header.deadline_boottime_nanoseconds == 0
        || !(4_096..=16 * 1_048_576).contains(&header.maximum_response_bytes)
    {
        return Err(LegacyGuestAdapterError::InvalidHeader);
    }
    Ok(())
}

type FenceProjection = (
    SandboxId,
    IncarnationId,
    AssignmentEpoch,
    DesiredGeneration,
    ObjectDigest,
);

fn project_fence(fence: &AssignmentFence) -> Result<FenceProjection, LegacyGuestAdapterError> {
    let sandbox: [u8; 16] = exact_array(&fence.sandbox_id)?;
    let incarnation: [u8; 16] = exact_array(&fence.incarnation_id)?;
    let digest: [u8; 32] = exact_array(&fence.assignment_digest)?;
    if sandbox == [0; 16]
        || incarnation == [0; 16]
        || fence.assignment_epoch == 0
        || fence.desired_generation == 0
        || digest == [0; 32]
    {
        return Err(LegacyGuestAdapterError::Sentinel);
    }
    Ok((
        SandboxId::from_bytes(sandbox),
        IncarnationId::from_bytes(incarnation),
        AssignmentEpoch::new(fence.assignment_epoch),
        DesiredGeneration::new(fence.desired_generation),
        ObjectDigest::from_bytes(digest),
    ))
}

fn exact_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], LegacyGuestAdapterError> {
    bytes
        .try_into()
        .map_err(|_| LegacyGuestAdapterError::InvalidLength)
}

/// Reports strict legacy-protobuf projection failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LegacyGuestAdapterError {
    /// A required protobuf message field is absent.
    #[error("legacy guest request is missing a required field")]
    MissingField,
    /// The request header does not use exact local protocol 1.0 or fixed identity shape.
    #[error("legacy guest request header is invalid")]
    InvalidHeader,
    /// A fixed-width byte field has another length.
    #[error("legacy guest request field length is invalid")]
    InvalidLength,
    /// A required identity, generation, challenge, or digest is zero.
    #[error("legacy guest request contains a sentinel field")]
    Sentinel,
    /// The action uses an unknown or unspecified discriminant.
    #[error("legacy guest execution action is unknown")]
    UnknownAction,
    /// Action-specific fields are absent, out of range, or unexpectedly present.
    #[error("legacy guest execution action arguments are invalid")]
    InvalidActionArguments,
    /// A canonical agent outcome cannot fit the legacy result shape.
    #[error("agent outcome is not representable by the legacy guest result")]
    InvalidResult,
}
