//! Validates inert, deadline-free Host Apply templates before signing.
//!
//! Templates carry the same closed action and assignment data as wire requests,
//! but have neither authenticated peer provenance nor a live deadline. Their
//! distinct type cannot be passed to a broker as a validated runtime request.

use aos_proto::aos::sandbox::local::v1::{
    ApplyRuntimeRequest, Audience, GuardianArmCompanionV1, RuntimeAction,
};
use aos_sandbox_core::{ProtocolId, ProtocolVersion};
use buffa::Message as _;

use crate::{
    MAXIMUM_REQUEST_BYTES, MAXIMUM_RESPONSE_BYTES, MINIMUM_RESPONSE_BYTES, ProtocolValidationError,
    ValidatedAssignmentFence, ValidatedRuntimePlan, exact_nonzero,
    session::validate_broker_plan_artifact_pair, validate_fence, validate_header_protocol,
    validate_runtime_plan,
};

const HOST_GUARDIAN_COMPANION_VERSION: ProtocolVersion = ProtocolVersion::new(1, 5);

/// Preserves the exact structurally valid but untrusted Guardian plan pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedGuardianArmCompanionV1 {
    broker_plan: Vec<u8>,
    broker_plan_signature: Vec<u8>,
}

impl ValidatedGuardianArmCompanionV1 {
    /// Returns the exact canonical Guardian broker-plan bytes.
    #[must_use]
    pub fn broker_plan(&self) -> &[u8] {
        &self.broker_plan
    }

    /// Returns the exact canonical detached Guardian plan signature bytes.
    #[must_use]
    pub fn broker_plan_signature(&self) -> &[u8] {
        &self.broker_plan_signature
    }
}

#[derive(Clone, Copy)]
enum RuntimeBodyProfile {
    Live,
    Template,
}

/// Carries structurally checked Host inputs without live request authority.
///
/// Inert templates cannot stand in for peer-validated wire requests:
///
/// ```compile_fail
/// use aos_sandbox_protocol::{ValidatedRuntimeRequest, ValidatedRuntimeTemplateV1};
/// fn dispatch(_: &ValidatedRuntimeRequest) {}
/// fn invalid_dispatch(template: &ValidatedRuntimeTemplateV1) {
///     dispatch(template);
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedRuntimeTemplateV1 {
    pub(super) fence: ValidatedAssignmentFence,
    pub(super) action: RuntimeAction,
    pub(super) launch_plan: Option<ValidatedRuntimePlan>,
    pub(super) guardian_arm: Option<ValidatedGuardianArmCompanionV1>,
}

impl ValidatedRuntimeTemplateV1 {
    /// Returns the complete validated assignment fence.
    #[must_use]
    pub const fn fence(&self) -> &ValidatedAssignmentFence {
        &self.fence
    }

    /// Returns the closed runtime action.
    #[must_use]
    pub const fn action(&self) -> RuntimeAction {
        self.action
    }

    /// Returns the launch plan, present only for a launch action.
    #[must_use]
    pub const fn launch_plan(&self) -> Option<&ValidatedRuntimePlan> {
        self.launch_plan.as_ref()
    }

    /// Returns the launch-only Guardian companion when validating a live Host 1.5 request.
    #[must_use]
    pub const fn guardian_arm(&self) -> Option<&ValidatedGuardianArmCompanionV1> {
        self.guardian_arm.as_ref()
    }
}

/// Decodes inert controller template bytes without fabricating a peer or clock.
///
/// The template uses the Host Apply protobuf encoding with an absent (zero)
/// deadline. Its header names the controller audience but does not authenticate
/// that claim. Signing and broker dispatch require their own authority checks.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for oversized or malformed bytes, unknown
/// fields, invalid header fields, a nonzero deadline, an incorrect audience,
/// malformed assignment identity, or an action/launch-plan mismatch.
pub fn decode_runtime_template_v1(
    bytes: &[u8],
) -> Result<ValidatedRuntimeTemplateV1, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = ApplyRuntimeRequest::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    let header = request
        .header
        .as_option()
        .ok_or(ProtocolValidationError::MissingField("header"))?;
    if !header.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let protocol_version = validate_header_protocol(header, ProtocolId::HostBroker)?;
    exact_nonzero::<16>(&header.request_id, "header.request_id")?;
    if header.audience.as_known() != Some(Audience::AUDIENCE_NODE_CONTROLLER)
        || header.deadline_boottime_nanoseconds != 0
    {
        return Err(ProtocolValidationError::InvalidField(
            "template header audience/deadline",
        ));
    }
    if !(MINIMUM_RESPONSE_BYTES..=MAXIMUM_RESPONSE_BYTES).contains(&header.maximum_response_bytes) {
        return Err(ProtocolValidationError::InvalidResponseBound);
    }
    validate_runtime_body(&request, protocol_version, RuntimeBodyProfile::Template)
}

pub(super) fn validate_live_runtime_body(
    request: &ApplyRuntimeRequest,
    protocol_version: ProtocolVersion,
) -> Result<ValidatedRuntimeTemplateV1, ProtocolValidationError> {
    validate_runtime_body(request, protocol_version, RuntimeBodyProfile::Live)
}

fn validate_runtime_body(
    request: &ApplyRuntimeRequest,
    protocol_version: ProtocolVersion,
    profile: RuntimeBodyProfile,
) -> Result<ValidatedRuntimeTemplateV1, ProtocolValidationError> {
    if !request.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let fence = validate_fence(
        request
            .fence
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("fence"))?,
    )?;
    let action = request
        .action
        .as_known()
        .filter(|action| *action != RuntimeAction::RUNTIME_ACTION_UNSPECIFIED)
        .ok_or(ProtocolValidationError::UnknownAction)?;
    let launch_plan = match (action, request.launch_plan.as_option()) {
        (RuntimeAction::RUNTIME_ACTION_LAUNCH, Some(plan)) => {
            Some(validate_runtime_plan(plan, protocol_version)?)
        }
        (RuntimeAction::RUNTIME_ACTION_LAUNCH, None) => {
            return Err(ProtocolValidationError::MissingField("launch_plan"));
        }
        (_, Some(_)) => return Err(ProtocolValidationError::InvalidField("launch_plan")),
        (_, None) => None,
    };
    let guardian_arm = request
        .guardian_arm
        .as_option()
        .map(validate_guardian_arm)
        .transpose()?;
    match (profile, action, protocol_version, guardian_arm.is_some()) {
        (RuntimeBodyProfile::Template, _, _, true) => {
            return Err(ProtocolValidationError::InvalidField("guardian_arm"));
        }
        (RuntimeBodyProfile::Template, _, _, false) => {}
        (
            RuntimeBodyProfile::Live,
            RuntimeAction::RUNTIME_ACTION_LAUNCH,
            HOST_GUARDIAN_COMPANION_VERSION,
            false,
        ) => return Err(ProtocolValidationError::MissingField("guardian_arm")),
        (
            RuntimeBodyProfile::Live,
            RuntimeAction::RUNTIME_ACTION_LAUNCH,
            HOST_GUARDIAN_COMPANION_VERSION,
            true,
        )
        | (RuntimeBodyProfile::Live, _, _, false) => {}
        (RuntimeBodyProfile::Live, _, _, true) => {
            return Err(ProtocolValidationError::InvalidField("guardian_arm"));
        }
    }
    Ok(ValidatedRuntimeTemplateV1 {
        fence,
        action,
        launch_plan,
        guardian_arm,
    })
}

fn validate_guardian_arm(
    companion: &GuardianArmCompanionV1,
) -> Result<ValidatedGuardianArmCompanionV1, ProtocolValidationError> {
    if !companion.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    validate_broker_plan_artifact_pair(
        &companion.broker_plan,
        &companion.broker_plan_signature,
        "guardian_arm.broker_plan",
        "guardian_arm.broker_plan_signature",
    )?;
    Ok(ValidatedGuardianArmCompanionV1 {
        broker_plan: companion.broker_plan.clone(),
        broker_plan_signature: companion.broker_plan_signature.clone(),
    })
}

/// Decodes the exact Guardian plan pair from a live Host 1.5 launch body.
///
/// This structural helper has no peer or clock authority. It exists so a
/// controller can revalidate byte-exact durable packets; Host still performs
/// full live request, plan, and lease verification before effects.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] unless the input is one bounded,
/// deadline-bearing Host 1.5 launch with exactly one valid companion.
pub fn decode_host_guardian_companion_v1(
    live_launch_body: &[u8],
) -> Result<ValidatedGuardianArmCompanionV1, ProtocolValidationError> {
    if live_launch_body.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = ApplyRuntimeRequest::decode_from_slice(live_launch_body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    let header = request
        .header
        .as_option()
        .ok_or(ProtocolValidationError::MissingField("header"))?;
    validate_live_host_guardian_header(&request, header)?;
    let validated = validate_runtime_body(
        &request,
        HOST_GUARDIAN_COMPANION_VERSION,
        RuntimeBodyProfile::Live,
    )?;
    validated
        .guardian_arm
        .ok_or(ProtocolValidationError::MissingField("guardian_arm"))
}

/// Adds the sole Host 1.5 Guardian companion to a live deadline-bearing launch body.
///
/// The plan pair is structurally checked but remains untrusted. The Host and
/// Guardian independently verify it against protected trust and the enclosing
/// request's exact ownership lease before any payload can start.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] unless the input is a companion-free,
/// deadline-bearing Host 1.5 launch body and the resulting request is bounded.
pub fn encode_host_guardian_companion_v1(
    live_launch_body: &[u8],
    broker_plan: &[u8],
    broker_plan_signature: &[u8],
) -> Result<Vec<u8>, ProtocolValidationError> {
    if live_launch_body.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let mut request = ApplyRuntimeRequest::decode_from_slice(live_launch_body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    let header = request
        .header
        .as_option()
        .ok_or(ProtocolValidationError::MissingField("header"))?;
    validate_live_host_guardian_header(&request, header)?;
    if header.deadline_boottime_nanoseconds == 0
        || request.action.as_known() != Some(RuntimeAction::RUNTIME_ACTION_LAUNCH)
        || request.guardian_arm.as_option().is_some()
    {
        return Err(ProtocolValidationError::InvalidField("guardian_arm"));
    }
    let companion = GuardianArmCompanionV1 {
        broker_plan: broker_plan.to_vec(),
        broker_plan_signature: broker_plan_signature.to_vec(),
        ..Default::default()
    };
    validate_guardian_arm(&companion)?;
    request.guardian_arm = Some(companion).into();
    validate_runtime_body(
        &request,
        HOST_GUARDIAN_COMPANION_VERSION,
        RuntimeBodyProfile::Live,
    )?;
    let encoded = request.encode_to_vec();
    if encoded.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    Ok(encoded)
}

fn validate_live_host_guardian_header(
    request: &ApplyRuntimeRequest,
    header: &aos_proto::aos::sandbox::local::v1::RequestHeader,
) -> Result<(), ProtocolValidationError> {
    if !request.__buffa_unknown_fields.is_empty() || !header.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    if validate_header_protocol(header, ProtocolId::HostBroker)? != HOST_GUARDIAN_COMPANION_VERSION
    {
        return Err(ProtocolValidationError::InvalidField("guardian_arm"));
    }
    exact_nonzero::<16>(&header.request_id, "header.request_id")?;
    if header.audience.as_known() != Some(Audience::AUDIENCE_NODE_CONTROLLER) {
        return Err(ProtocolValidationError::InvalidField("header.audience"));
    }
    if header.deadline_boottime_nanoseconds == 0 {
        return Err(ProtocolValidationError::InvalidField("header.deadline"));
    }
    if !(MINIMUM_RESPONSE_BYTES..=MAXIMUM_RESPONSE_BYTES).contains(&header.maximum_response_bytes) {
        return Err(ProtocolValidationError::InvalidResponseBound);
    }
    Ok(())
}
