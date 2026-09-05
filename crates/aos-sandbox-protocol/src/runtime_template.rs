//! Validates inert, deadline-free Host Apply templates before signing.
//!
//! Templates carry the same closed action and assignment data as wire requests,
//! but have neither authenticated peer provenance nor a live deadline. Their
//! distinct type cannot be passed to a broker as a validated runtime request.

use aos_proto::aos::sandbox::local::v1::{ApplyRuntimeRequest, Audience, RuntimeAction};
use aos_sandbox_core::ProtocolId;
use buffa::Message as _;

use crate::{
    MAXIMUM_REQUEST_BYTES, MAXIMUM_RESPONSE_BYTES, MINIMUM_RESPONSE_BYTES, ProtocolValidationError,
    ValidatedAssignmentFence, ValidatedRuntimePlan, exact_nonzero, validate_fence,
    validate_header_protocol, validate_runtime_plan,
};

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
    validate_header_protocol(header, ProtocolId::HostBroker)?;
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
    validate_runtime_body(&request)
}

pub(super) fn validate_runtime_body(
    request: &ApplyRuntimeRequest,
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
        (RuntimeAction::RUNTIME_ACTION_LAUNCH, Some(plan)) => Some(validate_runtime_plan(plan)?),
        (RuntimeAction::RUNTIME_ACTION_LAUNCH, None) => {
            return Err(ProtocolValidationError::MissingField("launch_plan"));
        }
        (_, Some(_)) => return Err(ProtocolValidationError::InvalidField("launch_plan")),
        (_, None) => None,
    };
    Ok(ValidatedRuntimeTemplateV1 {
        fence,
        action,
        launch_plan,
    })
}
