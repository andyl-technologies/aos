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

const HOST_GUARDIAN_COMPANION_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);

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

/// Selects a finite wire shape while sharing the sole Host body validator.
#[derive(Clone, Copy)]
pub(crate) enum RuntimeWirePurposeV1 {
    Ordinary,
    CaptureStop,
    RecoveryCleanup,
}

impl RuntimeWirePurposeV1 {
    pub(crate) const fn maximum_bytes_v1(self) -> usize {
        match self {
            Self::Ordinary => MAXIMUM_REQUEST_BYTES,
            Self::CaptureStop => crate::storage_capture_session::stop_cleanup::MAXIMUM_CANONICAL_CAPTURE_STOP_BODY_BYTES_V4,
            Self::RecoveryCleanup => crate::host_stop_cleanup::MAXIMUM_CANONICAL_HOST_STOP_CLEANUP_BODY_BYTES_V1,
        }
    }

    pub(crate) fn require_canonical_v1(self, request: &ApplyRuntimeRequest,
        template: &ValidatedRuntimeTemplateV1, original: &[u8],
    ) -> Result<(), ProtocolValidationError> {
        let expected_cleanup = match self {
            Self::Ordinary if template.host_stop_cleanup_v1().is_none() => return Ok(()),
            Self::Ordinary => true,
            Self::CaptureStop => false,
            Self::RecoveryCleanup => true,
        };
        if template.action() != RuntimeAction::RUNTIME_ACTION_STOP
            || template.host_stop_cleanup_v1().is_some() != expected_cleanup
            || request.encode_to_vec().as_slice() != original
        {
            let field = match self {
                Self::CaptureStop => "canonical Capture Stop",
                Self::Ordinary | Self::RecoveryCleanup => "canonical Host Stop cleanup",
            };
            return Err(ProtocolValidationError::InvalidField(field));
        }
        Ok(())
    }
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
    pub(super) host_stop_cleanup: Option<crate::host_stop_cleanup::HostStopCleanupSubjectDataV1>,
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

    /// Returns the launch-only Guardian companion when validating a live Host request.
    #[must_use]
    pub const fn guardian_arm(&self) -> Option<&ValidatedGuardianArmCompanionV1> {
        self.guardian_arm.as_ref()
    }

    /// Borrows the finite fresh Stop cleanup subject without granting its effect.
    #[must_use]
    pub const fn host_stop_cleanup_v1(&self)
        -> Option<&crate::host_stop_cleanup::HostStopCleanupSubjectDataV1> {
        self.host_stop_cleanup.as_ref()
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
    decode_runtime_template_with_header_data_v2(bytes).map(|(template, _)| template)
}

/// Lends existing inert header DATA from the same single template decode.
///
/// The typed header already belongs to the common prepared-resource family.
/// It authenticates no peer/time and carries the original zero deadline. The
/// caller prices its existing inline header carrier, then injects its actual
/// original Root cutoff after canonical request comparison.
pub(crate) fn decode_runtime_template_with_header_data_v2(
    bytes: &[u8],
) -> Result<(ValidatedRuntimeTemplateV1,
    crate::authorization_artifact::start_resource_plan::StartResourceRequestHeaderDataV2),
    ProtocolValidationError> {
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
    let request_id = exact_nonzero::<16>(&header.request_id, "header.request_id")?;
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
    let template = validate_runtime_body(&request, RuntimeBodyProfile::Template)?;
    RuntimeWirePurposeV1::Ordinary.require_canonical_v1(&request, &template, bytes)?;
    let header = crate::authorization_artifact::start_resource_plan::StartResourceRequestHeaderDataV2 {
        protocol_major: header.protocol_major,
        protocol_minor: header.protocol_minor,
        audience: Audience::AUDIENCE_NODE_CONTROLLER,
        request_id,
        deadline_boottime_nanoseconds: header.deadline_boottime_nanoseconds,
        maximum_response_bytes: header.maximum_response_bytes,
    };
    Ok((template, header))
}

pub(super) fn validate_live_runtime_body(
    request: &ApplyRuntimeRequest,
) -> Result<ValidatedRuntimeTemplateV1, ProtocolValidationError> {
    validate_runtime_body(request, RuntimeBodyProfile::Live)
}

fn validate_runtime_body(
    request: &ApplyRuntimeRequest,
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
        (RuntimeAction::RUNTIME_ACTION_LAUNCH, Some(plan)) => Some(validate_runtime_plan(plan)?),
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
    match (profile, action, guardian_arm.is_some()) {
        (RuntimeBodyProfile::Template, _, true) => {
            return Err(ProtocolValidationError::InvalidField("guardian_arm"));
        }
        (RuntimeBodyProfile::Template, _, false) => {}
        (RuntimeBodyProfile::Live, RuntimeAction::RUNTIME_ACTION_LAUNCH, false) => {
            return Err(ProtocolValidationError::MissingField("guardian_arm"));
        }
        (RuntimeBodyProfile::Live, RuntimeAction::RUNTIME_ACTION_LAUNCH, true)
        | (RuntimeBodyProfile::Live, _, false) => {}
        (RuntimeBodyProfile::Live, _, true) => {
            return Err(ProtocolValidationError::InvalidField("guardian_arm"));
        }
    }
    let host_stop_cleanup = if request.host_stop_cleanup_v1.is_empty() {
        None
    } else {
        if action != RuntimeAction::RUNTIME_ACTION_STOP {
            return Err(ProtocolValidationError::InvalidField("host_stop_cleanup_v1"));
        }
        let cleanup = crate::host_stop_cleanup::HostStopCleanupSubjectDataV1::decode_v1(
            &request.host_stop_cleanup_v1)?;
        let header = request.header.as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?;
        cleanup.require_request_data_v1(
            &exact_nonzero::<16>(&header.request_id, "header.request_id")?, &fence,
            header.deadline_boottime_nanoseconds)?;
        Some(cleanup)
    };
    Ok(ValidatedRuntimeTemplateV1 {
        fence,
        action,
        launch_plan,
        guardian_arm,
        host_stop_cleanup,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LiveHostRuntimeHeaderDataV2 {
    request_id: [u8; 16],
    deadline_boottime_nanoseconds: u64,
    maximum_response_bytes: u32,
}

/// Owns the exact structurally checked live Host header and body as inert DATA.
///
/// This type authenticates no peer, clock, Root plan or ownership lease and
/// cannot be dispatched as a validated runtime request. Its fields come from
/// the same single bounded decoder and existing Host 1.0 validators.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveHostRuntimeEnvelopeDataV2 {
    header: LiveHostRuntimeHeaderDataV2,
    template: ValidatedRuntimeTemplateV1,
}

impl LiveHostRuntimeEnvelopeDataV2 {
    /// Borrows the exact nonzero request identity in the original wire header.
    #[must_use]
    pub const fn request_id_v1(&self) -> &[u8; 16] { &self.header.request_id }

    /// Returns the original nonzero absolute BOOTTIME deadline.
    #[must_use]
    pub const fn deadline_boottime_nanoseconds_v1(&self) -> u64 {
        self.header.deadline_boottime_nanoseconds
    }

    /// Returns the original validated response-byte ceiling.
    #[must_use]
    pub const fn maximum_response_bytes_v1(&self) -> u32 {
        self.header.maximum_response_bytes
    }

    /// Borrows the same inert fence, action, launch plan and Guardian DATA.
    #[must_use]
    pub const fn template_v1(&self) -> &ValidatedRuntimeTemplateV1 { &self.template }
}

/// Decodes complete live Host body DATA without fabricating a peer or clock.
///
/// The same bounded Host 1.0 header, nonzero deadline, nested launch/action
/// fields and exact Guardian companion rules apply. The returned inert type
/// cannot be dispatched as a validated live request and authenticates neither
/// a Root plan, lease nor caller. Consumers must independently verify the
/// actual authorization quartet, original cutoff and native currentness.
///
/// # Errors
/// Returns the original structural refusal for malformed or oversized wire,
/// unsupported protocol, zero deadline, unknown fields or invalid body data.
pub fn decode_live_host_runtime_data_v1(
    live_launch_body: &[u8],
) -> Result<ValidatedRuntimeTemplateV1, ProtocolValidationError> {
    decode_live_host_runtime_envelope_data_v2(live_launch_body).map(|envelope| envelope.template)
}

/// Decodes the exact live Host header and complete body in one bounded pass.
///
/// The return remains inert comparison DATA. Actual consumers must verify
/// signed artifacts and clamp this original deadline against their genuine
/// purpose, current native owners, paired clock and lease/policy expiry.
///
/// # Errors
/// Preserves the existing header, nested runtime and Guardian validation order.
pub fn decode_live_host_runtime_envelope_data_v2(
    live_launch_body: &[u8],
) -> Result<LiveHostRuntimeEnvelopeDataV2, ProtocolValidationError> {
    decode_live_host_runtime_envelope_engine_v4(live_launch_body, RuntimeWirePurposeV1::Ordinary)
}

/// Decodes only a canonical live Stop body within its fixed protobuf schema.
///
/// This comparison DATA carries no peer, clock or signed authority. The same
/// existing Host decoder owns all actual header, fence and action validation.
///
/// # Errors
/// Refuses an excessive Stop body before allocation, non-Stop actions, unknown
/// or duplicate/noncanonical fields, and every existing Host body refusal.
pub fn decode_canonical_live_host_stop_envelope_data_v4(
    bytes: &[u8],
) -> Result<LiveHostRuntimeEnvelopeDataV2, ProtocolValidationError> {
    decode_live_host_runtime_envelope_engine_v4(bytes, RuntimeWirePurposeV1::CaptureStop)
}

/// Decodes canonical fresh recovery cleanup DATA within its actual fixed bound.
///
/// # Errors
/// Refuses excessive bytes before allocation, missing cleanup subject,
/// noncanonical encoding and every shared live Host body/header refusal.
pub fn decode_canonical_live_host_stop_cleanup_envelope_data_v1(bytes: &[u8])
    -> Result<LiveHostRuntimeEnvelopeDataV2, ProtocolValidationError> {
    decode_live_host_runtime_envelope_engine_v4(bytes, RuntimeWirePurposeV1::RecoveryCleanup)
}

fn decode_live_host_runtime_envelope_engine_v4(
    live_launch_body: &[u8],
    purpose: RuntimeWirePurposeV1,
) -> Result<LiveHostRuntimeEnvelopeDataV2, ProtocolValidationError> {
    let maximum = purpose.maximum_bytes_v1();
    if live_launch_body.len() > maximum {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = ApplyRuntimeRequest::decode_from_slice(live_launch_body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    let header = request
        .header
        .as_option()
        .ok_or(ProtocolValidationError::MissingField("header"))?;
    let header = validate_live_host_guardian_header(&request, header)?;
    let template = validate_runtime_body(&request, RuntimeBodyProfile::Live)?;
    purpose.require_canonical_v1(&request, &template, live_launch_body)?;
    Ok(LiveHostRuntimeEnvelopeDataV2 { header, template })
}

/// Decodes the exact Guardian plan pair from a live Host launch body.
///
/// This structural helper has no peer or clock authority. It exists so a
/// controller can revalidate byte-exact durable packets; Host still performs
/// full live request, plan, and lease verification before effects.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] unless the input is one bounded,
/// deadline-bearing Host 1.0 launch with exactly one valid companion.
pub fn decode_host_guardian_companion_v1(
    live_launch_body: &[u8],
) -> Result<ValidatedGuardianArmCompanionV1, ProtocolValidationError> {
    decode_live_host_runtime_data_v1(live_launch_body)?
        .guardian_arm
        .ok_or(ProtocolValidationError::MissingField("guardian_arm"))
}

/// Adds the sole Host Guardian companion to a live deadline-bearing launch body.
///
/// The plan pair is structurally checked but remains untrusted. The Host and
/// Guardian independently verify it against protected trust and the enclosing
/// request's exact ownership lease before any payload can start.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] unless the input is a companion-free,
/// deadline-bearing Host 1.0 launch body and the resulting request is bounded.
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
    validate_runtime_body(&request, RuntimeBodyProfile::Live)?;
    let encoded = request.encode_to_vec();
    if encoded.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    Ok(encoded)
}

fn validate_live_host_guardian_header(
    request: &ApplyRuntimeRequest,
    header: &aos_proto::aos::sandbox::local::v1::RequestHeader,
) -> Result<LiveHostRuntimeHeaderDataV2, ProtocolValidationError> {
    if !request.__buffa_unknown_fields.is_empty() || !header.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    if validate_header_protocol(header, ProtocolId::HostBroker)? != HOST_GUARDIAN_COMPANION_VERSION
    {
        return Err(ProtocolValidationError::InvalidField("guardian_arm"));
    }
    let request_id = exact_nonzero::<16>(&header.request_id, "header.request_id")?;
    if header.audience.as_known() != Some(Audience::AUDIENCE_NODE_CONTROLLER) {
        return Err(ProtocolValidationError::InvalidField("header.audience"));
    }
    if header.deadline_boottime_nanoseconds == 0 {
        return Err(ProtocolValidationError::InvalidField("header.deadline"));
    }
    if !(MINIMUM_RESPONSE_BYTES..=MAXIMUM_RESPONSE_BYTES).contains(&header.maximum_response_bytes) {
        return Err(ProtocolValidationError::InvalidResponseBound);
    }
    Ok(LiveHostRuntimeHeaderDataV2 {
        request_id,
        deadline_boottime_nanoseconds: header.deadline_boottime_nanoseconds,
        maximum_response_bytes: header.maximum_response_bytes,
    })
}

#[cfg(test)]
mod capture_stop_shape_tests {
    use super::*;
    use aos_proto::aos::sandbox::local::v1::{AssignmentFence, RequestHeader};

    fn widest_stop_body() -> ApplyRuntimeRequest {
        ApplyRuntimeRequest {
            header: Some(RequestHeader {
                protocol_major: 1,
                protocol_minor: 0,
                request_id: vec![1; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: u64::MAX,
                maximum_response_bytes: MAXIMUM_RESPONSE_BYTES,
                ..Default::default()
            })
            .into(),
            fence: Some(AssignmentFence {
                sandbox_id: vec![2; 16],
                incarnation_id: vec![3; 16],
                assignment_epoch: u64::MAX,
                desired_generation: u64::MAX,
                assignment_digest: vec![4; 32],
                ..Default::default()
            })
            .into(),
            action: RuntimeAction::RUNTIME_ACTION_STOP.into(),
            ..Default::default()
        }
    }

    #[test]
    fn actual_canonical_stop_with_widest_scalars_fits_the_closed_schema() {
        let bytes = widest_stop_body().encode_to_vec();
        let maximum = crate::storage_capture_session::stop_cleanup::MAXIMUM_CANONICAL_CAPTURE_STOP_BODY_BYTES_V4;

        assert!(bytes.len() <= maximum);
        let body = decode_canonical_live_host_stop_envelope_data_v4(&bytes).unwrap();
        assert_eq!(
            body.template_v1().action(),
            RuntimeAction::RUNTIME_ACTION_STOP
        );
    }

    #[test]
    fn closed_stop_refuses_duplicates_and_excess_before_generic_model_growth() {
        let mut bytes = widest_stop_body().encode_to_vec();
        // A duplicate of the actual action tag/value is noncanonical even if
        // a generic protobuf parser would retain the same final action.
        bytes.extend_from_slice(&[0x18, 0x02]);
        assert!(decode_canonical_live_host_stop_envelope_data_v4(&bytes).is_err());

        let maximum = crate::storage_capture_session::stop_cleanup::MAXIMUM_CANONICAL_CAPTURE_STOP_BODY_BYTES_V4;
        let excessive = vec![0; maximum + 1];
        assert!(matches!(
            decode_canonical_live_host_stop_envelope_data_v4(&excessive),
            Err(ProtocolValidationError::RequestTooLarge)
        ));
    }

    #[test]
    fn ordinary_host_actions_keep_their_existing_decoder() {
        let mut request = widest_stop_body();
        request.action = RuntimeAction::RUNTIME_ACTION_FREEZE.into();
        let bytes = request.encode_to_vec();

        assert!(decode_live_host_runtime_envelope_data_v2(&bytes).is_ok());
        assert!(decode_canonical_live_host_stop_envelope_data_v4(&bytes).is_err());
    }
}

#[cfg(test)]
mod template_header_data_tests {
    use super::*;

    #[test]
    fn same_decoder_lends_original_coordinates_and_keeps_template_validation() {
        let mut request = ApplyRuntimeRequest::default();
        let header = request.header.get_or_insert_default();
        header.protocol_major = 1;
        header.protocol_minor = 0;
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.request_id = vec![6; 16];
        header.maximum_response_bytes = MINIMUM_RESPONSE_BYTES;
        let fence = request.fence.get_or_insert_default();
        fence.sandbox_id = vec![1; 16];
        fence.incarnation_id = vec![2; 16];
        fence.assignment_epoch = 3;
        fence.desired_generation = 4;
        fence.assignment_digest = vec![5; 32];
        request.action = RuntimeAction::RUNTIME_ACTION_STOP.into();
        let body = request.encode_to_vec();

        let ordinary = decode_runtime_template_v1(&body).unwrap();
        let (template, header) = decode_runtime_template_with_header_data_v2(&body).unwrap();

        assert_eq!(ordinary, template);
        assert_eq!(header.protocol_major, 1);
        assert_eq!(header.protocol_minor, 0);
        assert_eq!(header.audience, Audience::AUDIENCE_NODE_CONTROLLER);
        assert_eq!(header.request_id, [6; 16]);
        assert_eq!(header.deadline_boottime_nanoseconds, 0);
        assert_eq!(header.maximum_response_bytes, MINIMUM_RESPONSE_BYTES);

        request.header.get_or_insert_default().deadline_boottime_nanoseconds = 9;
        let live_deadline = request.encode_to_vec();
        assert!(decode_runtime_template_v1(&live_deadline).is_err());
        assert!(decode_runtime_template_with_header_data_v2(&live_deadline).is_err());
    }
}
