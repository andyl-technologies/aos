//! Durable generic and authority-bound effect records.
//!
//! V2 records bind every dispatchable effect to one exact closed broker method.
//! Outer V1 records are rejected before semantic recovery or executor I/O.
//! Authority-bound dispatches retain the Host boot identity paired with their
//! BOOTTIME value.
//! V4 is the private, planned-only Controller Observe child; it has no dispatch
//! method and must match the retained AOSCOB01 reservation exactly.
//! V5 retains nonauthorizing project-admission history in the existing Create
//! Effect; V3 without that metadata remains valid but cannot retire Root history.
//! V6 appends an exact Applying-only Q04 policy-admission subgate. Ordinary
//! reconciliation cannot consume it as a completed public Create.

use aos_proto::aos::sandbox::local::v1::{
    ApplyAtomicStorageSnapshotRequest, ApplyMountRequest, ApplyNetworkRequest, ApplyRuntimeRequest,
    ApplyStorageRequest, Audience, BrokerMethod, BrokerRequestEnvelope, QueryRuntimeEffectRequest,
    QueryRuntimeEffectResponse, RequestHeader, RuntimeEffectStatus,
};
use aos_sandbox_core::{
    BrokerAudience, ObjectDigest, OperationId, PrincipalId, ProjectId, ProtocolVersion,
    RawPairedClockSample,
};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
};
use aos_sandbox_protocol::public_api::public_mutation_context::{
    InvalidPublicMutationContext, PublicMutationContextV1,
};
use buffa::Message as _;
#[cfg(test)]
use sha2::{Digest as _, Sha256};

use super::project_admission::{MAXIMUM_RECORD_BYTES, ProjectAdmissionMetadata};
use super::{EffectReceipt, ReconcilerError};
use crate::controller_execution_observe_reservation::ControllerExecutionObserveReservationV1;
use crate::{BrokerDispatchAttemptV1, BrokerDispatchSemanticIdentityV1};

mod history;

pub(super) use history::{decode_effect, effect_body_digest, encode_effect};
#[cfg(target_os = "linux")]
pub(super) use history::{decode_effect_with_q04, encode_q04_effect, q04_effect_subgate};
use history::{attempt_token_digest, effect_binding_digest, validate_broker_method_domain};
#[cfg(test)]
use history::{audience_code, audience_from_code};
pub(crate) use history::{
    compare_capacity_effect_history, decode_capacity_effect_history, validate_delete_effect_record,
};

pub(super) const MAXIMUM_REQUEST_BYTES: usize = 1024 * 1024;
pub(super) const MAXIMUM_RECEIPT_BYTES: usize = 64 * 1024;
pub(super) const MAXIMUM_DIAGNOSTIC_BYTES: usize = 4096;
const EFFECT_VERSION: u8 = 2;
const CONTROLLER_EFFECT_VERSION: u8 = 3;
pub(super) const RESERVED_OBSERVE_EFFECT_VERSION: u8 = 4;
pub(super) const CONTROLLER_PROJECT_EFFECT_VERSION: u8 = 5;
const CONTROLLER_Q04_EFFECT_VERSION: u8 = 6;
const AUTHORITY_BOUND_FLAG: u8 = 1;
const MAXIMUM_DISPATCH_PACKET_BYTES: usize = MAXIMUM_REQUEST_BYTES;
const BODY_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.effect-body.v1\0";
const BINDING_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.effect-binding.v1\0";
const ATTEMPT_TOKEN_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.effect-attempt-token.v1\0";
#[cfg(test)]
// The original golden vector remains independent of the relocated encoder.
const PUBLIC_MUTATION_EFFECT_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.public-mutation-effect.v1\0";

/// Carries authenticated admission identity with one exact public mutation.
///
/// The public envelope does not contain the mutually authenticated caller or
/// its project authority. Production lowering therefore persists those facts
/// beside the exact envelope instead of attempting to reconstruct them from a
/// target resource after admission.
/// Protocol owns its plain historical DATA and codec; this native wrapper
/// retains the original FUSE/Nix carrier selection and admission recipes.
#[derive(Clone, Eq, PartialEq)]
pub struct PublicMutationEffectV1 {
    plain: PublicMutationContextV1,
    #[cfg(target_os = "linux")]
    fuse_admission: Option<crate::controller_fuse_admission::ControllerFuseAdmissionCarrierV1>,
    #[cfg(target_os = "linux")]
    nix_start: Option<crate::production_operation_compiler::NixStartAdmissionCarrierV2>,
}

impl std::fmt::Debug for PublicMutationEffectV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Keep the original flat diagnostic fields despite nested DATA storage.
        let mut fields = formatter.debug_struct("PublicMutationEffectV1");
        fields.field("caller", &self.plain.caller());
        fields.field("project", &self.plain.project());
        fields.field("accepted_wall_seconds", &self.plain.accepted_wall_seconds());
        fields.field("canonical_request", &self.plain.canonical_request());
        #[cfg(target_os = "linux")]
        fields.field("fuse_admission", &self.fuse_admission);
        #[cfg(target_os = "linux")]
        fields.field("nix_start", &self.nix_start);
        fields.finish()
    }
}

fn invalid_public_mutation_context(error: InvalidPublicMutationContext) -> ReconcilerError {
    // Project before native callers retain or wrap the original Reconciler cause.
    ReconcilerError::InvalidPlan(error.reason())
}

impl PublicMutationEffectV1 {
    /// Binds authenticated request identity to exact canonical request bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidPlan`] for sentinel identities,
    /// nonpositive admission time, or an empty or oversized request.
    pub fn new(
        caller: PrincipalId,
        project: ProjectId,
        accepted_wall_seconds: i64,
        canonical_request: Vec<u8>,
    ) -> Result<Self, ReconcilerError> {
        let plain =
            PublicMutationContextV1::new(caller, project, accepted_wall_seconds, canonical_request)
                .map_err(invalid_public_mutation_context)?;
        Ok(Self {
            plain,
            #[cfg(target_os = "linux")]
            fuse_admission: None,
            #[cfg(target_os = "linux")]
            nix_start: None,
        })
    }

    /// Returns the authenticated caller fixed at admission.
    #[must_use]
    pub const fn caller(&self) -> PrincipalId {
        self.plain.caller()
    }

    /// Returns the authenticated project fixed at admission.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.plain.project()
    }

    /// Returns the protected admission clock in Unix seconds.
    #[must_use]
    pub const fn accepted_wall_seconds(&self) -> i64 {
        self.plain.accepted_wall_seconds()
    }

    /// Returns the exact canonical public mutation envelope.
    #[must_use]
    pub fn canonical_request(&self) -> &[u8] {
        self.plain.canonical_request()
    }

    /// Decodes the exact public request through the established mutation validator.
    ///
    /// This preserves the authenticated caller and project carried by this
    /// effect while reusing the same canonical protobuf and field validation as
    /// initial public admission. Lowering code must not decode the retained body
    /// through a second, weaker request path.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidPlan`] when the retained envelope or
    /// method-selected protobuf is malformed, noncanonical, or semantically
    /// invalid.
    pub fn validated_request(
        &self,
    ) -> Result<aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1, ReconcilerError> {
        self.plain
            .validated_request()
            .map_err(invalid_public_mutation_context)
    }

    fn encode(&self) -> Result<Vec<u8>, ReconcilerError> {
        #[cfg(target_os = "linux")]
        return aos_sandbox_protocol::public_api::mutation_history::encode_history(
            &self.plain,
            self.fuse_admission
                .as_ref()
                .map(|carrier| carrier.history()),
            self.nix_start.as_ref(),
        )
        .map_err(|error| ReconcilerError::InvalidPlan(error.reason()));
        #[cfg(not(target_os = "linux"))]
        self.encode_plain()
    }

    pub(crate) fn encode_plain(&self) -> Result<Vec<u8>, ReconcilerError> {
        self.plain.encode().map_err(invalid_public_mutation_context)
    }

    fn decode(bytes: &[u8]) -> Result<Option<Self>, ReconcilerError> {
        #[cfg(target_os = "linux")]
        return aos_sandbox_protocol::public_api::mutation_history::decode_history(bytes)
            .map(|parts| parts.map(|(plain, fuse_admission, nix_start)| Self {
                plain,
                fuse_admission: fuse_admission.map(crate::controller_fuse_admission::ControllerFuseAdmissionCarrierV1::from_history),
                nix_start,
            }))
            .map_err(|error| ReconcilerError::InvalidPlan(error.reason()));
        #[cfg(not(target_os = "linux"))]
        Self::decode_plain(bytes)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn with_fuse_admission(
        mut self,
        carrier: crate::controller_fuse_admission::ControllerFuseAdmissionCarrierV1,
    ) -> Result<Self, ReconcilerError> {
        aos_sandbox_protocol::public_api::mutation_history::require_fuse_context(
            &self.plain,
            self.nix_start.as_ref(),
            carrier.history(),
        )
        .map_err(|error| ReconcilerError::InvalidPlan(error.reason()))?;
        self.fuse_admission = Some(carrier);
        Ok(self)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn fuse_admission(
        &self,
    ) -> Option<&crate::controller_fuse_admission::ControllerFuseAdmissionCarrierV1> {
        self.fuse_admission.as_ref()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn with_nix_start(
        mut self,
        carrier: crate::production_operation_compiler::NixStartAdmissionCarrierV2,
    ) -> Result<Self, ReconcilerError> {
        aos_sandbox_protocol::public_api::mutation_history::require_nix_context(
            &self.plain,
            self.fuse_admission
                .as_ref()
                .map(|carrier| carrier.history()),
            &carrier,
        )
        .map_err(|error| ReconcilerError::InvalidPlan(error.reason()))?;
        self.nix_start = Some(carrier);
        Ok(self)
    }

    /// Reports retained Nix continuation DATA, never build or floor readiness.
    #[cfg(target_os = "linux")]
    pub fn has_retained_nix_start(&self) -> bool {
        self.nix_start.is_some()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn nix_start(&self) -> Option<&crate::production_operation_compiler::NixStartAdmissionCarrierV2> {
        self.nix_start.as_ref()
    }

    pub(crate) fn decode_plain(bytes: &[u8]) -> Result<Option<Self>, ReconcilerError> {
        PublicMutationContextV1::decode(bytes)
            .map(|context| {
                context.map(|plain| Self {
                    plain,
                    #[cfg(target_os = "linux")]
                    fuse_admission: None,
                    #[cfg(target_os = "linux")]
                    nix_start: None,
                })
            })
            .map_err(invalid_public_mutation_context)
    }
}

/// Selects the sole fixed-function boundary allowed to execute an effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EffectDomain {
    /// Typed systemd, cgroup, runtime, and freeze operations.
    Host = 1,
    /// Typed dataset, snapshot, hold, clone, quota, and destroy operations.
    Storage = 2,
    /// Descriptor-only mount preparation and namespace publication.
    Mount = 3,
    /// Typed network namespace, link, route, and packet-gate operations.
    Network = 4,
    /// Assignment ownership and fail-stop lease operations.
    Guardian = 5,
    /// Authenticated in-guest readiness, execution, and quiesce operations.
    Guest = 6,
    /// Controller-owned orchestration of one authenticated public mutation.
    Controller = 7,
}

impl EffectDomain {
    pub(super) fn from_byte(value: u8) -> Result<Self, ReconcilerError> {
        match value {
            1 => Ok(Self::Host),
            2 => Ok(Self::Storage),
            3 => Ok(Self::Mount),
            4 => Ok(Self::Network),
            5 => Ok(Self::Guardian),
            6 => Ok(Self::Guest),
            7 => Ok(Self::Controller),
            _ => Err(ReconcilerError::CorruptLedger("unknown effect domain")),
        }
    }

    pub(super) const fn from_audience(audience: BrokerAudience) -> Result<Self, ReconcilerError> {
        match audience {
            BrokerAudience::Host => Ok(Self::Host),
            BrokerAudience::Storage => Ok(Self::Storage),
            BrokerAudience::Mount => Ok(Self::Mount),
            BrokerAudience::Network => Ok(Self::Network),
            BrokerAudience::Guardian => Err(ReconcilerError::InvalidPlan(
                "guardian authority cannot use the generic broker effect path",
            )),
            BrokerAudience::Nix => Err(ReconcilerError::InvalidPlan(
                "Nix authority cannot use the generic broker effect path",
            )),
        }
    }
}

/// Defines one ordered, idempotent request to a fixed effect boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectPlan {
    pub(super) domain: EffectDomain,
    pub(super) method: Option<BrokerMethod>,
    pub(super) controller_method: Option<aos_sandbox_protocol::public_api::PublicOperationMethodV1>,
    pub(super) request: Vec<u8>,
    pub(super) authority: Option<AuthorityEffectBindingV1>,
}

impl EffectPlan {
    /// Retains an Observe child without a dispatch method or effect authority.
    #[must_use]
    pub(super) fn reserved_observe(reservation: &ControllerExecutionObserveReservationV1) -> Self {
        Self {
            domain: EffectDomain::Controller,
            method: None,
            controller_method: None,
            request: reservation.encode(),
            authority: None,
        }
    }

    pub(super) fn is_reserved_observe(&self) -> bool {
        self.domain == EffectDomain::Controller
            && self.method.is_none()
            && self.controller_method.is_none()
            && self.authority.is_none()
            && self.request.get(8..24).is_some_and(|execution| {
                ControllerExecutionObserveReservationV1::decode(execution, &self.request).is_ok()
            })
    }

    /// Constructs a controller effect with authenticated admission context.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidPlan`] when the context cannot be
    /// encoded or its inner envelope does not select `method`.
    pub fn authorized_public_mutation(
        method: aos_sandbox_protocol::public_api::PublicOperationMethodV1,
        effect: PublicMutationEffectV1,
    ) -> Result<Self, ReconcilerError> {
        Self::from_public_mutation_bytes(method, effect.encode()?)
    }

    /// Constructs a bounded generic broker effect from validated request bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidPlan`] for an unknown or cross-domain
    /// method, or for an empty or oversized request.
    pub fn new(
        domain: EffectDomain,
        method: BrokerMethod,
        request: Vec<u8>,
    ) -> Result<Self, ReconcilerError> {
        if request.is_empty() || request.len() > MAXIMUM_REQUEST_BYTES {
            return Err(ReconcilerError::InvalidPlan(
                "invalid effect request length",
            ));
        }
        validate_broker_method_domain(domain, method)?;

        Ok(Self {
            domain,
            method: Some(method),
            controller_method: None,
            request,
            authority: None,
        })
    }

    // Construction and recovery use the same context-bearing request validator.
    fn from_public_mutation_bytes(
        method: aos_sandbox_protocol::public_api::PublicOperationMethodV1,
        request: Vec<u8>,
    ) -> Result<Self, ReconcilerError> {
        if request.is_empty() || request.len() > MAXIMUM_REQUEST_BYTES {
            return Err(ReconcilerError::InvalidPlan(
                "invalid controller effect request length",
            ));
        }
        let authenticated = PublicMutationEffectV1::decode(&request)?.ok_or(
            ReconcilerError::InvalidPlan("controller effect lacks authenticated admission context"),
        )?;
        let canonical_request = authenticated.canonical_request();
        if method == aos_sandbox_protocol::public_api::PublicOperationMethodV1::OperatorRecover {
            let envelope = crate::cli_model::PublicMutationRequestV1::decode(canonical_request)
                .map_err(|_| ReconcilerError::InvalidPlan("invalid controller effect request"))?;
            let kind = envelope
                .decode_validated_kind()
                .map_err(|_| ReconcilerError::InvalidPlan("invalid controller effect request"))?;
            if envelope.method() != crate::cli_model::PublicApiAuditMethodV1::OperatorRecover
                || !matches!(
                    kind,
                    aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1::OperatorRecover(_)
                )
            {
                return Err(ReconcilerError::InvalidPlan(
                    "controller effect method does not match its request",
                ));
            }
        } else {
            let resolved =
                crate::public_mutation_compiler::ResolvedPublicMutationRequestV1::decode(
                    canonical_request,
                )
                .map_err(|_| ReconcilerError::InvalidPlan("invalid controller effect request"))?;
            if resolved.operation_method() != method {
                return Err(ReconcilerError::InvalidPlan(
                    "controller effect method does not match its request",
                ));
            }
        }

        Ok(Self {
            domain: EffectDomain::Controller,
            method: None,
            controller_method: Some(method),
            request,
            authority: None,
        })
    }

    /// Returns the fixed boundary selected for this effect.
    #[must_use]
    pub const fn domain(&self) -> EffectDomain {
        self.domain
    }

    /// Returns the exact broker method, or `None` for Controller-owned effects.
    #[must_use]
    pub const fn method(&self) -> Option<BrokerMethod> {
        self.method
    }

    /// Returns the exact public mutation handled by controller orchestration.
    #[must_use]
    pub const fn public_mutation_method(
        &self,
    ) -> Option<aos_sandbox_protocol::public_api::PublicOperationMethodV1> {
        self.controller_method
    }

    /// Decodes authenticated admission context for a controller mutation.
    ///
    /// Controller mutations retain a context. Broker effects and reserved
    /// Observe children return `None`.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidPlan`] when an authenticated envelope
    /// has malformed lengths, reserved bytes, identities, time, or digest.
    pub fn public_mutation_context(
        &self,
    ) -> Result<Option<PublicMutationEffectV1>, ReconcilerError> {
        if self.controller_method.is_none() {
            return Ok(None);
        }
        PublicMutationEffectV1::decode(&self.request)
    }

    /// Returns the exact idempotent request bytes sent to the executor.
    #[must_use]
    pub fn request(&self) -> &[u8] {
        &self.request
    }

    pub(super) fn authority(&self) -> Option<&AuthorityEffectBindingV1> {
        self.authority.as_ref()
    }
}

/// Freezes one exact draft-derived broker effect for gated admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityBoundEffectPlanV1 {
    plan: EffectPlan,
    source_draft_digest: ObjectDigest,
    audience: BrokerAudience,
    template_digest: ObjectDigest,
    descriptor_free: bool,
}

impl AuthorityBoundEffectPlanV1 {
    pub(crate) fn from_template(
        source_draft_digest: ObjectDigest,
        audience: BrokerAudience,
        method: BrokerMethod,
        template_digest: ObjectDigest,
        body: &[u8],
        semantics: BrokerDispatchSemanticIdentityV1,
        descriptor_free: bool,
    ) -> Result<Self, ReconcilerError> {
        if body.is_empty() || body.len() > MAXIMUM_REQUEST_BYTES {
            return Err(ReconcilerError::InvalidPlan(
                "invalid authority effect body",
            ));
        }
        let domain = EffectDomain::from_audience(audience)?;
        let body_digest = effect_body_digest(body);
        let semantic_digest = crate::dispatch::semantic_identity_digest(semantics);
        Ok(Self {
            plan: EffectPlan {
                domain,
                method: Some(method),
                controller_method: None,
                request: body.to_vec(),
                authority: Some(AuthorityEffectBindingV1 {
                    source_draft_digest,
                    audience,
                    method,
                    template_digest,
                    body_digest,
                    semantic_digest,
                    descriptor_free,
                    operation_id: OperationId::from_bytes([0; 16]),
                    step: 0,
                    digest: ObjectDigest::from_bytes([0; 32]),
                }),
            },
            source_draft_digest,
            audience,
            template_digest,
            descriptor_free,
        })
    }

    /// Returns the publication draft that supplied the exact template.
    #[must_use]
    pub fn source_draft_digest(&self) -> ObjectDigest {
        self.source_draft_digest
    }

    /// Returns the exact selected dispatch-template digest.
    #[must_use]
    pub fn template_digest(&self) -> ObjectDigest {
        self.template_digest
    }

    /// Returns the broker audience derived from the selected template.
    #[must_use]
    pub fn audience(&self) -> BrokerAudience {
        self.audience
    }

    /// Returns the exact deadline-free request body committed by the template.
    #[must_use]
    pub fn body_without_deadline(&self) -> &[u8] {
        &self.plan.request
    }

    pub(super) fn is_supported_authority_apply(&self) -> bool {
        let method_matches_audience = matches!(
            (self.audience, self.plan.method),
            (
                BrokerAudience::Host,
                Some(BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME)
            ) | (
                BrokerAudience::Storage,
                Some(BrokerMethod::BROKER_METHOD_STORAGE_APPLY)
            ) | (
                BrokerAudience::Mount,
                Some(BrokerMethod::BROKER_METHOD_MOUNT_APPLY)
            ) | (
                BrokerAudience::Network,
                Some(BrokerMethod::BROKER_METHOD_NETWORK_APPLY)
            )
        );

        method_matches_audience && self.descriptor_free
    }

    pub(super) fn into_inner(
        mut self,
        operation_id: OperationId,
        step: u32,
    ) -> Result<EffectPlan, ReconcilerError> {
        if let Some(binding) = &mut self.plan.authority {
            binding.operation_id = operation_id;
            binding.step = step;
            binding.digest = effect_binding_digest(
                operation_id,
                step,
                binding.source_draft_digest,
                binding.audience,
                binding.method,
                binding.template_digest,
                binding.body_digest,
                binding.semantic_digest,
            )?;
        }
        Ok(self.plan)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AuthorityEffectBindingV1 {
    pub(super) operation_id: OperationId,
    pub(super) step: u32,
    pub(super) source_draft_digest: ObjectDigest,
    pub(super) audience: BrokerAudience,
    pub(super) method: BrokerMethod,
    pub(super) template_digest: ObjectDigest,
    pub(super) body_digest: ObjectDigest,
    pub(super) semantic_digest: ObjectDigest,
    pub(super) descriptor_free: bool,
    pub(super) digest: ObjectDigest,
}

/// Supplies advisory clock facts used to attenuate one durable broker attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityEffectAttemptTimingV1 {
    clock: RawPairedClockSample,
    deadline_boottime_nanoseconds: u64,
}

impl AuthorityEffectAttemptTimingV1 {
    /// Constructs timing input checked against the selected signed authority.
    #[must_use]
    pub const fn new(clock: RawPairedClockSample, deadline_boottime_nanoseconds: u64) -> Self {
        Self {
            clock,
            deadline_boottime_nanoseconds,
        }
    }

    pub(crate) const fn clock(self) -> RawPairedClockSample {
        self.clock
    }

    pub(crate) const fn deadline(self) -> u64 {
        self.deadline_boottime_nanoseconds
    }
}

/// Carries the exact broker request made durable before external I/O.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedAuthorityEffectV1 {
    binding_digest: ObjectDigest,
    publication_digest: ObjectDigest,
    preparation_wall_seconds: i64,
    preparation_boottime_nanoseconds: u64,
    preparation_host_boot_id: [u8; 16],
    attempt: BrokerDispatchAttemptV1,
}

/// Carries one exact durable authority request into authenticated session custody.
///
/// This value can only be recovered from a reconciler-prepared effect. Its
/// request identity is therefore the identity made durable before transport,
/// rather than a caller-selected replacement generated at send time.
#[derive(Clone, Debug, PartialEq)]
pub struct PreparedAuthorityBrokerRequestV1 {
    envelope: BrokerRequestEnvelope,
    method: BrokerMethod,
    request_id: [u8; 16],
    deadline_boottime_nanoseconds: u64,
    maximum_response_bytes: u32,
    protocol_version: ProtocolVersion,
    audience: Audience,
}

impl PreparedAuthorityBrokerRequestV1 {
    /// Returns the exact closed broker method.
    #[must_use]
    pub const fn method(&self) -> BrokerMethod {
        self.method
    }

    /// Returns the exact durable request identifier.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the absolute durable attempt deadline.
    #[must_use]
    pub const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.deadline_boottime_nanoseconds
    }

    /// Returns the request-specific response ceiling.
    #[must_use]
    pub const fn maximum_response_bytes(&self) -> u32 {
        self.maximum_response_bytes
    }

    /// Returns the exact protocol version carried by the method body.
    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Returns the exact session audience carried by the method body.
    #[must_use]
    pub const fn audience(&self) -> Audience {
        self.audience
    }

    /// Consumes the binding and returns its canonical unsigned envelope.
    #[must_use]
    pub fn into_envelope(self) -> BrokerRequestEnvelope {
        self.envelope
    }
}

impl PreparedAuthorityEffectV1 {
    pub(crate) const fn new(
        binding_digest: ObjectDigest,
        publication_digest: ObjectDigest,
        preparation_clock: RawPairedClockSample,
        attempt: BrokerDispatchAttemptV1,
    ) -> Self {
        Self {
            binding_digest,
            publication_digest,
            preparation_wall_seconds: preparation_clock.wall_seconds(),
            preparation_boottime_nanoseconds: preparation_clock.boottime_nanoseconds(),
            preparation_host_boot_id: preparation_clock.host_boot_id(),
            attempt,
        }
    }

    pub(crate) const fn from_durable_parts(
        binding_digest: ObjectDigest,
        publication_digest: ObjectDigest,
        preparation_wall_seconds: i64,
        preparation_boottime_nanoseconds: u64,
        preparation_host_boot_id: [u8; 16],
        attempt: BrokerDispatchAttemptV1,
    ) -> Self {
        Self {
            binding_digest,
            publication_digest,
            preparation_wall_seconds,
            preparation_boottime_nanoseconds,
            preparation_host_boot_id,
            attempt,
        }
    }

    /// Validates a Host completion body against this exact persisted Apply.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidExecutorOutput`] when the receipt is
    /// malformed or does not name the Apply request's exact fence and handle.
    pub fn validate_host_receipt(
        &self,
        bytes: Vec<u8>,
    ) -> Result<ValidatedHostEffectReceiptV1, ReconcilerError> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_RECEIPT_BYTES {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "invalid Host effect receipt length",
            ));
        }
        aos_sandbox_protocol::validate_runtime_effect_receipt_for_apply(
            &bytes,
            self.attempt.body(),
        )
        .map_err(|_| ReconcilerError::InvalidExecutorOutput("invalid Host effect receipt"))?;
        Ok(ValidatedAuthorityEffectReceiptV1 {
            bytes,
            binding_digest: self.binding_digest,
            attempt_digest: attempt_token_digest(&self.attempt),
        })
    }

    /// Extracts one method-specific success body from an authenticated outcome.
    ///
    /// The authenticated protocol layer has already decoded and correlated the
    /// method-specific result. This final bridge additionally binds it to this
    /// reconciler's exact durable method and request body before the receipt can
    /// be committed.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidExecutorOutput`] for a different
    /// method or request, a signed broker error, or an oversized success body.
    pub fn validate_authenticated_outcome(
        &self,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<ValidatedAuthorityEffectReceiptV1, ReconcilerError> {
        let method = self.attempt_method()?;
        if outcome.method() != method || outcome.request().exact_body() != self.attempt.body() {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "authority effect outcome belongs to another durable attempt",
            ));
        }
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "authority effect returned a terminal broker error",
            ));
        };
        if exact_body.is_empty() || exact_body.len() > MAXIMUM_RECEIPT_BYTES {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "invalid authority effect receipt length",
            ));
        }

        Ok(ValidatedAuthorityEffectReceiptV1 {
            bytes: exact_body.clone(),
            binding_digest: self.binding_digest,
            attempt_digest: attempt_token_digest(&self.attempt),
        })
    }

    /// Validates a protected terminal exchange recovered from session history.
    ///
    /// The broker-session owner has already authenticated and cross-linked the
    /// retained request and outcome packets. This final bridge prevents a
    /// terminal result for another Apply from satisfying this reconciler
    /// attempt and re-applies the Host receipt's method-specific validation.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidExecutorOutput`] when the recovered
    /// method, request identifier, request body, or receipt does not belong to
    /// this exact durable attempt.
    pub fn validate_protected_terminal_receipt(
        &self,
        method: BrokerMethod,
        request_id: [u8; 16],
        request_body: &[u8],
        receipt: Vec<u8>,
    ) -> Result<ValidatedAuthorityEffectReceiptV1, ReconcilerError> {
        let request = self.broker_request()?;
        if method != request.method()
            || request_id != request.request_id()
            || request_body != self.attempt.body()
        {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "protected terminal exchange belongs to another durable attempt",
            ));
        }
        if receipt.is_empty() || receipt.len() > MAXIMUM_RECEIPT_BYTES {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "invalid protected terminal receipt length",
            ));
        }
        if method == BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME {
            return self.validate_host_receipt(receipt);
        }

        Ok(ValidatedAuthorityEffectReceiptV1 {
            bytes: receipt,
            binding_digest: self.binding_digest,
            attempt_digest: attempt_token_digest(&self.attempt),
        })
    }

    /// Validates one authenticated Host query for this exact durable Apply.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidExecutorOutput`] when the query does
    /// not embed this exact Apply, when the broker reports an invalid terminal
    /// body, or when a completed receipt does not match the original request.
    pub fn validate_authenticated_host_observation(
        &self,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<AuthorityEffectObservationV1, ReconcilerError> {
        let original = self.broker_request()?;
        if original.method() != BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
            || outcome.method() != BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT
        {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "authority effect query selected the wrong method",
            ));
        }
        let query = QueryRuntimeEffectRequest::decode_from_slice(outcome.request().exact_body())
            .map_err(|_| {
                ReconcilerError::InvalidExecutorOutput("authority effect query is malformed")
            })?;
        let header = query
            .header
            .as_option()
            .ok_or(ReconcilerError::InvalidExecutorOutput(
                "authority effect query header is missing",
            ))?;
        if !query.__buffa_unknown_fields.is_empty()
            || query.encode_to_vec() != outcome.request().exact_body()
            || header.request_id.as_slice() != original.request_id()
            || query.original_apply_request.as_slice() != self.attempt.body()
        {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "authority effect query does not name the durable Apply",
            ));
        }

        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "authority effect query returned a terminal broker error",
            ));
        };
        let response = QueryRuntimeEffectResponse::decode_from_slice(exact_body).map_err(|_| {
            ReconcilerError::InvalidExecutorOutput("authority effect query response is malformed")
        })?;
        if !response.__buffa_unknown_fields.is_empty() || response.encode_to_vec() != *exact_body {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "authority effect query response is not canonical",
            ));
        }

        match response.status.as_known() {
            Some(RuntimeEffectStatus::RUNTIME_EFFECT_STATUS_ABSENT)
                if response.receipt.is_empty() =>
            {
                Ok(AuthorityEffectObservationV1::Absent)
            }
            Some(RuntimeEffectStatus::RUNTIME_EFFECT_STATUS_PENDING)
                if response.receipt.is_empty() =>
            {
                Ok(AuthorityEffectObservationV1::Pending)
            }
            Some(RuntimeEffectStatus::RUNTIME_EFFECT_STATUS_COMPLETE) => self
                .validate_host_receipt(response.receipt)
                .map(AuthorityEffectObservationV1::Applied),
            _ => Err(ReconcilerError::InvalidExecutorOutput(
                "authority effect query response has an invalid status",
            )),
        }
    }

    /// Recovers the exact durable request for authenticated session admission.
    ///
    /// The returned envelope still lacks its session authentication carrier.
    /// Session custody may add that carrier, but it must preserve the exact
    /// method body and all request coordinates exposed by the returned value.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidExecutorOutput`] when the durable
    /// envelope or method body is noncanonical, incomplete, or inconsistent
    /// with the attempt deadline.
    pub fn broker_request(&self) -> Result<PreparedAuthorityBrokerRequestV1, ReconcilerError> {
        let envelope = self.attempt_envelope()?;
        let method = envelope
            .method
            .as_known()
            .ok_or(ReconcilerError::InvalidExecutorOutput(
                "authority effect method is unknown",
            ))?;
        let header = decode_authority_apply_header(method, self.attempt.body())?;
        let request_id: [u8; 16] = header.request_id.as_slice().try_into().map_err(|_| {
            ReconcilerError::InvalidExecutorOutput("authority effect request ID is invalid")
        })?;
        let protocol_major = u16::try_from(header.protocol_major).map_err(|_| {
            ReconcilerError::InvalidExecutorOutput("authority effect protocol version is invalid")
        })?;
        let protocol_minor = u16::try_from(header.protocol_minor).map_err(|_| {
            ReconcilerError::InvalidExecutorOutput("authority effect protocol version is invalid")
        })?;
        let audience = header
            .audience
            .as_known()
            .ok_or(ReconcilerError::InvalidExecutorOutput(
                "authority effect audience is unknown",
            ))?;
        if request_id == [0; 16]
            || header.deadline_boottime_nanoseconds != self.attempt.deadline_boottime_nanoseconds()
            || !(aos_sandbox_protocol::MINIMUM_RESPONSE_BYTES
                ..=aos_sandbox_protocol::MAXIMUM_RESPONSE_BYTES)
                .contains(&header.maximum_response_bytes)
        {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "authority effect request coordinates are invalid",
            ));
        }

        Ok(PreparedAuthorityBrokerRequestV1 {
            envelope,
            method,
            request_id,
            deadline_boottime_nanoseconds: header.deadline_boottime_nanoseconds,
            maximum_response_bytes: header.maximum_response_bytes,
            protocol_version: ProtocolVersion::new(protocol_major, protocol_minor),
            audience,
        })
    }

    pub(crate) fn validate_durable_receipt(&self, bytes: &[u8]) -> Result<(), ReconcilerError> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_RECEIPT_BYTES {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "invalid authority effect receipt length",
            ));
        }
        if self.attempt_method()? == BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME {
            aos_sandbox_protocol::validate_runtime_effect_receipt_for_apply(
                bytes,
                self.attempt.body(),
            )
            .map_err(|_| ReconcilerError::InvalidExecutorOutput("invalid Host effect receipt"))?;
        }

        Ok(())
    }

    fn attempt_method(&self) -> Result<BrokerMethod, ReconcilerError> {
        self.attempt_envelope()?
            .method
            .as_known()
            .ok_or(ReconcilerError::InvalidExecutorOutput(
                "authority effect method is unknown",
            ))
    }

    fn attempt_envelope(&self) -> Result<BrokerRequestEnvelope, ReconcilerError> {
        let packet =
            BrokerRequestEnvelope::decode_from_slice(self.attempt.packet()).map_err(|_| {
                ReconcilerError::InvalidExecutorOutput("authority effect request is malformed")
            })?;
        if !packet.__buffa_unknown_fields.is_empty()
            || packet.encode_to_vec() != self.attempt.packet()
            || packet.body.as_slice() != self.attempt.body()
        {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "authority effect request is not canonical",
            ));
        }

        Ok(packet)
    }

    pub(crate) const fn binding_digest(&self) -> ObjectDigest {
        self.binding_digest
    }

    /// Returns the exact current publication selected for this attempt.
    #[must_use]
    pub const fn publication_digest(&self) -> ObjectDigest {
        self.publication_digest
    }

    /// Returns the byte-exact deadline-bearing broker attempt.
    ///
    /// Its packet is the original Apply carrier retained for either direct
    /// transmission or construction of an authenticated effect query after a
    /// crash or ambiguous response.
    #[must_use]
    pub const fn attempt(&self) -> &BrokerDispatchAttemptV1 {
        &self.attempt
    }

    pub(crate) const fn preparation_wall_seconds(&self) -> i64 {
        self.preparation_wall_seconds
    }

    /// Returns the monotonic clock value at which this attempt became durable.
    #[must_use]
    pub const fn preparation_boottime_nanoseconds(&self) -> u64 {
        self.preparation_boottime_nanoseconds
    }

    /// Returns the host boot in which this attempt became durable.
    #[must_use]
    pub const fn preparation_host_boot_id(&self) -> [u8; 16] {
        self.preparation_host_boot_id
    }
}

fn decode_authority_apply_header(
    method: BrokerMethod,
    body: &[u8],
) -> Result<RequestHeader, ReconcilerError> {
    macro_rules! decode_header {
        ($message:ty) => {{
            let request = <$message>::decode_from_slice(body).map_err(|_| {
                ReconcilerError::InvalidExecutorOutput("authority effect body is malformed")
            })?;
            if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != body {
                return Err(ReconcilerError::InvalidExecutorOutput(
                    "authority effect body is not canonical",
                ));
            }
            request
                .header
                .as_option()
                .cloned()
                .ok_or(ReconcilerError::InvalidExecutorOutput(
                    "authority effect header is missing",
                ))
        }};
    }

    let header = match method {
        BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME => decode_header!(ApplyRuntimeRequest),
        BrokerMethod::BROKER_METHOD_STORAGE_APPLY => decode_header!(ApplyStorageRequest),
        BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT => {
            decode_header!(ApplyAtomicStorageSnapshotRequest)
        }
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY => decode_header!(ApplyMountRequest),
        BrokerMethod::BROKER_METHOD_NETWORK_APPLY => decode_header!(ApplyNetworkRequest),
        _ => Err(ReconcilerError::InvalidExecutorOutput(
            "authority effect method is not an Apply method",
        )),
    }?;
    if !header.__buffa_unknown_fields.is_empty() {
        return Err(ReconcilerError::InvalidExecutorOutput(
            "authority effect header is not canonical",
        ));
    }

    Ok(header)
}

/// Carries a broker completion receipt validated against one exact persisted Apply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedAuthorityEffectReceiptV1 {
    bytes: Vec<u8>,
    binding_digest: ObjectDigest,
    attempt_digest: ObjectDigest,
}

impl ValidatedAuthorityEffectReceiptV1 {
    pub(super) fn into_effect_receipt_for(
        self,
        prepared: &PreparedAuthorityEffectV1,
    ) -> Result<EffectReceipt, ReconcilerError> {
        if self.binding_digest != prepared.binding_digest
            || self.attempt_digest != attempt_token_digest(prepared.attempt())
        {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "authority effect receipt belongs to another durable attempt",
            ));
        }
        Ok(EffectReceipt(self.bytes))
    }
}

/// Preserves the original Host-specific receipt name for compatible callers.
pub type ValidatedHostEffectReceiptV1 = ValidatedAuthorityEffectReceiptV1;

/// Reports authenticated broker observation for one exact persisted Apply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityEffectObservationV1 {
    /// The broker durably proves the exact request is absent.
    Absent,
    /// The broker has admitted the exact request but has not completed it.
    Pending,
    /// The broker completed the exact request with validated receipt bytes.
    Applied(ValidatedAuthorityEffectReceiptV1),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum EffectState {
    Planned,
    Applying {
        attempt: u32,
        diagnostic: String,
    },
    Applied {
        attempt: u32,
        receipt: EffectReceipt,
    },
    PermanentlyBlocked {
        attempt: u32,
        diagnostic: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct EffectLedgerRecord {
    pub(super) plan: EffectPlan,
    pub(super) state: EffectState,
    pub(super) dispatch: Option<PreparedAuthorityEffectV1>,
    pub(super) project_admission: Option<ProjectAdmissionMetadata>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use aos_proto::aos::sandbox::v1::AttenuateCapabilityRequest;
    use aos_sandbox_core::{BrokerArgumentCommitment, BrokerGrantTarget, BrokerVerb};
    use buffa::Message as _;

    #[cfg(target_os = "linux")]
    #[test]
    fn ordinary_public_effect_retains_exact_original_time_without_nix_data() {
        let context = PublicMutationEffectV1::new(
            PrincipalId::from_bytes([1; 16]), ProjectId::from_bytes([2; 16]),
            123, b"historical-request-data".to_vec(),
        ).unwrap();
        let mut expected = b"AOSPME01".to_vec();
        expected.extend_from_slice(&1_u16.to_be_bytes());
        expected.extend_from_slice(&[0; 6]);
        expected.extend_from_slice(&[1; 16]);
        expected.extend_from_slice(&[2; 16]);
        expected.extend_from_slice(&123_i64.to_be_bytes());
        expected.extend_from_slice(&23_u32.to_be_bytes());
        expected.extend_from_slice(b"historical-request-data");
        let digest = Sha256::new().chain_update(PUBLIC_MUTATION_EFFECT_DIGEST_DOMAIN)
            .chain_update(&expected).finalize();
        expected.extend_from_slice(&digest);

        let retained = PublicMutationEffectV1::decode(&context.encode().unwrap()).unwrap().unwrap();
        assert_eq!(context.encode().unwrap(), expected);
        assert_eq!(retained, context);
        assert_eq!(retained.accepted_wall_seconds(), 123);
        assert!(!retained.has_retained_nix_start());
        assert!(retained.fuse_admission().is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn malformed_recognized_nix_carrier_never_falls_back_to_ordinary_effect() {
        assert!(PublicMutationEffectV1::decode(b"AOSNCA02").is_err());
        assert_eq!(PublicMutationEffectV1::decode(b"unrelated-format").unwrap(), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn public_effect_debug_keeps_original_flat_fields() {
        let context = PublicMutationEffectV1::new(
            PrincipalId::from_bytes([1; 16]),
            ProjectId::from_bytes([2; 16]),
            123,
            vec![7, 8],
        )
        .unwrap();
        let expected = format!(
            "PublicMutationEffectV1 {{ caller: {:?}, project: {:?}, accepted_wall_seconds: 123, canonical_request: [7, 8], fuse_admission: None, nix_start: None }}",
            context.caller(),
            context.project(),
        );

        assert_eq!(format!("{context:?}"), expected);
        assert!(!format!("{context:#?}").contains("plain:"));
    }

    #[test]
    fn retained_capability_effect_requires_context_and_checks_method_without_resource_uid() {
        let body = AttenuateCapabilityRequest {
            parent_capability_handle: vec![7; 32],
            attenuation: b"{}".to_vec(),
            holder_channel_binding: vec![8; 32],
            idempotency_key: vec![9],
            expected_parent_resource_version: vec![10],
            ..Default::default()
        }
        .encode_to_vec();
        let request = crate::cli_model::PublicMutationRequestV1::new(
            crate::cli_model::PublicApiAuditMethodV1::AttenuateCapability,
            &body,
        )
        .unwrap();

        let method = aos_sandbox_protocol::public_api::PublicOperationMethodV1::AttenuateCapability;
        let context = PublicMutationEffectV1::new(
            PrincipalId::from_bytes([1; 16]),
            ProjectId::from_bytes([2; 16]),
            123,
            request.encode(),
        )
        .unwrap();
        let plan = EffectPlan::authorized_public_mutation(method, context.clone()).unwrap();
        assert_eq!(plan.public_mutation_context().unwrap(), Some(context));
        let record = EffectLedgerRecord {
            plan,
            state: EffectState::Planned,
            dispatch: None,
            project_admission: None,
        };
        assert_eq!(
            decode_effect(&encode_effect(&record).unwrap()).unwrap(),
            record
        );

        assert!(matches!(
            EffectPlan::from_public_mutation_bytes(method, request.encode()),
            Err(ReconcilerError::InvalidPlan(
                "controller effect lacks authenticated admission context"
            ))
        ));
        let mut bare = record;
        bare.plan.request = request.encode();
        assert!(matches!(
            encode_effect(&bare),
            Err(ReconcilerError::InvalidPlan(
                "controller effect lacks authenticated admission context"
            ))
        ));
    }

    #[test]
    fn nix_audience_cannot_enter_or_encode_the_generic_broker_effect_path() {
        assert!(matches!(
            EffectDomain::from_audience(BrokerAudience::Nix),
            Err(ReconcilerError::InvalidPlan(
                "Nix authority cannot use the generic broker effect path"
            ))
        ));
        assert!(matches!(
            audience_code(BrokerAudience::Nix),
            Err(ReconcilerError::InvalidPlan(
                "Nix authority cannot use the generic broker effect path"
            ))
        ));

        for reserved in [0, 5, 6, u8::MAX] {
            assert!(matches!(
                audience_from_code(reserved),
                Err(ReconcilerError::CorruptLedger(
                    "unknown authority effect audience"
                ))
            ));
        }
    }

    #[test]
    fn guardian_audience_cannot_enter_the_generic_broker_effect_path() {
        let semantics = BrokerDispatchSemanticIdentityV1::new(
            BrokerVerb::GuardianArm,
            BrokerGrantTarget::Assignment,
            BrokerArgumentCommitment::for_canonical_bytes(b"guardian"),
        );

        assert!(matches!(
            AuthorityBoundEffectPlanV1::from_template(
                ObjectDigest::from_bytes([1; 32]),
                BrokerAudience::Guardian,
                BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
                ObjectDigest::from_bytes([2; 32]),
                b"guardian",
                semantics,
                true,
            ),
            Err(ReconcilerError::InvalidPlan(
                "guardian authority cannot use the generic broker effect path"
            ))
        ));

        let invalid_record = EffectLedgerRecord {
            plan: EffectPlan {
                domain: EffectDomain::Host,
                method: Some(BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME),
                controller_method: None,
                request: b"guardian".to_vec(),
                authority: Some(AuthorityEffectBindingV1 {
                    operation_id: OperationId::from_bytes([3; 16]),
                    step: 0,
                    source_draft_digest: ObjectDigest::from_bytes([1; 32]),
                    audience: BrokerAudience::Guardian,
                    method: BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
                    template_digest: ObjectDigest::from_bytes([2; 32]),
                    body_digest: ObjectDigest::from_bytes([4; 32]),
                    semantic_digest: ObjectDigest::from_bytes([5; 32]),
                    descriptor_free: true,
                    digest: ObjectDigest::from_bytes([6; 32]),
                }),
            },
            state: EffectState::Planned,
            dispatch: None,
            project_admission: None,
        };
        assert!(matches!(
            encode_effect(&invalid_record),
            Err(ReconcilerError::InvalidPlan(
                "guardian authority cannot use the generic broker effect path"
            ))
        ));

        for reserved in [0, 5] {
            assert!(matches!(
                audience_from_code(reserved),
                Err(ReconcilerError::CorruptLedger(
                    "unknown authority effect audience"
                ))
            ));
        }
    }

    #[test]
    fn generic_v1_effect_is_rejected_in_every_state() {
        let cases = [
            (
                "planned",
                vec![
                    1, 1, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, b'a', b'b', b'c',
                ],
            ),
            (
                "applying",
                vec![
                    1, 1, 2, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 3, 0, b'a', b'b', b'c', b't',
                    b'r', b'y',
                ],
            ),
            (
                "applied",
                vec![
                    1, 1, 3, 0, 3, 0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 0, 0, b'a', b'b', b'c', 9, 8,
                ],
            ),
            (
                "permanently blocked",
                vec![
                    1, 1, 4, 0, 4, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 2, 0, b'a', b'b', b'c', b'n',
                    b'o',
                ],
            ),
        ];
        for (state, bytes) in cases {
            assert!(
                matches!(
                    decode_effect(&bytes),
                    Err(ReconcilerError::CorruptLedger(
                        "invalid effect record header"
                    ))
                ),
                "{state}",
            );
        }
    }

    #[test]
    fn opaque_effect_plan_is_rejected_by_the_encoder() {
        let record = EffectLedgerRecord {
            plan: EffectPlan {
                domain: EffectDomain::Host,
                method: None,
                controller_method: None,
                request: b"abc".to_vec(),
                authority: None,
            },
            state: EffectState::Planned,
            dispatch: None,
            project_admission: None,
        };

        assert!(matches!(
            encode_effect(&record),
            Err(ReconcilerError::InvalidPlan("broker effect has no method"))
        ));
    }

    #[test]
    fn generic_v2_effect_bytes_remain_exact_in_every_state() {
        let cases = [
            (
                EffectState::Planned,
                vec![
                    2, 2, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, b'a', b'b',
                    b'c',
                ],
            ),
            (
                EffectState::Applying {
                    attempt: 2,
                    diagnostic: "try".to_owned(),
                },
                vec![
                    2, 2, 2, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 7, b'a', b'b',
                    b'c', b't', b'r', b'y',
                ],
            ),
            (
                EffectState::Applied {
                    attempt: 3,
                    receipt: EffectReceipt::new(vec![9, 8]).unwrap(),
                },
                vec![
                    2, 2, 3, 0, 3, 0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 7, b'a', b'b',
                    b'c', 9, 8,
                ],
            ),
            (
                EffectState::PermanentlyBlocked {
                    attempt: 4,
                    diagnostic: "no".to_owned(),
                },
                vec![
                    2, 2, 4, 0, 4, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 7, b'a', b'b',
                    b'c', b'n', b'o',
                ],
            ),
        ];
        for (state, expected) in cases {
            let record = EffectLedgerRecord {
                plan: EffectPlan::new(
                    EffectDomain::Storage,
                    BrokerMethod::BROKER_METHOD_STORAGE_APPLY,
                    b"abc".to_vec(),
                )
                .unwrap(),
                state,
                dispatch: None,
                project_admission: None,
            };
            assert_eq!(encode_effect(&record).unwrap(), expected);
            assert_eq!(decode_effect(&expected).unwrap(), record);
        }
    }

    #[test]
    fn generic_v2_effect_binds_the_exact_broker_method() {
        let record = EffectLedgerRecord {
            plan: EffectPlan::new(
                EffectDomain::Storage,
                BrokerMethod::BROKER_METHOD_STORAGE_APPLY,
                b"abc".to_vec(),
            )
            .unwrap(),
            state: EffectState::Planned,
            dispatch: None,
            project_admission: None,
        };
        let expected = vec![
            2, 2, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, b'a', b'b', b'c',
        ];
        assert_eq!(encode_effect(&record).unwrap(), expected);
        assert_eq!(decode_effect(&expected).unwrap(), record);

        let mut unknown_method = expected.clone();
        unknown_method[18..22].copy_from_slice(&5_i32.to_be_bytes());
        assert!(matches!(
            decode_effect(&unknown_method),
            Err(ReconcilerError::CorruptLedger(
                "unknown broker effect method"
            ))
        ));

        let mut cross_domain = expected;
        cross_domain[18..22].copy_from_slice(
            &(BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME as i32).to_be_bytes(),
        );
        assert!(matches!(
            decode_effect(&cross_domain),
            Err(ReconcilerError::CorruptLedger(
                "broker effect method/domain mismatch"
            ))
        ));
    }

    #[test]
    fn new_effect_rejects_unspecified_and_cross_domain_methods() {
        assert!(matches!(
            EffectPlan::new(
                EffectDomain::Host,
                BrokerMethod::BROKER_METHOD_UNSPECIFIED,
                b"body".to_vec(),
            ),
            Err(ReconcilerError::InvalidPlan("unknown broker effect method"))
        ));
        assert!(matches!(
            EffectPlan::new(
                EffectDomain::Storage,
                BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
                b"body".to_vec(),
            ),
            Err(ReconcilerError::InvalidPlan(
                "broker effect method crosses its fixed domain"
            ))
        ));
    }

    #[test]
    fn authority_bound_v2_effect_has_fixed_binding_and_record_digests() {
        let record = EffectLedgerRecord {
            plan: authority_bound_plan(),
            state: EffectState::Planned,
            dispatch: None,
            project_admission: None,
        };
        let binding = record.plan.authority().unwrap();
        assert_eq!(
            binding.digest.as_bytes(),
            &[
                0x93, 0xa5, 0xb9, 0xa6, 0x43, 0x87, 0xa8, 0x85, 0xf7, 0xe6, 0xd2, 0x06, 0x3e, 0x82,
                0x98, 0xaf, 0xd2, 0xbe, 0x2e, 0xf1, 0xbc, 0x51, 0x38, 0xfc, 0x29, 0x71, 0x70, 0xda,
                0xcd, 0x5a, 0xfb, 0x92,
            ]
        );

        let bytes = encode_effect(&record).unwrap();
        assert_eq!(bytes.len(), 400);
        assert_eq!(bytes[0], EFFECT_VERSION);
        assert_eq!(bytes[3], AUTHORITY_BOUND_FLAG);
        assert_eq!(decode_effect(&bytes).unwrap(), record);
        let record_digest: [u8; 32] = Sha256::digest(&bytes).into();
        assert_eq!(
            record_digest,
            [
                0x08, 0x44, 0x42, 0xef, 0x5f, 0x24, 0xfc, 0x96, 0xf3, 0xa3, 0xd4, 0x30, 0x65, 0x84,
                0x33, 0xae, 0xbb, 0x49, 0x72, 0xb3, 0x66, 0xfd, 0x2f, 0x89, 0x89, 0xfc, 0xc4, 0xf5,
                0x7a, 0xd4, 0x6c, 0xd7,
            ]
        );
    }

    #[test]
    fn authority_bound_v1_record_is_rejected_before_binding_recovery() {
        let record = EffectLedgerRecord {
            plan: authority_bound_plan(),
            state: EffectState::Planned,
            dispatch: None,
            project_admission: None,
        };
        let mut legacy = encode_effect(&record).unwrap();
        legacy[0] = 1;
        legacy.drain(18..22);

        assert!(matches!(
            decode_effect(&legacy),
            Err(ReconcilerError::CorruptLedger(
                "invalid effect record header"
            ))
        ));
    }

    #[test]
    fn effect_decoder_accepts_only_known_versions_and_closed_flags() {
        let generic = encode_effect(&EffectLedgerRecord {
            plan: EffectPlan::new(
                EffectDomain::Host,
                BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
                b"generic".to_vec(),
            )
            .unwrap(),
            state: EffectState::Planned,
            dispatch: None,
            project_admission: None,
        })
        .unwrap();
        let authority = encode_effect(&EffectLedgerRecord {
            plan: authority_bound_plan(),
            state: EffectState::Planned,
            dispatch: None,
            project_admission: None,
        })
        .unwrap();

        for version in [0, CONTROLLER_Q04_EFFECT_VERSION + 1, u8::MAX] {
            for canonical in [&generic, &authority] {
                let mut unknown_version = canonical.clone();
                unknown_version[0] = version;
                assert!(matches!(
                    decode_effect(&unknown_version),
                    Err(ReconcilerError::CorruptLedger(
                        "invalid effect record header"
                    ))
                ));
            }
        }
        for flags in [2, 3, u8::MAX] {
            for canonical in [&generic, &authority] {
                let mut unknown_flags = canonical.clone();
                unknown_flags[3] = flags;
                assert!(matches!(
                    decode_effect(&unknown_flags),
                    Err(ReconcilerError::CorruptLedger(
                        "invalid effect record header"
                    ))
                ));
            }
        }
    }

    #[test]
    fn authority_dispatch_requires_a_nonzero_preparation_host_boot() {
        const HOST_BOOT_OFFSET: usize = 373;
        const HOST_BOOT_BYTES: usize = 16;

        let plan = authority_bound_plan();
        let binding = plan.authority().unwrap();
        let dispatch = PreparedAuthorityEffectV1::from_durable_parts(
            binding.digest,
            ObjectDigest::from_bytes([7; 32]),
            10,
            20,
            [8; 16],
            BrokerDispatchAttemptV1::from_durable_parts(
                binding.template_digest,
                ObjectDigest::from_bytes([6; 32]),
                1,
                30,
                b"attempt".to_vec(),
                b"packet".to_vec(),
            ),
        );
        let record = EffectLedgerRecord {
            plan,
            state: EffectState::Applying {
                attempt: 1,
                diagnostic: String::new(),
            },
            dispatch: Some(dispatch),
            project_admission: None,
        };

        let bytes = encode_effect(&record).unwrap();
        assert_eq!(decode_effect(&bytes).unwrap(), record);

        let mut zero_boot_record = record.clone();
        zero_boot_record
            .dispatch
            .as_mut()
            .unwrap()
            .preparation_host_boot_id = [0; 16];
        assert!(matches!(
            encode_effect(&zero_boot_record),
            Err(ReconcilerError::InvalidPlan(
                "authority effect dispatch has a sentinel host boot"
            ))
        ));

        let mut zero_boot_bytes = bytes;
        zero_boot_bytes[HOST_BOOT_OFFSET..HOST_BOOT_OFFSET + HOST_BOOT_BYTES].fill(0);
        assert!(matches!(
            decode_effect(&zero_boot_bytes),
            Err(ReconcilerError::CorruptLedger(
                "invalid authority effect dispatch"
            ))
        ));
    }

    fn authority_bound_plan() -> EffectPlan {
        let operation_id = OperationId::from_bytes([3; 16]);
        let source_draft_digest = ObjectDigest::from_bytes([1; 32]);
        let template_digest = ObjectDigest::from_bytes([2; 32]);
        let body_digest = effect_body_digest(b"abc");
        let semantic_digest = ObjectDigest::from_bytes([5; 32]);
        let digest = effect_binding_digest(
            operation_id,
            7,
            source_draft_digest,
            BrokerAudience::Host,
            BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
            template_digest,
            body_digest,
            semantic_digest,
        )
        .unwrap();

        EffectPlan {
            domain: EffectDomain::Host,
            method: Some(BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME),
            controller_method: None,
            request: b"abc".to_vec(),
            authority: Some(AuthorityEffectBindingV1 {
                operation_id,
                step: 7,
                source_draft_digest,
                audience: BrokerAudience::Host,
                method: BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
                template_digest,
                body_digest,
                semantic_digest,
                descriptor_free: true,
                digest,
            }),
        }
    }
}
