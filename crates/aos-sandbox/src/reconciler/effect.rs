//! Durable generic and authority-bound effect records.
//!
//! V2 records bind every dispatchable effect to one exact closed broker method.
//! The decoder retains V1 compatibility, but an opaque V1 generic effect has no
//! dispatch identity and therefore cannot be sent to a broker. Authority-bound
//! dispatches retain the Host boot identity paired with their BOOTTIME value.

use aos_proto::aos::sandbox::local::v1::{
    ApplyMountRequest, ApplyNetworkRequest, ApplyRuntimeRequest, ApplyStorageRequest, Audience,
    BrokerMethod, BrokerRequestEnvelope, QueryRuntimeEffectRequest, QueryRuntimeEffectResponse,
    RequestHeader, RuntimeEffectStatus,
};
use aos_sandbox_core::{
    BrokerAudience, ObjectDigest, OperationId, PrincipalId, ProjectId, ProtocolVersion,
    RawPairedClockSample,
};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use super::{EffectReceipt, ReconcilerError};
use crate::{BrokerDispatchAttemptV1, BrokerDispatchSemanticIdentityV1};

pub(super) const MAXIMUM_REQUEST_BYTES: usize = 1024 * 1024;
pub(super) const MAXIMUM_RECEIPT_BYTES: usize = 64 * 1024;
pub(super) const MAXIMUM_DIAGNOSTIC_BYTES: usize = 4096;
const LEGACY_EFFECT_VERSION: u8 = 1;
const EFFECT_VERSION: u8 = 2;
const CONTROLLER_EFFECT_VERSION: u8 = 3;
const AUTHORITY_BOUND_FLAG: u8 = 1;
const MAXIMUM_DISPATCH_PACKET_BYTES: usize = MAXIMUM_REQUEST_BYTES;
const BODY_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.effect-body.v1\0";
const BINDING_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.effect-binding.v1\0";
const ATTEMPT_TOKEN_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.effect-attempt-token.v1\0";
const PUBLIC_MUTATION_EFFECT_MAGIC: &[u8; 8] = b"AOSPME01";
const PUBLIC_MUTATION_EFFECT_VERSION: u16 = 1;
const PUBLIC_MUTATION_EFFECT_HEADER_BYTES: usize = 60;
const PUBLIC_MUTATION_EFFECT_DIGEST_BYTES: usize = 32;
const PUBLIC_MUTATION_EFFECT_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.public-mutation-effect.v1\0";

/// Carries authenticated admission identity with one exact public mutation.
///
/// The public envelope does not contain the mutually authenticated caller or
/// its project authority. Production lowering therefore persists those facts
/// beside the exact envelope instead of attempting to reconstruct them from a
/// target resource after admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicMutationEffectV1 {
    caller: PrincipalId,
    project: ProjectId,
    accepted_wall_seconds: i64,
    canonical_request: Vec<u8>,
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
        let encoded_length = PUBLIC_MUTATION_EFFECT_HEADER_BYTES
            .checked_add(canonical_request.len())
            .and_then(|length| length.checked_add(PUBLIC_MUTATION_EFFECT_DIGEST_BYTES));
        if caller.as_bytes() == &[0; 16]
            || project.as_bytes() == &[0; 16]
            || accepted_wall_seconds <= 0
            || canonical_request.is_empty()
            || encoded_length.is_none_or(|length| length > MAXIMUM_REQUEST_BYTES)
        {
            return Err(ReconcilerError::InvalidPlan(
                "invalid authenticated public mutation effect",
            ));
        }

        Ok(Self {
            caller,
            project,
            accepted_wall_seconds,
            canonical_request,
        })
    }

    /// Returns the authenticated caller fixed at admission.
    #[must_use]
    pub const fn caller(&self) -> PrincipalId {
        self.caller
    }

    /// Returns the authenticated project fixed at admission.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the protected admission clock in Unix seconds.
    #[must_use]
    pub const fn accepted_wall_seconds(&self) -> i64 {
        self.accepted_wall_seconds
    }

    /// Returns the exact canonical public mutation envelope.
    #[must_use]
    pub fn canonical_request(&self) -> &[u8] {
        &self.canonical_request
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
    ) -> Result<crate::cli_model::DormantSandboxRequestKindV1, ReconcilerError> {
        crate::cli_model::PublicMutationRequestV1::decode(&self.canonical_request)
            .and_then(|request| request.decode_validated_kind())
            .map_err(|_| ReconcilerError::InvalidPlan("invalid controller effect request"))
    }

    fn encode(&self) -> Result<Vec<u8>, ReconcilerError> {
        let request_length = u32::try_from(self.canonical_request.len()).map_err(|_| {
            ReconcilerError::InvalidPlan("public mutation effect request exceeds its bound")
        })?;
        let capacity = PUBLIC_MUTATION_EFFECT_HEADER_BYTES
            .checked_add(self.canonical_request.len())
            .and_then(|length| length.checked_add(PUBLIC_MUTATION_EFFECT_DIGEST_BYTES))
            .ok_or(ReconcilerError::InvalidPlan(
                "public mutation effect request exceeds its bound",
            ))?;
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(PUBLIC_MUTATION_EFFECT_MAGIC);
        bytes.extend_from_slice(&PUBLIC_MUTATION_EFFECT_VERSION.to_be_bytes());
        bytes.extend_from_slice(&[0; 6]);
        bytes.extend_from_slice(self.caller.as_bytes());
        bytes.extend_from_slice(self.project.as_bytes());
        bytes.extend_from_slice(&self.accepted_wall_seconds.to_be_bytes());
        bytes.extend_from_slice(&request_length.to_be_bytes());
        bytes.extend_from_slice(&self.canonical_request);
        let digest: [u8; 32] = Sha256::new()
            .chain_update(PUBLIC_MUTATION_EFFECT_DIGEST_DOMAIN)
            .chain_update(&bytes)
            .finalize()
            .into();
        bytes.extend_from_slice(&digest);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Option<Self>, ReconcilerError> {
        if !bytes.starts_with(PUBLIC_MUTATION_EFFECT_MAGIC) {
            return Ok(None);
        }
        if bytes.len() < PUBLIC_MUTATION_EFFECT_HEADER_BYTES + PUBLIC_MUTATION_EFFECT_DIGEST_BYTES
            || u16::from_be_bytes(
                bytes[8..10]
                    .try_into()
                    .map_err(|_| ReconcilerError::InvalidPlan("invalid public mutation effect"))?,
            ) != PUBLIC_MUTATION_EFFECT_VERSION
            || bytes[10..16] != [0; 6]
        {
            return Err(ReconcilerError::InvalidPlan(
                "invalid public mutation effect",
            ));
        }
        let caller = PrincipalId::from_bytes(
            bytes[16..32]
                .try_into()
                .map_err(|_| ReconcilerError::InvalidPlan("invalid public mutation effect"))?,
        );
        let project = ProjectId::from_bytes(
            bytes[32..48]
                .try_into()
                .map_err(|_| ReconcilerError::InvalidPlan("invalid public mutation effect"))?,
        );
        let accepted_wall_seconds = i64::from_be_bytes(
            bytes[48..56]
                .try_into()
                .map_err(|_| ReconcilerError::InvalidPlan("invalid public mutation effect"))?,
        );
        let request_length = u32::from_be_bytes(
            bytes[56..60]
                .try_into()
                .map_err(|_| ReconcilerError::InvalidPlan("invalid public mutation effect"))?,
        ) as usize;
        let request_end =
            60_usize
                .checked_add(request_length)
                .ok_or(ReconcilerError::InvalidPlan(
                    "invalid public mutation effect",
                ))?;
        let digest_end = request_end
            .checked_add(PUBLIC_MUTATION_EFFECT_DIGEST_BYTES)
            .ok_or(ReconcilerError::InvalidPlan(
                "invalid public mutation effect",
            ))?;
        if digest_end != bytes.len() {
            return Err(ReconcilerError::InvalidPlan(
                "invalid public mutation effect",
            ));
        }
        let expected: [u8; 32] = Sha256::new()
            .chain_update(PUBLIC_MUTATION_EFFECT_DIGEST_DOMAIN)
            .chain_update(&bytes[..request_end])
            .finalize()
            .into();
        if bytes[request_end..] != expected {
            return Err(ReconcilerError::InvalidPlan(
                "invalid public mutation effect",
            ));
        }

        Self::new(
            caller,
            project,
            accepted_wall_seconds,
            bytes[60..request_end].to_vec(),
        )
        .map(Some)
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
        }
    }
}

fn validate_broker_method_domain(
    domain: EffectDomain,
    method: BrokerMethod,
) -> Result<(), ReconcilerError> {
    let expected = match method {
        BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
        | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME
        | BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME
        | BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT
        | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE
        | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE
        | BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG => EffectDomain::Host,
        BrokerMethod::BROKER_METHOD_STORAGE_APPLY
        | BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
        | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
        | BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN => EffectDomain::Storage,
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY
        | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES
        | BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_CATALOG
        | BrokerMethod::BROKER_METHOD_MOUNT_APPLY_DESTINATION_SLOT
        | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS
        | BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE
        | BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION
        | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_SOURCE_ACQUISITIONS => EffectDomain::Mount,
        BrokerMethod::BROKER_METHOD_NETWORK_APPLY
        | BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY
        | BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES => EffectDomain::Network,
        _ => {
            return Err(ReconcilerError::InvalidPlan("unknown broker effect method"));
        }
    };
    if domain != expected {
        return Err(ReconcilerError::InvalidPlan(
            "broker effect method crosses its fixed domain",
        ));
    }

    Ok(())
}

const fn broker_method_from_code(value: i32) -> Option<BrokerMethod> {
    Some(match value {
        1 => BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
        2 => BrokerMethod::BROKER_METHOD_HOST_OBSERVE_RUNTIME,
        3 => BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME,
        4 => BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
        6 => BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES,
        7 => BrokerMethod::BROKER_METHOD_STORAGE_APPLY,
        9 => BrokerMethod::BROKER_METHOD_NETWORK_APPLY,
        10 => BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY,
        11 => BrokerMethod::BROKER_METHOD_HOST_QUERY_RUNTIME_EFFECT,
        12 => BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE,
        13 => BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE,
        14 => BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_CATALOG,
        15 => BrokerMethod::BROKER_METHOD_MOUNT_APPLY_DESTINATION_SLOT,
        16 => BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS,
        17 => BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG,
        18 => BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
        19 => BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES,
        20 => BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG,
        21 => BrokerMethod::BROKER_METHOD_STORAGE_REPAIR_WORKSPACE_PIN,
        22 => BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE,
        23 => BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION,
        24 => BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_SOURCE_ACQUISITIONS,
        _ => return None,
    })
}

/// Defines one ordered, idempotent request to a fixed effect boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectPlan {
    pub(super) domain: EffectDomain,
    pub(super) method: Option<BrokerMethod>,
    pub(super) controller_method: Option<crate::controller_query::PublicOperationMethodV1>,
    pub(super) request: Vec<u8>,
    pub(super) authority: Option<AuthorityEffectBindingV1>,
}

impl EffectPlan {
    /// Constructs a controller effect with authenticated admission context.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidPlan`] when the context cannot be
    /// encoded or its inner envelope does not select `method`.
    pub fn authorized_public_mutation(
        method: crate::controller_query::PublicOperationMethodV1,
        effect: PublicMutationEffectV1,
    ) -> Result<Self, ReconcilerError> {
        Self::public_mutation(method, effect.encode()?)
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

    /// Constructs a bounded controller-orchestration effect for one exact
    /// authenticated public mutation envelope.
    ///
    /// The method is stored independently from the envelope and revalidated on
    /// recovery. This keeps high-level lifecycle work out of the fixed broker
    /// method registry while preserving one closed, restart-stable dispatch
    /// identity.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcilerError::InvalidPlan`] when the envelope is malformed,
    /// names another public method, or exceeds the effect-request bound.
    pub fn public_mutation(
        method: crate::controller_query::PublicOperationMethodV1,
        request: Vec<u8>,
    ) -> Result<Self, ReconcilerError> {
        if request.is_empty() || request.len() > MAXIMUM_REQUEST_BYTES {
            return Err(ReconcilerError::InvalidPlan(
                "invalid controller effect request length",
            ));
        }
        let authenticated = PublicMutationEffectV1::decode(&request)?;
        let canonical_request = authenticated.as_ref().map_or(
            request.as_slice(),
            PublicMutationEffectV1::canonical_request,
        );
        if method == crate::controller_query::PublicOperationMethodV1::OperatorRecover {
            let envelope = crate::cli_model::PublicMutationRequestV1::decode(canonical_request)
                .map_err(|_| ReconcilerError::InvalidPlan("invalid controller effect request"))?;
            let kind = envelope
                .decode_validated_kind()
                .map_err(|_| ReconcilerError::InvalidPlan("invalid controller effect request"))?;
            if envelope.method() != crate::cli_model::PublicApiAuditMethodV1::OperatorRecover
                || !matches!(
                    kind,
                    crate::cli_model::DormantSandboxRequestKindV1::OperatorRecover(_)
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

    /// Returns the exact broker method, or `None` for an opaque legacy V1 effect.
    #[must_use]
    pub const fn method(&self) -> Option<BrokerMethod> {
        self.method
    }

    /// Returns the exact public mutation handled by controller orchestration.
    #[must_use]
    pub const fn public_mutation_method(
        &self,
    ) -> Option<crate::controller_query::PublicOperationMethodV1> {
        self.controller_method
    }

    /// Decodes authenticated admission context for a controller mutation.
    ///
    /// Legacy controller effects contain only the canonical public envelope
    /// and return `None`. New production admissions always return `Some`.
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

    pub(super) const fn clock(self) -> RawPairedClockSample {
        self.clock
    }

    pub(super) const fn deadline(self) -> u64 {
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
}

pub(super) fn encode_effect(record: &EffectLedgerRecord) -> Result<Vec<u8>, ReconcilerError> {
    let (state, attempt, receipt, diagnostic) = state_parts(&record.state);
    validate_lengths(&record.plan, receipt, diagnostic)?;
    let request_length = u32::try_from(record.plan.request.len())
        .map_err(|_| ReconcilerError::InvalidPlan("effect request exceeds bounds"))?;
    let receipt_length = u32::try_from(receipt.len())
        .map_err(|_| ReconcilerError::InvalidPlan("effect receipt exceeds bounds"))?;
    let diagnostic_length = u16::try_from(diagnostic.len())
        .map_err(|_| ReconcilerError::InvalidPlan("effect diagnostic exceeds bounds"))?;
    let dispatch_shape_valid = if record.plan.authority.is_some() {
        matches!(
            (&record.state, &record.dispatch),
            (EffectState::Planned, None)
                | (EffectState::Applying { .. }, Some(_))
                | (EffectState::Applied { .. }, Some(_))
                | (EffectState::PermanentlyBlocked { .. }, Some(_))
        )
    } else {
        record.dispatch.is_none()
    };
    if !dispatch_shape_valid {
        return Err(ReconcilerError::InvalidPlan(
            "effect dispatch does not match record variant or state",
        ));
    }
    let dispatch_body_length = record
        .dispatch
        .as_ref()
        .map_or(0, |dispatch| dispatch.attempt.body().len());
    let dispatch_packet_length = record
        .dispatch
        .as_ref()
        .map_or(0, |dispatch| dispatch.attempt.packet().len());
    if dispatch_body_length > MAXIMUM_REQUEST_BYTES
        || dispatch_packet_length > MAXIMUM_DISPATCH_PACKET_BYTES
    {
        return Err(ReconcilerError::InvalidPlan(
            "authority effect dispatch exceeds bounds",
        ));
    }
    let authority_length = if record.plan.authority.is_some() {
        375 + dispatch_body_length + dispatch_packet_length
    } else {
        0
    };
    let version = if record.plan.controller_method.is_some() {
        CONTROLLER_EFFECT_VERSION
    } else if record.plan.method.is_some() {
        EFFECT_VERSION
    } else {
        LEGACY_EFFECT_VERSION
    };
    let header_length = if version == LEGACY_EFFECT_VERSION {
        18
    } else {
        22
    };
    let mut bytes = Vec::with_capacity(
        header_length
            + authority_length
            + record.plan.request.len()
            + receipt.len()
            + diagnostic.len(),
    );
    bytes.push(version);
    bytes.push(record.plan.domain as u8);
    bytes.push(state);
    bytes.push(if record.plan.authority.is_some() {
        AUTHORITY_BOUND_FLAG
    } else {
        0
    });
    bytes.extend_from_slice(&attempt.to_le_bytes());
    bytes.extend_from_slice(&request_length.to_le_bytes());
    bytes.extend_from_slice(&receipt_length.to_le_bytes());
    bytes.extend_from_slice(&diagnostic_length.to_le_bytes());
    if version == EFFECT_VERSION {
        let method = record
            .plan
            .method
            .ok_or(ReconcilerError::InvalidPlan("broker effect has no method"))?;
        bytes.extend_from_slice(&(method as i32).to_be_bytes());
    } else if version == CONTROLLER_EFFECT_VERSION {
        let method = record
            .plan
            .controller_method
            .ok_or(ReconcilerError::InvalidPlan(
                "controller effect has no method",
            ))?;
        bytes.extend_from_slice(&i32::from(method.record_code()).to_be_bytes());
    }
    if let Some(binding) = &record.plan.authority {
        bytes.extend_from_slice(binding.operation_id.as_bytes());
        bytes.extend_from_slice(&binding.step.to_be_bytes());
        bytes.extend_from_slice(binding.source_draft_digest.as_bytes());
        bytes.push(audience_code(binding.audience)?);
        bytes.extend_from_slice(&(binding.method as i32).to_be_bytes());
        bytes.extend_from_slice(binding.template_digest.as_bytes());
        bytes.extend_from_slice(binding.body_digest.as_bytes());
        bytes.extend_from_slice(binding.semantic_digest.as_bytes());
        bytes.extend_from_slice(binding.digest.as_bytes());
        bytes.push(u8::from(binding.descriptor_free));
        bytes.push(0);
        if let Some(dispatch) = &record.dispatch {
            bytes.push(1);
            bytes.extend_from_slice(&[0; 3]);
            bytes.extend_from_slice(dispatch.binding_digest.as_bytes());
            bytes.extend_from_slice(dispatch.publication_digest.as_bytes());
            bytes.extend_from_slice(dispatch.attempt.template_digest().as_bytes());
            bytes.extend_from_slice(dispatch.attempt.lease_digest().as_bytes());
            bytes.extend_from_slice(&dispatch.attempt.lease_generation().to_be_bytes());
            bytes.extend_from_slice(
                &dispatch
                    .attempt
                    .deadline_boottime_nanoseconds()
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(&dispatch.preparation_wall_seconds.to_be_bytes());
            bytes.extend_from_slice(&dispatch.preparation_boottime_nanoseconds.to_be_bytes());
            let host_boot_id = dispatch.preparation_host_boot_id;
            if host_boot_id == [0; 16] {
                return Err(ReconcilerError::InvalidPlan(
                    "authority effect dispatch has a sentinel host boot",
                ));
            }
            bytes.extend_from_slice(&host_boot_id);
            bytes.extend_from_slice(
                &u32::try_from(dispatch_body_length)
                    .map_err(|_| ReconcilerError::InvalidPlan("dispatch body exceeds bounds"))?
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(
                &u32::try_from(dispatch_packet_length)
                    .map_err(|_| ReconcilerError::InvalidPlan("dispatch packet exceeds bounds"))?
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(dispatch.attempt.body());
            bytes.extend_from_slice(dispatch.attempt.packet());
        } else {
            bytes.extend_from_slice(&[0; 188]);
        }
    }
    bytes.extend_from_slice(&record.plan.request);
    bytes.extend_from_slice(receipt);
    bytes.extend_from_slice(diagnostic.as_bytes());
    Ok(bytes)
}

pub(super) fn decode_effect(bytes: &[u8]) -> Result<EffectLedgerRecord, ReconcilerError> {
    if bytes.len() < 18
        || !matches!(
            bytes[0],
            LEGACY_EFFECT_VERSION | EFFECT_VERSION | CONTROLLER_EFFECT_VERSION
        )
        || !matches!(bytes[3], 0 | AUTHORITY_BOUND_FLAG)
    {
        return Err(ReconcilerError::CorruptLedger(
            "invalid effect record header",
        ));
    }
    let authority_bound = bytes[3] == AUTHORITY_BOUND_FLAG;
    let domain = EffectDomain::from_byte(bytes[1])?;
    let state_code = bytes[2];
    let attempt = u32::from_le_bytes(
        bytes[4..8]
            .try_into()
            .map_err(|_| ReconcilerError::CorruptLedger("invalid effect attempt"))?,
    );
    let request_length = u32::from_le_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| ReconcilerError::CorruptLedger("invalid request length"))?,
    ) as usize;
    let receipt_length = u32::from_le_bytes(
        bytes[12..16]
            .try_into()
            .map_err(|_| ReconcilerError::CorruptLedger("invalid receipt length"))?,
    ) as usize;
    let diagnostic_length = u16::from_le_bytes(
        bytes[16..18]
            .try_into()
            .map_err(|_| ReconcilerError::CorruptLedger("invalid diagnostic length"))?,
    ) as usize;
    let mut cursor = 18;
    let method = if bytes[0] == EFFECT_VERSION {
        let method_code = i32::from_be_bytes(take_array(bytes, &mut cursor)?);
        Some(
            broker_method_from_code(method_code).ok_or(ReconcilerError::CorruptLedger(
                "unknown broker effect method",
            ))?,
        )
    } else {
        None
    };
    let controller_method = if bytes[0] == CONTROLLER_EFFECT_VERSION {
        let method_code = i32::from_be_bytes(take_array(bytes, &mut cursor)?);
        let method_code = u8::try_from(method_code)
            .map_err(|_| ReconcilerError::CorruptLedger("unknown controller effect method"))?;
        Some(
            crate::controller_query::PublicOperationMethodV1::from_record_code(method_code).ok_or(
                ReconcilerError::CorruptLedger("unknown controller effect method"),
            )?,
        )
    } else {
        None
    };
    let (authority, dispatch) = if authority_bound {
        let operation_bytes = take_array(bytes, &mut cursor)?;
        if operation_bytes == [0; 16] {
            return Err(ReconcilerError::CorruptLedger(
                "zero authority effect operation identity",
            ));
        }
        let operation_id = OperationId::from_bytes(operation_bytes);
        let step = u32::from_be_bytes(take_array(bytes, &mut cursor)?);
        let source_draft_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let audience = audience_from_code(take_array::<1>(bytes, &mut cursor)?[0])?;
        let method_code = i32::from_be_bytes(take_array(bytes, &mut cursor)?);
        let authority_method = match method_code {
            1 => BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
            4 => BrokerMethod::BROKER_METHOD_MOUNT_APPLY,
            7 => BrokerMethod::BROKER_METHOD_STORAGE_APPLY,
            9 => BrokerMethod::BROKER_METHOD_NETWORK_APPLY,
            _ => {
                return Err(ReconcilerError::CorruptLedger(
                    "unknown authority effect method",
                ));
            }
        };
        let template_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let body_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let semantic_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let descriptor_free = take_array::<1>(bytes, &mut cursor)?[0];
        let expected_domain = EffectDomain::from_audience(audience)
            .map_err(|_| ReconcilerError::CorruptLedger("invalid authority effect audience"))?;
        if take_array::<1>(bytes, &mut cursor)? != [0]
            || descriptor_free != 1
            || domain != expected_domain
            || !matches!(
                (audience, authority_method),
                (
                    BrokerAudience::Host,
                    BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
                ) | (
                    BrokerAudience::Storage,
                    BrokerMethod::BROKER_METHOD_STORAGE_APPLY
                ) | (
                    BrokerAudience::Mount,
                    BrokerMethod::BROKER_METHOD_MOUNT_APPLY
                ) | (
                    BrokerAudience::Network,
                    BrokerMethod::BROKER_METHOD_NETWORK_APPLY
                )
            )
            || method.is_some_and(|method| method != authority_method)
        {
            return Err(ReconcilerError::CorruptLedger(
                "invalid authority effect binding",
            ));
        }
        let binding = AuthorityEffectBindingV1 {
            operation_id,
            step,
            source_draft_digest,
            audience,
            method: authority_method,
            template_digest,
            body_digest,
            semantic_digest,
            descriptor_free: descriptor_free == 1,
            digest,
        };
        let dispatch_present = take_array::<1>(bytes, &mut cursor)?[0];
        if take_array::<3>(bytes, &mut cursor)? != [0; 3] {
            return Err(ReconcilerError::CorruptLedger(
                "invalid effect dispatch reserved bytes",
            ));
        }
        let dispatch_binding_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let publication_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let dispatch_template = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let lease_digest = ObjectDigest::from_bytes(take_array(bytes, &mut cursor)?);
        let lease_generation = u64::from_be_bytes(take_array(bytes, &mut cursor)?);
        let deadline = u64::from_be_bytes(take_array(bytes, &mut cursor)?);
        let clock_wall = i64::from_be_bytes(take_array(bytes, &mut cursor)?);
        let clock_boottime = u64::from_be_bytes(take_array(bytes, &mut cursor)?);
        let clock_host_boot_id = take_array(bytes, &mut cursor)?;
        let body_length = u32::from_be_bytes(take_array(bytes, &mut cursor)?) as usize;
        let packet_length = u32::from_be_bytes(take_array(bytes, &mut cursor)?) as usize;
        let dispatch = match dispatch_present {
            0 if publication_digest.as_bytes() == &[0; 32]
                && dispatch_binding_digest.as_bytes() == &[0; 32]
                && dispatch_template.as_bytes() == &[0; 32]
                && lease_digest.as_bytes() == &[0; 32]
                && lease_generation == 0
                && deadline == 0
                && clock_wall == 0
                && clock_boottime == 0
                && clock_host_boot_id == [0; 16]
                && body_length == 0
                && packet_length == 0 =>
            {
                None
            }
            1 if publication_digest.as_bytes() != &[0; 32]
                && dispatch_template == template_digest
                && lease_digest.as_bytes() != &[0; 32]
                && lease_generation != 0
                && deadline != 0
                && body_length != 0
                && body_length <= MAXIMUM_REQUEST_BYTES
                && packet_length != 0
                && packet_length <= MAXIMUM_DISPATCH_PACKET_BYTES
                && clock_host_boot_id != [0; 16] =>
            {
                let body = take_vec(bytes, &mut cursor, body_length)?;
                let packet = take_vec(bytes, &mut cursor, packet_length)?;
                Some(PreparedAuthorityEffectV1::from_durable_parts(
                    dispatch_binding_digest,
                    publication_digest,
                    clock_wall,
                    clock_boottime,
                    clock_host_boot_id,
                    BrokerDispatchAttemptV1::from_durable_parts(
                        dispatch_template,
                        lease_digest,
                        lease_generation,
                        deadline,
                        body,
                        packet,
                    ),
                ))
            }
            _ => {
                return Err(ReconcilerError::CorruptLedger(
                    "invalid authority effect dispatch",
                ));
            }
        };
        (Some(binding), dispatch)
    } else {
        (None, None)
    };
    let method = method.or_else(|| authority.as_ref().map(|binding| binding.method));
    if let Some(method) = method {
        validate_broker_method_domain(domain, method)
            .map_err(|_| ReconcilerError::CorruptLedger("broker effect method/domain mismatch"))?;
    }
    let expected = cursor
        .checked_add(request_length)
        .and_then(|n| n.checked_add(receipt_length))
        .and_then(|n| n.checked_add(diagnostic_length))
        .ok_or(ReconcilerError::CorruptLedger("effect length overflow"))?;
    if expected != bytes.len()
        || request_length == 0
        || request_length > MAXIMUM_REQUEST_BYTES
        || receipt_length > MAXIMUM_RECEIPT_BYTES
        || diagnostic_length > MAXIMUM_DIAGNOSTIC_BYTES
    {
        return Err(ReconcilerError::CorruptLedger("invalid effect lengths"));
    }
    let request_end = cursor + request_length;
    let receipt_end = request_end + receipt_length;
    let request = bytes[cursor..request_end].to_vec();
    let receipt = bytes[request_end..receipt_end].to_vec();
    let diagnostic = std::str::from_utf8(&bytes[receipt_end..])
        .map_err(|_| ReconcilerError::CorruptLedger("diagnostic is not UTF-8"))?
        .to_owned();
    if let Some(binding) = &authority
        && (binding.body_digest != effect_body_digest(&request)
            || binding.digest
                != effect_binding_digest(
                    binding.operation_id,
                    binding.step,
                    binding.source_draft_digest,
                    binding.audience,
                    binding.method,
                    binding.template_digest,
                    binding.body_digest,
                    binding.semantic_digest,
                )?)
    {
        return Err(ReconcilerError::CorruptLedger(
            "authority effect binding digest mismatch",
        ));
    }
    if let Some(method) = controller_method {
        if domain != EffectDomain::Controller || authority.is_some() {
            return Err(ReconcilerError::CorruptLedger(
                "controller effect has invalid domain or authority",
            ));
        }
        EffectPlan::public_mutation(method, request.clone()).map_err(|_| {
            ReconcilerError::CorruptLedger("controller effect method/request mismatch")
        })?;
    }
    let state = decode_state(state_code, attempt, receipt, diagnostic)?;
    let dispatch_shape_valid = if authority.is_some() {
        matches!(
            (&state, &dispatch),
            (EffectState::Planned, None)
                | (EffectState::Applying { .. }, Some(_))
                | (EffectState::Applied { .. }, Some(_))
                | (EffectState::PermanentlyBlocked { .. }, Some(_))
        )
    } else {
        dispatch.is_none()
    };
    if !dispatch_shape_valid {
        return Err(ReconcilerError::CorruptLedger(
            "effect dispatch does not match authority state",
        ));
    }
    Ok(EffectLedgerRecord {
        plan: EffectPlan {
            domain,
            method,
            controller_method,
            request,
            authority,
        },
        state,
        dispatch,
    })
}

fn state_parts(state: &EffectState) -> (u8, u32, &[u8], &str) {
    match state {
        EffectState::Planned => (1, 0, &[], ""),
        EffectState::Applying {
            attempt,
            diagnostic,
        } => (2, *attempt, &[], diagnostic),
        EffectState::Applied { attempt, receipt } => (3, *attempt, receipt.as_bytes(), ""),
        EffectState::PermanentlyBlocked {
            attempt,
            diagnostic,
        } => (4, *attempt, &[], diagnostic),
    }
}

fn validate_lengths(
    plan: &EffectPlan,
    receipt: &[u8],
    diagnostic: &str,
) -> Result<(), ReconcilerError> {
    if plan.request.is_empty()
        || plan.request.len() > MAXIMUM_REQUEST_BYTES
        || receipt.len() > MAXIMUM_RECEIPT_BYTES
        || diagnostic.len() > MAXIMUM_DIAGNOSTIC_BYTES
    {
        return Err(ReconcilerError::InvalidPlan("effect record exceeds bounds"));
    }
    if let Some(method) = plan.method {
        validate_broker_method_domain(plan.domain, method)?;
    }
    if let Some(method) = plan.controller_method {
        if plan.domain != EffectDomain::Controller || plan.method.is_some() {
            return Err(ReconcilerError::InvalidPlan(
                "controller effect has an invalid dispatch identity",
            ));
        }
        EffectPlan::public_mutation(method, plan.request.clone())?;
    } else if plan.domain == EffectDomain::Controller {
        return Err(ReconcilerError::InvalidPlan(
            "controller effect has no dispatch method",
        ));
    }
    if plan
        .authority
        .as_ref()
        .is_some_and(|binding| plan.method != Some(binding.method))
    {
        return Err(ReconcilerError::InvalidPlan(
            "authority effect method does not match its dispatch method",
        ));
    }
    if plan.authority.is_some() && plan.method.is_none() {
        return Err(ReconcilerError::InvalidPlan(
            "authority effect has no dispatch method",
        ));
    }
    Ok(())
}

fn decode_state(
    state: u8,
    attempt: u32,
    receipt: Vec<u8>,
    diagnostic: String,
) -> Result<EffectState, ReconcilerError> {
    match state {
        1 if attempt == 0 && receipt.is_empty() && diagnostic.is_empty() => {
            Ok(EffectState::Planned)
        }
        2 if attempt > 0 && receipt.is_empty() => Ok(EffectState::Applying {
            attempt,
            diagnostic,
        }),
        3 if attempt > 0 && !receipt.is_empty() && diagnostic.is_empty() => {
            Ok(EffectState::Applied {
                attempt,
                receipt: EffectReceipt(receipt),
            })
        }
        4 if attempt > 0 && receipt.is_empty() && !diagnostic.is_empty() => {
            Ok(EffectState::PermanentlyBlocked {
                attempt,
                diagnostic,
            })
        }
        _ => Err(ReconcilerError::CorruptLedger(
            "invalid effect state fields",
        )),
    }
}

fn take_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], ReconcilerError> {
    let end = cursor.checked_add(N).ok_or(ReconcilerError::CorruptLedger(
        "effect binding length overflow",
    ))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(ReconcilerError::CorruptLedger("truncated effect binding"))?;
    *cursor = end;
    value
        .try_into()
        .map_err(|_| ReconcilerError::CorruptLedger("truncated effect binding"))
}

fn take_vec(bytes: &[u8], cursor: &mut usize, length: usize) -> Result<Vec<u8>, ReconcilerError> {
    let end = cursor
        .checked_add(length)
        .ok_or(ReconcilerError::CorruptLedger(
            "effect dispatch length overflow",
        ))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(ReconcilerError::CorruptLedger("truncated effect dispatch"))?
        .to_vec();
    *cursor = end;
    Ok(value)
}

pub(super) fn effect_body_digest(body: &[u8]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(BODY_DIGEST_DOMAIN);
    digest.update(u64::try_from(body.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(body);
    ObjectDigest::from_bytes(digest.finalize().into())
}

#[allow(clippy::too_many_arguments)]
fn effect_binding_digest(
    operation_id: OperationId,
    step: u32,
    source: ObjectDigest,
    audience: BrokerAudience,
    method: BrokerMethod,
    template: ObjectDigest,
    body: ObjectDigest,
    semantics: ObjectDigest,
) -> Result<ObjectDigest, ReconcilerError> {
    let mut digest = Sha256::new();
    digest.update(BINDING_DIGEST_DOMAIN);
    digest.update(operation_id.as_bytes());
    digest.update(step.to_be_bytes());
    digest.update(source.as_bytes());
    digest.update([audience_code(audience)?]);
    digest.update((method as i32).to_be_bytes());
    digest.update(template.as_bytes());
    digest.update(body.as_bytes());
    digest.update(semantics.as_bytes());
    Ok(ObjectDigest::from_bytes(digest.finalize().into()))
}

fn attempt_token_digest(attempt: &BrokerDispatchAttemptV1) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(ATTEMPT_TOKEN_DIGEST_DOMAIN);
    digest.update(
        u64::try_from(attempt.packet().len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    digest.update(attempt.packet());
    ObjectDigest::from_bytes(digest.finalize().into())
}

const fn audience_code(audience: BrokerAudience) -> Result<u8, ReconcilerError> {
    match audience {
        BrokerAudience::Host => Ok(1),
        BrokerAudience::Mount => Ok(2),
        BrokerAudience::Storage => Ok(3),
        BrokerAudience::Network => Ok(4),
        BrokerAudience::Guardian => Err(ReconcilerError::InvalidPlan(
            "guardian authority cannot use the generic broker effect path",
        )),
    }
}

fn audience_from_code(value: u8) -> Result<BrokerAudience, ReconcilerError> {
    match value {
        1 => Ok(BrokerAudience::Host),
        2 => Ok(BrokerAudience::Mount),
        3 => Ok(BrokerAudience::Storage),
        4 => Ok(BrokerAudience::Network),
        _ => Err(ReconcilerError::CorruptLedger(
            "unknown authority effect audience",
        )),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use aos_sandbox_core::{BrokerArgumentCommitment, BrokerGrantTarget, BrokerVerb};

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
    fn generic_v1_effect_bytes_remain_exact_in_every_state() {
        let record = EffectLedgerRecord {
            plan: legacy_effect_plan(b"abc"),
            state: EffectState::Planned,
            dispatch: None,
        };
        let expected = vec![
            1, 1, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, b'a', b'b', b'c',
        ];
        assert_eq!(encode_effect(&record).unwrap(), expected);
        assert_eq!(decode_effect(&expected).unwrap(), record);

        let cases = [
            (
                EffectState::Applying {
                    attempt: 2,
                    diagnostic: "try".to_owned(),
                },
                vec![
                    1, 1, 2, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 3, 0, b'a', b'b', b'c', b't',
                    b'r', b'y',
                ],
            ),
            (
                EffectState::Applied {
                    attempt: 3,
                    receipt: EffectReceipt::new(vec![9, 8]).unwrap(),
                },
                vec![
                    1, 1, 3, 0, 3, 0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 0, 0, b'a', b'b', b'c', 9, 8,
                ],
            ),
            (
                EffectState::PermanentlyBlocked {
                    attempt: 4,
                    diagnostic: "no".to_owned(),
                },
                vec![
                    1, 1, 4, 0, 4, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 2, 0, b'a', b'b', b'c', b'n',
                    b'o',
                ],
            ),
        ];
        for (state, expected) in cases {
            let record = EffectLedgerRecord {
                plan: legacy_effect_plan(b"abc"),
                state,
                dispatch: None,
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
    fn authority_bound_v1_record_recovers_its_method_from_the_binding() {
        let record = EffectLedgerRecord {
            plan: authority_bound_plan(),
            state: EffectState::Planned,
            dispatch: None,
        };
        let mut legacy = encode_effect(&record).unwrap();
        legacy[0] = LEGACY_EFFECT_VERSION;
        legacy.drain(18..22);

        assert_eq!(decode_effect(&legacy).unwrap(), record);
        assert_eq!(
            encode_effect(&decode_effect(&legacy).unwrap()).unwrap()[0],
            2
        );
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
        })
        .unwrap();
        let authority = encode_effect(&EffectLedgerRecord {
            plan: authority_bound_plan(),
            state: EffectState::Planned,
            dispatch: None,
        })
        .unwrap();

        for version in [0, 4, u8::MAX] {
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

    fn legacy_effect_plan(request: &[u8]) -> EffectPlan {
        EffectPlan {
            domain: EffectDomain::Host,
            method: None,
            controller_method: None,
            request: request.to_vec(),
            authority: None,
        }
    }
}
