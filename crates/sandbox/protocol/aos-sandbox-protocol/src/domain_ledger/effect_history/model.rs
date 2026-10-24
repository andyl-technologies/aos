//! Complete passive Effect plan, binding, state, receipt and row DATA.

use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_model::{BrokerAudience, ObjectDigest, OperationId};
use crate::domain_ledger::execution_observe_reservation::ControllerExecutionObserveReservationV1;
use super::{EffectHistoryDataError, PreparedAuthorityEffectHistoryV1, PublicMutationEffectHistoryV1};
use super::{MAXIMUM_REQUEST_BYTES, MAXIMUM_RECEIPT_BYTES};
use super::codec::validate_broker_method_domain;
use crate::domain_ledger::project_admission_metadata::ProjectAdmissionMetadataV1 as ProjectAdmissionMetadata;

/// Identifies the fixed-function domain recorded for an effect.
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
    pub(super) fn from_byte(value: u8) -> Result<Self, EffectHistoryDataError> {
        match value {
            1 => Ok(Self::Host),
            2 => Ok(Self::Storage),
            3 => Ok(Self::Mount),
            4 => Ok(Self::Network),
            5 => Ok(Self::Guardian),
            6 => Ok(Self::Guest),
            7 => Ok(Self::Controller),
            _ => Err(EffectHistoryDataError::CorruptLedger(
                "unknown effect domain",
            )),
        }
    }

    /// Selects the generic broker effect domain for a retained audience.
    ///
    /// # Errors
    ///
    /// Rejects Guardian and Nix audiences, which have separate execution paths.
    pub const fn from_audience(audience: BrokerAudience) -> Result<Self, EffectHistoryDataError> {
        match audience {
            BrokerAudience::Host => Ok(Self::Host),
            BrokerAudience::Storage => Ok(Self::Storage),
            BrokerAudience::Mount => Ok(Self::Mount),
            BrokerAudience::Network => Ok(Self::Network),
            BrokerAudience::Guardian => Err(EffectHistoryDataError::InvalidPlan(
                "guardian authority cannot use the generic broker effect path",
            )),
            BrokerAudience::Nix => Err(EffectHistoryDataError::InvalidPlan(
                "Nix authority cannot use the generic broker effect path",
            )),
        }
    }
}

/// Retains request bytes and method tags for one ordered effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectPlan {
    pub(super) domain: EffectDomain,
    pub(super) method: Option<BrokerMethod>,
    pub(super) controller_method: Option<crate::public_api::PublicOperationMethodV1>,
    pub(super) request: Vec<u8>,
    pub(super) authority: Option<AuthorityEffectBindingV1>,
}

impl EffectPlan {
    /// Retains an Observe child without a dispatch method or effect authority.
    #[must_use]
    pub fn reserved_observe(reservation: &ControllerExecutionObserveReservationV1) -> Self {
        Self {
            domain: EffectDomain::Controller,
            method: None,
            controller_method: None,
            request: reservation.encode(),
            authority: None,
        }
    }

    /// Reports whether the complete plan retains a decodable Observe reservation.
    pub fn is_reserved_observe(&self) -> bool {
        self.domain == EffectDomain::Controller
            && self.method.is_none()
            && self.controller_method.is_none()
            && self.authority.is_none()
            && self.request.get(8..24).is_some_and(|execution| {
                ControllerExecutionObserveReservationV1::decode(execution, &self.request).is_ok()
            })
    }

    /// Constructs a generic broker effect from bounded bytes and a closed method.
    ///
    /// This checks request length and method-domain identity. Consumers validate
    /// the broker body and establish Native dispatch eligibility.
    ///
    /// # Errors
    ///
    /// Returns [`EffectHistoryDataError::InvalidPlan`] for an unknown or cross-domain
    /// method, or for an empty or oversized request.
    pub fn new(
        domain: EffectDomain,
        method: BrokerMethod,
        request: Vec<u8>,
    ) -> Result<Self, EffectHistoryDataError> {
        if request.is_empty() || request.len() > MAXIMUM_REQUEST_BYTES {
            return Err(EffectHistoryDataError::InvalidPlan(
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
    /// Constructs a historical Controller plan from its retained context bytes.
    ///
    /// # Errors
    ///
    /// Rejects an empty or oversized request, malformed context, or a public method
    /// that does not match the validated request.
    pub fn from_public_mutation_bytes(
        method: crate::public_api::PublicOperationMethodV1,
        request: Vec<u8>,
    ) -> Result<Self, EffectHistoryDataError> {
        if request.is_empty() || request.len() > MAXIMUM_REQUEST_BYTES {
            return Err(EffectHistoryDataError::InvalidPlan(
                "invalid controller effect request length",
            ));
        }
        let authenticated = PublicMutationEffectHistoryV1::decode(&request)?.ok_or(
            EffectHistoryDataError::InvalidPlan(
                "controller effect lacks authenticated admission context",
            ),
        )?;
        let canonical_request = authenticated.canonical_request();
        if method == crate::public_api::PublicOperationMethodV1::OperatorRecover {
            let envelope =
                crate::public_api::mutation::PublicMutationRequestV1::decode(canonical_request)
                    .map_err(|_| {
                        EffectHistoryDataError::InvalidPlan("invalid controller effect request")
                    })?;
            let kind = envelope.decode_validated_kind().map_err(|_| {
                EffectHistoryDataError::InvalidPlan("invalid controller effect request")
            })?;
            if envelope.method()
                != crate::public_api::method::PublicApiAuditMethodV1::OperatorRecover
                || !matches!(
                    kind,
                    crate::public_api::request::DormantSandboxRequestKindV1::OperatorRecover(_)
                )
            {
                return Err(EffectHistoryDataError::InvalidPlan(
                    "controller effect method does not match its request",
                ));
            }
        } else {
            let resolved = crate::public_api::mutation::ResolvedPublicMutationRequestV1::decode(
                canonical_request,
            )
            .map_err(|_| {
                EffectHistoryDataError::InvalidPlan("invalid controller effect request")
            })?;
            if resolved.operation_method() != method {
                return Err(EffectHistoryDataError::InvalidPlan(
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
    ) -> Option<crate::public_api::PublicOperationMethodV1> {
        self.controller_method
    }

    /// Decodes recorded admission context for a Controller mutation.
    ///
    /// Controller mutations retain a context. Broker effects and reserved
    /// Observe children return `None`.
    ///
    /// # Errors
    ///
    /// Returns [`EffectHistoryDataError::InvalidPlan`] for malformed recognized
    /// context, including invalid lengths, reserved bytes, identities, time or
    /// digest. Decoding does not authenticate the recorded admission facts.
    pub fn public_mutation_context(
        &self,
    ) -> Result<Option<PublicMutationEffectHistoryV1>, EffectHistoryDataError> {
        if self.controller_method.is_none() {
            return Ok(None);
        }
        PublicMutationEffectHistoryV1::decode(&self.request)
    }

    /// Borrows the recorded effect request bytes.
    #[must_use]
    pub fn request(&self) -> &[u8] {
        &self.request
    }

    /// Borrows the retained operation and template binding, when present.
    pub fn authority(&self) -> Option<&AuthorityEffectBindingV1> {
        self.authority.as_ref()
    }
}

/// Retains the operation coordinates and template commitments attached to an effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityEffectBindingV1 {
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

/// Retains progress, diagnostic history and completion bytes for one effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectState {
    /// Records a planned effect awaiting a durable dispatch intent.
    Planned,
    /// Retains the durable intent for an attempted or ambiguous dispatch.
    Applying {
        /// Counts the retained attempt associated with this state.
        attempt: u32,
        /// Carries the last bounded UTF-8 diagnostic.
        diagnostic: String,
    },
    /// Retains an applied outcome and its exact executor receipt bytes.
    Applied {
        /// Counts the attempt associated with the retained completion.
        attempt: u32,
        /// Owns the exact completion bytes for later owner validation.
        receipt: EffectReceipt,
    },
    /// Retains an effect that cannot be retried automatically.
    PermanentlyBlocked {
        /// Counts the retained attempt associated with this state.
        attempt: u32,
        /// Carries the last bounded UTF-8 diagnostic.
        diagnostic: String,
    },
}

/// Owns a complete historical plan, state, optional dispatch and project metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectLedgerRecord {
    pub(super) plan: EffectPlan,
    pub(super) state: EffectState,
    pub(super) dispatch: Option<PreparedAuthorityEffectHistoryV1>,
    pub(super) project_admission: Option<ProjectAdmissionMetadata>,
}

/// Owns retained executor-receipt bytes for later owner validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectReceipt(Vec<u8>);

const CANCELED_BEFORE_COMMIT_RECEIPT_MAGIC: &[u8; 8] = b"AOSCXL01";
const CANCELED_BEFORE_COMMIT_RECEIPT_BYTES: usize = 40;

impl EffectReceipt {
    /// Constructs a bounded, nonempty executor receipt.
    ///
    /// # Errors
    ///
    /// Returns [`EffectHistoryDataError::InvalidExecutorOutput`] for an empty receipt
    /// or one exceeding 64 KiB.
    pub fn new(bytes: Vec<u8>) -> Result<Self, EffectHistoryDataError> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_RECEIPT_BYTES {
            return Err(EffectHistoryDataError::InvalidExecutorOutput(
                "invalid effect receipt length",
            ));
        }
        Ok(Self(bytes))
    }

    /// Returns the exact executor receipt bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Encodes a historical cancellation marker with a caller-supplied digest.
    ///
    /// This neither validates the digest nor establishes that cancellation occurred.
    #[must_use]
    pub fn canceled_before_commit(evidence: ObjectDigest) -> Self {
        let mut bytes = Vec::with_capacity(CANCELED_BEFORE_COMMIT_RECEIPT_BYTES);
        bytes.extend_from_slice(CANCELED_BEFORE_COMMIT_RECEIPT_MAGIC);
        bytes.extend_from_slice(evidence.as_bytes());
        Self(bytes)
    }

    /// Reads the recorded digest from a recognized cancellation marker.
    ///
    /// # Errors
    ///
    /// Rejects a recognized cancellation marker with the wrong length or a zero
    /// evidence digest; unrecognized receipts return None.
    pub fn canceled_before_commit_evidence(&self) -> Result<Option<ObjectDigest>, ()> {
        if !self.0.starts_with(CANCELED_BEFORE_COMMIT_RECEIPT_MAGIC) {
            return Ok(None);
        }
        if self.0.len() != CANCELED_BEFORE_COMMIT_RECEIPT_BYTES {
            return Err(());
        }

        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&self.0[CANCELED_BEFORE_COMMIT_RECEIPT_MAGIC.len()..]);
        if digest == [0; 32] {
            return Err(());
        }
        Ok(Some(ObjectDigest::from_bytes(digest)))
    }
}

impl EffectReceipt {
    /// Owns historical bytes without validating them or issuing a Native receipt.
    /// Length and content are not checked here. Encoding and Native owner
    /// validation enforce their respective contracts before accepting this history.
    #[must_use]
    pub fn from_bytes_unchecked(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl EffectPlan {
    /// Assembles complete historical DATA without validation or Native authority.
    #[must_use]
    pub fn from_parts(
        parts: (
            EffectDomain,
            Option<BrokerMethod>,
            Option<crate::public_api::PublicOperationMethodV1>,
            Vec<u8>,
            Option<AuthorityEffectBindingV1>,
        ),
    ) -> Self {
        let (domain, method, controller_method, request, authority) = parts;
        Self {
            domain,
            method,
            controller_method,
            request,
            authority,
        }
    }

    /// Consumes the complete DATA in original field and destruction order.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        EffectDomain,
        Option<BrokerMethod>,
        Option<crate::public_api::PublicOperationMethodV1>,
        Vec<u8>,
        Option<AuthorityEffectBindingV1>,
    ) {
        (
            self.domain,
            self.method,
            self.controller_method,
            self.request,
            self.authority,
        )
    }
}

impl AuthorityEffectBindingV1 {
    /// Assembles complete historical DATA without validation or Native authority.
    #[must_use]
    pub fn from_parts(
        parts: (
            OperationId,
            u32,
            ObjectDigest,
            BrokerAudience,
            BrokerMethod,
            ObjectDigest,
            ObjectDigest,
            ObjectDigest,
            bool,
            ObjectDigest,
        ),
    ) -> Self {
        let (
            operation_id,
            step,
            source_draft_digest,
            audience,
            method,
            template_digest,
            body_digest,
            semantic_digest,
            descriptor_free,
            digest,
        ) = parts;
        Self {
            operation_id,
            step,
            source_draft_digest,
            audience,
            method,
            template_digest,
            body_digest,
            semantic_digest,
            descriptor_free,
            digest,
        }
    }
}

impl AuthorityEffectBindingV1 {
    /// Returns the retained `operation_id` DATA without a currentness claim.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the retained `step` DATA without a currentness claim.
    #[must_use]
    pub const fn step(&self) -> u32 {
        self.step
    }

    /// Returns the retained `source_draft_digest` DATA without a currentness claim.
    #[must_use]
    pub const fn source_draft_digest(&self) -> ObjectDigest {
        self.source_draft_digest
    }

    /// Returns the retained `audience` DATA without a currentness claim.
    #[must_use]
    pub const fn audience(&self) -> BrokerAudience {
        self.audience
    }

    /// Returns the retained `method` DATA without a currentness claim.
    #[must_use]
    pub const fn method(&self) -> BrokerMethod {
        self.method
    }

    /// Returns the retained `template_digest` DATA without a currentness claim.
    #[must_use]
    pub const fn template_digest(&self) -> ObjectDigest {
        self.template_digest
    }

    /// Returns the retained `body_digest` DATA without a currentness claim.
    #[must_use]
    pub const fn body_digest(&self) -> ObjectDigest {
        self.body_digest
    }

    /// Returns the retained `semantic_digest` DATA without a currentness claim.
    #[must_use]
    pub const fn semantic_digest(&self) -> ObjectDigest {
        self.semantic_digest
    }

    /// Returns the retained `descriptor_free` DATA without a currentness claim.
    #[must_use]
    pub const fn descriptor_free(&self) -> bool {
        self.descriptor_free
    }

    /// Returns the retained `digest` DATA without a currentness claim.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }
}

impl EffectLedgerRecord {
    /// Assembles complete historical DATA without validation or Native authority.
    #[must_use]
    pub fn from_parts(
        parts: (
            EffectPlan,
            EffectState,
            Option<PreparedAuthorityEffectHistoryV1>,
            Option<ProjectAdmissionMetadata>,
        ),
    ) -> Self {
        let (plan, state, dispatch, project_admission) = parts;
        Self {
            plan,
            state,
            dispatch,
            project_admission,
        }
    }

    /// Consumes the complete DATA in original field and destruction order.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        EffectPlan,
        EffectState,
        Option<PreparedAuthorityEffectHistoryV1>,
        Option<ProjectAdmissionMetadata>,
    ) {
        (self.plan, self.state, self.dispatch, self.project_admission)
    }
}

impl EffectLedgerRecord {
    /// Returns the retained `plan` DATA without a currentness claim.
    #[must_use]
    pub const fn plan(&self) -> &EffectPlan {
        &self.plan
    }

    /// Returns the retained `state` DATA without a currentness claim.
    #[must_use]
    pub const fn state(&self) -> &EffectState {
        &self.state
    }

    /// Returns the retained `dispatch` DATA without a currentness claim.
    #[must_use]
    pub fn dispatch(&self) -> Option<&PreparedAuthorityEffectHistoryV1> {
        self.dispatch.as_ref()
    }

    /// Returns the retained `project_admission` DATA without a currentness claim.
    #[must_use]
    pub fn project_admission(&self) -> Option<&ProjectAdmissionMetadata> {
        self.project_admission.as_ref()
    }
}

impl EffectPlan {
    /// Fixes operation coordinates and recomputes the existing historical binding.
    /// This mutates passive DATA and cannot construct a Native authority plan.
    ///
    /// # Errors
    /// Returns the original invalid-plan cause for an unsupported broker audience.
    pub fn bind_operation(
        &mut self,
        operation_id: OperationId,
        step: u32,
    ) -> Result<(), EffectHistoryDataError> {
        if let Some(binding) = &mut self.authority {
            binding.operation_id = operation_id;
            binding.step = step;
            binding.digest = super::effect_binding_digest(
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
        Ok(())
    }
}

impl EffectLedgerRecord {
    /// Replaces only historical metadata at the caller's original assignment point.
    /// The old metadata is dropped here; other fields are not cloned or inspected.
    pub fn set_project_admission(&mut self, metadata: Option<ProjectAdmissionMetadata>) {
        self.project_admission = metadata;
    }
}

impl EffectPlan {
    /// Encodes and validates one whole context while retaining its original owned scope.
    ///
    /// # Errors
    /// Returns the original history encoding or complete method/request refusal.
    pub fn from_public_mutation_context(
        method: crate::public_api::PublicOperationMethodV1,
        context: PublicMutationEffectHistoryV1,
    ) -> Result<Self, EffectHistoryDataError> {
        Self::from_public_mutation_bytes(method, context.encode()?)
    }
}
