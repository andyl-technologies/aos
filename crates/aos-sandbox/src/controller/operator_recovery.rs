//! Protected operator-recovery ownership, durable replay, and bounded dispatch.
//!
//! The dormant service binds current authorization to a checked resource, while
//! the recovery owner lends the controller's sole Journal for issued, ambiguous,
//! and terminal transitions. Sealed handoffs retain the exact issued DATA; their
//! executor crossing rechecks that same durable issuance before and after I/O.
//! The private records module owns encoding and pure comparisons. Authority,
//! current-head monotonicity, and commits stay with this owner. Physical Repair
//! and Reconcile require their separate signed-receipt path.

use aos_proto::aos::sandbox::v1::OperatorRecoveryAction;
use aos_sandbox_core::{ObjectDigest, OperationId};
use sha2::{Digest as _, Sha256};

use super::{
    ActivatedOperationCompiler, DormantControllerCompositionV1, NodeController,
    RecoveryCurrentHeadV1,
};
use crate::cli_model::{
    AuthorizedOperatorRecoveryV1, InvalidObservationClientAdapter, OperatorRecoveryRequestV1,
};
use aos_sandbox_protocol::public_api::{
    CheckedOperationPhaseV1, CheckedOperationResourceV1, CheckedRetryClassV1,
    CheckedSandboxResourceV1, PublicConditionCodeV1,
};
use crate::{
    JournalRecord, JournalTransaction, OwnershipGateStatusV1, RecordNamespace,
    SingleNodeEffectExecutor,
};

mod records;

pub(super) use records::{
    decode_recovery_current, recovery_current_key, validate_recovery_current,
};

use records::{
    decode_recovery_reservation, encode_issued_recovery_reservation, encode_recovery_current,
    latest_recovery_transition, recovery_current_evidence, recovery_effect_id,
    recovery_issued_commit_id, recovery_reservation_key, recovery_terminal_commit_id,
    recovery_terminal_records, recovery_transition_key, requires_physical_recovery_receipt,
    validate_recovery_replay, validate_recovery_reservation_key, validate_recovery_terminal,
};

/// Borrows the controller's protected journal for a dormant recovery transition.
///
/// This owner registers no route. It owns the protected current-head,
/// idempotency, and canonical transition records. Effect dispatch requires a
/// durably issued handoff and the explicitly supplied recovery executor.
pub(crate) struct DormantOperatorRecoveryOwnerV1<'controller> {
    journal: &'controller mut crate::Journal,
}

/// Carries one checked operator-recovery current head for atomic admission.
pub(crate) struct PreparedOperatorRecoveryCurrentV1 {
    record: JournalRecord,
    already_current: bool,
}

impl PreparedOperatorRecoveryCurrentV1 {
    /// Checks the request fence and action against these exact prepared bytes.
    pub(crate) fn validates_request(&self, request: &OperatorRecoveryRequestV1) -> bool {
        self.record
            .value()
            .is_some_and(|current| validate_recovery_current(request, current).is_ok())
    }

    /// Consumes the preparation into its atomic journal record.
    pub(crate) fn into_record(self) -> JournalRecord {
        self.record
    }

    fn is_already_current(&self) -> bool {
        self.already_current
    }
}

/// Maximum dispatch attempts retained for one operator-recovery effect.
pub const MAXIMUM_OPERATOR_RECOVERY_EFFECT_ATTEMPTS_V1: u32 = 3;
/// Maximum consecutive unknown observer classifications retained before escalation.
pub const MAXIMUM_OPERATOR_RECOVERY_AMBIGUITY_QUERIES_V1: u32 = 3;
/// Maximum nonterminal operator-recovery rows returned by one startup scan.
pub const MAXIMUM_PENDING_OPERATOR_RECOVERIES_V1: usize = 4_096;

/// Reports durable admission, restart recovery, ambiguity, or exact terminal replay.
pub(crate) enum DormantOperatorRecoveryAdmissionV1 {
    /// A durable issued effect must be handed to the recovery executor.
    Issued(DormantOperatorRecoveryEffectHandoffV1),
    /// A previously issued effect must be observed before any redispatch.
    RecoveryRequired(DormantOperatorRecoveryPendingV1),
    /// Observation remains ambiguous and no redispatch is permitted.
    Ambiguous(DormantOperatorRecoveryPendingV1),
    /// The bounded observer ambiguity budget is exhausted without classification.
    AmbiguityExhausted(DormantOperatorRecoveryPendingV1),
    /// Absence was proven, but the bounded dispatch-attempt budget is exhausted.
    DispatchBudgetExhausted(DormantOperatorRecoveryPendingV1),
    /// The same authorized request already reached a durable terminal result.
    Terminal(aos_proto::aos::sandbox::v1::OperatorRecoveryResult),
    /// A terminal observation is retained while its atomic journal commit is ambiguous.
    TerminalCommitAmbiguous(DormantOperatorRecoveryTerminalV1),
}

/// Seals one durably issued recovery effect for a future typed executor.
#[must_use = "an issued operator-recovery effect must reach a terminal observation"]
pub(crate) struct DormantOperatorRecoveryEffectHandoffV1 {
    issued: DormantOperatorRecoveryIssuedStateV1,
    reservation_key: Vec<u8>,
}

/// Seals a checked executor terminal observation before durable reduction.
#[must_use = "a checked operator-recovery terminal must be durably recorded"]
pub(crate) struct DormantOperatorRecoveryTerminalV1 {
    handoff: DormantOperatorRecoveryEffectHandoffV1,
    result: aos_proto::aos::sandbox::v1::OperatorRecoveryResult,
}

/// Retains either a durable terminal result or exact custody after commit ambiguity.
pub(crate) enum DormantOperatorRecoveryTerminalCommitV1 {
    /// The terminal result and successor current head are durably committed.
    Complete(aos_proto::aos::sandbox::v1::OperatorRecoveryResult),
    /// Commit outcome is uncertain; the terminal token must be retried, never redispatched.
    Ambiguous(DormantOperatorRecoveryTerminalV1),
}

/// Retains a restart-enumerated issued effect without granting redispatch authority.
#[must_use = "a pending recovery must be classified through its effect observer"]
pub(crate) struct DormantOperatorRecoveryPendingV1 {
    issued: DormantOperatorRecoveryIssuedStateV1,
    reservation_key: Vec<u8>,
}

/// Carries the exact issued identity to an injected effect observer.
pub(crate) struct DormantOperatorRecoveryEffectQueryV1 {
    effect_id: ObjectDigest,
    attempt: u32,
    current_generation: u64,
    request: aos_proto::aos::sandbox::v1::OperatorRecoveryRequest,
}

impl DormantOperatorRecoveryEffectQueryV1 {
    /// Returns the stable durable effect identity.
    #[must_use]
    pub const fn effect_id(&self) -> ObjectDigest {
        self.effect_id
    }

    /// Returns the exact one-based dispatch attempt under observation.
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Returns the exact desired generation retained at initial issuance.
    #[must_use]
    pub const fn current_generation(&self) -> u64 {
        self.current_generation
    }

    /// Returns the canonical request retained before the first dispatch.
    #[must_use]
    pub const fn request(&self) -> &aos_proto::aos::sandbox::v1::OperatorRecoveryRequest {
        &self.request
    }
}

/// Classifies one exact issued effect from an authoritative receipt/inventory query.
pub(crate) enum DormantOperatorRecoveryEffectDispositionV1 {
    /// A terminal executor result is authoritatively retained.
    Terminal(aos_proto::aos::sandbox::v1::OperatorRecoveryResult),
    /// The observer proves this exact attempt did not apply an effect.
    NotObserved,
    /// The observer cannot distinguish absent, in-flight, or completed state.
    Unknown,
}

/// Seals an observer classification to the queried effect and attempt.
pub(crate) struct DormantOperatorRecoveryEffectReceiptV1 {
    effect_id: ObjectDigest,
    attempt: u32,
    current_generation: u64,
    disposition: DormantOperatorRecoveryEffectDispositionV1,
}

impl DormantOperatorRecoveryEffectReceiptV1 {
    /// Constructs a receipt proving an exact attempt did not apply an effect.
    #[must_use]
    pub(crate) const fn not_observed(query: &DormantOperatorRecoveryEffectQueryV1) -> Self {
        Self {
            effect_id: query.effect_id,
            attempt: query.attempt,
            current_generation: query.current_generation,
            disposition: DormantOperatorRecoveryEffectDispositionV1::NotObserved,
        }
    }

    /// Constructs a receipt retaining an authoritative terminal result.
    #[must_use]
    pub(crate) fn terminal(
        query: &DormantOperatorRecoveryEffectQueryV1,
        result: aos_proto::aos::sandbox::v1::OperatorRecoveryResult,
    ) -> Self {
        Self {
            effect_id: query.effect_id,
            attempt: query.attempt,
            current_generation: query.current_generation,
            disposition: DormantOperatorRecoveryEffectDispositionV1::Terminal(result),
        }
    }

    /// Constructs an explicitly unknown classification that never permits redispatch.
    #[must_use]
    pub(crate) const fn unknown(query: &DormantOperatorRecoveryEffectQueryV1) -> Self {
        Self {
            effect_id: query.effect_id,
            attempt: query.attempt,
            current_generation: query.current_generation,
            disposition: DormantOperatorRecoveryEffectDispositionV1::Unknown,
        }
    }
}

/// Queries authoritative effect receipts or independently enumerated effect inventory.
pub(crate) trait DormantOperatorRecoveryEffectObserverV1 {
    /// Classifies exactly one durable issued attempt without performing it.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationClientAdapter`] when the observer cannot
    /// authenticate or bound its response.
    fn classify(
        &mut self,
        query: &DormantOperatorRecoveryEffectQueryV1,
    ) -> Result<DormantOperatorRecoveryEffectReceiptV1, InvalidObservationClientAdapter>;
}

/// Performs one checked recovery effect while the protected journal is exclusively borrowed.
pub(crate) trait DormantOperatorRecoveryEffectExecutorV1 {
    /// Executes the exact durably issued attempt and returns its terminal observation.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationClientAdapter`] when dispatch or its authenticated
    /// terminal observation cannot be completed.
    fn execute(
        &mut self,
        query: &DormantOperatorRecoveryEffectQueryV1,
    ) -> Result<aos_proto::aos::sandbox::v1::OperatorRecoveryResult, InvalidObservationClientAdapter>;
}

/// Reports a rejected dormant public operator-recovery service request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DormantOperatorRecoveryServiceErrorV1 {
    /// The public request or authorization binding is malformed.
    #[error("dormant operator-recovery request is invalid")]
    InvalidRequest,
    /// The explicitly injected authorizer rejected the public context.
    #[error("dormant operator-recovery authorization was rejected")]
    AuthorizationRejected,
    /// Protected durable recovery state rejected the transition.
    #[error("dormant operator-recovery state rejected the transition")]
    RecoveryState,
}

/// Carries the principal and exact request binding proven by an injected authorizer.
pub(crate) struct DormantOperatorRecoveryPublicAuthorizationV1 {
    principal: ObjectDigest,
    request_binding: ObjectDigest,
}

impl DormantOperatorRecoveryPublicAuthorizationV1 {
    /// Constructs a decision bound to one already checked recovery request.
    ///
    /// # Errors
    ///
    /// Returns [`DormantOperatorRecoveryServiceErrorV1::InvalidRequest`] for a
    /// zero principal.
    pub(crate) fn for_request(
        principal: ObjectDigest,
        request: &OperatorRecoveryRequestV1,
    ) -> Result<Self, DormantOperatorRecoveryServiceErrorV1> {
        Self::new(principal, request.authority_binding())
    }

    /// Constructs an explicit public-service authorization decision.
    ///
    /// This constructor is for an injected authenticated transport authorizer;
    /// the dormant service independently checks the request binding before it
    /// reaches protected durable state.
    ///
    /// # Errors
    ///
    /// Returns [`DormantOperatorRecoveryServiceErrorV1::InvalidRequest`] for a
    /// zero principal or request commitment.
    pub(crate) fn new(
        principal: ObjectDigest,
        request_binding: ObjectDigest,
    ) -> Result<Self, DormantOperatorRecoveryServiceErrorV1> {
        if principal.as_bytes() == &[0; 32] || request_binding.as_bytes() == &[0; 32] {
            Err(DormantOperatorRecoveryServiceErrorV1::InvalidRequest)
        } else {
            Ok(Self {
                principal,
                request_binding,
            })
        }
    }
}

/// Authorizes one exact public recovery request from opaque transport context.
pub(crate) trait DormantOperatorRecoveryPublicAuthorizerV1 {
    /// Consumes the opaque context and returns its proven principal/request binding.
    ///
    /// # Errors
    ///
    /// Returns [`DormantOperatorRecoveryServiceErrorV1::AuthorizationRejected`]
    /// when authentication, authorization, or current policy rejects the request.
    fn authorize(
        &mut self,
        authorization: aos_sandbox_protocol::public_api::request::DormantPublicApiAuthorizationV1,
        request: &aos_proto::aos::sandbox::v1::OperatorRecoveryRequest,
    ) -> Result<DormantOperatorRecoveryPublicAuthorizationV1, DormantOperatorRecoveryServiceErrorV1>;
}

/// Binds a current-state observation to an authorized recovery request.
pub(crate) struct DormantOperatorRecoveryCurrentQueryV1 {
    principal: ObjectDigest,
    request_binding: ObjectDigest,
    request: aos_proto::aos::sandbox::v1::OperatorRecoveryRequest,
}

impl DormantOperatorRecoveryCurrentQueryV1 {
    /// Returns the authenticated principal commitment.
    #[must_use]
    pub const fn principal(&self) -> ObjectDigest {
        self.principal
    }

    /// Returns the exact authorized request commitment.
    #[must_use]
    pub const fn request_binding(&self) -> ObjectDigest {
        self.request_binding
    }

    /// Returns the exact public request requiring a current observation.
    #[must_use]
    pub const fn request(&self) -> &aos_proto::aos::sandbox::v1::OperatorRecoveryRequest {
        &self.request
    }
}

enum DormantOperatorRecoveryCurrentResourceV1 {
    Sandbox(CheckedSandboxResourceV1),
    Operation(CheckedOperationResourceV1),
}

/// Seals a fully checked current resource to its authorized observation query.
pub(crate) struct DormantOperatorRecoveryCurrentObservationV1 {
    principal: ObjectDigest,
    request_binding: ObjectDigest,
    resource: DormantOperatorRecoveryCurrentResourceV1,
}

impl DormantOperatorRecoveryCurrentObservationV1 {
    /// Constructs an exact checked sandbox observation receipt.
    #[must_use]
    pub(crate) fn sandbox(
        query: &DormantOperatorRecoveryCurrentQueryV1,
        resource: CheckedSandboxResourceV1,
    ) -> Self {
        Self {
            principal: query.principal,
            request_binding: query.request_binding,
            resource: DormantOperatorRecoveryCurrentResourceV1::Sandbox(resource),
        }
    }

    /// Constructs an exact checked operation observation receipt.
    #[must_use]
    pub(crate) fn operation(
        query: &DormantOperatorRecoveryCurrentQueryV1,
        resource: CheckedOperationResourceV1,
    ) -> Self {
        Self {
            principal: query.principal,
            request_binding: query.request_binding,
            resource: DormantOperatorRecoveryCurrentResourceV1::Operation(resource),
        }
    }
}

/// Obtains current public state through an explicitly injected authorized adapter.
pub(crate) trait DormantOperatorRecoveryCurrentObserverV1 {
    /// Returns one checked current sandbox or operation observation.
    ///
    /// # Errors
    ///
    /// Returns [`DormantOperatorRecoveryServiceErrorV1::RecoveryState`] when a
    /// current authenticated observation cannot be obtained or bounded.
    fn observe_current(
        &mut self,
        query: &DormantOperatorRecoveryCurrentQueryV1,
    ) -> Result<DormantOperatorRecoveryCurrentObservationV1, DormantOperatorRecoveryServiceErrorV1>;
}

/// Retains authorization only after current state is durably synchronized.
#[must_use = "synchronized recovery authority must be consumed by begin"]
pub(crate) struct DormantOperatorRecoverySynchronizedV1 {
    principal: ObjectDigest,
    request: OperatorRecoveryRequestV1,
}

/// Composes a callable dormant public recovery handler without route registration.
pub(crate) struct DormantOperatorRecoveryPublicServiceV1<'controller, C, E, A, S, O> {
    controller: &'controller mut NodeController<C, E>,
    authorizer: A,
    current_observer: S,
    effect_observer: O,
}

impl<'controller, C, E, A, S, O> DormantOperatorRecoveryPublicServiceV1<'controller, C, E, A, S, O>
where
    C: ActivatedOperationCompiler,
    E: SingleNodeEffectExecutor,
    A: DormantOperatorRecoveryPublicAuthorizerV1,
    S: DormantOperatorRecoveryCurrentObserverV1,
    O: DormantOperatorRecoveryEffectObserverV1,
{
    /// Constructs a callable handler around explicit dependencies.
    #[must_use]
    pub(crate) const fn new(
        controller: &'controller mut NodeController<C, E>,
        authorizer: A,
        current_observer: S,
        effect_observer: O,
    ) -> Self {
        Self {
            controller,
            authorizer,
            current_observer,
            effect_observer,
        }
    }

    /// Authorizes and durably begins or exactly replays one public request.
    ///
    /// # Errors
    ///
    /// Returns [`DormantOperatorRecoveryServiceErrorV1`] when request parsing,
    /// authorization, exact binding, or protected durable admission fails.
    pub(crate) fn begin(
        &mut self,
        authorization: aos_sandbox_protocol::public_api::request::DormantPublicApiAuthorizationV1,
        request: aos_proto::aos::sandbox::v1::OperatorRecoveryRequest,
    ) -> Result<DormantOperatorRecoveryAdmissionV1, DormantOperatorRecoveryServiceErrorV1> {
        let synchronized = self.synchronize_current(authorization, request)?;
        self.begin_synchronized(synchronized)
    }

    /// Authorizes, observes, and durably synchronizes current public state.
    ///
    /// No recovery effect can be issued by this method. The returned sealed
    /// authority is the only public-service input accepted by
    /// [`Self::begin_synchronized`].
    ///
    /// # Errors
    ///
    /// Returns [`DormantOperatorRecoveryServiceErrorV1`] when request parsing,
    /// authorization, observation binding, or durable synchronization fails.
    pub(crate) fn synchronize_current(
        &mut self,
        authorization: aos_sandbox_protocol::public_api::request::DormantPublicApiAuthorizationV1,
        request: aos_proto::aos::sandbox::v1::OperatorRecoveryRequest,
    ) -> Result<DormantOperatorRecoverySynchronizedV1, DormantOperatorRecoveryServiceErrorV1> {
        let checked = OperatorRecoveryRequestV1::try_from(request.clone())
            .map_err(|_| DormantOperatorRecoveryServiceErrorV1::InvalidRequest)?;
        if requires_physical_recovery_receipt(checked.action()) {
            return Err(DormantOperatorRecoveryServiceErrorV1::RecoveryState);
        }
        let authorized = self.authorizer.authorize(authorization, &request)?;
        if authorized.request_binding != checked.authority_binding() {
            return Err(DormantOperatorRecoveryServiceErrorV1::AuthorizationRejected);
        }
        let query = DormantOperatorRecoveryCurrentQueryV1 {
            principal: authorized.principal,
            request_binding: authorized.request_binding,
            request,
        };
        let observation = self.current_observer.observe_current(&query)?;
        if observation.principal != query.principal
            || observation.request_binding != query.request_binding
        {
            return Err(DormantOperatorRecoveryServiceErrorV1::RecoveryState);
        }
        let mut owner = self.controller.dormant_operator_recovery();
        match observation.resource {
            DormantOperatorRecoveryCurrentResourceV1::Sandbox(resource)
                if resource.sandbox_id() == checked.resource_id()
                    && resource.as_proto().resource_version.as_slice()
                        == checked.expected_resource_version() =>
            {
                owner.synchronize_sandbox(&resource)
            }
            DormantOperatorRecoveryCurrentResourceV1::Operation(resource)
                if resource.operation_id() == checked.resource_id()
                    && resource.resource_version().as_bytes()
                        == checked.expected_resource_version() =>
            {
                owner.synchronize_operation(&resource)
            }
            DormantOperatorRecoveryCurrentResourceV1::Sandbox(_)
            | DormantOperatorRecoveryCurrentResourceV1::Operation(_) => {
                return Err(DormantOperatorRecoveryServiceErrorV1::RecoveryState);
            }
        }
        .map_err(|_| DormantOperatorRecoveryServiceErrorV1::RecoveryState)?;
        let synchronized_evidence = owner
            .current_evidence(checked.resource_id())
            .map_err(|_| DormantOperatorRecoveryServiceErrorV1::RecoveryState)?;
        if &synchronized_evidence != checked.evidence() {
            return Err(DormantOperatorRecoveryServiceErrorV1::RecoveryState);
        }
        Ok(DormantOperatorRecoverySynchronizedV1 {
            principal: authorized.principal,
            request: checked,
        })
    }

    /// Durably begins a recovery only after authorized current synchronization.
    ///
    /// # Errors
    ///
    /// Returns [`DormantOperatorRecoveryServiceErrorV1::RecoveryState`] when
    /// protected current state no longer admits the synchronized request.
    pub(crate) fn begin_synchronized(
        &mut self,
        synchronized: DormantOperatorRecoverySynchronizedV1,
    ) -> Result<DormantOperatorRecoveryAdmissionV1, DormantOperatorRecoveryServiceErrorV1> {
        self.controller
            .dormant_operator_recovery()
            .begin_public_authorized(synchronized.principal, synchronized.request)
            .map_err(|_| DormantOperatorRecoveryServiceErrorV1::RecoveryState)
    }

    /// Enumerates all durable nonterminal recoveries at a startup boundary.
    ///
    /// # Errors
    ///
    /// Returns [`DormantOperatorRecoveryServiceErrorV1::RecoveryState`] when
    /// protected provenance or a durable recovery record is invalid.
    pub(crate) fn pending_recoveries(
        &mut self,
    ) -> Result<Vec<DormantOperatorRecoveryPendingV1>, DormantOperatorRecoveryServiceErrorV1> {
        self.controller
            .dormant_operator_recovery()
            .pending_recoveries()
            .map_err(|_| DormantOperatorRecoveryServiceErrorV1::RecoveryState)
    }

    /// Reconciles one startup-enumerated effect through the injected observer.
    ///
    /// # Errors
    ///
    /// Returns [`DormantOperatorRecoveryServiceErrorV1::RecoveryState`] when
    /// retained state or the authoritative observer receipt is invalid.
    pub(crate) fn reconcile(
        &mut self,
        pending: DormantOperatorRecoveryPendingV1,
    ) -> Result<DormantOperatorRecoveryAdmissionV1, DormantOperatorRecoveryServiceErrorV1> {
        self.controller
            .dormant_operator_recovery()
            .recover_pending(pending, &mut self.effect_observer)
            .map_err(|_| DormantOperatorRecoveryServiceErrorV1::RecoveryState)
    }

    /// Dispatches one sealed issuance under an exclusive protected-current borrow.
    pub(crate) fn dispatch<X>(
        &mut self,
        handoff: DormantOperatorRecoveryEffectHandoffV1,
        executor: &mut X,
    ) -> Result<DormantOperatorRecoveryAdmissionV1, DormantOperatorRecoveryServiceErrorV1>
    where
        X: DormantOperatorRecoveryEffectExecutorV1,
    {
        self.controller
            .dormant_operator_recovery()
            .dispatch_effect(handoff, executor)
            .map_err(|_| DormantOperatorRecoveryServiceErrorV1::RecoveryState)
    }

    /// Durably reduces one checked executor terminal returned by an issued handoff.
    ///
    /// # Errors
    ///
    /// Returns [`DormantOperatorRecoveryServiceErrorV1::RecoveryState`] when
    /// the issued record, current head, or terminal result no longer matches.
    pub(crate) fn record_terminal(
        &mut self,
        terminal: DormantOperatorRecoveryTerminalV1,
    ) -> Result<DormantOperatorRecoveryTerminalCommitV1, DormantOperatorRecoveryServiceErrorV1>
    {
        self.controller
            .dormant_operator_recovery()
            .record_terminal(terminal)
            .map_err(|_| DormantOperatorRecoveryServiceErrorV1::RecoveryState)
    }

    /// Dismantles the dormant service into its explicit dependencies.
    #[must_use]
    pub(crate) fn into_parts(self) -> (&'controller mut NodeController<C, E>, A, S, O) {
        (
            self.controller,
            self.authorizer,
            self.current_observer,
            self.effect_observer,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DormantOperatorRecoveryIssuedStateV1 {
    principal: ObjectDigest,
    binding: ObjectDigest,
    effect_id: ObjectDigest,
    request: OperatorRecoveryRequestV1,
    current: Vec<u8>,
    current_generation: u64,
    attempt: u32,
    ambiguity_queries: u32,
    recovery_state: DormantOperatorRecoveryDurableStateV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DormantOperatorRecoveryDurableStateV1 {
    InitialIssue,
    ReissuedAfterAbsence,
    ObservationUnknown,
}

impl DormantOperatorRecoveryDurableStateV1 {
    const fn to_wire(self) -> u32 {
        match self {
            Self::InitialIssue => 1,
            Self::ReissuedAfterAbsence => 2,
            Self::ObservationUnknown => 3,
        }
    }

    const fn from_wire(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::InitialIssue),
            2 => Some(Self::ReissuedAfterAbsence),
            3 => Some(Self::ObservationUnknown),
            _ => None,
        }
    }
}

impl DormantOperatorRecoveryEffectHandoffV1 {
    /// Returns the stable effect identity committed by durable issuance.
    #[must_use]
    pub const fn effect_id(&self) -> ObjectDigest {
        self.issued.effect_id
    }

    /// Returns the exact one-based dispatch attempt.
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.issued.attempt
    }

    /// Returns the desired generation retained before effect issuance.
    #[must_use]
    pub const fn current_generation(&self) -> u64 {
        self.issued.current_generation
    }

    fn check_terminal(
        self,
        result: aos_proto::aos::sandbox::v1::OperatorRecoveryResult,
    ) -> Result<DormantOperatorRecoveryTerminalV1, InvalidObservationClientAdapter> {
        validate_recovery_terminal(&self.issued.request, &result)?;
        Ok(DormantOperatorRecoveryTerminalV1 {
            handoff: self,
            result,
        })
    }
}

impl DormantOperatorRecoveryPendingV1 {
    /// Returns the stable effect identity that must be observed.
    #[must_use]
    pub const fn effect_id(&self) -> ObjectDigest {
        self.issued.effect_id
    }

    /// Returns the last durably issued attempt.
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.issued.attempt
    }

    /// Returns the number of consecutive durable unknown classifications.
    #[must_use]
    pub const fn ambiguity_queries(&self) -> u32 {
        self.issued.ambiguity_queries
    }

    /// Returns the desired generation retained with the original current head.
    #[must_use]
    pub const fn current_generation(&self) -> u64 {
        self.issued.current_generation
    }

    /// Returns the canonical request retained before the first dispatch.
    #[must_use]
    pub fn request(&self) -> aos_proto::aos::sandbox::v1::OperatorRecoveryRequest {
        self.issued.request.to_proto()
    }
}

impl DormantOperatorRecoveryOwnerV1<'_> {
    /// Executes one sealed attempt only while its durable issuance and current head are exact.
    pub(crate) fn dispatch_effect<X>(
        &mut self,
        handoff: DormantOperatorRecoveryEffectHandoffV1,
        executor: &mut X,
    ) -> Result<DormantOperatorRecoveryAdmissionV1, InvalidObservationClientAdapter>
    where
        X: DormantOperatorRecoveryEffectExecutorV1,
    {
        self.recheck_effect_handoff(&handoff)?;
        if requires_physical_recovery_receipt(handoff.issued.request.action()) {
            return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
        }
        let query = DormantOperatorRecoveryEffectQueryV1 {
            effect_id: handoff.issued.effect_id,
            attempt: handoff.issued.attempt,
            current_generation: handoff.issued.current_generation,
            request: handoff.issued.request.to_proto(),
        };
        let result = executor.execute(&query)?;
        self.recheck_effect_handoff(&handoff)?;
        let terminal = handoff.check_terminal(result)?;
        match self.record_terminal(terminal)? {
            DormantOperatorRecoveryTerminalCommitV1::Complete(result) => {
                Ok(DormantOperatorRecoveryAdmissionV1::Terminal(result))
            }
            DormantOperatorRecoveryTerminalCommitV1::Ambiguous(terminal) => Ok(
                DormantOperatorRecoveryAdmissionV1::TerminalCommitAmbiguous(terminal),
            ),
        }
    }

    fn recheck_effect_handoff(
        &self,
        handoff: &DormantOperatorRecoveryEffectHandoffV1,
    ) -> Result<(), InvalidObservationClientAdapter> {
        self.journal
            .ensure_protected_authority()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
        let retained = self
            .journal
            .get(RecordNamespace::OperatorRecovery, &handoff.reservation_key)
            .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
        let DormantOperatorRecoveryReservationV1::Issued(retained) =
            decode_recovery_reservation(retained)?
        else {
            return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
        };
        let current = self
            .journal
            .get(
                RecordNamespace::OperatorRecovery,
                &recovery_current_key(retained.request.resource_id()),
            )
            .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
        if retained != handoff.issued || current != retained.current {
            return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
        }
        validate_recovery_reservation_key(&retained, &handoff.reservation_key)?;
        validate_recovery_current(&retained.request, current)
    }

    /// Returns sealed evidence for the protected current head of one resource.
    pub(crate) fn current_evidence(
        &self,
        resource_id: [u8; 16],
    ) -> Result<aos_proto::aos::sandbox::v1::ObjectDescriptor, InvalidObservationClientAdapter>
    {
        self.journal
            .ensure_protected_authority()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
        let current = self
            .journal
            .get(
                RecordNamespace::OperatorRecovery,
                &recovery_current_key(resource_id),
            )
            .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
        Ok(recovery_current_evidence(resource_id, current))
    }

    /// Reserves a transition after checking protected journal provenance.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationClientAdapter`] when protected provenance is absent.
    pub(crate) fn begin(
        &mut self,
        authorized: AuthorizedOperatorRecoveryV1,
    ) -> Result<DormantOperatorRecoveryAdmissionV1, InvalidObservationClientAdapter> {
        let (request, provenance) = authorized.into_parts();
        self.begin_with_authority(provenance.commitments().0.digest(), request)
    }

    fn begin_public_authorized(
        &mut self,
        principal: ObjectDigest,
        request: OperatorRecoveryRequestV1,
    ) -> Result<DormantOperatorRecoveryAdmissionV1, InvalidObservationClientAdapter> {
        self.begin_with_authority(principal, request)
    }

    fn begin_with_authority(
        &mut self,
        principal: ObjectDigest,
        request: OperatorRecoveryRequestV1,
    ) -> Result<DormantOperatorRecoveryAdmissionV1, InvalidObservationClientAdapter> {
        self.journal
            .ensure_protected_authority()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
        if principal.as_bytes() == &[0; 32] {
            return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
        }
        // A generic result cannot prove a physical Reconcile or Repair.
        // Do not reserve an effect until a dedicated owner verifies the signed
        // intent and returns a protected post-effect inventory receipt.
        if requires_physical_recovery_receipt(request.action()) {
            return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
        }
        let reservation_key =
            recovery_reservation_key(principal.as_bytes(), request.idempotency_key());
        let binding = request.authority_binding();
        let effect_id = recovery_effect_id(principal, &request);
        if let Some(existing) = self
            .journal
            .get(RecordNamespace::OperatorRecovery, &reservation_key)
            .map(<[u8]>::to_vec)
        {
            return match decode_recovery_reservation(&existing)? {
                DormantOperatorRecoveryReservationV1::Issued(issued) => {
                    validate_recovery_replay(
                        &issued,
                        principal,
                        binding,
                        effect_id,
                        &request,
                        &reservation_key,
                    )?;
                    let pending = DormantOperatorRecoveryPendingV1 {
                        issued,
                        reservation_key,
                    };
                    if pending.issued.ambiguity_queries
                        == MAXIMUM_OPERATOR_RECOVERY_AMBIGUITY_QUERIES_V1
                    {
                        Ok(DormantOperatorRecoveryAdmissionV1::AmbiguityExhausted(
                            pending,
                        ))
                    } else {
                        Ok(DormantOperatorRecoveryAdmissionV1::RecoveryRequired(
                            pending,
                        ))
                    }
                }
                DormantOperatorRecoveryReservationV1::Complete { issued, result } => {
                    validate_recovery_replay(
                        &issued,
                        principal,
                        binding,
                        effect_id,
                        &request,
                        &reservation_key,
                    )?;
                    validate_recovery_terminal(&request, &result)?;
                    Ok(DormantOperatorRecoveryAdmissionV1::Terminal(result))
                }
            };
        }
        let current_key = recovery_current_key(request.resource_id());
        let current = self
            .journal
            .get(RecordNamespace::OperatorRecovery, &current_key)
            .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?
            .to_vec();
        validate_recovery_current(&request, &current)?;
        let current_generation = decode_recovery_current(&current)?.desired_generation;
        let issued = DormantOperatorRecoveryIssuedStateV1 {
            principal,
            binding,
            effect_id,
            request,
            current,
            current_generation,
            attempt: 1,
            ambiguity_queries: 0,
            recovery_state: DormantOperatorRecoveryDurableStateV1::InitialIssue,
        };
        commit_recovery_records(
            self.journal,
            recovery_issued_commit_id(&issued),
            vec![JournalRecord::put(
                RecordNamespace::OperatorRecovery,
                reservation_key.clone(),
                encode_issued_recovery_reservation(&issued)?,
            )],
        )?;
        Ok(DormantOperatorRecoveryAdmissionV1::Issued(
            DormantOperatorRecoveryEffectHandoffV1 {
                issued,
                reservation_key,
            },
        ))
    }

    /// Enumerates every nonterminal recovery row from protected startup state.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationClientAdapter`] for unhealthy provenance,
    /// foreign/corrupt records, or more than the bounded pending-row ceiling.
    pub fn pending_recoveries(
        &self,
    ) -> Result<Vec<DormantOperatorRecoveryPendingV1>, InvalidObservationClientAdapter> {
        self.journal
            .ensure_protected_authority()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
        let mut pending = Vec::new();
        for (key, encoded) in self.journal.records(RecordNamespace::OperatorRecovery) {
            if !key.starts_with(b"idempotency/") {
                continue;
            }
            match decode_recovery_reservation(encoded)? {
                DormantOperatorRecoveryReservationV1::Issued(issued) => {
                    validate_recovery_reservation_key(&issued, key)?;
                    if pending.len() == MAXIMUM_PENDING_OPERATOR_RECOVERIES_V1 {
                        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
                    }
                    pending.push(DormantOperatorRecoveryPendingV1 {
                        issued,
                        reservation_key: key.to_vec(),
                    });
                }
                DormantOperatorRecoveryReservationV1::Complete { issued, result } => {
                    validate_recovery_reservation_key(&issued, key)?;
                    validate_recovery_terminal(&issued.request, &result)?;
                }
            }
        }
        Ok(pending)
    }

    /// Classifies a restart-enumerated effect before deciding whether to redispatch.
    ///
    /// A positive `NotObserved` receipt is the only state that can produce a new
    /// issued handoff. `Unknown` consumes a bounded durable ambiguity query and
    /// never grants effect authority.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationClientAdapter`] when the pending token is no
    /// longer current or the injected observer returns a mismatched receipt.
    pub fn recover_pending<O>(
        &mut self,
        pending: DormantOperatorRecoveryPendingV1,
        observer: &mut O,
    ) -> Result<DormantOperatorRecoveryAdmissionV1, InvalidObservationClientAdapter>
    where
        O: DormantOperatorRecoveryEffectObserverV1,
    {
        self.journal
            .ensure_protected_authority()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
        if pending.issued.ambiguity_queries == MAXIMUM_OPERATOR_RECOVERY_AMBIGUITY_QUERIES_V1 {
            return Ok(DormantOperatorRecoveryAdmissionV1::AmbiguityExhausted(
                pending,
            ));
        }
        let retained = self
            .journal
            .get(RecordNamespace::OperatorRecovery, &pending.reservation_key)
            .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
        let DormantOperatorRecoveryReservationV1::Issued(retained) =
            decode_recovery_reservation(retained)?
        else {
            return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
        };
        if retained != pending.issued {
            return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
        }
        if requires_physical_recovery_receipt(retained.request.action()) {
            return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
        }
        validate_recovery_reservation_key(&retained, &pending.reservation_key)?;
        let current = self
            .journal
            .get(
                RecordNamespace::OperatorRecovery,
                &recovery_current_key(retained.request.resource_id()),
            )
            .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
        if current != retained.current {
            return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
        }
        let query = DormantOperatorRecoveryEffectQueryV1 {
            effect_id: retained.effect_id,
            attempt: retained.attempt,
            current_generation: retained.current_generation,
            request: retained.request.to_proto(),
        };
        let receipt = observer.classify(&query)?;
        if receipt.effect_id != retained.effect_id
            || receipt.attempt != retained.attempt
            || receipt.current_generation != retained.current_generation
        {
            return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
        }
        match receipt.disposition {
            DormantOperatorRecoveryEffectDispositionV1::Terminal(result) => {
                let handoff = DormantOperatorRecoveryEffectHandoffV1 {
                    issued: retained,
                    reservation_key: pending.reservation_key,
                };
                let terminal = handoff.check_terminal(result)?;
                match self.record_terminal(terminal)? {
                    DormantOperatorRecoveryTerminalCommitV1::Complete(result) => {
                        Ok(DormantOperatorRecoveryAdmissionV1::Terminal(result))
                    }
                    DormantOperatorRecoveryTerminalCommitV1::Ambiguous(terminal) => Ok(
                        DormantOperatorRecoveryAdmissionV1::TerminalCommitAmbiguous(terminal),
                    ),
                }
            }
            DormantOperatorRecoveryEffectDispositionV1::NotObserved => {
                if retained.attempt == MAXIMUM_OPERATOR_RECOVERY_EFFECT_ATTEMPTS_V1 {
                    return Ok(DormantOperatorRecoveryAdmissionV1::DispatchBudgetExhausted(
                        DormantOperatorRecoveryPendingV1 {
                            issued: retained,
                            reservation_key: pending.reservation_key,
                        },
                    ));
                }
                let mut reissued = retained;
                reissued.attempt += 1;
                reissued.ambiguity_queries = 0;
                reissued.recovery_state =
                    DormantOperatorRecoveryDurableStateV1::ReissuedAfterAbsence;
                commit_recovery_records(
                    self.journal,
                    recovery_issued_commit_id(&reissued),
                    vec![JournalRecord::put(
                        RecordNamespace::OperatorRecovery,
                        pending.reservation_key.clone(),
                        encode_issued_recovery_reservation(&reissued)?,
                    )],
                )?;
                Ok(DormantOperatorRecoveryAdmissionV1::Issued(
                    DormantOperatorRecoveryEffectHandoffV1 {
                        issued: reissued,
                        reservation_key: pending.reservation_key,
                    },
                ))
            }
            DormantOperatorRecoveryEffectDispositionV1::Unknown => {
                let mut ambiguous = retained;
                ambiguous.ambiguity_queries = ambiguous
                    .ambiguity_queries
                    .checked_add(1)
                    .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
                ambiguous.recovery_state =
                    DormantOperatorRecoveryDurableStateV1::ObservationUnknown;
                if ambiguous.ambiguity_queries > MAXIMUM_OPERATOR_RECOVERY_AMBIGUITY_QUERIES_V1 {
                    return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
                }
                commit_recovery_records(
                    self.journal,
                    recovery_issued_commit_id(&ambiguous),
                    vec![JournalRecord::put(
                        RecordNamespace::OperatorRecovery,
                        pending.reservation_key.clone(),
                        encode_issued_recovery_reservation(&ambiguous)?,
                    )],
                )?;
                let pending = DormantOperatorRecoveryPendingV1 {
                    issued: ambiguous,
                    reservation_key: pending.reservation_key,
                };
                if pending.issued.ambiguity_queries
                    == MAXIMUM_OPERATOR_RECOVERY_AMBIGUITY_QUERIES_V1
                {
                    Ok(DormantOperatorRecoveryAdmissionV1::AmbiguityExhausted(
                        pending,
                    ))
                } else {
                    Ok(DormantOperatorRecoveryAdmissionV1::Ambiguous(pending))
                }
            }
        }
    }

    /// Records one executor-supplied terminal result and resulting recovery head.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObservationClientAdapter`] when protected provenance is
    /// absent or the result fails semantic, identity, or exact binding checks.
    pub(crate) fn record_terminal(
        &mut self,
        terminal: DormantOperatorRecoveryTerminalV1,
    ) -> Result<DormantOperatorRecoveryTerminalCommitV1, InvalidObservationClientAdapter> {
        let handoff = &terminal.handoff;
        let result = &terminal.result;
        self.journal
            .ensure_protected_authority()
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
        let retained_bytes = self
            .journal
            .get(RecordNamespace::OperatorRecovery, &handoff.reservation_key)
            .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?
            .to_vec();
        let retained = match decode_recovery_reservation(&retained_bytes)? {
            DormantOperatorRecoveryReservationV1::Issued(retained) => retained,
            DormantOperatorRecoveryReservationV1::Complete {
                issued,
                result: completed,
            } => {
                if issued != handoff.issued || completed != *result {
                    return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
                }
                let (next_current, completed_reservation) =
                    recovery_terminal_records(&issued, result)?;
                let transition_key =
                    recovery_transition_key(issued.request.resource_id(), &result.resource_version);
                if self.journal.get(
                    RecordNamespace::OperatorRecovery,
                    &recovery_current_key(issued.request.resource_id()),
                ) != Some(next_current.as_slice())
                    || self
                        .journal
                        .get(RecordNamespace::OperatorRecovery, &transition_key)
                        != Some(completed_reservation.as_slice())
                {
                    return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
                }
                return Ok(DormantOperatorRecoveryTerminalCommitV1::Complete(
                    terminal.result,
                ));
            }
        };
        if retained != handoff.issued {
            return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
        }
        let current_key = recovery_current_key(handoff.issued.request.resource_id());
        let protected_current = self
            .journal
            .get(RecordNamespace::OperatorRecovery, &current_key)
            .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?
            .to_vec();
        validate_recovery_current(&handoff.issued.request, &protected_current)?;
        validate_recovery_terminal(&handoff.issued.request, result)?;
        if protected_current != handoff.issued.current {
            return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
        }
        let (next_current, completed_reservation) =
            recovery_terminal_records(&handoff.issued, result)?;
        let records = vec![
            JournalRecord::put(RecordNamespace::OperatorRecovery, current_key, next_current),
            JournalRecord::put(
                RecordNamespace::OperatorRecovery,
                handoff.reservation_key.clone(),
                completed_reservation.clone(),
            ),
            JournalRecord::put(
                RecordNamespace::OperatorRecovery,
                recovery_transition_key(
                    handoff.issued.request.resource_id(),
                    &result.resource_version,
                ),
                completed_reservation,
            ),
        ];
        if commit_recovery_records(
            self.journal,
            recovery_terminal_commit_id(&handoff.issued, result),
            records,
        )
        .is_err()
        {
            return Ok(DormantOperatorRecoveryTerminalCommitV1::Ambiguous(terminal));
        }
        Ok(DormantOperatorRecoveryTerminalCommitV1::Complete(
            terminal.result,
        ))
    }

    /// Synchronizes a fully checked current sandbox head into protected authority.
    pub(crate) fn synchronize_sandbox(
        &mut self,
        resource: &CheckedSandboxResourceV1,
    ) -> Result<(), InvalidObservationClientAdapter> {
        let prepared = prepare_operator_recovery_sandbox_current_v1(self.journal, resource)?;
        if prepared.is_already_current() {
            return Ok(());
        }
        commit_recovery_records(
            self.journal,
            ObjectDigest::from_bytes(
                Sha256::digest(
                    prepared
                        .record
                        .value()
                        .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
                )
                .into(),
            ),
            vec![prepared.into_record()],
        )
    }

    /// Synchronizes a fully checked current operation head into protected authority.
    pub(crate) fn synchronize_operation(
        &mut self,
        resource: &CheckedOperationResourceV1,
    ) -> Result<(), InvalidObservationClientAdapter> {
        let prepared = prepare_operator_recovery_operation_current_v1(self.journal, resource)?;
        if prepared.is_already_current() {
            return Ok(());
        }
        commit_recovery_records(
            self.journal,
            ObjectDigest::from_bytes(
                Sha256::digest(
                    prepared
                        .record
                        .value()
                        .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
                )
                .into(),
            ),
            vec![prepared.into_record()],
        )
    }
}

/// Prepares a sandbox recovery head without committing it independently.
pub(crate) fn prepare_operator_recovery_sandbox_current_v1(
    journal: &crate::Journal,
    resource: &CheckedSandboxResourceV1,
) -> Result<PreparedOperatorRecoveryCurrentV1, InvalidObservationClientAdapter> {
    let allowed = (u8::from(resource.has_true_condition(PublicConditionCodeV1::Blocked))
        | u8::from(resource.has_true_condition(PublicConditionCodeV1::Degraded))
        | u8::from(resource.has_true_condition(PublicConditionCodeV1::ResidualState))
        | u8::from(resource.has_true_condition(PublicConditionCodeV1::OwnershipPending)))
        * 4
        | (u8::from(resource.has_true_condition(PublicConditionCodeV1::Fenced))
            | u8::from(resource.has_true_condition(PublicConditionCodeV1::Blocked)))
            * 8;
    prepare_recovery_current(
        journal,
        resource.sandbox_id(),
        &resource.as_proto().resource_version,
        1,
        allowed,
        resource.desired_generation(),
        resource.observation_sequence(),
        latest_recovery_transition(
            resource.conditions(),
            resource
                .as_proto()
                .updated_at
                .as_option()
                .map(|timestamp| (timestamp.seconds, timestamp.nanoseconds)),
        )?,
    )
}

/// Derives the protected Repair successor without inventing a guest observation.
///
/// The completed terminal transaction advances the public desired generation
/// and version. Its observation sequence and time remain the predecessor's;
/// ordinary synchronization may advance them only after a later real sample.
///
/// # Errors
///
/// Rejects an inconsistent predecessor head or successor identity.
#[allow(dead_code, reason = "public operator Repair route remains closed")]
pub(crate) fn operator_repair_successor_current_v1(
    predecessor_current: &[u8],
    predecessor: &CheckedSandboxResourceV1,
    successor: &CheckedSandboxResourceV1,
) -> Result<Vec<u8>, InvalidObservationClientAdapter> {
    let head = decode_recovery_current(predecessor_current)?;
    let successor_generation = predecessor
        .desired_generation()
        .checked_add(1)
        .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    if head.kind != 1
        || head.allowed_actions
            & (1 << (OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_REPAIR as u8 - 1))
            == 0
        || head.version != predecessor.as_proto().resource_version
        || head.desired_generation != predecessor.desired_generation()
        || head.observation_sequence != predecessor.observation_sequence()
        || successor.sandbox_id() != predecessor.sandbox_id()
        || successor.as_proto().resource_version == head.version
        || successor.desired_generation() != successor_generation
        || successor.observation_sequence() != predecessor.observation_sequence()
    {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    encode_recovery_current(
        1,
        0,
        &successor.as_proto().resource_version,
        successor_generation,
        head.observation_sequence,
        head.transition,
    )
}

/// Prepares an operation recovery head without committing it independently.
pub(crate) fn prepare_operator_recovery_operation_current_v1(
    journal: &crate::Journal,
    resource: &CheckedOperationResourceV1,
) -> Result<PreparedOperatorRecoveryCurrentV1, InvalidObservationClientAdapter> {
    let ownership_retry = if resource.phase() == CheckedOperationPhaseV1::Committed
        && resource.retry() == CheckedRetryClassV1::AfterStateChange
    {
        matches!(
            crate::reconciler::validated_ownership_gate_from_journal_v1(
                journal,
                OperationId::from_bytes(resource.operation_id()),
            )
            .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
            Some(OwnershipGateStatusV1::Pending(_))
        )
    } else {
        false
    };
    let retry = ownership_retry
        || (resource.phase() == CheckedOperationPhaseV1::FailedBeforeCommit
            && resource.retry() != CheckedRetryClassV1::Never);
    let abandon = matches!(
        resource.phase(),
        CheckedOperationPhaseV1::PermanentlyBlocked
            | CheckedOperationPhaseV1::CommittedWithResidualCleanup
    );
    prepare_recovery_current(
        journal,
        resource.operation_id(),
        resource.resource_version().as_bytes(),
        2,
        u8::from(retry) | u8::from(abandon) * 2,
        resource.as_proto().accepted_generation,
        resource
            .conditions()
            .iter()
            .map(|condition| condition.as_proto().observation_sequence)
            .chain(std::iter::once(resource.as_proto().observation_sequence))
            .max()
            .filter(|sequence| *sequence != 0)
            .ok_or(InvalidObservationClientAdapter::InvalidOperatorRecovery)?,
        latest_recovery_transition(
            resource.conditions(),
            resource
                .as_proto()
                .accepted_at
                .as_option()
                .map(|timestamp| (timestamp.seconds, timestamp.nanoseconds)),
        )?,
    )
}

enum DormantOperatorRecoveryReservationV1 {
    Issued(DormantOperatorRecoveryIssuedStateV1),
    Complete {
        issued: DormantOperatorRecoveryIssuedStateV1,
        result: aos_proto::aos::sandbox::v1::OperatorRecoveryResult,
    },
}

fn prepare_recovery_current(
    journal: &crate::Journal,
    resource_id: [u8; 16],
    version: &[u8],
    kind: u8,
    allowed_actions: u8,
    desired_generation: u64,
    observation_sequence: u64,
    transition: (i64, u32),
) -> Result<PreparedOperatorRecoveryCurrentV1, InvalidObservationClientAdapter> {
    journal
        .ensure_protected_authority()
        .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    let value = encode_recovery_current(
        kind,
        allowed_actions,
        version,
        desired_generation,
        observation_sequence,
        transition,
    )?;
    let current_key = recovery_current_key(resource_id);
    let mut already_current = false;
    if let Some(existing) = journal.get(RecordNamespace::OperatorRecovery, &current_key) {
        if existing == value.as_slice() {
            already_current = true;
        } else {
            let existing = decode_recovery_current(existing)?;
            if existing.kind != kind
                || observation_sequence <= existing.observation_sequence
                || desired_generation < existing.desired_generation
                || transition < existing.transition
            {
                return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
            }
        }
    }
    Ok(PreparedOperatorRecoveryCurrentV1 {
        record: JournalRecord::put(RecordNamespace::OperatorRecovery, current_key, value),
        already_current,
    })
}

fn commit_recovery_records(
    journal: &mut crate::Journal,
    binding: ObjectDigest,
    records: Vec<JournalRecord>,
) -> Result<(), InvalidObservationClientAdapter> {
    let mut transaction_id = [0_u8; 16];
    transaction_id.copy_from_slice(&binding.as_bytes()[..16]);
    if transaction_id == [0; 16] {
        return Err(InvalidObservationClientAdapter::InvalidOperatorRecovery);
    }
    let transaction = JournalTransaction::new(transaction_id, records)
        .map_err(|_| InvalidObservationClientAdapter::InvalidOperatorRecovery)?;
    match journal.commit(&transaction) {
        Ok(_) => Ok(()),
        Err(_)
            if transaction
                .records()
                .iter()
                .all(|record| journal.get(record.namespace(), record.key()) == record.value()) =>
        {
            Ok(())
        }
        Err(_) => Err(InvalidObservationClientAdapter::InvalidOperatorRecovery),
    }
}

impl<C, E> NodeController<C, E>
where
    C: ActivatedOperationCompiler,
    E: SingleNodeEffectExecutor,
{
    /// Borrows the sole protected journal for a dormant operator-recovery transition.
    ///
    /// The returned owner registers no route. Effects require a sealed durable
    /// handoff and the explicitly supplied recovery executor.
    pub(crate) fn dormant_operator_recovery(&mut self) -> DormantOperatorRecoveryOwnerV1<'_> {
        DormantOperatorRecoveryOwnerV1 {
            journal: self.reconciler.journal_mut(),
        }
    }
}

impl<C, E, T> DormantControllerCompositionV1<C, E, T>
where
    C: ActivatedOperationCompiler,
    E: SingleNodeEffectExecutor,
{
    /// Constructs the dormant public recovery handler from explicit dependencies.
    ///
    /// The returned handler remains unregistered and borrows the sole controller
    /// journal through this composition.
    #[must_use]
    pub(crate) fn operator_recovery_service<A, S, O>(
        &mut self,
        authorizer: A,
        current_observer: S,
        effect_observer: O,
    ) -> DormantOperatorRecoveryPublicServiceV1<'_, C, E, A, S, O>
    where
        A: DormantOperatorRecoveryPublicAuthorizerV1,
        S: DormantOperatorRecoveryCurrentObserverV1,
        O: DormantOperatorRecoveryEffectObserverV1,
    {
        DormantOperatorRecoveryPublicServiceV1::new(
            &mut self.controller,
            authorizer,
            current_observer,
            effect_observer,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{OperatorRecoveryAction, requires_physical_recovery_receipt};

    #[test]
    fn effectful_operator_recovery_requires_physical_receipt() {
        assert!(!requires_physical_recovery_receipt(
            OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_RETRY as i32
        ));
        assert!(!requires_physical_recovery_receipt(
            OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_ABANDON as i32
        ));
        assert!(requires_physical_recovery_receipt(
            OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_RECONCILE as i32
        ));
        assert!(requires_physical_recovery_receipt(
            OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_REPAIR as i32
        ));
    }
}
