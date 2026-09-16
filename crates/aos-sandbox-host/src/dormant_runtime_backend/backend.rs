//! Concrete dormant implementation of the portable runtime backend.
//!
//! Calls create typed ambiguity tokens unless a previously submitted opaque,
//! authenticated observation exactly matches the operation. Submitting an
//! observation performs no host effect: it is the source-level seam where a
//! future protected worker can return evidence minted by the core verifier.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use aos_sandbox::runtime_execution::{
    DormantRuntimeExecutionClaimV1, JournalRuntimeExecutionError,
    agent_handshake_signing_message_v1, agent_outcome_signing_message_v1,
};
use aos_sandbox_agent::{
    AgentExecutionOperationV1, AgentExecutionOutcomeV1, AgentExecutionPhaseV1, AgentFeatureSetV1,
    AgentFeatureV1, AgentHandshakeRequestV1, AgentHandshakeResponseV1, AgentOperationIdV1,
    AgentOperationRequestV1, AgentOperationSequenceV1, AgentRuntimeBindingV1,
    AgentSessionBindingV1,
};
use aos_sandbox_core::runtime_backend::{
    BackendCapabilitiesV1, BackendEffectOutcome, BackendEvidenceVerifierV1, BackendExecutionHandle,
    BackendExecutionInspectionRequestV1, BackendExecutionInspectionV1, BackendExecutionOutcome,
    BackendExecutionPhaseV1, BackendExecutionRequestV1, BackendFreezeObservationV1,
    BackendLifecycleOperationV1, BackendLifecycleRecoveryRecordV1, BackendOperationIdV1,
    BackendOperationSequenceV1, BackendProbeReportV1, BackendRecoveryOutcome,
    BackendRuntimeInspectionV1, BackendRuntimePhaseV1, BackendStartObservationV1,
    BackendStopDeadlineV1, BackendStopObservationV1, DestroyableRuntime, DestroyedRuntime,
    FrozenRuntime, PreparedRuntime, ResolvedRuntimePlanV1, RunningRuntime, RuntimeBackend,
    RuntimeBackendError, RuntimeHandleCommitmentV1, RuntimeRecoveryToken,
    SignedBackendExecutionInspectionV1, SignedBackendRuntimeInspectionV1, StoppableRuntime,
    StoppedRuntime, backend_execution_inspection_binding_v1,
};
use aos_sandbox_core::{
    DecodeLimits, ExecutionId, ObjectDigest, ObservationSequence, decode_execution_spec_v1,
};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};

/// Carries an untrusted post-handshake agent outcome and detached signature.
pub struct SignedAgentOutcomeV1 {
    outcome: AgentExecutionOutcomeV1,
    signature: [u8; 64],
}

impl SignedAgentOutcomeV1 {
    /// Wraps one untrusted outcome for exact fixed-peer verification.
    #[must_use]
    pub const fn new(outcome: AgentExecutionOutcomeV1, signature: [u8; 64]) -> Self {
        Self { outcome, signature }
    }

    fn into_parts(self) -> (AgentExecutionOutcomeV1, [u8; 64]) {
        (self.outcome, self.signature)
    }
}

/// Retains a prepared-runtime commitment behind the portable typestate.
pub struct DormantPreparedHandleV1 {
    commitment: RuntimeHandleCommitmentV1,
}

/// Retains a started-runtime commitment behind the portable typestate.
pub struct DormantRuntimeHandleV1 {
    commitment: RuntimeHandleCommitmentV1,
}

/// Retains one execution binding behind the portable execution handle.
pub struct DormantExecutionHandleV1 {
    observation_commitment: ObjectDigest,
}

/// Carries fixed-root backend readiness evidence without advertising it.
///
/// The report is reconstructed from protected runtime-owner records. This
/// value is deliberately not connected to Host service readiness or routing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DormantRuntimeBackendReadinessEvidenceV1 {
    probe: BackendProbeReportV1,
    runtime: RuntimeHandleCommitmentV1,
    plan_commitment: ObjectDigest,
}

impl DormantRuntimeBackendReadinessEvidenceV1 {
    /// Borrows the authenticated backend capability probe.
    #[must_use]
    pub const fn probe(&self) -> &BackendProbeReportV1 {
        &self.probe
    }

    /// Borrows the exact protected runtime generation.
    #[must_use]
    pub const fn runtime(&self) -> &RuntimeHandleCommitmentV1 {
        &self.runtime
    }

    /// Returns the complete protected plan commitment.
    #[must_use]
    pub const fn plan_commitment(&self) -> ObjectDigest {
        self.plan_commitment
    }
}

impl DormantExecutionHandleV1 {
    /// Returns the authenticated handoff observation commitment.
    #[must_use]
    pub const fn observation_commitment(&self) -> ObjectDigest {
        self.observation_commitment
    }
}

/// Retains exact lifecycle ambiguity without containing callback authority.
pub struct DormantLifecycleRecoveryHandleV1 {
    lifecycle_operation: BackendLifecycleOperationV1,
    runtime_handle: Option<ObjectDigest>,
}

impl DormantLifecycleRecoveryHandleV1 {
    /// Returns the exact lifecycle effect awaiting external observation.
    #[must_use]
    pub const fn lifecycle_operation(&self) -> BackendLifecycleOperationV1 {
        self.lifecycle_operation
    }

    /// Returns the targeted runtime handle when the effect follows prepare.
    #[must_use]
    pub const fn runtime_handle(&self) -> Option<ObjectDigest> {
        self.runtime_handle
    }
}

/// Retains exact execution-handoff ambiguity without containing a callback.
pub struct DormantExecutionRecoveryHandleV1 {
    execution: ExecutionId,
    specification_digest: ObjectDigest,
    admission_commitment: ObjectDigest,
    effect_request_digest: ObjectDigest,
    runtime: RuntimeHandleCommitmentV1,
}

/// Carries the sole external agent request produced from one consumed effect.
#[must_use = "the exact agent request must be dispatched or retained for recovery"]
pub struct DormantAgentExecutionHandoffV1 {
    request: AgentOperationRequestV1,
}

/// Carries an untrusted signed protected-clock observation for Kill escalation.
pub struct SignedDormantKillDeadlineObservationV1 {
    operation: BackendOperationIdV1,
    sequence: BackendOperationSequenceV1,
    kill_operation: BackendOperationIdV1,
    kill_sequence: BackendOperationSequenceV1,
    stop_request_commitment: ObjectDigest,
    runtime: RuntimeHandleCommitmentV1,
    deadline: BackendStopDeadlineV1,
    host_boot_id: [u8; 16],
    stop_started_boottime_nanoseconds: u64,
    observed_boottime_nanoseconds: u64,
    signature: [u8; 64],
}

impl SignedDormantKillDeadlineObservationV1 {
    /// Wraps untrusted protected-clock fields and a detached peer signature.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        kill_operation: BackendOperationIdV1,
        kill_sequence: BackendOperationSequenceV1,
        stop_request_commitment: ObjectDigest,
        runtime: RuntimeHandleCommitmentV1,
        deadline: BackendStopDeadlineV1,
        host_boot_id: [u8; 16],
        stop_started_boottime_nanoseconds: u64,
        observed_boottime_nanoseconds: u64,
        signature: [u8; 64],
    ) -> Self {
        Self {
            operation,
            sequence,
            kill_operation,
            kill_sequence,
            stop_request_commitment,
            runtime,
            deadline,
            host_boot_id,
            stop_started_boottime_nanoseconds,
            observed_boottime_nanoseconds,
            signature,
        }
    }
}

/// Retains an ambiguous Kill stop until completion or protected deadline expiry.
#[must_use = "Kill ambiguity must be observed or escalated after protected expiry"]
pub struct DormantPendingKillV1 {
    token: RuntimeRecoveryToken<DormantLifecycleRecoveryHandleV1>,
    runtime: RuntimeHandleCommitmentV1,
    deadline: BackendStopDeadlineV1,
}

/// Carries the one-shot forced complete-payload teardown request.
#[must_use = "the forced teardown must be observed or retained for recovery"]
pub struct DormantForcedKillHandoffV1 {
    operation: BackendOperationIdV1,
    sequence: BackendOperationSequenceV1,
    request_commitment: ObjectDigest,
    runtime: RuntimeHandleCommitmentV1,
}

/// Retains Kill ambiguity when protected escalation validation fails.
pub struct DormantKillEscalationErrorV1 {
    error: RuntimeBackendError,
    pending: DormantPendingKillV1,
    proposed: Option<DormantForcedKillHandoffV1>,
}

impl DormantKillEscalationErrorV1 {
    /// Returns the closed escalation failure.
    #[must_use]
    pub const fn error(&self) -> RuntimeBackendError {
        self.error
    }

    /// Recovers both sides of a possibly committed Stop-to-Kill supersession.
    #[must_use]
    pub fn into_recovery(self) -> (DormantPendingKillV1, Option<DormantForcedKillHandoffV1>) {
        (self.pending, self.proposed)
    }
}

impl DormantForcedKillHandoffV1 {
    /// Returns the exact externally dispatched forced-teardown commitment.
    #[must_use]
    pub const fn request_commitment(&self) -> ObjectDigest {
        self.request_commitment
    }
}

/// Reports the first bounded Stop stage of dormant Kill orchestration.
pub enum DormantKillStopOutcomeV1 {
    /// Stop completed before its deadline.
    Stopped(StoppedRuntime<DormantRuntimeHandleV1>),
    /// Stop may have committed and must be observed or escalated after expiry.
    Awaiting(DormantPendingKillV1),
    /// Conflicting evidence retains exact recovery authority for quarantine.
    Quarantined {
        /// Closed integrity classification.
        error: RuntimeBackendError,
        /// Intact Kill ambiguity.
        pending: DormantPendingKillV1,
    },
    /// Stop was rejected before crossing the effect boundary.
    Rejected {
        /// Exact rejection.
        error: RuntimeBackendError,
        /// Retryable runtime state.
        runtime: StoppableRuntime<DormantRuntimeHandleV1>,
    },
}

impl DormantAgentExecutionHandoffV1 {
    /// Borrows the authenticated-session request for external transport.
    #[must_use]
    pub const fn request(&self) -> &AgentOperationRequestV1 {
        &self.request
    }
}

struct CoownedAgentSessionV1 {
    handshake: AgentHandshakeRequestV1,
    response: AgentHandshakeResponseV1,
    binding: AgentSessionBindingV1,
    features: AgentFeatureSetV1,
    next_operation_sequence: AgentOperationSequenceV1,
    outstanding: Option<CoownedAgentOutstandingV1>,
}

struct CoownedAgentOutstandingV1 {
    backend_request: BackendExecutionRequestV1,
    agent_request: AgentOperationRequestV1,
    execution: ExecutionId,
    runtime: RuntimeHandleCommitmentV1,
}

impl DormantExecutionRecoveryHandleV1 {
    /// Returns the execution awaiting authenticated guest observation.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the exact canonical execution-specification commitment.
    #[must_use]
    pub const fn specification_digest(&self) -> ObjectDigest {
        self.specification_digest
    }

    /// Returns the durable admission commitment.
    #[must_use]
    pub const fn admission_commitment(&self) -> ObjectDigest {
        self.admission_commitment
    }

    /// Returns the phase-independent effect request commitment.
    #[must_use]
    pub const fn effect_request_digest(&self) -> ObjectDigest {
        self.effect_request_digest
    }

    /// Returns the exact runtime commitment for the handoff.
    #[must_use]
    pub const fn runtime(&self) -> &RuntimeHandleCommitmentV1 {
        &self.runtime
    }
}

/// Owns a protected runtime claim and authenticated observation inbox.
pub struct DormantProtectedRuntimeBackendV1<'owner> {
    authority: DormantRuntimeExecutionClaimV1<'owner>,
    probe: BackendProbeReportV1,
    agent_evidence_verifier: BackendEvidenceVerifierV1,
    host_evidence_verifier: BackendEvidenceVerifierV1,
    runtime_observations: VecDeque<BackendRuntimeInspectionV1>,
    execution_observations: VecDeque<BackendExecutionInspectionV1>,
    authorized_execution_requests:
        BTreeMap<ObjectDigest, RuntimeRecoveryToken<DormantExecutionRecoveryHandleV1>>,
    authorized_lifecycle_requests: BTreeSet<ObjectDigest>,
    authorized_inspections: BTreeMap<
        ObjectDigest,
        (
            BackendOperationIdV1,
            BackendOperationSequenceV1,
            ObjectDigest,
        ),
    >,
    last_lifecycle_operation_sequence: u64,
    last_observation_sequence: u64,
    pending_agent_handshake: Option<AgentHandshakeRequestV1>,
    agent_session: Option<CoownedAgentSessionV1>,
}

impl<'owner> DormantProtectedRuntimeBackendV1<'owner> {
    /// Constructs the backend from an opaque fixed-root runtime claim.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeBackendError`] when the protected claim is stale or its
    /// exact protected probe currentness cannot mint the closed capability set.
    pub fn from_protected_claim(
        authority: DormantRuntimeExecutionClaimV1<'owner>,
    ) -> Result<Self, RuntimeBackendError> {
        authority
            .revalidate()
            .map_err(|_| RuntimeBackendError::StaleCurrentness)?;
        let capabilities = authority.backend_capabilities().clone();
        let peer = *authority.agent_peer();
        let pending_lifecycle = authority
            .pending_lifecycle_issue()
            .map_err(|_| RuntimeBackendError::IntegrityFailure)?;
        let protected_observation_floor = authority.next_observation_sequence().get() - 1;
        let protected_lifecycle_floor = authority.next_lifecycle_sequence() - 1;
        let agent_evidence_verifier = BackendEvidenceVerifierV1::new(
            peer.public_key(),
            peer.trust_context(),
            peer.channel_binding(),
        )
        .map_err(|_| RuntimeBackendError::IntegrityFailure)?;
        if agent_evidence_verifier.authority_binding() != peer.authority_binding() {
            return Err(RuntimeBackendError::IntegrityFailure);
        }
        let host = *authority.host_verifier();
        let host_evidence_verifier = BackendEvidenceVerifierV1::new(
            host.public_key(),
            host.trust_context(),
            host.channel_binding(),
        )
        .map_err(|_| RuntimeBackendError::IntegrityFailure)?;
        if host_evidence_verifier.authority_binding() != host.authority_binding() {
            return Err(RuntimeBackendError::IntegrityFailure);
        }
        let probe_commitment = probe_commitment(
            authority.currentness().backend_probe(),
            &capabilities,
            host.authority_binding(),
        );
        let probe = BackendProbeReportV1::new(
            *authority.currentness().backend_probe(),
            capabilities,
            probe_commitment,
        )
        .map_err(|_| RuntimeBackendError::IntegrityFailure)?;
        let mut authorized_lifecycle_requests = BTreeSet::new();
        let mut authorized_inspections = BTreeMap::new();
        if let Some(issue) = pending_lifecycle.filter(|issue| !issue.crossed()) {
            if issue.action() == BackendLifecycleOperationV1::Inspect {
                let handle = issue
                    .handle()
                    .ok_or(RuntimeBackendError::IntegrityFailure)?;
                authorized_inspections.insert(
                    handle,
                    (issue.operation(), issue.sequence(), issue.request()),
                );
            } else {
                authorized_lifecycle_requests.insert(issue.request());
            }
        }
        Ok(Self {
            authority,
            probe,
            agent_evidence_verifier,
            host_evidence_verifier,
            runtime_observations: VecDeque::new(),
            execution_observations: VecDeque::new(),
            authorized_execution_requests: BTreeMap::new(),
            authorized_lifecycle_requests,
            authorized_inspections,
            last_lifecycle_operation_sequence: protected_lifecycle_floor,
            last_observation_sequence: protected_observation_floor,
            pending_agent_handshake: None,
            agent_session: None,
        })
    }

    /// Revalidates and snapshots the protected evidence used for composition.
    ///
    /// This evidence is nonauthorizing and is not a Host readiness
    /// advertisement. It exists so dormant source composition cannot claim a
    /// backend from caller-invented capability or currentness scalars.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeBackendError::StaleCurrentness`] after the fixed owner
    /// records change or become unavailable.
    pub fn readiness_evidence(
        &self,
    ) -> Result<DormantRuntimeBackendReadinessEvidenceV1, RuntimeBackendError> {
        self.revalidate()?;
        Ok(DormantRuntimeBackendReadinessEvidenceV1 {
            probe: self.probe.clone(),
            runtime: *self.authority.currentness().runtime(),
            plan_commitment: self.authority.currentness().runtime().plan_commitment(),
        })
    }

    /// Reconstructs the exact ambiguity token for a crossed lifecycle issue.
    ///
    /// This is the cold-open entry to recovery. An Issued action remains
    /// resumable through its ordinary one-shot method and therefore does not
    /// produce an ambiguity token until its boundary is durably consumed.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeBackendError`] if protected currentness changed or the
    /// retained issue cannot form the exact portable recovery commitment.
    pub fn pending_lifecycle_recovery(
        &self,
    ) -> Result<Option<RuntimeRecoveryToken<DormantLifecycleRecoveryHandleV1>>, RuntimeBackendError>
    {
        let issue = self
            .authority
            .pending_lifecycle_issue()
            .map_err(|_| RuntimeBackendError::StaleCurrentness)?;
        let Some(issue) = issue.filter(|issue| issue.crossed()) else {
            return Ok(None);
        };
        lifecycle_token(
            issue.operation(),
            issue.sequence(),
            *self.authority.currentness().runtime().currentness(),
            issue.plan(),
            issue.request(),
            issue.action(),
            issue.handle(),
        )
        .map(Some)
    }

    /// Begins the authenticated guest session on this retained protected claim.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeBackendError`] unless runtime and channel bindings are
    /// exactly those authenticated by the fixed Host record.
    pub fn begin_agent_handshake(
        &mut self,
        request: AgentHandshakeRequestV1,
    ) -> Result<(), RuntimeBackendError> {
        self.revalidate()?;
        if self.pending_agent_handshake.is_some() || self.agent_session.is_some() {
            return Err(RuntimeBackendError::StateConflict);
        }
        let expected_runtime = agent_runtime_binding(self.authority.currentness())?;
        if request.runtime() != &expected_runtime
            || request.host_channel_binding() != self.authority.agent_peer().channel_binding()
        {
            return Err(RuntimeBackendError::IntegrityFailure);
        }
        self.pending_agent_handshake = Some(request);
        Ok(())
    }

    /// Verifies the guest response and retains one co-owned stop-and-wait session.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeBackendError`] for an unsolicited, substituted, or
    /// incorrectly signed response.
    pub fn complete_agent_handshake(
        &mut self,
        response: AgentHandshakeResponseV1,
    ) -> Result<(), RuntimeBackendError> {
        self.revalidate()?;
        let request = self
            .pending_agent_handshake
            .as_ref()
            .ok_or(RuntimeBackendError::StateConflict)?;
        let expected = AgentSessionBindingV1::derive(request, response.agent_instance())
            .map_err(|_| RuntimeBackendError::IntegrityFailure)?;
        if response.session_binding() != expected {
            return Err(RuntimeBackendError::IntegrityFailure);
        }
        let message = agent_handshake_signing_message_v1(
            request,
            expected,
            response.agent_instance(),
            response.features(),
        );
        verify_peer_signature(
            self.authority.agent_peer().public_key(),
            &message,
            response.challenge_signature(),
        )?;
        let features = response.features().clone();
        let next_operation_sequence =
            AgentOperationSequenceV1::new(1).map_err(|_| RuntimeBackendError::InvalidSequence)?;
        let request = self
            .pending_agent_handshake
            .take()
            .ok_or(RuntimeBackendError::StateConflict)?;
        self.agent_session = Some(CoownedAgentSessionV1 {
            handshake: request,
            response,
            binding: expected,
            features,
            next_operation_sequence,
            outstanding: None,
        });
        Ok(())
    }

    /// Consumes one freshly Issued effect into one co-owned agent handoff.
    ///
    /// The backend request stays private until the exact signed agent response
    /// is authenticated. The caller therefore cannot consume the move-only
    /// dispatch independently at both the backend and agent boundaries.
    ///
    /// # Errors
    ///
    /// Returns [`DormantBackendHandoffErrorV1`] for stale protected ownership,
    /// a nonfresh/foreign effect, wrong operation, or corrupt durability.
    pub fn prepare_execution_handoff(
        &mut self,
        effect: &aos_sandbox_core::runtime_backend::DurableExecutionEffectV1,
    ) -> Result<DormantAgentExecutionHandoffV1, DormantBackendHandoffErrorV1> {
        self.revalidate()
            .map_err(|_| DormantBackendHandoffErrorV1::StaleCurrentness)?;
        let live_session = self
            .agent_session
            .as_ref()
            .ok_or(DormantBackendHandoffErrorV1::MissingAgentSession)?;
        if live_session.outstanding.is_some()
            || !live_session
                .features
                .contains(AgentFeatureV1::ExecutionHandoff)
        {
            return Err(DormantBackendHandoffErrorV1::AlreadyStaged);
        }
        let request = effect
            .backend_execution_request()
            .map_err(|_| DormantBackendHandoffErrorV1::InvalidRoute)?;
        let specification = decode_execution_spec_v1(
            request.specification_bytes(),
            DecodeLimits {
                maximum_bytes: request.specification_bytes().len(),
                maximum_collection_items: 65_536,
                maximum_total_items: 262_144,
                maximum_byte_string_bytes: 15 * 1_048_576,
                maximum_text_bytes: 1_048_576,
                maximum_depth: 128,
            },
        )
        .map_err(|_| DormantBackendHandoffErrorV1::InvalidRoute)?;
        let evidence_authority = self.agent_evidence_authority();
        let runtime = *self.authority.currentness().runtime();
        let payload_boot_id = self.authority.currentness().payload_boot_id();
        let session = self
            .agent_session
            .as_mut()
            .ok_or(DormantBackendHandoffErrorV1::MissingAgentSession)?;
        let inspection = BackendExecutionInspectionRequestV1::new(
            evidence_authority,
            request.operation(),
            request.sequence(),
            request.effect_request_digest(),
            specification.execution(),
            request.specification_digest(),
            request.admission_commitment(),
            runtime,
            payload_boot_id,
        )
        .map_err(|_| DormantBackendHandoffErrorV1::InvalidRoute)?;
        let operation = AgentExecutionOperationV1::Authorize {
            execution: specification.execution(),
            specification_bytes: request.specification_bytes().to_vec(),
            specification_digest: request.specification_digest(),
            admission_commitment: request.admission_commitment(),
            principal: specification.principal(),
            audit: specification.audit(),
        };
        let agent_request = AgentOperationRequestV1::new(
            session.binding,
            session.next_operation_sequence,
            AgentOperationIdV1::new(*request.operation().as_bytes())
                .map_err(|_| DormantBackendHandoffErrorV1::InvalidRoute)?,
            backend_execution_inspection_binding_v1(&inspection),
            operation,
        )
        .map_err(|_| DormantBackendHandoffErrorV1::InvalidRoute)?;
        self.authority
            .consume_fresh_execution_for_authenticated_agent_route(
                &session.handshake,
                &session.response,
                &agent_request,
                effect,
            )?;
        session.outstanding = Some(CoownedAgentOutstandingV1 {
            backend_request: request,
            agent_request: agent_request.clone(),
            execution: specification.execution(),
            runtime,
        });
        Ok(DormantAgentExecutionHandoffV1 {
            request: agent_request,
        })
    }

    /// Stages one protected Prepare handoff for exact one-shot consumption.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeBackendError`] for stale currentness or duplicate issue.
    pub fn stage_prepare(
        &mut self,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
    ) -> Result<ResolvedRuntimePlanV1, RuntimeBackendError> {
        self.revalidate()?;
        let (plan, request) = self
            .authority
            .issue_protected_prepare(operation, sequence)
            .map_err(|_| RuntimeBackendError::InvalidSequence)?;
        self.remember_lifecycle_request(request, sequence)?;
        Ok(plan)
    }

    /// Stages one protected Start handoff for exact one-shot consumption.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeBackendError`] for stale currentness or duplicate issue.
    pub fn stage_start(
        &mut self,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        prepared: &PreparedRuntime<DormantPreparedHandleV1>,
    ) -> Result<ObjectDigest, RuntimeBackendError> {
        self.revalidate()?;
        self.stage_lifecycle(
            BackendLifecycleOperationV1::Start,
            operation,
            sequence,
            &prepared.handle().commitment,
        )
    }

    /// Stages one protected runtime transition for exact one-shot consumption.
    ///
    /// Freeze and Thaw are accepted here. Stop uses [`Self::stage_stop`], and
    /// destruction uses the matching protected typestate staging method.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeBackendError`] for another action, stale currentness,
    /// or a duplicate issue.
    pub fn stage_runtime_transition(
        &mut self,
        lifecycle: BackendLifecycleOperationV1,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        handle: &DormantRuntimeHandleV1,
    ) -> Result<ObjectDigest, RuntimeBackendError> {
        if !matches!(
            lifecycle,
            BackendLifecycleOperationV1::Freeze | BackendLifecycleOperationV1::Thaw
        ) {
            return Err(RuntimeBackendError::StateConflict);
        }
        self.revalidate()?;
        self.stage_lifecycle(lifecycle, operation, sequence, &handle.commitment)
    }

    /// Stages one protected Stop/Kill-stop handoff including its exact deadline.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeBackendError`] for stale currentness or duplicate issue.
    pub fn stage_stop(
        &mut self,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        handle: &DormantRuntimeHandleV1,
        deadline: BackendStopDeadlineV1,
    ) -> Result<ObjectDigest, RuntimeBackendError> {
        self.revalidate()?;
        let request = self
            .authority
            .issue_protected_stop(operation, sequence, &handle.commitment, deadline)
            .map_err(|_| RuntimeBackendError::InvalidSequence)?;
        self.remember_lifecycle_request(request, sequence)
    }

    /// Begins dormant Kill as a bounded graceful Stop.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeBackendError`] when currentness is stale or the exact
    /// stop request was already issued.
    pub fn begin_kill(
        &mut self,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        runtime: StoppableRuntime<DormantRuntimeHandleV1>,
        deadline: BackendStopDeadlineV1,
    ) -> Result<DormantKillStopOutcomeV1, RuntimeBackendError> {
        let runtime_handle = match &runtime {
            StoppableRuntime::Running(value) => value.handle(),
            StoppableRuntime::Frozen(value) => value.handle(),
        };
        let commitment = runtime_handle.commitment;
        self.stage_stop(operation, sequence, runtime_handle, deadline)?;
        Ok(match self.stop(operation, sequence, runtime, deadline) {
            BackendEffectOutcome::Complete((stopped, _)) => {
                DormantKillStopOutcomeV1::Stopped(stopped)
            }
            BackendEffectOutcome::RecoveryRequired(token) => {
                DormantKillStopOutcomeV1::Awaiting(DormantPendingKillV1 {
                    token,
                    runtime: commitment,
                    deadline,
                })
            }
            BackendEffectOutcome::Rejected { error, retry_state } => {
                DormantKillStopOutcomeV1::Rejected {
                    error,
                    runtime: retry_state,
                }
            }
        })
    }

    /// Reconciles Kill's graceful Stop from one exact authenticated observation.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeBackendError`] when the observation is foreign or
    /// quarantined. Absence and terminal Stop both produce the stopped typestate.
    pub fn recover_kill_stop(
        &mut self,
        pending: DormantPendingKillV1,
    ) -> Result<DormantKillStopOutcomeV1, RuntimeBackendError> {
        match self.recover_lifecycle(pending.token) {
            BackendRecoveryOutcome::Recovered(observation)
                if matches!(
                    observation.phase(),
                    BackendRuntimePhaseV1::Stopped | BackendRuntimePhaseV1::Absent
                ) =>
            {
                Ok(DormantKillStopOutcomeV1::Stopped(StoppedRuntime::new(
                    pending.runtime,
                    DormantRuntimeHandleV1 {
                        commitment: pending.runtime,
                    },
                )))
            }
            BackendRecoveryOutcome::Recovered(_) => Err(RuntimeBackendError::IntegrityFailure),
            BackendRecoveryOutcome::Retryable { token, .. } => {
                Ok(DormantKillStopOutcomeV1::Awaiting(DormantPendingKillV1 {
                    token,
                    runtime: pending.runtime,
                    deadline: pending.deadline,
                }))
            }
            BackendRecoveryOutcome::Quarantine { error, token } => {
                Ok(DormantKillStopOutcomeV1::Quarantined {
                    error,
                    pending: DormantPendingKillV1 {
                        token,
                        runtime: pending.runtime,
                        deadline: pending.deadline,
                    },
                })
            }
        }
    }

    /// Escalates an ambiguous Stop only after a signed protected-clock expiry.
    ///
    /// The resulting handoff authorizes complete-payload teardown, never a
    /// selected process kill. It remains observation-only and performs no host
    /// process or namespace effect.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeBackendError`] for stale ownership, early/foreign
    /// expiry evidence, signature failure, or duplicate forced issue.
    pub fn escalate_kill_after_deadline(
        &mut self,
        pending: DormantPendingKillV1,
        force_operation: BackendOperationIdV1,
        force_sequence: BackendOperationSequenceV1,
        evidence: SignedDormantKillDeadlineObservationV1,
    ) -> Result<DormantForcedKillHandoffV1, DormantKillEscalationErrorV1> {
        if let Err(error) = self.revalidate() {
            return Err(DormantKillEscalationErrorV1 {
                error,
                pending,
                proposed: None,
            });
        }
        if evidence.operation != pending.token.operation()
            || evidence.sequence != pending.token.sequence()
            || evidence.kill_operation != force_operation
            || evidence.kill_sequence != force_sequence
            || evidence.stop_request_commitment != pending.token.request_commitment()
            || evidence.runtime != pending.runtime
            || evidence.deadline != pending.deadline
            || evidence.host_boot_id != self.authority.host_verifier().boot_id()
            || evidence.stop_started_boottime_nanoseconds == 0
            || evidence.observed_boottime_nanoseconds < evidence.stop_started_boottime_nanoseconds
            || evidence.observed_boottime_nanoseconds - evidence.stop_started_boottime_nanoseconds
                < pending.deadline.after_nanoseconds()
            || force_sequence <= pending.token.sequence()
        {
            return Err(DormantKillEscalationErrorV1 {
                error: RuntimeBackendError::IntegrityFailure,
                pending,
                proposed: None,
            });
        }
        let message = dormant_kill_deadline_signing_message_v1(
            self.host_evidence_authority(),
            evidence.operation,
            evidence.sequence,
            evidence.kill_operation,
            evidence.kill_sequence,
            evidence.stop_request_commitment,
            evidence.runtime,
            evidence.deadline,
            evidence.host_boot_id,
            evidence.stop_started_boottime_nanoseconds,
            evidence.observed_boottime_nanoseconds,
        );
        if let Err(error) = verify_peer_signature(
            self.authority.host_verifier().public_key(),
            &message,
            &evidence.signature,
        ) {
            return Err(DormantKillEscalationErrorV1 {
                error,
                pending,
                proposed: None,
            });
        }
        let request_commitment = forced_kill_request_commitment(
            force_operation,
            force_sequence,
            pending.runtime,
            pending.token.request_commitment(),
            evidence.host_boot_id,
            evidence.stop_started_boottime_nanoseconds,
            evidence.observed_boottime_nanoseconds,
        );
        let protected_request = self.authority.issue_protected_kill(
            force_operation,
            force_sequence,
            &pending.runtime,
            pending.token.request_commitment(),
            evidence.host_boot_id,
            evidence.stop_started_boottime_nanoseconds,
            evidence.observed_boottime_nanoseconds,
        );
        if !matches!(protected_request, Ok(value) if value == request_commitment) {
            return Err(DormantKillEscalationErrorV1 {
                error: RuntimeBackendError::InvalidSequence,
                pending,
                proposed: Some(DormantForcedKillHandoffV1 {
                    operation: force_operation,
                    sequence: force_sequence,
                    request_commitment,
                    runtime: evidence.runtime,
                }),
            });
        }
        self.authorized_lifecycle_requests
            .insert(request_commitment);
        self.last_lifecycle_operation_sequence = self
            .last_lifecycle_operation_sequence
            .max(force_sequence.get());
        Ok(DormantForcedKillHandoffV1 {
            operation: force_operation,
            sequence: force_sequence,
            request_commitment,
            runtime: pending.runtime,
        })
    }

    /// Consumes an authenticated forced-teardown observation into stopped state.
    ///
    /// Missing, stale, replayed, or non-absent evidence produces a rejected or
    /// recoverable effect outcome according to whether the boundary crossed.
    pub fn complete_forced_kill(
        &mut self,
        handoff: DormantForcedKillHandoffV1,
    ) -> BackendEffectOutcome<
        StoppedRuntime<DormantRuntimeHandleV1>,
        DormantForcedKillHandoffV1,
        DormantLifecycleRecoveryHandleV1,
    > {
        if !self
            .authorized_lifecycle_requests
            .remove(&handoff.request_commitment)
        {
            return rejected(RuntimeBackendError::Equivocation, handoff);
        }
        let recovery = match lifecycle_token(
            handoff.operation,
            handoff.sequence,
            *handoff.runtime.currentness(),
            handoff.runtime.plan_commitment(),
            handoff.request_commitment,
            BackendLifecycleOperationV1::Kill,
            Some(handoff.runtime.handle()),
        ) {
            Ok(token) => token,
            Err(error) => return rejected(error, handoff),
        };
        if self
            .cross_lifecycle_effect(handoff.request_commitment)
            .is_err()
        {
            return BackendEffectOutcome::RecoveryRequired(recovery);
        }
        match self.take_runtime(
            handoff.operation,
            handoff.sequence,
            BackendLifecycleOperationV1::Kill,
            handoff.request_commitment,
            &handoff.runtime,
            BackendRuntimePhaseV1::Absent,
        ) {
            Ok(_) => BackendEffectOutcome::Complete(StoppedRuntime::new(
                handoff.runtime,
                DormantRuntimeHandleV1 {
                    commitment: handoff.runtime,
                },
            )),
            Err(_) => BackendEffectOutcome::RecoveryRequired(recovery),
        }
    }

    /// Stages and applies Kill's final resource destruction edge.
    ///
    /// This edge is required after either graceful Stop or forced complete-
    /// payload absence; it does not treat process exit as resource destruction.
    #[must_use]
    pub fn finish_kill(
        &mut self,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        stopped: StoppedRuntime<DormantRuntimeHandleV1>,
    ) -> BackendEffectOutcome<
        DestroyedRuntime,
        DestroyableRuntime<DormantPreparedHandleV1, DormantRuntimeHandleV1>,
        DormantLifecycleRecoveryHandleV1,
    > {
        if let Err(error) = self.stage_destroy_stopped(operation, sequence, &stopped) {
            return rejected(error, DestroyableRuntime::Stopped(stopped));
        }
        self.destroy(operation, sequence, DestroyableRuntime::Stopped(stopped))
    }

    /// Stages one protected Destroy handoff for exact one-shot consumption.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeBackendError`] for stale currentness or duplicate issue.
    pub fn stage_destroy_prepared(
        &mut self,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        prepared: &PreparedRuntime<DormantPreparedHandleV1>,
    ) -> Result<ObjectDigest, RuntimeBackendError> {
        self.revalidate()?;
        self.stage_lifecycle(
            BackendLifecycleOperationV1::Destroy,
            operation,
            sequence,
            &prepared.handle().commitment,
        )
    }

    /// Stages protected Destroy for a backend-issued stopped typestate.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeBackendError`] for stale currentness or duplicate issue.
    pub fn stage_destroy_stopped(
        &mut self,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        stopped: &StoppedRuntime<DormantRuntimeHandleV1>,
    ) -> Result<ObjectDigest, RuntimeBackendError> {
        self.revalidate()?;
        self.stage_lifecycle(
            BackendLifecycleOperationV1::Destroy,
            operation,
            sequence,
            &stopped.handle().commitment,
        )
    }

    /// Stages one exact read-only runtime inspection.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeBackendError`] for stale currentness or another pending
    /// inspection of the same runtime handle.
    pub fn stage_inspection(
        &mut self,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        handle: &DormantRuntimeHandleV1,
    ) -> Result<ObjectDigest, RuntimeBackendError> {
        self.revalidate()?;
        let request = self
            .authority
            .issue_protected_inspect(operation, sequence, &handle.commitment)
            .map_err(|_| RuntimeBackendError::InvalidSequence)?;
        self.authorized_inspections
            .insert(handle.commitment.handle(), (operation, sequence, request));
        self.last_lifecycle_operation_sequence =
            self.last_lifecycle_operation_sequence.max(sequence.get());
        Ok(request)
    }

    fn stage_lifecycle(
        &mut self,
        lifecycle: BackendLifecycleOperationV1,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        runtime: &RuntimeHandleCommitmentV1,
    ) -> Result<ObjectDigest, RuntimeBackendError> {
        let request = match lifecycle {
            BackendLifecycleOperationV1::Start => self
                .authority
                .issue_protected_start(operation, sequence, runtime),
            BackendLifecycleOperationV1::Freeze => self
                .authority
                .issue_protected_freeze(operation, sequence, runtime),
            BackendLifecycleOperationV1::Thaw => self
                .authority
                .issue_protected_thaw(operation, sequence, runtime),
            BackendLifecycleOperationV1::Destroy => self
                .authority
                .issue_protected_destroy(operation, sequence, runtime),
            BackendLifecycleOperationV1::Prepare
            | BackendLifecycleOperationV1::Stop
            | BackendLifecycleOperationV1::Inspect
            | BackendLifecycleOperationV1::Kill => {
                return Err(RuntimeBackendError::StateConflict);
            }
        }
        .map_err(|_| RuntimeBackendError::InvalidSequence)?;
        self.remember_lifecycle_request(request, sequence)
    }

    fn remember_lifecycle_request(
        &mut self,
        request: ObjectDigest,
        sequence: BackendOperationSequenceV1,
    ) -> Result<ObjectDigest, RuntimeBackendError> {
        self.authorized_lifecycle_requests.insert(request);
        self.last_lifecycle_operation_sequence =
            self.last_lifecycle_operation_sequence.max(sequence.get());
        Ok(request)
    }

    /// Queues one verifier-minted runtime observation for exact matching.
    fn submit_runtime_observation(
        &mut self,
        observation: BackendRuntimeInspectionV1,
    ) -> Result<(), RuntimeBackendError> {
        self.validate_runtime_observation(&observation)?;
        let is_next = observation.sequence().get()
            == self
                .last_observation_sequence
                .checked_add(1)
                .ok_or(RuntimeBackendError::InvalidSequence)?;
        let is_terminal_replay = self
            .authority
            .is_exact_terminal_observation(&observation)
            .map_err(|_| RuntimeBackendError::IntegrityFailure)?;
        if !is_next && !is_terminal_replay {
            return Err(RuntimeBackendError::InvalidSequence);
        }
        if !self.runtime_observations.is_empty() || !self.execution_observations.is_empty() {
            return Err(RuntimeBackendError::ResourceExhausted);
        }
        self.runtime_observations.push_back(observation);
        Ok(())
    }

    /// Verifies and queues one operation-bound signed runtime observation.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeBackendError`] for stale ownership, signature failure,
    /// request substitution, replay, or bounded inbox exhaustion.
    pub fn submit_signed_runtime_observation(
        &mut self,
        operation: BackendOperationIdV1,
        operation_sequence: BackendOperationSequenceV1,
        lifecycle_operation: BackendLifecycleOperationV1,
        request_commitment: ObjectDigest,
        expected: &RuntimeHandleCommitmentV1,
        envelope: SignedBackendRuntimeInspectionV1,
    ) -> Result<(), RuntimeBackendError> {
        self.revalidate()?;
        let observation = self
            .host_evidence_verifier
            .verify_runtime_inspection(
                self.host_evidence_authority(),
                operation,
                operation_sequence,
                lifecycle_operation,
                request_commitment,
                expected,
                envelope,
            )
            .map_err(|_| RuntimeBackendError::IntegrityFailure)?;
        self.submit_runtime_observation(observation)
    }

    /// Authenticates the exact outstanding agent response and releases its backend request.
    ///
    /// The returned request is accepted by [`RuntimeBackend::exec`] once. No
    /// second protected dispatch is acquired and no second peer journal is
    /// opened or locked.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeBackendError`] for stale currentness, an unsolicited or
    /// substituted response, invalid signature, unsupported phase, or replay.
    pub fn accept_agent_execution_outcome(
        &mut self,
        signed: SignedAgentOutcomeV1,
    ) -> Result<BackendExecutionRequestV1, RuntimeBackendError> {
        self.revalidate()?;
        if !self.execution_observations.is_empty() || !self.runtime_observations.is_empty() {
            return Err(RuntimeBackendError::ResourceExhausted);
        }
        let peer = *self.authority.agent_peer();
        let session = self
            .agent_session
            .as_mut()
            .ok_or(RuntimeBackendError::AgentUnavailable)?;
        let outstanding = session
            .outstanding
            .as_ref()
            .ok_or(RuntimeBackendError::StateConflict)?;
        let (outcome, signature) = signed.into_parts();
        if outcome.session() != session.binding
            || outcome.sequence() != outstanding.agent_request.sequence()
            || outcome.operation_id() != outstanding.agent_request.operation_id()
            || outcome.request_commitment() != outstanding.agent_request.request_commitment()
        {
            return Err(RuntimeBackendError::IntegrityFailure);
        }
        let message = agent_outcome_signing_message_v1(
            peer.channel_binding(),
            &outstanding.agent_request,
            &outcome,
        );
        verify_peer_signature(peer.public_key(), &message, &signature)?;
        let phase = core_execution_phase(outcome.phase())?;
        let next_observation = self
            .last_observation_sequence
            .checked_add(1)
            .filter(|value| *value != u64::MAX)
            .ok_or(RuntimeBackendError::InvalidSequence)?;
        let observation_sequence = ObservationSequence::new(next_observation);
        let expected = BackendExecutionInspectionRequestV1::new(
            peer.authority_binding(),
            outstanding.backend_request.operation(),
            outstanding.backend_request.sequence(),
            outstanding.backend_request.effect_request_digest(),
            outstanding.execution,
            outstanding.backend_request.specification_digest(),
            outstanding.backend_request.admission_commitment(),
            outstanding.runtime,
            self.authority.currentness().payload_boot_id(),
        )
        .map_err(|_| RuntimeBackendError::IntegrityFailure)?;
        if outstanding.agent_request.backend_request_binding()
            != backend_execution_inspection_binding_v1(&expected)
        {
            return Err(RuntimeBackendError::IntegrityFailure);
        }
        let input = aos_sandbox_core::runtime_backend::BackendExecutionInspectionInputV1 {
            authority_binding: ObjectDigest::from_bytes([0; 32]),
            operation: expected.operation(),
            operation_sequence: expected.operation_sequence(),
            effect_request_digest: expected.effect_request_digest(),
            execution: expected.execution(),
            specification_digest: expected.specification_digest(),
            admission_commitment: expected.admission_commitment(),
            runtime: *expected.runtime(),
            payload_boot_id: expected.payload_boot_id(),
            phase,
            sequence: observation_sequence,
            observation_commitment: ObjectDigest::from_bytes([0; 32]),
        };
        let envelope = SignedBackendExecutionInspectionV1::new(
            input,
            outcome.session().digest(),
            outcome.sequence().get(),
            *outcome.operation_id().as_bytes(),
            outcome.request_commitment(),
            outcome.outcome_commitment(),
            outcome.result_bytes().to_vec(),
            outcome.result_digest(),
            signature,
        );
        let observation = self
            .agent_evidence_verifier
            .verify_execution_inspection(&expected, observation_sequence, envelope)
            .map_err(|_| RuntimeBackendError::IntegrityFailure)?;
        let request_binding = execution_request_binding(&outstanding.backend_request);
        if self
            .authorized_execution_requests
            .contains_key(&request_binding)
        {
            return Err(RuntimeBackendError::Equivocation);
        }
        let recovery = execution_recovery_token(
            &outstanding.backend_request,
            outstanding.runtime,
            outstanding.execution,
        )?;
        let next_operation_sequence = session
            .next_operation_sequence
            .checked_next()
            .map_err(|_| RuntimeBackendError::InvalidSequence)?;
        let outstanding = session
            .outstanding
            .take()
            .ok_or(RuntimeBackendError::StateConflict)?;
        session.next_operation_sequence = next_operation_sequence;
        self.authorized_execution_requests
            .insert(request_binding, recovery);
        self.execution_observations.push_back(observation);
        Ok(outstanding.backend_request)
    }

    /// Verifies and submits one signed response for an ambiguous exec handoff.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeBackendError`] for stale protected ownership, foreign
    /// evidence authority/runtime, or a bounded inbox overflow.
    pub fn submit_signed_execution_observation(
        &mut self,
        token: &RuntimeRecoveryToken<DormantExecutionRecoveryHandleV1>,
        observation_sequence: ObservationSequence,
        envelope: SignedBackendExecutionInspectionV1,
    ) -> Result<(), RuntimeBackendError> {
        let handle = token.backend_handle();
        let expected = BackendExecutionInspectionRequestV1::new(
            self.agent_evidence_authority(),
            token.operation(),
            token.sequence(),
            handle.effect_request_digest,
            handle.execution,
            handle.specification_digest,
            handle.admission_commitment,
            handle.runtime,
            self.authority.currentness().payload_boot_id(),
        )
        .map_err(|_| RuntimeBackendError::IntegrityFailure)?;
        let observation = self
            .agent_evidence_verifier
            .verify_execution_inspection(&expected, observation_sequence, envelope)
            .map_err(|_| RuntimeBackendError::IntegrityFailure)?;
        self.submit_execution_observation(observation)
    }

    fn submit_execution_observation(
        &mut self,
        observation: BackendExecutionInspectionV1,
    ) -> Result<(), RuntimeBackendError> {
        self.revalidate()?;
        if observation.authority_binding() != self.agent_evidence_authority()
            || observation.runtime() != self.authority.currentness().runtime()
        {
            return Err(RuntimeBackendError::IntegrityFailure);
        }
        if observation.sequence().get()
            != self
                .last_observation_sequence
                .checked_add(1)
                .ok_or(RuntimeBackendError::InvalidSequence)?
        {
            return Err(RuntimeBackendError::InvalidSequence);
        }
        if !self.execution_observations.is_empty() || !self.runtime_observations.is_empty() {
            return Err(RuntimeBackendError::ResourceExhausted);
        }
        self.execution_observations.push_back(observation);
        Ok(())
    }

    fn revalidate(&self) -> Result<(), RuntimeBackendError> {
        self.authority
            .revalidate()
            .map_err(|_| RuntimeBackendError::StaleCurrentness)
    }

    fn agent_evidence_authority(&self) -> ObjectDigest {
        self.authority.currentness().authority_context()
    }

    fn host_evidence_authority(&self) -> ObjectDigest {
        self.authority.host_verifier().authority_binding()
    }

    fn validate_runtime_observation(
        &self,
        observation: &BackendRuntimeInspectionV1,
    ) -> Result<(), RuntimeBackendError> {
        self.revalidate()?;
        if observation.authority_binding() != self.host_evidence_authority()
            || observation.commitment() != self.authority.currentness().runtime()
        {
            return Err(RuntimeBackendError::IntegrityFailure);
        }
        Ok(())
    }

    fn take_runtime(
        &mut self,
        operation: BackendOperationIdV1,
        operation_sequence: BackendOperationSequenceV1,
        lifecycle_operation: BackendLifecycleOperationV1,
        request_commitment: ObjectDigest,
        expected: &RuntimeHandleCommitmentV1,
        phase: BackendRuntimePhaseV1,
    ) -> Result<BackendRuntimeInspectionV1, RuntimeBackendError> {
        let observation = self
            .runtime_observations
            .front()
            .copied()
            .ok_or(RuntimeBackendError::AgentUnavailable)?;
        self.validate_runtime_observation(&observation)?;
        if observation.operation() != operation
            || observation.operation_sequence() != operation_sequence
            || observation.lifecycle_operation() != lifecycle_operation
            || observation.request_commitment() != request_commitment
            || observation.commitment() != expected
            || observation.phase() != phase
        {
            return Err(RuntimeBackendError::IntegrityFailure);
        }
        self.authority
            .complete_lifecycle_effect_with_observation(&observation)
            .map_err(|_| RuntimeBackendError::IntegrityFailure)?;
        self.runtime_observations.pop_front();
        self.last_observation_sequence = self
            .last_observation_sequence
            .max(observation.sequence().get());
        Ok(observation)
    }

    fn cross_lifecycle_effect(
        &mut self,
        request_commitment: ObjectDigest,
    ) -> Result<(), RuntimeBackendError> {
        self.authority
            .consume_pending_lifecycle(request_commitment)
            .map_err(|_| RuntimeBackendError::StateConflict)
    }

    fn take_execution(
        &mut self,
        expected: &BackendExecutionInspectionRequestV1,
    ) -> Result<BackendExecutionInspectionV1, RuntimeBackendError> {
        let observation = self.peek_execution(expected)?;
        self.authority
            .consume_execution_observation(&observation)
            .map_err(|_| RuntimeBackendError::IntegrityFailure)?;
        self.execution_observations.pop_front();
        self.last_observation_sequence = observation.sequence().get();
        Ok(observation)
    }

    fn peek_execution(
        &self,
        expected: &BackendExecutionInspectionRequestV1,
    ) -> Result<BackendExecutionInspectionV1, RuntimeBackendError> {
        let observation = self
            .execution_observations
            .front()
            .copied()
            .ok_or(RuntimeBackendError::AgentUnavailable)?;
        if observation.authority_binding() != expected.evidence_authority_binding()
            || observation.operation() != expected.operation()
            || observation.operation_sequence() != expected.operation_sequence()
            || observation.effect_request_digest() != expected.effect_request_digest()
            || observation.execution() != expected.execution()
            || observation.specification_digest() != expected.specification_digest()
            || observation.admission_commitment() != expected.admission_commitment()
            || observation.runtime() != expected.runtime()
            || observation.payload_boot_id() != expected.payload_boot_id()
        {
            return Err(RuntimeBackendError::IntegrityFailure);
        }
        Ok(observation)
    }
}

impl RuntimeBackend for DormantProtectedRuntimeBackendV1<'_> {
    type PreparedHandle = DormantPreparedHandleV1;
    type RuntimeHandle = DormantRuntimeHandleV1;
    type ExecutionHandle = DormantExecutionHandleV1;
    type LifecycleRecoveryHandle = DormantLifecycleRecoveryHandleV1;
    type ExecutionRecoveryHandle = DormantExecutionRecoveryHandleV1;

    fn probe(&mut self) -> Result<BackendProbeReportV1, RuntimeBackendError> {
        self.revalidate()?;
        Ok(self.probe.clone())
    }

    fn prepare(
        &mut self,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        plan: ResolvedRuntimePlanV1,
    ) -> BackendEffectOutcome<
        PreparedRuntime<Self::PreparedHandle>,
        ResolvedRuntimePlanV1,
        Self::LifecycleRecoveryHandle,
    > {
        if self.revalidate().is_err()
            || plan.currentness() != self.authority.currentness().runtime().currentness()
            || plan.plan_commitment() != self.authority.currentness().runtime().plan_commitment()
        {
            return rejected(RuntimeBackendError::StaleCurrentness, plan);
        }
        if self
            .probe
            .capabilities()
            .satisfies(plan.required_capabilities())
            .is_err()
        {
            return rejected(RuntimeBackendError::UnsupportedPlan, plan);
        }
        let request = lifecycle_request_commitment(
            BackendLifecycleOperationV1::Prepare,
            operation,
            sequence,
            plan.plan_commitment(),
            None,
        );
        if !self.authorized_lifecycle_requests.remove(&request) {
            return rejected(RuntimeBackendError::Equivocation, plan);
        }
        let recovery = match lifecycle_token(
            operation,
            sequence,
            *plan.currentness(),
            plan.plan_commitment(),
            request,
            BackendLifecycleOperationV1::Prepare,
            None,
        ) {
            Ok(token) => token,
            Err(error) => return rejected(error, plan),
        };
        if self.cross_lifecycle_effect(request).is_err() {
            return BackendEffectOutcome::RecoveryRequired(recovery);
        }
        match self.runtime_observations.front().copied() {
            Some(observation)
                if self.validate_runtime_observation(&observation).is_ok()
                    && observation.phase() == BackendRuntimePhaseV1::Prepared
                    && observation.operation() == operation
                    && observation.operation_sequence() == sequence
                    && observation.lifecycle_operation()
                        == BackendLifecycleOperationV1::Prepare
                    && observation.request_commitment() == request
                    && observation.commitment().currentness() == plan.currentness()
                    && observation.commitment().plan_commitment() == plan.plan_commitment() =>
            {
                if self
                    .authority
                    .complete_lifecycle_effect_with_observation(&observation)
                    .is_err()
                {
                    return BackendEffectOutcome::RecoveryRequired(recovery);
                }
                self.runtime_observations.pop_front();
                self.last_observation_sequence = self
                    .last_observation_sequence
                    .max(observation.sequence().get());
                let handle = DormantPreparedHandleV1 {
                    commitment: *observation.commitment(),
                };
                BackendEffectOutcome::Complete(PreparedRuntime::new(plan, handle))
            }
            Some(_) | None => BackendEffectOutcome::RecoveryRequired(recovery),
        }
    }

    fn start(
        &mut self,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        prepared: PreparedRuntime<Self::PreparedHandle>,
    ) -> BackendEffectOutcome<
        (
            RunningRuntime<Self::RuntimeHandle>,
            BackendStartObservationV1,
        ),
        PreparedRuntime<Self::PreparedHandle>,
        Self::LifecycleRecoveryHandle,
    > {
        let (plan, prepared_handle) = prepared.into_parts();
        if self.revalidate().is_err()
            || prepared_handle.commitment.currentness() != plan.currentness()
            || prepared_handle.commitment.plan_commitment() != plan.plan_commitment()
        {
            return rejected(
                RuntimeBackendError::StaleCurrentness,
                PreparedRuntime::new(plan, prepared_handle),
            );
        }
        let request = lifecycle_request_commitment(
            BackendLifecycleOperationV1::Start,
            operation,
            sequence,
            plan.plan_commitment(),
            Some(prepared_handle.commitment.handle()),
        );
        if !self.authorized_lifecycle_requests.remove(&request) {
            return rejected(
                RuntimeBackendError::Equivocation,
                PreparedRuntime::new(plan, prepared_handle),
            );
        }
        let recovery = match lifecycle_token(
            operation,
            sequence,
            *plan.currentness(),
            plan.plan_commitment(),
            request,
            BackendLifecycleOperationV1::Start,
            Some(prepared_handle.commitment.handle()),
        ) {
            Ok(token) => token,
            Err(error) => return rejected(error, PreparedRuntime::new(plan, prepared_handle)),
        };
        if self.cross_lifecycle_effect(request).is_err() {
            return BackendEffectOutcome::RecoveryRequired(recovery);
        }
        match self.take_runtime(
            operation,
            sequence,
            BackendLifecycleOperationV1::Start,
            request,
            &prepared_handle.commitment,
            BackendRuntimePhaseV1::Running,
        ) {
            Ok(observation) => BackendEffectOutcome::Complete((
                RunningRuntime::new(
                    prepared_handle.commitment,
                    DormantRuntimeHandleV1 {
                        commitment: prepared_handle.commitment,
                    },
                ),
                observation,
            )),
            Err(_) => BackendEffectOutcome::RecoveryRequired(recovery),
        }
    }

    fn exec(
        &mut self,
        runtime: &mut RunningRuntime<Self::RuntimeHandle>,
        request: BackendExecutionRequestV1,
    ) -> BackendExecutionOutcome<Self::ExecutionHandle, Self::ExecutionRecoveryHandle> {
        let request_binding = execution_request_binding(&request);
        let recovery = match self.authorized_execution_requests.remove(&request_binding) {
            Some(recovery) => recovery,
            None => {
                return BackendExecutionOutcome::Rejected(RuntimeBackendError::Equivocation);
            }
        };
        let authorized_execution = recovery.backend_handle().execution;
        if recovery.currentness() != runtime.commitment().currentness()
            || recovery.plan_commitment() != runtime.commitment().plan_commitment()
        {
            return BackendExecutionOutcome::RecoveryRequired(recovery);
        }
        if self.revalidate().is_err() {
            return BackendExecutionOutcome::RecoveryRequired(recovery);
        }
        let specification = match decode_execution_spec_v1(
            request.specification_bytes(),
            DecodeLimits {
                maximum_bytes: request.specification_bytes().len(),
                maximum_collection_items: 65_536,
                maximum_total_items: 262_144,
                maximum_byte_string_bytes: 15 * 1_048_576,
                maximum_text_bytes: 1_048_576,
                maximum_depth: 128,
            },
        ) {
            Ok(value) => value,
            Err(_) => {
                return BackendExecutionOutcome::RecoveryRequired(recovery);
            }
        };
        if specification.execution() != authorized_execution {
            return BackendExecutionOutcome::RecoveryRequired(recovery);
        }
        let expected = match BackendExecutionInspectionRequestV1::new(
            self.agent_evidence_authority(),
            request.operation(),
            request.sequence(),
            request.effect_request_digest(),
            specification.execution(),
            request.specification_digest(),
            request.admission_commitment(),
            *runtime.commitment(),
            self.authority.currentness().payload_boot_id(),
        ) {
            Ok(value) => value,
            Err(_) => {
                return BackendExecutionOutcome::RecoveryRequired(recovery);
            }
        };
        let observation = match self.peek_execution(&expected) {
            Ok(observation)
                if matches!(
                    observation.phase(),
                    BackendExecutionPhaseV1::Authorized
                        | BackendExecutionPhaseV1::Starting
                        | BackendExecutionPhaseV1::Running
                ) =>
            {
                observation
            }
            Ok(_) | Err(_) => {
                return BackendExecutionOutcome::RecoveryRequired(recovery);
            }
        };
        let handle = match BackendExecutionHandle::new(
            specification.execution(),
            request.specification_digest(),
            *runtime.commitment(),
            DormantExecutionHandleV1 {
                observation_commitment: observation.observation_commitment(),
            },
        ) {
            Ok(handle) => handle,
            Err(_) => {
                return BackendExecutionOutcome::RecoveryRequired(recovery);
            }
        };
        match self.take_execution(&expected) {
            Ok(_) => BackendExecutionOutcome::Complete(handle),
            Err(_) => BackendExecutionOutcome::RecoveryRequired(recovery),
        }
    }

    fn freeze(
        &mut self,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        runtime: RunningRuntime<Self::RuntimeHandle>,
    ) -> BackendEffectOutcome<
        (
            FrozenRuntime<Self::RuntimeHandle>,
            BackendFreezeObservationV1,
        ),
        RunningRuntime<Self::RuntimeHandle>,
        Self::LifecycleRecoveryHandle,
    > {
        let (commitment, handle) = runtime.into_parts();
        runtime_transition(
            self,
            operation,
            sequence,
            commitment,
            handle,
            BackendLifecycleOperationV1::Freeze,
            BackendRuntimePhaseV1::Frozen,
            |commitment, handle| FrozenRuntime::new(commitment, handle),
            |commitment, handle| RunningRuntime::new(commitment, handle),
        )
    }

    fn thaw(
        &mut self,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        runtime: FrozenRuntime<Self::RuntimeHandle>,
    ) -> BackendEffectOutcome<
        (
            RunningRuntime<Self::RuntimeHandle>,
            BackendRuntimeInspectionV1,
        ),
        FrozenRuntime<Self::RuntimeHandle>,
        Self::LifecycleRecoveryHandle,
    > {
        let (commitment, handle) = runtime.into_parts();
        runtime_transition(
            self,
            operation,
            sequence,
            commitment,
            handle,
            BackendLifecycleOperationV1::Thaw,
            BackendRuntimePhaseV1::Running,
            |commitment, handle| RunningRuntime::new(commitment, handle),
            |commitment, handle| FrozenRuntime::new(commitment, handle),
        )
    }

    fn stop(
        &mut self,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        runtime: StoppableRuntime<Self::RuntimeHandle>,
        deadline: BackendStopDeadlineV1,
    ) -> BackendEffectOutcome<
        (
            StoppedRuntime<Self::RuntimeHandle>,
            BackendStopObservationV1,
        ),
        StoppableRuntime<Self::RuntimeHandle>,
        Self::LifecycleRecoveryHandle,
    > {
        let (commitment, handle, was_running) = match runtime {
            StoppableRuntime::Running(value) => {
                let (commitment, handle) = value.into_parts();
                (commitment, handle, true)
            }
            StoppableRuntime::Frozen(value) => {
                let (commitment, handle) = value.into_parts();
                (commitment, handle, false)
            }
        };
        let request = stop_request_commitment(operation, sequence, commitment, deadline);
        if !self.authorized_lifecycle_requests.remove(&request) {
            return rejected(
                RuntimeBackendError::Equivocation,
                if was_running {
                    StoppableRuntime::Running(RunningRuntime::new(commitment, handle))
                } else {
                    StoppableRuntime::Frozen(FrozenRuntime::new(commitment, handle))
                },
            );
        }
        let recovery = match lifecycle_token(
            operation,
            sequence,
            *commitment.currentness(),
            commitment.plan_commitment(),
            request,
            BackendLifecycleOperationV1::Stop,
            Some(commitment.handle()),
        ) {
            Ok(token) => token,
            Err(error) => {
                return rejected(
                    error,
                    if was_running {
                        StoppableRuntime::Running(RunningRuntime::new(commitment, handle))
                    } else {
                        StoppableRuntime::Frozen(FrozenRuntime::new(commitment, handle))
                    },
                );
            }
        };
        if self.cross_lifecycle_effect(request).is_err() {
            return BackendEffectOutcome::RecoveryRequired(recovery);
        }
        match self.take_runtime(
            operation,
            sequence,
            BackendLifecycleOperationV1::Stop,
            request,
            &commitment,
            BackendRuntimePhaseV1::Stopped,
        ) {
            Ok(observation) => BackendEffectOutcome::Complete((
                StoppedRuntime::new(commitment, handle),
                observation,
            )),
            Err(_) => BackendEffectOutcome::RecoveryRequired(recovery),
        }
    }

    fn inspect(
        &mut self,
        expected: &RuntimeHandleCommitmentV1,
    ) -> Result<BackendRuntimeInspectionV1, RuntimeBackendError> {
        let (operation, sequence, request) = self
            .authorized_inspections
            .remove(&expected.handle())
            .ok_or(RuntimeBackendError::Equivocation)?;
        self.cross_lifecycle_effect(request)?;
        self.take_runtime(
            operation,
            sequence,
            BackendLifecycleOperationV1::Inspect,
            request,
            expected,
            self.runtime_observations.front().map_or(
                BackendRuntimePhaseV1::Failed,
                BackendRuntimeInspectionV1::phase,
            ),
        )
    }

    fn inspect_execution(
        &mut self,
        expected: &BackendExecutionInspectionRequestV1,
    ) -> Result<BackendExecutionInspectionV1, RuntimeBackendError> {
        self.take_execution(expected)
    }

    fn recover_lifecycle(
        &mut self,
        token: RuntimeRecoveryToken<Self::LifecycleRecoveryHandle>,
    ) -> BackendRecoveryOutcome<BackendRuntimeInspectionV1, Self::LifecycleRecoveryHandle> {
        let handle = token.backend_handle();
        match self.runtime_observations.front().copied() {
            Some(observation)
                if self.validate_runtime_observation(&observation).is_ok()
                    && observation.operation() == token.operation()
                    && observation.operation_sequence() == token.sequence()
                    && observation.lifecycle_operation() == handle.lifecycle_operation
                    && observation.request_commitment() == token.request_commitment()
                    && observation.commitment().currentness() == token.currentness()
                    && observation.commitment().plan_commitment() == token.plan_commitment()
                    && recovery_phase_matches(handle.lifecycle_operation, observation.phase())
                    && handle
                        .runtime_handle
                        .is_none_or(|value| observation.commitment().handle() == value) =>
            {
                if self
                    .authority
                    .complete_lifecycle_effect_with_observation(&observation)
                    .is_err()
                {
                    return BackendRecoveryOutcome::Quarantine {
                        error: RuntimeBackendError::IntegrityFailure,
                        token,
                    };
                }
                self.runtime_observations.pop_front();
                self.last_observation_sequence = self
                    .last_observation_sequence
                    .max(observation.sequence().get());
                BackendRecoveryOutcome::Recovered(observation)
            }
            Some(_) => BackendRecoveryOutcome::Quarantine {
                error: RuntimeBackendError::IntegrityFailure,
                token,
            },
            None => BackendRecoveryOutcome::Retryable {
                error: RuntimeBackendError::AgentUnavailable,
                token,
            },
        }
    }

    fn recover_lifecycle_after_crash(
        &mut self,
        record: &BackendLifecycleRecoveryRecordV1,
    ) -> Result<BackendRuntimeInspectionV1, RuntimeBackendError> {
        self.revalidate()?;
        if record.authority_binding() != self.host_evidence_authority() {
            return Err(RuntimeBackendError::IntegrityFailure);
        }
        let observation = self
            .runtime_observations
            .front()
            .copied()
            .ok_or(RuntimeBackendError::AgentUnavailable)?;
        self.validate_runtime_observation(&observation)?;
        if observation.commitment().currentness() != record.currentness()
            || observation.operation() != record.operation()
            || observation.operation_sequence() != record.sequence()
            || observation.lifecycle_operation() != record.lifecycle_operation()
            || observation.request_commitment() != record.request_commitment()
            || observation.commitment().plan_commitment() != record.plan_commitment()
            || !recovery_phase_matches(record.lifecycle_operation(), observation.phase())
            || record
                .runtime_handle()
                .is_some_and(|handle| observation.commitment().handle() != handle)
        {
            return Err(RuntimeBackendError::IntegrityFailure);
        }
        self.authority
            .complete_lifecycle_effect_with_observation(&observation)
            .map_err(|_| RuntimeBackendError::IntegrityFailure)?;
        self.runtime_observations.pop_front();
        self.last_observation_sequence = self
            .last_observation_sequence
            .max(observation.sequence().get());
        Ok(observation)
    }

    fn recover_execution_handoff(
        &mut self,
        token: RuntimeRecoveryToken<Self::ExecutionRecoveryHandle>,
    ) -> BackendRecoveryOutcome<BackendExecutionInspectionV1, Self::ExecutionRecoveryHandle> {
        let handle = token.backend_handle();
        let expected = BackendExecutionInspectionRequestV1::new(
            self.agent_evidence_authority(),
            token.operation(),
            token.sequence(),
            handle.effect_request_digest,
            handle.execution,
            handle.specification_digest,
            handle.admission_commitment,
            handle.runtime,
            self.authority.currentness().payload_boot_id(),
        );
        let expected = match expected {
            Ok(value) => value,
            Err(_) => {
                return BackendRecoveryOutcome::Quarantine {
                    error: RuntimeBackendError::IntegrityFailure,
                    token,
                };
            }
        };
        match self.take_execution(&expected) {
            Ok(observation) => BackendRecoveryOutcome::Recovered(observation),
            Err(RuntimeBackendError::AgentUnavailable) => BackendRecoveryOutcome::Retryable {
                error: RuntimeBackendError::AgentUnavailable,
                token,
            },
            Err(_) => BackendRecoveryOutcome::Quarantine {
                error: RuntimeBackendError::IntegrityFailure,
                token,
            },
        }
    }

    fn destroy(
        &mut self,
        operation: BackendOperationIdV1,
        sequence: BackendOperationSequenceV1,
        runtime: DestroyableRuntime<Self::PreparedHandle, Self::RuntimeHandle>,
    ) -> BackendEffectOutcome<
        DestroyedRuntime,
        DestroyableRuntime<Self::PreparedHandle, Self::RuntimeHandle>,
        Self::LifecycleRecoveryHandle,
    > {
        let (commitment, retry) = match runtime {
            DestroyableRuntime::Prepared(prepared) => {
                let (plan, handle) = prepared.into_parts();
                let commitment = handle.commitment;
                (
                    commitment,
                    DestroyableRuntime::Prepared(PreparedRuntime::new(plan, handle)),
                )
            }
            DestroyableRuntime::Stopped(stopped) => {
                let (commitment, handle) = stopped.into_parts();
                (
                    commitment,
                    DestroyableRuntime::Stopped(StoppedRuntime::new(commitment, handle)),
                )
            }
        };
        let request = lifecycle_request_commitment(
            BackendLifecycleOperationV1::Destroy,
            operation,
            sequence,
            commitment.plan_commitment(),
            Some(commitment.handle()),
        );
        if !self.authorized_lifecycle_requests.remove(&request) {
            return rejected(RuntimeBackendError::Equivocation, retry);
        }
        let destroyed = match DestroyedRuntime::new(commitment.plan_commitment()) {
            Ok(value) => value,
            Err(_) => return rejected(RuntimeBackendError::IntegrityFailure, retry),
        };
        let recovery = match lifecycle_token(
            operation,
            sequence,
            *commitment.currentness(),
            commitment.plan_commitment(),
            request,
            BackendLifecycleOperationV1::Destroy,
            Some(commitment.handle()),
        ) {
            Ok(token) => token,
            Err(error) => return rejected(error, retry),
        };
        if self.cross_lifecycle_effect(request).is_err() {
            return BackendEffectOutcome::RecoveryRequired(recovery);
        }
        match self.take_runtime(
            operation,
            sequence,
            BackendLifecycleOperationV1::Destroy,
            request,
            &commitment,
            BackendRuntimePhaseV1::Absent,
        ) {
            Ok(_) => BackendEffectOutcome::Complete(destroyed),
            Err(_) => BackendEffectOutcome::RecoveryRequired(recovery),
        }
    }
}

/// Reports protected execution-handoff staging failure.
#[derive(Debug, thiserror::Error)]
pub enum DormantBackendHandoffErrorV1 {
    /// The exact request was already staged in this live backend instance.
    #[error("dormant backend execution request is already staged")]
    AlreadyStaged,
    /// No authenticated agent session is retained by the protected backend.
    #[error("dormant backend has no authenticated agent session")]
    MissingAgentSession,
    /// The protected effect cannot be projected to the exact agent/core route.
    #[error("dormant backend execution route is invalid")]
    InvalidRoute,
    /// The retained fixed-root currentness is stale.
    #[error("dormant backend currentness is stale")]
    StaleCurrentness,
    /// Protected execution dispatch projection failed.
    #[error("dormant backend execution handoff failed: {0}")]
    Store(#[from] JournalRuntimeExecutionError),
    /// Fixed-root ownership or currentness validation failed.
    #[error("dormant backend protected owner failed: {0}")]
    Owner(#[from] aos_sandbox::runtime_execution::DormantRuntimeExecutionOwnerErrorV1),
}

fn agent_runtime_binding(
    currentness: &aos_sandbox_core::runtime_backend::AdmissionCurrentnessV1,
) -> Result<AgentRuntimeBindingV1, RuntimeBackendError> {
    let runtime = currentness.runtime().currentness();
    AgentRuntimeBindingV1::new(
        runtime.sandbox(),
        runtime.incarnation(),
        runtime.assignment_epoch(),
        runtime.assignment_digest(),
        runtime.desired_generation(),
        runtime.namespace_generation(),
        *currentness.payload_boot_id().as_bytes(),
    )
    .map_err(|_| RuntimeBackendError::IntegrityFailure)
}

fn verify_peer_signature(
    public_key: [u8; 32],
    message: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), RuntimeBackendError> {
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| RuntimeBackendError::IntegrityFailure)?;
    verifying_key
        .verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| RuntimeBackendError::IntegrityFailure)
}

fn core_execution_phase(
    phase: AgentExecutionPhaseV1,
) -> Result<BackendExecutionPhaseV1, RuntimeBackendError> {
    match phase {
        AgentExecutionPhaseV1::Authorized => Ok(BackendExecutionPhaseV1::Authorized),
        AgentExecutionPhaseV1::Starting => Ok(BackendExecutionPhaseV1::Starting),
        AgentExecutionPhaseV1::Running => Ok(BackendExecutionPhaseV1::Running),
        AgentExecutionPhaseV1::Exited => Ok(BackendExecutionPhaseV1::Exited),
        AgentExecutionPhaseV1::Canceled => Ok(BackendExecutionPhaseV1::Canceled),
        AgentExecutionPhaseV1::Failed => Ok(BackendExecutionPhaseV1::Failed),
        AgentExecutionPhaseV1::Lost => Ok(BackendExecutionPhaseV1::Lost),
        AgentExecutionPhaseV1::Quiesced | AgentExecutionPhaseV1::Ready => {
            Err(RuntimeBackendError::IntegrityFailure)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn runtime_transition<S, T, F, G>(
    backend: &mut DormantProtectedRuntimeBackendV1<'_>,
    operation: BackendOperationIdV1,
    sequence: BackendOperationSequenceV1,
    commitment: RuntimeHandleCommitmentV1,
    handle: DormantRuntimeHandleV1,
    lifecycle_operation: BackendLifecycleOperationV1,
    expected_phase: BackendRuntimePhaseV1,
    success: F,
    retry: G,
) -> BackendEffectOutcome<(S, BackendRuntimeInspectionV1), T, DormantLifecycleRecoveryHandleV1>
where
    F: FnOnce(RuntimeHandleCommitmentV1, DormantRuntimeHandleV1) -> S,
    G: FnOnce(RuntimeHandleCommitmentV1, DormantRuntimeHandleV1) -> T,
{
    let request = lifecycle_request_commitment(
        lifecycle_operation,
        operation,
        sequence,
        commitment.plan_commitment(),
        Some(commitment.handle()),
    );
    if !backend.authorized_lifecycle_requests.remove(&request) {
        return rejected(RuntimeBackendError::Equivocation, retry(commitment, handle));
    }
    let recovery = match lifecycle_token(
        operation,
        sequence,
        *commitment.currentness(),
        commitment.plan_commitment(),
        request,
        lifecycle_operation,
        Some(commitment.handle()),
    ) {
        Ok(token) => token,
        Err(error) => return rejected(error, retry(commitment, handle)),
    };
    if backend.cross_lifecycle_effect(request).is_err() {
        return BackendEffectOutcome::RecoveryRequired(recovery);
    }
    match backend.take_runtime(
        operation,
        sequence,
        lifecycle_operation,
        request,
        &commitment,
        expected_phase,
    ) {
        Ok(observation) => {
            BackendEffectOutcome::Complete((success(commitment, handle), observation))
        }
        Err(_) => BackendEffectOutcome::RecoveryRequired(recovery),
    }
}

fn lifecycle_token(
    operation: BackendOperationIdV1,
    sequence: BackendOperationSequenceV1,
    currentness: aos_sandbox_core::runtime_backend::RuntimeCurrentnessV1,
    plan: ObjectDigest,
    request: ObjectDigest,
    lifecycle_operation: BackendLifecycleOperationV1,
    runtime_handle: Option<ObjectDigest>,
) -> Result<RuntimeRecoveryToken<DormantLifecycleRecoveryHandleV1>, RuntimeBackendError> {
    let handle = DormantLifecycleRecoveryHandleV1 {
        lifecycle_operation,
        runtime_handle,
    };
    RuntimeRecoveryToken::from_backend(operation, sequence, currentness, plan, request, handle)
        .map_err(|_| RuntimeBackendError::IntegrityFailure)
}

fn rejected<S, T, R>(error: RuntimeBackendError, retry_state: T) -> BackendEffectOutcome<S, T, R> {
    BackendEffectOutcome::Rejected { error, retry_state }
}

fn execution_recovery_token(
    request: &BackendExecutionRequestV1,
    runtime: RuntimeHandleCommitmentV1,
    execution: ExecutionId,
) -> Result<RuntimeRecoveryToken<DormantExecutionRecoveryHandleV1>, RuntimeBackendError> {
    let handle = DormantExecutionRecoveryHandleV1 {
        execution,
        specification_digest: request.specification_digest(),
        admission_commitment: request.admission_commitment(),
        effect_request_digest: request.effect_request_digest(),
        runtime,
    };
    RuntimeRecoveryToken::from_backend(
        request.operation(),
        request.sequence(),
        *runtime.currentness(),
        runtime.plan_commitment(),
        request.effect_request_digest(),
        handle,
    )
    .map_err(|_| RuntimeBackendError::IntegrityFailure)
}

fn lifecycle_request_commitment(
    lifecycle: BackendLifecycleOperationV1,
    operation: BackendOperationIdV1,
    sequence: BackendOperationSequenceV1,
    plan: ObjectDigest,
    handle: Option<ObjectDigest>,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.host.dormant-lifecycle-request.v1\0");
    digest.update([lifecycle as u8]);
    digest.update(operation.as_bytes());
    digest.update(sequence.get().to_be_bytes());
    digest.update(plan.as_bytes());
    digest.update(
        handle
            .unwrap_or(ObjectDigest::from_bytes([0; 32]))
            .as_bytes(),
    );
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn stop_request_commitment(
    operation: BackendOperationIdV1,
    sequence: BackendOperationSequenceV1,
    commitment: RuntimeHandleCommitmentV1,
    deadline: BackendStopDeadlineV1,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.host.dormant-stop-request.v1\0");
    digest.update(operation.as_bytes());
    digest.update(sequence.get().to_be_bytes());
    digest.update(commitment.plan_commitment().as_bytes());
    digest.update(commitment.handle().as_bytes());
    digest.update(deadline.after_nanoseconds().to_be_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

/// Returns the canonical protected-clock message for dormant Kill escalation.
///
/// This data-only helper grants no authority. Escalation additionally requires
/// a signature by the Host-only evidence key retained in the fixed claim.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn dormant_kill_deadline_signing_message_v1(
    authority: ObjectDigest,
    stop_operation: BackendOperationIdV1,
    stop_sequence: BackendOperationSequenceV1,
    kill_operation: BackendOperationIdV1,
    kill_sequence: BackendOperationSequenceV1,
    stop_request_commitment: ObjectDigest,
    runtime: RuntimeHandleCommitmentV1,
    deadline: BackendStopDeadlineV1,
    host_boot_id: [u8; 16],
    stop_started_boottime_nanoseconds: u64,
    observed_boottime_nanoseconds: u64,
) -> [u8; 32] {
    let kill_request_commitment = forced_kill_request_commitment(
        kill_operation,
        kill_sequence,
        runtime,
        stop_request_commitment,
        host_boot_id,
        stop_started_boottime_nanoseconds,
        observed_boottime_nanoseconds,
    );
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.host.dormant-kill-deadline.v1\0");
    digest.update(authority.as_bytes());
    digest.update(stop_operation.as_bytes());
    digest.update(stop_sequence.get().to_be_bytes());
    digest.update(kill_operation.as_bytes());
    digest.update(kill_sequence.get().to_be_bytes());
    digest.update(kill_request_commitment.as_bytes());
    digest.update(stop_request_commitment.as_bytes());
    digest.update(runtime.currentness().sandbox().as_bytes());
    digest.update(runtime.currentness().incarnation().as_bytes());
    digest.update(runtime.currentness().assignment_epoch().get().to_be_bytes());
    digest.update(runtime.currentness().assignment_digest().as_bytes());
    digest.update(
        runtime
            .currentness()
            .desired_generation()
            .get()
            .to_be_bytes(),
    );
    digest.update(
        runtime
            .currentness()
            .namespace_generation()
            .get()
            .to_be_bytes(),
    );
    digest.update(runtime.plan_commitment().as_bytes());
    digest.update(runtime.handle().as_bytes());
    digest.update(deadline.after_nanoseconds().to_be_bytes());
    digest.update(host_boot_id);
    digest.update(stop_started_boottime_nanoseconds.to_be_bytes());
    digest.update(observed_boottime_nanoseconds.to_be_bytes());
    digest.finalize().into()
}

fn forced_kill_request_commitment(
    operation: BackendOperationIdV1,
    sequence: BackendOperationSequenceV1,
    runtime: RuntimeHandleCommitmentV1,
    stop_request_commitment: ObjectDigest,
    host_boot_id: [u8; 16],
    stop_started_boottime_nanoseconds: u64,
    observed_boottime_nanoseconds: u64,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.host.dormant-forced-kill-request.v1\0");
    digest.update(operation.as_bytes());
    digest.update(sequence.get().to_be_bytes());
    digest.update(runtime.plan_commitment().as_bytes());
    digest.update(runtime.handle().as_bytes());
    digest.update(stop_request_commitment.as_bytes());
    digest.update(host_boot_id);
    digest.update(stop_started_boottime_nanoseconds.to_be_bytes());
    digest.update(observed_boottime_nanoseconds.to_be_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn execution_request_binding(request: &BackendExecutionRequestV1) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.host.dormant-execution-dispatch.v1\0");
    digest.update(request.operation().as_bytes());
    digest.update(request.sequence().get().to_be_bytes());
    digest.update((request.specification_bytes().len() as u64).to_be_bytes());
    digest.update(request.specification_bytes());
    digest.update(request.specification_digest().as_bytes());
    digest.update(request.admission_commitment().as_bytes());
    digest.update(request.effect_request_digest().as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn recovery_phase_matches(
    operation: BackendLifecycleOperationV1,
    phase: BackendRuntimePhaseV1,
) -> bool {
    match operation {
        BackendLifecycleOperationV1::Prepare => matches!(
            phase,
            BackendRuntimePhaseV1::Prepared
                | BackendRuntimePhaseV1::Failed
                | BackendRuntimePhaseV1::Absent
        ),
        BackendLifecycleOperationV1::Start | BackendLifecycleOperationV1::Thaw => matches!(
            phase,
            BackendRuntimePhaseV1::Running
                | BackendRuntimePhaseV1::Failed
                | BackendRuntimePhaseV1::Absent
        ),
        BackendLifecycleOperationV1::Freeze => matches!(
            phase,
            BackendRuntimePhaseV1::Frozen | BackendRuntimePhaseV1::Failed
        ),
        BackendLifecycleOperationV1::Stop => matches!(
            phase,
            BackendRuntimePhaseV1::Stopped | BackendRuntimePhaseV1::Absent
        ),
        BackendLifecycleOperationV1::Kill => phase == BackendRuntimePhaseV1::Absent,
        BackendLifecycleOperationV1::Destroy => phase == BackendRuntimePhaseV1::Absent,
        BackendLifecycleOperationV1::Inspect => true,
    }
}

fn probe_commitment(
    currentness: &aos_sandbox_core::runtime_backend::BackendProbeCurrentnessV1,
    capabilities: &BackendCapabilitiesV1,
    authority: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.host.dormant-protected-probe.v1\0");
    digest.update(currentness.node().as_bytes());
    digest.update(currentness.backend_build().as_bytes());
    digest.update(currentness.probe_epoch().get().to_be_bytes());
    digest.update(currentness.protected_context().as_bytes());
    digest.update(authority.as_bytes());
    digest.update((capabilities.as_slice().len() as u16).to_be_bytes());
    for capability in capabilities.as_slice() {
        digest.update([*capability as u8]);
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}
