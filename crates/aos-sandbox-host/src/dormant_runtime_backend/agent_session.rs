//! Dormant authenticated Host-side reducer and guest-agent execution bridge.
//!
//! No active service imports this module. It binds a peer public key, fresh
//! challenge, transport channel, runtime handle, payload boot, session,
//! outstanding request, and outcome before producing core inspection evidence.

use aos_sandbox::runtime_execution::ConsumedExecutionDispatchV1;
use aos_sandbox_agent::{
    AgentExecutionOperationV1, AgentExecutionOutcomeV1, AgentExecutionPhaseV1, AgentFeatureSetV1,
    AgentFeatureV1, AgentHandshakeRequestV1, AgentHandshakeResponseV1, AgentOperationIdV1,
    AgentOperationRequestV1, AgentOperationSequenceV1, AgentRuntimeBindingV1,
    AgentSessionBindingV1, InvalidAgentModel, agent_handshake_signing_message_v1,
    agent_outcome_signing_message_v1,
};
use aos_sandbox_core::runtime_backend::{
    BackendEvidenceVerifierV1, BackendExecutionInspectionInputV1,
    BackendExecutionInspectionRequestV1, BackendExecutionInspectionV1, BackendExecutionPhaseV1,
    EffectOperationV1, EffectPhaseV1, RuntimeHandleCommitmentV1,
    SignedBackendExecutionInspectionV1, backend_execution_inspection_binding_v1,
};
use aos_sandbox_core::{
    DecodeLimits, ObjectDigest, ObservationSequence, PayloadBootId, decode_execution_spec_v1,
    execution_spec_digest_v1,
};
use ed25519_dalek::{Signature, VerifyingKey};

use super::protected_agent_peer::DormantProtectedAgentPeerLeaseV1;

/// Carries an untrusted post-handshake outcome and its detached signature.
pub struct SignedAgentOutcomeV1 {
    outcome: AgentExecutionOutcomeV1,
    signature: [u8; 64],
}

impl SignedAgentOutcomeV1 {
    /// Constructs an untrusted envelope for concrete peer-key verification.
    #[must_use]
    pub const fn new(outcome: AgentExecutionOutcomeV1, signature: [u8; 64]) -> Self {
        Self { outcome, signature }
    }
}

/// Owns one outcome authenticated for the exact outstanding channel request.
pub struct AuthenticatedAgentOutcomeV1 {
    outcome: AgentExecutionOutcomeV1,
    signature: [u8; 64],
}

/// Owns a core-bound observation derived from a concretely verified envelope.
pub struct AuthenticatedHostAgentObservationV1 {
    core_inspection: BackendExecutionInspectionV1,
    operation: aos_sandbox_core::runtime_backend::BackendOperationIdV1,
    operation_sequence: aos_sandbox_core::runtime_backend::BackendOperationSequenceV1,
    effect_request_digest: ObjectDigest,
    execution: aos_sandbox_core::ExecutionId,
    specification_digest: ObjectDigest,
    admission_commitment: ObjectDigest,
    runtime: RuntimeHandleCommitmentV1,
    payload_boot_id: PayloadBootId,
    phase: BackendExecutionPhaseV1,
    sequence: ObservationSequence,
    observation_commitment: ObjectDigest,
}

impl AuthenticatedHostAgentObservationV1 {
    /// Consumes the Host wrapper and returns the core authenticated inspection.
    #[must_use]
    pub const fn into_core_inspection(self) -> BackendExecutionInspectionV1 {
        self.core_inspection
    }

    /// Returns the exact core operation identity.
    #[must_use]
    pub const fn operation(&self) -> aos_sandbox_core::runtime_backend::BackendOperationIdV1 {
        self.operation
    }

    /// Returns the exact core operation sequence.
    #[must_use]
    pub const fn operation_sequence(
        &self,
    ) -> aos_sandbox_core::runtime_backend::BackendOperationSequenceV1 {
        self.operation_sequence
    }

    /// Returns the exact effect-request commitment.
    #[must_use]
    pub const fn effect_request_digest(&self) -> ObjectDigest {
        self.effect_request_digest
    }

    /// Returns the durable execution identity.
    #[must_use]
    pub const fn execution(&self) -> aos_sandbox_core::ExecutionId {
        self.execution
    }

    /// Returns the exact execution-specification digest.
    #[must_use]
    pub const fn specification_digest(&self) -> ObjectDigest {
        self.specification_digest
    }

    /// Returns the durable admission commitment.
    #[must_use]
    pub const fn admission_commitment(&self) -> ObjectDigest {
        self.admission_commitment
    }

    /// Returns exact runtime handle currentness.
    #[must_use]
    pub const fn runtime(&self) -> &RuntimeHandleCommitmentV1 {
        &self.runtime
    }

    /// Returns the exact payload boot identity.
    #[must_use]
    pub const fn payload_boot_id(&self) -> PayloadBootId {
        self.payload_boot_id
    }

    /// Returns the authenticated execution phase.
    #[must_use]
    pub const fn phase(&self) -> BackendExecutionPhaseV1 {
        self.phase
    }

    /// Returns the protected Host observation sequence.
    #[must_use]
    pub const fn sequence(&self) -> ObservationSequence {
        self.sequence
    }

    /// Returns the signed-envelope observation commitment.
    #[must_use]
    pub const fn observation_commitment(&self) -> ObjectDigest {
        self.observation_commitment
    }
}

/// Stores protected peer identity and exact runtime transport expectations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DormantAgentPeerV1 {
    public_key: [u8; 32],
    runtime: RuntimeHandleCommitmentV1,
    agent_runtime: AgentRuntimeBindingV1,
    channel_binding: ObjectDigest,
    next_observation_sequence: ObservationSequence,
    protected_authority_binding: ObjectDigest,
}

impl DormantAgentPeerV1 {
    /// Constructs non-sentinel protected peer expectations.
    ///
    /// # Errors
    ///
    /// Returns [`DormantAgentSessionError`] for a zero peer key/channel or a
    /// mismatch between core and agent runtime currentness.
    #[allow(dead_code)]
    pub(crate) fn new(
        public_key: [u8; 32],
        runtime: RuntimeHandleCommitmentV1,
        agent_runtime: AgentRuntimeBindingV1,
        channel_binding: ObjectDigest,
        next_observation_sequence: ObservationSequence,
        protected_authority_binding: ObjectDigest,
    ) -> Result<Self, DormantAgentSessionError> {
        let currentness = runtime.currentness();
        if public_key == [0; 32]
            || channel_binding.as_bytes() == &[0; 32]
            || next_observation_sequence.get() == 0
            || next_observation_sequence.get() == u64::MAX
            || protected_authority_binding.as_bytes() == &[0; 32]
            || agent_runtime.sandbox() != currentness.sandbox()
            || agent_runtime.incarnation() != currentness.incarnation()
            || agent_runtime.assignment_epoch() != currentness.assignment_epoch()
            || agent_runtime.assignment_digest() != currentness.assignment_digest()
            || agent_runtime.desired_generation() != currentness.desired_generation()
            || agent_runtime.namespace_generation() != currentness.namespace_generation()
        {
            return Err(DormantAgentSessionError::BindingMismatch);
        }
        Ok(Self {
            public_key,
            runtime,
            agent_runtime,
            channel_binding,
            next_observation_sequence,
            protected_authority_binding,
        })
    }

    /// Returns the protected-journal provenance that minted this peer.
    #[must_use]
    pub(crate) const fn protected_authority_binding(&self) -> ObjectDigest {
        self.protected_authority_binding
    }

    pub(super) const fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    pub(super) const fn runtime(&self) -> RuntimeHandleCommitmentV1 {
        self.runtime
    }

    pub(super) const fn channel_binding(&self) -> ObjectDigest {
        self.channel_binding
    }
}

/// Owns a fresh challenge until the exact response is verified.
pub struct DormantPendingAgentHandshakeV1<'journal> {
    protected_peer: DormantProtectedAgentPeerLeaseV1<'journal>,
    peer: DormantAgentPeerV1,
    request: AgentHandshakeRequestV1,
}

impl<'journal> DormantPendingAgentHandshakeV1<'journal> {
    /// Creates a pending verifier from an exact protected peer and challenge.
    ///
    /// # Errors
    ///
    /// Returns [`DormantAgentSessionError`] if request runtime or channel does
    /// not equal the protected peer expectation.
    pub(super) fn from_protected_lease(
        protected_peer: DormantProtectedAgentPeerLeaseV1<'journal>,
        request: AgentHandshakeRequestV1,
    ) -> Result<Self, DormantAgentSessionError> {
        protected_peer
            .validate_current()
            .map_err(|_| DormantAgentSessionError::BindingMismatch)?;
        let peer = protected_peer.peer().clone();
        if request.runtime() != &peer.agent_runtime
            || request.host_channel_binding() != peer.channel_binding
        {
            return Err(DormantAgentSessionError::BindingMismatch);
        }
        Ok(Self {
            protected_peer,
            peer,
            request,
        })
    }

    /// Verifies the exact handshake and creates a stop-and-wait Host session.
    ///
    /// # Errors
    ///
    /// Returns [`DormantAgentSessionError`] for binding, signature, feature,
    /// or initial-sequence failure.
    pub fn verify(
        self,
        response: AgentHandshakeResponseV1,
    ) -> Result<DormantHostAgentSessionV1<'journal>, DormantAgentSessionError> {
        self.protected_peer
            .validate_current()
            .map_err(|_| DormantAgentSessionError::BindingMismatch)?;
        let expected = AgentSessionBindingV1::derive(&self.request, response.agent_instance())?;
        if response.session_binding() != expected {
            return Err(DormantAgentSessionError::BindingMismatch);
        }
        let message = agent_handshake_signing_message_v1(
            &self.request,
            expected,
            response.agent_instance(),
            response.features(),
        );
        verify_agent_signature(
            &self.peer.public_key,
            &message,
            response.challenge_signature(),
        )?;
        Ok(DormantHostAgentSessionV1 {
            protected_peer: self.protected_peer,
            peer: self.peer,
            binding: expected,
            negotiated_features: response.features().clone(),
            next_sequence: AgentOperationSequenceV1::new(1)?,
            outstanding: None,
            outstanding_binding: None,
            superseded: false,
        })
    }
}

/// Reduces one authenticated Host/agent session without transport effects.
pub struct DormantHostAgentSessionV1<'journal> {
    protected_peer: DormantProtectedAgentPeerLeaseV1<'journal>,
    peer: DormantAgentPeerV1,
    binding: AgentSessionBindingV1,
    negotiated_features: AgentFeatureSetV1,
    next_sequence: AgentOperationSequenceV1,
    outstanding: Option<AgentOperationRequestV1>,
    outstanding_binding: Option<OutstandingCoreBindingV1>,
    superseded: bool,
}

impl DormantHostAgentSessionV1<'_> {
    /// Consumes one core Issued authorization and projects it to `AOSAGE01`.
    ///
    /// # Errors
    ///
    /// Returns [`DormantAgentSessionError`] for a superseded/busy session,
    /// malformed core spec, cross-runtime substitution, or model failure.
    pub fn bridge_issued_execution(
        &mut self,
        dispatch: ConsumedExecutionDispatchV1,
    ) -> Result<AgentOperationRequestV1, DormantAgentSessionError> {
        self.validate_protected_current()?;
        if self.superseded {
            return Err(DormantAgentSessionError::Superseded);
        }
        if self.outstanding.is_some() {
            return Err(DormantAgentSessionError::Outstanding);
        }
        self.require_feature(AgentFeatureV1::ExecutionHandoff)?;
        let effect = dispatch.into_effect();
        if effect.phase() != EffectPhaseV1::Issued
            || effect.issue().operation() != EffectOperationV1::AuthorizeExecution
            || effect.admission().currentness().runtime() != &self.peer.runtime
            || effect
                .admission()
                .currentness()
                .payload_boot_id()
                .as_bytes()
                != self.peer.agent_runtime.payload_boot_id()
        {
            return Err(DormantAgentSessionError::BindingMismatch);
        }
        if effect.admission().currentness().authority_context()
            != self.protected_peer.evidence_authority_binding()
        {
            return Err(DormantAgentSessionError::BindingMismatch);
        }
        let request = effect
            .backend_execution_request()
            .map_err(|_| DormantAgentSessionError::WrongOperation)?;
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
        .map_err(|_| DormantAgentSessionError::InvalidSpecification)?;
        if execution_spec_digest_v1(&specification) != request.specification_digest()
            || specification.target().sandbox() != self.peer.agent_runtime.sandbox()
            || specification.target().incarnation() != self.peer.agent_runtime.incarnation()
            || specification.target().assignment_epoch()
                != self.peer.agent_runtime.assignment_epoch()
            || specification.target().assignment_digest()
                != self.peer.agent_runtime.assignment_digest()
            || specification.target().namespace_generation()
                != self.peer.agent_runtime.namespace_generation()
            || specification.target().payload_boot_id().as_bytes()
                != self.peer.agent_runtime.payload_boot_id()
        {
            return Err(DormantAgentSessionError::BindingMismatch);
        }
        let core_binding = OutstandingCoreBindingV1 {
            evidence_authority_binding: effect.admission().currentness().authority_context(),
            operation: request.operation(),
            operation_sequence: request.sequence(),
            effect_request_digest: request.effect_request_digest(),
            execution: specification.execution(),
            specification_digest: request.specification_digest(),
            admission_commitment: request.admission_commitment(),
        };
        let inspection_request = core_binding.inspection_request(
            self.peer.runtime,
            PayloadBootId::from_bytes(*self.peer.agent_runtime.payload_boot_id()),
        )?;
        let operation = AgentExecutionOperationV1::Authorize {
            execution: specification.execution(),
            specification_bytes: request.specification_bytes().to_vec(),
            specification_digest: request.specification_digest(),
            admission_commitment: request.admission_commitment(),
            principal: specification.principal(),
            audit: specification.audit(),
        };
        let agent_request = AgentOperationRequestV1::new(
            self.binding,
            self.next_sequence,
            AgentOperationIdV1::new(*request.operation().as_bytes())?,
            backend_execution_inspection_binding_v1(&inspection_request),
            operation,
        )?;
        self.outstanding_binding = Some(core_binding);
        self.outstanding = Some(agent_request.clone());
        Ok(agent_request)
    }

    /// Consumes a non-authorize core Issued effect into an `AOSAGE01` request.
    ///
    /// # Errors
    ///
    /// Returns [`DormantAgentSessionError`] unless the effect is exactly
    /// Issued, targets this runtime and payload boot, and the session is idle.
    pub fn bridge_issued_control(
        &mut self,
        dispatch: ConsumedExecutionDispatchV1,
    ) -> Result<AgentOperationRequestV1, DormantAgentSessionError> {
        self.validate_protected_current()?;
        if self.superseded {
            return Err(DormantAgentSessionError::Superseded);
        }
        if self.outstanding.is_some() {
            return Err(DormantAgentSessionError::Outstanding);
        }
        let effect = dispatch.into_effect();
        let admission = effect.admission();
        if effect.phase() != EffectPhaseV1::Issued
            || admission.currentness().runtime() != &self.peer.runtime
            || admission.currentness().payload_boot_id().as_bytes()
                != self.peer.agent_runtime.payload_boot_id()
        {
            return Err(DormantAgentSessionError::BindingMismatch);
        }
        if admission.currentness().authority_context()
            != self.protected_peer.evidence_authority_binding()
        {
            return Err(DormantAgentSessionError::BindingMismatch);
        }
        let operation = match effect.issue().operation() {
            EffectOperationV1::ResizeTerminal { rows, columns } => {
                self.require_feature(AgentFeatureV1::TerminalResize)?;
                AgentExecutionOperationV1::ResizeTerminal {
                    execution: admission.execution(),
                    rows,
                    columns,
                }
            }
            EffectOperationV1::Signal { signal_code } => {
                self.require_feature(AgentFeatureV1::ExecutionSignal)?;
                AgentExecutionOperationV1::Signal {
                    execution: admission.execution(),
                    signal_code,
                }
            }
            EffectOperationV1::Cancel => AgentExecutionOperationV1::Cancel {
                execution: admission.execution(),
            },
            EffectOperationV1::Observe => {
                self.require_feature(AgentFeatureV1::ExecutionObservation)?;
                AgentExecutionOperationV1::Observe {
                    execution: admission.execution(),
                }
            }
            EffectOperationV1::AuthorizeExecution => {
                return Err(DormantAgentSessionError::WrongOperation);
            }
        };
        let core_binding = OutstandingCoreBindingV1 {
            evidence_authority_binding: admission.currentness().authority_context(),
            operation: effect.issue().idempotency().operation(),
            operation_sequence: effect.issue().sequence(),
            effect_request_digest: effect.issue().idempotency().request_digest(),
            execution: admission.execution(),
            specification_digest: admission.specification_digest(),
            admission_commitment: admission.admission_commitment(),
        };
        let inspection_request = core_binding.inspection_request(
            self.peer.runtime,
            PayloadBootId::from_bytes(*self.peer.agent_runtime.payload_boot_id()),
        )?;
        let request = AgentOperationRequestV1::new(
            self.binding,
            self.next_sequence,
            AgentOperationIdV1::new(*effect.issue().idempotency().operation().as_bytes())?,
            backend_execution_inspection_binding_v1(&inspection_request),
            operation,
        )?;
        self.outstanding_binding = Some(core_binding);
        self.outstanding = Some(request.clone());
        Ok(request)
    }

    /// Authenticates one received outcome for the exact outstanding request.
    ///
    /// # Errors
    ///
    /// Returns [`DormantAgentSessionError`] for an unauthenticated,
    /// unsolicited, superseded, or cross-request outcome.
    pub fn authenticate_outcome(
        &self,
        signed: SignedAgentOutcomeV1,
    ) -> Result<AuthenticatedAgentOutcomeV1, DormantAgentSessionError> {
        self.validate_protected_current()?;
        if self.superseded {
            return Err(DormantAgentSessionError::Superseded);
        }
        let request = self
            .outstanding
            .as_ref()
            .ok_or(DormantAgentSessionError::UnsolicitedOutcome)?;
        let outcome = signed.outcome;
        if outcome.session() != self.binding
            || outcome.sequence() != request.sequence()
            || outcome.operation_id() != request.operation_id()
            || outcome.request_commitment() != request.request_commitment()
        {
            return Err(DormantAgentSessionError::BindingMismatch);
        }
        let message =
            agent_outcome_signing_message_v1(self.peer.channel_binding, request, &outcome);
        verify_agent_signature(&self.peer.public_key, &message, &signed.signature)?;
        Ok(AuthenticatedAgentOutcomeV1 {
            outcome,
            signature: signed.signature,
        })
    }

    /// Consumes one authenticated outcome into a Host-owned core-bound observation.
    ///
    /// # Errors
    ///
    /// Returns [`DormantAgentSessionError`] for unsolicited, replayed,
    /// superseded, or cross-request outcomes.
    pub fn accept_outcome(
        &mut self,
        authenticated: AuthenticatedAgentOutcomeV1,
    ) -> Result<AuthenticatedHostAgentObservationV1, DormantAgentSessionError> {
        self.validate_protected_current()?;
        let outcome = authenticated.outcome;
        if self.superseded {
            return Err(DormantAgentSessionError::Superseded);
        }
        let request = self
            .outstanding
            .as_ref()
            .ok_or(DormantAgentSessionError::UnsolicitedOutcome)?;
        if outcome.session() != self.binding
            || outcome.sequence() != request.sequence()
            || outcome.operation_id() != request.operation_id()
            || outcome.request_commitment() != request.request_commitment()
        {
            return Err(DormantAgentSessionError::BindingMismatch);
        }
        if matches!(
            request.operation(),
            AgentExecutionOperationV1::Cancel { .. }
        ) && !matches!(
            outcome.phase(),
            AgentExecutionPhaseV1::Exited
                | AgentExecutionPhaseV1::Canceled
                | AgentExecutionPhaseV1::Failed
                | AgentExecutionPhaseV1::Lost
        ) {
            return Err(DormantAgentSessionError::WrongOperation);
        }
        let binding = self
            .outstanding_binding
            .ok_or(DormantAgentSessionError::UnsolicitedOutcome)?;
        let observation_sequence = self.peer.next_observation_sequence;
        let payload_boot_id = PayloadBootId::from_bytes(*self.peer.agent_runtime.payload_boot_id());
        let inspection_request = binding.inspection_request(self.peer.runtime, payload_boot_id)?;
        if request.backend_request_binding()
            != backend_execution_inspection_binding_v1(&inspection_request)
        {
            return Err(DormantAgentSessionError::BindingMismatch);
        }
        let verifier = BackendEvidenceVerifierV1::new(
            self.peer.public_key,
            self.protected_peer.evidence_trust_context(),
            self.peer.channel_binding,
        )?;
        let input = BackendExecutionInspectionInputV1 {
            authority_binding: ObjectDigest::from_bytes([0; 32]),
            operation: binding.operation,
            operation_sequence: binding.operation_sequence,
            effect_request_digest: binding.effect_request_digest,
            execution: binding.execution,
            specification_digest: binding.specification_digest,
            admission_commitment: binding.admission_commitment,
            runtime: self.peer.runtime,
            payload_boot_id,
            phase: core_phase(outcome.phase())?,
            sequence: observation_sequence,
            observation_commitment: ObjectDigest::from_bytes([0; 32]),
        };
        let signed_inspection = SignedBackendExecutionInspectionV1::new(
            input,
            outcome.session().digest(),
            outcome.sequence().get(),
            *outcome.operation_id().as_bytes(),
            outcome.request_commitment(),
            outcome.outcome_commitment(),
            outcome.result_bytes().to_vec(),
            outcome.result_digest(),
            authenticated.signature,
        );
        let core_inspection = verifier.verify_execution_inspection(
            &inspection_request,
            observation_sequence,
            signed_inspection,
        )?;
        let observation = AuthenticatedHostAgentObservationV1 {
            core_inspection,
            operation: core_inspection.operation(),
            operation_sequence: core_inspection.operation_sequence(),
            effect_request_digest: core_inspection.effect_request_digest(),
            execution: core_inspection.execution(),
            specification_digest: core_inspection.specification_digest(),
            admission_commitment: core_inspection.admission_commitment(),
            runtime: *core_inspection.runtime(),
            payload_boot_id: core_inspection.payload_boot_id(),
            phase: core_inspection.phase(),
            sequence: core_inspection.sequence(),
            observation_commitment: core_inspection.observation_commitment(),
        };
        self.next_sequence = self.next_sequence.checked_next()?;
        self.peer.next_observation_sequence = observation_sequence
            .checked_next()
            .map_err(|_| DormantAgentSessionError::ObservationSequenceExhausted)?;
        self.outstanding = None;
        self.outstanding_binding = None;
        Ok(observation)
    }

    fn require_feature(&self, feature: AgentFeatureV1) -> Result<(), DormantAgentSessionError> {
        if self.negotiated_features.contains(feature) {
            Ok(())
        } else {
            Err(DormantAgentSessionError::FeatureUnavailable)
        }
    }

    fn validate_protected_current(&self) -> Result<(), DormantAgentSessionError> {
        self.protected_peer
            .validate_current()
            .map_err(|_| DormantAgentSessionError::BindingMismatch)
    }

    /// Supersedes this channel only when no operation is outstanding.
    ///
    /// # Errors
    ///
    /// Returns [`DormantAgentSessionError::Outstanding`] while reconciliation
    /// of a prior request remains mandatory.
    pub fn supersede(&mut self) -> Result<(), DormantAgentSessionError> {
        if self.outstanding.is_some() {
            return Err(DormantAgentSessionError::Outstanding);
        }
        self.protected_peer
            .revoke_current()
            .map_err(|_| DormantAgentSessionError::BindingMismatch)?;
        self.superseded = true;
        Ok(())
    }
}

fn verify_agent_signature(
    public_key: &[u8; 32],
    message: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), DormantAgentSessionError> {
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| DormantAgentSessionError::SignatureInvalid)?;
    verifying_key
        .verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| DormantAgentSessionError::SignatureInvalid)
}

#[derive(Clone, Copy)]
struct OutstandingCoreBindingV1 {
    evidence_authority_binding: ObjectDigest,
    operation: aos_sandbox_core::runtime_backend::BackendOperationIdV1,
    operation_sequence: aos_sandbox_core::runtime_backend::BackendOperationSequenceV1,
    effect_request_digest: ObjectDigest,
    execution: aos_sandbox_core::ExecutionId,
    specification_digest: ObjectDigest,
    admission_commitment: ObjectDigest,
}

impl OutstandingCoreBindingV1 {
    fn inspection_request(
        self,
        runtime: RuntimeHandleCommitmentV1,
        payload_boot_id: PayloadBootId,
    ) -> Result<BackendExecutionInspectionRequestV1, DormantAgentSessionError> {
        BackendExecutionInspectionRequestV1::new(
            self.evidence_authority_binding,
            self.operation,
            self.operation_sequence,
            self.effect_request_digest,
            self.execution,
            self.specification_digest,
            self.admission_commitment,
            runtime,
            payload_boot_id,
        )
        .map_err(|_| DormantAgentSessionError::BindingMismatch)
    }
}

fn core_phase(
    phase: AgentExecutionPhaseV1,
) -> Result<BackendExecutionPhaseV1, DormantAgentSessionError> {
    match phase {
        AgentExecutionPhaseV1::Authorized => Ok(BackendExecutionPhaseV1::Authorized),
        AgentExecutionPhaseV1::Starting => Ok(BackendExecutionPhaseV1::Starting),
        AgentExecutionPhaseV1::Running => Ok(BackendExecutionPhaseV1::Running),
        AgentExecutionPhaseV1::Exited => Ok(BackendExecutionPhaseV1::Exited),
        AgentExecutionPhaseV1::Canceled => Ok(BackendExecutionPhaseV1::Canceled),
        AgentExecutionPhaseV1::Failed => Ok(BackendExecutionPhaseV1::Failed),
        AgentExecutionPhaseV1::Lost => Ok(BackendExecutionPhaseV1::Lost),
        AgentExecutionPhaseV1::Quiesced | AgentExecutionPhaseV1::Ready => {
            Err(DormantAgentSessionError::WrongOperation)
        }
    }
}

/// Reports dormant Host/agent verifier or bridge rejection.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DormantAgentSessionError {
    /// Protected runtime, challenge, channel, request, or outcome bindings differ.
    #[error("Host/agent binding mismatch")]
    BindingMismatch,
    /// Signature verification failed closed.
    #[error("Host/agent signature verification failed")]
    SignatureInvalid,
    /// The session has an unresolved stop-and-wait operation.
    #[error("Host/agent session has an outstanding operation")]
    Outstanding,
    /// The channel has been superseded.
    #[error("Host/agent session is superseded")]
    Superseded,
    /// An outcome arrived without an outstanding request.
    #[error("Host/agent outcome is unsolicited")]
    UnsolicitedOutcome,
    /// The exact core specification is malformed.
    #[error("Host/agent execution specification is invalid")]
    InvalidSpecification,
    /// The outcome is not execution-scoped.
    #[error("Host/agent operation has the wrong shape")]
    WrongOperation,
    /// Negotiated features do not authorize this operation.
    #[error("Host/agent negotiated feature is unavailable")]
    FeatureUnavailable,
    /// The protected Host observation counter cannot advance safely.
    #[error("Host/agent observation sequence is exhausted")]
    ObservationSequenceExhausted,
    /// Portable agent model validation failed.
    #[error("Host/agent model failed: {0}")]
    Agent(#[from] InvalidAgentModel),
    /// Concrete core evidence verification failed.
    #[error("Host/agent core evidence failed: {0}")]
    Evidence(#[from] aos_sandbox_core::runtime_backend::BackendEvidenceVerificationError),
}
