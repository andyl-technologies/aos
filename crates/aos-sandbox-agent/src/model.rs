//! Portable guest-agent handshake, operation, and outcome values.

use sha2::{Digest as _, Sha256};

use aos_sandbox_core::{
    AssignmentEpoch, AuditId, DesiredGeneration, ExecutionId, IncarnationId, NamespaceGeneration,
    ObjectDigest, PrincipalId, SandboxId,
};

const SESSION_BINDING_DOMAIN: &[u8] = b"aos-sandbox-agent-session-v1\0";
const OPERATION_REQUEST_DOMAIN: &[u8] = b"aos-sandbox-agent-operation-v1\0";
const MAX_EXECUTION_SPEC_BYTES: usize = 15 * 1_048_576;
const MAX_AGENT_RESULT_BYTES: usize = 1_048_576;

const fn contains_nonzero<const N: usize>(bytes: &[u8; N]) -> bool {
    let mut index = 0;
    while index < N {
        if bytes[index] != 0 {
            return true;
        }
        index += 1;
    }
    false
}

/// Identifies the exact node-internal agent protocol version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentProtocolVersionV1;

impl AgentProtocolVersionV1 {
    /// Returns the protocol major version.
    #[must_use]
    pub const fn major(self) -> u16 {
        1
    }

    /// Returns the protocol minor version.
    #[must_use]
    pub const fn minor(self) -> u16 {
        0
    }
}

/// Identifies one live provisioned host/agent channel session.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AgentSessionIdV1([u8; 16]);

impl AgentSessionIdV1 {
    /// Constructs a nonzero unpredictable session identity.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAgentModel::Unspecified`] for the zero sentinel.
    pub const fn new(bytes: [u8; 16]) -> Result<Self, InvalidAgentModel> {
        if !contains_nonzero(&bytes) {
            Err(InvalidAgentModel::Unspecified)
        } else {
            Ok(Self(bytes))
        }
    }

    /// Returns exact portable bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Stores one fresh nonzero 256-bit handshake challenge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentNonceV1([u8; 32]);

impl AgentNonceV1 {
    /// Constructs a nonzero nonce supplied by a process-exclusive CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAgentModel::Unspecified`] for the zero sentinel.
    pub const fn new(bytes: [u8; 32]) -> Result<Self, InvalidAgentModel> {
        if !contains_nonzero(&bytes) {
            Err(InvalidAgentModel::Unspecified)
        } else {
            Ok(Self(bytes))
        }
    }

    /// Returns exact nonce bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Binds the agent to one exact payload incarnation and assignment generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentRuntimeBindingV1 {
    sandbox: SandboxId,
    incarnation: IncarnationId,
    assignment_epoch: AssignmentEpoch,
    assignment_digest: ObjectDigest,
    desired_generation: DesiredGeneration,
    namespace_generation: NamespaceGeneration,
    payload_boot_id: [u8; 16],
}

impl AgentRuntimeBindingV1 {
    /// Constructs a non-sentinel exact payload binding.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAgentModel::Unspecified`] for any zero field.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sandbox: SandboxId,
        incarnation: IncarnationId,
        assignment_epoch: AssignmentEpoch,
        assignment_digest: ObjectDigest,
        desired_generation: DesiredGeneration,
        namespace_generation: NamespaceGeneration,
        payload_boot_id: [u8; 16],
    ) -> Result<Self, InvalidAgentModel> {
        if sandbox.as_bytes() == &[0; 16]
            || incarnation.as_bytes() == &[0; 16]
            || assignment_epoch.get() == 0
            || assignment_digest.as_bytes() == &[0; 32]
            || desired_generation.get() == 0
            || namespace_generation.get() == 0
            || payload_boot_id == [0; 16]
        {
            return Err(InvalidAgentModel::Unspecified);
        }
        Ok(Self {
            sandbox,
            incarnation,
            assignment_epoch,
            assignment_digest,
            desired_generation,
            namespace_generation,
            payload_boot_id,
        })
    }

    /// Returns the sandbox identity.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    /// Returns the runtime incarnation.
    #[must_use]
    pub const fn incarnation(&self) -> IncarnationId {
        self.incarnation
    }

    /// Returns the assignment epoch.
    #[must_use]
    pub const fn assignment_epoch(&self) -> AssignmentEpoch {
        self.assignment_epoch
    }

    /// Returns the signed assignment digest.
    #[must_use]
    pub const fn assignment_digest(&self) -> ObjectDigest {
        self.assignment_digest
    }

    /// Returns the desired generation.
    #[must_use]
    pub const fn desired_generation(&self) -> DesiredGeneration {
        self.desired_generation
    }

    /// Returns the payload namespace generation.
    #[must_use]
    pub const fn namespace_generation(&self) -> NamespaceGeneration {
        self.namespace_generation
    }

    /// Returns the payload boot identity.
    #[must_use]
    pub const fn payload_boot_id(&self) -> &[u8; 16] {
        &self.payload_boot_id
    }
}

/// Names a semantic feature implemented by the guest agent.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum AgentFeatureV1 {
    /// Reports exact incarnation readiness after local checks.
    Readiness = 1,
    /// Accepts a durably admitted forced execution.
    ExecutionHandoff = 2,
    /// Reports execution lifecycle observations.
    ExecutionObservation = 3,
    /// Applies terminal geometry to an exact PTY execution.
    TerminalResize = 4,
    /// Delivers the closed portable execution signal vocabulary.
    ExecutionSignal = 5,
    /// Enters and leaves an explicit guest quiesce barrier.
    Quiesce = 6,
}

/// Stores a canonical bounded nonempty feature set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentFeatureSetV1(Vec<AgentFeatureV1>);

impl AgentFeatureSetV1 {
    /// Validates strict feature order and the mandatory handshake features.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAgentModel::InvalidFeatures`] for an empty, duplicated,
    /// unordered, oversized set or one lacking readiness and execution handoff.
    pub fn new(features: Vec<AgentFeatureV1>) -> Result<Self, InvalidAgentModel> {
        if features.is_empty()
            || features.len() > 16
            || features.windows(2).any(|pair| pair[0] >= pair[1])
            || !features.contains(&AgentFeatureV1::Readiness)
            || !features.contains(&AgentFeatureV1::ExecutionHandoff)
        {
            return Err(InvalidAgentModel::InvalidFeatures);
        }
        Ok(Self(features))
    }

    /// Returns features in closed canonical order.
    #[must_use]
    pub fn as_slice(&self) -> &[AgentFeatureV1] {
        &self.0
    }

    /// Reports exact feature support.
    #[must_use]
    pub fn contains(&self, feature: AgentFeatureV1) -> bool {
        self.0.binary_search(&feature).is_ok()
    }
}

/// Starts an exact authenticated incarnation handshake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentHandshakeRequestV1 {
    session: AgentSessionIdV1,
    version: AgentProtocolVersionV1,
    runtime: AgentRuntimeBindingV1,
    challenge: AgentNonceV1,
    host_channel_binding: ObjectDigest,
}

impl AgentHandshakeRequestV1 {
    /// Constructs a handshake bound to a provisioned host channel.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAgentModel::Unspecified`] for a zero channel binding.
    pub fn new(
        session: AgentSessionIdV1,
        runtime: AgentRuntimeBindingV1,
        challenge: AgentNonceV1,
        host_channel_binding: ObjectDigest,
    ) -> Result<Self, InvalidAgentModel> {
        if host_channel_binding.as_bytes() == &[0; 32] {
            return Err(InvalidAgentModel::Unspecified);
        }
        Ok(Self {
            session,
            version: AgentProtocolVersionV1,
            runtime,
            challenge,
            host_channel_binding,
        })
    }

    /// Returns the requested session identity.
    #[must_use]
    pub const fn session(&self) -> AgentSessionIdV1 {
        self.session
    }

    /// Returns the exact protocol version.
    #[must_use]
    pub const fn version(&self) -> AgentProtocolVersionV1 {
        self.version
    }

    /// Returns the exact runtime binding.
    #[must_use]
    pub const fn runtime(&self) -> &AgentRuntimeBindingV1 {
        &self.runtime
    }

    /// Returns the fresh handshake challenge.
    #[must_use]
    pub const fn challenge(&self) -> AgentNonceV1 {
        self.challenge
    }

    /// Returns the protected host-channel binding commitment.
    #[must_use]
    pub const fn host_channel_binding(&self) -> ObjectDigest {
        self.host_channel_binding
    }
}

/// Completes a handshake with exact challenge proof and agent capabilities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentHandshakeResponseV1 {
    session_binding: AgentSessionBindingV1,
    agent_instance: [u8; 16],
    features: AgentFeatureSetV1,
    challenge_signature: [u8; 64],
}

impl AgentHandshakeResponseV1 {
    /// Constructs a response from protected signer output.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAgentModel::InvalidSignature`] for an all-zero signature
    /// or [`InvalidAgentModel::Unspecified`] for a zero agent instance.
    pub fn new(
        session_binding: AgentSessionBindingV1,
        agent_instance: [u8; 16],
        features: AgentFeatureSetV1,
        challenge_signature: [u8; 64],
    ) -> Result<Self, InvalidAgentModel> {
        if agent_instance == [0; 16] {
            return Err(InvalidAgentModel::Unspecified);
        }
        if challenge_signature == [0; 64] {
            return Err(InvalidAgentModel::InvalidSignature);
        }
        Ok(Self {
            session_binding,
            agent_instance,
            features,
            challenge_signature,
        })
    }

    /// Returns the derived session binding.
    #[must_use]
    pub const fn session_binding(&self) -> AgentSessionBindingV1 {
        self.session_binding
    }

    /// Returns the process-unique agent instance.
    #[must_use]
    pub const fn agent_instance(&self) -> &[u8; 16] {
        &self.agent_instance
    }

    /// Returns the advertised canonical feature set.
    #[must_use]
    pub const fn features(&self) -> &AgentFeatureSetV1 {
        &self.features
    }

    /// Returns the exact challenge signature.
    #[must_use]
    pub const fn challenge_signature(&self) -> &[u8; 64] {
        &self.challenge_signature
    }
}

/// Commits both handshake peers and the exact runtime/channel binding.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AgentSessionBindingV1(ObjectDigest);

impl AgentSessionBindingV1 {
    /// Derives the exact session binding from one handshake and agent instance.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAgentModel::Unspecified`] for a zero agent instance.
    pub fn derive(
        request: &AgentHandshakeRequestV1,
        agent_instance: &[u8; 16],
    ) -> Result<Self, InvalidAgentModel> {
        if agent_instance == &[0; 16] {
            return Err(InvalidAgentModel::Unspecified);
        }
        let runtime = request.runtime();
        let mut digest = Sha256::new();
        digest.update(SESSION_BINDING_DOMAIN);
        digest.update(request.session().as_bytes());
        digest.update(request.version().major().to_be_bytes());
        digest.update(request.version().minor().to_be_bytes());
        digest.update(runtime.sandbox().as_bytes());
        digest.update(runtime.incarnation().as_bytes());
        digest.update(runtime.assignment_epoch().get().to_be_bytes());
        digest.update(runtime.assignment_digest().as_bytes());
        digest.update(runtime.desired_generation().get().to_be_bytes());
        digest.update(runtime.namespace_generation().get().to_be_bytes());
        digest.update(runtime.payload_boot_id());
        digest.update(request.challenge().as_bytes());
        digest.update(request.host_channel_binding().as_bytes());
        digest.update(agent_instance);
        Ok(Self(ObjectDigest::from_bytes(digest.finalize().into())))
    }

    /// Constructs a decoded nonzero session binding.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAgentModel::Unspecified`] for the zero digest.
    pub fn from_digest(digest: ObjectDigest) -> Result<Self, InvalidAgentModel> {
        if digest.as_bytes() == &[0; 32] {
            Err(InvalidAgentModel::Unspecified)
        } else {
            Ok(Self(digest))
        }
    }

    /// Returns the exact derived digest.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.0
    }
}

/// Identifies one idempotent guest-agent operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AgentOperationIdV1([u8; 16]);

impl AgentOperationIdV1 {
    /// Constructs a nonzero operation identity.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAgentModel::Unspecified`] for the zero sentinel.
    pub const fn new(bytes: [u8; 16]) -> Result<Self, InvalidAgentModel> {
        if !contains_nonzero(&bytes) {
            Err(InvalidAgentModel::Unspecified)
        } else {
            Ok(Self(bytes))
        }
    }

    /// Returns exact operation bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Orders stop-and-wait traffic within one exact agent session.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AgentOperationSequenceV1(u64);

impl AgentOperationSequenceV1 {
    /// Constructs a nonzero non-exhausted operation sequence.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAgentModel::InvalidSequence`] for zero or `u64::MAX`.
    pub const fn new(value: u64) -> Result<Self, InvalidAgentModel> {
        if value == 0 || value == u64::MAX {
            Err(InvalidAgentModel::InvalidSequence)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the portable integer value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Advances without entering the exhausted sentinel.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAgentModel::SequenceExhausted`] at `u64::MAX - 1`.
    pub const fn checked_next(self) -> Result<Self, InvalidAgentModel> {
        if self.0 >= u64::MAX - 1 {
            Err(InvalidAgentModel::SequenceExhausted)
        } else {
            Ok(Self(self.0 + 1))
        }
    }
}

/// Defines the closed guest-agent operation vocabulary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentExecutionOperationV1 {
    /// Hands off one exact durably admitted execution specification.
    Authorize {
        /// Durable execution identity.
        execution: ExecutionId,
        /// Exact canonical execution-specification bytes.
        specification_bytes: Vec<u8>,
        /// Exact execution-specification digest.
        specification_digest: ObjectDigest,
        /// Durable admission-record commitment.
        admission_commitment: ObjectDigest,
        /// Authenticated principal bound to the execution.
        principal: PrincipalId,
        /// Durable audit identity.
        audit: AuditId,
    },
    /// Changes terminal geometry for an exact running execution.
    ResizeTerminal {
        /// Durable execution identity.
        execution: ExecutionId,
        /// Positive terminal row count.
        rows: u16,
        /// Positive terminal column count.
        columns: u16,
    },
    /// Delivers one closed portable signal code.
    Signal {
        /// Durable execution identity.
        execution: ExecutionId,
        /// Portable signal number in the closed range 1 through 64.
        signal_code: u8,
    },
    /// Cancels one exact nonterminal execution.
    Cancel {
        /// Durable execution identity.
        execution: ExecutionId,
    },
    /// Observes one exact execution without mutation.
    Observe {
        /// Durable execution identity.
        execution: ExecutionId,
    },
    /// Enters the guest-local quiesce barrier after execution admission closes.
    BeginQuiesce,
    /// Leaves the exact guest-local quiesce barrier.
    EndQuiesce,
}

impl AgentExecutionOperationV1 {
    /// Returns the closed operation code.
    #[must_use]
    pub const fn code(&self) -> u8 {
        match self {
            Self::Authorize { .. } => 1,
            Self::ResizeTerminal { .. } => 2,
            Self::Signal { .. } => 3,
            Self::Cancel { .. } => 4,
            Self::Observe { .. } => 5,
            Self::BeginQuiesce => 6,
            Self::EndQuiesce => 7,
        }
    }

    /// Returns the targeted execution when the operation is execution-scoped.
    #[must_use]
    pub const fn execution(&self) -> Option<ExecutionId> {
        match self {
            Self::Authorize { execution, .. }
            | Self::ResizeTerminal { execution, .. }
            | Self::Signal { execution, .. }
            | Self::Cancel { execution }
            | Self::Observe { execution } => Some(*execution),
            Self::BeginQuiesce | Self::EndQuiesce => None,
        }
    }
}

/// Carries one exact bounded operation under a live session binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentOperationRequestV1 {
    session: AgentSessionBindingV1,
    sequence: AgentOperationSequenceV1,
    operation_id: AgentOperationIdV1,
    backend_request_binding: ObjectDigest,
    operation: AgentExecutionOperationV1,
    request_commitment: ObjectDigest,
}

impl AgentOperationRequestV1 {
    /// Constructs and internally commits one semantically valid operation.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAgentModel`] for a zero backend binding or execution
    /// identity, invalid geometry/signal, oversized or mismatched execution
    /// bytes, or cross-spec principal/audit/execution substitution.
    pub fn new(
        session: AgentSessionBindingV1,
        sequence: AgentOperationSequenceV1,
        operation_id: AgentOperationIdV1,
        backend_request_binding: ObjectDigest,
        operation: AgentExecutionOperationV1,
    ) -> Result<Self, InvalidAgentModel> {
        if backend_request_binding.as_bytes() == &[0; 32] {
            return Err(InvalidAgentModel::Unspecified);
        }
        validate_operation(&operation)?;
        let request_commitment = commit_operation(
            session,
            sequence,
            operation_id,
            backend_request_binding,
            &operation,
        );
        Ok(Self {
            session,
            sequence,
            operation_id,
            backend_request_binding,
            operation,
            request_commitment,
        })
    }

    /// Returns the exact live session binding.
    #[must_use]
    pub const fn session(&self) -> AgentSessionBindingV1 {
        self.session
    }

    /// Returns the stop-and-wait operation sequence.
    #[must_use]
    pub const fn sequence(&self) -> AgentOperationSequenceV1 {
        self.sequence
    }

    /// Returns the idempotent operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> AgentOperationIdV1 {
        self.operation_id
    }

    /// Returns the exact phase-independent core request binding.
    #[must_use]
    pub const fn backend_request_binding(&self) -> ObjectDigest {
        self.backend_request_binding
    }

    /// Returns the closed operation and exact arguments.
    #[must_use]
    pub const fn operation(&self) -> &AgentExecutionOperationV1 {
        &self.operation
    }

    /// Returns the internally derived complete request commitment.
    #[must_use]
    pub const fn request_commitment(&self) -> ObjectDigest {
        self.request_commitment
    }
}

/// Defines guest-agent execution states returned to the controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentExecutionPhaseV1 {
    /// The exact execution is admitted but has not started.
    Authorized,
    /// Guest-local process creation has begun.
    Starting,
    /// The command is running in the provisioned payload.
    Running,
    /// The command exited with a terminal result.
    Exited,
    /// Cancellation completed with a terminal result.
    Canceled,
    /// Execution failed permanently with a terminal result.
    Failed,
    /// Durable reconciliation cannot establish the command outcome.
    Lost,
    /// The complete guest-local quiesce barrier is held.
    Quiesced,
    /// The guest-local quiesce barrier is released.
    Ready,
}

/// Stores one exact bounded operation outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentExecutionOutcomeV1 {
    session: AgentSessionBindingV1,
    sequence: AgentOperationSequenceV1,
    operation_id: AgentOperationIdV1,
    request_commitment: ObjectDigest,
    phase: AgentExecutionPhaseV1,
    result_bytes: Vec<u8>,
    result_digest: ObjectDigest,
}

impl AgentExecutionOutcomeV1 {
    /// Constructs and commits one exact operation outcome.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAgentModel::InvalidResult`] for empty or oversized bytes.
    pub fn new(
        request: &AgentOperationRequestV1,
        phase: AgentExecutionPhaseV1,
        result_bytes: Vec<u8>,
    ) -> Result<Self, InvalidAgentModel> {
        if result_bytes.is_empty() || result_bytes.len() > MAX_AGENT_RESULT_BYTES {
            return Err(InvalidAgentModel::InvalidResult);
        }
        let result_digest = result_digest(&result_bytes);
        Ok(Self {
            session: request.session(),
            sequence: request.sequence(),
            operation_id: request.operation_id(),
            request_commitment: request.request_commitment(),
            phase,
            result_bytes,
            result_digest,
        })
    }

    /// Returns the exact session binding.
    #[must_use]
    pub const fn session(&self) -> AgentSessionBindingV1 {
        self.session
    }

    /// Returns the exact operation sequence.
    #[must_use]
    pub const fn sequence(&self) -> AgentOperationSequenceV1 {
        self.sequence
    }

    /// Returns the operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> AgentOperationIdV1 {
        self.operation_id
    }

    /// Returns the request commitment answered by this outcome.
    #[must_use]
    pub const fn request_commitment(&self) -> ObjectDigest {
        self.request_commitment
    }

    /// Returns the closed observed phase.
    #[must_use]
    pub const fn phase(&self) -> AgentExecutionPhaseV1 {
        self.phase
    }

    /// Returns exact canonical result bytes.
    #[must_use]
    pub fn result_bytes(&self) -> &[u8] {
        &self.result_bytes
    }

    /// Returns the internally derived result commitment.
    #[must_use]
    pub const fn result_digest(&self) -> ObjectDigest {
        self.result_digest
    }

    /// Returns the internally derived commitment to the complete outcome.
    #[must_use]
    pub fn outcome_commitment(&self) -> ObjectDigest {
        aos_sandbox_core::runtime_backend::backend_agent_outcome_commitment_v1(
            self.session.digest(),
            self.sequence.get(),
            *self.operation_id.as_bytes(),
            self.request_commitment,
            phase_code(self.phase),
            &self.result_bytes,
            self.result_digest,
        )
    }

    pub(crate) fn restore(
        session: AgentSessionBindingV1,
        sequence: AgentOperationSequenceV1,
        operation_id: AgentOperationIdV1,
        request_commitment: ObjectDigest,
        phase: AgentExecutionPhaseV1,
        result_bytes: Vec<u8>,
        result_digest: ObjectDigest,
    ) -> Result<Self, InvalidAgentModel> {
        if request_commitment.as_bytes() == &[0; 32]
            || result_bytes.is_empty()
            || result_bytes.len() > MAX_AGENT_RESULT_BYTES
            || result_digest != self::result_digest(&result_bytes)
        {
            return Err(InvalidAgentModel::InvalidResult);
        }
        Ok(Self {
            session,
            sequence,
            operation_id,
            request_commitment,
            phase,
            result_bytes,
            result_digest,
        })
    }
}

/// Reports invalid portable guest-agent model input.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidAgentModel {
    /// An identity, generation, or commitment uses its zero sentinel.
    #[error("agent model contains an unspecified field")]
    Unspecified,
    /// Feature set is empty, oversized, unordered, duplicated, or incomplete.
    #[error("agent feature set is invalid")]
    InvalidFeatures,
    /// A protected handshake signer returned an invalid signature.
    #[error("agent handshake signature is invalid")]
    InvalidSignature,
    /// Operation sequence is zero or uses the exhausted sentinel.
    #[error("agent operation sequence is invalid")]
    InvalidSequence,
    /// Operation sequence cannot advance safely.
    #[error("agent operation sequence is exhausted")]
    SequenceExhausted,
    /// Operation arguments or target are invalid.
    #[error("agent operation is invalid")]
    InvalidOperation,
    /// Execution specification bytes are malformed, mismatched, or oversized.
    #[error("agent execution specification is invalid")]
    InvalidExecutionSpecification,
    /// Result bytes are empty or oversized.
    #[error("agent operation result is invalid")]
    InvalidResult,
}

fn validate_operation(operation: &AgentExecutionOperationV1) -> Result<(), InvalidAgentModel> {
    match operation {
        AgentExecutionOperationV1::Authorize {
            execution,
            specification_bytes,
            specification_digest,
            admission_commitment,
            principal,
            audit,
        } => {
            if execution.as_bytes() == &[0; 16]
                || specification_bytes.is_empty()
                || specification_bytes.len() > MAX_EXECUTION_SPEC_BYTES
                || specification_digest.as_bytes() == &[0; 32]
                || admission_commitment.as_bytes() == &[0; 32]
                || principal.as_bytes() == &[0; 16]
                || audit.as_bytes() == &[0; 16]
            {
                return Err(InvalidAgentModel::InvalidExecutionSpecification);
            }
            let specification = aos_sandbox_core::decode_execution_spec_v1(
                specification_bytes,
                execution_limits(specification_bytes.len()),
            )
            .map_err(|_| InvalidAgentModel::InvalidExecutionSpecification)?;
            if specification.execution() != *execution
                || aos_sandbox_core::execution_spec_digest_v1(&specification)
                    != *specification_digest
                || specification.principal() != *principal
                || specification.audit() != *audit
            {
                return Err(InvalidAgentModel::InvalidExecutionSpecification);
            }
        }
        AgentExecutionOperationV1::ResizeTerminal {
            execution,
            rows,
            columns,
        } => {
            if execution.as_bytes() == &[0; 16] || *rows == 0 || *columns == 0 {
                return Err(InvalidAgentModel::InvalidOperation);
            }
        }
        AgentExecutionOperationV1::Signal {
            execution,
            signal_code,
        } => {
            if execution.as_bytes() == &[0; 16] || !(1..=64).contains(signal_code) {
                return Err(InvalidAgentModel::InvalidOperation);
            }
        }
        AgentExecutionOperationV1::Cancel { execution }
        | AgentExecutionOperationV1::Observe { execution } => {
            if execution.as_bytes() == &[0; 16] {
                return Err(InvalidAgentModel::InvalidOperation);
            }
        }
        AgentExecutionOperationV1::BeginQuiesce | AgentExecutionOperationV1::EndQuiesce => {}
    }
    Ok(())
}

fn commit_operation(
    session: AgentSessionBindingV1,
    sequence: AgentOperationSequenceV1,
    operation_id: AgentOperationIdV1,
    backend_request_binding: ObjectDigest,
    operation: &AgentExecutionOperationV1,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(OPERATION_REQUEST_DOMAIN);
    digest.update(session.digest().as_bytes());
    digest.update(sequence.get().to_be_bytes());
    digest.update(operation_id.as_bytes());
    digest.update(backend_request_binding.as_bytes());
    digest.update([operation.code()]);
    match operation {
        AgentExecutionOperationV1::Authorize {
            execution,
            specification_bytes,
            specification_digest,
            admission_commitment,
            principal,
            audit,
        } => {
            digest.update(execution.as_bytes());
            digest.update((specification_bytes.len() as u64).to_be_bytes());
            digest.update(specification_bytes);
            digest.update(specification_digest.as_bytes());
            digest.update(admission_commitment.as_bytes());
            digest.update(principal.as_bytes());
            digest.update(audit.as_bytes());
        }
        AgentExecutionOperationV1::ResizeTerminal {
            execution,
            rows,
            columns,
        } => {
            digest.update(execution.as_bytes());
            digest.update(rows.to_be_bytes());
            digest.update(columns.to_be_bytes());
        }
        AgentExecutionOperationV1::Signal {
            execution,
            signal_code,
        } => {
            digest.update(execution.as_bytes());
            digest.update([*signal_code]);
        }
        AgentExecutionOperationV1::Cancel { execution }
        | AgentExecutionOperationV1::Observe { execution } => digest.update(execution.as_bytes()),
        AgentExecutionOperationV1::BeginQuiesce | AgentExecutionOperationV1::EndQuiesce => {}
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn result_digest(bytes: &[u8]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-agent-result-v1\0");
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    ObjectDigest::from_bytes(digest.finalize().into())
}

const fn phase_code(phase: AgentExecutionPhaseV1) -> u8 {
    match phase {
        AgentExecutionPhaseV1::Authorized => 1,
        AgentExecutionPhaseV1::Starting => 2,
        AgentExecutionPhaseV1::Running => 3,
        AgentExecutionPhaseV1::Exited => 4,
        AgentExecutionPhaseV1::Canceled => 5,
        AgentExecutionPhaseV1::Failed => 6,
        AgentExecutionPhaseV1::Lost => 7,
        AgentExecutionPhaseV1::Quiesced => 8,
        AgentExecutionPhaseV1::Ready => 9,
    }
}

fn execution_limits(maximum_bytes: usize) -> aos_sandbox_core::DecodeLimits {
    aos_sandbox_core::DecodeLimits {
        maximum_bytes,
        maximum_collection_items: 65_536,
        maximum_total_items: 262_144,
        maximum_byte_string_bytes: MAX_EXECUTION_SPEC_BYTES,
        maximum_text_bytes: 1_048_576,
        maximum_depth: 128,
    }
}
