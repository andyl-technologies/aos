//! Guest-agent handshake, replay, sequence-CAS, and execution state reducer.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};

use aos_sandbox_core::{ExecutionId, ObjectDigest};

use aos_sandbox_agent::{
    AgentExecutionOperationV1, AgentExecutionOutcomeV1, AgentExecutionPhaseV1, AgentFeatureSetV1,
    AgentFeatureV1, AgentHandshakeRequestV1, AgentHandshakeResponseV1, AgentOperationIdV1,
    AgentOperationRequestV1, AgentOperationSequenceV1, AgentRuntimeBindingV1,
    AgentSessionBindingV1, InvalidAgentModel,
};

use super::agent_checkpoint::{
    AgentCheckpointCandidateV1, AgentDurableCheckpointV1, OutstandingCheckpointState,
    ReducerCheckpointState, SessionCheckpointState, checkpoint_from_reducer, reopen_reducer,
};

const HANDSHAKE_SIGNATURE_DOMAIN: &[u8] = b"aos-sandbox-agent-handshake-signature-v1\0";
const MAX_ACTIVE_EXECUTIONS: usize = 4_096;
const MAX_COMPLETED_HISTORY: usize = 1_024;

/// Stores protected expectations provisioned for one agent process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentProvisioningV1 {
    runtime: AgentRuntimeBindingV1,
    host_channel_binding: ObjectDigest,
    agent_instance: [u8; 16],
    features: AgentFeatureSetV1,
    recovery_authority_binding: ObjectDigest,
}

impl AgentProvisioningV1 {
    /// Constructs exact process-local provisioning state.
    ///
    /// # Errors
    ///
    /// Returns [`AgentReducerError::InvalidProvisioning`] for a zero channel,
    /// agent instance, or recovered-outcome authority binding.
    pub fn new(
        runtime: AgentRuntimeBindingV1,
        host_channel_binding: ObjectDigest,
        agent_instance: [u8; 16],
        features: AgentFeatureSetV1,
        recovery_authority_binding: ObjectDigest,
    ) -> Result<Self, AgentReducerError> {
        if host_channel_binding.as_bytes() == &[0; 32]
            || agent_instance == [0; 16]
            || recovery_authority_binding.as_bytes() == &[0; 32]
        {
            return Err(AgentReducerError::InvalidProvisioning);
        }
        Ok(Self {
            runtime,
            host_channel_binding,
            agent_instance,
            features,
            recovery_authority_binding,
        })
    }

    /// Returns the exact provisioned runtime binding.
    #[must_use]
    pub const fn runtime(&self) -> &AgentRuntimeBindingV1 {
        &self.runtime
    }

    /// Returns the protected channel binding.
    #[must_use]
    pub const fn host_channel_binding(&self) -> ObjectDigest {
        self.host_channel_binding
    }

    /// Returns the process-unique agent instance.
    #[must_use]
    pub const fn agent_instance(&self) -> &[u8; 16] {
        &self.agent_instance
    }

    /// Returns the fixed advertised feature set.
    #[must_use]
    pub const fn features(&self) -> &AgentFeatureSetV1 {
        &self.features
    }

    /// Returns the protected key identity authorized for Reserved recovery.
    #[must_use]
    pub const fn recovery_authority_binding(&self) -> ObjectDigest {
        self.recovery_authority_binding
    }
}

/// Signs one exact domain-separated handshake message using protected key custody.
pub trait AgentHandshakeSigner {
    /// Returns an exact 64-byte signature without exposing private key material.
    ///
    /// # Errors
    ///
    /// Returns [`AgentReducerError`] if protected key custody is unavailable or
    /// refuses the exact handshake binding.
    fn sign_handshake(&mut self, signing_message: &[u8]) -> Result<[u8; 64], AgentReducerError>;
}

/// Signs one durably completed agent outcome using protected peer key custody.
pub trait AgentOutcomeSigner {
    /// Signs the exact Host-bound outcome transcript without exposing the key.
    ///
    /// # Errors
    ///
    /// Returns [`AgentReducerError`] if protected key custody is unavailable
    /// or refuses this outcome transcript.
    fn sign_outcome(&mut self, signing_message: &[u8]) -> Result<[u8; 64], AgentReducerError>;
}

/// Records an atomic operation-sequence reservation from the durable agent store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentOperationReservationV1 {
    session: AgentSessionBindingV1,
    sequence: AgentOperationSequenceV1,
    operation_id: AgentOperationIdV1,
    request_commitment: ObjectDigest,
    store_commitment: ObjectDigest,
    disposition: AgentReservationDispositionV1,
}

/// Classifies whether a CAS reservation is new or an exact durable replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentReservationDispositionV1 {
    /// This CAS call created the durable reservation.
    Created,
    /// The byte-identical reservation already existed before this call.
    ExactReplay,
}

impl AgentOperationReservationV1 {
    /// Constructs a store-produced non-sentinel reservation.
    ///
    /// # Errors
    ///
    /// Returns [`AgentOperationCasError::InvalidReceipt`] for a zero store commitment.
    pub fn new(
        session: AgentSessionBindingV1,
        sequence: AgentOperationSequenceV1,
        operation_id: AgentOperationIdV1,
        request_commitment: ObjectDigest,
        store_commitment: ObjectDigest,
        disposition: AgentReservationDispositionV1,
    ) -> Result<Self, AgentOperationCasError> {
        if request_commitment.as_bytes() == &[0; 32] || store_commitment.as_bytes() == &[0; 32] {
            return Err(AgentOperationCasError::InvalidReceipt);
        }
        Ok(Self {
            session,
            sequence,
            operation_id,
            request_commitment,
            store_commitment,
            disposition,
        })
    }

    /// Returns the exact session binding.
    #[must_use]
    pub const fn session(&self) -> AgentSessionBindingV1 {
        self.session
    }

    /// Returns the reserved sequence.
    #[must_use]
    pub const fn sequence(&self) -> AgentOperationSequenceV1 {
        self.sequence
    }

    /// Returns the idempotent operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> AgentOperationIdV1 {
        self.operation_id
    }

    /// Returns the exact request commitment.
    #[must_use]
    pub const fn request_commitment(&self) -> ObjectDigest {
        self.request_commitment
    }

    /// Returns the protected reservation commitment.
    #[must_use]
    pub const fn store_commitment(&self) -> ObjectDigest {
        self.store_commitment
    }

    /// Returns whether this call created or exactly replayed the reservation.
    #[must_use]
    pub const fn disposition(&self) -> AgentReservationDispositionV1 {
        self.disposition
    }
}

/// Owns atomic sequence reservation and outcome completion for the agent session.
pub(super) trait AgentOperationCas {
    /// Atomically reserves the exact next sequence and request binding.
    ///
    /// # Errors
    ///
    /// Returns [`AgentOperationCasError`] for sequence conflict, equivocation,
    /// invalid receipt state, or ambiguous durability.
    fn reserve_operation(
        &mut self,
        request: &AgentOperationRequestV1,
    ) -> Result<AgentReservationStoreTransitionV1, AgentOperationCasError>;
    /// Atomically commits the exact response before it can be returned.
    ///
    /// Success returns [`AgentExecutionOutcomeV1::outcome_commitment`] for the
    /// exact supplied outcome. Another digest is an invalid receipt.
    ///
    /// # Errors
    ///
    /// Returns [`AgentOperationCasError`] for reservation conflict,
    /// equivocation, invalid receipt state, or ambiguous durability.
    fn commit_operation_outcome(
        &mut self,
        reservation: &AgentOperationReservationV1,
        outcome: &AgentExecutionOutcomeV1,
    ) -> Result<AgentOutcomeStoreTransitionV1, AgentOperationCasError>;
}

/// Borrows one canonical protected-store history row for reducer replay.
pub struct AgentDurableHistoryRecordV1<'record> {
    request: &'record AgentOperationRequestV1,
    store_commitment: ObjectDigest,
    outcome: Option<&'record AgentExecutionOutcomeV1>,
}

impl<'record> AgentDurableHistoryRecordV1<'record> {
    /// Constructs one history row from its exact request and optional outcome.
    #[must_use]
    pub const fn new(
        request: &'record AgentOperationRequestV1,
        store_commitment: ObjectDigest,
        outcome: Option<&'record AgentExecutionOutcomeV1>,
    ) -> Self {
        Self {
            request,
            store_commitment,
            outcome,
        }
    }
}

/// Reports a committed reservation or exact store ambiguity metadata.
#[must_use]
pub enum AgentReservationStoreTransitionV1 {
    /// The exact reservation is durably committed.
    Committed(AgentOperationReservationV1),
    /// The store append may have committed and must be recovered before dispatch.
    RecoveryRequired {
        /// Predicted exact reservation-store commitment.
        store_commitment: ObjectDigest,
        /// Commitment to the exact predecessor sequence head.
        predecessor_commitment: ObjectDigest,
        /// Store-authenticated binding of the ambiguity metadata.
        recovery_binding: ObjectDigest,
    },
}

/// Reports a committed terminal outcome or exact store ambiguity metadata.
#[must_use]
pub enum AgentOutcomeStoreTransitionV1 {
    /// The exact terminal outcome is durably committed.
    Committed(ObjectDigest),
    /// The outcome append may have committed and must be cold-reopened.
    RecoveryRequired {
        /// Commitment to the exact terminal outcome.
        outcome_commitment: ObjectDigest,
        /// Commitment to the reservation record preceding the append.
        predecessor_commitment: ObjectDigest,
        /// Store-authenticated binding of the ambiguity metadata.
        recovery_binding: ObjectDigest,
    },
}

/// Retains one exact may-have-committed operation reservation across checkpoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentReservationRecoveryTokenV1 {
    session: AgentSessionBindingV1,
    sequence: AgentOperationSequenceV1,
    operation_id: AgentOperationIdV1,
    request_commitment: ObjectDigest,
    store_commitment: ObjectDigest,
    predecessor_commitment: ObjectDigest,
    recovery_binding: ObjectDigest,
}

impl AgentReservationRecoveryTokenV1 {
    pub(crate) fn from_store_ambiguity(
        request: &AgentOperationRequestV1,
        store_commitment: ObjectDigest,
        predecessor_commitment: ObjectDigest,
        recovery_binding: ObjectDigest,
    ) -> Result<Self, AgentOperationCasError> {
        if store_commitment.as_bytes() == &[0; 32]
            || predecessor_commitment.as_bytes() == &[0; 32]
            || recovery_binding.as_bytes() == &[0; 32]
        {
            return Err(AgentOperationCasError::InvalidReceipt);
        }
        Ok(Self {
            session: request.session(),
            sequence: request.sequence(),
            operation_id: request.operation_id(),
            request_commitment: request.request_commitment(),
            store_commitment,
            predecessor_commitment,
            recovery_binding,
        })
    }

    /// Returns the exact session binding.
    #[must_use]
    pub const fn session(&self) -> AgentSessionBindingV1 {
        self.session
    }

    /// Returns the exact reserved sequence.
    #[must_use]
    pub const fn sequence(&self) -> AgentOperationSequenceV1 {
        self.sequence
    }

    /// Returns the exact idempotency identity.
    #[must_use]
    pub const fn operation_id(&self) -> AgentOperationIdV1 {
        self.operation_id
    }

    /// Returns the exact request commitment.
    #[must_use]
    pub const fn request_commitment(&self) -> ObjectDigest {
        self.request_commitment
    }

    /// Returns the predicted protected reservation commitment.
    #[must_use]
    pub const fn store_commitment(&self) -> ObjectDigest {
        self.store_commitment
    }

    /// Returns the exact predecessor-head commitment.
    #[must_use]
    pub const fn predecessor_commitment(&self) -> ObjectDigest {
        self.predecessor_commitment
    }

    /// Returns the protected store's ambiguity binding.
    #[must_use]
    pub const fn recovery_binding(&self) -> ObjectDigest {
        self.recovery_binding
    }
}

/// Retains one exact may-have-committed terminal outcome across cold reopen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentOutcomeRecoveryTokenV1 {
    session: AgentSessionBindingV1,
    sequence: AgentOperationSequenceV1,
    operation_id: AgentOperationIdV1,
    request_commitment: ObjectDigest,
    store_commitment: ObjectDigest,
    outcome_commitment: ObjectDigest,
    predecessor_commitment: ObjectDigest,
    recovery_binding: ObjectDigest,
}

impl AgentOutcomeRecoveryTokenV1 {
    fn from_store_ambiguity(
        reservation: &AgentOperationReservationV1,
        outcome: &AgentExecutionOutcomeV1,
        outcome_commitment: ObjectDigest,
        predecessor_commitment: ObjectDigest,
        recovery_binding: ObjectDigest,
    ) -> Result<Self, AgentOperationCasError> {
        if outcome_commitment != outcome.outcome_commitment()
            || predecessor_commitment.as_bytes() == &[0; 32]
            || recovery_binding.as_bytes() == &[0; 32]
        {
            return Err(AgentOperationCasError::InvalidReceipt);
        }
        Ok(Self {
            session: reservation.session(),
            sequence: reservation.sequence(),
            operation_id: reservation.operation_id(),
            request_commitment: reservation.request_commitment(),
            store_commitment: reservation.store_commitment(),
            outcome_commitment,
            predecessor_commitment,
            recovery_binding,
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

    /// Returns the exact operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> AgentOperationIdV1 {
        self.operation_id
    }

    /// Returns the exact request commitment.
    #[must_use]
    pub const fn request_commitment(&self) -> ObjectDigest {
        self.request_commitment
    }

    /// Returns the protected reservation commitment.
    #[must_use]
    pub const fn store_commitment(&self) -> ObjectDigest {
        self.store_commitment
    }

    /// Returns the exact terminal outcome commitment.
    #[must_use]
    pub const fn outcome_commitment(&self) -> ObjectDigest {
        self.outcome_commitment
    }

    /// Returns the exact pre-append record commitment.
    #[must_use]
    pub const fn predecessor_commitment(&self) -> ObjectDigest {
        self.predecessor_commitment
    }

    /// Returns the protected store's ambiguity binding.
    #[must_use]
    pub const fn recovery_binding(&self) -> ObjectDigest {
        self.recovery_binding
    }
}

/// Reports protected recovery of a may-have-committed reservation.
#[must_use]
pub enum AgentRecoveredReservationV1 {
    /// The exact reservation committed and is now recovery-only.
    Committed(AgentOperationReservationV1),
    /// Protected reopen proved the reservation transaction absent.
    Absent,
}

/// Reports protected state for one operation after an agent process restart.
#[must_use]
pub enum AgentRecoveredOperationV1 {
    /// The exact reservation remains durable and requires authenticated
    /// observation or terminal outcome commitment before the session proceeds.
    Reserved,
    /// The exact request has a durable completed outcome.
    Completed(AgentExecutionOutcomeV1),
    /// Protected storage proves the reservation is absent.
    Absent,
}

/// Owns a recovered outcome authenticated by guest-local protected evidence.
pub struct AuthenticatedRecoveredAgentOutcomeV1 {
    outcome: AgentExecutionOutcomeV1,
    provenance: ObjectDigest,
    authority_binding: ObjectDigest,
}

impl AuthenticatedRecoveredAgentOutcomeV1 {
    /// Returns the exact authenticated recovered outcome.
    #[must_use]
    pub const fn outcome(&self) -> &AgentExecutionOutcomeV1 {
        &self.outcome
    }

    /// Returns the protected observation provenance commitment.
    #[must_use]
    pub const fn provenance(&self) -> ObjectDigest {
        self.provenance
    }

    /// Returns the exact recovery key identity that authenticated the outcome.
    #[must_use]
    pub const fn authority_binding(&self) -> ObjectDigest {
        self.authority_binding
    }
}

/// Carries an untrusted signed recovered-outcome envelope.
pub struct SignedRecoveredAgentOutcomeV1 {
    outcome: AgentExecutionOutcomeV1,
    signature: [u8; 64],
}

impl SignedRecoveredAgentOutcomeV1 {
    /// Constructs an untrusted envelope for concrete signature verification.
    #[must_use]
    pub const fn new(outcome: AgentExecutionOutcomeV1, signature: [u8; 64]) -> Self {
        Self { outcome, signature }
    }
}

/// Mints an opaque recovered outcome through concrete Ed25519 verification.
///
/// # Errors
///
/// Returns [`AgentOperationCasError`] if the key/signature is invalid, the
/// outcome answers another request, or its phase is not definitive.
pub fn verify_signed_recovered_agent_outcome_v1(
    request: &AgentOperationRequestV1,
    public_key: &[u8; 32],
    authority_binding: ObjectDigest,
    signed: SignedRecoveredAgentOutcomeV1,
) -> Result<AuthenticatedRecoveredAgentOutcomeV1, AgentOperationCasError> {
    if public_key == &[0; 32] || authority_binding.as_bytes() == &[0; 32] {
        return Err(AgentOperationCasError::InvalidReceipt);
    }
    let outcome = signed.outcome;
    if outcome.session() != request.session()
        || outcome.sequence() != request.sequence()
        || outcome.operation_id() != request.operation_id()
        || outcome.request_commitment() != request.request_commitment()
        || !recovered_outcome_shape_is_terminal(request.operation(), outcome.phase())
    {
        return Err(AgentOperationCasError::InvalidReceipt);
    }
    let message = recovered_agent_outcome_signing_message_v1(request, &outcome);
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| AgentOperationCasError::InvalidReceipt)?;
    verifying_key
        .verify_strict(&message, &Signature::from_bytes(&signed.signature))
        .map_err(|_| AgentOperationCasError::InvalidReceipt)?;
    let provenance = recovered_outcome_provenance(public_key, &message, &signed.signature);
    Ok(AuthenticatedRecoveredAgentOutcomeV1 {
        outcome,
        provenance,
        authority_binding,
    })
}

/// Returns the canonical message protected recovery key custody must sign.
#[must_use]
pub fn recovered_agent_outcome_signing_message_v1(
    request: &AgentOperationRequestV1,
    outcome: &AgentExecutionOutcomeV1,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-agent-recovered-outcome-signature-v1\0");
    digest.update(request.session().digest().as_bytes());
    digest.update(request.sequence().get().to_be_bytes());
    digest.update(request.operation_id().as_bytes());
    digest.update(request.request_commitment().as_bytes());
    digest.update(outcome.outcome_commitment().as_bytes());
    digest.finalize().into()
}

fn recovered_outcome_provenance(
    public_key: &[u8; 32],
    message: &[u8; 32],
    signature: &[u8; 64],
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-agent-recovered-outcome-provenance-v1\0");
    digest.update(public_key);
    digest.update(message);
    digest.update(signature);
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn recovered_outcome_shape_is_terminal(
    operation: &AgentExecutionOperationV1,
    phase: AgentExecutionPhaseV1,
) -> bool {
    match operation {
        AgentExecutionOperationV1::Authorize { .. } => matches!(
            phase,
            AgentExecutionPhaseV1::Authorized
                | AgentExecutionPhaseV1::Starting
                | AgentExecutionPhaseV1::Running
                | AgentExecutionPhaseV1::Failed
        ),
        AgentExecutionOperationV1::ResizeTerminal { .. }
        | AgentExecutionOperationV1::Signal { .. }
        | AgentExecutionOperationV1::Observe { .. } => !matches!(
            phase,
            AgentExecutionPhaseV1::Quiesced | AgentExecutionPhaseV1::Ready
        ),
        AgentExecutionOperationV1::Cancel { .. } => matches!(
            phase,
            AgentExecutionPhaseV1::Exited
                | AgentExecutionPhaseV1::Canceled
                | AgentExecutionPhaseV1::Failed
                | AgentExecutionPhaseV1::Lost
        ),
        AgentExecutionOperationV1::BeginQuiesce => phase == AgentExecutionPhaseV1::Quiesced,
        AgentExecutionOperationV1::EndQuiesce => phase == AgentExecutionPhaseV1::Ready,
    }
}

/// Authenticates outstanding operation state after reopening a checkpoint.
pub(super) trait AgentOperationRecoveryCas {
    /// Resolves an ambiguous reservation without creating another transaction.
    ///
    /// # Errors
    ///
    /// Returns [`AgentOperationCasError`] for foreign tokens, equivocation,
    /// corrupt predecessor state, or unavailable protected storage.
    fn recover_reservation(
        &mut self,
        token: &AgentReservationRecoveryTokenV1,
        request: &AgentOperationRequestV1,
    ) -> Result<AgentRecoveredReservationV1, AgentOperationCasError>;

    /// Loads one exact reservation/outcome without reissuing its effect.
    ///
    /// # Errors
    ///
    /// Returns [`AgentOperationCasError`] for unavailable, corrupt, ambiguous,
    /// or equivocating protected state.
    fn recover_operation(
        &mut self,
        reservation: &AgentOperationReservationV1,
        request: &AgentOperationRequestV1,
    ) -> Result<AgentRecoveredOperationV1, AgentOperationCasError>;

    /// Resolves one ambiguous terminal append without writing or redispatching.
    ///
    /// # Errors
    ///
    /// Returns [`AgentOperationCasError`] for a foreign token, substituted
    /// outcome, corrupt predecessor state, or unavailable protected storage.
    fn recover_outcome_commit(
        &mut self,
        token: &AgentOutcomeRecoveryTokenV1,
        reservation: &AgentOperationReservationV1,
        outcome: &AgentExecutionOutcomeV1,
    ) -> Result<AgentRecoveredOutcomeCommitV1, AgentOperationCasError>;

    /// Resolves a Reserved record only from authenticated process observation.
    ///
    /// # Errors
    ///
    /// Returns [`AgentOperationCasError`] for binding mismatch, equivocation,
    /// ambiguous durability, or nonterminal protected observation.
    fn resolve_reserved_operation(
        &mut self,
        reservation: &AgentOperationReservationV1,
        request: &AgentOperationRequestV1,
        authenticated: AuthenticatedRecoveredAgentOutcomeV1,
    ) -> Result<AgentOutcomeStoreTransitionV1, AgentOperationCasError>;
}

/// Reports the cold-reopened result of one ambiguous terminal append.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentRecoveredOutcomeCommitV1 {
    /// The exact terminal outcome is present and authenticated.
    Committed(ObjectDigest),
    /// The exact predecessor remains present, proving the append absent.
    Absent,
}

/// Names the guest-local action authorized by a prepared operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentDecisionV1 {
    /// Hands off the exact execution specification in the prepared request.
    HandoffExecution(ExecutionId),
    /// Changes PTY geometry for an exact running execution.
    ResizeTerminal {
        /// Durable execution identity.
        execution: ExecutionId,
        /// Positive terminal row count.
        rows: u16,
        /// Positive terminal column count.
        columns: u16,
    },
    /// Delivers one closed signal code.
    Signal {
        /// Durable execution identity.
        execution: ExecutionId,
        /// Portable signal number in the closed range 1 through 64.
        signal_code: u8,
    },
    /// Cancels one exact execution.
    Cancel(ExecutionId),
    /// Observes one exact execution without mutation.
    Observe(ExecutionId),
    /// Begins the guest-local quiesce barrier.
    BeginQuiesce,
    /// Ends the exact guest-local quiesce barrier.
    EndQuiesce,
}

/// Owns a durably reserved request and its validated semantic decision.
pub struct PreparedAgentOperationV1 {
    request: AgentOperationRequestV1,
    reservation: AgentOperationReservationV1,
    decision: AgentDecisionV1,
}

impl PreparedAgentOperationV1 {
    /// Returns the complete exact request, including execution bytes.
    #[must_use]
    pub const fn request(&self) -> &AgentOperationRequestV1 {
        &self.request
    }

    /// Returns the protected sequence reservation.
    #[must_use]
    pub const fn reservation(&self) -> &AgentOperationReservationV1 {
        &self.reservation
    }

    /// Returns the closed guest-local decision.
    #[must_use]
    pub const fn decision(&self) -> AgentDecisionV1 {
        self.decision
    }
}

/// Classifies a newly reserved request, exact completed replay, or in-flight replay.
#[must_use]
pub enum AgentReplayDispositionV1 {
    /// The request is newly reserved and may cross the guest-local effect boundary.
    Prepared(PreparedAgentOperationV1),
    /// The byte-identical latest completed request returns its retained outcome.
    ExactReplay(AgentExecutionOutcomeV1),
    /// The byte-identical outstanding request must be resolved, not reissued.
    OutstandingExact,
    /// Reservation durability is ambiguous and is retained for checkpoint recovery.
    ReservationRecoveryRequired(AgentReservationRecoveryTokenV1),
}

struct SessionState {
    binding: AgentSessionBindingV1,
    next_sequence: AgentOperationSequenceV1,
    outstanding: Option<OutstandingOperation>,
    completed_history: Vec<AgentExecutionOutcomeV1>,
    poisoned: bool,
}

#[derive(Clone)]
enum OutstandingOperation {
    Reserved {
        reservation: AgentOperationReservationV1,
        request: AgentOperationRequestV1,
    },
    ReservationRecovery {
        token: AgentReservationRecoveryTokenV1,
        request: AgentOperationRequestV1,
    },
}

impl OutstandingOperation {
    fn request(&self) -> &AgentOperationRequestV1 {
        match self {
            Self::Reserved { request, .. } | Self::ReservationRecovery { request, .. } => request,
        }
    }

    fn reservation(&self) -> Option<&AgentOperationReservationV1> {
        match self {
            Self::Reserved { reservation, .. } => Some(reservation),
            Self::ReservationRecovery { .. } => None,
        }
    }
}

/// Reduces one provisioned agent process without performing guest effects.
pub struct GuestAgentReducerV1 {
    provisioning: AgentProvisioningV1,
    session: Option<SessionState>,
    executions: BTreeMap<ExecutionId, AgentExecutionPhaseV1>,
    quiesced: bool,
}

impl GuestAgentReducerV1 {
    pub(super) fn recovery_cursor(
        &self,
    ) -> Result<(AgentSessionBindingV1, AgentOperationSequenceV1), AgentReducerError> {
        let session = self.session.as_ref().ok_or(AgentReducerError::NoSession)?;
        Ok((session.binding, session.next_sequence))
    }

    pub(super) fn outstanding_for_reopen(
        &self,
    ) -> Option<(&AgentOperationReservationV1, &AgentOperationRequestV1)> {
        self.session
            .as_ref()
            .and_then(|session| session.outstanding.as_ref())
            .and_then(|outstanding| match outstanding {
                OutstandingOperation::Reserved {
                    reservation,
                    request,
                } => Some((reservation, request)),
                OutstandingOperation::ReservationRecovery { .. } => None,
            })
    }

    pub(super) fn checkpointed_prepared(
        &self,
        request: &AgentOperationRequestV1,
    ) -> Result<PreparedAgentOperationV1, AgentReducerError> {
        let (reservation, retained) = self
            .outstanding_for_reopen()
            .ok_or(AgentReducerError::OutstandingRecordMissing)?;
        if retained != request {
            return Err(AgentReducerError::CasReceiptMismatch);
        }
        Ok(PreparedAgentOperationV1 {
            request: retained.clone(),
            reservation: *reservation,
            decision: self.validate_decision(retained)?,
        })
    }

    pub(super) fn checkpointed_outstanding_prepared(
        &self,
    ) -> Result<PreparedAgentOperationV1, AgentReducerError> {
        let request = self
            .outstanding_for_reopen()
            .map(|(_, request)| request.clone())
            .ok_or(AgentReducerError::OutstandingRecordMissing)?;
        self.checkpointed_prepared(&request)
    }

    pub(super) fn validate_unreserved_successor(
        &self,
        request: &AgentOperationRequestV1,
    ) -> Result<(), AgentReducerError> {
        let session = self.session.as_ref().ok_or(AgentReducerError::NoSession)?;
        if session.poisoned || session.outstanding.is_some() {
            return Err(AgentReducerError::SessionRecoveryRequired);
        }
        if request.session() != session.binding || request.sequence() != session.next_sequence {
            return Err(AgentReducerError::SequenceConflict);
        }
        self.validate_decision(request).map(|_| ())
    }

    pub(super) fn contains_completed_outcome(&self, outcome: &AgentExecutionOutcomeV1) -> bool {
        self.session.as_ref().is_some_and(|session| {
            session
                .completed_history
                .iter()
                .any(|retained| retained == outcome)
        })
    }

    /// Creates an unbound reducer for exact process-local provisioning.
    #[must_use]
    pub fn new(provisioning: AgentProvisioningV1) -> Self {
        Self {
            provisioning,
            session: None,
            executions: BTreeMap::new(),
            quiesced: false,
        }
    }

    /// Authenticates and signs a new exact incarnation session.
    ///
    /// A successful replacement drops volatile replay authority from the old
    /// session and starts sequence one. Durable outstanding effects must be
    /// resolved by the host before it provisions a replacement channel.
    ///
    /// # Errors
    ///
    /// Returns [`AgentReducerError`] for runtime/channel mismatch, signer
    /// failure, or invalid signature output. No session is installed on error.
    pub fn accept_handshake<S: AgentHandshakeSigner>(
        &mut self,
        request: AgentHandshakeRequestV1,
        signer: &mut S,
    ) -> Result<AgentHandshakeResponseV1, AgentReducerError> {
        if self
            .session
            .as_ref()
            .is_some_and(|session| session.outstanding.is_some() || session.poisoned)
        {
            return Err(AgentReducerError::SessionRecoveryRequired);
        }
        if request.runtime() != self.provisioning.runtime()
            || request.host_channel_binding() != self.provisioning.host_channel_binding()
        {
            return Err(AgentReducerError::HandshakeMismatch);
        }
        let binding = AgentSessionBindingV1::derive(&request, self.provisioning.agent_instance())?;
        let signing_message = agent_handshake_signing_message_v1(
            &request,
            binding,
            self.provisioning.agent_instance(),
            self.provisioning.features(),
        );
        let signature = signer.sign_handshake(&signing_message)?;
        let response = AgentHandshakeResponseV1::new(
            binding,
            *self.provisioning.agent_instance(),
            self.provisioning.features().clone(),
            signature,
        )?;
        let next_sequence = AgentOperationSequenceV1::new(1)?;
        self.session = Some(SessionState {
            binding,
            next_sequence,
            outstanding: None,
            completed_history: Vec::new(),
            poisoned: false,
        });
        Ok(response)
    }

    /// Classifies replay, validates state, and atomically reserves a new operation.
    ///
    /// # Errors
    ///
    /// Returns [`AgentReducerError`] for absent/superseded session, sequence
    /// gap/rollback/equivocation, another outstanding request, invalid state,
    /// missing feature, or durable CAS failure.
    pub(super) fn prepare_operation<C: AgentOperationCas>(
        &mut self,
        request: AgentOperationRequestV1,
        cas: &mut C,
    ) -> Result<AgentReplayDispositionV1, AgentReducerError> {
        let session = self.session.as_ref().ok_or(AgentReducerError::NoSession)?;
        if session.poisoned {
            return Err(AgentReducerError::SessionRecoveryRequired);
        }
        if request.session() != session.binding {
            return Err(AgentReducerError::SessionSuperseded);
        }

        if let Some(outstanding) = &session.outstanding {
            let retained = outstanding.request();
            if request.sequence() == retained.sequence()
                && request.operation_id() == retained.operation_id()
                && request.request_commitment() == retained.request_commitment()
            {
                return Ok(AgentReplayDispositionV1::OutstandingExact);
            }
            return Err(if request.sequence() == retained.sequence() {
                AgentReducerError::Equivocation
            } else {
                AgentReducerError::OutstandingOperation
            });
        }

        if let Some(completed) = session
            .completed_history
            .iter()
            .find(|outcome| outcome.sequence() == request.sequence())
        {
            if request.operation_id() == completed.operation_id()
                && request.request_commitment() == completed.request_commitment()
            {
                return Ok(AgentReplayDispositionV1::ExactReplay(completed.clone()));
            }
            return Err(AgentReducerError::Equivocation);
        }
        if request.sequence() != session.next_sequence {
            return Err(AgentReducerError::SequenceConflict);
        }

        let decision = self.validate_decision(&request)?;
        let session_binding = session.binding;
        let next_sequence = session.next_sequence;
        let reservation = match cas.reserve_operation(&request) {
            Ok(AgentReservationStoreTransitionV1::Committed(reservation)) => reservation,
            Ok(AgentReservationStoreTransitionV1::RecoveryRequired {
                store_commitment,
                predecessor_commitment,
                recovery_binding,
            }) => {
                let token = AgentReservationRecoveryTokenV1::from_store_ambiguity(
                    &request,
                    store_commitment,
                    predecessor_commitment,
                    recovery_binding,
                )?;
                let session = self.session.as_mut().ok_or(AgentReducerError::NoSession)?;
                session.outstanding =
                    Some(OutstandingOperation::ReservationRecovery { token, request });
                session.poisoned = true;
                return Ok(AgentReplayDispositionV1::ReservationRecoveryRequired(token));
            }
            Err(error) => return Err(error.into()),
        };
        if reservation.session() != session_binding
            || reservation.sequence() != next_sequence
            || reservation.operation_id() != request.operation_id()
            || reservation.request_commitment() != request.request_commitment()
        {
            if let Some(session) = self.session.as_mut() {
                session.poisoned = true;
            }
            return Err(AgentReducerError::CasReceiptMismatch);
        }
        let session = self.session.as_mut().ok_or(AgentReducerError::NoSession)?;
        session.outstanding = Some(OutstandingOperation::Reserved {
            reservation,
            request: request.clone(),
        });
        if reservation.disposition() == AgentReservationDispositionV1::ExactReplay {
            return Ok(AgentReplayDispositionV1::OutstandingExact);
        }
        Ok(AgentReplayDispositionV1::Prepared(
            PreparedAgentOperationV1 {
                request,
                reservation,
                decision,
            },
        ))
    }

    pub(super) fn install_cold_recovered_reservation(
        &mut self,
        request: AgentOperationRequestV1,
        reservation: AgentOperationReservationV1,
    ) -> Result<PreparedAgentOperationV1, AgentReducerError> {
        let session = self.session.as_ref().ok_or(AgentReducerError::NoSession)?;
        if session.poisoned || session.outstanding.is_some() {
            return Err(AgentReducerError::SessionRecoveryRequired);
        }
        if request.session() != session.binding
            || request.sequence() != session.next_sequence
            || reservation.session() != request.session()
            || reservation.sequence() != request.sequence()
            || reservation.operation_id() != request.operation_id()
            || reservation.request_commitment() != request.request_commitment()
            || reservation.disposition() != AgentReservationDispositionV1::ExactReplay
        {
            return Err(AgentReducerError::CasReceiptMismatch);
        }
        let decision = self.validate_decision(&request)?;
        let prepared = PreparedAgentOperationV1 {
            request: request.clone(),
            reservation,
            decision,
        };
        let session = self.session.as_mut().ok_or(AgentReducerError::NoSession)?;
        session.outstanding = Some(OutstandingOperation::Reserved {
            reservation,
            request,
        });
        Ok(prepared)
    }

    /// Commits an effect outcome and only then advances volatile reducer state.
    ///
    /// # Errors
    ///
    /// Returns [`AgentReducerError`] for reservation mismatch, invalid state
    /// transition, malformed result, or ambiguous durable outcome commit.
    pub(super) fn complete_operation<C: AgentOperationCas>(
        &mut self,
        prepared: &PreparedAgentOperationV1,
        phase: AgentExecutionPhaseV1,
        result_bytes: &[u8],
        cas: &mut C,
    ) -> Result<AgentExecutionOutcomeV1, AgentReducerError> {
        let session = self.session.as_ref().ok_or(AgentReducerError::NoSession)?;
        let outstanding = session
            .outstanding
            .as_ref()
            .ok_or(AgentReducerError::OutstandingRecordMissing)?;
        let Some(reservation) = outstanding.reservation() else {
            return Err(AgentReducerError::SessionRecoveryRequired);
        };
        if reservation != &prepared.reservation || outstanding.request() != &prepared.request {
            return Err(AgentReducerError::CasReceiptMismatch);
        }
        let current_phase = prepared
            .request
            .operation()
            .execution()
            .and_then(|execution| self.executions.get(&execution));
        validate_completion_phase(
            prepared.request.operation(),
            current_phase,
            self.quiesced,
            phase,
        )?;
        let outcome =
            AgentExecutionOutcomeV1::new(&prepared.request, phase, result_bytes.to_vec())?;
        let outcome_commitment =
            match cas.commit_operation_outcome(&prepared.reservation, &outcome)? {
                AgentOutcomeStoreTransitionV1::Committed(commitment) => commitment,
                AgentOutcomeStoreTransitionV1::RecoveryRequired {
                    outcome_commitment,
                    predecessor_commitment,
                    recovery_binding,
                } => {
                    let token = AgentOutcomeRecoveryTokenV1::from_store_ambiguity(
                        &prepared.reservation,
                        &outcome,
                        outcome_commitment,
                        predecessor_commitment,
                        recovery_binding,
                    )?;
                    if let Some(session) = self.session.as_mut() {
                        session.poisoned = true;
                    }
                    return Err(AgentReducerError::OutcomeRecoveryRequired(token));
                }
            };
        if outcome_commitment != outcome.outcome_commitment() {
            if let Some(session) = self.session.as_mut() {
                session.poisoned = true;
            }
            return Err(AgentReducerError::CasReceiptMismatch);
        }

        self.apply_completed_state(prepared.request.operation(), phase)?;
        let session = self.session.as_mut().ok_or(AgentReducerError::NoSession)?;
        session.next_sequence = session.next_sequence.checked_next()?;
        session.outstanding = None;
        session.completed_history.push(outcome.clone());
        trim_completed_history(&mut session.completed_history);
        Ok(outcome)
    }

    /// Returns the exact phase retained for one execution.
    #[must_use]
    pub fn execution_phase(&self, execution: ExecutionId) -> Option<AgentExecutionPhaseV1> {
        self.executions.get(&execution).copied()
    }

    /// Reports whether the guest-local quiesce barrier is complete.
    #[must_use]
    pub const fn is_quiesced(&self) -> bool {
        self.quiesced
    }

    /// Creates a canonical bounded checkpoint for protected durable storage.
    ///
    /// # Errors
    ///
    /// Returns [`AgentReducerError`] for a zero checkpoint sequence or when
    /// retained canonical history exceeds the checkpoint ceiling. The result
    /// remains non-authoritative until a protected store replays its history.
    pub fn checkpoint(
        &self,
        checkpoint_sequence: u64,
    ) -> Result<AgentCheckpointCandidateV1, AgentReducerError> {
        checkpoint_from_reducer(self, checkpoint_sequence)
    }

    /// Restores a reducer from canonical checkpoint data.
    ///
    /// A restored reducer may produce a new checkpoint candidate, but concrete
    /// protected storage must independently replay retained operation history
    /// before committing it. Decoding bytes alone never creates store authority.
    ///
    /// # Errors
    ///
    /// Returns [`AgentReducerError`] when provisioning differs, checkpoint
    /// bytes are corrupt, or retained state violates reducer bounds.
    pub fn restore_checkpoint(
        provisioning: AgentProvisioningV1,
        checkpoint: AgentDurableCheckpointV1,
    ) -> Result<Self, AgentReducerError> {
        reopen_reducer(provisioning, checkpoint)
    }

    /// Reconciles a checkpointed outstanding operation without reissuing it.
    ///
    /// # Errors
    ///
    /// Returns [`AgentReducerError`] for absent/conflicting durable state or a
    /// completion that does not match the checkpointed exact request.
    pub(super) fn reconcile_outstanding<C: AgentOperationRecoveryCas>(
        &mut self,
        cas: &mut C,
    ) -> Result<(), AgentReducerError> {
        let session = self.session.as_ref().ok_or(AgentReducerError::NoSession)?;
        let outstanding = session
            .outstanding
            .as_ref()
            .ok_or(AgentReducerError::OutstandingRecordMissing)?
            .clone();
        let (reservation, request) = match outstanding {
            OutstandingOperation::Reserved {
                reservation,
                request,
            } => (reservation, request),
            OutstandingOperation::ReservationRecovery { token, request } => {
                match cas.recover_reservation(&token, &request)? {
                    AgentRecoveredReservationV1::Absent => {
                        let session = self.session.as_mut().ok_or(AgentReducerError::NoSession)?;
                        session.outstanding = None;
                        session.poisoned = false;
                        return Ok(());
                    }
                    AgentRecoveredReservationV1::Committed(reservation) => {
                        if reservation.session() != request.session()
                            || reservation.sequence() != request.sequence()
                            || reservation.operation_id() != request.operation_id()
                            || reservation.request_commitment() != request.request_commitment()
                            || reservation.store_commitment() != token.store_commitment()
                        {
                            return Err(AgentReducerError::CasReceiptMismatch);
                        }
                        let session = self.session.as_mut().ok_or(AgentReducerError::NoSession)?;
                        session.outstanding = Some(OutstandingOperation::Reserved {
                            reservation,
                            request: request.clone(),
                        });
                        (reservation, request)
                    }
                }
            }
        };
        match cas.recover_operation(&reservation, &request)? {
            AgentRecoveredOperationV1::Reserved => {
                let session = self.session.as_mut().ok_or(AgentReducerError::NoSession)?;
                session.poisoned = true;
                Err(AgentReducerError::SessionRecoveryRequired)
            }
            AgentRecoveredOperationV1::Completed(outcome) => {
                if outcome.session() != request.session()
                    || outcome.sequence() != request.sequence()
                    || outcome.operation_id() != request.operation_id()
                    || outcome.request_commitment() != request.request_commitment()
                {
                    return Err(AgentReducerError::CasReceiptMismatch);
                }
                self.apply_completed_state(request.operation(), outcome.phase())?;
                let session = self.session.as_mut().ok_or(AgentReducerError::NoSession)?;
                session.next_sequence = session.next_sequence.checked_next()?;
                session.outstanding = None;
                session.completed_history.push(outcome);
                trim_completed_history(&mut session.completed_history);
                session.poisoned = false;
                Ok(())
            }
            AgentRecoveredOperationV1::Absent => {
                let session = self.session.as_mut().ok_or(AgentReducerError::NoSession)?;
                session.poisoned = true;
                Err(AgentReducerError::SessionRecoveryRequired)
            }
        }
    }

    /// Resolves a Reserved restart record from authenticated process evidence.
    ///
    /// The authenticated outcome is committed before the reducer advances its
    /// session sequence. No reserved operation is reissued by this path.
    ///
    /// # Errors
    ///
    /// Returns [`AgentReducerError`] for missing outstanding state, evidence
    /// substitution, ambiguous durability, or an invalid recovered phase.
    pub(super) fn resolve_reserved_outstanding<C: AgentOperationRecoveryCas>(
        &mut self,
        cas: &mut C,
        authenticated: AuthenticatedRecoveredAgentOutcomeV1,
    ) -> Result<AgentExecutionOutcomeV1, AgentReducerError> {
        if authenticated.authority_binding() != self.provisioning.recovery_authority_binding() {
            return Err(AgentReducerError::CasReceiptMismatch);
        }
        let session = self.session.as_ref().ok_or(AgentReducerError::NoSession)?;
        let outstanding = session
            .outstanding
            .as_ref()
            .ok_or(AgentReducerError::OutstandingRecordMissing)?
            .clone();
        let OutstandingOperation::Reserved {
            reservation,
            request,
        } = outstanding
        else {
            return Err(AgentReducerError::SessionRecoveryRequired);
        };
        let current_phase = request
            .operation()
            .execution()
            .and_then(|execution| self.executions.get(&execution));
        validate_completion_phase(
            request.operation(),
            current_phase,
            self.quiesced,
            authenticated.outcome().phase(),
        )?;
        let outcome = authenticated.outcome().clone();
        let expected = outcome.outcome_commitment();
        let committed =
            match cas.resolve_reserved_operation(&reservation, &request, authenticated)? {
                AgentOutcomeStoreTransitionV1::Committed(commitment) => commitment,
                AgentOutcomeStoreTransitionV1::RecoveryRequired {
                    outcome_commitment,
                    predecessor_commitment,
                    recovery_binding,
                } => {
                    let token = AgentOutcomeRecoveryTokenV1::from_store_ambiguity(
                        &reservation,
                        &outcome,
                        outcome_commitment,
                        predecessor_commitment,
                        recovery_binding,
                    )?;
                    if let Some(session) = self.session.as_mut() {
                        session.poisoned = true;
                    }
                    return Err(AgentReducerError::OutcomeRecoveryRequired(token));
                }
            };
        if committed != expected {
            if let Some(session) = self.session.as_mut() {
                session.poisoned = true;
            }
            return Err(AgentReducerError::CasReceiptMismatch);
        }
        self.reconcile_outstanding(cas)?;
        Ok(outcome)
    }

    fn validate_decision(
        &self,
        request: &AgentOperationRequestV1,
    ) -> Result<AgentDecisionV1, AgentReducerError> {
        match request.operation() {
            AgentExecutionOperationV1::Authorize { execution, .. } => {
                if self.quiesced {
                    return Err(AgentReducerError::Quiesced);
                }
                if self.executions.contains_key(execution) {
                    return Err(AgentReducerError::ExecutionConflict);
                }
                if self.executions.len() >= MAX_ACTIVE_EXECUTIONS {
                    return Err(AgentReducerError::ExecutionCapacity);
                }
                require_feature(
                    self.provisioning.features(),
                    AgentFeatureV1::ExecutionHandoff,
                )?;
                validate_authorized_target(request.operation(), self.provisioning.runtime())?;
                Ok(AgentDecisionV1::HandoffExecution(*execution))
            }
            AgentExecutionOperationV1::ResizeTerminal {
                execution,
                rows,
                columns,
            } => {
                require_phase(
                    self.executions.get(execution),
                    &[AgentExecutionPhaseV1::Running],
                )?;
                require_feature(self.provisioning.features(), AgentFeatureV1::TerminalResize)?;
                Ok(AgentDecisionV1::ResizeTerminal {
                    execution: *execution,
                    rows: *rows,
                    columns: *columns,
                })
            }
            AgentExecutionOperationV1::Signal {
                execution,
                signal_code,
            } => {
                require_phase(
                    self.executions.get(execution),
                    &[
                        AgentExecutionPhaseV1::Starting,
                        AgentExecutionPhaseV1::Running,
                    ],
                )?;
                require_feature(
                    self.provisioning.features(),
                    AgentFeatureV1::ExecutionSignal,
                )?;
                Ok(AgentDecisionV1::Signal {
                    execution: *execution,
                    signal_code: *signal_code,
                })
            }
            AgentExecutionOperationV1::Cancel { execution } => {
                require_phase(
                    self.executions.get(execution),
                    &[
                        AgentExecutionPhaseV1::Authorized,
                        AgentExecutionPhaseV1::Starting,
                        AgentExecutionPhaseV1::Running,
                    ],
                )?;
                Ok(AgentDecisionV1::Cancel(*execution))
            }
            AgentExecutionOperationV1::Observe { execution } => {
                require_phase(
                    self.executions.get(execution),
                    &[
                        AgentExecutionPhaseV1::Authorized,
                        AgentExecutionPhaseV1::Starting,
                        AgentExecutionPhaseV1::Running,
                        AgentExecutionPhaseV1::Exited,
                        AgentExecutionPhaseV1::Canceled,
                        AgentExecutionPhaseV1::Failed,
                        AgentExecutionPhaseV1::Lost,
                    ],
                )?;
                require_feature(
                    self.provisioning.features(),
                    AgentFeatureV1::ExecutionObservation,
                )?;
                Ok(AgentDecisionV1::Observe(*execution))
            }
            AgentExecutionOperationV1::BeginQuiesce => {
                if self.quiesced {
                    return Err(AgentReducerError::QuiesceConflict);
                }
                require_feature(self.provisioning.features(), AgentFeatureV1::Quiesce)?;
                Ok(AgentDecisionV1::BeginQuiesce)
            }
            AgentExecutionOperationV1::EndQuiesce => {
                if !self.quiesced {
                    return Err(AgentReducerError::QuiesceConflict);
                }
                require_feature(self.provisioning.features(), AgentFeatureV1::Quiesce)?;
                Ok(AgentDecisionV1::EndQuiesce)
            }
        }
    }

    fn apply_completed_state(
        &mut self,
        operation: &AgentExecutionOperationV1,
        phase: AgentExecutionPhaseV1,
    ) -> Result<(), AgentReducerError> {
        match operation {
            AgentExecutionOperationV1::Authorize { execution, .. } => {
                self.executions.insert(*execution, phase);
            }
            AgentExecutionOperationV1::ResizeTerminal { execution, .. }
            | AgentExecutionOperationV1::Signal { execution, .. }
            | AgentExecutionOperationV1::Cancel { execution }
            | AgentExecutionOperationV1::Observe { execution } => {
                let stored = self
                    .executions
                    .get_mut(execution)
                    .ok_or(AgentReducerError::UnknownExecution)?;
                *stored = phase;
            }
            AgentExecutionOperationV1::BeginQuiesce => self.quiesced = true,
            AgentExecutionOperationV1::EndQuiesce => self.quiesced = false,
        }
        Ok(())
    }
}

impl GuestAgentReducerV1 {
    pub(crate) const fn provisioning(&self) -> &AgentProvisioningV1 {
        &self.provisioning
    }

    pub(crate) fn checkpoint_state(&self) -> ReducerCheckpointState {
        let session = self.session.as_ref().map(|session| SessionCheckpointState {
            binding: session.binding,
            next_sequence: session.next_sequence,
            outstanding: session
                .outstanding
                .as_ref()
                .map(|outstanding| match outstanding {
                    OutstandingOperation::Reserved {
                        reservation,
                        request,
                    } => OutstandingCheckpointState::Reserved {
                        reservation: *reservation,
                        request: request.clone(),
                    },
                    OutstandingOperation::ReservationRecovery { token, request } => {
                        OutstandingCheckpointState::ReservationRecovery {
                            token: *token,
                            request: request.clone(),
                        }
                    }
                }),
            completed_history: session.completed_history.clone(),
            poisoned: session.poisoned,
        });
        ReducerCheckpointState {
            session,
            executions: self
                .executions
                .iter()
                .map(|(execution, phase)| (*execution, *phase))
                .collect(),
            quiesced: self.quiesced,
        }
    }

    pub(crate) fn from_checkpoint_state(
        provisioning: AgentProvisioningV1,
        state: ReducerCheckpointState,
    ) -> Result<Self, AgentReducerError> {
        if state.executions.len() > MAX_ACTIVE_EXECUTIONS {
            return Err(AgentReducerError::InvalidCheckpoint);
        }
        let executions: BTreeMap<_, _> = state.executions.into_iter().collect();
        if executions.len() > MAX_ACTIVE_EXECUTIONS {
            return Err(AgentReducerError::InvalidCheckpoint);
        }
        let session = state
            .session
            .map(|checkpoint| {
                if checkpoint.completed_history.len() > MAX_COMPLETED_HISTORY {
                    return Err(AgentReducerError::InvalidCheckpoint);
                }
                if let Some(outstanding) = &checkpoint.outstanding {
                    if matches!(
                        outstanding,
                        OutstandingCheckpointState::ReservationRecovery { .. }
                    ) && !checkpoint.poisoned
                    {
                        return Err(AgentReducerError::InvalidCheckpoint);
                    }
                    let (session, sequence, operation, request_commitment, request) =
                        match outstanding {
                            OutstandingCheckpointState::Reserved {
                                reservation,
                                request,
                            } => (
                                reservation.session(),
                                reservation.sequence(),
                                reservation.operation_id(),
                                reservation.request_commitment(),
                                request,
                            ),
                            OutstandingCheckpointState::ReservationRecovery { token, request } => (
                                token.session(),
                                token.sequence(),
                                token.operation_id(),
                                token.request_commitment(),
                                request,
                            ),
                        };
                    if session != checkpoint.binding
                        || request.session() != checkpoint.binding
                        || sequence != checkpoint.next_sequence
                        || request.sequence() != checkpoint.next_sequence
                        || operation != request.operation_id()
                        || request_commitment != request.request_commitment()
                    {
                        return Err(AgentReducerError::InvalidCheckpoint);
                    }
                }
                if let Some(latest) = checkpoint.completed_history.last() {
                    let expected_next = latest.sequence().checked_next()?;
                    if expected_next != checkpoint.next_sequence {
                        return Err(AgentReducerError::InvalidCheckpoint);
                    }
                }
                let outstanding = checkpoint.outstanding.map(|outstanding| match outstanding {
                    OutstandingCheckpointState::Reserved {
                        reservation,
                        request,
                    } => OutstandingOperation::Reserved {
                        reservation,
                        request,
                    },
                    OutstandingCheckpointState::ReservationRecovery { token, request } => {
                        OutstandingOperation::ReservationRecovery { token, request }
                    }
                });
                Ok(SessionState {
                    binding: checkpoint.binding,
                    next_sequence: checkpoint.next_sequence,
                    outstanding,
                    completed_history: checkpoint.completed_history,
                    poisoned: checkpoint.poisoned,
                })
            })
            .transpose()?;
        Ok(Self {
            provisioning,
            session,
            executions,
            quiesced: state.quiesced,
        })
    }
}

/// Replays protected operation history and compares its exact reducer projection.
///
/// The rows must be ordered by their durable reservation sequence. This
/// verifier is intentionally pure: concrete protected stores retain authority
/// over row provenance and use this function only after authenticated replay.
///
/// # Errors
///
/// Returns [`AgentReducerError::InvalidCheckpoint`] for a sequence gap,
/// session overlap, invalid operation transition, mismatched outcome, or a
/// checkpoint that differs from the complete retained projection.
pub fn validate_agent_checkpoint_history_v1(
    checkpoint: &AgentDurableCheckpointV1,
    records: &[AgentDurableHistoryRecordV1<'_>],
    authenticated_session: Option<AgentSessionBindingV1>,
) -> Result<(), AgentReducerError> {
    let mut executions = BTreeMap::new();
    let mut quiesced = false;
    let mut current_session = None;
    let mut seen_sessions = std::collections::BTreeSet::new();
    let mut next_sequence = None;
    let mut completed_history = Vec::new();
    let mut outstanding = None;

    for (index, record) in records.iter().enumerate() {
        let request = record.request;
        if current_session != Some(request.session()) {
            if current_session.is_some() && outstanding.is_some() {
                return Err(AgentReducerError::InvalidCheckpoint);
            }
            current_session = Some(request.session());
            if !seen_sessions.insert(request.session().digest()) {
                return Err(AgentReducerError::InvalidCheckpoint);
            }
            next_sequence = Some(AgentOperationSequenceV1::new(1)?);
            completed_history.clear();
        }
        if next_sequence != Some(request.sequence()) || outstanding.is_some() {
            return Err(AgentReducerError::InvalidCheckpoint);
        }

        validate_replayed_decision(request.operation(), &executions, quiesced)?;
        let Some(outcome) = record.outcome else {
            if index + 1 != records.len() {
                return Err(AgentReducerError::InvalidCheckpoint);
            }
            outstanding = Some(record);
            continue;
        };
        if outcome.session() != request.session()
            || outcome.sequence() != request.sequence()
            || outcome.operation_id() != request.operation_id()
            || outcome.request_commitment() != request.request_commitment()
        {
            return Err(AgentReducerError::InvalidCheckpoint);
        }
        let current_phase = request
            .operation()
            .execution()
            .and_then(|execution| executions.get(&execution));
        validate_completion_phase(
            request.operation(),
            current_phase,
            quiesced,
            outcome.phase(),
        )?;
        apply_replayed_state(
            request.operation(),
            outcome.phase(),
            &mut executions,
            &mut quiesced,
        )?;
        next_sequence = Some(request.sequence().checked_next()?);
        completed_history.push(outcome.clone());
        trim_completed_history(&mut completed_history);
    }

    let state = &checkpoint.state;
    if state.executions != executions.into_iter().collect::<Vec<_>>() || state.quiesced != quiesced
    {
        return Err(AgentReducerError::InvalidCheckpoint);
    }
    let Some(session) = state.session.as_ref() else {
        return if records.is_empty() && authenticated_session.is_none() {
            Ok(())
        } else {
            Err(AgentReducerError::InvalidCheckpoint)
        };
    };
    if authenticated_session != Some(session.binding) || session.poisoned {
        return Err(AgentReducerError::InvalidCheckpoint);
    }
    if current_session != Some(session.binding) {
        return if outstanding.is_none()
            && session.next_sequence.get() == 1
            && session.outstanding.is_none()
            && session.completed_history.is_empty()
        {
            Ok(())
        } else {
            Err(AgentReducerError::InvalidCheckpoint)
        };
    }
    if next_sequence != Some(session.next_sequence)
        || session.completed_history != completed_history
    {
        return Err(AgentReducerError::InvalidCheckpoint);
    }
    match (outstanding, session.outstanding.as_ref()) {
        (None, None) => Ok(()),
        (
            Some(record),
            Some(OutstandingCheckpointState::Reserved {
                reservation,
                request,
            }),
        ) if request == record.request
            && reservation.session() == request.session()
            && reservation.sequence() == request.sequence()
            && reservation.operation_id() == request.operation_id()
            && reservation.request_commitment() == request.request_commitment()
            && reservation.store_commitment() == record.store_commitment =>
        {
            Ok(())
        }
        _ => Err(AgentReducerError::InvalidCheckpoint),
    }
}

fn validate_replayed_decision(
    operation: &AgentExecutionOperationV1,
    executions: &BTreeMap<ExecutionId, AgentExecutionPhaseV1>,
    quiesced: bool,
) -> Result<(), AgentReducerError> {
    let valid = match operation {
        AgentExecutionOperationV1::Authorize { execution, .. } => {
            !quiesced && !executions.contains_key(execution)
        }
        AgentExecutionOperationV1::ResizeTerminal { execution, .. } => {
            executions.get(execution) == Some(&AgentExecutionPhaseV1::Running)
        }
        AgentExecutionOperationV1::Signal { execution, .. } => matches!(
            executions.get(execution),
            Some(AgentExecutionPhaseV1::Starting | AgentExecutionPhaseV1::Running)
        ),
        AgentExecutionOperationV1::Cancel { execution } => matches!(
            executions.get(execution),
            Some(
                AgentExecutionPhaseV1::Authorized
                    | AgentExecutionPhaseV1::Starting
                    | AgentExecutionPhaseV1::Running
            )
        ),
        AgentExecutionOperationV1::Observe { execution } => executions.contains_key(execution),
        AgentExecutionOperationV1::BeginQuiesce => !quiesced,
        AgentExecutionOperationV1::EndQuiesce => quiesced,
    };
    if valid {
        Ok(())
    } else {
        Err(AgentReducerError::InvalidCheckpoint)
    }
}

fn apply_replayed_state(
    operation: &AgentExecutionOperationV1,
    phase: AgentExecutionPhaseV1,
    executions: &mut BTreeMap<ExecutionId, AgentExecutionPhaseV1>,
    quiesced: &mut bool,
) -> Result<(), AgentReducerError> {
    match operation {
        AgentExecutionOperationV1::Authorize { execution, .. } => {
            executions.insert(*execution, phase);
        }
        AgentExecutionOperationV1::ResizeTerminal { execution, .. }
        | AgentExecutionOperationV1::Signal { execution, .. }
        | AgentExecutionOperationV1::Cancel { execution }
        | AgentExecutionOperationV1::Observe { execution } => {
            let current = executions
                .get_mut(execution)
                .ok_or(AgentReducerError::InvalidCheckpoint)?;
            *current = phase;
        }
        AgentExecutionOperationV1::BeginQuiesce => *quiesced = true,
        AgentExecutionOperationV1::EndQuiesce => *quiesced = false,
    }
    Ok(())
}

fn trim_completed_history(history: &mut Vec<AgentExecutionOutcomeV1>) {
    // Keeps room for a maximum-size outstanding execution specification and
    // the complete execution table under the protected journal record ceiling.
    const MAX_HISTORY_RESULT_BYTES: usize = 128 * 1_024;
    while history.len() > MAX_COMPLETED_HISTORY
        || history
            .iter()
            .map(|outcome| outcome.result_bytes().len())
            .sum::<usize>()
            > MAX_HISTORY_RESULT_BYTES
    {
        history.remove(0);
    }
}

fn validate_completion_phase(
    operation: &AgentExecutionOperationV1,
    current: Option<&AgentExecutionPhaseV1>,
    quiesced: bool,
    next: AgentExecutionPhaseV1,
) -> Result<(), AgentReducerError> {
    let valid = match operation {
        AgentExecutionOperationV1::Authorize { .. } => matches!(
            next,
            AgentExecutionPhaseV1::Authorized
                | AgentExecutionPhaseV1::Starting
                | AgentExecutionPhaseV1::Running
                | AgentExecutionPhaseV1::Failed
        ),
        AgentExecutionOperationV1::ResizeTerminal { .. }
        | AgentExecutionOperationV1::Signal { .. }
        | AgentExecutionOperationV1::Observe { .. } => {
            current.is_some_and(|phase| execution_transition(*phase, next))
        }
        AgentExecutionOperationV1::Cancel { .. } => matches!(
            next,
            AgentExecutionPhaseV1::Canceled
                | AgentExecutionPhaseV1::Exited
                | AgentExecutionPhaseV1::Failed
                | AgentExecutionPhaseV1::Lost
        ),
        AgentExecutionOperationV1::BeginQuiesce => {
            !quiesced && next == AgentExecutionPhaseV1::Quiesced
        }
        AgentExecutionOperationV1::EndQuiesce => quiesced && next == AgentExecutionPhaseV1::Ready,
    };
    if valid {
        Ok(())
    } else {
        Err(AgentReducerError::InvalidTransition)
    }
}

fn execution_transition(current: AgentExecutionPhaseV1, next: AgentExecutionPhaseV1) -> bool {
    current == next
        || matches!(
            (current, next),
            (
                AgentExecutionPhaseV1::Authorized,
                AgentExecutionPhaseV1::Starting
                    | AgentExecutionPhaseV1::Running
                    | AgentExecutionPhaseV1::Canceled
                    | AgentExecutionPhaseV1::Failed
                    | AgentExecutionPhaseV1::Lost
            ) | (
                AgentExecutionPhaseV1::Starting,
                AgentExecutionPhaseV1::Running
                    | AgentExecutionPhaseV1::Exited
                    | AgentExecutionPhaseV1::Canceled
                    | AgentExecutionPhaseV1::Failed
                    | AgentExecutionPhaseV1::Lost
            ) | (
                AgentExecutionPhaseV1::Running,
                AgentExecutionPhaseV1::Exited
                    | AgentExecutionPhaseV1::Canceled
                    | AgentExecutionPhaseV1::Failed
                    | AgentExecutionPhaseV1::Lost
            )
        )
}

fn require_phase(
    current: Option<&AgentExecutionPhaseV1>,
    allowed: &[AgentExecutionPhaseV1],
) -> Result<(), AgentReducerError> {
    match current {
        Some(phase) if allowed.contains(phase) => Ok(()),
        Some(_) => Err(AgentReducerError::ExecutionConflict),
        None => Err(AgentReducerError::UnknownExecution),
    }
}

fn require_feature(
    features: &AgentFeatureSetV1,
    feature: AgentFeatureV1,
) -> Result<(), AgentReducerError> {
    if features.contains(feature) {
        Ok(())
    } else {
        Err(AgentReducerError::FeatureUnavailable)
    }
}

/// Derives the exact domain-separated handshake message signed by the agent.
///
/// The host verifier calls the same pure function with the received response's
/// session binding, agent instance, and canonical feature set. The return value
/// is a fixed 32-byte SHA-256 transcript commitment.
#[must_use]
pub fn agent_handshake_signing_message_v1(
    request: &AgentHandshakeRequestV1,
    binding: AgentSessionBindingV1,
    agent_instance: &[u8; 16],
    features: &AgentFeatureSetV1,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(HANDSHAKE_SIGNATURE_DOMAIN);
    digest.update(binding.digest().as_bytes());
    digest.update(request.challenge().as_bytes());
    digest.update(request.host_channel_binding().as_bytes());
    digest.update(agent_instance);
    digest.update((features.as_slice().len() as u16).to_be_bytes());
    for feature in features.as_slice() {
        digest.update([*feature as u8]);
    }
    digest.finalize().into()
}

/// Returns the exact domain-separated post-handshake outcome message.
#[must_use]
pub fn agent_outcome_signing_message_v1(
    channel: ObjectDigest,
    request: &AgentOperationRequestV1,
    outcome: &AgentExecutionOutcomeV1,
) -> [u8; 32] {
    aos_sandbox_core::runtime_backend::backend_agent_outcome_signing_message_v1(
        channel,
        request.backend_request_binding(),
        request.session().digest(),
        request.sequence().get(),
        *request.operation_id().as_bytes(),
        request.request_commitment(),
        outcome.outcome_commitment(),
    )
}

/// Reports atomic agent operation-store failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AgentOperationCasError {
    /// The expected sequence is stale, has a gap, or is exhausted.
    #[error("agent operation CAS sequence conflicts")]
    SequenceConflict,
    /// The same sequence or operation identity binds different bytes.
    #[error("agent operation CAS detected equivocation")]
    Equivocation,
    /// A store receipt is zero or malformed.
    #[error("agent operation CAS receipt is invalid")]
    InvalidReceipt,
}

/// Reports handshake, replay, state, or durable-CAS rejection.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AgentReducerError {
    /// Durable checkpoint bytes or retained state violate canonical bounds.
    #[error("agent durable checkpoint is invalid")]
    InvalidCheckpoint,
    /// Protected checkpoint belongs to different process provisioning.
    #[error("agent checkpoint provisioning does not match")]
    CheckpointProvisioningMismatch,
    /// Protected process provisioning contains a sentinel field.
    #[error("agent provisioning is invalid")]
    InvalidProvisioning,
    /// The handshake targets another runtime or channel.
    #[error("agent handshake does not match provisioning")]
    HandshakeMismatch,
    /// Protected signing failed or refused the exact message.
    #[error("agent handshake signing failed")]
    SigningFailed,
    /// No successful handshake is installed.
    #[error("agent session is not established")]
    NoSession,
    /// The operation belongs to a replaced session.
    #[error("agent session was superseded")]
    SessionSuperseded,
    /// An outstanding or ambiguous durable record blocks session replacement.
    #[error("agent session requires durable recovery")]
    SessionRecoveryRequired,
    /// A sequence is stale, has a gap, or is exhausted.
    #[error("agent operation sequence conflicts")]
    SequenceConflict,
    /// Same sequence or operation identity carries different bytes.
    #[error("agent operation equivocated")]
    Equivocation,
    /// A different operation remains unresolved.
    #[error("agent has an outstanding operation")]
    OutstandingOperation,
    /// Volatile state lost an expected durable outstanding reservation.
    #[error("agent outstanding operation record is missing")]
    OutstandingRecordMissing,
    /// A durable CAS receipt does not bind the exact request.
    #[error("agent operation CAS receipt does not match")]
    CasReceiptMismatch,
    /// The requested feature is not advertised by this exact agent.
    #[error("agent feature is unavailable")]
    FeatureUnavailable,
    /// Execution admission is closed while the guest is quiesced.
    #[error("agent is quiesced")]
    Quiesced,
    /// The guest quiesce transition conflicts with current state.
    #[error("agent quiesce state conflicts")]
    QuiesceConflict,
    /// The execution identity is unknown.
    #[error("agent execution is unknown")]
    UnknownExecution,
    /// The execution already exists or is in an incompatible phase.
    #[error("agent execution state conflicts")]
    ExecutionConflict,
    /// The bounded active execution table is full.
    #[error("agent execution capacity is exhausted")]
    ExecutionCapacity,
    /// The completion phase is absent from the closed transition graph.
    #[error("agent execution transition is invalid")]
    InvalidTransition,
    /// Portable model validation failed.
    #[error("agent model is invalid: {0}")]
    Model(#[from] InvalidAgentModel),
    /// Durable sequence reservation or completion failed.
    #[error("agent operation CAS failed: {0}")]
    Cas(#[from] AgentOperationCasError),
    /// A terminal append may have committed and requires cold reopen.
    #[error("agent terminal outcome commit requires cold reopen")]
    OutcomeRecoveryRequired(AgentOutcomeRecoveryTokenV1),
}

fn validate_authorized_target(
    operation: &AgentExecutionOperationV1,
    runtime: &AgentRuntimeBindingV1,
) -> Result<(), AgentReducerError> {
    let AgentExecutionOperationV1::Authorize {
        specification_bytes,
        ..
    } = operation
    else {
        return Err(AgentReducerError::ExecutionConflict);
    };
    let specification = aos_sandbox_core::decode_execution_spec_v1(
        specification_bytes,
        aos_sandbox_core::DecodeLimits {
            maximum_bytes: specification_bytes.len(),
            maximum_collection_items: 65_536,
            maximum_total_items: 262_144,
            maximum_byte_string_bytes: 15 * 1_048_576,
            maximum_text_bytes: 1_048_576,
            maximum_depth: 128,
        },
    )
    .map_err(|_| AgentReducerError::ExecutionConflict)?;
    let target = specification.target();
    if target.sandbox() != runtime.sandbox()
        || target.incarnation() != runtime.incarnation()
        || target.assignment_epoch() != runtime.assignment_epoch()
        || target.assignment_digest() != runtime.assignment_digest()
        || target.namespace_generation() != runtime.namespace_generation()
        || target.payload_boot_id().as_bytes() != runtime.payload_boot_id()
    {
        return Err(AgentReducerError::ExecutionConflict);
    }
    Ok(())
}
