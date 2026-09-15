//! Fixed-root ownership for dormant runtime execution durability.
//!
//! This module is the only public entry to the execution and agent journals.
//! It resolves exact Host peer and backend-currentness records from the fixed
//! protected Host root, derives all journal bindings from those records, and
//! retains the protected claim while admission, recovery, and agent CAS are
//! possible. It performs no backend, guest, route, or service effect.
//!
//! ```text
//! AOSREC01 || backend_build[32] || probe_epoch:u64be
//! || probe_protected_context[32] || resource_ledger[32]
//! || output_reservation[32] || record_digest[32]
//! ```

use aos_sandbox_agent::{
    AgentCheckpointCandidateV1, AgentCheckpointError, AgentExecutionOutcomeV1, AgentOperationCas,
    AgentOperationCasError, AgentOperationRecoveryCas, AgentOperationRequestV1,
    AgentOperationReservationV1, AgentRecoveredOperationV1, AgentRecoveredReservationV1,
    AgentReservationRecoveryTokenV1, AgentReservationStoreTransitionV1,
    AuthenticatedRecoveredAgentOutcomeV1,
};
use aos_sandbox_core::runtime_backend::{
    AdmissionCommitError, AdmissionCurrentnessV1, AdmissionStoreCommitV1, AdmittedExecutionV1,
    BackendExecutionInventoryV1, BackendProbeCurrentnessV1, DurableExecutionEffectV1,
    EffectCommitError, EffectCompletionV1, EffectIssueV1, EffectStoreTransitionV1,
    ExecutionAdmissionDraftV1, ExecutionAdmissionStore, ExecutionEffectStore, RuntimeCurrentnessV1,
    RuntimeHandleCommitmentV1, backend_evidence_authority_binding_v1,
};
use aos_sandbox_core::{
    AssignmentEpoch, DesiredGeneration, ExecutionId, IncarnationId, NamespaceGeneration, NodeId,
    ObjectDigest, PayloadBootId, Revision, SandboxId,
};
use sha2::{Digest as _, Sha256};

use crate::journal::{
    GlobalCapacityReservationPurposeV1, Journal, JournalError, JournalLimits,
    ProtectedJournalAuthority, RecordNamespace,
};

use super::agent_store::{
    AuthenticatedJournalAgentCheckpointV1, DormantJournalAgentStoreV1, JournalAgentStoreError,
};
use super::evidence::JournalExecutionCompletionV1;
use super::recovery::{AppliedExecutionRecoveryV1, apply_execution_recovery_v1};
use super::store::{
    AuthenticatedJournalExecutionRecoveryV1 as JournalRecoveryV1, ExecutionJournalRecoveryTokenV1,
    JournalRuntimeExecutionError, JournalRuntimeExecutionStoreV1,
    ProtectedExecutionAdmissionStateV1,
};

const HOST_STATE_ROOT: &str = "/var/lib/aos/sandbox-host";
const PEER_JOURNAL_NAME: &str = "runtime-agent-peer.journal";
const EXECUTION_JOURNAL_NAME: &str = "runtime-execution.journal";
const AGENT_JOURNAL_NAME: &str = "runtime-agent-state.journal";
const PEER_CURRENT_KEY: &[u8] = b"dormant-agent-peer-current-v1";
const CURRENTNESS_KEY: &[u8] = b"runtime-execution-currentness-v1";
const PEER_MAGIC: &[u8; 8] = b"AOSHPE01";
const CURRENTNESS_MAGIC: &[u8; 8] = b"AOSREC01";
const PEER_BYTES: usize = 296;
const CURRENTNESS_BYTES: usize = 176;

/// Owns the fixed protected Host, execution, and agent journals.
pub struct DormantRuntimeExecutionOwnerV1 {
    peer_journal: Journal,
    execution_journal: Journal,
    agent_journal: Journal,
}

impl DormantRuntimeExecutionOwnerV1 {
    /// Opens the fixed root-owned journals without activating runtime dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] when a protected path,
    /// exclusive lock, journal replay, or fixed-root invariant fails.
    pub fn open() -> Result<Self, DormantRuntimeExecutionOwnerErrorV1> {
        let limits = JournalLimits::default();
        let (peer_journal, _) =
            Journal::open_protected_at(HOST_STATE_ROOT, PEER_JOURNAL_NAME, limits)?;
        let (execution_journal, _) =
            Journal::open_protected_at(HOST_STATE_ROOT, EXECUTION_JOURNAL_NAME, limits)?;
        let (agent_journal, _) =
            Journal::open_protected_at(HOST_STATE_ROOT, AGENT_JOURNAL_NAME, limits)?;

        Ok(Self {
            peer_journal,
            execution_journal,
            agent_journal,
        })
    }

    /// Claims current runtime execution authority from protected Host state.
    ///
    /// The returned claim keeps the exact peer/currentness journal borrowed,
    /// so those records cannot be superseded through another owner while an
    /// admission, recovery, completion, or agent CAS operation is in flight.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] when current protected
    /// records are absent, malformed, inconsistent, stale, or when either
    /// dedicated durable store cannot be initialized or reopened exactly.
    pub fn claim(
        &mut self,
    ) -> Result<DormantRuntimeExecutionClaimV1<'_>, DormantRuntimeExecutionOwnerErrorV1> {
        let Self {
            peer_journal,
            execution_journal,
            agent_journal,
        } = self;
        let peer_authority =
            peer_journal.claim_protected_authority(RecordNamespace::HostExecution)?;
        let protected_sequence = peer_authority.snapshot()?.sequence();
        let peer_record = peer_authority
            .get(PEER_CURRENT_KEY)?
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::MissingCurrentness)?
            .to_vec();
        let currentness_record = peer_authority
            .get(CURRENTNESS_KEY)?
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::MissingCurrentness)?
            .to_vec();

        let resolved = resolve_currentness(
            protected_sequence,
            peer_record.as_slice(),
            currentness_record.as_slice(),
        )?;
        let admission_state = ProtectedExecutionAdmissionStateV1::new(&resolved.currentness);
        let execution = open_execution_store(
            execution_journal,
            resolved.execution_store_binding,
            admission_state,
        )?;
        let agent = open_agent_store(
            agent_journal,
            resolved.agent_store_binding,
            resolved.recovery_authority_binding,
        )?;

        Ok(DormantRuntimeExecutionClaimV1 {
            peer_authority,
            protected_sequence,
            peer_record,
            currentness_record,
            currentness: resolved.currentness,
            execution,
            agent,
        })
    }
}

/// Retains exact protected Host currentness across dormant durable operations.
pub struct DormantRuntimeExecutionClaimV1<'owner> {
    peer_authority: ProtectedJournalAuthority<'owner>,
    protected_sequence: u64,
    peer_record: Vec<u8>,
    currentness_record: Vec<u8>,
    currentness: AdmissionCurrentnessV1,
    execution: JournalRuntimeExecutionStoreV1<'owner>,
    agent: DormantJournalAgentStoreV1<'owner>,
}

impl DormantRuntimeExecutionClaimV1<'_> {
    /// Borrows the exact currentness admitted by this protected claim.
    #[must_use]
    pub const fn currentness(&self) -> &AdmissionCurrentnessV1 {
        &self.currentness
    }

    /// Loads one admitted execution after revalidating protected currentness.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] for stale Host state or
    /// corrupt/unavailable execution durability.
    pub fn load_admission(
        &self,
        execution: ExecutionId,
    ) -> Result<Option<AdmittedExecutionV1>, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        self.execution.load_admission(execution).map_err(Into::into)
    }

    /// Loads one durable effect after revalidating protected currentness.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] for stale Host state or
    /// corrupt/unavailable execution durability.
    pub fn load_effect(
        &self,
        operation: &[u8; 16],
    ) -> Result<Option<DurableExecutionEffectV1>, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        self.execution.load_effect(operation).map_err(Into::into)
    }

    /// Loads durable recovery evidence before any live inventory is supplied.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] for stale Host state or
    /// absent, corrupt, or unavailable protected execution state.
    pub fn load_recovery(
        &self,
        operation: &[u8; 16],
    ) -> Result<JournalRecoveryV1, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        self.execution.load_recovery(operation).map_err(Into::into)
    }

    /// Applies one closed recovery decision without dispatching an effect.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] for stale Host state,
    /// invalid inventory/evidence, or durable transition failure.
    pub fn apply_recovery(
        &mut self,
        snapshot: JournalRecoveryV1,
        inventory: Option<BackendExecutionInventoryV1>,
    ) -> Result<AppliedExecutionRecoveryV1, DormantRuntimeExecutionOwnerErrorV1> {
        self.validate_current()?;
        apply_execution_recovery_v1(&mut self.execution, snapshot, inventory).map_err(Into::into)
    }

    /// Commits operation-specific terminal evidence after currentness recheck.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] for stale Host state,
    /// substituted evidence, phase conflict, or protected durability failure.
    pub fn commit_verified_completion(
        &mut self,
        effect: &DurableExecutionEffectV1,
        evidence: &JournalExecutionCompletionV1,
    ) -> Result<
        aos_sandbox_core::runtime_backend::ExecutionEffectTransitionV1<
            ExecutionJournalRecoveryTokenV1,
        >,
        DormantRuntimeExecutionOwnerErrorV1,
    > {
        self.validate_current()?;
        self.execution
            .commit_verified_completion(effect, evidence)
            .map_err(Into::into)
    }

    /// Resolves an ambiguous terminal commit without dispatching another effect.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeExecutionOwnerErrorV1`] for stale Host state,
    /// foreign recovery authority, corrupt replay, or receipt mismatch.
    pub fn recover_verified_completion(
        &mut self,
        effect: &DurableExecutionEffectV1,
        evidence: &JournalExecutionCompletionV1,
        token: ExecutionJournalRecoveryTokenV1,
    ) -> Result<
        aos_sandbox_core::runtime_backend::ExecutionEffectTransitionV1<
            ExecutionJournalRecoveryTokenV1,
        >,
        DormantRuntimeExecutionOwnerErrorV1,
    > {
        self.validate_current()?;
        self.execution
            .recover_verified_completion(effect, evidence, token)
            .map_err(Into::into)
    }

    /// Persists a checkpoint candidate only after protected full-history replay.
    ///
    /// # Errors
    ///
    /// Returns [`AgentCheckpointError`] for stale currentness, a projection
    /// mismatch, sequence conflict, corrupt state, or unavailable durability.
    pub fn commit_agent_checkpoint(
        &mut self,
        candidate: &AgentCheckpointCandidateV1,
    ) -> Result<AuthenticatedJournalAgentCheckpointV1, AgentCheckpointError> {
        self.validate_current()
            .map_err(|_| AgentCheckpointError::StoreUnavailable)?;
        self.agent.commit_checkpoint(candidate)
    }

    /// Loads the authenticated newest agent checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`AgentCheckpointError`] for stale currentness or malformed,
    /// unavailable, rolled-back, or unauthenticated protected state.
    pub fn load_agent_checkpoint(
        &mut self,
    ) -> Result<Option<AuthenticatedJournalAgentCheckpointV1>, AgentCheckpointError> {
        self.validate_current()
            .map_err(|_| AgentCheckpointError::StoreUnavailable)?;
        self.agent.load_checkpoint()
    }

    fn validate_current(&self) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
        if self.peer_authority.snapshot()?.sequence() != self.protected_sequence
            || self.peer_authority.get(PEER_CURRENT_KEY)? != Some(self.peer_record.as_slice())
            || self.peer_authority.get(CURRENTNESS_KEY)? != Some(self.currentness_record.as_slice())
        {
            return Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness);
        }
        Ok(())
    }
}

impl ExecutionAdmissionStore for DormantRuntimeExecutionClaimV1<'_> {
    type RecoveryToken = ExecutionJournalRecoveryTokenV1;

    fn commit_execution_admission(
        &mut self,
        draft: &ExecutionAdmissionDraftV1,
    ) -> Result<AdmissionStoreCommitV1<Self::RecoveryToken>, AdmissionCommitError> {
        self.validate_current()
            .map_err(|_| AdmissionCommitError::StaleAuthority)?;
        self.execution.commit_execution_admission(draft)
    }

    fn recover_execution_admission(
        &mut self,
        token: Self::RecoveryToken,
        draft: &ExecutionAdmissionDraftV1,
    ) -> Result<AdmissionStoreCommitV1<Self::RecoveryToken>, AdmissionCommitError> {
        self.validate_current()
            .map_err(|_| AdmissionCommitError::StaleAuthority)?;
        self.execution.recover_execution_admission(token, draft)
    }
}

impl ExecutionEffectStore for DormantRuntimeExecutionClaimV1<'_> {
    type RecoveryToken = ExecutionJournalRecoveryTokenV1;

    fn commit_pending_effect(
        &mut self,
        admission: &AdmittedExecutionV1,
        issue: &EffectIssueV1,
        expected_record: ObjectDigest,
    ) -> Result<EffectStoreTransitionV1<Self::RecoveryToken>, EffectCommitError> {
        self.validate_current()
            .map_err(|_| EffectCommitError::StaleAuthority)?;
        self.execution
            .commit_pending_effect(admission, issue, expected_record)
    }

    fn commit_effect_issued(
        &mut self,
        effect: &DurableExecutionEffectV1,
        expected_record: ObjectDigest,
    ) -> Result<EffectStoreTransitionV1<Self::RecoveryToken>, EffectCommitError> {
        self.validate_current()
            .map_err(|_| EffectCommitError::StaleAuthority)?;
        self.execution.commit_effect_issued(effect, expected_record)
    }

    fn commit_effect_indeterminate(
        &mut self,
        effect: &DurableExecutionEffectV1,
        expected_record: ObjectDigest,
    ) -> Result<EffectStoreTransitionV1<Self::RecoveryToken>, EffectCommitError> {
        self.validate_current()
            .map_err(|_| EffectCommitError::StaleAuthority)?;
        self.execution
            .commit_effect_indeterminate(effect, expected_record)
    }

    fn commit_effect_complete(
        &mut self,
        effect: &DurableExecutionEffectV1,
        completion: &EffectCompletionV1,
        expected_record: ObjectDigest,
    ) -> Result<EffectStoreTransitionV1<Self::RecoveryToken>, EffectCommitError> {
        self.validate_current()
            .map_err(|_| EffectCommitError::StaleAuthority)?;
        self.execution
            .commit_effect_complete(effect, completion, expected_record)
    }

    fn recover_effect_transition(
        &mut self,
        token: Self::RecoveryToken,
        expected_record: ObjectDigest,
    ) -> Result<EffectStoreTransitionV1<Self::RecoveryToken>, EffectCommitError> {
        self.validate_current()
            .map_err(|_| EffectCommitError::StaleAuthority)?;
        self.execution
            .recover_effect_transition(token, expected_record)
    }
}

impl AgentOperationCas for DormantRuntimeExecutionClaimV1<'_> {
    fn reserve_operation(
        &mut self,
        request: &AgentOperationRequestV1,
    ) -> Result<AgentReservationStoreTransitionV1, AgentOperationCasError> {
        self.validate_current()
            .map_err(|_| AgentOperationCasError::Equivocation)?;
        self.agent.reserve_operation(request)
    }

    fn commit_operation_outcome(
        &mut self,
        reservation: &AgentOperationReservationV1,
        outcome: &AgentExecutionOutcomeV1,
    ) -> Result<ObjectDigest, AgentOperationCasError> {
        self.validate_current()
            .map_err(|_| AgentOperationCasError::Equivocation)?;
        self.agent.commit_operation_outcome(reservation, outcome)
    }
}

impl AgentOperationRecoveryCas for DormantRuntimeExecutionClaimV1<'_> {
    fn recover_reservation(
        &mut self,
        token: &AgentReservationRecoveryTokenV1,
        request: &AgentOperationRequestV1,
    ) -> Result<AgentRecoveredReservationV1, AgentOperationCasError> {
        self.validate_current()
            .map_err(|_| AgentOperationCasError::Equivocation)?;
        self.agent.recover_reservation(token, request)
    }

    fn recover_operation(
        &mut self,
        reservation: &AgentOperationReservationV1,
        request: &AgentOperationRequestV1,
    ) -> Result<AgentRecoveredOperationV1, AgentOperationCasError> {
        self.validate_current()
            .map_err(|_| AgentOperationCasError::Equivocation)?;
        self.agent.recover_operation(reservation, request)
    }

    fn resolve_reserved_operation(
        &mut self,
        reservation: &AgentOperationReservationV1,
        request: &AgentOperationRequestV1,
        authenticated: AuthenticatedRecoveredAgentOutcomeV1,
    ) -> Result<ObjectDigest, AgentOperationCasError> {
        self.validate_current()
            .map_err(|_| AgentOperationCasError::Equivocation)?;
        self.agent
            .resolve_reserved_operation(reservation, request, authenticated)
    }
}

struct ResolvedOwnerCurrentnessV1 {
    currentness: AdmissionCurrentnessV1,
    execution_store_binding: ObjectDigest,
    agent_store_binding: ObjectDigest,
    recovery_authority_binding: ObjectDigest,
}

fn resolve_currentness(
    protected_sequence: u64,
    peer: &[u8],
    currentness: &[u8],
) -> Result<ResolvedOwnerCurrentnessV1, DormantRuntimeExecutionOwnerErrorV1> {
    validate_record(peer, PEER_MAGIC, PEER_BYTES)?;
    validate_record(currentness, CURRENTNESS_MAGIC, CURRENTNESS_BYTES)?;

    let public_key = read_array(peer, 8)?;
    if public_key == [0; 32] {
        return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
    }
    let sandbox = SandboxId::from_bytes(read_array(peer, 40)?);
    let incarnation = IncarnationId::from_bytes(read_array(peer, 56)?);
    let node = NodeId::from_bytes(read_array(peer, 72)?);
    let runtime_currentness = RuntimeCurrentnessV1::new(
        sandbox,
        incarnation,
        node,
        AssignmentEpoch::new(read_u64(peer, 88)?),
        ObjectDigest::from_bytes(read_array(peer, 96)?),
        DesiredGeneration::new(read_u64(peer, 128)?),
        NamespaceGeneration::new(read_u64(peer, 136)?),
    )
    .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
    let runtime = RuntimeHandleCommitmentV1::new(
        runtime_currentness,
        ObjectDigest::from_bytes(read_array(peer, 144)?),
        ObjectDigest::from_bytes(read_array(peer, 176)?),
    )
    .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
    let payload_boot_id = PayloadBootId::new(read_array(peer, 208)?)
        .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
    let channel_binding = ObjectDigest::from_bytes(read_array(peer, 224)?);
    if channel_binding.as_bytes() == &[0; 32] {
        return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
    }

    let peer_digest = ObjectDigest::from_bytes(read_array(peer, PEER_BYTES - 32)?);
    let protected_peer_binding = hash_parts(
        b"aos.sandbox.host.agent-peer-authority.v1\0",
        &[
            &protected_sequence.to_be_bytes(),
            peer_digest.as_bytes(),
            &public_key,
            runtime.handle().as_bytes(),
            channel_binding.as_bytes(),
        ],
    );
    let trust_context = hash_parts(
        b"aos.sandbox.host.agent-peer-evidence-trust.v1\0",
        &[
            runtime.handle().as_bytes(),
            protected_peer_binding.as_bytes(),
        ],
    );
    let recovery_authority_binding =
        backend_evidence_authority_binding_v1(public_key, trust_context, channel_binding);

    let backend_probe = BackendProbeCurrentnessV1::new(
        node,
        ObjectDigest::from_bytes(read_array(currentness, 8)?),
        Revision::new(read_u64(currentness, 40)?),
        ObjectDigest::from_bytes(read_array(currentness, 48)?),
    )
    .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
    let currentness_value = AdmissionCurrentnessV1::new(
        runtime,
        payload_boot_id,
        backend_probe,
        recovery_authority_binding,
        ObjectDigest::from_bytes(read_array(currentness, 80)?),
        ObjectDigest::from_bytes(read_array(currentness, 112)?),
    )
    .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
    let currentness_digest = ObjectDigest::from_bytes(read_array(currentness, 144)?);

    Ok(ResolvedOwnerCurrentnessV1 {
        currentness: currentness_value,
        execution_store_binding: hash_parts(
            b"aos.sandbox.runtime-execution.store-owner.v1\0",
            &[
                protected_peer_binding.as_bytes(),
                currentness_digest.as_bytes(),
                recovery_authority_binding.as_bytes(),
            ],
        ),
        agent_store_binding: hash_parts(
            b"aos.sandbox.runtime-execution.agent-store-owner.v1\0",
            &[
                protected_peer_binding.as_bytes(),
                currentness_digest.as_bytes(),
                recovery_authority_binding.as_bytes(),
            ],
        ),
        recovery_authority_binding,
    })
}

fn open_execution_store<'journal>(
    journal: &'journal mut Journal,
    store_binding: ObjectDigest,
    admission_state: ProtectedExecutionAdmissionStateV1,
) -> Result<JournalRuntimeExecutionStoreV1<'journal>, JournalRuntimeExecutionError> {
    let empty = {
        let authority = journal.claim_global_capacity_reservation_authority(
            GlobalCapacityReservationPurposeV1::RuntimeExecution,
        )?;
        authority.is_materialized_empty()?
    };
    if empty {
        JournalRuntimeExecutionStoreV1::initialize(journal, store_binding, admission_state)
    } else {
        JournalRuntimeExecutionStoreV1::claim(journal, store_binding)
    }
}

fn open_agent_store<'journal>(
    journal: &'journal mut Journal,
    store_binding: ObjectDigest,
    recovery_authority_binding: ObjectDigest,
) -> Result<DormantJournalAgentStoreV1<'journal>, JournalAgentStoreError> {
    let empty = {
        let authority = journal.claim_protected_authority(RecordNamespace::Effect)?;
        authority.is_materialized_empty()?
    };
    if empty {
        DormantJournalAgentStoreV1::initialize(journal, store_binding, recovery_authority_binding)
    } else {
        DormantJournalAgentStoreV1::claim(journal, store_binding, recovery_authority_binding)
    }
}

fn validate_record(
    bytes: &[u8],
    magic: &[u8; 8],
    length: usize,
) -> Result<(), DormantRuntimeExecutionOwnerErrorV1> {
    if bytes.len() != length || bytes.get(..8) != Some(magic.as_slice()) {
        return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
    }
    let expected = digest(
        bytes
            .get(..length - 32)
            .ok_or(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?,
    );
    if bytes.get(length - 32..) != Some(expected.as_bytes().as_slice()) {
        return Err(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness);
    }
    Ok(())
}

fn read_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], DormantRuntimeExecutionOwnerErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, DormantRuntimeExecutionOwnerErrorV1> {
    read_array(bytes, offset).map(u64::from_be_bytes)
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(domain);
    for part in parts {
        digest.update(part);
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn digest(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(Sha256::digest(bytes).into())
}

/// Reports fixed-root runtime execution ownership and replay failure.
#[derive(Debug, thiserror::Error)]
pub enum DormantRuntimeExecutionOwnerErrorV1 {
    /// The protected Host peer or runtime-currentness record is absent.
    #[error("protected runtime execution currentness is absent")]
    MissingCurrentness,
    /// A protected record is noncanonical, invalid, or internally inconsistent.
    #[error("protected runtime execution currentness is malformed")]
    MalformedCurrentness,
    /// The protected peer/currentness record changed while the claim was live.
    #[error("protected runtime execution currentness is stale")]
    StaleCurrentness,
    /// Fixed-root protected journal access or replay failed.
    #[error("runtime execution owner journal failed: {0}")]
    Journal(#[from] JournalError),
    /// The execution store failed initialization, replay, or mutation.
    #[error("runtime execution durable store failed: {0}")]
    Execution(#[from] JournalRuntimeExecutionError),
    /// The agent store failed initialization or full replay.
    #[error("runtime execution agent store failed: {0}")]
    Agent(#[from] JournalAgentStoreError),
}
