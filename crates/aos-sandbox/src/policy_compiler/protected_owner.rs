//! Fixed-root ownership for dormant compiled-policy publication.
//!
//! A dedicated root-owned authority journal carries exact prerequisite and
//! compiler-output bindings. The owner never accepts a caller-provided
//! verifier: it authenticates replay, planning, commit, recovery, and
//! postcommit handoff against those protected records while holding their
//! currentness lock.

use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
};

use aos_sandbox_core::{ObjectDigest, ProjectId, SandboxId};
use sha2::{Digest as _, Sha256};

use crate::journal::{Journal, JournalError, JournalLimits, RecordNamespace, RecoveryReport};
use crate::lifecycle::protected_journal_adapter::ProtectedDomainJournalErrorV1;

use super::binding_v2::{BINDING_V2_KEY_PREFIX, decode_closed_policy_binding_v2};
use super::protected_journal::{
    PolicyEffectObservationRequestV1, PolicyPublicationVerifierV1,
    VerifiedPolicyEffectObservationV1, VerifiedPolicyPublicationV1,
};

use super::{
    PolicyCheckpointCommitOutcomeV1, PolicyCheckpointOutcomeUnknownV1, PolicyCheckpointRecoveryV1,
    PolicyCompilerEffectHandoffV1, PolicyCompilerInputV1, PolicyCompilerJournalErrorV1,
    PolicyCompilerJournalProjectionV1, PolicyCompilerJournalSnapshotV1,
    PolicyCompilerProtectedJournalV1, PolicyCompilerReplayValidatorV1, PolicyCompilerV1,
    PolicyEffectObservationCommitOutcomeV1, PolicyEffectObservationOutcomeUnknownV1,
    PolicyEffectObservationRecoveryV1, PolicyPublicationColdRecoveryV1,
    PolicyPublicationCommitOutcomeV1, PolicyPublicationOutcomeUnknownV1,
    PolicyPublicationPrerequisitesV1, PolicyPublicationRecoveryV1,
};

pub(super) const PROTECTED_POLICY_ROOT: &str = "/var/lib/aos/sandbox/policy-compiler";
const POLICY_STATE_JOURNAL: &str = "state.journal";
pub(super) const POLICY_AUTHORITY_JOURNAL: &str = "authority.journal";
pub(super) const POLICY_BINDING_KEY_PREFIX: &[u8] = b"\0aos-policy-compiler-binding-v1\0";
const POLICY_BINDING_MAGIC: &[u8; 8] = b"AOSPCB01";
const POLICY_BINDING_BYTES: usize = 280;
const POLICY_EFFECT_OBSERVATION_KEY_PREFIX: &[u8] =
    b"\0aos-policy-effect-observation-authority-v1\0";
const POLICY_EFFECT_OBSERVATION_MAGIC: &[u8; 8] = b"AOSPEO01";
const POLICY_EFFECT_OBSERVATION_BYTES: usize = 248;
pub(super) const MAXIMUM_POLICY_BINDINGS: usize = 4_096;

impl From<JournalError> for PolicyCompilerJournalErrorV1 {
    fn from(error: JournalError) -> Self {
        Self::Journal(ProtectedDomainJournalErrorV1::Journal(error))
    }
}

/// Reports protected replay of policy state and its authority bindings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyCompilerProtectedOpenReportV1 {
    /// Reports compiled-policy state replay.
    pub state: RecoveryReport,
    /// Reports compiler-authority binding replay.
    pub authority: RecoveryReport,
}

/// Owns the complete dormant policy compiler and publication boundary.
pub struct PolicyCompilerProtectedOwnerV1 {
    state_journal: Option<Journal>,
    validator: PolicyCompilerReplayValidatorV1,
    verifier: Arc<ProtectedPolicyPublicationVerifierV1>,
}

/// Classifies cold policy resolution without leaking instance-bound authority.
#[must_use = "cold policy resolution must be handled"]
pub enum PolicyCompilerProtectedColdOutcomeV1<R> {
    /// The transaction carries no current effect or publication authority.
    StateOnly,
    /// A pending installation requires a trusted external observation.
    ObservationRequired,
    /// The exact observation successor reached the protected journal.
    ObservationCommitted(PolicyEffectObservationCommitOutcomeV1),
    /// A terminal publication was revalidated inside the supplied callback.
    Terminal(R),
}

/// Classifies checkpoint recovery after any safe retry is handled in-claim.
#[must_use = "checkpoint recovery must be handled"]
pub enum PolicyCompilerProtectedCheckpointRecoveryV1 {
    /// The exact checkpoint was already durable.
    Applied,
    /// Exact predecessors permitted one retry, whose result is retained here.
    Retried(PolicyCheckpointCommitOutcomeV1),
    /// Durable state differs from both the predecessor and successor.
    Diverged(PolicyCheckpointOutcomeUnknownV1),
    /// Full protected replay could not classify the retained transaction.
    Indeterminate {
        /// Retains the exact checkpoint transaction for another owner recovery.
        pending: PolicyCheckpointOutcomeUnknownV1,
        /// Reports the fail-closed typed replay failure.
        cause: PolicyCompilerJournalErrorV1,
    },
}

/// Classifies protected observation recovery after any exact retry is committed.
#[must_use = "observation recovery must be handled"]
pub enum PolicyCompilerProtectedObservationRecoveryV1 {
    /// The exact observed successor was already durable.
    Applied,
    /// Exact predecessors permitted one retry, whose result is retained here.
    Retried(PolicyEffectObservationCommitOutcomeV1),
    /// Durable state differs from both the predecessor and observed successor.
    Diverged(PolicyEffectObservationOutcomeUnknownV1),
}

impl PolicyCompilerProtectedOwnerV1 {
    /// Opens fixed root-owned journals and authenticates complete cold replay.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe protected paths, malformed or duplicate
    /// authority bindings, or invalid compiled-policy history.
    pub fn open_fixed_protected()
    -> Result<(Self, PolicyCompilerProtectedOpenReportV1), PolicyCompilerJournalErrorV1> {
        let root = Path::new(PROTECTED_POLICY_ROOT);
        let (authority_journal, authority_report) = Journal::open_protected_at(
            root,
            POLICY_AUTHORITY_JOURNAL,
            policy_authority_journal_limits(),
        )?;
        let verifier = Arc::new(ProtectedPolicyPublicationVerifierV1::from_journal(
            authority_journal,
        )?);
        let prerequisites = verifier.authenticated_prerequisites();
        let validator =
            PolicyCompilerReplayValidatorV1::authenticate(prerequisites, verifier.as_ref())?;

        let (mut state_journal, state_report) =
            Journal::open_protected_at(root, POLICY_STATE_JOURNAL, policy_state_journal_limits())?;
        PolicyCompilerProtectedJournalV1::claim(&mut state_journal, validator.clone())?.replay()?;

        Ok((
            Self {
                state_journal: Some(state_journal),
                validator,
                verifier,
            },
            PolicyCompilerProtectedOpenReportV1 {
                state: state_report,
                authority: authority_report,
            },
        ))
    }

    /// Replays every compiled output, diagnostic, effect, and current head.
    ///
    /// # Errors
    ///
    /// Returns an error when protected state or an authority binding is no
    /// longer canonical.
    pub fn replay(
        &mut self,
    ) -> Result<PolicyCompilerJournalProjectionV1, PolicyCompilerJournalErrorV1> {
        self.claim()?.replay()
    }

    /// Captures exact compiled-policy currentness.
    ///
    /// # Errors
    ///
    /// Returns an error when protected replay fails.
    pub fn snapshot(
        &mut self,
    ) -> Result<PolicyCompilerJournalSnapshotV1, PolicyCompilerJournalErrorV1> {
        self.claim()?.snapshot()
    }

    /// Compiles, authenticates, plans, commits, and reads back one publication.
    ///
    /// The protected authority journal must already contain the exact target,
    /// normalized-input, candidate, and prerequisite binding. This method
    /// performs no live installation or advertisement.
    ///
    /// # Errors
    ///
    /// Returns an error for compilation failure, missing protected authority,
    /// stale prerequisites, invalid generation/CAS, or rejected durability.
    pub fn compile_plan_commit_and_handoff<R>(
        &mut self,
        transaction_id: [u8; 16],
        generation: u64,
        input: PolicyCompilerInputV1,
        prerequisites: PolicyPublicationPrerequisitesV1,
        handoff: impl for<'guard> FnOnce(PolicyCompilerEffectHandoffV1<'guard>) -> R,
    ) -> Result<(PolicyPublicationCommitOutcomeV1, Option<R>), PolicyCompilerJournalErrorV1> {
        let candidate = PolicyCompilerV1::compile(input.clone())
            .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        let verified = VerifiedPolicyPublicationV1::authenticate(
            &input,
            candidate,
            prerequisites,
            self.verifier.as_ref(),
        )?;
        let verifier = Arc::clone(&self.verifier);
        let mut journal = self.claim()?;
        let prepared = journal.plan_publication(transaction_id, generation, verified)?;
        let mut outcome = journal.commit(prepared, verifier.as_ref())?;
        let handoff_result = match &mut outcome {
            PolicyPublicationCommitOutcomeV1::Applied(applied) => {
                let capability = applied
                    .take_postcommit()
                    .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
                Some(capability.consume_with(&journal, verifier.as_ref(), handoff)?)
            }
            PolicyPublicationCommitOutcomeV1::OutcomeUnknown { .. } => None,
        };
        Ok((outcome, handoff_result))
    }

    /// Reopens protected state and classifies one ambiguous publication.
    ///
    /// # Errors
    ///
    /// Returns an error when protected reopen, currentness, or typed replay
    /// fails closed.
    pub fn recover_publication<R>(
        &mut self,
        pending: PolicyPublicationOutcomeUnknownV1,
        handoff: impl for<'guard> FnOnce(PolicyCompilerEffectHandoffV1<'guard>) -> R,
    ) -> Result<(PolicyPublicationRecoveryV1, Option<R>), PolicyCompilerJournalErrorV1> {
        self.reopen_state()?;
        let verifier = Arc::clone(&self.verifier);
        let journal = self.claim()?;
        let mut recovery = journal.recover(pending, verifier.as_ref())?;
        let handoff_result = match &mut recovery {
            PolicyPublicationRecoveryV1::Applied(applied) => {
                let capability = applied
                    .take_postcommit()
                    .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
                Some(capability.consume_with(&journal, verifier.as_ref(), handoff)?)
            }
            PolicyPublicationRecoveryV1::Retry(_) | PolicyPublicationRecoveryV1::Diverged(_) => {
                None
            }
        };
        Ok((recovery, handoff_result))
    }

    /// Resolves one cold publication with observation-only pending effects.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed grouping or unauthenticated replay.
    pub fn resolve_current_transaction<R>(
        &mut self,
        transaction_id: [u8; 16],
        observation: Option<([u8; 16], ObjectDigest)>,
        handoff: impl for<'guard> FnOnce(PolicyCompilerEffectHandoffV1<'guard>) -> R,
    ) -> Result<PolicyCompilerProtectedColdOutcomeV1<R>, PolicyCompilerJournalErrorV1> {
        let verifier = Arc::clone(&self.verifier);
        let mut journal = self.claim()?;
        match journal.recover_current_transaction(transaction_id)? {
            PolicyPublicationColdRecoveryV1::StateOnly => {
                Ok(PolicyCompilerProtectedColdOutcomeV1::StateOnly)
            }
            PolicyPublicationColdRecoveryV1::ObservePending(cold) => {
                let Some((settlement_transaction_id, observation)) = observation else {
                    return Ok(PolicyCompilerProtectedColdOutcomeV1::ObservationRequired);
                };
                let prepared = journal.plan_cold_observation(
                    settlement_transaction_id,
                    cold,
                    observation,
                    verifier.as_ref(),
                )?;
                let outcome = journal.commit_observation(prepared, verifier.as_ref())?;
                Ok(PolicyCompilerProtectedColdOutcomeV1::ObservationCommitted(
                    outcome,
                ))
            }
            PolicyPublicationColdRecoveryV1::Terminal(cold) => {
                let result = cold.consume_with(&journal, verifier.as_ref(), handoff)?;
                Ok(PolicyCompilerProtectedColdOutcomeV1::Terminal(result))
            }
        }
    }

    /// Reopens protected state, resolves an ambiguous observation, and retries safely.
    ///
    /// # Errors
    ///
    /// Returns an error when protected reopen, observation currentness, or
    /// typed effect replay fails closed.
    pub fn recover_observation(
        &mut self,
        pending: PolicyEffectObservationOutcomeUnknownV1,
    ) -> Result<PolicyCompilerProtectedObservationRecoveryV1, PolicyCompilerJournalErrorV1> {
        self.reopen_state()?;
        let verifier = Arc::clone(&self.verifier);
        let mut journal = self.claim()?;
        Ok(
            match journal.recover_observation(pending, verifier.as_ref())? {
                PolicyEffectObservationRecoveryV1::Applied => {
                    PolicyCompilerProtectedObservationRecoveryV1::Applied
                }
                PolicyEffectObservationRecoveryV1::Retry(prepared) => {
                    PolicyCompilerProtectedObservationRecoveryV1::Retried(
                        journal.commit_observation(prepared, verifier.as_ref())?,
                    )
                }
                PolicyEffectObservationRecoveryV1::Diverged(pending) => {
                    PolicyCompilerProtectedObservationRecoveryV1::Diverged(pending)
                }
            },
        )
    }

    /// Plans and commits one state-only checkpoint join.
    ///
    /// # Errors
    ///
    /// Returns an error for a sentinel checkpoint, stale state, or durability
    /// failure.
    pub fn checkpoint(
        &mut self,
        transaction_id: [u8; 16],
        checkpoint: ObjectDigest,
    ) -> Result<PolicyCheckpointCommitOutcomeV1, PolicyCompilerJournalErrorV1> {
        let mut journal = self.claim()?;
        let prepared = journal.plan_checkpoint(transaction_id, checkpoint)?;
        journal.commit_checkpoint(prepared)
    }

    /// Reopens protected state, classifies an ambiguous checkpoint, and retries safely.
    ///
    /// A retry is committed before this fresh adapter claim ends, so its
    /// instance-bound prepared state never escapes the owner.
    ///
    /// # Errors
    ///
    /// Returns an error when protected reopen or typed checkpoint replay fails.
    pub fn recover_checkpoint(
        &mut self,
        pending: PolicyCheckpointOutcomeUnknownV1,
    ) -> Result<PolicyCompilerProtectedCheckpointRecoveryV1, PolicyCompilerJournalErrorV1> {
        self.reopen_state()?;
        let mut journal = self.claim()?;
        Ok(match journal.recover_checkpoint(pending)? {
            PolicyCheckpointRecoveryV1::Applied => {
                PolicyCompilerProtectedCheckpointRecoveryV1::Applied
            }
            PolicyCheckpointRecoveryV1::Retry(prepared) => {
                PolicyCompilerProtectedCheckpointRecoveryV1::Retried(
                    journal.commit_checkpoint(prepared)?,
                )
            }
            PolicyCheckpointRecoveryV1::Diverged(pending) => {
                PolicyCompilerProtectedCheckpointRecoveryV1::Diverged(pending)
            }
            PolicyCheckpointRecoveryV1::Indeterminate { pending, cause } => {
                PolicyCompilerProtectedCheckpointRecoveryV1::Indeterminate { pending, cause }
            }
        })
    }

    fn claim(
        &mut self,
    ) -> Result<PolicyCompilerProtectedJournalV1<'_>, PolicyCompilerJournalErrorV1> {
        let journal = self
            .state_journal
            .as_mut()
            .ok_or(PolicyCompilerJournalErrorV1::Journal(
                ProtectedDomainJournalErrorV1::StaleAuthority,
            ))?;
        PolicyCompilerProtectedJournalV1::claim(journal, self.validator.clone())
    }

    fn reopen_state(&mut self) -> Result<(), PolicyCompilerJournalErrorV1> {
        drop(self.state_journal.take());
        let (journal, _) = Journal::open_protected_at(
            Path::new(PROTECTED_POLICY_ROOT),
            POLICY_STATE_JOURNAL,
            policy_state_journal_limits(),
        )?;
        self.state_journal = Some(journal);
        self.claim()?.replay()?;
        Ok(())
    }
}

pub(super) struct ProtectedPolicyPublicationVerifierV1 {
    journal: Mutex<Journal>,
    bindings: BTreeMap<ObjectDigest, Vec<ProtectedPolicyBindingV1>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProtectedPolicyBindingV1 {
    prerequisites: PolicyPublicationPrerequisitesV1,
    project: ProjectId,
    sandbox: SandboxId,
    normalized_input: ObjectDigest,
    candidate: ObjectDigest,
    key: Vec<u8>,
    encoded: Vec<u8>,
}

impl ProtectedPolicyPublicationVerifierV1 {
    pub(super) fn from_journal(mut journal: Journal) -> Result<Self, PolicyCompilerJournalErrorV1> {
        let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
        let mut bindings = BTreeMap::<ObjectDigest, Vec<ProtectedPolicyBindingV1>>::new();
        let mut binding_count = 0_usize;
        for (key, value) in authority.records()? {
            if key.starts_with(BINDING_V2_KEY_PREFIX) {
                if binding_count >= MAXIMUM_POLICY_BINDINGS {
                    return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
                }
                decode_closed_policy_binding_v2(key, value)?;
                binding_count += 1;
                continue;
            }
            if !key.starts_with(POLICY_BINDING_KEY_PREFIX) {
                continue;
            }
            if binding_count >= MAXIMUM_POLICY_BINDINGS {
                return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
            }
            let mut binding = decode_policy_binding(value)?;
            let suffix = key
                .get(POLICY_BINDING_KEY_PREFIX.len()..)
                .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
            if suffix != binding_digest(&binding).as_bytes() {
                return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
            }
            binding.key = key.to_vec();
            binding.encoded = value.to_vec();
            let bucket = bindings.entry(binding.prerequisites.digest()).or_default();
            if bucket.iter().any(|current| current == &binding) {
                return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
            }
            bucket.push(binding);
            binding_count += 1;
        }
        drop(authority);

        // Neither a legacy nor a structurally complete V2 root record can
        // fence the independent Create, hierarchy, cache, and revocation
        // writers. Until their leases span binding CAS and handoff, retained
        // bindings confer no authority.
        if binding_count != 0 {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }

        Ok(Self {
            journal: Mutex::new(journal),
            bindings,
        })
    }

    fn authenticated_prerequisites(&self) -> Vec<PolicyPublicationPrerequisitesV1> {
        self.bindings
            .values()
            .filter_map(|bindings| bindings.first())
            .map(|binding| binding.prerequisites.clone())
            .collect()
    }

    fn binding_is_current(
        &self,
        authority: &crate::journal::ProtectedJournalAuthority<'_>,
        binding: &ProtectedPolicyBindingV1,
    ) -> bool {
        authority
            .get(&binding.key)
            .ok()
            .flatten()
            .is_some_and(|value| value == binding.encoded.as_slice())
    }

    fn prerequisite_is_current(
        &self,
        authority: &crate::journal::ProtectedJournalAuthority<'_>,
        prerequisites: &PolicyPublicationPrerequisitesV1,
    ) -> bool {
        self.bindings
            .get(&prerequisites.digest())
            .filter(|bindings| {
                bindings
                    .iter()
                    .all(|binding| binding.prerequisites == *prerequisites)
            })
            .is_some_and(|bindings| {
                !bindings.is_empty()
                    && bindings
                        .iter()
                        .all(|binding| self.binding_is_current(authority, binding))
            })
    }

    fn effect_observation_is_current(
        &self,
        authority: &crate::journal::ProtectedJournalAuthority<'_>,
        request: &PolicyEffectObservationRequestV1,
    ) -> bool {
        let Some((key, encoded)) = encode_policy_effect_observation(request) else {
            return false;
        };
        authority
            .get(&key)
            .ok()
            .flatten()
            .is_some_and(|value| value == encoded.as_slice())
    }
}

impl PolicyPublicationVerifierV1 for ProtectedPolicyPublicationVerifierV1 {
    fn prerequisite_evidence_is_authentic(
        &self,
        prerequisites: &PolicyPublicationPrerequisitesV1,
    ) -> bool {
        let Ok(mut journal) = self.journal.lock() else {
            return false;
        };
        let Ok(authority) = journal.claim_protected_authority(RecordNamespace::DesiredState) else {
            return false;
        };
        self.prerequisite_is_current(&authority, prerequisites)
    }

    fn prerequisites_are_current(&self, prerequisites: &PolicyPublicationPrerequisitesV1) -> bool {
        self.prerequisite_evidence_is_authentic(prerequisites)
    }

    fn while_prerequisites_current<T>(
        &self,
        prerequisites: &PolicyPublicationPrerequisitesV1,
        action: impl FnOnce() -> T,
    ) -> Option<T> {
        let mut journal = self.journal.lock().ok()?;
        let authority = journal
            .claim_protected_authority(RecordNamespace::DesiredState)
            .ok()?;
        if !self.prerequisite_is_current(&authority, prerequisites) {
            return None;
        }
        let snapshot = authority.snapshot().ok()?;
        let result = action();
        authority.validate_snapshot_for_effect(&snapshot).ok()?;
        Some(result)
    }

    fn while_effect_observation_current<T>(
        &self,
        prerequisites: &PolicyPublicationPrerequisitesV1,
        request: &PolicyEffectObservationRequestV1,
        action: impl FnOnce(VerifiedPolicyEffectObservationV1) -> T,
    ) -> Option<T> {
        let mut journal = self.journal.lock().ok()?;
        let authority = journal
            .claim_protected_authority(RecordNamespace::DesiredState)
            .ok()?;
        if !self.prerequisite_is_current(&authority, prerequisites)
            || request.prerequisites() != prerequisites.digest()
            || !self.effect_observation_is_current(&authority, request)
        {
            return None;
        }
        let snapshot = authority.snapshot().ok()?;
        let verified = VerifiedPolicyEffectObservationV1::from_protected_authority(request.clone());
        let result = action(verified);
        authority.validate_snapshot_for_effect(&snapshot).ok()?;
        Some(result)
    }

    fn verify(
        &self,
        project: ProjectId,
        sandbox: SandboxId,
        normalized_input: ObjectDigest,
        candidate: ObjectDigest,
        prerequisites: &PolicyPublicationPrerequisitesV1,
    ) -> bool {
        let Ok(mut journal) = self.journal.lock() else {
            return false;
        };
        let Ok(authority) = journal.claim_protected_authority(RecordNamespace::DesiredState) else {
            return false;
        };
        self.bindings
            .get(&prerequisites.digest())
            .and_then(|bindings| {
                bindings.iter().find(|binding| {
                    binding.prerequisites == *prerequisites
                        && binding.project == project
                        && binding.sandbox == sandbox
                        && binding.normalized_input == normalized_input
                        && binding.candidate == candidate
                })
            })
            .is_some_and(|binding| self.binding_is_current(&authority, binding))
    }
}

fn decode_policy_binding(
    bytes: &[u8],
) -> Result<ProtectedPolicyBindingV1, PolicyCompilerJournalErrorV1> {
    if bytes.len() != POLICY_BINDING_BYTES
        || &bytes[..8] != POLICY_BINDING_MAGIC
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[10..16] != [0; 6]
        || bytes[248..280]
            != Sha256::new()
                .chain_update(b"aos.sandbox.policy-compiler.protected-binding.v1\0")
                .chain_update(&bytes[..248])
                .finalize()[..]
    {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    let prerequisites = PolicyPublicationPrerequisitesV1::new(
        ObjectDigest::from_bytes(read_array(bytes, 16)?),
        ObjectDigest::from_bytes(read_array(bytes, 48)?),
        ObjectDigest::from_bytes(read_array(bytes, 80)?),
        ObjectDigest::from_bytes(read_array(bytes, 112)?),
        read_u64(bytes, 144)?,
    )?;
    let project_bytes = read_array(bytes, 152)?;
    let sandbox_bytes = read_array(bytes, 168)?;
    let normalized_input = ObjectDigest::from_bytes(read_array(bytes, 184)?);
    let candidate = ObjectDigest::from_bytes(read_array(bytes, 216)?);
    if project_bytes == [0; 16]
        || sandbox_bytes == [0; 16]
        || normalized_input.as_bytes() == &[0; 32]
        || candidate.as_bytes() == &[0; 32]
    {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    Ok(ProtectedPolicyBindingV1 {
        prerequisites,
        project: ProjectId::from_bytes(project_bytes),
        sandbox: SandboxId::from_bytes(sandbox_bytes),
        normalized_input,
        candidate,
        key: Vec::new(),
        encoded: Vec::new(),
    })
}

fn encode_policy_effect_observation(
    request: &PolicyEffectObservationRequestV1,
) -> Option<(Vec<u8>, [u8; POLICY_EFFECT_OBSERVATION_BYTES])> {
    if request.project().as_bytes() == &[0; 16]
        || request.sandbox().as_bytes() == &[0; 16]
        || request.effect_transaction_id() == [0; 16]
        || request.settlement_transaction_id() == [0; 16]
        || request.effect_transaction_id() == request.settlement_transaction_id()
        || request.effect_predecessor().as_bytes() == &[0; 32]
        || request.outputs().as_bytes() == &[0; 32]
        || request.generation() == 0
        || request.result().as_bytes() == &[0; 32]
        || request.prerequisites().as_bytes() == &[0; 32]
    {
        return None;
    }

    let mut key = Vec::with_capacity(POLICY_EFFECT_OBSERVATION_KEY_PREFIX.len() + 64);
    key.extend_from_slice(POLICY_EFFECT_OBSERVATION_KEY_PREFIX);
    key.extend_from_slice(&request.effect_transaction_id());
    key.extend_from_slice(&request.settlement_transaction_id());
    key.extend_from_slice(request.effect_predecessor().as_bytes());

    let mut encoded = [0_u8; POLICY_EFFECT_OBSERVATION_BYTES];
    encoded[..8].copy_from_slice(POLICY_EFFECT_OBSERVATION_MAGIC);
    encoded[8..10].copy_from_slice(&1_u16.to_be_bytes());
    encoded[16..32].copy_from_slice(request.project().as_bytes());
    encoded[32..48].copy_from_slice(request.sandbox().as_bytes());
    encoded[48..64].copy_from_slice(&request.effect_transaction_id());
    encoded[64..80].copy_from_slice(&request.settlement_transaction_id());
    encoded[80..112].copy_from_slice(request.effect_predecessor().as_bytes());
    encoded[112..144].copy_from_slice(request.outputs().as_bytes());
    encoded[144..152].copy_from_slice(&request.generation().to_be_bytes());
    encoded[152..184].copy_from_slice(request.result().as_bytes());
    encoded[184..216].copy_from_slice(request.prerequisites().as_bytes());
    let checksum = Sha256::new()
        .chain_update(b"aos.sandbox.policy-compiler.protected-effect-observation.v1\0")
        .chain_update(&encoded[..216])
        .finalize();
    encoded[216..248].copy_from_slice(&checksum);
    Some((key, encoded))
}

fn binding_digest(binding: &ProtectedPolicyBindingV1) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.policy-compiler.binding-key.v1\0")
            .chain_update(binding.prerequisites.digest().as_bytes())
            .chain_update(binding.project.as_bytes())
            .chain_update(binding.sandbox.as_bytes())
            .chain_update(binding.normalized_input.as_bytes())
            .chain_update(binding.candidate.as_bytes())
            .finalize()
            .into(),
    )
}

fn policy_state_journal_limits() -> JournalLimits {
    JournalLimits::default()
}

pub(super) fn policy_authority_journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 64 * 1024 * 1024,
        maximum_record_bytes: 4 * 1024,
        maximum_key_bytes: 128,
        maximum_records_per_transaction: 256,
        maximum_transaction_bytes: 2 * 1024 * 1024,
        maximum_transactions: 262_144,
        maximum_materialized_bytes: 8 * 1024 * 1024,
        // Fixed custody plus a bounded window of Cache packet settlements.
        maximum_materialized_records: MAXIMUM_POLICY_BINDINGS
            + 11
            + super::cache_root_settlement::SETTLEMENT_ARCHIVE_WINDOW as usize,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use crate::journal::{JournalRecord, JournalTransaction};

    use super::*;

    #[test]
    fn root_authority_budget_reserves_the_binding_hold_record() {
        let limits = policy_authority_journal_limits();
        assert_eq!(
            limits.maximum_materialized_records,
            MAXIMUM_POLICY_BINDINGS
                + 11
                + super::super::cache_root_settlement::SETTLEMENT_ARCHIVE_WINDOW as usize
        );
        assert!(
            limits.maximum_record_bytes >= super::super::binding_v2::CLOSED_POLICY_BINDING_BYTES_V2
        );
    }

    #[test]
    fn legacy_binding_cannot_authorize_without_cross_owner_fence() {
        let prerequisites = PolicyPublicationPrerequisitesV1::new(
            ObjectDigest::from_bytes([1; 32]),
            ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
            1,
        )
        .expect("prerequisites");
        let binding = ProtectedPolicyBindingV1 {
            prerequisites,
            project: ProjectId::from_bytes([5; 16]),
            sandbox: SandboxId::from_bytes([6; 16]),
            normalized_input: ObjectDigest::from_bytes([7; 32]),
            candidate: ObjectDigest::from_bytes([8; 32]),
            key: Vec::new(),
            encoded: Vec::new(),
        };
        let mut encoded = [0_u8; POLICY_BINDING_BYTES];
        encoded[..8].copy_from_slice(POLICY_BINDING_MAGIC);
        encoded[8..10].copy_from_slice(&1_u16.to_be_bytes());
        encoded[16..48].copy_from_slice(binding.prerequisites.ancestry_head().as_bytes());
        encoded[48..80].copy_from_slice(binding.prerequisites.compiler_authority_head().as_bytes());
        encoded[80..112].copy_from_slice(binding.prerequisites.cache_domain_head().as_bytes());
        encoded[112..144].copy_from_slice(binding.prerequisites.revocation_head().as_bytes());
        encoded[144..152].copy_from_slice(&binding.prerequisites.generation().to_be_bytes());
        encoded[152..168].copy_from_slice(binding.project.as_bytes());
        encoded[168..184].copy_from_slice(binding.sandbox.as_bytes());
        encoded[184..216].copy_from_slice(binding.normalized_input.as_bytes());
        encoded[216..248].copy_from_slice(binding.candidate.as_bytes());
        let checksum = Sha256::new()
            .chain_update(b"aos.sandbox.policy-compiler.protected-binding.v1\0")
            .chain_update(&encoded[..248])
            .finalize();
        encoded[248..280].copy_from_slice(&checksum);

        let mut key = POLICY_BINDING_KEY_PREFIX.to_vec();
        key.extend_from_slice(binding_digest(&binding).as_bytes());
        let directory = tempfile::tempdir().expect("protected test directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private test directory");
        let uid = fs::metadata(directory.path())
            .expect("directory owner")
            .uid();
        let (mut journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            "authority.journal",
            policy_authority_journal_limits(),
            uid,
        )
        .expect("protected authority journal");
        let transaction = JournalTransaction::new(
            [9; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                key,
                encoded.to_vec(),
            )],
        )
        .expect("binding transaction");
        journal
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("protected claim")
            .commit(&transaction)
            .expect("durable binding");

        assert!(matches!(
            ProtectedPolicyPublicationVerifierV1::from_journal(journal),
            Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)
        ));
    }
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, PolicyCompilerJournalErrorV1> {
    Ok(u64::from_be_bytes(read_array(bytes, offset)?))
}

fn read_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], PolicyCompilerJournalErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)
}
