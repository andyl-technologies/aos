//! Dormant protected publication for compiled policy artifacts.
//!
//! Compilation remains inert until the crate-sealed protected verifier authenticates the
//! normalized input and ancestry/currentness joins. This adapter then commits
//! the complete portable output, complete diagnostics, immediate-successor
//! publication head, and effect handoff in one exact CAS transaction.

use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
};

use aos_sandbox_core::{
    DecodeLimits, ObjectDescriptor, ObjectDigest, PortableMediaType, ProjectId, SandboxId,
    format::{decode_optimization, decode_policy, encode_optimization, encode_policy},
};
use sha2::{Digest as _, Sha256};

use crate::journal::{Journal, JournalError, RecordNamespace};
use crate::lifecycle::protected_journal_adapter::{
    AppliedDomainTransactionV1, DomainCommitOutcomeV1, DomainOutcomeUnknownV1,
    DomainPostcommitCapabilityV1, DomainRecoveryV1, PreparedDomainTransactionV1,
    ProtectedDomainEnvelopeV1, ProtectedDomainJournalErrorV1, ProtectedDomainJournalV1,
    ProtectedDomainKeyV1, ProtectedDomainProjectionV1, ProtectedDomainSchemaV1,
    ProtectedDomainSnapshotV1, ProtectedRecordRoleV1, ProtectedReducerPhaseV1,
    ReplayedDomainPostcommitV1, ValidatedDomainPostcommitV1, decode_reducer_payload_with_validator,
    encode_reducer_payload_with_validator,
};

use super::{
    CandidateAuthorityV1, CompiledPolicyCandidateV1, PolicyCompilerInputV1, PolicyModelError,
};

const CURRENT_MAGIC: &[u8; 8] = b"AOSPCU01";
const CANDIDATE_MAGIC: &[u8; 8] = b"AOSPCC01";
const MAXIMUM_AUTHENTICATED_REPLAY_PREREQUISITES: usize = 4_096;
const DIAGNOSTICS_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.diagnostics.v1";
const INPUT_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.normalized-input.v1\0";
const PREREQUISITE_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.prerequisites.v1\0";

/// Selects one closed policy-publication record family.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum PolicyCompilerJournalRecordKindV1 {
    /// Stores complete portable policy outputs and their normalized input digest.
    Candidate = 1,
    /// Stores complete canonical compiler diagnostics.
    Diagnostics = 2,
    /// Stores a prepared downstream policy-installation effect.
    Effect = 3,
    /// Publishes the exact immediate-successor policy head.
    Current = 4,
    /// Publishes a replay join without granting compaction authority.
    Checkpoint = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum PolicyEffectStateV1 {
    Prepared = 1,
    Observed = 2,
}

/// Defines the policy-compiler protected-journal schema.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PolicyCompilerJournalSchemaV1;

/// Carries authenticated prerequisite evidence used during durable replay.
#[derive(Clone, Debug)]
pub struct PolicyCompilerReplayValidatorV1 {
    authenticated_prerequisites: BTreeMap<ObjectDigest, PolicyPublicationPrerequisitesV1>,
}

impl PolicyCompilerReplayValidatorV1 {
    /// Authenticates the complete bounded prerequisite set before journal claim.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1::UnauthenticatedCandidate`] when
    /// any prerequisite tuple lacks durable provenance evidence, is duplicated,
    /// or would exceed the fixed replay bound.
    pub(crate) fn authenticate(
        prerequisites: impl IntoIterator<Item = PolicyPublicationPrerequisitesV1>,
        verifier: &impl PolicyPublicationVerifierV1,
    ) -> Result<Self, PolicyCompilerJournalErrorV1> {
        let mut authenticated_prerequisites = BTreeMap::new();
        for prerequisite in prerequisites {
            if authenticated_prerequisites.len() >= MAXIMUM_AUTHENTICATED_REPLAY_PREREQUISITES
                || !verifier.prerequisite_evidence_is_authentic(&prerequisite)
                || authenticated_prerequisites
                    .insert(prerequisite.digest(), prerequisite)
                    .is_some()
            {
                return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
            }
        }
        Ok(Self {
            authenticated_prerequisites,
        })
    }

    fn contains(&self, prerequisites: &PolicyPublicationPrerequisitesV1) -> bool {
        self.authenticated_prerequisites
            .get(&prerequisites.digest())
            == Some(prerequisites)
    }
}

impl ProtectedDomainSchemaV1 for PolicyCompilerJournalSchemaV1 {
    type Kind = PolicyCompilerJournalRecordKindV1;
    type ReplayValidator = PolicyCompilerReplayValidatorV1;

    const MAGIC: [u8; 8] = *b"AOSPCJ01";
    const HASH_DOMAIN: &'static [u8] = b"aos.sandbox.policy-compiler.journal.v1\0";
    const KEY_PREFIX: &'static [u8] = b"\0aos-policy-compiler-v1\0";
    const MAXIMUM_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;

    fn kind_code(kind: Self::Kind) -> u8 {
        kind as u8
    }

    fn kind_from_code(code: u8) -> Option<Self::Kind> {
        match code {
            1 => Some(Self::Kind::Candidate),
            2 => Some(Self::Kind::Diagnostics),
            3 => Some(Self::Kind::Effect),
            4 => Some(Self::Kind::Current),
            5 => Some(Self::Kind::Checkpoint),
            _ => None,
        }
    }

    fn namespace(kind: Self::Kind) -> RecordNamespace {
        match kind {
            Self::Kind::Candidate | Self::Kind::Diagnostics => RecordNamespace::PublisherPolicy,
            Self::Kind::Effect => RecordNamespace::Effect,
            Self::Kind::Current => RecordNamespace::AuthorityPublication,
            Self::Kind::Checkpoint => RecordNamespace::RuntimeGeneration,
        }
    }

    fn order(kind: Self::Kind) -> u8 {
        kind as u8
    }

    fn role(kind: Self::Kind) -> ProtectedRecordRoleV1 {
        match kind {
            Self::Kind::Candidate | Self::Kind::Diagnostics => ProtectedRecordRoleV1::State,
            Self::Kind::Effect => ProtectedRecordRoleV1::Effect,
            Self::Kind::Current | Self::Kind::Checkpoint => ProtectedRecordRoleV1::Publication,
        }
    }

    fn is_checkpoint(kind: Self::Kind) -> bool {
        matches!(kind, Self::Kind::Checkpoint)
    }

    fn family(kind: Self::Kind) -> u8 {
        kind as u8
    }

    fn decode_reducer_phase(
        validator: &Self::ReplayValidator,
        kind: Self::Kind,
        identity: &[u8],
        body: &[u8],
    ) -> Option<ProtectedReducerPhaseV1> {
        match kind {
            Self::Kind::Candidate => {
                let candidate = validate_candidate_payload(body).ok()?;
                (identity.len() == 64
                    && body.get(10..42) == identity.get(..32)
                    && identity[32..] == *candidate.candidate.as_bytes()
                    && validator.contains(&candidate.prerequisite_tuple))
                .then_some(ProtectedReducerPhaseV1::Terminal)
            }
            Self::Kind::Diagnostics => (body.get(10..74) == Some(identity))
                .then(|| decode_diagnostics_payload(body).ok())
                .flatten()
                .map(|_| ProtectedReducerPhaseV1::Terminal),
            Self::Kind::Effect => {
                let effect = decode_effect_header(body).ok()?;
                (body.get(10..58) == Some(identity)
                    && validator.contains(&effect.prerequisite_tuple))
                .then_some(match effect.state {
                    PolicyEffectStateV1::Prepared => ProtectedReducerPhaseV1::Prepared,
                    PolicyEffectStateV1::Observed => ProtectedReducerPhaseV1::Observed,
                })
            }
            Self::Kind::Current => {
                let current = decode_current_payload(body).ok()?;
                (body.get(10..42) == Some(identity)
                    && validator.contains(&current.prerequisite_tuple))
                .then_some(ProtectedReducerPhaseV1::Terminal)
            }
            Self::Kind::Checkpoint => None,
        }
    }

    fn validates_identity(kind: Self::Kind, identity: &[u8]) -> bool {
        match kind {
            Self::Kind::Candidate | Self::Kind::Diagnostics => {
                identity.len() == 64
                    && identity[..16] != [0; 16]
                    && identity[16..32] != [0; 16]
                    && identity[32..] != [0; 32]
            }
            Self::Kind::Effect => {
                identity.len() == 48
                    && identity[..16] != [0; 16]
                    && identity[16..32] != [0; 16]
                    && identity[32..] != [0; 16]
            }
            Self::Kind::Current => {
                identity.len() == 32 && identity[..16] != [0; 16] && identity[16..] != [0; 16]
            }
            Self::Kind::Checkpoint => identity.len() == 32 && identity != [0; 32],
        }
    }

    fn semantic_tuple(kind: Self::Kind, identity: &[u8], body: &[u8]) -> Option<[u8; 32]> {
        if body.len() < 8 || identity.len() < 32 {
            return None;
        }
        if kind == Self::Kind::Checkpoint {
            return None;
        }
        Some(
            Sha256::new()
                .chain_update(b"aos.sandbox.policy-compiler.semantic-tuple.v1\0")
                .chain_update(&identity[..32])
                .finalize()
                .into(),
        )
    }
}

/// Canonical policy-publication key.
pub type PolicyCompilerJournalKeyV1 = ProtectedDomainKeyV1<PolicyCompilerJournalSchemaV1>;
/// Canonical policy-publication value and predecessor CAS.
pub type PolicyCompilerJournalEnvelopeV1 = ProtectedDomainEnvelopeV1<PolicyCompilerJournalSchemaV1>;
/// Exact policy-publication currentness snapshot.
pub type PolicyCompilerJournalSnapshotV1 = ProtectedDomainSnapshotV1<PolicyCompilerJournalSchemaV1>;
/// Replayed policy-publication projection.
pub type PolicyCompilerJournalProjectionV1 =
    ProtectedDomainProjectionV1<PolicyCompilerJournalSchemaV1>;
type RawPolicyCompilerPostcommitCapabilityV1 =
    DomainPostcommitCapabilityV1<PolicyCompilerJournalSchemaV1>;

/// Binds one composite policy transaction to exact prerequisite currentness.
#[must_use = "policy postcommit authority must be revalidated exactly once"]
pub struct PolicyCompilerPostcommitCapabilityV1 {
    inner: RawPolicyCompilerPostcommitCapabilityV1,
    prerequisites: PolicyPublicationPrerequisitesV1,
}

/// Retains cold-replayed policy authority until exact semantic revalidation.
#[must_use = "cold policy authority must be consumed or deliberately discarded"]
pub struct PolicyCompilerColdObservationV1 {
    inner: RawPolicyCompilerPostcommitCapabilityV1,
    prerequisites: PolicyPublicationPrerequisitesV1,
}

/// Borrows fresh effect authority only while prerequisite currentness is held.
#[must_use = "the policy effect handoff must be used inside its guarded callback"]
pub struct PolicyCompilerEffectHandoffV1<'handoff> {
    transaction_digest: ObjectDigest,
    marker: PhantomData<&'handoff mut ()>,
}

/// Reports policy verification, framing, currentness, or durability failures.
#[derive(Debug, thiserror::Error)]
pub enum PolicyCompilerJournalErrorV1 {
    /// A verifier rejected the exact candidate and prerequisite tuple.
    #[error("compiled policy candidate lacks authenticated publication authority")]
    UnauthenticatedCandidate,
    /// A digest, identity, generation, descriptor, or current head is invalid.
    #[error("compiled policy publication is noncanonical")]
    NonCanonicalPublication,
    /// Canonical compiler serialization failed.
    #[error(transparent)]
    Model(#[from] PolicyModelError),
    /// Protected currentness, CAS, replay, or durability failed.
    #[error(transparent)]
    Journal(#[from] ProtectedDomainJournalErrorV1),
}

/// Binds external ancestry, authority, cache, and revocation currentness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyPublicationPrerequisitesV1 {
    ancestry_head: ObjectDigest,
    compiler_authority_head: ObjectDigest,
    cache_domain_head: ObjectDigest,
    revocation_head: ObjectDigest,
    generation: u64,
    digest: ObjectDigest,
}

impl PolicyPublicationPrerequisitesV1 {
    /// Constructs an exact protected-current prerequisite tuple.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1::NonCanonicalPublication`] for a
    /// sentinel digest or generation.
    pub fn new(
        ancestry_head: ObjectDigest,
        compiler_authority_head: ObjectDigest,
        cache_domain_head: ObjectDigest,
        revocation_head: ObjectDigest,
        generation: u64,
    ) -> Result<Self, PolicyCompilerJournalErrorV1> {
        if generation == 0
            || [
                ancestry_head,
                compiler_authority_head,
                cache_domain_head,
                revocation_head,
            ]
            .iter()
            .any(|digest| digest.as_bytes() == &[0; 32])
        {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        let mut value = Self {
            ancestry_head,
            compiler_authority_head,
            cache_domain_head,
            revocation_head,
            generation,
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        value.digest = prerequisite_digest(&value);
        Ok(value)
    }

    /// Returns the complete prerequisite tuple commitment.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    /// Returns the exact protected hierarchy/ancestry head.
    #[must_use]
    pub const fn ancestry_head(&self) -> ObjectDigest {
        self.ancestry_head
    }

    /// Returns the exact compiler-authority head.
    #[must_use]
    pub const fn compiler_authority_head(&self) -> ObjectDigest {
        self.compiler_authority_head
    }

    /// Returns the exact cache-domain authority head.
    #[must_use]
    pub const fn cache_domain_head(&self) -> ObjectDigest {
        self.cache_domain_head
    }

    /// Returns the exact revocation head.
    #[must_use]
    pub const fn revocation_head(&self) -> ObjectDigest {
        self.revocation_head
    }

    /// Returns the protected prerequisite generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// Authenticates a candidate against exact current protected prerequisites.
pub(crate) trait PolicyPublicationVerifierV1 {
    /// Authenticates one durable prerequisite tuple independently of currentness.
    fn prerequisite_evidence_is_authentic(
        &self,
        prerequisites: &PolicyPublicationPrerequisitesV1,
    ) -> bool;

    /// Reports whether all four protected prerequisite heads remain current.
    fn prerequisites_are_current(&self, prerequisites: &PolicyPublicationPrerequisitesV1) -> bool;

    /// Runs one journal action while holding exact prerequisite currentness.
    ///
    /// Implementations must prevent every protected prerequisite head from
    /// changing until `action` returns. Returning `None` denies the action.
    fn while_prerequisites_current<T>(
        &self,
        prerequisites: &PolicyPublicationPrerequisitesV1,
        action: impl FnOnce() -> T,
    ) -> Option<T>;

    /// Runs one settlement action while its exact protected observation remains current.
    fn while_effect_observation_current<T>(
        &self,
        prerequisites: &PolicyPublicationPrerequisitesV1,
        request: &PolicyEffectObservationRequestV1,
        action: impl FnOnce(VerifiedPolicyEffectObservationV1) -> T,
    ) -> Option<T>;

    /// Verifies the exact target, normalized input, candidate, and prerequisite tuple.
    fn verify(
        &self,
        project: ProjectId,
        sandbox: SandboxId,
        normalized_input: ObjectDigest,
        candidate: ObjectDigest,
        prerequisites: &PolicyPublicationPrerequisitesV1,
    ) -> bool;
}

/// Describes the complete effect result that protected authority must attest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PolicyEffectObservationRequestV1 {
    project: ProjectId,
    sandbox: SandboxId,
    effect_transaction_id: [u8; 16],
    settlement_transaction_id: [u8; 16],
    effect_predecessor: ObjectDigest,
    outputs: ObjectDigest,
    generation: u64,
    result: ObjectDigest,
    prerequisites: ObjectDigest,
}

impl PolicyEffectObservationRequestV1 {
    pub(crate) const fn project(&self) -> ProjectId {
        self.project
    }

    pub(crate) const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    pub(crate) const fn effect_transaction_id(&self) -> [u8; 16] {
        self.effect_transaction_id
    }

    pub(crate) const fn settlement_transaction_id(&self) -> [u8; 16] {
        self.settlement_transaction_id
    }

    pub(crate) const fn effect_predecessor(&self) -> ObjectDigest {
        self.effect_predecessor
    }

    pub(crate) const fn outputs(&self) -> ObjectDigest {
        self.outputs
    }

    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) const fn result(&self) -> ObjectDigest {
        self.result
    }

    pub(crate) const fn prerequisites(&self) -> ObjectDigest {
        self.prerequisites
    }
}

/// Carries one effect result minted from an exact protected observation record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedPolicyEffectObservationV1 {
    request: PolicyEffectObservationRequestV1,
}

impl VerifiedPolicyEffectObservationV1 {
    pub(crate) fn from_protected_authority(request: PolicyEffectObservationRequestV1) -> Self {
        Self { request }
    }

    fn request(&self) -> &PolicyEffectObservationRequestV1 {
        &self.request
    }

    fn result(&self) -> ObjectDigest {
        self.request.result
    }
}

/// Carries a candidate branded for one exact publication attempt.
#[must_use = "verified policy publication authority must be consumed by the journal adapter"]
pub(crate) struct VerifiedPolicyPublicationV1 {
    project: ProjectId,
    sandbox: SandboxId,
    normalized_input: ObjectDigest,
    candidate: CompiledPolicyCandidateV1,
    diagnostics: Vec<u8>,
    prerequisites: PolicyPublicationPrerequisitesV1,
}

impl VerifiedPolicyPublicationV1 {
    /// Authenticates the exact compiler output and complete diagnostic record.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1`] when normalization fails,
    /// identities are sentinel, or protected verification rejects currentness.
    pub(crate) fn authenticate(
        input: &PolicyCompilerInputV1,
        candidate: CompiledPolicyCandidateV1,
        prerequisites: PolicyPublicationPrerequisitesV1,
        verifier: &impl PolicyPublicationVerifierV1,
    ) -> Result<Self, PolicyCompilerJournalErrorV1> {
        let project = input.project().project();
        let sandbox = input.sandbox();
        let normalized_input = normalized_policy_input_digest_v1(input)?;
        let candidate_digest = candidate.commitment().digest();
        let diagnostics =
            super::model::canonical_bytes(DIAGNOSTICS_DOMAIN, candidate.explanation())?;
        if project.as_bytes() == &[0; 16]
            || sandbox.as_bytes() == &[0; 16]
            || candidate.authority_status() != CandidateAuthorityV1::NonAuthoritativeAncestry
            || candidate_digest.as_bytes() == &[0; 32]
            || diagnostics.is_empty()
            || !verifier.prerequisite_evidence_is_authentic(&prerequisites)
            || !verifier.prerequisites_are_current(&prerequisites)
            || !verifier.verify(
                project,
                sandbox,
                normalized_input,
                candidate_digest,
                &prerequisites,
            )
        {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        Ok(Self {
            project,
            sandbox,
            normalized_input,
            candidate,
            diagnostics,
            prerequisites,
        })
    }
}

/// Holds one exact policy publication before durable mutation.
#[must_use = "a prepared policy publication must be committed or deliberately discarded"]
pub struct PreparedPolicyPublicationV1 {
    inner: PreparedDomainTransactionV1<PolicyCompilerJournalSchemaV1>,
    prerequisites: PolicyPublicationPrerequisitesV1,
}

/// Retains an exact policy publication after ambiguous durability.
#[must_use = "an ambiguous policy publication must be resolved after protected reopen"]
pub struct PolicyPublicationOutcomeUnknownV1 {
    inner: DomainOutcomeUnknownV1<PolicyCompilerJournalSchemaV1>,
    prerequisites: PolicyPublicationPrerequisitesV1,
}

/// Holds one durable cold-effect observation successor.
#[must_use = "a prepared policy observation must be committed or discarded"]
pub struct PreparedPolicyEffectObservationV1 {
    inner: PreparedDomainTransactionV1<PolicyCompilerJournalSchemaV1>,
    prerequisites: PolicyPublicationPrerequisitesV1,
    observation: VerifiedPolicyEffectObservationV1,
}

/// Retains one ambiguous cold-effect observation without recreating authority.
#[must_use = "an ambiguous policy observation must be recovered"]
pub struct PolicyEffectObservationOutcomeUnknownV1 {
    inner: DomainOutcomeUnknownV1<PolicyCompilerJournalSchemaV1>,
    prerequisites: PolicyPublicationPrerequisitesV1,
    observation: VerifiedPolicyEffectObservationV1,
}

/// Holds one exact policy checkpoint before durable mutation.
#[must_use = "a prepared policy checkpoint must be committed or discarded"]
pub struct PreparedPolicyCheckpointV1 {
    inner: PreparedDomainTransactionV1<PolicyCompilerJournalSchemaV1>,
}

/// Retains one exact policy checkpoint whose classification is incomplete.
#[must_use = "an ambiguous policy checkpoint must be recovered"]
pub struct PolicyCheckpointOutcomeUnknownV1 {
    inner: PolicyCheckpointOutcomeUnknownStateV1,
}

enum PolicyCheckpointOutcomeUnknownStateV1 {
    Commit(DomainOutcomeUnknownV1<PolicyCompilerJournalSchemaV1>),
    PostcommitValidation(AppliedDomainTransactionV1<PolicyCompilerJournalSchemaV1>),
}

/// Classifies durable policy-checkpoint commit without publication authority.
#[must_use = "an ambiguous checkpoint outcome must be recovered"]
pub enum PolicyCheckpointCommitOutcomeV1 {
    /// The exact checkpoint is durable and full replay accepted it.
    Applied,
    /// Append or synchronization has an unknown durable outcome.
    OutcomeUnknown {
        /// Retains the exact checkpoint transaction for recovery.
        pending: PolicyCheckpointOutcomeUnknownV1,
        /// Reports the underlying durability failure.
        cause: JournalError,
    },
    /// Readback succeeded but full policy replay could not classify it.
    ValidationUnknown {
        /// Retains the exact applied checkpoint until replay succeeds.
        pending: PolicyCheckpointOutcomeUnknownV1,
        /// Reports the fail-closed replay failure.
        cause: PolicyCompilerJournalErrorV1,
    },
}

/// Classifies recovery of one exact policy checkpoint.
#[must_use = "checkpoint recovery must be applied, retried, or retained"]
pub enum PolicyCheckpointRecoveryV1 {
    /// The exact checkpoint is durable and full replay accepted it.
    Applied,
    /// Every predecessor is exact and the same checkpoint may be retried.
    Retry(PreparedPolicyCheckpointV1),
    /// Durable state differs from both the predecessor and successor.
    Diverged(PolicyCheckpointOutcomeUnknownV1),
    /// Full replay could not yet classify the exact retained state.
    Indeterminate {
        /// Retains the exact checkpoint for another protected recovery pass.
        pending: PolicyCheckpointOutcomeUnknownV1,
        /// Reports the fail-closed replay failure.
        cause: PolicyCompilerJournalErrorV1,
    },
}

/// Classifies durable observation settlement without effect authority.
#[must_use = "an ambiguous observation outcome must be recovered"]
pub enum PolicyEffectObservationCommitOutcomeV1 {
    /// The observed successor is durable and suppresses future cold handoff.
    Applied,
    /// Durability is unknown and exact recovery state is retained.
    OutcomeUnknown {
        /// Exact observation transaction requiring recovery.
        pending: PolicyEffectObservationOutcomeUnknownV1,
        /// Underlying durability error.
        cause: JournalError,
    },
}

/// Classifies recovery of one exact observation settlement.
#[must_use = "policy observation recovery must be applied, retried, or rejected"]
pub enum PolicyEffectObservationRecoveryV1 {
    /// The observed successor is durable.
    Applied,
    /// Every predecessor remains exact and the same retry is retained.
    Retry(PreparedPolicyEffectObservationV1),
    /// Durable state diverged from both predecessor and successor.
    Diverged(PolicyEffectObservationOutcomeUnknownV1),
}

/// Releases policy publication and effect authority after exact readback.
#[must_use = "policy postcommit authority must be consumed or deliberately discarded"]
pub struct AppliedPolicyPublicationV1 {
    inner: AppliedDomainTransactionV1<PolicyCompilerJournalSchemaV1>,
    prerequisites: Option<PolicyPublicationPrerequisitesV1>,
}

impl AppliedPolicyPublicationV1 {
    /// Takes composite authority for exact current revalidation.
    #[must_use]
    pub fn take_postcommit(&mut self) -> Option<PolicyCompilerPostcommitCapabilityV1> {
        Some(PolicyCompilerPostcommitCapabilityV1 {
            inner: self.inner.take_postcommit()?,
            prerequisites: self.prerequisites.take()?,
        })
    }
}

/// Distinguishes exact policy commit success from mandatory reopen recovery.
#[must_use = "ambiguous policy commits retain mandatory recovery state"]
pub enum PolicyPublicationCommitOutcomeV1 {
    /// Every output, diagnostic, effect, and head record is durable and exact.
    Applied(AppliedPolicyPublicationV1),
    /// Durable outcome is unknown and no authority may escape.
    OutcomeUnknown {
        /// Retains the complete exact publication transaction.
        pending: PolicyPublicationOutcomeUnknownV1,
        /// Reports the underlying durability failure.
        cause: JournalError,
    },
}

/// Classifies protected recovery of one exact policy publication.
#[must_use = "policy recovery must be applied, retried, or quarantined"]
pub enum PolicyPublicationRecoveryV1 {
    /// Every exact successor was found after reopen.
    Applied(AppliedPolicyPublicationV1),
    /// Every exact predecessor was found; only the retained retry is legal.
    Retry(PreparedPolicyPublicationV1),
    /// Mixed or substituted state denies authority.
    Diverged(PolicyPublicationOutcomeUnknownV1),
}

/// Classifies a complete policy transaction reconstructed after cold reopen.
#[must_use = "pending policy effects permit observation only"]
pub enum PolicyPublicationColdRecoveryV1 {
    /// No current effect or publication authority exists for the transaction.
    StateOnly,
    /// An installation effect is retained only for external observation.
    ObservePending(PolicyCompilerColdObservationV1),
    /// A terminal publication may be revalidated as one exact transaction.
    Terminal(PolicyCompilerColdObservationV1),
}

/// Owns dormant policy compilation and publication durability.
pub struct PolicyCompilerProtectedJournalV1<'journal> {
    inner: ProtectedDomainJournalV1<'journal, PolicyCompilerJournalSchemaV1>,
    validator: PolicyCompilerReplayValidatorV1,
}

impl<'journal> PolicyCompilerProtectedJournalV1<'journal> {
    /// Claims the adapter over a protected-open journal.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1`] unless protected provenance and
    /// a healthy replay boundary are available.
    pub(crate) fn claim(
        journal: &'journal mut Journal,
        validator: PolicyCompilerReplayValidatorV1,
    ) -> Result<Self, PolicyCompilerJournalErrorV1> {
        Ok(Self {
            inner: ProtectedDomainJournalV1::claim_with_validator(journal, validator.clone())?,
            validator,
        })
    }

    /// Replays and validates every retained policy head and artifact join.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1`] for malformed or substituted
    /// current-head state.
    pub fn replay(
        &self,
    ) -> Result<PolicyCompilerJournalProjectionV1, PolicyCompilerJournalErrorV1> {
        let projection = self.inner.replay()?;
        validate_policy_projection(&projection, &self.validator)?;
        Ok(projection)
    }

    /// Captures exact policy-publication currentness.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1`] when replay fails.
    pub fn snapshot(
        &self,
    ) -> Result<PolicyCompilerJournalSnapshotV1, PolicyCompilerJournalErrorV1> {
        self.replay()?;
        Ok(self.inner.snapshot()?)
    }

    /// Plans one complete immediate-successor policy publication.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1`] for candidate reuse, skipped
    /// generation, stale CAS, malformed outputs, or failed journal preflight.
    pub(crate) fn plan_publication(
        &self,
        transaction_id: [u8; 16],
        generation: u64,
        verified: VerifiedPolicyPublicationV1,
    ) -> Result<PreparedPolicyPublicationV1, PolicyCompilerJournalErrorV1> {
        if generation == 0 || transaction_id == [0; 16] {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        let projection = self.replay()?;
        let current = current_policy_head(
            &projection,
            verified.project,
            verified.sandbox,
            &self.validator,
        )?;
        let expected_generation = current
            .as_ref()
            .map_or(Some(1), |head| head.generation.checked_add(1))
            .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        if generation != expected_generation {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }

        let candidate_digest = verified.candidate.commitment().digest();
        let candidate_key = policy_key(
            PolicyCompilerJournalRecordKindV1::Candidate,
            verified.project,
            verified.sandbox,
            candidate_digest,
        )?;
        let diagnostic_key = policy_key(
            PolicyCompilerJournalRecordKindV1::Diagnostics,
            verified.project,
            verified.sandbox,
            candidate_digest,
        )?;
        if projection
            .records()
            .iter()
            .any(|record| record.key() == &candidate_key || record.key() == &diagnostic_key)
        {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }

        let diagnostics_payload = encode_diagnostics_payload(
            verified.project,
            verified.sandbox,
            candidate_digest,
            &verified.diagnostics,
        )?;
        let diagnostics_digest = digest_bytes(DIAGNOSTICS_DOMAIN, &diagnostics_payload);
        let candidate_payload =
            encode_candidate_payload(generation, &verified, diagnostics_digest)?;
        let effect_payload =
            encode_effect_payload(transaction_id, generation, &verified, diagnostics_digest)?;
        let mut successors = vec![
            policy_reducer_envelope(candidate_key, 1, None, &candidate_payload, &self.validator)?,
            policy_reducer_envelope(
                diagnostic_key,
                1,
                None,
                &diagnostics_payload,
                &self.validator,
            )?,
        ];
        successors.push(policy_reducer_envelope(
            policy_effect_key(verified.project, verified.sandbox, transaction_id)?,
            1,
            None,
            &effect_payload,
            &self.validator,
        )?);
        let (revision, predecessor) = match current.as_ref() {
            Some(head) => (
                head.envelope_revision
                    .checked_add(1)
                    .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
                Some(head.envelope_digest),
            ),
            None => (1, None),
        };
        successors.push(policy_reducer_envelope(
            policy_current_key(verified.project, verified.sandbox)?,
            revision,
            predecessor,
            &encode_current_payload(
                verified.project,
                verified.sandbox,
                generation,
                candidate_digest,
                verified.normalized_input,
                diagnostics_digest,
                &verified.prerequisites,
            ),
            &self.validator,
        )?);
        let inner = self.inner.plan(transaction_id, successors)?;
        Ok(PreparedPolicyPublicationV1 {
            inner,
            prerequisites: verified.prerequisites,
        })
    }

    /// Commits one policy publication and performs exact readback.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1`] for stale authority or an
    /// invalid protected-journal operation.
    pub(crate) fn commit(
        &mut self,
        prepared: PreparedPolicyPublicationV1,
        verifier: &impl PolicyPublicationVerifierV1,
    ) -> Result<PolicyPublicationCommitOutcomeV1, PolicyCompilerJournalErrorV1> {
        let prerequisites = prepared.prerequisites;
        let outcome = verifier
            .while_prerequisites_current(&prerequisites, || self.inner.commit(prepared.inner))
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)??;
        match outcome {
            DomainCommitOutcomeV1::Applied(inner) => Ok(PolicyPublicationCommitOutcomeV1::Applied(
                AppliedPolicyPublicationV1 {
                    inner,
                    prerequisites: Some(prerequisites),
                },
            )),
            DomainCommitOutcomeV1::OutcomeUnknown { pending, cause } => {
                Ok(PolicyPublicationCommitOutcomeV1::OutcomeUnknown {
                    pending: PolicyPublicationOutcomeUnknownV1 {
                        inner: pending,
                        prerequisites,
                    },
                    cause,
                })
            }
        }
    }

    /// Resolves one ambiguous policy publication after protected reopen.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1`] when replay is malformed.
    pub(crate) fn recover(
        &self,
        pending: PolicyPublicationOutcomeUnknownV1,
        verifier: &impl PolicyPublicationVerifierV1,
    ) -> Result<PolicyPublicationRecoveryV1, PolicyCompilerJournalErrorV1> {
        self.replay()?;
        let prerequisites = pending.prerequisites;
        let recovery = verifier
            .while_prerequisites_current(&prerequisites, || self.inner.recover(pending.inner))
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)??;
        match recovery {
            DomainRecoveryV1::Applied(inner) => Ok(PolicyPublicationRecoveryV1::Applied(
                AppliedPolicyPublicationV1 {
                    inner,
                    prerequisites: Some(prerequisites),
                },
            )),
            DomainRecoveryV1::Retry(inner) => Ok(PolicyPublicationRecoveryV1::Retry(
                PreparedPolicyPublicationV1 {
                    inner,
                    prerequisites,
                },
            )),
            DomainRecoveryV1::Diverged(inner) => Ok(PolicyPublicationRecoveryV1::Diverged(
                PolicyPublicationOutcomeUnknownV1 {
                    inner,
                    prerequisites,
                },
            )),
        }
    }

    /// Reconstructs one complete policy transaction after cold reopen.
    ///
    /// Pending installation records authorize observation only until their
    /// composite capability passes exact current readback.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1`] when semantic replay or durable
    /// transaction grouping fails closed.
    pub fn recover_current_transaction(
        &self,
        transaction_id: [u8; 16],
    ) -> Result<PolicyPublicationColdRecoveryV1, PolicyCompilerJournalErrorV1> {
        let projection = self.replay()?;
        let prerequisites = projection
            .transactions()
            .iter()
            .find(|transaction| transaction.transaction_id() == transaction_id)
            .map(|transaction| transaction_prerequisites(transaction.records(), &self.validator))
            .transpose()?
            .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        Ok(
            match self.inner.recover_current_postcommit(transaction_id)? {
                Some(ReplayedDomainPostcommitV1::Prepared(capability)) => {
                    PolicyPublicationColdRecoveryV1::ObservePending(
                        PolicyCompilerColdObservationV1 {
                            inner: capability,
                            prerequisites: prerequisites.clone(),
                        },
                    )
                }
                Some(ReplayedDomainPostcommitV1::Terminal(capability)) => {
                    PolicyPublicationColdRecoveryV1::Terminal(PolicyCompilerColdObservationV1 {
                        inner: capability,
                        prerequisites,
                    })
                }
                None => PolicyPublicationColdRecoveryV1::StateOnly,
            },
        )
    }

    /// Plans one durable observed successor for a cold pending effect.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1`] unless the cold transaction,
    /// prerequisite heads, effect predecessor, and observation are exact.
    pub(crate) fn plan_cold_observation(
        &self,
        transaction_id: [u8; 16],
        cold: PolicyCompilerColdObservationV1,
        observation: ObjectDigest,
        verifier: &impl PolicyPublicationVerifierV1,
    ) -> Result<PreparedPolicyEffectObservationV1, PolicyCompilerJournalErrorV1> {
        let prerequisites = cold.prerequisites;
        let validated = cold.inner.consume(&self.inner)?;
        let retained = validated_postcommit_prerequisites(&validated, &self.validator)?;
        if retained != prerequisites {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        let effect = validated
            .records()
            .iter()
            .find(|record| {
                record.envelope().key().kind() == PolicyCompilerJournalRecordKindV1::Effect
            })
            .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?
            .envelope();
        if effect.key().identity().get(32..48) == Some(transaction_id.as_slice()) {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        let key = effect.key().clone();
        let revision = effect
            .revision()
            .checked_add(1)
            .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        let predecessor = Some(effect.digest());
        let effect_body = policy_body(effect, &self.validator)?.to_vec();
        let request = policy_effect_observation_request(
            effect,
            &effect_body,
            transaction_id,
            observation,
            prerequisites.digest(),
        )?;
        drop(validated);

        verifier
            .while_effect_observation_current(&prerequisites, &request, |verified| {
                let body = encode_observed_effect_payload(&effect_body, verified.result())?;
                let envelope =
                    policy_reducer_envelope(key, revision, predecessor, &body, &self.validator)?;
                Ok(PreparedPolicyEffectObservationV1 {
                    inner: self.inner.plan(transaction_id, vec![envelope])?,
                    prerequisites: prerequisites.clone(),
                    observation: verified,
                })
            })
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?
    }

    /// Commits one observation successor without minting effect authority.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1`] when prerequisite currentness,
    /// CAS, durability, or exact readback fails.
    pub(crate) fn commit_observation(
        &mut self,
        prepared: PreparedPolicyEffectObservationV1,
        verifier: &impl PolicyPublicationVerifierV1,
    ) -> Result<PolicyEffectObservationCommitOutcomeV1, PolicyCompilerJournalErrorV1> {
        let prerequisites = prepared.prerequisites;
        let observation = prepared.observation;
        let request = observation.request().clone();
        let outcome = verifier
            .while_effect_observation_current(&prerequisites, &request, |current| {
                if current != observation {
                    return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
                }
                self.inner.commit(prepared.inner).map_err(Into::into)
            })
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)??;
        Ok(match outcome {
            DomainCommitOutcomeV1::Applied(_) => {
                self.replay()?;
                PolicyEffectObservationCommitOutcomeV1::Applied
            }
            DomainCommitOutcomeV1::OutcomeUnknown { pending, cause } => {
                PolicyEffectObservationCommitOutcomeV1::OutcomeUnknown {
                    pending: PolicyEffectObservationOutcomeUnknownV1 {
                        inner: pending,
                        prerequisites,
                        observation,
                    },
                    cause,
                }
            }
        })
    }

    /// Recovers one ambiguous observation successor without minting authority.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1`] for unauthenticated currentness
    /// or malformed durable recovery state.
    pub(crate) fn recover_observation(
        &self,
        pending: PolicyEffectObservationOutcomeUnknownV1,
        verifier: &impl PolicyPublicationVerifierV1,
    ) -> Result<PolicyEffectObservationRecoveryV1, PolicyCompilerJournalErrorV1> {
        let prerequisites = pending.prerequisites;
        let observation = pending.observation;
        let request = observation.request().clone();
        let recovery = verifier
            .while_effect_observation_current(&prerequisites, &request, |current| {
                if current != observation {
                    return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
                }
                self.inner.recover(pending.inner).map_err(Into::into)
            })
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)??;
        Ok(match recovery {
            DomainRecoveryV1::Applied(_) => {
                self.replay()?;
                PolicyEffectObservationRecoveryV1::Applied
            }
            DomainRecoveryV1::Retry(inner) => {
                self.replay()?;
                PolicyEffectObservationRecoveryV1::Retry(PreparedPolicyEffectObservationV1 {
                    inner,
                    prerequisites,
                    observation,
                })
            }
            DomainRecoveryV1::Diverged(inner) => PolicyEffectObservationRecoveryV1::Diverged(
                PolicyEffectObservationOutcomeUnknownV1 {
                    inner,
                    prerequisites,
                    observation,
                },
            ),
        })
    }

    /// Plans an immutable replay join without granting compaction authority.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1`] for a sentinel checkpoint,
    /// stale projection, or failed preflight.
    pub fn plan_checkpoint(
        &self,
        transaction_id: [u8; 16],
        checkpoint: ObjectDigest,
    ) -> Result<PreparedPolicyCheckpointV1, PolicyCompilerJournalErrorV1> {
        if checkpoint.as_bytes() == &[0; 32] {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        self.replay()?;
        let key = PolicyCompilerJournalKeyV1::new(
            PolicyCompilerJournalRecordKindV1::Checkpoint,
            checkpoint.as_bytes().to_vec(),
        )?;
        let envelope = self.inner.checkpoint_successor(key, 1, None)?;
        Ok(PreparedPolicyCheckpointV1 {
            inner: self.inner.plan(transaction_id, vec![envelope])?,
        })
    }

    /// Commits one checkpoint without minting publication or effect authority.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1`] when precommit replay, CAS, or
    /// protected-journal preflight fails before durable mutation.
    pub fn commit_checkpoint(
        &mut self,
        prepared: PreparedPolicyCheckpointV1,
    ) -> Result<PolicyCheckpointCommitOutcomeV1, PolicyCompilerJournalErrorV1> {
        self.replay()?;
        Ok(match self.inner.commit(prepared.inner)? {
            DomainCommitOutcomeV1::Applied(inner) => {
                if let Err(cause) = self.replay() {
                    PolicyCheckpointCommitOutcomeV1::ValidationUnknown {
                        pending: PolicyCheckpointOutcomeUnknownV1 {
                            inner: PolicyCheckpointOutcomeUnknownStateV1::PostcommitValidation(
                                inner,
                            ),
                        },
                        cause,
                    }
                } else {
                    PolicyCheckpointCommitOutcomeV1::Applied
                }
            }
            DomainCommitOutcomeV1::OutcomeUnknown { pending, cause } => {
                PolicyCheckpointCommitOutcomeV1::OutcomeUnknown {
                    pending: PolicyCheckpointOutcomeUnknownV1 {
                        inner: PolicyCheckpointOutcomeUnknownStateV1::Commit(pending),
                    },
                    cause,
                }
            }
        })
    }

    /// Recovers one exact ambiguous checkpoint after full protected replay.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1`] if generic protected recovery
    /// cannot decode or authenticate its exact retained transaction.
    pub fn recover_checkpoint(
        &self,
        pending: PolicyCheckpointOutcomeUnknownV1,
    ) -> Result<PolicyCheckpointRecoveryV1, PolicyCompilerJournalErrorV1> {
        if let Err(cause) = self.replay() {
            return Ok(PolicyCheckpointRecoveryV1::Indeterminate { pending, cause });
        }
        let inner = match pending.inner {
            PolicyCheckpointOutcomeUnknownStateV1::PostcommitValidation(applied) => {
                let _transaction_digest = applied.transaction_digest();
                return Ok(PolicyCheckpointRecoveryV1::Applied);
            }
            PolicyCheckpointOutcomeUnknownStateV1::Commit(inner) => inner,
        };
        Ok(match self.inner.recover(inner)? {
            DomainRecoveryV1::Applied(applied) => {
                if let Err(cause) = self.replay() {
                    PolicyCheckpointRecoveryV1::Indeterminate {
                        pending: PolicyCheckpointOutcomeUnknownV1 {
                            inner: PolicyCheckpointOutcomeUnknownStateV1::PostcommitValidation(
                                applied,
                            ),
                        },
                        cause,
                    }
                } else {
                    PolicyCheckpointRecoveryV1::Applied
                }
            }
            DomainRecoveryV1::Retry(inner) => {
                PolicyCheckpointRecoveryV1::Retry(PreparedPolicyCheckpointV1 { inner })
            }
            DomainRecoveryV1::Diverged(inner) => {
                PolicyCheckpointRecoveryV1::Diverged(PolicyCheckpointOutcomeUnknownV1 {
                    inner: PolicyCheckpointOutcomeUnknownStateV1::Commit(inner),
                })
            }
        })
    }
}

impl PolicyCompilerPostcommitCapabilityV1 {
    /// Consumes one policy transaction after revalidating all prerequisite heads.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1`] when any prerequisite changed,
    /// the journal advanced, or the exact transaction bodies disagree.
    pub(crate) fn consume_with<R>(
        self,
        authority: &PolicyCompilerProtectedJournalV1<'_>,
        verifier: &impl PolicyPublicationVerifierV1,
        handoff: impl for<'guard> FnOnce(PolicyCompilerEffectHandoffV1<'guard>) -> R,
    ) -> Result<R, PolicyCompilerJournalErrorV1> {
        verifier
            .while_prerequisites_current(&self.prerequisites, || {
                let validated = self.inner.consume(&authority.inner)?;
                let retained =
                    validated_postcommit_prerequisites(&validated, &authority.validator)?;
                if retained != self.prerequisites {
                    return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
                }
                Ok::<_, PolicyCompilerJournalErrorV1>(handoff(PolicyCompilerEffectHandoffV1 {
                    transaction_digest: validated.transaction_digest(),
                    marker: PhantomData,
                }))
            })
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?
    }
}

impl PolicyCompilerColdObservationV1 {
    /// Consumes cold terminal authority while protected prerequisites are held.
    ///
    /// # Errors
    ///
    /// Returns an error when prerequisites, replay, or transaction currentness
    /// changed after cold recovery.
    pub(crate) fn consume_with<R>(
        self,
        authority: &PolicyCompilerProtectedJournalV1<'_>,
        verifier: &impl PolicyPublicationVerifierV1,
        handoff: impl for<'guard> FnOnce(PolicyCompilerEffectHandoffV1<'guard>) -> R,
    ) -> Result<R, PolicyCompilerJournalErrorV1> {
        verifier
            .while_prerequisites_current(&self.prerequisites, || {
                let validated = self.inner.consume(&authority.inner)?;
                let retained =
                    validated_postcommit_prerequisites(&validated, &authority.validator)?;
                if retained != self.prerequisites {
                    return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
                }
                Ok::<_, PolicyCompilerJournalErrorV1>(handoff(PolicyCompilerEffectHandoffV1 {
                    transaction_digest: validated.transaction_digest(),
                    marker: PhantomData,
                }))
            })
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?
    }
}

impl PolicyCompilerEffectHandoffV1<'_> {
    /// Returns the exact durable publication transaction commitment.
    #[must_use]
    pub const fn transaction_digest(&self) -> ObjectDigest {
        self.transaction_digest
    }
}

fn transaction_prerequisites(
    records: &[PolicyCompilerJournalEnvelopeV1],
    validator: &PolicyCompilerReplayValidatorV1,
) -> Result<PolicyPublicationPrerequisitesV1, PolicyCompilerJournalErrorV1> {
    let mut retained = None;
    for envelope in records {
        let candidate = match envelope.key().kind() {
            PolicyCompilerJournalRecordKindV1::Candidate => Some(
                validate_candidate_payload(policy_body(envelope, validator)?)?.prerequisite_tuple,
            ),
            PolicyCompilerJournalRecordKindV1::Effect => {
                Some(decode_effect_header(policy_body(envelope, validator)?)?.prerequisite_tuple)
            }
            PolicyCompilerJournalRecordKindV1::Current => {
                Some(decode_current_payload(policy_body(envelope, validator)?)?.prerequisite_tuple)
            }
            _ => None,
        };
        if let Some(candidate) = candidate {
            if retained.as_ref().is_some_and(|value| value != &candidate) {
                return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
            }
            retained = Some(candidate);
        }
    }
    retained.ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)
}

fn validated_postcommit_prerequisites(
    validated: &ValidatedDomainPostcommitV1<'_, PolicyCompilerJournalSchemaV1>,
    validator: &PolicyCompilerReplayValidatorV1,
) -> Result<PolicyPublicationPrerequisitesV1, PolicyCompilerJournalErrorV1> {
    let mut retained = None;
    for record in validated.records() {
        let envelope = record.envelope();
        let candidate = match envelope.key().kind() {
            PolicyCompilerJournalRecordKindV1::Candidate => Some(
                validate_candidate_payload(policy_body(envelope, validator)?)?.prerequisite_tuple,
            ),
            PolicyCompilerJournalRecordKindV1::Effect => {
                Some(decode_effect_header(policy_body(envelope, validator)?)?.prerequisite_tuple)
            }
            PolicyCompilerJournalRecordKindV1::Current => {
                Some(decode_current_payload(policy_body(envelope, validator)?)?.prerequisite_tuple)
            }
            PolicyCompilerJournalRecordKindV1::Diagnostics
            | PolicyCompilerJournalRecordKindV1::Checkpoint => None,
        };
        if let Some(candidate) = candidate {
            if retained
                .as_ref()
                .is_some_and(|current| current != &candidate)
            {
                return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
            }
            retained = Some(candidate);
        }
    }
    retained.ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)
}

#[derive(Clone, Copy)]
struct CurrentPolicyHeadV1 {
    generation: u64,
    envelope_revision: u64,
    envelope_digest: ObjectDigest,
}

/// Computes the canonical normalized-input digest used by publication checks.
///
/// # Errors
///
/// Returns [`PolicyCompilerJournalErrorV1::NonCanonicalPublication`] if an
/// input descriptor or target identity is sentinel-valued.
pub fn normalized_policy_input_digest_v1(
    input: &PolicyCompilerInputV1,
) -> Result<ObjectDigest, PolicyCompilerJournalErrorV1> {
    if input.sandbox().as_bytes() == &[0; 16] || input.project().project().as_bytes() == &[0; 16] {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let mut hasher = Sha256::new();
    hasher.update(INPUT_DOMAIN);
    hasher.update(input.sandbox().as_bytes());
    hasher.update(input.project().project().as_bytes());
    update_descriptor(&mut hasher, input.relation().descriptor())?;
    update_descriptor(&mut hasher, input.node().descriptor())?;
    update_descriptor(&mut hasher, input.site().descriptor())?;
    update_descriptor(&mut hasher, input.project().descriptor())?;
    for ancestor in input.ancestors() {
        update_descriptor(&mut hasher, ancestor.descriptor())?;
    }
    update_descriptor(&mut hasher, input.request().descriptor())?;
    update_descriptor(&mut hasher, input.endpoints().descriptor())?;
    update_descriptor(&mut hasher, input.destinations().descriptor())?;
    update_descriptor(&mut hasher, input.backend().descriptor())?;
    hasher.update(input.limits().work().to_be_bytes());
    hasher.update(input.limits().dag_depth().to_be_bytes());
    let rule_limit = u64::try_from(input.limits().rules())
        .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    hasher.update(rule_limit.to_be_bytes());
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}

fn validate_policy_projection(
    projection: &PolicyCompilerJournalProjectionV1,
    validator: &PolicyCompilerReplayValidatorV1,
) -> Result<(), PolicyCompilerJournalErrorV1> {
    let mut candidate_generations = BTreeMap::<[u8; 32], BTreeSet<u64>>::new();
    let mut current_generations = BTreeMap::<[u8; 32], u64>::new();
    for envelope in projection.records() {
        validate_policy_key(envelope.key())?;
        match envelope.key().kind() {
            PolicyCompilerJournalRecordKindV1::Candidate => {
                let candidate = validate_candidate_payload(policy_body(envelope, validator)?)?;
                let target = envelope.key().identity()[..32]
                    .try_into()
                    .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
                if !candidate_generations
                    .entry(target)
                    .or_default()
                    .insert(candidate.generation)
                {
                    return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
                }
            }
            PolicyCompilerJournalRecordKindV1::Diagnostics => {
                decode_diagnostics_payload(policy_body(envelope, validator)?)?;
            }
            PolicyCompilerJournalRecordKindV1::Effect => {
                let effect = decode_effect_header(policy_body(envelope, validator)?)?;
                let target = &envelope.key().identity()[..32];
                let candidate_key = policy_key_from_identity(
                    PolicyCompilerJournalRecordKindV1::Candidate,
                    target,
                    effect.candidate,
                )?;
                let diagnostics_key = policy_key_from_identity(
                    PolicyCompilerJournalRecordKindV1::Diagnostics,
                    target,
                    effect.candidate,
                )?;
                let candidate = projection
                    .records()
                    .iter()
                    .find(|record| record.key() == &candidate_key)
                    .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
                let diagnostics = projection
                    .records()
                    .iter()
                    .find(|record| record.key() == &diagnostics_key)
                    .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
                let candidate_header =
                    validate_candidate_payload(policy_body(candidate, validator)?)?;
                if candidate_header.generation != effect.generation
                    || candidate_header.candidate != effect.candidate
                    || candidate_header.normalized_input != effect.normalized_input
                    || candidate_header.diagnostics != effect.diagnostics
                    || candidate_header.prerequisites != effect.prerequisites
                    || candidate_header.outputs != effect.outputs
                    || digest_bytes(DIAGNOSTICS_DOMAIN, policy_body(diagnostics, validator)?)
                        != effect.diagnostics
                {
                    return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
                }
            }
            PolicyCompilerJournalRecordKindV1::Current => {
                let current = decode_current_payload(policy_body(envelope, validator)?)?;
                let target = envelope
                    .key()
                    .identity()
                    .try_into()
                    .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
                if current_generations
                    .insert(target, current.generation)
                    .is_some()
                {
                    return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
                }
            }
            PolicyCompilerJournalRecordKindV1::Checkpoint => {}
        }
    }
    if candidate_generations.len() != current_generations.len() {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    for (target, generations) in &candidate_generations {
        let current = current_generations
            .get(target)
            .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        let count = u64::try_from(generations.len())
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        if count != *current
            || generations
                .iter()
                .copied()
                .enumerate()
                .any(|(index, generation)| {
                    u64::try_from(index)
                        .ok()
                        .and_then(|value| value.checked_add(1))
                        != Some(generation)
                })
        {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
    }
    for current in projection
        .records()
        .iter()
        .filter(|record| record.key().kind() == PolicyCompilerJournalRecordKindV1::Current)
    {
        let head = decode_current_payload(policy_body(current, validator)?)?;
        let identity = current.key().identity();
        if identity.len() != 32 || head.generation != current.revision() {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        let candidate_key = policy_key_from_identity(
            PolicyCompilerJournalRecordKindV1::Candidate,
            identity,
            head.candidate,
        )?;
        let diagnostic_key = policy_key_from_identity(
            PolicyCompilerJournalRecordKindV1::Diagnostics,
            identity,
            head.candidate,
        )?;
        let candidate = projection
            .records()
            .iter()
            .find(|record| record.key() == &candidate_key)
            .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        let diagnostics = projection
            .records()
            .iter()
            .find(|record| record.key() == &diagnostic_key)
            .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        let candidate_header = validate_candidate_payload(policy_body(candidate, validator)?)?;
        if candidate.revision() != 1
            || candidate.predecessor().is_some()
            || diagnostics.revision() != 1
            || diagnostics.predecessor().is_some()
            || candidate_header.generation != head.generation
            || digest_bytes(DIAGNOSTICS_DOMAIN, policy_body(diagnostics, validator)?)
                != head.diagnostics
            || candidate_header.candidate != head.candidate
            || candidate_header.normalized_input != head.normalized_input
            || candidate_header.diagnostics != head.diagnostics
            || candidate_header.prerequisites != head.prerequisites
        {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
    }
    for transaction in projection.transactions() {
        validate_policy_transaction(
            transaction.transaction_id(),
            transaction.records(),
            validator,
        )?;
    }
    Ok(())
}

fn validate_policy_transaction(
    transaction_id: [u8; 16],
    records: &[PolicyCompilerJournalEnvelopeV1],
    validator: &PolicyCompilerReplayValidatorV1,
) -> Result<(), PolicyCompilerJournalErrorV1> {
    use PolicyCompilerJournalRecordKindV1 as Kind;
    if records.len() == 1 && records[0].key().kind() == Kind::Checkpoint {
        return Ok(());
    }
    if records.len() == 1 && records[0].key().kind() == Kind::Effect {
        let effect = &records[0];
        let header = decode_effect_header(policy_body(effect, validator)?)?;
        if header.state != PolicyEffectStateV1::Observed || effect.revision() != 2 {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        let mut prepared_body = policy_body(effect, validator)?.to_vec();
        prepared_body[330] = PolicyEffectStateV1::Prepared as u8;
        prepared_body[331..363].fill(0);
        let prepared =
            policy_reducer_envelope(effect.key().clone(), 1, None, &prepared_body, validator)?;
        if effect.predecessor() != Some(prepared.digest()) {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        return Ok(());
    }
    if !matches!(records.len(), 3 | 4) {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let one = |kind| {
        let mut matches = records.iter().filter(|record| record.key().kind() == kind);
        let first = matches.next();
        if matches.next().is_some() {
            None
        } else {
            first
        }
    };
    let candidate =
        one(Kind::Candidate).ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    let diagnostics =
        one(Kind::Diagnostics).ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    let effect = one(Kind::Effect);
    let current = one(Kind::Current);
    if effect.is_none() {
        let current = current.ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        if records.len() != 3 {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        let candidate_header = validate_candidate_payload(policy_body(candidate, validator)?)?;
        let current_header = decode_current_payload(policy_body(current, validator)?)?;
        let target = &candidate.key().identity()[..32];
        if current.key().identity() != target
            || &diagnostics.key().identity()[..32] != target
            || candidate_header.generation != current_header.generation
            || candidate_header.candidate != current_header.candidate
            || candidate_header.normalized_input != current_header.normalized_input
            || candidate_header.diagnostics != current_header.diagnostics
            || candidate_header.prerequisites != current_header.prerequisites
            || candidate_header.prerequisite_tuple != current_header.prerequisite_tuple
            || digest_bytes(DIAGNOSTICS_DOMAIN, policy_body(diagnostics, validator)?)
                != candidate_header.diagnostics
        {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        return Ok(());
    }
    let effect = effect.ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    if (records.len() == 4) != current.is_some() {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let candidate_header = validate_candidate_payload(policy_body(candidate, validator)?)?;
    let effect_header = decode_effect_header(policy_body(effect, validator)?)?;
    let target = &candidate.key().identity()[..32];
    if effect_header.state != PolicyEffectStateV1::Prepared
        || effect.key().identity()[32..] != transaction_id
    {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    if &diagnostics.key().identity()[..32] != target
        || &effect.key().identity()[..32] != target
        || candidate_header.generation != effect_header.generation
        || candidate_header.candidate != effect_header.candidate
        || candidate_header.normalized_input != effect_header.normalized_input
        || candidate_header.diagnostics != effect_header.diagnostics
        || candidate_header.prerequisites != effect_header.prerequisites
        || candidate_header.outputs != effect_header.outputs
        || candidate_header.prerequisite_tuple != effect_header.prerequisite_tuple
        || digest_bytes(DIAGNOSTICS_DOMAIN, policy_body(diagnostics, validator)?)
            != candidate_header.diagnostics
    {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    if let Some(current) = current {
        let current_header = decode_current_payload(policy_body(current, validator)?)?;
        if current.key().identity() != target
            || candidate_header.generation != current_header.generation
            || candidate_header.candidate != current_header.candidate
            || candidate_header.normalized_input != current_header.normalized_input
            || candidate_header.diagnostics != current_header.diagnostics
            || candidate_header.prerequisites != current_header.prerequisites
            || candidate_header.prerequisite_tuple != current_header.prerequisite_tuple
        {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
    }
    Ok(())
}

fn validate_policy_key(
    key: &PolicyCompilerJournalKeyV1,
) -> Result<(), PolicyCompilerJournalErrorV1> {
    let identity = key.identity();
    let expected_length = match key.kind() {
        PolicyCompilerJournalRecordKindV1::Candidate
        | PolicyCompilerJournalRecordKindV1::Diagnostics => 64,
        PolicyCompilerJournalRecordKindV1::Effect => 48,
        PolicyCompilerJournalRecordKindV1::Current => 32,
        PolicyCompilerJournalRecordKindV1::Checkpoint => 32,
    };
    if identity.len() != expected_length {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let invalid_identity = match key.kind() {
        PolicyCompilerJournalRecordKindV1::Candidate
        | PolicyCompilerJournalRecordKindV1::Diagnostics => {
            identity[..16] == [0; 16]
                || identity[16..32] == [0; 16]
                || identity[32..].iter().all(|byte| *byte == 0)
        }
        PolicyCompilerJournalRecordKindV1::Effect => {
            identity[..16] == [0; 16] || identity[16..32] == [0; 16] || identity[32..] == [0; 16]
        }
        PolicyCompilerJournalRecordKindV1::Current => {
            identity[..16] == [0; 16] || identity[16..32] == [0; 16]
        }
        PolicyCompilerJournalRecordKindV1::Checkpoint => identity.iter().all(|byte| *byte == 0),
    };
    if invalid_identity {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    Ok(())
}

struct DecodedCurrentPolicyHeadV1 {
    generation: u64,
    candidate: ObjectDigest,
    normalized_input: ObjectDigest,
    diagnostics: ObjectDigest,
    prerequisites: ObjectDigest,
    prerequisite_tuple: PolicyPublicationPrerequisitesV1,
}

struct DecodedCandidateHeaderV1 {
    generation: u64,
    candidate: ObjectDigest,
    normalized_input: ObjectDigest,
    diagnostics: ObjectDigest,
    prerequisites: ObjectDigest,
    prerequisite_tuple: PolicyPublicationPrerequisitesV1,
    outputs: [(ObjectDigest, u64); 4],
}

struct DecodedEffectHeaderV1 {
    state: PolicyEffectStateV1,
    observation: ObjectDigest,
    generation: u64,
    candidate: ObjectDigest,
    normalized_input: ObjectDigest,
    diagnostics: ObjectDigest,
    prerequisites: ObjectDigest,
    prerequisite_tuple: PolicyPublicationPrerequisitesV1,
    outputs: [(ObjectDigest, u64); 4],
}

fn current_policy_head(
    projection: &PolicyCompilerJournalProjectionV1,
    project: ProjectId,
    sandbox: SandboxId,
    validator: &PolicyCompilerReplayValidatorV1,
) -> Result<Option<CurrentPolicyHeadV1>, PolicyCompilerJournalErrorV1> {
    let key = policy_current_key(project, sandbox)?;
    projection
        .records()
        .iter()
        .find(|record| record.key() == &key)
        .map(|envelope| {
            let decoded = decode_current_payload(policy_body(envelope, validator)?)?;
            if decoded.generation != envelope.revision() {
                return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
            }
            Ok(CurrentPolicyHeadV1 {
                generation: decoded.generation,
                envelope_revision: envelope.revision(),
                envelope_digest: envelope.digest(),
            })
        })
        .transpose()
}

fn policy_key(
    kind: PolicyCompilerJournalRecordKindV1,
    project: ProjectId,
    sandbox: SandboxId,
    subject: ObjectDigest,
) -> Result<PolicyCompilerJournalKeyV1, PolicyCompilerJournalErrorV1> {
    if project.as_bytes() == &[0; 16]
        || sandbox.as_bytes() == &[0; 16]
        || subject.as_bytes() == &[0; 32]
    {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let mut identity = Vec::with_capacity(64);
    identity.extend_from_slice(project.as_bytes());
    identity.extend_from_slice(sandbox.as_bytes());
    identity.extend_from_slice(subject.as_bytes());
    Ok(PolicyCompilerJournalKeyV1::new(kind, identity)?)
}

fn policy_key_from_identity(
    kind: PolicyCompilerJournalRecordKindV1,
    target: &[u8],
    subject: ObjectDigest,
) -> Result<PolicyCompilerJournalKeyV1, PolicyCompilerJournalErrorV1> {
    if target.len() != 32 || subject.as_bytes() == &[0; 32] {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let mut identity = Vec::with_capacity(64);
    identity.extend_from_slice(target);
    identity.extend_from_slice(subject.as_bytes());
    Ok(PolicyCompilerJournalKeyV1::new(kind, identity)?)
}

fn policy_current_key(
    project: ProjectId,
    sandbox: SandboxId,
) -> Result<PolicyCompilerJournalKeyV1, PolicyCompilerJournalErrorV1> {
    if project.as_bytes() == &[0; 16] || sandbox.as_bytes() == &[0; 16] {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let mut identity = Vec::with_capacity(32);
    identity.extend_from_slice(project.as_bytes());
    identity.extend_from_slice(sandbox.as_bytes());
    Ok(PolicyCompilerJournalKeyV1::new(
        PolicyCompilerJournalRecordKindV1::Current,
        identity,
    )?)
}

fn policy_effect_key(
    project: ProjectId,
    sandbox: SandboxId,
    transaction: [u8; 16],
) -> Result<PolicyCompilerJournalKeyV1, PolicyCompilerJournalErrorV1> {
    if transaction == [0; 16] {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let mut identity = Vec::with_capacity(48);
    identity.extend_from_slice(project.as_bytes());
    identity.extend_from_slice(sandbox.as_bytes());
    identity.extend_from_slice(&transaction);
    Ok(PolicyCompilerJournalKeyV1::new(
        PolicyCompilerJournalRecordKindV1::Effect,
        identity,
    )?)
}

fn policy_reducer_envelope(
    key: PolicyCompilerJournalKeyV1,
    revision: u64,
    predecessor: Option<ObjectDigest>,
    canonical_body: &[u8],
    validator: &PolicyCompilerReplayValidatorV1,
) -> Result<PolicyCompilerJournalEnvelopeV1, PolicyCompilerJournalErrorV1> {
    let payload = encode_reducer_payload_with_validator::<PolicyCompilerJournalSchemaV1>(
        &key,
        canonical_body,
        validator,
    )?;
    Ok(PolicyCompilerJournalEnvelopeV1::new_with_validator(
        key,
        revision,
        predecessor,
        payload,
        validator,
    )?)
}

fn policy_body<'body>(
    envelope: &'body PolicyCompilerJournalEnvelopeV1,
    validator: &PolicyCompilerReplayValidatorV1,
) -> Result<&'body [u8], PolicyCompilerJournalErrorV1> {
    Ok(
        decode_reducer_payload_with_validator::<PolicyCompilerJournalSchemaV1>(
            envelope.key(),
            envelope.payload(),
            validator,
        )?
        .body(),
    )
}

fn output_descriptors(
    portable: &super::model::PortablePolicyOutputV1,
) -> [(u8, PortableMediaType, &ObjectDescriptor); 4] {
    [
        (1, PortableMediaType::Policy, portable.policy_descriptor()),
        (
            2,
            PortableMediaType::Optimization,
            portable.optimization_descriptor(),
        ),
        (
            3,
            PortableMediaType::Content,
            portable.namespace_graph_descriptor(),
        ),
        (
            4,
            PortableMediaType::Content,
            portable.advisory_program_descriptor(),
        ),
    ]
}

fn encode_candidate_payload(
    generation: u64,
    verified: &VerifiedPolicyPublicationV1,
    diagnostics: ObjectDigest,
) -> Result<Vec<u8>, PolicyCompilerJournalErrorV1> {
    let portable = verified.candidate.portable();
    let fields = [
        portable.policy_bytes(),
        portable.optimization_bytes(),
        portable.namespace_graph_bytes(),
        portable.advisory_program_bytes(),
    ];
    let aggregate = fields.iter().try_fold(0_usize, |total, field| {
        total
            .checked_add(4)
            .and_then(|value| value.checked_add(field.len()))
    });
    let capacity = aggregate
        .and_then(|value| value.checked_add(8 + 2 + 32 + 32 * 4 + 136 + 8 + 41 * 4))
        .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    bytes.extend_from_slice(CANDIDATE_MAGIC);
    bytes.extend_from_slice(&2_u16.to_be_bytes());
    bytes.extend_from_slice(verified.project.as_bytes());
    bytes.extend_from_slice(verified.sandbox.as_bytes());
    bytes.extend_from_slice(verified.candidate.commitment().digest().as_bytes());
    bytes.extend_from_slice(verified.normalized_input.as_bytes());
    bytes.extend_from_slice(diagnostics.as_bytes());
    bytes.extend_from_slice(verified.prerequisites.digest().as_bytes());
    append_prerequisite_tuple(&mut bytes, &verified.prerequisites);
    bytes.extend_from_slice(&generation.to_be_bytes());
    for (media_code, expected_media, descriptor) in output_descriptors(portable) {
        if descriptor.media_type().as_str() != expected_media.as_str() {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        bytes.push(media_code);
        bytes.extend_from_slice(descriptor.digest().as_bytes());
        bytes.extend_from_slice(&descriptor.encoded_size().to_be_bytes());
    }
    for field in fields {
        let length = u32::try_from(field.len())
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(field);
    }
    Ok(bytes)
}

fn encode_diagnostics_payload(
    project: ProjectId,
    sandbox: SandboxId,
    candidate: ObjectDigest,
    canonical_diagnostics: &[u8],
) -> Result<Vec<u8>, PolicyCompilerJournalErrorV1> {
    validate_canonical_diagnostics(canonical_diagnostics)?;
    let length = u32::try_from(canonical_diagnostics.len())
        .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    let mut bytes = Vec::with_capacity(78 + canonical_diagnostics.len() + 32);
    bytes.extend_from_slice(b"AOSPCD01");
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(project.as_bytes());
    bytes.extend_from_slice(sandbox.as_bytes());
    bytes.extend_from_slice(candidate.as_bytes());
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(canonical_diagnostics);
    bytes.extend_from_slice(digest_bytes(DIAGNOSTICS_DOMAIN, canonical_diagnostics).as_bytes());
    Ok(bytes)
}

fn decode_diagnostics_payload(bytes: &[u8]) -> Result<&[u8], PolicyCompilerJournalErrorV1> {
    if bytes.len() < 111 || &bytes[..8] != b"AOSPCD01" || bytes[8..10] != 1_u16.to_be_bytes() {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let length = usize::try_from(u32::from_be_bytes(
        bytes[74..78]
            .try_into()
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
    ))
    .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    let payload_end = 78_usize
        .checked_add(length)
        .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    if length == 0 || bytes.len() != payload_end + 32 {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let payload = &bytes[78..payload_end];
    if digest_bytes(DIAGNOSTICS_DOMAIN, payload).as_bytes() != &bytes[payload_end..] {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    validate_canonical_diagnostics(payload)?;
    Ok(payload)
}

fn validate_canonical_diagnostics(bytes: &[u8]) -> Result<(), PolicyCompilerJournalErrorV1> {
    if bytes.len() < 16 {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let domain_length = usize::try_from(u64::from_be_bytes(
        bytes[..8]
            .try_into()
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
    ))
    .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    let domain_end = 8_usize
        .checked_add(domain_length)
        .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    let payload_length_end = domain_end
        .checked_add(8)
        .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    if payload_length_end > bytes.len() || bytes.get(8..domain_end) != Some(DIAGNOSTICS_DOMAIN) {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let payload_length = usize::try_from(u64::from_be_bytes(
        bytes[domain_end..payload_length_end]
            .try_into()
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
    ))
    .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    let payload_end = payload_length_end
        .checked_add(payload_length)
        .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    if payload_length == 0 || payload_end != bytes.len() {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes[payload_length_end..])
        .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    if serde_json::to_vec(&value)
        .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?
        != bytes[payload_length_end..]
    {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    Ok(())
}

fn encode_effect_payload(
    transaction_id: [u8; 16],
    generation: u64,
    verified: &VerifiedPolicyPublicationV1,
    diagnostics: ObjectDigest,
) -> Result<Vec<u8>, PolicyCompilerJournalErrorV1> {
    let portable = verified.candidate.portable();
    let mut bytes = Vec::with_capacity(527);
    bytes.extend_from_slice(b"AOSPCE01");
    bytes.extend_from_slice(&3_u16.to_be_bytes());
    bytes.extend_from_slice(verified.project.as_bytes());
    bytes.extend_from_slice(verified.sandbox.as_bytes());
    bytes.extend_from_slice(&transaction_id);
    bytes.extend_from_slice(verified.candidate.commitment().digest().as_bytes());
    bytes.extend_from_slice(verified.normalized_input.as_bytes());
    bytes.extend_from_slice(diagnostics.as_bytes());
    bytes.extend_from_slice(verified.prerequisites.digest().as_bytes());
    append_prerequisite_tuple(&mut bytes, &verified.prerequisites);
    bytes.extend_from_slice(&generation.to_be_bytes());
    bytes.push(PolicyEffectStateV1::Prepared as u8);
    bytes.extend_from_slice(&[0; 32]);
    for (media_code, expected_media, descriptor) in output_descriptors(portable) {
        if descriptor.media_type().as_str() != expected_media.as_str() {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        bytes.push(media_code);
        bytes.extend_from_slice(descriptor.digest().as_bytes());
        bytes.extend_from_slice(&descriptor.encoded_size().to_be_bytes());
    }
    Ok(bytes)
}

fn encode_observed_effect_payload(
    prepared: &[u8],
    observation: ObjectDigest,
) -> Result<Vec<u8>, PolicyCompilerJournalErrorV1> {
    let header = decode_effect_header(prepared)?;
    if header.state != PolicyEffectStateV1::Prepared || observation.as_bytes() == &[0; 32] {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let mut observed = prepared.to_vec();
    observed[330] = PolicyEffectStateV1::Observed as u8;
    observed[331..363].copy_from_slice(observation.as_bytes());
    let decoded = decode_effect_header(&observed)?;
    if decoded.state != PolicyEffectStateV1::Observed || decoded.observation != observation {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    Ok(observed)
}

fn encode_current_payload(
    project: ProjectId,
    sandbox: SandboxId,
    generation: u64,
    candidate: ObjectDigest,
    normalized_input: ObjectDigest,
    diagnostics: ObjectDigest,
    prerequisites: &PolicyPublicationPrerequisitesV1,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(314);
    bytes.extend_from_slice(CURRENT_MAGIC);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(project.as_bytes());
    bytes.extend_from_slice(sandbox.as_bytes());
    bytes.extend_from_slice(&generation.to_be_bytes());
    bytes.extend_from_slice(candidate.as_bytes());
    bytes.extend_from_slice(normalized_input.as_bytes());
    bytes.extend_from_slice(diagnostics.as_bytes());
    bytes.extend_from_slice(prerequisites.digest().as_bytes());
    append_prerequisite_tuple(&mut bytes, prerequisites);
    bytes
}

fn append_prerequisite_tuple(
    bytes: &mut Vec<u8>,
    prerequisites: &PolicyPublicationPrerequisitesV1,
) {
    bytes.extend_from_slice(prerequisites.ancestry_head().as_bytes());
    bytes.extend_from_slice(prerequisites.compiler_authority_head().as_bytes());
    bytes.extend_from_slice(prerequisites.cache_domain_head().as_bytes());
    bytes.extend_from_slice(prerequisites.revocation_head().as_bytes());
    bytes.extend_from_slice(&prerequisites.generation().to_be_bytes());
}

fn decode_current_payload(
    bytes: &[u8],
) -> Result<DecodedCurrentPolicyHeadV1, PolicyCompilerJournalErrorV1> {
    if bytes.len() != 314 || &bytes[..8] != CURRENT_MAGIC || bytes[8..10] != 1_u16.to_be_bytes() {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let generation = u64::from_be_bytes(
        bytes[42..50]
            .try_into()
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
    );
    let digest_at = |offset: usize| -> Result<ObjectDigest, PolicyCompilerJournalErrorV1> {
        let digest = ObjectDigest::from_bytes(
            bytes[offset..offset + 32]
                .try_into()
                .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
        );
        if digest.as_bytes() == &[0; 32] {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        Ok(digest)
    };
    if generation == 0 {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let prerequisites = digest_at(146)?;
    let prerequisite_tuple = decode_prerequisite_tuple(bytes, 178, prerequisites)?;
    Ok(DecodedCurrentPolicyHeadV1 {
        generation,
        candidate: digest_at(50)?,
        normalized_input: digest_at(82)?,
        diagnostics: digest_at(114)?,
        prerequisites,
        prerequisite_tuple,
    })
}

fn decode_candidate_header(
    bytes: &[u8],
) -> Result<DecodedCandidateHeaderV1, PolicyCompilerJournalErrorV1> {
    if bytes.len() < 478 || &bytes[..8] != CANDIDATE_MAGIC || bytes[8..10] != 2_u16.to_be_bytes() {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let digest_at = |offset: usize| -> Result<ObjectDigest, PolicyCompilerJournalErrorV1> {
        let digest = ObjectDigest::from_bytes(
            bytes[offset..offset + 32]
                .try_into()
                .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
        );
        if digest.as_bytes() == &[0; 32] {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        Ok(digest)
    };
    let mut outputs = [(ObjectDigest::from_bytes([0; 32]), 0_u64); 4];
    for (index, (output, offset)) in outputs
        .iter_mut()
        .zip([314_usize, 355, 396, 437])
        .enumerate()
    {
        if bytes[offset] != (index as u8) + 1 {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        let size = u64::from_be_bytes(
            bytes[offset + 33..offset + 41]
                .try_into()
                .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
        );
        if size == 0 {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        *output = (digest_at(offset + 1)?, size);
    }
    let generation = u64::from_be_bytes(
        bytes[306..314]
            .try_into()
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
    );
    if generation == 0 {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let mut cursor = 478_usize;
    for output in outputs {
        let length_end = cursor
            .checked_add(4)
            .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        if length_end > bytes.len() {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        let length = usize::try_from(u32::from_be_bytes(
            bytes[cursor..length_end]
                .try_into()
                .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
        ))
        .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        let payload_end = length_end
            .checked_add(length)
            .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        if length == 0 || payload_end > bytes.len() {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        let encoded_length = u64::try_from(length)
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        if output.1 != encoded_length {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        cursor = payload_end;
    }
    if cursor != bytes.len() {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let prerequisites = digest_at(138)?;
    let prerequisite_tuple = decode_prerequisite_tuple(bytes, 170, prerequisites)?;
    Ok(DecodedCandidateHeaderV1 {
        generation,
        candidate: digest_at(42)?,
        normalized_input: digest_at(74)?,
        diagnostics: digest_at(106)?,
        prerequisites,
        prerequisite_tuple,
        outputs,
    })
}

fn validate_candidate_payload(
    bytes: &[u8],
) -> Result<DecodedCandidateHeaderV1, PolicyCompilerJournalErrorV1> {
    let header = decode_candidate_header(bytes)?;
    let mut cursor = 478_usize;
    for (index, (digest, expected_size)) in header.outputs.iter().enumerate() {
        let length_end = cursor
            .checked_add(4)
            .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        let length = usize::try_from(u32::from_be_bytes(
            bytes[cursor..length_end]
                .try_into()
                .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
        ))
        .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        let payload_end = length_end
            .checked_add(length)
            .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        let payload = bytes
            .get(length_end..payload_end)
            .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        let actual_size = u64::try_from(payload.len())
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        let actual_digest = ObjectDigest::from_bytes(Sha256::digest(payload).into());
        if actual_size != *expected_size || actual_digest != *digest {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        match index {
            0 => {
                let decoded = decode_policy(payload, DecodeLimits::default())
                    .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
                if encode_policy(&decoded) != payload {
                    return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
                }
            }
            1 => {
                let decoded = decode_optimization(payload, DecodeLimits::default())
                    .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
                if encode_optimization(&decoded) != payload {
                    return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
                }
            }
            2 => {
                validate_canonical_json_domain(payload, b"aos.sandbox.portable-namespace-graph.v1")?
            }
            3 => validate_canonical_json_domain(
                payload,
                b"aos.sandbox.portable-advisory-program.v1",
            )?,
            _ => return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication),
        }
        cursor = payload_end;
    }
    if cursor != bytes.len() {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    Ok(header)
}

fn validate_canonical_json_domain(
    bytes: &[u8],
    expected_domain: &[u8],
) -> Result<(), PolicyCompilerJournalErrorV1> {
    if bytes.len() < 16 {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let domain_length = usize::try_from(u64::from_be_bytes(
        bytes[..8]
            .try_into()
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
    ))
    .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    let domain_end = 8_usize
        .checked_add(domain_length)
        .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    let length_end = domain_end
        .checked_add(8)
        .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    if bytes.get(8..domain_end) != Some(expected_domain) || length_end > bytes.len() {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let length = usize::try_from(u64::from_be_bytes(
        bytes[domain_end..length_end]
            .try_into()
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
    ))
    .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    if length == 0 || length_end.checked_add(length) != Some(bytes.len()) {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let payload = &bytes[length_end..];
    let value: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    if serde_json::to_vec(&value)
        .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?
        != payload
    {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    Ok(())
}

fn policy_effect_observation_request(
    effect: &ProtectedDomainEnvelopeV1<PolicyCompilerJournalSchemaV1>,
    body: &[u8],
    settlement_transaction_id: [u8; 16],
    result: ObjectDigest,
    prerequisites: ObjectDigest,
) -> Result<PolicyEffectObservationRequestV1, PolicyCompilerJournalErrorV1> {
    let identity = effect.key().identity();
    let header = decode_effect_header(body)?;
    if identity.len() != 48
        || header.state != PolicyEffectStateV1::Prepared
        || settlement_transaction_id == [0; 16]
        || result.as_bytes() == &[0; 32]
        || header.prerequisites != prerequisites
    {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let project = ProjectId::from_bytes(
        identity[..16]
            .try_into()
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
    );
    let sandbox = SandboxId::from_bytes(
        identity[16..32]
            .try_into()
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
    );
    let effect_transaction_id = identity[32..48]
        .try_into()
        .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    let mut output_hasher = Sha256::new();
    output_hasher.update(b"aos.sandbox.policy-compiler.effect-outputs.v1\0");
    for (digest, size) in header.outputs {
        output_hasher.update(digest.as_bytes());
        output_hasher.update(size.to_be_bytes());
    }

    Ok(PolicyEffectObservationRequestV1 {
        project,
        sandbox,
        effect_transaction_id,
        settlement_transaction_id,
        effect_predecessor: effect.digest(),
        outputs: ObjectDigest::from_bytes(output_hasher.finalize().into()),
        generation: header.generation,
        result,
        prerequisites,
    })
}

fn decode_effect_header(
    bytes: &[u8],
) -> Result<DecodedEffectHeaderV1, PolicyCompilerJournalErrorV1> {
    if bytes.len() != 527 || &bytes[..8] != b"AOSPCE01" || bytes[8..10] != 3_u16.to_be_bytes() {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let digest_at = |offset: usize| -> Result<ObjectDigest, PolicyCompilerJournalErrorV1> {
        let digest = ObjectDigest::from_bytes(
            bytes[offset..offset + 32]
                .try_into()
                .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
        );
        if digest.as_bytes() == &[0; 32] {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        Ok(digest)
    };
    let mut outputs = [(ObjectDigest::from_bytes([0; 32]), 0_u64); 4];
    for (index, (output, offset)) in outputs
        .iter_mut()
        .zip([363_usize, 404, 445, 486])
        .enumerate()
    {
        if bytes[offset] != (index as u8) + 1 {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        let descriptor = digest_at(offset + 1)?;
        let size = u64::from_be_bytes(
            bytes[offset + 33..offset + 41]
                .try_into()
                .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
        );
        if size == 0 {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        *output = (descriptor, size);
    }
    let prerequisites = digest_at(154)?;
    let prerequisite_tuple = decode_prerequisite_tuple(bytes, 186, prerequisites)?;
    let generation = u64::from_be_bytes(
        bytes[322..330]
            .try_into()
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
    );
    if generation == 0 {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    let state = match bytes[330] {
        1 => PolicyEffectStateV1::Prepared,
        2 => PolicyEffectStateV1::Observed,
        _ => return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication),
    };
    let observation = ObjectDigest::from_bytes(
        bytes[331..363]
            .try_into()
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
    );
    if (state == PolicyEffectStateV1::Prepared && observation.as_bytes() != &[0; 32])
        || (state == PolicyEffectStateV1::Observed && observation.as_bytes() == &[0; 32])
    {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    Ok(DecodedEffectHeaderV1 {
        state,
        observation,
        generation,
        candidate: digest_at(58)?,
        normalized_input: digest_at(90)?,
        diagnostics: digest_at(122)?,
        prerequisites,
        prerequisite_tuple,
        outputs,
    })
}

fn decode_prerequisite_tuple(
    bytes: &[u8],
    offset: usize,
    expected_digest: ObjectDigest,
) -> Result<PolicyPublicationPrerequisitesV1, PolicyCompilerJournalErrorV1> {
    let digest_at = |start: usize| -> Result<ObjectDigest, PolicyCompilerJournalErrorV1> {
        Ok(ObjectDigest::from_bytes(
            bytes
                .get(start..start + 32)
                .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?
                .try_into()
                .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
        ))
    };
    let generation_offset = offset
        .checked_add(128)
        .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    let generation = u64::from_be_bytes(
        bytes
            .get(generation_offset..generation_offset + 8)
            .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?
            .try_into()
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
    );
    let prerequisites = PolicyPublicationPrerequisitesV1::new(
        digest_at(offset)?,
        digest_at(offset + 32)?,
        digest_at(offset + 64)?,
        digest_at(offset + 96)?,
        generation,
    )?;
    if prerequisites.digest() != expected_digest {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    Ok(prerequisites)
}

fn update_descriptor(
    hasher: &mut Sha256,
    descriptor: &ObjectDescriptor,
) -> Result<(), PolicyCompilerJournalErrorV1> {
    if descriptor.digest().as_bytes() == &[0; 32] || descriptor.encoded_size() == 0 {
        return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
    }
    hasher.update((descriptor.media_type().as_str().len() as u64).to_be_bytes());
    hasher.update(descriptor.media_type().as_str().as_bytes());
    hasher.update(descriptor.digest().as_bytes());
    hasher.update(descriptor.encoded_size().to_be_bytes());
    Ok(())
}

fn prerequisite_digest(value: &PolicyPublicationPrerequisitesV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(PREREQUISITE_DOMAIN);
    hasher.update(value.ancestry_head.as_bytes());
    hasher.update(value.compiler_authority_head.as_bytes());
    hasher.update(value.cache_domain_head.as_bytes());
    hasher.update(value.revocation_head.as_bytes());
    hasher.update(value.generation.to_be_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn digest_bytes(domain: &[u8], bytes: &[u8]) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    ObjectDigest::from_bytes(hasher.finalize().into())
}
