//! Retains Policy publication's original typed prepared/pending and compiler evidence.
//!
//! Native original and final publication constructors remain in the actual role
//! owner. Fields stay scoped to the enclosing publication implementation; no
//! DATA supplied-parts constructor for an effect-facing capability is added.

use super::*;

/// Exact policy-publication currentness snapshot.
pub type PolicyCompilerJournalSnapshotV1 = ProtectedDomainSnapshotV1<PolicyCompilerJournalSchemaV1>;
type RawPolicyCompilerPostcommitCapabilityV1 =
    DomainPostcommitCapabilityV1<PolicyCompilerJournalSchemaV1>;

/// Binds one composite policy transaction to exact prerequisite currentness.
#[must_use = "policy postcommit authority must be revalidated exactly once"]
pub struct PolicyCompilerPostcommitCapabilityV1 {
    pub(super) inner: RawPolicyCompilerPostcommitCapabilityV1,
    pub(super) prerequisites: PolicyPublicationPrerequisitesV1,
}

/// Retains cold-replayed policy authority until exact semantic revalidation.
#[must_use = "cold policy authority must be consumed or deliberately discarded"]
pub struct PolicyCompilerColdObservationV1 {
    pub(super) inner: RawPolicyCompilerPostcommitCapabilityV1,
    pub(super) prerequisites: PolicyPublicationPrerequisitesV1,
}

/// Borrows fresh effect authority only while prerequisite currentness is held.
#[must_use = "the policy effect handoff must be used inside its guarded callback"]
pub struct PolicyCompilerEffectHandoffV1<'handoff> {
    pub(super) transaction_digest: ObjectDigest,
    pub(super) marker: PhantomData<&'handoff mut ()>,
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
    pub(super) project: ProjectId,
    pub(super) sandbox: SandboxId,
    pub(super) effect_transaction_id: [u8; 16],
    pub(super) settlement_transaction_id: [u8; 16],
    pub(super) effect_predecessor: ObjectDigest,
    pub(super) outputs: ObjectDigest,
    pub(super) generation: u64,
    pub(super) result: ObjectDigest,
    pub(super) prerequisites: ObjectDigest,
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
    pub(super) request: PolicyEffectObservationRequestV1,
}

impl VerifiedPolicyEffectObservationV1 {
    pub(crate) fn from_protected_authority(request: PolicyEffectObservationRequestV1) -> Self {
        Self { request }
    }

    pub(super) fn request(&self) -> &PolicyEffectObservationRequestV1 {
        &self.request
    }

    pub(super) fn result(&self) -> ObjectDigest {
        self.request.result
    }
}

/// Carries a candidate branded for one exact publication attempt.
#[must_use = "verified policy publication authority must be consumed by the journal adapter"]
pub(crate) struct VerifiedPolicyPublicationV1 {
    pub(super) project: ProjectId,
    pub(super) sandbox: SandboxId,
    pub(super) normalized_input: ObjectDigest,
    pub(super) candidate: CompiledPolicyCandidateV1,
    pub(super) diagnostics: Vec<u8>,
    pub(super) prerequisites: PolicyPublicationPrerequisitesV1,
}

// Capacity is comparison DATA from the actual adapter. In particular, this
// wrapper cannot be passed to commit and cannot manufacture Verified inputs.
pub(in crate::native) struct Q04PublicationCapacityV1 {
    pub(super) inner: PreparedDomainTransactionV1<PolicyCompilerJournalSchemaV1>,
    pub(super) current_envelope: ObjectDigest,
}

impl Q04PublicationCapacityV1 {
    pub(in crate::native) const fn transaction_id(&self) -> [u8; 16] {
        self.inner.transaction_id()
    }

    pub(in crate::native) const fn transaction_digest(&self) -> ObjectDigest {
        self.inner.transaction_digest()
    }

    pub(in crate::native) fn journal_records(
        &self,
    ) -> &[aos_sandbox_protocol::domain_ledger::transaction::JournalRecord] {
        self.inner.journal_records()
    }

    pub(in crate::native) const fn current_envelope_digest(&self) -> ObjectDigest {
        self.current_envelope
    }
}

impl VerifiedPolicyPublicationV1 {
    pub(super) fn body_fields(&self) -> PublicationBodyFieldsV1<'_> {
        PublicationBodyFieldsV1 {
            project: self.project,
            sandbox: self.sandbox,
            normalized_input: self.normalized_input,
            candidate: &self.candidate,
            prerequisites: &self.prerequisites,
        }
    }

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
        let normalized_input = normalized_policy_input_digest_v1(input)
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        let candidate_digest = candidate.commitment().digest();
        let diagnostics = aos_sandbox_protocol::policy_data::canonical_bytes(
            DIAGNOSTICS_DOMAIN,
            candidate.explanation(),
        )
        .map_err(crate::PolicyModelError::from)?;
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
    pub(super) inner: PreparedDomainTransactionV1<PolicyCompilerJournalSchemaV1>,
    pub(super) prerequisites: PolicyPublicationPrerequisitesV1,
}

// This move-only local position is parked in the actual Root attempt before
// invoking the strict adapter. No returned token crosses an unowned postcheck
// interval, and a failed prerequisite check leaves the original plan intact.
pub(in crate::native) struct Q04PolicyPublicationAttemptV1 {
    pub(super) prerequisites: PolicyPublicationPrerequisitesV1,
    pub(super) prepared: Option<PreparedDomainTransactionV1<PolicyCompilerJournalSchemaV1>>,
    pub(super) returned: Option<
        Result<
            DomainCommitOutcomeV1<PolicyCompilerJournalSchemaV1>,
            DomainRetainedCommitFailureV1<PolicyCompilerJournalSchemaV1>,
        >,
    >,
    pub(super) applied: Option<AppliedDomainTransactionV1<PolicyCompilerJournalSchemaV1>>,
    pub(super) pending: Option<DomainOutcomeUnknownV1<PolicyCompilerJournalSchemaV1>>,
}

impl Q04PolicyPublicationAttemptV1 {
    pub(in crate::native) fn park(prepared: PreparedPolicyPublicationV1) -> Self {
        Self {
            prerequisites: prepared.prerequisites,
            prepared: Some(prepared.inner),
            returned: None,
            applied: None,
            pending: None,
        }
    }

    pub(in crate::native) fn applied(
        &self,
    ) -> Option<&AppliedDomainTransactionV1<PolicyCompilerJournalSchemaV1>> {
        self.applied.as_ref()
    }

    pub(super) fn classify_returned(&mut self) -> Result<(), PolicyCompilerJournalErrorV1> {
        if self.applied.is_some() || self.pending.is_some() || self.prepared.is_some() {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        let returned = self
            .returned
            .take()
            .ok_or(PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        match returned {
            Ok(DomainCommitOutcomeV1::Applied(applied)) => {
                self.applied = Some(applied);
                Ok(())
            }
            Ok(DomainCommitOutcomeV1::OutcomeUnknown { pending, cause }) => {
                self.pending = Some(pending);
                Err(ProtectedDomainJournalErrorV1::from(cause).into())
            }
            Err(RetainedCommitFailureV1::BeforeJournalAppend { prepared, cause }) => {
                self.prepared = Some(prepared);
                Err(cause.into())
            }
            Err(
                RetainedCommitFailureV1::AfterAppendReadback { pending, cause }
                | RetainedCommitFailureV1::AfterAppendSealing { pending, cause },
            ) => {
                self.pending = Some(pending);
                Err(cause.into())
            }
        }
    }
}

// Replayed comparison DATA for Root's same held policy-state writer. This is
// neither a postcommit capability nor a replacement for the resident actual
// strict-commit outcome, original native prefix, floor and clock loans.
pub(in crate::native) struct Q04PolicyPublicationReadbackV1 {
    pub(in crate::native) sequence: u64,
    pub(in crate::native) transaction: ObjectDigest,
    pub(in crate::native) current: ObjectDigest,
}

/// Retains an exact policy publication after ambiguous durability.
#[must_use = "an ambiguous policy publication must be resolved after protected reopen"]
pub struct PolicyPublicationOutcomeUnknownV1 {
    pub(super) inner: DomainOutcomeUnknownV1<PolicyCompilerJournalSchemaV1>,
    pub(super) prerequisites: PolicyPublicationPrerequisitesV1,
}

/// Holds one durable cold-effect observation successor.
#[must_use = "a prepared policy observation must be committed or discarded"]
pub struct PreparedPolicyEffectObservationV1 {
    pub(super) inner: PreparedDomainTransactionV1<PolicyCompilerJournalSchemaV1>,
    pub(super) prerequisites: PolicyPublicationPrerequisitesV1,
    pub(super) observation: VerifiedPolicyEffectObservationV1,
}

/// Retains one ambiguous cold-effect observation without recreating authority.
#[must_use = "an ambiguous policy observation must be recovered"]
pub struct PolicyEffectObservationOutcomeUnknownV1 {
    pub(super) inner: DomainOutcomeUnknownV1<PolicyCompilerJournalSchemaV1>,
    pub(super) prerequisites: PolicyPublicationPrerequisitesV1,
    pub(super) observation: VerifiedPolicyEffectObservationV1,
}

/// Holds one exact policy checkpoint before durable mutation.
#[must_use = "a prepared policy checkpoint must be committed or discarded"]
pub struct PreparedPolicyCheckpointV1 {
    pub(super) inner: PreparedDomainTransactionV1<PolicyCompilerJournalSchemaV1>,
}

/// Retains one exact policy checkpoint whose classification is incomplete.
#[must_use = "an ambiguous policy checkpoint must be recovered"]
pub struct PolicyCheckpointOutcomeUnknownV1 {
    pub(super) inner: PolicyCheckpointOutcomeUnknownStateV1,
}

pub(super) enum PolicyCheckpointOutcomeUnknownStateV1 {
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
    pub(super) inner: AppliedDomainTransactionV1<PolicyCompilerJournalSchemaV1>,
    pub(super) prerequisites: Option<PolicyPublicationPrerequisitesV1>,
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
