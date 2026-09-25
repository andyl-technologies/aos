//! Atomic protected-journal joins across RFC-0021 source domains.
//!
//! Environment advances, hierarchy realization, Git publication, and lifecycle
//! orchestration sometimes form one logical controller mutation. This dormant
//! adapter preserves that atomic boundary and fixes their canonical ordering;
//! it performs no external effect and is not connected to controller routing.

use std::path::Path;
use std::sync::Arc;

use aos_sandbox_core::{ObjectDigest, ProjectId, ResourceId};
use sha2::{Digest as _, Sha256};

use crate::environment::protected_journal::{
    EnvironmentProtectedJournalEnvelopeV1, EnvironmentProtectedJournalSchemaV1,
};
use crate::environment::protected_owner::{
    recover_environment_generation_history_v1, recover_environment_journal_verifier_v1,
};
use crate::environment::{EnvironmentGenerationHistoryV1, EnvironmentProtectedEvidenceOwnerV1};
use crate::git::protected_journal::{GitProtectedJournalEnvelopeV1, GitProtectedJournalSchemaV1};
use crate::git::protected_owner::recover_git_journal_verifier_v1;
use crate::git::{GitProtectedEvidenceOwnerV1, GitTrustedValidatorV1};
use crate::hierarchy::protected_journal::{
    HierarchyProtectedJournalEnvelopeV1, HierarchyProtectedJournalSchemaV1,
    HierarchyProtectedReplayValidatorV1, recover_hierarchy_replay_validator_v1,
};
use crate::journal::{
    Journal, JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
    RecoveryReport, SourceDomainPolicyHoldV1,
};

use super::LifecycleJournalVerifierV1;
use super::protected_journal::{
    LifecycleProtectedJournalEnvelopeV1, LifecycleProtectedJournalSchemaV1,
};
use super::protected_journal_adapter::{
    DurableDomainMemberV1, ProtectedDomainJournalErrorV1, ProtectedDomainKeyV1,
    ProtectedDomainSchemaV1, ProtectedRecordRoleV1, ProtectedReducerPhaseV1, decode_durable_member,
    decode_reducer_payload_with_validator, encode_durable_member, replay_projection,
    validate_successor,
};
use super::protected_owner::recover_lifecycle_journal_verifier_v1;

const MAXIMUM_CROSS_DOMAIN_REPLAY_MEMBERS: usize = 262_144;
pub(crate) const PROTECTED_SOURCE_DOMAIN_ROOT: &str = "/var/lib/aos/sandbox/source-domains";
pub(crate) const PROTECTED_SOURCE_DOMAIN_JOURNAL: &str = "source-domains-v1.journal";

/// Owns the fixed protected journal shared by all dormant source domains.
///
/// Its journal is private and can enter Environment, Git, lifecycle, hierarchy,
/// or cross-domain claim only through crate-controlled adapters.
pub struct ProtectedSourceDomainJournalOwnerV1 {
    journal: Journal,
}

impl ProtectedSourceDomainJournalOwnerV1 {
    #[cfg(test)]
    pub(crate) fn from_test_journal(journal: Journal) -> Self {
        Self { journal }
    }

    /// Opens and cold-replays the fixed shared source-domain journal.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] when fixed-root protection or journal replay
    /// fails. Callers must not fall back to a generic journal opener.
    pub fn open_fixed_protected() -> Result<(Self, RecoveryReport), JournalError> {
        let (journal, report) = Journal::open_protected_at(
            Path::new(PROTECTED_SOURCE_DOMAIN_ROOT),
            PROTECTED_SOURCE_DOMAIN_JOURNAL,
            source_domain_journal_limits(),
        )?;
        Ok((Self { journal }, report))
    }

    /// Opens and cold-replays the fixed shared journal for one service UID.
    ///
    /// The fixed path remains part of the lifecycle replay-authority
    /// commitment. `expected_uid` only selects the exact filesystem owner that
    /// the protected opener accepts; callers cannot redirect durable state to
    /// another location.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] when the fixed root is absent or unsafe, its
    /// ownership differs from `expected_uid`, or bounded cold replay fails.
    pub fn open_fixed_protected_for_uid(
        expected_uid: u32,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        let (journal, report) = Journal::open_protected_at_for_uid(
            Path::new(PROTECTED_SOURCE_DOMAIN_ROOT),
            PROTECTED_SOURCE_DOMAIN_JOURNAL,
            source_domain_journal_limits(),
            expected_uid,
        )?;
        Ok((Self { journal }, report))
    }

    pub(crate) fn journal(&mut self) -> &mut Journal {
        &mut self.journal
    }

    /// Freezes every source-domain writer for one exact closed Q04 proposal.
    ///
    /// This is custody, not ancestry or publication authority. The caller
    /// must already hold Controller and retain this owner through root CAS.
    ///
    /// # Errors
    ///
    /// Rejects stale, malformed, or already-held custody and failed durable
    /// acquisition or exact readback.
    pub fn acquire_closed_policy_source_hold_v1(
        &mut self,
        hold: SourceDomainPolicyHoldV1,
    ) -> Result<(), JournalError> {
        self.journal.acquire_source_domain_policy_hold_v1(hold)
    }

    /// Reads retained source-domain custody under its protected writer.
    ///
    /// This observation is not a root or Cache currentness claim.
    ///
    /// # Errors
    ///
    /// Rejects unsafe or malformed protected custody.
    pub fn closed_policy_source_hold_v1(
        &self,
    ) -> Result<Option<SourceDomainPolicyHoldV1>, JournalError> {
        self.journal.source_domain_policy_hold_v1()
    }

    /// Rechecks the fixed journal and lock names against this retained writer.
    pub(crate) fn require_fixed_named_writer_v1(&self) -> Result<(), JournalError> {
        self.require_named_writer_at(
            Path::new(PROTECTED_SOURCE_DOMAIN_ROOT),
            source_domain_journal_limits(),
        )
    }

    fn require_named_writer_at(
        &self,
        directory: &Path,
        limits: JournalLimits,
    ) -> Result<(), JournalError> {
        let uid = self.journal.protected_owner_uid()?;
        self.journal.require_protected_named_location(
            directory,
            PROTECTED_SOURCE_DOMAIN_JOURNAL,
            uid,
            limits,
        )
    }

    #[cfg(test)]
    pub(crate) fn require_named_writer_for_test(&self) -> Result<(), JournalError> {
        self.journal.require_protected_names_current_for_test()
    }

    pub(crate) fn release_closed_policy_source_hold_after_root_readback_v1(
        &mut self,
        expected: SourceDomainPolicyHoldV1,
    ) -> Result<(), JournalError> {
        self.journal
            .release_source_domain_policy_hold_after_root_readback_v1(expected)
    }
}

/// Names the common project and subject bound by every joined source domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CrossDomainSemanticTupleV1 {
    project: ProjectId,
    subject: ResourceId,
}

impl CrossDomainSemanticTupleV1 {
    /// Constructs one non-sentinel common source-domain identity.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedDomainJournalErrorV1::NonCanonicalRecord`] for a
    /// zero project or subject identity.
    pub fn new(
        project: ProjectId,
        subject: ResourceId,
    ) -> Result<Self, ProtectedDomainJournalErrorV1> {
        if project.as_bytes() == &[0; 16] || subject.as_bytes() == &[0; 16] {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        Ok(Self { project, subject })
    }

    fn bytes(self) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[..16].copy_from_slice(self.project.as_bytes());
        bytes[16..].copy_from_slice(self.subject.as_bytes());
        bytes
    }
}

/// Selects one closed source-domain successor in an atomic journal join.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CrossDomainJournalSuccessorV1 {
    /// Carries one hierarchy successor.
    Hierarchy(HierarchyProtectedJournalEnvelopeV1),
    /// Carries one environment successor.
    Environment(EnvironmentProtectedJournalEnvelopeV1),
    /// Carries one Git successor.
    Git(GitProtectedJournalEnvelopeV1),
    /// Carries one lifecycle successor.
    Lifecycle(LifecycleProtectedJournalEnvelopeV1),
}

impl CrossDomainJournalSuccessorV1 {
    fn domain_order(&self) -> u8 {
        match self {
            Self::Git(_) => 1,
            Self::Environment(_) => 2,
            Self::Hierarchy(_) => 3,
            Self::Lifecycle(_) => 4,
        }
    }

    fn domain_bit(&self) -> u8 {
        1_u8 << (self.domain_order() - 1)
    }

    fn kind_order(&self) -> u8 {
        match self {
            Self::Hierarchy(envelope) => {
                HierarchyProtectedJournalSchemaV1::order(envelope.key().kind())
            }
            Self::Environment(envelope) => {
                EnvironmentProtectedJournalSchemaV1::order(envelope.key().kind())
            }
            Self::Git(envelope) => GitProtectedJournalSchemaV1::order(envelope.key().kind()),
            Self::Lifecycle(envelope) => {
                LifecycleProtectedJournalSchemaV1::order(envelope.key().kind())
            }
        }
    }

    fn namespace(&self) -> RecordNamespace {
        match self {
            Self::Hierarchy(envelope) => {
                HierarchyProtectedJournalSchemaV1::namespace(envelope.key().kind())
            }
            Self::Environment(envelope) => {
                EnvironmentProtectedJournalSchemaV1::namespace(envelope.key().kind())
            }
            Self::Git(envelope) => GitProtectedJournalSchemaV1::namespace(envelope.key().kind()),
            Self::Lifecycle(envelope) => {
                LifecycleProtectedJournalSchemaV1::namespace(envelope.key().kind())
            }
        }
    }

    fn key(&self) -> &[u8] {
        match self {
            Self::Hierarchy(envelope) => envelope.key().as_bytes(),
            Self::Environment(envelope) => envelope.key().as_bytes(),
            Self::Git(envelope) => envelope.key().as_bytes(),
            Self::Lifecycle(envelope) => envelope.key().as_bytes(),
        }
    }

    fn identity(&self) -> &[u8] {
        match self {
            Self::Hierarchy(envelope) => envelope.key().identity(),
            Self::Environment(envelope) => envelope.key().identity(),
            Self::Git(envelope) => envelope.key().identity(),
            Self::Lifecycle(envelope) => envelope.key().identity(),
        }
    }

    fn digest(&self) -> ObjectDigest {
        match self {
            Self::Hierarchy(envelope) => envelope.digest(),
            Self::Environment(envelope) => envelope.digest(),
            Self::Git(envelope) => envelope.digest(),
            Self::Lifecycle(envelope) => envelope.digest(),
        }
    }

    fn encode_durable(
        self,
        transaction_id: [u8; 16],
        member_index: u16,
        member_count: u16,
        set_digest: ObjectDigest,
    ) -> Result<(Self, Vec<u8>), ProtectedDomainJournalErrorV1> {
        match self {
            Self::Hierarchy(envelope) => {
                let member = encode_durable_member(
                    transaction_id,
                    member_index,
                    member_count,
                    set_digest,
                    envelope,
                )?;
                Ok((Self::Hierarchy(member.envelope), member.encoded))
            }
            Self::Environment(envelope) => {
                let member = encode_durable_member(
                    transaction_id,
                    member_index,
                    member_count,
                    set_digest,
                    envelope,
                )?;
                Ok((Self::Environment(member.envelope), member.encoded))
            }
            Self::Git(envelope) => {
                let member = encode_durable_member(
                    transaction_id,
                    member_index,
                    member_count,
                    set_digest,
                    envelope,
                )?;
                Ok((Self::Git(member.envelope), member.encoded))
            }
            Self::Lifecycle(envelope) => {
                let member = encode_durable_member(
                    transaction_id,
                    member_index,
                    member_count,
                    set_digest,
                    envelope,
                )?;
                Ok((Self::Lifecycle(member.envelope), member.encoded))
            }
        }
    }

    fn role(&self) -> ProtectedRecordRoleV1 {
        match self {
            Self::Hierarchy(envelope) => {
                HierarchyProtectedJournalSchemaV1::role(envelope.key().kind())
            }
            Self::Environment(envelope) => {
                EnvironmentProtectedJournalSchemaV1::role(envelope.key().kind())
            }
            Self::Git(envelope) => GitProtectedJournalSchemaV1::role(envelope.key().kind()),
            Self::Lifecycle(envelope) => {
                LifecycleProtectedJournalSchemaV1::role(envelope.key().kind())
            }
        }
    }

    fn phase(&self) -> ProtectedReducerPhaseV1 {
        match self {
            Self::Hierarchy(envelope) => envelope.validated_phase(),
            Self::Environment(envelope) => envelope.validated_phase(),
            Self::Git(envelope) => envelope.validated_phase(),
            Self::Lifecycle(envelope) => envelope.validated_phase(),
        }
    }

    fn binds_tuple(
        &self,
        tuple: CrossDomainSemanticTupleV1,
        validators: &CrossDomainReplayValidatorsV1,
    ) -> Result<bool, ProtectedDomainJournalErrorV1> {
        let tuple_bytes = tuple.bytes();
        let identity_matches = self.identity().get(..32) == Some(tuple_bytes.as_slice());
        if !identity_matches {
            return Ok(false);
        }
        let subject = common_subject_digest(tuple);
        let companions = match self {
            Self::Hierarchy(envelope) => {
                let payload = decode_reducer_payload_with_validator::<
                    HierarchyProtectedJournalSchemaV1,
                >(
                    envelope.key(), envelope.payload(), &validators.hierarchy
                )?;
                payload.companions().contains(&subject)
                    && hierarchy_body_binds_subject(payload.body(), tuple.subject.as_bytes())
            }
            Self::Environment(envelope) => {
                decode_reducer_payload_with_validator::<EnvironmentProtectedJournalSchemaV1>(
                    envelope.key(),
                    envelope.payload(),
                    &validators.environment,
                )?
                .companions()
                .contains(&subject)
            }
            Self::Git(envelope) => decode_reducer_payload_with_validator::<
                GitProtectedJournalSchemaV1,
            >(
                envelope.key(), envelope.payload(), &validators.git
            )?
            .companions()
            .contains(&subject),
            Self::Lifecycle(envelope) => {
                decode_reducer_payload_with_validator::<LifecycleProtectedJournalSchemaV1>(
                    envelope.key(),
                    envelope.payload(),
                    &validators.lifecycle,
                )?
                .companions()
                .contains(&subject)
            }
        };
        Ok(companions)
    }

    fn is_checkpoint(&self) -> bool {
        match self {
            Self::Hierarchy(envelope) => {
                HierarchyProtectedJournalSchemaV1::is_checkpoint(envelope.key().kind())
            }
            Self::Environment(envelope) => {
                EnvironmentProtectedJournalSchemaV1::is_checkpoint(envelope.key().kind())
            }
            Self::Git(envelope) => {
                GitProtectedJournalSchemaV1::is_checkpoint(envelope.key().kind())
            }
            Self::Lifecycle(envelope) => {
                LifecycleProtectedJournalSchemaV1::is_checkpoint(envelope.key().kind())
            }
        }
    }

    fn validate_successor(
        &self,
        journal: &Journal,
        validators: &CrossDomainReplayValidatorsV1,
    ) -> Result<(), ProtectedDomainJournalErrorV1> {
        let previous = journal.get(self.namespace(), self.key());
        match self {
            Self::Hierarchy(envelope) => {
                validate_successor(previous, envelope, &validators.hierarchy)
            }
            Self::Environment(envelope) => {
                validate_successor(previous, envelope, &validators.environment)
            }
            Self::Git(envelope) => validate_successor(previous, envelope, &validators.git),
            Self::Lifecycle(envelope) => {
                validate_successor(previous, envelope, &validators.lifecycle)
            }
        }
    }
}

fn hierarchy_body_binds_subject(body: &[u8], subject: &[u8; 16]) -> bool {
    let Some(magic) = body.get(..8) else {
        return false;
    };
    (magic == b"AOSHHI01"
        || magic == b"AOSHRG01"
        || magic == b"AOSHDG01"
        || magic == b"AOSHRH01"
        || magic == b"AOSHDH01")
        && body.get(36..52) == Some(subject.as_slice())
}

/// Retains one exact typed successor after cross-domain durable readback.
#[derive(Debug)]
pub struct CrossDomainPostcommitRecordV1 {
    namespace: RecordNamespace,
    role: ProtectedRecordRoleV1,
    phase: ProtectedReducerPhaseV1,
    transaction_phase: ProtectedReducerPhaseV1,
    successor: CrossDomainJournalSuccessorV1,
    encoded: Vec<u8>,
}

impl CrossDomainPostcommitRecordV1 {
    /// Returns the fixed shared-journal namespace of this record.
    #[must_use]
    pub const fn namespace(&self) -> RecordNamespace {
        self.namespace
    }

    /// Returns the exact typed successor read back after commit.
    #[must_use]
    pub const fn successor(&self) -> &CrossDomainJournalSuccessorV1 {
        &self.successor
    }

    /// Reports whether decoded terminal state may publish protected current state.
    #[must_use]
    pub fn is_publication(&self) -> bool {
        matches!(self.role, ProtectedRecordRoleV1::Publication)
            && self.phase == ProtectedReducerPhaseV1::Terminal
            && self.transaction_phase == ProtectedReducerPhaseV1::Terminal
    }

    /// Reports whether decoded state still admits exactly one external effect.
    #[must_use]
    pub fn is_effect(&self) -> bool {
        matches!(self.role, ProtectedRecordRoleV1::Effect)
            && self.phase == ProtectedReducerPhaseV1::Prepared
            && self.transaction_phase == ProtectedReducerPhaseV1::Prepared
    }

    /// Returns the phase decoded from canonical domain reducer state.
    #[must_use]
    pub const fn phase(&self) -> ProtectedReducerPhaseV1 {
        self.phase
    }
}

/// Seals the complete shared-journal state used by one cross-domain plan.
#[derive(Clone, Debug)]
pub struct CrossDomainJournalSnapshotV1 {
    instance: Arc<CrossDomainAdapterInstanceV1>,
    sequence: u64,
    root: ObjectDigest,
}

impl CrossDomainJournalSnapshotV1 {
    /// Returns the exact shared-journal sequence.
    #[must_use]
    pub const fn journal_sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the complete namespace/key/value materialization commitment.
    #[must_use]
    pub const fn materialized_root(&self) -> ObjectDigest {
        self.root
    }
}

/// Holds one exact prepared atomic cross-domain transaction.
#[must_use = "a prepared cross-domain transaction must be committed or discarded"]
pub struct PreparedCrossDomainJournalTransactionV1 {
    snapshot: CrossDomainJournalSnapshotV1,
    transaction: JournalTransaction,
    before: Vec<Option<Vec<u8>>>,
    after: Vec<Vec<u8>>,
    successors: Vec<CrossDomainJournalSuccessorV1>,
    digest: ObjectDigest,
    set_digest: ObjectDigest,
}

/// Retains exact cross-domain predecessors and successors after ambiguity.
#[must_use = "an ambiguous cross-domain transaction must be resolved after reopen"]
pub struct CrossDomainJournalOutcomeUnknownV1 {
    prepared: PreparedCrossDomainJournalTransactionV1,
}

/// Retains one composite exact-readback cross-domain transaction capability.
#[must_use = "cross-domain authority must be revalidated and consumed atomically"]
pub struct CrossDomainPostcommitCapabilityV1 {
    instance: Arc<CrossDomainAdapterInstanceV1>,
    transaction: ObjectDigest,
    set_digest: ObjectDigest,
    sequence: u64,
    root: ObjectDigest,
    records: Vec<CrossDomainPostcommitRecordV1>,
}

/// Carries a consumed, current cross-domain transaction to a dormant seam.
#[must_use = "validated cross-domain authority must drive at most one action"]
pub struct ValidatedCrossDomainPostcommitV1<'current> {
    transaction: ObjectDigest,
    set_digest: ObjectDigest,
    records: Vec<CrossDomainPostcommitRecordV1>,
    current: std::marker::PhantomData<&'current ()>,
}

/// Proves every exact cross-domain successor was durably read back.
#[must_use = "cross-domain authority must be consumed by the intended dormant seam"]
pub struct AppliedCrossDomainJournalTransactionV1 {
    transaction: ObjectDigest,
    snapshot: CrossDomainJournalSnapshotV1,
    capability: Option<CrossDomainPostcommitCapabilityV1>,
}

impl AppliedCrossDomainJournalTransactionV1 {
    /// Returns the commitment to the complete ordered atomic transaction.
    #[must_use]
    pub const fn transaction_digest(&self) -> ObjectDigest {
        self.transaction
    }

    /// Returns the exact sealed postcommit shared-journal snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &CrossDomainJournalSnapshotV1 {
        &self.snapshot
    }

    /// Takes the composite cross-domain postcommit capability.
    #[must_use]
    pub fn take_postcommit(&mut self) -> Option<CrossDomainPostcommitCapabilityV1> {
        self.capability.take()
    }
}

impl CrossDomainPostcommitCapabilityV1 {
    /// Returns the exact durable transaction commitment.
    #[must_use]
    pub const fn transaction_digest(&self) -> ObjectDigest {
        self.transaction
    }

    /// Returns the commitment to the exact ordered four-domain member set.
    #[must_use]
    pub const fn transaction_set_digest(&self) -> ObjectDigest {
        self.set_digest
    }

    /// Consumes the whole transaction after exact current-envelope revalidation.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedDomainJournalErrorV1::StaleAuthority`] when another
    /// commit advanced the journal or any transaction member is no longer the
    /// byte-exact current envelope.
    pub fn consume<'current>(
        self,
        authority: &'current mut ProtectedCrossDomainJournalV1<'_, '_>,
    ) -> Result<ValidatedCrossDomainPostcommitV1<'current>, ProtectedDomainJournalErrorV1> {
        let current = authority.snapshot()?;
        if !Arc::ptr_eq(&self.instance, &authority.instance)
            || self.sequence != current.sequence
            || self.root != current.root
            || self.records.iter().any(|record| {
                authority
                    .journal
                    .get(record.namespace, record.successor.key())
                    != Some(record.encoded.as_slice())
            })
        {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        Ok(ValidatedCrossDomainPostcommitV1 {
            transaction: self.transaction,
            set_digest: self.set_digest,
            records: self.records,
            current: std::marker::PhantomData,
        })
    }
}

impl ValidatedCrossDomainPostcommitV1<'_> {
    /// Returns the exact ordered atomic transaction commitment.
    #[must_use]
    pub const fn transaction_digest(&self) -> ObjectDigest {
        self.transaction
    }

    /// Returns the commitment to the exact ordered four-domain member set.
    #[must_use]
    pub const fn transaction_set_digest(&self) -> ObjectDigest {
        self.set_digest
    }

    /// Returns the complete ordered current transaction member set.
    #[must_use]
    pub fn records(&self) -> &[CrossDomainPostcommitRecordV1] {
        &self.records
    }
}

/// Distinguishes exact success from an append requiring protected reopen.
#[must_use = "ambiguous cross-domain commits must retain their recovery token"]
pub enum CrossDomainJournalCommitOutcomeV1 {
    /// Every successor was durably committed and read back exactly.
    Applied(AppliedCrossDomainJournalTransactionV1),
    /// Append or synchronization failed after preflight.
    OutcomeUnknown {
        /// Retains the complete atomic transaction.
        pending: CrossDomainJournalOutcomeUnknownV1,
        /// Reports the underlying journal failure.
        cause: JournalError,
    },
}

/// Classifies an exact cross-domain transaction after protected reopen.
#[must_use = "recovered cross-domain state must be applied, retried, or quarantined"]
pub enum CrossDomainJournalRecoveryV1 {
    /// Reopen found every exact successor.
    Applied(AppliedCrossDomainJournalTransactionV1),
    /// Reopen found every exact predecessor and retained the only safe retry.
    Retry(PreparedCrossDomainJournalTransactionV1),
    /// Reopen found mixed or substituted materialized values.
    Diverged(CrossDomainJournalOutcomeUnknownV1),
}

/// Carries a complete current cross-domain transaction reconstructed on reopen.
#[must_use = "cold-replayed authority must be revalidated and consumed"]
pub enum ReplayedCrossDomainPostcommitV1 {
    /// The complete current transaction retains at least one eligible effect.
    Prepared(CrossDomainPostcommitCapabilityV1),
    /// The complete current transaction contains a terminal publication.
    Terminal(CrossDomainPostcommitCapabilityV1),
}

struct CrossDomainDurableMemberV1 {
    transaction_id: [u8; 16],
    member_index: u16,
    member_count: u16,
    set_digest: ObjectDigest,
    namespace: RecordNamespace,
    successor: CrossDomainJournalSuccessorV1,
    encoded: Vec<u8>,
}

#[derive(Debug)]
struct CrossDomainAdapterInstanceV1;

#[derive(Clone, Debug, Eq, PartialEq)]
struct CrossDomainReplayValidatorsV1 {
    git: GitTrustedValidatorV1,
    environment: EnvironmentGenerationHistoryV1,
    hierarchy: HierarchyProtectedReplayValidatorV1,
    lifecycle: LifecycleJournalVerifierV1,
}

/// Owns one dormant protected cross-domain journal boundary.
pub struct ProtectedCrossDomainJournalV1<'journal, 'evidence> {
    journal: &'journal mut Journal,
    instance: Arc<CrossDomainAdapterInstanceV1>,
    validators: CrossDomainReplayValidatorsV1,
    environment_evidence_owner: &'evidence mut EnvironmentProtectedEvidenceOwnerV1,
    git_evidence_owner: &'evidence mut GitProtectedEvidenceOwnerV1,
}

impl<'journal, 'evidence> ProtectedCrossDomainJournalV1<'journal, 'evidence> {
    /// Cold-replays all four protected source domains and claims their atomic
    /// dormant join without activating any controller or effect consumer.
    ///
    /// Git validator and both boot-clock observations are issued by their
    /// fixed protected evidence owners. Every journal validator, hierarchy
    /// head, and domain projection is reconstructed from actual protected
    /// current records; the final snapshot replays all four domains before
    /// returning the owner.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedDomainJournalErrorV1`] for malformed or inconsistent
    /// protected records, invalid trust evidence, incomplete hierarchy heads,
    /// or absent protected-open provenance.
    pub fn claim_cold_replayed(
        journal_owner: &'journal mut ProtectedSourceDomainJournalOwnerV1,
        environment_evidence_owner: &'evidence mut EnvironmentProtectedEvidenceOwnerV1,
        git_evidence_owner: &'evidence mut GitProtectedEvidenceOwnerV1,
    ) -> Result<Self, ProtectedDomainJournalErrorV1> {
        let journal = journal_owner.journal();
        let git_evidence = git_evidence_owner
            .issue_claim_evidence()
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        let environment_evidence = environment_evidence_owner
            .issue_claim_evidence()
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        let git_verifier = recover_git_journal_verifier_v1(journal, git_evidence)?;
        let environment_verifier =
            recover_environment_journal_verifier_v1(journal, environment_evidence)?;
        if environment_verifier.current_time().boot().digest()
            != git_verifier.current_boottime().boot().digest()
            || environment_verifier.boot_rollover().predecessor_boots()
                != git_verifier.boot_rollover().predecessor_boots()
        {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let environment = recover_environment_generation_history_v1(journal)?;
        let hierarchy = recover_hierarchy_replay_validator_v1(journal)?;
        let lifecycle = recover_lifecycle_journal_verifier_v1(journal)?;
        let mut joined = Self::claim(
            journal,
            git_verifier.validator().clone(),
            environment,
            hierarchy,
            lifecycle,
            environment_evidence_owner,
            git_evidence_owner,
        )?;
        joined.snapshot()?;
        Ok(joined)
    }

    /// Claims an already protected-open healthy journal.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] when protected storage provenance is absent or
    /// an earlier ambiguous write poisoned the handle.
    pub(crate) fn claim(
        journal: &'journal mut Journal,
        git: GitTrustedValidatorV1,
        environment: EnvironmentGenerationHistoryV1,
        hierarchy: HierarchyProtectedReplayValidatorV1,
        lifecycle: LifecycleJournalVerifierV1,
        environment_evidence_owner: &'evidence mut EnvironmentProtectedEvidenceOwnerV1,
        git_evidence_owner: &'evidence mut GitProtectedEvidenceOwnerV1,
    ) -> Result<Self, ProtectedDomainJournalErrorV1> {
        journal.ensure_protected_authority()?;
        Ok(Self {
            journal,
            instance: Arc::new(CrossDomainAdapterInstanceV1),
            validators: CrossDomainReplayValidatorsV1 {
                git,
                environment,
                hierarchy,
                lifecycle,
            },
            environment_evidence_owner,
            git_evidence_owner,
        })
    }

    /// Captures the complete protected shared-journal materialization.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] when the journal is poisoned.
    pub fn snapshot(
        &mut self,
    ) -> Result<CrossDomainJournalSnapshotV1, ProtectedDomainJournalErrorV1> {
        self.revalidate_evidence()?;
        self.journal.ensure_healthy()?;
        validate_source_domain_projections(self.journal, &self.validators)?;
        Ok(CrossDomainJournalSnapshotV1 {
            instance: Arc::clone(&self.instance),
            sequence: self.journal.snapshot_sequence(),
            root: complete_materialized_root(self.journal),
        })
    }

    /// Reconstructs one current exact four-domain postcommit capability.
    ///
    /// Superseded or incomplete groups grant no authority. A complete group
    /// must retain every original member, cover all four closed source domains,
    /// and reproduce the durable member-set commitment and canonical order.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedDomainJournalErrorV1`] for malformed durable members,
    /// excessive replay state, an unhealthy journal, or invalid grouping.
    pub fn recover_current_postcommit(
        &mut self,
        transaction_id: [u8; 16],
    ) -> Result<Option<ReplayedCrossDomainPostcommitV1>, ProtectedDomainJournalErrorV1> {
        let snapshot = self.snapshot()?;
        let mut members = Vec::new();
        for (namespace, key, value) in self.journal.all_records() {
            let Some(member) = decode_cross_domain_member(namespace, key, value, &self.validators)?
            else {
                continue;
            };
            if member.transaction_id != transaction_id {
                continue;
            }
            if members.len() >= MAXIMUM_CROSS_DOMAIN_REPLAY_MEMBERS {
                return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
            }
            members.push(member);
        }
        if members.is_empty() {
            return Ok(None);
        }
        members.sort_by_key(|member| member.member_index);
        let first = members
            .first()
            .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        let complete = usize::from(first.member_count) == members.len()
            && members
                .iter()
                .enumerate()
                .all(|(index, member)| usize::from(member.member_index) == index);
        if !complete {
            return Ok(None);
        }
        if members.iter().any(|member| {
            member.transaction_id != transaction_id
                || member.member_count != first.member_count
                || member.set_digest != first.set_digest
        }) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let domain_set = members
            .iter()
            .fold(0_u8, |set, member| set | member.successor.domain_bit());
        let tuple = semantic_tuple_from_successor(&first.successor)?;
        let tuple_matches = members.iter().try_fold(true, |matches, member| {
            member
                .successor
                .binds_tuple(tuple, &self.validators)
                .map(|current| matches && current)
        })?;
        if members.len() != 4
            || domain_set != 0b1111
            || members
                .iter()
                .any(|member| member.successor.is_checkpoint())
            || !tuple_matches
            || members.windows(2).any(|pair| {
                (
                    pair[0].successor.domain_order(),
                    pair[0].successor.kind_order(),
                    pair[0].successor.key(),
                ) >= (
                    pair[1].successor.domain_order(),
                    pair[1].successor.kind_order(),
                    pair[1].successor.key(),
                )
            })
        {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let successors: Vec<_> = members
            .iter()
            .map(|member| member.successor.clone())
            .collect();
        let set_digest = cross_transaction_set_digest(transaction_id, &successors);
        if set_digest != first.set_digest {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let records = members
            .iter()
            .map(|member| {
                JournalRecord::put(
                    member.namespace,
                    member.successor.key().to_vec(),
                    member.encoded.clone(),
                )
            })
            .collect();
        let transaction = JournalTransaction::new(transaction_id, records)?;
        let transaction_digest = cross_transaction_digest(&transaction);
        let phases = members
            .iter()
            .map(|member| member.successor.phase())
            .collect::<Vec<_>>();
        let replay_phase = aggregate_cross_phase(&phases);
        if matches!(
            replay_phase,
            ProtectedReducerPhaseV1::Observed | ProtectedReducerPhaseV1::Superseded
        ) {
            return Ok(None);
        }
        let mut records = Vec::with_capacity(members.len());
        for member in members {
            let phase = member.successor.phase();
            records.push(CrossDomainPostcommitRecordV1 {
                namespace: member.namespace,
                role: member.successor.role(),
                phase,
                transaction_phase: replay_phase,
                successor: member.successor,
                encoded: member.encoded,
            });
        }
        let capability = CrossDomainPostcommitCapabilityV1 {
            instance: Arc::clone(&self.instance),
            transaction: transaction_digest,
            set_digest,
            sequence: snapshot.sequence,
            root: snapshot.root,
            records,
        };
        Ok(Some(if replay_phase == ProtectedReducerPhaseV1::Terminal {
            ReplayedCrossDomainPostcommitV1::Terminal(capability)
        } else {
            ReplayedCrossDomainPostcommitV1::Prepared(capability)
        }))
    }

    /// Plans one atomic mutation in canonical dependency order.
    ///
    /// Git source state precedes derived environment state, which precedes
    /// hierarchy realization, which precedes lifecycle orchestration. Each
    /// domain's own closed kind order then applies before bytewise key order.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedDomainJournalErrorV1`] for empty or duplicate input,
    /// failed predecessor CAS, or a journal preflight failure.
    pub fn plan(
        &mut self,
        transaction_id: [u8; 16],
        tuple: CrossDomainSemanticTupleV1,
        mut successors: Vec<CrossDomainJournalSuccessorV1>,
    ) -> Result<PreparedCrossDomainJournalTransactionV1, ProtectedDomainJournalErrorV1> {
        let snapshot = self.snapshot()?;
        successors.sort_by(|left, right| {
            (left.domain_order(), left.kind_order(), left.key()).cmp(&(
                right.domain_order(),
                right.kind_order(),
                right.key(),
            ))
        });
        let domain_set = successors
            .iter()
            .fold(0_u8, |set, successor| set | successor.domain_bit());
        let tuple_matches = successors.iter().try_fold(true, |matches, successor| {
            successor
                .binds_tuple(tuple, &self.validators)
                .map(|current| matches && current)
        })?;
        if successors.len() != 4
            || domain_set != 0b1111
            || successors.iter().any(|successor| successor.is_checkpoint())
            || !tuple_matches
            || successors.windows(2).any(|pair| {
                pair[0].namespace() == pair[1].namespace() && pair[0].key() == pair[1].key()
            })
        {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let mut records = Vec::with_capacity(successors.len());
        let mut before = Vec::with_capacity(successors.len());
        let mut after = Vec::with_capacity(successors.len());
        let member_count = u16::try_from(successors.len())
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        let set_digest = cross_transaction_set_digest(transaction_id, &successors);
        let mut retained_successors = Vec::with_capacity(successors.len());
        for (index, successor) in successors.into_iter().enumerate() {
            successor.validate_successor(self.journal, &self.validators)?;
            let namespace = successor.namespace();
            let key = successor.key().to_vec();
            let member_index = u16::try_from(index)
                .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
            let (successor, value) =
                successor.encode_durable(transaction_id, member_index, member_count, set_digest)?;
            before.push(self.journal.get(namespace, &key).map(<[u8]>::to_vec));
            after.push(value.clone());
            records.push(JournalRecord::put(namespace, key, value));
            retained_successors.push(successor);
        }
        let transaction = JournalTransaction::new(transaction_id, records)?;
        self.journal
            .preflight_transactions(std::slice::from_ref(&transaction))?;
        let digest = cross_transaction_digest(&transaction);
        Ok(PreparedCrossDomainJournalTransactionV1 {
            snapshot,
            transaction,
            before,
            after,
            successors: retained_successors,
            digest,
            set_digest,
        })
    }

    /// Commits a cross-domain plan and performs exact successor readback.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedDomainJournalErrorV1::StaleAuthority`] when an
    /// intervening commit or another adapter instance invalidated the plan.
    pub fn commit(
        &mut self,
        prepared: PreparedCrossDomainJournalTransactionV1,
    ) -> Result<CrossDomainJournalCommitOutcomeV1, ProtectedDomainJournalErrorV1> {
        self.validate_snapshot(&prepared.snapshot)?;
        if !cross_values_match(self.journal, &prepared, false) {
            return Err(ProtectedDomainJournalErrorV1::CompareAndSwapFailed);
        }
        self.journal
            .preflight_transactions(std::slice::from_ref(&prepared.transaction))?;
        if let Err(cause) = self.journal.commit(&prepared.transaction) {
            return Ok(CrossDomainJournalCommitOutcomeV1::OutcomeUnknown {
                pending: CrossDomainJournalOutcomeUnknownV1 { prepared },
                cause,
            });
        }
        if !cross_values_match(self.journal, &prepared, true) {
            return Ok(CrossDomainJournalCommitOutcomeV1::OutcomeUnknown {
                pending: CrossDomainJournalOutcomeUnknownV1 { prepared },
                cause: JournalError::AuthorityPreflightMismatch,
            });
        }
        self.applied(prepared)
            .map(CrossDomainJournalCommitOutcomeV1::Applied)
    }

    /// Resolves one ambiguous cross-domain transaction after protected reopen.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] when the reopened handle is not healthy.
    pub fn recover(
        &mut self,
        pending: CrossDomainJournalOutcomeUnknownV1,
    ) -> Result<CrossDomainJournalRecoveryV1, ProtectedDomainJournalErrorV1> {
        self.revalidate_evidence()?;
        self.journal.ensure_healthy()?;
        let prepared = pending.prepared;
        if cross_values_match(self.journal, &prepared, true) {
            return self
                .applied(prepared)
                .map(CrossDomainJournalRecoveryV1::Applied);
        }
        if cross_values_match(self.journal, &prepared, false) {
            let mut prepared = prepared;
            prepared.snapshot = self.snapshot()?;
            self.journal
                .preflight_transactions(std::slice::from_ref(&prepared.transaction))?;
            return Ok(CrossDomainJournalRecoveryV1::Retry(prepared));
        }
        Ok(CrossDomainJournalRecoveryV1::Diverged(
            CrossDomainJournalOutcomeUnknownV1 { prepared },
        ))
    }

    fn validate_snapshot(
        &mut self,
        snapshot: &CrossDomainJournalSnapshotV1,
    ) -> Result<(), ProtectedDomainJournalErrorV1> {
        let current = self.snapshot()?;
        if !Arc::ptr_eq(&snapshot.instance, &self.instance)
            || snapshot.sequence != current.sequence
            || snapshot.root != current.root
        {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        Ok(())
    }

    fn applied(
        &mut self,
        prepared: PreparedCrossDomainJournalTransactionV1,
    ) -> Result<AppliedCrossDomainJournalTransactionV1, ProtectedDomainJournalErrorV1> {
        if prepared.successors.len() != prepared.transaction.records().len() {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let snapshot = self.snapshot()?;
        let mut records = Vec::with_capacity(prepared.successors.len());
        for (successor, encoded) in prepared.successors.into_iter().zip(prepared.after) {
            let role = successor.role();
            let phase = successor.phase();
            let postcommit = CrossDomainPostcommitRecordV1 {
                namespace: successor.namespace(),
                role,
                phase,
                transaction_phase: ProtectedReducerPhaseV1::Observed,
                successor,
                encoded,
            };
            records.push(postcommit);
        }
        let transaction_phase = aggregate_cross_phase(
            &records
                .iter()
                .map(|record| record.phase)
                .collect::<Vec<_>>(),
        );
        for record in &mut records {
            record.transaction_phase = transaction_phase;
        }
        Ok(AppliedCrossDomainJournalTransactionV1 {
            transaction: prepared.digest,
            snapshot: snapshot.clone(),
            capability: Some(CrossDomainPostcommitCapabilityV1 {
                instance: Arc::clone(&self.instance),
                transaction: prepared.digest,
                set_digest: prepared.set_digest,
                sequence: snapshot.sequence,
                root: snapshot.root,
                records,
            }),
        })
    }

    fn revalidate_evidence(&mut self) -> Result<(), ProtectedDomainJournalErrorV1> {
        self.environment_evidence_owner
            .revalidate_pinned()
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        self.git_evidence_owner
            .revalidate_pinned()
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)
    }
}

pub(crate) fn source_domain_journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 4 * 1024 * 1024 * 1024,
        maximum_record_bytes: 256 * 1024 * 1024,
        maximum_key_bytes: 512,
        maximum_records_per_transaction: 64,
        maximum_transaction_bytes: 1024 * 1024 * 1024,
        maximum_transactions: 1_000_000,
        maximum_materialized_bytes: 2 * 1024 * 1024 * 1024,
        maximum_materialized_records: MAXIMUM_CROSS_DOMAIN_REPLAY_MEMBERS,
    }
}

fn validate_source_domain_projections(
    journal: &Journal,
    validators: &CrossDomainReplayValidatorsV1,
) -> Result<(), ProtectedDomainJournalErrorV1> {
    replay_projection::<GitProtectedJournalSchemaV1>(journal, &validators.git)?;
    replay_projection::<EnvironmentProtectedJournalSchemaV1>(journal, &validators.environment)?;
    replay_projection::<HierarchyProtectedJournalSchemaV1>(journal, &validators.hierarchy)?;
    replay_projection::<LifecycleProtectedJournalSchemaV1>(journal, &validators.lifecycle)?;
    Ok(())
}

fn decode_cross_domain_member(
    namespace: RecordNamespace,
    key_bytes: &[u8],
    value: &[u8],
    validators: &CrossDomainReplayValidatorsV1,
) -> Result<Option<CrossDomainDurableMemberV1>, ProtectedDomainJournalErrorV1> {
    if key_bytes.starts_with(GitProtectedJournalSchemaV1::KEY_PREFIX) {
        let key = ProtectedDomainKeyV1::<GitProtectedJournalSchemaV1>::decode(key_bytes)?;
        if namespace != GitProtectedJournalSchemaV1::namespace(key.kind()) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let member = decode_durable_member(key, value, &validators.git)?;
        return Ok(Some(cross_member(
            namespace,
            member,
            CrossDomainJournalSuccessorV1::Git,
        )));
    }
    if key_bytes.starts_with(EnvironmentProtectedJournalSchemaV1::KEY_PREFIX) {
        let key = ProtectedDomainKeyV1::<EnvironmentProtectedJournalSchemaV1>::decode(key_bytes)?;
        if namespace != EnvironmentProtectedJournalSchemaV1::namespace(key.kind()) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let member = decode_durable_member(key, value, &validators.environment)?;
        return Ok(Some(cross_member(
            namespace,
            member,
            CrossDomainJournalSuccessorV1::Environment,
        )));
    }
    if key_bytes.starts_with(HierarchyProtectedJournalSchemaV1::KEY_PREFIX) {
        let key = ProtectedDomainKeyV1::<HierarchyProtectedJournalSchemaV1>::decode(key_bytes)?;
        if namespace != HierarchyProtectedJournalSchemaV1::namespace(key.kind()) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let member = decode_durable_member(key, value, &validators.hierarchy)?;
        return Ok(Some(cross_member(
            namespace,
            member,
            CrossDomainJournalSuccessorV1::Hierarchy,
        )));
    }
    if key_bytes.starts_with(LifecycleProtectedJournalSchemaV1::KEY_PREFIX) {
        let key = ProtectedDomainKeyV1::<LifecycleProtectedJournalSchemaV1>::decode(key_bytes)?;
        if namespace != LifecycleProtectedJournalSchemaV1::namespace(key.kind()) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let member = decode_durable_member(key, value, &validators.lifecycle)?;
        return Ok(Some(cross_member(
            namespace,
            member,
            CrossDomainJournalSuccessorV1::Lifecycle,
        )));
    }
    Ok(None)
}

fn cross_member<S: ProtectedDomainSchemaV1>(
    namespace: RecordNamespace,
    member: DurableDomainMemberV1<S>,
    wrap: impl FnOnce(
        super::protected_journal_adapter::ProtectedDomainEnvelopeV1<S>,
    ) -> CrossDomainJournalSuccessorV1,
) -> CrossDomainDurableMemberV1 {
    CrossDomainDurableMemberV1 {
        transaction_id: member.transaction_id,
        member_index: member.member_index,
        member_count: member.member_count,
        set_digest: member.set_digest,
        namespace,
        successor: wrap(member.envelope),
        encoded: member.encoded,
    }
}

fn cross_values_match(
    journal: &Journal,
    prepared: &PreparedCrossDomainJournalTransactionV1,
    after: bool,
) -> bool {
    let records = prepared.transaction.records();
    if records.len() != prepared.before.len() || records.len() != prepared.after.len() {
        return false;
    }
    records
        .iter()
        .zip(prepared.before.iter().zip(&prepared.after))
        .all(|(record, (before, after_value))| {
            let expected = if after {
                Some(after_value.as_slice())
            } else {
                before.as_deref()
            };
            journal.get(record.namespace(), record.key()) == expected
        })
}

fn cross_transaction_set_digest(
    transaction_id: [u8; 16],
    successors: &[CrossDomainJournalSuccessorV1],
) -> ObjectDigest {
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.cross-domain-journal.transaction-set.v1\0")
        .chain_update(transaction_id)
        .chain_update((successors.len() as u64).to_be_bytes());
    for successor in successors {
        hasher = hasher
            .chain_update([successor.domain_order()])
            .chain_update([successor.namespace() as u8])
            .chain_update((successor.key().len() as u32).to_be_bytes())
            .chain_update(successor.key())
            .chain_update(successor.digest().as_bytes());
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn semantic_tuple_from_successor(
    successor: &CrossDomainJournalSuccessorV1,
) -> Result<CrossDomainSemanticTupleV1, ProtectedDomainJournalErrorV1> {
    let identity = successor.identity();
    let project: [u8; 16] = identity
        .get(..16)
        .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?
        .try_into()
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    let subject: [u8; 16] = identity
        .get(16..32)
        .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?
        .try_into()
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    CrossDomainSemanticTupleV1::new(
        ProjectId::from_bytes(project),
        ResourceId::from_bytes(subject),
    )
}

fn common_subject_digest(tuple: CrossDomainSemanticTupleV1) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.protected-journal.subject.v1\0")
            .chain_update(tuple.bytes())
            .finalize()
            .into(),
    )
}

fn aggregate_cross_phase(phases: &[ProtectedReducerPhaseV1]) -> ProtectedReducerPhaseV1 {
    if phases.contains(&ProtectedReducerPhaseV1::Superseded) {
        ProtectedReducerPhaseV1::Superseded
    } else if phases.contains(&ProtectedReducerPhaseV1::Prepared) {
        ProtectedReducerPhaseV1::Prepared
    } else if phases.contains(&ProtectedReducerPhaseV1::Terminal) {
        ProtectedReducerPhaseV1::Terminal
    } else {
        ProtectedReducerPhaseV1::Observed
    }
}

fn complete_materialized_root(journal: &Journal) -> ObjectDigest {
    let record_count = journal.all_records().count();
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.cross-domain-journal.materialization.v1\0")
        .chain_update((record_count as u64).to_be_bytes());
    for (namespace, key, value) in journal.all_records() {
        hasher = hasher
            .chain_update([namespace as u8])
            .chain_update((key.len() as u32).to_be_bytes())
            .chain_update(key)
            .chain_update((value.len() as u64).to_be_bytes())
            .chain_update(value);
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn cross_transaction_digest(transaction: &JournalTransaction) -> ObjectDigest {
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.cross-domain-journal.transaction.v1\0")
        .chain_update(transaction.id())
        .chain_update((transaction.records().len() as u64).to_be_bytes());
    for record in transaction.records() {
        hasher = hasher
            .chain_update([record.namespace() as u8])
            .chain_update((record.key().len() as u32).to_be_bytes())
            .chain_update(record.key());
        if let Some(value) = record.value() {
            hasher = hasher
                .chain_update((value.len() as u64).to_be_bytes())
                .chain_update(value);
        }
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}
