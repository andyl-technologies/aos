//! Dormant protected-journal adapter for hierarchy state and realization.
//!
//! The adapter stores only canonical controller facts. No type in this module
//! opens a broker, performs a mount, publishes a route, or activates a service.

use std::collections::BTreeSet;

use aos_sandbox_core::{ObjectDigest, ProjectId, ResourceId, Revision, SandboxId};

use crate::journal::{Journal, RecordNamespace};
use crate::lifecycle::protected_journal_adapter::{
    AppliedDomainTransactionV1, DomainCommitOutcomeV1, DomainOutcomeUnknownV1,
    DomainPostcommitCapabilityV1, DomainRecoveryV1, PreparedDomainTransactionV1,
    ProtectedDomainEnvelopeV1, ProtectedDomainJournalErrorV1, ProtectedDomainJournalV1,
    ProtectedDomainKeyV1, ProtectedDomainProjectionV1, ProtectedDomainReplayPhaseV1,
    ProtectedDomainReplayTransactionV1, ProtectedDomainSchemaV1, ProtectedDomainSnapshotV1,
    ProtectedRecordRoleV1, ProtectedReducerPhaseV1, ReplayedDomainPostcommitV1,
    ValidatedDomainPostcommitV1, decode_reducer_payload_with_validator,
    encode_reducer_payload_with_validator, protected_current_record_candidates_v1,
};
use crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;

use super::artifact_codec::{
    decode_detach_progress_v1, decode_protected_detach_head_v1,
    decode_protected_realization_head_v1, decode_protected_transaction_head_v1,
    decode_realization_plan_v1, decode_realization_progress_v1,
    decode_realization_transaction_state_v1, encode_detach_progress_v1,
    encode_protected_detach_head_v1, encode_protected_realization_head_v1,
    encode_protected_transaction_head_v1, encode_realization_plan_v1,
    encode_realization_progress_v1, encode_realization_transaction_state_v1,
};
use super::codec::{
    decode_history_record_v1, decode_history_v1, decode_tree_v1, encode_history_record_v1,
    encode_history_v1, encode_tree_v1, tree_commitment_v1,
};
use super::evidence::{
    CurrentAssignmentEvidenceV1, CurrentLiveInspectionObservationV1,
    CurrentSlotInventoryEvidenceV1, RetainedSnapshotManifestV1, RetainedViewSourceEvidenceV1,
    VerifiedAttachmentAuthorityV1, VerifiedDetachAuthorityV1, VerifiedDetachCompletionV1,
    VerifiedInspectionGrantV1, VerifiedRealizationTransactionCompletionV1,
};
use super::graph::SandboxTreeV1;
use super::history::{HierarchyHistoryRecordV1, HierarchyHistoryV1};
use super::protected_evidence::{
    HierarchyProtectedEvidenceV1, decode_hierarchy_protected_evidence_v1,
    encode_hierarchy_protected_evidence_v1,
};
use super::realizer::ViewRealizationPlanV1;
use super::recovery::{
    DurableDetachProgressV1, DurableRealizationProgressV1, DurableRealizationTransactionV1,
    RebootRealizationInventoryV1, RetainedDetachHeadV1, RetainedRealizationHeadV1,
    RetainedRealizationTransactionHeadV1, VerifiedDetachRebootInventoryV1,
    VerifiedPreparedRealizationAuthorityV1, VerifiedPublishedRollbackAuthorityV1,
    VerifiedSnapshotRecoveryAuthorityV1, VerifiedStageTransitionV1,
};

const MAXIMUM_PROTECTED_CURRENT_HEADS: usize = 262_144;

/// Selects one closed hierarchy journal family.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum HierarchyProtectedRecordKindV1 {
    /// Stores the current canonical sandbox tree and attenuation state.
    Tree = 1,
    /// Stores a durable hierarchy-history head.
    History = 2,
    /// Stores a prepared or observed realization transaction.
    RealizationEffect = 3,
    /// Stores a prepared or observed detach transaction.
    DetachEffect = 4,
    /// Publishes a verified hierarchy replay checkpoint without compaction authority.
    Checkpoint = 5,
    /// Stores one opaque fact recovered only through protected-current replay.
    Evidence = 6,
}

/// Defines the closed hierarchy adapter schema.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct HierarchyProtectedJournalSchemaV1;

/// Authenticates retained heads against typed protected-current evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HierarchyProtectedReplayValidatorV1 {
    realization_heads: Vec<RetainedRealizationHeadV1>,
    detach_heads: Vec<RetainedDetachHeadV1>,
    transaction_heads: Vec<RetainedRealizationTransactionHeadV1>,
}

impl HierarchyProtectedReplayValidatorV1 {
    /// Constructs replay evidence only from already typed retained heads.
    pub(crate) fn from_protected_current_heads(
        realization_heads: &[RetainedRealizationHeadV1],
        detach_heads: &[RetainedDetachHeadV1],
        transaction_heads: &[RetainedRealizationTransactionHeadV1],
    ) -> Result<Self, HierarchyProtectedJournalErrorV1> {
        let realization_count = realization_heads.len();
        let detach_count = detach_heads.len();
        let transaction_count = transaction_heads.len();
        if realization_count
            .checked_add(detach_count)
            .and_then(|count| count.checked_add(transaction_count))
            .is_none_or(|count| count > MAXIMUM_PROTECTED_CURRENT_HEADS)
        {
            return Err(HierarchyProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let realization_commitments = realization_heads
            .iter()
            .map(|head| head.protected_head_commitment())
            .collect::<BTreeSet<_>>();
        let detach_commitments = detach_heads
            .iter()
            .map(|head| head.protected_head_commitment())
            .collect::<BTreeSet<_>>();
        let transaction_commitments = transaction_heads
            .iter()
            .map(|head| head.protected_head_commitment())
            .collect::<BTreeSet<_>>();
        let all_commitments = realization_commitments
            .iter()
            .chain(&detach_commitments)
            .chain(&transaction_commitments)
            .copied()
            .collect::<BTreeSet<_>>();
        let exact = realization_commitments.len() == realization_count
            && detach_commitments.len() == detach_count
            && transaction_commitments.len() == transaction_count
            && all_commitments.len() == realization_count + detach_count + transaction_count
            && all_commitments
                .iter()
                .all(|digest| digest.as_bytes() != &[0; 32]);
        if !exact {
            return Err(HierarchyProtectedJournalErrorV1::NonCanonicalRecord);
        }
        Ok(Self {
            realization_heads: realization_heads.to_vec(),
            detach_heads: detach_heads.to_vec(),
            transaction_heads: transaction_heads.to_vec(),
        })
    }

    fn accepts_realization(&self, head: RetainedRealizationHeadV1) -> bool {
        self.realization_heads.contains(&head)
    }

    fn accepts_detach(&self, head: RetainedDetachHeadV1) -> bool {
        self.detach_heads.contains(&head)
    }

    fn accepts_transaction(&self, head: RetainedRealizationTransactionHeadV1) -> bool {
        self.transaction_heads.contains(&head)
    }
}

impl ProtectedDomainSchemaV1 for HierarchyProtectedJournalSchemaV1 {
    type Kind = HierarchyProtectedRecordKindV1;
    type ReplayValidator = HierarchyProtectedReplayValidatorV1;

    const MAGIC: [u8; 8] = *b"AOSHTJ01";
    const HASH_DOMAIN: &'static [u8] = b"aos.sandbox.hierarchy.protected-journal.v1\0";
    const KEY_PREFIX: &'static [u8] = b"\0aos-hierarchy-v1\0";
    const MAXIMUM_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;

    fn kind_code(kind: Self::Kind) -> u8 {
        kind as u8
    }

    fn kind_from_code(code: u8) -> Option<Self::Kind> {
        match code {
            1 => Some(Self::Kind::Tree),
            2 => Some(Self::Kind::History),
            3 => Some(Self::Kind::RealizationEffect),
            4 => Some(Self::Kind::DetachEffect),
            5 => Some(Self::Kind::Checkpoint),
            6 => Some(Self::Kind::Evidence),
            _ => None,
        }
    }

    fn namespace(kind: Self::Kind) -> RecordNamespace {
        match kind {
            Self::Kind::Tree | Self::Kind::History | Self::Kind::Evidence => {
                RecordNamespace::DesiredState
            }
            Self::Kind::RealizationEffect | Self::Kind::DetachEffect => RecordNamespace::Effect,
            Self::Kind::Checkpoint => RecordNamespace::RuntimeGeneration,
        }
    }

    fn order(kind: Self::Kind) -> u8 {
        match kind {
            Self::Kind::Tree => 1,
            Self::Kind::History => 2,
            Self::Kind::RealizationEffect => 3,
            Self::Kind::DetachEffect => 4,
            Self::Kind::Checkpoint => 5,
            Self::Kind::Evidence => 6,
        }
    }

    fn role(kind: Self::Kind) -> ProtectedRecordRoleV1 {
        match kind {
            Self::Kind::Tree | Self::Kind::History | Self::Kind::Evidence => {
                ProtectedRecordRoleV1::State
            }
            Self::Kind::RealizationEffect | Self::Kind::DetachEffect => {
                ProtectedRecordRoleV1::Effect
            }
            Self::Kind::Checkpoint => ProtectedRecordRoleV1::Publication,
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
        if identity.len() != 48
            || body.len() < 12
            || (kind != Self::Kind::Evidence && body[8..12] != [0, 1, 0, 0])
        {
            return None;
        }
        match kind {
            Self::Kind::Tree
                if decode_tree_v1(body)
                    .and_then(|decoded| encode_tree_v1(&decoded))
                    .is_ok_and(|encoded| encoded == body)
                    && body.get(12..28) == identity.get(..16)
                    && identity.get(16..32) == identity.get(..16)
                    && identity.get(32..48) == identity.get(..16) =>
            {
                Some(ProtectedReducerPhaseV1::Observed)
            }
            Self::Kind::History if canonical_history_body(body, identity) => {
                Some(ProtectedReducerPhaseV1::Observed)
            }
            Self::Kind::RealizationEffect | Self::Kind::DetachEffect => {
                canonical_hierarchy_artifact_phase(validator, kind, body, identity)
            }
            Self::Kind::Evidence => decode_hierarchy_protected_evidence_v1(body)
                .filter(|evidence| evidence.identity().as_slice() == identity)
                .map(|_| ProtectedReducerPhaseV1::Observed),
            Self::Kind::Tree | Self::Kind::History | Self::Kind::Checkpoint => None,
        }
    }

    fn semantic_tuple(kind: Self::Kind, identity: &[u8], body: &[u8]) -> Option<[u8; 32]> {
        let magic = body.get(..8)?;
        let has_one_subject = match kind {
            Self::Kind::History => magic == b"AOSHHI01",
            Self::Kind::RealizationEffect => magic == b"AOSHRG01" || magic == b"AOSHRH01",
            Self::Kind::DetachEffect => magic == b"AOSHDG01" || magic == b"AOSHDH01",
            Self::Kind::Tree | Self::Kind::Checkpoint | Self::Kind::Evidence => false,
        };
        if !has_one_subject {
            return None;
        }
        identity.get(..32)?.try_into().ok()
    }

    fn validates_identity(kind: Self::Kind, identity: &[u8]) -> bool {
        identity.len() == 48
            && identity
                .chunks_exact(16)
                .all(|component| component != [0; 16])
            && (!matches!(kind, Self::Kind::Tree | Self::Kind::Checkpoint)
                || (identity[..16] == identity[16..32] && identity[..16] == identity[32..48]))
    }
}

fn canonical_history_body(body: &[u8], identity: &[u8]) -> bool {
    if body.starts_with(b"AOSHHI01") {
        return decode_history_record_v1(body)
            .and_then(encode_history_record_v1)
            .is_ok_and(|encoded| encoded.as_slice() == body)
            && body.get(12..28) == identity.get(..16)
            && body.get(36..52) == identity.get(16..32)
            && body.get(52..68) == identity.get(32..48);
    }
    if !body.starts_with(b"AOSHLG01")
        || !decode_history_v1(body)
            .and_then(|decoded| encode_history_v1(&decoded))
            .is_ok_and(|encoded| encoded == body)
        || body.get(12..28) != identity.get(..16)
    {
        return false;
    }
    let count = body
        .get(28..32)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_be_bytes)
        .and_then(|value| usize::try_from(value).ok());
    match count {
        Some(0) => {
            identity.get(16..32) == identity.get(..16) && identity.get(32..48) == identity.get(..16)
        }
        Some(count) => {
            let Some(start) = count
                .checked_sub(1)
                .and_then(|index| index.checked_mul(262))
                .and_then(|offset| 32_usize.checked_add(offset))
            else {
                return false;
            };
            body.get(start + 36..start + 52) == identity.get(16..32)
                && body.get(start + 52..start + 68) == identity.get(32..48)
        }
        None => false,
    }
}

fn canonical_hierarchy_artifact_phase(
    validator: &HierarchyProtectedReplayValidatorV1,
    kind: HierarchyProtectedRecordKindV1,
    body: &[u8],
    identity: &[u8],
) -> Option<ProtectedReducerPhaseV1> {
    let magic = body.get(..8)?;
    match kind {
        HierarchyProtectedRecordKindV1::RealizationEffect if magic == b"AOSHRP01" => {
            let plan = decode_realization_plan_v1(body).ok()?;
            (plan.project().as_bytes() == identity.get(..16)?
                && plan.plan_commitment().as_bytes() == identity.get(16..48)?)
            .then_some(ProtectedReducerPhaseV1::Prepared)
        }
        HierarchyProtectedRecordKindV1::RealizationEffect if magic == b"AOSHRG01" => {
            let progress = decode_realization_progress_v1(body).ok()?;
            if progress.project().as_bytes() != identity.get(..16)?
                || progress.attachment().as_bytes() != identity.get(16..32)?
                || progress.recipe_commitment().as_bytes().get(..16)? != identity.get(32..48)?
            {
                return None;
            }
            match progress.current_stage()? {
                super::realizer::RealizationStageV1::Planned
                | super::realizer::RealizationStageV1::Prepared => {
                    Some(ProtectedReducerPhaseV1::Prepared)
                }
                super::realizer::RealizationStageV1::Published
                | super::realizer::RealizationStageV1::Verified
                | super::realizer::RealizationStageV1::Draining => {
                    Some(ProtectedReducerPhaseV1::Observed)
                }
                super::realizer::RealizationStageV1::Reaped
                | super::realizer::RealizationStageV1::Aborted
                | super::realizer::RealizationStageV1::Faulted => {
                    Some(ProtectedReducerPhaseV1::Terminal)
                }
            }
        }
        HierarchyProtectedRecordKindV1::DetachEffect if magic == b"AOSHDG01" => {
            let progress = decode_detach_progress_v1(body).ok()?;
            if progress.project().as_bytes() != identity.get(..16)?
                || progress.attachment().as_bytes() != identity.get(16..32)?
                || progress.detach_commitment().as_bytes().get(..16)? != identity.get(32..48)?
            {
                return None;
            }
            match progress.current_stage()? {
                super::recovery::DetachStageV1::Planned => Some(ProtectedReducerPhaseV1::Prepared),
                super::recovery::DetachStageV1::Detached
                | super::recovery::DetachStageV1::Verified => {
                    Some(ProtectedReducerPhaseV1::Observed)
                }
                super::recovery::DetachStageV1::Completed
                | super::recovery::DetachStageV1::Aborted
                | super::recovery::DetachStageV1::Faulted => {
                    Some(ProtectedReducerPhaseV1::Terminal)
                }
            }
        }
        HierarchyProtectedRecordKindV1::RealizationEffect if magic == b"AOSHRH01" => {
            let head = decode_protected_realization_head_v1(body).ok()?;
            if head.project().as_bytes() != identity.get(..16)?
                || head.attachment().as_bytes() != identity.get(16..32)?
                || head.recipe_commitment().as_bytes().get(..16)? != identity.get(32..48)?
                || !validator.accepts_realization(head)
            {
                return None;
            }
            match head.stage() {
                super::realizer::RealizationStageV1::Planned
                | super::realizer::RealizationStageV1::Prepared => {
                    Some(ProtectedReducerPhaseV1::Prepared)
                }
                super::realizer::RealizationStageV1::Published
                | super::realizer::RealizationStageV1::Verified
                | super::realizer::RealizationStageV1::Draining => {
                    Some(ProtectedReducerPhaseV1::Observed)
                }
                super::realizer::RealizationStageV1::Reaped
                | super::realizer::RealizationStageV1::Aborted
                | super::realizer::RealizationStageV1::Faulted => {
                    Some(ProtectedReducerPhaseV1::Terminal)
                }
            }
        }
        HierarchyProtectedRecordKindV1::DetachEffect if magic == b"AOSHDH01" => {
            let head = decode_protected_detach_head_v1(body).ok()?;
            (head.project().as_bytes() == identity.get(..16)?
                && head.attachment().as_bytes() == identity.get(16..32)?
                && head.detach_commitment().as_bytes().get(..16)? == identity.get(32..48)?
                && validator.accepts_detach(head))
            .then_some(ProtectedReducerPhaseV1::Terminal)
        }
        HierarchyProtectedRecordKindV1::RealizationEffect if magic == b"AOSHTS01" => {
            let state = decode_realization_transaction_state_v1(body).ok()?;
            if state.project().as_bytes() != identity.get(..16)?
                || state.plan_commitment().as_bytes() != identity.get(16..48)?
            {
                return None;
            }
            match state.actions().last().map(|action| action.outcome()) {
                None => Some(ProtectedReducerPhaseV1::Prepared),
                Some(super::recovery::TransactionActionOutcomeV1::Completed) => {
                    Some(ProtectedReducerPhaseV1::Observed)
                }
                Some(
                    super::recovery::TransactionActionOutcomeV1::Aborted
                    | super::recovery::TransactionActionOutcomeV1::Faulted,
                ) => Some(ProtectedReducerPhaseV1::Terminal),
            }
        }
        HierarchyProtectedRecordKindV1::RealizationEffect if magic == b"AOSHTH01" => {
            let head = decode_protected_transaction_head_v1(body).ok()?;
            (head.project().as_bytes() == identity.get(..16)?
                && head.plan_commitment().as_bytes() == identity.get(16..48)?
                && validator.accepts_transaction(head))
            .then_some(ProtectedReducerPhaseV1::Terminal)
        }
        _ => None,
    }
}

/// Selects one typed canonical hierarchy reducer record.
pub(crate) enum HierarchyReducerRecordV1<'record> {
    /// Encodes one complete project tree.
    Tree(&'record SandboxTreeV1),
    /// Encodes one fixed hierarchy transition.
    HistoryRecord(HierarchyHistoryRecordV1),
    /// Encodes one complete hierarchy history.
    History(&'record HierarchyHistoryV1),
    /// Encodes one prepared multi-action realization plan.
    RealizationPlan(&'record ViewRealizationPlanV1),
    /// Encodes one observed realization progress record.
    RealizationProgress(&'record DurableRealizationProgressV1),
    /// Encodes one observed detach progress record.
    DetachProgress(&'record DurableDetachProgressV1),
    /// Encodes one terminal multi-action transaction state.
    Transaction(&'record DurableRealizationTransactionV1),
    /// Encodes one terminal retained realization head.
    RealizationHead(RetainedRealizationHeadV1),
    /// Encodes one terminal retained detach head.
    DetachHead(RetainedDetachHeadV1),
    /// Encodes one terminal retained transaction head.
    TransactionHead(RetainedRealizationTransactionHeadV1),
    /// Encodes one evidence value previously minted by this protected owner.
    Evidence(&'record HierarchyProtectedEvidenceV1),
}

/// Canonical hierarchy shared-journal key.
pub type HierarchyProtectedJournalKeyV1 = ProtectedDomainKeyV1<HierarchyProtectedJournalSchemaV1>;
/// Canonical hierarchy value and predecessor CAS.
pub type HierarchyProtectedJournalEnvelopeV1 =
    ProtectedDomainEnvelopeV1<HierarchyProtectedJournalSchemaV1>;
/// Sealed hierarchy journal currentness snapshot.
pub type HierarchyProtectedJournalSnapshotV1 =
    ProtectedDomainSnapshotV1<HierarchyProtectedJournalSchemaV1>;
/// Replayed materialized hierarchy projection.
pub type HierarchyProtectedJournalProjectionV1 =
    ProtectedDomainProjectionV1<HierarchyProtectedJournalSchemaV1>;
/// Hierarchy transaction group reconstructed during bounded cold replay.
pub type HierarchyJournalReplayTransactionV1 =
    ProtectedDomainReplayTransactionV1<HierarchyProtectedJournalSchemaV1>;
/// Fail-closed hierarchy cold-replay phase.
pub type HierarchyJournalReplayPhaseV1 = ProtectedDomainReplayPhaseV1;
/// Semantic phase decoded from one hierarchy reducer body.
pub type HierarchyReducerPhaseV1 = ProtectedReducerPhaseV1;
/// Exact prepared hierarchy transaction.
pub type PreparedHierarchyJournalTransactionV1 =
    PreparedDomainTransactionV1<HierarchyProtectedJournalSchemaV1>;
/// Exact ambiguous hierarchy transaction recovery token.
pub type HierarchyJournalOutcomeUnknownV1 =
    DomainOutcomeUnknownV1<HierarchyProtectedJournalSchemaV1>;
/// Hierarchy transaction commit outcome.
pub type HierarchyJournalCommitOutcomeV1 = DomainCommitOutcomeV1<HierarchyProtectedJournalSchemaV1>;
/// Hierarchy outcome-unknown recovery classification.
pub type HierarchyJournalRecoveryV1 = DomainRecoveryV1<HierarchyProtectedJournalSchemaV1>;
/// Exact-readback hierarchy transaction result.
pub type AppliedHierarchyJournalTransactionV1 =
    AppliedDomainTransactionV1<HierarchyProtectedJournalSchemaV1>;
/// Composite postcommit hierarchy transaction authority.
pub type HierarchyPostcommitCapabilityV1 =
    DomainPostcommitCapabilityV1<HierarchyProtectedJournalSchemaV1>;
/// Current, consumed hierarchy transaction authority.
pub type ValidatedHierarchyPostcommitV1<'current> =
    ValidatedDomainPostcommitV1<'current, HierarchyProtectedJournalSchemaV1>;
/// Current hierarchy postcommit authority reconstructed during cold replay.
pub type ReplayedHierarchyPostcommitV1 =
    ReplayedDomainPostcommitV1<HierarchyProtectedJournalSchemaV1>;
/// Protected hierarchy journal owner.
pub type HierarchyProtectedJournalV1<'journal> =
    ProtectedDomainJournalV1<'journal, HierarchyProtectedJournalSchemaV1>;
/// Hierarchy adapter validation or durability failure.
pub type HierarchyProtectedJournalErrorV1 = ProtectedDomainJournalErrorV1;

/// Constructs the canonical key for a project sandbox's hierarchy record.
///
/// # Errors
///
/// Returns [`HierarchyProtectedJournalErrorV1`] only if the fixed typed
/// identity cannot be represented by the bounded key schema.
pub fn hierarchy_protected_key_v1(
    kind: HierarchyProtectedRecordKindV1,
    project: ProjectId,
    sandbox: SandboxId,
    subject: ResourceId,
) -> Result<HierarchyProtectedJournalKeyV1, HierarchyProtectedJournalErrorV1> {
    if project.as_bytes() == &[0; 16]
        || sandbox.as_bytes() == &[0; 16]
        || subject.as_bytes() == &[0; 16]
    {
        return Err(HierarchyProtectedJournalErrorV1::NonCanonicalRecord);
    }
    let mut identity = Vec::with_capacity(48);
    identity.extend_from_slice(project.as_bytes());
    identity.extend_from_slice(sandbox.as_bytes());
    identity.extend_from_slice(subject.as_bytes());
    HierarchyProtectedJournalKeyV1::new(kind, identity)
}

/// Claims the dormant hierarchy adapter over an already protected-open journal.
pub(crate) fn claim_hierarchy_protected_journal_v1(
    journal: &mut Journal,
    validator: HierarchyProtectedReplayValidatorV1,
) -> Result<HierarchyProtectedJournalV1<'_>, HierarchyProtectedJournalErrorV1> {
    HierarchyProtectedJournalV1::claim_with_validator(journal, validator)
}

/// Owns the dormant hierarchy adapter and its exact protected-current replay
/// validator.
pub struct HierarchyProtectedJournalOwnerV1<'journal> {
    journal: HierarchyProtectedJournalV1<'journal>,
    validator: HierarchyProtectedReplayValidatorV1,
}

/// Borrows one opaque evidence value at the exact owner snapshot which minted
/// it.
#[must_use = "protected-current evidence must remain tied to its owner borrow"]
pub struct CurrentHierarchyProtectedEvidenceV1<'current, T> {
    evidence: T,
    _current: std::marker::PhantomData<&'current ()>,
}

/// Identifies one project tree read from the current protected source-domain owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CurrentProjectAncestryHeadV1 {
    project: ProjectId,
    record_revision: u64,
    tree_generation: Revision,
    tree_commitment: ObjectDigest,
    head: ObjectDigest,
}

impl CurrentProjectAncestryHeadV1 {
    /// Returns the project selected by the protected hierarchy key and tree.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the protected journal record's CAS revision.
    #[must_use]
    pub const fn record_revision(self) -> u64 {
        self.record_revision
    }

    /// Returns the tree's independently validated logical generation.
    #[must_use]
    pub const fn tree_generation(self) -> Revision {
        self.tree_generation
    }

    /// Returns the canonical project tree commitment.
    #[must_use]
    pub const fn tree_commitment(self) -> ObjectDigest {
        self.tree_commitment
    }

    /// Returns the exact protected hierarchy envelope head used for CAS.
    #[must_use]
    pub const fn head(self) -> ObjectDigest {
        self.head
    }
}

impl<T> CurrentHierarchyProtectedEvidenceV1<'_, T> {
    /// Borrows the evidence while its protected-current owner remains frozen.
    #[must_use]
    pub const fn evidence(&self) -> &T {
        &self.evidence
    }

    pub(super) fn into_evidence(self) -> T {
        self.evidence
    }
}

impl<'journal> HierarchyProtectedJournalOwnerV1<'journal> {
    /// Cold-replays exact protected records and claims the dormant adapter.
    ///
    /// The provisional head decoder grants no authority. Ordinary typed replay
    /// must subsequently authenticate every complete retained head against the
    /// candidate set before this owner is returned.
    ///
    /// # Errors
    ///
    /// Returns [`HierarchyProtectedJournalErrorV1`] for malformed framing,
    /// duplicate head commitments, invalid hierarchy bodies, or an unprotected
    /// or unhealthy journal.
    pub fn claim(
        journal_owner: &'journal mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<Self, HierarchyProtectedJournalErrorV1> {
        let journal = journal_owner.journal();
        let validator = recover_hierarchy_replay_validator_v1(journal)?;
        let claimed = claim_hierarchy_protected_journal_v1(journal, validator.clone())?;
        claimed.replay()?;
        Ok(Self {
            journal: claimed,
            validator,
        })
    }

    /// Replays the complete current hierarchy projection.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained fixed journal is unhealthy or any
    /// current record fails full typed validation.
    pub fn replay(
        &self,
    ) -> Result<HierarchyProtectedJournalProjectionV1, HierarchyProtectedJournalErrorV1> {
        self.journal.replay()
    }

    /// Reads the current project tree head under the source-domain writer lock.
    ///
    /// This is a source observation, not standalone policy publication
    /// authority. A cross-owner issuer must keep this owner borrowed through
    /// its root binding commit and effect handoff.
    ///
    /// # Errors
    ///
    /// Rejects invalid project identities, malformed current hierarchy
    /// records, or failed complete protected replay.
    pub fn project_ancestry_head(
        &self,
        project: ProjectId,
    ) -> Result<
        Option<CurrentHierarchyProtectedEvidenceV1<'_, CurrentProjectAncestryHeadV1>>,
        HierarchyProtectedJournalErrorV1,
    > {
        if project.as_bytes() == &[0; 16] {
            return Err(HierarchyProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let mut identity = Vec::with_capacity(48);
        for _ in 0..3 {
            identity.extend_from_slice(project.as_bytes());
        }
        let key =
            HierarchyProtectedJournalKeyV1::new(HierarchyProtectedRecordKindV1::Tree, identity)?;
        let projection = self.journal.replay()?;
        let Some(record) = projection
            .records()
            .iter()
            .find(|record| record.key() == &key)
        else {
            return Ok(None);
        };
        let payload = decode_reducer_payload_with_validator::<HierarchyProtectedJournalSchemaV1>(
            &key,
            record.payload(),
            &self.validator,
        )?;
        let tree = decode_tree_v1(payload.body())
            .map_err(|_| HierarchyProtectedJournalErrorV1::NonCanonicalRecord)?;
        if tree.project() != project {
            return Err(HierarchyProtectedJournalErrorV1::NonCanonicalRecord);
        }
        let tree_commitment = tree_commitment_v1(&tree)
            .map_err(|_| HierarchyProtectedJournalErrorV1::NonCanonicalRecord)?;
        Ok(Some(current(CurrentProjectAncestryHeadV1 {
            project,
            record_revision: record.revision(),
            tree_generation: tree.tree_generation(),
            tree_commitment,
            head: record.digest(),
        })))
    }

    /// Mints a descendant-inspection grant from one exact current record.
    ///
    /// # Errors
    ///
    /// Returns an error when protected-current replay or evidence decoding fails.
    pub fn inspection_grant(
        &self,
        key: &HierarchyProtectedJournalKeyV1,
    ) -> Result<
        Option<CurrentHierarchyProtectedEvidenceV1<'_, VerifiedInspectionGrantV1>>,
        HierarchyProtectedJournalErrorV1,
    > {
        self.current_evidence(key).map(|value| match value {
            Some(HierarchyProtectedEvidenceV1::InspectionGrant(value)) => Some(current(value)),
            _ => None,
        })
    }

    /// Mints a retained snapshot manifest from one exact current record.
    ///
    /// # Errors
    ///
    /// Returns an error when protected-current replay or evidence decoding fails.
    pub fn snapshot_manifest(
        &self,
        key: &HierarchyProtectedJournalKeyV1,
    ) -> Result<
        Option<CurrentHierarchyProtectedEvidenceV1<'_, RetainedSnapshotManifestV1>>,
        HierarchyProtectedJournalErrorV1,
    > {
        self.current_evidence(key).map(|value| match value {
            Some(HierarchyProtectedEvidenceV1::SnapshotManifest(value)) => Some(current(value)),
            _ => None,
        })
    }

    /// Mints a live inspection observation from one exact current record.
    ///
    /// # Errors
    ///
    /// Returns an error when protected-current replay or evidence decoding fails.
    pub fn live_inspection(
        &self,
        key: &HierarchyProtectedJournalKeyV1,
    ) -> Result<
        Option<CurrentHierarchyProtectedEvidenceV1<'_, CurrentLiveInspectionObservationV1>>,
        HierarchyProtectedJournalErrorV1,
    > {
        self.current_evidence(key).map(|value| match value {
            Some(HierarchyProtectedEvidenceV1::LiveInspection(value)) => Some(current(value)),
            _ => None,
        })
    }

    /// Mints assignment evidence from one exact current record.
    ///
    /// # Errors
    ///
    /// Returns an error when protected-current replay or evidence decoding fails.
    pub fn assignment(
        &self,
        key: &HierarchyProtectedJournalKeyV1,
    ) -> Result<
        Option<CurrentHierarchyProtectedEvidenceV1<'_, CurrentAssignmentEvidenceV1>>,
        HierarchyProtectedJournalErrorV1,
    > {
        self.current_evidence(key).map(|value| match value {
            Some(HierarchyProtectedEvidenceV1::Assignment(value)) => Some(current(value)),
            _ => None,
        })
    }

    /// Mints retained view-source evidence from one exact current record.
    ///
    /// # Errors
    ///
    /// Returns an error when protected-current replay or evidence decoding fails.
    pub fn view_source(
        &self,
        key: &HierarchyProtectedJournalKeyV1,
    ) -> Result<
        Option<CurrentHierarchyProtectedEvidenceV1<'_, RetainedViewSourceEvidenceV1>>,
        HierarchyProtectedJournalErrorV1,
    > {
        self.current_evidence(key).map(|value| match value {
            Some(HierarchyProtectedEvidenceV1::ViewSource(value)) => Some(current(value)),
            _ => None,
        })
    }

    /// Mints destination-slot inventory evidence from one exact current record.
    ///
    /// # Errors
    ///
    /// Returns an error when protected-current replay or evidence decoding fails.
    pub fn slot_inventory(
        &self,
        key: &HierarchyProtectedJournalKeyV1,
    ) -> Result<
        Option<CurrentHierarchyProtectedEvidenceV1<'_, CurrentSlotInventoryEvidenceV1>>,
        HierarchyProtectedJournalErrorV1,
    > {
        self.current_evidence(key).map(|value| match value {
            Some(HierarchyProtectedEvidenceV1::SlotInventory(value)) => Some(current(value)),
            _ => None,
        })
    }

    /// Mints attachment authority from one exact current record.
    ///
    /// # Errors
    ///
    /// Returns an error when protected-current replay or evidence decoding fails.
    pub fn attachment_authority(
        &self,
        key: &HierarchyProtectedJournalKeyV1,
    ) -> Result<
        Option<CurrentHierarchyProtectedEvidenceV1<'_, VerifiedAttachmentAuthorityV1>>,
        HierarchyProtectedJournalErrorV1,
    > {
        self.current_evidence(key).map(|value| match value {
            Some(HierarchyProtectedEvidenceV1::AttachmentAuthority(value)) => Some(current(value)),
            _ => None,
        })
    }

    /// Mints detach authority from one exact current record.
    ///
    /// # Errors
    ///
    /// Returns an error when protected-current replay or evidence decoding fails.
    pub fn detach_authority(
        &self,
        key: &HierarchyProtectedJournalKeyV1,
    ) -> Result<
        Option<CurrentHierarchyProtectedEvidenceV1<'_, VerifiedDetachAuthorityV1>>,
        HierarchyProtectedJournalErrorV1,
    > {
        self.current_evidence(key).map(|value| match value {
            Some(HierarchyProtectedEvidenceV1::DetachAuthority(value)) => Some(current(value)),
            _ => None,
        })
    }

    /// Mints terminal detach evidence from one exact current record.
    ///
    /// # Errors
    ///
    /// Returns an error when protected-current replay or evidence decoding fails.
    pub fn detach_completion(
        &self,
        key: &HierarchyProtectedJournalKeyV1,
    ) -> Result<
        Option<CurrentHierarchyProtectedEvidenceV1<'_, VerifiedDetachCompletionV1>>,
        HierarchyProtectedJournalErrorV1,
    > {
        self.current_evidence(key).map(|value| match value {
            Some(HierarchyProtectedEvidenceV1::DetachCompletion(value)) => Some(current(value)),
            _ => None,
        })
    }

    /// Mints terminal multi-action evidence from one exact current record.
    ///
    /// # Errors
    ///
    /// Returns an error when protected-current replay or evidence decoding fails.
    pub fn transaction_completion(
        &self,
        key: &HierarchyProtectedJournalKeyV1,
    ) -> Result<
        Option<CurrentHierarchyProtectedEvidenceV1<'_, VerifiedRealizationTransactionCompletionV1>>,
        HierarchyProtectedJournalErrorV1,
    > {
        self.current_evidence(key).map(|value| match value {
            Some(HierarchyProtectedEvidenceV1::TransactionCompletion(value)) => {
                Some(current(value))
            }
            _ => None,
        })
    }

    /// Mints snapshot recovery authority from one exact current record.
    ///
    /// # Errors
    ///
    /// Returns an error when protected-current replay or evidence decoding fails.
    pub fn snapshot_recovery_authority(
        &self,
        key: &HierarchyProtectedJournalKeyV1,
    ) -> Result<
        Option<CurrentHierarchyProtectedEvidenceV1<'_, VerifiedSnapshotRecoveryAuthorityV1>>,
        HierarchyProtectedJournalErrorV1,
    > {
        self.current_evidence(key).map(|value| match value {
            Some(HierarchyProtectedEvidenceV1::SnapshotRecoveryAuthority(value)) => {
                Some(current(value))
            }
            _ => None,
        })
    }

    /// Mints one verified realization-stage transition from a current record.
    ///
    /// # Errors
    ///
    /// Returns an error when protected-current replay or evidence decoding fails.
    pub fn stage_transition(
        &self,
        key: &HierarchyProtectedJournalKeyV1,
    ) -> Result<
        Option<CurrentHierarchyProtectedEvidenceV1<'_, VerifiedStageTransitionV1>>,
        HierarchyProtectedJournalErrorV1,
    > {
        self.current_evidence(key).map(|value| match value {
            Some(HierarchyProtectedEvidenceV1::StageTransition(value)) => Some(current(value)),
            _ => None,
        })
    }

    /// Mints realization reboot inventory from one exact current record.
    ///
    /// # Errors
    ///
    /// Returns an error when protected-current replay or evidence decoding fails.
    pub fn reboot_realization_inventory(
        &self,
        key: &HierarchyProtectedJournalKeyV1,
    ) -> Result<
        Option<CurrentHierarchyProtectedEvidenceV1<'_, RebootRealizationInventoryV1>>,
        HierarchyProtectedJournalErrorV1,
    > {
        self.current_evidence(key).map(|value| match value {
            Some(HierarchyProtectedEvidenceV1::RebootRealizationInventory(value)) => {
                Some(current(value))
            }
            _ => None,
        })
    }

    /// Mints published rollback authority from one exact current record.
    ///
    /// # Errors
    ///
    /// Returns an error when protected-current replay or evidence decoding fails.
    pub fn published_rollback_authority(
        &self,
        key: &HierarchyProtectedJournalKeyV1,
    ) -> Result<
        Option<CurrentHierarchyProtectedEvidenceV1<'_, VerifiedPublishedRollbackAuthorityV1>>,
        HierarchyProtectedJournalErrorV1,
    > {
        self.current_evidence(key).map(|value| match value {
            Some(HierarchyProtectedEvidenceV1::PublishedRollbackAuthority(value)) => {
                Some(current(value))
            }
            _ => None,
        })
    }

    /// Mints prepared-realization recovery authority from a current record.
    ///
    /// # Errors
    ///
    /// Returns an error when protected-current replay or evidence decoding fails.
    pub fn prepared_realization_authority(
        &self,
        key: &HierarchyProtectedJournalKeyV1,
    ) -> Result<
        Option<CurrentHierarchyProtectedEvidenceV1<'_, VerifiedPreparedRealizationAuthorityV1>>,
        HierarchyProtectedJournalErrorV1,
    > {
        self.current_evidence(key).map(|value| match value {
            Some(HierarchyProtectedEvidenceV1::PreparedRealizationAuthority(value)) => {
                Some(current(value))
            }
            _ => None,
        })
    }

    /// Mints detach reboot inventory from one exact current record.
    ///
    /// # Errors
    ///
    /// Returns an error when protected-current replay or evidence decoding fails.
    pub fn detach_reboot_inventory(
        &self,
        key: &HierarchyProtectedJournalKeyV1,
    ) -> Result<
        Option<CurrentHierarchyProtectedEvidenceV1<'_, VerifiedDetachRebootInventoryV1>>,
        HierarchyProtectedJournalErrorV1,
    > {
        self.current_evidence(key).map(|value| match value {
            Some(HierarchyProtectedEvidenceV1::DetachRebootInventory(value)) => {
                Some(current(value))
            }
            _ => None,
        })
    }

    fn current_evidence(
        &self,
        key: &HierarchyProtectedJournalKeyV1,
    ) -> Result<Option<HierarchyProtectedEvidenceV1>, HierarchyProtectedJournalErrorV1> {
        if key.kind() != HierarchyProtectedRecordKindV1::Evidence {
            return Ok(None);
        }
        let projection = self.journal.replay()?;
        let Some(record) = projection
            .records()
            .iter()
            .find(|record| record.key() == key)
        else {
            return Ok(None);
        };
        let body = decode_reducer_payload_with_validator::<HierarchyProtectedJournalSchemaV1>(
            key,
            record.payload(),
            &self.validator,
        )?;
        let evidence = decode_hierarchy_protected_evidence_v1(body.body())
            .filter(|evidence| evidence.identity().as_slice() == key.identity())
            .ok_or(HierarchyProtectedJournalErrorV1::NonCanonicalRecord)?;
        Ok(Some(evidence))
    }
}

/// Replays the typed hierarchy projection without acquiring a Source writer.
pub(crate) fn replay_project_ancestry_head_v1(
    journal: &mut Journal,
    project: ProjectId,
) -> Result<Option<CurrentProjectAncestryHeadV1>, HierarchyProtectedJournalErrorV1> {
    if project.as_bytes() == &[0; 16] {
        return Err(HierarchyProtectedJournalErrorV1::NonCanonicalRecord);
    }
    let validator = recover_hierarchy_replay_validator_v1(journal)?;
    let claimed = claim_hierarchy_protected_journal_v1(journal, validator.clone())?;
    let projection = claimed.replay()?;

    let mut identity = Vec::with_capacity(48);
    for _ in 0..3 {
        identity.extend_from_slice(project.as_bytes());
    }
    let key = HierarchyProtectedJournalKeyV1::new(HierarchyProtectedRecordKindV1::Tree, identity)?;
    let Some(record) = projection
        .records()
        .iter()
        .find(|record| record.key() == &key)
    else {
        return Ok(None);
    };
    let payload = decode_reducer_payload_with_validator::<HierarchyProtectedJournalSchemaV1>(
        &key,
        record.payload(),
        &validator,
    )?;
    let tree = decode_tree_v1(payload.body())
        .map_err(|_| HierarchyProtectedJournalErrorV1::NonCanonicalRecord)?;
    if tree.project() != project {
        return Err(HierarchyProtectedJournalErrorV1::NonCanonicalRecord);
    }
    let tree_commitment = tree_commitment_v1(&tree)
        .map_err(|_| HierarchyProtectedJournalErrorV1::NonCanonicalRecord)?;
    Ok(Some(CurrentProjectAncestryHeadV1 {
        project,
        record_revision: record.revision(),
        tree_generation: tree.tree_generation(),
        tree_commitment,
        head: record.digest(),
    }))
}

pub(crate) fn recover_hierarchy_replay_validator_v1(
    journal: &Journal,
) -> Result<HierarchyProtectedReplayValidatorV1, HierarchyProtectedJournalErrorV1> {
    let candidates =
        protected_current_record_candidates_v1::<HierarchyProtectedJournalSchemaV1>(journal)?;
    let mut realization_heads = Vec::new();
    let mut detach_heads = Vec::new();
    let mut transaction_heads = Vec::new();
    for candidate in &candidates {
        match candidate.body().get(..8) {
            Some(magic) if magic == b"AOSHRH01" => realization_heads.push(
                decode_protected_realization_head_v1(candidate.body())
                    .map_err(|_| HierarchyProtectedJournalErrorV1::NonCanonicalRecord)?,
            ),
            Some(magic) if magic == b"AOSHDH01" => detach_heads.push(
                decode_protected_detach_head_v1(candidate.body())
                    .map_err(|_| HierarchyProtectedJournalErrorV1::NonCanonicalRecord)?,
            ),
            Some(magic) if magic == b"AOSHTH01" => transaction_heads.push(
                decode_protected_transaction_head_v1(candidate.body())
                    .map_err(|_| HierarchyProtectedJournalErrorV1::NonCanonicalRecord)?,
            ),
            _ => {}
        }
    }
    HierarchyProtectedReplayValidatorV1::from_protected_current_heads(
        &realization_heads,
        &detach_heads,
        &transaction_heads,
    )
}

fn current<'current, T>(evidence: T) -> CurrentHierarchyProtectedEvidenceV1<'current, T> {
    CurrentHierarchyProtectedEvidenceV1 {
        evidence,
        _current: std::marker::PhantomData,
    }
}

/// Wraps one reducer-issued canonical hierarchy body for journal admission.
pub(crate) fn hierarchy_reducer_envelope_v1(
    key: HierarchyProtectedJournalKeyV1,
    revision: u64,
    predecessor: Option<ObjectDigest>,
    record: HierarchyReducerRecordV1<'_>,
    validator: &HierarchyProtectedReplayValidatorV1,
) -> Result<HierarchyProtectedJournalEnvelopeV1, HierarchyProtectedJournalErrorV1> {
    let (required_kind, body) = match record {
        HierarchyReducerRecordV1::Tree(value) => (
            HierarchyProtectedRecordKindV1::Tree,
            encode_tree_v1(value)
                .map(Vec::from)
                .map_err(|_| HierarchyProtectedJournalErrorV1::NonCanonicalRecord),
        ),
        HierarchyReducerRecordV1::HistoryRecord(value) => (
            HierarchyProtectedRecordKindV1::History,
            encode_history_record_v1(value)
                .map(Vec::from)
                .map_err(|_| HierarchyProtectedJournalErrorV1::NonCanonicalRecord),
        ),
        HierarchyReducerRecordV1::History(value) => (
            HierarchyProtectedRecordKindV1::History,
            encode_history_v1(value)
                .map_err(|_| HierarchyProtectedJournalErrorV1::NonCanonicalRecord),
        ),
        HierarchyReducerRecordV1::RealizationPlan(value) => (
            HierarchyProtectedRecordKindV1::RealizationEffect,
            encode_realization_plan_v1(value)
                .map_err(|_| HierarchyProtectedJournalErrorV1::NonCanonicalRecord),
        ),
        HierarchyReducerRecordV1::RealizationProgress(value) => (
            HierarchyProtectedRecordKindV1::RealizationEffect,
            encode_realization_progress_v1(value)
                .map_err(|_| HierarchyProtectedJournalErrorV1::NonCanonicalRecord),
        ),
        HierarchyReducerRecordV1::DetachProgress(value) => (
            HierarchyProtectedRecordKindV1::DetachEffect,
            encode_detach_progress_v1(value)
                .map_err(|_| HierarchyProtectedJournalErrorV1::NonCanonicalRecord),
        ),
        HierarchyReducerRecordV1::Transaction(value) => (
            HierarchyProtectedRecordKindV1::RealizationEffect,
            encode_realization_transaction_state_v1(value)
                .map_err(|_| HierarchyProtectedJournalErrorV1::NonCanonicalRecord),
        ),
        HierarchyReducerRecordV1::RealizationHead(value) => (
            HierarchyProtectedRecordKindV1::RealizationEffect,
            encode_protected_realization_head_v1(value)
                .map_err(|_| HierarchyProtectedJournalErrorV1::NonCanonicalRecord),
        ),
        HierarchyReducerRecordV1::DetachHead(value) => (
            HierarchyProtectedRecordKindV1::DetachEffect,
            encode_protected_detach_head_v1(value)
                .map_err(|_| HierarchyProtectedJournalErrorV1::NonCanonicalRecord),
        ),
        HierarchyReducerRecordV1::TransactionHead(value) => (
            HierarchyProtectedRecordKindV1::RealizationEffect,
            encode_protected_transaction_head_v1(value)
                .map_err(|_| HierarchyProtectedJournalErrorV1::NonCanonicalRecord),
        ),
        HierarchyReducerRecordV1::Evidence(value) => (
            HierarchyProtectedRecordKindV1::Evidence,
            encode_hierarchy_protected_evidence_v1(value)
                .ok_or(HierarchyProtectedJournalErrorV1::NonCanonicalRecord),
        ),
    };
    if key.kind() != required_kind {
        return Err(HierarchyProtectedJournalErrorV1::NonCanonicalRecord);
    }
    let body = body?;
    let payload = encode_reducer_payload_with_validator::<HierarchyProtectedJournalSchemaV1>(
        &key, &body, validator,
    )?;
    HierarchyProtectedJournalEnvelopeV1::new_with_validator(
        key,
        revision,
        predecessor,
        payload,
        validator,
    )
}
