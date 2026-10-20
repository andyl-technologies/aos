//! Defines the complete seven-family saved Source hierarchy schema.
//!
//! These canonical comparisons validate saved bytes, identities, ordering and
//! commitments. They cannot acquire a writer or issue currentness, payment,
//! rollback or effect authority. Native consumers choose this closed schema.

pub mod artifact_codec;
pub mod claims;
pub mod evidence_codec;
pub mod lineage;
pub mod realization;
pub mod recovery;
mod source_tree_capture;
pub use source_tree_capture::SourceTreeSchemaOriginalsV1;

use std::collections::{BTreeMap, BTreeSet};
use aos_sandbox_model::{ObjectDigest, ProjectId, ResourceId, Revision, SandboxId, RecordNamespace};
use aos_sandbox_protocol::domain_ledger::DomainLedgerDataError as HierarchyProtectedJournalErrorV1;
use aos_sandbox_protocol::domain_ledger::records::{ProtectedDomainEnvelopeV1, ProtectedDomainKeyV1, ProtectedDomainProjectionV1, ProtectedDomainReplayPhaseV1, ProtectedDomainReplayTransactionV1, ProtectedDomainSchemaV1, ProtectedRecordRoleV1, ProtectedReducerPhaseV1, decode_reducer_payload_with_validator, encode_reducer_payload_with_validator};
use crate::hierarchy::codec::{decode_history_record_v1, decode_history_v1, decode_tree_v1, encode_history_record_v1, encode_history_v1, encode_tree_v1, tree_commitment_v1};
use crate::hierarchy::graph::SandboxTreeV1;
use crate::hierarchy::history::{HierarchyHistoryRecordV1, HierarchyHistoryV1};
use self::artifact_codec::{decode_detach_progress_v1, decode_protected_detach_head_v1, decode_protected_realization_head_v1, decode_protected_transaction_head_v1, decode_realization_plan_v1, decode_realization_progress_v1, decode_realization_transaction_state_v1, encode_detach_progress_v1, encode_protected_detach_head_v1, encode_protected_realization_head_v1, encode_protected_transaction_head_v1, encode_realization_plan_v1, encode_realization_progress_v1, encode_realization_transaction_state_v1};
use self::evidence_codec::{HierarchyProtectedEvidenceV1, decode_hierarchy_protected_evidence_v1, encode_hierarchy_protected_evidence_v1};
use self::realization::ViewRealizationPlanV1;
use self::recovery::{DurableDetachProgressV1, DurableRealizationProgressV1, DurableRealizationTransactionV1, RetainedDetachHeadV1, RetainedRealizationHeadV1, RetainedRealizationTransactionHeadV1};
use self::lineage::{ClosedTreeLineageRecordV1, decode_closed_tree_lineage_v1};

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
    /// Retains one immutable, nonauthorizing Tree generation link.
    TreeLineage = 7,
}

/// Defines the closed hierarchy adapter schema.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct HierarchyProtectedJournalSchemaV1;

/// Compares saved heads against exact historical record commitments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HierarchyProtectedReplayValidatorV1 {
    realization_heads: Vec<RetainedRealizationHeadV1>,
    detach_heads: Vec<RetainedDetachHeadV1>,
    transaction_heads: Vec<RetainedRealizationTransactionHeadV1>,
}

impl HierarchyProtectedReplayValidatorV1 {
    /// Compares the complete bounded set of recorded historical head DATA.
    ///
    /// # Errors
    /// Rejects zero, duplicate or excessive saved head commitments.
    pub fn from_protected_current_heads(
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
            7 => Some(Self::Kind::TreeLineage),
            _ => None,
        }
    }

    fn namespace(kind: Self::Kind) -> RecordNamespace {
        match kind {
            Self::Kind::Tree
            | Self::Kind::History
            | Self::Kind::Evidence
            | Self::Kind::TreeLineage => RecordNamespace::DesiredState,
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
            Self::Kind::TreeLineage => 7,
        }
    }

    fn role(kind: Self::Kind) -> ProtectedRecordRoleV1 {
        match kind {
            Self::Kind::Tree
            | Self::Kind::History
            | Self::Kind::Evidence
            | Self::Kind::TreeLineage => ProtectedRecordRoleV1::State,
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
                if source_tree_capture::canonical_tree(body, None)
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
            Self::Kind::TreeLineage => source_tree_capture::canonical_lineage(body, identity, None),
            Self::Kind::Tree | Self::Kind::History | Self::Kind::Checkpoint => None,
        }
    }

    fn semantic_tuple(kind: Self::Kind, identity: &[u8], body: &[u8]) -> Option<[u8; 32]> {
        let magic = body.get(..8)?;
        let has_one_subject = match kind {
            Self::Kind::History => magic == b"AOSHHI01",
            Self::Kind::RealizationEffect => magic == b"AOSHRG01" || magic == b"AOSHRH01",
            Self::Kind::DetachEffect => magic == b"AOSHDG01" || magic == b"AOSHDH01",
            Self::Kind::Tree
            | Self::Kind::Checkpoint
            | Self::Kind::Evidence
            | Self::Kind::TreeLineage => false,
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
    canonical_history_body_with_originals(body, identity, None)
}

fn canonical_history_body_with_originals(
    body: &[u8],
    identity: &[u8],
    originals: Option<&mut source_tree_capture::SourceTreeSchemaOriginalsV1>,
) -> bool {
    if body.starts_with(b"AOSHHI01") {
        let canonical = match originals {
            Some(originals) => source_tree_capture::canonical_history_encoding(body, originals),
            None => decode_history_record_v1(body).and_then(encode_history_record_v1)
                .is_ok_and(|encoded| encoded.as_slice() == body),
        };
        return canonical && body.get(12..28) == identity.get(..16)
            && body.get(36..52) == identity.get(16..32)
            && body.get(52..68) == identity.get(32..48);
    }
    if !body.starts_with(b"AOSHLG01") { return false; }
    let canonical = match originals {
        Some(originals) => source_tree_capture::canonical_history_encoding(body, originals),
        None => decode_history_v1(body).and_then(|decoded| encode_history_v1(&decoded))
            .is_ok_and(|encoded| encoded == body),
    };
    if !canonical || body.get(12..28) != identity.get(..16) {
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
                self::realization::RealizationStageV1::Planned
                | self::realization::RealizationStageV1::Prepared => {
                    Some(ProtectedReducerPhaseV1::Prepared)
                }
                self::realization::RealizationStageV1::Published
                | self::realization::RealizationStageV1::Verified
                | self::realization::RealizationStageV1::Draining => {
                    Some(ProtectedReducerPhaseV1::Observed)
                }
                self::realization::RealizationStageV1::Reaped
                | self::realization::RealizationStageV1::Aborted
                | self::realization::RealizationStageV1::Faulted => {
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
                self::recovery::DetachStageV1::Planned => Some(ProtectedReducerPhaseV1::Prepared),
                self::recovery::DetachStageV1::Detached
                | self::recovery::DetachStageV1::Verified => {
                    Some(ProtectedReducerPhaseV1::Observed)
                }
                self::recovery::DetachStageV1::Completed
                | self::recovery::DetachStageV1::Aborted
                | self::recovery::DetachStageV1::Faulted => {
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
                self::realization::RealizationStageV1::Planned
                | self::realization::RealizationStageV1::Prepared => {
                    Some(ProtectedReducerPhaseV1::Prepared)
                }
                self::realization::RealizationStageV1::Published
                | self::realization::RealizationStageV1::Verified
                | self::realization::RealizationStageV1::Draining => {
                    Some(ProtectedReducerPhaseV1::Observed)
                }
                self::realization::RealizationStageV1::Reaped
                | self::realization::RealizationStageV1::Aborted
                | self::realization::RealizationStageV1::Faulted => {
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
                Some(self::recovery::TransactionActionOutcomeV1::Completed) => {
                    Some(ProtectedReducerPhaseV1::Observed)
                }
                Some(
                    self::recovery::TransactionActionOutcomeV1::Aborted
                    | self::recovery::TransactionActionOutcomeV1::Faulted,
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
pub enum HierarchyReducerRecordV1<'record> {
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
    /// Encodes one immutable structural lineage link.
    TreeLineage(&'record ClosedTreeLineageRecordV1),
}

/// Canonical hierarchy shared-journal key.
pub type HierarchyProtectedJournalKeyV1 = ProtectedDomainKeyV1<HierarchyProtectedJournalSchemaV1>;
/// Canonical hierarchy value and predecessor CAS.
pub type HierarchyProtectedJournalEnvelopeV1 =
    ProtectedDomainEnvelopeV1<HierarchyProtectedJournalSchemaV1>;
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
    HierarchyProtectedJournalKeyV1::new(kind, identity).map_err(HierarchyProtectedJournalErrorV1::from)
}

/// Encodes one canonical hierarchy comparison envelope.
///
/// # Errors
/// Rejects a body, kind, identity, revision or predecessor mismatch.
pub fn hierarchy_reducer_envelope_v1(
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
        HierarchyReducerRecordV1::TreeLineage(value) => (
            HierarchyProtectedRecordKindV1::TreeLineage,
            Ok(value.encode()),
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
    ).map_err(HierarchyProtectedJournalErrorV1::from)
}

/// Validates saved hierarchy head bindings including structural Source rows.
///
/// # Errors
/// Rejects malformed retained heads or inconsistent/duplicate commitments.
pub fn replay_validator_from_saved_rows_v1(
    candidates: &[aos_sandbox_protocol::domain_ledger::records::ProtectedCurrentRecordCandidateV1<HierarchyProtectedJournalSchemaV1>],
) -> Result<HierarchyProtectedReplayValidatorV1, HierarchyProtectedJournalErrorV1> {
    replay_validator_from_candidates_impl(candidates, true)
}

/// Validates saved ancestry bindings while rejecting structural-only Trees.
///
/// # Errors
/// Rejects structural Tree/Lineage rows, malformed heads or duplicate bindings.
pub fn ancestry_validator_from_saved_rows_v1(
    candidates: &[aos_sandbox_protocol::domain_ledger::records::ProtectedCurrentRecordCandidateV1<HierarchyProtectedJournalSchemaV1>],
) -> Result<HierarchyProtectedReplayValidatorV1, HierarchyProtectedJournalErrorV1> {
    replay_validator_from_candidates_impl(candidates, false)
}

fn replay_validator_from_candidates_impl(
    candidates: &[aos_sandbox_protocol::domain_ledger::records::ProtectedCurrentRecordCandidateV1<HierarchyProtectedJournalSchemaV1>],
    allow_structural_tree: bool,
) -> Result<HierarchyProtectedReplayValidatorV1, HierarchyProtectedJournalErrorV1> {
    let mut realization_heads = Vec::new();
    let mut detach_heads = Vec::new();
    let mut transaction_heads = Vec::new();
    for candidate in candidates {
        if !allow_structural_tree
            && matches!(
                candidate.key().kind(),
                HierarchyProtectedRecordKindV1::Tree | HierarchyProtectedRecordKindV1::TreeLineage
            )
        {
            // Structural lineage does not establish Controller currentness or
            // an independent rollback floor for the public ancestry readers.
            return Err(HierarchyProtectedJournalErrorV1::NonCanonicalRecord);
        }
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

#[cfg(test)]
mod closed_schema_tests {
    use super::*;

    #[test]
    fn complete_historical_schema_keeps_all_seven_fixed_families() {
        let expected = [
            (HierarchyProtectedRecordKindV1::Tree, RecordNamespace::DesiredState),
            (HierarchyProtectedRecordKindV1::History, RecordNamespace::DesiredState),
            (HierarchyProtectedRecordKindV1::RealizationEffect, RecordNamespace::Effect),
            (HierarchyProtectedRecordKindV1::DetachEffect, RecordNamespace::Effect),
            (HierarchyProtectedRecordKindV1::Checkpoint, RecordNamespace::RuntimeGeneration),
            (HierarchyProtectedRecordKindV1::Evidence, RecordNamespace::DesiredState),
            (HierarchyProtectedRecordKindV1::TreeLineage, RecordNamespace::DesiredState),
        ];
        for (index, (kind, namespace)) in expected.into_iter().enumerate() {
            let code = u8::try_from(index + 1).unwrap();
            assert_eq!(HierarchyProtectedJournalSchemaV1::kind_from_code(code), Some(kind));
            assert_eq!(HierarchyProtectedJournalSchemaV1::kind_code(kind), code);
            assert_eq!(HierarchyProtectedJournalSchemaV1::namespace(kind), namespace);
        }
        assert!(HierarchyProtectedJournalSchemaV1::kind_from_code(0).is_none());
        assert!(HierarchyProtectedJournalSchemaV1::kind_from_code(8).is_none());
    }
}
