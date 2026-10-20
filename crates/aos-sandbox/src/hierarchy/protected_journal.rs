//! Keeps actual Source journal custody and current ancestry observations.
//!
//! The complete seven-family canonical record schema lives in Source. This
//! adapter joins it to the real protected journal and its native lifetime.

use std::collections::{BTreeMap, BTreeSet};
use aos_sandbox_core::{ObjectDigest, ProjectId, ResourceId, Revision, SandboxId};
use crate::journal::{Journal, RecordNamespace};
use aos_sandbox_protocol::domain_ledger::records::{decode_reducer_payload_with_validator, ProtectedDomainSchemaV1};
use aos_sandbox_ledger_replay::replay::hierarchy_records::{HierarchyProtectedRecordKindV1, HierarchyProtectedJournalSchemaV1, HierarchyProtectedReplayValidatorV1, HierarchyProtectedJournalKeyV1, HierarchyProtectedJournalEnvelopeV1, HierarchyProtectedJournalProjectionV1, HierarchyJournalReplayTransactionV1, HierarchyJournalReplayPhaseV1, HierarchyReducerPhaseV1, HierarchyReducerRecordV1};
use aos_sandbox_ledger_replay::replay::hierarchy_records::SourceTreeSchemaOriginalsV1;
use aos_sandbox_ledger_replay::hierarchy::codec::{decode_tree_v1, tree_commitment_v1};
use aos_sandbox_ledger_replay::hierarchy::graph::SandboxTreeV1;
use crate::protected_domain_journal::{DomainCommitOutcomeV1, ProtectedDomainJournalErrorV1, ProtectedDomainJournalV1, ProtectedDomainSnapshotV1, protected_current_record_candidates_v1};
use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;

/// Sealed hierarchy journal currentness snapshot.
pub type HierarchyProtectedJournalSnapshotV1 =
    ProtectedDomainSnapshotV1<HierarchyProtectedJournalSchemaV1>;
/// Hierarchy transaction commit outcome.
pub type HierarchyJournalCommitOutcomeV1 = DomainCommitOutcomeV1<HierarchyProtectedJournalSchemaV1>;
/// Protected hierarchy journal owner.
pub type HierarchyProtectedJournalV1<'journal> =
    ProtectedDomainJournalV1<'journal, HierarchyProtectedJournalSchemaV1>;
/// Hierarchy adapter validation or durability failure.
pub type HierarchyProtectedJournalErrorV1 = ProtectedDomainJournalErrorV1;

/// Constructs the canonical DATA key at the existing Native error boundary.
pub fn hierarchy_protected_key_v1(
    kind: HierarchyProtectedRecordKindV1,
    project: ProjectId,
    sandbox: SandboxId,
    subject: ResourceId,
) -> Result<HierarchyProtectedJournalKeyV1, HierarchyProtectedJournalErrorV1> {
    aos_sandbox_ledger_replay::replay::hierarchy_records::hierarchy_protected_key_v1(kind, project, sandbox, subject)
        .map_err(HierarchyProtectedJournalErrorV1::from)
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

/// Holds one structurally empty generation-one Tree from the held Source map.
///
/// This copied DATA has no ancestry authority once the original loan ends.
#[derive(Clone, Copy)]
pub(crate) struct CreateStorageEmptyTreeDataV1 {
    pub(crate) tree_head: ObjectDigest,
    pub(crate) lineage_head: ObjectDigest,
}

// Reuses the sole complete lineage replay and tree codec. The genuine J owner
// pays before this call and independently retains named/native before and after
// samples; this helper performs no fresh named File IO or authority issuance.
pub(crate) fn create_storage_empty_tree_data_v1(
    journal: &Journal,
    project: ProjectId,
) -> Result<CreateStorageEmptyTreeDataV1, HierarchyProtectedJournalErrorV1> {
    journal.ensure_healthy()?;
    let heads = super::tree_lineage::replay_closed_tree_lineage_records_v2(journal.all_records())?;
    let head = heads.get(&project).ok_or(HierarchyProtectedJournalErrorV1::StaleAuthority)?;
    if head.tree.project() != project || head.tree.tree_generation().get() != 1
        || head.tree.records().next().is_some() || head.tree.tombstones().next().is_some()
        || head.tree_head.as_bytes() == &[0; 32] || head.lineage_head.as_bytes() == &[0; 32]
    {
        return Err(HierarchyProtectedJournalErrorV1::StaleAuthority);
    }
    Ok(CreateStorageEmptyTreeDataV1 { tree_head: head.tree_head, lineage_head: head.lineage_head })
}

/// Retains complete local Tree structure beside its original Source writer.
///
/// The Tree and lineage heads are structural DATA, not authenticated current
/// ancestry. In particular, local replay supplies no Controller receipt,
/// independent rollback floor, deletion permit, or physical drain evidence.
#[must_use = "local Tree inventory must retain its original journal borrow"]
#[allow(dead_code, reason = "the retained ancestry consumer is Linux-only")]
pub(crate) struct RetainedTreeInventoryDataV1<'journal> {
    journal: &'journal Journal,
    sequence: u64,
    heads: BTreeMap<ProjectId, super::tree_lineage::ClosedTreeLineageHeadV1>,
}

#[allow(dead_code, reason = "the retained ancestry consumer is Linux-only")]
impl RetainedTreeInventoryDataV1<'_> {
    // Only hierarchy's existing readback validator can reborrow this owner;
    // these accessors neither reopen it nor export a detached writer token.
    pub(super) const fn journal(&self) -> &Journal {
        self.journal
    }

    pub(super) const fn heads(
        &self,
    ) -> &BTreeMap<ProjectId, super::tree_lineage::ClosedTreeLineageHeadV1> {
        &self.heads
    }

    /// Returns the original shared-journal watermark, without granting authority.
    pub(crate) const fn journal_sequence(&self) -> u64 {
        self.sequence
    }

    /// Borrows every local Tree and its exact Tree and lineage envelope heads.
    ///
    /// Trees remain in canonical project order. Their existing record and
    /// tombstone iterators preserve the complete logical subtree structure.
    ///
    /// # Errors
    ///
    /// Rejects unhealthy or replaced named journal/lock custody or a changed
    /// watermark. This does not re-resolve the original directory path.
    pub(crate) fn trees(
        &self,
    ) -> Result<
        impl ExactSizeIterator<Item = (&SandboxTreeV1, ObjectDigest, ObjectDigest)>,
        HierarchyProtectedJournalErrorV1,
    > {
        self.recheck()?;
        Ok(self
            .heads
            .values()
            .map(|head| (&head.tree, head.tree_head, head.lineage_head)))
    }

    /// Rechecks the original named writer and unchanged logical watermark.
    ///
    /// # Errors
    ///
    /// Returns an error for lost named custody, poison, or a changed sequence.
    pub(crate) fn recheck(&self) -> Result<(), HierarchyProtectedJournalErrorV1> {
        self.journal.validate_held_protected_names()?;
        if self.journal.snapshot_sequence() != self.sequence {
            return Err(HierarchyProtectedJournalErrorV1::StaleAuthority);
        }
        Ok(())
    }
}

/// Reads complete local Tree/lineage DATA while borrowing the original owner.
///
/// This deliberately uses the existing structural lineage replay, not the
/// public ancestry owner whose materialized-Tree admission remains closed.
/// No Tree is omitted when current ancestry authentication is unavailable;
/// instead, the entire result remains explicitly nonauthorizing local DATA.
///
/// # Errors
///
/// Rejects lost named custody, invalid complete lineage replay, or a changed
/// journal watermark. Controller receipt/floor authentication remains absent.
#[allow(dead_code, reason = "the retained ancestry consumer is Linux-only")]
pub(crate) fn retained_tree_inventory_data_v1(
    source: &mut ProtectedSourceDomainJournalOwnerV1,
) -> Result<RetainedTreeInventoryDataV1<'_>, HierarchyProtectedJournalErrorV1> {
    let journal = source.journal();
    journal.validate_held_protected_names()?;
    let sequence = journal.snapshot_sequence();
    let heads = super::tree_lineage::replay_closed_tree_lineage_v1(journal)?;

    let inventory = RetainedTreeInventoryDataV1 {
        journal,
        sequence,
        heads,
    };
    inventory.recheck()?;
    Ok(inventory)
}

type CurrentNixInventoryReplayV1 = Result<
    BTreeMap<ProjectId, super::tree_lineage::ClosedTreeLineageHeadV1>,
    HierarchyProtectedJournalErrorV1,
>;

/// Keeps a current-Nix Tree replay and its failed-result owner in one borrow.
///
/// The original journal remains available for independent name and watermark
/// observations even when the native replay fails. No result installs a cache,
/// supplies authenticated ancestry or exposes the borrowed journal or map.
pub(crate) struct CurrentNixSourceInventoryAttemptV1<'journal> {
    journal: &'journal Journal,
    sequence: u64,
    names: Result<crate::journal::ProtectedJournalNamesV1, crate::JournalError>,
    replay: Option<CurrentNixInventoryReplayV1>,
    name_post: Option<Result<(), crate::JournalError>>,
    watermark_post: Option<Result<(), HierarchyProtectedJournalErrorV1>>,
}

/// Retains completed current-Nix replay payloads after their journal loan ends.
///
/// The actual replay, names and independent posts move without cloning. This
/// archival DATA cannot recheck, lend or reconstruct the former journal owner.
pub(crate) struct CurrentNixSourceInventoryDataV1 {
    sequence: u64,
    names: Result<crate::journal::ProtectedJournalNamesV1, crate::JournalError>,
    replay: Option<CurrentNixInventoryReplayV1>,
    name_post: Option<Result<(), crate::JournalError>>,
    watermark_post: Option<Result<(), HierarchyProtectedJournalErrorV1>>,
}

fn current_nix_inventory_first_error<'original>(
    names: &'original Result<crate::journal::ProtectedJournalNamesV1, crate::JournalError>,
    replay: &'original Option<CurrentNixInventoryReplayV1>,
    name_post: &'original Option<Result<(), crate::JournalError>>,
    watermark_post: &'original Option<Result<(), HierarchyProtectedJournalErrorV1>>,
) -> Option<&'original (dyn std::error::Error + 'static)> {
    names.as_ref().err().map(|error| error as _)
        .or_else(|| replay.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _))
        .or_else(|| name_post.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _))
        .or_else(|| watermark_post.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _))
}

impl CurrentNixSourceInventoryDataV1 {
    /// Borrows the same retained replay or post failure after the loan ends.
    pub(crate) fn first_error(&self) -> Option<&(dyn std::error::Error + 'static)> {
        current_nix_inventory_first_error(
            &self.names, &self.replay, &self.name_post, &self.watermark_post,
        )
    }
}

impl CurrentNixSourceInventoryAttemptV1<'_> {
    /// Ends the original loan while preserving all already returned payloads.
    pub(crate) fn into_retained_data(self) -> CurrentNixSourceInventoryDataV1 {
        CurrentNixSourceInventoryDataV1 {
            sequence: self.sequence, names: self.names, replay: self.replay,
            name_post: self.name_post, watermark_post: self.watermark_post,
        }
    }

    pub(crate) fn first_error(&self) -> Option<&(dyn std::error::Error + 'static)> {
        current_nix_inventory_first_error(
            &self.names, &self.replay, &self.name_post, &self.watermark_post,
        )
    }

    /// Borrows the actual original physical-name observation as comparison DATA.
    pub(crate) fn original_names_data(&self) -> Option<crate::journal::ProtectedJournalNamesV1> {
        self.names.as_ref().ok().copied()
    }

    pub(crate) const fn original_sequence_data(&self) -> u64 {
        self.sequence
    }

    /// Compares the exact original cut without replaying or repairing a failure.
    ///
    /// # Errors
    /// Rejects changed original names/watermark or any retained earlier failure.
    pub(crate) fn recheck(&self) -> Result<(), HierarchyProtectedJournalErrorV1> {
        self.journal.validate_held_protected_names()?;
        if self.first_error().is_some() || self.journal.snapshot_sequence() != self.sequence {
            return Err(HierarchyProtectedJournalErrorV1::StaleAuthority);
        }
        Ok(())
    }

    /// Selects one original Nix target row and its immutable envelope heads.
    ///
    /// The tuple is DATA, not the replay map or an ancestry permission.
    ///
    /// # Errors
    /// Rejects changed original custody, failed replay or an absent exact row.
    pub(crate) fn original_nix_target_data(
        &self,
        project: ProjectId,
        sandbox: SandboxId,
    ) -> Result<
        (aos_sandbox_core::source_tree_model::SandboxTreeRecordV1, ObjectDigest, ObjectDigest),
        HierarchyProtectedJournalErrorV1,
    > {
        self.recheck()?;
        let heads = self.replay.as_ref().and_then(|r| r.as_ref().ok())
            .ok_or(HierarchyProtectedJournalErrorV1::StaleAuthority)?;
        let head = heads.get(&project)
            .ok_or(HierarchyProtectedJournalErrorV1::NonCanonicalRecord)?;
        let record = *head.tree.record(sandbox)
            .ok_or(HierarchyProtectedJournalErrorV1::NonCanonicalRecord)?;
        Ok((record, head.tree_head, head.lineage_head))
    }
}

/// Captures one complete current-Nix replay beside the same original writer.
pub(crate) fn capture_current_nix_inventory_v1(
    source: &mut ProtectedSourceDomainJournalOwnerV1,
) -> CurrentNixSourceInventoryAttemptV1<'_> {
    let returned_names = source.fixed_physical_names_v1();
    let journal = source.journal();
    let sequence = journal.snapshot_sequence();
    let replay = if returned_names.is_ok() {
        Some(super::tree_lineage::replay_closed_tree_lineage_v1(journal))
    } else {
        None
    };

    // Both posts run after the whole replay result is parked, including Err.
    let name_post = Some(journal.validate_held_protected_names());
    let watermark_post = Some(if journal.snapshot_sequence() == sequence {
        Ok(())
    } else {
        Err(HierarchyProtectedJournalErrorV1::StaleAuthority)
    });
    CurrentNixSourceInventoryAttemptV1 {
        journal,
        sequence,
        names: returned_names,
        replay,
        name_post,
        watermark_post,
    }
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
    /// candidate set before this owner is returned. Structural lineage alone
    /// cannot open a Tree: Controller receipt/currentness and an independent
    /// anti-rollback floor must be verified together.
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
    /// its root binding commit and effect handoff. Until protected Controller
    /// receipt and floor verification exists, a materialized Tree fails claim.
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
        let fields = aos_sandbox_ledger_replay::source_readback_queries::ancestry_fields_from_projection_v1(
            &projection, &key, &self.validator, project,
        ).map_err(HierarchyProtectedJournalErrorV1::from)?;
        Ok(fields.map(|(record_revision, tree_generation, tree_commitment, head)|
            current(CurrentProjectAncestryHeadV1 {
                project, record_revision, tree_generation, tree_commitment, head,
            })))
    }

}

/// Replays the typed hierarchy projection without acquiring a Source writer.
/// A materialized bare Tree is rejected by the shared cold validator.
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
    let fields = aos_sandbox_ledger_replay::source_readback_queries::ancestry_fields_from_projection_v1(
        &projection, &key, &validator, project,
    ).map_err(HierarchyProtectedJournalErrorV1::from)?;
    Ok(fields.map(|(record_revision, tree_generation, tree_commitment, head)|
        CurrentProjectAncestryHeadV1 {
            project, record_revision, tree_generation, tree_commitment, head,
        }))
}

pub(crate) fn recover_hierarchy_replay_validator_v1(
    journal: &Journal,
) -> Result<HierarchyProtectedReplayValidatorV1, HierarchyProtectedJournalErrorV1> {
    recover_hierarchy_replay_validator_impl_v1(journal, false)
}

pub(super) fn recover_hierarchy_replay_validator_for_closed_lineage_v1(
    journal: &Journal,
) -> Result<HierarchyProtectedReplayValidatorV1, HierarchyProtectedJournalErrorV1> {
    recover_hierarchy_replay_validator_impl_v1(journal, true)
}

fn recover_hierarchy_replay_validator_impl_v1(
    journal: &Journal,
    allow_structural_tree: bool,
) -> Result<HierarchyProtectedReplayValidatorV1, HierarchyProtectedJournalErrorV1> {
    let candidates =
        protected_current_record_candidates_v1::<HierarchyProtectedJournalSchemaV1>(journal)?;
    if allow_structural_tree {
        aos_sandbox_ledger_replay::replay::hierarchy_records::replay_validator_from_saved_rows_v1(&candidates)
            .map_err(HierarchyProtectedJournalErrorV1::from)
    } else {
        aos_sandbox_ledger_replay::replay::hierarchy_records::ancestry_validator_from_saved_rows_v1(&candidates)
            .map_err(HierarchyProtectedJournalErrorV1::from)
    }
}

fn current<'current, T>(evidence: T) -> CurrentHierarchyProtectedEvidenceV1<'current, T> {
    CurrentHierarchyProtectedEvidenceV1 {
        evidence,
        _current: std::marker::PhantomData,
    }
}

/// Encodes the canonical reducer DATA at the existing Native error boundary.
pub(crate) fn hierarchy_reducer_envelope_v1(
    key: HierarchyProtectedJournalKeyV1,
    revision: u64,
    predecessor: Option<ObjectDigest>,
    record: HierarchyReducerRecordV1<'_>,
    validator: &HierarchyProtectedReplayValidatorV1,
) -> Result<HierarchyProtectedJournalEnvelopeV1, HierarchyProtectedJournalErrorV1> {
    aos_sandbox_ledger_replay::replay::hierarchy_records::hierarchy_reducer_envelope_v1(key, revision, predecessor, record, validator)
        .map_err(HierarchyProtectedJournalErrorV1::from)
}

// Prices one additional structural replay from this SAME held map. Tree's
// binary decoder checks 58-byte record/16-byte tombstone totals before reserve;
// using 16 for either family also covers malformed reached prefixes. Generic
// Native/Protocol replay and canonical byte lanes remain separately priced.
pub(crate) fn create_storage_tree_model_demand_v1(
    journal: &Journal,
) -> Result<aos_sandbox_core::ResourceVector, crate::JournalError> {
    use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
    use aos_sandbox_core::source_tree_model::SandboxTreeRecordV1;
    let invalid = || crate::JournalError::JournalTooLarge;
    let mut bytes = 0_usize;
    let mut rows = 0_usize;
    for (_, key, value) in journal.all_records() {
        bytes = bytes.checked_add(key.len()).and_then(|n| n.checked_add(value.len())).ok_or_else(invalid)?;
        rows = rows.checked_add(1).ok_or_else(invalid)?;
    }
    let children = bytes.checked_div(16).and_then(|n| n.checked_add(rows)).ok_or_else(invalid)?;
    let width = std::mem::size_of::<(SandboxTreeRecordV1, SandboxId, usize, [usize; 6])>();
    let cells = children.checked_mul(8).and_then(|n| n.checked_add(8)).ok_or_else(invalid)?;
    let maps = rows.checked_mul(8).and_then(|n| n.checked_mul(std::mem::size_of::<(
        ProjectId, super::tree_lineage::ClosedTreeLineageHeadV1, [usize; 6],
    )>())).ok_or_else(invalid)?;
    let memory = cells.checked_mul(width).and_then(|n| n.checked_add(maps))
        .and_then(|n| n.checked_add(bytes.checked_mul(32)?)).ok_or_else(invalid)?;
    Ok(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).map_err(|_| invalid())?)
        .with(D::MetadataEntries, u64::try_from(cells).map_err(|_| invalid())?))
}

/// Selects the exact predecessor Tree row through the sole complete lineage replay.
///
/// The genuine Start/Root caller owns and prepays its actual Source native
/// interval separately. This copied structural DATA grants no ancestry, lease
/// or mutation authority and performs no additional physical observation.
///
/// # Errors
/// Rejects an unhealthy Source, invalid complete lineage or missing exact target.
pub(crate) fn start_assignment_source_tree_data_v2(
    journal: &Journal,
    project: ProjectId,
    sandbox: SandboxId,
) -> Result<(aos_sandbox_core::source_tree_model::SandboxTreeRecordV1, ObjectDigest, ObjectDigest),
    HierarchyProtectedJournalErrorV1>
{
    journal.ensure_healthy()?;
    let heads = super::tree_lineage::replay_closed_tree_lineage_records_v2(journal.all_records())?;
    let head = heads.get(&project).ok_or(HierarchyProtectedJournalErrorV1::StaleAuthority)?;
    let record = *head.tree.record(sandbox).ok_or(HierarchyProtectedJournalErrorV1::StaleAuthority)?;
    Ok((record, head.tree_head, head.lineage_head))
}

/// Prices the same full structural replay with only actual named containers.
///
/// The existing decoder/model memory recipe remains unchanged. The canonical
/// format owners separately count their keyed rows, maps and indices; parser
/// cursors and vector headers do not create namespace entries.
///
/// # Errors
/// Rejects malformed structural cardinalities or checked geometry overflow.
pub(crate) fn start_assignment_tree_receiving_demand_v2(
    journal: &Journal,
) -> Result<aos_sandbox_core::ResourceVector, crate::JournalError> {
    use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

    let memory = create_storage_tree_model_demand_v1(journal)?.get(D::MemoryBytes);
    let names = aos_sandbox_ledger_replay::replay::tree_lineage::retained::
        closed_tree_lineage_named_entries_v2(journal.all_records())
        .map_err(crate::JournalError::from)?;
    Ok(ResourceVector::ZERO
        .with(D::MemoryBytes, memory)
        .with(D::MetadataEntries, names))
}
