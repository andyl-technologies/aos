//! Resident first-successor Source mutation and same-writer observation.
//!
//! The canonical records are DATA. Positive append and ACK require the real
//! Controller writer and original Root flight; each caller keeps a separate
//! single-use result reservoir through all independent postchecks.

use std::path::Path;

use aos_sandbox_core::{DesiredGeneration, ObjectDigest, ProjectId, Revision};

use crate::journal::source_tree_successor::{
    FirstSourceSuccessorNativePhaseV2, PENDING_KEY, SourceFirstSuccessorRowsV2, ack_key, receipt_key,
    SourceSuccessorFamilyRecipeV3, source_capacity_request, transaction_id,
};
use crate::journal::{
    CommitResult, Journal, JournalError, JournalRecord,
    JournalTransaction, ProtectedJournalNamesV1, RecordNamespace,
};
use crate::lifecycle::protected_journal_join::{
    PROTECTED_SOURCE_DOMAIN_JOURNAL, PROTECTED_SOURCE_DOMAIN_ROOT,
    ProtectedSourceDomainJournalOwnerV1, source_domain_journal_limits,
};
use crate::policy_compiler::{
    ControllerFirstSourceSuccessorAnchoredFieldsV2, ControllerFirstSourceSuccessorAnchoredV2,
    HeldControllerFirstSourceSuccessorV2, HeldRootFirstSourceSuccessorIntentV2,
    RootFirstSourceSuccessorFloorFieldsV2, RootFirstSourceSuccessorFloorProofV2,
    RootFirstSourceSuccessorFloorV2, RootFirstSourceSuccessorIntentV2,
    SourceFirstSuccessorAckFieldsV2, SourceFirstSuccessorAckV2,
    SourceFirstSuccessorPendingFieldsV2, SourceFirstSuccessorPendingV2,
    SourceFirstSuccessorReceiptFieldsV2, SourceFirstSuccessorReceiptV2,
    HeldControllerProjectSuccessorV3, HeldRootProjectSuccessorIntentV3,
    RootProjectSuccessorFloorProofV3, ControllerSuccessorOwnerViewV3,
    RootSuccessorIntentViewV3, RootSuccessorFloorViewV3,
};

use super::codec::tree_commitment_v1;
use super::genesis_profile::SourceGenesisErrorV1;
use super::model::SandboxTreeRecordV1;
use super::protected_journal::RetainedTreeInventoryDataV1;
use super::source_genesis::SourceTreeGenesisReceiptV1;
use super::tree_lineage::{
    PreparedSourceFirstSuccessorPairV2, prepare_source_first_successor_pair_v2,
    replay_closed_tree_lineage_v1,
};

/// Identifies actual Source progress, without a Root floor or admission permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceFirstSuccessorStateV2 {
    /// Retains anchored generation one and no successor flight.
    Before,
    /// Retains the exact new pair, receipt, pending marker and suffix reserve.
    Prepared,
    /// Retains the new pair and its exact settled ACK.
    Anchored,
}

/// Holds the actual same-writer cut through signatures and the Root handoff.
#[must_use = "the actual Source observation must remain borrowed through its handoff"]
pub struct HeldSourceFirstSuccessorObservationV2<'source> {
    journal: &'source Journal,
    uid: u32,
    project: ProjectId,
    names: ProtectedJournalNamesV1,
    sequence: u64,
    state: SourceFirstSuccessorStateV2,
    genesis: crate::journal::source_tree_genesis::SourceGenesisRowsV1,
    successor: SourceFirstSuccessorRowsV2,
    tree_head: ObjectDigest,
    lineage_head: ObjectDigest,
    tree_commit: ObjectDigest,
    generation: u64,
    recipe: SourceSuccessorFamilyRecipeV3,
}

impl HeldSourceFirstSuccessorObservationV2<'_> {
    /// Returns actual progress DATA, never remote settlement authority.
    pub const fn state(&self) -> SourceFirstSuccessorStateV2 {
        self.state
    }

    /// Returns the selected project of this actual inventory borrow.
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the privileged Source UID independently checked at capture.
    pub const fn source_uid(&self) -> u32 {
        self.uid
    }

    /// Returns original physical names as diagnostic DATA.
    pub const fn names(&self) -> ProtectedJournalNamesV1 {
        self.names
    }

    /// Returns the unchanged native frame watermark as diagnostic DATA.
    pub const fn snapshot_sequence(&self) -> u64 {
        self.sequence
    }

    /// Borrows the immutable original genesis receipt.
    pub fn genesis_receipt(&self) -> Option<&SourceTreeGenesisReceiptV1> {
        self.genesis.receipts.get(&self.project)
    }

    /// Borrows the new receipt, absent only for actual Before.
    pub fn receipt(&self) -> Option<&SourceFirstSuccessorReceiptV2> {
        self.successor.receipts.get(&self.project)
    }

    /// Borrows the actual settled local ACK, absent until Anchored.
    pub fn ack(&self) -> Option<&SourceFirstSuccessorAckV2> {
        self.successor.acks.get(&self.project)
    }

    /// Returns the original genesis ACK commitment as DATA.
    pub fn genesis_ack_digest(&self) -> Option<ObjectDigest> {
        self.genesis.acks.get(&self.project).map(|ack| ack.digest())
    }

    /// Returns the actual retained original Root floor commitment DATA.
    pub fn genesis_root_floor(&self) -> Option<ObjectDigest> {
        self.genesis.acks.get(&self.project).map(|ack| ack.root_floor)
    }

    /// Returns the current canonical Tree envelope commitment.
    pub const fn current_tree_head(&self) -> ObjectDigest {
        self.tree_head
    }

    /// Returns the current immutable lineage envelope commitment.
    pub const fn current_lineage_head(&self) -> ObjectDigest {
        self.lineage_head
    }

    /// Returns the canonical current Tree body commitment.
    pub const fn current_tree_commit(&self) -> ObjectDigest {
        self.tree_commit
    }

    /// Returns the actual current Tree generation.
    pub const fn current_generation(&self) -> u64 {
        self.generation
    }

    /// Rechecks the same healthy writer, physical cut and complete joined rows.
    ///
    /// # Errors
    /// Rejects changed names, watermark, materialized state or native health.
    pub fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        require_location(self.journal, self.uid)?;
        if self.journal.protected_writer_physical_names_v1()? != self.names
            || self.journal.snapshot_sequence() != self.sequence
            || self.journal.source_tree_genesis_rows_v1()? != self.genesis
            || match self.recipe {
                SourceSuccessorFamilyRecipeV3::SingleProjectV2 => self.journal.source_first_successor_rows_v2()?,
                SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { selected } => {
                    self.journal.source_project_continuation_rows_v3(selected)?
                }
            } != self.successor
        {
            return Err(SourceGenesisErrorV1::Stale);
        }
        Ok(())
    }

    /// Rejoins the real inventory by pointer and its unchanged watermark.
    ///
    /// # Errors
    /// Rejects a substituted inventory or any stale original cut.
    pub(crate) fn require_retained_inventory_v2(
        &self, inventory: &RetainedTreeInventoryDataV1<'_>,
    ) -> Result<(), SourceGenesisErrorV1> {
        self.recheck()?;
        inventory.recheck()?;
        if !std::ptr::eq(self.journal, inventory.journal())
            || self.sequence != inventory.journal_sequence()
        {
            return Err(SourceGenesisErrorV1::Stale);
        }
        Ok(())
    }
}

/// Borrows actual progress from the same retained Source inventory.
///
/// # Errors
/// Rejects unsafe names, unanchored genesis, foreign pending state or a Tree
/// which does not match the sole complete native/lineage replay.
pub fn observe_source_first_successor_v2<'source>(
    inventory: &'source RetainedTreeInventoryDataV1<'_>,
    expected_source_uid: u32,
    project: ProjectId,
) -> Result<HeldSourceFirstSuccessorObservationV2<'source>, SourceGenesisErrorV1> {
    observe_source_successor_with_recipe(
        inventory, expected_source_uid, project, SourceSuccessorFamilyRecipeV3::SingleProjectV2,
    )
}

// A v3 observation retains its original loan and every named result, including
// failures. It is never returned as the strict v2 typed observation.
/// Retains a complete mixed-family DATA observation and independent bookends.
#[must_use = "the original DATA loan and its failed results must remain resident"]
pub struct SourceProjectContinuationObservationV3<'source> {
    journal: &'source Journal,
    action: Result<HeldSourceFirstSuccessorObservationV2<'source>, SourceGenesisErrorV1>,
    posts: [Result<(), SourceGenesisErrorV1>; 3],
}

// This terminal evidence owns every decoded field, but no Journal reference.
// There is deliberately no conversion from it back into a live observation.
pub(crate) struct SourceProjectContinuationEvidenceV3 {
    action: Result<SourceProjectContinuationDataV3, SourceGenesisErrorV1>,
    posts: [Result<(), SourceGenesisErrorV1>; 3],
}

struct SourceProjectContinuationDataV3 {
    uid: u32,
    project: ProjectId,
    names: ProtectedJournalNamesV1,
    sequence: u64,
    state: SourceFirstSuccessorStateV2,
    genesis: crate::journal::source_tree_genesis::SourceGenesisRowsV1,
    successor: SourceFirstSuccessorRowsV2,
    tree_head: ObjectDigest,
    lineage_head: ObjectDigest,
    tree_commit: ObjectDigest,
    generation: u64,
    recipe: SourceSuccessorFamilyRecipeV3,
}

impl SourceProjectContinuationEvidenceV3 {
    pub(crate) fn error(&self) -> Option<&SourceGenesisErrorV1> {
        self.action.as_ref().err()
            .or_else(|| self.posts.iter().find_map(|post| post.as_ref().err()))
    }

    pub(crate) fn post_failures(&self) -> impl Iterator<Item = &SourceGenesisErrorV1> {
        self.posts.iter().filter_map(|post| post.as_ref().err())
    }
}

// A short private comparison view preserves the public purpose boundary.
// The mixed variant never exposes the shared strict-typed storage to callers.
#[derive(Clone, Copy)]
pub(crate) enum SourceSuccessorObservationViewV3<'loan, 'source> {
    Strict(&'loan HeldSourceFirstSuccessorObservationV2<'source>),
    Mixed(&'loan SourceProjectContinuationObservationV3<'source>),
}

impl<'loan, 'source> SourceSuccessorObservationViewV3<'loan, 'source> {
    fn data(&self) -> Result<&HeldSourceFirstSuccessorObservationV2<'source>, SourceGenesisErrorV1> {
        match self {
            Self::Strict(data) => Ok(data),
            Self::Mixed(data) => {
                if data.error().is_some() { return Err(SourceGenesisErrorV1::Stale); }
                data.action.as_ref().map_err(|_| SourceGenesisErrorV1::Stale)
            }
        }
    }

    pub(crate) fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        match self { Self::Strict(data) => data.recheck(), Self::Mixed(data) => data.recheck() }
    }

    pub(crate) fn state(&self) -> Result<SourceFirstSuccessorStateV2, SourceGenesisErrorV1> { Ok(self.data()?.state()) }
    pub(crate) fn project(&self) -> Result<ProjectId, SourceGenesisErrorV1> { Ok(self.data()?.project()) }
    pub(crate) fn source_uid(&self) -> Result<u32, SourceGenesisErrorV1> { Ok(self.data()?.source_uid()) }
    pub(crate) fn names(&self) -> Result<ProtectedJournalNamesV1, SourceGenesisErrorV1> { Ok(self.data()?.names()) }
    pub(crate) fn snapshot_sequence(&self) -> Result<u64, SourceGenesisErrorV1> { Ok(self.data()?.snapshot_sequence()) }
    pub(crate) fn genesis_receipt(&self) -> Option<&SourceTreeGenesisReceiptV1> { self.data().ok()?.genesis_receipt() }
    pub(crate) fn genesis_root_floor(&self) -> Option<ObjectDigest> { self.data().ok()?.genesis_root_floor() }
    pub(crate) fn receipt(&self) -> Option<&SourceFirstSuccessorReceiptV2> { self.data().ok()?.receipt() }
    pub(crate) fn ack(&self) -> Option<&SourceFirstSuccessorAckV2> { self.data().ok()?.ack() }
}

impl SourceProjectContinuationObservationV3<'_> {
    pub(crate) fn into_evidence_v3(self) -> SourceProjectContinuationEvidenceV3 {
        let action = self.action.map(|observed| {
            let HeldSourceFirstSuccessorObservationV2 {
                journal: _, uid, project, names, sequence, state, genesis,
                successor, tree_head, lineage_head, tree_commit, generation, recipe,
            } = observed;
            SourceProjectContinuationDataV3 {
                uid, project, names, sequence, state, genesis, successor,
                tree_head, lineage_head, tree_commit, generation, recipe,
            }
        });
        SourceProjectContinuationEvidenceV3 { action, posts: self.posts }
    }

    /// Borrows the earliest actual action or independent bookend failure.
    pub fn error(&self) -> Option<&SourceGenesisErrorV1> {
        self.action.as_ref().err().or_else(|| self.posts.iter().find_map(|post| post.as_ref().err()))
    }

    /// Borrows all independently retained post-observation results.
    pub fn post_results(&self) -> &[Result<(), SourceGenesisErrorV1>; 3] {
        &self.posts
    }

    /// Rechecks the same original writer without replacing retained failures.
    ///
    /// # Errors
    /// Refuses any prior action/bookend failure or a changed current source cut.
    pub fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        if self.error().is_some() {
            return Err(SourceGenesisErrorV1::Stale);
        }
        self.action.as_ref().map_err(|_| SourceGenesisErrorV1::Stale)?.recheck()
    }

    /// Returns selected phase DATA only after all independent bookends succeed.
    pub fn state(&self) -> Option<SourceFirstSuccessorStateV2> {
        if self.error().is_some() {
            return None;
        }

        self.action.as_ref().ok().map(|observed| observed.state())
    }

    /// Returns the selected project without exporting a strict observation loan.
    pub fn project(&self) -> Option<ProjectId> {
        if self.error().is_some() {
            return None;
        }

        self.action.as_ref().ok().map(|observed| observed.project())
    }

    /// Borrows the immutable selected genesis receipt as DATA.
    pub fn genesis_receipt(&self) -> Option<&SourceTreeGenesisReceiptV1> {
        if self.error().is_some() { return None; }
        self.action.as_ref().ok()?.genesis_receipt()
    }

    /// Borrows the selected successor receipt as DATA.
    pub fn receipt(&self) -> Option<&SourceFirstSuccessorReceiptV2> {
        if self.error().is_some() { return None; }
        self.action.as_ref().ok()?.receipt()
    }

    /// Borrows the selected settled ACK as DATA.
    pub fn ack(&self) -> Option<&SourceFirstSuccessorAckV2> {
        if self.error().is_some() { return None; }
        self.action.as_ref().ok()?.ack()
    }

    pub(crate) fn require_retained_inventory_v3(
        &self, inventory: &RetainedTreeInventoryDataV1<'_>,
    ) -> Result<(), SourceGenesisErrorV1> {
        self.recheck()?;
        inventory.recheck()?;
        if !std::ptr::eq(self.journal, inventory.journal()) {
            return Err(SourceGenesisErrorV1::Stale);
        }
        self.action.as_ref().map_err(|_| SourceGenesisErrorV1::Stale)?
            .require_retained_inventory_v2(inventory)
    }
}

/// Observes every genuine initial/successor family before selecting one project.
///
/// The returned owner retains both a failed action and all independent posts.
/// It grants no current Root floor, writer admission or mutation permission.
pub fn observe_source_project_continuation_v3<'source>(
    inventory: &'source RetainedTreeInventoryDataV1<'_>,
    expected_source_uid: u32,
    project: ProjectId,
) -> SourceProjectContinuationObservationV3<'source> {
    let journal = inventory.journal();
    let sequence = journal.snapshot_sequence();
    let action = observe_source_successor_with_recipe(
        inventory, expected_source_uid, project,
        SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { selected: Some(project) },
    );
    // None of these independent observations is short-circuited by action Err.
    let location = require_location(journal, expected_source_uid);
    let watermark = if journal.snapshot_sequence() == sequence {
        Ok(())
    } else {
        Err(SourceGenesisErrorV1::Stale)
    };
    let retained = inventory.recheck().map_err(SourceGenesisErrorV1::from);
    SourceProjectContinuationObservationV3 {
        journal, action, posts: [location, watermark, retained],
    }
}

fn observe_source_successor_with_recipe<'source>(
    inventory: &'source RetainedTreeInventoryDataV1<'_>,
    expected_source_uid: u32,
    project: ProjectId,
    recipe: SourceSuccessorFamilyRecipeV3,
) -> Result<HeldSourceFirstSuccessorObservationV2<'source>, SourceGenesisErrorV1> {
    inventory.recheck()?;
    let journal = inventory.journal();
    require_location(journal, expected_source_uid)?;
    let genesis = journal.source_tree_genesis_rows_v1()?;
    let successor = match recipe {
        SourceSuccessorFamilyRecipeV3::SingleProjectV2 => journal.source_first_successor_rows_v2()?,
        SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { selected } => {
            journal.source_project_continuation_rows_v3(selected)?
        }
    };
    let original = genesis.receipts.get(&project).ok_or(SourceGenesisErrorV1::Conflict)?;
    if genesis.pending.is_some() || !genesis.acks.contains_key(&project)
        || (recipe == SourceSuccessorFamilyRecipeV3::SingleProjectV2
            && successor.receipts.keys().any(|selected| *selected != project))
    {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    let head = inventory.heads().get(&project).ok_or(SourceGenesisErrorV1::Conflict)?;
    let state = if let Some(receipt) = successor.receipts.get(&project) {
        if receipt.instance() != original.instance()
            || receipt.next_tree_head() != head.tree_head
            || receipt.next_lineage_head() != head.lineage_head
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        if successor.acks.contains_key(&project) {
            SourceFirstSuccessorStateV2::Anchored
        } else {
            SourceFirstSuccessorStateV2::Prepared
        }
    } else {
        // Keep generation-one receipt/member checks in the existing engine;
        // structural inventory replay alone does not authenticate that join.
        if recipe == SourceSuccessorFamilyRecipeV3::SingleProjectV2 {
            super::source_genesis::observe_retained_source_genesis_v1(
                inventory, expected_source_uid, project,
            )?.recheck()?;
        }
        if head.tree.tree_generation().get() != 1
            || head.tree_head != original.tree_head() || head.lineage_head != original.lineage_head()
            || head.tree.records().next().is_some() || head.tree.tombstones().next().is_some()
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        SourceFirstSuccessorStateV2::Before
    };
    let observation = HeldSourceFirstSuccessorObservationV2 {
        journal, uid: expected_source_uid, project,
        names: journal.protected_writer_physical_names_v1()?,
        sequence: journal.snapshot_sequence(), state, genesis, successor,
        tree_head: head.tree_head, lineage_head: head.lineage_head,
        tree_commit: tree_commitment_v1(&head.tree)
            .map_err(|_| SourceGenesisErrorV1::NonCanonical)?,
        generation: head.tree.tree_generation().get(), recipe,
    };
    observation.require_retained_inventory_v2(inventory)?;
    Ok(observation)
}

fn require_location(journal: &Journal, uid: u32) -> Result<(), SourceGenesisErrorV1> {
    journal.ensure_healthy()?;
    journal.require_protected_named_location(
        Path::new(PROTECTED_SOURCE_DOMAIN_ROOT), PROTECTED_SOURCE_DOMAIN_JOURNAL,
        uid, source_domain_journal_limits(),
    )?;
    Ok(())
}

/// Projects actual fixed-owner UID DATA without exporting the Journal loan.
pub(crate) fn first_source_successor_inventory_uid_v2(
    inventory: &RetainedTreeInventoryDataV1<'_>,
) -> Result<u32, SourceGenesisErrorV1> {
    inventory.recheck()?;
    let uid = inventory.journal().protected_owner_uid()?;
    require_location(inventory.journal(), uid)?;
    inventory.recheck()?;
    Ok(uid)
}

/// Borrows the real first failure without moving its owning native result.
pub enum SourceFirstSuccessorMutationFailureV2<'failure> {
    /// Borrows an original preparation or independent owner-check failure.
    Admission(&'failure SourceGenesisErrorV1),
    /// Borrows an actual preflight, commit or native readback failure.
    Native(&'failure JournalError),
}

/// Retains one action's preparations, native result and independent post debt.
///
/// This reservoir is single-use. The caller retains separate append and ACK
/// instances in the original invocation; an error never resets the action.
#[derive(Default)]
pub struct SourceFirstSuccessorMutationResultsV2 {
    attempted: bool,
    tree: Option<super::graph::SandboxTreeV1>,
    pair: Option<PreparedSourceFirstSuccessorPairV2>,
    initial_rows: Option<SourceFirstSuccessorRowsV2>,
    genesis: Option<crate::journal::source_tree_genesis::SourceGenesisRowsV1>,
    heads: Option<std::collections::BTreeMap<ProjectId, super::tree_lineage::ClosedTreeLineageHeadV1>>,
    receipt: Option<SourceFirstSuccessorReceiptV2>,
    pending: Option<SourceFirstSuccessorPendingV2>,
    ack: Option<SourceFirstSuccessorAckV2>,
    transactions: Vec<JournalTransaction>,
    append_records: Vec<JournalRecord>,
    preparation: Option<Result<(), SourceGenesisErrorV1>>,
    preflight: Option<Result<(), JournalError>>,
    crossing: Option<Result<(), SourceGenesisErrorV1>>,
    crossing_clock: Option<Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1>>,
    native: Option<Result<CommitResult, JournalError>>,
    readback: Option<Result<SourceFirstSuccessorRowsV2, JournalError>>,
    source_post: Option<Result<(), SourceGenesisErrorV1>>,
    controller_post: Option<Result<(), SourceGenesisErrorV1>>,
    root_post: Option<Result<(), SourceGenesisErrorV1>>,
    equality_post: Option<Result<(), SourceGenesisErrorV1>>,
    clock_post: Option<Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1>>,
}

impl SourceFirstSuccessorMutationResultsV2 {
    /// Creates an unused local reservoir, not an action permission.
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrows the chronological action cause; later failures remain debt.
    pub fn error(&self) -> Option<SourceFirstSuccessorMutationFailureV2<'_>> {
        if let Some(Err(error)) = &self.preparation {
            return Some(SourceFirstSuccessorMutationFailureV2::Admission(error));
        }
        if let Some(Err(error)) = &self.preflight {
            return Some(SourceFirstSuccessorMutationFailureV2::Native(error));
        }
        if let Some(Err(error)) = &self.crossing {
            return Some(SourceFirstSuccessorMutationFailureV2::Admission(error));
        }
        if let Some(Err(error)) = &self.crossing_clock {
            return Some(SourceFirstSuccessorMutationFailureV2::Admission(error));
        }
        if let Some(Err(error)) = &self.native {
            return Some(SourceFirstSuccessorMutationFailureV2::Native(error));
        }
        if let Some(Err(error)) = &self.readback {
            return Some(SourceFirstSuccessorMutationFailureV2::Native(error));
        }
        for result in [&self.source_post, &self.controller_post, &self.root_post, &self.equality_post] {
            if let Some(Err(error)) = result {
                return Some(SourceFirstSuccessorMutationFailureV2::Admission(error));
            }
        }
        if let Some(Err(error)) = &self.clock_post {
            return Some(SourceFirstSuccessorMutationFailureV2::Admission(error));
        }
        None
    }

    /// Borrows each independent post failure without granting release or retry.
    pub fn post_failures(&self) -> [Option<&SourceGenesisErrorV1>; 4] {
        [&self.source_post, &self.controller_post, &self.root_post, &self.equality_post]
            .map(|result| result.as_ref().and_then(|result| result.as_ref().err()))
    }

    /// Borrows the independent original-clock Result, even after owner failure.
    pub fn clock_post_result(&self) -> Option<&Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1>> {
        self.clock_post.as_ref()
    }
}

/// Appends exactly one admitted parentless, non-live generation-two record.
///
/// The entire Append/ACK suffix is preflighted before the genuine append. Every
/// returned native result stays in `results`, including failures through all
/// independent original-owner postchecks. Exact prepared replay is read-only.
///
/// # Errors
/// Returns only a phase marker on failure; [`SourceFirstSuccessorMutationResultsV2::error`]
/// borrows the actual retained cause. A reused reservoir is always refused.
pub fn append_source_first_successor_v2(
    source: &mut ProtectedSourceDomainJournalOwnerV1,
    controller: &HeldControllerFirstSourceSuccessorV2<'_>,
    root: &HeldRootFirstSourceSuccessorIntentV2<'_>,
    results: &mut SourceFirstSuccessorMutationResultsV2,
) -> Result<SourceFirstSuccessorReceiptV2, ()> {
    append_source_successor_with_recipe(
        source, ControllerSuccessorOwnerViewV3::Strict(controller), RootSuccessorIntentViewV3::Strict(root),
        results, SourceSuccessorFamilyRecipeV3::SingleProjectV2,
    )
}

/// Appends a selected successor only under the existing genuine owner loans.
///
/// This selects complete mixed-family comparison, not a new admission
/// constructor. A DATA observation cannot supply either required owner loan.
/// Fresh project issuance and its installed consumer remain separate work.
///
/// # Errors
/// Returns a retaining marker for reused reservoirs, unjoined foreign members,
/// changed original admission, native ambiguity or independent post debt.
pub(crate) fn append_source_project_continuation_v3(
    source: &mut ProtectedSourceDomainJournalOwnerV1,
    controller: &HeldControllerProjectSuccessorV3<'_>,
    root: &HeldRootProjectSuccessorIntentV3<'_>,
    results: &mut SourceFirstSuccessorMutationResultsV2,
) -> Result<SourceFirstSuccessorReceiptV2, ()> {
    append_source_successor_with_recipe(source, ControllerSuccessorOwnerViewV3::Mixed(controller), RootSuccessorIntentViewV3::Mixed(root), results,
        SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { selected: Some(root.record().project()) })
}

fn append_source_successor_with_recipe(
    source: &mut ProtectedSourceDomainJournalOwnerV1,
    controller: ControllerSuccessorOwnerViewV3<'_, '_>,
    root: RootSuccessorIntentViewV3<'_, '_>,
    results: &mut SourceFirstSuccessorMutationResultsV2,
    recipe: SourceSuccessorFamilyRecipeV3,
) -> Result<SourceFirstSuccessorReceiptV2, ()> {
    if results.attempted {
        return Err(());
    }
    results.attempted = true;
    let journal = source.journal();
    results.preparation = Some(match recipe {
        SourceSuccessorFamilyRecipeV3::SingleProjectV2 => prepare_append(journal, controller, root, results),
        SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { .. } => {
            prepare_append_with_recipe(journal, controller, root, results, recipe)
        }
    });
    if matches!(results.preparation, Some(Ok(()))) && !results.transactions.is_empty() {
        results.preflight = Some(journal.preflight_first_source_successor_v2(
            &results.transactions,
            &[
                selected_native_phase(recipe, FirstSourceSuccessorNativePhaseV2::SourceAppend),
                selected_native_phase(recipe, FirstSourceSuccessorNativePhaseV2::SourceAck),
            ],
        ));
        if matches!(results.preflight, Some(Ok(()))) {
            results.crossing = Some((|| {
                controller.recheck_current_admission()?;
                root.recheck_current_admission()?;
                require_location(journal, root.source_uid())?;
                Ok(())
            })());
            if matches!(results.crossing, Some(Ok(()))) {
                results.crossing_clock = Some(root.current_admission_clock());
            }
            if matches!(results.crossing_clock, Some(Ok(_))) {
                results.native = Some(match recipe {
                    SourceSuccessorFamilyRecipeV3::SingleProjectV2 => journal.commit_first_source_successor_v2(
                        &results.transactions[0], selected_native_phase(recipe, FirstSourceSuccessorNativePhaseV2::SourceAppend),
                    ),
                    SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { .. } => journal.commit_selected_source_successor_v3(
                        &results.transactions[0], selected_native_phase(recipe, FirstSourceSuccessorNativePhaseV2::SourceAppend),
                        crate::journal::source_tree_successor::FirstSuccessorNativeCutV3::SourcePrepared(root),
                    ),
                });
            }
        }
    }
    // Each check runs even after an earlier action or native failure. No result
    // is moved out to manufacture a new success or release/retry permission.
    results.readback = Some(selected_source_rows(journal, recipe));
    results.source_post = Some(require_location(journal, root.source_uid()));
    results.controller_post = Some(controller.recheck());
    results.root_post = Some(root.recheck());
    results.equality_post = Some((|| {
        let receipt = results.receipt.as_ref().ok_or(SourceGenesisErrorV1::Stale)?;
        let rows = results.readback.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(SourceGenesisErrorV1::Stale)?;
        if rows.receipts.get(&receipt.project()) != Some(receipt)
            || (rows.acks.get(&receipt.project()).is_none()
                && rows.pending.as_ref() != results.pending.as_ref())
        {
            return Err(SourceGenesisErrorV1::Stale);
        }
        require_first_successor_context_v2(receipt, root.record())
    })());
    results.clock_post = Some(root.observe_original_clock());
    if results.error().is_some() {
        return Err(());
    }
    results.receipt.clone().ok_or(())
}

fn prepare_append(
    journal: &mut Journal,
    controller: ControllerSuccessorOwnerViewV3<'_, '_>,
    root: RootSuccessorIntentViewV3<'_, '_>,
    results: &mut SourceFirstSuccessorMutationResultsV2,
) -> Result<(), SourceGenesisErrorV1> {
    prepare_append_with_recipe(journal, controller, root, results,
        SourceSuccessorFamilyRecipeV3::SingleProjectV2)
}

fn prepare_append_with_recipe(
    journal: &mut Journal,
    controller: ControllerSuccessorOwnerViewV3<'_, '_>,
    root: RootSuccessorIntentViewV3<'_, '_>,
    results: &mut SourceFirstSuccessorMutationResultsV2,
    recipe: SourceSuccessorFamilyRecipeV3,
) -> Result<(), SourceGenesisErrorV1> {
    controller.recheck()?;
    root.recheck()?;
    let context = root.record();
    let approval = controller.packet();
    if context.approval_packet() != approval || context.begin() != controller.begin().digest()
        || root.source_uid() != controller.source_uid()
    {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    require_location(journal, root.source_uid())?;
    results.initial_rows = Some(selected_source_rows(journal, recipe)?);
    let rows = results.initial_rows.as_ref().ok_or(SourceGenesisErrorV1::NonCanonical)?;
    if let Some(receipt) = rows.receipts.get(&context.project()) {
        require_first_successor_context_v2(receipt, context)?;
        if rows.pending.as_ref().is_some_and(|pending| {
            pending.source_names() != context.source_names()
                || journal.protected_writer_physical_names_v1().ok() != Some(pending.source_names())
        }) {
            return Err(SourceGenesisErrorV1::Stale);
        }
        results.receipt = Some(receipt.clone());
        results.pending = rows.pending.clone();
        return Ok(());
    }
    if (recipe == SourceSuccessorFamilyRecipeV3::SingleProjectV2 && !rows.receipts.is_empty())
        || rows.pending.is_some()
    {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    controller.recheck_current_admission()?;
    root.recheck_current_admission()?;
    results.genesis = Some(match recipe {
        SourceSuccessorFamilyRecipeV3::SingleProjectV2 => super::source_genesis::validate_actual_rows(journal)?,
        SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { selected } => {
            if selected != Some(context.project()) { return Err(SourceGenesisErrorV1::Conflict); }
            // selected_source_rows already joined every actual lineage member,
            // original genesis receipt/ACK and settled foreign successor.
            journal.source_tree_genesis_rows_v1()?
        }
    });
    let genesis = results.genesis.as_ref().ok_or(SourceGenesisErrorV1::NonCanonical)?;
    let original = genesis.receipts.get(&context.project()).ok_or(SourceGenesisErrorV1::Conflict)?;
    let ack = genesis.acks.get(&context.project()).ok_or(SourceGenesisErrorV1::Conflict)?;
    if genesis.pending.is_some() || original.instance() != context.instance()
        || ack.root_floor != context.predecessor_floor()
        || original.tree_head() != context.old_tree_head()
        || original.lineage_head() != context.old_lineage_head()
        || journal.protected_writer_physical_names_v1()? != context.source_names()
        || controller.begin().source_names() != context.source_names()
    {
        return Err(SourceGenesisErrorV1::Conflict);
    }

    results.heads = Some(replay_closed_tree_lineage_v1(journal)?);
    let heads = results.heads.as_ref().ok_or(SourceGenesisErrorV1::NonCanonical)?;
    let previous = heads.get(&context.project()).ok_or(SourceGenesisErrorV1::Conflict)?;
    let intent = approval.intent()?;
    results.tree = Some(previous.tree.insert(SandboxTreeRecordV1::new(
        intent.project(), intent.sandbox(), None, DesiredGeneration::new(1), None,
    ).map_err(|_| SourceGenesisErrorV1::NonCanonical)?, Revision::new(1), None)
        .map_err(|_| SourceGenesisErrorV1::Conflict)?);
    let tree = results.tree.as_ref().ok_or(SourceGenesisErrorV1::NonCanonical)?;
    if tree_commitment_v1(tree).map_err(|_| SourceGenesisErrorV1::NonCanonical)? != context.next_tree_commit() {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    results.pair = Some(prepare_source_first_successor_pair_v2(
        journal, tree, context.old_tree_head(), context.old_lineage_head(),
        transaction_id(approval.digest(), FirstSourceSuccessorNativePhaseV2::SourceAppend),
    )?);
    let pair = results.pair.as_ref().ok_or(SourceGenesisErrorV1::NonCanonical)?;
    results.receipt = Some(SourceFirstSuccessorReceiptV2::new(SourceFirstSuccessorReceiptFieldsV2 {
        instance: context.instance(), project: context.project(), request: context.request(),
        approval: approval.digest(), epoch: context.epoch(), before_generation: 1, after_generation: 2,
        predecessor_floor: context.predecessor_floor(), old_tree_head: context.old_tree_head(),
        old_lineage_head: context.old_lineage_head(),
        old_tree_commit: approval.old_tree_commit(),
        next_tree_head: pair.tree_head, next_lineage_head: pair.lineage_head,
        next_tree_commit: context.next_tree_commit(), roles: context.roles(),
        begin: controller.begin().digest(), root_intent: context.digest(), source_names: context.source_names(),
    })?);
    let receipt = results.receipt.as_ref().ok_or(SourceGenesisErrorV1::NonCanonical)?;
    results.pending = Some(SourceFirstSuccessorPendingV2::new(SourceFirstSuccessorPendingFieldsV2 {
        instance: receipt.instance(), project: receipt.project(), request: receipt.request(),
        approval: receipt.approval(), root_intent: receipt.root_intent(), receipt: receipt.digest(),
        source_names: receipt.source_names(),
    })?);
    // These are canonical prospective DATA, not a fabricated held floor or ACK.
    // Actual ACK still requires the real Root floor and Controller Anchored loans.
    results.ack = Some(expected_ack(receipt)?);
    let capacity = source_capacity_request(receipt)?;
    results.append_records = pair.records.clone();
    results.append_records.push(JournalRecord::put(RecordNamespace::DesiredState,
        receipt_key(receipt.project()), receipt.as_bytes().to_vec()));
    results.append_records.push(JournalRecord::put(RecordNamespace::DesiredState, PENDING_KEY.to_vec(),
        results.pending.as_ref().ok_or(SourceGenesisErrorV1::NonCanonical)?.as_bytes().to_vec()));
    results.append_records.push(journal.prepare_first_source_successor_capacity_v2(&capacity,
        transaction_id(receipt.approval(), FirstSourceSuccessorNativePhaseV2::SourceAppend))?);
    results.transactions.push(JournalTransaction::new(
        transaction_id(receipt.approval(), FirstSourceSuccessorNativePhaseV2::SourceAppend),
        results.append_records.clone(),
    )?);
    let reservation = results.transactions[0].records().last().ok_or(SourceGenesisErrorV1::NonCanonical)?;
    results.transactions.push(ack_transaction(
        results.ack.as_ref().ok_or(SourceGenesisErrorV1::NonCanonical)?,
        receipt.approval(),
        JournalRecord::delete(reservation.namespace(), reservation.key().to_vec()),
    )?);
    Ok(())
}

/// Settles the exact pending successor only under genuine cross-owner loans.
///
/// # Errors
/// Returns a marker while all owning action errors and post debt remain in the
/// supplied single-use reservoir. Exact already-settled replay performs no write.
pub fn acknowledge_source_first_successor_v2(
    source: &mut ProtectedSourceDomainJournalOwnerV1,
    controller: &HeldControllerFirstSourceSuccessorV2<'_>,
    root: &RootFirstSourceSuccessorFloorProofV2<'_>,
    results: &mut SourceFirstSuccessorMutationResultsV2,
) -> Result<SourceFirstSuccessorAckV2, ()> {
    acknowledge_source_successor_with_recipe(source, ControllerSuccessorOwnerViewV3::Strict(controller), RootSuccessorFloorViewV3::Strict(root), results,
        SourceSuccessorFamilyRecipeV3::SingleProjectV2)
}

/// Settles the selected actual pending suffix under genuine original owners.
///
/// # Errors
/// Returns a retaining marker for changed actual pending project/transaction,
/// unjoined foreign members, ambiguity or independent owner/clock debt.
pub(crate) fn acknowledge_source_project_continuation_v3(
    source: &mut ProtectedSourceDomainJournalOwnerV1,
    controller: &HeldControllerProjectSuccessorV3<'_>,
    root: &RootProjectSuccessorFloorProofV3<'_>,
    results: &mut SourceFirstSuccessorMutationResultsV2,
) -> Result<SourceFirstSuccessorAckV2, ()> {
    acknowledge_source_successor_with_recipe(source, ControllerSuccessorOwnerViewV3::Mixed(controller), RootSuccessorFloorViewV3::Mixed(root), results,
        SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { selected: Some(root.floor().receipt().project()) })
}

fn acknowledge_source_successor_with_recipe(
    source: &mut ProtectedSourceDomainJournalOwnerV1,
    controller: ControllerSuccessorOwnerViewV3<'_, '_>,
    root: RootSuccessorFloorViewV3<'_, '_>,
    results: &mut SourceFirstSuccessorMutationResultsV2,
    recipe: SourceSuccessorFamilyRecipeV3,
) -> Result<SourceFirstSuccessorAckV2, ()> {
    if results.attempted {
        return Err(());
    }
    results.attempted = true;
    let journal = source.journal();
    results.preparation = Some(match recipe {
        SourceSuccessorFamilyRecipeV3::SingleProjectV2 => prepare_ack(journal, controller, root, results),
        SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { .. } => prepare_ack_with_recipe(journal, controller, root, results, recipe),
    });
    if matches!(results.preparation, Some(Ok(()))) && !results.transactions.is_empty() {
        results.preflight = Some(journal.preflight_first_source_successor_v2(
            &results.transactions, &[selected_native_phase(recipe, FirstSourceSuccessorNativePhaseV2::SourceAck)],
        ));
        if matches!(results.preflight, Some(Ok(()))) {
            results.crossing = Some((|| {
                // Settlement compares the original prepared authority. It does
                // not renew admission or require an expired approval to revive.
                controller.recheck()?;
                root.recheck()?;
                require_location(journal, root.source_uid())?;
                Ok(())
            })());
            if matches!(results.crossing, Some(Ok(()))) {
                results.crossing_clock = Some(root.observe_original_clock());
            }
            if matches!(results.crossing_clock, Some(Ok(_))) {
                results.native = Some(match recipe {
                    SourceSuccessorFamilyRecipeV3::SingleProjectV2 => journal.commit_first_source_successor_v2(
                        &results.transactions[0], selected_native_phase(recipe, FirstSourceSuccessorNativePhaseV2::SourceAck),
                    ),
                    SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { .. } => journal.commit_selected_source_successor_v3(
                        &results.transactions[0], selected_native_phase(recipe, FirstSourceSuccessorNativePhaseV2::SourceAck),
                        crate::journal::source_tree_successor::FirstSuccessorNativeCutV3::Settled(root),
                    ),
                });
            }
        }
    }
    results.readback = Some(selected_source_rows(journal, recipe));
    results.source_post = Some(require_location(journal, root.source_uid()));
    results.controller_post = Some(controller.recheck());
    results.root_post = Some(root.recheck());
    results.equality_post = Some((|| {
        let ack = results.ack.as_ref().ok_or(SourceGenesisErrorV1::Stale)?;
        let rows = results.readback.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(SourceGenesisErrorV1::Stale)?;
        if rows.acks.get(&ack.project()) != Some(ack) || rows.pending.is_some() {
            return Err(SourceGenesisErrorV1::Stale);
        }
        Ok(())
    })());
    results.clock_post = Some(root.observe_original_clock());
    if results.error().is_some() {
        return Err(());
    }
    results.ack.clone().ok_or(())
}

fn prepare_ack(
    journal: &mut Journal,
    controller: ControllerSuccessorOwnerViewV3<'_, '_>,
    root: RootSuccessorFloorViewV3<'_, '_>,
    results: &mut SourceFirstSuccessorMutationResultsV2,
) -> Result<(), SourceGenesisErrorV1> {
    prepare_ack_with_recipe(journal, controller, root, results,
        SourceSuccessorFamilyRecipeV3::SingleProjectV2)
}

fn prepare_ack_with_recipe(
    journal: &mut Journal,
    controller: ControllerSuccessorOwnerViewV3<'_, '_>,
    root: RootSuccessorFloorViewV3<'_, '_>,
    results: &mut SourceFirstSuccessorMutationResultsV2,
    recipe: SourceSuccessorFamilyRecipeV3,
) -> Result<(), SourceGenesisErrorV1> {
    controller.recheck()?;
    root.recheck()?;
    require_location(journal, root.source_uid())?;
    let floor = root.floor();
    let receipt = floor.receipt();
    let anchored = controller.anchored().ok_or(SourceGenesisErrorV1::Conflict)?;
    if controller.packet().digest() != receipt.approval()
        || controller.begin().digest() != receipt.begin()
        || anchored.receipt() != receipt.digest() || anchored.floor() != floor.digest()
        || controller.source_uid() != root.source_uid()
    {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    results.receipt = Some(receipt.clone());
    results.ack = Some(SourceFirstSuccessorAckV2::new(SourceFirstSuccessorAckFieldsV2 {
        instance: receipt.instance(), project: receipt.project(), receipt: receipt.digest(),
        root_floor: floor.digest(), controller_anchored: anchored.digest(),
    })?);
    results.initial_rows = Some(selected_source_rows(journal, recipe)?);
    let rows = results.initial_rows.as_ref().ok_or(SourceGenesisErrorV1::NonCanonical)?;
    if rows.receipts.get(&receipt.project()) != Some(receipt) {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    if let Some(ack) = rows.acks.get(&receipt.project()) {
        if Some(ack) != results.ack.as_ref() {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        return Ok(());
    }
    let pending = rows.pending.as_ref().ok_or(SourceGenesisErrorV1::Conflict)?;
    if pending.receipt() != receipt.digest() || pending.source_names() != receipt.source_names()
        || journal.protected_writer_physical_names_v1()? != receipt.source_names()
    {
        return Err(SourceGenesisErrorV1::Stale);
    }
    results.pending = Some(pending.clone());
    let capacity = source_capacity_request(receipt)?;
    let deletion = journal.first_source_successor_capacity_deletion_v2(&capacity,
        transaction_id(receipt.approval(), FirstSourceSuccessorNativePhaseV2::SourceAppend))?;
    results.transactions.push(ack_transaction(
        results.ack.as_ref().ok_or(SourceGenesisErrorV1::NonCanonical)?, receipt.approval(), deletion,
    )?);
    Ok(())
}

fn selected_source_rows(
    journal: &Journal, recipe: SourceSuccessorFamilyRecipeV3,
) -> Result<SourceFirstSuccessorRowsV2, JournalError> {
    match recipe {
        SourceSuccessorFamilyRecipeV3::SingleProjectV2 => journal.source_first_successor_rows_v2(),
        SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { selected } => journal.source_project_continuation_rows_v3(selected),
    }
}

fn selected_native_phase(
    recipe: SourceSuccessorFamilyRecipeV3, phase: FirstSourceSuccessorNativePhaseV2,
) -> FirstSourceSuccessorNativePhaseV2 {
    match (recipe, phase) {
        (SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { .. }, FirstSourceSuccessorNativePhaseV2::SourceAppend) => {
            FirstSourceSuccessorNativePhaseV2::MixedSourceAppend
        }
        (SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { .. }, FirstSourceSuccessorNativePhaseV2::SourceAck) => {
            FirstSourceSuccessorNativePhaseV2::MixedSourceAck
        }
        _ => phase,
    }
}

fn expected_ack(
    receipt: &SourceFirstSuccessorReceiptV2,
) -> Result<SourceFirstSuccessorAckV2, SourceGenesisErrorV1> {
    let floor = RootFirstSourceSuccessorFloorV2::new(RootFirstSourceSuccessorFloorFieldsV2 {
        predecessor_floor: receipt.predecessor_floor(), approval: receipt.approval(),
        receipt: receipt.clone(), roles: receipt.roles(),
    })?;
    let anchored = ControllerFirstSourceSuccessorAnchoredV2::new(ControllerFirstSourceSuccessorAnchoredFieldsV2 {
        approval: receipt.approval(), receipt: receipt.digest(), floor: floor.digest(),
    })?;
    SourceFirstSuccessorAckV2::new(SourceFirstSuccessorAckFieldsV2 {
        instance: receipt.instance(), project: receipt.project(), receipt: receipt.digest(),
        root_floor: floor.digest(), controller_anchored: anchored.digest(),
    })
}

fn ack_transaction(
    ack: &SourceFirstSuccessorAckV2,
    approval: ObjectDigest,
    reservation_delete: JournalRecord,
) -> Result<JournalTransaction, JournalError> {
    JournalTransaction::new(
        transaction_id(approval, FirstSourceSuccessorNativePhaseV2::SourceAck),
        vec![
            JournalRecord::delete(RecordNamespace::DesiredState, PENDING_KEY.to_vec()),
            JournalRecord::put(
                RecordNamespace::DesiredState,
                ack_key(ack.project()),
                ack.as_bytes().to_vec(),
            ),
            reservation_delete,
        ],
    )
}

/// Compares canonical receipt DATA with the actual saved intent, not authority.
pub(crate) fn require_first_successor_context_v2(
    receipt: &SourceFirstSuccessorReceiptV2, context: &RootFirstSourceSuccessorIntentV2,
) -> Result<(), SourceGenesisErrorV1> {
    if receipt.instance() != context.instance() || receipt.project() != context.project()
        || receipt.request() != context.request() || receipt.approval() != context.approval()
        || receipt.epoch() != context.epoch() || receipt.predecessor_floor() != context.predecessor_floor()
        || receipt.old_tree_head() != context.old_tree_head() || receipt.old_lineage_head() != context.old_lineage_head()
        || receipt.old_tree_commit() != context.approval_packet().old_tree_commit()
        || receipt.next_tree_commit() != context.next_tree_commit() || receipt.roles() != context.roles()
        || receipt.begin() != context.begin() || receipt.root_intent() != context.digest()
        || receipt.source_names() != context.source_names()
    {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    Ok(())
}
