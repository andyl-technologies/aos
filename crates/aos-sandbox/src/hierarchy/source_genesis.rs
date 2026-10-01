//! Genuine Source genesis transaction and live, borrowed floor-ACK handoff.
//!
//! Controller acceptance and the original authenticated Root flight remain
//! held across the atomic Tree/seed-lineage/receipt/pending append. Pending
//! state is not ancestry. Only exact live Root-floor and Controller acceptance
//! joins may anchor it; later Tree transitions need separate full authority.
//! Neither cold receipt data nor this Source-only observation authenticates
//! Root currentness, whole-host rollback resistance or unrelated Source facts.
//! The live append/ACK entry points are Linux-only; receipt and readback data
//! remain available independently of those owner interfaces.

use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

use aos_sandbox_core::{ObjectDigest, ProjectId};
use sha2::{Digest as _, Sha256};

use crate::journal::source_tree_genesis::{
    PENDING_KEY, SourceGenesisAckV1, SourceGenesisPendingV1, SourceGenesisRowsV1,
    SourceGenesisTransitionV1, ack_key, receipt_key,
};
use crate::journal::{
    Journal, JournalRecord, JournalTransaction, ProtectedJournalNamesV1, RecordNamespace,
};
use crate::lifecycle::protected_journal_join::{
    PROTECTED_SOURCE_DOMAIN_JOURNAL, PROTECTED_SOURCE_DOMAIN_ROOT,
    ProtectedSourceDomainJournalOwnerV1, source_domain_journal_limits,
};
#[cfg(target_os = "linux")]
use crate::policy_compiler::{HeldRootSourceGenesisIntentV1, RootSourceGenesisFloorProofV1};

#[cfg(target_os = "linux")]
use super::controller_genesis::HeldControllerSourceGenesisV1;
use super::genesis_profile::SourceGenesisErrorV1;
use super::tree_lineage::{
    prepare_source_tree_genesis_pair_v1, replay_closed_tree_lineage_v1,
    source_tree_genesis_members_v1,
};

mod receipt;
pub use receipt::{SOURCE_TREE_GENESIS_RECEIPT_BYTES_V1, SourceTreeGenesisReceiptV1};

/// Distinguishes global absence, a vacant target and actual prepared/ACK data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceTreeGenesisStateV1 {
    /// No row exists anywhere in this Source writer.
    Empty,
    /// An absent target under actual existing-instance data, never signed Empty.
    VacantProject,
    /// An exact initial Tree remains fenced awaiting authenticated floor ACK.
    Prepared,
    /// The exact receipt has a local ACK; current Root authority is separate.
    Anchored,
}

/// Retains the actual named Source writer borrow and its typed genesis readback.
///
/// This is not serializable, cloneable, a Root floor, or ancestry authority.
/// The enclosing Source owner remains held after this borrow is dropped for
/// the exact ACK. Controller and the original Root flight must remain held too.
#[must_use = "the Source cut must remain borrowed across its Root floor handoff"]
pub struct HeldSourceTreeGenesisObservationV1<'source> {
    journal: &'source Journal,
    uid: u32,
    names: ProtectedJournalNamesV1,
    sequence: u64,
    rows: SourceGenesisRowsV1,
    selection: SourceGenesisSelectionV1,
    location: SourceGenesisLocationV1,
}

#[derive(Clone, Copy)]
enum SourceGenesisSelectionV1 {
    GlobalEmpty,
    Present(ProjectId),
    Vacant(ProjectId),
}

enum SourceGenesisLocationV1 {
    Fixed,
    #[cfg(test)]
    Test(PathBuf),
}

impl SourceGenesisLocationV1 {
    fn recheck(&self, journal: &Journal, uid: u32) -> Result<(), SourceGenesisErrorV1> {
        journal.ensure_healthy()?;
        match self {
            Self::Fixed => require_location(journal, uid),
            #[cfg(test)]
            Self::Test(directory) => {
                journal.require_protected_named_location_at_uid_for_test(
                    directory,
                    PROTECTED_SOURCE_DOMAIN_JOURNAL,
                    uid,
                    crate::JournalLimits::default(),
                )?;
                Ok(())
            }
        }
    }
}

impl HeldSourceTreeGenesisObservationV1<'_> {
    // Same original owner, not equality of detached names or receipt data.
    #[cfg(target_os = "linux")]
    pub(crate) fn require_retained_inventory_v1(
        &self,
        inventory: &super::protected_journal::RetainedTreeInventoryDataV1<'_>,
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

    /// Returns the actual observed phase, not Root authority or freshness.
    #[must_use]
    pub fn state(&self) -> SourceTreeGenesisStateV1 {
        match self.selection {
            SourceGenesisSelectionV1::GlobalEmpty => SourceTreeGenesisStateV1::Empty,
            SourceGenesisSelectionV1::Vacant(_) => SourceTreeGenesisStateV1::VacantProject,
            SourceGenesisSelectionV1::Present(project) if self.rows.acks.contains_key(&project) => {
                SourceTreeGenesisStateV1::Anchored
            }
            SourceGenesisSelectionV1::Present(_) => SourceTreeGenesisStateV1::Prepared,
        }
    }

    /// Returns the selected actual target, absent only for global Empty.
    #[must_use]
    pub const fn project(&self) -> Option<ProjectId> {
        match self.selection {
            SourceGenesisSelectionV1::GlobalEmpty => None,
            SourceGenesisSelectionV1::Present(project)
            | SourceGenesisSelectionV1::Vacant(project) => Some(project),
        }
    }

    /// Returns the actual retained instance claim, never Root authority.
    ///
    /// A vacant-project cut derives this only from the other anchored receipts.
    /// Root must compare it with its independently held existing instance.
    #[must_use]
    pub fn instance(&self) -> Option<[u8; 32]> {
        match self.selection {
            SourceGenesisSelectionV1::GlobalEmpty => None,
            SourceGenesisSelectionV1::Present(project) => self
                .rows
                .receipts
                .get(&project)
                .map(|receipt| receipt.instance()),
            SourceGenesisSelectionV1::Vacant(_) => self
                .rows
                .receipts
                .values()
                .next()
                .map(|receipt| receipt.instance()),
        }
    }

    /// Borrows the exact receipt, absent for Empty or the distinct vacant target.
    #[must_use]
    pub fn receipt(&self) -> Option<&SourceTreeGenesisReceiptV1> {
        self.project()
            .and_then(|project| self.rows.receipts.get(&project))
    }

    /// Returns the retained exact local Root-floor ACK digest, if anchored.
    #[must_use]
    pub fn ack_floor_digest(&self) -> Option<ObjectDigest> {
        self.project()
            .and_then(|project| self.rows.acks.get(&project))
            .map(|ack| ack.root_floor)
    }

    /// Returns the actual canonical local ACK commitment, if anchored.
    #[must_use]
    pub fn ack_record_digest(&self) -> Option<ObjectDigest> {
        self.project()
            .and_then(|project| self.rows.acks.get(&project))
            .map(SourceGenesisAckV1::digest)
    }

    /// Returns diagnostic original fixed names, not standalone custody authority.
    #[must_use]
    pub const fn names(&self) -> ProtectedJournalNamesV1 {
        self.names
    }

    /// Returns the diagnostic frame boundary, never the semantic rollback floor.
    #[must_use]
    pub const fn snapshot_sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the configured UID rechecked against this actual fixed writer.
    #[must_use]
    pub const fn source_uid(&self) -> u32 {
        self.uid
    }

    /// Rechecks the exact healthy writer, physical names, frame cut and rows.
    ///
    /// # Errors
    ///
    /// Rejects changed or unsafe names, a poisoned writer, or changed state.
    pub fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        self.location.recheck(self.journal, self.uid)?;
        if self.journal.protected_writer_physical_names_v1()? != self.names
            || self.journal.snapshot_sequence() != self.sequence
            || self.journal.source_tree_genesis_rows_v1()? != self.rows
        {
            return Err(SourceGenesisErrorV1::Stale);
        }
        Ok(())
    }
}

/// Appends genuine administrative genesis and its pending-floor fence atomically.
///
/// The opaque Controller and Root tokens retain real protected writers and the
/// original authenticated connection. Their fields cannot be reconstructed
/// from historical signed bytes. Exact prepared retries are readback-only.
/// Append plus the full fixed-width ACK suffix is preflighted before mutation;
/// ambiguity poisons the journal and requires exact protected cold recovery.
///
/// # Errors
///
/// Rejects missing or stale owner cuts, foreign instance/intent/acceptance,
/// unsafe fixed Source names, an occupied project or another pending flight,
/// malformed history, insufficient suffix capacity, and append/readback failure.
#[cfg(target_os = "linux")]
pub fn append_source_tree_genesis_v1<'source>(
    source: &'source mut ProtectedSourceDomainJournalOwnerV1,
    controller: &HeldControllerSourceGenesisV1<'_>,
    root: &HeldRootSourceGenesisIntentV1<'_>,
) -> Result<HeldSourceTreeGenesisObservationV1<'source>, SourceGenesisErrorV1> {
    controller.recheck()?;
    root.recheck()?;
    let intent = root.record();
    let acceptance = controller.acceptance();
    if intent.project() != acceptance.project() || intent.acceptance() != acceptance.digest() {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    let journal = source.journal();
    require_location(journal, intent.source_uid())?;
    let rows = validate_actual_rows(journal)?;
    let project = acceptance.project();
    if let Some(receipt) = rows.receipts.get(&project) {
        if receipt.instance() != intent.instance()
            || receipt.intent_digest() != intent.digest()
            || receipt.acceptance_digest() != acceptance.digest()
            || &receipt.seed_packet() != acceptance.seed_packet()
            || &receipt.auth_packet() != acceptance.auth_packet()
            || rows.pending.as_ref().is_some_and(|pending| {
                pending.project != project
                    || pending.nonce != intent.nonce()
                    || journal.protected_writer_physical_names_v1().ok() != Some(pending.names)
            })
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
    } else {
        controller.recheck_current_admission()?;
        root.recheck_current_admission()?;
        if rows.pending.is_some()
            || rows
                .receipts
                .values()
                .any(|receipt| receipt.instance() != intent.instance())
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        let transaction_id = transaction_id(b"append", intent.digest());
        let pair = prepare_source_tree_genesis_pair_v1(
            journal,
            *acceptance.seed_packet(),
            transaction_id,
        )?;
        let [tree, lineage] = pair.records.as_slice() else {
            return Err(SourceGenesisErrorV1::NonCanonical);
        };
        let receipt = SourceTreeGenesisReceiptV1::from_owner_fields(
            intent.instance(),
            intent.digest(),
            acceptance,
            pair.tree_head,
            pair.lineage_head,
            tree.value().ok_or(SourceGenesisErrorV1::NonCanonical)?,
            lineage.value().ok_or(SourceGenesisErrorV1::NonCanonical)?,
        )?;
        let pending = SourceGenesisPendingV1 {
            instance: intent.instance(),
            project,
            intent: intent.digest(),
            receipt: receipt.digest(),
            nonce: intent.nonce(),
            names: journal.protected_writer_physical_names_v1()?,
        };
        let mut records = pair.records;
        records.push(JournalRecord::put(
            RecordNamespace::DesiredState,
            receipt_key(project),
            receipt.encode().to_vec(),
        ));
        records.push(JournalRecord::put(
            RecordNamespace::DesiredState,
            PENDING_KEY.to_vec(),
            pending.encode().to_vec(),
        ));
        let append = JournalTransaction::new(transaction_id, records)?;
        // These fixed-width placeholders reserve space only. The actual ACK
        // producer still requires the genuine Root and Controller proof borrows.
        let suffix = ack_transaction(&SourceGenesisAckV1 {
            instance: intent.instance(),
            project,
            receipt: receipt.digest(),
            root_floor: ObjectDigest::from_bytes([1; 32]),
            controller_floor: ObjectDigest::from_bytes([1; 32]),
        })?;
        journal.preflight_source_tree_genesis_v1(
            &[append.clone(), suffix],
            &[
                SourceGenesisTransitionV1::Append,
                SourceGenesisTransitionV1::Anchor,
            ],
        )?;
        controller.recheck()?;
        root.recheck()?;
        controller.recheck_current_admission()?;
        root.recheck_current_admission()?;
        require_location(journal, intent.source_uid())?;
        journal.commit_source_tree_genesis_v1(&append, SourceGenesisTransitionV1::Append)?;
        let actual = validate_actual_rows(journal)?;
        if actual.receipts.get(&project) != Some(&receipt)
            || actual.pending.as_ref() != Some(&pending)
        {
            return Err(SourceGenesisErrorV1::Stale);
        }
    }
    controller.recheck()?;
    root.recheck()?;
    observation(journal, intent.source_uid(), Some(project))
}

/// Anchors exactly one prepared Source genesis after real Controller acceptance.
///
/// No decoded receipt or floor may call this path. The Root proof borrows the
/// original authenticated flight, and Controller revalidates its exact accepted
/// floor while its protected writer stays held through append and readback.
/// The returned actual Source ACK readback is required for Controller's final
/// completion; Controller's floor ACK alone does not lift its own fence.
///
/// # Errors
///
/// Rejects stale/foreign live owner proofs, receipt/semantic-head substitution,
/// changed Source names or pending nonce lineage, conflicting prior ACK,
/// capacity failure, and ambiguous append/readback.
#[cfg(target_os = "linux")]
pub fn acknowledge_source_tree_genesis_v1<'source>(
    source: &'source mut ProtectedSourceDomainJournalOwnerV1,
    controller: &HeldControllerSourceGenesisV1<'_>,
    root: &RootSourceGenesisFloorProofV1<'_>,
) -> Result<HeldSourceTreeGenesisObservationV1<'source>, SourceGenesisErrorV1> {
    controller.recheck()?;
    root.recheck()?;
    let floor = root.floor();
    let journal = source.journal();
    require_location(journal, root.source_uid())?;
    let rows = validate_actual_rows(journal)?;
    let receipt = rows
        .receipts
        .get(&floor.project())
        .ok_or(SourceGenesisErrorV1::Stale)?;
    if receipt.instance() != floor.instance()
        || receipt.digest() != floor.receipt_digest()
        || receipt.tree_head() != floor.tree_head()
        || receipt.lineage_head() != floor.lineage_head()
        || receipt.materialization() != floor.materialization()
        || floor.semantic_revision() != 1
        || floor.predecessor().is_some()
    {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    controller.validate_source_ack(receipt, floor)?;
    let ack = SourceGenesisAckV1 {
        instance: receipt.instance(),
        project: receipt.project(),
        receipt: receipt.digest(),
        root_floor: floor.digest(),
        controller_floor: controller.accepted_floor_digest()?,
    };
    match rows.acks.get(&receipt.project()) {
        Some(current) if current == &ack => {}
        Some(_) => return Err(SourceGenesisErrorV1::Conflict),
        None => {
            let pending = rows.pending.as_ref().ok_or(SourceGenesisErrorV1::Stale)?;
            if pending.project != receipt.project()
                || pending.receipt != receipt.digest()
                || pending.names != journal.protected_writer_physical_names_v1()?
            {
                return Err(SourceGenesisErrorV1::Stale);
            }
            let transaction = ack_transaction(&ack)?;
            journal.preflight_source_tree_genesis_v1(
                std::slice::from_ref(&transaction),
                &[SourceGenesisTransitionV1::Anchor],
            )?;
            controller.recheck()?;
            root.recheck()?;
            controller.validate_source_ack(receipt, floor)?;
            require_location(journal, root.source_uid())?;
            journal
                .commit_source_tree_genesis_v1(&transaction, SourceGenesisTransitionV1::Anchor)?;
        }
    }
    let actual = validate_actual_rows(journal)?;
    if actual.pending.is_some() || actual.acks.get(&ack.project) != Some(&ack) {
        return Err(SourceGenesisErrorV1::Stale);
    }
    controller.recheck()?;
    root.recheck()?;
    controller.validate_source_ack(
        actual
            .receipts
            .get(&ack.project)
            .ok_or(SourceGenesisErrorV1::Stale)?,
        floor,
    )?;
    observation(journal, root.source_uid(), Some(ack.project))
}

/// Borrows actual whole-absence or exact project data from the fixed Source owner.
///
/// `expected_source_uid` comes from privileged configuration, not journal
/// metadata. Even an Anchored observation is not a live Root floor; current
/// ancestry requires an independent authenticated Root owner join.
///
/// # Errors
///
/// Rejects unsafe names, mixed/unreceipted Tree history, malformed or orphaned
/// genesis rows, or project absence when any other genesis/Tree state exists.
pub fn observe_source_tree_genesis_v1(
    source: &mut ProtectedSourceDomainJournalOwnerV1,
    expected_source_uid: u32,
    project: Option<ProjectId>,
) -> Result<HeldSourceTreeGenesisObservationV1<'_>, SourceGenesisErrorV1> {
    observation(source.journal(), expected_source_uid, project)
}

/// Borrows a genuine vacant target under the actual existing Source instance.
///
/// This DATA cut never becomes a signed global Empty, ancestry or Root proof.
/// The caller must retain its Source writer while genuine Root joins the exact
/// target and observed instance to its independent existing instance and floor.
/// No instance may be nominated by a caller or reconstructed from a lookup miss.
///
/// # Errors
///
/// Rejects unsafe names, missing existing-instance rows, malformed whole replay,
/// a zero or occupied target, or any global pending genesis flight.
pub fn observe_vacant_source_tree_genesis_project_v1(
    source: &mut ProtectedSourceDomainJournalOwnerV1,
    expected_source_uid: u32,
    project: ProjectId,
) -> Result<HeldSourceTreeGenesisObservationV1<'_>, SourceGenesisErrorV1> {
    capture_observation(
        source.journal(),
        expected_source_uid,
        SourceGenesisSelectionV1::Vacant(project),
        SourceGenesisLocationV1::Fixed,
    )
}

// Selection is derived under the real named writer, not nominated by a
// caller or recovered from a failed lookup. Root independently verifies this
// whole-source cut before granting the deployment instance or project floor.
#[cfg(target_os = "linux")]
pub(crate) fn observe_source_genesis_attempt_v1(
    source: &mut ProtectedSourceDomainJournalOwnerV1,
    expected_source_uid: u32,
    project: ProjectId,
) -> Result<HeldSourceTreeGenesisObservationV1<'_>, SourceGenesisErrorV1> {
    let journal = source.journal();
    require_location(journal, expected_source_uid)?;
    let rows = validate_actual_rows(journal)?;
    let selection = if rows.receipts.contains_key(&project) {
        SourceGenesisSelectionV1::Present(project)
    } else if rows.receipts.is_empty() {
        // Fresh deployment instance creation requires whole-source absence,
        // not just a missing Tree. Reject locally before Controller admission;
        // Root's separate Source signer still verifies all-source Empty itself.
        if journal.all_records().next().is_some() {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        SourceGenesisSelectionV1::GlobalEmpty
    } else {
        SourceGenesisSelectionV1::Vacant(project)
    };
    capture_validated_observation(
        journal,
        expected_source_uid,
        selection,
        SourceGenesisLocationV1::Fixed,
        rows,
    )
}

fn observation(
    journal: &mut Journal,
    uid: u32,
    project: Option<ProjectId>,
) -> Result<HeldSourceTreeGenesisObservationV1<'_>, SourceGenesisErrorV1> {
    observation_at(journal, uid, project, SourceGenesisLocationV1::Fixed)
}

fn observation_at(
    journal: &mut Journal,
    uid: u32,
    project: Option<ProjectId>,
    location: SourceGenesisLocationV1,
) -> Result<HeldSourceTreeGenesisObservationV1<'_>, SourceGenesisErrorV1> {
    let selection = project.map_or(
        SourceGenesisSelectionV1::GlobalEmpty,
        SourceGenesisSelectionV1::Present,
    );
    capture_observation(journal, uid, selection, location)
}

fn capture_observation(
    journal: &mut Journal,
    uid: u32,
    selection: SourceGenesisSelectionV1,
    location: SourceGenesisLocationV1,
) -> Result<HeldSourceTreeGenesisObservationV1<'_>, SourceGenesisErrorV1> {
    location.recheck(journal, uid)?;
    let rows = validate_actual_rows(journal)?;
    capture_validated_observation(journal, uid, selection, location, rows)
}

// Both callers validate these rows under the same unchanged sole-writer
// borrow. This avoids a second full Tree/lineage replay just to select a cut;
// it cannot adopt decoded/historical rows across owners or coordinator phases.
fn capture_validated_observation(
    journal: &Journal,
    uid: u32,
    selection: SourceGenesisSelectionV1,
    location: SourceGenesisLocationV1,
    rows: SourceGenesisRowsV1,
) -> Result<HeldSourceTreeGenesisObservationV1<'_>, SourceGenesisErrorV1> {
    location.recheck(journal, uid)?;
    let valid_selection = match selection {
        SourceGenesisSelectionV1::GlobalEmpty => {
            rows.receipts.is_empty()
                && rows.pending.is_none()
                && rows.acks.is_empty()
                && journal.all_records().next().is_none()
        }
        SourceGenesisSelectionV1::Present(project) => rows.receipts.contains_key(&project),
        SourceGenesisSelectionV1::Vacant(project) => {
            project.as_bytes() != &[0; 16]
                && !rows.receipts.is_empty()
                && rows.pending.is_none()
                && !rows.receipts.contains_key(&project)
        }
    };
    if !valid_selection {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    let observation = HeldSourceTreeGenesisObservationV1 {
        uid,
        names: journal.protected_writer_physical_names_v1()?,
        sequence: journal.snapshot_sequence(),
        rows,
        selection,
        journal,
        location,
    };
    observation.recheck()?;
    Ok(observation)
}

/// Replays actual genesis members without granting ancestry or Root authority.
pub(crate) fn validate_actual_rows(
    journal: &mut Journal,
) -> Result<SourceGenesisRowsV1, SourceGenesisErrorV1> {
    let rows = journal.source_tree_genesis_rows_v1()?;
    let heads = replay_closed_tree_lineage_v1(journal)?;
    validate_rows_with_lineage(journal, rows, &heads)
}

// The inventory already performed the same complete lineage replay while
// borrowing this original writer. Reuse the receipt/member validator below;
// neither a decoded row nor an unrelated journal can nominate this cut.
#[cfg(target_os = "linux")]
pub(crate) fn observe_retained_source_genesis_v1<'source>(
    inventory: &'source super::protected_journal::RetainedTreeInventoryDataV1<'_>,
    uid: u32,
    project: ProjectId,
) -> Result<HeldSourceTreeGenesisObservationV1<'source>, SourceGenesisErrorV1> {
    inventory.recheck()?;
    let journal = inventory.journal();
    require_location(journal, uid)?;
    let rows = validate_rows_with_lineage(
        journal,
        journal.source_tree_genesis_rows_v1()?,
        inventory.heads(),
    )?;
    let observed = capture_validated_observation(
        journal,
        uid,
        SourceGenesisSelectionV1::Present(project),
        SourceGenesisLocationV1::Fixed,
        rows,
    )?;
    inventory.recheck()?;
    Ok(observed)
}

fn validate_rows_with_lineage(
    journal: &Journal,
    rows: SourceGenesisRowsV1,
    heads: &std::collections::BTreeMap<ProjectId, super::tree_lineage::ClosedTreeLineageHeadV1>,
) -> Result<SourceGenesisRowsV1, SourceGenesisErrorV1> {
    if heads.len() != rows.receipts.len()
        || heads
            .keys()
            .any(|project| !rows.receipts.contains_key(project))
    {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    for receipt in rows.receipts.values() {
        let head = heads
            .get(&receipt.project())
            .ok_or(SourceGenesisErrorV1::Conflict)?;
        let (tree_head, lineage_head, tree, lineage) = source_tree_genesis_members_v1(
            journal,
            head,
            receipt.project(),
            &receipt.seed_packet(),
        )?;
        if tree_head != receipt.tree_head()
            || lineage_head != receipt.lineage_head()
            || !receipt.matches_members(&tree, &lineage)
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
    }
    Ok(rows)
}

fn require_location(journal: &Journal, uid: u32) -> Result<(), SourceGenesisErrorV1> {
    if uid == 0 {
        return Err(SourceGenesisErrorV1::Stale);
    }
    journal.require_protected_named_location(
        Path::new(PROTECTED_SOURCE_DOMAIN_ROOT),
        PROTECTED_SOURCE_DOMAIN_JOURNAL,
        uid,
        source_domain_journal_limits(),
    )?;
    Ok(())
}

fn ack_transaction(ack: &SourceGenesisAckV1) -> Result<JournalTransaction, crate::JournalError> {
    JournalTransaction::new(
        transaction_id(b"anchor", ack.receipt),
        vec![
            JournalRecord::delete(RecordNamespace::DesiredState, PENDING_KEY.to_vec()),
            JournalRecord::put(
                RecordNamespace::DesiredState,
                ack_key(ack.project),
                ack.encode().to_vec(),
            ),
        ],
    )
}

fn transaction_id(kind: &[u8], digest: ObjectDigest) -> [u8; 16] {
    let hash: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.source-tree-genesis.transaction.v1\0")
        .chain_update(kind)
        .chain_update(digest.as_bytes())
        .finalize()
        .into();
    let mut id = [0; 16];
    id.copy_from_slice(&hash[..16]);
    id
}

#[cfg(test)]
pub(crate) mod tests;
