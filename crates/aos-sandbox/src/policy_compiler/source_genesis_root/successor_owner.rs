//! Actual Root successor owner and shared native provenance reducer.
//!
//! The stored floor is an immutable archive, not merely the wire floor:
//!
//! ```text
//! DesiredState[intent-prefix || project16] = Intent1248
//! DesiredState[floor-prefix || project16] = Floor688 || original Intent1248
//! Prepare = intent PUT | reserve PUT
//! Anchor = archive PUT | intent DELETE | reserve DELETE
//! ```
//!
//! Both archive members are independently canonical and fully joined. Keeping
//! the original intent allows cold settlement without reconstructing its nonce,
//! boot or deadline. Neither replay nor an archive decoder renews admission.

use std::collections::BTreeMap;

use aos_sandbox_core::{ObjectDigest, ProjectId};

use crate::hierarchy::genesis_profile::{SourceGenesisErrorV1, digest_at, take};
use crate::journal::source_tree_successor::{
    FirstSourceSuccessorNativePhaseV2 as Phase, capacity_request,
    require_exact_capacity_family, sizing_capacity_delete, touches_capacity_purpose, transaction_id,
};
use crate::journal::{
    GlobalCapacityReservationPurposeV1 as Purpose, GlobalCapacityReservationRequestV1, Journal,
    CommitResult, JournalError, JournalRecord, JournalTransaction, RecordNamespace,
    first_source_successor_capacity_delete_v2, first_source_successor_capacity_identity_v2,
    first_source_successor_capacity_record_v2,
};

use super::records::{FLOOR_PREFIX, INSTANCE_KEY, PINS_KEY, SourceHierarchyFloorRecordV1, decode_instance};
use super::successor_records::{
    RootFirstSourceSuccessorFloorFieldsV2, RootFirstSourceSuccessorFloorV2,
    RootFirstSourceSuccessorIntentFieldsV2, RootFirstSourceSuccessorIntentV2, SourceFirstSuccessorReceiptV2,
};

const PREFIX: &[u8] = b"\0aos-root-first-source-successor-v2\0";
const INTENT_PREFIX: &[u8] = b"\0aos-root-first-source-successor-v2\0intent\0";
const SUCCESSOR_FLOOR_PREFIX: &[u8] = b"\0aos-root-first-source-successor-v2\0floor\0";
const ARCHIVE_BYTES: usize = 1936;

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RootFirstSourceSuccessorArchiveV2 {
    pub(super) floor: RootFirstSourceSuccessorFloorV2,
    pub(super) original: RootFirstSourceSuccessorIntentV2,
}

impl RootFirstSourceSuccessorArchiveV2 {
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, SourceGenesisErrorV1> {
        if bytes.len() != ARCHIVE_BYTES {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        let archive = Self {
            floor: RootFirstSourceSuccessorFloorV2::decode(&bytes[..688])?,
            original: RootFirstSourceSuccessorIntentV2::decode(&bytes[688..])?,
        };
        require_receipt_intent(archive.floor.receipt(), &archive.original)?;
        if archive.floor.approval() != archive.original.approval()
            || archive.floor.roles() != archive.original.roles()
            || archive.floor.predecessor_floor() != archive.original.predecessor_floor()
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        Ok(archive)
    }

    pub(super) fn bytes(&self) -> Vec<u8> {
        [self.floor.as_bytes().as_slice(), self.original.as_bytes().as_slice()].concat()
    }
}

#[derive(Default)]
struct Rows {
    intent: Option<RootFirstSourceSuccessorIntentV2>,
    archive: Option<RootFirstSourceSuccessorArchiveV2>,
}

// All members are historical comparison DATA. A selected active intent is
// not admitted by archive counts or by this structural fold.
struct ProjectRowsV3 {
    intent: Option<RootFirstSourceSuccessorIntentV2>,
    archives: BTreeMap<ProjectId, RootFirstSourceSuccessorArchiveV2>,
}

fn project_rows_v3(state: &State, selected: Option<ProjectId>) -> Result<ProjectRowsV3, JournalError> {
    let mut retained = ProjectRowsV3 { intent: None, archives: BTreeMap::new() };
    for ((namespace, member_key), value) in state {
        if !member_key.starts_with(PREFIX) { continue; }
        if *namespace != RecordNamespace::DesiredState { return Err(JournalError::ProtectedBoundary); }
        if member_key.starts_with(INTENT_PREFIX) {
            let intent = RootFirstSourceSuccessorIntentV2::decode(value)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            if member_key != &intent_key(&intent) || selected != Some(intent.project())
                || retained.intent.replace(intent).is_some()
            { return Err(JournalError::ProtectedBoundary); }
        } else if member_key.starts_with(SUCCESSOR_FLOOR_PREFIX) {
            let archive = RootFirstSourceSuccessorArchiveV2::decode(value)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            if member_key != &floor_key(&archive.floor)
                || retained.archives.insert(archive.original.project(), archive).is_some()
            { return Err(JournalError::ProtectedBoundary); }
        } else { return Err(JournalError::ProtectedBoundary); }
    }
    if retained.intent.as_ref().is_some_and(|intent| retained.archives.contains_key(&intent.project())) {
        return Err(JournalError::ProtectedBoundary);
    }
    for archive in retained.archives.values() {
        require_predecessor(state, &archive.original)?;
    }
    if let Some(intent) = &retained.intent {
        require_predecessor(state, intent)?;
        first_source_successor_capacity_delete_v2(
            state, &root_capacity_request(intent)?, transaction_id(intent.approval(), Phase::RootPrepared),
        )?;
    }
    require_exact_capacity_family(state, Purpose::RootFirstSourceSuccessorAnchor,
        usize::from(retained.intent.is_some()))?;
    Ok(retained)
}

impl super::store::RootSourceGenesisAuthorityV1 {
    // An associated DATA fold avoids a new parent-module export or any new
    // authority constructor. Native cold/compaction callers borrow real maps.
    pub(crate) fn validate_project_successor_replay_v3(state: &State) -> Result<(), JournalError> {
        let mut selected = None;
        for ((namespace, member_key), value) in state {
            if member_key.starts_with(INTENT_PREFIX) {
                if *namespace != RecordNamespace::DesiredState || selected.is_some() {
                    return Err(JournalError::ProtectedBoundary);
                }
                selected = Some(RootFirstSourceSuccessorIntentV2::decode(value)
                    .map_err(|_| JournalError::ProtectedBoundary)?.project());
            }
        }
        project_rows_v3(state, selected)?;
        Ok(())
    }

    pub(crate) fn validate_project_successor_transition_v3(
        state: &State, transaction: &JournalTransaction, phase: Option<Phase>,
    ) -> Result<Option<[u8; 32]>, JournalError> {
        let canonical = phase.map(Phase::canonical);
        let selected = if canonical == Some(Phase::RootPrepared) {
            let put = transaction.records().first().ok_or(JournalError::ProtectedBoundary)?;
            Some(RootFirstSourceSuccessorIntentV2::decode(
                put.value().ok_or(JournalError::ProtectedBoundary)?,
            ).map_err(|_| JournalError::ProtectedBoundary)?.project())
        } else {
            let mut selected = None;
            for ((namespace, member_key), value) in state {
                if member_key.starts_with(INTENT_PREFIX) {
                    if *namespace != RecordNamespace::DesiredState || selected.is_some() {
                        return Err(JournalError::ProtectedBoundary);
                    }
                    selected = Some(RootFirstSourceSuccessorIntentV2::decode(value)
                        .map_err(|_| JournalError::ProtectedBoundary)?.project());
                }
            }
            selected
        };
        let before = project_rows_v3(state, selected)?;
        let touches = transaction.records().iter().any(|record| record.key().starts_with(PREFIX))
            || touches_capacity_purpose(state, transaction, Purpose::RootFirstSourceSuccessorAnchor)?;
        if !touches {
            if matches!(canonical, Some(Phase::RootPrepared | Phase::RootAnchor)) || before.intent.is_some() {
                return Err(JournalError::ProtectedBoundary);
            }
            return Ok(None);
        }
        let settled = match canonical {
            Some(Phase::RootPrepared) => {
                let [put, reservation] = transaction.records() else { return Err(JournalError::ProtectedBoundary); };
                let intent = RootFirstSourceSuccessorIntentV2::decode(put.value().ok_or(JournalError::ProtectedBoundary)?)
                    .map_err(|_| JournalError::ProtectedBoundary)?;
                require_predecessor(state, &intent)?;
                let request = root_capacity_request(&intent)?;
                let admission = transaction_id(intent.approval(), Phase::RootPrepared);
                if before.intent.is_some() || before.archives.contains_key(&intent.project())
                    || put.namespace() != RecordNamespace::DesiredState || put.key() != intent_key(&intent)
                    || transaction.id() != &admission
                    || reservation != &first_source_successor_capacity_record_v2(&request, admission)?
                { return Err(JournalError::ProtectedBoundary); }
                None
            }
            Some(Phase::RootAnchor) => {
                let intent = before.intent.as_ref().ok_or(JournalError::ProtectedBoundary)?;
                let [put, deletion, settlement] = transaction.records() else { return Err(JournalError::ProtectedBoundary); };
                let archive = RootFirstSourceSuccessorArchiveV2::decode(put.value().ok_or(JournalError::ProtectedBoundary)?)
                    .map_err(|_| JournalError::ProtectedBoundary)?;
                let request = root_capacity_request(intent)?;
                let admission = transaction_id(intent.approval(), Phase::RootPrepared);
                if &archive.original != intent || put.namespace() != RecordNamespace::DesiredState
                    || put.key() != floor_key(&archive.floor) || before.archives.contains_key(&intent.project())
                    || transaction.id() != &transaction_id(intent.approval(), Phase::RootAnchor)
                    || deletion != &JournalRecord::delete(RecordNamespace::DesiredState, intent_key(intent))
                    || settlement != &first_source_successor_capacity_delete_v2(state, &request, admission)?
                { return Err(JournalError::ProtectedBoundary); }
                Some(first_source_successor_capacity_identity_v2(&request, admission)?)
            }
            _ => return Err(JournalError::ProtectedBoundary),
        };
        let after = crate::journal::root_original_inventory::materialize(state, transaction);
        let prospective = project_rows_v3(&after, selected)?;
        if before.archives.iter().any(|(project, archive)| prospective.archives.get(project) != Some(archive)) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(settled)
    }
}

fn key(prefix: &[u8], project: ProjectId) -> Vec<u8> {
    [prefix, project.as_bytes()].concat()
}

pub(super) fn intent_key(intent: &RootFirstSourceSuccessorIntentV2) -> Vec<u8> {
    key(INTENT_PREFIX, intent.project())
}

pub(super) fn floor_key(floor: &RootFirstSourceSuccessorFloorV2) -> Vec<u8> {
    key(SUCCESSOR_FLOOR_PREFIX, floor.receipt().project())
}

fn journal_state(journal: &Journal) -> State {
    journal.all_records().map(|(namespace, key, value)| {
        ((namespace, key.to_vec()), value.to_vec())
    }).collect()
}

fn rows(state: &State) -> Result<Rows, JournalError> {
    let mut rows = Rows::default();
    for ((namespace, key), value) in state {
        if !key.starts_with(PREFIX) {
            continue;
        }
        if *namespace != RecordNamespace::DesiredState {
            return Err(JournalError::ProtectedBoundary);
        }
        if key.starts_with(INTENT_PREFIX) {
            let intent = RootFirstSourceSuccessorIntentV2::decode(value)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            if key != &intent_key(&intent) || rows.intent.replace(intent).is_some() {
                return Err(JournalError::ProtectedBoundary);
            }
        } else if key.starts_with(SUCCESSOR_FLOOR_PREFIX) {
            let archive = RootFirstSourceSuccessorArchiveV2::decode(value)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            if key != &floor_key(&archive.floor) || rows.archive.replace(archive).is_some() {
                return Err(JournalError::ProtectedBoundary);
            }
        } else {
            return Err(JournalError::ProtectedBoundary);
        }
    }
    if rows.intent.is_some() && rows.archive.is_some() {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(rows)
}

pub(super) fn retained_root_first_successor_v2(
    journal: &Journal,
    project: ProjectId,
) -> Result<Option<RootFirstSourceSuccessorIntentV2>, SourceGenesisErrorV1> {
    let retained = rows(&journal_state(journal))?;
    let original = retained.intent.or_else(|| retained.archive.map(|archive| archive.original));
    match original {
        Some(original) if original.project() == project => Ok(Some(original)),
        Some(_) | None => Ok(None),
    }
}

pub(crate) fn require_root_first_source_successor_capacity_owner_v2(
    journal: &Journal,
) -> Result<(), JournalError> {
    super::capacity::require_owner(journal)
}

pub(super) fn validate_root_first_successor_journal_v2(
    journal: &Journal,
) -> Result<(), SourceGenesisErrorV1> {
    let state = journal_state(journal);
    // This store hook compares retained DATA only. Keep singleton validation
    // and its allocations/errors in the old order; a foreign actual project
    // key selects the complete structural fold, never a live floor permit.
    let mut first_project = None;
    let has_foreign_project = state.keys().any(|(_, key)| {
        let project = key.strip_prefix(INTENT_PREFIX)
            .or_else(|| key.strip_prefix(SUCCESSOR_FLOOR_PREFIX));
        match (first_project, project) {
            (None, Some(project)) => { first_project = Some(project); false }
            (Some(first), Some(project)) => first != project,
            _ => false,
        }
    });
    if has_foreign_project {
        super::store::RootSourceGenesisAuthorityV1::validate_project_successor_replay_v3(&state)?;
    } else {
        validate_root_first_source_successor_state_v2(&state)?;
    }
    Ok(())
}

pub(crate) fn validate_root_first_source_successor_state_v2(state: &State)
    -> Result<(), JournalError>
{
    let rows = rows(state)?;
    let original = rows.intent.as_ref().or_else(|| rows.archive.as_ref().map(|row| &row.original));
    if let Some(original) = original {
        require_predecessor(state, original)?;
    }
    if let Some(intent) = &rows.intent {
        first_source_successor_capacity_delete_v2(
            state, &root_capacity_request(intent)?, transaction_id(intent.approval(), Phase::RootPrepared),
        )?;
    }
    require_exact_capacity_family(state, Purpose::RootFirstSourceSuccessorAnchor, usize::from(rows.intent.is_some()))
}

fn require_predecessor(state: &State, intent: &RootFirstSourceSuccessorIntentV2)
    -> Result<(), JournalError>
{
    let get = |key: &[u8]| state.get(&(RecordNamespace::DesiredState, key.to_vec()))
        .map(Vec::as_slice).ok_or(JournalError::ProtectedBoundary);
    let instance = decode_instance(get(INSTANCE_KEY)?)
        .map_err(|_| JournalError::ProtectedBoundary)?;
    let pins = get(PINS_KEY)?;
    let roles = super::pins::role_tuple_digest(pins)
        .map_err(|_| JournalError::ProtectedBoundary)?;
    super::pins::verify_retained_first_source_successor_v2(pins, intent.approval_packet())
        .map_err(|_| JournalError::ProtectedBoundary)?;
    let predecessor = SourceHierarchyFloorRecordV1::from_record_bytes(
        get(&key(FLOOR_PREFIX, intent.project()))?,
    ).map_err(|_| JournalError::ProtectedBoundary)?;
    let body = intent.approval_packet().body();
    if instance != intent.instance() || roles != intent.roles()
        || predecessor.instance() != instance || predecessor.roles() != roles
        || predecessor.digest() != intent.predecessor_floor()
        || predecessor.receipt().tree_head() != intent.old_tree_head()
        || predecessor.receipt().lineage_head() != intent.old_lineage_head()
        || predecessor.roles().as_bytes() != &body[112..144]
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

pub(super) fn require_receipt_intent(
    receipt: &SourceFirstSuccessorReceiptV2,
    intent: &RootFirstSourceSuccessorIntentV2,
) -> Result<(), SourceGenesisErrorV1> {
    let body = intent.approval_packet().body();
    if receipt.instance() != intent.instance() || receipt.project() != intent.project()
        || receipt.request() != intent.request() || receipt.approval() != intent.approval()
        || receipt.epoch() != intent.epoch() || receipt.root_intent() != intent.digest()
        || receipt.begin() != intent.begin() || receipt.roles() != intent.roles()
        || receipt.predecessor_floor() != intent.predecessor_floor()
        || receipt.old_tree_head() != intent.old_tree_head()
        || receipt.old_lineage_head() != intent.old_lineage_head()
        || receipt.old_tree_commit().as_bytes() != &body[600..632]
        || receipt.next_tree_commit() != intent.next_tree_commit()
        || receipt.source_names() != intent.source_names()
    {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    Ok(())
}

pub(super) fn root_capacity_request(intent: &RootFirstSourceSuccessorIntentV2)
    -> Result<GlobalCapacityReservationRequestV1, JournalError>
{
    // Only shape: successor envelope heads do not exist before Source append.
    // This exact physical archive width includes the preserved original intent.
    let suffix = JournalTransaction::new([1; 16], vec![
        JournalRecord::put(RecordNamespace::DesiredState, key(SUCCESSOR_FLOOR_PREFIX, intent.project()), vec![0; ARCHIVE_BYTES]),
        JournalRecord::delete(RecordNamespace::DesiredState, intent_key(intent)),
        sizing_capacity_delete(),
    ])?;
    capacity_request(
        Purpose::RootFirstSourceSuccessorAnchor, intent.instance(), intent.project(), intent.request(),
        intent.digest(), intent.approval(), intent.begin(), intent.predecessor_floor(), &[suffix], 1,
    )
}

pub(crate) fn validate_root_first_source_successor_transition_v2(
    state: &State,
    transaction: &JournalTransaction,
    phase: Option<Phase>,
) -> Result<Option<[u8; 32]>, JournalError> {
    if matches!(phase, Some(Phase::MixedRootPrepared | Phase::MixedRootAnchor)) {
        return super::store::RootSourceGenesisAuthorityV1::validate_project_successor_transition_v3(
            state, transaction, phase,
        );
    }
    validate_root_first_source_successor_state_v2(state)?;
    let touches = transaction.records().iter().any(|record| record.key().starts_with(PREFIX))
        || touches_capacity_purpose(state, transaction, Purpose::RootFirstSourceSuccessorAnchor)?;
    if !touches {
        if matches!(phase, Some(Phase::RootPrepared | Phase::RootAnchor)) {
            return Err(JournalError::ProtectedBoundary);
        }
        if rows(state)?.intent.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        return Ok(None);
    }
    let before = rows(state)?;
    match phase {
        Some(Phase::RootPrepared) => {
            let [put, reservation] = transaction.records() else { return Err(JournalError::ProtectedBoundary); };
            let intent = RootFirstSourceSuccessorIntentV2::decode(put.value().ok_or(JournalError::ProtectedBoundary)?)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            require_predecessor(state, &intent)?;
            let request = root_capacity_request(&intent)?;
            let admission = transaction_id(intent.approval(), Phase::RootPrepared);
            if before.intent.is_some() || before.archive.is_some()
                || put.namespace() != RecordNamespace::DesiredState || put.key() != intent_key(&intent)
                || transaction.id() != &admission
                || reservation != &first_source_successor_capacity_record_v2(&request, admission)?
            {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(None)
        }
        Some(Phase::RootAnchor) => {
            let intent = before.intent.ok_or(JournalError::ProtectedBoundary)?;
            let [put, deletion, settlement] = transaction.records() else { return Err(JournalError::ProtectedBoundary); };
            let archive = RootFirstSourceSuccessorArchiveV2::decode(put.value().ok_or(JournalError::ProtectedBoundary)?)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            let request = root_capacity_request(&intent)?;
            let admission = transaction_id(intent.approval(), Phase::RootPrepared);
            if archive.original != intent || put.namespace() != RecordNamespace::DesiredState
                || put.key() != floor_key(&archive.floor)
                || transaction.id() != &transaction_id(intent.approval(), Phase::RootAnchor)
                || deletion != &JournalRecord::delete(RecordNamespace::DesiredState, intent_key(&intent))
                || settlement != &first_source_successor_capacity_delete_v2(state, &request, admission)?
            {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(Some(first_source_successor_capacity_identity_v2(&request, admission)?))
        }
        _ => Err(JournalError::ProtectedBoundary),
    }
}

/// Retains one Root mutation's whole native Result and independent post debt.
///
/// A new reservoir is required for Prepare and Anchor. It cannot grant a retry
/// after an ambiguous append or release the actual Root owner on failure.
#[derive(Default)]
pub struct RootFirstSuccessorMutationResultsV2 {
    attempted: bool,
    transaction: Option<JournalTransaction>,
    preparation: Option<Result<(), SourceGenesisErrorV1>>,
    preflight: Option<Result<(), JournalError>>,
    crossing: Option<Result<(), SourceGenesisErrorV1>>,
    crossing_clock: Option<Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1>>,
    native: Option<Result<CommitResult, JournalError>>,
    post: Option<Result<(), SourceGenesisErrorV1>>,
    clock_post: Option<Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1>>,
    data: Option<Result<Option<RootFirstSourceSuccessorIntentV2>, SourceGenesisErrorV1>>,
    data_name_post: Option<Result<(), SourceGenesisErrorV1>>,
    data_watermark_post: Option<Result<(), SourceGenesisErrorV1>>,
}

impl RootFirstSuccessorMutationResultsV2 {
    /// Creates an unused local reservoir, not a mutation permission.
    pub fn new() -> Self { Self::default() }

    /// Borrows the first action cause without moving its owning Result.
    pub fn error(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(error)) = &self.data { return Some(error); }
        if let Some(Err(error)) = &self.preparation { return Some(error); }
        if let Some(Err(error)) = &self.preflight { return Some(error); }
        if let Some(Err(error)) = &self.crossing { return Some(error); }
        if let Some(Err(error)) = &self.crossing_clock { return Some(error); }
        if let Some(Err(error)) = &self.native { return Some(error); }
        if let Some(Err(error)) = &self.post { return Some(error); }
        if let Some(Err(error)) = &self.clock_post { return Some(error); }
        if let Some(Err(error)) = &self.data_name_post { return Some(error); }
        if let Some(Err(error)) = &self.data_watermark_post { return Some(error); }
        None
    }

    /// Borrows later original-owner debt separately from the action cause.
    pub fn post_error(&self) -> Option<&SourceGenesisErrorV1> {
        self.post.as_ref().and_then(|result| result.as_ref().err())
    }

    /// Borrows the independent original server-clock Result after any action.
    pub fn clock_post_result(&self) -> Option<&Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1>> {
        self.clock_post.as_ref()
    }

    /// Borrows independent DATA owner/name/watermark posts without disposal.
    pub fn project_data_post_results(&self) -> [Option<&Result<(), SourceGenesisErrorV1>>; 3] {
        [self.post.as_ref(), self.data_name_post.as_ref(), self.data_watermark_post.as_ref()]
    }
}

// These are the actual Broker attempt's borrowed original comparison inputs.
// They do not construct a permit or replace the authenticated Root writer.
fn original_server_crossing_clock(
    original: &aos_sandbox_core::RawPairedClockSample,
    deadline: &std::time::Instant,
) -> Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1> {
    let current = super::flight::observe_root_first_source_successor_clock_v2(Some(*original))?;
    if std::time::Instant::now() >= *deadline { return Err(SourceGenesisErrorV1::Stale); }
    Ok(current)
}

impl super::store::RootSourceGenesisAuthorityV1 {
    /// Compares every retained archive before selecting immutable intent DATA.
    ///
    /// Absence remains absence: this never constructs a new admission context,
    /// Root floor loan, writer permission or renewed original nonce/deadline.
    ///
    /// # Errors
    /// Returns a marker while the supplied single-use reservoir retains the
    /// actual comparison cause and every independent owner/name/watermark post.
    pub fn retained_project_successor_context_v3(
        &self, project: ProjectId, results: &mut RootFirstSuccessorMutationResultsV2,
    ) -> Result<Option<RootFirstSourceSuccessorIntentV2>, ()> {
        self.compare_retained_project_successor_v3(project, None, results)
    }

    /// Compares one exact historical archive against the complete actual map.
    ///
    /// # Errors
    /// Returns a retaining marker for missing/changed archive, original intent,
    /// predecessor, role or capacity joins, or independent post-observation debt.
    pub fn compare_project_successor_archive_v3(
        &self, context: &RootFirstSourceSuccessorIntentV2,
        floor: &RootFirstSourceSuccessorFloorV2,
        results: &mut RootFirstSuccessorMutationResultsV2,
    ) -> Result<(), ()> {
        self.compare_retained_project_successor_v3(context.project(), Some((context, floor)), results)
            .map(|_| ())
    }

    fn compare_retained_project_successor_v3(
        &self, project: ProjectId,
        expected: Option<(&RootFirstSourceSuccessorIntentV2, &RootFirstSourceSuccessorFloorV2)>,
        results: &mut RootFirstSuccessorMutationResultsV2,
    ) -> Result<Option<RootFirstSourceSuccessorIntentV2>, ()> {
        if results.attempted { return Err(()); }
        results.attempted = true;
        let sequence = self.journal.snapshot_sequence();
        results.data = Some((|| {
            self.recheck()?;
            let retained = project_rows_v3(&journal_state(&self.journal), Some(project))?;
            if let Some((context, floor)) = expected {
                let archive = retained.archives.get(&project).ok_or(SourceGenesisErrorV1::Conflict)?;
                if &archive.original != context || &archive.floor != floor {
                    return Err(SourceGenesisErrorV1::Conflict);
                }
            }
            Ok(retained.intent.or_else(|| retained.archives.get(&project)
                .map(|archive| archive.original.clone())))
        })());
        // A failed actual comparison never prevents these independent posts.
        // The same supplied reservoir remains owned by the original caller.
        results.post = Some(self.recheck());
        results.data_name_post = Some(self.journal.validate_held_protected_names()
            .map_err(SourceGenesisErrorV1::from));
        results.data_watermark_post = Some(if self.journal.snapshot_sequence() == sequence {
            Ok(())
        } else {
            Err(SourceGenesisErrorV1::Stale)
        });
        if results.error().is_some() { return Err(()); }
        results.data.as_ref().and_then(|result| result.as_ref().ok()).cloned().ok_or(())
    }

    /// Selects only an existing immutable intent/archive for historical recovery.
    ///
    /// # Errors
    /// Rejects absent work rather than constructing fresh admission context.
    pub fn historical_first_source_successor_context_v2(&self, controller_packet: &[u8])
        -> Result<RootFirstSourceSuccessorIntentV2, SourceGenesisErrorV1>
    {
        let controller = self.verify_first_successor_controller(controller_packet)?;
        let original = retained_root_first_successor_v2(&self.journal, controller.packet.intent()?.project())?
            .ok_or(SourceGenesisErrorV1::AdmissionClosed)?;
        let checked = self.first_source_successor_context_v2(controller_packet)?;
        if checked != original { return Err(SourceGenesisErrorV1::Conflict); }
        Ok(original)
    }
    /// Selects the original intent or derives new comparison context from custody.
    ///
    /// An archived intent is returned byte-for-byte. A newly constructed value
    /// is only Source-signer comparison DATA until native Prepare has committed.
    ///
    /// # Errors
    /// Rejects foreign observations, pins, fixed roles or semantic predecessors.
    pub fn first_source_successor_context_v2(&self, controller_packet: &[u8])
        -> Result<RootFirstSourceSuccessorIntentV2, SourceGenesisErrorV1>
    {
        self.recheck()?;
        let controller = self.verify_first_successor_controller(controller_packet)?;
        self.pins.verify_first_source_successor_v2(&controller.packet)?;
        let project = controller.packet.intent()?.project();
        if let Some(original) = retained_root_first_successor_v2(&self.journal, project)? {
            if original.approval_packet() != &controller.packet
                || original.begin() != controller.begin.digest() || original.source_uid() != self.source_uid
                || controller.root_intent.is_some_and(|digest| digest != original.digest())
            {
                return Err(SourceGenesisErrorV1::Conflict);
            }
            self.recheck()?;
            return Ok(original);
        }
        if controller.phase != super::successor_consumer::ControllerObservationPhaseV2::Before {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        let clock = super::flight::kernel_pair()?;
        super::successor_consumer::require_approval_clock(&controller.packet, clock)?;
        let body = controller.packet.body();
        let signed_deadline = u64::from_be_bytes(take(body, 728)?)
            .checked_add(u64::from(controller.packet.intent()?.validity_seconds())
                .checked_mul(1_000_000_000).ok_or(SourceGenesisErrorV1::NonCanonical)?)
            .ok_or(SourceGenesisErrorV1::NonCanonical)?;
        let custody_bound = clock.boottime_nanoseconds().checked_add(60_000_000_000)
            .ok_or(SourceGenesisErrorV1::NonCanonical)?;
        let original = RootFirstSourceSuccessorIntentV2::new(RootFirstSourceSuccessorIntentFieldsV2 {
            nonce: self.nonce, approval: controller.packet.clone(), begin: controller.begin.digest(),
            source_uid: self.source_uid, source_names: controller.source_names,
            predecessor_floor: controller.begin.predecessor_floor(), predecessor_revision: 1,
            old_tree_head: controller.begin.old_tree_head(), old_lineage_head: controller.begin.old_lineage_head(),
            next_tree_commit: controller.begin.next_tree_commit(), roles: self.pins.digest(),
            boot: clock.host_boot_id(), boottime_deadline: signed_deadline.min(custody_bound),
            expires_wall: u64::from_be_bytes(take(body, 744)?),
        })?;
        require_predecessor(&journal_state(&self.journal), &original)?;
        self.recheck()?;
        Ok(original)
    }

    fn verify_first_successor_controller(&self, bytes: &[u8])
        -> Result<super::successor_consumer::VerifiedControllerFirstSuccessorObservationV2, SourceGenesisErrorV1>
    {
        self.recheck()?;
        let controller = super::successor_consumer::verify_controller_first_successor_readback_v2(
            bytes, &self.pins.controller, self.nonce, self.controller_uid, self.source_uid,
        )?;
        self.pins.verify_first_source_successor_v2(&controller.packet)?;
        self.recheck()?;
        Ok(controller)
    }

    fn observe_first_successor_source(
        &self,
        context: &RootFirstSourceSuccessorIntentV2,
        controller_packet: &[u8],
        source_packet: &[u8],
    ) -> Result<crate::policy_compiler::VerifiedSourceFirstSuccessorReadbackV2, SourceGenesisErrorV1> {
        let controller = self.verify_first_successor_controller(controller_packet)?;
        if context.approval_packet() != &controller.packet || context.begin() != controller.begin.digest()
            || context.roles() != self.pins.digest() || context.source_uid() != self.source_uid
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        let source = crate::policy_compiler::verify_source_first_successor_readback_v2(
            source_packet, &self.pins.source, self.nonce, context,
        )?;
        if source.names() != controller.source_names || source.sequence() != controller.source_sequence
            || source.receipt() != controller.receipt.as_ref() || source.ack() != controller.ack.as_ref()
            || source.genesis_receipt().instance() != context.instance()
            || source.genesis_receipt().tree_head() != context.old_tree_head()
            || source.genesis_receipt().lineage_head() != context.old_lineage_head()
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        self.recheck()?;
        Ok(source)
    }

    fn require_first_successor_admission(&self, intent: &RootFirstSourceSuccessorIntentV2)
        -> Result<(), SourceGenesisErrorV1>
    {
        self.recheck()?;
        super::store::require_current_deployment(&self.journal)?;
        let clock = super::flight::kernel_pair()?;
        super::successor_consumer::require_approval_clock(intent.approval_packet(), clock)?;
        if clock.host_boot_id() != intent.boot() || clock.boottime_nanoseconds() >= intent.boottime_deadline()
            || u64::try_from(clock.wall_seconds()).map_err(|_| SourceGenesisErrorV1::AdmissionClosed)? >= intent.expires_wall()
        {
            return Err(SourceGenesisErrorV1::AdmissionClosed);
        }
        Ok(())
    }

    /// Writes or exact-replays Prepared under the actual held Root writer.
    ///
    /// # Errors
    /// Returns a marker retaining the whole action/native Result in `results`.
    /// Expired Before without an actual receipt remains fenced, not renewed.
    /// The server clock and deadline borrow the same original Broker attempt;
    /// they are comparison inputs, not admission authority or a fresh epoch.
    pub fn prepare_first_successor_v2(
        &mut self, context: &RootFirstSourceSuccessorIntentV2,
        controller_packet: &[u8], source_packet: &[u8],
        original_server_clock: &aos_sandbox_core::RawPairedClockSample,
        original_server_deadline: &std::time::Instant,
        results: &mut RootFirstSuccessorMutationResultsV2,
    ) -> Result<RootFirstSourceSuccessorIntentV2, ()> {
        if results.attempted { return Err(()); }
        results.attempted = true;
        let mut before = false;
        results.preparation = Some((|| {
            let source = self.observe_first_successor_source(context, controller_packet, source_packet)?;
            before = source.phase() == crate::policy_compiler::SourceFirstSuccessorReadbackPhaseV2::Before;
            if before { self.require_first_successor_admission(context)?; }
            if let Some(original) = retained_root_first_successor_v2(&self.journal, context.project())? {
                if &original != context { return Err(SourceGenesisErrorV1::Conflict); }
                return Ok(());
            }
            if !before || context.nonce() != self.nonce { return Err(SourceGenesisErrorV1::Conflict); }
            let request = root_capacity_request(context)?;
            let admission = transaction_id(context.approval(), Phase::RootPrepared);
            results.transaction = Some(JournalTransaction::new(admission, vec![
                JournalRecord::put(RecordNamespace::DesiredState, intent_key(context), context.as_bytes().to_vec()),
                self.journal.prepare_first_source_successor_capacity_v2(&request, admission)?,
            ])?);
            Ok(())
        })());
        if matches!(results.preparation, Some(Ok(()))) {
            if let Some(transaction) = &results.transaction {
                results.preflight = Some(self.journal.preflight_root_first_successor_shape_v2(transaction, context));
                if matches!(results.preflight, Some(Ok(()))) {
                    results.crossing = Some(self.require_first_successor_admission(context));
                    if matches!(results.crossing, Some(Ok(()))) {
                        results.crossing_clock = Some(original_server_crossing_clock(original_server_clock, original_server_deadline));
                    }
                    if matches!(results.crossing_clock, Some(Ok(_))) {
                        results.native = Some(self.journal.commit_first_source_successor_v2(transaction, Phase::RootPrepared));
                    }
                }
            }
        }
        results.post = Some((|| {
            self.recheck()?;
            if retained_root_first_successor_v2(&self.journal, context.project())?.as_ref() != Some(context) {
                return Err(SourceGenesisErrorV1::Stale);
            }
            Ok(())
        })());
        results.clock_post = Some(original_server_crossing_clock(original_server_clock, original_server_deadline));
        if results.error().is_some() { Err(()) } else { Ok(context.clone()) }
    }

    /// Anchors the exact actual receipt and preserves its immutable intent archive.
    ///
    /// # Errors
    /// Returns a retaining marker for any action, native or readback failure.
    /// Historical exact recovery never appends an existing archive again.
    /// The borrowed server cut remains the original recovery attempt's cut,
    /// independent of the immutable persisted admission deadline.
    pub fn anchor_first_successor_v2(
        &mut self, context: &RootFirstSourceSuccessorIntentV2,
        controller_packet: &[u8], source_packet: &[u8],
        original_server_clock: &aos_sandbox_core::RawPairedClockSample,
        original_server_deadline: &std::time::Instant,
        results: &mut RootFirstSuccessorMutationResultsV2,
    ) -> Result<RootFirstSourceSuccessorFloorV2, ()> {
        if results.attempted { return Err(()); }
        results.attempted = true;
        let mut expected = None;
        results.preparation = Some((|| {
            let source = self.observe_first_successor_source(context, controller_packet, source_packet)?;
            let receipt = source.receipt().ok_or(SourceGenesisErrorV1::Conflict)?;
            require_receipt_intent(receipt, context)?;
            let floor = RootFirstSourceSuccessorFloorV2::new(RootFirstSourceSuccessorFloorFieldsV2 {
                predecessor_floor: context.predecessor_floor(), approval: context.approval(),
                receipt: receipt.clone(), roles: self.pins.digest(),
            })?;
            let archive = RootFirstSourceSuccessorArchiveV2 { floor: floor.clone(), original: context.clone() };
            expected = Some(floor);
            let retained = rows(&journal_state(&self.journal))?;
            if let Some(existing) = retained.archive {
                if existing != archive { return Err(SourceGenesisErrorV1::Conflict); }
                return Ok(());
            }
            if retained.intent.as_ref() != Some(context) { return Err(SourceGenesisErrorV1::Conflict); }
            let request = root_capacity_request(context)?;
            results.transaction = Some(JournalTransaction::new(transaction_id(context.approval(), Phase::RootAnchor), vec![
                JournalRecord::put(RecordNamespace::DesiredState, floor_key(&archive.floor), archive.bytes()),
                JournalRecord::delete(RecordNamespace::DesiredState, intent_key(context)),
                self.journal.first_source_successor_capacity_deletion_v2(&request, transaction_id(context.approval(), Phase::RootPrepared))?,
            ])?);
            Ok(())
        })());
        if matches!(results.preparation, Some(Ok(()))) {
            if let Some(transaction) = &results.transaction {
                // Actual receipt heads now exist: this is exact semantic preview,
                // never the earlier conservative shape-only capacity decision.
                results.preflight = Some(self.journal.preflight_first_source_successor_v2(
                    std::slice::from_ref(transaction), &[Phase::RootAnchor],
                ));
                if matches!(results.preflight, Some(Ok(()))) {
                    results.crossing = Some(self.recheck());
                    if matches!(results.crossing, Some(Ok(()))) {
                        results.crossing_clock = Some(original_server_crossing_clock(original_server_clock, original_server_deadline));
                    }
                    if matches!(results.crossing_clock, Some(Ok(_))) {
                        results.native = Some(self.journal.commit_first_source_successor_v2(transaction, Phase::RootAnchor));
                    }
                }
            }
        }
        results.post = Some((|| {
            self.recheck()?;
            let archive = rows(&journal_state(&self.journal))?.archive.ok_or(SourceGenesisErrorV1::Stale)?;
            if Some(&archive.floor) != expected.as_ref() || &archive.original != context {
                return Err(SourceGenesisErrorV1::Stale);
            }
            Ok(())
        })());
        results.clock_post = Some(original_server_crossing_clock(original_server_clock, original_server_deadline));
        if results.error().is_some() { Err(()) } else { expected.ok_or(()) }
    }

    /// Rejoins genuine Controller Complete, Source ACK and the full current archive.
    ///
    /// # Errors
    /// Rejects absent or changed completion, current observation or archive.
    pub fn confirm_first_successor_ack_v2(
        &self, context: &RootFirstSourceSuccessorIntentV2,
        controller_packet: &[u8], source_packet: &[u8], floor: &RootFirstSourceSuccessorFloorV2,
    ) -> Result<[u8; 96], SourceGenesisErrorV1> {
        let source = self.observe_first_successor_source(context, controller_packet, source_packet)?;
        let controller = self.verify_first_successor_controller(controller_packet)?;
        let complete = controller.complete.as_ref().ok_or(SourceGenesisErrorV1::Conflict)?;
        let ack = source.ack().ok_or(SourceGenesisErrorV1::Conflict)?;
        if controller.phase != super::successor_consumer::ControllerObservationPhaseV2::Completed
            || source.phase() != crate::policy_compiler::SourceFirstSuccessorReadbackPhaseV2::Anchored
            || complete.floor() != floor.digest() || complete.ack() != ack.digest()
            || source.receipt() != Some(floor.receipt())
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        let archive = rows(&journal_state(&self.journal))?.archive.ok_or(SourceGenesisErrorV1::Conflict)?;
        if &archive.floor != floor || &archive.original != context { return Err(SourceGenesisErrorV1::Conflict); }
        let mut payload = [0; 96];
        payload[..32].copy_from_slice(floor.digest().as_bytes());
        payload[32..64].copy_from_slice(complete.digest().as_bytes());
        payload[64..].copy_from_slice(ack.digest().as_bytes());
        self.recheck()?;
        Ok(payload)
    }

    /// Borrows current populated floor custody after genuine completion joins.
    ///
    /// # Errors
    /// Rejects a changed full archive or either actual fresh observation.
    pub fn current_anchored_first_successor_floor_v2<'root>(
        &'root self, context: &RootFirstSourceSuccessorIntentV2,
        controller_packet: &[u8], source_packet: &[u8], floor: &RootFirstSourceSuccessorFloorV2,
    ) -> Result<super::current::CurrentRootFirstSourceSuccessorFloorV2<'root>, SourceGenesisErrorV1> {
        let completion = self.confirm_first_successor_ack_v2(context, controller_packet, source_packet, floor)?;
        let archive = rows(&journal_state(&self.journal))?.archive.ok_or(SourceGenesisErrorV1::Conflict)?;
        super::current::CurrentRootFirstSourceSuccessorFloorV2::from_completed_owner(self, archive, completion)
    }

    pub(super) fn require_current_first_successor_archive_v2(
        &self, archive: &RootFirstSourceSuccessorArchiveV2,
    ) -> Result<(), SourceGenesisErrorV1> {
        self.recheck()?;
        if rows(&journal_state(&self.journal))?.archive.as_ref() != Some(archive) {
            return Err(SourceGenesisErrorV1::Stale);
        }
        self.recheck()
    }
}
