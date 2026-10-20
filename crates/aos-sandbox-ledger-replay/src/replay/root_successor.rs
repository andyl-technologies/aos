//! Owns the complete saved Root successor archive and phase reducer.
//!
//! Complete saved project folds, predecessor pins/signatures, remaining suffix
//! reservations and original archive association are DATA comparisons. The
//! live Root writer/current-clock/credential and admission gates stay upper.

use std::collections::BTreeMap;
use aos_sandbox_core::{ObjectDigest, ProjectId, RecordNamespace};
use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as JournalError;
use aos_sandbox_protocol::domain_ledger::transaction::{JournalRecord, JournalTransaction};
use aos_sandbox_protocol::domain_ledger::capacity::{
    GlobalCapacityReservationPurposeV1 as Purpose, GlobalCapacityReservationRequestV1,
};
use crate::data::SourceSuccessorDataErrorV2 as SourceGenesisErrorV1;
use super::source_tree_successor::{FirstSourceSuccessorNativePhaseV2 as Phase,
    capacity_request, require_exact_capacity_family, sizing_capacity_delete,
    touches_capacity_purpose, transaction_id, first_source_successor_capacity_delete_v2,
    first_source_successor_capacity_identity_v2, first_source_successor_capacity_record_v2};
use super::root_genesis_records::{FLOOR_PREFIX, INSTANCE_KEY, PINS_KEY,
    SourceHierarchyFloorRecordV1, decode_instance};
use super::phase_records::{RootFirstSourceSuccessorFloorV2,
    RootFirstSourceSuccessorIntentV2, SourceFirstSuccessorReceiptV2};

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

pub const PREFIX: &[u8] = b"\0aos-root-first-source-successor-v2\0";
pub const INTENT_PREFIX: &[u8] = b"\0aos-root-first-source-successor-v2\0intent\0";
pub const SUCCESSOR_FLOOR_PREFIX: &[u8] = b"\0aos-root-first-source-successor-v2\0floor\0";
pub const ARCHIVE_BYTES: usize = 1936;
pub const RESOURCE_ARCHIVE_BYTES: usize = 2112;


#[derive(Clone, Debug, Eq, PartialEq)]
/// Keeps the complete saved floor and original intent comparison DATA.
pub struct RootFirstSourceSuccessorArchiveV2 {
    pub floor: RootFirstSourceSuccessorFloorV2,
    pub original: RootFirstSourceSuccessorIntentV2,
}

impl RootFirstSourceSuccessorArchiveV2 {
    /// Applies the canonical saved Root successor comparison.
    ///
    /// # Errors
    /// Rejects malformed or inconsistent saved association, pins or suffix DATA.
    pub fn decode(bytes: &[u8]) -> Result<Self, SourceGenesisErrorV1> {
        if !matches!(bytes.len(), ARCHIVE_BYTES | RESOURCE_ARCHIVE_BYTES) {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        let archive = Self {
            floor: RootFirstSourceSuccessorFloorV2::decode(&bytes[..688]).map_err(SourceGenesisErrorV1::from)?,
            original: RootFirstSourceSuccessorIntentV2::decode(&bytes[688..]).map_err(SourceGenesisErrorV1::from)?,
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

    /// Returns the canonical saved key or archive bytes without live authority.
    pub fn bytes(&self) -> Vec<u8> {
        [self.floor.as_bytes().as_slice(), self.original.as_bytes()].concat()
    }
}

#[derive(Default)]
/// Keeps the original strict singleton saved successor selection.
pub struct Rows {
    pub intent: Option<RootFirstSourceSuccessorIntentV2>,
    pub archive: Option<RootFirstSourceSuccessorArchiveV2>,
}

// All members are historical comparison DATA. A selected active intent is
// not admitted by archive counts or by this structural fold.
/// Keeps the complete per-project saved successor selection.
pub struct ProjectRowsV3 {
    pub intent: Option<RootFirstSourceSuccessorIntentV2>,
    pub archives: BTreeMap<ProjectId, RootFirstSourceSuccessorArchiveV2>,
}



/// Applies the canonical saved Root successor comparison.
///
/// # Errors
/// Rejects malformed or inconsistent saved association, pins or suffix DATA.
pub fn project_rows_v3(state: &State, selected: Option<ProjectId>) -> Result<ProjectRowsV3, JournalError> {
    let mut retained = ProjectRowsV3 { intent: None, archives: BTreeMap::new() };
    for ((namespace, member_key), value) in state {
        if !member_key.starts_with(PREFIX) { continue; }
        if *namespace != RecordNamespace::DesiredState { return Err(JournalError::ProtectedBoundary); }
        if member_key.starts_with(INTENT_PREFIX) {
            let intent = RootFirstSourceSuccessorIntentV2::decode(value).map_err(SourceGenesisErrorV1::from)
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

/// Returns the canonical saved key or archive bytes without live authority.
pub fn key(prefix: &[u8], project: ProjectId) -> Vec<u8> {
    [prefix, project.as_bytes()].concat()
}

/// Returns the canonical saved key or archive bytes without live authority.
pub fn intent_key(intent: &RootFirstSourceSuccessorIntentV2) -> Vec<u8> {
    key(INTENT_PREFIX, intent.project())
}

/// Returns the canonical saved key or archive bytes without live authority.
pub fn floor_key(floor: &RootFirstSourceSuccessorFloorV2) -> Vec<u8> {
    key(SUCCESSOR_FLOOR_PREFIX, floor.receipt().project())
}

/// Applies the canonical saved Root successor comparison.
///
/// # Errors
/// Rejects malformed or inconsistent saved association, pins or suffix DATA.
pub fn rows(state: &State) -> Result<Rows, JournalError> {
    let mut rows = Rows::default();
    for ((namespace, key), value) in state {
        if !key.starts_with(PREFIX) {
            continue;
        }
        if *namespace != RecordNamespace::DesiredState {
            return Err(JournalError::ProtectedBoundary);
        }
        if key.starts_with(INTENT_PREFIX) {
            let intent = RootFirstSourceSuccessorIntentV2::decode(value).map_err(SourceGenesisErrorV1::from)
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

/// Applies the canonical saved Root successor comparison.
///
/// # Errors
/// Rejects malformed or inconsistent saved association, pins or suffix DATA.
pub fn validate_root_first_source_successor_state_v2(state: &State)
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

/// Applies the canonical saved Root successor comparison.
///
/// # Errors
/// Rejects malformed or inconsistent saved association, pins or suffix DATA.
pub fn require_predecessor(state: &State, intent: &RootFirstSourceSuccessorIntentV2)
    -> Result<(), JournalError>
{
    let get = |key: &[u8]| state.get(&(RecordNamespace::DesiredState, key.to_vec()))
        .map(Vec::as_slice).ok_or(JournalError::ProtectedBoundary);
    let instance = decode_instance(get(INSTANCE_KEY)?)
        .map_err(|_| JournalError::ProtectedBoundary)?;
    let pins = get(PINS_KEY)?;
    let roles = super::root_genesis_pins::role_tuple_digest(pins)
        .map_err(|_| JournalError::ProtectedBoundary)?;
    super::root_genesis_pins::verify_retained_first_source_successor_v2(pins, intent.approval_packet())
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

/// Applies the canonical saved Root successor comparison.
///
/// # Errors
/// Rejects malformed or inconsistent saved association, pins or suffix DATA.
pub fn require_receipt_intent(
    receipt: &SourceFirstSuccessorReceiptV2,
    intent: &RootFirstSourceSuccessorIntentV2,
) -> Result<(), SourceGenesisErrorV1> {
    if receipt.instance() != intent.instance() || receipt.project() != intent.project()
        || receipt.request() != intent.request() || receipt.approval() != intent.approval()
        || receipt.epoch() != intent.epoch() || receipt.root_intent() != intent.digest()
        || receipt.begin() != intent.begin() || receipt.roles() != intent.roles()
        || receipt.predecessor_floor() != intent.predecessor_floor()
        || receipt.old_tree_head() != intent.old_tree_head()
        || receipt.old_lineage_head() != intent.old_lineage_head()
        || receipt.old_tree_commit() != intent.approval_packet().old_tree_commit()
        || receipt.next_tree_commit() != intent.next_tree_commit()
        || receipt.source_names() != intent.source_names()
    {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    Ok(())
}

/// Applies the canonical saved Root successor comparison.
///
/// # Errors
/// Rejects malformed or inconsistent saved association, pins or suffix DATA.
pub fn root_capacity_request(intent: &RootFirstSourceSuccessorIntentV2)
    -> Result<GlobalCapacityReservationRequestV1, JournalError>
{
    // Only shape: successor envelope heads do not exist before Source append.
    // This exact physical archive width includes the preserved original intent.
    let suffix = JournalTransaction::new([1; 16], vec![
        JournalRecord::put(RecordNamespace::DesiredState, key(SUCCESSOR_FLOOR_PREFIX, intent.project()), vec![0; 688 + intent.as_bytes().len()]),
        JournalRecord::delete(RecordNamespace::DesiredState, intent_key(intent)),
        sizing_capacity_delete(),
    ])?;
    capacity_request(
        Purpose::RootFirstSourceSuccessorAnchor, intent.instance(), intent.project(), intent.request(),
        intent.digest(), intent.approval(), intent.begin(), intent.predecessor_floor(), &[suffix], 1,
    )
}

/// Applies the canonical saved Root successor comparison.
///
/// # Errors
/// Rejects malformed or inconsistent saved association, pins or suffix DATA.
pub fn validate_root_first_source_successor_transition_v2(
    state: &State,
    transaction: &JournalTransaction,
    phase: Option<Phase>,
) -> Result<Option<[u8; 32]>, JournalError> {
    if matches!(phase, Some(Phase::MixedRootPrepared | Phase::MixedRootAnchor)) {
        return validate_project_successor_transition_v3(
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
            let intent = RootFirstSourceSuccessorIntentV2::decode(put.value().ok_or(JournalError::ProtectedBoundary)?).map_err(SourceGenesisErrorV1::from)
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

/// Applies the canonical saved Root successor comparison.
///
/// # Errors
/// Rejects malformed or inconsistent saved association, pins or suffix DATA.
pub fn validate_project_successor_replay_v3(state: &State) -> Result<(), JournalError> {
    let mut selected = None;
    for ((namespace, member_key), value) in state {
        if member_key.starts_with(INTENT_PREFIX) {
            if *namespace != RecordNamespace::DesiredState || selected.is_some() {
                return Err(JournalError::ProtectedBoundary);
            }
            selected = Some(RootFirstSourceSuccessorIntentV2::decode(value).map_err(SourceGenesisErrorV1::from)
                .map_err(|_| JournalError::ProtectedBoundary)?.project());
        }
    }
    project_rows_v3(state, selected)?;
    Ok(())
}

/// Applies the canonical saved Root successor comparison.
///
/// # Errors
/// Rejects malformed or inconsistent saved association, pins or suffix DATA.
pub fn validate_project_successor_transition_v3(
    state: &State, transaction: &JournalTransaction, phase: Option<Phase>,
) -> Result<Option<[u8; 32]>, JournalError> {
    let canonical = phase.map(Phase::canonical);
    let selected = if canonical == Some(Phase::RootPrepared) {
        let put = transaction.records().first().ok_or(JournalError::ProtectedBoundary)?;
        Some(RootFirstSourceSuccessorIntentV2::decode(
            put.value().ok_or(JournalError::ProtectedBoundary)?,
        ).map_err(SourceGenesisErrorV1::from).map_err(|_| JournalError::ProtectedBoundary)?.project())
    } else {
        let mut selected = None;
        for ((namespace, member_key), value) in state {
            if member_key.starts_with(INTENT_PREFIX) {
                if *namespace != RecordNamespace::DesiredState || selected.is_some() {
                    return Err(JournalError::ProtectedBoundary);
                }
                selected = Some(RootFirstSourceSuccessorIntentV2::decode(value).map_err(SourceGenesisErrorV1::from)
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
            let intent = RootFirstSourceSuccessorIntentV2::decode(put.value().ok_or(JournalError::ProtectedBoundary)?).map_err(SourceGenesisErrorV1::from)
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
    let after = super::root_original_inventory::materialize(state, transaction);
    let prospective = project_rows_v3(&after, selected)?;
    if before.archives.iter().any(|(project, archive)| prospective.archives.get(project) != Some(archive)) {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(settled)
}
