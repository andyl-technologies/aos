//! Exact Controller retention and publication of first-successor approvals.
//!
//! ```text
//! DesiredState[prefix || "packet"] = AOSCSA02[896]
//! DesiredState[prefix || "epoch"] = administrative-epoch:u64be
//! DesiredState[prefix || "pending"] = AOSCSI02[80]
//! DesiredState[prefix || "delivered"] = packet-commitment[32]
//! DesiredState[prefix || "consumer-begin"] = AOSCSB02[296]
//! DesiredState[prefix || "consumer-anchored"] = AOSCSH02[144]
//! DesiredState[prefix || "consumer-complete"] = AOSCSC02[240]
//! ```
//!
//! One outstanding fixed slot fences unrelated Controller mutations. Its
//! complete context lives in the signed packet, never in a reconstructed
//! current-head receipt. Both appends use the sole Journal transaction engine;
//! publication uses that SAME writer's retained directory and no-replace name.
//! Consumer completion preserves every issuer row, including the immutable
//! issuance intent named `pending`; only the active consumer fence is released.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write as _;
use std::os::fd::AsFd as _;

#[cfg(target_os = "linux")]
use aos_sandbox_linux::protected_file::{open_nofollow_child, read_exact_positioned};
use rustix::fs::{FileType, Mode, OFlags, RenameFlags};
use aos_sandbox_core::ProjectId;

use super::{
    CacheMutationGateV1, Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace,
};
use crate::hierarchy::genesis_profile::{digest_at, hash, take};
use crate::hierarchy::source_successor::{
    SOURCE_SUCCESSOR_APPROVAL_BYTES_V2, SourceSuccessorApprovalDataV2,
};
use crate::policy_compiler::{
    ControllerFirstSourceSuccessorAnchoredV2, ControllerFirstSourceSuccessorBeginV2,
    ControllerFirstSourceSuccessorCompleteV2,
    SourceFirstSuccessorAckFieldsV2, SourceFirstSuccessorAckV2,
};
use super::source_tree_successor::{
    FirstSourceSuccessorNativePhaseV2, State, array,
    digest_at as successor_digest_at, transaction_id as successor_transaction_id,
};

const PREFIX: &[u8] = b"\0aos-controller-source-successor-issuance-v2\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.source-successor.issuance.transaction.v2\0";
const OUTPUT_NAME: &str = "source-successor-input-v2";
const TEMPORARY_NAME: &str = ".source-successor-input-v2.tmp";
const PROJECT_PREFIX: &[u8] = b"\0aos-controller-source-successor-issuance-v3\0";
const PROJECT_TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.source-successor.issuance.transaction.v3\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum IssuanceKeyRecipeV3 {
    GlobalV2,
    ProjectV3(ProjectId),
}

impl IssuanceKeyRecipeV3 {
    fn key(self, suffix: &[u8]) -> Result<Vec<u8>, JournalError> {
        let Self::ProjectV3(project) = self else { return Ok(key(suffix)); };
        let tag = match suffix {
            b"packet" => 0, b"epoch" => 1, b"pending" => 2, b"delivered" => 3,
            b"consumer-begin" => 4, b"consumer-anchored" => 5, b"consumer-complete" => 6,
            _ => return Err(JournalError::ProtectedBoundary),
        };
        let mut key = PROJECT_PREFIX.to_vec();
        key.extend_from_slice(project.as_bytes());
        key.push(tag);
        Ok(key)
    }

    fn owns(self, key: &[u8]) -> bool {
        match self {
            Self::GlobalV2 => key.starts_with(PREFIX),
            Self::ProjectV3(project) => key.starts_with(PROJECT_PREFIX)
                && key.get(PROJECT_PREFIX.len()..PROJECT_PREFIX.len() + 16) == Some(project.as_bytes().as_slice()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Transition {
    Save,
    Delivered,
    Begin,
    Anchored,
    Complete,
    ProjectSave(ProjectId),
    ProjectDelivered(ProjectId),
    ProjectBegin(ProjectId),
    ProjectAnchored(ProjectId),
    ProjectComplete(ProjectId),
}

impl Transition {
    pub(crate) fn canonical(self) -> Self {
        match self {
            Self::ProjectSave(_) => Self::Save,
            Self::ProjectDelivered(_) => Self::Delivered,
            Self::ProjectBegin(_) => Self::Begin,
            Self::ProjectAnchored(_) => Self::Anchored,
            Self::ProjectComplete(_) => Self::Complete,
            phase => phase,
        }
    }

    pub(crate) fn recipe(self) -> IssuanceKeyRecipeV3 {
        match self {
            Self::ProjectSave(project) | Self::ProjectDelivered(project) | Self::ProjectBegin(project)
            | Self::ProjectAnchored(project) | Self::ProjectComplete(project) => IssuanceKeyRecipeV3::ProjectV3(project),
            _ => IssuanceKeyRecipeV3::GlobalV2,
        }
    }
}

pub(crate) struct RetainedIssuanceDataV2 {
    pub(crate) packet: SourceSuccessorApprovalDataV2,
    pub(crate) delivered: bool,
    pub(crate) begin: Option<ControllerFirstSourceSuccessorBeginV2>,
    pub(crate) anchored: Option<ControllerFirstSourceSuccessorAnchoredV2>,
    pub(crate) complete: Option<ControllerFirstSourceSuccessorCompleteV2>,
}

/// Keeps every opened publication description resident on partial failure.
pub(crate) struct PublicationCustodyV2 {
    staged: Option<File>,
    original: Option<File>,
    readbacks: Vec<[u8; SOURCE_SUCCESSOR_APPROVAL_BYTES_V2]>,
}

impl PublicationCustodyV2 {
    pub(crate) fn new() -> Self {
        Self {
            staged: None,
            original: None,
            readbacks: Vec::new(),
        }
    }
}

fn project_publication_names_v3(project: ProjectId) -> (String, String) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::from("source-successor-input-v3-");
    for byte in project.as_bytes() {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 15)]));
    }
    let temporary = format!(".{output}.tmp");
    (output, temporary)
}

pub(crate) fn retained(journal: &Journal) -> Result<Option<RetainedIssuanceDataV2>, JournalError> {
    journal.ensure_protected_authority()?;
    validate_rows(&journal.state)
}

pub(crate) fn retained_project_v3(journal: &Journal, project: ProjectId) -> Result<Option<RetainedIssuanceDataV2>, JournalError> {
    journal.ensure_protected_authority()?;
    Ok(validate_project_family_v3(&journal.state)?.remove(&IssuanceKeyRecipeV3::ProjectV3(project)))
}

pub(crate) fn project_key_v3(project: ProjectId, suffix: &[u8]) -> Result<Vec<u8>, JournalError> {
    IssuanceKeyRecipeV3::ProjectV3(project).key(suffix)
}

pub(crate) fn key(suffix: &[u8]) -> Vec<u8> {
    let mut key = PREFIX.to_vec();
    key.extend_from_slice(suffix);
    key
}

fn transaction(
    packet: &SourceSuccessorApprovalDataV2,
    transition: Transition,
) -> Result<JournalTransaction, JournalError> {
    transaction_with_recipe(packet, transition.canonical(), transition.recipe())
}

fn transaction_with_recipe(
    packet: &SourceSuccessorApprovalDataV2,
    transition: Transition,
    recipe: IssuanceKeyRecipeV3,
) -> Result<JournalTransaction, JournalError> {
    let namespace = RecordNamespace::DesiredState;
    let (suffix, records) = match transition {
        Transition::Save => (
            b"save".as_slice(),
            vec![
                JournalRecord::put(namespace, recipe.key(b"packet")?, packet.as_bytes().to_vec()),
                JournalRecord::put(
                    namespace,
                    recipe.key(b"epoch")?,
                    packet.epoch().map_err(|_| JournalError::ProtectedBoundary)?
                        .to_be_bytes().to_vec(),
                ),
                JournalRecord::put(
                    namespace,
                    recipe.key(b"pending")?,
                    packet.intent().map_err(|_| JournalError::ProtectedBoundary)?
                        .as_bytes().to_vec(),
                ),
            ],
        ),
        Transition::Delivered => (
            b"delivered".as_slice(),
            vec![JournalRecord::put(
                namespace, recipe.key(b"delivered")?, packet.digest().as_bytes().to_vec(),
            )],
        ),
        _ => {
            return Err(JournalError::ProtectedBoundary);
        }
    };

    let (domain, mut identity) = match recipe {
        IssuanceKeyRecipeV3::GlobalV2 => (TRANSACTION_DOMAIN, suffix.to_vec()),
        IssuanceKeyRecipeV3::ProjectV3(project) => {
            if packet.intent().map_err(|_| JournalError::ProtectedBoundary)?.project() != project {
                return Err(JournalError::ProtectedBoundary);
            }
            let mut identity = project.as_bytes().to_vec();
            identity.push(match transition { Transition::Save => 1, Transition::Delivered => 2, _ => return Err(JournalError::ProtectedBoundary) });
            (PROJECT_TRANSACTION_DOMAIN, identity)
        }
    };
    identity.extend_from_slice(packet.digest().as_bytes());
    let id = take::<16>(hash(domain, &identity).as_bytes(), 0)
        .map_err(|_| JournalError::ProtectedBoundary)?;
    JournalTransaction::new(id, records)
}

pub(super) fn require_no_mutation(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    proposed: &JournalTransaction,
    transition: Option<Transition>,
) -> Result<(), JournalError> {
    if transition.is_some_and(|phase| matches!(phase.recipe(), IssuanceKeyRecipeV3::ProjectV3(_)))
        || state.keys().any(|(_, key)| key.starts_with(PROJECT_PREFIX))
        || proposed.records().iter().any(|record| record.key().starts_with(PROJECT_PREFIX))
    {
        return require_project_mutation_v3(state, proposed, transition);
    }
    let before = validate_rows(state)?;
    let touches_owned = proposed.records().iter().any(|record| {
        record.key().starts_with(PREFIX)
    });
    let Some(transition) = transition else {
        return if before.as_ref().is_some_and(|row| row.complete.is_none()) || touches_owned {
            Err(JournalError::ProtectedBoundary)
        } else {
            Ok(())
        };
    };
    if matches!(transition, Transition::Begin | Transition::Anchored | Transition::Complete) {
        return require_consumer_transition(state, proposed, transition).map(|_| ());
    }

    let packet = match transition {
        Transition::Save => {
            if before.is_some() {
                return Err(JournalError::ProtectedBoundary);
            }
            let record = proposed.records().first().ok_or(JournalError::ProtectedBoundary)?;
            let packet = SourceSuccessorApprovalDataV2::from_record_bytes(
                record.value().ok_or(JournalError::ProtectedBoundary)?,
            ).map_err(|_| JournalError::ProtectedBoundary)?;
            require_administrative_epoch(state, &packet)?;
            packet
        }
        Transition::Delivered => {
            let saved = before.ok_or(JournalError::ProtectedBoundary)?;
            if saved.delivered {
                return Err(JournalError::ProtectedBoundary);
            }
            saved.packet
        }
        _ => {
            return Err(JournalError::ProtectedBoundary);
        }
    };

    if proposed != &transaction(&packet, transition)? {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn require_project_mutation_v3(
    state: &State,
    proposed: &JournalTransaction,
    transition: Option<Transition>,
) -> Result<(), JournalError> {
    let mut family = validate_project_family_v3(state)?;
    let Some(selected) = transition else {
        return if family.values().any(|row| row.complete.is_none())
            || proposed.records().iter().any(|record| record.key().starts_with(PREFIX) || record.key().starts_with(PROJECT_PREFIX))
        { Err(JournalError::ProtectedBoundary) } else { Ok(()) };
    };
    let recipe = selected.recipe();
    let phase = selected.canonical();
    let before = family.remove(&recipe);
    if family.values().any(|row| row.complete.is_none()) { return Err(JournalError::ProtectedBoundary); }
    if matches!(phase, Transition::Begin | Transition::Anchored | Transition::Complete) {
        return require_consumer_transition_with_recipe(state, proposed, phase, recipe).map(|_| ());
    }
    let packet = match phase {
        Transition::Save => {
            if before.is_some() { return Err(JournalError::ProtectedBoundary); }
            let first = proposed.records().first().ok_or(JournalError::ProtectedBoundary)?;
            let packet = SourceSuccessorApprovalDataV2::from_record_bytes(first.value().ok_or(JournalError::ProtectedBoundary)?)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            require_administrative_epoch(state, &packet)?;
            packet
        }
        Transition::Delivered => {
            let before = before.ok_or(JournalError::ProtectedBoundary)?;
            if before.delivered { return Err(JournalError::ProtectedBoundary); }
            before.packet
        }
        _ => return Err(JournalError::ProtectedBoundary),
    };
    if proposed != &transaction_with_recipe(&packet, phase, recipe)? { return Err(JournalError::ProtectedBoundary); }
    validate_project_family_v3(&super::root_original_inventory::materialize(state, proposed))?;
    Ok(())
}

pub(super) fn validate_rows(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<RetainedIssuanceDataV2>, JournalError> {
    if state.keys().any(|(_, key)| key.starts_with(PROJECT_PREFIX)) {
        return Ok(validate_project_family_v3(state)?.remove(&IssuanceKeyRecipeV3::GlobalV2));
    }
    validate_rows_with_recipe(state, IssuanceKeyRecipeV3::GlobalV2, true)
}

fn validate_rows_with_recipe(
    state: &State,
    recipe: IssuanceKeyRecipeV3,
    exact_capacity: bool,
) -> Result<Option<RetainedIssuanceDataV2>, JournalError> {
    if state.keys().any(|(namespace, key)| recipe.owns(key) && *namespace != RecordNamespace::DesiredState) {
        return Err(JournalError::ProtectedBoundary);
    }
    let row_count = state.keys()
        .filter(|(namespace, key)| {
            *namespace == RecordNamespace::DesiredState && recipe.owns(key)
        })
        .count();
    if row_count == 0 {
        if exact_capacity { super::source_tree_successor::require_exact_capacity_family(
            state, super::GlobalCapacityReservationPurposeV1::ControllerFirstSourceSuccessorComplete, 0,
        )?; }
        return Ok(None);
    }
    if !(3..=7).contains(&row_count) {
        return Err(JournalError::ProtectedBoundary);
    }

    let value = |suffix: &[u8]| recipe.key(suffix).ok().and_then(|key| state.get(&(RecordNamespace::DesiredState, key)));
    let packet = SourceSuccessorApprovalDataV2::from_record_bytes(
        value(b"packet").ok_or(JournalError::ProtectedBoundary)?,
    ).map_err(|_| JournalError::ProtectedBoundary)?;
    if let IssuanceKeyRecipeV3::ProjectV3(project) = recipe
        && packet.intent().map_err(|_| JournalError::ProtectedBoundary)?.project() != project
    { return Err(JournalError::ProtectedBoundary); }
    let epoch = packet.epoch().map_err(|_| JournalError::ProtectedBoundary)?;
    let intent = packet.intent().map_err(|_| JournalError::ProtectedBoundary)?;
    if value(b"epoch").map(Vec::as_slice) != Some(epoch.to_be_bytes().as_slice())
        || value(b"pending").map(Vec::as_slice) != Some(intent.as_bytes().as_slice())
    {
        return Err(JournalError::ProtectedBoundary);
    }

    let delivered = value(b"delivered");
    if delivered.is_some_and(|bytes| bytes.as_slice() != packet.digest().as_bytes())
    {
        return Err(JournalError::ProtectedBoundary);
    }
    let begin = value(b"consumer-begin").map(|bytes| ControllerFirstSourceSuccessorBeginV2::decode(bytes))
        .transpose().map_err(|_| JournalError::ProtectedBoundary)?;
    let anchored = value(b"consumer-anchored").map(|bytes| ControllerFirstSourceSuccessorAnchoredV2::decode(bytes))
        .transpose().map_err(|_| JournalError::ProtectedBoundary)?;
    let complete = value(b"consumer-complete").map(|bytes| ControllerFirstSourceSuccessorCompleteV2::decode(bytes))
        .transpose().map_err(|_| JournalError::ProtectedBoundary)?;
    if row_count != 3 + usize::from(delivered.is_some()) + usize::from(begin.is_some())
        + usize::from(anchored.is_some()) + usize::from(complete.is_some())
        || begin.is_some() && delivered.is_none()
        || anchored.is_some() && begin.is_none()
        || complete.is_some() && anchored.is_none()
    {
        return Err(JournalError::ProtectedBoundary);
    }
    require_administrative_epoch(state, &packet)?;
    let rows = RetainedIssuanceDataV2 {
        packet,
        delivered: delivered.is_some(),
        begin, anchored, complete,
    };
    validate_consumer_rows_with_recipe(state, &rows, recipe, exact_capacity)?;
    Ok(Some(rows))
}

fn validate_consumer_rows(
    state: &State,
    rows: &RetainedIssuanceDataV2,
) -> Result<(), JournalError> {
    validate_consumer_rows_with_recipe(state, rows, IssuanceKeyRecipeV3::GlobalV2, true)
}

fn validate_consumer_rows_with_recipe(
    state: &State,
    rows: &RetainedIssuanceDataV2,
    recipe: IssuanceKeyRecipeV3,
    exact_capacity: bool,
) -> Result<(), JournalError> {
    let Some(begin) = &rows.begin else {
        if exact_capacity { super::source_tree_successor::require_exact_capacity_family(
            state, super::GlobalCapacityReservationPurposeV1::ControllerFirstSourceSuccessorComplete, 0,
        )?; }
        return Ok(());
    };
    let body = rows.packet.body();
    let bytes = begin.as_bytes();
    if successor_digest_at(bytes, 16)? != rows.packet.digest()
        || bytes[48..80] != body[144..176]
        || bytes[80..112] != body[176..208]
        || bytes[112..144] != body[536..568]
        || bytes[144..176] != body[568..600]
        || bytes[176..208] != body[680..712]
    {
        return Err(JournalError::ProtectedBoundary);
    }

    if let Some(anchored) = &rows.anchored {
        if successor_digest_at(anchored.as_bytes(), 16)? != rows.packet.digest() {
            return Err(JournalError::ProtectedBoundary);
        }
    }

    if let Some(complete) = &rows.complete {
        let anchored = rows.anchored.as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        let ack = SourceFirstSuccessorAckV2::new(SourceFirstSuccessorAckFieldsV2 {
            instance: array(body, 32)?,
            project: ProjectId::from_bytes(array(body, 64)?),
            receipt: anchored.receipt(),
            root_floor: anchored.floor(),
            controller_anchored: anchored.digest(),
        }).map_err(|_| JournalError::ProtectedBoundary)?;
        if complete.as_bytes()[16..112] != anchored.as_bytes()[16..112]
            || successor_digest_at(complete.as_bytes(), 112)? != ack.digest()
            || successor_digest_at(complete.as_bytes(), 144)? != begin.digest()
            || successor_digest_at(complete.as_bytes(), 176)? != anchored.digest()
        {
            return Err(JournalError::ProtectedBoundary);
        }
    } else {
        super::first_source_successor_capacity_delete_v2(
            state, &controller_capacity_request_with_recipe(&rows.packet, begin, recipe)?,
            successor_transaction_id(rows.packet.digest(), FirstSourceSuccessorNativePhaseV2::ControllerBegin),
        )?;
    }
    if exact_capacity { super::source_tree_successor::require_exact_capacity_family(
        state, super::GlobalCapacityReservationPurposeV1::ControllerFirstSourceSuccessorComplete,
        usize::from(rows.complete.is_none()),
    ) } else { Ok(()) }
}

/// Folds every real global/project row without constructing a filtered Journal.
pub(crate) fn validate_project_family_v3(
    state: &State,
) -> Result<BTreeMap<IssuanceKeyRecipeV3, RetainedIssuanceDataV2>, JournalError> {
    let mut projects = std::collections::BTreeSet::new();
    for ((namespace, key), _) in state {
        if !key.starts_with(PROJECT_PREFIX) { continue; }
        if *namespace != RecordNamespace::DesiredState
            || key.len() != PROJECT_PREFIX.len() + 17 || key[PROJECT_PREFIX.len() + 16] > 6
        { return Err(JournalError::ProtectedBoundary); }
        let project = ProjectId::from_bytes(array(key, PROJECT_PREFIX.len())?);
        if project.as_bytes() == &[0; 16] { return Err(JournalError::ProtectedBoundary); }
        projects.insert(project);
    }
    let mut family = BTreeMap::new();
    if let Some(row) = validate_rows_with_recipe(state, IssuanceKeyRecipeV3::GlobalV2, false)? {
        family.insert(IssuanceKeyRecipeV3::GlobalV2, row);
    }
    for project in projects {
        let recipe = IssuanceKeyRecipeV3::ProjectV3(project);
        let row = validate_rows_with_recipe(state, recipe, false)?.ok_or(JournalError::ProtectedBoundary)?;
        if family.values().any(|other| other.packet.intent().ok().map(|intent| intent.project()) == Some(project)) {
            return Err(JournalError::ProtectedBoundary);
        }
        family.insert(recipe, row);
    }
    let active = family.values().filter(|row| row.complete.is_none()).count();
    let reserved = family.values().filter(|row| row.begin.is_some() && row.complete.is_none()).count();
    if active > 1 { return Err(JournalError::ProtectedBoundary); }
    super::source_tree_successor::require_exact_capacity_family(
        state, super::GlobalCapacityReservationPurposeV1::ControllerFirstSourceSuccessorComplete, reserved,
    )?;
    Ok(family)
}

/// Derives the exact conservative two-transaction Controller suffix budget.
pub(crate) fn controller_capacity_request(
    packet: &SourceSuccessorApprovalDataV2,
    begin: &ControllerFirstSourceSuccessorBeginV2,
) -> Result<super::GlobalCapacityReservationRequestV1, JournalError> {
    controller_capacity_request_with_recipe(packet, begin, IssuanceKeyRecipeV3::GlobalV2)
}

pub(crate) fn controller_capacity_request_with_recipe(
    packet: &SourceSuccessorApprovalDataV2,
    begin: &ControllerFirstSourceSuccessorBeginV2,
    recipe: IssuanceKeyRecipeV3,
) -> Result<super::GlobalCapacityReservationRequestV1, JournalError> {
    let anchored = JournalTransaction::new([1; 16], vec![JournalRecord::put(
        RecordNamespace::DesiredState, recipe.key(b"consumer-anchored")?, vec![1; 144],
    )])?;
    let complete = JournalTransaction::new([2; 16], vec![
        JournalRecord::put(RecordNamespace::DesiredState, recipe.key(b"consumer-complete")?, vec![1; 240]),
        super::source_tree_successor::sizing_capacity_delete(),
    ])?;
    super::source_tree_successor::capacity_request(
        super::GlobalCapacityReservationPurposeV1::ControllerFirstSourceSuccessorComplete,
        array(packet.body(), 32)?, ProjectId::from_bytes(array(packet.body(), 64)?),
        array(packet.body(), 80)?, begin.digest(), packet.digest(),
        successor_digest_at(begin.as_bytes(), 80)?, successor_digest_at(begin.as_bytes(), 48)?,
        &[anchored, complete], 2,
    )
}

fn require_consumer_transition(
    state: &State,
    transaction: &JournalTransaction,
    transition: Transition,
) -> Result<Option<[u8; 32]>, JournalError> {
    require_consumer_transition_with_recipe(state, transaction, transition, IssuanceKeyRecipeV3::GlobalV2)
}

fn require_consumer_transition_with_recipe(
    state: &State,
    transaction: &JournalTransaction,
    transition: Transition,
    recipe: IssuanceKeyRecipeV3,
) -> Result<Option<[u8; 32]>, JournalError> {
    let rows = if recipe == IssuanceKeyRecipeV3::GlobalV2 && !state.keys().any(|(_, key)| key.starts_with(PROJECT_PREFIX)) {
        validate_rows(state)?
    } else {
        validate_project_family_v3(state)?.remove(&recipe)
    }.ok_or(JournalError::ProtectedBoundary)?;
    if !rows.delivered || rows.complete.is_some() {
        return Err(JournalError::ProtectedBoundary);
    }
    let (suffix, phase, width) = match transition {
        Transition::Begin => (
            b"consumer-begin".as_slice(), FirstSourceSuccessorNativePhaseV2::ControllerBegin, 296,
        ),
        Transition::Anchored => (
            b"consumer-anchored".as_slice(), FirstSourceSuccessorNativePhaseV2::ControllerAnchored, 144,
        ),
        Transition::Complete => (
            b"consumer-complete".as_slice(), FirstSourceSuccessorNativePhaseV2::ControllerComplete, 240,
        ),
        _ => return Err(JournalError::ProtectedBoundary),
    };
    let record = transaction.records().first()
        .ok_or(JournalError::ProtectedBoundary)?;
    if transaction.id() != &successor_transaction_id(rows.packet.digest(), phase)
        || record.namespace() != RecordNamespace::DesiredState
        || record.key() != recipe.key(suffix)?
        || record.value().is_none_or(|value| value.len() != width)
        || state.contains_key(&(record.namespace(), record.key().to_vec()))
    {
        return Err(JournalError::ProtectedBoundary);
    }

    let settling = match transition {
        Transition::Begin => {
            let [begin_record, capacity] = transaction.records() else {
                return Err(JournalError::ProtectedBoundary);
            };
            if rows.begin.is_some() {
                return Err(JournalError::ProtectedBoundary);
            }
            let bytes = begin_record.value().ok_or(JournalError::ProtectedBoundary)?;
            let begin = ControllerFirstSourceSuccessorBeginV2::decode(bytes)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            let request = controller_capacity_request_with_recipe(&rows.packet, &begin, recipe)?;
            if capacity != &super::first_source_successor_capacity_record_v2(&request, *transaction.id())?
                || state.contains_key(&(capacity.namespace(), capacity.key().to_vec()))
            {
                return Err(JournalError::ProtectedBoundary);
            }
            None
        }
        Transition::Anchored => {
            if transaction.records().len() != 1 || rows.begin.is_none() || rows.anchored.is_some() {
                return Err(JournalError::ProtectedBoundary);
            }
            None
        }
        Transition::Complete => {
            let [_, deletion] = transaction.records() else {
                return Err(JournalError::ProtectedBoundary);
            };
            let begin = rows.begin.as_ref().ok_or(JournalError::ProtectedBoundary)?;
            if rows.anchored.is_none() {
                return Err(JournalError::ProtectedBoundary);
            }
            let request = controller_capacity_request_with_recipe(&rows.packet, begin, recipe)?;
            let admission = successor_transaction_id(rows.packet.digest(), FirstSourceSuccessorNativePhaseV2::ControllerBegin);
            if deletion != &super::first_source_successor_capacity_delete_v2(state, &request, admission)? {
                return Err(JournalError::ProtectedBoundary);
            }
            Some(super::first_source_successor_capacity_identity_v2(&request, admission)?)
        }
        _ => return Err(JournalError::ProtectedBoundary),
    };

    let after = super::root_original_inventory::materialize(state, transaction);
    if recipe == IssuanceKeyRecipeV3::GlobalV2 && !state.keys().any(|(_, key)| key.starts_with(PROJECT_PREFIX)) {
        validate_rows(&after)?;
    } else {
        validate_project_family_v3(&after)?;
    }
    Ok(settling)
}

pub(super) fn consumer_settling(
    state: &State,
    transaction: &JournalTransaction,
    phase: Option<FirstSourceSuccessorNativePhaseV2>,
) -> Result<Option<[u8; 32]>, JournalError> {
    if let Some(transition) = phase.map(|phase| phase.controller_transition_for(transaction)).transpose()?.flatten() {
        return require_consumer_transition_with_recipe(state, transaction, transition.canonical(), transition.recipe());
    }
    if super::source_tree_successor::touches_capacity_purpose(
        state, transaction, super::GlobalCapacityReservationPurposeV1::ControllerFirstSourceSuccessorComplete,
    )? {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(None)
}

pub(crate) fn recognize_replayed_transition(
    transaction: &JournalTransaction,
) -> Result<Option<Transition>, JournalError> {
    if let Some(record) = transaction.records().iter().find(|record| record.key().starts_with(PROJECT_PREFIX)) {
        let key = record.key();
        if record.namespace() != RecordNamespace::DesiredState || key.len() != PROJECT_PREFIX.len() + 17 {
            return Err(JournalError::ProtectedBoundary);
        }
        let project = ProjectId::from_bytes(array(key, PROJECT_PREFIX.len())?);
        return Ok(Some(match key[PROJECT_PREFIX.len() + 16] {
            0 => Transition::ProjectSave(project), 3 => Transition::ProjectDelivered(project),
            4 => Transition::ProjectBegin(project), 5 => Transition::ProjectAnchored(project),
            6 => Transition::ProjectComplete(project), _ => return Err(JournalError::ProtectedBoundary),
        }));
    }
    let Some(record) = transaction.records().iter().find(|record| record.key().starts_with(PREFIX)) else {
        return Ok(None);
    };
    let transition = if record.key() == key(b"packet") {
        Transition::Save
    } else if record.key() == key(b"delivered") {
        Transition::Delivered
    } else if record.key() == key(b"consumer-begin") {
        Transition::Begin
    } else if record.key() == key(b"consumer-anchored") {
        Transition::Anchored
    } else if record.key() == key(b"consumer-complete") {
        Transition::Complete
    } else {
        return Err(JournalError::ProtectedBoundary);
    };
    Ok(Some(transition))
}

fn require_administrative_epoch(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    packet: &SourceSuccessorApprovalDataV2,
) -> Result<(), JournalError> {
    let project = packet.intent()
        .map_err(|_| JournalError::ProtectedBoundary)?.project();
    let current = super::controller_source_genesis::all_rows(state)?;
    let original = current.get(&project).ok_or(JournalError::ProtectedBoundary)?;
    let completed = original.complete.as_ref()
        .ok_or(JournalError::ProtectedBoundary)?;
    let original_epoch = original.acceptance.seed_claims()
        .map_err(|_| JournalError::ProtectedBoundary)?.epoch();
    if packet.epoch().map_err(|_| JournalError::ProtectedBoundary)?
        != original_epoch.checked_add(1).ok_or(JournalError::ProtectedBoundary)?
        || packet.body()[144..176] != *digest_at(completed, 80).as_bytes()
        || packet.body()[176..208] != *digest_at(completed, 112).as_bytes()
    {
        return Err(JournalError::ProtectedBoundary);
    }

    // Full Root roles and the two administrative roles use different domains.
    // The original received-floor/accepted-input join belongs to the real
    // coordinator; the administrative digest cannot stand in for that tuple.
    Ok(())
}

pub(super) fn require_no_compaction(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<(), JournalError> {
    if state.keys().any(|(_, key)| key.starts_with(PROJECT_PREFIX)) {
        return if validate_project_family_v3(state)?.values().any(|row| row.complete.is_none()) {
            Err(JournalError::ProtectedBoundary)
        } else { Ok(()) };
    }
    if validate_rows(state)?.is_some_and(|row| row.complete.is_none()) {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

impl Journal {
    pub(crate) fn prepare_project_successor_issuance_v3(
        &self, packet: &SourceSuccessorApprovalDataV2, transition: Transition,
    ) -> Result<Option<JournalTransaction>, JournalError> {
        let project = packet.intent().map_err(|_| JournalError::ProtectedBoundary)?.project();
        if transition.recipe() != IssuanceKeyRecipeV3::ProjectV3(project)
            || !matches!(transition, Transition::ProjectSave(_) | Transition::ProjectDelivered(_))
        { return Err(JournalError::ProtectedBoundary); }
        let saved = retained_project_v3(self, project)?;
        let needed = match (transition, saved) {
            (Transition::ProjectSave(_), None) => true,
            (Transition::ProjectSave(_), Some(saved)) if saved.packet == *packet => false,
            (Transition::ProjectDelivered(_), Some(saved)) if saved.packet == *packet => !saved.delivered,
            _ => return Err(JournalError::ProtectedBoundary),
        };
        if !needed { return Ok(None); }
        let transaction = transaction(packet, transition)?;
        require_no_mutation(&self.state, &transaction, Some(transition))?;
        Ok(Some(transaction))
    }

    pub(crate) fn controller_first_successor_rows_v2(&self) -> Result<Option<RetainedIssuanceDataV2>, JournalError> {
        retained(self)
    }

    /// Checks the complete two-append suffix with the existing native fold.
    pub(crate) fn preflight_source_successor_issuance_v2(
        &self,
        packet: &SourceSuccessorApprovalDataV2,
    ) -> Result<(), JournalError> {
        self.preflight_successor_issuance_with_recipe(packet, IssuanceKeyRecipeV3::GlobalV2)
    }

    pub(crate) fn preflight_project_successor_issuance_v3(
        &self, packet: &SourceSuccessorApprovalDataV2,
    ) -> Result<(), JournalError> {
        let project = packet.intent().map_err(|_| JournalError::ProtectedBoundary)?.project();
        self.preflight_successor_issuance_with_recipe(packet, IssuanceKeyRecipeV3::ProjectV3(project))
    }

    fn preflight_successor_issuance_with_recipe(
        &self, packet: &SourceSuccessorApprovalDataV2, recipe: IssuanceKeyRecipeV3,
    ) -> Result<(), JournalError> {
        let saved = match recipe {
            IssuanceKeyRecipeV3::GlobalV2 => retained(self)?,
            IssuanceKeyRecipeV3::ProjectV3(project) => retained_project_v3(self, project)?,
        };
        let (save, delivered) = match recipe {
            IssuanceKeyRecipeV3::GlobalV2 => (Transition::Save, Transition::Delivered),
            IssuanceKeyRecipeV3::ProjectV3(project) => (Transition::ProjectSave(project), Transition::ProjectDelivered(project)),
        };
        let (transactions, transitions) = match saved {
            None => (
                vec![
                    transaction(packet, save)?,
                    transaction(packet, delivered)?,
                ],
                vec![save, delivered],
            ),
            Some(saved) if saved.packet == *packet && !saved.delivered => (
                vec![transaction(packet, delivered)?],
                vec![delivered],
            ),
            Some(saved) if saved.packet == *packet && saved.delivered => return Ok(()),
            Some(_) => return Err(JournalError::ProtectedBoundary),
        };
        self.preflight_with_cache_gate_and_successor_issuance(
            &transactions,
            None,
            false,
            false,
            None,
            None,
            None,
            None,
            CacheMutationGateV1::Ordinary,
            Some(&transitions),
        )
    }

    pub(crate) fn save_source_successor_issuance_v2(
        &mut self,
        packet: &SourceSuccessorApprovalDataV2,
    ) -> Result<(), JournalError> {
        if let Some(saved) = retained(self)? {
            return if saved.packet == *packet {
                Ok(())
            } else {
                Err(JournalError::ProtectedBoundary)
            };
        }

        self.commit_source_successor_transition_v2(packet, Transition::Save)?;
        if retained(self)?.is_none_or(|saved| saved.packet != *packet || saved.delivered) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn complete_source_successor_delivery_v2(
        &mut self,
        packet: &SourceSuccessorApprovalDataV2,
    ) -> Result<(), JournalError> {
        let saved = retained(self)?.ok_or(JournalError::ProtectedBoundary)?;
        if saved.packet != *packet {
            return Err(JournalError::ProtectedBoundary);
        }
        if !saved.delivered {
            self.commit_source_successor_transition_v2(packet, Transition::Delivered)?;
        }
        if retained(self)?.is_none_or(|saved| saved.packet != *packet || !saved.delivered) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    fn commit_source_successor_transition_v2(
        &mut self,
        packet: &SourceSuccessorApprovalDataV2,
        transition: Transition,
    ) -> Result<(), JournalError> {
        self.commit_with_cache_gate_and_successor_issuance(
            &transaction(packet, transition)?,
            None,
            false,
            false,
            false,
            false,
            false,
            super::SourceProjectAdmissionTransition::None,
            super::controller_source_genesis::ControllerSourceGenesisTransition::None,
            super::source_tree_genesis::SourceGenesisTransitionV1::None,
            super::RootSourceGenesisTransitionV1::None,
            None,
            CacheMutationGateV1::Ordinary,
            Some(transition),
        ).map(|_| ())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn publish_source_successor_v2(
        &self,
        packet: &SourceSuccessorApprovalDataV2,
        custody: &mut PublicationCustodyV2,
    ) -> Result<(), JournalError> {
        self.publish_successor_with_names(packet, custody, IssuanceKeyRecipeV3::GlobalV2, OUTPUT_NAME, TEMPORARY_NAME)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn publish_project_successor_v3(
        &self, packet: &SourceSuccessorApprovalDataV2, custody: &mut PublicationCustodyV2,
    ) -> Result<(), JournalError> {
        let project = packet.intent().map_err(|_| JournalError::ProtectedBoundary)?.project();
        let (output, temporary) = project_publication_names_v3(project);
        self.publish_successor_with_names(packet, custody, IssuanceKeyRecipeV3::ProjectV3(project), &output, &temporary)
    }

    #[cfg(target_os = "linux")]
    fn publish_successor_with_names(
        &self, packet: &SourceSuccessorApprovalDataV2, custody: &mut PublicationCustodyV2,
        recipe: IssuanceKeyRecipeV3, output: &str, temporary: &str,
    ) -> Result<(), JournalError> {
        self.ensure_protected_authority()?;
        let saved = match recipe {
            IssuanceKeyRecipeV3::GlobalV2 => retained(self)?,
            IssuanceKeyRecipeV3::ProjectV3(project) => retained_project_v3(self, project)?,
        };
        if saved.is_none_or(|saved| saved.packet != *packet) {
            return Err(JournalError::ProtectedBoundary);
        }
        let directory = &self.protected.as_ref()
            .ok_or(JournalError::ProtectedBoundary)?.directory;
        match rustix::fs::statat(
            directory, temporary, rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Err(error) if error == rustix::io::Errno::NOENT => {}
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(JournalError::ProtectedBoundary),
        }

        match open_nofollow_child(directory, output) {
            Ok(file) => custody.original = Some(File::from(file)),
            Err(error) if error == rustix::io::Errno::NOENT => {
                if custody.staged.is_some() || custody.original.is_some() {
                    return Err(JournalError::ProtectedBoundary);
                }
                custody.staged = Some(File::from(rustix::fs::openat(
                    directory,
                    temporary,
                    OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::from_bits_truncate(0o600),
                )?));
                let staged = custody.staged.as_mut().ok_or(JournalError::ProtectedBoundary)?;
                staged.write_all(packet.as_bytes())?;
                staged.sync_all()?;
                self.ensure_protected_authority()?;
                rustix::fs::renameat_with(
                    directory, temporary, directory, output, RenameFlags::NOREPLACE,
                )?;
                custody.original = Some(File::from(open_nofollow_child(directory, output)?));
            }
            Err(error) => return Err(error.into()),
        }

        // Replay equality is not delivery durability. Both branches validate
        // and sync the same retained final description and original directory
        // before a Delivered append or SAME-flight Finish can follow.
        self.recheck_successor_publication_with_name(packet, custody, output)?;

        let original = custody.original.as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        original.sync_all()?;
        self.ensure_protected_authority()?;
        rustix::fs::fsync(directory)?;

        self.recheck_successor_publication_with_name(packet, custody, output)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn recheck_source_successor_publication_v2(
        &self,
        packet: &SourceSuccessorApprovalDataV2,
        custody: &mut PublicationCustodyV2,
    ) -> Result<(), JournalError> {
        self.recheck_successor_publication_with_name(packet, custody, OUTPUT_NAME)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn recheck_project_successor_publication_v3(
        &self, packet: &SourceSuccessorApprovalDataV2, custody: &mut PublicationCustodyV2,
    ) -> Result<(), JournalError> {
        let project = packet.intent().map_err(|_| JournalError::ProtectedBoundary)?.project();
        let (output, _) = project_publication_names_v3(project);
        self.recheck_successor_publication_with_name(packet, custody, &output)
    }

    #[cfg(target_os = "linux")]
    fn recheck_successor_publication_with_name(
        &self, packet: &SourceSuccessorApprovalDataV2, custody: &mut PublicationCustodyV2, output: &str,
    ) -> Result<(), JournalError> {
        self.ensure_protected_authority()?;
        let location = self.protected.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        let original = custody.original.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        let metadata = rustix::fs::fstat(original)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
            || metadata.st_mode & 0o7777 != 0o600
            || metadata.st_uid != location.expected_uid
            || metadata.st_gid != rustix::process::getegid().as_raw()
            || metadata.st_nlink != 1
            || metadata.st_size != SOURCE_SUCCESSOR_APPROVAL_BYTES_V2 as i64
            || custody.readbacks.len() >= 16
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let named = open_nofollow_child(&location.directory, output)?;
        let named_metadata = rustix::fs::fstat(&named)?;
        if named_metadata.st_dev != metadata.st_dev || named_metadata.st_ino != metadata.st_ino {
            return Err(JournalError::ProtectedBoundary);
        }

        custody.readbacks.push([0; SOURCE_SUCCESSOR_APPROVAL_BYTES_V2]);
        let readback = custody.readbacks.last_mut().ok_or(JournalError::ProtectedBoundary)?;
        read_exact_positioned(original.as_fd(), readback)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let after = rustix::fs::fstat(original)?;
        if readback != packet.as_bytes()
            || metadata.st_dev != after.st_dev
            || metadata.st_ino != after.st_ino
            || metadata.st_mode != after.st_mode
            || metadata.st_uid != after.st_uid
            || metadata.st_gid != after.st_gid
            || metadata.st_nlink != after.st_nlink
            || metadata.st_size != after.st_size
            || metadata.st_mtime != after.st_mtime
            || metadata.st_mtime_nsec != after.st_mtime_nsec
            || metadata.st_ctime != after.st_ctime
            || metadata.st_ctime_nsec != after.st_ctime_nsec
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let final_named = open_nofollow_child(&location.directory, output)?;
        let final_metadata = rustix::fs::fstat(&final_named)?;
        if final_metadata.st_dev != metadata.st_dev || final_metadata.st_ino != metadata.st_ino {
            return Err(JournalError::ProtectedBoundary);
        }
        self.ensure_protected_authority()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hierarchy::source_genesis::tests as genesis_fixture;
    use crate::hierarchy::source_successor::tests::approval_fixture;

    type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

    fn apply(state: &mut State, transaction: &JournalTransaction) {
        for record in transaction.records() {
            state.insert(
                (record.namespace(), record.key().to_vec()),
                record.value().unwrap().to_vec(),
            );
        }
    }

    // Reuses canonical old records without constructing a protected owner.
    fn completed_fixture() -> (State, SourceSuccessorApprovalDataV2) {
        let (packet, _) = approval_fixture();
        let acceptance = genesis_fixture::acceptance(packet.intent().unwrap().project());
        let floor = aos_sandbox_core::ObjectDigest::from_bytes([71; 32]);
        let ack = super::super::controller_source_genesis::ack_bytes(
            acceptance.digest(), floor, aos_sandbox_core::ObjectDigest::from_bytes([72; 32]),
        ).unwrap();
        let complete = super::super::controller_source_genesis::complete_bytes(
            &ack, aos_sandbox_core::ObjectDigest::from_bytes([73; 32]), floor,
        ).unwrap();
        let mut state = State::new();
        for transaction in [
            super::super::controller_source_genesis::acceptance_transaction(&acceptance).unwrap(),
            super::super::controller_source_genesis::ack_transaction(acceptance.project(), &ack).unwrap(),
            super::super::controller_source_genesis::complete_transaction(acceptance.project(), &complete).unwrap(),
        ] {
            apply(&mut state, &transaction);
        }

        // The guard checks structural DATA, not this fixture's stale signature.
        let mut bytes = *packet.as_bytes();
        bytes[24..32].copy_from_slice(&(acceptance.seed_claims().unwrap().epoch() + 1).to_be_bytes());
        bytes[144..176].copy_from_slice(floor.as_bytes());
        bytes[176..208].copy_from_slice(digest_at(&complete, 112).as_bytes());
        let packet = SourceSuccessorApprovalDataV2::from_record_bytes(&bytes).unwrap();
        (state, packet)
    }

    #[test]
    fn exact_save_then_delivery_reuses_completed_genesis_and_fences_the_slot() {
        let (mut state, packet) = completed_fixture();
        let save = transaction(&packet, Transition::Save).unwrap();

        assert!(require_no_mutation(&state, &save, Some(Transition::Save)).is_ok());
        apply(&mut state, &save);
        assert!(!validate_rows(&state).unwrap().unwrap().delivered);
        assert!(require_no_mutation(&state, &save, Some(Transition::Save)).is_err());

        let delivered = transaction(&packet, Transition::Delivered).unwrap();
        assert!(require_no_mutation(&state, &delivered, Some(Transition::Delivered)).is_ok());
        apply(&mut state, &delivered);
        assert!(validate_rows(&state).unwrap().unwrap().delivered);
        assert!(require_no_mutation(&state, &delivered, Some(Transition::Delivered)).is_err());
        assert!(require_no_compaction(&state).is_err());
    }

    #[test]
    fn issuer_guard_rejects_reordering_interleaving_and_untyped_owned_mutations() {
        let (mut state, packet) = completed_fixture();
        let save = transaction(&packet, Transition::Save).unwrap();
        let unrelated = JournalRecord::put(RecordNamespace::DesiredState, b"unrelated".to_vec(), vec![1]);
        let ordinary = JournalTransaction::new([11; 16], vec![unrelated.clone()]).unwrap();

        assert!(require_no_mutation(&state, &ordinary, None).is_ok());
        assert!(require_no_mutation(&state, &save, None).is_err());
        let mut reordered = save.records().to_vec();
        reordered.swap(0, 1);
        let reordered = JournalTransaction::new([12; 16], reordered).unwrap();
        assert!(require_no_mutation(&state, &reordered, Some(Transition::Save)).is_err());
        let mut interleaved = save.records().to_vec();
        interleaved.insert(1, unrelated);
        let interleaved = JournalTransaction::new([13; 16], interleaved).unwrap();
        assert!(require_no_mutation(&state, &interleaved, Some(Transition::Save)).is_err());

        apply(&mut state, &save);
        assert!(require_no_mutation(&state, &ordinary, None).is_err());
        state.insert((RecordNamespace::DesiredState, key(b"foreign")), vec![1]);
        assert!(validate_rows(&state).is_err());
    }

    #[test]
    fn issuer_guard_requires_actual_completed_checksum_and_next_original_epoch() {
        let (state, packet) = completed_fixture();
        for offset in [24, 144, 176] {
            let mut bytes = *packet.as_bytes();
            bytes[offset] ^= 1;
            let substituted = SourceSuccessorApprovalDataV2::from_record_bytes(&bytes).unwrap();
            let save = transaction(&substituted, Transition::Save).unwrap();
            assert!(require_no_mutation(&state, &save, Some(Transition::Save)).is_err(), "{offset}");
        }

        let project = packet.intent().unwrap().project();
        let acceptance = genesis_fixture::acceptance(project);
        let mut pending = State::new();
        apply(&mut pending, &super::super::controller_source_genesis::acceptance_transaction(&acceptance).unwrap());
        let save = transaction(&packet, Transition::Save).unwrap();
        assert!(require_no_mutation(&pending, &save, Some(Transition::Save)).is_err());
        assert!(matches!(validate_rows(&pending), Ok(None)));

        let mut saved = state;
        apply(&mut saved, &transaction(&packet, Transition::Save).unwrap());
        saved.insert((RecordNamespace::DesiredState, key(b"epoch")), vec![0; 8]);
        assert!(matches!(validate_rows(&saved), Err(JournalError::ProtectedBoundary)));
    }
}
