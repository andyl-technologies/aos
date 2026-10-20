//! Owns the sole saved Controller Source-successor issuance comparisons.
//!
//! Exact global/project row folds, canonical transaction builders, replay and
//! capacity recipes consume historical DATA only. Real publication Files,
//! retained native Journal access and live mutation/preflight remain upper.

use std::collections::BTreeMap;
use aos_sandbox_core::{ProjectId, RecordNamespace};
use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as JournalError;
use aos_sandbox_protocol::domain_ledger::transaction::{JournalRecord, JournalTransaction};
use aos_sandbox_protocol::domain_ledger::capacity::{GlobalCapacityReservationPurposeV1, GlobalCapacityReservationRequestV1};
use crate::data::{digest_at, hash, take};
use crate::successor::SourceSuccessorApprovalDataV2;
use super::phase_records::{ControllerFirstSourceSuccessorAnchoredV2, ControllerFirstSourceSuccessorBeginV2, ControllerFirstSourceSuccessorCompleteV2, SourceFirstSuccessorAckFieldsV2, SourceFirstSuccessorAckV2};
use super::source_tree_successor::{FirstSourceSuccessorNativePhaseV2, State, array, digest_at as successor_digest_at, transaction_id as successor_transaction_id};

#[doc(hidden)]
/// Names the exact canonical saved-key or frame constant.
pub const PREFIX: &[u8] = b"\0aos-controller-source-successor-issuance-v2\0";
#[doc(hidden)]
/// Names the exact canonical saved-key or frame constant.
pub const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.source-successor.issuance.transaction.v2\0";
#[doc(hidden)]
/// Names the exact canonical saved-key or frame constant.
pub const PROJECT_PREFIX: &[u8] = b"\0aos-controller-source-successor-issuance-v3\0";
#[doc(hidden)]
/// Names the exact canonical saved-key or frame constant.
pub const PROJECT_TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.source-successor.issuance.transaction.v3\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum IssuanceKeyRecipeV3 {
    GlobalV2,
    ProjectV3(ProjectId),
}

impl IssuanceKeyRecipeV3 {
    /// Returns the canonical saved key for the selected issuance recipe.
    pub fn key(self, suffix: &[u8]) -> Result<Vec<u8>, JournalError> {
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

    /// Selects the exact saved comparison phase without native authority.
    pub fn owns(self, key: &[u8]) -> bool {
        match self {
            Self::GlobalV2 => key.starts_with(PREFIX),
            Self::ProjectV3(project) => key.starts_with(PROJECT_PREFIX)
                && key.get(PROJECT_PREFIX.len()..PROJECT_PREFIX.len() + 16) == Some(project.as_bytes().as_slice()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transition {
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
    /// Selects the exact saved comparison phase without native authority.
    pub fn canonical(self) -> Self {
        match self {
            Self::ProjectSave(_) => Self::Save,
            Self::ProjectDelivered(_) => Self::Delivered,
            Self::ProjectBegin(_) => Self::Begin,
            Self::ProjectAnchored(_) => Self::Anchored,
            Self::ProjectComplete(_) => Self::Complete,
            phase => phase,
        }
    }

    /// Selects the exact saved comparison phase without native authority.
    pub fn recipe(self) -> IssuanceKeyRecipeV3 {
        match self {
            Self::ProjectSave(project) | Self::ProjectDelivered(project) | Self::ProjectBegin(project)
            | Self::ProjectAnchored(project) | Self::ProjectComplete(project) => IssuanceKeyRecipeV3::ProjectV3(project),
            _ => IssuanceKeyRecipeV3::GlobalV2,
        }
    }
}

pub struct RetainedIssuanceDataV2 {
    /// Retains this exact saved family member without live authority.
    pub packet: SourceSuccessorApprovalDataV2,
    /// Retains this exact saved family member without live authority.
    pub delivered: bool,
    /// Retains this exact saved family member without live authority.
    pub begin: Option<ControllerFirstSourceSuccessorBeginV2>,
    /// Retains this exact saved family member without live authority.
    pub anchored: Option<ControllerFirstSourceSuccessorAnchoredV2>,
    /// Retains this exact saved family member without live authority.
    pub complete: Option<ControllerFirstSourceSuccessorCompleteV2>,
}



/// Returns the canonical project issuance key.
///
/// # Errors
/// Rejects malformed, foreign, incomplete or exhausted saved DATA.
pub fn project_key_v3(project: ProjectId, suffix: &[u8]) -> Result<Vec<u8>, JournalError> {
    IssuanceKeyRecipeV3::ProjectV3(project).key(suffix)
}

/// Returns the canonical saved key for the selected issuance recipe.
pub fn key(suffix: &[u8]) -> Vec<u8> {
    let mut key = PREFIX.to_vec();
    key.extend_from_slice(suffix);
    key
}

/// Constructs the exact saved issuance transaction for its comparison phase.
///
/// # Errors
/// Rejects malformed, foreign, incomplete or exhausted saved DATA.
pub fn transaction(
    packet: &SourceSuccessorApprovalDataV2,
    transition: Transition,
) -> Result<JournalTransaction, JournalError> {
    transaction_with_recipe(packet, transition.canonical(), transition.recipe())
}

/// Constructs the canonical global or project issuance transaction.
///
/// # Errors
/// Rejects malformed, foreign, incomplete or exhausted saved DATA.
pub fn transaction_with_recipe(
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
    JournalTransaction::new(id, records).map_err(JournalError::from)
}

/// Checks the complete saved issuance mutation fence.
///
/// # Errors
/// Rejects malformed, foreign, incomplete or exhausted saved DATA.
pub fn require_no_mutation(
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

/// Checks the exact saved project issuance transition.
///
/// # Errors
/// Rejects malformed, foreign, incomplete or exhausted saved DATA.
pub fn require_project_mutation_v3(
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

/// Rejoins the complete saved global or project issuance family.
///
/// # Errors
/// Rejects malformed, foreign, incomplete or exhausted saved DATA.
pub fn validate_rows(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<RetainedIssuanceDataV2>, JournalError> {
    if state.keys().any(|(_, key)| key.starts_with(PROJECT_PREFIX)) {
        return Ok(validate_project_family_v3(state)?.remove(&IssuanceKeyRecipeV3::GlobalV2));
    }
    validate_rows_with_recipe(state, IssuanceKeyRecipeV3::GlobalV2, true)
}

/// Checks every saved row and binding in the selected issuance recipe.
///
/// # Errors
/// Rejects malformed, foreign, incomplete or exhausted saved DATA.
pub fn validate_rows_with_recipe(
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
            state, GlobalCapacityReservationPurposeV1::ControllerFirstSourceSuccessorComplete, 0,
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
    let begin = value(b"consumer-begin").map(|bytes| ControllerFirstSourceSuccessorBeginV2::decode(bytes).map_err(crate::data::SourceSuccessorDataErrorV2::from))
        .transpose().map_err(|_| JournalError::ProtectedBoundary)?;
    let anchored = value(b"consumer-anchored").map(|bytes| ControllerFirstSourceSuccessorAnchoredV2::decode(bytes).map_err(crate::data::SourceSuccessorDataErrorV2::from))
        .transpose().map_err(|_| JournalError::ProtectedBoundary)?;
    let complete = value(b"consumer-complete").map(|bytes| ControllerFirstSourceSuccessorCompleteV2::decode(bytes).map_err(crate::data::SourceSuccessorDataErrorV2::from))
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

/// Rejoins saved global consumer rows and their exact capacity family.
///
/// # Errors
/// Rejects malformed, foreign, incomplete or exhausted saved DATA.
pub fn validate_consumer_rows(
    state: &State,
    rows: &RetainedIssuanceDataV2,
) -> Result<(), JournalError> {
    validate_consumer_rows_with_recipe(state, rows, IssuanceKeyRecipeV3::GlobalV2, true)
}

/// Rejoins saved consumer rows under the selected immutable key recipe.
///
/// # Errors
/// Rejects malformed, foreign, incomplete or exhausted saved DATA.
pub fn validate_consumer_rows_with_recipe(
    state: &State,
    rows: &RetainedIssuanceDataV2,
    recipe: IssuanceKeyRecipeV3,
    exact_capacity: bool,
) -> Result<(), JournalError> {
    let Some(begin) = &rows.begin else {
        if exact_capacity { super::source_tree_successor::require_exact_capacity_family(
            state, GlobalCapacityReservationPurposeV1::ControllerFirstSourceSuccessorComplete, 0,
        )?; }
        return Ok(());
    };
    let body = rows.packet.body();
    let bytes = begin.as_bytes();
    if successor_digest_at(bytes, 16)? != rows.packet.digest()
        || bytes[48..80] != body[144..176]
        || bytes[80..112] != body[176..208]
        || bytes[112..144] != *rows.packet.old_tree_head().as_bytes()
        || bytes[144..176] != *rows.packet.old_lineage_head().as_bytes()
        || bytes[176..208] != *rows.packet.next_tree_commit().as_bytes()
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
        }).map_err(crate::data::SourceSuccessorDataErrorV2::from).map_err(|_| JournalError::ProtectedBoundary)?;
        if complete.as_bytes()[16..112] != anchored.as_bytes()[16..112]
            || successor_digest_at(complete.as_bytes(), 112)? != ack.digest()
            || successor_digest_at(complete.as_bytes(), 144)? != begin.digest()
            || successor_digest_at(complete.as_bytes(), 176)? != anchored.digest()
        {
            return Err(JournalError::ProtectedBoundary);
        }
    } else {
        super::source_tree_successor::first_source_successor_capacity_delete_v2(
            state, &controller_capacity_request_with_recipe(&rows.packet, begin, recipe)?,
            successor_transaction_id(rows.packet.digest(), FirstSourceSuccessorNativePhaseV2::ControllerBegin),
        )?;
    }
    if exact_capacity { super::source_tree_successor::require_exact_capacity_family(
        state, GlobalCapacityReservationPurposeV1::ControllerFirstSourceSuccessorComplete,
        usize::from(rows.complete.is_none()),
    ) } else { Ok(()) }
}

/// Folds the complete global and project saved issuance families.
///
/// # Errors
/// Rejects malformed, foreign, incomplete or exhausted saved DATA.
pub fn validate_project_family_v3(
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
        state, GlobalCapacityReservationPurposeV1::ControllerFirstSourceSuccessorComplete, reserved,
    )?;
    Ok(family)
}

/// Derives the exact remaining global consumer suffix geometry DATA.
///
/// # Errors
/// Rejects malformed, foreign, incomplete or exhausted saved DATA.
pub fn controller_capacity_request(
    packet: &SourceSuccessorApprovalDataV2,
    begin: &ControllerFirstSourceSuccessorBeginV2,
) -> Result<GlobalCapacityReservationRequestV1, JournalError> {
    controller_capacity_request_with_recipe(packet, begin, IssuanceKeyRecipeV3::GlobalV2)
}

/// Derives exact remaining consumer suffix geometry for one saved recipe.
///
/// # Errors
/// Rejects malformed, foreign, incomplete or exhausted saved DATA.
pub fn controller_capacity_request_with_recipe(
    packet: &SourceSuccessorApprovalDataV2,
    begin: &ControllerFirstSourceSuccessorBeginV2,
    recipe: IssuanceKeyRecipeV3,
) -> Result<GlobalCapacityReservationRequestV1, JournalError> {
    let anchored = JournalTransaction::new([1; 16], vec![JournalRecord::put(
        RecordNamespace::DesiredState, recipe.key(b"consumer-anchored")?, vec![1; 144],
    )])?;
    let complete = JournalTransaction::new([2; 16], vec![
        JournalRecord::put(RecordNamespace::DesiredState, recipe.key(b"consumer-complete")?, vec![1; 240]),
        super::source_tree_successor::sizing_capacity_delete(),
    ])?;
    super::source_tree_successor::capacity_request(
        GlobalCapacityReservationPurposeV1::ControllerFirstSourceSuccessorComplete,
        array(packet.body(), 32)?, ProjectId::from_bytes(array(packet.body(), 64)?),
        array(packet.body(), 80)?, begin.digest(), packet.digest(),
        successor_digest_at(begin.as_bytes(), 80)?, successor_digest_at(begin.as_bytes(), 48)?,
        &[anchored, complete], 2,
    )
}

/// Checks the exact saved global consumer transition.
///
/// # Errors
/// Rejects malformed, foreign, incomplete or exhausted saved DATA.
pub fn require_consumer_transition(
    state: &State,
    transaction: &JournalTransaction,
    transition: Transition,
) -> Result<Option<[u8; 32]>, JournalError> {
    require_consumer_transition_with_recipe(state, transaction, transition, IssuanceKeyRecipeV3::GlobalV2)
}

/// Checks the exact saved consumer transition and capacity settlement.
///
/// # Errors
/// Rejects malformed, foreign, incomplete or exhausted saved DATA.
pub fn require_consumer_transition_with_recipe(
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
            let begin = ControllerFirstSourceSuccessorBeginV2::decode(bytes).map_err(crate::data::SourceSuccessorDataErrorV2::from)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            let request = controller_capacity_request_with_recipe(&rows.packet, &begin, recipe)?;
            if capacity != &super::source_tree_successor::first_source_successor_capacity_record_v2(&request, *transaction.id())?
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
            if deletion != &super::source_tree_successor::first_source_successor_capacity_delete_v2(state, &request, admission)? {
                return Err(JournalError::ProtectedBoundary);
            }
            Some(super::source_tree_successor::first_source_successor_capacity_identity_v2(&request, admission)?)
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

/// Identifies the saved consumer settlement without issuing a live reservation.
///
/// # Errors
/// Rejects malformed, foreign, incomplete or exhausted saved DATA.
pub fn consumer_settling(
    state: &State,
    transaction: &JournalTransaction,
    phase: Option<FirstSourceSuccessorNativePhaseV2>,
) -> Result<Option<[u8; 32]>, JournalError> {
    if let Some(transition) = phase.map(|phase| phase.controller_transition_for(transaction)).transpose()?.flatten() {
        return require_consumer_transition_with_recipe(state, transaction, transition.canonical(), transition.recipe());
    }
    if super::source_tree_successor::touches_capacity_purpose(
        state, transaction, GlobalCapacityReservationPurposeV1::ControllerFirstSourceSuccessorComplete,
    )? {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(None)
}

/// Classifies the exact immutable issuance keys in one saved transaction.
///
/// # Errors
/// Rejects malformed, foreign, incomplete or exhausted saved DATA.
pub fn recognize_replayed_transition(
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

/// Compares the saved administrative epoch to its completed genesis rows.
///
/// # Errors
/// Rejects malformed, foreign, incomplete or exhausted saved DATA.
pub fn require_administrative_epoch(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    packet: &SourceSuccessorApprovalDataV2,
) -> Result<(), JournalError> {
    let project = packet.intent()
        .map_err(|_| JournalError::ProtectedBoundary)?.project();
    let current = crate::replay::controller_source_genesis::all_rows(state)?;
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

/// Checks that no unfinished saved issuance family would lose its history.
///
/// # Errors
/// Rejects malformed, foreign, incomplete or exhausted saved DATA.
pub fn require_no_compaction(
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
