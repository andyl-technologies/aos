//! Closed native first-successor transitions and their durable Source joins.
//!
//! The fixed record codecs describe DATA. Only the actual named Controller,
//! Source and Root owners call the phase-specific native engine. This reducer
//! is also used by suffix preview and cold COMMIT; it never reconstructs a live
//! role loan or renews the original admission deadline.
//!
//! ```text
//! Source Append = Tree PUT | lineage PUT | receipt PUT | pending PUT | reserve PUT
//! Source ACK = pending DELETE | ACK PUT | reserve DELETE
//! Controller Begin = Begin PUT | reserve PUT
//! Controller Anchored = Anchored PUT
//! Controller Complete = Complete PUT | reserve DELETE
//! Root stored floor = logical floor688 | complete original intent1248 or1424
//! ```

use aos_sandbox_protocol::domain_ledger::capacity_family::family::accounting_reservations;

use crate::journal::semantic_append::{AppendScope, PreflightScope};

use std::collections::BTreeMap;
use std::path::Path;

use aos_sandbox_model::bounded_codec::checked_byte_region;
use aos_sandbox_model::{ObjectDigest, ProjectId};
use sha2::{Digest as _, Sha256};

use super::capacity_reservation::{
    first_source_successor_capacity_delete_v2, first_source_successor_capacity_identity_v2,
    first_source_successor_capacity_record_v2, reservation_key,
};
use super::{
    CacheMutationGateV1, CommitResult, GlobalCapacityReservationPurposeV1,
    GlobalCapacityReservationRequestV1, Journal, JournalError, JournalRecord, JournalTransaction,
    PreflightTransactionViewV1, RecordNamespace,
};
use aos_sandbox_ledger_replay::replay::phase_records::{
    ControllerFirstSourceSuccessorAnchoredFieldsV2, ControllerFirstSourceSuccessorAnchoredV2, RootFirstSourceSuccessorFloorFieldsV2, RootFirstSourceSuccessorFloorV2, RootFirstSourceSuccessorIntentV2, SourceFirstSuccessorAckV2, SourceFirstSuccessorPendingV2, SourceFirstSuccessorReceiptV2,
};

pub(crate) use aos_sandbox_ledger_replay::replay::source_tree_successor::{
    State, FirstSourceSuccessorNativePhaseV2, SourceFirstSuccessorRowsV2,
    SourceProjectFamilyDataV3, SourceSuccessorFamilyRecipeV3, ProjectGenesisNativePhaseV3,
};
use aos_sandbox_ledger_replay::replay::source_tree_successor::{PREFIX, RECEIPT_PREFIX, ACK_PREFIX, ACK_SIZING_BYTES};
pub(crate) use aos_sandbox_ledger_replay::replay::source_tree_successor::PENDING_KEY;

mod retained;
pub(super) use retained::SourceReplayFamilyOriginalsV1;

mod transition_retained;
pub(super) use transition_retained::SourceReplayTransactionOriginalsV1;

mod predecessor_retained;
pub(super) use predecessor_retained::SourceGenesisPredecessorOriginalsV1;

mod project_genesis_retained;
use project_genesis_retained::SourceProjectGenesisOriginalsV1;



pub(crate) fn receipt_key(project: ProjectId) -> Vec<u8> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::receipt_key(project)
}

pub(crate) fn ack_key(project: ProjectId) -> Vec<u8> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::ack_key(project)
}

pub(crate) fn transaction_id(
    approval: ObjectDigest,
    phase: FirstSourceSuccessorNativePhaseV2,
) -> [u8; 16] {
    aos_sandbox_ledger_replay::replay::source_tree_successor::transaction_id(approval, phase)
}

/// Rejoins the complete immutable Source predecessor and successor family.
pub(crate) fn current_rows(state: &State) -> Result<SourceFirstSuccessorRowsV2, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::current_rows(state)
        .map_err(JournalError::from)
}

pub(super) enum ProjectGenesisNativeCutV3<'cut> {
    #[cfg(target_os = "linux")]
    SourcePrepared(&'cut crate::policy_compiler::HeldRootSourceProjectGenesisIntentV3<'cut>),
    #[cfg(target_os = "linux")]
    SourceAnchored(&'cut crate::policy_compiler::RootSourceProjectGenesisFloorProofV3<'cut>),
}

// Only actual selected owners supply these loans. No replay, preview, scalar
// project or decoded archive can construct a positive original crossing.
#[cfg(target_os = "linux")]
pub(crate) enum FirstSuccessorNativeCutV3<'loan, 'owner> {
    ControllerBegin(&'loan crate::policy_compiler::HeldControllerFirstSourceSuccessorV2<'owner>),
    SourcePrepared(crate::policy_compiler::RootSuccessorIntentViewV3<'loan, 'owner>),
    Settled(crate::policy_compiler::RootSuccessorFloorViewV3<'loan, 'owner>),
}

#[cfg(target_os = "linux")]
impl FirstSuccessorNativeCutV3<'_, '_> {
    pub(super) fn final_crossing(
        &self, journal: &mut Journal, transaction: &JournalTransaction,
        phase: FirstSourceSuccessorNativePhaseV2,
    ) -> Result<(), crate::hierarchy::genesis_profile::SourceGenesisErrorV1> {
        use FirstSourceSuccessorNativePhaseV2 as Phase;
        use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;

        match (self, phase) {
            (Self::ControllerBegin(controller), Phase::MixedControllerBegin) => {
                controller.native_begin_crossing_v3(journal)
            }
            (Self::SourcePrepared(root), Phase::MixedSourceAppend) => {
                root.recheck()?;
                root.current_admission_clock().map(|_| ())
            }
            (Self::Settled(root), Phase::MixedSourceAck | Phase::MixedControllerAnchored | Phase::MixedControllerComplete) => {
                root.recheck()?;
                root.observe_original_clock().map(|_| ())
            }
            _ => Err(SourceGenesisErrorV1::Conflict),
        }
    }
}

#[cfg(target_os = "linux")]
impl ProjectGenesisNativeCutV3<'_> {
    pub(super) fn final_crossing(&self) -> Result<(), crate::hierarchy::genesis_profile::SourceGenesisErrorV1> {
        match self {
            Self::SourcePrepared(root) => root.native_crossing_clock_v3(),
            Self::SourceAnchored(root) => root.native_crossing_clock_v3(),

        }
    }
}

pub(crate) fn current_project_rows_v3(
    state: &State,
    selected: Option<ProjectId>,
) -> Result<SourceFirstSuccessorRowsV2, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::current_project_rows_v3(state, selected)
        .map_err(JournalError::from)
}

pub(crate) fn current_project_genesis_rows_v3(
    state: &State,
    selected: ProjectId,
) -> Result<SourceFirstSuccessorRowsV2, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::current_project_genesis_rows_v3(state, selected)
        .map_err(JournalError::from)
}

/// Returns both already-decoded families after the same selected whole fold.
///
/// # Errors
/// Rejects a sentinel project or any incomplete predecessor, successor,
/// capacity or lineage join. Returned DATA grants no live owner permission.
pub(super) fn current_project_genesis_data_v3(
    state: &State,
    selected: ProjectId,
) -> Result<SourceProjectFamilyDataV3, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::current_project_genesis_data_v3(state, selected)
        .map_err(JournalError::from)
}

// Cold replay selects only comparison DATA from the actual canonical pending
// member. It cannot provide a live selected writer or renew its admission.
fn replay_rows(state: &State) -> Result<SourceFirstSuccessorRowsV2, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::replay_rows(state)
        .map_err(JournalError::from)
}

// Both owned families stay local to the same immutable comparison window.
fn replay_family(state: &State) -> Result<SourceProjectFamilyDataV3, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::replay_family(state)
        .map_err(JournalError::from)
}

fn replay_family_with_originals(
    state: &State,
    originals: Option<&mut SourceReplayFamilyOriginalsV1>,
) -> Result<SourceProjectFamilyDataV3, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::replay_family_with_originals(state, originals)
}

fn current_rows_with_recipe(
    state: &State,
    recipe: SourceSuccessorFamilyRecipeV3,
) -> Result<SourceFirstSuccessorRowsV2, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::current_rows_with_recipe(state, recipe)
        .map_err(JournalError::from)
}

fn current_rows_with_genesis_selection(
    state: &State,
    recipe: SourceSuccessorFamilyRecipeV3,
    genesis_selection: Option<ProjectId>,
) -> Result<SourceFirstSuccessorRowsV2, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::current_rows_with_genesis_selection(state, recipe, genesis_selection)
        .map_err(JournalError::from)
}

fn current_family_with_genesis_selection(
    state: &State,
    recipe: SourceSuccessorFamilyRecipeV3,
    genesis_selection: Option<ProjectId>,
) -> Result<SourceProjectFamilyDataV3, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::current_family_with_genesis_selection(state, recipe, genesis_selection)
        .map_err(JournalError::from)
}

// Replay moves the whole genesis DATA parsed from this same immutable State.
// Its maps remain resident during the successor scan; ordinary callers still
// decode at the original point below, after that scan and the singleton check.
fn current_family_with_genesis_data(
    state: &State,
    recipe: SourceSuccessorFamilyRecipeV3,
    genesis_selection: Option<ProjectId>,
    decoded_genesis: Option<aos_sandbox_ledger_replay::replay::source_tree_genesis::SourceGenesisRowsV1>,
) -> Result<SourceProjectFamilyDataV3, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::current_family_with_genesis_data(state, recipe, genesis_selection, decoded_genesis)
        .map_err(JournalError::from)
}

fn current_family_with_genesis_data_originals(
    state: &State,
    recipe: SourceSuccessorFamilyRecipeV3,
    genesis_selection: Option<ProjectId>,
    decoded_genesis: Option<aos_sandbox_ledger_replay::replay::source_tree_genesis::SourceGenesisRowsV1>,
    originals: Option<&mut retained::SourceFamilyOriginalsV1>,
) -> Result<SourceProjectFamilyDataV3, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::current_family_with_genesis_data_originals(state, recipe, genesis_selection, decoded_genesis, originals)
}

/// Derives exact ACK sizing from the receipt and the sole canonical frame codec.
pub(crate) fn source_capacity_request(
    receipt: &SourceFirstSuccessorReceiptV2,
) -> Result<GlobalCapacityReservationRequestV1, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::source_capacity_request(receipt)
        .map_err(JournalError::from)
}

/// Binds one closed owner to its exact conservative remaining suffix budget.
#[allow(clippy::too_many_arguments)]
pub(crate) fn capacity_request(
    purpose: GlobalCapacityReservationPurposeV1,
    instance: [u8; 32],
    project: ProjectId,
    request: [u8; 16],
    owner_digest: ObjectDigest,
    approval: ObjectDigest,
    checkpoint: ObjectDigest,
    predecessor: ObjectDigest,
    suffix: &[JournalTransaction],
    future_transactions: u32,
) -> Result<GlobalCapacityReservationRequestV1, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::capacity_request(purpose, instance, project, request, owner_digest, approval, checkpoint, predecessor, suffix, future_transactions)
        .map_err(JournalError::from)
}

/// Returns fixed-width deletion sizing DATA with the actual capacity key codec.
pub(crate) fn sizing_capacity_delete() -> JournalRecord {
    aos_sandbox_ledger_replay::replay::source_tree_successor::sizing_capacity_delete()
}

fn pending_matches_receipt(
    pending: &SourceFirstSuccessorPendingV2,
    receipt: &SourceFirstSuccessorReceiptV2,
) -> bool {
    aos_sandbox_ledger_replay::replay::source_tree_successor::pending_matches_receipt(pending, receipt)
}

pub(super) fn require_transition(
    state: &State,
    transaction: &JournalTransaction,
    phase: Option<FirstSourceSuccessorNativePhaseV2>,
) -> Result<Option<[u8; 32]>, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::require_transition::<JournalError,
        crate::hierarchy::protected_journal::HierarchyProtectedJournalErrorV1,
        crate::hierarchy::genesis_profile::SourceGenesisErrorV1>(
        state, transaction, phase,
    )
}

fn require_replayed_transition(
    state: &State, transaction: &JournalTransaction,
    phase: Option<FirstSourceSuccessorNativePhaseV2>,
    originals: Option<&mut transition_retained::SourceTransitionOriginalsV1>,
    project_originals: Option<&mut SourceProjectGenesisOriginalsV1>,
) -> Result<Option<[u8; 32]>, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::require_replayed_transition::<JournalError,
        crate::hierarchy::protected_journal::HierarchyProtectedJournalErrorV1,
        crate::hierarchy::genesis_profile::SourceGenesisErrorV1>(
        state, transaction, phase, originals, project_originals,
    )
}

fn select_replayed_genesis_project_engine(
    state: &State,
    transaction: &JournalTransaction,
    phase: Option<FirstSourceSuccessorNativePhaseV2>,
    originals: Option<&mut project_genesis_retained::SourceGenesisSelectionOriginalsV1>,
) -> Result<Option<ProjectId>, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::select_replayed_genesis_project_engine(state, transaction, phase, originals)
}

// The canonical genesis reducer still owns the exact four/two-record shape.
// This comparison adds all settled foreign successor members and preserves
// their bytes before and after the selected initial-project transition.
pub(super) fn require_project_genesis_transition_v3(
    state: &State,
    transaction: &JournalTransaction,
    project: ProjectId,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::require_project_genesis_transition_v3(state, transaction, project)
        .map_err(JournalError::from)
}

fn require_project_genesis_transition_engine(
    state: &State,
    transaction: &JournalTransaction,
    project: ProjectId,
    originals: Option<&mut SourceProjectGenesisOriginalsV1>,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::require_project_genesis_transition_engine(state, transaction, project, originals)
}

fn current_project_genesis_rows_with_originals(
    state: &State,
    selected: ProjectId,
    originals: &mut retained::SourceFamilyOriginalsV1,
) -> Result<SourceFirstSuccessorRowsV2, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::current_project_genesis_rows_with_originals(state, selected, originals)
}

pub(super) fn require_project_genesis_family_v3(
    state: &State,
    transaction: &JournalTransaction,
    phase: ProjectGenesisNativePhaseV3,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::require_project_genesis_family_v3(state, transaction, phase)
        .map_err(JournalError::from)
}

pub(super) fn require_project_genesis_native_owner_v3(
    journal: &Journal,
    phase: ProjectGenesisNativePhaseV3,
) -> Result<(), JournalError> {
    match phase {
        ProjectGenesisNativePhaseV3::SourceAppend(_) | ProjectGenesisNativePhaseV3::SourceAck(_) => {
            require_capacity_owner(journal, GlobalCapacityReservationPurposeV1::SourceFirstSourceSuccessorAck)
        }
        ProjectGenesisNativePhaseV3::RootPrepared(_) | ProjectGenesisNativePhaseV3::RootAnchor(_) => {
            Err(JournalError::ProtectedBoundary)
        }
        ProjectGenesisNativePhaseV3::ControllerFloorAck(_) | ProjectGenesisNativePhaseV3::ControllerComplete(_) => {
            crate::hierarchy::controller_genesis::require_controller(journal, journal.protected_owner_uid()?)
                .map_err(|_| JournalError::ProtectedBoundary)
        }
    }
}

fn require_source_transition(
    state: &State,
    transaction: &JournalTransaction,
    phase: Option<FirstSourceSuccessorNativePhaseV2>,
) -> Result<Option<[u8; 32]>, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::require_source_transition::<JournalError,
        crate::hierarchy::protected_journal::HierarchyProtectedJournalErrorV1,
        crate::hierarchy::genesis_profile::SourceGenesisErrorV1>(
        state, transaction, phase,
    )
}

fn require_source_transition_with_originals(
    state: &State,
    transaction: &JournalTransaction,
    phase: Option<FirstSourceSuccessorNativePhaseV2>,
    originals: Option<&mut transition_retained::SourceTransitionOriginalsV1>,
) -> Result<Option<[u8; 32]>, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::require_source_transition_with_originals::<JournalError,
        crate::hierarchy::protected_journal::HierarchyProtectedJournalErrorV1,
        crate::hierarchy::genesis_profile::SourceGenesisErrorV1>(
        state, transaction, phase, originals,
    )
}

fn require_source_transition_with_recipe(
    state: &State,
    transaction: &JournalTransaction,
    phase: Option<FirstSourceSuccessorNativePhaseV2>,
    recipe: SourceSuccessorFamilyRecipeV3,
) -> Result<Option<[u8; 32]>, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::require_source_transition_with_recipe::<JournalError,
        crate::hierarchy::protected_journal::HierarchyProtectedJournalErrorV1,
        crate::hierarchy::genesis_profile::SourceGenesisErrorV1>(
        state, transaction, phase, recipe,
    )
}

fn require_source_transition_with_recipe_originals(
    state: &State,
    transaction: &JournalTransaction,
    phase: Option<FirstSourceSuccessorNativePhaseV2>,
    recipe: SourceSuccessorFamilyRecipeV3,
    originals: Option<&mut transition_retained::SourceTransitionOriginalsV1>,
) -> Result<Option<[u8; 32]>, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::require_source_transition_with_recipe_originals::<JournalError,
        crate::hierarchy::protected_journal::HierarchyProtectedJournalErrorV1,
        crate::hierarchy::genesis_profile::SourceGenesisErrorV1>(
        state, transaction, phase, recipe, originals,
    )
}

fn require_source_transition_engine(
    state: &State,
    transaction: &JournalTransaction,
    phase: Option<FirstSourceSuccessorNativePhaseV2>,
    recipe: SourceSuccessorFamilyRecipeV3,
    originals: Option<&mut transition_retained::SourceTransitionOriginalsV1>,
) -> Result<Option<[u8; 32]>, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::require_source_transition_engine::<JournalError,
        crate::hierarchy::protected_journal::HierarchyProtectedJournalErrorV1,
        crate::hierarchy::genesis_profile::SourceGenesisErrorV1>(
        state, transaction, phase, recipe, originals,
    )
}

pub(super) fn require_genesis_predecessor(
    state: &State,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::require_genesis_predecessor(state, transaction)
        .map_err(JournalError::from)
}

pub(super) fn require_genesis_predecessor_with_originals(
    state: &State,
    transaction: &JournalTransaction,
    originals: Option<&mut SourceGenesisPredecessorOriginalsV1>,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::require_genesis_predecessor_with_originals(state, transaction, originals)
}

fn require_genesis_predecessor_engine(
    state: &State,
    transaction: &JournalTransaction,
    originals: Option<&mut SourceGenesisPredecessorOriginalsV1>,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::require_genesis_predecessor_engine(state, transaction, originals)
}

fn require_project_genesis_predecessor_v3(
    state: &State,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::require_project_genesis_predecessor_v3(state, transaction)
        .map_err(JournalError::from)
}

fn require_project_genesis_predecessor_engine(
    state: &State,
    transaction: &JournalTransaction,
    originals: Option<&mut SourceGenesisPredecessorOriginalsV1>,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::require_project_genesis_predecessor_engine(state, transaction, originals)
}

pub(crate) fn require_capacity_owner(
    journal: &Journal,
    purpose: GlobalCapacityReservationPurposeV1,
) -> Result<(), JournalError> {
    match purpose {
        GlobalCapacityReservationPurposeV1::RootFirstSourceSuccessorAnchor => {
            Err(JournalError::ProtectedBoundary)
        }
        GlobalCapacityReservationPurposeV1::SourceFirstSourceSuccessorAck => {
            let location = journal.native.protected_view()
                .ok_or(JournalError::ProtectedBoundary)?;
            if location.expected_uid() == 0 {
                return Err(JournalError::ProtectedBoundary);
            }
            journal.require_protected_named_location(
                Path::new(crate::source_domain::PROTECTED_SOURCE_DOMAIN_ROOT),
                crate::source_domain::PROTECTED_SOURCE_DOMAIN_JOURNAL,
                location.expected_uid(),
                crate::source_domain::source_domain_journal_limits(),
            )
        }
        GlobalCapacityReservationPurposeV1::ControllerFirstSourceSuccessorComplete => {
            let location = journal.native.protected_view()
                .ok_or(JournalError::ProtectedBoundary)?;
            if location.expected_uid() == 0 {
                return Err(JournalError::ProtectedBoundary);
            }
            journal.require_protected_named_location(
                Path::new("/var/lib/aos/sandboxd"),
                "controller.journal",
                location.expected_uid(),
                crate::journal::controller::production_journal_limits(),
            )
        }
        _ => Err(JournalError::ProtectedBoundary),
    }
}

pub(super) fn require_phase_owner(
    journal: &Journal,
    phase: FirstSourceSuccessorNativePhaseV2,
) -> Result<(), JournalError> {
    let purpose = match phase.canonical() {
        FirstSourceSuccessorNativePhaseV2::RootPrepared
        | FirstSourceSuccessorNativePhaseV2::RootAnchor => {
            GlobalCapacityReservationPurposeV1::RootFirstSourceSuccessorAnchor
        }
        FirstSourceSuccessorNativePhaseV2::SourceAppend
        | FirstSourceSuccessorNativePhaseV2::SourceAck => {
            GlobalCapacityReservationPurposeV1::SourceFirstSourceSuccessorAck
        }
        _ => GlobalCapacityReservationPurposeV1::ControllerFirstSourceSuccessorComplete,
    };
    require_capacity_owner(journal, purpose)
}

pub(super) fn require_live_custody(
    journal: &Journal,
    state: &State,
    transaction: &JournalTransaction,
    phase: FirstSourceSuccessorNativePhaseV2,
) -> Result<(), JournalError> {
    require_phase_owner(journal, phase)?;
    let receipt = match phase {
        FirstSourceSuccessorNativePhaseV2::SourceAppend => {
            let record = transaction.records().get(2).ok_or(JournalError::ProtectedBoundary)?;
            Some(SourceFirstSuccessorReceiptV2::decode(required_value(record)?).map_err(crate::hierarchy::genesis_profile::SourceGenesisErrorV1::from)
                .map_err(|_| JournalError::ProtectedBoundary)?)
        }
        FirstSourceSuccessorNativePhaseV2::SourceAck => {
            current_rows(state)?.receipts.into_values().next()
        }
        FirstSourceSuccessorNativePhaseV2::MixedSourceAppend => {
            let record = transaction.records().get(2).ok_or(JournalError::ProtectedBoundary)?;
            Some(SourceFirstSuccessorReceiptV2::decode(required_value(record)?).map_err(crate::hierarchy::genesis_profile::SourceGenesisErrorV1::from)
                .map_err(|_| JournalError::ProtectedBoundary)?)
        }
        FirstSourceSuccessorNativePhaseV2::MixedSourceAck => {
            let rows = replay_rows(state)?;
            let project = rows.pending.as_ref().ok_or(JournalError::ProtectedBoundary)?.project();
            Some(rows.receipts.get(&project).ok_or(JournalError::ProtectedBoundary)?.clone())
        }
        _ => None,
    };
    if let Some(receipt) = receipt
        && journal.protected_writer_physical_names_v1()? != receipt.source_names()
    {
        return Err(JournalError::StaleAuthoritySnapshot);
    }
    Ok(())
}

pub(super) fn require_sequence_headroom(state: &State, next: u64) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::require_sequence_headroom(state, next)
        .map_err(JournalError::from)
}

pub(super) fn require_no_compaction(state: &State) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::require_no_compaction(state)
        .map_err(JournalError::from)
}

pub(super) fn recognize_replayed_phase(
    transaction: &JournalTransaction,
) -> Result<Option<FirstSourceSuccessorNativePhaseV2>, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::recognize_replayed_phase(transaction)
        .map_err(JournalError::from)
}

pub(super) fn validate_replayed_transaction(
    state: &State,
    transaction: &JournalTransaction,
    limits: super::JournalLimits,
) -> Result<bool, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::validate_replayed_transaction::<JournalError,
        crate::hierarchy::protected_journal::HierarchyProtectedJournalErrorV1,
        crate::hierarchy::genesis_profile::SourceGenesisErrorV1>(
        state, transaction, limits,
    )
}

fn validate_replayed_transaction_with_originals(
    state: &State,
    transaction: &JournalTransaction,
    limits: super::JournalLimits,
    originals: Option<&mut transition_retained::SourceTransitionOriginalsV1>,
    genesis_originals: Option<&mut super::source_tree_genesis::SourceGenesisMutationOriginalsV1>,
    project_originals: Option<&mut SourceProjectGenesisOriginalsV1>,
) -> Result<bool, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::validate_replayed_transaction_with_originals::<JournalError,
        crate::hierarchy::protected_journal::HierarchyProtectedJournalErrorV1,
        crate::hierarchy::genesis_profile::SourceGenesisErrorV1>(
        state, transaction, limits, originals, genesis_originals, project_originals,
    )
}

pub(super) fn source_member_dynamic_demand_v1(
    state: &State,
    transaction: Option<&JournalTransaction>,
) -> Result<aos_sandbox_model::ResourceVector, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::source_member_dynamic_demand_v1::<JournalError,
        crate::hierarchy::protected_journal::HierarchyProtectedJournalErrorV1,
        crate::hierarchy::genesis_profile::SourceGenesisErrorV1>(
        state, transaction,
    )
}

pub(super) fn validate_replayed_state(state: &State, compacted: bool) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::validate_replayed_state::<JournalError,
        crate::hierarchy::protected_journal::HierarchyProtectedJournalErrorV1,
        crate::hierarchy::genesis_profile::SourceGenesisErrorV1>(
        state, compacted,
    )
}

pub(super) fn validate_replayed_state_with_originals(
    state: &State,
    compacted: bool,
    originals: Option<&mut SourceReplayFamilyOriginalsV1>,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::validate_replayed_state_with_originals::<JournalError,
        crate::hierarchy::protected_journal::HierarchyProtectedJournalErrorV1,
        crate::hierarchy::genesis_profile::SourceGenesisErrorV1>(
        state, compacted, originals,
    )
}

fn validate_root_state(state: &State) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::validate_root_state(state)
        .map_err(JournalError::from)
}

fn validate_root_transition(
    state: &State,
    transaction: &JournalTransaction,
    phase: Option<FirstSourceSuccessorNativePhaseV2>,
) -> Result<Option<[u8; 32]>, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::validate_root_transition(state, transaction, phase)
        .map_err(JournalError::from)
}

pub(crate) fn touches_capacity_purpose(
    state: &State,
    transaction: &JournalTransaction,
    purpose: GlobalCapacityReservationPurposeV1,
) -> Result<bool, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::touches_capacity_purpose(state, transaction, purpose)
        .map_err(JournalError::from)
}

pub(crate) fn require_exact_capacity_family(
    state: &State,
    purpose: GlobalCapacityReservationPurposeV1,
    count: usize,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::require_exact_capacity_family(state, purpose, count)
        .map_err(JournalError::from)
}

pub(crate) fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::array::<N>(bytes, offset)
        .map_err(JournalError::from)
}

pub(crate) fn digest_at(bytes: &[u8], offset: usize) -> Result<ObjectDigest, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::digest_at(bytes, offset)
        .map_err(JournalError::from)
}

pub(crate) fn receipt_project(receipt: &SourceFirstSuccessorReceiptV2) -> Result<ProjectId, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::receipt_project(receipt)
        .map_err(JournalError::from)
}

fn project_key(key: &[u8], prefix: &[u8]) -> Result<Option<ProjectId>, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::project_key(key, prefix)
        .map_err(JournalError::from)
}

fn required_value(record: &JournalRecord) -> Result<&[u8], JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::required_value(record)
        .map_err(JournalError::from)
}

impl Journal {



    /// Returns complete local Source phase DATA under the healthy writer.
    ///
    /// # Errors
    /// Rejects poisoning or malformed predecessor, successor and reservation
    /// joins; this does not substitute for actual Controller or Root custody.
    pub(crate) fn source_first_successor_rows_v2(
        &self,
    ) -> Result<SourceFirstSuccessorRowsV2, JournalError> {
        self.ensure_healthy()?;
        current_rows(self.native.state())
    }

    /// Returns the complete mixed family as selected comparison DATA.
    pub(crate) fn source_project_continuation_rows_v3(
        &self,
        selected: Option<ProjectId>,
    ) -> Result<SourceFirstSuccessorRowsV2, JournalError> {
        self.ensure_healthy()?;
        current_project_rows_v3(self.native.state(), selected)
    }

    pub(crate) fn source_project_genesis_rows_v3(
        &self,
        selected: ProjectId,
    ) -> Result<SourceFirstSuccessorRowsV2, JournalError> {
        self.ensure_healthy()?;
        current_project_genesis_rows_v3(self.native.state(), selected)
    }

    /// Appends one exact native phase under its fixed genuine writer.
    ///
    /// # Errors
    /// Rejects a wrong phase, changed named custody or joined rows, or any
    /// native bound. An ambiguous durable append poisons the original writer.
    pub(crate) fn commit_first_source_successor_v2(
        &mut self,
        transaction: &JournalTransaction,
        phase: FirstSourceSuccessorNativePhaseV2,
    ) -> Result<CommitResult, JournalError> {
        self.commit_in_scope(
            transaction,
            AppendScope {
                allow_capacity_records: phase.has_capacity_records(),
                first_successor: Some(phase),
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
        )
    }

    /// Appends a selected phase with its genuine original final crossing loan.
    ///
    /// # Errors
    /// Rejects mismatched owner/phase, failed original cut or native bounds.
    /// The ordinary phase-only entry and all DATA previews remain unchanged.
    #[cfg(target_os = "linux")]
    pub(crate) fn commit_selected_source_successor_v3(
        &mut self, transaction: &JournalTransaction,
        phase: FirstSourceSuccessorNativePhaseV2,
        original: FirstSuccessorNativeCutV3<'_, '_>,
    ) -> Result<CommitResult, JournalError> {
        self.commit_with_native_scope(
            transaction,
            AppendScope {
                allow_capacity_records: phase.has_capacity_records(),
                first_successor: Some(phase),
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
            #[cfg(target_os = "linux")]
            None,
            Some(super::ProjectNativeTransitionV3::FirstSuccessor(original)),
            #[cfg(target_os = "linux")]
            None,
        )
    }

    /// Previews an ordered exact suffix with the same native phase reducers.
    ///
    /// # Errors
    /// Rejects mismatched phase counts, wrong owners or joined states, duplicate
    /// native IDs, and all transaction, materialization and reserved bounds.
    pub(crate) fn preflight_first_source_successor_v2(
        &self,
        transactions: &[JournalTransaction],
        phases: &[FirstSourceSuccessorNativePhaseV2],
    ) -> Result<(), JournalError> {
        self.preflight_in_scope(
            PreflightTransactionViewV1::Ordinary(transactions),
            PreflightScope {
                first_successors: Some(phases),
                ..PreflightScope::default()
            },
            CacheMutationGateV1::Ordinary,
        )
    }
}

#[cfg(test)]
mod phase_regression_tests {
    use super::{FirstSourceSuccessorNativePhaseV2 as Phase, ObjectDigest, transaction_id};

    #[test]
    fn mixed_selectors_preserve_canonical_phases_and_transaction_identities() {
        let approval = ObjectDigest::from_bytes([7; 32]);
        let cases = [
            (Phase::MixedSourceAppend, Phase::SourceAppend, 3),
            (Phase::MixedSourceAck, Phase::SourceAck, 6),
            (Phase::MixedRootPrepared, Phase::RootPrepared, 2),
            (Phase::MixedRootAnchor, Phase::RootAnchor, 4),
        ];

        for (mixed, canonical, phase_byte) in cases {
            assert_eq!(mixed.canonical(), canonical, "{mixed:?}");
            assert_eq!(mixed.canonical() as u8, phase_byte, "{mixed:?}");
            assert_eq!(
                transaction_id(approval, mixed),
                transaction_id(approval, canonical),
                "{mixed:?}",
            );
        }
    }

    #[test]
    fn ordinary_native_phases_keep_their_original_mapping() {
        let cases = [
            (Phase::ControllerBegin, 1),
            (Phase::RootPrepared, 2),
            (Phase::SourceAppend, 3),
            (Phase::RootAnchor, 4),
            (Phase::ControllerAnchored, 5),
            (Phase::SourceAck, 6),
            (Phase::ControllerComplete, 7),
        ];

        for (phase, phase_byte) in cases {
            assert_eq!(phase.canonical(), phase, "{phase:?}");
            assert_eq!(phase as u8, phase_byte, "{phase:?}");
        }
    }
}
