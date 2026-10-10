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

use crate::journal::semantic_append::{AppendScope, PreflightScope};

use std::collections::BTreeMap;
use std::path::Path;

use aos_sandbox_core::bounded_codec::checked_byte_region;
use aos_sandbox_core::{ObjectDigest, ProjectId};
use sha2::{Digest as _, Sha256};

use super::capacity_reservation::{
    accounting_reservations, first_source_successor_capacity_delete_v2,
    first_source_successor_capacity_identity_v2, first_source_successor_capacity_record_v2,
    reservation_key,
};
use super::{
    CacheMutationGateV1, CommitResult, GlobalCapacityReservationPurposeV1,
    GlobalCapacityReservationRequestV1, Journal, JournalError, JournalRecord, JournalTransaction,
    PreflightTransactionViewV1, RecordNamespace,
};
use crate::policy_compiler::{
    ControllerFirstSourceSuccessorAnchoredFieldsV2, ControllerFirstSourceSuccessorAnchoredV2,
    RootFirstSourceSuccessorFloorFieldsV2, RootFirstSourceSuccessorFloorV2,
    RootFirstSourceSuccessorIntentV2, SourceFirstSuccessorAckV2,
    SourceFirstSuccessorPendingV2, SourceFirstSuccessorReceiptV2,
};

pub(crate) type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

const PREFIX: &[u8] = b"\0aos-source-first-successor-v2\0";
pub(crate) const PENDING_KEY: &[u8] = b"\0aos-source-first-successor-v2\0pending";
const RECEIPT_PREFIX: &[u8] = b"\0aos-source-first-successor-v2\0receipt\0";
const ACK_PREFIX: &[u8] = b"\0aos-source-first-successor-v2\0ACK\0";

/// Selects one exact native phase, never a public request or capacity scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum FirstSourceSuccessorNativePhaseV2 {
    ControllerBegin = 1,
    RootPrepared = 2,
    SourceAppend = 3,
    RootAnchor = 4,
    ControllerAnchored = 5,
    SourceAck = 6,
    ControllerComplete = 7,
    MixedSourceAppend,
    MixedSourceAck,
    MixedRootPrepared,
    MixedRootAnchor,
    MixedControllerBegin,
    MixedControllerAnchored,
    MixedControllerComplete,
}

impl FirstSourceSuccessorNativePhaseV2 {
    // These four variants are private comparison selectors, never durable
    // phase bytes. Retain the selected mode until the complete family join.
    pub(crate) const fn canonical(self) -> Self {
        match self {
            Self::MixedSourceAppend => Self::SourceAppend,
            Self::MixedSourceAck => Self::SourceAck,
            Self::MixedRootPrepared => Self::RootPrepared,
            Self::MixedRootAnchor => Self::RootAnchor,
            Self::MixedControllerBegin => Self::ControllerBegin,
            Self::MixedControllerAnchored => Self::ControllerAnchored,
            Self::MixedControllerComplete => Self::ControllerComplete,
            ordinary => ordinary,
        }
    }

    pub(super) const fn has_capacity_records(self) -> bool {
        !matches!(self.canonical(), Self::ControllerAnchored)
    }

    pub(super) const fn source_genesis_transition(
        self,
    ) -> super::source_tree_genesis::SourceGenesisTransitionV1 {
        use super::source_tree_genesis::SourceGenesisTransitionV1;
        match self.canonical() {
            Self::SourceAppend => SourceGenesisTransitionV1::FirstSuccessorAppend,
            Self::SourceAck => SourceGenesisTransitionV1::FirstSuccessorAck,
            _ => SourceGenesisTransitionV1::None,
        }
    }

    pub(super) const fn controller_transition(
        self,
    ) -> Option<super::controller_source_successor_issuance::Transition> {
        use super::controller_source_successor_issuance::Transition;
        match self.canonical() {
            Self::ControllerBegin => Some(Transition::Begin),
            Self::ControllerAnchored => Some(Transition::Anchored),
            Self::ControllerComplete => Some(Transition::Complete),
            _ => None,
        }
    }

    pub(super) fn controller_transition_for(
        self, transaction: &JournalTransaction,
    ) -> Result<Option<super::controller_source_successor_issuance::Transition>, JournalError> {
        if matches!(self, Self::MixedControllerBegin | Self::MixedControllerAnchored | Self::MixedControllerComplete) {
            let actual = super::controller_source_successor_issuance::recognize_replayed_transition(transaction)?
                .ok_or(JournalError::ProtectedBoundary)?;
            if Some(actual.canonical()) != self.controller_transition()
            { return Err(JournalError::ProtectedBoundary); }
            return Ok(Some(actual));
        }
        Ok(self.controller_transition())
    }
}

/// Retains validated local phase DATA without a cross-owner currentness loan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SourceFirstSuccessorRowsV2 {
    pub(crate) receipts: BTreeMap<ProjectId, SourceFirstSuccessorReceiptV2>,
    pub(crate) acks: BTreeMap<ProjectId, SourceFirstSuccessorAckV2>,
    pub(crate) pending: Option<SourceFirstSuccessorPendingV2>,
}

/// Owns the two decoded families from one complete local DATA comparison.
///
/// These maps carry no writer, Root floor loan or admission authority. Each
/// consumer moves its required family out within the same observation window;
/// the other family is dropped rather than retained across an owner effect.
pub(crate) struct SourceProjectFamilyDataV3 {
    genesis: super::source_tree_genesis::SourceGenesisRowsV1,
    successor: SourceFirstSuccessorRowsV2,
}

impl SourceProjectFamilyDataV3 {
    /// Moves the already-decoded genesis rows, discarding successor DATA.
    pub(crate) fn into_genesis(self) -> super::source_tree_genesis::SourceGenesisRowsV1 {
        self.genesis
    }

    fn into_successor(self) -> SourceFirstSuccessorRowsV2 {
        self.successor
    }
}

pub(crate) fn receipt_key(project: ProjectId) -> Vec<u8> {
    [RECEIPT_PREFIX, project.as_bytes()].concat()
}

pub(crate) fn ack_key(project: ProjectId) -> Vec<u8> {
    [ACK_PREFIX, project.as_bytes()].concat()
}

pub(crate) fn transaction_id(
    approval: ObjectDigest,
    phase: FirstSourceSuccessorNativePhaseV2,
) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.source-first-successor.transaction.v2\0");
    digest.update(approval.as_bytes());
    digest.update([phase.canonical() as u8]);
    let digest: [u8; 32] = digest.finalize().into();
    let mut identity = [0; 16];
    identity.copy_from_slice(&digest[..16]);
    identity
}

/// Rejoins the complete immutable Source predecessor and successor family.
pub(crate) fn current_rows(state: &State) -> Result<SourceFirstSuccessorRowsV2, JournalError> {
    current_rows_with_recipe(state, SourceSuccessorFamilyRecipeV3::SingleProjectV2)
}

/// Selects a structural family comparison, never native admission authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceSuccessorFamilyRecipeV3 {
    SingleProjectV2,
    MixedProjectsV3 { selected: Option<ProjectId> },
}

/// Selects an initial-project comparison without changing any durable phase byte.
#[derive(Clone, Copy)]
pub(super) enum ProjectGenesisNativePhaseV3 {
    SourceAppend(ProjectId),
    SourceAck(ProjectId),
    RootPrepared(ProjectId),
    RootAnchor(ProjectId),
    ControllerFloorAck(ProjectId),
    ControllerComplete(ProjectId),
}

impl ProjectGenesisNativePhaseV3 {
    pub(super) const fn project(self) -> ProjectId {
        match self {
            Self::SourceAppend(project) | Self::SourceAck(project)
            | Self::RootPrepared(project) | Self::RootAnchor(project)
            | Self::ControllerFloorAck(project) | Self::ControllerComplete(project) => project,
        }
    }
}

pub(super) enum ProjectGenesisNativeCutV3<'cut> {
    #[cfg(target_os = "linux")]
    SourcePrepared(&'cut crate::policy_compiler::HeldRootSourceProjectGenesisIntentV3<'cut>),
    #[cfg(target_os = "linux")]
    SourceAnchored(&'cut crate::policy_compiler::RootSourceProjectGenesisFloorProofV3<'cut>),
    RootServer { original: &'cut aos_sandbox_core::RawPairedClockSample, deadline: std::time::Instant },
}

// Only actual selected owners supply these loans. No replay, preview, scalar
// project or decoded archive can construct a positive original crossing.
#[cfg(target_os = "linux")]
pub(crate) enum FirstSuccessorNativeCutV3<'loan, 'owner> {
    ControllerBegin(&'loan crate::policy_compiler::HeldControllerFirstSourceSuccessorV2<'owner>),
    SourcePrepared(crate::policy_compiler::RootSuccessorIntentViewV3<'loan, 'owner>),
    Settled(crate::policy_compiler::RootSuccessorFloorViewV3<'loan, 'owner>),
    RootServer(crate::policy_compiler::RootSuccessorNativeServerCutV3<'loan>),
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
            (Self::RootServer(root), Phase::MixedRootPrepared | Phase::MixedRootAnchor) => {
                root.final_crossing(journal, transaction, phase)
            }
            _ => Err(SourceGenesisErrorV1::Conflict),
        }
    }
}

#[cfg(target_os = "linux")]
impl ProjectGenesisNativeCutV3<'_> {
    pub(super) fn final_crossing(&self, admission_expiry: Option<i64>) -> Result<(), crate::hierarchy::genesis_profile::SourceGenesisErrorV1> {
        match self {
            Self::SourcePrepared(root) => root.native_crossing_clock_v3(),
            Self::SourceAnchored(root) => root.native_crossing_clock_v3(),
            Self::RootServer { original, deadline } => {
                let current = crate::policy_compiler::observe_root_first_source_successor_clock_v2(Some(**original))?;
                if admission_expiry.is_some_and(|expiry| current.wall_seconds() >= expiry) {
                    return Err(crate::hierarchy::genesis_profile::SourceGenesisErrorV1::AdmissionClosed);
                }
                if std::time::Instant::now() >= *deadline {
                    return Err(crate::hierarchy::genesis_profile::SourceGenesisErrorV1::Stale);
                }
                Ok(())
            }
        }
    }
}

pub(crate) fn current_project_rows_v3(
    state: &State,
    selected: Option<ProjectId>,
) -> Result<SourceFirstSuccessorRowsV2, JournalError> {
    current_rows_with_recipe(state, SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { selected })
}

pub(crate) fn current_project_genesis_rows_v3(
    state: &State,
    selected: ProjectId,
) -> Result<SourceFirstSuccessorRowsV2, JournalError> {
    if selected.as_bytes() == &[0; 16] {
        return Err(JournalError::ProtectedBoundary);
    }
    current_rows_with_genesis_selection(
        state,
        SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { selected: None },
        Some(selected),
    )
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
    if selected.as_bytes() == &[0; 16] {
        return Err(JournalError::ProtectedBoundary);
    }
    current_family_with_genesis_selection(
        state,
        SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { selected: None },
        Some(selected),
    )
}

// Cold replay selects only comparison DATA from the actual canonical pending
// member. It cannot provide a live selected writer or renew its admission.
fn replay_rows(state: &State) -> Result<SourceFirstSuccessorRowsV2, JournalError> {
    replay_family(state).map(SourceProjectFamilyDataV3::into_successor)
}

// Both owned families stay local to the same immutable comparison window.
fn replay_family(state: &State) -> Result<SourceProjectFamilyDataV3, JournalError> {
    if !state.keys().any(|(_, key)| key.starts_with(RECEIPT_PREFIX)) {
        // An ordinary genesis-only replay retains its original incomplete
        // genesis handling. Explicit mixed Before observation below still
        // checks every completed member, even without a successor receipt.
        return current_family_with_genesis_selection(
            state, SourceSuccessorFamilyRecipeV3::SingleProjectV2, None,
        );
    }
    let selected = state.get(&(RecordNamespace::DesiredState, PENDING_KEY.to_vec()))
        .map(|bytes| SourceFirstSuccessorPendingV2::decode(bytes)
            .map(|pending| pending.project()).map_err(|_| JournalError::ProtectedBoundary))
        .transpose()?;
    let genesis = super::source_tree_genesis::current_rows(state)?;
    if let Some(pending) = genesis.pending.as_ref() {
        if selected.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        let project = pending.project;
        if project.as_bytes() == &[0; 16] {
            return Err(JournalError::ProtectedBoundary);
        }
        return current_family_with_genesis_data(
            state,
            SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { selected: None },
            Some(project),
            Some(genesis),
        );
    }
    current_family_with_genesis_data(
        state,
        SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { selected },
        None,
        Some(genesis),
    )
}

fn current_rows_with_recipe(
    state: &State,
    recipe: SourceSuccessorFamilyRecipeV3,
) -> Result<SourceFirstSuccessorRowsV2, JournalError> {
    current_rows_with_genesis_selection(state, recipe, None)
}

fn current_rows_with_genesis_selection(
    state: &State,
    recipe: SourceSuccessorFamilyRecipeV3,
    genesis_selection: Option<ProjectId>,
) -> Result<SourceFirstSuccessorRowsV2, JournalError> {
    current_family_with_genesis_selection(state, recipe, genesis_selection)
        .map(SourceProjectFamilyDataV3::into_successor)
}

fn current_family_with_genesis_selection(
    state: &State,
    recipe: SourceSuccessorFamilyRecipeV3,
    genesis_selection: Option<ProjectId>,
) -> Result<SourceProjectFamilyDataV3, JournalError> {
    current_family_with_genesis_data(state, recipe, genesis_selection, None)
}

// Replay moves the whole genesis DATA parsed from this same immutable State.
// Its maps remain resident during the successor scan; ordinary callers still
// decode at the original point below, after that scan and the singleton check.
fn current_family_with_genesis_data(
    state: &State,
    recipe: SourceSuccessorFamilyRecipeV3,
    genesis_selection: Option<ProjectId>,
    decoded_genesis: Option<super::source_tree_genesis::SourceGenesisRowsV1>,
) -> Result<SourceProjectFamilyDataV3, JournalError> {
    let mut rows = SourceFirstSuccessorRowsV2 {
        receipts: BTreeMap::new(),
        acks: BTreeMap::new(),
        pending: None,
    };
    for ((namespace, key), value) in state {
        if !key.starts_with(PREFIX) {
            continue;
        }
        if *namespace != RecordNamespace::DesiredState {
            return Err(JournalError::ProtectedBoundary);
        }
        if key == PENDING_KEY {
            rows.pending = Some(SourceFirstSuccessorPendingV2::decode(value)
                .map_err(|_| JournalError::ProtectedBoundary)?);
        } else if let Some(project) = project_key(key, RECEIPT_PREFIX)? {
            let receipt = SourceFirstSuccessorReceiptV2::decode(value)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            if project != receipt.project() {
                return Err(JournalError::ProtectedBoundary);
            }
            rows.receipts.insert(project, receipt);
        } else if let Some(project) = project_key(key, ACK_PREFIX)? {
            let ack = SourceFirstSuccessorAckV2::decode(value)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            if project != ack.project() {
                return Err(JournalError::ProtectedBoundary);
            }
            rows.acks.insert(project, ack);
        } else {
            return Err(JournalError::ProtectedBoundary);
        }
    }
    // Issuance is globally singleton. Another project cannot hide a second
    // successor behind its otherwise valid, independent genesis provenance.
    if recipe == SourceSuccessorFamilyRecipeV3::SingleProjectV2 && rows.receipts.len() > 1 {
        return Err(JournalError::ProtectedBoundary);
    }
    let genesis = match decoded_genesis {
        Some(genesis) => genesis,
        None => super::source_tree_genesis::current_rows(state)?,
    };
    for (project, receipt) in &rows.receipts {
        let predecessor = genesis.receipts.get(project)
            .ok_or(JournalError::ProtectedBoundary)?;
        let original_ack = genesis.acks.get(project)
            .ok_or(JournalError::ProtectedBoundary)?;
        if predecessor.instance() != receipt.instance()
            || predecessor.tree_head() != receipt.old_tree_head()
            || predecessor.lineage_head() != receipt.old_lineage_head()
            || original_ack.root_floor != receipt.predecessor_floor()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        if recipe == SourceSuccessorFamilyRecipeV3::SingleProjectV2 {
            crate::hierarchy::validate_source_first_successor_members_v2(state, receipt, None)?;
        }
        match rows.acks.get(project) {
            Some(ack) => {
                let floor = RootFirstSourceSuccessorFloorV2::new(RootFirstSourceSuccessorFloorFieldsV2 {
                    predecessor_floor: receipt.predecessor_floor(),
                    approval: receipt.approval(),
                    receipt: receipt.clone(),
                    roles: receipt.roles(),
                }).map_err(|_| JournalError::ProtectedBoundary)?;
                let anchored = ControllerFirstSourceSuccessorAnchoredV2::new(ControllerFirstSourceSuccessorAnchoredFieldsV2 {
                    approval: receipt.approval(),
                    receipt: receipt.digest(),
                    floor: floor.digest(),
                }).map_err(|_| JournalError::ProtectedBoundary)?;
                if ack.instance() != predecessor.instance()
                    || ack.receipt() != receipt.digest()
                    || ack.root_floor() != floor.digest()
                    || ack.controller_anchored() != anchored.digest()
                    || match recipe {
                        SourceSuccessorFamilyRecipeV3::SingleProjectV2 => rows.pending.is_some(),
                        SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { .. } => rows.pending
                            .as_ref().is_some_and(|pending| pending.project() == *project),
                    }
                {
                    return Err(JournalError::ProtectedBoundary);
                }
            }
            None => {
                if let SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { selected } = recipe
                    && selected != Some(*project)
                {
                    return Err(JournalError::ProtectedBoundary);
                }
                let pending = rows.pending.as_ref()
                    .ok_or(JournalError::ProtectedBoundary)?;
                if !pending_matches_receipt(pending, receipt) {
                    return Err(JournalError::ProtectedBoundary);
                }
                first_source_successor_capacity_delete_v2(
                    state,
                    &source_capacity_request(receipt)?,
                    transaction_id(receipt.approval(), FirstSourceSuccessorNativePhaseV2::SourceAppend),
                )?;
            }
        }
    }
    if rows.acks.keys().any(|project| !rows.receipts.contains_key(project))
        || (rows.pending.is_some() && rows.receipts.is_empty())
    {
        return Err(JournalError::ProtectedBoundary);
    }
    require_exact_capacity_family(
        state,
        GlobalCapacityReservationPurposeV1::SourceFirstSourceSuccessorAck,
        usize::from(rows.pending.is_some()),
    )?;
    if let SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { selected } = recipe {
        if rows.pending.as_ref().is_some_and(|pending| {
            selected != Some(pending.project()) || !rows.receipts.contains_key(&pending.project())
        }) {
            return Err(JournalError::ProtectedBoundary);
        }
        match genesis_selection {
            Some(project) => {
                crate::hierarchy::validate_source_project_genesis_members_from_genesis_data_v3(
                    state, &genesis, &rows.receipts, project,
                )?
            }
            None => {
                crate::hierarchy::validate_source_project_continuation_members_from_genesis_data_v3(
                    state, &genesis, &rows.receipts,
                )?
            }
        }
    }
    Ok(SourceProjectFamilyDataV3 { genesis, successor: rows })
}

/// Derives exact ACK sizing from the receipt and the sole canonical frame codec.
pub(crate) fn source_capacity_request(
    receipt: &SourceFirstSuccessorReceiptV2,
) -> Result<GlobalCapacityReservationRequestV1, JournalError> {
    let suffix = JournalTransaction::new([1; 16], vec![
        JournalRecord::delete(RecordNamespace::DesiredState, PENDING_KEY.to_vec()),
        JournalRecord::put(
            RecordNamespace::DesiredState, ack_key(receipt.project()), vec![1; 192],
        ),
        sizing_capacity_delete(),
    ])?;
    capacity_request(
        GlobalCapacityReservationPurposeV1::SourceFirstSourceSuccessorAck,
        receipt.instance(), receipt.project(), receipt.request(),
        receipt.digest(), receipt.approval(), receipt.root_intent(), receipt.old_lineage_head(),
        &[suffix], 1,
    )
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
    let label: &[u8] = match purpose {
        GlobalCapacityReservationPurposeV1::RootFirstSourceSuccessorAnchor => b"root-capacity-owner",
        GlobalCapacityReservationPurposeV1::SourceFirstSourceSuccessorAck => b"source-capacity-owner",
        GlobalCapacityReservationPurposeV1::ControllerFirstSourceSuccessorComplete => b"controller-capacity-owner",
        _ => return Err(JournalError::ProtectedBoundary),
    };
    let mut owner = Sha256::new();
    owner.update(b"aos.sandbox.source-first-successor.");
    owner.update(label);
    owner.update(b".v2\0");
    owner.update(instance);
    owner.update(project.as_bytes());
    owner.update(request);
    let (records, bytes) = suffix.iter().try_fold((0_u32, 0_u64), |(records, bytes), transaction| {
        Ok::<_, JournalError>((
            records.checked_add(u32::try_from(transaction.records().len())
                .map_err(|_| JournalError::InvalidTransaction)?).ok_or(JournalError::InvalidTransaction)?,
            bytes.checked_add(super::encoded_transaction_append_bytes(transaction)?)
                .ok_or(JournalError::JournalTooLarge)?,
        ))
    })?;
    Ok(GlobalCapacityReservationRequestV1 {
        purpose,
        owner_namespace: RecordNamespace::DesiredState,
        owner_id: owner.finalize().into(),
        owner_digest: *owner_digest.as_bytes(),
        operation_id: request,
        artifact_digest: *approval.as_bytes(),
        checkpoint_digest: *checkpoint.as_bytes(),
        chain_head_digest: *predecessor.as_bytes(),
        future_transactions,
        terminal_records: records,
        terminal_bytes: bytes,
        poison_records: records,
        poison_bytes: bytes,
    })
}

/// Returns fixed-width deletion sizing DATA with the actual capacity key codec.
pub(crate) fn sizing_capacity_delete() -> JournalRecord {
    JournalRecord::delete(
        RecordNamespace::GlobalCapacityReservation,
        reservation_key([1; 32]),
    )
}

fn pending_matches_receipt(
    pending: &SourceFirstSuccessorPendingV2,
    receipt: &SourceFirstSuccessorReceiptV2,
) -> bool {
    pending.instance() == receipt.instance()
        && pending.project() == receipt.project()
        && pending.request() == receipt.request()
        && pending.approval() == receipt.approval()
        && pending.root_intent() == receipt.root_intent()
        && pending.receipt() == receipt.digest()
        && pending.source_names() == receipt.source_names()
}

pub(super) fn require_transition(
    state: &State,
    transaction: &JournalTransaction,
    phase: Option<FirstSourceSuccessorNativePhaseV2>,
) -> Result<Option<[u8; 32]>, JournalError> {
    let root_settling = validate_root_transition(state, transaction, phase)?;
    let source_settling = require_source_transition(state, transaction, phase)?;
    if root_settling.is_some() && source_settling.is_some() {
        return Err(JournalError::ProtectedBoundary);
    }
    let controller_settling = super::controller_source_successor_issuance::consumer_settling(
        state, transaction, phase,
    )?;
    Ok(root_settling.or(source_settling).or(controller_settling))
}

fn require_replayed_transition(
    state: &State, transaction: &JournalTransaction,
    phase: Option<FirstSourceSuccessorNativePhaseV2>,
) -> Result<Option<[u8; 32]>, JournalError> {
    #[cfg(target_os = "linux")]
    let root_settling = crate::policy_compiler::RootSourceGenesisAuthorityV1::validate_project_successor_transition_v3(
        state, transaction, phase,
    )?;
    #[cfg(not(target_os = "linux"))]
    let root_settling = validate_root_transition(state, transaction, phase)?;
    let genesis_selection = if phase.is_none()
        && state.keys().any(|(_, key)| key.starts_with(RECEIPT_PREFIX))
    {
        match super::source_tree_genesis::recognize_replayed_transition(transaction)? {
            super::source_tree_genesis::SourceGenesisTransitionV1::Append => {
                let receipt = crate::hierarchy::SourceTreeGenesisReceiptV1::decode(
                    required_value(transaction.records().get(2).ok_or(JournalError::ProtectedBoundary)?)?,
                ).map_err(|_| JournalError::ProtectedBoundary)?;
                Some(receipt.project())
            }
            _ => super::source_tree_genesis::current_rows(state)?.pending.map(|pending| pending.project),
        }
    } else {
        None
    };
    let source_settling = if let Some(project) = genesis_selection {
        require_project_genesis_transition_v3(state, transaction, project)?;
        None
    } else if matches!(phase, Some(FirstSourceSuccessorNativePhaseV2::MixedSourceAppend
        | FirstSourceSuccessorNativePhaseV2::MixedSourceAck))
    {
        require_source_transition(state, transaction, phase)?
    } else if !state.keys().any(|(_, key)| key.starts_with(RECEIPT_PREFIX)) {
        require_source_transition(state, transaction, phase.map(FirstSourceSuccessorNativePhaseV2::canonical))?
    } else {
        let selected = state.get(&(RecordNamespace::DesiredState, PENDING_KEY.to_vec()))
            .map(|bytes| SourceFirstSuccessorPendingV2::decode(bytes)
                .map(|pending| pending.project()).map_err(|_| JournalError::ProtectedBoundary))
            .transpose()?;
        require_source_transition_with_recipe(state, transaction, phase,
            SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { selected })?
    };
    if root_settling.is_some() && source_settling.is_some() { return Err(JournalError::ProtectedBoundary); }
    let controller_settling = super::controller_source_successor_issuance::consumer_settling(
        state, transaction, phase.map(FirstSourceSuccessorNativePhaseV2::canonical),
    )?;
    Ok(root_settling.or(source_settling).or(controller_settling))
}

// The canonical genesis reducer still owns the exact four/two-record shape.
// This comparison adds all settled foreign successor members and preserves
// their bytes before and after the selected initial-project transition.
pub(super) fn require_project_genesis_transition_v3(
    state: &State,
    transaction: &JournalTransaction,
    project: ProjectId,
) -> Result<(), JournalError> {
    let before = current_project_genesis_rows_v3(state, project)?;
    if before.pending.is_some() {
        return Err(JournalError::ProtectedBoundary);
    }
    let transition = super::source_tree_genesis::recognize_replayed_transition(transaction)?;
    match transition {
        super::source_tree_genesis::SourceGenesisTransitionV1::Append => {
            let receipt = crate::hierarchy::SourceTreeGenesisReceiptV1::decode(
                required_value(transaction.records().get(2).ok_or(JournalError::ProtectedBoundary)?)?,
            ).map_err(|_| JournalError::ProtectedBoundary)?;
            if receipt.project() != project {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        super::source_tree_genesis::SourceGenesisTransitionV1::Anchor => {
            if super::source_tree_genesis::current_rows(state)?.pending
                .is_none_or(|pending| pending.project != project)
            {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        _ => return Err(JournalError::ProtectedBoundary),
    }
    super::source_tree_genesis::require_no_mutation(state, transaction, transition)?;
    let after = super::root_original_inventory::materialize(state, transaction);
    let next = current_project_genesis_rows_v3(&after, project)?;
    if next != before {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

pub(super) fn require_project_genesis_family_v3(
    state: &State,
    transaction: &JournalTransaction,
    phase: ProjectGenesisNativePhaseV3,
) -> Result<(), JournalError> {
    let project = phase.project();
    match phase {
        ProjectGenesisNativePhaseV3::SourceAppend(_) | ProjectGenesisNativePhaseV3::SourceAck(_) => {
            require_project_genesis_transition_v3(state, transaction, project)?;
        }
        ProjectGenesisNativePhaseV3::RootPrepared(_) | ProjectGenesisNativePhaseV3::RootAnchor(_) => {
            #[cfg(target_os = "linux")]
            crate::policy_compiler::RootSourceGenesisAuthorityV1::validate_project_successor_transition_v3(
                state, transaction, None,
            )?;
            #[cfg(not(target_os = "linux"))]
            return Err(JournalError::ProtectedBoundary);
            let expected_prefix = match phase {
                ProjectGenesisNativePhaseV3::RootPrepared(_) => b"\0aos-source-genesis-intent-v1\0".as_slice(),
                _ => b"\0aos-source-hierarchy-floor-v1\0".as_slice(),
            };
            let first = transaction.records().first().ok_or(JournalError::ProtectedBoundary)?;
            if first.namespace() != RecordNamespace::DesiredState
                || first.key() != [expected_prefix, project.as_bytes()].concat()
                || first.value().is_none()
            {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        ProjectGenesisNativePhaseV3::ControllerFloorAck(_) | ProjectGenesisNativePhaseV3::ControllerComplete(_) => {
            use super::controller_source_genesis::ControllerSourceGenesisTransition as Transition;
            let transition = match phase {
                ProjectGenesisNativePhaseV3::ControllerFloorAck(_) => Transition::FloorAck,
                _ => Transition::Complete,
            };
            super::controller_source_genesis::require_no_mutation(state, transaction, transition)?;
            let rows = super::controller_source_genesis::all_rows(state)?
                .remove(&project).ok_or(JournalError::ProtectedBoundary)?;
            let expected = match phase {
                ProjectGenesisNativePhaseV3::ControllerFloorAck(_) => {
                    let record = transaction.records().first().ok_or(JournalError::ProtectedBoundary)?;
                    let value: &[u8; 144] = required_value(record)?.try_into().map_err(|_| JournalError::ProtectedBoundary)?;
                    if digest_at(value, 16)? != rows.acceptance.digest() { return Err(JournalError::ProtectedBoundary); }
                    super::controller_source_genesis::ack_transaction(project, value)?
                }
                _ => {
                    let record = transaction.records().first().ok_or(JournalError::ProtectedBoundary)?;
                    let value: &[u8; 144] = required_value(record)?.try_into().map_err(|_| JournalError::ProtectedBoundary)?;
                    super::controller_source_genesis::complete_transaction(project, value)?
                }
            };
            if transaction != &expected { return Err(JournalError::ProtectedBoundary); }
        }
    }
    Ok(())
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
            #[cfg(target_os = "linux")]
            { crate::policy_compiler::require_root_source_genesis_capacity_owner_v1(journal) }
            #[cfg(not(target_os = "linux"))]
            { Err(JournalError::ProtectedBoundary) }
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
    let recipe = match phase {
        Some(FirstSourceSuccessorNativePhaseV2::MixedSourceAppend) => {
            let record = transaction.records().get(2).ok_or(JournalError::ProtectedBoundary)?;
            let receipt = SourceFirstSuccessorReceiptV2::decode(required_value(record)?)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { selected: Some(receipt.project()) }
        }
        Some(FirstSourceSuccessorNativePhaseV2::MixedSourceAck) => {
            let pending = SourceFirstSuccessorPendingV2::decode(
                state.get(&(RecordNamespace::DesiredState, PENDING_KEY.to_vec()))
                    .ok_or(JournalError::ProtectedBoundary)?,
            ).map_err(|_| JournalError::ProtectedBoundary)?;
            SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { selected: Some(pending.project()) }
        }
        Some(FirstSourceSuccessorNativePhaseV2::MixedControllerBegin
            | FirstSourceSuccessorNativePhaseV2::MixedControllerAnchored
            | FirstSourceSuccessorNativePhaseV2::MixedControllerComplete) => {
            SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { selected: None }
        }
        _ => SourceSuccessorFamilyRecipeV3::SingleProjectV2,
    };
    require_source_transition_with_recipe(state, transaction, phase, recipe)
}

fn require_source_transition_with_recipe(
    state: &State,
    transaction: &JournalTransaction,
    phase: Option<FirstSourceSuccessorNativePhaseV2>,
    recipe: SourceSuccessorFamilyRecipeV3,
) -> Result<Option<[u8; 32]>, JournalError> {
    let rows = current_rows_with_recipe(state, recipe)?;
    match phase.map(FirstSourceSuccessorNativePhaseV2::canonical) {
        Some(FirstSourceSuccessorNativePhaseV2::SourceAppend) => {
            let [_, _, receipt_record, pending_record, capacity] = transaction.records() else {
                return Err(JournalError::ProtectedBoundary);
            };
            if rows.pending.is_some()
                || (recipe == SourceSuccessorFamilyRecipeV3::SingleProjectV2 && !rows.receipts.is_empty())
            {
                return Err(JournalError::ProtectedBoundary);
            }
            let receipt = SourceFirstSuccessorReceiptV2::decode(required_value(receipt_record)?)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            let pending = SourceFirstSuccessorPendingV2::decode(required_value(pending_record)?)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            let project = receipt.project();
            if matches!(recipe, SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { .. })
                && rows.receipts.contains_key(&project)
            {
                return Err(JournalError::ProtectedBoundary);
            }
            let expected_id = transaction_id(receipt.approval(), FirstSourceSuccessorNativePhaseV2::SourceAppend);
            let expected_capacity = first_source_successor_capacity_record_v2(
                &source_capacity_request(&receipt)?, *transaction.id(),
            )?;
            if transaction.id() != &expected_id
                || receipt_record.namespace() != RecordNamespace::DesiredState
                || receipt_record.key() != receipt_key(project)
                || pending_record.namespace() != RecordNamespace::DesiredState
                || pending_record.key() != PENDING_KEY
                || !pending_matches_receipt(&pending, &receipt)
                || capacity != &expected_capacity
                || [receipt_record, pending_record, capacity].iter().any(|record| {
                    state.contains_key(&(record.namespace(), record.key().to_vec()))
                })
            {
                return Err(JournalError::ProtectedBoundary);
            }
            let pair = &transaction.records()[..2];
            match recipe {
                SourceSuccessorFamilyRecipeV3::SingleProjectV2 => {
                    crate::hierarchy::validate_source_first_successor_members_v2(state, &receipt, Some(pair))?;
                }
                SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { selected } => {
                    if selected != Some(project) { return Err(JournalError::ProtectedBoundary); }
                    crate::hierarchy::validate_source_project_continuation_members_v3(
                        state, &rows.receipts, Some((&receipt, pair)),
                    )?;
                }
            }
            let after = super::root_original_inventory::materialize(state, transaction);
            current_rows_with_recipe(&after, recipe)?;
            Ok(None)
        }
        Some(FirstSourceSuccessorNativePhaseV2::SourceAck) => {
            let [pending_delete, ack_record, capacity_delete] = transaction.records() else {
                return Err(JournalError::ProtectedBoundary);
            };
            let pending = rows.pending.as_ref()
                .ok_or(JournalError::ProtectedBoundary)?;
            let project = pending.project();
            let receipt = rows.receipts.get(&project)
                .ok_or(JournalError::ProtectedBoundary)?;
            let ack = SourceFirstSuccessorAckV2::decode(required_value(ack_record)?)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            let request = source_capacity_request(receipt)?;
            let admission = transaction_id(receipt.approval(), FirstSourceSuccessorNativePhaseV2::SourceAppend);
            let expected_id = transaction_id(receipt.approval(), FirstSourceSuccessorNativePhaseV2::SourceAck);
            let expected_deletion = first_source_successor_capacity_delete_v2(state, &request, admission)?;
            if transaction.id() != &expected_id
                || pending_delete != &JournalRecord::delete(RecordNamespace::DesiredState, PENDING_KEY.to_vec())
                || ack_record.namespace() != RecordNamespace::DesiredState
                || ack_record.key() != ack_key(project)
                || ack.instance() != receipt.instance()
                || ack.project() != receipt.project()
                || ack.receipt() != receipt.digest()
                || state.contains_key(&(ack_record.namespace(), ack_record.key().to_vec()))
                || capacity_delete != &expected_deletion
            {
                return Err(JournalError::ProtectedBoundary);
            }
            current_rows_with_recipe(&super::root_original_inventory::materialize(state, transaction), recipe)?;
            Ok(Some(first_source_successor_capacity_identity_v2(&request, admission)?))
        }
        _ => {
            if rows.pending.is_some()
                || transaction.records().iter().any(|record| record.key().starts_with(PREFIX))
                || touches_capacity_purpose(state, transaction, GlobalCapacityReservationPurposeV1::SourceFirstSourceSuccessorAck)?
            {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(None)
        }
    }
}

pub(super) fn require_genesis_predecessor(
    state: &State,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    // Source genesis forwards the canonical durable phase only. Derive this
    // DATA comparison target from the actual receipt/ACK key, not the first
    // retained receipt or a fabricated Journal. Singleton forwarding retains
    // strict validation order while keeping both DATA families through selection.
    let target = transaction.records().iter().find_map(|record| {
        record.key().strip_prefix(RECEIPT_PREFIX)
            .or_else(|| record.key().strip_prefix(ACK_PREFIX))
    });
    if let Some(target) = target
        && state.keys().any(|(_, key)| key.strip_prefix(RECEIPT_PREFIX)
            .is_some_and(|project| project != target))
    {
        return require_project_genesis_predecessor_v3(state, transaction);
    }
    let record = transaction.records().iter()
        .find(|record| record.key().starts_with(RECEIPT_PREFIX));
    let SourceProjectFamilyDataV3 { genesis, successor: rows } =
        current_family_with_genesis_selection(
            state, SourceSuccessorFamilyRecipeV3::SingleProjectV2, None,
        )?;
    let receipt = match record {
        Some(record) => SourceFirstSuccessorReceiptV2::decode(required_value(record)?)
            .map_err(|_| JournalError::ProtectedBoundary)?,
        None => rows.receipts.values().next().cloned().ok_or(JournalError::ProtectedBoundary)?,
    };
    let project = receipt.project();
    let original = genesis.receipts.get(&project)
        .ok_or(JournalError::ProtectedBoundary)?;
    if genesis.pending.is_some()
        || !genesis.acks.contains_key(&project)
        || original.tree_head() != receipt.old_tree_head()
        || original.lineage_head() != receipt.old_lineage_head()
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn require_project_genesis_predecessor_v3(
    state: &State,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    let SourceProjectFamilyDataV3 { genesis, successor: rows } = replay_family(state)?;
    let receipt = match transaction.records().iter()
        .find(|record| record.key().starts_with(RECEIPT_PREFIX))
    {
        Some(record) => SourceFirstSuccessorReceiptV2::decode(required_value(record)?)
            .map_err(|_| JournalError::ProtectedBoundary)?,
        None => {
            let pending = rows.pending.as_ref().ok_or(JournalError::ProtectedBoundary)?;
            let receipt = rows.receipts.get(&pending.project())
                .ok_or(JournalError::ProtectedBoundary)?;
            if !transaction.records().iter().any(|record| {
                record.namespace() == RecordNamespace::DesiredState
                    && record.key() == ack_key(pending.project())
            }) {
                return Err(JournalError::ProtectedBoundary);
            }
            receipt.clone()
        }
    };
    let original = genesis.receipts.get(&receipt.project())
        .ok_or(JournalError::ProtectedBoundary)?;
    if genesis.pending.is_some()
        || !genesis.acks.contains_key(&receipt.project())
        || original.tree_head() != receipt.old_tree_head()
        || original.lineage_head() != receipt.old_lineage_head()
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

pub(crate) fn require_capacity_owner(
    journal: &Journal,
    purpose: GlobalCapacityReservationPurposeV1,
) -> Result<(), JournalError> {
    match purpose {
        GlobalCapacityReservationPurposeV1::RootFirstSourceSuccessorAnchor => {
            #[cfg(target_os = "linux")]
            {
                crate::policy_compiler::require_root_first_source_successor_capacity_owner_v2(journal)
            }
            #[cfg(not(target_os = "linux"))]
            {
                journal.ensure_healthy()?;
                Err(JournalError::ProtectedBoundary)
            }
        }
        GlobalCapacityReservationPurposeV1::SourceFirstSourceSuccessorAck => {
            let location = journal
                .protected
                .as_ref()
                .ok_or(JournalError::ProtectedBoundary)?;
            if location.expected_uid() == 0 {
                return Err(JournalError::ProtectedBoundary);
            }
            journal.require_protected_named_location(
                Path::new(crate::lifecycle::protected_journal_join::PROTECTED_SOURCE_DOMAIN_ROOT),
                crate::lifecycle::protected_journal_join::PROTECTED_SOURCE_DOMAIN_JOURNAL,
                location.expected_uid(),
                crate::lifecycle::protected_journal_join::source_domain_journal_limits(),
            )
        }
        GlobalCapacityReservationPurposeV1::ControllerFirstSourceSuccessorComplete => {
            let location = journal
                .protected
                .as_ref()
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
            Some(SourceFirstSuccessorReceiptV2::decode(required_value(record)?)
                .map_err(|_| JournalError::ProtectedBoundary)?)
        }
        FirstSourceSuccessorNativePhaseV2::SourceAck => {
            current_rows(state)?.receipts.into_values().next()
        }
        FirstSourceSuccessorNativePhaseV2::MixedSourceAppend => {
            let record = transaction.records().get(2).ok_or(JournalError::ProtectedBoundary)?;
            Some(SourceFirstSuccessorReceiptV2::decode(required_value(record)?)
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
    accounting_reservations(state)?.values().try_fold(next, |sequence, reservation| {
        let records = u64::try_from(reservation.maximum_records)
            .map_err(|_| JournalError::SequenceExhausted)?;
        let transactions = u64::try_from(reservation.maximum_transactions)
            .map_err(|_| JournalError::SequenceExhausted)?;
        let framing = transactions.checked_mul(2)
            .ok_or(JournalError::SequenceExhausted)?;

        sequence.checked_add(records).and_then(|value| value.checked_add(framing))
            .ok_or(JournalError::SequenceExhausted)
    })?;
    Ok(())
}

pub(super) fn require_no_compaction(state: &State) -> Result<(), JournalError> {
    if replay_rows(state)?.pending.is_some()
        || state.keys().any(|(_, key)| key.starts_with(b"\0aos-root-first-source-successor-v2\0intent\0"))
    {
        return Err(JournalError::ProtectedBoundary);
    }
    validate_root_state(state)
}

pub(super) fn recognize_replayed_phase(
    transaction: &JournalTransaction,
) -> Result<Option<FirstSourceSuccessorNativePhaseV2>, JournalError> {
    let mut selected = None;
    for record in transaction.records() {
        let phase = if record.key().starts_with(PREFIX) {
            if record.key().starts_with(RECEIPT_PREFIX) { Some(FirstSourceSuccessorNativePhaseV2::SourceAppend) }
            else if record.key().starts_with(ACK_PREFIX) { Some(FirstSourceSuccessorNativePhaseV2::SourceAck) }
            else { None }
        } else if record.key().starts_with(b"\0aos-root-first-source-successor-v2\0") {
            if record.key().starts_with(b"\0aos-root-first-source-successor-v2\0intent\0") && record.value().is_some() {
                Some(FirstSourceSuccessorNativePhaseV2::RootPrepared)
            } else if record.key().starts_with(b"\0aos-root-first-source-successor-v2\0floor\0") {
                Some(FirstSourceSuccessorNativePhaseV2::RootAnchor)
            } else { None }
        } else { None };
        if let Some(phase) = phase {
            if selected.replace(phase).is_some_and(|previous| previous != phase) {
                return Err(JournalError::ProtectedBoundary);
            }
        }
    }
    if let Some(transition) = super::controller_source_successor_issuance::recognize_replayed_transition(transaction)? {
        let phase = match transition {
            super::controller_source_successor_issuance::Transition::Begin => Some(FirstSourceSuccessorNativePhaseV2::ControllerBegin),
            super::controller_source_successor_issuance::Transition::Anchored => Some(FirstSourceSuccessorNativePhaseV2::ControllerAnchored),
            super::controller_source_successor_issuance::Transition::Complete => Some(FirstSourceSuccessorNativePhaseV2::ControllerComplete),
            super::controller_source_successor_issuance::Transition::ProjectBegin(_) => Some(FirstSourceSuccessorNativePhaseV2::MixedControllerBegin),
            super::controller_source_successor_issuance::Transition::ProjectAnchored(_) => Some(FirstSourceSuccessorNativePhaseV2::MixedControllerAnchored),
            super::controller_source_successor_issuance::Transition::ProjectComplete(_) => Some(FirstSourceSuccessorNativePhaseV2::MixedControllerComplete),
            _ => None,
        };
        if phase.is_some() && selected.is_some() { return Err(JournalError::ProtectedBoundary); }
        selected = phase.or(selected);
    }
    Ok(selected)
}

pub(super) fn validate_replayed_transaction(
    state: &State,
    transaction: &JournalTransaction,
    limits: super::JournalLimits,
) -> Result<bool, JournalError> {
    let phase = recognize_replayed_phase(transaction)?;
    // A cold phase is complete structural DATA, not a live selected admission.
    let comparison_phase = phase.map(|phase| match phase {
        FirstSourceSuccessorNativePhaseV2::SourceAppend => FirstSourceSuccessorNativePhaseV2::MixedSourceAppend,
        FirstSourceSuccessorNativePhaseV2::SourceAck => FirstSourceSuccessorNativePhaseV2::MixedSourceAck,
        FirstSourceSuccessorNativePhaseV2::RootPrepared => FirstSourceSuccessorNativePhaseV2::MixedRootPrepared,
        FirstSourceSuccessorNativePhaseV2::RootAnchor => FirstSourceSuccessorNativePhaseV2::MixedRootAnchor,
        ordinary => ordinary,
    });
    require_replayed_transition(state, transaction, comparison_phase)?;
    if phase.is_some() {
        for record in transaction.records() {
            if record.namespace() != RecordNamespace::GlobalCapacityReservation
                || record.value().is_none()
            {
                continue;
            }
            let (request, admission, _) = super::decode_capacity_reservation_request_v1(record)?;
            if !request.purpose.is_first_source_successor() || &admission != transaction.id() {
                return Err(JournalError::ProtectedBoundary);
            }
            super::capacity_reservation::validate_request_with_limits(&request, limits)?;
        }
    }
    super::controller_source_successor_issuance::require_no_mutation(
        state, transaction,
        super::controller_source_successor_issuance::recognize_replayed_transition(transaction)?,
    )?;
    let genesis_transition = phase.map(|phase| phase.source_genesis_transition())
        .map_or_else(|| super::source_tree_genesis::recognize_replayed_transition(transaction), Ok)?;
    super::source_tree_genesis::require_no_mutation(state, transaction, genesis_transition)?;
    Ok(phase.is_some() || state.keys().any(|(_, key)| {
        key.starts_with(PREFIX) || key.starts_with(b"\0aos-root-first-source-successor-v2\0")
            || key.starts_with(b"\0aos-controller-source-successor-issuance-v2\0consumer-")
    }))
}

pub(super) fn validate_replayed_state(state: &State, compacted: bool) -> Result<(), JournalError> {
    replay_rows(state)?;
    validate_root_state(state)?;
    super::controller_source_successor_issuance::validate_rows(state)?;
    if compacted {
        require_no_compaction(state)?;
        super::controller_source_successor_issuance::require_no_compaction(state)?;
        super::source_tree_genesis::require_no_compaction(state)?;
    }
    Ok(())
}

fn validate_root_state(state: &State) -> Result<(), JournalError> {
    #[cfg(target_os = "linux")]
    {
        crate::policy_compiler::RootSourceGenesisAuthorityV1::validate_project_successor_replay_v3(state)
    }
    #[cfg(not(target_os = "linux"))]
    {
        if state.keys().any(|(_, key)| key.starts_with(b"\0aos-root-first-source-successor-v2\0")) {
            return Err(JournalError::ProtectedBoundary);
        }
        require_exact_capacity_family(
            state, GlobalCapacityReservationPurposeV1::RootFirstSourceSuccessorAnchor, 0,
        )
    }
}

fn validate_root_transition(
    state: &State,
    transaction: &JournalTransaction,
    phase: Option<FirstSourceSuccessorNativePhaseV2>,
) -> Result<Option<[u8; 32]>, JournalError> {
    #[cfg(target_os = "linux")]
    {
        crate::policy_compiler::validate_root_first_source_successor_transition_v2(
            state, transaction, phase,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        validate_root_state(state)?;
        if matches!(phase, Some(FirstSourceSuccessorNativePhaseV2::RootPrepared
            | FirstSourceSuccessorNativePhaseV2::RootAnchor))
            || transaction.records().iter().any(|record| {
                record.key().starts_with(b"\0aos-root-first-source-successor-v2\0")
            })
            || touches_capacity_purpose(
                state, transaction, GlobalCapacityReservationPurposeV1::RootFirstSourceSuccessorAnchor,
            )?
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(None)
    }
}

pub(crate) fn touches_capacity_purpose(
    state: &State,
    transaction: &JournalTransaction,
    purpose: GlobalCapacityReservationPurposeV1,
) -> Result<bool, JournalError> {
    let mut touches = false;
    for record in transaction.records() {
        if record.namespace() != RecordNamespace::GlobalCapacityReservation {
            continue;
        }
        let value = record.value().or_else(|| {
            state.get(&(record.namespace(), record.key().to_vec())).map(Vec::as_slice)
        })
            .ok_or(JournalError::ProtectedBoundary)?;
        let put = JournalRecord::put(record.namespace(), record.key().to_vec(), value.to_vec());
        touches |= super::capacity_reservation::capacity_record_has_legacy_purpose(&put, purpose)?;
    }
    Ok(touches)
}

pub(crate) fn require_exact_capacity_family(
    state: &State,
    purpose: GlobalCapacityReservationPurposeV1,
    count: usize,
) -> Result<(), JournalError> {
    super::capacity_reservation::validate_all_reservations(state)?;
    let mut actual = 0_usize;
    for ((namespace, key), value) in state {
        if *namespace != RecordNamespace::GlobalCapacityReservation {
            continue;
        }
        let record = JournalRecord::put(*namespace, key.clone(), value.clone());
        if super::capacity_reservation::capacity_record_has_legacy_purpose(&record, purpose)? {
            actual = actual.checked_add(1).ok_or(JournalError::ProtectedBoundary)?;
        }
    }
    if actual != count {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

pub(crate) fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], JournalError> {
    let (value, _) =
        checked_byte_region(bytes, offset, N).map_err(|_| JournalError::ProtectedBoundary)?;
    value
        .try_into()
        .map_err(|_| JournalError::ProtectedBoundary)
}

pub(crate) fn digest_at(bytes: &[u8], offset: usize) -> Result<ObjectDigest, JournalError> {
    Ok(ObjectDigest::from_bytes(array(bytes, offset)?))
}

pub(crate) fn receipt_project(receipt: &SourceFirstSuccessorReceiptV2) -> Result<ProjectId, JournalError> {
    Ok(ProjectId::from_bytes(array(receipt.as_bytes(), 48)?))
}

fn project_key(key: &[u8], prefix: &[u8]) -> Result<Option<ProjectId>, JournalError> {
    if !key.starts_with(prefix) {
        return Ok(None);
    }
    if key.len() != prefix.len() + 16 {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(Some(ProjectId::from_bytes(array(key, prefix.len())?)))
}

fn required_value(record: &JournalRecord) -> Result<&[u8], JournalError> {
    record.value().ok_or(JournalError::ProtectedBoundary)
}

impl Journal {
    /// Checks only the fixed Root suffix shape before a Source receipt exists.
    ///
    /// The real Prepared prefix passes the normal semantic reducer. The zero
    /// stored floor archive below is exclusively sizing and growth DATA;
    /// it is never passed to the floor decoder or a native mutation reducer.
    /// Actual Anchor requires its own exact semantic preflight after Source
    /// Prepared, under the retained original Root owner.
    ///
    /// # Errors
    /// Rejects a foreign owner, an invalid real Prepared prefix, an altered
    /// intent, duplicate native IDs, or any transaction, growth, capacity,
    /// journal-length or sequence bound in the fixed remaining suffix.
    pub(crate) fn preflight_root_first_successor_shape_v2(
        &self,
        prepared: &JournalTransaction,
        intent: &RootFirstSourceSuccessorIntentV2,
    ) -> Result<(), JournalError> {
        self.preflight_root_successor_shape_with_phase(
            prepared, intent, FirstSourceSuccessorNativePhaseV2::RootPrepared,
        )
    }

    /// Compares a selected mixed Root prefix and its exact conservative suffix.
    ///
    /// # Errors
    /// Rejects a foreign actual owner, unjoined archives/active intent, any
    /// native bound or changed exact sizing identity. Success is preview DATA.
    pub(crate) fn preflight_root_project_successor_shape_v3(
        &self,
        prepared: &JournalTransaction,
        intent: &RootFirstSourceSuccessorIntentV2,
    ) -> Result<(), JournalError> {
        self.preflight_root_successor_shape_with_phase(
            prepared, intent, FirstSourceSuccessorNativePhaseV2::MixedRootPrepared,
        )
    }

    fn preflight_root_successor_shape_with_phase(
        &self,
        prepared: &JournalTransaction,
        intent: &RootFirstSourceSuccessorIntentV2,
        phase: FirstSourceSuccessorNativePhaseV2,
    ) -> Result<(), JournalError> {
        require_capacity_owner(self, GlobalCapacityReservationPurposeV1::RootFirstSourceSuccessorAnchor)?;
        self.preflight_first_source_successor_v2(
            std::slice::from_ref(prepared),
            &[phase],
        )?;
        let [intent_record, reservation] = prepared.records() else {
            return Err(JournalError::ProtectedBoundary);
        };
        if intent_record.value() != Some(intent.as_bytes()) {
            return Err(JournalError::AuthorityPreflightMismatch);
        }
        let (_, admission, capacity_id) = super::decode_capacity_reservation_request_v1(reservation)?;
        if &admission != prepared.id() {
            return Err(JournalError::AuthorityPreflightMismatch);
        }
        let suffix = JournalTransaction::new(
            transaction_id(intent.approval(), FirstSourceSuccessorNativePhaseV2::RootAnchor),
            vec![
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    [b"\0aos-root-first-source-successor-v2\0floor\0".as_slice(), intent.project().as_bytes()].concat(),
                    vec![0; 688 + intent.as_bytes().len()],
                ),
                JournalRecord::delete(RecordNamespace::DesiredState, intent_record.key().to_vec()),
                JournalRecord::delete(RecordNamespace::GlobalCapacityReservation, reservation.key().to_vec()),
            ],
        )?;
        super::validate_transaction(&suffix, self.native.limits())?;
        if suffix.id() == prepared.id() || self.native.transaction_ids().contains(suffix.id()) {
            return Err(JournalError::DuplicateTransaction);
        }

        let after_prepared = super::root_original_inventory::materialize(self.native.state(), prepared);
        let prefix_bytes = super::validate_materialized_change(
            self.native.state(), self.native.materialized_bytes(), prepared.records(), self.native.limits(),
        )?;
        let terminal_bytes = super::validate_materialized_change(
            &after_prepared, prefix_bytes, suffix.records(), self.native.limits(),
        )?;
        let prefix_append_bytes = super::encoded_transaction_append_bytes(prepared)?;
        let suffix_append_bytes = super::encoded_transaction_append_bytes(&suffix)?;
        let journal_bytes = self.native.file().metadata()?.len()
            .checked_add(prefix_append_bytes)
            .and_then(|bytes| bytes.checked_add(suffix_append_bytes))
            .ok_or(JournalError::JournalTooLarge)?;
        if journal_bytes > self.native.limits().maximum_journal_bytes {
            return Err(JournalError::JournalTooLarge);
        }
        let transactions = self.native.committed_transactions().checked_add(2)
            .ok_or(JournalError::LimitExceeded("committed transaction count"))?;
        if transactions > self.native.limits().maximum_transactions {
            return Err(JournalError::LimitExceeded("committed transaction count"));
        }
        super::validate_reserved_capacity(
            &after_prepared, terminal_bytes, suffix.records(), Some(capacity_id),
            journal_bytes, transactions, self.native.limits(), None,
        )?;

        let prefix_frames = u64::try_from(prepared.records().len())
            .map_err(|_| JournalError::SequenceExhausted)?
            .checked_add(2).ok_or(JournalError::SequenceExhausted)?;
        let terminal_frames = u64::try_from(suffix.records().len())
            .map_err(|_| JournalError::SequenceExhausted)?
            .checked_add(2).ok_or(JournalError::SequenceExhausted)?;
        let next = self.native.next_sequence().checked_add(prefix_frames)
            .and_then(|sequence| sequence.checked_add(terminal_frames))
            .ok_or(JournalError::SequenceExhausted)?;
        let after_terminal = super::root_original_inventory::materialize(&after_prepared, &suffix);
        require_sequence_headroom(&after_terminal, next)?;
        require_capacity_owner(self, GlobalCapacityReservationPurposeV1::RootFirstSourceSuccessorAnchor)
    }

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
