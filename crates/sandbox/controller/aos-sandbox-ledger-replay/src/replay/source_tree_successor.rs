//! Defines saved first-successor phase, row, key and capacity DATA.
//!
//! These selectors and recipes preserve canonical bytes and comparisons. They
//! own no native cut, writer, currentness loan, capacity grant or effect gate.
//! Actual Native effects continue to require their original private owners.

use std::collections::BTreeMap;
use aos_sandbox_model::{ObjectDigest, ProjectId, RecordNamespace};
use aos_sandbox_model::bounded_codec::checked_byte_region;
use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as JournalError;
use aos_sandbox_protocol::domain_ledger::transaction::{JournalRecord, JournalTransaction};
use aos_sandbox_protocol::domain_ledger::capacity::{
    GlobalCapacityReservationPurposeV1, GlobalCapacityReservationRequestV1,
    reservation_key, reservation_id, encode_reservation,
};
use aos_sandbox_protocol::domain_ledger::capacity_family::family::canonical_reservations;
use sha2::{Digest as _, Sha256};
use super::phase_records::{SourceFirstSuccessorReceiptV2, SourceFirstSuccessorAckV2, SourceFirstSuccessorPendingV2};

/// Borrows or owns the complete saved namespace/key/value map as DATA.
pub type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

#[doc(hidden)]
/// Names the exact canonical saved-key or frame constant.
pub const PREFIX: &[u8] = b"\0aos-source-first-successor-v2\0";
/// Names the exact canonical saved-key or frame constant.
pub const PENDING_KEY: &[u8] = b"\0aos-source-first-successor-v2\0pending";
#[doc(hidden)]
/// Names the exact canonical saved-key or frame constant.
pub const RECEIPT_PREFIX: &[u8] = b"\0aos-source-first-successor-v2\0receipt\0";
#[doc(hidden)]
/// Names the exact canonical saved-key or frame constant.
pub const ACK_PREFIX: &[u8] = b"\0aos-source-first-successor-v2\0ACK\0";
#[doc(hidden)]
/// Names the exact canonical saved-key or frame constant.
pub const ACK_SIZING_BYTES: usize = 192;

/// Selects one exact native phase, never a public request or capacity scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FirstSourceSuccessorNativePhaseV2 {
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
    /// Selects the exact saved comparison phase without native authority.
    pub const fn canonical(self) -> Self {
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

    /// Selects the exact saved comparison phase without native authority.
    pub const fn has_capacity_records(self) -> bool {
        !matches!(self.canonical(), Self::ControllerAnchored)
    }

    /// Selects the exact saved comparison phase without native authority.
    pub const fn source_genesis_transition(
        self,
    ) -> super::source_tree_genesis::SourceGenesisTransitionV1 {
        use super::source_tree_genesis::SourceGenesisTransitionV1;
        match self.canonical() {
            Self::SourceAppend => SourceGenesisTransitionV1::FirstSuccessorAppend,
            Self::SourceAck => SourceGenesisTransitionV1::FirstSuccessorAck,
            _ => SourceGenesisTransitionV1::None,
        }
    }

    /// Selects the exact saved comparison phase without native authority.
    pub const fn controller_transition(
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

    /// Selects the exact saved comparison phase without native authority.
    ///
    /// # Errors
    /// Rejects malformed, foreign, incomplete or exhausted saved DATA.
    pub fn controller_transition_for(
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
pub struct SourceFirstSuccessorRowsV2 {
    /// Retains this exact saved family member without live authority.
    pub receipts: BTreeMap<ProjectId, SourceFirstSuccessorReceiptV2>,
    /// Retains this exact saved family member without live authority.
    pub acks: BTreeMap<ProjectId, SourceFirstSuccessorAckV2>,
    /// Retains this exact saved family member without live authority.
    pub pending: Option<SourceFirstSuccessorPendingV2>,
}

/// Owns the two decoded families from one complete local DATA comparison.
///
/// These maps carry no writer, Root floor loan or admission authority. Each
/// consumer moves its required family out within the same observation window;
/// the other family is dropped rather than retained across an owner effect.
pub struct SourceProjectFamilyDataV3 {
    /// Holds the already compared historical genesis rows.
    pub genesis: crate::replay::source_tree_genesis::SourceGenesisRowsV1,
    /// Holds the already compared historical successor rows.
    pub successor: SourceFirstSuccessorRowsV2,
}

impl SourceProjectFamilyDataV3 {
    /// Moves the already-decoded genesis rows, discarding successor DATA.
    pub fn into_genesis(self) -> crate::replay::source_tree_genesis::SourceGenesisRowsV1 {
        self.genesis
    }

    /// Moves already-decoded successor rows, discarding genesis DATA.
    pub fn into_successor(self) -> SourceFirstSuccessorRowsV2 {
        self.successor
    }
}

/// Selects a structural family comparison, never native admission authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceSuccessorFamilyRecipeV3 {
    SingleProjectV2,
    MixedProjectsV3 { selected: Option<ProjectId> },
}

/// Selects an initial-project comparison without changing any durable phase byte.
#[derive(Clone, Copy)]
pub enum ProjectGenesisNativePhaseV3 {
    SourceAppend(ProjectId),
    SourceAck(ProjectId),
    RootPrepared(ProjectId),
    RootAnchor(ProjectId),
    ControllerFloorAck(ProjectId),
    ControllerComplete(ProjectId),
}

impl ProjectGenesisNativePhaseV3 {
    /// Selects the exact saved comparison phase without native authority.
    pub const fn project(self) -> ProjectId {
        match self {
            Self::SourceAppend(project) | Self::SourceAck(project)
            | Self::RootPrepared(project) | Self::RootAnchor(project)
            | Self::ControllerFloorAck(project) | Self::ControllerComplete(project) => project,
        }
    }
}



/// Returns the canonical saved receipt key for one project.
pub fn receipt_key(project: ProjectId) -> Vec<u8> {
    [RECEIPT_PREFIX, project.as_bytes()].concat()
}

/// Returns the canonical saved ACK key for one project.
pub fn ack_key(project: ProjectId) -> Vec<u8> {
    [ACK_PREFIX, project.as_bytes()].concat()
}

/// Derives the exact canonical phase transaction identity.
pub fn transaction_id(
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

/// Measures and binds the exact remaining saved owner suffix.
///
/// # Errors
/// Rejects malformed, foreign, incomplete or exhausted saved DATA.
pub fn capacity_request(
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
            bytes.checked_add(aos_sandbox_protocol::domain_ledger::transaction::encoded_transaction_append_bytes(transaction)?)
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

/// Returns fixed-width deletion sizing DATA using the canonical key codec.
pub fn sizing_capacity_delete() -> JournalRecord {
    JournalRecord::delete(
        RecordNamespace::GlobalCapacityReservation,
        reservation_key([1; 32]),
    )
}

/// Checks whether actual saved and proposed rows touch one capacity purpose.
///
/// # Errors
/// Rejects malformed, foreign, incomplete or exhausted saved DATA.
pub fn touches_capacity_purpose(
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
        touches |= aos_sandbox_protocol::domain_ledger::capacity_family::capacity_record_has_legacy_purpose(&put, purpose)?;
    }
    Ok(touches)
}

/// Checks the exact saved capacity-family cardinality.
///
/// # Errors
/// Rejects malformed, foreign, incomplete or exhausted saved DATA.
pub fn require_exact_capacity_family(
    state: &State,
    purpose: GlobalCapacityReservationPurposeV1,
    count: usize,
) -> Result<(), JournalError> {
    aos_sandbox_protocol::domain_ledger::capacity_family::validate_capacity_snapshot_data_v2(
        state,
    )?;
    let mut actual = 0_usize;
    for ((namespace, key), value) in state {
        if *namespace != RecordNamespace::GlobalCapacityReservation {
            continue;
        }
        let record = JournalRecord::put(*namespace, key.clone(), value.clone());
        if aos_sandbox_protocol::domain_ledger::capacity_family::capacity_record_has_legacy_purpose(
            &record, purpose,
        )? {
            actual = actual
                .checked_add(1)
                .ok_or(JournalError::ProtectedBoundary)?;
        }
    }
    if actual != count {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

/// Copies an exact bounded field from the supplied saved bytes.
///
/// # Errors
/// Rejects malformed, foreign, incomplete or exhausted saved DATA.
pub fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], JournalError> {
    let (value, _) =
        checked_byte_region(bytes, offset, N).map_err(|_| JournalError::ProtectedBoundary)?;
    value
        .try_into()
        .map_err(|_| JournalError::ProtectedBoundary)
}

/// Copies an exact bounded digest from the supplied saved bytes.
///
/// # Errors
/// Rejects malformed, foreign, incomplete or exhausted saved DATA.
pub fn digest_at(bytes: &[u8], offset: usize) -> Result<ObjectDigest, JournalError> {
    Ok(ObjectDigest::from_bytes(array(bytes, offset)?))
}

/// Returns the immutable project named by the supplied receipt.
///
/// # Errors
/// Rejects malformed, foreign, incomplete or exhausted saved DATA.
pub fn receipt_project(receipt: &SourceFirstSuccessorReceiptV2) -> Result<ProjectId, JournalError> {
    Ok(ProjectId::from_bytes(array(receipt.as_bytes(), 48)?))
}

/// Constructs the exact saved first-successor capacity record DATA.
///
/// # Errors
/// Rejects malformed, foreign, incomplete or exhausted saved DATA.
pub fn first_source_successor_capacity_record_v2(
    request: &GlobalCapacityReservationRequestV1,
    admission: [u8; 16],
) -> Result<JournalRecord, JournalError> {
    if !request.purpose.is_first_source_successor()
        || request.owner_namespace != RecordNamespace::DesiredState
        || admission == [0; 16]
    {
        return Err(JournalError::ProtectedBoundary);
    }
    let identity = reservation_id(request, admission);
    Ok(JournalRecord::put(
        RecordNamespace::GlobalCapacityReservation,
        reservation_key(identity),
        encode_reservation(request, admission, identity),
    ))
}

/// Rejoins the exact saved reservation before constructing its deletion DATA.
///
/// # Errors
/// Rejects malformed, foreign, incomplete or exhausted saved DATA.
pub fn first_source_successor_capacity_delete_v2(
    state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    request: &GlobalCapacityReservationRequestV1,
    admission: [u8; 16],
) -> Result<JournalRecord, JournalError> {
    canonical_reservations(state)?;
    let expected = first_source_successor_capacity_record_v2(request, admission)?;
    if state.get(&(expected.namespace(), expected.key().to_vec())).map(Vec::as_slice)
        != expected.value()
    {
        return Err(JournalError::AuthorityPreflightMismatch);
    }
    Ok(JournalRecord::delete(expected.namespace(), expected.key().to_vec()))
}

/// Derives the canonical saved reservation identity.
///
/// # Errors
/// Rejects malformed, foreign, incomplete or exhausted saved DATA.
pub fn first_source_successor_capacity_identity_v2(
    request: &GlobalCapacityReservationRequestV1,
    admission: [u8; 16],
) -> Result<[u8; 32], JournalError> {
    first_source_successor_capacity_record_v2(request, admission)?;
    Ok(reservation_id(request, admission))
}


pub mod retained;
pub use retained::SourceReplayFamilyOriginalsV1;
use aos_sandbox_protocol::domain_ledger::DomainLedgerDataError;
use super::phase_records::{RootFirstSourceSuccessorFloorV2,
    RootFirstSourceSuccessorFloorFieldsV2, ControllerFirstSourceSuccessorAnchoredV2,
    ControllerFirstSourceSuccessorAnchoredFieldsV2};

pub fn current_rows(state: &State) -> Result<SourceFirstSuccessorRowsV2, JournalError> {
    current_rows_with_recipe(state, SourceSuccessorFamilyRecipeV3::SingleProjectV2)
}

pub fn current_project_rows_v3(
    state: &State,
    selected: Option<ProjectId>,
) -> Result<SourceFirstSuccessorRowsV2, JournalError> {
    current_rows_with_recipe(state, SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { selected })
}

pub fn current_project_genesis_rows_v3(
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

pub fn current_project_genesis_data_v3(
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

pub fn replay_rows(state: &State) -> Result<SourceFirstSuccessorRowsV2, JournalError> {
    replay_family(state).map(SourceProjectFamilyDataV3::into_successor)
}

pub fn replay_family(state: &State) -> Result<SourceProjectFamilyDataV3, JournalError> {
    replay_family_with_originals::<JournalError, DomainLedgerDataError, crate::genesis::SourceGenesisReceiptDataErrorV1>(state, None)
}

pub fn replay_family_with_originals<E: From<JournalError> + std::error::Error + 'static, H: From<DomainLedgerDataError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static>(
    state: &State,
    originals: Option<&mut SourceReplayFamilyOriginalsV1<E, H, R>>,
) -> Result<SourceProjectFamilyDataV3, E> {
    use aos_sandbox_model::bounded_codec::CaptureOnDropV1;

    let (selected_sink, decoded_sink, genesis_sink, family_sink) = match originals {
        Some(originals) => (
            Some(&mut originals.selected), Some(&mut originals.decoded_genesis),
            Some(&mut originals.genesis), Some(&mut originals.family),
        ),
        None => (None, None, None, None),
    };
    if !state.keys().any(|(_, key)| key.starts_with(RECEIPT_PREFIX)) {
        // An ordinary genesis-only replay retains its original incomplete
        // genesis handling. Explicit mixed Before observation below still
        // checks every completed member, even without a successor receipt.
        return current_family_with_genesis_data_originals(
            state, SourceSuccessorFamilyRecipeV3::SingleProjectV2, None, None, family_sink,
        );
    }
    let selected = state.get(&(RecordNamespace::DesiredState, PENDING_KEY.to_vec()))
        .map(|bytes| SourceFirstSuccessorPendingV2::decode(bytes).map_err(crate::data::SourceSuccessorDataErrorV2::from)
            .map_err(|_| E::from(JournalError::ProtectedBoundary)))
        .transpose()?;
    let (selected_project, selected) = match selected_sink {
        Some(sink) => {
            let project = selected.as_ref().map(|pending| pending.project());
            (project, Some(CaptureOnDropV1::new(selected, Some(sink))))
        }
        None => (selected.map(|pending| pending.project()), None),
    };
    let genesis = match genesis_sink {
        Some(originals) => {
            originals.observe_once(state)?;
            originals.take_rows_once()?
        }
        None => super::source_tree_genesis::current_rows::<E>(state)?,
    };
    let genesis = CaptureOnDropV1::new(genesis, decoded_sink);
    if let Some(pending) = genesis.pending.as_ref() {
        if selected_project.is_some() {
            return Err(E::from(JournalError::ProtectedBoundary));
        }
        let project = pending.project;
        if project.as_bytes() == &[0; 16] {
            return Err(E::from(JournalError::ProtectedBoundary));
        }
        let family = current_family_with_genesis_data_originals(
            state,
            SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { selected: None },
            Some(project),
            Some(genesis.into_inner()),
            family_sink,
        );
        if family.is_ok() {
            if let Some(selected) = selected { selected.discard_positive(); }
        }
        return family;
    }
    let family = current_family_with_genesis_data_originals(
        state,
        SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { selected: selected_project },
        None,
        Some(genesis.into_inner()),
        family_sink,
    );
    if family.is_ok() {
        if let Some(selected) = selected { selected.discard_positive(); }
    }
    family
}

pub fn current_rows_with_recipe(
    state: &State,
    recipe: SourceSuccessorFamilyRecipeV3,
) -> Result<SourceFirstSuccessorRowsV2, JournalError> {
    current_rows_with_genesis_selection(state, recipe, None)
}

pub fn current_rows_with_genesis_selection(
    state: &State,
    recipe: SourceSuccessorFamilyRecipeV3,
    genesis_selection: Option<ProjectId>,
) -> Result<SourceFirstSuccessorRowsV2, JournalError> {
    current_family_with_genesis_selection(state, recipe, genesis_selection)
        .map(SourceProjectFamilyDataV3::into_successor)
}

pub fn current_family_with_genesis_selection(
    state: &State,
    recipe: SourceSuccessorFamilyRecipeV3,
    genesis_selection: Option<ProjectId>,
) -> Result<SourceProjectFamilyDataV3, JournalError> {
    current_family_with_genesis_data(state, recipe, genesis_selection, None)
}

pub fn current_family_with_genesis_data(
    state: &State,
    recipe: SourceSuccessorFamilyRecipeV3,
    genesis_selection: Option<ProjectId>,
    decoded_genesis: Option<crate::replay::source_tree_genesis::SourceGenesisRowsV1>,
) -> Result<SourceProjectFamilyDataV3, JournalError> {
    current_family_with_genesis_data_originals::<JournalError, DomainLedgerDataError, crate::genesis::SourceGenesisReceiptDataErrorV1>(
        state, recipe, genesis_selection, decoded_genesis, None,
    )
}

pub fn current_family_with_genesis_data_originals<E: From<JournalError> + std::error::Error + 'static, H: From<DomainLedgerDataError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static>(
    state: &State,
    recipe: SourceSuccessorFamilyRecipeV3,
    genesis_selection: Option<ProjectId>,
    decoded_genesis: Option<crate::replay::source_tree_genesis::SourceGenesisRowsV1>,
    originals: Option<&mut retained::SourceFamilyOriginalsV1<E, H, R>>,
) -> Result<SourceProjectFamilyDataV3, E> {
    use aos_sandbox_model::bounded_codec::CaptureOnDropV1;

    let (input_sink, rows_sink, receipt_sink, ack_sink, genesis_sink, genesis_rows_sink,
        floor_sink, anchored_sink, members_sink): retained::SourceFamilySinksV1<'_, E, H, R> = match originals {
        Some(originals) => (
            Some(&mut originals.input_genesis), Some(&mut originals.rows),
            Some(&mut originals.receipt), Some(&mut originals.ack),
            Some(&mut originals.genesis), Some(&mut originals.genesis_rows),
            Some(&mut originals.floor), Some(&mut originals.anchored), Some(&mut originals.members),
        ),
        None => (None, None, None, None, None, None, None, None, None),
    };
    // Arguments outlive the local rows in the ordinary engine. Declaring this
    // guard first preserves that cleanup order on every early scan refusal.
    let decoded_genesis = CaptureOnDropV1::new(decoded_genesis, input_sink);
    let mut rows = CaptureOnDropV1::new(SourceFirstSuccessorRowsV2 {
        receipts: BTreeMap::new(),
        acks: BTreeMap::new(),
        pending: None,
    }, rows_sink);
    let mut receipt_sink = receipt_sink;
    let mut ack_sink = ack_sink;
    let mut floor_sink = floor_sink;
    let mut anchored_sink = anchored_sink;
    let mut members_sink = members_sink;
    for ((namespace, key), value) in state {
        if !key.starts_with(PREFIX) {
            continue;
        }
        if *namespace != RecordNamespace::DesiredState {
            return Err(E::from(JournalError::ProtectedBoundary));
        }
        if key == PENDING_KEY {
            rows.pending = Some(SourceFirstSuccessorPendingV2::decode(value).map_err(crate::data::SourceSuccessorDataErrorV2::from)
                .map_err(|_| E::from(JournalError::ProtectedBoundary))?);
        } else if let Some(project) = project_key(key, RECEIPT_PREFIX)? {
            let receipt = SourceFirstSuccessorReceiptV2::decode(value).map_err(crate::data::SourceSuccessorDataErrorV2::from)
                .map_err(|_| E::from(JournalError::ProtectedBoundary))?;
            let receipt = CaptureOnDropV1::new(receipt, receipt_sink.as_deref_mut());
            if project != receipt.project() {
                return Err(E::from(JournalError::ProtectedBoundary));
            }
            rows.receipts.insert(project, receipt.into_inner());
        } else if let Some(project) = project_key(key, ACK_PREFIX)? {
            let ack = SourceFirstSuccessorAckV2::decode(value).map_err(crate::data::SourceSuccessorDataErrorV2::from)
                .map_err(|_| E::from(JournalError::ProtectedBoundary))?;
            let ack = CaptureOnDropV1::new(ack, ack_sink.as_deref_mut());
            if project != ack.project() {
                return Err(E::from(JournalError::ProtectedBoundary));
            }
            rows.acks.insert(project, ack.into_inner());
        } else {
            return Err(E::from(JournalError::ProtectedBoundary));
        }
    }
    // Issuance is globally singleton. Another project cannot hide a second
    // successor behind its otherwise valid, independent genesis provenance.
    if recipe == SourceSuccessorFamilyRecipeV3::SingleProjectV2 && rows.receipts.len() > 1 {
        return Err(E::from(JournalError::ProtectedBoundary));
    }
    let genesis = match decoded_genesis.into_inner() {
        Some(genesis) => genesis,
        None => match genesis_rows_sink {
            Some(originals) => {
                originals.observe_once(state)?;
                originals.take_rows_once()?
            }
            None => super::source_tree_genesis::current_rows::<E>(state)?,
        },
    };
    let genesis = CaptureOnDropV1::new(genesis, genesis_sink);
    for (project, receipt) in rows.receipts.iter() {
        let predecessor = genesis.receipts.get(project)
            .ok_or(E::from(JournalError::ProtectedBoundary))?;
        let original_ack = genesis.acks.get(project)
            .ok_or(E::from(JournalError::ProtectedBoundary))?;
        if predecessor.instance() != receipt.instance()
            || predecessor.tree_head() != receipt.old_tree_head()
            || predecessor.lineage_head() != receipt.old_lineage_head()
            || original_ack.root_floor != receipt.predecessor_floor()
        {
            return Err(E::from(JournalError::ProtectedBoundary));
        }
        if recipe == SourceSuccessorFamilyRecipeV3::SingleProjectV2 {
            match members_sink.as_deref_mut() {
                Some(originals) => originals.observe_once(
                    state, crate::replay::tree_lineage::SourceSuccessorMemberRecipe::SingleProjectV2(receipt), None, None,
                )?,
                None => crate::replay::tree_lineage::validate_source_first_successor_members_v2(state, receipt, None)?,
            }
        }
        match rows.acks.get(project) {
            Some(ack) => {
                let floor = RootFirstSourceSuccessorFloorV2::new(RootFirstSourceSuccessorFloorFieldsV2 {
                    predecessor_floor: receipt.predecessor_floor(),
                    approval: receipt.approval(),
                    receipt: receipt.clone(),
                    roles: receipt.roles(),
                }).map_err(crate::data::SourceSuccessorDataErrorV2::from).map_err(|_| E::from(JournalError::ProtectedBoundary))?;
                let floor = CaptureOnDropV1::new(floor, floor_sink.as_deref_mut());
                let anchored = ControllerFirstSourceSuccessorAnchoredV2::new(ControllerFirstSourceSuccessorAnchoredFieldsV2 {
                    approval: receipt.approval(),
                    receipt: receipt.digest(),
                    floor: floor.digest(),
                }).map_err(crate::data::SourceSuccessorDataErrorV2::from).map_err(|_| E::from(JournalError::ProtectedBoundary))?;
                let anchored = CaptureOnDropV1::new(anchored, anchored_sink.as_deref_mut());
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
                    return Err(E::from(JournalError::ProtectedBoundary));
                }
                anchored.discard_positive();
                floor.discard_positive();
            }
            None => {
                if let SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { selected } = recipe
                    && selected != Some(*project)
                {
                    return Err(E::from(JournalError::ProtectedBoundary));
                }
                let pending = rows.pending.as_ref()
                    .ok_or(E::from(JournalError::ProtectedBoundary))?;
                if !pending_matches_receipt(pending, receipt) {
                    return Err(E::from(JournalError::ProtectedBoundary));
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
        return Err(E::from(JournalError::ProtectedBoundary));
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
            return Err(E::from(JournalError::ProtectedBoundary));
        }
        match genesis_selection {
            Some(project) => {
                match members_sink.as_deref_mut() {
                    Some(originals) => originals.observe_once(
                        state, crate::replay::tree_lineage::SourceSuccessorMemberRecipe::MixedGenesisV3 {
                            receipts: &rows.receipts, selected: project,
                        }, None, Some(&genesis),
                    )?,
                    None => crate::replay::tree_lineage::validate_source_project_genesis_members_from_genesis_data_v3(
                        state, &genesis, &rows.receipts, project,
                    )?,
                }
            }
            None => {
                match members_sink.as_deref_mut() {
                    Some(originals) => originals.observe_once(
                        state, crate::replay::tree_lineage::SourceSuccessorMemberRecipe::MixedProjectsV3 {
                            receipts: &rows.receipts, proposed: None,
                        }, None, Some(&genesis),
                    )?,
                    None => crate::replay::tree_lineage::validate_source_project_continuation_members_from_genesis_data_v3(
                        state, &genesis, &rows.receipts,
                    )?,
                }
            }
        }
    }
    Ok(SourceProjectFamilyDataV3 { genesis: genesis.into_inner(), successor: rows.into_inner() })
}

pub fn source_capacity_request(
    receipt: &SourceFirstSuccessorReceiptV2,
) -> Result<GlobalCapacityReservationRequestV1, JournalError> {
    let suffix = JournalTransaction::new([1; 16], vec![
        JournalRecord::delete(RecordNamespace::DesiredState, PENDING_KEY.to_vec()),
        JournalRecord::put(
            RecordNamespace::DesiredState, ack_key(receipt.project()), vec![1; ACK_SIZING_BYTES],
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

pub fn pending_matches_receipt(
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

pub fn project_key(key: &[u8], prefix: &[u8]) -> Result<Option<ProjectId>, JournalError> {
    if !key.starts_with(prefix) {
        return Ok(None);
    }
    if key.len() != prefix.len() + 16 {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(Some(ProjectId::from_bytes(array(key, prefix.len())?)))
}

pub fn required_value(record: &JournalRecord) -> Result<&[u8], JournalError> {
    record.value().ok_or(JournalError::ProtectedBoundary)
}


use aos_sandbox_protocol::domain_ledger::capacity_family::family::accounting_reservations;
pub fn require_sequence_headroom(state: &State, next: u64) -> Result<(), JournalError> {
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

pub fn require_no_compaction(state: &State) -> Result<(), JournalError> {
    if replay_rows(state)?.pending.is_some()
        || state.keys().any(|(_, key)| key.starts_with(b"\0aos-root-first-source-successor-v2\0intent\0"))
    {
        return Err(JournalError::ProtectedBoundary);
    }
    validate_root_state(state)
}

pub fn recognize_replayed_phase(
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

pub fn validate_root_state(state: &State) -> Result<(), JournalError> {
    #[cfg(target_os = "linux")]
    {
        super::root_successor::validate_project_successor_replay_v3(state)
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

pub fn validate_root_transition(
    state: &State,
    transaction: &JournalTransaction,
    phase: Option<FirstSourceSuccessorNativePhaseV2>,
) -> Result<Option<[u8; 32]>, JournalError> {
    #[cfg(target_os = "linux")]
    {
        super::root_successor::validate_root_first_source_successor_transition_v2(
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

pub mod predecessor_retained;
pub use predecessor_retained::SourceGenesisPredecessorOriginalsV1;

pub fn require_genesis_predecessor(
    state: &State,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    require_genesis_predecessor_with_originals::<JournalError, DomainLedgerDataError, crate::genesis::SourceGenesisReceiptDataErrorV1>(state, transaction, None)
}

pub fn require_genesis_predecessor_with_originals<E: From<JournalError> + std::error::Error + 'static, H: From<DomainLedgerDataError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static>(
    state: &State,
    transaction: &JournalTransaction,
    originals: Option<&mut SourceGenesisPredecessorOriginalsV1<E, H, R>>,
) -> Result<(), E> {
    match originals {
        Some(originals) => originals.observe_once(state, transaction),
        None => require_genesis_predecessor_engine::<E, H, R>(state, transaction, None),
    }
}

pub fn require_genesis_predecessor_engine<E: From<JournalError> + std::error::Error + 'static, H: From<DomainLedgerDataError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static>(
    state: &State,
    transaction: &JournalTransaction,
    originals: Option<&mut SourceGenesisPredecessorOriginalsV1<E, H, R>>,
) -> Result<(), E> {
    use aos_sandbox_model::bounded_codec::CaptureOnDropV1;
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
        return match originals {
            Some(originals) => require_project_genesis_predecessor_engine::<E, H, R>(state, transaction, Some(originals)),
            None => require_project_genesis_predecessor_v3(state, transaction).map_err(E::from),
        };
    }
    let record = transaction.records().iter()
        .find(|record| record.key().starts_with(RECEIPT_PREFIX));
    let (family, genesis_sink, rows_sink, receipt_sink) = match originals {
        Some(originals) => (Some(&mut originals.family), Some(&mut originals.genesis),
            Some(&mut originals.rows), Some(&mut originals.receipt)),
        None => (None, None, None, None),
    };
    let SourceProjectFamilyDataV3 { genesis, successor: rows } = match family {
        Some(originals) => current_family_with_genesis_data_originals(
            state, SourceSuccessorFamilyRecipeV3::SingleProjectV2, None, None, Some(originals),
        )?,
        None => current_family_with_genesis_selection(
            state, SourceSuccessorFamilyRecipeV3::SingleProjectV2, None,
        )?,
    };
    let genesis = CaptureOnDropV1::new(genesis, genesis_sink);
    let rows = CaptureOnDropV1::new(rows, rows_sink);
    let receipt = match record {
        Some(record) => SourceFirstSuccessorReceiptV2::decode(required_value(record)?).map_err(crate::data::SourceSuccessorDataErrorV2::from)
            .map_err(|_| E::from(JournalError::ProtectedBoundary))?,
        None => rows.receipts.values().next().cloned().ok_or(E::from(JournalError::ProtectedBoundary))?,
    };
    let receipt = CaptureOnDropV1::new(receipt, receipt_sink);
    let project = receipt.project();
    let original = genesis.receipts.get(&project)
        .ok_or(E::from(JournalError::ProtectedBoundary))?;
    if genesis.pending.is_some()
        || !genesis.acks.contains_key(&project)
        || original.tree_head() != receipt.old_tree_head()
        || original.lineage_head() != receipt.old_lineage_head()
    {
        return Err(E::from(JournalError::ProtectedBoundary));
    }
    Ok(())
}

pub fn require_project_genesis_predecessor_v3(
    state: &State,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    require_project_genesis_predecessor_engine::<JournalError, DomainLedgerDataError, crate::genesis::SourceGenesisReceiptDataErrorV1>(state, transaction, None)
}

pub fn require_project_genesis_predecessor_engine<E: From<JournalError> + std::error::Error + 'static, H: From<DomainLedgerDataError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static>(
    state: &State,
    transaction: &JournalTransaction,
    originals: Option<&mut SourceGenesisPredecessorOriginalsV1<E, H, R>>,
) -> Result<(), E> {
    use aos_sandbox_model::bounded_codec::CaptureOnDropV1;
    let (replay, genesis_sink, rows_sink, receipt_sink) = match originals {
        Some(originals) => (Some(&mut originals.replay), Some(&mut originals.genesis),
            Some(&mut originals.rows), Some(&mut originals.receipt)),
        None => (None, None, None, None),
    };
    let SourceProjectFamilyDataV3 { genesis, successor: rows } = match replay {
        Some(originals) => replay_family_with_originals(state, Some(originals))?,
        None => replay_family(state)?,
    };
    let genesis = CaptureOnDropV1::new(genesis, genesis_sink);
    let rows = CaptureOnDropV1::new(rows, rows_sink);
    let receipt = match transaction.records().iter()
        .find(|record| record.key().starts_with(RECEIPT_PREFIX))
    {
        Some(record) => SourceFirstSuccessorReceiptV2::decode(required_value(record)?).map_err(crate::data::SourceSuccessorDataErrorV2::from)
            .map_err(|_| E::from(JournalError::ProtectedBoundary))?,
        None => {
            let pending = rows.pending.as_ref().ok_or(E::from(JournalError::ProtectedBoundary))?;
            let receipt = rows.receipts.get(&pending.project())
                .ok_or(E::from(JournalError::ProtectedBoundary))?;
            if !transaction.records().iter().any(|record| {
                record.namespace() == RecordNamespace::DesiredState
                    && record.key() == ack_key(pending.project())
            }) {
                return Err(E::from(JournalError::ProtectedBoundary));
            }
            receipt.clone()
        }
    };
    let receipt = CaptureOnDropV1::new(receipt, receipt_sink);
    let original = genesis.receipts.get(&receipt.project())
        .ok_or(E::from(JournalError::ProtectedBoundary))?;
    if genesis.pending.is_some()
        || !genesis.acks.contains_key(&receipt.project())
        || original.tree_head() != receipt.old_tree_head()
        || original.lineage_head() != receipt.old_lineage_head()
    {
        return Err(E::from(JournalError::ProtectedBoundary));
    }
    Ok(())
}

pub mod project_genesis_retained;
pub use project_genesis_retained::SourceProjectGenesisOriginalsV1;

pub fn select_replayed_genesis_project_engine<E: From<JournalError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static>(
    state: &State,
    transaction: &JournalTransaction,
    phase: Option<FirstSourceSuccessorNativePhaseV2>,
    originals: Option<&mut project_genesis_retained::SourceGenesisSelectionOriginalsV1<E, R>>,
) -> Result<Option<ProjectId>, E> {
    use aos_sandbox_model::bounded_codec::CaptureOnDropV1;
    let (receipt_sink, rows_parser, rows_sink, receipt_decoder) = match originals {
        Some(originals) => (Some(&mut originals.receipt), Some(&mut originals.parser), Some(&mut originals.rows), Some(&mut originals.receipt_decode)),
        None => (None, None, None, None),
    };
    let selected = if phase.is_none()
        && state.keys().any(|(_, key)| key.starts_with(RECEIPT_PREFIX))
    {
        match super::source_tree_genesis::recognize_replayed_transition(transaction)? {
            super::source_tree_genesis::SourceGenesisTransitionV1::Append => {
                let receipt = super::source_tree_genesis::decode_receipt_with_originals::<E, R>(
                    required_value(transaction.records().get(2).ok_or(E::from(JournalError::ProtectedBoundary))?)?, receipt_decoder,
                )?;
                let receipt = CaptureOnDropV1::new(receipt, receipt_sink);
                Some(receipt.project())
            }
            _ => match rows_parser {
                Some(parser) => {
                    parser.observe_once(state)?;
                    let rows = parser.take_rows_once()?;
                    let slot = rows_sink.ok_or(E::from(JournalError::ProtectedBoundary))?;
                    *slot = Some(rows);
                    slot.as_ref().and_then(|rows| rows.pending.as_ref()).map(|pending| pending.project)
                }
                None => super::source_tree_genesis::current_rows::<E>(state)?.pending.map(|pending| pending.project),
            },
        }
    } else {
        None
    };
    Ok(selected)
}

pub fn require_project_genesis_transition_v3(
    state: &State,
    transaction: &JournalTransaction,
    project: ProjectId,
) -> Result<(), JournalError> {
    require_project_genesis_transition_engine::<JournalError, DomainLedgerDataError, crate::genesis::SourceGenesisReceiptDataErrorV1>(state, transaction, project, None)
}

pub fn require_project_genesis_transition_engine<E: From<JournalError> + std::error::Error + 'static, H: From<DomainLedgerDataError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static>(
    state: &State,
    transaction: &JournalTransaction,
    project: ProjectId,
    originals: Option<&mut SourceProjectGenesisOriginalsV1<E, H, R>>,
) -> Result<(), E> {
    use aos_sandbox_model::bounded_codec::CaptureOnDropV1;
    let (before_family, after_family, before_sink, next_sink, receipt_sink,
        anchor_parser, anchor_sink, mutation, after_sink, receipt_decoder) = match originals {
        Some(originals) => (
            Some(&mut originals.before_family), Some(&mut originals.after_family),
            Some(&mut originals.before), Some(&mut originals.next), Some(&mut originals.receipt),
            Some(&mut originals.anchor_parser), Some(&mut originals.anchor_rows),
            Some(&mut originals.mutation), Some(&mut originals.after), Some(&mut originals.receipt_decode),
        ),
        None => (None, None, None, None, None, None, None, None, None, None),
    };
    let before = match before_family {
        Some(originals) => current_project_genesis_rows_with_originals::<E, H, R>(state, project, originals)?,
        None => current_project_genesis_rows_v3(state, project)?,
    };
    let before = CaptureOnDropV1::new(before, before_sink);
    if before.pending.is_some() {
        return Err(E::from(JournalError::ProtectedBoundary));
    }
    let transition = super::source_tree_genesis::recognize_replayed_transition(transaction)?;
    match transition {
        super::source_tree_genesis::SourceGenesisTransitionV1::Append => {
            let receipt = super::source_tree_genesis::decode_receipt_with_originals::<E, R>(
                required_value(transaction.records().get(2).ok_or(E::from(JournalError::ProtectedBoundary))?)?, receipt_decoder,
            )?;
            let receipt = CaptureOnDropV1::new(receipt, receipt_sink);
            if receipt.project() != project {
                return Err(E::from(JournalError::ProtectedBoundary));
            }
        }
        super::source_tree_genesis::SourceGenesisTransitionV1::Anchor => {
            match anchor_parser {
                Some(parser) => {
                    parser.observe_once(state)?;
                    let rows = parser.take_rows_once()?;
                    let slot = anchor_sink.ok_or(E::from(JournalError::ProtectedBoundary))?;
                    *slot = Some(rows);
                    if slot.as_ref().and_then(|rows| rows.pending.as_ref())
                        .is_none_or(|pending| pending.project != project)
                    {
                        return Err(E::from(JournalError::ProtectedBoundary));
                    }
                }
                None => {
                    if super::source_tree_genesis::current_rows::<E>(state)?.pending
                        .is_none_or(|pending| pending.project != project)
                    {
                        return Err(E::from(JournalError::ProtectedBoundary));
                    }
                }
            }
        }
        _ => return Err(E::from(JournalError::ProtectedBoundary)),
    }
    match mutation {
        Some(originals) => super::source_tree_genesis::require_no_mutation_with_originals(state, transaction, transition, Some(originals))?,
        None => super::source_tree_genesis::require_no_mutation(state, transaction, transition)?,
    }
    let after = super::root_original_inventory::materialize(state, transaction);
    let after = CaptureOnDropV1::new(after, after_sink);
    let next = match after_family {
        Some(originals) => current_project_genesis_rows_with_originals::<E, H, R>(&after, project, originals)?,
        None => current_project_genesis_rows_v3(&after, project)?,
    };
    let next = CaptureOnDropV1::new(next, next_sink);
    if *next != *before {
        return Err(E::from(JournalError::ProtectedBoundary));
    }
    Ok(())
}

pub fn current_project_genesis_rows_with_originals<E: From<JournalError> + std::error::Error + 'static, H: From<DomainLedgerDataError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static>(
    state: &State,
    selected: ProjectId,
    originals: &mut retained::SourceFamilyOriginalsV1<E, H, R>,
) -> Result<SourceFirstSuccessorRowsV2, E> {
    if selected.as_bytes() == &[0; 16] {
        return Err(E::from(JournalError::ProtectedBoundary));
    }
    current_family_with_genesis_data_originals(
        state, SourceSuccessorFamilyRecipeV3::MixedProjectsV3 { selected: None },
        Some(selected), None, Some(originals),
    ).map(SourceProjectFamilyDataV3::into_successor)
}

pub fn require_project_genesis_family_v3(
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
            super::root_successor::validate_project_successor_transition_v3(
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
            use crate::replay::controller_source_genesis::ControllerSourceGenesisTransition as Transition;
            let transition = match phase {
                ProjectGenesisNativePhaseV3::ControllerFloorAck(_) => Transition::FloorAck,
                _ => Transition::Complete,
            };
            crate::replay::controller_source_genesis::require_no_mutation(state, transaction, transition).map_err(JournalError::from)?;
            let rows = crate::replay::controller_source_genesis::all_rows(state).map_err(JournalError::from)?
                .remove(&project).ok_or(JournalError::ProtectedBoundary)?;
            let expected = match phase {
                ProjectGenesisNativePhaseV3::ControllerFloorAck(_) => {
                    let record = transaction.records().first().ok_or(JournalError::ProtectedBoundary)?;
                    let value: &[u8; 144] = required_value(record)?.try_into().map_err(|_| JournalError::ProtectedBoundary)?;
                    if digest_at(value, 16)? != rows.acceptance.digest() { return Err(JournalError::ProtectedBoundary); }
                    crate::replay::controller_source_genesis::ack_transaction(project, value).map_err(JournalError::from)?
                }
                _ => {
                    let record = transaction.records().first().ok_or(JournalError::ProtectedBoundary)?;
                    let value: &[u8; 144] = required_value(record)?.try_into().map_err(|_| JournalError::ProtectedBoundary)?;
                    crate::replay::controller_source_genesis::complete_transaction(project, value).map_err(JournalError::from)?
                }
            };
            if transaction != &expected { return Err(JournalError::ProtectedBoundary); }
        }
    }
    Ok(())
}

/// Owns the sole complete saved transition comparisons.
pub mod transition;
pub use transition::{require_transition, require_replayed_transition,
    require_source_transition, require_source_transition_with_originals,
    require_source_transition_with_recipe, require_source_transition_with_recipe_originals,
    require_source_transition_engine};
/// Owns the sole raw-COMMIT and final-state replay hooks.
pub mod replay_hooks;
pub use replay_hooks::{validate_replayed_transaction, validate_replayed_transaction_with_originals,
    validate_replayed_state, validate_replayed_state_with_originals, source_member_dynamic_demand_v1};
/// Retains reached transition DATA and original typed errors.
pub mod transition_retained;
pub use transition_retained::SourceReplayTransactionOriginalsV1;

/// Checks each proposed closed successor capacity record as DATA.
///
/// Native phase ownership remains a separate caller check. The canonical
/// decoder and request-limit engine are shared with the existing Domain route.
///
/// # Errors
/// Rejects another purpose, an unequal admission transaction or invalid bounds.
pub fn require_capacity_records_data_v1(
    limits: aos_sandbox_protocol::domain_ledger::transaction::JournalLimits,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    for record in transaction.records() {
        if record.namespace() != RecordNamespace::GlobalCapacityReservation
            || record.value().is_none()
        {
            continue;
        }
        let (request, admission, _) = aos_sandbox_protocol::domain_ledger::capacity_family::decode_capacity_reservation_request_v1(record)?;
        if !request.purpose.is_first_source_successor() || &admission != transaction.id() {
            return Err(JournalError::ProtectedBoundary);
        }
        aos_sandbox_protocol::domain_ledger::capacity_family::validate_request_with_limits(&request, limits)?;
    }
    Ok(())
}
