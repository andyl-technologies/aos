//! Named original-root ordinary Inventory owner edges and cold metadata rejoin.
//!
//! Query6 independently funds Q/H while the original phase11 Root5 floor and
//! immutable Pending cut remain unchanged. Replay and compaction retain DATA
//! only; they supply no received packet, Session, signer or hot owner factory.
//! There is no count-one uncertain-debt release producer in this module.

use aos_sandbox_protocol::domain_ledger::capacity_family::family::{
    CanonicalCapacityFamily, canonical_reservations, canonical_reservations_after,
};
use aos_sandbox_protocol::domain_ledger::capacity_family::native_held::OriginalRootCapacityRecordV5;
use aos_sandbox_protocol::domain_ledger::capacity_family::query::{
    QueryCapacityDataV6, QueryCapacityProfileV6, QueryCapacityRecordV6,
};

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox_protocol::mount_source_acquisition_state::{
    ProviderAttemptStateV2, ProviderMethodV2, ProviderStatusV2, RecordRefV2,
    SourceProviderQueryAttemptV2,
    decode_mount_source_state_record_v2, provider_attempt_key,
    native_held_completion::{
        OriginalInventoryTransitionKindV6 as Kind, OriginalInventoryTransitionV6,
        RootNativeHeldGraphV2, has_original_pending_closed_cut_v5,
        native_root_sidecar_key_v2, original_root_remaining_v5,
        validate_native_root_graph_v2, validate_original_inventory_transition_v6,
    },
};
use aos_sandbox_source_provider_protocol::native_held_completion::NativeHeldControlKindV1;

use super::root_original_native::require_supported_funding_families as require_supported_families;
use super::{
    JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace, RootOwnerEdge,
};

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

mod bindings;

fn invalid() -> JournalError {
    aos_sandbox_ledger_replay::replay::root_original_inventory::invalid().into()
}

fn graph(state: &State) -> Result<RootNativeHeldGraphV2, JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_inventory::graph(state)
        .map_err(JournalError::from)
}

fn reference(query: &SourceProviderQueryAttemptV2) -> RecordRefV2 {
    aos_sandbox_ledger_replay::replay::root_original_inventory::reference(query)
}

fn root_floor(
    state: &State,
    checked: &RootNativeHeldGraphV2,
    root: [u8; 32],
) -> Result<OriginalRootCapacityRecordV5, JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_inventory::root_floor(state, checked, root)
        .map_err(JournalError::from)
}

/// Rejoins all Query profiles before an owner can be selected.
///
/// # Errors
/// Rejects any canonical floor, original graph, Query profile, opened envelope
/// or retained immutable-reference violation, including duplicate Query owners.
pub(super) fn pending(
    state: &State,
    limits: JournalLimits,
) -> Result<Vec<(QueryCapacityRecordV6, [u8; 32])>, JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_inventory::pending(state, limits)
        .map_err(JournalError::from)
}

fn apply_owners(state: &State, owners: &JournalTransaction) -> Result<State, JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_inventory::apply_owners(state, owners)
        .map_err(JournalError::from)
}

/// Projects DATA rows for a separately validated coupled owner transaction.
pub(crate) fn materialize(state: &State, transaction: &JournalTransaction) -> State {
    aos_sandbox_ledger_replay::replay::root_original_inventory::materialize(state, transaction)
}

use aos_sandbox_ledger_replay::replay::root_original_inventory::DerivedAppend;

fn derive(
    state: &State,
    owners: &JournalTransaction,
    root: [u8; 32],
    query: [u8; 32],
    limits: JournalLimits,
) -> Result<DerivedAppend, JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_inventory::derive(state, owners, root, query, limits)
        .map_err(JournalError::from)
}

fn validate_derived(
    state: &State,
    candidate: &DerivedAppend,
    limits: JournalLimits,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_inventory::validate_derived(state, candidate, limits)
        .map_err(JournalError::from)
}

/// Validates the exact Protocol-derived owner and its own complete floor edge.
///
/// # Errors
/// Rejects altered owners, TX identity, kind, root association, floor or spend.
pub(super) fn validate_edge(
    state: &State,
    transaction: &JournalTransaction,
    root: [u8; 32],
    query: [u8; 32],
    kind: Kind,
    limits: JournalLimits,
) -> Result<Option<[u8; 32]>, JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_inventory::validate_edge(
        state,
        transaction,
        root,
        query,
        kind,
        limits,
    )
        .map_err(JournalError::from)
}

/// Projects strict owner PUT input before separately checking the coupled TX.
fn owner_projection(transaction: &JournalTransaction) -> Result<JournalTransaction, JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_inventory::owner_projection(transaction)
        .map_err(JournalError::from)
}

/// Recognizes a Query floor before any old native/local replay route.
///
/// # Errors
/// Rejects malformed candidate floors, unjoined roots or any edge that differs
/// from the actual Protocol-derived coupled transaction; no fallback follows.
pub(super) fn replay_edge(
    state: &State,
    transaction: &JournalTransaction,
    limits: JournalLimits,
) -> Result<Option<RootOwnerEdge>, JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_inventory::replay_edge(state, transaction, limits)
        .map(|edge| {
            edge.map(|aos_sandbox_ledger_replay::replay::RootReplayOwnerEdgeV1::OriginalInventory {
                root,
                query,
                kind,
            }| RootOwnerEdge::OriginalInventory { root, query, kind })
        })
        .map_err(JournalError::from)
}

/// Keeps bare Query floors and protected Query owner rows out of generic writes.
///
/// # Errors
/// Rejects malformed retained metadata or any generic mutation of these rows.
pub(super) fn require_generic_transaction(
    state: &State,
    transaction: &JournalTransaction,
    limits: JournalLimits,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_inventory::require_generic_transaction(
        state,
        transaction,
        limits,
    )
        .map_err(JournalError::from)
}

/// Keeps older Query debt immutable across an independently validated owner.
///
/// # Errors
/// Rejects changed floors, Query rows or unavailable/replaced immutable refs.
pub(super) fn preserve_other_owner(
    state: &State,
    transaction: &JournalTransaction,
    limits: JournalLimits,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_inventory::preserve_other_owner(
        state,
        transaction,
        limits,
    )
        .map_err(JournalError::from)
}

/// Checks all-family future frame headroom against the actual NEXT sequence.
///
/// # Errors
/// Rejects malformed floor accounting or checked physical-sequence overflow.
pub(super) fn require_sequence_headroom(
    state: &State,
    next_sequence: u64,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_inventory::require_sequence_headroom(
        state,
        next_sequence,
    )
        .map_err(JournalError::from)
}

/// Traverses every canonical family before detecting any Query floor.
///
/// # Errors
/// Rejects any malformed or unknown floor, regardless of selection order.
pub(super) fn has_query_floor(state: &State) -> Result<bool, JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_inventory::has_query_floor(state)
        .map_err(JournalError::from)
}

/// Traverses every prospective canonical floor before detecting any Query.
///
/// # Errors
/// Rejects malformed/unknown projected rows or duplicate canonical identities.
pub(super) fn has_query_floor_after(
    state: &State,
    transaction: &JournalTransaction,
) -> Result<bool, JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_inventory::has_query_floor_after(state, transaction)
        .map_err(JournalError::from)
}

/// Preserves funded sequence space across every independent append while held.
///
/// # Errors
/// Rejects malformed floors or prospective all-family NEXT-sequence overflow.
pub(super) fn require_append_sequence_headroom(
    state: &State,
    transaction: &JournalTransaction,
    next_sequence: u64,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_inventory::require_append_sequence_headroom(
        state,
        transaction,
        next_sequence,
    )
        .map_err(JournalError::from)
}

/// Rejoins compacted metadata and charges every retained family under real bounds.
///
/// # Errors
/// Rejects failed metadata rejoin, opened outstanding-capacity limits or actual
/// NEXT-sequence overflow. This accounting helper grants no owner mutation.
pub(super) fn validate_rejoined_capacity(
    state: &State,
    materialized_bytes: usize,
    journal_bytes: u64,
    transactions: usize,
    limits: JournalLimits,
    next_sequence: u64,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_inventory::validate_rejoined_capacity(
        state,
        materialized_bytes,
        journal_bytes,
        transactions,
        limits,
        next_sequence,
    )
        .map_err(JournalError::from)
}
