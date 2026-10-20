//! Delegates kind2/kind5 historical admission and retirement comparisons.
//!
//! The canonical LedgerReplay owner retains the complete saved-row grammar.
//! Mount's native package separately owns the real writer, current Session
//! lenders, physical readback and private table-installation frontier. These
//! Domain delegates preserve replay and generic mutation fences without
//! reconstructing an old live plan or historical Head as current custody.
//!
//! The R1 commitments use exact canonical record bytes, not decoded field hashes:
//!
//! ```text
//! H = SHA256(R1-domain || suffix || NUL || u32be(payload length) || payload)
//! map = u16be(count) || sorted(namespace, u32be(key length), key,
//!                            presence, u32be(value length), exact value)
//! profile = kind/selector || owner/operation/admission bindings || scope
//!           || postimage reads || retained reference map || local DELETE budget
//! ```

use aos_sandbox_protocol::domain_ledger::capacity_family::ordinary::{
    OrdinaryCapacityDataV4, OrdinaryCapacityKindV4 as Kind, OrdinaryCapacityProfileV4 as Profile,
    OrdinaryCapacityRecordV4,
};

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox_protocol::mount_source_acquisition_state::{
    AcquisitionRecoveryV2, MountSourceAcquisitionStateV2, MutationTagV2, ProviderAttemptStateV2,
    ProviderMethodV2, ProviderQueryOwnerV2, ProviderScopeV2, SourceAcquisitionPhaseV2,
    SourceProviderHeadV2, SourceProviderSessionV2, StoredRecordV2, acquisition_key,
    encode_mount_source_state_record_v2, holder_sequence_key, key_kind,
    native_held_completion::{RootNativeHeldGraphV2, validate_native_root_graph_v2},
    seal_record, transaction_id,
};
use sha2::{Digest as _, Sha256};

use super::{JournalError, JournalRecord, JournalTransaction, RecordNamespace};

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;
type Map = BTreeMap<Vec<u8>, Option<Vec<u8>>>;
type FencedFloors = Vec<(OrdinaryCapacityRecordV4, BTreeSet<Vec<u8>>)>;

mod dead_replacement;

fn invalid() -> JournalError {
    aos_sandbox_ledger_replay::replay::root_local_recovery::invalid().into()
}

pub(super) fn graph(state: &State) -> Result<RootNativeHeldGraphV2, JournalError> {
    aos_sandbox_ledger_replay::replay::root_local_recovery::graph(state)
        .map_err(JournalError::from)
}

fn checked_owner(state: &State) -> Result<(RootNativeHeldGraphV2, FencedFloors), JournalError> {
    aos_sandbox_ledger_replay::replay::root_local_recovery::checked_owner(state)
        .map_err(JournalError::from)
}

fn checked_owner_floors(
    state: &State,
    floors: Vec<OrdinaryCapacityRecordV4>,
) -> Result<(RootNativeHeldGraphV2, FencedFloors), JournalError> {
    aos_sandbox_ledger_replay::replay::root_local_recovery::checked_owner_floors(state, floors)
        .map_err(JournalError::from)
}

fn stored(record: StoredRecordV2) -> Result<(Vec<u8>, Vec<u8>), JournalError> {
    aos_sandbox_ledger_replay::replay::root_local_recovery::stored(record)
        .map_err(JournalError::from)
}

fn map_record(map: &mut Map, record: StoredRecordV2) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_local_recovery::map_record(map, record)
        .map_err(JournalError::from)
}

/// Encodes typed, sorted optional-row maps without assigning owner policy.
///
/// # Errors
/// Rejects map counts or key/value lengths outside the canonical framing widths.
pub(super) fn map_bytes(namespace: RecordNamespace, map: &Map) -> Result<Vec<u8>, JournalError> {
    aos_sandbox_ledger_replay::replay::root_local_recovery::map_bytes(namespace, map)
        .map_err(JournalError::from)
}

fn commitment(suffix: &str, payload: &[u8]) -> Result<[u8; 32], JournalError> {
    aos_sandbox_ledger_replay::replay::root_local_recovery::commitment(suffix, payload)
        .map_err(JournalError::from)
}

/// Shares framing mechanics only; callers retain their own domains and policies.
///
/// # Errors
/// Rejects a payload length outside the commitment's canonical u32 framing.
pub(super) fn scoped_commitment(
    domain: &[u8],
    suffix: &str,
    payload: &[u8],
) -> Result<[u8; 32], JournalError> {
    aos_sandbox_ledger_replay::replay::root_local_recovery::scoped_commitment(domain, suffix, payload)
        .map_err(JournalError::from)
}

pub(super) fn scope_bytes(scope: ProviderScopeV2) -> Vec<u8> {
    aos_sandbox_ledger_replay::replay::root_local_recovery::scope_bytes(scope)
}

fn read_map(state: &State, head: &SourceProviderHeadV2) -> Result<Map, JournalError> {
    aos_sandbox_ledger_replay::replay::root_local_recovery::read_map(state, head)
        .map_err(JournalError::from)
}

/// Reconstructs only current local postimages/references, never a prior guard.
use aos_sandbox_ledger_replay::replay::root_local_recovery::LocalPostimageBindings;

fn installed(
    state: &State,
    table: &MountSourceAcquisitionStateV2,
    session: SourceProviderSessionV2,
    head: SourceProviderHeadV2,
) -> Result<LocalPostimageBindings, JournalError> {
    aos_sandbox_ledger_replay::replay::root_local_recovery::installed(state, table, session, head)
        .map_err(JournalError::from)
}

fn local_bindings(
    installed: &LocalPostimageBindings,
) -> Result<([u8; 32], [u8; 32], [u8; 32]), JournalError> {
    aos_sandbox_ledger_replay::replay::root_local_recovery::local_bindings(installed)
        .map_err(JournalError::from)
}

pub(super) fn rejoin(
    state: &State,
    floor: &OrdinaryCapacityRecordV4,
) -> Result<BTreeSet<Vec<u8>>, JournalError> {
    aos_sandbox_ledger_replay::replay::root_local_recovery::rejoin(state, floor)
        .map_err(JournalError::from)
}

fn rejoin_checked(
    state: &State,
    floor: &OrdinaryCapacityRecordV4,
    table: &MountSourceAcquisitionStateV2,
) -> Result<BTreeSet<Vec<u8>>, JournalError> {
    aos_sandbox_ledger_replay::replay::root_local_recovery::rejoin_checked(state, floor, table)
        .map_err(JournalError::from)
}

pub(super) fn pending(state: &State) -> Result<Vec<OrdinaryCapacityRecordV4>, JournalError> {
    aos_sandbox_ledger_replay::replay::root_local_recovery::pending(state)
        .map_err(JournalError::from)
}

fn fenced_floors(state: &State) -> Result<FencedFloors, JournalError> {
    aos_sandbox_ledger_replay::replay::root_local_recovery::fenced_floors(state)
        .map_err(JournalError::from)
}

fn local_floors(state: &State) -> Result<Vec<OrdinaryCapacityRecordV4>, JournalError> {
    aos_sandbox_ledger_replay::replay::root_local_recovery::local_floors(state)
        .map_err(JournalError::from)
}

pub(super) fn require_fences(
    state: &State,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_local_recovery::require_fences(state, transaction)
        .map_err(JournalError::from)
}

fn require_derived_fences(
    floors: &[(OrdinaryCapacityRecordV4, BTreeSet<Vec<u8>>)],
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_local_recovery::require_derived_fences(floors, transaction)
        .map_err(JournalError::from)
}

/// These variants are internal exact owner edges, not caller bypass flags.
pub(super) use aos_sandbox_ledger_replay::replay::root_local_recovery::Edge;

pub(super) fn prepare(
    state: &State,
    successor: SourceProviderSessionV2,
) -> Result<(JournalTransaction, OrdinaryCapacityRecordV4), JournalError> {
    aos_sandbox_ledger_replay::replay::root_local_recovery::prepare(state, successor)
        .map_err(JournalError::from)
}

/// Rejects unsupported owner debt before creating any new local floor.
fn require_funded_local_owner(
    state: &State,
    checked: &RootNativeHeldGraphV2,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_local_recovery::require_funded_local_owner(state, checked)
        .map_err(JournalError::from)
}

/// Couples one named owner proposal with its exact profile1 local installation debt.
fn admitted_local_operation(
    state: &State,
    owner_records: Vec<StoredRecordV2>,
    installed: LocalPostimageBindings,
    mut reads: Map,
    fences: &FencedFloors,
) -> Result<(JournalTransaction, OrdinaryCapacityRecordV4), JournalError> {
    aos_sandbox_ledger_replay::replay::root_local_recovery::admitted_local_operation(
        state,
        owner_records,
        installed,
        reads,
        fences,
    )
        .map_err(JournalError::from)
}

pub(super) fn settlement(
    floor: &OrdinaryCapacityRecordV4,
) -> Result<JournalTransaction, JournalError> {
    aos_sandbox_ledger_replay::replay::root_local_recovery::settlement(floor)
        .map_err(JournalError::from)
}

pub(super) fn validate_edge(
    state: &State,
    transaction: &JournalTransaction,
    edge: Edge,
) -> Result<Option<[u8; 32]>, JournalError> {
    aos_sandbox_ledger_replay::replay::root_local_recovery::validate_edge(state, transaction, edge)
        .map_err(JournalError::from)
}

/// Rechecks both named local logical edges and durable dependency fences.
pub(super) fn validate_replayed_transaction(
    state: &State,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_local_recovery::validate_replayed_transaction(
        state,
        transaction,
    )
        .map_err(JournalError::from)
}
