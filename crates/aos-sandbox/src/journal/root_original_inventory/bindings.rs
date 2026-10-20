//! Typed historical Query commitments and immutable-reference rejoin.
//!
//! The profile commits a concrete original Root sidecar/floor and query Q1,
//! Session, predecessor, correlations and lineage. The admission global union
//! is checked at its actual before cut. Rejoin preserves that historical hash;
//! fixed300 cannot reconstruct an arbitrary historical global materialization.
//!
//! Each typed commitment uses the same canonical framing mechanics as R1:
//! ```text
//! SHA256(Query6 domain || typed suffix || NUL || u32be(payload length) || payload)
//! ```

use crate::journal::JournalError;

use aos_sandbox_protocol::domain_ledger::capacity_family::family::canonical_reservations;
use aos_sandbox_protocol::domain_ledger::capacity_family::query::{
    QueryCapacityDataV6, QueryCapacityProfileV6, QueryCapacityRecordV6,
};

use aos_sandbox_protocol::mount_source_acquisition_state::{
    MutationTagV2, OwnerPredecessorWitnessV2, ProviderHeadPredecessorWitnessV2, ProviderIntentV2,
    ProviderQueryOwnerV2, SourceProviderHeadV2, SourceProviderQueryAttemptV2, StoredRecordV2,
    acquisition_key, derive_inventory_reservation_head_v2, encode_mount_source_state_record_v2,
    holder_sequence_key, provider_attempt_key, seal_record, transaction_id,
};

use super::*;
use crate::journal::root_local_recovery::{map_bytes, scope_bytes, scoped_commitment};

const DOMAIN: &[u8] = b"aos.journal.root-recovery-query-capacity.v6.";
type Map = BTreeMap<Vec<u8>, Option<Vec<u8>>>;

fn commitment(suffix: &str, bytes: &[u8]) -> Result<[u8; 32], JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_inventory::bindings::commitment(suffix, bytes)
        .map_err(JournalError::from)
}

fn stored(record: StoredRecordV2) -> Result<(Vec<u8>, Vec<u8>), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_inventory::bindings::stored(record)
        .map_err(JournalError::from)
}

fn put(map: &mut Map, record: StoredRecordV2) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_inventory::bindings::put(map, record)
        .map_err(JournalError::from)
}

/// Reconstructs immutable reservation DATA, without recreating hot reservation.
fn reserved_query(
    query: &SourceProviderQueryAttemptV2,
) -> Result<SourceProviderQueryAttemptV2, JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_inventory::bindings::reserved_query(query)
        .map_err(JournalError::from)
}

fn predecessor_head(
    value: &ProviderHeadPredecessorWitnessV2,
) -> Result<SourceProviderHeadV2, JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_inventory::bindings::predecessor_head(value)
        .map_err(JournalError::from)
}

use aos_sandbox_ledger_replay::replay::root_original_inventory::bindings::QueryReferences;

fn references(
    checked: &RootNativeHeldGraphV2,
    query: [u8; 32],
) -> Result<QueryReferences, JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_inventory::bindings::references(checked, query)
        .map_err(JournalError::from)
}

fn owner_digest(
    suffix: &str,
    transaction: [u8; 16],
    map: &Map,
) -> Result<[u8; 32], JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_inventory::bindings::owner_digest(
        suffix,
        transaction,
        map,
    )
        .map_err(JournalError::from)
}

fn immutable_digest(references: &QueryReferences) -> Result<[u8; 32], JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_inventory::bindings::immutable_digest(references)
        .map_err(JournalError::from)
}

fn profile_digest(
    state: &State,
    checked: &RootNativeHeldGraphV2,
    root: [u8; 32],
    data: QueryCapacityDataV6,
    references: &QueryReferences,
) -> Result<[u8; 32], JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_inventory::bindings::profile_digest(
        state,
        checked,
        root,
        data,
        references,
    )
        .map_err(JournalError::from)
}

/// Binds the actual admission preimages, PUT map and historical native union.
///
/// # Errors
/// Rejects mismatched Protocol DATA, immutable references or canonical framing.
pub(super) fn admission_floor(
    state: &State,
    after: &RootNativeHeldGraphV2,
    proposal: &OriginalInventoryTransitionV6,
) -> Result<QueryCapacityRecordV6, JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_inventory::bindings::admission_floor(
        state,
        after,
        proposal,
    )
        .map_err(JournalError::from)
}

/// Includes all actual native rows and every canonical current floor preimage.
fn native_union(state: &State) -> Result<[u8; 32], JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_inventory::bindings::native_union(state)
        .map_err(JournalError::from)
}

/// Retains every admission binding while deriving the exact count-one profile.
///
/// # Errors
/// Rejects missing/replaced immutable references or invalid Root/profile DATA.
pub(super) fn successor_floor(
    state: &State,
    checked: &RootNativeHeldGraphV2,
    root: [u8; 32],
    old: &QueryCapacityRecordV6,
) -> Result<QueryCapacityRecordV6, JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_inventory::bindings::successor_floor(
        state,
        checked,
        root,
        old,
    )
        .map_err(JournalError::from)
}

/// Derives the exact root association from concrete rows and a typed profile.
///
/// # Errors
/// Rejects unjoined historical references, mismatched commitments or absent or
/// duplicate concrete Root associations. Today's global union is not substituted.
pub(super) fn rejoin(
    state: &State,
    checked: &RootNativeHeldGraphV2,
    floor: &QueryCapacityRecordV6,
) -> Result<[u8; 32], JournalError> {
    aos_sandbox_ledger_replay::replay::root_original_inventory::bindings::rejoin(state, checked, floor)
        .map_err(JournalError::from)
}
