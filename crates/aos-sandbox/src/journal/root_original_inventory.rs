//! Named original-root ordinary Inventory owner edges and cold metadata rejoin.
//!
//! Query6 independently funds Q/H while the original phase11 Root5 floor and
//! immutable Pending cut remain unchanged. Replay and compaction retain DATA
//! only; they supply no received packet, Session, signer or hot owner factory.
//! There is no count-one uncertain-debt release producer in this module.

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

use super::capacity_reservation::{
    QueryCapacityDataV6, QueryCapacityProfileV6, QueryCapacityRecordV6,
};
use super::capacity_reservation::family::{CanonicalCapacityFamily, canonical_reservations};
use super::native_held::OriginalRootCapacityRecordV5;
use super::root_original_native::require_supported_funding_families as require_supported_families;
use super::{
    JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace, RootOwnerEdge,
};

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

mod bindings;
mod writer;
pub use writer::{
    MountOriginalInventoryJournalAuthorityV6, OriginalInventoryProtectedReadbackV6,
    PreparedOriginalInventoryAppendV6,
};

#[cfg(test)]
mod tests;

fn invalid() -> JournalError {
    JournalError::MalformedRecord("invalid original Inventory Query6 owner edge")
}

fn graph(state: &State) -> Result<RootNativeHeldGraphV2, JournalError> {
    validate_native_root_graph_v2(state.iter().filter_map(|((namespace, key), value)| {
        (*namespace == RecordNamespace::MountSourceAcquisition).then_some((key.as_slice(), value.as_slice()))
    }))
    .map_err(|_| invalid())
}

fn reference(query: &SourceProviderQueryAttemptV2) -> RecordRefV2 {
    RecordRefV2 {
        id: query.attempt_id,
        revision: query.revision,
        record_digest: query.record_digest,
    }
}

fn root_floor(
    state: &State,
    checked: &RootNativeHeldGraphV2,
    root: [u8; 32],
) -> Result<OriginalRootCapacityRecordV5, JournalError> {
    let mut selected = None;
    for family in canonical_reservations(state)? {
        let CanonicalCapacityFamily::OriginalRoot5(floor) = family else {
            continue;
        };
        if floor.request().owner_id == root && selected.replace(floor).is_some() {
            return Err(invalid());
        }
    }

    let floor = selected.ok_or_else(invalid)?;
    let sidecar = checked.sidecars().get(&root).ok_or_else(invalid)?;
    if sidecar.suffix().phase() != 11
        || sidecar.suffix().prepared().is_some()
        || sidecar.suffix().control(NativeHeldControlKindV1::RootClosed).is_none()
        || sidecar.settlement().is_some()
        || sidecar.terminal_verifier().is_some()
        || sidecar.no_interest_terminal().is_some()
        || !has_original_pending_closed_cut_v5(checked, sidecar).map_err(|_| invalid())?
        || original_root_remaining_v5(checked, root).map_err(|_| invalid())? != 2
        || floor.request().future_transactions != 2
    {
        return Err(invalid());
    }

    floor.validate_preserved_graph(checked)?;
    Ok(floor)
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
    let families = canonical_reservations(state)?;
    let mut floors = Vec::new();
    let mut owners = BTreeSet::new();
    for family in &families {
        if let CanonicalCapacityFamily::Query6(floor) = family {
            if !owners.insert(floor.data().owner_id) {
                return Err(invalid());
            }
            floors.push(floor.clone());
        }
    }
    if floors.is_empty() {
        return Ok(Vec::new());
    }

    require_supported_families(&families)?;
    super::root_original_native::pending(state, limits)?;
    let checked = graph(state)?;

    let mut joined = Vec::new();
    for floor in floors {
        let data = floor.data();
        data.profile.validate_limits(limits)?;
        let query = checked.legacy().provider_attempts.get(&data.owner_id)
            .ok_or_else(invalid)?;
        match (data.profile, &query.state) {
            (QueryCapacityProfileV6::StatusOrComplete, ProviderAttemptStateV2::Reserved) if query.revision == 1 => {
                let identity = (query.scope.holder_authority_id, query.scope.provider_authority_id);
                let head = checked.legacy().provider_heads.get(&identity).ok_or_else(invalid)?;
                if head.pending_attempt != Some(reference(query))
                    || head.current_session_id != query.session_id
                    || head.current_session_record_digest != query.session_record_digest
                {
                    return Err(invalid());
                }
            }
            (QueryCapacityProfileV6::RetainedUncertain, ProviderAttemptStateV2::DispositionConsumed { status, .. })
                if query.revision == 2 && *status != ProviderStatusV2::Complete => {}
            _ => return Err(invalid()),
        }

        let root = bindings::rejoin(state, &checked, &floor)?;
        joined.push((floor, root));
    }
    Ok(joined)
}

fn apply_owners(state: &State, owners: &JournalTransaction) -> Result<State, JournalError> {
    let mut after = state.clone();
    let mut keys = BTreeSet::new();
    for record in owners.records() {
        if record.namespace() != RecordNamespace::MountSourceAcquisition || !keys.insert(record.key()) {
            return Err(invalid());
        }
        after.insert(
            (record.namespace(), record.key().to_vec()),
            record.value().ok_or_else(invalid)?.to_vec(),
        );
    }
    Ok(after)
}

/// Projects DATA rows for a separately validated coupled owner transaction.
pub(super) fn materialize(state: &State, transaction: &JournalTransaction) -> State {
    let mut after = state.clone();
    for record in transaction.records() {
        let key = (record.namespace(), record.key().to_vec());
        match record.value() {
            Some(bytes) => {
                after.insert(key, bytes.to_vec());
            }
            None => {
                after.remove(&key);
            }
        }
    }
    after
}

struct DerivedAppend {
    transaction: JournalTransaction,
    root: [u8; 32],
    query: [u8; 32],
    kind: Kind,
    old: Option<QueryCapacityRecordV6>,
    floor: Option<QueryCapacityRecordV6>,
}

fn derive(
    state: &State,
    owners: &JournalTransaction,
    root: [u8; 32],
    query: [u8; 32],
    limits: JournalLimits,
) -> Result<DerivedAppend, JournalError> {
    let families = canonical_reservations(state)?;
    require_supported_families(&families)?;
    let joined = pending(state, limits)?;
    super::root_original_native::pending(state, limits)?;
    super::root_local_recovery::require_fences(state, owners)?;

    let before = graph(state)?;
    root_floor(state, &before, root)?.validate_graph(&before, limits)?;
    let after = graph(&apply_owners(state, owners)?)?;
    let proposal = validate_original_inventory_transition_v6(
        &before, &after, root, query, *owners.id(),
    ).map_err(|_| invalid())?;
    if owners.records().len() != 2
        || proposal.puts.len() != 2
        || owners.records().iter().any(|record| {
            proposal.puts.get(record.key()).map(Vec::as_slice) != record.value()
        })
    {
        return Err(invalid());
    }

    let old = joined.into_iter().find(|(floor, _)| floor.data().owner_id == query);
    let (old, floor) = match proposal.kind {
        Kind::Reserved => {
            if old.is_some() {
                return Err(invalid());
            }
            (None, Some(bindings::admission_floor(state, &after, &proposal)?))
        }
        Kind::NonCompleteConsumed | Kind::CompleteConsumed => {
            let (old, association) = old.ok_or_else(invalid)?;
            if association != root || old.data().profile != QueryCapacityProfileV6::StatusOrComplete {
                return Err(invalid());
            }
            let next = if proposal.kind == Kind::NonCompleteConsumed {
                Some(bindings::successor_floor(state, &after, root, &old)?)
            } else {
                None
            };
            (Some(old), next)
        }
    };

    let mut records = owners.records().to_vec();
    if let Some(old) = &old {
        records.push(JournalRecord::delete(
            RecordNamespace::GlobalCapacityReservation,
            old.to_journal_record().key().to_vec(),
        ));
    }
    if let Some(floor) = &floor {
        records.push(floor.to_journal_record());
    }
    let transaction = JournalTransaction::new(proposal.transaction_id, records)?;

    Ok(DerivedAppend {
        transaction,
        root,
        query,
        kind: proposal.kind,
        old,
        floor,
    })
}

fn validate_derived(
    state: &State,
    candidate: &DerivedAppend,
    limits: JournalLimits,
) -> Result<(), JournalError> {
    if let Some(old) = &candidate.old {
        let budget = |floor: &QueryCapacityRecordV6| {
            (floor.data().remaining_record_frames, floor.data().remaining_append_bytes)
        };
        super::native_held::check_bounded_transfer(
            &candidate.transaction,
            budget(old),
            candidate.floor.as_ref().map(budget),
            limits,
            ("query consumed records", "query transferred suffix"),
        )?;
    } else {
        super::validate_transaction(&candidate.transaction, limits)?;
    }

    pending(&materialize(state, &candidate.transaction), limits)?;
    super::root_original_native::preserve_local_owner(state, &candidate.transaction)?;
    Ok(())
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
    let owners = owner_projection(transaction)?;
    let derived = derive(state, &owners, root, query, limits)?;
    if derived.kind != kind || derived.transaction != *transaction {
        return Err(invalid());
    }
    validate_derived(state, &derived, limits)?;
    Ok(derived.old.as_ref().map(QueryCapacityRecordV6::reservation_id))
}

/// Projects strict owner PUT input before separately checking the coupled TX.
fn owner_projection(transaction: &JournalTransaction) -> Result<JournalTransaction, JournalError> {
    JournalTransaction::new(
        *transaction.id(),
        transaction.records().iter()
            .filter(|record| record.namespace() == RecordNamespace::MountSourceAcquisition)
            .cloned()
            .collect(),
    )
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
    canonical_reservations(state)?;
    let mut query = None;
    for record in transaction.records() {
        if record.namespace() != RecordNamespace::GlobalCapacityReservation {
            continue;
        }
        let bytes = record.value().or_else(|| {
            state.get(&(record.namespace(), record.key().to_vec())).map(Vec::as_slice)
        });
        let Some(bytes) = bytes else {
            continue;
        };
        if let CanonicalCapacityFamily::Query6(floor) = CanonicalCapacityFamily::decode(record.key(), bytes)? {
            if query.is_some_and(|old| old != floor.data().owner_id) {
                return Err(invalid());
            }
            query = Some(floor.data().owner_id);
        }
    }
    let Some(query) = query else {
        return Ok(None);
    };

    let owners = owner_projection(transaction)?;
    let after = graph(&apply_owners(state, &owners)?)?;
    let old = pending(state, limits)?.into_iter()
        .find(|(floor, _)| floor.data().owner_id == query);
    let root = if let Some((_, root)) = old {
        root
    } else {
        let floors: Vec<_> = transaction.records().iter()
            .filter(|record| record.namespace() == RecordNamespace::GlobalCapacityReservation)
            .map(QueryCapacityRecordV6::from_journal_record)
            .collect::<Result<_, _>>()?;
        let [floor] = floors.as_slice() else {
            return Err(invalid());
        };
        bindings::rejoin(state, &after, floor)?
    };

    let before = graph(state)?;
    let proposal = validate_original_inventory_transition_v6(
        &before, &after, root, query, *transaction.id(),
    ).map_err(|_| invalid())?;
    validate_edge(state, transaction, root, query, proposal.kind, limits)?;
    Ok(Some(RootOwnerEdge::OriginalInventory {
        root,
        query,
        kind: proposal.kind,
    }))
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
    let joined = pending(state, limits)?;
    for record in transaction.records() {
        if record.namespace() == RecordNamespace::MountSourceAcquisition && !joined.is_empty() {
            return Err(JournalError::ProtectedBoundary);
        }
        if record.namespace() != RecordNamespace::GlobalCapacityReservation {
            continue;
        }
        let before = state.get(&(record.namespace(), record.key().to_vec())).map(Vec::as_slice);
        for bytes in [record.value(), before].into_iter().flatten() {
            if matches!(CanonicalCapacityFamily::decode(record.key(), bytes)?, CanonicalCapacityFamily::Query6(_)) {
                return Err(JournalError::ProtectedBoundary);
            }
        }
    }
    Ok(())
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
    let before = pending(state, limits)?;
    if before.is_empty() {
        return Ok(());
    }
    let after = materialize(state, transaction);
    for (floor, _) in &before {
        let record = floor.to_journal_record();
        if after.get(&(record.namespace(), record.key().to_vec())).map(Vec::as_slice) != record.value() {
            return Err(JournalError::ProtectedBoundary);
        }
        let key = provider_attempt_key(floor.data().owner_id);
        if state.get(&(RecordNamespace::MountSourceAcquisition, key.clone()))
            != after.get(&(RecordNamespace::MountSourceAcquisition, key))
        {
            return Err(JournalError::ProtectedBoundary);
        }
    }
    pending(&after, limits)?;
    Ok(())
}

/// Checks all-family future frame headroom against the actual NEXT sequence.
///
/// # Errors
/// Rejects malformed floor accounting or checked physical-sequence overflow.
pub(super) fn require_sequence_headroom(state: &State, next_sequence: u64) -> Result<(), JournalError> {
    let future_frames = super::capacity_reservation::accounting_reservations(state)?.values()
        .try_fold(0_u64, |total, floor| {
            let records = u64::try_from(floor.maximum_records).map_err(|_| JournalError::SequenceExhausted)?;
            let transactions = u64::try_from(floor.maximum_transactions).map_err(|_| JournalError::SequenceExhausted)?;
            total.checked_add(records).and_then(|value| {
                transactions.checked_mul(2).and_then(|frames| value.checked_add(frames))
            })
                .ok_or(JournalError::SequenceExhausted)
        })?;
    next_sequence.checked_add(future_frames).ok_or(JournalError::SequenceExhausted)?;
    Ok(())
}

/// Traverses every canonical family before detecting any Query floor.
///
/// # Errors
/// Rejects any malformed or unknown floor, regardless of selection order.
pub(super) fn has_query_floor(state: &State) -> Result<bool, JournalError> {
    Ok(canonical_reservations(state)?.iter()
        .any(|family| matches!(family, CanonicalCapacityFamily::Query6(_))))
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
    let after = materialize(state, transaction);
    if has_query_floor(state)? || has_query_floor(&after)? {
        require_sequence_headroom(&after, next_sequence)?;
    }
    Ok(())
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
    if pending(state, limits)?.is_empty() {
        return Ok(());
    }
    super::validate_reserved_capacity(
        state, materialized_bytes, &[], None, journal_bytes, transactions, limits, None,
    )?;
    require_sequence_headroom(state, next_sequence)
}
