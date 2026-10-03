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
    scoped_commitment(DOMAIN, suffix, bytes)
}

fn stored(record: StoredRecordV2) -> Result<(Vec<u8>, Vec<u8>), JournalError> {
    encode_mount_source_state_record_v2(&record).map_err(|_| invalid())
}

fn put(map: &mut Map, record: StoredRecordV2) -> Result<(), JournalError> {
    let (key, bytes) = stored(record)?;
    if map.insert(key, Some(bytes)).is_some() {
        return Err(invalid());
    }

    Ok(())
}

/// Reconstructs immutable reservation DATA, without recreating hot reservation.
fn reserved_query(
    query: &SourceProviderQueryAttemptV2,
) -> Result<SourceProviderQueryAttemptV2, JournalError> {
    let mut reserved = query.clone();
    reserved.revision = 1;
    reserved.state = ProviderAttemptStateV2::Reserved;
    reserved.record_digest = [0; 32];
    match seal_record(StoredRecordV2::ProviderQueryAttempt { value: reserved })
        .map_err(|_| invalid())?
    {
        StoredRecordV2::ProviderQueryAttempt { value } => Ok(value),
        _ => Err(invalid()),
    }
}

fn predecessor_head(
    value: &ProviderHeadPredecessorWitnessV2,
) -> Result<SourceProviderHeadV2, JournalError> {
    let head = SourceProviderHeadV2 {
        revision: value.record.revision,
        scope: value.scope,
        holder_authority_generation: value.holder_authority_generation,
        holder_authority_digest: value.holder_authority_digest,
        provider_authority_generation: value.provider_authority_generation,
        provider_authority_digest: value.provider_authority_digest,
        current_session_id: value.current_session_id,
        current_session_record_digest: value.current_session_record_digest,
        next_request_sequence: value.next_request_sequence,
        next_response_sequence: value.next_response_sequence,
        pending_attempt: value.pending_attempt,
        inventory_observation_ordinal: value.inventory_observation_ordinal,
        inventory_floor: value.inventory_floor.clone(),
        last_inventory_attempt: value.last_inventory_attempt,
        current_projection_epoch: value.current_projection_epoch,
        current_projection_digest: value.current_projection_digest,
        last_reconciliation: value.last_reconciliation.clone(),
        recovery_barrier: value.recovery_barrier.clone(),
        record_digest: [0; 32],
    };
    let StoredRecordV2::ProviderHead { value: head } =
        seal_record(StoredRecordV2::ProviderHead { value: head }).map_err(|_| invalid())?
    else {
        return Err(invalid());
    };

    let mut identity = [0; 32];
    identity[..16].copy_from_slice(&head.scope.holder_authority_id);
    identity[16..].copy_from_slice(&head.scope.provider_authority_id);
    if identity != value.record.id || head.record_digest != value.record.record_digest {
        return Err(invalid());
    }

    Ok(head)
}

struct QueryReferences {
    reserved: SourceProviderQueryAttemptV2,
    before: Map,
    puts: Map,
    retained: Map,
    admission_transaction: [u8; 16],
}

fn references(
    checked: &RootNativeHeldGraphV2,
    query: [u8; 32],
) -> Result<QueryReferences, JournalError> {
    let table = checked.legacy();
    let actual = table.provider_attempts.get(&query).ok_or_else(invalid)?;
    if actual.method != ProviderMethodV2::Inventory
        || actual.owner != ProviderQueryOwnerV2::Inventory
        || !matches!(&actual.intent, ProviderIntentV2::Inventory { value }
            if value.recovery_root_attempt_id.is_none())
    {
        return Err(invalid());
    }
    let reserved = reserved_query(actual)?;
    let Some(OwnerPredecessorWitnessV2::ProviderHead { value: witness }) = &reserved.owner_predecessor
    else {
        return Err(invalid());
    };
    let head = predecessor_head(witness)?;
    if head.scope != reserved.scope
        || head.pending_attempt.is_some()
        || head.recovery_barrier.is_some()
        || head.next_request_sequence != reserved.request_sequence
        || head.next_request_sequence != head.next_response_sequence
        || head.current_session_id != reserved.session_id
        || head.current_session_record_digest != reserved.session_record_digest
        || head.revision != reserved.owner_predecessor_revision
        || head.record_digest != reserved.owner_predecessor_digest
    {
        return Err(invalid());
    }

    let mut before = Map::new();
    put(
        &mut before,
        StoredRecordV2::ProviderHead { value: head.clone() },
    )?;
    before.insert(provider_attempt_key(query), None);

    let next = derive_inventory_reservation_head_v2(&head, reference(&reserved))
        .map_err(|_| invalid())?;
    let holder_revision = table
        .holder_sequences
        .get(&reserved.scope.holder_authority_id)
        .map_or(0, |row| row.revision);
    let admission_transaction = transaction_id(
        MutationTagV2::ReserveRetry,
        reserved.scope.holder_authority_id,
        reserved.scope.provider_authority_id,
        holder_revision,
        next.revision,
        None,
        None,
        Some(reserved.attempt_id),
        Some(reserved.revision),
        None,
    );
    let mut puts = Map::new();
    put(
        &mut puts,
        seal_record(StoredRecordV2::ProviderHead { value: next }).map_err(|_| invalid())?,
    )?;
    put(
        &mut puts,
        StoredRecordV2::ProviderQueryAttempt { value: reserved.clone() },
    )?;

    let session = table
        .provider_sessions
        .get(&reserved.session_id)
        .filter(|row| row.record_digest == reserved.session_record_digest)
        .ok_or_else(invalid)?;
    let mut retained = Map::new();
    let holder_key = holder_sequence_key(reserved.scope.holder_authority_id);
    retained.insert(
        holder_key.clone(),
        checked.canonical_records().get(&holder_key).cloned(),
    );
    put(
        &mut retained,
        StoredRecordV2::ProviderSession { value: session.clone() },
    )?;
    for id in [reserved.previous_attempt_id, Some(reserved.lineage_root_attempt_id)] {
        let Some(id) = id.filter(|id| *id != query) else {
            continue;
        };
        let key = provider_attempt_key(id);
        let value = checked.canonical_records().get(&key).ok_or_else(invalid)?;
        retained.insert(key, Some(value.clone()));
    }

    let correlations = reserved.inventory_correlations.as_ref().ok_or_else(invalid)?;
    for correlation in &correlations.entries {
        let row = table
            .acquisitions
            .get(&correlation.mount_acquisition_id)
            .ok_or_else(invalid)?;
        if row.revision != correlation.acquisition_record.revision
            || row.record_digest != correlation.acquisition_record.record_digest
        {
            // The exact immutable reference is required for a compacted rejoin.
            return Err(invalid());
        }
        let key = acquisition_key(row.acquisition_id);
        let bytes = checked.canonical_records().get(&key).ok_or_else(invalid)?;
        retained.insert(key, Some(bytes.clone()));
    }

    Ok(QueryReferences { reserved, before, puts, retained, admission_transaction })
}

fn owner_digest(
    suffix: &str,
    transaction: [u8; 16],
    map: &Map,
) -> Result<[u8; 32], JournalError> {
    let mut bytes = transaction.to_vec();
    bytes.extend_from_slice(&map_bytes(RecordNamespace::MountSourceAcquisition, map)?);
    commitment(suffix, &bytes)
}

fn immutable_digest(references: &QueryReferences) -> Result<[u8; 32], JournalError> {
    let query = &references.reserved;
    let mut bytes = scope_bytes(query.scope);
    bytes.extend_from_slice(&query.attempt_id);
    bytes.extend_from_slice(&query.request_id);
    bytes.extend_from_slice(&query.request_sequence.to_be_bytes());
    // Canonical Q1 binds method, exact signed bytes, full predecessor witness,
    // Session snapshots, correlations and every lineage coordinate together.
    let (key, value) = stored(StoredRecordV2::ProviderQueryAttempt { value: query.clone() })?;
    let projection = Map::from([(key, Some(value))]);
    bytes.extend_from_slice(&map_bytes(RecordNamespace::MountSourceAcquisition, &projection)?);
    bytes.extend_from_slice(&map_bytes(
        RecordNamespace::MountSourceAcquisition,
        &references.retained,
    )?);
    commitment("request-immutable-projection", &bytes)
}

fn profile_digest(
    state: &State,
    checked: &RootNativeHeldGraphV2,
    root: [u8; 32],
    data: QueryCapacityDataV6,
    references: &QueryReferences,
) -> Result<[u8; 32], JournalError> {
    let floor = root_floor(state, checked, root)?;
    let sidecar_key = native_root_sidecar_key_v2(root).map_err(|_| invalid())?;
    let sidecar = checked.canonical_records().get(&sidecar_key).ok_or_else(invalid)?;
    let root_map = BTreeMap::from([(sidecar_key, Some(sidecar.clone()))]);
    let record = floor.to_journal_record()?;
    let floor_map = BTreeMap::from([(
        record.key().to_vec(),
        Some(record.value().ok_or_else(invalid)?.to_vec()),
    )]);

    let mut bytes = vec![0, 6, 40, 10, 7, data.profile as u8];
    bytes.extend_from_slice(&root);
    bytes.extend_from_slice(&data.owner_id);
    bytes.extend_from_slice(&data.operation_id);
    bytes.extend_from_slice(&data.admission_transaction);
    bytes.extend_from_slice(&data.original_owner_cut_digest);
    bytes.extend_from_slice(&data.original_artifact_digest);
    bytes.extend_from_slice(&data.admission_owner_mutation_digest);
    bytes.extend_from_slice(&data.admission_native_preservation_union_digest);
    bytes.extend_from_slice(&immutable_digest(references)?);
    bytes.extend_from_slice(&map_bytes(RecordNamespace::MountSourceAcquisition, &root_map)?);
    bytes.extend_from_slice(&map_bytes(
        RecordNamespace::GlobalCapacityReservation,
        &floor_map,
    )?);
    bytes.extend_from_slice(&data.remaining_transactions.to_be_bytes());
    bytes.extend_from_slice(&data.remaining_record_frames.to_be_bytes());
    bytes.extend_from_slice(&data.remaining_append_bytes.to_be_bytes());
    bytes.extend_from_slice(&data.maximum_retained_growth_entries.to_be_bytes());
    bytes.extend_from_slice(&data.maximum_retained_growth_bytes.to_be_bytes());
    commitment("profile", &bytes)
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
    let references = references(after, proposal.query_attempt)?;
    let puts: Map = proposal.puts.iter()
        .map(|(key, value)| (key.clone(), Some(value.clone())))
        .collect();
    if references.before != proposal.before_images
        || references.puts != puts
        || references.admission_transaction != proposal.transaction_id
    {
        return Err(invalid());
    }

    let profile = QueryCapacityProfileV6::StatusOrComplete;
    let append_bytes = profile.remaining_append_bytes()?;
    let mut data = QueryCapacityDataV6 {
        profile,
        owner_id: proposal.query_attempt,
        original_owner_cut_digest: owner_digest(
            "owner-before-cut", proposal.transaction_id, &references.before,
        )?,
        operation_id: references.reserved.request_id,
        original_artifact_digest: commitment("request-artifact", &references.reserved.signed_request)?,
        admission_owner_mutation_digest: owner_digest("owner-put-map", proposal.transaction_id, &puts)?,
        admission_native_preservation_union_digest: native_union(state)?,
        remaining_transactions: profile.remaining_transactions(),
        remaining_record_frames: profile.remaining_record_frames(),
        remaining_append_bytes: append_bytes,
        maximum_retained_growth_entries: 0,
        maximum_retained_growth_bytes: append_bytes,
        admission_transaction: proposal.transaction_id,
        remaining_profile_digest: [0; 32],
    };
    data.remaining_profile_digest = profile_digest(
        state, after, proposal.root_attempt, data, &references,
    )?;
    QueryCapacityRecordV6::new(data)
}

/// Includes all actual native rows and every canonical current floor preimage.
fn native_union(state: &State) -> Result<[u8; 32], JournalError> {
    canonical_reservations(state)?;
    let mut bytes = Vec::new();
    for namespace in [
        RecordNamespace::MountSourceAcquisition,
        RecordNamespace::GlobalCapacityReservation,
    ] {
        let map: Map = state.iter()
            .filter(|((ns, _), _)| *ns == namespace)
            .map(|((_, key), value)| (key.clone(), Some(value.clone())))
            .collect();
        bytes.extend_from_slice(&map_bytes(namespace, &map)?);
    }
    commitment("native-union", &bytes)
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
    let references = references(checked, old.data().owner_id)?;
    let mut data = old.data();
    let profile = QueryCapacityProfileV6::RetainedUncertain;
    data.profile = profile;
    data.remaining_transactions = profile.remaining_transactions();
    data.remaining_record_frames = profile.remaining_record_frames();
    data.remaining_append_bytes = profile.remaining_append_bytes()?;
    data.maximum_retained_growth_bytes = data.remaining_append_bytes;
    data.remaining_profile_digest = profile_digest(state, checked, root, data, &references)?;
    QueryCapacityRecordV6::new(data)
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
    let data = floor.data();
    let references = references(checked, data.owner_id)?;
    if data.admission_transaction != references.admission_transaction
        || data.operation_id != references.reserved.request_id
        || data.original_artifact_digest
            != commitment("request-artifact", &references.reserved.signed_request)?
        || data.original_owner_cut_digest
            != owner_digest("owner-before-cut", data.admission_transaction, &references.before)?
        || data.admission_owner_mutation_digest
            != owner_digest("owner-put-map", data.admission_transaction, &references.puts)?
    {
        return Err(invalid());
    }

    let mut selected = None;
    for root in checked.sidecars().keys().copied() {
        // Every candidate original is validated before profile selection.
        if checked.legacy().provider_attempts.get(&root)
            .is_none_or(|row| row.scope != references.reserved.scope)
        {
            continue;
        }
        let sidecar = checked.sidecars().get(&root).ok_or_else(invalid)?;
        if sidecar.suffix().phase() != 11
            || !has_original_pending_closed_cut_v5(checked, sidecar).map_err(|_| invalid())?
            || original_root_remaining_v5(checked, root).map_err(|_| invalid())? != 2
        {
            continue;
        }
        let original = root_floor(state, checked, root)?;
        if original.request().future_transactions != 2 {
            continue;
        }
        if profile_digest(state, checked, root, data, &references)? == data.remaining_profile_digest {
            if selected.replace(root).is_some() {
                return Err(invalid());
            }
        }
    }
    selected.ok_or_else(invalid)
}
