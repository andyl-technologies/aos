//! Same-writer kind2 admission and local installed-metadata retirement.
//!
//! The lower scope proves physical protected rows, not live Security custody or
//! Mount's private table installation. The trusted fixed coordinator consumes
//! the real current Session plan and installs its table before local deletion.
//! Pending local floors derive durable postimage/read fences; no old live plan
//! or historical Head is reconstructed by replay.
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

use super::capacity_reservation::{
    OrdinaryCapacityDataV4, OrdinaryCapacityKindV4 as Kind, OrdinaryCapacityProfileV4 as Profile,
    OrdinaryCapacityRecordV4,
};
use super::{JournalError, JournalRecord, JournalTransaction, RecordNamespace};

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;
type Map = BTreeMap<Vec<u8>, Option<Vec<u8>>>;
type FencedFloors = Vec<(OrdinaryCapacityRecordV4, BTreeSet<Vec<u8>>)>;

#[cfg(test)]
mod tests;
mod writer;
pub use writer::{
    Kind2ProtectedReadbackV4, MountBarrierIdleReplacementJournalAuthorityV4,
    PreparedBarrierIdleReplacementV4,
};

fn invalid() -> JournalError {
    JournalError::MalformedRecord("invalid kind2 local recovery binding")
}

pub(super) fn graph(state: &State) -> Result<RootNativeHeldGraphV2, JournalError> {
    Ok(checked_owner(state)?.0)
}

fn checked_owner(state: &State) -> Result<(RootNativeHeldGraphV2, FencedFloors), JournalError> {
    let floors = kind2_floors(state)?;
    checked_owner_floors(state, floors)
}

fn checked_owner_floors(
    state: &State,
    floors: Vec<OrdinaryCapacityRecordV4>,
) -> Result<(RootNativeHeldGraphV2, FencedFloors), JournalError> {
    let graph =
        validate_native_root_graph_v2(state.iter().filter_map(|((namespace, key), value)| {
            (*namespace == RecordNamespace::MountSourceAcquisition)
                .then_some((key.as_slice(), value.as_slice()))
        }))
        .map_err(|_| invalid())?;
    let fences = floors
        .into_iter()
        .map(|floor| {
            let keys = rejoin_checked(state, &floor, graph.legacy())?;
            Ok((floor, keys))
        })
        .collect::<Result<_, JournalError>>()?;
    Ok((graph, fences))
}

fn stored(record: StoredRecordV2) -> Result<(Vec<u8>, Vec<u8>), JournalError> {
    encode_mount_source_state_record_v2(&record).map_err(|_| invalid())
}

fn map_record(map: &mut Map, record: StoredRecordV2) -> Result<(), JournalError> {
    let (key, value) = stored(record)?;
    if map.insert(key, Some(value)).is_some() {
        return Err(invalid());
    }
    Ok(())
}

fn map_bytes(namespace: RecordNamespace, map: &Map) -> Result<Vec<u8>, JournalError> {
    let mut bytes = u16::try_from(map.len())
        .map_err(|_| invalid())?
        .to_be_bytes()
        .to_vec();
    for (key, value) in map {
        bytes.extend_from_slice(&(namespace as u16).to_be_bytes());
        bytes.extend_from_slice(
            &u32::try_from(key.len())
                .map_err(|_| invalid())?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(key);
        bytes.push(u8::from(value.is_some()));
        let value = value.as_deref().unwrap_or_default();
        bytes.extend_from_slice(
            &u32::try_from(value.len())
                .map_err(|_| invalid())?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(value);
    }
    Ok(bytes)
}

fn commitment(suffix: &str, payload: &[u8]) -> Result<[u8; 32], JournalError> {
    let mut hash = Sha256::new();
    hash.update(b"aos.journal.root-ordinary-capacity.v4.r1.");
    hash.update(suffix.as_bytes());
    hash.update([0]);
    hash.update(
        u32::try_from(payload.len())
            .map_err(|_| invalid())?
            .to_be_bytes(),
    );
    hash.update(payload);
    Ok(hash.finalize().into())
}

fn scope_bytes(scope: ProviderScopeV2) -> Vec<u8> {
    let mut bytes = scope.holder_authority_id.to_vec();
    bytes.extend_from_slice(&scope.provider_authority_id);
    bytes.extend_from_slice(&scope.route_id);
    bytes.extend_from_slice(&scope.resource_namespace_digest);
    bytes
}

fn read_map(state: &State, head: &SourceProviderHeadV2) -> Result<Map, JournalError> {
    let mut map = Map::new();
    map_record(
        &mut map,
        StoredRecordV2::ProviderHead {
            value: head.clone(),
        },
    )?;
    let key = holder_sequence_key(head.scope.holder_authority_id);
    map.insert(
        key.clone(),
        state
            .get(&(RecordNamespace::MountSourceAcquisition, key))
            .cloned(),
    );
    Ok(map)
}

/// Reconstructs only current local postimages/references, never a prior guard.
struct Kind2PostimageBindings {
    owner: Map,
    reads: Map,
    references: Map,
    acquisition: Vec<u8>,
    transaction: [u8; 16],
    session: SourceProviderSessionV2,
}

fn installed(
    state: &State,
    table: &MountSourceAcquisitionStateV2,
    session: SourceProviderSessionV2,
    head: SourceProviderHeadV2,
) -> Result<Kind2PostimageBindings, JournalError> {
    let witness = session
        .barrier_idle_replacement
        .as_ref()
        .ok_or_else(invalid)?;
    let predecessor = table
        .provider_sessions
        .get(&witness.predecessor_head.current_session_id)
        .filter(|value| {
            value.record_digest == witness.predecessor_head.current_session_record_digest
        })
        .ok_or_else(invalid)?;
    let root = table
        .provider_attempts
        .get(&witness.root_attempt.id)
        .filter(|value| {
            value.revision == witness.root_attempt.revision
                && value.record_digest == witness.root_attempt.record_digest
        })
        .ok_or_else(invalid)?;
    let ProviderQueryOwnerV2::Acquire { acquisition_id } = root.owner else {
        return Err(invalid());
    };
    if root.method != ProviderMethodV2::Acquire
        || !matches!(
            root.state,
            ProviderAttemptStateV2::AbandonedIndeterminate {
                resolution: None,
                ..
            }
        )
        || head.scope != session.scope
        || head.current_session_id != session.session_id
        || head.current_session_record_digest != session.record_digest
        || head.recovery_barrier.as_ref().is_none_or(|barrier| {
            barrier.root_attempt != witness.root_attempt
                || barrier.required_session_id != session.session_id
                || barrier.replacement_count != witness.replacement_count
                || barrier.recovery_inventory_tail.is_some()
        })
    {
        return Err(invalid());
    }
    let mut owner = Map::new();
    map_record(
        &mut owner,
        StoredRecordV2::ProviderSession {
            value: session.clone(),
        },
    )?;
    map_record(
        &mut owner,
        StoredRecordV2::ProviderHead {
            value: head.clone(),
        },
    )?;
    let mut references = Map::new();
    map_record(
        &mut references,
        StoredRecordV2::ProviderSession {
            value: predecessor.clone(),
        },
    )?;
    map_record(
        &mut references,
        StoredRecordV2::ProviderQueryAttempt {
            value: root.clone(),
        },
    )?;
    let hseq = table
        .holder_sequences
        .get(&head.scope.holder_authority_id)
        .map_or(0, |value| value.revision);
    let transaction = transaction_id(
        MutationTagV2::BarrierIdleReplacement,
        head.scope.holder_authority_id,
        head.scope.provider_authority_id,
        hseq,
        head.revision,
        None,
        None,
        None,
        None,
        Some(session.session_id),
    );
    Ok(Kind2PostimageBindings {
        owner,
        reads: read_map(state, &head)?,
        references,
        acquisition: acquisition_key(acquisition_id),
        transaction,
        session,
    })
}

fn local_bindings(
    installed: &Kind2PostimageBindings,
) -> Result<([u8; 32], [u8; 32], [u8; 32]), JournalError> {
    let mut owner = vec![Kind::BarrierIdleReplacement as u8];
    owner.extend_from_slice(&installed.transaction);
    owner.extend_from_slice(&map_bytes(
        RecordNamespace::MountSourceAcquisition,
        &installed.owner,
    )?);
    let owner_digest = commitment("owner-put-map", &owner)?;
    let artifact = commitment("local-artifact", &owner)?;
    let mut profile = vec![0, 4, 10, 40, 2, 1];
    profile.extend_from_slice(&installed.session.session_id);
    profile.extend_from_slice(&installed.transaction);
    profile.extend_from_slice(&installed.transaction);
    profile.extend_from_slice(&artifact);
    profile.extend_from_slice(&owner_digest);
    profile.push(2); // Closed Session selector.
    profile.extend_from_slice(&installed.session.session_id);
    profile.extend_from_slice(&scope_bytes(installed.session.scope));
    profile.extend_from_slice(&map_bytes(
        RecordNamespace::MountSourceAcquisition,
        &installed.reads,
    )?);
    profile.extend_from_slice(&map_bytes(
        RecordNamespace::MountSourceAcquisition,
        &installed.references,
    )?);
    profile.extend_from_slice(&0_u16.to_be_bytes());
    profile.extend_from_slice(&1_u32.to_be_bytes());
    profile.extend_from_slice(&1_u32.to_be_bytes());
    profile.extend_from_slice(&338_u64.to_be_bytes());
    profile.extend_from_slice(&0_u32.to_be_bytes());
    profile.extend_from_slice(&0_u64.to_be_bytes());
    Ok((owner_digest, artifact, commitment("profile", &profile)?))
}

pub(super) fn rejoin(
    state: &State,
    floor: &OrdinaryCapacityRecordV4,
) -> Result<BTreeSet<Vec<u8>>, JournalError> {
    checked_owner(state)?
        .1
        .into_iter()
        .find(|(current, _)| current == floor)
        .map(|(_, keys)| keys)
        .ok_or_else(invalid)
}

fn rejoin_checked(
    state: &State,
    floor: &OrdinaryCapacityRecordV4,
    table: &MountSourceAcquisitionStateV2,
) -> Result<BTreeSet<Vec<u8>>, JournalError> {
    let data = floor.data();
    if data.kind != Kind::BarrierIdleReplacement || data.profile != Profile::LocalCommittedReadback
    {
        return Err(invalid());
    }
    let session = table
        .provider_sessions
        .get(&data.owner_id)
        .ok_or_else(invalid)?
        .clone();
    let head = table
        .provider_heads
        .get(&(
            session.scope.holder_authority_id,
            session.scope.provider_authority_id,
        ))
        .ok_or_else(invalid)?
        .clone();
    let installed = installed(state, table, session, head)?;
    let (owner, artifact, profile) = local_bindings(&installed)?;
    if data.admission_transaction != installed.transaction
        || data.operation_id != installed.transaction
        || data.admission_owner_mutation_digest != owner
        || data.original_artifact_digest != artifact
        || data.remaining_profile_digest != profile
    {
        return Err(invalid());
    }
    Ok(installed
        .owner
        .keys()
        .chain(installed.reads.keys())
        .chain(installed.references.keys())
        .cloned()
        .chain(std::iter::once(installed.acquisition))
        .collect())
}

pub(super) fn pending(state: &State) -> Result<Vec<OrdinaryCapacityRecordV4>, JournalError> {
    Ok(fenced_floors(state)?
        .into_iter()
        .map(|(floor, _)| floor)
        .collect())
}

fn fenced_floors(state: &State) -> Result<FencedFloors, JournalError> {
    // The common hook also runs for journals with no Root owner. Do not impose
    // a Root graph on those journals merely to prove that no kind2 fence exists.
    let floors = kind2_floors(state)?;
    if floors.is_empty() {
        return Ok(Vec::new());
    }
    Ok(checked_owner_floors(state, floors)?.1)
}

fn kind2_floors(state: &State) -> Result<Vec<OrdinaryCapacityRecordV4>, JournalError> {
    super::capacity_reservation::accounting_reservations(state)?;
    let floors = state
        .iter()
        .filter(|((namespace, _), value)| {
            *namespace == RecordNamespace::GlobalCapacityReservation
                && value.get(8..10) == Some(&[0, 4])
        })
        .map(|((_, key), value)| {
            let floor = OrdinaryCapacityRecordV4::decode(key, value)?;
            if floor.data().kind == Kind::BarrierIdleReplacement {
                Ok(Some(floor))
            } else {
                Ok(None)
            }
        })
        .collect::<Result<Vec<_>, JournalError>>()?;
    Ok(floors.into_iter().flatten().collect())
}

pub(super) fn require_fences(
    state: &State,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    require_derived_fences(&fenced_floors(state)?, transaction)
}

fn require_derived_fences(
    floors: &[(OrdinaryCapacityRecordV4, BTreeSet<Vec<u8>>)],
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    for (_, keys) in floors {
        if transaction.records().iter().any(|record| {
            record.namespace() == RecordNamespace::MountSourceAcquisition
                && keys.contains(record.key())
        }) {
            return Err(JournalError::ProtectedBoundary);
        }
    }
    Ok(())
}

/// These variants are internal exact owner edges, not caller bypass flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Edge {
    Admission,
    InstalledDelete,
}

pub(super) fn prepare(
    state: &State,
    successor: SourceProviderSessionV2,
) -> Result<(JournalTransaction, OrdinaryCapacityRecordV4), JournalError> {
    let (checked, fences) = checked_owner(state)?;
    let table = checked.legacy();
    // No production original-native admission/envelope exists yet. Canonical
    // native DATA cannot justify an ordinary change to that original debt.
    if !checked.sidecars().is_empty()
        || state.iter().any(|((namespace, _), value)| {
            *namespace == RecordNamespace::GlobalCapacityReservation
                && value.get(8..11) == Some(&[0, 3, 40])
        })
    {
        return Err(JournalError::ProtectedBoundary);
    }
    // Other ordinary owner grammars can pin the very Head/Session changed here.
    // Their numerical floors alone do not prove independence from this edge.
    for ((namespace, key), value) in state {
        if *namespace == RecordNamespace::MountSourceAcquisition && key_kind(key).is_err() {
            return Err(JournalError::ProtectedBoundary);
        }
        if *namespace == RecordNamespace::GlobalCapacityReservation
            && value.get(8..10) == Some(&[0, 4])
            && OrdinaryCapacityRecordV4::decode(key, value)?.data().kind
                != Kind::BarrierIdleReplacement
        {
            return Err(JournalError::ProtectedBoundary);
        }
    }
    let witness = successor
        .barrier_idle_replacement
        .as_ref()
        .ok_or_else(invalid)?;
    let scope = successor.scope;
    let before = table
        .provider_heads
        .get(&(scope.holder_authority_id, scope.provider_authority_id))
        .filter(|head| **head == *witness.predecessor_head)
        .ok_or_else(invalid)?;
    let root = table
        .provider_attempts
        .get(&witness.root_attempt.id)
        .ok_or_else(invalid)?;
    let ProviderQueryOwnerV2::Acquire { acquisition_id } = root.owner else {
        return Err(invalid());
    };
    let acquisition = table
        .acquisitions
        .get(&acquisition_id)
        .ok_or_else(invalid)?;
    if table.provider_sessions.contains_key(&successor.session_id)
        || before.pending_attempt.is_some()
        || before.next_request_sequence != before.next_response_sequence
        || before.recovery_barrier.as_ref().is_none_or(|barrier| {
            barrier.root_attempt != witness.root_attempt
                || barrier.recovery_inventory_tail.is_some()
                || barrier.replacement_count.checked_add(1) != Some(witness.replacement_count)
        })
        || acquisition.phase != SourceAcquisitionPhaseV2::PendingQuery
        || acquisition.acquire_lineage.root != witness.root_attempt
        || acquisition.acquire_lineage.tail != witness.root_attempt
        || !matches!(acquisition.recovery, AcquisitionRecoveryV2::InventoryRequired { root_attempt }
            if root_attempt == witness.root_attempt)
    {
        return Err(invalid());
    }
    let mut head = before.clone();
    head.revision = head.revision.checked_add(1).ok_or_else(invalid)?;
    head.holder_authority_generation = successor.root_mount_authority_generation;
    head.holder_authority_digest = successor.root_mount_authority_digest;
    head.provider_authority_generation = successor.provider_authority_generation;
    head.provider_authority_digest = successor.provider_authority_digest;
    head.current_session_id = successor.session_id;
    head.current_session_record_digest = successor.record_digest;
    head.next_request_sequence = 1;
    head.next_response_sequence = 1;
    head.last_reconciliation = None;
    let barrier = head.recovery_barrier.as_mut().ok_or_else(invalid)?;
    barrier.required_session_id = successor.session_id;
    barrier.replacement_count = witness.replacement_count;
    let head =
        match seal_record(StoredRecordV2::ProviderHead { value: head }).map_err(|_| invalid())? {
            StoredRecordV2::ProviderHead { value } => value,
            _ => return Err(invalid()),
        };
    let (skey, svalue) = stored(StoredRecordV2::ProviderSession {
        value: successor.clone(),
    })?;
    let (hkey, hvalue) = stored(StoredRecordV2::ProviderHead {
        value: head.clone(),
    })?;
    let mut after = state.clone();
    after.insert(
        (RecordNamespace::MountSourceAcquisition, skey.clone()),
        svalue.clone(),
    );
    after.insert(
        (RecordNamespace::MountSourceAcquisition, hkey.clone()),
        hvalue.clone(),
    );
    let after_graph = graph(&after)?;
    let installed = installed(&after, after_graph.legacy(), successor, head)?;
    let (owner, artifact, profile) = local_bindings(&installed)?;
    let mut before_map = Map::new();
    before_map.insert(skey.clone(), None);
    before_map.insert(
        hkey.clone(),
        state
            .get(&(RecordNamespace::MountSourceAcquisition, hkey.clone()))
            .cloned(),
    );
    let mut reads = read_map(state, before)?;
    for (key, value) in &installed.references {
        reads.insert(key.clone(), value.clone());
    }
    map_record(
        &mut reads,
        StoredRecordV2::Acquisition {
            value: acquisition.clone(),
        },
    )?;
    let mut cut = vec![2];
    cut.extend_from_slice(&installed.transaction);
    cut.extend_from_slice(&map_bytes(
        RecordNamespace::MountSourceAcquisition,
        &before_map,
    )?);
    cut.extend_from_slice(&map_bytes(RecordNamespace::MountSourceAcquisition, &reads)?);
    let floors: Map = state
        .iter()
        .filter(|((namespace, _), _)| *namespace == RecordNamespace::GlobalCapacityReservation)
        .map(|((_, key), value)| (key.clone(), Some(value.clone())))
        .collect();
    let native: Map = state
        .iter()
        .filter(|((namespace, key), _)| {
            *namespace == RecordNamespace::MountSourceAcquisition && key_kind(key).is_err()
        })
        .map(|((_, key), value)| (key.clone(), Some(value.clone())))
        .collect();
    let mut union = map_bytes(RecordNamespace::GlobalCapacityReservation, &floors)?;
    union.extend_from_slice(&map_bytes(
        RecordNamespace::MountSourceAcquisition,
        &native,
    )?);
    let floor = OrdinaryCapacityRecordV4::new(OrdinaryCapacityDataV4 {
        kind: Kind::BarrierIdleReplacement,
        profile: Profile::LocalCommittedReadback,
        owner_id: installed.session.session_id,
        original_owner_cut_digest: commitment("owner-before-cut", &cut)?,
        operation_id: installed.transaction,
        original_artifact_digest: artifact,
        admission_owner_mutation_digest: owner,
        admission_native_preservation_union_digest: commitment("native-union", &union)?,
        remaining_transactions: 1,
        remaining_record_frames: 1,
        remaining_append_bytes: 338,
        maximum_retained_growth_entries: 0,
        maximum_retained_growth_bytes: 0,
        admission_transaction: installed.transaction,
        remaining_profile_digest: profile,
    })?;
    let transaction = JournalTransaction::new(
        installed.transaction,
        vec![
            JournalRecord::put(RecordNamespace::MountSourceAcquisition, skey, svalue),
            JournalRecord::put(RecordNamespace::MountSourceAcquisition, hkey, hvalue),
            floor.to_journal_record(),
        ],
    )?;
    require_derived_fences(&fences, &transaction)?;
    Ok((transaction, floor))
}

pub(super) fn settlement(
    floor: &OrdinaryCapacityRecordV4,
) -> Result<JournalTransaction, JournalError> {
    let data = floor.data();
    let mut payload = floor.reservation_id().to_vec();
    payload.extend_from_slice(&data.admission_transaction);
    payload.extend_from_slice(&data.admission_owner_mutation_digest);
    payload.extend_from_slice(&data.remaining_profile_digest);
    let hash = commitment("local-settlement-tx", &payload)?;
    let mut tx = [0; 16];
    tx.copy_from_slice(&hash[..16]);
    JournalTransaction::new(
        tx,
        vec![JournalRecord::delete(
            RecordNamespace::GlobalCapacityReservation,
            floor.to_journal_record().key().to_vec(),
        )],
    )
}

pub(super) fn validate_edge(
    state: &State,
    transaction: &JournalTransaction,
    edge: Edge,
) -> Result<Option<[u8; 32]>, JournalError> {
    match edge {
        Edge::Admission => {
            let first = transaction.records().first().ok_or_else(invalid)?;
            let record = aos_sandbox_protocol::mount_source_acquisition_state::decode_mount_source_state_record_v2(
                first.key(), first.value().ok_or_else(invalid)?).map_err(|_| invalid())?;
            let StoredRecordV2::ProviderSession { value } = record else {
                return Err(invalid());
            };
            if prepare(state, value)?.0 != *transaction {
                return Err(invalid());
            }
            Ok(None)
        }
        Edge::InstalledDelete => {
            let record = transaction.records().first().ok_or_else(invalid)?;
            let floor = checked_owner(state)?
                .1
                .into_iter()
                .find(|(floor, _)| floor.to_journal_record().key() == record.key())
                .map(|(floor, _)| floor)
                .ok_or_else(invalid)?;
            if settlement(&floor)? != *transaction {
                return Err(invalid());
            }
            Ok(Some(floor.reservation_id()))
        }
    }
}

/// Rechecks kind2's logical edges and retained dependency fences during replay.
pub(super) fn validate_replayed_transaction(
    state: &State,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    let mut edge = None;
    for record in transaction.records() {
        if record.namespace() != RecordNamespace::GlobalCapacityReservation {
            continue;
        }
        let value = record.value().or_else(|| {
            state
                .get(&(record.namespace(), record.key().to_vec()))
                .map(Vec::as_slice)
        });
        let Some(value) = value else { continue };
        if value.get(8..10) != Some(&[0, 4]) {
            continue;
        }
        let floor = OrdinaryCapacityRecordV4::decode(record.key(), value)?;
        if floor.data().kind != Kind::BarrierIdleReplacement {
            continue;
        }
        if edge.is_some() {
            return Err(invalid());
        }
        edge = Some(if record.value().is_some() {
            Edge::Admission
        } else {
            Edge::InstalledDelete
        });
    }
    if let Some(edge) = edge {
        validate_edge(state, transaction, edge)?;
    } else {
        require_fences(state, transaction)?;
    }
    Ok(())
}
