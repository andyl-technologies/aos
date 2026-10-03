//! Canonical kind2/kind5 DATA edges, dependency fences and replay vectors.
//!
//! These vectors borrow the existing signed fixture, not protected custody. No
//! live Security, fixed writer or private Mount installation is manufactured.

use aos_sandbox_protocol as protocol;
use protocol::mount_source_acquisition_state::format::death_digest;
use protocol::mount_source_acquisition_state::*;
use tempfile::NamedTempFile;

#[path = "../../../../aos-sandbox-protocol/src/mount_source_acquisition_state/native_held_completion/tests/fixture.rs"]
mod fixture;

use super::*;
use crate::journal::{
    JournalLimits, append_and_sync, encode_transaction, encoded_transaction_append_bytes, replay,
    validate_reserved_capacity, write_compacted,
};

fn put(state: &mut State, record: StoredRecordV2) {
    let (key, value) = stored(record).unwrap();
    state.insert((RecordNamespace::MountSourceAcquisition, key), value);
}

fn sealed(record: StoredRecordV2) -> StoredRecordV2 {
    seal_record(record).unwrap()
}

// This is the existing four-row dead-replacement shape, with genuine signed
// initial records. It supplies canonical DATA only, not a death capability.
fn reserved_dead() -> (
    State,
    SourceProviderSessionV2,
    DeadProviderExecutionProjectionV2,
) {
    let original = fixture::signed_session([19; 16], 31);
    let records =
        fixture::initial_signed_graph_with_catalog(original.clone(), 500, [62; 32], [63; 32], None);
    let mut state = State::new();
    for record in records {
        put(&mut state, record);
    }
    let mut successor = fixture::signed_session([32; 16], 32);
    successor.predecessor_session_id = Some(original.session_id);
    let StoredRecordV2::ProviderSession { value: successor } =
        sealed(StoredRecordV2::ProviderSession { value: successor })
    else {
        panic!("Session")
    };
    let mut death = DeadProviderExecutionProjectionV2 {
        proof_kind: DeadProviderExecutionProofKindV2::PidfdExited,
        old_session_id: original.session_id,
        old_session_record_digest: original.record_digest,
        node_id: original.node_id,
        old_kernel_boot_id: original.kernel_boot_id,
        provider_process_instance: original.provider_process_instance,
        process_execution_digest: original.provider_execution.process_execution_digest,
        observed_kernel_boot_id: original.kernel_boot_id,
        death_evidence_digest: [0; 32],
    };
    death.death_evidence_digest = death_digest(&death).unwrap();
    (state, successor, death)
}

fn recovery() -> (State, SourceProviderSessionV2) {
    let (mut state, replacement, death) = reserved_dead();
    let table = graph(&state).unwrap().legacy().clone();
    for record in prepare_dead_replacement_v2(&table, replacement.clone(), death).unwrap() {
        put(&mut state, record);
    }
    let table = graph(&state).unwrap().legacy().clone();
    let head = table.provider_heads.values().next().unwrap().clone();
    let reference = head.recovery_barrier.as_ref().unwrap().root_attempt;
    let mut successor = fixture::signed_session([33; 16], 33);
    successor.predecessor_session_id = Some(replacement.session_id);
    successor.barrier_idle_replacement = Some(BarrierIdleReplacementWitnessV2 {
        root_attempt: reference,
        predecessor_head: Box::new(head),
        replacement_count: 2,
        predecessor_observation: BarrierIdlePredecessorObservationV2::Live,
    });
    let StoredRecordV2::ProviderSession { value: successor } =
        sealed(StoredRecordV2::ProviderSession { value: successor })
    else {
        panic!("Session")
    };
    (state, successor)
}

fn apply(state: &mut State, transaction: &JournalTransaction) {
    for record in transaction.records() {
        let key = (record.namespace(), record.key().to_vec());
        if let Some(value) = record.value() {
            state.insert(key, value.to_vec());
        } else {
            state.remove(&key);
        }
    }
}

fn native_floor(
    purpose: super::super::capacity_reservation::native_held::NativeHeldCapacityPurposeV3,
) -> JournalRecord {
    use super::super::capacity_reservation::native_held::{
        NativeHeldCapacityRecordV3, NativeHeldCapacityRequestV3,
    };
    NativeHeldCapacityRecordV3::new(
        NativeHeldCapacityRequestV3 {
            purpose,
            owner_id: [71; 32],
            owner_digest: [72; 32],
            operation_id: [73; 16],
            artifact_digest: [74; 32],
            checkpoint_digest: [75; 32],
            chain_head_digest: [76; 32],
            future_transactions: 1,
            terminal_records: 1,
            terminal_bytes: 338,
            poison_records: 1,
            poison_bytes: 338,
        },
        [77; 16],
    )
    .unwrap()
    .to_journal_record()
}

#[test]
fn canonical_native_data_does_not_justify_original_root_debt() {
    use super::super::capacity_reservation::native_held::NativeHeldCapacityPurposeV3;
    let (mut state, successor) = recovery();
    let floor = native_floor(NativeHeldCapacityPurposeV3::Root);
    state.insert(
        (floor.namespace(), floor.key().to_vec()),
        floor.value().unwrap().to_vec(),
    );
    assert!(matches!(
        prepare(&state, successor),
        Err(JournalError::ProtectedBoundary)
    ));
}

#[test]
fn unrelated_native_floor_remains_byte_exact_and_is_counted() {
    use super::super::capacity_reservation::native_held::NativeHeldCapacityPurposeV3;
    let (mut state, successor) = recovery();
    let unrelated = native_floor(NativeHeldCapacityPurposeV3::Provider);
    let key = (unrelated.namespace(), unrelated.key().to_vec());
    state.insert(key.clone(), unrelated.value().unwrap().to_vec());
    let (admission, own) = prepare(&state, successor).unwrap();
    let mut limits = JournalLimits::default();
    limits.maximum_transactions = 2;
    assert!(
        validate_reserved_capacity(
            &state,
            0,
            admission.records(),
            None,
            0,
            1,
            limits,
            Some(Edge::Admission)
        )
        .is_err()
    );
    apply(&mut state, &admission);
    apply(&mut state, &settlement(&own).unwrap());
    assert_eq!(state.get(&key).map(Vec::as_slice), unrelated.value());
}

#[test]
fn canonical_admission_and_own_delete_rederive_exact_maps() {
    let (before, successor) = recovery();
    let (admission, floor) = prepare(&before, successor.clone()).unwrap();
    assert_eq!(admission.records().len(), 3);
    assert_eq!(
        validate_edge(&before, &admission, Edge::Admission).unwrap(),
        None
    );
    let mut after = before.clone();
    apply(&mut after, &admission);
    assert_eq!(pending(&after).unwrap(), vec![floor.clone()]);
    assert!(prepare(&after, successor).is_err());

    let deletion = settlement(&floor).unwrap();
    assert_eq!(encoded_transaction_append_bytes(&deletion).unwrap(), 338);
    assert_eq!(
        validate_edge(&after, &deletion, Edge::InstalledDelete).unwrap(),
        Some(floor.reservation_id())
    );
    let owner_before: Vec<_> = after
        .iter()
        .filter(|((ns, _), _)| *ns != RecordNamespace::GlobalCapacityReservation)
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    apply(&mut after, &deletion);
    assert!(pending(&after).unwrap().is_empty());
    assert_eq!(owner_before, after.into_iter().collect::<Vec<_>>());
}

#[test]
fn every_postimage_read_reference_and_derived_acquisition_key_is_fenced() {
    let (mut state, successor) = recovery();
    let (admission, floor) = prepare(&state, successor).unwrap();
    apply(&mut state, &admission);

    for key in rejoin(&state, &floor).unwrap() {
        let deletion = JournalTransaction::new(
            [81; 16],
            vec![JournalRecord::delete(
                RecordNamespace::MountSourceAcquisition,
                key.clone(),
            )],
        )
        .unwrap();
        assert!(require_fences(&state, &deletion).is_err());
        let value = state
            .get(&(RecordNamespace::MountSourceAcquisition, key.clone()))
            .cloned()
            .unwrap_or_else(|| vec![1]);
        let unchanged_put = JournalTransaction::new(
            [82; 16],
            vec![JournalRecord::put(
                RecordNamespace::MountSourceAcquisition,
                key,
                value,
            )],
        )
        .unwrap();
        assert!(require_fences(&state, &unchanged_put).is_err());
    }
}

#[test]
fn unsupported_kind3_overlap_refuses_before_head_mutation() {
    let (mut state, successor) = recovery();
    let (_, proposed) = prepare(&state, successor.clone()).unwrap();
    // This other local owner grammar is not implemented by the closed writer.
    let mut data = proposed.data();
    data.kind = Kind::BackendRecoveryReplacement;
    data.owner_id = graph(&state)
        .unwrap()
        .legacy()
        .provider_attempts
        .keys()
        .next()
        .copied()
        .unwrap();
    let record = OrdinaryCapacityRecordV4::new(data)
        .unwrap()
        .to_journal_record();
    state.insert(
        (record.namespace(), record.key().to_vec()),
        record.value().unwrap().to_vec(),
    );

    assert!(matches!(
        prepare(&state, successor),
        Err(JournalError::ProtectedBoundary)
    ));
}

#[test]
fn kind5_atomic_first_admission_fences_and_own_delete_are_exact() {
    let (before, successor, death) = reserved_dead();
    let (admission, floor) =
        dead_replacement::prepare(&before, successor.clone(), death.clone()).unwrap();
    assert_eq!(admission.records().len(), 5);
    assert_eq!(floor.data().kind, Kind::DeadReplacement);
    assert_eq!(floor.data().profile, Profile::LocalCommittedReadback);
    assert_eq!(
        validate_edge(&before, &admission, Edge::DeadAdmission).unwrap(),
        None
    );
    let mut state = before.clone();
    apply(&mut state, &admission);
    assert_eq!(pending(&state).unwrap(), vec![floor.clone()]);
    assert!(dead_replacement::prepare(&state, successor, death).is_err());

    let (_, barrier_successor) = recovery();
    assert!(prepare(&state, barrier_successor).is_err());
    for key in rejoin(&state, &floor).unwrap() {
        let deletion = JournalTransaction::new(
            [89; 16],
            vec![JournalRecord::delete(
                RecordNamespace::MountSourceAcquisition,
                key,
            )],
        )
        .unwrap();
        assert!(require_fences(&state, &deletion).is_err());
        assert!(validate_replayed_transaction(&state, &deletion).is_err());
    }
    let deletion = settlement(&floor).unwrap();
    assert_eq!(encoded_transaction_append_bytes(&deletion).unwrap(), 338);
    assert_eq!(
        validate_edge(&state, &deletion, Edge::InstalledDelete).unwrap(),
        Some(floor.reservation_id())
    );
    apply(&mut state, &deletion);
    assert!(pending(&state).unwrap().is_empty());
}

#[test]
fn kind5_wrong_death_or_original_native_debt_refuses_before_admission() {
    let (mut state, successor, mut death) = reserved_dead();
    death.old_session_record_digest[0] ^= 1;
    death.death_evidence_digest = death_digest(&death).unwrap();
    assert!(dead_replacement::prepare(&state, successor, death).is_err());
    let (_, successor, death) = reserved_dead();
    let floor = native_floor(
        super::super::capacity_reservation::native_held::NativeHeldCapacityPurposeV3::Root,
    );
    state.insert(
        (floor.namespace(), floor.key().to_vec()),
        floor.value().unwrap().to_vec(),
    );
    assert!(matches!(
        dead_replacement::prepare(&state, successor, death),
        Err(JournalError::ProtectedBoundary)
    ));
}

#[test]
fn kind5_counts_new_floor_and_retains_unrelated_native_promises() {
    use super::super::capacity_reservation::native_held::NativeHeldCapacityPurposeV3;
    let (mut state, successor, death) = reserved_dead();
    let unrelated = native_floor(NativeHeldCapacityPurposeV3::Provider);
    let key = (unrelated.namespace(), unrelated.key().to_vec());
    state.insert(key.clone(), unrelated.value().unwrap().to_vec());
    let (admission, floor) = dead_replacement::prepare(&state, successor, death).unwrap();
    let mut limits = JournalLimits::default();
    limits.maximum_transactions = 2;
    assert!(
        validate_reserved_capacity(
            &state,
            0,
            admission.records(),
            None,
            0,
            1,
            limits,
            Some(Edge::DeadAdmission),
        )
        .is_err()
    );
    apply(&mut state, &admission);
    apply(&mut state, &settlement(&floor).unwrap());
    assert_eq!(state.get(&key).map(Vec::as_slice), unrelated.value());
}

#[test]
fn kind5_compaction_preserves_readback_and_logical_replay_rejects_fenced_put() {
    let (before, successor, death) = reserved_dead();
    let (admission, floor) = dead_replacement::prepare(&before, successor, death).unwrap();
    let mut file = NamedTempFile::new().unwrap();
    write_compacted(file.as_file_mut(), &before, JournalLimits::default()).unwrap();
    let initial = replay(file.as_file_mut(), JournalLimits::default()).unwrap();
    append_and_sync(
        file.as_file_mut(),
        &encode_transaction(&admission, initial.next_sequence).unwrap(),
    )
    .unwrap();
    let admitted = replay(file.as_file_mut(), JournalLimits::default()).unwrap();
    assert_eq!(pending(&admitted.state).unwrap(), vec![floor.clone()]);
    let mut compact = NamedTempFile::new().unwrap();
    write_compacted(
        compact.as_file_mut(),
        &admitted.state,
        JournalLimits::default(),
    )
    .unwrap();
    let recovered = replay(compact.as_file_mut(), JournalLimits::default()).unwrap();
    assert_eq!(recovered.state, admitted.state);
    assert_eq!(pending(&recovered.state).unwrap(), vec![floor.clone()]);
    let key = rejoin(&recovered.state, &floor)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let value = recovered
        .state
        .get(&(RecordNamespace::MountSourceAcquisition, key.clone()))
        .unwrap()
        .clone();
    let mutation = JournalTransaction::new(
        [90; 16],
        vec![JournalRecord::put(
            RecordNamespace::MountSourceAcquisition,
            key,
            value,
        )],
    )
    .unwrap();
    append_and_sync(
        compact.as_file_mut(),
        &encode_transaction(&mutation, recovered.next_sequence).unwrap(),
    )
    .unwrap();
    assert!(replay(compact.as_file_mut(), JournalLimits::default()).is_err());
}

#[test]
fn coupled_admission_accounts_own_floor_physical_postimage_and_remaining_credit() {
    let (state, successor) = recovery();
    let (admission, _) = prepare(&state, successor).unwrap();
    let mut limits = JournalLimits::default();
    limits.maximum_materialized_records = state.len() + 2;
    assert!(
        validate_reserved_capacity(
            &state,
            0,
            admission.records(),
            None,
            0,
            1,
            limits,
            Some(Edge::Admission)
        )
        .is_err()
    );
    limits.maximum_materialized_records += 1;
    assert!(
        validate_reserved_capacity(
            &state,
            0,
            admission.records(),
            None,
            0,
            1,
            limits,
            Some(Edge::Admission)
        )
        .is_ok()
    );
}

#[test]
fn compacted_readback_is_exact_and_later_logical_acquisition_delete_refuses() {
    let (mut state, successor) = recovery();
    let (admission, floor) = prepare(&state, successor).unwrap();
    apply(&mut state, &admission);
    let mut file = NamedTempFile::new().unwrap();
    write_compacted(file.as_file_mut(), &state, JournalLimits::default()).unwrap();
    let compacted = replay(file.as_file_mut(), JournalLimits::default()).unwrap();
    assert_eq!(compacted.state, state);
    assert_eq!(pending(&compacted.state).unwrap(), vec![floor.clone()]);

    let table = graph(&state).unwrap();
    let key = acquisition_key(*table.legacy().acquisitions.keys().next().unwrap());
    let mutation = JournalTransaction::new(
        [88; 16],
        vec![JournalRecord::delete(
            RecordNamespace::MountSourceAcquisition,
            key,
        )],
    )
    .unwrap();
    let frames = encode_transaction(&mutation, compacted.next_sequence).unwrap();
    append_and_sync(file.as_file_mut(), &frames).unwrap();
    assert!(replay(file.as_file_mut(), JournalLimits::default()).is_err());
}

#[test]
fn ordinary_logical_admission_and_delete_replay_after_initial_snapshot() {
    let (before, successor) = recovery();
    let (admission, floor) = prepare(&before, successor).unwrap();
    let mut file = NamedTempFile::new().unwrap();
    write_compacted(file.as_file_mut(), &before, JournalLimits::default()).unwrap();
    let prefix = replay(file.as_file_mut(), JournalLimits::default()).unwrap();
    append_and_sync(
        file.as_file_mut(),
        &encode_transaction(&admission, prefix.next_sequence).unwrap(),
    )
    .unwrap();
    let admitted = replay(file.as_file_mut(), JournalLimits::default()).unwrap();
    assert_eq!(pending(&admitted.state).unwrap(), vec![floor.clone()]);
    let deletion = settlement(&floor).unwrap();
    append_and_sync(
        file.as_file_mut(),
        &encode_transaction(&deletion, admitted.next_sequence).unwrap(),
    )
    .unwrap();
    let settled = replay(file.as_file_mut(), JournalLimits::default()).unwrap();
    assert!(pending(&settled.state).unwrap().is_empty());
}
