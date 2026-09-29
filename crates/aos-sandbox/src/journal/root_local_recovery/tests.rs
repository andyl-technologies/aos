//! Canonical kind2 DATA edges, dependency fences and physical replay vectors.
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
fn recovery() -> (State, SourceProviderSessionV2) {
    let original = fixture::signed_session([19; 16], 31);
    let records =
        fixture::initial_signed_graph_with_catalog(original.clone(), 500, [62; 32], [63; 32], None);
    let mut state = State::new();
    for record in records {
        put(&mut state, record);
    }
    let table = graph(&state).unwrap().legacy().clone();
    let mut root = table.provider_attempts.values().next().unwrap().clone();
    let mut row = table.acquisitions.values().next().unwrap().clone();
    let mut head = table.provider_heads.values().next().unwrap().clone();
    let mut replacement = fixture::signed_session([32; 16], 32);
    replacement.predecessor_session_id = Some(original.session_id);
    let StoredRecordV2::ProviderSession { value: replacement } =
        sealed(StoredRecordV2::ProviderSession { value: replacement })
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
    root.revision += 1;
    root.state = ProviderAttemptStateV2::AbandonedIndeterminate {
        dead_execution: death,
        successor_session_id: replacement.session_id,
        recovery_root_attempt_id: root.attempt_id,
        outcome_may_exist: true,
        resolution: None,
    };
    let StoredRecordV2::ProviderQueryAttempt { value: root } =
        sealed(StoredRecordV2::ProviderQueryAttempt { value: root })
    else {
        panic!("Attempt")
    };
    let reference = RecordRefV2 {
        id: root.attempt_id,
        revision: root.revision,
        record_digest: root.record_digest,
    };
    row.revision += 1;
    row.acquire_lineage.root = reference;
    row.acquire_lineage.tail = reference;
    row.recovery = AcquisitionRecoveryV2::InventoryRequired {
        root_attempt: reference,
    };
    head.revision += 1;
    head.current_session_id = replacement.session_id;
    head.current_session_record_digest = replacement.record_digest;
    head.next_request_sequence = 1;
    head.next_response_sequence = 1;
    head.pending_attempt = None;
    head.recovery_barrier = Some(RecoveryBarrierV2 {
        root_attempt: reference,
        required_session_id: replacement.session_id,
        replacement_count: 1,
        baseline_inventory_ordinal: head.inventory_observation_ordinal,
        recovery_inventory_tail: None,
    });
    put(
        &mut state,
        StoredRecordV2::ProviderSession {
            value: replacement.clone(),
        },
    );
    put(
        &mut state,
        StoredRecordV2::ProviderQueryAttempt { value: root },
    );
    put(
        &mut state,
        sealed(StoredRecordV2::Acquisition { value: row }),
    );
    put(
        &mut state,
        sealed(StoredRecordV2::ProviderHead { value: head }),
    );
    let table = graph(&state).unwrap().legacy().clone();
    let head = table.provider_heads.values().next().unwrap().clone();
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
fn unsupported_kind5_overlap_refuses_before_head_mutation() {
    let (mut state, successor) = recovery();
    let (_, proposed) = prepare(&state, successor.clone()).unwrap();
    // Canonical kind5 DATA stands for the unsupported retained owner grammar;
    // it is deliberately not a qualified protected kind5 producer proof.
    let mut data = proposed.data();
    data.kind = Kind::DeadReplacement;
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
