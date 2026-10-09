//! UNRUN real coupled-floor framing and original witness-sequence vectors.
//!
//! These use canonical signed DATA and the actual pure funded edge. They do not
//! construct a protected writer, run journal I/O or prove runtime qualification.

use aos_sandbox_protocol as protocol;
use aos_sandbox_source_provider_protocol::native_held_completion::frame::NativeHeldSectionV1;

use super::*;
use crate::journal::capacity_reservation::native_held::NativeRootDataFixture;

#[path = "../../../../../aos-sandbox-protocol/src/mount_source_acquisition_state/native_held_completion/tests/fixture.rs"]
mod fixture;

/// Derives pure canonical DATA with the existing exact original floor.
pub(in crate::journal::root_original_native) fn funded_state(
    graph: &RootNativeHeldGraphV2,
    prepared: PreparedNativeHeldControlV1,
) -> State {
    let attempt = *prepared.scope().mount_attempt.as_bytes();
    let floor = OriginalRootCapacityRecordV5::for_graph(
        graph,
        prepared,
        graph.sidecars()[&attempt].admission_cut().clone(),
        JournalLimits::default(),
    )
    .unwrap()
    .to_journal_record()
    .unwrap();
    let mut state: State = graph
        .canonical_records()
        .iter()
        .map(|(key, value)| ((RecordNamespace::MountSourceAcquisition, key.clone()), value.clone()))
        .collect();
    state.insert(
        (floor.namespace(), floor.key().to_vec()),
        floor.value().unwrap().to_vec(),
    );
    state
}

/// Derives the existing canonical Pending first-R DATA for sibling vectors.
pub(in crate::journal::root_original_native) fn pending_owners(
    original: &NativeRootDataFixture,
    sequence: u64,
) -> JournalTransaction {
    let before = original.graph(true, false);
    let old = &before.sidecars()[&original.attempt];
    let root1 = old
        .suffix()
        .control(NativeHeldControlKindV1::RootPrepared)
        .unwrap();
    let rows = fixture::pending_original_rows(&original.rows);
    let legacy = validate_mount_source_state_graph_v2(
        rows.iter().map(|(key, value)| (key.as_slice(), value.as_slice())),
    )
    .unwrap();
    let cut = RootNativeCutV1::capture(
        RootNativeCutKindV1::Disposition,
        [161; 16],
        &legacy,
        original.attempt,
    )
    .unwrap();
    let captured = cut.reconstruct(&legacy, original.attempt).unwrap();
    let r = RootNativeDispositionAssertionV1 {
        disposition: NativeHeldDispositionV1::Closed,
        observation: RootNativeObservationV1::PreparedOnly,
        scope: *old.original_scope(),
        source_artifact: ObjectDigest::from_bytes([0; 32]),
        descriptor_commitment: ObjectDigest::from_bytes([0; 32]),
        records: captured.witnesses().clone(),
    };
    let NativeHeldOwnerWitnessV1::Root(mut witness) = NativeHeldOwnerWitnessV1::from_canonical_bytes(
        NativeHeldOwnerV1::Root,
        root1.section(Tag::Witness).unwrap(),
    )
    .unwrap()
    else {
        panic!("Root1 witness");
    };
    witness.journal_sequence = sequence;
    witness.records = r.records.clone();
    let unsigned = PreparedNativeHeldControlV1::new(
        NativeHeldControlKindV1::RootClosed,
        r.scope,
        root1.digest(),
        vec![
            NativeHeldSectionV1::new(
                Tag::Witness,
                NativeHeldOwnerWitnessV1::Root(witness).to_canonical_bytes().unwrap(),
            )
            .unwrap(),
            NativeHeldSectionV1::new(Tag::RootPrepared, root1.to_canonical_bytes()).unwrap(),
            NativeHeldSectionV1::new(
                Tag::RootDispositionAssertion,
                r.to_canonical_bytes().unwrap().to_vec(),
            )
            .unwrap(),
        ],
        root1.prepared().signer().clone(),
    )
    .unwrap();
    let sidecar = RootNativeHeldSidecarV2::new(
        *old.original_scope(),
        [0; 16],
        Some(r),
        None,
        None,
        NativeHeldCompletionSuffixV1::new(
            NativeHeldOwnerV1::Root,
            10,
            old.suffix().flight(),
            Some(unsigned),
            old.suffix().controls().to_vec(),
        )
        .unwrap(),
        old.admission_cut().clone(),
        Some(cut),
        None,
    )
    .unwrap();
    let mut records: Vec<_> = rows.iter()
        .filter(|(key, value)| before.canonical_records().get(*key) != Some(*value))
        .map(|(key, value)| JournalRecord::put(RecordNamespace::MountSourceAcquisition, key.clone(), value.clone()))
        .collect();
    records.push(JournalRecord::put(
        RecordNamespace::MountSourceAcquisition,
        native_root_sidecar_key_v2(original.attempt).unwrap(),
        sidecar.to_canonical_bytes().unwrap(),
    ));
    JournalTransaction::new([161; 16], records).unwrap()
}

#[test]
fn actual_pending_coupled_floor_delete_put_preserves_owner_projection_and_exact_sequence() {
    let original = NativeRootDataFixture::new();
    let before = original.graph(true, false);
    let state = funded_state(&before, original.prepared());
    let sequence = 900;
    let owners = pending_owners(&original, sequence);
    let (coupled, successor, _) =
        continuation(&state, &owners, original.attempt, JournalLimits::default()).unwrap();

    assert_eq!(coupled.records().len(), 6);
    assert_eq!(successor.unwrap().request().future_transactions, 3);
    assert!(coupled.records().iter().any(|record| {
        record.namespace() == RecordNamespace::GlobalCapacityReservation && record.value().is_none()
    }));
    assert!(coupled.records().iter().any(|record| {
        record.namespace() == RecordNamespace::GlobalCapacityReservation && record.value().is_some()
    }));
    assert!(validate_pending_sequence(&state, &coupled, original.attempt, sequence).is_ok());
    assert!(validate_pending_sequence(&state, &coupled, original.attempt, sequence - 1).is_err());
    assert!(validate_pending_sequence(&state, &coupled, original.attempt, sequence + 1).is_err());
    assert!(validate_replayed_transaction(&state, &coupled, JournalLimits::default(), sequence).unwrap());
    assert!(validate_replayed_transaction(&state, &coupled, JournalLimits::default(), sequence - 1).is_err());
}

#[test]
fn pending_floor_does_not_reserve_consumed_owners_again_after_head_record_movement() {
    use aos_sandbox_protocol::mount_source_acquisition_state::{
        StoredRecordV2, encode_mount_source_state_record_v2, seal_record,
    };

    let original = NativeRootDataFixture::new();
    let before = original.graph(true, false);
    let state = funded_state(&before, original.prepared());
    let owners = pending_owners(&original, 900);
    let mut state = apply(&state, owners.records()).unwrap();
    let pending = graph(&state).unwrap();
    let mut head = pending.legacy().provider_heads.values().next().unwrap().clone();
    // This independently valid Head DATA has new canonical bytes. No new
    // attempt, custody or request is created by the fixture.
    head.revision += 1;
    let head = seal_record(StoredRecordV2::ProviderHead { value: head }).unwrap();
    let (key, value) = encode_mount_source_state_record_v2(&head).unwrap();
    state.insert((RecordNamespace::MountSourceAcquisition, key), value);

    let moved = graph(&state).unwrap();
    let sidecar = &moved.sidecars()[&original.attempt];
    let floor = OriginalRootCapacityRecordV5::for_graph(
        &moved,
        original.prepared(),
        sidecar.admission_cut().clone(),
        JournalLimits::default(),
    )
    .unwrap();

    assert_eq!(floor.request().future_transactions, 3);
    assert_eq!(floor.request().terminal_records, 8);
    assert_ne!(
        sidecar.disposition_cut().unwrap().head(),
        moved.legacy().provider_heads.values().next().unwrap(),
    );
}

#[test]
fn old_root1_store_coupled_floor_projection_remains_accepted() {
    let original = NativeRootDataFixture::new();
    let phase0 = original.graph(false, false);
    let phase1 = original.graph(true, false);
    let state = funded_state(&phase0, original.prepared());
    let key = native_root_sidecar_key_v2(original.attempt).unwrap();
    let owners = JournalTransaction::new(
        [102; 16],
        vec![JournalRecord::put(
            RecordNamespace::MountSourceAcquisition,
            key.clone(),
            phase1.canonical_records()[&key].clone(),
        )],
    )
    .unwrap();
    let (coupled, _, _) =
        continuation(&state, &owners, original.attempt, JournalLimits::default()).unwrap();

    assert_eq!(coupled.records().len(), 3);
    assert!(validate_pending_sequence(&state, &coupled, original.attempt, 900).is_ok());
    assert!(validate_replayed_transaction(&state, &coupled, JournalLimits::default(), 900).unwrap());
}
