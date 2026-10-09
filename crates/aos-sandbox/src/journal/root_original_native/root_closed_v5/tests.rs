//! UNRUN canonical original8 store, coupled funding and replay refusal vectors.
//!
//! Existing P fixtures supply signed DATA only. No protected writer, received
//! token, original clock/guard or carrier is constructed by this module.

use aos_sandbox_source_provider_protocol::native_held_completion::{
    NativeHeldSectionTagV1 as Tag,
    frame::NativeHeldSectionV1,
    witness::NativeHeldOwnerWitnessV1,
};
use ed25519_dalek::{Signer as _, SigningKey};

use super::*;
use crate::journal::capacity_reservation::native_held::NativeRootDataFixture;
use crate::journal::root_original_native::pending_v5::{
    tests::{funded_state, pending_owners},
    validate_pending_sequence,
};

struct PendingStoreData {
    state: State,
    graph: RootNativeHeldGraphV2,
    floor: OriginalRootCapacityRecordV5,
    signed: SignedNativeHeldControlV1,
    attempt: [u8; 32],
}

/// Materializes already-derived coupled owner/floor records as test DATA only.
fn materialize_coupled_data(before: &State, records: &[JournalRecord]) -> State {
    let mut after = before.clone();
    for record in records {
        let key = (record.namespace(), record.key().to_vec());
        match (record.namespace(), record.value()) {
            (RecordNamespace::MountSourceAcquisition, Some(bytes))
            | (RecordNamespace::GlobalCapacityReservation, Some(bytes)) => {
                after.insert(key, bytes.to_vec());
            }
            (RecordNamespace::GlobalCapacityReservation, None) => {
                assert!(after.remove(&key).is_some(), "coupled old floor exists");
            }
            _ => panic!("coupled DATA has only owner PUTs and floor DEL/PUTs"),
        }
    }

    after
}

impl PendingStoreData {
    fn new() -> Self {
        let original = NativeRootDataFixture::new();
        let phase1 = original.graph(true, false);
        let before = funded_state(&phase1, original.prepared());
        let pending = pending_owners(&original, 900);
        let (transaction, floor, _) = continuation(
            &before,
            &pending,
            original.attempt,
            JournalLimits::default(),
        )
        .unwrap();
        assert!(validate_pending_sequence(&before, &transaction, original.attempt, 900).is_ok());

        let state = materialize_coupled_data(&before, transaction.records());
        let graph = graph(&state).unwrap();
        let unsigned = graph.sidecars()[&original.attempt]
            .suffix()
            .prepared()
            .unwrap()
            .clone();
        let signature = SigningKey::from_bytes(&[12; 32])
            .sign(&unsigned.signature_message())
            .to_bytes();

        Self {
            state,
            graph,
            floor: floor.unwrap(),
            signed: unsigned.with_signature(signature),
            attempt: original.attempt,
        }
    }

    fn owners(&self) -> JournalTransaction {
        root_closed_owners(&self.graph, self.attempt, &self.floor, &self.signed).unwrap()
    }
}

/// Reuses the existing original8 DATA producer for sibling Query vectors only.
pub(in crate::journal) fn phase11_funded_data() -> State {
    let data = PendingStoreData::new();
    let (transaction, _, _) = continuation(
        &data.state, &data.owners(), data.attempt, JournalLimits::default(),
    ).unwrap();
    materialize_coupled_data(&data.state, transaction.records())
}

#[test]
fn exact_store_has_three_records_native_two_and_preserves_first_r_witness() {
    let data = PendingStoreData::new();
    let owners = data.owners();
    let (transaction, successor, _) = continuation(
        &data.state,
        &owners,
        data.attempt,
        JournalLimits::default(),
    )
    .unwrap();

    let records = transaction.records();
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].namespace(), RecordNamespace::MountSourceAcquisition);
    assert_eq!(
        records[1].namespace(),
        RecordNamespace::GlobalCapacityReservation,
    );
    assert!(records[1].value().is_none());
    assert_eq!(
        records[2].namespace(),
        RecordNamespace::GlobalCapacityReservation,
    );
    assert!(records[2].value().is_some());

    let next = successor.unwrap();
    assert_eq!(next.request().future_transactions, 2);
    assert_eq!(next.original_prepared(), data.floor.original_prepared());
    assert_eq!(next.admission_cut(), data.floor.admission_cut());
    assert_eq!(
        next.admission_transaction_id(),
        data.floor.admission_transaction_id(),
    );
    assert_eq!(
        (
            data.floor.request().terminal_records,
            next.request().terminal_records,
        ),
        (8, 5),
    );

    let stored_state = materialize_coupled_data(&data.state, transaction.records());
    let stored = graph(&stored_state).unwrap();
    let old = &data.graph.sidecars()[&data.attempt];
    let sidecar = &stored.sidecars()[&data.attempt];
    assert_eq!(sidecar.suffix().phase(), 11);
    assert!(sidecar.suffix().prepared().is_none());
    assert_eq!(
        sidecar.suffix().control(NativeHeldControlKindV1::RootClosed),
        Some(&data.signed),
    );
    assert_eq!(sidecar.disposition(), old.disposition());
    assert_eq!(sidecar.disposition_cut(), old.disposition_cut());
    for (key, bytes) in data.graph.canonical_records() {
        if *key != native_root_sidecar_key_v2(data.attempt).unwrap() {
            assert_eq!(stored.canonical_records().get(key), Some(bytes));
        }
    }

    let NativeHeldOwnerWitnessV1::Root(witness) = NativeHeldOwnerWitnessV1::from_canonical_bytes(
        NativeHeldOwnerV1::Root,
        data.signed.section(Tag::Witness).unwrap(),
    )
    .unwrap() else {
        panic!("Root original witness");
    };
    assert_eq!(witness.journal_sequence, 900);
    assert!(validate_replayed_transaction(
        &data.state,
        &transaction,
        JournalLimits::default(),
        905,
    )
    .unwrap());
}

#[test]
fn rewritten_store_sequence_is_a_different_signature_input_and_refused() {
    let data = PendingStoreData::new();
    let unsigned = data.signed.prepared();
    let NativeHeldOwnerWitnessV1::Root(mut witness) = NativeHeldOwnerWitnessV1::from_canonical_bytes(
        NativeHeldOwnerV1::Root,
        unsigned.section(Tag::Witness).unwrap(),
    )
    .unwrap() else {
        panic!("Root original witness");
    };

    witness.journal_sequence += 5;
    let witness_bytes = NativeHeldOwnerWitnessV1::Root(witness).to_canonical_bytes().unwrap();
    let sections = unsigned
        .sections()
        .iter()
        .map(|section| {
            let bytes = if section.tag() == Tag::Witness {
                witness_bytes.clone()
            } else {
                section.bytes().to_vec()
            };
            NativeHeldSectionV1::new(section.tag(), bytes).unwrap()
        })
        .collect();
    let changed = PreparedNativeHeldControlV1::new(
        unsigned.kind(),
        *unsigned.scope(),
        unsigned.predecessor(),
        sections,
        unsigned.signer().clone(),
    )
    .unwrap();
    let signature = SigningKey::from_bytes(&[12; 32])
        .sign(&changed.signature_message())
        .to_bytes();

    assert!(root_closed_owners(
        &data.graph,
        data.attempt,
        &data.floor,
        &changed.with_signature(signature),
    )
    .is_err());
}

#[test]
fn store_id_binds_admission_capture_and_exact_signed_bytes() {
    let data = PendingStoreData::new();
    let admission = data.floor.admission_transaction_id();
    let capture = data.graph.sidecars()[&data.attempt]
        .disposition_cut()
        .unwrap()
        .capture_transaction();
    let exact = store_transaction_id(admission, capture, &data.signed);

    assert_eq!(*data.owners().id(), exact);
    assert_eq!(store_transaction_id(admission, capture, &data.signed), exact);
    assert_ne!(store_transaction_id([9; 16], capture, &data.signed), exact);
    assert_ne!(store_transaction_id(admission, [9; 16], &data.signed), exact);

    let other = data.signed.prepared().clone().with_signature([17; 64]);
    assert_ne!(store_transaction_id(admission, capture, &other), exact);
}

#[test]
fn a_valid_historical_pending_cut_with_changed_current_head_cannot_store_hot8() {
    use aos_sandbox_protocol::mount_source_acquisition_state::{
        StoredRecordV2, encode_mount_source_state_record_v2, seal_record,
    };

    let data = PendingStoreData::new();
    let mut head = data
        .graph
        .legacy()
        .provider_heads
        .values()
        .next()
        .unwrap()
        .clone();
    head.revision += 1;
    let head = seal_record(StoredRecordV2::ProviderHead { value: head }).unwrap();
    let (key, bytes) = encode_mount_source_state_record_v2(&head).unwrap();
    let mut state = data.state.clone();
    state.insert((RecordNamespace::MountSourceAcquisition, key), bytes);
    let moved = graph(&state).unwrap();
    let floor = OriginalRootCapacityRecordV5::for_graph(
        &moved,
        data.floor.original_prepared().clone(),
        data.floor.admission_cut().clone(),
        JournalLimits::default(),
    )
    .unwrap();

    assert!(has_original_pending_closed_cut_v5(&moved, &moved.sidecars()[&data.attempt]).unwrap());
    assert!(root_closed_owners(&moved, data.attempt, &floor, &data.signed).is_err());
}

#[test]
fn replay_refuses_extra_owner_record_or_missing_floor_at_that_boundary() {
    let data = PendingStoreData::new();
    let owners = data.owners();
    let (transaction, _, _) = continuation(
        &data.state,
        &owners,
        data.attempt,
        JournalLimits::default(),
    )
    .unwrap();

    let owner_only = JournalTransaction::new(
        *transaction.id(),
        vec![transaction.records()[0].clone()],
    )
    .unwrap();
    assert!(validate_edge(&data.state, &owner_only, data.attempt, JournalLimits::default()).is_err());

    let mut extra = transaction.records().to_vec();
    let (key, bytes) = data
        .graph
        .canonical_records()
        .iter()
        .find(|(key, _)| **key != native_root_sidecar_key_v2(data.attempt).unwrap())
        .unwrap();
    extra.push(JournalRecord::put(
        RecordNamespace::MountSourceAcquisition,
        key.clone(),
        bytes.clone(),
    ));
    let extra = JournalTransaction::new(*transaction.id(), extra).unwrap();
    assert!(validate_replayed_transaction(
        &data.state,
        &extra,
        JournalLimits::default(),
        906,
    )
    .is_err());
}
