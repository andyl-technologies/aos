//! Regression tests for authenticated physical-catalog records and bounds.

#![allow(clippy::unwrap_used)]

use aos_sandbox::{Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_core::ObjectDigest;
use tempfile::TempDir;

use super::*;
use crate::{PlannedDataset, ProjectAncestorPolicyV1, StorageDomainsV1};

fn domains() -> StorageDomainsV1 {
    StorageDomainsV1::new(
        ObjectDigest::from_bytes([21; 32]),
        ObjectDigest::from_bytes([22; 32]),
        ObjectDigest::from_bytes([23; 32]),
        ObjectDigest::from_bytes([24; 32]),
    )
    .unwrap()
}

fn catalog(generation: u64, name: &str) -> ResolvedCatalogCommitmentV1 {
    let root = ManagedDatasetRoot::from_catalog("tank", "tank/aos", 10).unwrap();
    let ancestor_dataset =
        ResolvedDataset::from_catalog(root.clone(), "tank/aos/project", 15, [1; 32], domains())
            .unwrap();
    let ancestor = ProjectAncestorPolicyV1::new(ancestor_dataset, 65_536, 8, 16).unwrap();
    let destination = PlannedDataset::from_catalog(root, name, domains()).unwrap();
    let space = WorkspaceSpacePolicyV1::new(4096, ReservationPolicy::Exact(1024)).unwrap();
    ResolvedCatalogCommitmentV1::new(
        generation,
        domains(),
        CatalogPlanV1::CreateWorkspace {
            destination,
            space,
            ancestor,
        },
    )
    .unwrap()
}

fn transaction(id: u8, records: Vec<JournalRecord>) -> JournalTransaction {
    JournalTransaction::new([id; 16], records).unwrap()
}

#[test]
fn authenticated_codec_round_trips_each_typed_envelope() {
    let catalog = catalog(7, "tank/aos/project/work");
    let state = PhysicalCatalogState::bootstrap(6, std::slice::from_ref(&catalog)).unwrap();
    let key_id = [31; 16];
    let secret = [32; 32];
    let empty = StorageCatalogTransitionProvider {
        genesis: None,
        head: None,
        reservations: BTreeMap::new(),
        transitions: BTreeMap::new(),
    };
    let bootstrap = empty
        .prepare_bootstrap(6, std::slice::from_ref(&catalog), key_id, &secret)
        .unwrap();
    let bootstrap_record = bootstrap.record();
    let decoded_head: HeadPayload =
        decode_authenticated(bootstrap_record.value().unwrap(), key_id, &secret).unwrap();
    assert_eq!(decoded_head.genesis_state, Some(state.wire.clone()));

    let mut provider = StorageCatalogTransitionProvider {
        genesis: Some(state.binding),
        head: Some(state.clone()),
        reservations: BTreeMap::new(),
        transitions: BTreeMap::new(),
    };
    let reservation = provider
        .reserve(
            [33; 16],
            ObjectDigest::from_bytes([34; 32]),
            ObjectDigest::from_bytes([35; 32]),
            &catalog,
            key_id,
            &secret,
        )
        .unwrap();
    let decoded: ReservationPayload =
        decode_authenticated(&reservation.bytes, key_id, &secret).unwrap();
    assert_eq!(decoded, reservation.payload);
    provider.install_reservation(reservation);
    let transition = provider
        .prepare_transition(
            [33; 16],
            ObjectDigest::from_bytes([35; 32]),
            &catalog,
            Some(36),
            ObjectDigest::from_bytes([37; 32]),
            key_id,
            &secret,
        )
        .unwrap();
    let decoded_transition: TransitionPayload =
        decode_authenticated(&transition.transition_bytes, key_id, &secret).unwrap();
    assert_eq!(decoded_transition, transition.transition);
    let decoded_head: HeadPayload =
        decode_authenticated(&transition.head_bytes, key_id, &secret).unwrap();
    assert_eq!(decoded_head.operation_id, Some([33; 16]));
}

#[test]
fn transition_capacity_bound_covers_input_widths_and_derived_mac() {
    let catalog = catalog(7, "tank/aos/project/work");
    let predecessor = PhysicalCatalogState::bootstrap(6, std::slice::from_ref(&catalog)).unwrap();

    for pattern in [0_u8, 9, 99, u8::MAX] {
        let identity = pattern.max(1);
        let operation_id = [identity; 16];
        let mutation_digest = ObjectDigest::from_bytes([identity; 32]);
        let key_id = [identity; 16];
        let secret = [pattern; 32];
        let result = predecessor
            .apply(operation_id, &catalog, Some(u64::from(pattern).max(1)))
            .unwrap();
        let payload = transition_payload(
            operation_id,
            mutation_digest,
            &catalog,
            &predecessor,
            &result,
            Some(u64::from(pattern).max(1)),
            ObjectDigest::from_bytes([pattern; 32]),
        )
        .unwrap();
        let actual = encode_authenticated(&payload, key_id, &secret)
            .unwrap()
            .len();
        let worst_result = predecessor
            .apply(operation_id, &catalog, Some(u64::MAX))
            .unwrap();
        let bound = encoded_transition_size(
            operation_id,
            mutation_digest,
            &catalog,
            &predecessor,
            &worst_result,
            Some(u64::MAX),
            ObjectDigest::from_bytes([u8::MAX; 32]),
            key_id,
            &secret,
        )
        .unwrap();

        assert!(actual <= bound, "pattern {pattern}: {actual} > {bound}");
        assert!(bound <= MAXIMUM_RECORD_BYTES);
    }
}

#[test]
fn authenticated_semantic_conflicts_and_disconnected_branches_fail_closed() {
    let first_catalog = catalog(7, "tank/aos/project/first");
    let second_catalog = catalog(7, "tank/aos/project/second");
    let key_id = [41; 16];
    let secret = [42; 32];
    let bootstrap_state =
        PhysicalCatalogState::bootstrap(6, std::slice::from_ref(&first_catalog)).unwrap();

    let mut conflicting_wire = bootstrap_state.wire.clone();
    let mut duplicate = conflicting_wire.datasets[0].clone();
    duplicate.guid += 1;
    conflicting_wire.datasets.push(duplicate);
    conflicting_wire.datasets.sort();
    let conflicting_bytes = serde_json::to_vec(&conflicting_wire).unwrap();
    let mut conflicting_hash = Sha256::new();
    conflicting_hash.update(STATE_DIGEST_DOMAIN);
    conflicting_hash.update(conflicting_bytes);
    let conflicting_binding = CatalogBindingV1::from_publisher(
        conflicting_wire.generation,
        ObjectDigest::from_bytes(conflicting_hash.finalize().into()),
    )
    .unwrap();
    let conflicting_head = HeadPayload {
        magic: HEAD_MAGIC.to_owned(),
        version: FORMAT_VERSION,
        binding: conflicting_binding.into(),
        operation_id: None,
        transition_digest: None,
        genesis_state: Some(conflicting_wire),
    };
    let authenticated = encode_authenticated(&conflicting_head, key_id, &secret).unwrap();
    let decoded: HeadPayload = decode_authenticated(&authenticated, key_id, &secret).unwrap();
    assert!(matches!(
        validate_head(&decoded, &BTreeMap::new()),
        Err(StorageStateError::CorruptRecord)
    ));

    let directory = TempDir::new().unwrap();
    let (mut journal, _) = Journal::open(
        directory.path().join("catalog.journal"),
        JournalLimits::default(),
    )
    .unwrap();
    let empty = StorageCatalogTransitionProvider::load(&journal, key_id, &secret).unwrap();
    let bootstrap = empty
        .prepare_bootstrap(6, std::slice::from_ref(&first_catalog), key_id, &secret)
        .unwrap();
    journal
        .commit(&transaction(1, vec![bootstrap.record()]))
        .unwrap();
    let mut provider = StorageCatalogTransitionProvider::load(&journal, key_id, &secret).unwrap();
    let first = provider
        .reserve(
            [51; 16],
            ObjectDigest::from_bytes([52; 32]),
            ObjectDigest::from_bytes([53; 32]),
            &first_catalog,
            key_id,
            &secret,
        )
        .unwrap();
    let second = provider
        .reserve(
            [54; 16],
            ObjectDigest::from_bytes([55; 32]),
            ObjectDigest::from_bytes([56; 32]),
            &second_catalog,
            key_id,
            &secret,
        )
        .unwrap();
    journal
        .commit(&transaction(
            2,
            vec![
                StorageCatalogTransitionProvider::reservation_record(&first),
                StorageCatalogTransitionProvider::reservation_record(&second),
            ],
        ))
        .unwrap();
    provider.install_reservation(first);
    provider.install_reservation(second);
    let first_transition = provider
        .prepare_transition(
            [51; 16],
            ObjectDigest::from_bytes([53; 32]),
            &first_catalog,
            Some(61),
            ObjectDigest::from_bytes([62; 32]),
            key_id,
            &secret,
        )
        .unwrap();
    let second_transition = provider
        .prepare_transition(
            [54; 16],
            ObjectDigest::from_bytes([56; 32]),
            &second_catalog,
            Some(63),
            ObjectDigest::from_bytes([64; 32]),
            key_id,
            &secret,
        )
        .unwrap();
    let mut records = first_transition.records();
    records.push(JournalRecord::put(
        RecordNamespace::StorageCatalogTransition,
        [54; 16].to_vec(),
        second_transition.transition_bytes,
    ));
    journal.commit(&transaction(3, records)).unwrap();

    assert!(matches!(
        StorageCatalogTransitionProvider::load(&journal, key_id, &secret),
        Err(StorageStateError::CorruptRecord)
    ));
}
