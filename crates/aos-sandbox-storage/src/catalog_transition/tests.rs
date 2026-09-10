//! Regression tests for authenticated physical-catalog records and bounds.

#![allow(clippy::unwrap_used)]

use aos_sandbox::{Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_core::ObjectDigest;
use tempfile::TempDir;

use super::*;
use crate::root_policy::{PortableRootAttributesV1, WorkspaceRootPolicyV1};
use crate::{
    PlannedDataset, PlannedSnapshot, ProjectAncestorPolicyV1, StorageDomainsV1,
    resolver::inventory::CheckedSnapshotRootMetadataRecordV1,
};

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
    ResolvedCatalogCommitmentV1::new_execution_v1(
        generation,
        domains(),
        CatalogPlanV1::CreateWorkspace {
            destination,
            space,
            ancestor,
        },
        Some(WorkspaceRootPolicyV1::create_initialize()),
    )
    .unwrap()
}

fn snapshot_catalog(
    generation: u64,
    source: ResolvedDataset,
    component: &str,
) -> ResolvedCatalogCommitmentV1 {
    let destination = PlannedSnapshot::from_catalog(source.clone(), component).unwrap();
    ResolvedCatalogCommitmentV1::new_execution_v1(
        generation,
        domains(),
        CatalogPlanV1::Snapshot {
            source,
            destination,
        },
        None,
    )
    .unwrap()
}

fn transaction(id: u8, records: Vec<JournalRecord>) -> JournalTransaction {
    JournalTransaction::new([id; 16], records).unwrap()
}

#[test]
fn authenticated_codec_round_trips_each_v1_record() {
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
    let decoded_head =
        format::decode_head_payload(bootstrap_record.value().unwrap(), key_id, &secret).unwrap();
    assert_eq!(decoded_head.genesis_state, Some(state.clone()));

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
    let (decoded, decoded_predecessor) =
        format::decode_reservation_payload(&reservation.bytes, key_id, &secret).unwrap();
    assert_eq!(decoded, reservation.payload);
    assert_eq!(decoded_predecessor, reservation.predecessor);
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
    let decoded_transition =
        format::decode_transition_payload(&transition.transition_bytes, key_id, &secret).unwrap();
    assert_eq!(decoded_transition, transition.transition);
    let decoded_head =
        format::decode_head_payload(&transition.head_bytes, key_id, &secret).unwrap();
    assert_eq!(decoded_head.operation_id, Some([33; 16]));
}

#[test]
fn v1_chain_authenticates_snapshot_metadata_and_rejects_unknown_versions() {
    let create_catalog = catalog(7, "tank/aos/project/work");
    let key_id = [71; 16];
    let secret = [72; 32];
    let directory = TempDir::new().unwrap();
    let (mut journal, _) = Journal::open(
        directory.path().join("catalog.journal"),
        JournalLimits::default(),
    )
    .unwrap();
    let empty = StorageCatalogTransitionProvider::load(&journal, key_id, &secret).unwrap();
    let bootstrap = empty
        .prepare_bootstrap(6, std::slice::from_ref(&create_catalog), key_id, &secret)
        .unwrap();
    journal
        .commit(&transaction(1, vec![bootstrap.record()]))
        .unwrap();

    let mut provider = StorageCatalogTransitionProvider::load(&journal, key_id, &secret).unwrap();
    let create_reservation = provider
        .reserve(
            [73; 16],
            ObjectDigest::from_bytes([74; 32]),
            ObjectDigest::from_bytes([75; 32]),
            &create_catalog,
            key_id,
            &secret,
        )
        .unwrap();
    journal
        .commit(&transaction(
            2,
            vec![StorageCatalogTransitionProvider::reservation_record(
                &create_reservation,
            )],
        ))
        .unwrap();
    provider.install_reservation(create_reservation);
    let create_transition = provider
        .prepare_transition(
            [73; 16],
            ObjectDigest::from_bytes([75; 32]),
            &create_catalog,
            Some(76),
            ObjectDigest::from_bytes([77; 32]),
            key_id,
            &secret,
        )
        .unwrap();
    journal
        .commit(&transaction(3, create_transition.records()))
        .unwrap();
    provider.install_transition(create_transition);

    let CatalogPlanV1::CreateWorkspace { destination, .. } = create_catalog.plan() else {
        unreachable!();
    };
    let source = ResolvedDataset::from_catalog(
        destination.root().clone(),
        destination.name(),
        76,
        [78; 32],
        destination.domains(),
    )
    .unwrap();
    let snapshot_catalog = snapshot_catalog(9, source.clone(), "snapshot-proof");
    let snapshot_metadata = CheckedSnapshotRootMetadataRecordV1::new(
        79,
        source.guid(),
        PortableRootAttributesV1::new(1000, 1001, 0o2750).unwrap(),
        source.storage_handle(),
        [80; 32],
        ObjectDigest::from_bytes([81; 32]),
    )
    .unwrap();
    let snapshot_reservation = provider
        .reserve(
            [82; 16],
            ObjectDigest::from_bytes([83; 32]),
            ObjectDigest::from_bytes([84; 32]),
            &snapshot_catalog,
            key_id,
            &secret,
        )
        .unwrap();
    journal
        .commit(&transaction(
            4,
            vec![StorageCatalogTransitionProvider::reservation_record(
                &snapshot_reservation,
            )],
        ))
        .unwrap();
    provider.install_reservation(snapshot_reservation.clone());
    let snapshot_transition = provider
        .prepare_transition_with_snapshot_metadata_for_test(
            [82; 16],
            ObjectDigest::from_bytes([84; 32]),
            &snapshot_catalog,
            79,
            ObjectDigest::from_bytes([85; 32]),
            snapshot_metadata,
            key_id,
            &secret,
        )
        .unwrap();
    journal
        .commit(&transaction(5, snapshot_transition.records()))
        .unwrap();

    let recovered = StorageCatalogTransitionProvider::load(&journal, key_id, &secret).unwrap();
    assert_eq!(
        recovered.head_binding(),
        Some(snapshot_transition.result_binding())
    );
    let resolver =
        StorageCatalogTransitionProvider::load_resolver_snapshot(&journal, key_id, &secret)
            .unwrap();
    assert_eq!(resolver.binding(), snapshot_transition.result_binding());
    assert_eq!(resolver.snapshots().len(), 1);
    assert_eq!(
        resolver.snapshots()[0].root_metadata(),
        Some(snapshot_metadata)
    );

    let mut missing_metadata = snapshot_transition.transition.clone();
    missing_metadata.result_state.snapshot_root_metadata.clear();
    let authenticated =
        format::encode_transition_payload(&missing_metadata, key_id, &secret).unwrap();
    assert!(matches!(
        format::decode_transition_payload(&authenticated, key_id, &secret),
        Err(StorageStateError::CorruptRecord)
    ));

    for mutation in 0..4 {
        let mut tampered = snapshot_transition.transition.clone();
        let metadata = tampered
            .result_state
            .snapshot_root_metadata
            .values_mut()
            .next()
            .unwrap();
        match mutation {
            0 => {
                metadata.record.pop();
            }
            1 => metadata.record_digest[0] ^= 1,
            2 => metadata.record[19] ^= 1,
            3 => metadata.content_commitment[0] ^= 1,
            _ => unreachable!(),
        }
        let authenticated = format::encode_transition_payload(&tampered, key_id, &secret).unwrap();
        assert!(matches!(
            format::decode_transition_payload(&authenticated, key_id, &secret),
            Err(StorageStateError::CorruptRecord)
        ));
    }

    let unknown_version = ReservationPayloadV1 {
        magic: RESERVATION_MAGIC.to_owned(),
        version: 2,
        operation_id: snapshot_reservation.payload.operation_id,
        request_digest: snapshot_reservation.payload.request_digest,
        mutation_digest: snapshot_reservation.payload.mutation_digest,
        catalog: snapshot_reservation.payload.catalog,
        catalog_bytes_digest: snapshot_reservation.payload.catalog_bytes_digest,
        predecessor: snapshot_reservation.payload.predecessor,
        predecessor_state: snapshot_reservation.predecessor.persistent_wire().unwrap(),
        maximum_transition_bytes: snapshot_reservation.payload.maximum_transition_bytes,
    };
    let authenticated = format::encode_authenticated(&unknown_version, key_id, &secret).unwrap();
    assert!(matches!(
        format::decode_reservation_payload(&authenticated, key_id, &secret),
        Err(StorageStateError::CorruptRecord)
    ));

    let mut maximum_reservation = snapshot_reservation.payload.clone();
    maximum_reservation.predecessor.generation = u64::MAX;
    maximum_reservation.catalog.generation = u64::MAX;
    let authenticated = format::encode_reservation_payload(
        &maximum_reservation,
        &snapshot_reservation.predecessor,
        key_id,
        &secret,
    )
    .unwrap();
    assert!(matches!(
        format::decode_reservation_payload(&authenticated, key_id, &secret),
        Err(StorageStateError::CorruptRecord)
    ));

    let mut maximum_transition = snapshot_transition.transition.clone();
    maximum_transition.catalog.generation = u64::MAX;
    let authenticated =
        format::encode_transition_payload(&maximum_transition, key_id, &secret).unwrap();
    assert!(matches!(
        format::decode_transition_payload(&authenticated, key_id, &secret),
        Err(StorageStateError::CorruptRecord)
    ));
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
        let actual = format::encode_transition_payload(&payload, key_id, &secret)
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
fn version_dispatch_rejects_oversized_envelopes_before_typed_decode() {
    let mut oversized = br#"{"payload":{"version":2}}"#.to_vec();
    oversized.resize(MAXIMUM_RECORD_BYTES + 1, b' ');

    assert!(matches!(
        format::payload_version(&oversized),
        Err(StorageStateError::CorruptRecord)
    ));
}

#[test]
fn snapshot_capacity_includes_variable_root_metadata_digest() {
    let root = ManagedDatasetRoot::from_catalog("tank", "tank/aos", 10).unwrap();
    let source =
        ResolvedDataset::from_catalog(root, "tank/aos/project/work", 15, [1; 32], domains())
            .unwrap();
    let catalog = snapshot_catalog(7, source.clone(), "snapshot-capacity");
    let predecessor = PhysicalCatalogState::bootstrap(6, std::slice::from_ref(&catalog)).unwrap();
    let key_id = [91; 16];
    let secret = [92; 32];
    let operation_id = [93; 16];
    let mutation_digest = ObjectDigest::from_bytes([94; 32]);
    let mut provider = StorageCatalogTransitionProvider {
        genesis: Some(predecessor.binding),
        head: Some(predecessor.clone()),
        reservations: BTreeMap::new(),
        transitions: BTreeMap::new(),
    };
    let reservation = provider
        .reserve(
            operation_id,
            ObjectDigest::from_bytes([95; 32]),
            mutation_digest,
            &catalog,
            key_id,
            &secret,
        )
        .unwrap();

    let synthetic_guid = u64::MAX;
    let synthetic_metadata = maximum_snapshot_root_metadata_wire(&catalog, synthetic_guid)
        .unwrap()
        .unwrap();
    let synthetic_result = predecessor
        .apply_with_snapshot_metadata(
            operation_id,
            &catalog,
            Some(synthetic_guid),
            Some(synthetic_metadata),
        )
        .unwrap();
    let synthetic_payload = transition_payload(
        operation_id,
        mutation_digest,
        &catalog,
        &predecessor,
        &synthetic_result,
        Some(synthetic_guid),
        ObjectDigest::from_bytes([u8::MAX; 32]),
    )
    .unwrap();
    let synthetic_bytes =
        format::encode_transition_payload(&synthetic_payload, key_id, &secret).unwrap();
    let digest_slack = SNAPSHOT_VARIABLE_ARRAY_BYTES * MAXIMUM_JSON_BYTE_EXPANSION;
    let common_slack = VARIABLE_TRANSITION_ARRAY_BYTES * MAXIMUM_JSON_BYTE_EXPANSION;
    let reserved_bytes = reservation.payload.maximum_transition_bytes as usize;

    assert_eq!(
        format::transition_variable_array_bytes(&catalog),
        VARIABLE_TRANSITION_ARRAY_BYTES + SNAPSHOT_VARIABLE_ARRAY_BYTES
    );
    assert_eq!(
        reserved_bytes,
        synthetic_bytes.len() + common_slack + digest_slack
    );

    provider.install_reservation(reservation);
    for (pattern, snapshot_guid, mode) in [
        (1_u8, 1_u64, 0o1_u32),
        (9, 9, 0o11),
        (99, 99, 0o111),
        (u8::MAX, u64::MAX - 1, 0o7777),
    ] {
        let metadata = CheckedSnapshotRootMetadataRecordV1::new(
            snapshot_guid,
            source.guid(),
            PortableRootAttributesV1::new(u32::from(pattern), u32::MAX - u32::from(pattern), mode)
                .unwrap(),
            source.storage_handle(),
            [pattern; 32],
            ObjectDigest::from_bytes([pattern; 32]),
        )
        .unwrap();
        let transition = provider
            .prepare_transition_with_snapshot_metadata_for_test(
                operation_id,
                mutation_digest,
                &catalog,
                snapshot_guid,
                ObjectDigest::from_bytes([pattern; 32]),
                metadata,
                key_id,
                &secret,
            )
            .unwrap();

        assert!(
            transition.transition_bytes.len() <= reserved_bytes,
            "pattern {pattern}: {} > {reserved_bytes}",
            transition.transition_bytes.len()
        );
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

    let mut conflicting_wire = bootstrap_state.persistent_wire().unwrap();
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
    let conflicting_head = HeadPayloadV1 {
        magic: HEAD_MAGIC.to_owned(),
        version: FORMAT_VERSION,
        binding: conflicting_binding.into(),
        operation_id: None,
        transition_digest: None,
        genesis_state: Some(conflicting_wire),
    };
    let authenticated = format::encode_authenticated(&conflicting_head, key_id, &secret).unwrap();
    assert!(matches!(
        format::decode_head_payload(&authenticated, key_id, &secret),
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
