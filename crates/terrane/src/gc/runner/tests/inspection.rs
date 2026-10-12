//! Distinguishes actual catalog inspection from semantic reachability observations.

use super::*;
use crate::bucket::held::SingleHeld;
use crate::bucket::publication::collection_observation::MetadataStore;
use crate::guard::{ConsumedResolver, HistoryObservation};
use crate::pack::PackId;
use crate::store::{ContentStore, ContentUpload, MetaUpload};
use terrane_core::derived::{AttrRecord, AttributeValue};
use terrane_core::properties::semantics::associations::RecordedAssociations;

#[tokio::test]
async fn gc_attribute_catalog_inspection_does_not_mark_unrelated_rows() {
    let fixture = Fixture::new().await;
    let object = TERRANE_V1
        .calculate(IdentityKind::Chunk, b"published source")
        .unwrap()
        .terrane_v1_digest()
        .unwrap();
    let records = [
        AttrRecord::new(object, AttributeValue::Sha256([1; 32]), fixture.head.commit),
        AttrRecord::new(
            [2; 32],
            AttributeValue::Sha256([3; 32]),
            fixture.head.commit,
        ),
    ];
    let mut identities = Vec::new();
    for record in &records {
        let bytes = record.encode().unwrap();
        identities.push(
            fixture
                .guard()
                .store()
                .put(ContentUpload::Meta(
                    MetaUpload::new(IdentityKind::Attribute, &bytes).unwrap(),
                ))
                .await
                .unwrap(),
        );
    }
    let collection = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "collector".into(),
        1_000,
        1,
        windows(),
    )
    .await
    .unwrap();
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let store = MetadataStore::new(&held, &observed, &collection.session);

    let inspected = store.attribute_records().await.unwrap();

    assert_eq!(inspected.len(), 2);
    for (identity, record) in &inspected {
        assert_eq!(record.identity().unwrap(), *identity);
        assert!(records.contains(record));
    }
    assert!(store.identities().unwrap().is_empty());
    assert!(!store.reads().unwrap().is_empty());
    let reads_before = store.reads().unwrap().len();

    let body = store.get(&identities[0], None).await.unwrap();

    assert_eq!(AttrRecord::decode(&body).unwrap(), records[0]);
    assert_eq!(store.identities().unwrap(), vec![identities[0].clone()]);
    assert_eq!(store.reads().unwrap().len(), reads_before);
    assert!(!store.identities().unwrap().contains(&identities[1]));
    drop(store);
    drop(observed);
    drop(held);
    drop(holder);
    drop(collection);
    fixture.cleanup();
}

#[tokio::test]
async fn gc_historical_adapter_preserves_explicit_empty_interpretation() {
    let fixture = Fixture::new().await;
    let collection = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "collector".into(),
        1_000,
        1,
        windows(),
    )
    .await
    .unwrap();
    let bucket = FileBucket::open(
        fixture.config.clone(),
        fixture.fs.clone(),
        fixture.clock.retain_native_clock().unwrap(),
        super::super::fixture::Validator,
    )
    .await
    .unwrap();
    let explicit = Guard::new_with_recorded_views(
        bucket,
        fixture.clock.retain_native_clock().unwrap(),
        fixture.guard().keys().to_vec(),
        fixture.guard().config().clone(),
        RecordedAssociations::new([]).unwrap(),
    );
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let legacy = crate::guard::collection_authority::historical_guard(
        fixture.guard(),
        &held,
        &observed,
        &collection.session,
        collection.session.clock().unwrap(),
    )
    .unwrap();
    let consumed = ConsumedResolver::new(fixture.guard(), &fixture.authority).unwrap();
    let checked = legacy
        .verified_collection_tree_observed(
            fixture.head.commit,
            HistoryObservation::held(observed.identity()).tracked(&consumed),
        )
        .await
        .unwrap();
    assert!(!legacy.collection_occurrences(&checked).unwrap().is_empty());

    let adapted = crate::guard::collection_authority::historical_guard(
        &explicit,
        &held,
        &observed,
        &collection.session,
        collection.session.clock().unwrap(),
    )
    .unwrap();

    // A mode downgrade would accept the already completed legacy occurrence.
    // Explicit empty configuration must instead refuse it before reinterpretation.
    assert!(adapted.collection_occurrences(&checked).is_err());
    drop(adapted);
    drop(legacy);
    drop(observed);
    drop(held);
    drop(holder);
    drop(collection);
    fixture.cleanup();
}

#[tokio::test]
async fn gc_selected_pack_index_observation_never_reads_data_bodies() {
    let fixture = Fixture::new().await;
    let collection = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "collector".into(),
        1_000,
        1,
        windows(),
    )
    .await
    .unwrap();
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let store = MetadataStore::new(&held, &observed, &collection.session);
    let catalog = store.collection_catalog().await.unwrap();
    let mut data_paths = Vec::new();
    let mut indexes = std::collections::BTreeMap::new();
    for entry in catalog.inventory().unwrap() {
        let pack = PackId::from_random_bytes(entry.pack_id);
        let bytes = tokio::fs::read(fixture.config.root.join(pack.index_key()))
            .await
            .unwrap();
        assert_eq!(&bytes[..6], b"TRPK\x01\x00");
        // Independent fixed header flag: bit one distinguishes metadata packs.
        if bytes[6] & 2 == 0 {
            data_paths.push(fixture.config.root.join(pack.pack_key()));
        }
        indexes.insert(pack, bytes);
    }
    assert!(!data_paths.is_empty());
    assert!(catalog.exclusions().unwrap().is_empty());
    assert!(catalog.burns().unwrap().is_empty());
    assert!(!catalog.shards().is_empty());
    fixture.fs.forbid_data_body_reads(&data_paths).unwrap();
    fixture.fs.reset();
    let before = store.reads().unwrap().len();

    for entry in catalog.inventory().unwrap() {
        let pack = PackId::from_random_bytes(entry.pack_id);
        let read = store.pack_index(&catalog, pack).await.unwrap();
        assert_eq!(read.inventory(), entry);
        assert_eq!(read.pack_path(), fixture.config.root.join(pack.pack_key()));
        assert_eq!(read.metadata().len(), entry.pack_size);
        assert!(read.metadata().modified().is_ok());
        assert_eq!(read.index().bytes(), Some(indexes[&pack].as_slice()));
        assert_eq!(read.snapshot().header().id(), pack);
        assert!(!read.snapshot().entries().is_empty());
    }

    assert_eq!(fixture.fs.data_body_read_attempts(), 0);
    assert_eq!(fixture.fs.effects(), 0);
    assert!(store.identities().unwrap().is_empty());
    assert!(store.reads().unwrap()[before..].iter().all(|read| {
        read.path()
            .extension()
            .is_some_and(|extension| extension == "idx")
    }));
    // Exercise each trap after the operation to prove every counted lane is armed.
    assert!(fixture.fs.read(&data_paths[0]).await.is_err());
    assert!(
        fixture
            .fs
            .read_range(
                &data_paths[0],
                crate::store::ByteRange {
                    start: 0,
                    length: 1
                }
            )
            .await
            .is_err()
    );
    assert!(fixture.fs.read_nofollow(&data_paths[0]).await.is_err());
    assert_eq!(fixture.fs.data_body_read_attempts(), 3);
    drop(store);
    drop(observed);
    drop(held);
    drop(holder);
    drop(collection);
    fixture.cleanup();
}

#[tokio::test]
async fn gc_selected_lineage_observation_retains_exact_protected_receipt() {
    let fixture = Fixture::new().await;
    let collection = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "collector".into(),
        1_000,
        1,
        windows(),
    )
    .await
    .unwrap();
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let name = "refs/heads/_/main";
    let source = observed
        .state()
        .sources
        .iter()
        .find(|row| row.name == name)
        .unwrap();
    let suffix = source
        .digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let control = fixture
        .config
        .publication_control
        .as_ref()
        .unwrap()
        .control
        .as_ref()
        .unwrap();
    let expected_path = control.join(format!("publication/lineage/{suffix}"));
    let expected = tokio::fs::read(&expected_path).await.unwrap();
    fixture.fs.reset();

    let read = held
        .selected_lineage_record(&observed, name)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(read.path(), expected_path);
    assert_eq!(read.bytes(), Some(expected.as_slice()));
    assert_eq!(
        blake3::hash(read.bytes().unwrap()).as_bytes(),
        &source.digest
    );
    assert_eq!(
        terrane_core::gc::publication::evidence::CheckedLineage::decode(read.bytes().unwrap())
            .unwrap()
            .source,
        fixture.head
    );
    assert!(read.metadata().unwrap().is_file());
    assert!(
        held.selected_lineage_record(&observed, "refs/heads/_/absent")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(fixture.fs.effects(), 0);

    tokio::fs::write(&expected_path, b"corrupt selected lineage")
        .await
        .unwrap();
    assert!(held.selected_lineage_record(&observed, name).await.is_err());
    assert_eq!(fixture.fs.effects(), 0);
    tokio::fs::write(&expected_path, expected).await.unwrap();
    drop(observed);
    drop(held);
    drop(holder);
    drop(collection);
    fixture.cleanup();
}
