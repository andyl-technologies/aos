//! Distinguishes catalog inspection and operation-local container sharing from
//! semantic reachability and native publication authority.

mod catalog_concurrency;
mod catalog_sharing;

use super::*;
use crate::bucket::held::SingleHeld;
use crate::bucket::publication::collection_observation::MetadataStore;
use crate::guard::{ConsumedResolver, HistoryObservation};
use crate::pack::PackId;
use crate::store::{Clock, ContentStore, ContentUpload, MetaUpload, RefStore, StoreErrorKind};
use std::time::Duration;
use terrane_format::derived::{AttrRecord, AttributeValue};
use terrane_format::identity::Identity;
use terrane_format::properties::semantics::associations::RecordedAssociations;

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
        terrane_format::gc::publication::evidence::CheckedLineage::decode(read.bytes().unwrap())
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

/// Publishes a new Node and its signed Commit in the same actual native batch.
struct SharingSource {
    fixture: Fixture,
    members: [Identity; 2],
    bytes: [Vec<u8>; 2],
}

impl SharingSource {
    async fn publish() -> Self {
        let mut fixture = Fixture::new().await;
        let previous = fixture.head.commit;
        let mut request = super::super::fixture::request(
            vec![previous],
            b"shared metadata container source",
            None,
        );
        // The final metadata run includes the real signed Commit. Chunk-first
        // staging makes this new Node part of that run without extra authority.
        request.uploads.rotate_left(1);
        let mut writer = fixture
            .repository
            .begin("refs/heads/_/main", &request.token, "sdk")
            .await
            .unwrap();
        fixture.head = fixture
            .repository
            .commit_request(&mut writer, request)
            .await
            .unwrap();
        let commit = TERRANE_V1
            .from_digest(IdentityKind::Commit, &fixture.head.commit)
            .unwrap();
        let commit_bytes = fixture.guard().store().get(&commit, None).await.unwrap();
        let decoded = terrane_format::refs::Commit::decode(&commit_bytes).unwrap();
        assert_eq!(decoded.parents, [previous]);
        let node = TERRANE_V1
            .from_digest(IdentityKind::Node, &decoded.tree)
            .unwrap();
        let node_bytes = fixture.guard().store().get(&node, None).await.unwrap();
        Self {
            fixture,
            members: [commit, node],
            bytes: [commit_bytes, node_bytes],
        }
    }
}

/// Uses a genuine acknowledged collector lease without manufacturing checkpoints.
async fn metadata_session(fixture: &Fixture) -> super::super::session::Session {
    let receipt = Collector::new(fixture.guard(), &fixture.authority)
        .acquire("metadata-observer".into(), 1_000)
        .await
        .unwrap();
    super::super::session::Session::from_receipt(
        receipt,
        1_000,
        fixture.clock.retain_native_clock().unwrap(),
    )
    .unwrap()
}

/// Resolves actual selected typed members independently of the container cache.
fn member_pack(
    catalog: &crate::bucket::publication::collection_observation::CollectionCatalog,
    identity: &Identity,
) -> PackId {
    let hash = identity.terrane_v1_digest().unwrap();
    let row = catalog
        .shards()
        .iter()
        .flat_map(|shard| shard.entries())
        .find(|row| row.entry().hash() == &hash)
        .unwrap();
    assert_eq!(row.entry().kind().identity_kind(), identity.kind());
    assert_eq!(row.state(), crate::pack::RecordState::Live);
    row.pack()
}

fn assert_absent(error: &StoreFailure, identity: &Identity) {
    assert_eq!(error.kind(), &StoreErrorKind::Absent(identity.clone()));
}

/// Requires a real filesystem fault rather than another incomplete-evidence path.
fn assert_pack_io(error: &StoreFailure) {
    assert_eq!(
        error.kind(),
        &StoreErrorKind::Unavailable { retry_after: None }
    );
    let io = std::error::Error::source(error)
        .and_then(|source| source.downcast_ref::<std::io::Error>())
        .unwrap();
    assert_eq!(io.kind(), std::io::ErrorKind::Other);
    assert_eq!(io.to_string(), "forbidden data-pack body read");
}

#[tokio::test]
async fn gc_metadata_pack_sharing_preserves_consumed_identities_and_fresh_store_reads() {
    let source = SharingSource::publish().await;
    let fixture = &source.fixture;
    let session = metadata_session(fixture).await;
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let store = MetadataStore::new(&held, &observed, &session);
    let catalog = store.collection_catalog().await.unwrap();
    let pack = member_pack(&catalog, &source.members[0]);
    assert_eq!(member_pack(&catalog, &source.members[1]), pack);
    let pack_path = fixture.config.root.join(pack.pack_key());
    let index_path = fixture.config.root.join(pack.index_key());
    fixture.fs.reset();

    assert_eq!(
        store.get(&source.members[0], None).await.unwrap(),
        source.bytes[0]
    );
    assert_eq!(store.identities().unwrap(), [source.members[0].clone()]);
    let reads = store.reads().unwrap();
    assert_eq!(
        reads.iter().filter(|read| read.path() == pack_path).count(),
        1
    );
    assert_eq!(
        reads
            .iter()
            .filter(|read| read.path() == index_path)
            .count(),
        1
    );
    assert!(!store.identities().unwrap().contains(&source.members[1]));
    fixture
        .fs
        .forbid_data_body_reads(std::slice::from_ref(&pack_path))
        .unwrap();

    assert_eq!(
        store.get(&source.members[1], None).await.unwrap(),
        source.bytes[1]
    );
    assert_eq!(store.identities().unwrap(), source.members);
    assert_eq!(fixture.fs.data_body_read_attempts(), 0);
    assert_eq!(
        store
            .reads()
            .unwrap()
            .iter()
            .filter(|read| read.path() == pack_path)
            .count(),
        1,
    );
    assert_eq!(fixture.fs.effects(), 0);

    // A new adapter must read the same actual container independently.
    let fresh = MetadataStore::new(&held, &observed, &session);
    let error = fresh.get(&source.members[1], None).await.unwrap_err();
    assert_pack_io(&error);
    assert_eq!(fixture.fs.data_body_read_attempts(), 1);
    assert!(fresh.identities().unwrap().is_empty());
    assert_eq!(fixture.fs.effects(), 0);
    fixture.fs.forbid_data_body_reads(&[]).unwrap();
    assert_eq!(
        fresh.get(&source.members[1], None).await.unwrap(),
        source.bytes[1]
    );
    assert_eq!(fresh.identities().unwrap(), [source.members[1].clone()]);

    drop(fresh);
    drop(store);
    drop(observed);
    drop(held);
    drop(holder);
    drop(session);
    source.fixture.cleanup();
}

/// Selects the actual payload or retained Original mutated at native handoff.
#[derive(Clone, Copy)]
enum SharingMutation {
    Pack,
    Index,
    Original,
    CatalogShard,
    CatalogFilter,
}

/// Changes a consumed physical input only after the real checkpoint walk finished.
async fn refuse_changed_checkpoint(mutation: SharingMutation) {
    use crate::repository::local_authority::retention::{CommitAssociation, Record};

    let source = SharingSource::publish().await;
    let fixture = &source.fixture;
    if matches!(mutation, SharingMutation::CatalogFilter) {
        catalog_sharing::publish_filtered_generation(fixture).await;
    }
    let mut collection = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "sharing-collector".into(),
        1_000,
        41,
        windows(),
    )
    .await
    .unwrap();
    let (pack, before_state, before_logical) = {
        let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
        let held = holder.destination();
        let observed = held.observe_publication_unrepaired().await.unwrap();
        let store = MetadataStore::new(&held, &observed, &collection.session);
        let catalog = store.collection_catalog().await.unwrap();
        let pack = member_pack(&catalog, &source.members[0]);
        assert_eq!(member_pack(&catalog, &source.members[1]), pack);
        assert_eq!(
            store.get(&source.members[0], None).await.unwrap(),
            source.bytes[0]
        );
        assert_eq!(
            store.get(&source.members[1], None).await.unwrap(),
            source.bytes[1]
        );
        (pack, observed.state().clone(), observed.logical().clone())
    };
    let path = match mutation {
        SharingMutation::Pack => fixture.config.root.join(pack.pack_key()),
        SharingMutation::Index => fixture.config.root.join(pack.index_key()),
        SharingMutation::CatalogShard | SharingMutation::CatalogFilter => {
            let capabilities = terrane_format::bucket::BucketCapabilities::decode(
                before_logical["CAPABILITIES"].as_deref().unwrap(),
            )
            .unwrap();
            let generation = capabilities.generation.unwrap();
            let manifest = terrane_format::bucket::GenerationManifest::decode(
                before_logical[&format!("objects/index/{generation}/MANIFEST")]
                    .as_deref()
                    .unwrap(),
            )
            .unwrap();
            let shard = manifest
                .shards
                .iter()
                .find(|shard| {
                    matches!(mutation, SharingMutation::CatalogShard) || shard.filter.is_some()
                })
                .unwrap();
            let extension = if matches!(mutation, SharingMutation::CatalogFilter) {
                "flt"
            } else {
                "idx"
            };
            fixture.config.root.join(format!(
                "objects/index/{generation}/{}.{extension}",
                shard.shard
            ))
        }
        SharingMutation::Original => fixture.authority.control().join(format!(
            "commit-{}.cbor",
            fixture
                .head
                .commit
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        )),
    };
    let original = std::fs::read(&path).unwrap();
    let changed = if matches!(mutation, SharingMutation::Original) {
        let mut record = CommitAssociation::decode(&original).unwrap();
        assert_eq!(record.commit, fixture.head.commit);
        record.reference = "refs/heads/_/different-original".into();
        record.encode().unwrap()
    } else {
        let mut changed = original.clone();
        changed[0] ^= 1;
        changed
    };
    let slot = fixture.next_checkpoint_slot().await;
    assert!(!slot.exists());
    let (arrived, release) = fixture.fs.before_slot(slot.clone());
    let arrival =
        tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(10)).unwrap());
    let mut operation = Box::pin(collection.mark_batch(32));
    tokio::select! {
        result = &mut operation => panic!("checkpoint ended before native handoff: {result:?}"),
        result = arrival => result.unwrap(),
    }
    // Consumed catalog/container DATA and protected Original preimages now
    // belong to the actual worker; changed bytes must invalidate its ACK.
    std::fs::write(&path, &changed).unwrap();
    release.send(()).unwrap();
    let error = operation.await.unwrap_err();
    let CollectionError::Store(error) = error else {
        panic!("expected exact native storage refusal: {error:?}");
    };
    assert_eq!(
        error.kind(),
        &StoreErrorKind::Unavailable { retry_after: None }
    );
    assert!(!slot.exists());
    std::fs::write(&path, original).unwrap();

    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let after = held.observe_publication_unrepaired().await.unwrap();
    let mut renewed_state = before_state;
    renewed_state.revision += 1;
    assert_eq!(after.state(), &renewed_state);
    for (key, value) in &before_logical {
        if key != "gc/lease" {
            assert_eq!(after.logical().get(key), Some(value));
        }
    }
    let before_checkpoint =
        GcState::decode(before_logical["gc/41/state"].as_deref().unwrap()).unwrap();
    assert_eq!(collection.state(), &before_checkpoint);
    drop(after);
    drop(held);
    drop(holder);
    assert_eq!(
        fixture
            .guard()
            .store()
            .ref_get("refs/heads/_/main")
            .await
            .unwrap(),
        Some(fixture.head.clone())
    );
    drop(collection);
    source.fixture.cleanup();
}

#[tokio::test]
async fn gc_metadata_pack_sharing_rejects_changed_payload_before_native_handoff() {
    refuse_changed_checkpoint(SharingMutation::Pack).await;
    refuse_changed_checkpoint(SharingMutation::Index).await;
}

#[tokio::test]
async fn gc_metadata_pack_sharing_preserves_session_and_original_refusal() {
    let source = SharingSource::publish().await;
    let fixture = &source.fixture;
    let session = metadata_session(fixture).await;
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let before = (observed.state().clone(), observed.logical().clone());
    let store = MetadataStore::new(&held, &observed, &session);
    assert_eq!(
        store.get(&source.members[0], None).await.unwrap(),
        source.bytes[0]
    );
    // Cancel a genuine operation after warming DATA, poisoning the same Session.
    drop(session.operation().unwrap());
    fixture.fs.reset();
    for identity in &source.members {
        let error = store.get(identity, None).await.unwrap_err();
        assert_eq!(
            error.kind(),
            &StoreErrorKind::Denied {
                verb: "gc-checkpoint",
                pattern: "current configured collector session".into(),
            }
        );
        assert!(std::error::Error::source(&error).is_none());
    }
    assert_eq!(store.identities().unwrap(), [source.members[0].clone()]);
    assert_eq!(fixture.fs.effects(), 0);
    assert_eq!(
        observed
            .state()
            .branches
            .iter()
            .find(|row| row.name == "refs/heads/_/main")
            .unwrap()
            .selection,
        terrane_format::gc::publication::CommittedSelection::Selected(Box::new(
            fixture.head.clone()
        ))
    );
    drop(store);
    drop(observed);
    drop(held);
    drop(holder);
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let after = held.observe_publication_unrepaired().await.unwrap();
    assert_eq!((after.state(), after.logical()), (&before.0, &before.1));
    drop(after);
    drop(held);
    drop(holder);
    drop(session);
    source.fixture.cleanup();

    refuse_changed_checkpoint(SharingMutation::Original).await;
}

#[tokio::test]
async fn gc_metadata_pack_sharing_keeps_membership_and_restore_checks_independent() {
    let source = SharingSource::publish().await;
    let fixture = &source.fixture;
    // Actual sticky quarantine changes only the second member's selected row.
    fixture
        .guard()
        .store()
        .exclude(&source.members[1])
        .await
        .unwrap();
    let session = metadata_session(fixture).await;
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let before = (observed.state().clone(), observed.logical().clone());
    let store = MetadataStore::new(&held, &observed, &session);
    let catalog = store.collection_catalog().await.unwrap();
    let pack = member_pack(&catalog, &source.members[0]);
    let quarantined = catalog
        .shards()
        .iter()
        .flat_map(|shard| shard.entries())
        .find(|row| row.entry().hash() == &source.members[1].terrane_v1_digest().unwrap())
        .unwrap();
    assert_eq!(quarantined.pack(), pack);
    assert_eq!(quarantined.state(), crate::pack::RecordState::Quarantine);
    fixture.fs.reset();
    assert_eq!(
        store.get(&source.members[0], None).await.unwrap(),
        source.bytes[0]
    );
    let wrong_kind = TERRANE_V1
        .from_digest(
            IdentityKind::Node,
            &source.members[0].terrane_v1_digest().unwrap(),
        )
        .unwrap();
    let missing = TERRANE_V1
        .from_digest(IdentityKind::Node, &[0x5a; 32])
        .unwrap();
    for identity in [&source.members[1], &wrong_kind, &missing] {
        let error = store.get(identity, None).await.unwrap_err();
        assert_absent(&error, identity);
    }
    assert_eq!(store.identities().unwrap(), [source.members[0].clone()]);
    assert_eq!(fixture.fs.effects(), 0);
    drop(store);
    drop(observed);
    drop(held);
    drop(holder);
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let after = held.observe_publication_unrepaired().await.unwrap();
    assert_eq!((after.state(), after.logical()), (&before.0, &before.1));
    drop(after);
    drop(held);
    drop(holder);
    drop(session);
    source.fixture.cleanup();

    restore_metadata_member().await;
}

/// Exercises actual active exclusion and genuine native candidate continuity.
async fn restore_metadata_member() {
    use terrane_format::tree_builder::Tree;
    use terrane_format::tree_format::{Entry, EntryKind, LeafItem, TreeUse};

    let fixture = Fixture::new().await;
    let bytes = {
        let tree = Tree::build(
            vec![LeafItem {
                key: b"unrooted-directory".to_vec(),
                entry: Entry {
                    kind: EntryKind::Directory { mode: 0o755 },
                    attrs: Vec::new(),
                    attrs_present: false,
                    xattrs: Vec::new(),
                    xattrs_present: false,
                    provenance: None,
                },
            }],
            None,
            262144,
            TreeUse::Ordinary,
        )
        .unwrap();
        tree.root().encoded().to_vec()
    };
    let identity = fixture
        .guard()
        .store()
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Node, &bytes).unwrap(),
        ))
        .await
        .unwrap();
    let pack = {
        let session = metadata_session(&fixture).await;
        let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
        let held = holder.destination();
        let observed = held.observe_publication_unrepaired().await.unwrap();
        let store = MetadataStore::new(&held, &observed, &session);
        member_pack(&store.collection_catalog().await.unwrap(), &identity)
    };
    let mut modified = 0;
    for key in [pack.pack_key(), pack.index_key()] {
        let time = std::fs::symlink_metadata(fixture.config.root.join(key))
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        modified = modified.max(time.as_secs() + u64::from(time.subsec_nanos() != 0));
    }
    let base = modified + windows().grace() + 1;
    fixture.clock.set(base, base - 100);
    let mut collection = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "restore-observer".into(),
        1_000,
        42,
        windows(),
    )
    .await
    .unwrap();
    collection.mark_batch(32).await.unwrap();
    collection.finish_mark().await.unwrap();
    let retired = collection
        .retire_one(fixture.repository.coordinator())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retired.pack, *pack.as_bytes());

    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let before = (observed.state().clone(), observed.logical().clone());
    let store = MetadataStore::new(&held, &observed, &collection.session);
    let catalog = store.collection_catalog().await.unwrap();
    let exclusion = catalog
        .exclusions()
        .unwrap()
        .iter()
        .find(|row| row.pack_id == *pack.as_bytes())
        .unwrap();
    assert_eq!(
        (exclusion.cycle, exclusion.epoch),
        (retired.cycle, retired.epoch)
    );
    let root = TERRANE_V1
        .from_digest(IdentityKind::Commit, &fixture.head.commit)
        .unwrap();
    store.get(&root, None).await.unwrap();
    assert_absent(&store.get(&identity, None).await.unwrap_err(), &identity);
    let read = store.pack_index(&catalog, pack).await.unwrap();
    let pair = crate::store::native_publication_effects::observe_restore_pair(
        &fixture.fs,
        &observed,
        &read,
        exclusion,
    )
    .await
    .unwrap();
    store.enable_restore(&pair).await.unwrap();
    fixture.fs.reset();
    assert_eq!(store.get(&identity, None).await.unwrap(), bytes);
    assert_eq!(store.identities().unwrap(), [root, identity.clone()]);
    let wrong_kind = TERRANE_V1
        .from_digest(IdentityKind::Commit, &identity.terrane_v1_digest().unwrap())
        .unwrap();
    assert_absent(
        &store.get(&wrong_kind, None).await.unwrap_err(),
        &wrong_kind,
    );
    assert_eq!(fixture.fs.effects(), 0);

    // A fresh member request still checks the actual pair even though its raw
    // container is cached. The original body cache is not a restore capability.
    let index_path = fixture.config.root.join(pack.index_key());
    let index_bytes = std::fs::read(&index_path).unwrap();
    let mut changed = index_bytes.clone();
    changed[0] ^= 1;
    std::fs::write(&index_path, changed).unwrap();
    let error = store.get(&wrong_kind, None).await.unwrap_err();
    assert_eq!(
        error.kind(),
        &StoreErrorKind::Unavailable { retry_after: None }
    );
    std::fs::write(&index_path, index_bytes).unwrap();
    assert_eq!(fixture.fs.effects(), 0);
    drop(pair);
    drop(store);
    drop(observed);
    drop(held);
    drop(holder);
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let after = held.observe_publication_unrepaired().await.unwrap();
    assert_eq!((after.state(), after.logical()), (&before.0, &before.1));
    drop(after);
    drop(held);
    drop(holder);
    drop(collection);
    fixture.cleanup();
}
