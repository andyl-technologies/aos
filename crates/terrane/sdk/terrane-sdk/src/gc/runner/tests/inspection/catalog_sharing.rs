//! Checks per-adapter catalog DATA reuse independently of body-cache hits.
//!
//! Actual selected artifact paths, fresh native reads and existing checkpoint
//! barriers keep parsed data separate from membership and publication authority.

use super::*;
use std::path::PathBuf;
use terrane_format::bucket::{BucketCapabilities, GenerationManifest};

/// Admits canonical Filter data and publishes actual hash-bound filter artifacts.
///
/// The backend-only publication lane changes no content row or actor authority.
/// It establishes no filter algorithm semantics beyond canonical opaque DATA.
///
/// # Panics
/// Panics if real admission, native publication or preserved-row checks fail.
pub(super) async fn publish_filtered_generation(fixture: &Fixture) {
    use terrane_format::gc::publication::LogicalChange;

    let filter_bytes = b"\x44test";
    let filter = fixture
        .guard()
        .store()
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Filter, filter_bytes).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(
        filter,
        TERRANE_V1
            .calculate(IdentityKind::Filter, filter_bytes)
            .unwrap()
    );
    assert_eq!(
        fixture.guard().store().get(&filter, None).await.unwrap(),
        filter_bytes
    );

    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let mut capabilities =
        BucketCapabilities::decode(observed.logical()["CAPABILITIES"].as_deref().unwrap()).unwrap();
    let previous = capabilities.generation.unwrap();
    let mut manifest = GenerationManifest::decode(
        observed.logical()[&format!("objects/index/{previous}/MANIFEST")]
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    assert!(manifest.shards.iter().all(|shard| shard.filter.is_none()));
    let generation = previous.checked_add(1).unwrap();
    let mut changes = Vec::new();
    for shard in &mut manifest.shards {
        let previous_key = format!("objects/index/{previous}/{}.idx", shard.shard);
        changes.push(LogicalChange {
            key: format!("objects/index/{generation}/{}.idx", shard.shard),
            expected: None,
            new: observed.logical()[&previous_key].clone(),
        });
        shard.filter = Some((
            filter.terrane_v1_digest().unwrap(),
            filter_bytes.len() as u64,
        ));
        changes.push(LogicalChange {
            key: format!("objects/index/{generation}/{}.flt", shard.shard),
            expected: None,
            new: Some(filter_bytes.to_vec()),
        });
    }
    manifest.generation = generation;
    manifest.written_at = fixture
        .clock
        .now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    changes.push(LogicalChange {
        key: format!("objects/index/{generation}/MANIFEST"),
        expected: None,
        new: Some(manifest.encode().unwrap()),
    });
    capabilities.generation = Some(generation);
    changes.push(LogicalChange {
        key: "CAPABILITIES".into(),
        expected: observed.logical()["CAPABILITIES"].clone(),
        new: Some(capabilities.encode().unwrap()),
    });
    let receipt = held.publish_raw(&observed, changes).await.unwrap();
    let selected = held.observe_publication_unrepaired().await.unwrap();
    assert_eq!(selected.stamp(), receipt.stamp);
    assert_eq!(selected.state(), &receipt.state);
    for (key, value) in observed.logical() {
        if key != "CAPABILITIES" {
            assert_eq!(selected.logical().get(key), Some(value));
        }
    }
    drop(selected);
    drop(observed);
    drop(held);
    drop(holder);
    assert_eq!(
        fixture.guard().store().get(&filter, None).await.unwrap(),
        filter_bytes
    );
    assert_eq!(
        fixture
            .guard()
            .store()
            .ref_get("refs/heads/_/main")
            .await
            .unwrap(),
        Some(fixture.head.clone())
    );
}

/// Resolves every actual shard/filter path from the selected manifest.
fn catalog_paths(
    fixture: &Fixture,
    logical: &std::collections::BTreeMap<String, Option<Vec<u8>>>,
) -> Vec<PathBuf> {
    let capabilities =
        BucketCapabilities::decode(logical["CAPABILITIES"].as_deref().unwrap()).unwrap();
    let generation = capabilities.generation.unwrap();
    let manifest = GenerationManifest::decode(
        logical[&format!("objects/index/{generation}/MANIFEST")]
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    let mut paths = Vec::new();
    for shard in &manifest.shards {
        paths.push(
            fixture
                .config
                .root
                .join(format!("objects/index/{generation}/{}.idx", shard.shard)),
        );
        if shard.filter.is_some() {
            paths.push(
                fixture
                    .config
                    .root
                    .join(format!("objects/index/{generation}/{}.flt", shard.shard)),
            );
        }
    }
    assert!(!paths.is_empty());
    paths
}

#[tokio::test]
async fn gc_catalog_sharing_reuses_artifacts_without_reusing_member_checks() {
    let source = SharingSource::publish().await;
    let fixture = &source.fixture;
    let previous = terrane_format::refs::Commit::decode(&source.bytes[0])
        .unwrap()
        .parents[0];
    let other = TERRANE_V1
        .from_digest(IdentityKind::Commit, &previous)
        .unwrap();
    let expected = fixture.guard().store().get(&other, None).await.unwrap();
    fixture
        .guard()
        .store()
        .exclude(&source.members[1])
        .await
        .unwrap();
    publish_filtered_generation(fixture).await;
    let session = metadata_session(fixture).await;
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let before = (observed.state().clone(), observed.logical().clone());
    let paths = catalog_paths(fixture, observed.logical());
    let store = MetadataStore::new(&held, &observed, &session);

    // The first filter follows a successfully decoded shard. A failed partial
    // load must keep that preimage without publishing a partial catalog cache.
    let filter_path = paths
        .iter()
        .find(|path| path.extension().unwrap() == "flt")
        .unwrap();
    fixture
        .fs
        .forbid_data_body_reads(std::slice::from_ref(filter_path))
        .unwrap();
    let error = match store.collection_catalog().await {
        Err(error) => error,
        Ok(_) => panic!("partial catalog load bypassed actual filter I/O failure"),
    };
    assert_pack_io(&error);
    let partial_reads = store.reads().unwrap();
    assert_eq!(partial_reads.len(), 1);
    assert_eq!(partial_reads[0].path(), &paths[0]);
    assert!(store.identities().unwrap().is_empty());
    fixture.fs.forbid_data_body_reads(&[]).unwrap();
    let catalog = store.collection_catalog().await.unwrap();
    assert_ne!(
        member_pack(&catalog, &source.members[0]),
        member_pack(&catalog, &other)
    );
    assert_eq!(
        store.get(&source.members[0], None).await.unwrap(),
        source.bytes[0]
    );
    assert_eq!(store.identities().unwrap(), [source.members[0].clone()]);
    fixture.fs.forbid_data_body_reads(&paths).unwrap();
    fixture.fs.reset();

    // This member is uncached and in another pack, so success must pass through
    // the catalog cache independently of raw containing-pack or body reuse.
    assert_eq!(store.get(&other, None).await.unwrap(), expected);
    let wrong_kind = TERRANE_V1
        .from_digest(
            IdentityKind::Node,
            &source.members[0].terrane_v1_digest().unwrap(),
        )
        .unwrap();
    for identity in [&source.members[1], &wrong_kind] {
        assert_absent(&store.get(identity, None).await.unwrap_err(), identity);
    }
    assert_eq!(
        store.identities().unwrap(),
        [source.members[0].clone(), other.clone()]
    );
    assert_eq!(fixture.fs.data_body_read_attempts(), 0);
    for path in &paths {
        assert_eq!(
            store
                .reads()
                .unwrap()
                .iter()
                .filter(|read| read.path() == path)
                .count(),
            1 + usize::from(path == partial_reads[0].path())
        );
    }
    let fresh = MetadataStore::new(&held, &observed, &session);
    assert_pack_io(&fresh.get(&other, None).await.unwrap_err());
    assert_eq!(fixture.fs.data_body_read_attempts(), 1);
    assert!(fresh.identities().unwrap().is_empty());
    assert_eq!(fixture.fs.effects(), 0);
    fixture.fs.forbid_data_body_reads(&[]).unwrap();
    assert_eq!(fresh.get(&other, None).await.unwrap(), expected);
    drop(fresh);
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
}

#[tokio::test]
async fn gc_catalog_sharing_refuses_changed_artifacts_at_native_handoff() {
    refuse_changed_checkpoint(SharingMutation::CatalogShard).await;
    refuse_changed_checkpoint(SharingMutation::CatalogFilter).await;
}

#[tokio::test]
async fn gc_catalog_sharing_preserves_session_original_and_restore_checks() {
    let fixture = Fixture::new().await;
    let session = metadata_session(&fixture).await;
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let before = (observed.state().clone(), observed.logical().clone());
    let store = MetadataStore::new(&held, &observed, &session);
    store.collection_catalog().await.unwrap();
    drop(session.operation().unwrap());
    fixture.fs.reset();
    let error = match store.collection_catalog().await {
        Err(error) => error,
        Ok(_) => panic!("cached parsed catalog survived Session cancellation"),
    };
    assert_eq!(
        error.kind(),
        &StoreErrorKind::Denied {
            verb: "gc-checkpoint",
            pattern: "current configured collector session".into(),
        }
    );
    assert!(std::error::Error::source(&error).is_none());
    assert!(store.identities().unwrap().is_empty());
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
    fixture.cleanup();

    refuse_changed_checkpoint(SharingMutation::Original).await;
    restore_metadata_member().await;
}
