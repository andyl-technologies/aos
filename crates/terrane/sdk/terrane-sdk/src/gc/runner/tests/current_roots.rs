//! Qualifies cycle/current union and whole fences using the real native factory.
//!
//! These cases exercise read-only current-root production. They select no
//! retirement, Trash or deletion effect and establish no backend age permission.

use super::*;
use crate::bucket::held::SingleHeld;
use crate::bucket::publication::collection_observation::MetadataStore;
use terrane_format::gc::publication::{CommittedSelection, LogicalChange};

#[tokio::test]
async fn gc_current_native_recomputes_after_ref_change_and_preserves_cycle_marks() {
    let fixture = Fixture::new().await;
    let mut collection = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "current-collector".into(),
        1_000,
        41,
        windows(),
    )
    .await
    .unwrap();
    collection.mark_batch(32).await.unwrap();
    collection.finish_mark().await.unwrap();
    let cycle_roots = collection.roots().clone();
    let cycle_state = collection.state().clone();
    let replacement = fixture.publish_count_zero().await;
    fixture.clock.set(101, 1);
    let operation = collection.session.operation().unwrap();
    collection
        .session
        .renew(&Collector::new(fixture.guard(), &fixture.authority))
        .await
        .unwrap();
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let store = MetadataStore::new(&held, &observed, &collection.session);
    let catalog = store.collection_catalog().await.unwrap();
    let mut data_paths = Vec::new();
    let mut indexes = Vec::new();
    for row in catalog.inventory().unwrap() {
        let id = crate::pack::PackId::from_random_bytes(row.pack_id);
        let read = store.pack_index(&catalog, id).await.unwrap();
        let header = read.index().bytes().unwrap();
        assert_eq!(&header[..6], b"TRPK\x01\x00");
        // Independent canonical wire flag: bit one distinguishes metadata.
        if header[6] & 2 == 0 {
            data_paths.push(read.pack_path().to_owned());
        }
        indexes.push(read);
    }
    assert!(!data_paths.is_empty());
    fixture.fs.forbid_data_body_reads(&data_paths).unwrap();
    fixture.fs.reset();

    let current = crate::selected_bridge::native_current_collection::qualify(
        fixture.guard(),
        &fixture.authority,
        &collection.session,
        &held,
        &observed,
        (&cycle_roots, &cycle_state),
        windows(),
    )
    .await
    .unwrap();
    let old_chunk = TERRANE_V1
        .calculate(IdentityKind::Chunk, b"published source")
        .unwrap()
        .terrane_v1_digest()
        .unwrap();
    let new_chunk = TERRANE_V1
        .calculate(IdentityKind::Chunk, b"current source")
        .unwrap()
        .terrane_v1_digest()
        .unwrap();
    let (cycle, fresh) = current.verified_marks();
    assert!(cycle.contains(&old_chunk));
    assert!(!cycle.contains(&new_chunk));
    assert!(!fresh.contains(&old_chunk));
    assert!(fresh.contains(&new_chunk));
    assert_eq!(current.selected_checkpoint(), (&cycle_roots, &cycle_state));
    assert_eq!(current.fresh_traversal().0.timestamp, 101);
    assert!(
        current
            .fresh_traversal()
            .0
            .roots
            .iter()
            .any(|root| root.commit == replacement.commit && root.reason == RootReason::Current)
    );
    let old_container = indexes
        .iter()
        .find(|read| {
            read.snapshot()
                .entries()
                .iter()
                .any(|entry| entry.hash() == &old_chunk)
        })
        .unwrap();
    assert!(!current.members_unmarked(old_container.snapshot()));
    assert_eq!(fixture.fs.data_body_read_attempts(), 0);
    assert_eq!(fixture.fs.effects(), 0);
    current.revalidate().await.unwrap();

    // Exercise every forbidden body-read lane after qualification so an
    // unarmed trap cannot turn a zero-attempt count into a false positive.
    assert!(fixture.fs.read(&data_paths[0]).await.is_err());
    assert!(
        fixture
            .fs
            .read_range(
                &data_paths[0],
                crate::store::ByteRange {
                    start: 0,
                    length: 1,
                }
            )
            .await
            .is_err()
    );
    assert!(fixture.fs.read_nofollow(&data_paths[0]).await.is_err());
    assert_eq!(fixture.fs.data_body_read_attempts(), 3);

    drop(current);
    drop(store);
    drop(observed);
    drop(held);
    drop(holder);
    operation.complete();
    drop(collection);
    fixture.cleanup();
}

#[tokio::test]
async fn gc_current_native_keeps_opaque_notes_absent_history_and_guard_record() {
    let fixture = Fixture::new().await;
    let name = "refs/notes/profiles/_/opaque";
    let bytes = [0xff, 0x00, 0x81];
    fixture.publish_notes(&[(name, &bytes)]).await;
    let mut collection = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "current-collector".into(),
        1_000,
        42,
        windows(),
    )
    .await
    .unwrap();
    collection.mark_batch(32).await.unwrap();
    collection.finish_mark().await.unwrap();
    let operation = collection.session.operation().unwrap();
    collection
        .session
        .renew(&Collector::new(fixture.guard(), &fixture.authority))
        .await
        .unwrap();
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let previous = held.observe_publication_unrepaired().await.unwrap();
    let key = BucketKey::ref_record("refs/heads/_/main")
        .unwrap()
        .as_str()
        .to_owned();
    let expected = previous.logical().get(&key).unwrap().clone();
    held.publish_raw(
        &previous,
        vec![LogicalChange {
            key,
            expected,
            new: None,
        }],
    )
    .await
    .unwrap();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    fixture.fs.reset();

    let current = crate::selected_bridge::native_current_collection::qualify(
        fixture.guard(),
        &fixture.authority,
        &collection.session,
        &held,
        &observed,
        (collection.roots(), collection.state()),
        windows(),
    )
    .await
    .unwrap();
    let note = current
        .fence()
        .refs
        .iter()
        .find(|row| row.name == name)
        .unwrap();
    assert_eq!(note.current.as_deref(), Some(bytes.as_slice()));
    assert_eq!(note.selection, CommittedSelection::Never);
    assert!(note.log.is_none());
    assert!(
        current
            .fresh_traversal()
            .0
            .roots
            .iter()
            .all(|root| root.reference.class() != terrane_format::refs::RefClass::Notes)
    );
    let removed = current
        .fence()
        .refs
        .iter()
        .find(|row| row.name == "refs/heads/_/main")
        .unwrap();
    assert!(removed.current.is_none());
    assert_eq!(
        removed.selection,
        CommittedSelection::Selected(fixture.head.clone().into())
    );
    assert_eq!(removed.log.as_ref().unwrap().record, fixture.head);
    let guard_read = current.guard_record();
    assert!(
        guard_read
            .path()
            .starts_with(fixture.parent.join("publication"))
    );
    assert_eq!(
        *blake3::hash(guard_read.bytes().unwrap()).as_bytes(),
        current.fence().guard
    );
    assert_eq!(
        current.effect_context().control_owners()[0].configured_operator_uid(),
        observed.configured_operator_uid()
    );
    assert!(!current.effect_context().controls()[0].records().is_empty());
    assert_eq!(fixture.fs.effects(), 0);
    current.revalidate().await.unwrap();

    held.publish_raw(
        &observed,
        vec![LogicalChange {
            key: BucketKey::ref_record(name).unwrap().as_str().to_owned(),
            expected: Some(bytes.to_vec()),
            new: Some(b"changed".to_vec()),
        }],
    )
    .await
    .unwrap();
    assert!(current.revalidate().await.is_err());
    drop(current);
    drop(observed);
    drop(previous);
    drop(held);
    drop(holder);
    operation.complete();
    drop(collection);
    fixture.cleanup();
}

#[tokio::test]
async fn gc_current_native_refuses_incomplete_checkpoint_and_stale_whole_lease() {
    let fixture = Fixture::new().await;
    let mut collection = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "current-collector".into(),
        1_000,
        43,
        windows(),
    )
    .await
    .unwrap();
    {
        let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
        let held = holder.destination();
        let observed = held.observe_publication_unrepaired().await.unwrap();
        fixture.fs.reset();
        assert!(
            crate::selected_bridge::native_current_collection::qualify(
                fixture.guard(),
                &fixture.authority,
                &collection.session,
                &held,
                &observed,
                (collection.roots(), collection.state()),
                windows()
            )
            .await
            .is_err()
        );
        assert_eq!(fixture.fs.effects(), 0);
    }
    collection.mark_batch(32).await.unwrap();
    collection.finish_mark().await.unwrap();
    Collector::new(fixture.guard(), &fixture.authority)
        .renew(collection.lease(), 10_000)
        .await
        .unwrap();
    {
        let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
        let held = holder.destination();
        let observed = held.observe_publication_unrepaired().await.unwrap();
        fixture.fs.reset();
        assert!(
            crate::selected_bridge::native_current_collection::qualify(
                fixture.guard(),
                &fixture.authority,
                &collection.session,
                &held,
                &observed,
                (collection.roots(), collection.state()),
                windows()
            )
            .await
            .is_err()
        );
        assert_eq!(fixture.fs.effects(), 0);
    }
    drop(collection);
    fixture.cleanup();
}
