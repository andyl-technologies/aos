//! Qualifies opaque selected Notes without deriving content roots from their bytes.

use super::*;
use crate::bucket::held::SingleHeld;
use crate::bucket::publication::collection_observation;
use terrane_core::bucket::BucketCapabilities;
use terrane_core::gc::publication::LogicalChange;
use terrane_core::refs::{RefClass, RefRecord};

#[tokio::test]
async fn gc_native_opaque_notes_complete_mark_resume_and_keep_derived_roots() {
    let fixture = Fixture::new().await;
    let derived = fixture.publish_derived().await;
    let opaque_name = "refs/notes/completeness/_/opaque";
    let resembling_name = "refs/notes/memos/_/resembling";
    let opaque = [0xff, 0x00, 0x81, 0x7f];
    let invented_commit = [0xe1; 32];
    let resembling = RefRecord::first(invented_commit, 1, Default::default())
        .encode()
        .unwrap();
    let notes = [
        (opaque_name, opaque.as_slice()),
        (resembling_name, resembling.as_slice()),
    ];
    let notes_revision = fixture.publish_notes(&notes).await;

    {
        let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
        let held = holder.destination();
        let selected = held.observe_publication_unrepaired().await.unwrap();
        assert_eq!(selected.state().revision, notes_revision);
        let capabilities = BucketCapabilities::decode(
            selected
                .logical()
                .get("CAPABILITIES")
                .unwrap()
                .as_deref()
                .unwrap(),
        )
        .unwrap();
        let names = capabilities.ref_names.unwrap();
        for (name, bytes) in notes {
            assert!(names.iter().any(|registered| registered == name));
            let key = BucketKey::ref_record(name).unwrap();
            assert_eq!(
                selected.logical().get(key.as_str()).unwrap().as_deref(),
                Some(bytes)
            );
        }
        selected.revalidate().await.unwrap();
    }

    let mut collection = Collection::start(
        fixture.guard(),
        &fixture.authority,
        "notes-collector".into(),
        1_000,
        8,
        windows(),
    )
    .await
    .unwrap();
    assert!(collection.roots().roots.iter().all(|root| {
        root.reference.class() != RefClass::Notes && root.commit != invented_commit
    }));
    assert!(collection.roots().roots.iter().any(|root| {
        root.reference.as_str() == "refs/derived/_/collection"
            && root.commit == derived.commit
            && root.reason == RootReason::Current
    }));
    collection.mark_batch(32).await.unwrap();
    collection.finish_mark().await.unwrap();
    assert_eq!(collection.state().phase, Phase::Sweep);
    assert_eq!(fixture.selected_state(8).await, *collection.state());
    for pointer in &collection.state().checkpoints {
        let path = fixture
            .config
            .root
            .join(format!("gc/8/mark/{}/{}", pointer.shard, pointer.revision,));
        let mark = GcMark::decode(&std::fs::read(path).unwrap()).unwrap();
        assert!(!mark.contains(&invented_commit));
    }
    let completed = collection.state().clone();
    let lease = collection.lease().clone();
    drop(collection);

    let reopened = fixture.reopen_repository().await;
    let resumed = Collection::resume(
        reopened.coordinator().guard(),
        &fixture.authority,
        lease,
        1_000,
        8,
        windows(),
    )
    .await
    .unwrap();
    assert_eq!(resumed.state(), &completed);
    {
        let holder = SingleHeld::acquire(reopened.coordinator().guard().store())
            .await
            .unwrap();
        let held = holder.destination();
        let selected = held.observe_publication_unrepaired().await.unwrap();
        for (name, bytes) in notes {
            let key = BucketKey::ref_record(name).unwrap();
            assert_eq!(
                selected.logical().get(key.as_str()).unwrap().as_deref(),
                Some(bytes)
            );
        }
        selected.revalidate().await.unwrap();
    }
    drop(resumed);
    drop(reopened);
    fixture.cleanup();
}

#[tokio::test]
async fn gc_native_selected_note_change_fences_inventory_and_retained_effects() {
    let fixture = Fixture::new().await;
    let name = "refs/notes/profiles/_/current";
    let first = b"first opaque profile";
    let second = b"updated opaque profile";
    let initial_revision = fixture.publish_notes(&[(name, first)]).await;
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let before = held.observe_publication_unrepaired().await.unwrap();
    assert_eq!(before.state().revision, initial_revision);
    let roots = collection_observation::inventory(&held, &before, &mut Vec::new())
        .await
        .unwrap();
    assert!(
        roots
            .iter()
            .all(|root| root.name.class() != RefClass::Notes)
    );

    let key = BucketKey::ref_record(name).unwrap().as_str().to_owned();
    let change = LogicalChange {
        key: key.clone(),
        expected: Some(first.to_vec()),
        new: Some(second.to_vec()),
    };
    let selected = held.publish_raw(&before, vec![change]).await.unwrap();
    assert_eq!(selected.stamp.0, initial_revision + 1);

    assert!(before.revalidate().await.is_err());
    assert!(
        collection_observation::inventory(&held, &before, &mut Vec::new())
            .await
            .is_err()
    );
    assert!(
        held.publish_raw(
            &before,
            vec![LogicalChange {
                key: key.clone(),
                expected: Some(first.to_vec()),
                new: Some(b"stale opaque profile".to_vec()),
            }]
        )
        .await
        .is_err()
    );

    let after = held.observe_publication_unrepaired().await.unwrap();
    assert_eq!(after.stamp(), selected.stamp);
    assert_eq!(after.state(), &selected.state);
    assert_eq!(
        after.logical().get(&key).unwrap().as_deref(),
        Some(second.as_slice())
    );
    let roots = collection_observation::inventory(&held, &after, &mut Vec::new())
        .await
        .unwrap();
    assert!(
        roots
            .iter()
            .any(|root| root.name.as_str() == "refs/heads/_/main")
    );
    assert!(
        roots
            .iter()
            .all(|root| root.name.class() != RefClass::Notes)
    );
    after.revalidate().await.unwrap();

    drop(after);
    drop(before);
    drop(holder);
    fixture.cleanup();
}
