//! Checks genuine durable collection checkpoints and fresh complete replay.

use super::*;
use terrane_format::gc::{GcMark, Phase};

/// Reopens complete I/P/G and side-record marks under the actual selected lease.
///
/// # Panics
/// Panics if native publication, marking, replay or an immutable-byte oracle fails.
pub(super) async fn complete_checkpoint_reopens_and_preserves_contextual_marks() {
    let fixture = Fixture::new_indexed().await;
    let repository = production_repository(&fixture).await;
    let publication = publish_indexed(&fixture, &repository).await;
    let verified = repository
        .coordinator()
        .guard()
        .verified_tree(publication.head.commit)
        .await
        .assert_success();
    let mut record = AttrRecord::new(
        publication.present_object,
        AttributeValue::Sha256([11; 32]),
        publication.head.commit,
    );
    record
        .sign(&verified.commit, &terminal_seed())
        .assert_success();
    let bytes = record.encode().assert_success();
    let record_hash = repository
        .coordinator()
        .guard()
        .store()
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Attribute, &bytes).assert_success(),
        ))
        .await
        .assert_success()
        .terrane_v1_digest()
        .assert_success();
    let mut collection = Collection::start(
        repository.coordinator().guard(),
        &fixture.authority,
        "collector".into(),
        1_000,
        1,
        windows(),
    )
    .await
    .assert_success();
    let holder = SingleHeld::acquire(repository.coordinator().guard().store())
        .await
        .assert_success();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.assert_success();
    let adapted = crate::guard::collection_authority::historical_guard(
        repository.coordinator().guard(),
        &held,
        &observed,
        &collection.session,
        collection.session.clock().assert_success(),
    )
    .assert_success();
    let paths = arm_data_reads(&fixture, adapted.store()).await;
    drop(adapted);
    drop(observed);
    drop(held);
    drop(holder);

    collection.mark_batch(512).await.assert_success();

    assert!(collection.state().pending.is_empty());
    assert_eq!(collection.state().phase, Phase::Mark);
    let selected = fixture.selected_state(1).await;
    assert_eq!(collection.state(), &selected);
    let context = ProofContext::new(publication.head.commit, publication.owner, b"/".to_vec())
        .assert_success();
    for hash in publication.data.nodes.keys() {
        assert!(selected.objects.contains(&ExpandedObject {
            kind: 2,
            hash: *hash,
            flags: INDEX | ROOT,
            proof_context: Some(context.clone())
        }));
    }
    assert!(selected.objects.contains(&ExpandedObject {
        kind: 7,
        hash: record_hash,
        flags: 0,
        proof_context: Some(context)
    }));
    let mut marked = BTreeSet::new();
    let immutable = selected
        .checkpoints
        .iter()
        .map(|pointer| {
            let path = fixture
                .config
                .root
                .join(format!("gc/1/mark/{}/{}", pointer.shard, pointer.revision));
            let bytes = std::fs::read(&path).assert_success();
            let mark = GcMark::decode(&bytes).assert_success();
            marked.extend(mark.hashes().iter().copied());
            (path, bytes)
        })
        .collect::<Vec<_>>();
    assert!(
        publication
            .data
            .nodes
            .keys()
            .all(|hash| marked.contains(hash))
    );
    assert!(marked.contains(&record_hash));
    assert!(marked.contains(&publication.present_object));
    assert!(marked.contains(&publication.missing_object));
    let lease = collection.lease().clone();
    drop(collection);
    let selections = crate::gc::runner::fixture::capture_view_selections(
        repository.coordinator().guard(),
        &[publication.head.commit],
    )
    .await;
    drop(repository);
    let reopened = production_repository_with_selections(&fixture, selections).await;

    let mut resumed = Collection::resume(
        reopened.coordinator().guard(),
        &fixture.authority,
        lease,
        1_000,
        1,
        windows(),
    )
    .await
    .assert_success();

    assert_eq!(resumed.state(), &selected);
    resumed.finish_mark().await.assert_success();
    assert_eq!(resumed.state().phase, Phase::Sweep);
    assert_eq!(resumed.state().checkpoints, selected.checkpoints);
    for (path, bytes) in immutable {
        assert_eq!(std::fs::read(path).assert_success(), bytes);
    }
    prove_data_read_traps(&fixture, &paths).await;
    drop(resumed);
    drop(reopened);
    fixture.cleanup();
}
