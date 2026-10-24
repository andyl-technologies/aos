//! Checks completed collector dependency observations against real signed histories.

use super::*;
use crate::bucket::held::SingleHeld;
use crate::guard::{ConsumedResolver, HistoryObservation};
use crate::ref_advance::{DisclosureCommitRequest, DisclosureCommitSelection};
use witness_support::{MINIMUM, REFERENCE, file, physical_snapshot, proposal};

#[tokio::test]
async fn collection_history_preserves_ordinary_parents_and_independent_witnesses() {
    let source = fixture().await;
    let mut writer = source.begin(REFERENCE, &token(), "sdk").await.unwrap();
    let first = source
        .advance(
            &mut writer,
            request_file(Vec::new(), b"first ordinary source"),
        )
        .await
        .unwrap();
    let second = source
        .advance(
            &mut writer,
            request_file(vec![first.commit], b"second ordinary source"),
        )
        .await
        .unwrap();
    let authority = source.guard().configured_original_authority().unwrap();
    let holder = SingleHeld::acquire(source.store()).await.unwrap();
    let held = holder.destination();
    let identity = held.identity_proof();
    let guard = source
        .guard()
        .held_guard(holder.destination(), TokioClock)
        .unwrap();
    let consumed = ConsumedResolver::new(source.guard(), &authority).unwrap();
    let observation = HistoryObservation::held(&identity).tracked(&consumed);
    let before = physical_snapshot(source.store().root()).await;

    let checked = guard
        .verified_collection_tree_observed(second.commit, observation)
        .await
        .unwrap();
    let completed = checked.completed();
    let current = completed.dependencies(second.commit).unwrap();
    let ancestor = completed.dependencies(first.commit).unwrap();

    assert_eq!(checked.tree().commit.identity(), second.commit);
    assert_eq!(current.parents(), &[first.commit]);
    assert!(current.witnesses().contains(&first.commit));
    assert!(current.disclosure().is_none());
    assert!(ancestor.parents().is_empty());
    assert!(ancestor.witnesses().is_empty());
    assert!(ancestor.disclosure().is_none());
    assert!(completed.dependencies([0xa5; 32]).is_none());
    assert!(completed.history().commit(&first.commit).is_some());
    assert!(completed.history().commit(&second.commit).is_some());
    let occurrences = guard.collection_occurrences(&checked).unwrap();
    assert_eq!(occurrences.len(), 1);
    assert_eq!(occurrences[0].root(), checked.tree().evidence.root);
    assert_eq!(occurrences[0].path(), b"/");
    assert_eq!(occurrences[0].domain(), "public");
    assert_eq!(
        occurrences[0].interpretation(),
        &crate::guard::SelectedReadInterpretation::Legacy
    );
    let inputs = consumed.finish().unwrap();
    assert!(inputs.views.iter().any(|view| view.view == first.commit));
    assert!(inputs.views.iter().any(|view| view.view == second.commit));
    assert!(!inputs.controls.is_empty());
    assert_eq!(physical_snapshot(source.store().root()).await, before);

    // A signature/tree read cannot turn an invalid protected original record
    // into a completed result, even if this Guard previously checked the history.
    let registration = authority.control().join("registration.cbor");
    let original = tokio::fs::read(&registration).await.unwrap();
    tokio::fs::write(&registration, b"invalid registration")
        .await
        .unwrap();
    let invalid_before = physical_snapshot(source.store().root()).await;
    assert!(
        guard
            .verified_collection_tree_observed(second.commit, observation)
            .await
            .is_err()
    );
    assert_eq!(
        physical_snapshot(source.store().root()).await,
        invalid_before
    );
    tokio::fs::write(&registration, original).await.unwrap();
}

#[tokio::test]
async fn collection_history_retains_exact_certified_cuts_after_private_source_erasure() {
    let (source, source_authority, source_credentials) =
        independent_factory("private:writer").await;
    let (destination, destination_authority, _) = independent_factory("public").await;
    let plaintext = b"collector proof observation survives private source removal";
    let tree = |private| {
        Tree::build(
            vec![LeafItem {
                key: b"file".to_vec(),
                entry: file(plaintext),
            }],
            materialization::properties(private),
            MINIMUM,
            TreeUse::Ordinary,
        )
        .unwrap()
    };
    let private_tree = tree(true);
    let mut source_writer = source
        .begin(REFERENCE, source_authority.token(), "sdk")
        .await
        .unwrap();
    let source_head = source
        .advance(
            &mut source_writer,
            proposal(&source_authority, Vec::new(), &private_tree, &[plaintext]),
        )
        .await
        .unwrap();
    let public_tree = tree(false);
    let mut destination_writer = destination
        .begin(REFERENCE, destination_authority.token(), "sdk")
        .await
        .unwrap();
    let destination_head = destination
        .advance_disclosure(
            source.guard(),
            &mut destination_writer,
            DisclosureCommitRequest {
                proposal: proposal(
                    &destination_authority,
                    Vec::new(),
                    &public_tree,
                    &[plaintext],
                ),
                selections: vec![DisclosureCommitSelection {
                    source_reference: REFERENCE.into(),
                    source_commit: source_head.commit,
                    source_path: b"/file".to_vec(),
                    source_token: source_authority.token().to_vec(),
                    destination_path: b"/file".to_vec(),
                }],
            },
        )
        .await
        .unwrap();
    drop(source_writer);
    drop(source_authority);
    witness_support::erase_source(source, source_credentials).await;
    drop(destination_writer);
    let reopened = witness_support::reopen(destination, &destination_authority).await;
    let authority = reopened.guard().configured_original_authority().unwrap();
    let holder = SingleHeld::acquire(reopened.store()).await.unwrap();
    let held = holder.destination();
    let identity = held.identity_proof();
    let guard = reopened
        .guard()
        .held_guard(holder.destination(), TokioClock)
        .unwrap();
    let consumed = ConsumedResolver::new(reopened.guard(), &authority).unwrap();
    let observation = HistoryObservation::held(&identity).tracked(&consumed);
    let before = physical_snapshot(reopened.store().root()).await;

    let checked = guard
        .verified_collection_tree_observed(destination_head.commit, observation)
        .await
        .unwrap();
    let completed = checked.completed();
    let dependencies = completed.dependencies(destination_head.commit).unwrap();
    let batch = dependencies.disclosure().unwrap();

    assert_eq!(
        checked.tree().commit.commit().parents,
        vec![source_head.commit]
    );
    assert_eq!(batch.view(), destination_head.commit);
    assert!(batch.certified_parent(destination_head.commit, source_head.commit));
    assert!(!batch.certified_parent(source_head.commit, destination_head.commit));
    assert!(dependencies.parents().is_empty());
    assert!(dependencies.witnesses().is_empty());
    assert!(completed.dependencies(source_head.commit).is_none());
    assert!(completed.history().commit(&source_head.commit).is_none());
    assert!(
        completed
            .history()
            .commit(&destination_head.commit)
            .is_some()
    );
    assert_eq!(batch.boundaries().len(), 1);
    let boundary = &batch.boundaries()[0];
    assert_eq!(boundary.source().commit, source_head.commit);
    assert_eq!(boundary.root_occurrences(), &[b"/".to_vec()]);
    let occurrences = guard.collection_occurrences(&checked).unwrap();
    assert_eq!(occurrences.len(), 1);
    assert_eq!(occurrences[0].root(), checked.tree().evidence.root);
    assert_eq!(occurrences[0].path(), b"/");
    assert_eq!(occurrences[0].domain(), "public");
    let inputs = consumed.finish().unwrap();
    assert!(!inputs.disclosures.is_empty());
    assert!(
        inputs
            .views
            .iter()
            .any(|view| view.view == destination_head.commit)
    );
    assert!(
        inputs
            .views
            .iter()
            .all(|view| view.view != source_head.commit)
    );
    assert_eq!(physical_snapshot(reopened.store().root()).await, before);
}
