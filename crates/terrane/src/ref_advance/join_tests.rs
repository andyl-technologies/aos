//! Exercises explicit ordered merge publication under concurrent native writers.

#![allow(clippy::unwrap_used)]

use super::tests::{fixture, request, request_file, token};
use crate::store::RefStore;

#[tokio::test]
async fn explicit_multiwriter_merges_complete_after_actual_publication_races() {
    use terrane_core::refs::{MergePolicy, RefPolicy};

    let coordinator = fixture().await;
    let destination = "refs/heads/_/main";
    let source = "refs/heads/_/child";
    let mut initial = coordinator
        .begin(destination, &token(), "sdk")
        .await
        .unwrap();
    coordinator
        .advance(&mut initial, request_file(Vec::new(), b"base"))
        .await
        .unwrap();
    let mut fork_request = request(Vec::new());
    fork_request.uploads.clear();
    coordinator
        .fork(destination, source, fork_request)
        .await
        .unwrap();
    let mut child = coordinator.begin(source, &token(), "sdk").await.unwrap();
    let child_parent = child.record().unwrap().commit;
    coordinator
        .advance(&mut child, request_file(vec![child_parent], b"incoming"))
        .await
        .unwrap();
    coordinator
        .set_policy(
            destination,
            Some(RefPolicy {
                multi_writer: Some(true),
                merge_policies: Some(vec![MergePolicy::PreferTheirs]),
                ..Default::default()
            }),
            &token(),
            "sdk",
        )
        .await
        .unwrap();
    let mut one = coordinator
        .begin(destination, &token(), "sdk")
        .await
        .unwrap();
    let mut two = coordinator
        .begin(destination, &token(), "sdk")
        .await
        .unwrap();
    let mut first_request = request(Vec::new());
    first_request.uploads.clear();
    let mut second_request = request(Vec::new());
    second_request.uploads.clear();
    let policies = [MergePolicy::PreferTheirs];
    let (first, second) = tokio::join!(
        coordinator.merge(&mut one, source, first_request, &policies),
        coordinator.merge(&mut two, source, second_request, &policies),
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_ne!(first.seq, second.seq);
    assert_eq!(first.seq.abs_diff(second.seq), 1);
    let head = coordinator
        .store()
        .ref_get(destination)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head.seq, first.seq.max(second.seq));
    let signed_head = coordinator
        .guard()
        .verified_tree(head.commit)
        .await
        .unwrap();
    assert_eq!(signed_head.commit.commit().parents.len(), 2);
    assert_ne!(
        signed_head.commit.commit().parents[1],
        child.record().unwrap().commit,
        "loser must rebase its own signed merge proposal, not merely rerun the source merge"
    );
    let original_proposal = coordinator
        .guard()
        .verified_tree(signed_head.commit.commit().parents[1])
        .await
        .unwrap();
    assert_eq!(
        original_proposal.commit.commit().parents[1],
        child.record().unwrap().commit
    );
    let snapshot = coordinator
        .guard()
        .read_snapshot(destination, &token(), b"/file", "sdk")
        .await
        .unwrap();
    let entry = snapshot
        .history
        .entry(
            &snapshot
                .history
                .locate(snapshot.commit.identity(), b"file")
                .unwrap()
                .0,
        )
        .unwrap();
    let terrane_core::tree_format::EntryKind::File { content, size, .. } = entry.kind else {
        panic!("missing file");
    };
    assert_eq!(
        coordinator
            .guard()
            .read_content(&snapshot, b"/file", content, size)
            .await
            .unwrap(),
        b"incoming"
    );
}

#[tokio::test]
async fn keep_conflict_admits_verified_base_and_both_candidate_references() {
    let coordinator = fixture().await;
    let mut parent = coordinator
        .begin("refs/heads/_/main", &token(), "sdk")
        .await
        .unwrap();
    let base = coordinator
        .advance(&mut parent, request_file(Vec::new(), b"base"))
        .await
        .unwrap();
    let mut fork_request = request(Vec::new());
    fork_request.uploads.clear();
    coordinator
        .fork(parent.reference(), "refs/heads/_/child", fork_request)
        .await
        .unwrap();
    let mut child = coordinator
        .begin("refs/heads/_/child", &token(), "sdk")
        .await
        .unwrap();
    let child_parent = child.record().unwrap().commit;
    coordinator
        .advance(&mut child, request_file(vec![child_parent], b"theirs"))
        .await
        .unwrap();
    coordinator
        .advance(&mut parent, request_file(vec![base.commit], b"ours"))
        .await
        .unwrap();
    let mut proposal = request(Vec::new());
    proposal.uploads.clear();
    let published = coordinator
        .merge(
            &mut parent,
            child.reference(),
            proposal,
            &[terrane_core::refs::MergePolicy::KeepConflict],
        )
        .await
        .unwrap();
    assert_eq!(published.policy.as_ref().unwrap().conflicted, Some(true));
    let checked = coordinator
        .guard()
        .verified_tree(published.commit)
        .await
        .unwrap();
    let tree = checked
        .evidence
        .tree(checked.evidence.root, 262144)
        .unwrap();
    let entry = tree.get(b"file").unwrap();
    let terrane_core::tree_format::EntryKind::Conflict { candidates, base } = &entry.kind else {
        panic!("missing retained conflict");
    };
    assert_eq!(candidates.len(), 2);
    assert!(base.as_ref().unwrap().is_some());
    drop(tree);
    coordinator
        .guard()
        .verified_history(published.commit)
        .await
        .unwrap();
}
