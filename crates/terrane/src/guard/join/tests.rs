//! Checks ordinary join witness reuse without weakening independent authority.

#![allow(
    clippy::unwrap_used,
    reason = "genuine native fixture failures must fail tests"
)]

use crate::guard::admission::tests::support::{archive_original, observed};
use crate::guard::{JoinKind, JoinRequest};
use crate::ref_advance::tests::{fixture, request_file, token};
use crate::store::{RefStore, StoreErrorKind};
use std::error::Error;
use terrane_core::auth::Verb;
use terrane_core::identity::IdentityKind;
use terrane_core::refs::MergePolicy;

const MAIN: &str = "refs/heads/_/main";
const CHILD: &str = "refs/heads/_/child";
const PLAINTEXT: &[u8] = b"one exact tree and complete history per ordinary join input";

#[tokio::test]
async fn join_admission_retains_exact_trees_with_histories_and_verifies_base_independently() {
    assert_join_work(JoinKind::Merge).await;
}

#[tokio::test]
async fn fold_admission_retains_exact_inputs_and_checks_the_independent_fork_base() {
    assert_join_work(JoinKind::Fold).await;
}

async fn assert_join_work(kind: JoinKind) {
    let coordinator = fixture().await;
    let mut session = coordinator.begin(MAIN, &token(), "sdk").await.unwrap();
    let ancestor = coordinator
        .advance(&mut session, request_file(Vec::new(), b"earlier join tree"))
        .await
        .unwrap();
    let base = coordinator
        .advance(&mut session, request_file(vec![ancestor.commit], PLAINTEXT))
        .await
        .unwrap();
    let mut proposal = request_file(Vec::new(), PLAINTEXT);
    proposal.uploads.clear();
    let incoming = coordinator.fork(MAIN, CHILD, proposal).await.unwrap();
    let root = coordinator
        .guard()
        .verified_tree(base.commit)
        .await
        .unwrap()
        .evidence
        .root;
    let guard = observed(coordinator.guard());
    let mut request = request_file(Vec::new(), PLAINTEXT);
    request.uploads.clear();

    let native_reads = coordinator.store().observe_content_for_tests();
    native_reads.reset();

    let (admitted, excluded) = guard
        .admit_join(
            MAIN,
            session.epoch(),
            JoinRequest {
                source: CHILD,
                request,
                policies: &[MergePolicy::PreferTheirs],
                kind,
            },
        )
        .await
        .unwrap();

    // Retained native current readers bypass the addressed ordinary store
    // observer. Both paths must do work; totals are not an ACL oracle.
    let base_reads = guard
        .store()
        .content_reads(IdentityKind::Commit, base.commit);
    let incoming_reads = guard
        .store()
        .content_reads(IdentityKind::Commit, incoming.commit);
    assert!(base_reads > 0);
    assert!(
        guard
            .store()
            .content_reads(IdentityKind::Commit, ancestor.commit)
            > 0
    );
    assert!(incoming_reads > 0);
    assert!(guard.store().content_reads(IdentityKind::Node, root) > 0);
    let physical_reads = native_reads.snapshot();
    assert_eq!(physical_reads.commit_puts, 0);
    assert_eq!(physical_reads.node_puts, 0);
    assert!(physical_reads.commit_gets > guard.store().total_content_reads(IdentityKind::Commit));
    assert!(physical_reads.node_gets > guard.store().content_reads(IdentityKind::Node, root));
    assert_eq!(guard.store().reference_reads(CHILD), 2);
    assert_eq!(
        admitted.commit.commit().parents,
        [base.commit, incoming.commit]
    );
    let source = admitted.source_authorization.as_ref().unwrap();
    assert_eq!(source.record, incoming);
    assert_eq!(source.reference, CHILD);
    assert_eq!(
        source.verb,
        match kind {
            JoinKind::Merge => Verb::Read,
            JoinKind::Fold => Verb::Fork,
        }
    );
    assert_eq!(source.paths, [b"/".to_vec()]);
    assert_eq!(admitted.expected.as_ref(), Some(&base));
    assert_eq!(admitted.commit.commit().tree, root);
    assert!(excluded.is_empty());
    guard.store().assert_no_effects();
    assert_eq!(
        coordinator.store().ref_get(MAIN).await.unwrap(),
        Some(base.clone())
    );
    assert_eq!(
        coordinator.store().ref_get(CHILD).await.unwrap(),
        Some(incoming.clone())
    );

    let (original, archived) = archive_original(coordinator.guard(), ancestor.commit).await;
    guard.store().reset();
    let mut request = request_file(Vec::new(), PLAINTEXT);
    request.uploads.clear();
    let failure = match guard
        .admit_join(
            MAIN,
            session.epoch(),
            JoinRequest {
                source: CHILD,
                request,
                policies: &[MergePolicy::PreferTheirs],
                kind,
            },
        )
        .await
    {
        Err(failure) => failure,
        Ok(_) => panic!("missing ancestor Original must refuse join admission"),
    };
    tokio::fs::rename(&archived, &original).await.unwrap();
    assert!(matches!(
        failure.kind(),
        StoreErrorKind::Unavailable { retry_after: None }
    ));
    assert_eq!(
        failure
            .source()
            .and_then(|source| source.downcast_ref::<std::io::Error>())
            .unwrap()
            .kind(),
        std::io::ErrorKind::NotFound
    );
    guard.store().assert_no_effects();
    assert_eq!(coordinator.store().ref_get(MAIN).await.unwrap(), Some(base));
    assert_eq!(
        coordinator.store().ref_get(CHILD).await.unwrap(),
        Some(incoming)
    );
}
