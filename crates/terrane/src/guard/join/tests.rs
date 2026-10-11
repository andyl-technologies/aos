//! Checks ordinary join witness reuse without weakening independent authority.

#![allow(
    clippy::unwrap_used,
    reason = "genuine native fixture failures must fail tests"
)]

use crate::guard::admission::tests::support::observed;
use crate::guard::{JoinKind, JoinRequest};
use crate::ref_advance::tests::{fixture, request_file, token};
use crate::store::RefStore;
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
    let base = coordinator
        .advance(&mut session, request_file(Vec::new(), PLAINTEXT))
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

    // These addressed reads include independent destination/source and source
    // path authorizations, input witnesses, base verification, and subsequent
    // candidate admission. The former repeated histories added three base
    // reads and one incoming read; no current decision is removed.
    assert_eq!(
        guard
            .store()
            .content_reads(IdentityKind::Commit, base.commit),
        13
    );
    assert_eq!(
        guard
            .store()
            .content_reads(IdentityKind::Commit, incoming.commit),
        6
    );
    assert_eq!(guard.store().content_reads(IdentityKind::Node, root), 22);
    assert_eq!(guard.store().reference_reads(CHILD), 2);
    assert_eq!(
        admitted.commit.commit().parents,
        [base.commit, incoming.commit]
    );
    assert_eq!(
        admitted.source_authorization.as_ref().unwrap().record,
        incoming
    );
    assert_eq!(admitted.commit.commit().tree, root);
    assert!(excluded.is_empty());
    guard.store().assert_no_effects();
    assert_eq!(coordinator.store().ref_get(MAIN).await.unwrap(), Some(base));
}
