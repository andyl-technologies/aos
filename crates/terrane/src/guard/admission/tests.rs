//! Checks addressed native work and fresh refusal after earlier successful admission.

#![allow(
    clippy::unwrap_used,
    reason = "genuine native fixture failures must fail tests"
)]

pub(in crate::guard) mod support;

use crate::ref_advance::tests::{fixture, request_file, request_file_acl, token};
use crate::store::{RefStore, StoreErrorKind};
use std::error::Error;
use support::{fork_request, observed, refresh_retained};
use terrane_core::identity::IdentityKind;

const SOURCE: &str = "refs/heads/_/main";
const CHILD: &str = "refs/heads/_/child";
const PLAINTEXT: &[u8] = b"ordinary admission retains exact immutable witnesses";

#[tokio::test]
async fn fork_admission_uses_one_complete_source_tree_check_and_keeps_path_checks() {
    let coordinator = fixture().await;
    let mut session = coordinator.begin(SOURCE, &token(), "sdk").await.unwrap();
    let head = coordinator
        .advance(&mut session, request_file(Vec::new(), PLAINTEXT))
        .await
        .unwrap();
    let request = fork_request(coordinator.guard(), head.commit).await;
    let source_tree = coordinator
        .guard()
        .verified_tree(head.commit)
        .await
        .unwrap()
        .evidence
        .root;
    let guard = observed(coordinator.guard());

    let admitted = guard.admit_fork(SOURCE, CHILD, 1, request).await.unwrap();

    // Root authorization, exact source verification and root-path authorization
    // each load the target and its complete history. The former standalone
    // history traversal added a seventh addressed commit read.
    assert_eq!(
        guard
            .store()
            .content_reads(IdentityKind::Commit, head.commit),
        6
    );
    assert_eq!(
        guard.store().content_reads(IdentityKind::Node, source_tree),
        7
    );
    assert_eq!(guard.store().reference_reads(SOURCE), 2);
    assert_eq!(admitted.commit.commit().tree, source_tree);
    assert_eq!(admitted.commit.commit().parents, [head.commit]);
    assert_eq!(admitted.source_authorization.as_ref().unwrap().record, head);
    assert!(admitted.uploads.is_empty());
    guard.store().assert_no_effects();
    assert!(coordinator.store().ref_get(CHILD).await.unwrap().is_none());
}

#[tokio::test]
async fn existing_commit_admission_checks_the_exact_parent_once_after_current_authorization() {
    let coordinator = fixture().await;
    let mut session = coordinator.begin(SOURCE, &token(), "sdk").await.unwrap();
    let head = coordinator
        .advance(&mut session, request_file(Vec::new(), PLAINTEXT))
        .await
        .unwrap();
    let root = coordinator
        .guard()
        .verified_tree(head.commit)
        .await
        .unwrap()
        .evidence
        .root;
    let guard = observed(coordinator.guard());

    let admitted = guard
        .admit(
            SOURCE,
            session.epoch(),
            request_file(vec![head.commit], PLAINTEXT),
        )
        .await
        .unwrap();

    // Independent current authorization and exact parent verification each
    // perform two addressed reads. The discarded standalone history added one.
    assert_eq!(
        guard
            .store()
            .content_reads(IdentityKind::Commit, head.commit),
        4
    );
    assert_eq!(guard.store().content_reads(IdentityKind::Node, root), 4);
    assert_eq!(admitted.expected.as_ref(), Some(&head));
    assert_eq!(admitted.commit.commit().parents, [head.commit]);
    guard.store().assert_no_effects();
    assert_eq!(
        coordinator.store().ref_get(SOURCE).await.unwrap(),
        Some(head)
    );
}

#[tokio::test]
async fn fork_admission_rechecks_current_source_acl_after_an_earlier_success() {
    let coordinator = fixture().await;
    let mut session = coordinator.begin(SOURCE, &token(), "sdk").await.unwrap();
    let head = coordinator
        .advance(&mut session, request_file(Vec::new(), PLAINTEXT))
        .await
        .unwrap();
    let first = fork_request(coordinator.guard(), head.commit).await;
    let next = fork_request(coordinator.guard(), head.commit).await;
    let guard = observed(coordinator.guard());
    guard.admit_fork(SOURCE, CHILD, 1, first).await.unwrap();

    let revoked = coordinator
        .advance(
            &mut session,
            request_file_acl(vec![head.commit], PLAINTEXT, 0),
        )
        .await
        .unwrap();
    refresh_retained(coordinator.guard(), &guard);
    guard.store().reset();
    let result = guard.admit_fork(SOURCE, CHILD, 1, next).await;

    let Err(failure) = result else {
        panic!("old admission must not retain source authority")
    };
    assert!(
        matches!(failure.kind(), StoreErrorKind::Denied { verb: "fork", pattern } if pattern == SOURCE)
    );
    assert_eq!(guard.store().reference_reads(SOURCE), 1);
    assert!(
        guard
            .store()
            .content_reads(IdentityKind::Commit, revoked.commit)
            > 0
    );
    guard.store().assert_no_effects();
    assert!(coordinator.store().ref_get(CHILD).await.unwrap().is_none());
}

#[tokio::test]
async fn existing_commit_admission_rechecks_protected_original_association_across_calls() {
    let coordinator = fixture().await;
    let mut session = coordinator.begin(SOURCE, &token(), "sdk").await.unwrap();
    let head = coordinator
        .advance(&mut session, request_file(Vec::new(), PLAINTEXT))
        .await
        .unwrap();
    let guard = observed(coordinator.guard());
    guard
        .admit(
            SOURCE,
            session.epoch(),
            request_file(vec![head.commit], PLAINTEXT),
        )
        .await
        .unwrap();
    let context = coordinator.guard().original_commit(&head.commit).unwrap();
    let hex = head
        .commit
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let association = context
        .baseline()
        .authority()
        .control()
        .join(format!("commit-{hex}.cbor"));
    let archived = association.with_extension("removed");
    tokio::fs::rename(&association, &archived).await.unwrap();
    guard.store().reset();

    let result = guard
        .admit(
            SOURCE,
            session.epoch(),
            request_file(vec![head.commit], PLAINTEXT),
        )
        .await;

    let Err(failure) = result else {
        panic!("retained in-memory context must not replace missing physical evidence")
    };
    // OriginalVerifier checks the real association's metadata before its bytes.
    // An absent file retains the native NotFound cause as an unavailable read.
    assert!(
        matches!(
            failure.kind(),
            StoreErrorKind::Unavailable { retry_after: None }
        ),
        "{failure:?}"
    );
    assert_eq!(
        failure
            .source()
            .and_then(|source| source.downcast_ref::<std::io::Error>())
            .unwrap()
            .kind(),
        std::io::ErrorKind::NotFound
    );
    assert!(
        guard
            .store()
            .content_reads(IdentityKind::Commit, head.commit)
            > 0
    );
    guard.store().assert_no_effects();
    assert_eq!(
        coordinator.store().ref_get(SOURCE).await.unwrap(),
        Some(head)
    );
    assert!(!association.exists());
}
