//! Checks whole source observations before publishing a previously admitted fork.

#![allow(clippy::unwrap_used)]

use super::AdvanceError;
use super::tests::{fixture, request, request_file, token};
use crate::store::{Clock, ContentStore, RefStore, StoreErrorKind};
use terrane_core::identity::{IdentityKind, TERRANE_V1};
use terrane_core::refs::RefLogReason;

#[tokio::test]
async fn changed_source_record_rejects_fork_before_immutable_publication() {
    let coordinator = fixture().await;
    let mut source = coordinator
        .begin("refs/heads/_/main", &token(), "sdk")
        .await
        .unwrap();
    let initial = coordinator
        .advance(&mut source, request_file(Vec::new(), b"source"))
        .await
        .unwrap();
    let mut destination = coordinator
        .begin("refs/heads/_/child", &token(), "sdk")
        .await
        .unwrap();
    let mut fork = request(Vec::new());
    fork.uploads.clear();
    let admitted = coordinator
        .guard()
        .admit_fork(
            source.reference(),
            destination.reference(),
            destination.epoch(),
            fork,
        )
        .await
        .unwrap();
    let candidate = TERRANE_V1
        .from_digest(IdentityKind::Commit, &admitted.commit.identity())
        .unwrap();
    let changed = coordinator
        .advance(&mut source, request_file(vec![initial.commit], b"changed"))
        .await
        .unwrap();
    assert_ne!(changed, initial);

    let outcome = coordinator
        .publish(
            &mut destination,
            admitted,
            coordinator.guard().clock().monotonic(),
            RefLogReason::Commit,
        )
        .await;

    assert!(
        matches!(outcome, Err(AdvanceError::Store(error)) if matches!(error.kind(), StoreErrorKind::Denied { .. }))
    );
    assert!(coordinator.store().get(&candidate, None).await.is_err());
    assert_eq!(
        coordinator
            .store()
            .ref_get(destination.reference())
            .await
            .unwrap(),
        None
    );
    assert!(
        coordinator
            .store()
            .ref_log_read(destination.reference(), 1)
            .await
            .unwrap()
            .is_empty()
    );
}
