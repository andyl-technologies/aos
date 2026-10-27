//! Changes real native policy heads between independently checked read phases.

use super::SnapshotPathBatch;
use crate::{
    ref_advance::tests::{fixture, request_file, token},
    store::{StoreErrorKind, StoreFailure},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const REFERENCE: &str = "refs/heads/_/main";

fn assert_denied(result: Result<(), StoreFailure>) {
    assert!(matches!(result, Err(error) if matches!(error.kind(), StoreErrorKind::Denied { .. })));
}

#[tokio::test]
async fn stable_current_policy_accepts_a_complete_historical_read() -> TestResult {
    let repository = fixture().await;
    let mut writer = repository.begin(REFERENCE, &token(), "sdk").await?;
    let first = repository
        .advance(&mut writer, request_file(Vec::new(), b"historical bytes"))
        .await?;
    repository
        .advance(
            &mut writer,
            request_file(vec![first.commit], b"current bytes"),
        )
        .await?;
    let guard = repository.guard();
    let snapshot = guard
        .read_commit_snapshot(first.commit, &token(), b"/", "sdk")
        .await?;

    let batch = SnapshotPathBatch::begin(guard, &snapshot).await?;
    batch.authorize_path(b"/").await?;
    batch.authorize_path(b"/file").await?;
    batch.finish().await?;
    Ok(())
}

#[tokio::test]
async fn a_policy_transition_between_paths_refuses_the_bulk_read() -> TestResult {
    let repository = fixture().await;
    let mut writer = repository.begin(REFERENCE, &token(), "sdk").await?;
    let first = repository
        .advance(&mut writer, request_file(Vec::new(), b"historical bytes"))
        .await?;
    let guard = repository.guard();
    let snapshot = guard
        .read_snapshot(REFERENCE, &token(), b"/", "sdk")
        .await?;
    let batch = SnapshotPathBatch::begin(guard, &snapshot).await?;
    batch.authorize_path(b"/").await?;

    repository
        .advance(
            &mut writer,
            request_file(vec![first.commit], b"new policy head"),
        )
        .await?;

    // Both paths still pass ordinary independent Read. The complete disclosure
    // must additionally refuse mixing the two actual policy reference values.
    guard.authorize_snapshot_path(&snapshot, b"/").await?;
    guard.authorize_snapshot_path(&snapshot, b"/file").await?;
    assert_denied(batch.authorize_path(b"/file").await);
    assert_denied(batch.finish().await);

    let restarted = SnapshotPathBatch::begin(guard, &snapshot).await?;
    restarted.authorize_path(b"/file").await?;
    restarted.finish().await?;
    Ok(())
}

#[tokio::test]
async fn returning_to_the_same_commit_does_not_hide_a_closing_head_change() -> TestResult {
    let repository = fixture().await;
    let mut writer = repository.begin(REFERENCE, &token(), "sdk").await?;
    let first = repository
        .advance(&mut writer, request_file(Vec::new(), b"historical bytes"))
        .await?;
    let guard = repository.guard();
    let snapshot = guard
        .read_snapshot(REFERENCE, &token(), b"/", "sdk")
        .await?;
    let batch = SnapshotPathBatch::begin(guard, &snapshot).await?;
    batch.authorize_path(b"/file").await?;

    let second = repository
        .advance(
            &mut writer,
            request_file(vec![first.commit], b"intermediate head"),
        )
        .await?;
    let returned = repository
        .rollback(&mut writer, first.commit, &token(), "sdk")
        .await?;
    assert_eq!(returned.commit, first.commit);
    assert_eq!(returned.seq, second.seq + 1);
    assert_ne!(returned, first);

    guard.authorize_snapshot_path(&snapshot, b"/file").await?;
    assert_denied(batch.finish().await);
    Ok(())
}
