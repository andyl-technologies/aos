//! Exercises fresh authenticated cycles under one actual original collector session.

use terrane_format::gc::{Phase, RootReason, Windows};
use terrane_sdk::gc::runner::maintenance::{MAX_HINTS, MaintenanceCursor};
use terrane_sdk::gc::{lease::LeaseError, runner::CollectionError};

use super::{Fixture, OLD, TestResult};

#[tokio::test]
async fn fresh_cycles_retain_the_live_session_and_authenticate_changed_roots() -> TestResult {
    let fixture = Fixture::new().await?;
    let first = fixture.commit_bytes(OLD).await?;
    let mut collection = fixture
        .repository
        .start_local_collection(
            "repeating-collector".into(),
            1_000,
            1,
            Windows::new(30, 60, 60, 90)?,
        )
        .await?;
    let initial = collection.lease().clone();
    let original_roots = collection.roots().clone();
    let initial_state = collection.state().clone();

    let mut cursor = MaintenanceCursor::default();
    let original_cursor = cursor.clone();
    assert!(collection.maintenance_hints(&mut cursor, 0).await.is_err());
    assert!(
        collection
            .maintenance_hints(&mut cursor, MAX_HINTS + 1)
            .await
            .is_err()
    );
    assert_eq!(cursor, original_cursor);
    assert_eq!(collection.lease(), &initial);
    assert!(
        collection
            .maintenance_hints(&mut cursor, 2)
            .await?
            .is_empty()
    );
    assert_eq!(collection.roots(), &original_roots);
    assert_eq!(collection.state(), &initial_state);

    let refreshed = collection.lease().clone();
    assert!(collection.begin_cycle(2).await.is_err());
    assert_eq!(collection.state(), &initial_state);
    assert_eq!(collection.roots(), &original_roots);
    assert_eq!(collection.lease(), &refreshed);
    collection.mark_batch(32).await?;
    assert!(collection.state().pending.is_empty());
    collection.finish_mark().await?;

    let second = fixture
        .commit_bytes(b"new current root between marking cycles")
        .await?;
    assert_ne!(second, first);
    collection.begin_cycle(2).await?;

    assert_eq!(collection.state().cycle, 2);
    assert_eq!(collection.state().phase, Phase::Mark);
    assert_eq!(collection.lease().holder, initial.holder);
    assert_eq!(collection.lease().epoch, initial.epoch);
    assert!(collection.lease().expiry >= initial.expiry);
    assert!(
        collection
            .roots()
            .roots
            .iter()
            .any(|root| { root.reason == RootReason::Current && root.commit == second })
    );
    assert!(
        !collection
            .roots()
            .roots
            .iter()
            .any(|root| { root.reason == RootReason::Current && root.commit == first })
    );
    let competing = fixture
        .repository
        .start_local_collection(
            initial.holder.clone(),
            1_000,
            3,
            Windows::new(30, 60, 60, 90)?,
        )
        .await;
    assert!(matches!(
        competing,
        Err(CollectionError::Lease(LeaseError::Lease(
            terrane_format::gc::GcError::LeaseLost
        )))
    ));

    collection.mark_batch(32).await?;
    assert!(collection.state().pending.is_empty());
    collection.finish_mark().await?;
    let second_state = collection.state().clone();
    assert!(collection.begin_cycle(2).await.is_err());
    assert_eq!(collection.state(), &second_state);
    collection.begin_cycle(3).await?;

    assert_eq!(collection.state().cycle, 3);
    assert_eq!(collection.state().phase, Phase::Mark);
    assert_eq!(collection.lease().holder, initial.holder);
    assert_eq!(collection.lease().epoch, initial.epoch);
    collection.mark_batch(32).await?;
    assert!(collection.state().pending.is_empty());
    collection.finish_mark().await?;
    Ok(())
}
