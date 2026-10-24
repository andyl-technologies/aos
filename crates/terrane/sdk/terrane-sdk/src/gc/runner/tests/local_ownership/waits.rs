//! Exercises uninterrupted real deletion windows and permanent Session refusal.

use super::support::*;
use crate::store::{Clock, EffectFault, StoreErrorKind};
use std::time::{Duration, UNIX_EPOCH};
use terrane_format::gc::DeletePhase;

#[tokio::test]
async fn full_d_with_multiple_real_renewals_reaches_invalidated() {
    let fixture = Fixture::new().await;
    let (mut collection, requested) = retired(&fixture).await;
    let before = before(&fixture, &requested).await;
    let initial = collection.lease().clone();
    let previous = fixture.fs.renewals();
    fixture.clock.enable_timer();
    let started = fixture.clock.monotonic();
    assert!(
        initial.expiry
            - fixture
                .clock
                .now()
                .duration_since(UNIX_EPOCH)
                .require()
                .as_secs()
            < windows().deletion()
    );

    let operation = collection
        .own_local_pack(fixture.repository.coordinator(), requested)
        .await
        .require();

    assert!(fixture.clock.monotonic() - started >= Duration::from_secs(windows().deletion()));
    assert!(fixture.fs.renewals() >= previous + 3);
    assert_eq!(operation.current_lease, *collection.lease());
    assert_eq!(
        operation.authorization.original_lease,
        operation.current_lease
    );
    assert_eq!(operation.current_lease.holder, initial.holder);
    assert_eq!(operation.current_lease.epoch, initial.epoch);
    assert!(operation.current_lease.expiry > initial.expiry);
    assert_eq!(
        fixture
            .fs
            .ownership()
            .iter()
            .map(|(boundary, _)| *boundary)
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 4]
    );
    let persisted = assert_prefix(&fixture, &before, Some(DeletePhase::Invalidated), 3)
        .await
        .require();
    assert_eq!(persisted, operation);
    assert_eq!(fixture.selected_lease().await, operation.current_lease);
    drop(collection);
    fixture.cleanup();
}

async fn early() {
    let fixture = Fixture::new().await;
    let (mut collection, requested) = retired(&fixture).await;
    let before = before(&fixture, &requested).await;
    let previous = fixture.fs.renewals();
    fixture.clock.enable_timer();
    let mut operation =
        Box::pin(collection.own_local_pack(fixture.repository.coordinator(), requested));
    tokio::select! {
        result = &mut operation => panic!("ownership ended before genuine wait: {result:?}"),
        () = waiting(&fixture, previous) => {}
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(80), &mut operation)
            .await
            .is_err()
    );
    assert!(fixture.fs.ownership().is_empty());
    for original in &before.journals {
        assert_eq!(
            std::fs::read(journal(&fixture, &original.key)).require(),
            original.encode().require()
        );
    }
    drop(operation);

    assert_session_denied(&collection.finish_mark().await.require_error());
    assert_prefix(&fixture, &before, None, 0).await;
    drop(collection);
    fixture.cleanup();
}

async fn expired() {
    let fixture = Fixture::new().await;
    let (mut collection, requested) = retired(&fixture).await;
    let before = before(&fixture, &requested).await;
    let previous = fixture.fs.renewals();
    fixture.clock.enable_timer();
    let mut operation =
        Box::pin(collection.own_local_pack(fixture.repository.coordinator(), requested));
    tokio::select! {
        result = &mut operation => panic!("ownership ended before actual expiry injection: {result:?}"),
        () = waiting(&fixture, previous) => {}
    }
    expire(&fixture);
    assert_session_denied(&operation.await.require_error());

    // Restoring a readable clock never revives this poisoned original Session.
    fixture.clock.set(collection.lease().expiry - 1, 1);
    assert_session_denied(&collection.finish_mark().await.require_error());
    assert_prefix(&fixture, &before, None, 0).await;
    drop(collection);
    fixture.cleanup();
}

#[tokio::test]
async fn early_and_expired_wait_never_create_authorized() {
    tokio::join!(early(), expired());
}

async fn regression() {
    let fixture = Fixture::new().await;
    let (mut collection, requested) = retired(&fixture).await;
    let before = before(&fixture, &requested).await;
    let previous = fixture.fs.renewals();
    fixture.clock.enable_timer();
    let mut operation =
        Box::pin(collection.own_local_pack(fixture.repository.coordinator(), requested));
    tokio::select! {
        result = &mut operation => panic!("ownership ended before actual regression: {result:?}"),
        () = waiting(&fixture, previous) => {}
    }
    let wall = fixture
        .clock
        .now()
        .duration_since(UNIX_EPOCH)
        .require()
        .as_secs();
    let ticks = fixture.clock.monotonic().as_secs();
    fixture.clock.set(wall - 1, ticks - 1);
    assert_session_denied(&operation.await.require_error());

    assert_session_denied(&collection.finish_mark().await.require_error());
    assert_prefix(&fixture, &before, None, 0).await;
    drop(collection);
    fixture.cleanup();
}

async fn changed_incarnation() {
    let fixture = Fixture::new().await;
    let (mut collection, requested) = retired(&fixture).await;
    let mut before = before(&fixture, &requested).await;
    let previous = fixture.fs.renewals();
    fixture.clock.enable_timer();
    let mut operation =
        Box::pin(collection.own_local_pack(fixture.repository.coordinator(), requested));
    tokio::select! {
        result = &mut operation => panic!("ownership ended before actual replacement: {result:?}"),
        () = waiting(&fixture, previous) => {}
    }
    replace_pack(&mut before);
    let error = operation.await.require_error();
    let crate::gc::runner::CollectionError::Store(error) = error else {
        panic!("expected exact physical replacement refusal: {error:?}")
    };
    assert_eq!(
        error.kind(),
        &StoreErrorKind::Unavailable { retry_after: None }
    );
    assert_eq!(
        std::error::Error::source(&error).require().to_string(),
        "opened native descriptor no longer matches its name"
    );

    assert_session_denied(&collection.finish_mark().await.require_error());
    assert_prefix(&fixture, &before, None, 0).await;
    drop(collection);
    fixture.cleanup();
}

#[tokio::test]
async fn regression_or_changed_incarnation_discards_wait() {
    tokio::join!(regression(), changed_incarnation());
}

async fn renewal_failure() {
    let fixture = Fixture::new().await;
    let (mut collection, requested) = retired(&fixture).await;
    let before = before(&fixture, &requested).await;
    let previous = fixture.fs.renewals();
    fixture.clock.enable_timer();
    fixture.fs.fault(crate::store::native_publication_effects::collection_local_ownership::WorkerSelection::Renewal(previous + 2), EffectFault::BeforeFileSync);

    let error = collection
        .own_local_pack(fixture.repository.coordinator(), requested)
        .await
        .require_error();
    let crate::gc::runner::CollectionError::Lease(crate::gc::lease::LeaseError::Store(error)) =
        error
    else {
        panic!("expected genuine whole-lease renewal I/O failure: {error:?}")
    };
    assert_eq!(
        error.kind(),
        &StoreErrorKind::Unavailable { retry_after: None }
    );
    assert_eq!(
        std::error::Error::source(&error).require().to_string(),
        "injected creation file sync failure"
    );
    fixture.fs.assert_consumed();
    assert!(fixture.fs.triples() > 0);
    assert_session_denied(&collection.finish_mark().await.require_error());
    assert_prefix(&fixture, &before, None, 0).await;
    drop(collection);
    fixture.cleanup();
}

#[tokio::test]
async fn renewal_failure_and_dropped_wait_poison_session() {
    tokio::join!(renewal_failure(), early());
}
