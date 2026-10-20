//! Checks exact durable ownership prefixes and fresh authority at native handoffs.

use super::support::*;
use crate::gc::runner::CollectionError;
use crate::store::native_publication_effects::collection_local_ownership::{
    OwnershipPhase, WorkerSelection,
};
use crate::store::{EffectFault, StoreErrorKind};
use std::sync::mpsc;
use terrane_format::gc::DeletePhase;
use tokio::sync::Semaphore;

async fn fault_boundary(boundary: u8) {
    let fixture = Fixture::new().await;
    let (mut collection, requested) = retired(&fixture).await;
    let before = before(&fixture, &requested).await;
    fixture.clock.enable_timer();
    fixture.fs.fault(
        WorkerSelection::Ownership(boundary),
        EffectFault::BeforeFileSync,
    );

    let error = collection
        .own_local_pack(fixture.repository.coordinator(), requested)
        .await
        .require_error();

    let CollectionError::Store(error) = error else {
        panic!("expected exact ownership sync I/O failure: {error:?}")
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
    assert_eq!(
        fixture
            .fs
            .ownership()
            .iter()
            .map(|(actual, _)| *actual)
            .collect::<Vec<_>>(),
        (0..=boundary).collect::<Vec<_>>()
    );
    let phase = (boundary != 0).then_some(DeletePhase::Authorized);
    let prefix = usize::from(boundary.saturating_sub(1));
    assert_prefix(&fixture, &before, phase, prefix).await;
    assert_session_denied(&collection.finish_mark().await.require_error());
    drop(collection);
    fixture.cleanup();
}

#[tokio::test]
async fn authorized_and_each_owner_sync_fault_preserve_exact_partial_prefix() {
    // Each independent real wait is finite; concurrent fixtures share no controls.
    tokio::join!(
        fault_boundary(0),
        fault_boundary(1),
        fault_boundary(2),
        fault_boundary(3),
        fault_boundary(4)
    );
}

#[derive(Clone, Copy)]
enum Change {
    Expiry,
    Control,
}

async fn current_boundary(
    setup: &Semaphore,
    boundary: u8,
    phase: OwnershipPhase,
    change: Change,
    observe_later: bool,
) {
    let permit = setup.acquire().await.require();
    let fixture = Fixture::new().await;
    let (mut collection, requested) = retired(&fixture).await;
    let before = before(&fixture, &requested).await;
    drop(permit);

    fixture.clock.enable_timer();
    let (arrived, release, later) = if observe_later {
        let (arrived, release, later) = fixture.fs.pause_with_later_directory(boundary, phase);
        (arrived, release, Some(later))
    } else {
        let (arrived, release) = fixture
            .fs
            .pause(WorkerSelection::Ownership(boundary), phase);
        (arrived, release, None)
    };
    let mut operation =
        Box::pin(collection.own_local_pack(fixture.repository.coordinator(), requested));
    tokio::select! {
        result = &mut operation => panic!("ownership ended before actual current handoff: {result:?}"),
        () = arrival(arrived) => {}
    }
    match change {
        Change::Expiry => expire(&fixture),
        Change::Control => replace_control(&fixture),
    }
    release.send(()).require();
    let error = operation.await.require_error();

    match change {
        Change::Expiry => assert_session_denied(&error),
        Change::Control => {
            let CollectionError::Store(error) = error else {
                panic!("expected retained control identity refusal: {error:?}")
            };
            assert_eq!(
                error.kind(),
                &StoreErrorKind::Unavailable { retry_after: None }
            );
            assert_eq!(
                std::error::Error::source(&error).require().to_string(),
                "exact read metadata changed"
            );
        }
    }
    if let Some(later) = later {
        // The later actual-sync handoff sender is dropped without sending: the
        // queued change refused before that next native directory syscall.
        assert_eq!(later.try_recv(), Err(mpsc::TryRecvError::Disconnected));
    }
    fixture.fs.assert_consumed();
    assert_eq!(
        fixture
            .fs
            .ownership()
            .iter()
            .map(|(actual, _)| *actual)
            .collect::<Vec<_>>(),
        (0..=boundary).collect::<Vec<_>>()
    );
    assert_prefix(
        &fixture,
        &before,
        (boundary != 0).then_some(DeletePhase::Authorized),
        usize::from(boundary.saturating_sub(1)),
    )
    .await;
    assert_session_denied(&collection.finish_mark().await.require_error());
    drop(collection);
    fixture.cleanup();
}

async fn final_read(setup: &Semaphore, change: Change) {
    let permit = setup.acquire().await.require();
    let fixture = Fixture::new().await;
    let (mut collection, requested) = retired(&fixture).await;
    let before = before(&fixture, &requested).await;
    drop(permit);

    fixture.clock.enable_timer();
    let (arrived, release) = fixture.fs.pause_final_read();
    let mut operation =
        Box::pin(collection.own_local_pack(fixture.repository.coordinator(), requested));
    tokio::select! {
        result = &mut operation => panic!("ownership ended before final real rebind/read: {result:?}"),
        () = arrival(arrived) => {}
    }
    match change {
        Change::Expiry => expire(&fixture),
        Change::Control => replace_control(&fixture),
    }
    release.send(()).require();
    let error = operation.await.require_error();

    match change {
        Change::Expiry => assert_session_denied(&error),
        Change::Control => {
            let CollectionError::Store(error) = error else {
                panic!("expected refreshed Original control denial: {error:?}")
            };
            assert_eq!(
                error.kind(),
                &StoreErrorKind::Denied {
                    verb: "gc-lease",
                    pattern: "configured collector lease".into()
                }
            );
        }
    }
    fixture.fs.assert_consumed();
    assert_eq!(
        fixture
            .fs
            .ownership()
            .iter()
            .map(|(boundary, _)| *boundary)
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 4]
    );
    // Completed durability is monotone even when late completion qualification
    // refuses. This checks preserved ownership, not a rollback or recovery claim.
    assert_prefix(&fixture, &before, Some(DeletePhase::Invalidated), 3).await;
    assert_session_denied(&collection.finish_mark().await.require_error());
    drop(collection);
    fixture.cleanup();
}

async fn queued_incarnation(setup: &Semaphore) {
    let permit = setup.acquire().await.require();
    let fixture = Fixture::new().await;
    let (mut collection, requested) = retired(&fixture).await;
    let mut before = before(&fixture, &requested).await;
    drop(permit);

    fixture.clock.enable_timer();
    let (arrived, release, later) = fixture
        .fs
        .pause_with_later_directory(2, OwnershipPhase::BeforeDirectorySync);
    let mut operation =
        Box::pin(collection.own_local_pack(fixture.repository.coordinator(), requested));
    tokio::select! {
        result = &mut operation => panic!("ownership ended before actual triple handoff: {result:?}"),
        () = arrival(arrived) => {}
    }
    replace_pack(&mut before);
    release.send(()).require();
    let error = operation.await.require_error();

    let CollectionError::Store(error) = error else {
        panic!("expected actual retained pack refusal: {error:?}")
    };
    assert_eq!(
        error.kind(),
        &StoreErrorKind::Unavailable { retry_after: None }
    );
    assert_eq!(
        std::error::Error::source(&error).require().to_string(),
        "opened native descriptor no longer matches its name"
    );
    assert_eq!(later.try_recv(), Err(mpsc::TryRecvError::Disconnected));
    fixture.fs.assert_consumed();
    assert_prefix(&fixture, &before, Some(DeletePhase::Authorized), 1).await;
    assert_session_denied(&collection.finish_mark().await.require_error());
    drop(collection);
    fixture.cleanup();
}

#[tokio::test]
async fn fresh_current_authority_required_before_each_ownership_effect() {
    // Bound native setup overlap while preserving concurrent authority handoffs.
    let setup = Semaphore::new(1);

    tokio::join!(
        current_boundary(
            &setup,
            0,
            OwnershipPhase::AfterSourceSync,
            Change::Expiry,
            true
        ),
        current_boundary(
            &setup,
            1,
            OwnershipPhase::BeforeDirectorySync,
            Change::Control,
            true
        ),
        current_boundary(&setup, 2, OwnershipPhase::BeforeOpen, Change::Expiry, false),
        current_boundary(
            &setup,
            3,
            OwnershipPhase::BeforeOpen,
            Change::Control,
            false
        ),
        current_boundary(&setup, 4, OwnershipPhase::BeforeOpen, Change::Expiry, false),
        final_read(&setup, Change::Expiry),
        final_read(&setup, Change::Control),
        queued_incarnation(&setup),
    );
}
