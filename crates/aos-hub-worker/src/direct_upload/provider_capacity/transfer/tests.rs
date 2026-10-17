//! Real pool ownership at the smallest accepted copy bound.

use std::{
    future::Future,
    task::{Context, Poll},
};

use futures_util::{task::noop_waker, FutureExt};

use super::super::{acquire_class, acquire_class_checked, configure, observation};
use super::*;

fn digest() -> String {
    "a".repeat(64)
}

#[tokio::test]
async fn minimum_pool_moves_the_reserved_get_once_and_preserves_metadata() {
    configure(3).unwrap();
    let atomic = acquire_class(2, Class::Bulk).await.unwrap();
    let (destination, source) = split(atomic).unwrap();
    let reservation = register(source, digest()).unwrap();
    let source = accept(&reservation.ticket(), &digest()).unwrap().unwrap();

    assert_eq!(observation().active, 2);
    assert_eq!(observation().bulk_active, 2);
    assert!(accept(&reservation.ticket(), &digest()).is_err());
    let metadata = acquire_class(1, Class::Metadata).await.unwrap();
    assert_eq!(observation().active, 3);

    drop(metadata);
    drop(source);
    drop(reservation);
    assert_eq!(observation().active, 1);
    drop(destination);
    assert_eq!(observation().active, 0);
}

#[tokio::test]
async fn concurrent_destinations_cannot_steal_the_second_pass_get_slot() {
    configure(3).unwrap();
    let atomic = acquire_class(2, Class::Bulk).await.unwrap();
    let (destination, source) = split(atomic).unwrap();
    let first = register(source, digest()).unwrap();
    let source = accept(&first.ticket(), &digest()).unwrap().unwrap();
    let mut other = Box::pin(acquire_class(2, Class::Bulk));
    let waker = noop_waker();
    let mut context = Context::from_waker(&waker);
    assert!(matches!(other.as_mut().poll(&mut context), Poll::Pending));

    drop(source);
    drop(first);
    assert_eq!(observation().bulk_active, 1);
    assert!(matches!(other.as_mut().poll(&mut context), Poll::Pending));
    let second_source = acquire_class(1, Class::Bulk).await.unwrap();
    let second = register(second_source, "b".repeat(64)).unwrap();
    let source = accept(&second.ticket(), &"b".repeat(64)).unwrap().unwrap();
    assert_eq!(observation().bulk_active, 2);

    drop(source);
    drop(second);
    drop(destination);
    let other = other.await.unwrap();
    assert_eq!(observation().bulk_active, 2);
    drop(other);
    assert_eq!(observation().active, 0);
}

#[tokio::test]
async fn changed_local_ticket_cannot_fallback_or_consume_the_original() {
    configure(3).unwrap();
    let (destination, source) = split(acquire_class(2, Class::Bulk).await.unwrap()).unwrap();
    let reservation = register(source, digest()).unwrap();
    let original = reservation.ticket();
    for change in 0..3 {
        let mut ticket = original.clone();
        match change {
            0 => ticket.request_digest = "b".repeat(64),
            1 => ticket.pool_generation = uuid::Uuid::new_v4().to_string(),
            _ => ticket.ticket_id = uuid::Uuid::new_v4().to_string(),
        }
        assert!(accept(&ticket, &digest()).is_err());
        assert_eq!(observation().active, 2);
    }
    let source = accept(&original, &digest()).unwrap().unwrap();
    drop(source);
    drop(reservation);
    drop(destination);
    assert_eq!(observation().active, 0);
}

#[tokio::test]
async fn unused_cancellation_releases_only_its_source_slot_and_refuses_reuse() {
    configure(3).unwrap();
    let (destination, source) = split(acquire_class(2, Class::Bulk).await.unwrap()).unwrap();
    let reservation = register(source, digest()).unwrap();
    reservation.cancellation().cancel();

    assert_eq!(observation().active, 1);
    assert!(accept(&reservation.ticket(), &digest()).is_err());
    drop(reservation);
    assert_eq!(observation().active, 1);
    drop(destination);
    assert_eq!(observation().active, 0);
}

#[tokio::test]
async fn consumed_cancellation_refuses_source_work_without_double_release() {
    configure(3).unwrap();
    let (destination, source) = split(acquire_class(2, Class::Bulk).await.unwrap()).unwrap();
    let reservation = register(source, digest()).unwrap();
    let source = accept(&reservation.ticket(), &digest()).unwrap().unwrap();
    source.cancellation.check().unwrap();
    drop(reservation);

    assert!(source.cancellation.check().is_err());
    assert_eq!(observation().active, 2);
    drop(source);
    assert_eq!(observation().active, 1);
    drop(destination);
    assert_eq!(observation().active, 0);
}

#[tokio::test]
async fn a_real_distinct_isolate_uses_its_own_pool_and_keeps_origin_reservation() {
    configure(3).unwrap();
    let (destination, source) = split(acquire_class(2, Class::Bulk).await.unwrap()).unwrap();
    let reservation = register(source, digest()).unwrap();
    let ticket = reservation.ticket();
    let remote = std::thread::spawn(move || {
        configure(3).unwrap();
        assert!(accept(&ticket, &digest()).unwrap().is_none());
        let own = acquire_class(1, Class::Bulk)
            .now_or_never()
            .unwrap()
            .unwrap();
        assert_eq!(observation().active, 1);
        drop(own);
        observation().active
    })
    .join()
    .unwrap();

    assert_eq!(remote, 0);
    assert_eq!(observation().active, 2);
    drop(reservation);
    assert_eq!(observation().active, 1);
    drop(destination);
    assert_eq!(observation().active, 0);
}

#[tokio::test]
async fn cutoff_while_queued_cannot_admit_or_extend_a_source_slot() {
    configure(3).unwrap();
    let retained = acquire_class(2, Class::Bulk).await.unwrap();
    let now = Cell::new(119);
    let current = || {
        ensure!(now.get() < 120, "retained request expired");
        Ok(())
    };
    let mut waiting = Box::pin(acquire_class_checked(1, Class::Bulk, &current));
    let waker = noop_waker();
    assert!(matches!(
        waiting.as_mut().poll(&mut Context::from_waker(&waker)),
        Poll::Pending
    ));
    now.set(120);

    assert!(waiting.await.is_err());
    assert_eq!(observation().active, 2);
    drop(retained);
    assert_eq!(observation().active, 0);
}

#[tokio::test]
async fn invalid_registration_and_dropped_range_release_exact_owned_capacity() {
    configure(3).unwrap();
    let (destination, source) = split(acquire_class(2, Class::Bulk).await.unwrap()).unwrap();
    assert!(register(source, "not-a-request-digest".into()).is_err());
    assert_eq!(observation().active, 1);
    let source = acquire_class(1, Class::Bulk).await.unwrap();
    let reservation = register(source, digest()).unwrap();
    let ticket = reservation.ticket();
    drop(reservation);

    assert!(accept(&ticket, &digest()).is_err());
    assert_eq!(observation().active, 1);
    drop(destination);
    assert_eq!(observation().active, 0);
}
