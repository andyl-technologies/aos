//! Checks shared queue admission without consuming delivery retries.

use std::{
    future::Future as _,
    task::{Context, Poll},
};

use super::*;

#[tokio::test]
async fn bulk_waits_for_the_next_slot_before_fresh_metadata() {
    let first = Capacity::acquire(DirectDependencyPhase::Visibility, 3).unwrap();
    let second = Capacity::acquire(DirectDependencyPhase::Visibility, 3).unwrap();
    let third = Capacity::acquire(DirectDependencyPhase::Visibility, 3).unwrap();
    let waker = futures_util::task::noop_waker();
    let mut context = Context::from_waker(&waker);
    let mut bulk = Box::pin(Capacity::acquire_waiting(DirectDependencyPhase::Content, 3));
    let mut metadata = Box::pin(Capacity::acquire_waiting(
        DirectDependencyPhase::Visibility,
        3,
    ));

    assert!(bulk.as_mut().poll(&mut context).is_pending());
    assert!(metadata.as_mut().poll(&mut context).is_pending());

    drop(first);
    assert!(metadata.as_mut().poll(&mut context).is_pending());
    let bulk = match bulk.as_mut().poll(&mut context) {
        Poll::Ready(Ok(capacity)) => capacity,
        _ => panic!("the waiting bulk delivery did not get the released slot"),
    };
    let occupied = object_observation();
    assert_eq!(occupied.aggregate_active, 3);
    assert_eq!(occupied.bulk_active, 1);
    assert_eq!(occupied.metadata_active, 2);

    drop(second);
    let metadata = match metadata.as_mut().poll(&mut context) {
        Poll::Ready(Ok(capacity)) => capacity,
        _ => panic!("metadata did not progress during the bulk verification"),
    };
    assert_eq!(object_observation().aggregate_active, 3);

    drop((bulk, metadata, third));
    assert_eq!(object_observation().aggregate_active, 0);
}

#[tokio::test]
async fn cancelled_waiter_cannot_block_the_reserved_metadata_slot() {
    let first = Capacity::acquire(DirectDependencyPhase::Content, 3).unwrap();
    let second = Capacity::acquire(DirectDependencyPhase::Content, 3).unwrap();
    let waker = futures_util::task::noop_waker();
    let mut context = Context::from_waker(&waker);
    let mut bulk = Box::pin(Capacity::acquire_waiting(DirectDependencyPhase::Content, 3));

    assert!(bulk.as_mut().poll(&mut context).is_pending());
    let metadata = Capacity::acquire_waiting(DirectDependencyPhase::Visibility, 3)
        .await
        .unwrap();
    assert_eq!(object_observation().aggregate_active, 3);

    drop(bulk);
    drop(first);
    let replacement = Capacity::acquire_waiting(DirectDependencyPhase::Visibility, 3)
        .await
        .unwrap();
    assert_eq!(object_observation().aggregate_active, 3);

    drop((second, metadata, replacement));
    assert_eq!(object_observation().aggregate_active, 0);
}
