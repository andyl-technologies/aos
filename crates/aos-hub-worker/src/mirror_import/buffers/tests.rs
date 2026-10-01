//! Actual admission bounds, independent metadata progress and cancelled waiters.

use std::future::Future as _;
use std::task::{Context, Poll};

use super::*;

#[test]
fn metadata_runs_while_bulk_owns_a_decoder_and_both_classes_remain_bounded() {
    let waker = futures_util::task::noop_waker();
    let mut context = Context::from_waker(&waker);
    let mut bulk = Box::pin(acquire(false, || Ok(())));
    let Poll::Ready(Ok(bulk)) = bulk.as_mut().poll(&mut context) else {
        panic!("first bulk admission failed");
    };
    let mut blocked_bulk = Box::pin(acquire(false, || Ok(())));
    assert!(blocked_bulk.as_mut().poll(&mut context).is_pending());

    let mut small_one = Box::pin(acquire(true, || Ok(())));
    let Poll::Ready(Ok(small_one)) = small_one.as_mut().poll(&mut context) else {
        panic!("metadata serialized behind bulk");
    };
    let mut small_two = Box::pin(acquire(true, || Ok(())));
    let Poll::Ready(Ok(small_two)) = small_two.as_mut().poll(&mut context) else {
        panic!("second metadata admission failed");
    };
    let mut blocked_small = Box::pin(acquire(true, || Ok(())));
    assert!(blocked_small.as_mut().poll(&mut context).is_pending());

    drop(bulk);
    let Poll::Ready(Ok(replacement)) = blocked_bulk.as_mut().poll(&mut context) else {
        panic!("bulk admission did not resume");
    };
    drop(small_one);
    assert!(matches!(
        blocked_small.as_mut().poll(&mut context),
        Poll::Ready(Ok(_))
    ));
    drop(small_two);
    drop(replacement);
}

#[test]
fn cancelled_waiter_does_not_block_the_next_and_freshness_runs_after_wait() {
    let waker = futures_util::task::noop_waker();
    let mut context = Context::from_waker(&waker);
    let mut held = Box::pin(acquire(false, || Ok(())));
    let Poll::Ready(Ok(held)) = held.as_mut().poll(&mut context) else {
        panic!("bulk admission failed");
    };
    let mut cancelled = Box::pin(acquire(false, || Ok(())));
    assert!(cancelled.as_mut().poll(&mut context).is_pending());
    let checks = std::cell::Cell::new(0);
    let expired = std::cell::Cell::new(false);
    let mut next = Box::pin(acquire(false, || {
        checks.set(checks.get() + 1);
        anyhow::ensure!(!expired.get(), "expired original");
        Ok(())
    }));
    assert!(next.as_mut().poll(&mut context).is_pending());
    assert_eq!(checks.get(), 1);

    drop(cancelled);
    drop(held);
    expired.set(true);
    assert!(matches!(
        next.as_mut().poll(&mut context),
        Poll::Ready(Err(_))
    ));
    assert_eq!(checks.get(), 2);
    assert_eq!(BULK.with(|pool| pool.borrow().active), 0);
}
