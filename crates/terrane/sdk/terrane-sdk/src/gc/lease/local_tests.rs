//! Qualifies genuine selected leases with Rc bindings and non-Send futures.

#![allow(
    clippy::unwrap_used,
    reason = "Bounded native fixture assertions intentionally panic."
)]

use super::fixture::Fixture;
use std::future::Future;
use std::task::{Context, Poll, Waker};

fn inline<T>(future: impl Future<Output = T>) -> T {
    let mut context = Context::from_waker(Waker::noop());
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("The synchronous native binding must finish inline"),
    }
}

#[test]
fn native_gc_rc_bindings_acquire_renew_take_over_and_reopen() {
    inline(async {
        let fixture = Fixture::new().await;
        let acquired = fixture
            .collector()
            .acquire("local".into(), 20)
            .await
            .unwrap();
        fixture.clock.set(105, 5);
        let renewed = fixture
            .collector()
            .renew(&acquired.lease, 30)
            .await
            .unwrap();
        assert_eq!(renewed.lease.epoch, acquired.lease.epoch);
        assert_eq!(renewed.revision, acquired.revision + 1);
        fixture.fs.reset();
        assert!(
            fixture
                .collector()
                .acquire("other".into(), 20)
                .await
                .is_err()
        );
        assert_eq!(fixture.fs.effects(), 0);
        fixture.clock.set(135, 35);
        let takeover = fixture
            .collector()
            .acquire("other".into(), 20)
            .await
            .unwrap();
        assert_eq!(takeover.lease.epoch, renewed.lease.epoch + 1);
        let opened = fixture.reopen().await;
        let observed = super::fixture::selection(opened.store()).await;
        assert_eq!(observed.1, Some(takeover.lease));
    });
}
