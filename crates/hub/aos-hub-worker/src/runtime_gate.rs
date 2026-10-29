//! Wakes serialized Worker requests promptly while retaining runtime I/O.
//!
//! Workerd needs a runtime event while a request waits on isolate-local state.
//! A pending timer supplies that event; the mutex still wakes the request as
//! soon as its owner releases it. Timer ticks never grant a permit.

use std::{future::Future, sync::Arc};

use futures_util::{future::Either, lock::Mutex, lock::OwnedMutexGuard};

/// Acquires one gate with runtime timers keeping a contended request alive.
#[cfg(target_arch = "wasm32")]
pub(crate) async fn acquire(
    gate: Arc<Mutex<()>>,
    interval: std::time::Duration,
) -> OwnedMutexGuard<()> {
    acquire_with_ticks(gate, || worker::Delay::from(interval)).await
}

async fn acquire_with_ticks<T: Future<Output = ()>>(
    gate: Arc<Mutex<()>>,
    mut tick: impl FnMut() -> T,
) -> OwnedMutexGuard<()> {
    if let Some(permit) = gate.try_lock_owned() {
        return permit;
    }

    // Retain the registered lock future across timer ticks. Polling only
    // try_lock after each timer would delay every contended binding lookup.
    let mut pending = Box::pin(gate.lock_owned());
    loop {
        match futures_util::future::select(pending, Box::pin(tick())).await {
            Either::Left((permit, _)) => return permit,
            Either::Right(((), next)) => pending = next,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Poll},
    };

    use futures_util::{future, task::ArcWake};

    use super::*;

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl ArcWake for WakeCount {
        fn wake_by_ref(this: &Arc<Self>) {
            this.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn release_wakes_the_waiter_without_waiting_for_a_timer() {
        let gate = Arc::new(Mutex::new(()));
        let held = gate.try_lock_owned().unwrap();
        let wake = Arc::new(WakeCount::default());
        let waker = futures_util::task::waker(Arc::clone(&wake));
        let mut context = Context::from_waker(&waker);
        let mut waiting = Box::pin(acquire_with_ticks(Arc::clone(&gate), future::pending));

        assert!(waiting.as_mut().poll(&mut context).is_pending());
        assert_eq!(wake.0.load(Ordering::SeqCst), 0);

        drop(held);

        assert!(wake.0.load(Ordering::SeqCst) > 0);
        let Poll::Ready(permit) = waiting.as_mut().poll(&mut context) else {
            panic!("a released gate must not wait for its pending timer");
        };
        assert!(gate.try_lock_owned().is_none());
        drop(permit);
        assert!(gate.try_lock_owned().is_some());
    }

    #[test]
    fn timer_ticks_keep_waiting_for_the_original_gate() {
        let gate = Arc::new(Mutex::new(()));
        let held = gate.try_lock_owned().unwrap();
        let ticks = Cell::new(0);
        let mut waiting = Box::pin(acquire_with_ticks(Arc::clone(&gate), || {
            let index = ticks.get();
            ticks.set(index + 1);
            if index == 0 {
                Either::Left(future::ready(()))
            } else {
                Either::Right(future::pending())
            }
        }));
        let waker = futures_util::task::noop_waker();
        let mut context = Context::from_waker(&waker);

        assert!(waiting.as_mut().poll(&mut context).is_pending());
        assert_eq!(ticks.get(), 2);
        assert!(gate.try_lock_owned().is_none());

        drop(held);

        assert!(waiting.as_mut().poll(&mut context).is_ready());
        assert_eq!(ticks.get(), 2);
    }

    #[test]
    fn cancelling_a_waiter_does_not_retain_a_permit() {
        let gate = Arc::new(Mutex::new(()));
        let held = gate.try_lock_owned().unwrap();
        let mut waiting = Box::pin(acquire_with_ticks(Arc::clone(&gate), future::pending));
        let waker = futures_util::task::noop_waker();
        let mut context = Context::from_waker(&waker);
        assert!(waiting.as_mut().poll(&mut context).is_pending());

        drop(waiting);
        drop(held);

        assert!(gate.try_lock_owned().is_some());
    }

    #[test]
    fn an_uncontended_gate_needs_no_timer() {
        let gate = Arc::new(Mutex::new(()));
        let ticks = Cell::new(0);
        let mut waiting = Box::pin(acquire_with_ticks(Arc::clone(&gate), || {
            ticks.set(ticks.get() + 1);
            future::pending::<()>()
        }));
        let waker = futures_util::task::noop_waker();
        let mut context = Context::from_waker(&waker);

        let Poll::Ready(permit) = waiting.as_mut().poll(&mut context) else {
            panic!("an uncontended gate must be ready");
        };
        assert!(gate.try_lock_owned().is_none());
        assert_eq!(ticks.get(), 0);
        drop(permit);
        assert!(gate.try_lock_owned().is_some());
    }
}
