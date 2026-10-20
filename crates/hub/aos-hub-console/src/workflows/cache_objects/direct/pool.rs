//! Document-local aggregate provider permits, independent of each file's wave.
//!
//! The shared async semaphore bounds selected local transfer futures at 32.
//! Separate tabs have separate pools; releasing a permit does not prove remote
//! provider drain or settlement of an unknown request.

use std::sync::Arc;

use async_lock::{Semaphore, SemaphoreGuardArc};

const MAXIMUM_PARTS: usize = 32;

thread_local! {
    static PROVIDER_PARTS: Arc<Semaphore> = Arc::new(Semaphore::new(MAXIMUM_PARTS));
}

/// Acquires a shared slot before source-slice allocation or provider dispatch.
pub(crate) async fn acquire() -> SemaphoreGuardArc {
    PROVIDER_PARTS.with(Arc::clone).acquire_arc().await
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::task::{Context, Poll};

    use super::*;

    #[test]
    fn document_pool_caps_parts_and_canceling_a_waiter_does_not_take_a_slot() {
        let held: Vec<_> = (0..MAXIMUM_PARTS)
            .map(|_| futures::executor::block_on(acquire()))
            .collect();
        let mut waiting = Box::pin(acquire());
        let mut context = Context::from_waker(futures::task::noop_waker_ref());
        assert!(matches!(waiting.as_mut().poll(&mut context), Poll::Pending));
        drop(waiting);
        drop(held);

        let held: Vec<_> = (0..MAXIMUM_PARTS)
            .map(|_| futures::executor::block_on(acquire()))
            .collect();
        assert!(PROVIDER_PARTS.with(|pool| pool.try_acquire_arc()).is_none());
        drop(held);
        assert!(PROVIDER_PARTS.with(|pool| pool.try_acquire_arc()).is_some());
    }

    #[test]
    fn provider_error_and_canceled_transfer_release_owned_permits() {
        let error: Result<(), &str> = futures::executor::block_on(async {
            let _permit = acquire().await;
            Err("provider response unknown")
        });
        assert!(error.is_err());
        let mut transfer = Box::pin(async {
            let _permit = acquire().await;
            std::future::pending::<()>().await;
        });
        let mut context = Context::from_waker(futures::task::noop_waker_ref());
        assert!(matches!(
            transfer.as_mut().poll(&mut context),
            Poll::Pending
        ));
        drop(transfer);
        let held: Vec<_> = (0..MAXIMUM_PARTS)
            .map(|_| futures::executor::block_on(acquire()))
            .collect();
        assert!(PROVIDER_PARTS.with(|pool| pool.try_acquire_arc()).is_none());
        drop(held);
    }
}
