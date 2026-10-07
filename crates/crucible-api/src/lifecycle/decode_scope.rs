//! Original input admission restored on every native session actor poll.

use super::LifecycleApiError;
use crucible::owned_decode::DecodeBudget;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

pub(super) struct ScopedFuture<F> {
    future: Pin<Box<F>>,
    // Field order keeps input credits through the actor's final destructor,
    // including native cleanup and uncertain-cleanup custody transfer.
    decoding: Option<DecodeBudget>,
}

impl<F: Future> Future for ScopedFuture<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        // A task may resume on a different executor thread after any await.
        // Restore the actual origin account only for this synchronous poll.
        let _scope = self.decoding.as_ref().map(DecodeBudget::enter);
        self.future.as_mut().poll(context)
    }
}

pub(super) fn spawn<F>(
    future: F,
    decoding: Option<DecodeBudget>,
) -> Result<tokio::task::JoinHandle<F::Output>, LifecycleApiError>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    Ok(tokio::spawn(scoped(future, decoding)?))
}

pub(super) fn scoped<F>(
    future: F,
    decoding: Option<DecodeBudget>,
) -> Result<ScopedFuture<F>, LifecycleApiError>
where
    F: Future,
{
    if let Some(budget) = &decoding {
        budget
            .charge_bytes(std::mem::size_of::<F>() as u64)
            .map_err(LifecycleApiError::ConfigurationCopy)?;
    }
    Ok(ScopedFuture {
        future: Box::pin(future),
        decoding,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible::owned_decode::{DecodeAdmissionError, DecodeResourceAuthority};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    };

    struct FixtureAuthority(Arc<AtomicU64>);
    struct Credit {
        used: Arc<AtomicU64>,
        bytes: u64,
    }

    impl Drop for Credit {
        fn drop(&mut self) {
            self.used.fetch_sub(self.bytes, Ordering::AcqRel);
        }
    }

    impl DecodeResourceAuthority for FixtureAuthority {
        fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
            if self.0.load(Ordering::Acquire) > 4096 {
                return Err(DecodeAdmissionError::new(std::io::Error::other(
                    "original component accounting is invalid",
                )));
            }
            Ok(())
        }

        fn reserve(&self, bytes: u64) -> Result<Arc<dyn Send + Sync>, DecodeAdmissionError> {
            self.0
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                    used.checked_add(bytes).filter(|next| *next <= 4096)
                })
                .map_err(|_| {
                    DecodeAdmissionError::new(std::io::Error::other(
                        "fixture metadata capacity exhausted",
                    ))
                })?;
            Ok(Arc::new(Credit {
                used: Arc::clone(&self.0),
                bytes,
            }))
        }
    }

    struct CleanupProbe {
        used: Arc<AtomicU64>,
        cleaned: Arc<AtomicBool>,
    }

    impl Future for CleanupProbe {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
            Poll::Pending
        }
    }

    impl Drop for CleanupProbe {
        fn drop(&mut self) {
            assert!(self.used.load(Ordering::Acquire) > 0);
            self.cleaned.store(true, Ordering::Release);
        }
    }

    #[test]
    fn cancelled_actor_retains_input_credit_through_its_cleanup_destructor() {
        let used = Arc::new(AtomicU64::new(0));
        let cleaned = Arc::new(AtomicBool::new(false));
        let budget = DecodeBudget::new(Arc::new(FixtureAuthority(Arc::clone(&used))), 4096)
            .unwrap_or_else(|error| panic!("finite original account: {error}"));
        let future = scoped(
            CleanupProbe {
                used: Arc::clone(&used),
                cleaned: Arc::clone(&cleaned),
            },
            Some(budget.clone()),
        )
        .unwrap_or_else(|error| panic!("actor future admission: {error}"));
        drop(budget);

        assert!(!cleaned.load(Ordering::Acquire));
        assert!(used.load(Ordering::Acquire) > 0);
        drop(future);

        assert!(cleaned.load(Ordering::Acquire));
        assert_eq!(used.load(Ordering::Acquire), 0);
    }

    #[test]
    fn origin_account_is_reinstalled_on_each_thread_and_retained_until_final_poll() {
        let used = Arc::new(AtomicU64::new(0));
        let budget = DecodeBudget::new(Arc::new(FixtureAuthority(Arc::clone(&used))), 4096)
            .unwrap_or_else(|error| panic!("finite original account: {error}"));
        let future = async {
            assert!(crucible::owned_decode::current_budget().is_some());
            tokio::task::yield_now().await;
            assert!(crucible::owned_decode::current_budget().is_some());
            crucible::owned_decode::charge_bytes(128)
                .unwrap_or_else(|error| panic!("actual actor copy admission: {error}"));
        };
        let mut future = Box::pin(
            scoped(future, Some(budget.clone()))
                .unwrap_or_else(|error| panic!("actor future admission: {error}")),
        );
        drop(budget);

        let mut future = std::thread::spawn(move || {
            assert!(crucible::owned_decode::current_budget().is_none());
            let waker = futures_util::task::noop_waker();
            assert!(
                future
                    .as_mut()
                    .poll(&mut std::task::Context::from_waker(&waker))
                    .is_pending()
            );
            assert!(crucible::owned_decode::current_budget().is_none());
            future
        })
        .join()
        .unwrap_or_else(|_| panic!("first actor poll panicked"));
        assert!(used.load(Ordering::Acquire) > 0);

        std::thread::spawn(move || {
            assert!(crucible::owned_decode::current_budget().is_none());
            let waker = futures_util::task::noop_waker();
            assert!(
                future
                    .as_mut()
                    .poll(&mut std::task::Context::from_waker(&waker))
                    .is_ready()
            );
            assert!(crucible::owned_decode::current_budget().is_none());
        })
        .join()
        .unwrap_or_else(|_| panic!("second actor poll panicked"));
        assert_eq!(used.load(Ordering::Acquire), 0);
    }
}
