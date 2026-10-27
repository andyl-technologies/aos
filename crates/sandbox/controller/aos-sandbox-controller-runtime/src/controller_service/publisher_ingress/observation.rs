//! Keeps one actual Publisher observation alive across its first deadline.
//!
//! The timeout borrows the original future. It never detaches a replacement
//! connect job. Later worker turns poll that same future without another wait,
//! preserving command/recovery progress while the original native job finishes.

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

use super::RegistrationRuntimeV1;
use aos_sandbox_controller_domain::ControllerPublisherReceivingV1;

#[cfg(test)]
use super::{PublisherIngressError, PublisherServiceRegistration};

type ObservationFutureV1<T> = Pin<Box<dyn Future<Output = T> + Send>>;

pub(super) type PublisherObservationV1 = PendingObservationV1<ControllerPublisherReceivingV1>;

pub(super) struct PendingObservationV1<T> {
    future: Option<ObservationFutureV1<T>>,
    deadline: Option<Result<(), tokio::time::error::Elapsed>>,
    completion: Option<T>,
}

impl PublisherObservationV1 {
    pub(super) fn new(original: ControllerPublisherReceivingV1) -> Self {
        Self {
            future: Some(Box::pin(original.observe())),
            deadline: None,
            completion: None,
        }
    }

    // The actual compiler-generated future width is DATA. This calls no
    // constructor and manufactures no original, loan, scope or registration.
    pub(super) fn future_bytes() -> usize {
        fn extent<F>(_: fn(ControllerPublisherReceivingV1) -> F) -> usize {
            std::mem::size_of::<F>()
        }
        extent(ControllerPublisherReceivingV1::observe)
    }
}

impl<T> PendingObservationV1<T> {
    pub(super) fn advance(&mut self, runtime: &RegistrationRuntimeV1, timeout: Duration) {
        if self.completion.is_some() {
            return;
        }
        let Some(future) = self.future.as_mut() else {
            return;
        };
        if self.deadline.is_none() {
            match runtime.block_on(async {
                tokio::time::timeout(timeout, future.as_mut()).await
            }) {
                Ok(result) => {
                    self.completion = Some(result);
                    self.deadline = Some(Ok(()));
                }
                Err(cause) => self.deadline = Some(Err(cause)),
            }
        } else {
            // The elapsed deadline is retained, not restarted. One poll lets
            // the same connection continue while this sole worker stays free
            // to process Stop/Delete/recovery commands on subsequent turns.
            self.completion = runtime.block_on(poll_fn(|context| {
                Poll::Ready(match future.as_mut().poll(context) {
                    Poll::Ready(result) => Some(result),
                    Poll::Pending => None,
                })
            }));
        }
        if self.completion.is_some() {
            // A reached blocking connect has been awaited by this SAME future
            // before completion. No timeout can release the outstanding slot.
            drop(self.future.take());
        }
    }

    pub(super) fn timed_out(&self) -> bool {
        matches!(self.deadline, Some(Err(_)))
    }

    pub(super) fn take_completion(&mut self) -> Option<T> {
        self.completion.take()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Instant;

    use super::*;

    struct ReleaseJob(Arc<(Mutex<bool>, Condvar)>);

    impl Drop for ReleaseJob {
        fn drop(&mut self) {
            let (lock, changed) = &*self.0;
            if let Ok(mut released) = lock.lock() {
                *released = true;
            }
            changed.notify_all();
        }
    }

    #[test]
    fn elapsed_future_keeps_one_real_blocking_job_until_actual_completion() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all().max_blocking_threads(5).build().unwrap();
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let started = Arc::new(AtomicUsize::new(0));
        let ended = Arc::new(AtomicUsize::new(0));
        let job_gate = Arc::clone(&gate);
        let job_started = Arc::clone(&started);
        let job_ended = Arc::clone(&ended);
        let job = runtime.spawn_blocking(move || {
            job_started.fetch_add(1, Ordering::SeqCst);
            let (lock, changed) = &*job_gate;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = changed.wait(released).unwrap();
            }
            job_ended.fetch_add(1, Ordering::SeqCst);
        });
        let driver = RegistrationRuntimeV1::Owned(runtime);
        // On assertion failure the job is released BEFORE Runtime::drop joins.
        let _release = ReleaseJob(Arc::clone(&gate));
        let started_by = Instant::now() + Duration::from_secs(1);
        while started.load(Ordering::SeqCst) == 0 && Instant::now() < started_by {
            std::thread::yield_now();
        }
        assert_eq!(started.load(Ordering::SeqCst), 1);
        let mut pending = PendingObservationV1::<Result<PublisherServiceRegistration, PublisherIngressError>> {
            future: Some(Box::pin(async move {
                job.await.unwrap();
                Err(PublisherIngressError::Execution)
            })),
            deadline: None,
            completion: None,
        };

        pending.advance(&driver, Duration::from_millis(1));
        assert!(matches!(pending.deadline, Some(Err(_))));
        let original = std::ptr::from_ref(pending.deadline.as_ref().unwrap().as_ref().unwrap_err());
        for _ in 0..5 {
            pending.advance(&driver, Duration::from_millis(1));
        }
        assert!(pending.future.is_some());
        assert!(pending.completion.is_none());
        assert_eq!(started.load(Ordering::SeqCst), 1);
        assert_eq!(ended.load(Ordering::SeqCst), 0);

        let (lock, changed) = &*gate;
        *lock.lock().unwrap() = true;
        changed.notify_one();
        let until = Instant::now() + Duration::from_secs(1);
        while pending.completion.is_none() && Instant::now() < until {
            pending.advance(&driver, Duration::from_millis(1));
            std::thread::yield_now();
        }
        assert!(matches!(pending.take_completion(), Some(Err(PublisherIngressError::Execution))));
        assert!(pending.future.is_none());
        assert_eq!(started.load(Ordering::SeqCst), 1);
        assert_eq!(ended.load(Ordering::SeqCst), 1);
        assert_eq!(std::ptr::from_ref(pending.deadline.as_ref().unwrap().as_ref().unwrap_err()), original);
    }
}
