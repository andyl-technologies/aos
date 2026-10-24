//! Bounds one actual child read within its original whole-request deadline.

use super::{Clock, RoutingPolicy, StoreFailure, unavailable};
use crate::bucket::BucketBinding;
use std::{
    future::{Future, poll_fn},
    task::Poll,
    time::Duration,
};

pub(super) async fn read<T>(
    clock: &(impl Clock + BucketBinding),
    policy: &RoutingPolicy,
    started: Duration,
    future: impl Future<Output = Result<T, StoreFailure>>,
) -> Result<T, StoreFailure> {
    let now = clock.monotonic();
    let remaining = remaining(clock, policy, started)?;
    let wait = remaining.min(policy.child_budget);
    let deadline = now.checked_add(wait).ok_or_else(unavailable)?;
    let mut future = Box::pin(future);
    let mut timer = Box::pin(clock.sleep(wait));
    let mut last = now;
    poll_fn(|context| {
        let current = clock.monotonic();
        if current < last || current >= deadline {
            return Poll::Ready(Err(unavailable()));
        }
        last = current;
        if let Poll::Ready(result) = future.as_mut().poll(context) {
            let completed = clock.monotonic();
            return Poll::Ready(if completed < current || completed >= deadline {
                Err(unavailable())
            } else {
                result
            });
        }
        match timer.as_mut().poll(context) {
            Poll::Ready(Ok(())) => Poll::Ready(Err(unavailable())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(StoreFailure::with_source(
                super::StoreErrorKind::Unavailable { retry_after: None },
                error,
            ))),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

/// Rejects a spent whole-request budget before another child can be attempted.
pub(super) fn remaining(
    clock: &impl Clock,
    policy: &RoutingPolicy,
    started: Duration,
) -> Result<Duration, StoreFailure> {
    let elapsed = clock
        .monotonic()
        .checked_sub(started)
        .ok_or_else(unavailable)?;
    policy
        .read_budget
        .checked_sub(elapsed)
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(unavailable)
}
