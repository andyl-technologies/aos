//! Drives owned provider I/O while preserving cancellation and final authority checks.

use std::{future::Future, time::Duration};

use anyhow::Result;
use futures_util::future::{select, Either};

use crate::direct_upload::provider_capacity::poll_with_runtime_ticks;

/// Completes owned work or drops it when its original stop condition fires.
///
/// # Errors
/// Propagates work, cancellation, deadline and final authority-check failures.
pub(super) async fn run<T, F, S, Tick>(
    work: F,
    stop: S,
    check: &dyn Fn() -> Result<()>,
    tick: impl FnMut(Duration) -> Tick,
) -> Result<T>
where
    F: Future<Output = Result<T>>,
    S: Future<Output = Result<T>>,
    Tick: Future<Output = ()>,
{
    // Progress ticks do not repeat the expensive authority checks. The caller
    // retains its original cancellation cadence, deadline and final check.
    let work = poll_with_runtime_ticks(work, tick);
    futures_util::pin_mut!(work, stop);
    match select(work, stop).await {
        Either::Left((result, _)) => {
            check()?;
            result
        }
        Either::Right((result, _)) => result,
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, task::Context};

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn ready_headers_and_body_finish_without_a_foreign_context_wakeup() {
        let mut response = Box::pin(async {
            tokio::time::sleep(Duration::from_millis(1)).await;
            tokio::time::sleep(Duration::from_millis(1)).await;
            Ok(b"provider body".to_vec())
        });
        let work = futures_util::future::poll_fn(|_| {
            let waker = futures_util::task::noop_waker();
            response.as_mut().poll(&mut Context::from_waker(&waker))
        });
        let deadline = tokio::time::Instant::now() + Duration::from_millis(25);
        let stop = async {
            tokio::time::sleep_until(deadline).await;
            anyhow::bail!("original response deadline elapsed")
        };
        let check = || {
            anyhow::ensure!(tokio::time::Instant::now() < deadline, "response expired");
            Ok(())
        };

        let body = run(work, stop, &check, tokio::time::sleep).await.unwrap();

        assert_eq!(body, b"provider body");
        assert!(tokio::time::Instant::now() < deadline);
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_drops_the_pending_body_before_returning() {
        struct BodyOwner<'a>(&'a Cell<bool>);

        impl Drop for BodyOwner<'_> {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }

        let dropped = Cell::new(false);
        let owner = BodyOwner(&dropped);
        let work = async move {
            let _owner = owner;
            futures_util::future::pending::<Result<()>>().await
        };
        let stop = async {
            tokio::time::sleep(Duration::from_millis(11)).await;
            anyhow::bail!("response canceled")
        };

        let result = run(work, stop, &|| Ok(()), tokio::time::sleep).await;

        assert_eq!(result.unwrap_err().to_string(), "response canceled");
        assert!(dropped.get());
    }

    #[tokio::test(start_paused = true)]
    async fn completed_body_cannot_bypass_a_revoked_authority_check() {
        let authorized = Cell::new(true);
        let work = async {
            authorized.set(false);
            Ok(b"completed body".to_vec())
        };
        let check = || {
            anyhow::ensure!(authorized.get(), "response authority revoked");
            Ok(())
        };

        let result = run(
            work,
            futures_util::future::pending(),
            &check,
            tokio::time::sleep,
        )
        .await;

        assert_eq!(
            result.unwrap_err().to_string(),
            "response authority revoked"
        );
    }
}
