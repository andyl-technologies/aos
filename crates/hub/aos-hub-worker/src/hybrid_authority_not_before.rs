//! Bounded not-before waiting for authenticated authority metadata requests.
//!
//! A sender's whole-second timestamp can lead the receiver's clock. Waiting
//! grants no authority: the unchanged request must pass strict validation at
//! the actual receiver clock afterward, within its original exclusive expiry.

use std::future::Future;
use std::time::Duration;

use anyhow::{ensure, Context as _, Result};
use aos_hub_db::storage_authority::control::StorageAuthorityRequest;

// Leave most of the original thirty-second lifetime for the control exchange.
const MAX_NOT_BEFORE_WAIT_SECONDS: i64 = 2;

/// Waits briefly for a signed original to become current, then validates it.
///
/// Callers authenticate the exact request before invoking this helper and
/// dispatch no ledger operation until it succeeds. The clock is read again
/// after waiting; neither the signed timestamps nor receiver time are adjusted.
///
/// # Errors
/// Refuses malformed or mismatched requests, excessive future skew, a clock
/// still behind the original after waiting, or reaching its exclusive expiry.
pub(crate) async fn validate_when_current<C, S, F>(
    request: &StorageAuthorityRequest,
    deployment: &str,
    namespace: &str,
    mut clock: C,
    sleep: S,
) -> Result<()>
where
    C: FnMut() -> i64,
    S: FnOnce(Duration) -> F,
    F: Future<Output = ()>,
{
    let observed = clock();
    if request.issued_at > observed {
        let remaining = request
            .issued_at
            .checked_sub(observed)
            .context("authority not-before interval overflowed")?;
        ensure!(
            remaining <= MAX_NOT_BEFORE_WAIT_SECONDS,
            "authority request is too far ahead of the receiver clock"
        );
        // This checks only structure and domain before allocating a timer.
        // Actual admission always uses the fresh receiver clock below.
        request.validate(deployment, namespace, request.issued_at)?;
        sleep(Duration::from_secs(u64::try_from(remaining)?)).await;
    }

    request.validate(deployment, namespace, clock())
}

#[cfg(test)]
#[path = "hybrid_authority_not_before_tests.rs"]
mod tests;
