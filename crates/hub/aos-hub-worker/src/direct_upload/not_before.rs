//! Strict admission after bounded waiting for authenticated metadata originals.
//!
//! Whole-second sender timestamps can briefly lead a qualified receiver clock.
//! Waiting changes neither signed bounds nor the accepted producer window. No
//! profile, durable original, or guard is accessed until fresh validation passes.

use std::future::Future;
use std::time::Duration;

use anyhow::{ensure, Result};

const MAX_NOT_BEFORE_WAIT_SECONDS: u64 = 2;

/// Waits for an authenticated original, then checks the actual qualified clock.
///
/// The caller authenticates and canonically decodes the bounded original first.
/// `validate` checks its unchanged structure, audience, and exclusive deadline.
/// `clock` must recheck the applicable qualified clock policy on every invocation.
///
/// # Errors
/// Refuses malformed or mismatched originals before waiting, excessive future
/// skew, failed clock qualification, rollback, or reaching the original expiry.
pub(crate) async fn validate_when_current<C, V, S, F>(
    issued_at: u64,
    mut clock: C,
    validate: V,
    sleep: S,
) -> Result<()>
where
    C: FnMut() -> Result<u64>,
    V: Fn(u64) -> Result<()>,
    S: FnOnce(Duration) -> F,
    F: Future<Output = ()>,
{
    let observed = clock()?;
    if issued_at > observed {
        let remaining = issued_at - observed;
        ensure!(
            remaining <= MAX_NOT_BEFORE_WAIT_SECONDS,
            "direct metadata request is too far ahead of the receiver clock"
        );
        // This is only a structural/audience check before allocating a timer.
        // Admission always uses the fresh qualified receiver clock below.
        validate(issued_at)?;
        sleep(Duration::from_secs(remaining)).await;
    }

    validate(clock()?)
}

#[cfg(test)]
mod tests;
