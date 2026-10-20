//! Bounded recovery for read-only registry bearer-token GET requests.

use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use tokio_util::sync::CancellationToken;

use super::has_closed_connection_cause;

/// Sends one prepared bearer GET with at most one connection-reset retry.
///
/// The clone preserves the validated realm, query, credentials, and confined
/// HTTP client. Establishment resets are safe to retry for this bodyless read;
/// provider mutations retain their existing transport behavior. Both attempts
/// share the original five-minute request timeout.
///
/// # Errors
/// Returns an error on cancellation, deadline, or an unrecovered transport fault.
pub(super) async fn send(
    request: reqwest::RequestBuilder,
    cancellation: &CancellationToken,
    request_context: &'static str,
) -> Result<reqwest::Response> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(5 * 60))
        .context("registry token request deadline overflowed")?;

    for attempt in 0..2 {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .context("registry token request deadline elapsed")?;
        let prepared = request
            .try_clone()
            .context("registry token request cannot be retained")?
            .timeout(remaining);
        let result = tokio::select! {
            biased;
            () = cancellation.cancelled() => bail!("OCI transfer cancelled"),
            response = prepared.send() => response,
        };

        match result {
            Ok(response) => return Ok(response),
            Err(error)
                if attempt == 0
                    && !error.is_timeout()
                    && !error.is_redirect()
                    && !error.is_body()
                    && has_closed_connection_cause(&error) => {}
            Err(error) => return Err(error).context(request_context),
        }
    }

    bail!("registry token request exhausted its transport attempts")
}
