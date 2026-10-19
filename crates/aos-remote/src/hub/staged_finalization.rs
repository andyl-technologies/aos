//! Exact frozen-stage retries inside the existing total finalization deadline.

use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use serde::de::DeserializeOwned;

use super::{ConnectError, STAGED_FINALIZATION_TIMEOUT_SECS};

/// Completes one frozen stage after at most three explicit temporary refusals.
///
/// A single prepared JSON request preserves the original identity and body.
/// Native resumes its frozen pointer transaction on replay; other RPC methods,
/// transport failures and precondition refusals never enter this retry path.
///
/// # Errors
/// Returns an error for transport, deadline, decoding or terminal Hub refusal.
pub(super) async fn call<Resp: DeserializeOwned>(
    request: reqwest::RequestBuilder,
    url: &str,
) -> Result<Resp> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(STAGED_FINALIZATION_TIMEOUT_SECS))
        .context("staged finalization deadline overflowed")?;
    let mut attempt = 0;
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .context("staged finalization deadline elapsed")?;
        attempt += 1;
        let response = request
            .try_clone()
            .context("staged finalization request body cannot be retained")?
            .timeout(remaining)
            .send()
            .await
            .with_context(|| format!("contacting the hub at {url}"))?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .with_context(|| format!("reading the hub response from {url}"))?;

        if status.is_success() {
            return serde_json::from_slice(&body)
                .with_context(|| format!("decoding the hub response from {url}"));
        }
        if let Ok(envelope) = serde_json::from_slice::<ConnectError>(&body) {
            if status == reqwest::StatusCode::SERVICE_UNAVAILABLE
                && envelope.code == "unavailable"
                && attempt < 3
            {
                let remaining = deadline.saturating_duration_since(Instant::now());
                tokio::time::sleep(remaining.min(Duration::from_millis(100))).await;
                continue;
            }
            anyhow::bail!("hub error [{}]: {}", envelope.code, envelope.message);
        }

        let detail = String::from_utf8_lossy(&body);
        let detail = detail.trim();
        anyhow::bail!(
            "hub request to {url} failed ({status}){}",
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        );
    }
}
