//! Shared bounded source throttling facts for physical executor settlement.
//!
//! HTTP headers affect operational eligibility, never vulnerability coverage.
//! Malformed hints cannot hide a failed response or grant another source call.
//!
//! A compact provider result may carry this observation-bound `retry` value:
//!
//! ```json
//! {
//!   "status": 429,
//!   "sourceDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
//!   "observedAt": "2026-10-10T00:00:00Z",
//!   "notBefore": "2026-10-10T00:02:00Z"
//! }
//! ```

use anyhow::{Result, ensure};
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

/// Maximum source-directed cooldown accepted from one physical response.
pub const MAX_SOURCE_RETRY_SECONDS: u64 = 86_400;

/// Carries only bounded throttling headers from an installed source response.
#[derive(Clone, Debug, Default)]
pub struct SourceThrottleHeaders {
    /// HTTP delay seconds or HTTP-date, at most 128 bytes.
    pub retry_after: Option<String>,
    /// GitHub's remaining request count, at most 128 bytes.
    pub rate_limit_remaining: Option<String>,
    /// GitHub's reset time in Unix seconds, at most 128 bytes.
    pub rate_limit_reset: Option<String>,
}

/// Commits one source-directed cooldown to its exact failed response observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProviderRetryV1 {
    /// Exact retryable HTTP status; ordinary permission denials are excluded.
    pub status: u16,
    /// Digest of the retained response bytes associated with this hint.
    pub source_digest: Sha256Digest,
    /// Physical response validation time within the admitted attempt.
    pub observed_at: Timestamp,
    /// Earliest eligible source time, bounded to one day after observation.
    pub not_before: Timestamp,
}

impl ProviderRetryV1 {
    /// Checks the retryable status and installed operational time ceiling.
    ///
    /// # Errors
    /// Returns an error for an unsupported status or negative/excessive delay.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            matches!(self.status, 403 | 429 | 500..=599),
            "source cooldown has a non-retryable status"
        );
        let delay = self.not_before.elapsed_since(&self.observed_at)?;
        ensure!(
            delay <= MAX_SOURCE_RETRY_SECONDS,
            "source cooldown exceeds the installed one-day ceiling"
        );
        Ok(())
    }
}

/// Normalizes an installed source's retry facts without trusting response text.
pub(super) fn source_retry(
    provider: &str,
    status: u16,
    headers: &SourceThrottleHeaders,
    digest: Sha256Digest,
    observed_at: &Timestamp,
) -> Result<Option<ProviderRetryV1>> {
    let github = matches!(provider, "github-releases" | "github-tags");
    let delay = headers
        .retry_after
        .as_deref()
        .and_then(|value| retry_after_delay(value, observed_at.unix_seconds()));
    let exhausted = github && headers.rate_limit_remaining.as_deref().and_then(decimal) == Some(0);
    let reset = exhausted
        .then(|| {
            headers
                .rate_limit_reset
                .as_deref()
                .and_then(decimal)
                .map(|reset| reset.saturating_sub(observed_at.unix_seconds()))
        })
        .flatten();

    // A plain 403 remains a permission failure. GitHub documents explicit
    // Retry-After or an exhausted primary quota as evidence of throttling.
    let seconds = match status {
        403 if github && (delay.is_some() || exhausted) => {
            Some(delay.unwrap_or(60).max(reset.unwrap_or(0)))
        }
        429 => Some(delay.unwrap_or(60).max(reset.unwrap_or(0))),
        500..=599 => delay,
        _ => None,
    };
    let Some(seconds) = seconds else {
        return Ok(None);
    };
    let retry = ProviderRetryV1 {
        status,
        source_digest: digest,
        observed_at: observed_at.clone(),
        not_before: Timestamp::from_unix_seconds(
            observed_at.unix_seconds() + seconds.min(MAX_SOURCE_RETRY_SECONDS),
        )?,
    };
    retry.validate()?;
    Ok(Some(retry))
}

fn safe_value(value: &str) -> Option<&str> {
    if value.len() > 128
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() && byte != b'\t')
    {
        return None;
    }
    let value = value.trim_matches([' ', '\t']);
    (!value.is_empty()).then_some(value)
}

fn decimal(value: &str) -> Option<u64> {
    let value = safe_value(value)?;
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    // Saturation preserves a conservative bounded cooldown for very large
    // syntactically valid seconds; overflow must not become an immediate retry.
    Some(value.bytes().fold(0_u64, |total, byte| {
        total
            .saturating_mul(10)
            .saturating_add(u64::from(byte - b'0'))
    }))
}

fn retry_after_delay(value: &str, observed_at: u64) -> Option<u64> {
    if let Some(seconds) = decimal(value) {
        return Some(seconds);
    }
    let date = httpdate::parse_http_date(safe_value(value)?).ok()?;
    let seconds = date.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    Some(seconds.saturating_sub(observed_at))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_supports_seconds_http_dates_and_bounded_large_values() -> Result<()> {
        let now = Timestamp::parse("2026-10-10T00:00:00Z")?;
        assert_eq!(retry_after_delay(" 120\t", now.unix_seconds()), Some(120));
        assert_eq!(
            retry_after_delay("Sat, 10 Oct 2026 00:02:00 GMT", now.unix_seconds()),
            Some(120)
        );
        assert_eq!(
            retry_after_delay("Fri, 09 Oct 2026 23:59:59 GMT", now.unix_seconds()),
            Some(0)
        );
        for value in ["-1", "+1", "1.2", "120,240", "120\r\nsecret", "tomorrow"] {
            assert_eq!(
                retry_after_delay(value, now.unix_seconds()),
                None,
                "{value:?}"
            );
        }
        let headers = SourceThrottleHeaders {
            retry_after: Some("9".repeat(100)),
            ..Default::default()
        };
        let retry = source_retry("osv", 429, &headers, Sha256Digest::of_bytes("error"), &now)?
            .expect("bounded retry");
        assert_eq!(
            retry.not_before.elapsed_since(&now)?,
            MAX_SOURCE_RETRY_SECONDS
        );
        Ok(())
    }

    #[test]
    fn github_throttling_requires_explicit_evidence_and_preserves_later_reset() -> Result<()> {
        let now = Timestamp::parse("2026-10-10T00:00:00Z")?;
        let digest = Sha256Digest::of_bytes("error");
        let mut headers = SourceThrottleHeaders::default();
        assert!(source_retry("github-releases", 403, &headers, digest, &now)?.is_none());
        headers.rate_limit_remaining = Some("0".into());
        headers.rate_limit_reset = Some((now.unix_seconds() + 3600).to_string());
        headers.retry_after = Some("120".into());
        let retry = source_retry("github-tags", 403, &headers, digest, &now)?
            .expect("explicit primary quota");
        assert_eq!(retry.not_before.elapsed_since(&now)?, 3600);
        assert!(source_retry("osv", 403, &headers, digest, &now)?.is_none());
        assert!(source_retry("github-tags", 401, &headers, digest, &now)?.is_none());
        assert!(source_retry("github-tags", 200, &headers, digest, &now)?.is_none());
        headers.rate_limit_remaining = Some("1".into());
        headers.retry_after = Some("malformed".into());
        assert!(source_retry("github-tags", 403, &headers, digest, &now)?.is_none());
        let fallback = source_retry("github-tags", 429, &headers, digest, &now)?
            .expect("status establishes throttling");
        assert_eq!(fallback.not_before.elapsed_since(&now)?, 60);
        Ok(())
    }

    #[test]
    fn outage_hints_and_serialized_facts_obey_exact_time_and_status_bounds() -> Result<()> {
        let now = Timestamp::parse("2026-10-10T00:00:00Z")?;
        let digest = Sha256Digest::of_bytes("error");
        let headers = SourceThrottleHeaders {
            retry_after: Some("7200".into()),
            ..Default::default()
        };
        let mut retry =
            source_retry("nvd", 503, &headers, digest, &now)?.expect("source-directed outage wait");
        assert_eq!(retry.not_before.elapsed_since(&now)?, 7200);
        retry.status = 404;
        assert!(retry.validate().is_err());
        retry.status = 503;
        retry.not_before =
            Timestamp::from_unix_seconds(now.unix_seconds() + MAX_SOURCE_RETRY_SECONDS + 1)?;
        assert!(retry.validate().is_err());
        retry.not_before = Timestamp::from_unix_seconds(now.unix_seconds() - 1)?;
        assert!(retry.validate().is_err());
        Ok(())
    }
}
