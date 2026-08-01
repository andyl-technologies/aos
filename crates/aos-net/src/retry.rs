//! Retry logic with exponential backoff and jitter.

use std::time::Duration;

use anyhow::Result;
use rand::Rng;

/// Configuration for retry behavior.
///
/// The default is 3 attempts with a 1 second initial delay, a 2x
/// backoff factor, a 30 second delay cap, and jitter enabled.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of attempts (including the first).
    pub max_attempts: u32,
    /// Initial delay before the first retry.
    pub initial_delay: Duration,
    /// Maximum delay between retries.
    pub max_delay: Duration,
    /// Multiplier applied to the delay after each attempt.
    pub backoff_factor: f64,
    /// Whether to add random jitter to delays. When enabled, each
    /// delay is drawn uniformly from `0..=computed_backoff` to avoid
    /// thundering-herd retries.
    pub jitter: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            backoff_factor: 2.0,
            jitter: true,
        }
    }
}

/// Classification of errors for retry decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    /// Transient errors that may succeed on retry (5xx, timeout, connection reset).
    Transient,
    /// Permanent errors that should not be retried (4xx except 429, auth failure).
    Permanent,
    /// Rate limiting (429) -- retry with Retry-After delay if available.
    RateLimit,
}

/// Classify an error based on HTTP status and error type.
///
/// If `status` is provided it takes precedence: 429 is
/// [`ErrorClass::RateLimit`], other 4xx are [`ErrorClass::Permanent`],
/// and 5xx are [`ErrorClass::Transient`]. Otherwise the error chain is
/// inspected: reqwest timeouts/connect failures and I/O errors are
/// transient, and a reqwest error carrying a status is classified by
/// that status. Unknown errors default to transient so they get
/// retried.
pub fn classify_error(status: Option<u16>, error: &anyhow::Error) -> ErrorClass {
    if let Some(status) = status {
        return classify_status(status);
    }

    // Check for reqwest-specific errors.
    if let Some(reqwest_err) = error.downcast_ref::<reqwest::Error>() {
        if reqwest_err.is_timeout() {
            return ErrorClass::Transient;
        }
        if reqwest_err.is_connect() {
            return ErrorClass::Transient;
        }
        if let Some(status) = reqwest_err.status() {
            return classify_status(status.as_u16());
        }
    }

    // Check for I/O errors (connection reset, broken pipe, etc.).
    if error.downcast_ref::<std::io::Error>().is_some() {
        return ErrorClass::Transient;
    }

    // Default to transient for unknown errors.
    ErrorClass::Transient
}

/// Classify a bare HTTP status code into an [`ErrorClass`].
fn classify_status(status: u16) -> ErrorClass {
    match status {
        429 => ErrorClass::RateLimit,
        400..=499 => ErrorClass::Permanent,
        500..=599 => ErrorClass::Transient,
        _ => ErrorClass::Transient,
    }
}

/// Execute an async operation with retry logic.
///
/// The `operation` closure is called on each attempt. If it fails with a
/// transient error, it will be retried according to the config. Permanent
/// errors cause an immediate return.
///
/// For rate-limit errors (429), the delay is either the Retry-After value
/// (if extractable from the error) or the computed backoff delay.
///
/// # Errors
///
/// Returns the operation's error immediately if it is classified as
/// [`ErrorClass::Permanent`], or the last error observed once
/// `max_attempts` retryable failures have occurred.
pub async fn with_retry<F, Fut, T>(config: &RetryConfig, operation: F) -> Result<T>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut last_err: Option<anyhow::Error> = None;

    for attempt in 0..config.max_attempts {
        match operation().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                let class = classify_error(None, &err);

                match class {
                    ErrorClass::Permanent => {
                        tracing::debug!(
                            attempt = attempt + 1,
                            "permanent error, not retrying: {}",
                            err
                        );
                        return Err(err);
                    }
                    ErrorClass::RateLimit | ErrorClass::Transient => {
                        if attempt + 1 >= config.max_attempts {
                            tracing::debug!(
                                attempt = attempt + 1,
                                max = config.max_attempts,
                                "max retries reached: {}",
                                err
                            );
                            last_err = Some(err);
                            break;
                        }

                        let delay = compute_delay(config, attempt);
                        tracing::debug!(
                            attempt = attempt + 1,
                            delay_ms = delay.as_millis(),
                            "transient error, retrying: {}",
                            err
                        );
                        last_err = Some(err);
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("retry exhausted with no error captured")))
}

/// Execute an async operation with retry logic and HTTP status classification.
///
/// Similar to [`with_retry`] but accepts an operation that returns
/// `(Option<u16>, Result<T>)` where the first element is the HTTP status
/// code for error classification.
///
/// # Errors
///
/// Returns the operation's error immediately if the status/error is
/// classified as [`ErrorClass::Permanent`], or the last error observed
/// once `max_attempts` retryable failures have occurred.
pub async fn with_retry_status<F, Fut, T>(config: &RetryConfig, operation: F) -> Result<T>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = (Option<u16>, Result<T>)>,
{
    let mut last_err: Option<anyhow::Error> = None;

    for attempt in 0..config.max_attempts {
        let (status, result) = operation().await;

        match result {
            Ok(value) => return Ok(value),
            Err(err) => {
                let class = classify_error(status, &err);

                match class {
                    ErrorClass::Permanent => {
                        return Err(err);
                    }
                    ErrorClass::RateLimit | ErrorClass::Transient => {
                        if attempt + 1 >= config.max_attempts {
                            last_err = Some(err);
                            break;
                        }

                        let delay = compute_delay(config, attempt);
                        tracing::debug!(
                            attempt = attempt + 1,
                            delay_ms = delay.as_millis(),
                            ?status,
                            "retrying after error: {}",
                            err
                        );
                        last_err = Some(err);
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("retry exhausted with no error captured")))
}

/// Compute the delay for a retry attempt.
///
/// `attempt` is zero-based: attempt 0 yields the initial delay,
/// attempt 1 the initial delay times the backoff factor, and so on,
/// clamped to `max_delay` (with jitter applied if configured).
///
/// Used by the transfer engine's manual retry loop.
pub fn compute_retry_delay(config: &RetryConfig, attempt: u32) -> Duration {
    compute_delay(config, attempt)
}

/// Exponential backoff: `initial_delay * backoff_factor^attempt`,
/// clamped to `max_delay`, optionally jittered over `0..=delay`.
#[allow(clippy::disallowed_methods)]
fn compute_delay(config: &RetryConfig, attempt: u32) -> Duration {
    let base = config.initial_delay.as_secs_f64() * config.backoff_factor.powi(attempt as i32);
    let clamped = base.min(config.max_delay.as_secs_f64());

    let delay_secs = if config.jitter {
        let mut rng = rand::rng();
        rng.random_range(0.0..=clamped)
    } else {
        clamped
    };

    Duration::from_secs_f64(delay_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_status_5xx() {
        assert_eq!(classify_status(500), ErrorClass::Transient);
        assert_eq!(classify_status(502), ErrorClass::Transient);
        assert_eq!(classify_status(503), ErrorClass::Transient);
    }

    #[test]
    fn test_classify_status_4xx() {
        assert_eq!(classify_status(400), ErrorClass::Permanent);
        assert_eq!(classify_status(403), ErrorClass::Permanent);
        assert_eq!(classify_status(404), ErrorClass::Permanent);
    }

    #[test]
    fn test_classify_status_429() {
        assert_eq!(classify_status(429), ErrorClass::RateLimit);
    }

    #[test]
    fn test_classify_unknown_error() {
        let err = anyhow::anyhow!("connection refused");
        assert_eq!(classify_error(None, &err), ErrorClass::Transient);
    }

    #[test]
    fn test_classify_with_status() {
        let err = anyhow::anyhow!("not found");
        assert_eq!(classify_error(Some(404), &err), ErrorClass::Permanent);
    }

    #[test]
    fn test_compute_delay_no_jitter() {
        let config = RetryConfig {
            initial_delay: Duration::from_secs(1),
            backoff_factor: 2.0,
            max_delay: Duration::from_secs(30),
            jitter: false,
            ..Default::default()
        };

        let d0 = compute_delay(&config, 0);
        assert_eq!(d0, Duration::from_secs(1));

        let d1 = compute_delay(&config, 1);
        assert_eq!(d1, Duration::from_secs(2));

        let d2 = compute_delay(&config, 2);
        assert_eq!(d2, Duration::from_secs(4));
    }

    #[test]
    fn test_compute_delay_clamped() {
        let config = RetryConfig {
            initial_delay: Duration::from_secs(10),
            backoff_factor: 10.0,
            max_delay: Duration::from_secs(30),
            jitter: false,
            ..Default::default()
        };

        let d2 = compute_delay(&config, 2);
        assert_eq!(d2, Duration::from_secs(30));
    }

    #[test]
    fn test_default_config() {
        let config = RetryConfig::default();
        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.initial_delay, Duration::from_secs(1));
        assert_eq!(config.max_delay, Duration::from_secs(30));
        assert_eq!(config.backoff_factor, 2.0);
        assert!(config.jitter);
    }

    #[tokio::test]
    async fn test_with_retry_immediate_success() {
        let config = RetryConfig::default();
        let result = with_retry(&config, || async { Ok::<_, anyhow::Error>(42) }).await;
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_with_retry_permanent_error() {
        let config = RetryConfig {
            max_attempts: 3,
            jitter: false,
            initial_delay: Duration::from_millis(1),
            ..Default::default()
        };
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let c = counter.clone();

        let result: Result<i32> = with_retry_status(&config, || {
            let c = c.clone();
            async move {
                c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                (Some(404), Err(anyhow::anyhow!("not found")))
            }
        })
        .await;

        assert!(result.is_err());
        // Should only be called once (permanent error, no retry).
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
