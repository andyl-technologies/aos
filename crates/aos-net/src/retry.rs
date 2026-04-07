//! Retry with exponential backoff.
//!
//! Provides a generic retry loop that classifies errors as transient or
//! permanent, and retries transient failures with exponential backoff.

use std::time::Duration;

/// Maximum number of retry attempts (default).
pub const DEFAULT_MAX_RETRIES: u32 = 3;

/// Base delay between retries (exponential backoff: delay * 2^attempt).
pub const DEFAULT_RETRY_BASE_DELAY: Duration = Duration::from_secs(1);

/// Classification of an error for retry purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    /// Transient error (5xx, timeout, connection reset) -- should be retried.
    Transient,
    /// Permanent error (4xx, hash mismatch) -- should NOT be retried.
    Permanent,
}

/// Classify an HTTP status code for retry purposes.
///
/// - 4xx -> Permanent (client error, retrying won't help)
/// - 5xx -> Transient (server error, may recover)
/// - Other non-success -> Transient
pub fn classify_http_status(status: u16) -> ErrorClass {
    if (400..500).contains(&status) {
        ErrorClass::Permanent
    } else {
        ErrorClass::Transient
    }
}

/// Check if an error message indicates a permanent (non-retryable) failure.
///
/// Looks for HTTP 4xx status codes in the error message string.
pub fn is_permanent_error_message(message: &str) -> bool {
    message.contains("HTTP 4")
}

/// Run an async operation with exponential backoff retry.
///
/// The `classify` function examines each error to decide whether to retry.
/// Returns the first successful result, or the last error after all retries
/// are exhausted.
pub async fn with_retry<F, Fut, T, E>(
    max_retries: u32,
    base_delay: Duration,
    classify: impl Fn(&E) -> ErrorClass,
    mut operation: F,
) -> Result<T, E>
where
    F: FnMut(u32) -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let mut last_err: Option<E> = None;

    for attempt in 0..=max_retries {
        if attempt > 0 {
            let delay = base_delay * 2u32.pow(attempt - 1);
            tokio::time::sleep(delay).await;
        }

        match operation(attempt).await {
            Ok(val) => return Ok(val),
            Err(e) => {
                if classify(&e) == ErrorClass::Permanent {
                    return Err(e);
                }
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_4xx_is_permanent() {
        assert_eq!(classify_http_status(400), ErrorClass::Permanent);
        assert_eq!(classify_http_status(404), ErrorClass::Permanent);
        assert_eq!(classify_http_status(403), ErrorClass::Permanent);
        assert_eq!(classify_http_status(499), ErrorClass::Permanent);
    }

    #[test]
    fn classify_5xx_is_transient() {
        assert_eq!(classify_http_status(500), ErrorClass::Transient);
        assert_eq!(classify_http_status(502), ErrorClass::Transient);
        assert_eq!(classify_http_status(503), ErrorClass::Transient);
    }

    #[test]
    fn classify_2xx_is_transient() {
        // Non-error statuses treated as transient (shouldn't reach here normally)
        assert_eq!(classify_http_status(200), ErrorClass::Transient);
    }

    #[test]
    fn permanent_error_message_detection() {
        assert!(is_permanent_error_message("HTTP 404 for https://example.com"));
        assert!(is_permanent_error_message("HTTP 403 forbidden"));
        assert!(!is_permanent_error_message("HTTP 503 service unavailable"));
        assert!(!is_permanent_error_message("connection refused"));
    }

    #[tokio::test]
    async fn retry_succeeds_first_try() {
        let result: Result<i32, String> = with_retry(
            3,
            Duration::from_millis(1),
            |_e| ErrorClass::Transient,
            |_attempt| async { Ok(42) },
        )
        .await;
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn retry_succeeds_after_failures() {
        let result: Result<i32, String> = with_retry(
            3,
            Duration::from_millis(1),
            |_e| ErrorClass::Transient,
            |attempt| async move {
                if attempt < 2 {
                    Err("transient".into())
                } else {
                    Ok(42)
                }
            },
        )
        .await;
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn retry_stops_on_permanent_error() {
        let result: Result<i32, String> = with_retry(
            3,
            Duration::from_millis(1),
            |_e: &String| ErrorClass::Permanent,
            |_attempt| async { Err::<i32, String>("permanent".into()) },
        )
        .await;
        assert_eq!(result.unwrap_err(), "permanent");
    }

    #[tokio::test]
    async fn retry_exhausts_all_attempts() {
        let result: Result<i32, String> = with_retry(
            2,
            Duration::from_millis(1),
            |_e| ErrorClass::Transient,
            |_attempt| async { Err::<i32, String>("still failing".into()) },
        )
        .await;
        assert_eq!(result.unwrap_err(), "still failing");
    }
}
