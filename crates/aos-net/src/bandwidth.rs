//! Bandwidth limiting via token bucket algorithm.
//!
//! Provides a rate limiter that controls the throughput of transfers
//! by requiring tokens to be consumed before sending/receiving data.
//! Tokens are refilled continuously based on the configured rate.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A token-bucket bandwidth limiter.
///
/// The bucket is continuously refilled at the configured rate. Before
/// sending or receiving data, callers must consume tokens equal to the
/// number of bytes. If insufficient tokens are available, the caller
/// is delayed until enough tokens have accumulated.
pub struct BandwidthLimiter {
    /// Rate limit in bytes per second. 0 means unlimited.
    rate: AtomicU64,
    /// Available tokens, in (possibly fractional) bytes.
    tokens: Mutex<f64>,
    /// Time of last refill.
    last_refill: Mutex<Instant>,
    /// Maximum burst size (equals one second of tokens).
    max_burst: AtomicU64,
}

impl BandwidthLimiter {
    /// Create a new bandwidth limiter.
    ///
    /// # Arguments
    ///
    /// * `bytes_per_second` - The rate limit in bytes per second.
    ///   Use 0 for unlimited bandwidth.
    #[allow(clippy::disallowed_methods)]
    pub fn new(bytes_per_second: u64) -> Self {
        Self {
            rate: AtomicU64::new(bytes_per_second),
            tokens: Mutex::new(bytes_per_second as f64),
            last_refill: Mutex::new(Instant::now()),
            max_burst: AtomicU64::new(bytes_per_second),
        }
    }

    /// Wait until `bytes` worth of tokens are available, then consume them.
    ///
    /// If the limiter rate is 0 (unlimited), returns immediately.
    /// For large requests, the data is consumed in smaller chunks
    /// (capped at one second's worth of tokens) to maintain smooth
    /// throughput. If the rate is changed to 0 while waiting, the call
    /// returns without consuming the remainder.
    pub async fn consume(&self, bytes: u64) {
        let rate = self.rate.load(Ordering::Relaxed);
        if rate == 0 {
            return;
        }

        let mut remaining = bytes;

        while remaining > 0 {
            // Calculate chunk size (limit to max_burst to avoid long waits).
            let chunk = remaining.min(self.max_burst.load(Ordering::Relaxed));

            loop {
                self.refill();

                let available = {
                    let mut tokens = self.tokens.lock().unwrap();
                    if *tokens >= chunk as f64 {
                        *tokens -= chunk as f64;
                        true
                    } else {
                        false
                    }
                };

                if available {
                    break;
                }

                // Calculate sleep time to accumulate enough tokens.
                let current_rate = self.rate.load(Ordering::Relaxed);
                if current_rate == 0 {
                    return; // Rate changed to unlimited.
                }

                let needed = {
                    let tokens = self.tokens.lock().unwrap();
                    (chunk as f64 - *tokens).max(0.0)
                };
                let sleep_secs = needed / current_rate as f64;
                let sleep_duration = Duration::from_secs_f64(sleep_secs.min(0.1));
                tokio::time::sleep(sleep_duration).await;
            }

            remaining -= chunk;
        }
    }

    /// Set a new rate limit.
    ///
    /// Takes effect immediately. Setting to 0 disables the limiter.
    pub fn set_rate(&self, bytes_per_second: u64) {
        self.rate.store(bytes_per_second, Ordering::Relaxed);
        self.max_burst.store(bytes_per_second, Ordering::Relaxed);
    }

    /// Get the current rate limit in bytes per second.
    pub fn rate(&self) -> u64 {
        self.rate.load(Ordering::Relaxed)
    }

    /// Check if the limiter is active (rate > 0).
    pub fn is_active(&self) -> bool {
        self.rate.load(Ordering::Relaxed) > 0
    }

    /// Refill tokens based on elapsed time since last refill.
    #[allow(clippy::disallowed_methods)]
    fn refill(&self) {
        let rate = self.rate.load(Ordering::Relaxed);
        if rate == 0 {
            return;
        }

        let now = Instant::now();
        let elapsed = {
            let mut last = self.last_refill.lock().unwrap();
            let elapsed = now.duration_since(*last);
            *last = now;
            elapsed
        };

        let new_tokens = elapsed.as_secs_f64() * rate as f64;
        let max = self.max_burst.load(Ordering::Relaxed) as f64;

        let mut tokens = self.tokens.lock().unwrap();
        *tokens = (*tokens + new_tokens).min(max);
    }
}

impl std::fmt::Debug for BandwidthLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BandwidthLimiter")
            .field("rate", &self.rate.load(Ordering::Relaxed))
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    #[test]
    fn test_new_limiter() {
        let limiter = BandwidthLimiter::new(1024);
        assert_eq!(limiter.rate(), 1024);
        assert!(limiter.is_active());
    }

    #[test]
    fn test_unlimited() {
        let limiter = BandwidthLimiter::new(0);
        assert_eq!(limiter.rate(), 0);
        assert!(!limiter.is_active());
    }

    #[test]
    fn test_set_rate() {
        let limiter = BandwidthLimiter::new(1024);
        limiter.set_rate(2048);
        assert_eq!(limiter.rate(), 2048);
    }

    #[tokio::test]
    async fn test_consume_unlimited() {
        let limiter = BandwidthLimiter::new(0);
        // Should return immediately.
        limiter.consume(1_000_000).await;
    }

    #[tokio::test]
    async fn test_consume_within_budget() {
        let limiter = BandwidthLimiter::new(1_000_000);
        // Consuming less than available should be near-instant.
        let start = Instant::now();
        limiter.consume(100).await;
        let elapsed = start.elapsed();
        assert!(elapsed < Duration::from_millis(100));
    }
}
