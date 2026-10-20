//! Bandwidth limiting and human-readable rate/size parsing.
//!
//! [`BandwidthLimiter`] is a token-bucket rate limiter shared (via
//! [`Arc`]) across all parallel transfers of a push or pull. A background
//! Tokio task refills the bucket every 100 ms; consumers either call
//! [`BandwidthLimiter::acquire`] before a whole-buffer transfer, or wrap
//! a stream in [`RateLimitedRead`] / [`RateLimitedWrite`] for byte-level
//! throttling.
//!
//! [`parse_bandwidth`] and [`parse_size`] parse the CLI's human-readable
//! values like `"100MB/s"` or `"1MiB"` into byte counts, accepting both
//! decimal (`kb`, `mb`, `gb`) and binary (`kib`, `mib`, `gib`) units.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;
use tokio::time::{Duration, interval};

/// Token-bucket rate limiter shared across all parallel connections.
///
/// When `rate` is 0, all methods are no-ops (unlimited).
///
/// The bucket refills by `rate / 10` tokens every 100 ms and is capped at
/// `rate / 5` (two ticks' worth) to allow modest bursts after idle
/// periods. The refill task holds only a [`Weak`](std::sync::Weak)
/// reference, so it shuts down automatically once the last `Arc` clone
/// of the limiter is dropped.
#[allow(dead_code)]
pub struct BandwidthLimiter {
    /// Configured rate in bytes per second; 0 means unlimited.
    rate: u64,
    /// Currently available token budget, in bytes.
    tokens: AtomicU64,
    /// Wakes waiters in [`BandwidthLimiter::acquire`] after each refill.
    notify: Notify,
}

impl BandwidthLimiter {
    /// Creates a new limiter with the given bytes/sec rate and spawns its
    /// refill task. Pass 0 for unlimited (no task is spawned).
    ///
    /// # Panics
    ///
    /// Panics if `rate > 0` and this is called outside a Tokio runtime,
    /// since the refill task is spawned with [`tokio::spawn`].
    pub fn new(rate: u64) -> Arc<Self> {
        let limiter = Arc::new(Self {
            rate,
            tokens: AtomicU64::new(rate / 10), // Start with one tick's worth
            notify: Notify::new(),
        });

        if rate > 0 {
            let weak = Arc::downgrade(&limiter);
            tokio::spawn(async move {
                let mut tick = interval(Duration::from_millis(100));
                loop {
                    tick.tick().await;
                    let Some(limiter) = weak.upgrade() else {
                        break;
                    };
                    let refill = limiter.rate / 10; // 100ms tick = rate/10 tokens
                    let current = limiter.tokens.load(Ordering::Relaxed);
                    // Cap at 2x one tick's worth to allow burst
                    let new = (current + refill).min(limiter.rate / 5);
                    limiter.tokens.store(new, Ordering::Relaxed);
                    limiter.notify.notify_waiters();
                }
            });
        }

        limiter
    }

    /// Returns whether this limiter is active (rate > 0).
    pub fn is_active(&self) -> bool {
        self.rate > 0
    }

    /// Waits until bandwidth budget is available for an `n`-byte transfer.
    ///
    /// Returns immediately when the limiter is unlimited. If fewer than
    /// `n` tokens are available but the bucket is non-empty, the whole
    /// remaining budget is consumed and the call returns — the caller is
    /// expected to come back before its next transfer, so debt is repaid
    /// on subsequent acquires rather than blocking mid-transfer.
    pub async fn acquire(&self, n: u64) {
        if self.rate == 0 {
            return;
        }

        loop {
            let current = self.tokens.load(Ordering::Relaxed);
            if current >= n {
                if self
                    .tokens
                    .compare_exchange(current, current - n, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    return;
                }
            } else if current > 0 {
                // Take what's available — caller will come back for the rest.
                let _ =
                    self.tokens
                        .compare_exchange(current, 0, Ordering::Relaxed, Ordering::Relaxed);
                return;
            }
            self.notify.notified().await;
        }
    }

    /// Wraps an [`AsyncRead`] with rate limiting.
    ///
    /// Part of the public API for streaming rate-limited I/O (not yet used internally).
    #[allow(dead_code)]
    pub fn wrap_read<R: AsyncRead + Unpin>(self: &Arc<Self>, r: R) -> RateLimitedRead<R> {
        RateLimitedRead {
            inner: r,
            limiter: Arc::clone(self),
        }
    }

    /// Wraps an [`AsyncWrite`] with rate limiting.
    ///
    /// Part of the public API for streaming rate-limited I/O (not yet used internally).
    #[allow(dead_code)]
    pub fn wrap_write<W: AsyncWrite + Unpin>(self: &Arc<Self>, w: W) -> RateLimitedWrite<W> {
        RateLimitedWrite {
            inner: w,
            limiter: Arc::clone(self),
        }
    }
}

/// An [`AsyncRead`] wrapper that enforces bandwidth limits.
///
/// Each `poll_read` is clamped to the tokens currently available; when
/// the bucket is empty the read returns [`Poll::Pending`] and is retried
/// after the next refill tick. Created via
/// [`BandwidthLimiter::wrap_read`].
pub struct RateLimitedRead<R> {
    inner: R,
    limiter: Arc<BandwidthLimiter>,
}

impl<R: AsyncRead + Unpin> AsyncRead for RateLimitedRead<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if !this.limiter.is_active() {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }

        // Try to acquire some tokens. If none available, register waker.
        let current = this.limiter.tokens.load(Ordering::Relaxed);
        if current == 0 {
            // Register to be woken when tokens are refilled.
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        // Limit read size to available tokens.
        let max_read = current.min(buf.remaining() as u64) as usize;
        if max_read == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);

        if let Poll::Ready(Ok(())) = &result {
            let read = (buf.filled().len() - before) as u64;
            if read > 0 {
                this.limiter
                    .tokens
                    .fetch_sub(read.min(current), Ordering::Relaxed);
            }
        }

        result
    }
}

/// An [`AsyncWrite`] wrapper that enforces bandwidth limits.
///
/// Each `poll_write` is clamped to the tokens currently available
/// (callers see a short write and retry with the remainder); when the
/// bucket is empty the write returns [`Poll::Pending`]. Flush and
/// shutdown pass through unthrottled. Created via
/// [`BandwidthLimiter::wrap_write`].
pub struct RateLimitedWrite<W> {
    inner: W,
    limiter: Arc<BandwidthLimiter>,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for RateLimitedWrite<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        if !this.limiter.is_active() {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        let current = this.limiter.tokens.load(Ordering::Relaxed);
        if current == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        let max_write = current.min(buf.len() as u64) as usize;
        let result = Pin::new(&mut this.inner).poll_write(cx, &buf[..max_write]);

        if let Poll::Ready(Ok(written)) = &result {
            this.limiter
                .tokens
                .fetch_sub((*written as u64).min(current), Ordering::Relaxed);
        }

        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Parses a human-readable bandwidth string like `"100MB/s"` into
/// bytes/sec.
///
/// Parsing is case-insensitive and an optional `/s` suffix is ignored.
/// Decimal units (`kb`/`mb`/`gb`, or bare `k`/`m`/`g`) are powers of
/// 1000; binary units (`kib`/`mib`/`gib`) are powers of 1024; `b` or no
/// unit means bytes. Fractional values like `"1.5MB"` are accepted and
/// truncated to whole bytes.
///
/// # Errors
///
/// Returns an error if the numeric part does not parse as a number, or
/// if the resulting value is negative or exceeds `u64::MAX`.
pub fn parse_bandwidth(s: &str) -> anyhow::Result<u64> {
    let s = s.trim().to_lowercase();
    let s = s.strip_suffix("/s").unwrap_or(&s);

    let (num_str, multiplier) = if let Some(n) = s.strip_suffix("gb") {
        (n, 1_000_000_000u64)
    } else if let Some(n) = s.strip_suffix("mb") {
        (n, 1_000_000)
    } else if let Some(n) = s.strip_suffix("kb") {
        (n, 1_000)
    } else if let Some(n) = s.strip_suffix("gib") {
        (n, 1 << 30)
    } else if let Some(n) = s.strip_suffix("mib") {
        (n, 1 << 20)
    } else if let Some(n) = s.strip_suffix("kib") {
        (n, 1 << 10)
    } else if let Some(n) = s.strip_suffix('g') {
        (n, 1_000_000_000)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 1_000_000)
    } else if let Some(n) = s.strip_suffix('k') {
        (n, 1_000)
    } else if let Some(n) = s.strip_suffix('b') {
        (n, 1)
    } else {
        (s, 1)
    };

    let num: f64 = num_str
        .trim()
        .parse::<f64>()
        .map_err(|_| anyhow::anyhow!("invalid bandwidth value: {num_str}"))?;

    let result = num * multiplier as f64;
    if result < 0.0 || result > u64::MAX as f64 {
        anyhow::bail!(
            "bandwidth value out of range: {num_str}{}",
            if multiplier > 1 { " (with unit)" } else { "" }
        );
    }
    Ok(result as u64)
}

/// Parses a human-readable size string like `"1MB"` into bytes.
///
/// Sizes and bandwidths share a grammar, so this delegates to
/// [`parse_bandwidth`] (a stray `/s` suffix is therefore tolerated).
///
/// # Errors
///
/// Returns an error under the same conditions as [`parse_bandwidth`].
pub fn parse_size(s: &str) -> anyhow::Result<u64> {
    parse_bandwidth(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bandwidth_values() {
        assert_eq!(parse_bandwidth("100MB/s").unwrap(), 100_000_000);
        assert_eq!(parse_bandwidth("1GB/s").unwrap(), 1_000_000_000);
        assert_eq!(parse_bandwidth("10KB/s").unwrap(), 10_000);
        assert_eq!(parse_bandwidth("500").unwrap(), 500);
        assert_eq!(parse_bandwidth("1MiB").unwrap(), 1 << 20);
    }

    #[test]
    fn parse_size_values() {
        assert_eq!(parse_size("1MB").unwrap(), 1_000_000);
        assert_eq!(parse_size("5MB").unwrap(), 5_000_000);
        assert_eq!(parse_size("256KB").unwrap(), 256_000);
    }
}
