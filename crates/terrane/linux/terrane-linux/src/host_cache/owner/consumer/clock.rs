//! Bounds acknowledged consumer deadlines with the native wall and monotonic clock.
//!
//! Wall deadlines persist across restart. A live process additionally retains a
//! conservative monotonic bound so a wall-clock rollback cannot prolong a grant.

use std::{io, time::SystemTime};
use terrane_sdk::store::{Clock, TokioClock};

/// Retains one checked expiry and its process-local monotonic upper bound.
#[derive(Clone, Copy)]
pub(super) struct Deadline {
    /// Absolute durable Unix-second expiry.
    pub(super) expires: u64,
    /// Conservative cutoff in the actual process clock's nanosecond domain.
    pub(super) monotonic_end: u64,
}

impl Deadline {
    /// Samples the actual clock before any source or pin effects.
    ///
    /// # Errors
    /// Refuses elapsed, unencodable or overflowing deadlines and invalid clocks.
    pub(super) fn new(expires: u64) -> io::Result<Self> {
        let monotonic = monotonic_nanos()?;
        let wall = wall_nanos()?;
        let end = u128::from(expires)
            .checked_mul(1_000_000_000)
            .filter(|_| expires <= i64::MAX as u64)
            .ok_or_else(|| invalid("consumer expiry cannot be encoded"))?;
        let remaining = end
            .checked_sub(wall)
            .filter(|duration| *duration != 0)
            .ok_or_else(|| invalid("consumer expiry has elapsed"))?;
        let monotonic_end = monotonic
            .checked_add(u64::try_from(remaining).map_err(io::Error::other)?)
            .ok_or_else(|| invalid("consumer monotonic deadline overflows"))?;
        Ok(Self {
            expires,
            monotonic_end,
        })
    }

    /// Extends the original monotonic bound without reanchoring a rolled-back clock.
    ///
    /// # Errors
    /// Refuses an expired original grant, nonincreasing expiry or arithmetic overflow.
    pub(super) fn renew(self, expires: u64) -> io::Result<Self> {
        self.check_live()?;
        let extra = expires
            .checked_sub(self.expires)
            .filter(|extra| *extra != 0 && expires <= i64::MAX as u64)
            .and_then(|extra| extra.checked_mul(1_000_000_000))
            .ok_or_else(|| invalid("consumer renewal must extend a representable expiry"))?;
        let monotonic_end = self
            .monotonic_end
            .checked_add(extra)
            .ok_or_else(|| invalid("consumer renewal monotonic deadline overflows"))?;
        Ok(Self {
            expires,
            monotonic_end,
        })
    }

    /// Checks both retained deadline bounds without consulting embedded policy.
    ///
    /// # Errors
    /// Refuses either elapsed bound or an unavailable clock representation.
    pub(super) fn check_live(self) -> io::Result<()> {
        if now_seconds()? >= self.expires || monotonic_nanos()? >= self.monotonic_end {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "consumer lease expired",
            ));
        }
        Ok(())
    }
}

/// Samples Unix seconds through the existing native clock binding.
///
/// # Errors
/// Refuses a native wall clock before the Unix epoch.
pub(in crate::host_cache::owner) fn now_seconds() -> io::Result<u64> {
    TokioClock
        .now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(io::Error::other)
}

fn wall_nanos() -> io::Result<u128> {
    TokioClock
        .now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .map_err(io::Error::other)
}

fn monotonic_nanos() -> io::Result<u64> {
    u64::try_from(TokioClock.monotonic().as_nanos()).map_err(io::Error::other)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// Rounds durable grace upward to the policy snapshot's Unix-second resolution.
///
/// An expired lease uses its original expiry, never the eventual sweep time.
/// Rounding is conservative and bounded by less than one policy clock tick.
///
/// # Errors
/// Refuses invalid clocks and deadlines beyond the existing TOML integer range.
pub(in crate::host_cache::owner) fn grace_end(
    expired_at: Option<u64>,
    grace: std::time::Duration,
) -> io::Result<u64> {
    let start = match expired_at {
        Some(expiry) => u128::from(expiry) * 1_000_000_000,
        None => wall_nanos()?,
    };
    let end = start
        .checked_add(grace.as_nanos())
        .and_then(|value| value.checked_add(999_999_999))
        .map(|value| value / 1_000_000_000)
        .ok_or_else(|| invalid("consumer grace overflows"))?;
    u64::try_from(end)
        .ok()
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or_else(|| invalid("consumer grace cannot be encoded"))
}
