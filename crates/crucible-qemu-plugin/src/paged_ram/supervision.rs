//! SPDX-License-Identifier: GPL-2.0-or-later
//! Contains private operational monotonic clock access for pager containment.
//!
//! Operation starts remain opaque. The one shared-kernel integer coordinate
//! serves only the authenticated operational outer-cap record; it never enters
//! guest time, state identity, deterministic decisions or RAM content records.

#[cfg(test)]
use std::io;
use std::time::{Duration, Instant};

/// Opaque monotonic checkpoint for original starts and completed-work progress.
///
/// An operation retains its original checkpoint throughout its lifetime. Only
/// authenticated completed work can replace a separate progress checkpoint.
#[derive(Clone, Copy)]
pub(super) struct OperationalStart(Instant);

impl OperationalStart {
    /// Samples the private monotonic clock for one operational checkpoint.
    pub(super) fn begin() -> Self {
        Self(monotonic_now())
    }

    /// Returns elapsed time without changing the retained checkpoint.
    pub(super) fn elapsed(&self) -> Duration {
        monotonic_now().saturating_duration_since(self.0)
    }
}

/// Finite containment cap for explicit non-live transport utilities.
#[cfg(test)]
pub(super) struct TransportDeadline {
    started: OperationalStart,
    total: Duration,
}

#[cfg(test)]
impl TransportDeadline {
    /// Starts a finite checked transport allowance.
    ///
    /// # Errors
    /// Refuses zero or unrepresentable absolute monotonic allowances.
    pub(super) fn new(total: Duration) -> io::Result<Self> {
        let started = OperationalStart::begin();
        if total.is_zero() || started.0.checked_add(total).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid RAM transport allowance",
            ));
        }
        Ok(Self { started, total })
    }

    /// Returns remaining time under the original cap.
    ///
    /// # Errors
    /// Returns timeout when the original cap has expired.
    pub(super) fn remaining(&self) -> io::Result<Duration> {
        self.total
            .checked_sub(self.started.elapsed())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "RAM transport allowance expired")
            })
    }
}

/// Reads only the local operational monotonic coordinate shared with the host.
///
/// # Errors
/// Refuses unavailable or unrepresentable kernel monotonic time.
pub(super) fn monotonic_ns() -> std::io::Result<u64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime initializes this live stack value and retains no pointer.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let seconds = u64::try_from(value.tv_sec)
        .map_err(|_| std::io::Error::other("negative operational monotonic time"))?;
    let nanos = u64::try_from(value.tv_nsec)
        .map_err(|_| std::io::Error::other("negative operational monotonic fraction"))?;
    if nanos >= 1_000_000_000 {
        return Err(std::io::Error::other(
            "invalid operational monotonic fraction",
        ));
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .ok_or_else(|| std::io::Error::other("operational monotonic coordinate overflow"))
}

// crucible-lint: allow clippy-disallowed-method -- This private operational pager deadline samples host monotonic time; its opaque token never enters guest execution state.
#[allow(
    clippy::disallowed_methods,
    reason = "private operational supervision clock boundary"
)]
fn monotonic_now() -> Instant {
    Instant::now()
}
