//! Retains one bounded native readiness observation on an original descriptor.
//!
//! Initial approval and fixed helper handoffs share the same BOOTTIME poll
//! recipe. Readiness is mechanical DATA, never Source or peer authority.

use std::os::fd::BorrowedFd;

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::time::{ClockId, clock_gettime};

/// Retains the before/timeout/poll/events/after originals of one readiness check.
#[must_use = "retain actual native outcomes through their independent posts"]
pub struct SeqpacketReadinessOriginalV1 {
    pub(super) before: Option<Timespec>,
    timeout: Option<Timespec>,
    pub(super) result: Option<rustix::io::Result<usize>>,
    events: Option<PollFlags>,
    after: Option<Timespec>,
}

impl SeqpacketReadinessOriginalV1 {
    /// Creates inert native result destinations without clock or socket IO.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            before: None,
            timeout: None,
            result: None,
            events: None,
            after: None,
        }
    }

    /// Polls the original descriptor once before a finite BOOTTIME deadline.
    ///
    /// Returns false for reentry, invalid or expired time, interruption, timeout,
    /// unexpected events or a late result. Actual samples and the native result
    /// remain resident. Readiness grants no send, receive or application role.
    #[must_use]
    pub fn observe(&mut self, fd: BorrowedFd<'_>, expected: PollFlags, deadline: u64) -> bool {
        if self.before.is_some() {
            return false;
        }
        self.before = Some(clock_gettime(ClockId::Boottime));
        if deadline == 0 || deadline == u64::MAX {
            return false;
        }
        let Some(before) = self.before.and_then(nanoseconds) else {
            return false;
        };
        let Some(remaining) = deadline
            .checked_sub(before)
            .filter(|remaining| *remaining > 0)
        else {
            return false;
        };
        self.timeout = Some(Timespec {
            tv_sec: (remaining / 1_000_000_000) as i64,
            tv_nsec: (remaining % 1_000_000_000) as i64,
        });
        let mut descriptors = [PollFd::new(&fd, expected)];
        self.result = Some(poll(&mut descriptors, self.timeout.as_ref()));
        self.events = Some(descriptors[0].revents());
        self.after = Some(clock_gettime(ClockId::Boottime));

        matches!(self.result, Some(Ok(1)))
            && self.events == Some(expected)
            && self
                .after
                .and_then(nanoseconds)
                .is_some_and(|after| after < deadline)
    }
}

fn nanoseconds(sample: Timespec) -> Option<u64> {
    let seconds = u64::try_from(sample.tv_sec).ok()?;
    let nanos = u64::try_from(sample.tv_nsec)
        .ok()
        .filter(|nanos| *nanos < 1_000_000_000)?;
    seconds.checked_mul(1_000_000_000)?.checked_add(nanos)
}

impl Default for SeqpacketReadinessOriginalV1 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deadline() -> u64 {
        nanoseconds(clock_gettime(ClockId::Boottime))
            .unwrap()
            .checked_add(1_000_000_000)
            .unwrap()
    }

    #[test]
    fn readiness_preserves_original_native_samples_on_reentry() {
        let (read, write) = rustix::pipe::pipe().unwrap();
        rustix::io::write(&write, b"x").unwrap();
        use std::os::fd::AsFd as _;
        let mut original = SeqpacketReadinessOriginalV1::new();

        assert!(original.observe(read.as_fd(), PollFlags::IN, deadline()));
        let first = original.before;
        let events = original.events;
        assert!(!original.observe(read.as_fd(), PollFlags::OUT, deadline()));

        assert_eq!(original.before, first);
        assert_eq!(original.events, events);
        assert!(matches!(original.result, Some(Ok(1))));
    }

    #[test]
    fn readiness_refuses_hangup_instead_of_treating_it_as_data() {
        let (read, write) = rustix::pipe::pipe().unwrap();
        drop(write);
        use std::os::fd::AsFd as _;
        let mut original = SeqpacketReadinessOriginalV1::new();

        assert!(!original.observe(read.as_fd(), PollFlags::IN, deadline()));

        assert!(original.events.unwrap().contains(PollFlags::HUP));
        assert!(matches!(original.result, Some(Ok(1))));
        assert!(original.after.is_some());
    }

    #[test]
    fn readiness_invalid_or_expired_deadline_does_not_poll() {
        let (read, _write) = rustix::pipe::pipe().unwrap();
        use std::os::fd::AsFd as _;
        for cut in [0, 1, u64::MAX] {
            let mut original = SeqpacketReadinessOriginalV1::new();

            assert!(!original.observe(read.as_fd(), PollFlags::IN, cut));

            assert!(original.result.is_none());
        }
    }
}
