//! Keeps the same signer process alive through its clients' final live checks.
//!
//! A peer's write EOF cannot establish that its signature and PIDFD posts have
//! finished. After both finite purposes reply, this private owner waits through
//! their original cutoff. It accepts no new request, financial original, or
//! caller completion assertion. The whole inline carrier is included in the
//! original service's upfront receiving size; the wait allocates no memory and
//! installs no descriptors.

use std::error::Error;

use aos_sandbox_broker::cache_signer_connection::{
    CacheSignerConnectionClosedV1, deadline_timeout_v1,
};
use rustix::event::{PollFd, poll};
use rustix::time::{ClockId, Timespec, clock_gettime};

use super::{CacheSignerReceivingClosedV1 as Closed, cause};

#[derive(Clone, Copy)]
enum First {
    Order,
    Clock,
    Timeout,
    Poll,
    After,
}

#[derive(Default)]
pub(super) struct CacheSignerLifetimeOriginalV1 {
    cutoff: Option<u64>,
    before: Option<Timespec>,
    before_nanos: Option<Result<u64, Closed>>,
    timeout: Option<Result<Timespec, CacheSignerConnectionClosedV1>>,
    poll: Option<rustix::io::Result<usize>>,
    after: Option<Timespec>,
    after_nanos: Option<Result<u64, Closed>>,
    completion: Option<Result<(), Closed>>,
    first: Option<First>,
}

impl CacheSignerLifetimeOriginalV1 {
    pub(super) fn wait_until_cutoff_once(&mut self, cutoff: u64) -> Result<(), Closed> {
        if self.cutoff.is_some() {
            self.first.get_or_insert(First::Order);
            return Err(Closed);
        }
        self.cutoff = Some(cutoff);
        let now = clock_gettime(ClockId::Boottime);
        self.before = Some(now);
        self.before_nanos = Some(boottime_nanos(now));
        match self.before_nanos {
            Some(Ok(nanos)) if nanos >= cutoff => {
                // No new role operation is entered after expiry. The process
                // already remained live through the complete original bound.
                self.completion = Some(Ok(()));
                return Ok(());
            }
            Some(Ok(_)) => {}
            _ => {
                self.first = Some(First::Clock);
                self.completion = Some(Err(Closed));
                return Err(Closed);
            }
        }
        self.timeout = Some(deadline_timeout_v1(now, cutoff));
        if let Some(Ok(timeout)) = self.timeout.as_ref() {
            let mut descriptors: [PollFd<'_>; 0] = [];
            self.poll = Some(poll(&mut descriptors, Some(timeout)));
        } else {
            self.first.get_or_insert(First::Timeout);
        }
        if !matches!(self.poll, Some(Ok(0))) {
            self.first.get_or_insert(First::Poll);
        }
        let now = clock_gettime(ClockId::Boottime);
        self.after = Some(now);
        self.after_nanos = Some(boottime_nanos(now));
        if !matches!(self.after_nanos, Some(Ok(nanos)) if nanos >= cutoff) {
            self.first.get_or_insert(First::After);
        }
        self.completion = Some(if self.first.is_none() {
            Ok(())
        } else {
            Err(Closed)
        });
        if matches!(self.completion, Some(Ok(()))) {
            Ok(())
        } else {
            Err(Closed)
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Order => Some(&Closed),
            First::Clock => cause(&self.before_nanos),
            First::Timeout => cause(&self.timeout),
            First::Poll => cause(&self.poll).or_else(|| cause(&self.completion)),
            First::After => cause(&self.after_nanos).or_else(|| cause(&self.completion)),
        }
    }
}

fn boottime_nanos(value: Timespec) -> Result<u64, Closed> {
    let seconds = u64::try_from(value.tv_sec).map_err(|_| Closed)?;
    let nanos = u64::try_from(value.tv_nsec).map_err(|_| Closed)?;
    if nanos >= 1_000_000_000 {
        return Err(Closed);
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(nanos))
        .ok_or(Closed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completed_expiry_does_not_enter_poll_or_allow_reentry() {
        let mut original = CacheSignerLifetimeOriginalV1::default();
        original.wait_until_cutoff_once(0).unwrap();
        assert!(original.poll.is_none());
        let actual_before = original.before;
        assert!(original.wait_until_cutoff_once(u64::MAX).is_err());
        assert_eq!(original.cutoff, Some(0));
        assert_eq!(original.before, actual_before);
        assert!(matches!(original.completion, Some(Ok(()))));
    }

    #[test]
    fn native_wait_keeps_the_original_process_until_actual_cutoff() {
        let before = boottime_nanos(clock_gettime(ClockId::Boottime)).unwrap();
        let cutoff = before.checked_add(1_000_000).unwrap();
        let mut original = CacheSignerLifetimeOriginalV1::default();
        original.wait_until_cutoff_once(cutoff).unwrap();
        assert!(matches!(original.after_nanos, Some(Ok(now)) if now >= cutoff));
        assert!(matches!(original.poll, Some(Ok(0))));
        assert!(original.failure().is_none());
    }
}
