//! Retains the actual finite readiness gate before each strict Root receive.
//!
//! The strict subject reader intentionally uses MSG_DONTWAIT. Socket timeouts
//! cannot wait for a peer to enqueue its next frame; this poll uses the same
//! actual stream and immutable Root cutoff. It performs no receive or retry.

use std::error::Error;
use std::mem::size_of;
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;

use rustix::event::{PollFd, PollFlags, Timespec, poll};

#[derive(Debug, thiserror::Error)]
enum ReadinessErrorV1 {
    #[error("the original Root readiness cutoff expired")]
    Cutoff,
    #[error("the original Root readiness clock cannot be represented")]
    Clock,
    #[error("the Root readiness observation was entered more than once")]
    Reentry,
}

/// Retains one finite poll against the same borrowed stream and absolute cutoff.
///
/// This mechanical observation performs no receive and grants no role or phase.
#[derive(Default)]
pub struct RootSubjectReadinessV1 {
    clock: Option<Timespec>,
    timeout: Option<Result<Timespec, ReadinessErrorV1>>,
    native: Option<Result<usize, rustix::io::Errno>>,
    after_clock: Option<Timespec>,
    after_timeout: Option<Result<Timespec, ReadinessErrorV1>>,
    ready: Option<Result<(), ReadinessErrorV1>>,
    entered: bool,
    closed: Option<ReadinessErrorV1>,
}

impl RootSubjectReadinessV1 {
    /// Reports whether the same poll capsule has already been entered.
    pub fn entered(&self) -> bool {
        self.entered
    }

    /// Polls the same original stream once against the supplied absolute cutoff.
    pub fn wait_once(&mut self, original: &UnixStream, cutoff: u64) -> bool {
        self.wait_borrowed_once_v1(original.as_fd(), cutoff)
    }

    /// Polls the same retained stream once against the supplied absolute cutoff.
    pub fn wait_retained_once_v1(
        &mut self, original: &aos_linux_descriptors::unix_stream::RetainedUnixStream, cutoff: u64,
    ) -> bool {
        self.wait_borrowed_once_v1(original.as_fd(), cutoff)
    }

    fn wait_borrowed_once_v1(&mut self, original: std::os::fd::BorrowedFd<'_>, cutoff: u64) -> bool {
        if self.entered {
            self.closed.get_or_insert(ReadinessErrorV1::Reentry);
            return false;
        }
        self.entered = true;
        let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        self.clock = Some(now);
        self.timeout = Some(remaining(now, cutoff));
        let Some(Ok(timeout)) = self.timeout.as_ref() else {
            return false;
        };
        let readiness = PollFlags::IN;
        let mut descriptors = [PollFd::from_borrowed_fd(original, readiness)];
        self.native = Some(poll(&mut descriptors, Some(timeout)));
        let after = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        self.after_clock = Some(after);
        self.after_timeout = Some(remaining(after, cutoff));
        if let Some(Ok(count)) = self.native.as_ref() {
            self.ready = Some(if *count == 0 {
                Err(ReadinessErrorV1::Cutoff)
            } else {
                Ok(())
            });
        }
        self.positive()
    }

    /// Reports a positive poll and positive unchanged-cutoff bookend.
    pub fn positive(&self) -> bool {
        self.entered
            && matches!(self.ready, Some(Ok(())))
            && matches!(self.after_timeout, Some(Ok(_)))
            && self.failure().is_none()
    }

    /// Borrows the first actual clock, poll, timeout or reentry refusal.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.timeout
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn Error)
            .or_else(|| {
                self.native
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.after_timeout
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.ready
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    /// Measures the existing poll capsule and its actual construction planes.
    pub fn receiving_construction_bytes_v1() -> Option<u64> {
        // The surrounding Ready sizeof pays the resident capsule. Count its
        // replacement, clock/timeout return copies and actual borrowed pollfd.
        let bytes = size_of::<Self>()
            .checked_add(6 * size_of::<Timespec>())?
            .checked_add(4 * size_of::<Result<Timespec, ReadinessErrorV1>>())?
            .checked_add(2 * size_of::<Result<usize, rustix::io::Errno>>())?
            .checked_add(size_of::<PollFd<'static>>())?
            .checked_add(size_of::<PollFlags>())?;
        u64::try_from(bytes).ok()
    }

    /// Reports that mechanical poll controls create no namespace rows.
    pub const fn receiving_metadata_cells_v1() -> u64 {
        // Poll descriptors and pure readiness results create no namespace rows.
        0
    }
}

// Both native bookends use this same checked absolute-cutoff conversion.
fn remaining(now: Timespec, cutoff: u64) -> Result<Timespec, ReadinessErrorV1> {
    let seconds = u64::try_from(now.tv_sec).map_err(|_| ReadinessErrorV1::Clock)?;
    let nanoseconds = u64::try_from(now.tv_nsec).map_err(|_| ReadinessErrorV1::Clock)?;
    let current = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(ReadinessErrorV1::Clock)?;
    let remaining = cutoff
        .checked_sub(current)
        .filter(|value| *value != 0)
        .ok_or(ReadinessErrorV1::Cutoff)?;
    Ok(Timespec {
        tv_sec: i64::try_from(remaining / 1_000_000_000).map_err(|_| ReadinessErrorV1::Clock)?,
        tv_nsec: i64::try_from(remaining % 1_000_000_000).map_err(|_| ReadinessErrorV1::Clock)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn readable_original_retains_native_poll_until_all_upper_posts() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        peer.write_all(b"ready").unwrap();
        let mut capture = RootSubjectReadinessV1::default();

        assert!(capture.wait_once(&stream, u64::MAX));

        assert!(matches!(capture.native, Some(Ok(count)) if count > 0));
        assert!(capture.clock.is_some());
        assert!(capture.timeout.is_some());
        assert!(capture.after_clock.is_some());
        assert!(matches!(capture.after_timeout, Some(Ok(_))));
        assert!(capture.failure().is_none());
    }

    #[test]
    fn expired_original_preserves_first_cause_without_poll_or_new_deadline() {
        let (stream, _peer) = UnixStream::pair().unwrap();
        let mut capture = RootSubjectReadinessV1::default();

        assert!(!capture.wait_once(&stream, 0));
        assert!(capture.native.is_none());
        assert!(matches!(
            capture.timeout,
            Some(Err(ReadinessErrorV1::Cutoff))
        ));
        let first = capture.failure().unwrap() as *const dyn Error as *const ();
        assert!(!capture.wait_once(&stream, u64::MAX));
        assert_eq!(
            first,
            capture.failure().unwrap() as *const dyn Error as *const ()
        );
    }

    #[test]
    fn late_positive_poll_cannot_enter_native_receive_or_clear_its_step() {
        let mut capture = RootSubjectReadinessV1::default();
        capture.entered = true;
        capture.timeout = Some(Ok(Timespec {
            tv_sec: 1,
            tv_nsec: 0,
        }));
        capture.native = Some(Ok(1));
        capture.ready = Some(Ok(()));
        let after = Timespec {
            tv_sec: 5,
            tv_nsec: 0,
        };
        capture.after_clock = Some(after);
        capture.after_timeout = Some(remaining(after, 5_000_000_000));

        assert!(!capture.positive());
        assert!(matches!(capture.native, Some(Ok(1))));
        assert!(matches!(
            capture.after_timeout,
            Some(Err(ReadinessErrorV1::Cutoff))
        ));
    }

    #[test]
    fn native_poll_error_precedes_its_later_deadline_refusal() {
        let mut capture = RootSubjectReadinessV1::default();
        capture.entered = true;
        capture.native = Some(Err(rustix::io::Errno::IO));
        capture.after_timeout = Some(Err(ReadinessErrorV1::Cutoff));
        let native = capture.native.as_ref().unwrap().as_ref().unwrap_err();

        assert!(std::ptr::eq(
            capture
                .failure()
                .unwrap()
                .downcast_ref::<rustix::io::Errno>()
                .unwrap(),
            native
        ));
        assert!(!capture.positive());
    }
}
