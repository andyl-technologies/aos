//! Checks immutable Capture BOOTTIME and WALL ceilings at process boundaries.
//!
//! These values deny mechanical process activity only. They authenticate no
//! clock domain, Source, worker or permission. The genuine Storage owner keeps
//! those associations and passes the original ceilings without renewal.

use super::*;

const OPERATION: &str = "fixed Capture process original cutoff";

/// Carries fixed, nonauthorizing original process cutoff DATA.
#[derive(Clone, Copy, Debug)]
pub struct FixedProcessCaptureCutV3 {
    boottime: FixedProcessBoottimeCutV1,
    wall_seconds: i64,
}

impl FixedProcessCaptureCutV3 {
    /// Checks finite numeric ceilings without sampling or granting execution.
    ///
    /// # Errors
    /// Rejects an unbounded BOOTTIME or nonpositive WALL endpoint.
    pub fn new(boottime_nanoseconds: u64, wall_seconds: i64) -> Result<Self> {
        let boottime = FixedProcessBoottimeCutV1::new(boottime_nanoseconds)?;
        if wall_seconds <= 0 {
            return Err(Error::invalid(
                "Capture process WALL cutoff",
                "must be positive",
            ));
        }
        Ok(Self {
            boottime,
            wall_seconds,
        })
    }
}

// Positive primitive samples are complete before replacement. Only the latest
// validated values are needed by the next wait; a failed sample is never reset.
#[derive(Default)]
pub(crate) struct CaptureProcessCutOriginalV3 {
    boottime: Option<Result<u64>>,
    wall: Option<rustix::time::Timespec>,
    error: Option<Error>,
    poll: Option<rustix::io::Result<usize>>,
    read: Option<rustix::io::Result<usize>>,
    poll_flags: [Option<rustix::event::PollFlags>; 3],
}

impl CaptureProcessCutOriginalV3 {
    pub(crate) fn observe(&mut self, cut: FixedProcessCaptureCutV3) -> Result<Duration> {
        if self.failure().is_some() {
            return Err(marker());
        }
        self.boottime = Some(uapi::boottime_nanoseconds());
        self.wall = Some(rustix::time::clock_gettime(rustix::time::ClockId::Realtime));
        let remaining: Result<Duration> = (|| {
            let boot = self
                .boottime
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .copied()
                .ok_or_else(marker)?;
            let wall = self.wall.ok_or_else(marker)?;
            let boot_remaining = cut
                .boottime
                .exclusive_nanoseconds()
                .checked_sub(boot)
                .filter(|remaining| *remaining != 0)
                .ok_or_else(marker)?;
            let seconds = cut
                .wall_seconds
                .checked_sub(wall.tv_sec)
                .and_then(|seconds| u64::try_from(seconds).ok())
                .ok_or_else(marker)?;
            let nanos = u64::try_from(wall.tv_nsec)
                .ok()
                .filter(|nanos| *nanos < 1_000_000_000)
                .ok_or_else(marker)?;
            let wall_remaining = seconds
                .checked_mul(1_000_000_000)
                .and_then(|remaining| remaining.checked_sub(nanos))
                .filter(|remaining| *remaining != 0)
                .ok_or_else(marker)?;
            Ok(Duration::from_nanos(boot_remaining.min(wall_remaining)))
        })();
        match remaining {
            Ok(remaining) => Ok(remaining),
            Err(error) => {
                self.error = Some(error);
                Err(marker())
            }
        }
    }

    pub(super) fn retain_read_v3(&mut self, native: rustix::io::Result<usize>) {
        self.read = Some(native);
    }

    pub(super) fn retain_poll_v3(
        &mut self,
        native: rustix::io::Result<usize>,
        descriptors: &[rustix::event::PollFd<'_>],
    ) {
        self.poll = Some(native);
        self.poll_flags =
            std::array::from_fn(|index| descriptors.get(index).map(|entry| entry.revents()));
    }

    pub(crate) fn failure(&self) -> Option<&Error> {
        self.boottime
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .or_else(|| self.error.as_ref())
    }

    // Reborrows the actual completed sample for the shared retained80 kernel.
    // This DATA can only deny work within the same unchanged absolute cuts.
    pub(crate) fn retained_native_cutoff_v1(&self, cut: FixedProcessCaptureCutV3)
        -> Result<crate::seqpacket::NetworkWorkerNativeCutoffV4>
    {
        if self.failure().is_some() { return Err(marker()); }
        let boot = self.boottime.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or_else(marker)?;
        let wall = self.wall.ok_or_else(marker)?;
        Ok(crate::seqpacket::NetworkWorkerNativeCutoffV4::new(
            boot, wall.tv_sec, cut.boottime.exclusive_nanoseconds(),
            Some(cut.wall_seconds),
        ))
    }
}

pub(super) fn marker() -> Error {
    Error::DeadlineExceeded {
        operation: OPERATION,
    }
}

pub(crate) fn is_marker(error: &Error) -> bool {
    matches!(error, Error::DeadlineExceeded { operation } if *operation == OPERATION)
}

// Native interruption/backpressure is ordinary retry control flow. When its
// independent after fails, that clock refusal is selected; fatal native errors
// keep priority. The raw native result remains resident in either case.
pub(super) fn read_errno_is_primary_v3(error: rustix::io::Errno) -> bool {
    !matches!(error, rustix::io::Errno::INTR | rustix::io::Errno::AGAIN)
}

pub(super) fn poll_errno_is_primary_v3(error: rustix::io::Errno) -> bool {
    error != rustix::io::Errno::INTR
}

pub(super) fn limit_wait_v3(previous: Duration, fresh_absolute: Duration) -> Duration {
    previous.min(fresh_absolute)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_control_flow_does_not_hide_an_independent_clock_refusal() {
        assert!(!read_errno_is_primary_v3(rustix::io::Errno::INTR));
        assert!(!read_errno_is_primary_v3(rustix::io::Errno::AGAIN));
        assert!(read_errno_is_primary_v3(rustix::io::Errno::IO));

        assert!(!poll_errno_is_primary_v3(rustix::io::Errno::INTR));
        assert!(poll_errno_is_primary_v3(rustix::io::Errno::AGAIN));
        assert!(poll_errno_is_primary_v3(rustix::io::Errno::IO));
    }

    #[test]
    fn fresh_cut_can_only_shorten_the_already_computed_wait() {
        assert_eq!(limit_wait_v3(Duration::from_secs(60), Duration::from_secs(2)),
            Duration::from_secs(2));
        assert_eq!(limit_wait_v3(Duration::from_secs(1), Duration::from_secs(2)),
            Duration::from_secs(1));
    }
}
