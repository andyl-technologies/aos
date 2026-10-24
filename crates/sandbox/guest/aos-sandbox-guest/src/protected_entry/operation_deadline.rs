//! Retains the original selected operation's pre-receive BOOTTIME endpoint.

use super::*;

/// Keeps one actual transport interval's original BOOTTIME cutoff.
///
/// Only the protected loop constructs this value, before receiving a request.
/// It is not a grant, process lifetime or replacement for a signed WALL bound.
pub struct GuestOperationDeadlineOriginalV1 {
    sample: rustix::time::Timespec,
    cutoff: Result<u64, ProtectedGuestAgentErrorV1>,
}

impl GuestOperationDeadlineOriginalV1 {
    pub(super) fn start() -> Self {
        let sample = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        let cutoff = (|| {
            if sample.tv_sec < 0 || !(0..1_000_000_000).contains(&sample.tv_nsec) {
                return Err(ProtectedGuestAgentErrorV1::Deadline);
            }
            let seconds =
                u64::try_from(sample.tv_sec).map_err(|_| ProtectedGuestAgentErrorV1::Deadline)?;
            let nanos =
                u64::try_from(sample.tv_nsec).map_err(|_| ProtectedGuestAgentErrorV1::Deadline)?;
            let interval = u64::try_from(OPERATION_TIMEOUT.as_nanos())
                .map_err(|_| ProtectedGuestAgentErrorV1::Deadline)?;
            seconds
                .checked_mul(1_000_000_000)
                .and_then(|value| value.checked_add(nanos))
                .and_then(|value| value.checked_add(interval))
                .ok_or(ProtectedGuestAgentErrorV1::Deadline)
        })();
        Self { sample, cutoff }
    }

    pub(crate) fn cutoff_data_v1(&self) -> Result<u64, ProtectedGuestAgentErrorV1> {
        self.cutoff
            .as_ref()
            .copied()
            .map_err(|_| ProtectedGuestAgentErrorV1::Deadline)
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cutoff.as_ref().err().map(|cause| cause as _)
    }
}
