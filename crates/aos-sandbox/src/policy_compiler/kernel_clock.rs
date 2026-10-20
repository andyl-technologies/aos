//! Preserves Domain clock diagnostics over the sole shared native sampler.

use aos_sandbox_core::RawPairedClockSample;
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;

impl aos_sandbox_broker::kernel_clock::KernelPairedClockErrorV1 for SourceGenesisErrorV1 {
    fn stale() -> Self { Self::Stale }

    fn kernel(error: aos_sandbox_linux::Error) -> Self { Self::Kernel(error) }
}

pub(crate) type RetainedKernelPairedClockAttemptV1 =
    aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1<SourceGenesisErrorV1>;

pub(super) fn ordinary_kernel_pair() -> Result<RawPairedClockSample, SourceGenesisErrorV1> {
    aos_sandbox_broker::kernel_clock::ordinary_kernel_pair()
}

pub(super) fn require_original_clock(
    original: Option<RawPairedClockSample>, current: RawPairedClockSample,
) -> Result<RawPairedClockSample, SourceGenesisErrorV1> {
    aos_sandbox_broker::kernel_clock::require_original_clock(original, current)
}

#[cfg(test)]
fn pair_from_observations(
    before: [u8; 16], boot: rustix::time::Timespec, wall: i64, after: [u8; 16],
) -> Result<RawPairedClockSample, SourceGenesisErrorV1> {
    aos_sandbox_broker::kernel_clock::pair_from_observations(before, boot, wall, after)
}
#[cfg(test)]
use rustix::time::Timespec;

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(seconds: i64, fraction: i64, boot: [u8; 16]) -> RawPairedClockSample {
        // Keep elapsed integer wall time aligned with elapsed boot time so
        // age controls reach the age check instead of failing drift first.
        pair_from_observations(boot, Timespec { tv_sec: seconds, tv_nsec: fraction }, seconds + 9, boot).unwrap()
    }

    #[test]
    fn paired_conversion_rejects_changed_boot_and_invalid_nanoseconds() {
        let tick = Timespec { tv_sec: 1, tv_nsec: 0 };

        assert!(pair_from_observations([1; 16], tick, 10, [2; 16]).is_err());
        assert!(pair_from_observations([1; 16], Timespec { tv_sec: -1, tv_nsec: 0 }, 10, [1; 16]).is_err());
        assert!(pair_from_observations([1; 16], Timespec { tv_sec: 1, tv_nsec: -1 }, 10, [1; 16]).is_err());
        assert_eq!(sample(1, 234, [1; 16]).boottime_nanoseconds(), 1_000_000_234);
    }

    #[test]
    fn original_age_preserves_strict_sixty_five_second_boundary_and_boot() {
        let original = sample(1, 0, [1; 16]);

        let just_before = sample(65, 999_999_999, [1; 16]);
        let at_deadline = sample(66, 0, [1; 16]);

        assert!(original.validate_later_sample(just_before).is_ok());
        assert!(original.validate_later_sample(at_deadline).is_ok());
        assert!(require_original_clock(Some(original), just_before).is_ok());
        assert!(require_original_clock(Some(original), at_deadline).is_err());
        assert!(require_original_clock(Some(original), sample(2, 0, [2; 16])).is_err());
        assert!(require_original_clock(None, sample(2, 0, [2; 16])).is_ok());
    }

    #[test]
    fn original_clock_rejects_wall_boot_drift_before_the_age_limit() {
        let original = sample(1, 0, [1; 16]);
        let drifted = pair_from_observations(
            [1; 16], Timespec { tv_sec: 7, tv_nsec: 0 }, 10, [1; 16],
        ).unwrap();

        assert_eq!(
            original.validate_later_sample(drifted),
            Err(aos_sandbox_core::OwnershipLeaseVerificationError::ClockDivergence),
        );
        assert!(require_original_clock(Some(original), drifted).is_err());
    }
}
