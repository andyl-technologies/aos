//! Fixed native clock observations for one real authenticated Apply interval.
//!
//! Both procfs boot samples use the existing bounded retained reader. The
//! ordinary adapter keeps its original clock source/order. These inert owners
//! return DATA and keep native failures; only the genuine State stage pays IO.

use aos_sandbox_linux::boot::RootOriginalKernelBootIdAttemptV1;

use super::*;

const SAMPLES: usize = aos_sandbox_controller_domain::StorageStateRecoveryEncodingLoanV1
    ::MAXIMUM_APPLY_CLOCK_SAMPLES_V1;

struct PairedClockOriginalV1 {
    before: RootOriginalKernelBootIdAttemptV1,
    after: RootOriginalKernelBootIdAttemptV1,
    boottime: Option<Result<u64, crate::ZfsWorkerError>>,
    result: Option<Result<RawPairedClockSample, StorageRuntimeError>>,
}

impl PairedClockOriginalV1 {
    fn new() -> Self {
        Self {
            before: RootOriginalKernelBootIdAttemptV1::new(),
            after: RootOriginalKernelBootIdAttemptV1::new(),
            boottime: None,
            result: None,
        }
    }

    fn observe(&mut self) -> Result<RawPairedClockSample, StorageRuntimeError> {
        if self.result.is_some() {
            return Err(StorageRuntimeError::Receiving);
        }
        let Self { before, after, boottime, result } = self;
        let mut second_boot = false;
        *result = Some(crate::runtime::paired_clock_sample_from_kernel_readers(
            || {
                let reader = if second_boot { &mut *after } else { &mut *before };
                second_boot = true;
                let boot = reader.observe_once().map(|boot| boot.into_bytes())
                    .map_err(|_| StorageRuntimeError::Recovery)?;
                // This existing closed reader completes canonical EOF before
                // retiring its actual positive file. Input/native results stay
                // here; a partial/error file never reaches this disposition.
                reader.retire_positive_file_once()
                    .map_err(|_| StorageRuntimeError::Recovery)?;
                Ok(boot)
            },
            || {
                *boottime = Some(boottime_now_nanoseconds());
                match boottime.as_ref() {
                    Some(Ok(value)) => Ok(*value),
                    _ => Err(StorageRuntimeError::Recovery),
                }
            },
            || rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec,
        ));
        match result.as_ref() {
            Some(Ok(sample)) => Ok(*sample),
            _ => Err(StorageRuntimeError::Receiving),
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // Before → boottime → after is the unchanged paired observation order.
        self.before.failure()
            .or_else(|| self.boottime.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.after.failure())
            .or_else(|| self.result.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
    }
}

pub(super) struct ApplyClockOriginalV1 {
    samples: [PairedClockOriginalV1; SAMPLES],
    next: usize,
    exhausted: bool,
}

impl ApplyClockOriginalV1 {
    pub(super) fn requested_bytes_v1() -> Option<usize> {
        let native = RootOriginalKernelBootIdAttemptV1::dominant_requested_bytes_v1()?
            .checked_mul(2 * SAMPLES)?;
        native.checked_add(3 * std::mem::size_of::<Self>())
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<Option<Box<Self>>>()))
    }

    pub(super) fn new() -> Self {
        Self { samples: std::array::from_fn(|_| PairedClockOriginalV1::new()), next: 0, exhausted: false }
    }

    pub(super) fn sample(&mut self) -> Result<RawPairedClockSample, StorageRuntimeError> {
        if self.failure().is_some() {
            return Err(StorageRuntimeError::Receiving);
        }
        let Some(sample) = self.samples.get_mut(self.next) else {
            self.exhausted = true;
            return Err(StorageRuntimeError::Receiving);
        };
        self.next += 1;
        sample.observe()
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.samples.iter().find_map(PairedClockOriginalV1::failure)
            .or_else(|| self.exhausted.then_some(&StorageRuntimeError::Receiving as &dyn std::error::Error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_paired_clock_retires_only_the_two_completed_procfs_reads() {
        let mut original = PairedClockOriginalV1::new();

        let sample = original.observe().unwrap();

        assert_ne!(sample.host_boot_id(), [0; 16]);
        assert!(original.failure().is_none());
        // These are the same actual reader objects used above. A second close
        // refuses, demonstrating the positive EOF disposition already ran.
        assert!(original.before.retire_positive_file_once().is_err());
        assert!(original.after.retire_positive_file_once().is_err());
    }

    #[test]
    fn a_fixed_clock_recipe_retains_its_first_error_before_an_exhaustion_marker() {
        let mut original = ApplyClockOriginalV1::new();
        original.samples[0].result = Some(Err(StorageRuntimeError::Recovery));
        original.next = SAMPLES;
        let first = original.failure().unwrap() as *const dyn std::error::Error as *const ();

        assert!(original.sample().is_err());

        assert!(!original.exhausted);
        assert_eq!(original.failure().unwrap() as *const dyn std::error::Error as *const (), first);
    }
}
