//! Shared retained native paired-clock observations without lease authority.
//!
//! Role owners prepay these actual layouts before capture, retain the baseline
//! boot original for their full lifetime, and own the complete samples through
//! their independent posts. This module owns no ledger, key, publication or
//! authority reset port. Explicit positive-leaf disposal closes only complete
//! temporary input files; native outcomes and one-shot sample latches remain.

use aos_sandbox_core::{RawClockProvenance, RawPairedClockSample,
    ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::boot::RootOriginalKernelBootIdAttemptV1;

mod incremental;
pub use incremental::PairedClockIncrementalSamplesV3;

/// Reports unavailable paired-clock DATA while the actual native cause is held.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("protected paired clock is unavailable")]
pub struct ProtectedOwnershipClockError;

/// Retains the original boot and monotonically observed time baseline.
#[doc(hidden)]
pub struct PairedClockBaselineV1 {
    provenance: Result<RawClockProvenance, aos_sandbox_core::OwnershipLeaseVerificationError>,
    original_boot: RootOriginalKernelBootIdAttemptV1,
    file_retired: bool,
    boot: Option<[u8; 16]>,
    last_boottime_nanoseconds: u64,
}

impl PairedClockBaselineV1 {
    /// Captures only native comparison DATA; supplies no role authority or payer.
    pub fn capture(provenance: Result<RawClockProvenance, aos_sandbox_core::OwnershipLeaseVerificationError>) -> Self {
        let mut original_boot = RootOriginalKernelBootIdAttemptV1::new();
        let boot = original_boot.observe_once().ok().map(|boot| boot.into_bytes());
        Self { provenance, original_boot, file_retired: false, boot, last_boottime_nanoseconds: 0 }
    }

    /// Closes a completely observed baseline input while retaining all DATA.
    ///
    /// The original EOF, parsed bytes, provenance and one-shot latch remain.
    /// Calling this again after actual disposal performs no native operation.
    ///
    /// # Errors
    /// Leaves failed or incomplete native originals resident and reports their
    /// retained cause through [`Self::failure`].
    pub fn retire_positive_native_file_v2(&mut self) -> Result<(), ProtectedOwnershipClockError> {
        if self.failure().is_some() || self.boot.is_none() {
            return Err(ProtectedOwnershipClockError);
        }
        if !self.file_retired {
            self.original_boot.retire_positive_file_once()
                .map_err(|_| ProtectedOwnershipClockError)?;
            self.file_retired = true;
        }
        Ok(())
    }

    /// Borrows the original provenance/boot cause without resampling.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.provenance.as_ref().err().map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.original_boot.failure())
    }
}

/// Owns two actual native clock samples without a sample reset method.
#[doc(hidden)]
pub struct PairedClockSamplesV1 { observations: Vec<LocalClockObservation> }

struct LocalClockObservation {
    files_retired: bool,
    before: RootOriginalKernelBootIdAttemptV1,
    after: RootOriginalKernelBootIdAttemptV1,
    boottime: Option<rustix::time::Timespec>,
    realtime: Option<rustix::time::Timespec>,
    validation: Option<Result<RawPairedClockSample, aos_sandbox_core::OwnershipLeaseVerificationError>>,
    sample: Option<Result<RawPairedClockSample, ProtectedOwnershipClockError>>,
}


impl PairedClockSamplesV1 {
    /// Allocates the exact two-cell representation after the role's own debit.
    pub fn new() -> Self { Self { observations: Vec::with_capacity(2) } }

    /// Prices both real observation cells, excluding their resident Vec header.
    pub const fn representation_memory_bytes() -> usize {
        2 * std::mem::size_of::<LocalClockObservation>()
    }

    /// Prices the unchanged baseline and two-sample native geometry DATA.
    pub fn receiving_demand_v1() -> Option<ResourceVector> {
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(Self::representation_memory_bytes()).ok()?)
            .with(D::OpenFiles, 5).with(D::MetadataEntries, 5))
    }

    /// Borrows the chosen retained sample's earliest actual native cause.
    pub fn observation_failure(&self, index: usize) -> Option<&(dyn std::error::Error + 'static)> {
        let observation = self.observations.get(index)?;
        observation.before.failure().or_else(|| observation.after.failure())
            .or_else(|| observation.validation.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| observation.sample.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
    }


    /// Closes only complete positive bookend files without resetting samples.
    ///
    /// Every sample and native/parser result stays in its original observation.
    /// Already disposed positive observations are skipped. This grants no new
    /// observation slot or financial credit.
    ///
    /// # Errors
    /// Rejects an absent, partial or failed sample before disposing any files.
    /// Actual failed originals remain reachable through observation_failure.
    pub fn retire_positive_native_files_v2(&mut self) -> Result<(), ProtectedOwnershipClockError> {
        if self.observations.is_empty() || self.observations.iter().any(|observation| {
            !matches!(observation.sample, Some(Ok(_)))
                || !matches!(observation.validation, Some(Ok(_)))
                || observation.before.failure().is_some() || observation.after.failure().is_some()
        }) {
            return Err(ProtectedOwnershipClockError);
        }
        for observation in &mut self.observations {
            if !observation.files_retired {
                observation.before.retire_positive_file_once()
                    .map_err(|_| ProtectedOwnershipClockError)?;
                observation.after.retire_positive_file_once()
                    .map_err(|_| ProtectedOwnershipClockError)?;
                observation.files_retired = true;
            }
        }
        Ok(())
    }

    /// Samples BOOTTIME/realtime between the same original boot bookends.
    ///
    /// # Errors
    /// Retains both native boot readers and exact validation/sample Results.
    /// Refuses a third sample, changed boot or decreasing monotone time.
    pub fn sample(&mut self, baseline: &mut PairedClockBaselineV1) -> Result<RawPairedClockSample, ProtectedOwnershipClockError> {
        if self.observations.len() >= 2 {
            return Err(ProtectedOwnershipClockError);
        }
        self.observations.push(LocalClockObservation::new());
        let observation = self.observations.last_mut().ok_or(ProtectedOwnershipClockError)?;
        observation.observe(baseline)
    }
}

impl LocalClockObservation {
    fn new() -> Self {
        LocalClockObservation {
            files_retired: false,
            before: RootOriginalKernelBootIdAttemptV1::new(),
            after: RootOriginalKernelBootIdAttemptV1::new(),
            boottime: None, realtime: None, validation: None, sample: None,
        }
    }

    fn observe(&mut self, baseline: &mut PairedClockBaselineV1)
        -> Result<RawPairedClockSample, ProtectedOwnershipClockError>
    {
        let before = self.before.observe_once().ok().map(|boot| boot.into_bytes());
        self.boottime = Some(rustix::time::clock_gettime(rustix::time::ClockId::Boottime));
        self.realtime = Some(rustix::time::clock_gettime(rustix::time::ClockId::Realtime));
        let after = self.after.observe_once().ok().map(|boot| boot.into_bytes());
        self.sample = Some((|| {
            let boot = baseline.boot.ok_or(ProtectedOwnershipClockError)?;
            let provenance = *baseline.provenance.as_ref().map_err(|_| ProtectedOwnershipClockError)?;
            let boottime = self.boottime.ok_or(ProtectedOwnershipClockError)?;
            let realtime = self.realtime.ok_or(ProtectedOwnershipClockError)?;
            let seconds = u64::try_from(boottime.tv_sec).map_err(|_| ProtectedOwnershipClockError)?;
            let nanos = u64::try_from(boottime.tv_nsec).map_err(|_| ProtectedOwnershipClockError)?;
            let nanoseconds = seconds.checked_mul(1_000_000_000)
                .and_then(|value| value.checked_add(nanos)).ok_or(ProtectedOwnershipClockError)?;
            if before != Some(boot) || after != Some(boot) || nanoseconds < baseline.last_boottime_nanoseconds {
                return Err(ProtectedOwnershipClockError);
            }
            self.validation = Some(RawPairedClockSample::new_untrusted(
                provenance, boot, realtime.tv_sec, nanoseconds,
            ));
            let sample = *self.validation.as_ref()
                .and_then(|result| result.as_ref().ok()).ok_or(ProtectedOwnershipClockError)?;
            baseline.last_boottime_nanoseconds = nanoseconds;
            Ok(sample)
        })());
        self.sample.as_ref().copied().ok_or(ProtectedOwnershipClockError)?
    }
}

/// Holds a complete baseline/two-sample native comparison owner.
///
/// It returns only untrusted paired-clock DATA. There is no transient reset,
/// F/J account, signing capability or positive-publication constructor here.
#[doc(hidden)]
pub struct RetainedPairedClockV1 {
    baseline: PairedClockBaselineV1,
    samples: PairedClockSamplesV1,
}

impl RetainedPairedClockV1 {
    /// Captures the baseline using the held caller's comparison provenance DATA.
    pub fn open_with_comparison(original: RawPairedClockSample) -> Self {
        Self { baseline: PairedClockBaselineV1::capture(Ok(original.provenance())), samples: PairedClockSamplesV1::new() }
    }

    /// Samples the same original without issuing a live permission.
    ///
    /// # Errors
    /// Borrows causes through the retained baseline and samples on refusal.
    pub fn sample(&mut self) -> Result<RawPairedClockSample, ProtectedOwnershipClockError> {
        self.samples.sample(&mut self.baseline)
    }

    /// Borrows the original boot/provenance failure.
    pub fn initial_failure(&self) -> Option<&(dyn std::error::Error + 'static)> { self.baseline.failure() }

    /// Borrows a specific actual sample's earliest native cause.
    pub fn observation_failure(&self, index: usize) -> Option<&(dyn std::error::Error + 'static)> {
        self.samples.observation_failure(index)
    }
}

#[cfg(test)]
mod positive_leaf_tests {
    use super::*;

    #[test]
    fn positive_files_retire_without_rearming_samples_or_changing_data() {
        let mut baseline = PairedClockBaselineV1::capture(
            RawClockProvenance::new_untrusted(crate::ownership_clock::CLOCK_PROVENANCE));
        let mut samples = PairedClockSamplesV1::new();
        let first = samples.sample(&mut baseline).unwrap();
        let boot = baseline.boot;
        let monotone = baseline.last_boottime_nanoseconds;
        baseline.retire_positive_native_file_v2().unwrap();
        samples.retire_positive_native_files_v2().unwrap();
        assert!(baseline.file_retired);
        assert!(samples.observations[0].files_retired);
        assert_eq!(samples.observations[0].sample.as_ref().unwrap().as_ref().unwrap(), &first);
        assert_eq!(baseline.boot, boot);
        assert_eq!(baseline.last_boottime_nanoseconds, monotone);
        baseline.retire_positive_native_file_v2().unwrap();
        samples.retire_positive_native_files_v2().unwrap();
        samples.sample(&mut baseline).unwrap();
        samples.retire_positive_native_files_v2().unwrap();
        assert_eq!(samples.observations.len(), 2);
        assert!(samples.sample(&mut baseline).is_err());
        assert!(samples.observations[0].before.observe_once().is_err());
    }

    #[test]
    fn incomplete_or_failed_bookend_never_disposes_its_positive_peer() {
        let mut baseline = PairedClockBaselineV1::capture(
            RawClockProvenance::new_untrusted(crate::ownership_clock::CLOCK_PROVENANCE));
        let mut samples = PairedClockSamplesV1::new();
        assert!(samples.retire_positive_native_files_v2().is_err());
        // A changed comparison boot fails only after both actual native reads.
        baseline.boot = Some([0; 16]);
        assert!(samples.sample(&mut baseline).is_err());
        assert!(samples.retire_positive_native_files_v2().is_err());
        assert!(!samples.observations[0].files_retired);
        assert!(!baseline.file_retired);
        assert!(samples.observation_failure(0).is_some());
    }
}
