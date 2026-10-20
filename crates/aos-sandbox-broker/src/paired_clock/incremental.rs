//! Holds the last validated observation and a finite native retry budget.
//!
//! The original baseline remains the caller's same resident owner. A successful
//! temporary may retire only after the caller validates its complete permission
//! clock contract and explicitly accepts that exact returned DATA. Failed or
//! unaccepted observations cannot be replaced by a subsequent sample.

use super::{LocalClockObservation, PairedClockBaselineV1, ProtectedOwnershipClockError};
use aos_sandbox_core::RawPairedClockSample;

/// Retains one native observation under an immutable finite attempt ceiling.
#[doc(hidden)]
pub struct PairedClockIncrementalSamplesV3 {
    maximum: usize,
    spent: usize,
    current: Option<LocalClockObservation>,
    accepted: bool,
    last_validated: Option<RawPairedClockSample>,
}

impl PairedClockIncrementalSamplesV3 {
    /// Constructs an inert finite sampler without capturing another baseline.
    pub fn new(maximum: usize) -> Self {
        Self { maximum, spent: 0, current: None, accepted: false, last_validated: None }
    }

    /// Prices both actual observation carriers and their bounded native inputs.
    pub fn receiving_bytes_v3() -> Option<usize> {
        let boot = super::RootOriginalKernelBootIdAttemptV1::dominant_requested_bytes_v1()?;
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(std::mem::size_of::<LocalClockObservation>().checked_mul(2)?)?
            .checked_add(boot.checked_mul(4)?)
    }

    /// Samples through the same native engine and the caller's original baseline.
    ///
    /// # Errors
    /// Retains all failed/partial bookends, refuses an unaccepted observation,
    /// and refuses once the original finite attempt ceiling has been spent.
    pub fn sample(&mut self, baseline: &mut PairedClockBaselineV1)
        -> Result<RawPairedClockSample, ProtectedOwnershipClockError>
    {
        if self.spent == self.maximum || self.current.is_some() && !self.accepted {
            return Err(ProtectedOwnershipClockError);
        }

        // The prior complete observation was accepted only after the caller's
        // full clock contract. No later consumer needs its native prefix.
        drop(self.current.take());
        self.accepted = false;
        self.spent += 1;
        self.current = Some(LocalClockObservation::new());
        self.current.as_mut().ok_or(ProtectedOwnershipClockError)?.observe(baseline)
    }

    /// Accepts one exact fully validated sample before another native entry.
    ///
    /// This method supplies no permission. The purpose owner must first apply
    /// its own genuine durable effect's complete clock comparison contract.
    ///
    /// # Errors
    /// Refuses mismatched, partial or failed samples before disposing any input.
    pub fn accept_positive_sample_v3(&mut self, sample: RawPairedClockSample)
        -> Result<(), ProtectedOwnershipClockError>
    {
        let observation = self.current.as_mut().ok_or(ProtectedOwnershipClockError)?;
        if self.accepted || observation.sample != Some(Ok(sample))
            || !matches!(observation.validation, Some(Ok(_)))
            || observation.before.failure().is_some() || observation.after.failure().is_some()
        {
            return Err(ProtectedOwnershipClockError);
        }

        observation.before.retire_positive_file_once().map_err(|_| ProtectedOwnershipClockError)?;
        observation.after.retire_positive_file_once().map_err(|_| ProtectedOwnershipClockError)?;
        observation.files_retired = true;
        self.last_validated = Some(sample);
        self.accepted = true;
        Ok(())
    }

    /// Borrows the actual first native or validation error without resampling.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let observation = self.current.as_ref()?;
        observation.before.failure().or_else(|| observation.after.failure())
            .or_else(|| observation.validation.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| observation.sample.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::RawClockProvenance;

    #[test]
    fn only_accepted_positive_sample_retires_without_resetting_budget() {
        let mut baseline = PairedClockBaselineV1::capture(
            RawClockProvenance::new_untrusted(crate::ownership_clock::CLOCK_PROVENANCE));
        let mut samples = PairedClockIncrementalSamplesV3::new(2);
        let first = samples.sample(&mut baseline).unwrap();
        assert!(samples.sample(&mut baseline).is_err());
        assert_eq!(samples.spent, 1);
        samples.accept_positive_sample_v3(first).unwrap();
        assert!(samples.current.as_ref().unwrap().files_retired);
        assert_eq!(samples.last_validated, Some(first));

        let second = samples.sample(&mut baseline).unwrap();
        samples.accept_positive_sample_v3(second).unwrap();

        assert_eq!(samples.spent, 2);
        assert!(samples.sample(&mut baseline).is_err());
        assert_eq!(samples.last_validated, Some(second));
        assert_eq!(samples.current.as_ref().unwrap().sample, Some(Ok(second)));
    }

    #[test]
    fn failed_native_bookends_cannot_be_replaced_or_retired() {
        let mut baseline = PairedClockBaselineV1::capture(
            RawClockProvenance::new_untrusted(crate::ownership_clock::CLOCK_PROVENANCE));
        baseline.boot = Some([0; 16]);
        let mut samples = PairedClockIncrementalSamplesV3::new(2);
        assert!(samples.sample(&mut baseline).is_err());
        let first = samples.failure().unwrap().downcast_ref::<ProtectedOwnershipClockError>()
            .unwrap() as *const _;
        assert!(!samples.current.as_ref().unwrap().files_retired);

        assert!(samples.sample(&mut baseline).is_err());

        assert_eq!(samples.spent, 1);
        assert_eq!(samples.failure().unwrap().downcast_ref::<ProtectedOwnershipClockError>()
            .unwrap() as *const _, first);
        assert!(!samples.current.as_ref().unwrap().files_retired);
        assert!(samples.current.as_mut().unwrap().before.observe_once().is_err());
    }
}
