//! Gates the actual Start Source append after schema work, on the same engine.
//!
//! The temporary interior destination is moved whole into its retained slot
//! immediately after the commit returns. No borrowed native cause is cloned,
//! dropped or reconstructed, and the completed slot cannot be rearmed.

use super::*;

#[derive(Default)]
pub(super) struct StartSourceAppendClockV2 {
    clock: PairOriginal,
    sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    time: Option<Result<(), ResourceReservationErrorV1>>,
}

impl StartSourceAppendClockV2 {
    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if self.sample.as_ref().is_some_and(Result::is_err) {
            return self
                .clock
                .failure()
                .or_else(|| self.sample.as_ref()?.as_ref().err().map(|cause| cause as _));
        }
        self.time.as_ref()?.as_ref().err().map(|cause| cause as _)
    }

    pub(super) fn require_after_v2(
        &self,
        after: RawPairedClockSample,
    ) -> Result<(), ResourceReservationErrorV1> {
        match self.sample.as_ref().and_then(|value| value.as_ref().ok()) {
            Some(sample) => sample.validate_later_sample(after).map_err(|_| CLOSED),
            None => Ok(()),
        }
    }
}

impl StartSourceAdmissionAuthorizationV1<'_> {
    pub(crate) fn final_native_cut_v2(&self) -> Result<(), crate::JournalError> {
        self.require_current_v1()?;
        let mut actual = self
            .state
            .append_clock
            .try_borrow_mut()
            .map_err(|_| crate::JournalError::ProtectedBoundary)?;
        if actual.sample.is_some() {
            return Err(crate::JournalError::ProtectedBoundary);
        }
        actual.sample = Some(
            actual
                .clock
                .observe_once(Some(self.origin.first_native_clock_v1())),
        );
        actual.time = Some((|| {
            let sample = *actual
                .sample
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(CLOSED)?;
            StartSourceOriginOriginalV1::require_sample_v1(self.origin, sample)?;
            self.state
                .before
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(CLOSED)?
                .validate_later_sample(sample)
                .map_err(|_| CLOSED)
        })());
        if matches!(actual.time, Some(Ok(()))) {
            Ok(())
        } else {
            Err(crate::JournalError::ProtectedBoundary)
        }
    }
}
