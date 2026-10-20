//! Lends the real Stop Root purpose to the sole native opening engine.

use super::*;
use crate::policy_compiler::root_resource_opening::{
    OpeningQueryV2, OpeningReceivingV2, RootResourceOpeningOriginalV2,
};

#[derive(Default)]
pub(crate) struct RootStopCleanupOpeningOriginalV1 {
    original: RootResourceOpeningOriginalV2,
}

impl RootStopCleanupOpeningOriginalV1 {
    pub(super) fn admit_query(
        &mut self,
        stage: &mut RootStopCleanupStageReceivingV1<'_, '_>,
    ) -> Result<(), JournalError> {
        self.original
            .admit_query_once_v1(OpeningReceivingV2::StopCleanup(stage), size_of::<Native>())
    }

    pub(super) fn observe_query(&mut self, bytes: &[u8]) -> Result<(), JournalError> {
        self.original.observe_query_once_v1(bytes)
    }

    pub(super) fn admit_subject(
        &mut self,
        stage: &mut RootStopCleanupStageReceivingV1<'_, '_>,
    ) -> Result<(), JournalError> {
        self.original
            .admit_subject_once_v1(OpeningReceivingV2::StopCleanup(stage), size_of::<Native>())
    }

    pub(super) fn query(&self) -> Result<StopCleanupQueryDataV1, JournalError> {
        match self.original.query_v1()? {
            OpeningQueryV2::StopCleanup(query) => Ok(query),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    pub(super) fn tighten(
        &mut self,
        original: &RootStopCleanupNativeOriginalV1,
    ) -> Result<(), JournalError> {
        self.original.tighten_stop_cleanup_inputs_once_v1(original)
    }

    pub(crate) fn current_cutoff_v1(&self) -> Result<u64, JournalError> {
        self.original.current_cutoff_v1()
    }
    pub(crate) fn require_paid_chunk_peak_v1(&self) -> Result<(), JournalError> {
        self.original.require_paid_chunk_peak_v1()
    }
    pub(crate) fn require_current_clock_v1(
        &self,
        sample: RawPairedClockSample,
    ) -> Result<(), JournalError> {
        self.original.require_current_clock_v1(sample)
    }
    pub(super) fn horizon(&self) -> Result<RootContinuationHorizonDataV1, JournalError> {
        self.original.horizon_v1()
    }
    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.original.failure()
    }
}
