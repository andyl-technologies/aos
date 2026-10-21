//! Lends normal Apply's actual stage to the sole complete final-read engine.

use crate::journal::JournalError;
use crate::journal::historical_observation::HistoricalObservationV1;
use crate::normal_root::RootApplyStageReceivingV1;
use crate::policy_compiler::provisioning_current::{RootContinuationClockGateV1,
    finality_readonly::{RootCreateFinalityReadonlyOriginalV1, RootCreateFinalityReadStageV1}};
use aos_sandbox_protocol::domain_ledger::readonly::FixedJournalReadbackDataV1 as RootFixedNativeReadbackV1;
pub(super) use crate::policy_compiler::provisioning_current::finality_readonly::NativeCutDataV1;

// One actual complete reader owner, with the same old field layout and
// independent native/model posts, stays behind this closed Apply adapter.
pub(super) struct RootApplyFinalReadonlyOriginalV1 {
    original: RootCreateFinalityReadonlyOriginalV1,
}

impl RootApplyFinalReadonlyOriginalV1 {
    /// Prices this actual Apply facade, separate from the shared owner getter.
    pub(super) fn observation_control_bytes_v2() -> Option<usize> {
        std::mem::size_of::<&Self>().checked_mul(3)?
            .checked_add(std::mem::size_of::<Result<HistoricalObservationV1<'_>, JournalError>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Result<
                (HistoricalObservationV1<'_>, HistoricalObservationV1<'_>), JournalError,
            >>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Option<usize>>().checked_mul(3)?)
    }

    pub(super) fn new() -> Self { Self { original: RootCreateFinalityReadonlyOriginalV1::new() } }

    pub(super) fn observe_once_v1(&mut self, stage: &mut RootApplyStageReceivingV1<'_, '_>,
        clock: &mut RootContinuationClockGateV1,
    ) -> Result<(), JournalError> {
        self.original.observe_once_v1(&mut RootCreateFinalityReadStageV1::Apply(stage), clock)
    }

    pub(super) fn controller_model_v1(&self) -> Result<HistoricalObservationV1<'_>, JournalError> {
        self.original.controller_model_v1()
    }

    pub(super) fn models_v1(&self) -> Result<(HistoricalObservationV1<'_>, HistoricalObservationV1<'_>), JournalError> {
        self.original.models_v1()
    }

    pub(super) fn source_model_v1(&self) -> Result<HistoricalObservationV1<'_>, JournalError> {
        self.original.source_model_v1()
    }

    pub(super) fn session_v1(&self) -> Result<RootFixedNativeReadbackV1<'_>, JournalError> {
        self.original.session_v1()
    }

    pub(super) fn cuts_v1(&self) -> Result<(NativeCutDataV1, NativeCutDataV1), JournalError> {
        self.original.cuts_v1()
    }

    pub(super) fn finish_posts_once_v1(&mut self) { self.original.finish_posts_once_v1(); }

    pub(super) fn require_complete_v1(&self) -> Result<(), JournalError> {
        self.original.require_complete_v1()
    }

    pub(super) fn selected_funding_failed_v1(&self) -> bool {
        self.original.selected_funding_failed_v1()
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.failure()
    }
}
