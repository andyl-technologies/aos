//! Lends normal Apply's actual stage to the sole complete final-read engine.

use crate::journal::{Journal, JournalError};
use crate::normal_root::RootApplyStageReceivingV1;
use crate::policy_compiler::provisioning_current::{RootContinuationClockGateV1,
    finality_readonly::{RootCreateFinalityReadonlyOriginalV1, RootCreateFinalityReadStageV1}};
use crate::policy_compiler::create_storage_current::controller_readonly::native_read::RootFixedNativeReadbackV1;
pub(super) use crate::policy_compiler::provisioning_current::finality_readonly::NativeCutDataV1;

// One actual complete reader owner, with the same old field layout and
// independent native/model posts, stays behind this closed Apply adapter.
pub(super) struct RootApplyFinalReadonlyOriginalV1 {
    original: RootCreateFinalityReadonlyOriginalV1,
}

impl RootApplyFinalReadonlyOriginalV1 {
    pub(super) fn new() -> Self { Self { original: RootCreateFinalityReadonlyOriginalV1::new() } }

    pub(super) fn observe_once_v1(&mut self, stage: &mut RootApplyStageReceivingV1<'_, '_>,
        clock: &mut RootContinuationClockGateV1,
    ) -> Result<(), JournalError> {
        self.original.observe_once_v1(&mut RootCreateFinalityReadStageV1::Apply(stage), clock)
    }

    pub(super) fn controller_v1(&mut self) -> Result<&mut Journal, JournalError> {
        self.original.controller_v1()
    }

    pub(super) fn journals_v1(&mut self) -> Result<(&mut Journal, &mut Journal), JournalError> {
        self.original.journals_v1()
    }

    pub(super) fn source_v1(&mut self) -> Result<&mut Journal, JournalError> {
        self.original.source_v1()
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
