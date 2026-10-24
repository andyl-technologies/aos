//! Completes one accepted Start from its actual disposed Host and Source owners.
//!
//! The Host disposition is qualified once at its original C ordinal. All later
//! Source transitions and the public terminal CAS stay on the same original
//! Start, financial receiver and immutable publication contract. Errors retain
//! every entered prefix and fence the actual Controller; no retry heals it.

mod controller;
mod material;
pub(crate) use controller::StartTerminalAppendContextV2;
pub(super) use material::StartTerminalMaterialV2;

use super::super::source::SourceAdmissionErrorV1;
use super::*;
use source_origin::{StartSourceOriginOriginalV1, StartSourcePurposeV2};

const CLOSED: ResourceReservationErrorV1 = ResourceReservationErrorV1::Conflict;

const PURPOSES: [StartSourcePurposeV2; 6] = [
    StartSourcePurposeV2::BindPlan,
    StartSourcePurposeV2::InitialProgress,
    StartSourcePurposeV2::SemanticReadiness,
    StartSourcePurposeV2::SemanticCommit,
    StartSourcePurposeV2::Completing,
    StartSourcePurposeV2::Terminal,
];

pub(super) struct StartTerminalOriginalV2 {
    material: Option<Result<StartTerminalMaterialV2, ResourceReservationErrorV1>>,
    source: [StartSourceOriginOriginalV1; 6],
    controller: controller::StartControllerTerminalOriginalV2,
    fence: Option<Result<(), crate::JournalError>>,
}

impl StartTerminalOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            material: None,
            source: PURPOSES.map(StartSourceOriginOriginalV1::for_purpose_v2),
            controller: controller::StartControllerTerminalOriginalV2::new(),
            fence: None,
        }
    }

    pub(super) fn failure<'actual>(
        &'actual self,
        native: Option<&'actual (dyn Error + 'static)>,
    ) -> Option<&'actual (dyn Error + 'static)> {
        self.material
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| self.source.iter().find_map(|source| source.failure(native)))
            .or_else(|| self.controller.failure(native))
            .or_else(|| {
                self.fence
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|cause| cause as _)
            })
    }

    pub(super) fn native_failure_is_selected_v2(&self) -> bool {
        self.source
            .iter()
            .find(|source| source.has_selected_failure_v1())
            .map_or_else(
                || self.controller.native_failure_is_selected_v2(),
                StartSourceOriginOriginalV1::native_failure_is_selected_v1,
            )
    }

    pub(super) fn fmt_selected_decoder_failure_v2(
        &self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> Option<std::fmt::Result> {
        self.source
            .iter()
            .find_map(|source| source.fmt_selected_decoder_failure_v1(formatter))
    }
}

impl AcceptedStartEntryOriginalV1 {
    /// Advances Source or the final public CAS after actual Host disposition.
    ///
    /// The first call requires the genuine Host completed/disposed proof at its
    /// exact original C ordinal. Subsequent calls use only the privately retained
    /// association while every native turn enforces the same original Start
    /// bounds. One call enters at most one Source transition or Controller CAS.
    ///
    /// # Errors
    /// Retains Host association, Source semantic/native/append, Controller CAS,
    /// currentness, clock and independent-post failures on the same owner.
    #[doc(hidden)]
    pub fn progress_completed_start_terminal_once_v2(
        &mut self,
        completed: &crate::normal_root::RootStartResourceCompletedOriginalV2,
        controller: &mut Journal,
        source: &mut crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.failure().is_some() {
            return Err(CLOSED);
        }
        if self.terminal.material.is_none() {
            self.terminal.material = Some(StartTerminalMaterialV2::from_completed_host_v2(
                self,
                completed,
                controller,
                source.journal_ref_v1(),
            ));
        }
        let returned = (|| {
            let material = self
                .terminal
                .material
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(CLOSED)?;
            let plan = Arc::clone(self.body.plan_v1()?);
            let origin = self.body.origin_v1()?;
            material.require_original_v2(&plan, origin)?;
            let native = self.native_state.as_mut().ok_or(CLOSED)?;
            for turn in &mut self.terminal.source {
                if turn.completed_v1() {
                    continue;
                }
                if turn.entered_v2() {
                    return Err(CLOSED);
                }
                return turn.run_once_v2(native, &plan, origin, controller, source, Some(material));
            }
            let record = self
                .terminal
                .source
                .last()
                .ok_or(CLOSED)?
                .completed_record_v2()?;
            self.terminal
                .controller
                .run_once_v2(native, &plan, origin, material, record, controller)
        })();
        if returned.is_err() && self.terminal.fence.is_none() {
            self.terminal.fence = Some(
                match self
                    .journal_identity
                    .as_ref()
                    .and_then(|value| value.as_ref().ok())
                {
                    Some(identity) => controller.fence_start_admission_v1(identity),
                    None => Err(crate::JournalError::ProtectedBoundary),
                },
            );
        }
        returned
    }
}
