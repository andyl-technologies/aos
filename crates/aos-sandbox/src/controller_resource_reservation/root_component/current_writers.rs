//! Admits the two same-file current-cut replays under the original RootR.
//!
//! This finite connected stage uses the completed startup/credential baseline,
//! retains both native owners and cumulative actual-prefix permits, and checks
//! the same original selected service before work and after every reached role.

use aos_sandbox_core::ResourceVector;

use crate::journal::JournalError;
use crate::normal_root::{NormalRootStartupErrorV1, ProductionNormalRootStartupV1};
use crate::policy_compiler::root_current_writers::{
    RootCreateStorageCurrentWritersV1, RootCurrentWriterRoleV1,
};

use super::{RootReceivingOriginalV1, root_journal::RootJournalDemandErrorV1};
use super::super::ResourceReservationErrorV1;
use super::service_observation::RootServicePostPurposeV1 as PostPurpose;


#[derive(Default)]
pub(super) struct RootCurrentWritersReceivingV1 {
    fixed: Option<Result<ResourceVector, RootJournalDemandErrorV1>>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    variable: [Option<Result<ResourceVector, RootJournalDemandErrorV1>>; 2],
    replay: [Option<Result<(), NormalRootStartupErrorV1>>; 2],
    after: [Option<Result<(), NormalRootStartupErrorV1>>; 2],
    completion: Option<Result<(), NormalRootStartupErrorV1>>,
    held_extents: [Option<crate::journal::ProtectedJournalPreopenReplayExtentV1>; 2],
}

impl RootCurrentWritersReceivingV1 {
    pub(super) fn service_post_can_retire_v1(&self, index: usize) -> bool {
        matches!(self.fixed, Some(Ok(_))) && matches!(self.before, Some(Ok(())))
            && matches!(self.variable[index], Some(Ok(_))) && matches!(self.replay[index], Some(Ok(())))
            && matches!(self.after[index], Some(Ok(())))
    }

    pub(super) fn may_arm_service_post_v1(&self, index: usize) -> bool {
        matches!(self.fixed, Some(Ok(_))) && self.completion.is_none()
            && self.variable.get(index).is_some_and(Option::is_none)
            && self.after.get(index).is_some_and(Option::is_none)
            && (index == 0 || (index == 1 && matches!(self.after[0], Some(Ok(())))))
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(cause)) = &self.fixed { return Some(cause); }
        if let Some(Err(cause)) = &self.before { return Some(cause); }
        for index in 0..2 {
            if let Some(Err(cause)) = &self.variable[index] { return Some(cause); }
            if let Some(Err(cause)) = &self.replay[index] { return Some(cause); }
            if let Some(Err(cause)) = &self.after[index] { return Some(cause); }
        }
        self.completion.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
    }
    pub(super) fn completed_prefix(&self) -> Option<ResourceVector> {
        if self.failure().is_some() || !matches!(self.completion, Some(Ok(()))) { return None; }
        self.variable[1].as_ref()?.as_ref().ok().copied()
    }

    pub(super) fn authority_extent(&self) -> Option<&crate::journal::ProtectedJournalPreopenReplayExtentV1> {
        self.completed_prefix()?;
        self.held_extents[0].as_ref()
    }


}

impl RootReceivingOriginalV1 {
    pub(crate) fn receive_create_storage_current_writers_once(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        writers: &mut RootCreateStorageCurrentWritersV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.current_writers_receiving.is_some() || self.failure().is_some() {
            self.activation.latch_root_refusal_v1();
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.current_writers_receiving = Some(RootCurrentWritersReceivingV1::default());
        let result = self.receive_current_writers_inner(startup, writers);
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_writers_stage()?.completion, result,
        );
        if matches!(self.current_writers_stage()?.completion, Some(Ok(()))) {
            Ok(())
        } else {
            self.activation.latch_root_refusal_v1();
            Err(NormalRootStartupErrorV1::Service)
        }
    }

    fn receive_current_writers_inner(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        writers: &mut RootCreateStorageCurrentWritersV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let fixed = (|| {
            let error = || ResourceReservationErrorV1::EnrollmentUnavailable;
            let base = self.completed_controller_peer_prefix().ok_or_else(error)?;
            let demand = base.checked_add(RootCreateStorageCurrentWritersV1::fixed_preparation_demand()?)
                .map_err(|_| error())?;
            self.require_receiving_demand_v1(demand).map_err(|_| error())?;
            Ok(demand)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_writers_stage()?.fixed, fixed,
        );
        let Some(Ok(mut cumulative)) = self.current_writers_stage()?.fixed else {
            return Err(NormalRootStartupErrorV1::Service);
        };
        let before = self.arm_service_post_once_v1(startup, PostPurpose::AuthorityWriter)
            .and_then(|()| self.recheck_service(startup));
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_writers_stage()?.before, before,
        );
        if !matches!(self.current_writers_stage()?.before, Some(Ok(()))) {
            if self.service_post_is_armed_v1(PostPurpose::AuthorityWriter) {
                let after = self.observe_service_post_once_v1(startup, PostPurpose::AuthorityWriter);
                self.native_refusal_original_v1().park_empty_result_v1(
                    &mut self.current_writers_stage()?.after[0], after,
                );
            }
            return Err(NormalRootStartupErrorV1::Service);
        }

        for role in RootCurrentWriterRoleV1::ALL {
            let index = role.index();
            let purpose = if index == 0 { PostPurpose::AuthorityWriter } else { PostPurpose::PolicyWriter };
            if index == 1 { self.arm_service_post_once_v1(startup, purpose)?; }
            writers.prepare_once(role, &mut self.activation);
            let variable = (|| {
                let error = || ResourceReservationErrorV1::EnrollmentUnavailable;
                let extent = writers.captured_extent(role).ok_or(JournalError::ProtectedBoundary)?;
                // Missing private stage is a provision refusal here, not a
                // blanket conversion of unrelated startup/native errors. The
                // outer completion and same-role independent posts stay intact.
                self.current_writers_stage().map_err(|_| error())?
                    .held_extents[index] = Some(*extent);
                let native = extent.dominant_native_receiving_demand_v1()?;
                let semantic = extent.dominant_semantic_receiving_demand_v1()?;
                let index_demand = writers.index_demand_v1(role)?;
                let demand = cumulative.checked_add(native)
                    .and_then(|demand| demand.checked_add(semantic))
                    .and_then(|demand| demand.checked_add(index_demand)).map_err(|_| error())?;
                self.require_receiving_demand_v1(demand).map_err(|_| error())?;
                Ok(demand)
            })();
            self.native_refusal_original_v1().park_empty_result_v1(
                &mut self.current_writers_stage()?.variable[index], variable,
            );
            if let Some(Ok(demand)) = self.current_writers_stage()?.variable[index] {
                cumulative = demand;
                writers.replay_once(role);
                let returned = if writers.failure().is_none() {
                    Ok(())
                } else {
                    Err(NormalRootStartupErrorV1::Image)
                };
                self.native_refusal_original_v1().park_empty_result_v1(
                    &mut self.current_writers_stage()?.replay[index], returned,
                );
            }
            // These posts execute on variable refusal and parser/native error.
            writers.finish_names_once(role);
            let after = self.observe_service_post_once_v1(startup, purpose);
            self.native_refusal_original_v1().park_empty_result_v1(
                &mut self.current_writers_stage()?.after[index], after,
            );
            if self.current_writers_stage()?.failure().is_some() || !writers.replay_ready(role) {
                return Err(NormalRootStartupErrorV1::Service);
            }
            writers.take_opened_once(role);
            if writers.failure().is_some() || !writers.opened_ready(role) {
                return Err(NormalRootStartupErrorV1::Image);
            }
            self.retire_service_post_after_positive_v1(purpose);
        }
        Ok(())
    }

    pub(super) fn current_writers_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let stage = self.current_writers_receiving.as_ref()?;
        if matches!(stage.fixed, Some(Ok(_))) && matches!(stage.before, Some(Err(_))) {
            return self.service_post_arm_failure_v1(PostPurpose::AuthorityWriter)
                .or_else(|| self.activation.currentness_failure_v1()).or_else(|| stage.failure());
        }
        for index in 0..2 {
            if matches!(stage.variable[index], Some(Err(_))) || matches!(stage.replay[index], Some(Err(_))) {
                return stage.failure();
            }
            let purpose = if index == 0 { PostPurpose::AuthorityWriter } else { PostPurpose::PolicyWriter };
            if let Some(cause) = self.service_post_arm_failure_v1(purpose) { return Some(cause); }
            if matches!(stage.after[index], Some(Err(_))) {
                let purpose = if index == 0 { PostPurpose::AuthorityWriter } else { PostPurpose::PolicyWriter };
                return self.service_post_failure_v1(purpose).or_else(|| stage.failure());
            }
        }
        stage.failure()
    }

    fn current_writers_stage(&mut self) -> Result<&mut RootCurrentWritersReceivingV1, NormalRootStartupErrorV1> {
        self.current_writers_receiving.as_mut().ok_or(NormalRootStartupErrorV1::Service)
    }
}
