//! Same-original RootR admission of the actual fixed startup journal.
//!
//! Native preparation follows its fixed permit. The same held prefix then
//! supplies both Native and semantic dominant demand before the original
//! argument-free replay. All reached results and independent posts stay owned.

use aos_sandbox_core::ResourceVector;

use crate::normal_root::{NormalRootStartupErrorV1, ProductionNormalRootStartupV1};
use crate::policy_compiler::RootPolicyStartupJournalV1;
use crate::journal::JournalError;

use super::RootReceivingOriginalV1;
use super::service_observation::RootServicePostPurposeV1 as PostPurpose;

use super::super::ResourceReservationErrorV1;

#[derive(Debug, thiserror::Error)]
pub(super) enum RootJournalDemandErrorV1 {
    #[error("Root original receiving provision is insufficient")]
    Provision(#[from] ResourceReservationErrorV1),
    #[error("Root held prefix representation cannot be priced")]
    Native(#[from] JournalError),
}

#[derive(Default)]
pub(super) struct RootJournalReceivingV1 {
    fixed: Option<Result<ResourceVector, RootJournalDemandErrorV1>>,
    before_native: Option<Result<(), NormalRootStartupErrorV1>>,
    native: Option<Result<(), NormalRootStartupErrorV1>>,
    pub(super) variable: Option<Result<ResourceVector, RootJournalDemandErrorV1>>,
    pub(super) held_extent: Option<crate::journal::ProtectedJournalPreopenReplayExtentV1>,
    before_replay: Option<Result<(), NormalRootStartupErrorV1>>,
    replay: Option<Result<(), NormalRootStartupErrorV1>>,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
}

impl RootJournalReceivingV1 {
    pub(super) fn service_post_can_retire_v1(&self) -> bool {
        matches!(self.fixed, Some(Ok(_))) && matches!(self.before_native, Some(Ok(())))
            && matches!(self.native, Some(Ok(()))) && matches!(self.variable, Some(Ok(_)))
            && matches!(self.before_replay, Some(Ok(()))) && matches!(self.replay, Some(Ok(())))
            && matches!(self.after, Some(Ok(())))
    }

    pub(super) fn may_arm_service_post_v1(&self) -> bool {
        matches!(self.fixed, Some(Ok(_))) && self.before_native.is_none() && self.after.is_none()
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        macro_rules! cause {
            ($slot:expr) => { $slot.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)) };
        }
        cause!(self.fixed).or_else(|| cause!(self.before_native))
            .or_else(|| cause!(self.native)).or_else(|| cause!(self.variable))
            .or_else(|| cause!(self.before_replay)).or_else(|| cause!(self.replay))
            .or_else(|| cause!(self.after))
    }

    fn service_failed_first(&self) -> bool {
        matches!(self.before_native, Some(Err(_)))
            || (matches!(self.native, Some(Ok(())))
                && matches!(self.variable, Some(Ok(_)))
                && matches!(self.before_replay, Some(Err(_))))
    }
}

impl RootReceivingOriginalV1 {
    pub(crate) fn receive_startup_journal_once(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        journal: &mut RootPolicyStartupJournalV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.journal_receiving.is_some() || self.failure().is_some()
            || self.activation.process_id_v1() != std::process::id()
        {
            self.activation.latch_root_refusal_v1();
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.journal_receiving = Some(RootJournalReceivingV1::default());
        let result = self.receive_startup_journal_inner(startup, journal);
        if result.is_err() { self.activation.latch_root_refusal_v1(); }
        // The post was paid/armed before the first primary service sample.
        // Even its refusal or a later variable/native error cannot skip this
        // independently owed observation; no healthy reentry/debit is needed.
        if self.service_post_is_armed_v1(PostPurpose::Journal) {
            journal.finish_receiving_names_after_once();
            let after = self.observe_service_post_once_v1(startup, PostPurpose::Journal);
            self.native_refusal_original_v1().park_empty_result_v1(
                &mut self.journal_stage()?.after, after,
            );
        }
        let stage = self.journal_stage()?;
        if result.is_ok() && matches!(stage.after, Some(Ok(())))
            && stage.failure().is_none() && journal.receiving_replay_ready() {
            self.retire_service_post_after_positive_v1(PostPurpose::Journal);
            Ok(())
        } else { Err(NormalRootStartupErrorV1::Service) }
    }

    fn receive_startup_journal_inner(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        journal: &mut RootPolicyStartupJournalV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let fixed = (|| {
            let error = || ResourceReservationErrorV1::EnrollmentUnavailable;
            let selected = self.selected_prefix.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or_else(error)?;
            let demand = selected.checked_add(RootPolicyStartupJournalV1::fixed_receiving_preparation_demand()?)
                .map_err(|_| error())?;
            self.require_receiving_demand_v1(demand).map_err(|_| error())?;
            Ok(demand)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.journal_stage()?.fixed, fixed,
        );
        if !matches!(self.journal_stage()?.fixed, Some(Ok(_))) {
            return Err(NormalRootStartupErrorV1::Service);
        }

        let before = self.arm_service_post_once_v1(startup, PostPurpose::Journal)
            .and_then(|()| self.recheck_service(startup));
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.journal_stage()?.before_native, before,
        );
        if !matches!(self.journal_stage()?.before_native, Some(Ok(()))) {
            return Err(NormalRootStartupErrorV1::Service);
        }
        journal.prepare_receiving_once(&mut self.activation);
        let returned = if journal.receiving_extent().is_some()
            && journal.failure().is_none()
        {
            Ok(())
        } else {
            Err(NormalRootStartupErrorV1::Image)
        };
        self.native_refusal_original_v1().park_empty_result_v1(&mut self.journal_stage()?.native, returned);

        if matches!(self.journal_stage()?.native, Some(Ok(()))) {
            // Preserve exactly this held prefix for the later fixed append peak;
            // it is never replaced with a future capture or configured ceiling.
            self.journal_stage()?.held_extent = journal.receiving_extent().copied();
            let variable = (|| {
                let error = || ResourceReservationErrorV1::EnrollmentUnavailable;
                let extent = journal.receiving_extent().ok_or(JournalError::ProtectedBoundary)?;
                let native = extent.dominant_native_receiving_demand_v1()?;
                let semantic = extent.dominant_semantic_receiving_demand_v1()?;
                let index = journal.receiving_index_demand_v1()?;
                let fixed = self.journal_receiving.as_ref()
                    .and_then(|stage| stage.fixed.as_ref()).and_then(|result| result.as_ref().ok())
                    .copied().ok_or_else(error)?;
                let demand = fixed.checked_add(native)
                    .and_then(|demand| demand.checked_add(semantic))
                    .and_then(|demand| demand.checked_add(index)).map_err(|_| error())?;
                self.require_receiving_demand_v1(demand).map_err(|_| error())?;
                Ok(demand)
            })();
            self.native_refusal_original_v1().park_empty_result_v1(
                &mut self.journal_stage()?.variable, variable,
            );
            if matches!(self.journal_stage()?.variable, Some(Ok(_))) {
                let before = self.recheck_service(startup);
                self.native_refusal_original_v1().park_empty_result_v1(
                    &mut self.journal_stage()?.before_replay, before,
                );
                if matches!(self.journal_stage()?.before_replay, Some(Ok(()))) {
                    journal.replay_receiving_once();
                    let returned = if journal.receiving_replay_ready() {
                        Ok(())
                    } else {
                        Err(NormalRootStartupErrorV1::Image)
                    };
                    self.native_refusal_original_v1().park_empty_result_v1(&mut self.journal_stage()?.replay, returned);
                }
            }
        }

        if matches!(self.journal_stage()?.replay, Some(Ok(()))) && journal.receiving_replay_ready() {
            Ok(())
        } else { Err(NormalRootStartupErrorV1::Service) }
    }

    fn journal_stage(&mut self) -> Result<&mut RootJournalReceivingV1, NormalRootStartupErrorV1> {
        self.journal_receiving.as_mut().ok_or(NormalRootStartupErrorV1::Service)
    }

    // All callers join cumulative stages, permanent flight capacity and native
    // debt in require_complete_liability. Return the actual original envelope;
    // subtracting debt here would charge that same liability twice.
    pub(super) fn receiving_envelope(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.original.as_ref().and_then(|result| result.as_ref().ok())
            .and_then(|original| original.policy.bootstrap_provisions().root_receiving)
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)
    }

    pub(super) fn journal_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let stage = self.journal_receiving.as_ref()?;
        if stage.service_failed_first() {
            self.service_post_arm_failure_v1(PostPurpose::Journal)
                .or_else(|| self.activation.currentness_failure_v1())
                .or_else(|| self.service_currentness.as_ref().and_then(|attempt| attempt.failure()))
                .or_else(|| stage.failure())
        } else if stage.fixed.as_ref().is_some_and(Result::is_ok)
            && matches!(stage.before_native, Some(Ok(())))
            && matches!(stage.native, Some(Ok(())))
            && matches!(stage.variable, Some(Ok(_)))
            && matches!(stage.before_replay, Some(Ok(())))
            && matches!(stage.replay, Some(Ok(()))) && matches!(stage.after, Some(Err(_))) {
            self.service_post_failure_v1(PostPurpose::Journal).or_else(|| stage.failure())
        } else { stage.failure() }
    }
}
