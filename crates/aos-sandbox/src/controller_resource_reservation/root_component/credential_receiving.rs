//! Prepays the fixed credential/schema and bounded startup-append peak.
//!
//! The same original RootR is retained through the actual daemon read and
//! admission sequence. The future append bound is a fixed recipe forecast;
//! it is not future captured metadata or a new journal authority.

use aos_sandbox_core::ResourceVector;
use crate::journal::JournalError;
use crate::normal_root::{NormalRootStartupErrorV1, ProductionNormalRootStartupV1};
use crate::policy_compiler::RootPolicyStartupJournalV1;

use super::{RootReceivingOriginalV1, root_journal::RootJournalDemandErrorV1};
use super::super::ResourceReservationErrorV1;
use super::service_observation::RootServicePostPurposeV1 as PostPurpose;


#[derive(Default)]
pub(super) struct RootCredentialReceivingV1 {
    permit: Option<Result<ResourceVector, RootJournalDemandErrorV1>>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    names: Option<Result<(), JournalError>>,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
}

impl RootCredentialReceivingV1 {
    pub(super) fn service_post_can_retire_v1(&self) -> bool {
        matches!(self.permit, Some(Ok(_))) && matches!(self.before, Some(Ok(())))
            && matches!(self.names, Some(Ok(()))) && matches!(self.after, Some(Ok(())))
    }

    pub(super) fn may_arm_service_post_v1(&self) -> bool {
        matches!(self.permit, Some(Ok(_))) && self.before.is_none()
            && self.names.is_none() && self.after.is_none()
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        macro_rules! cause {
            ($slot:expr) => { $slot.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)) };
        }
        cause!(self.permit).or_else(|| cause!(self.before))
            .or_else(|| cause!(self.names)).or_else(|| cause!(self.after))
    }
}

impl RootReceivingOriginalV1 {
    pub(crate) fn borrow_startup_credential_financial_v1<'original>(
        &'original mut self,
        mutation: &'original aos_sandbox_broker::receiving::RootUpperMutationGuardV1<'_>,
    ) -> Result<aos_sandbox_broker::receiving::RootJournalFinancialBorrowV1<'original>, NormalRootStartupErrorV1>
    {
        if self.require_startup_credentials_receiving().is_err() {
            self.activation.latch_root_refusal_v1();
            return Err(NormalRootStartupErrorV1::Service);
        }
        // The return lifetime borrows this WHOLE upper original. None of its
        // entered credential fields can change during the fixed admission.
        self.activation.borrow_journal_financial_v1(mutation)
            .map_err(|_| NormalRootStartupErrorV1::Service)
    }

    pub(super) fn completed_startup_credential_demand(&self) -> Option<ResourceVector> {
        let stage = self.credential_receiving.as_ref()?;
        if stage.failure().is_some() || !matches!(stage.names, Some(Ok(())))
            || !matches!(stage.after, Some(Ok(())))
        {
            return None;
        }
        stage.permit.as_ref()?.as_ref().ok().copied()
    }

    pub(super) fn credential_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let stage = self.credential_receiving.as_ref()?;
        if matches!(stage.permit, Some(Ok(_))) && matches!(stage.before, Some(Err(_))) {
            self.service_post_arm_failure_v1(PostPurpose::Credentials)
                .or_else(|| self.activation.currentness_failure_v1())
                .or_else(|| self.service_currentness.as_ref().and_then(|attempt| attempt.failure()))
                .or_else(|| stage.failure())
        } else if matches!(stage.permit, Some(Ok(_))) && matches!(stage.before, Some(Ok(())))
            && matches!(stage.names, Some(Ok(()))) && matches!(stage.after, Some(Err(_))) {
            self.service_post_failure_v1(PostPurpose::Credentials).or_else(|| stage.failure())
        } else { stage.failure() }
    }

    pub(crate) fn prepay_startup_credentials_once(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        journal: &RootPolicyStartupJournalV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.credential_receiving.is_some() || self.failure().is_some()
            || !journal.receiving_replay_ready()
        {
            self.activation.latch_root_refusal_v1();
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.credential_receiving = Some(RootCredentialReceivingV1::default());
        let permit = (|| {
            let error = || ResourceReservationErrorV1::EnrollmentUnavailable;
            let journal_stage = self.journal_receiving.as_ref().ok_or_else(error)?;
            let base = journal_stage.variable.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or_else(error)?;
            let held = journal_stage.held_extent.as_ref().ok_or_else(error)?;
            let append_peak = RootPolicyStartupJournalV1::fixed_credential_append_peak_v1(held)?;
            let credentials = crate::normal_root::fixed_root_credential_demand_v1()?;
            let demand = base.checked_add(append_peak)
                .and_then(|demand| demand.checked_add(credentials)).map_err(|_| error())?;
            self.require_receiving_demand_v1(demand).map_err(|_| error())?;
            Ok(demand)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.credential_receiving.as_mut().ok_or(NormalRootStartupErrorV1::Service)?.permit, permit,
        );
        if self.credential_receiving.as_ref().is_none_or(|stage| !matches!(stage.permit, Some(Ok(_)))) {
            self.activation.latch_root_refusal_v1();
            return Err(NormalRootStartupErrorV1::Service);
        }
        let before = self.arm_service_post_once_v1(startup, PostPurpose::Credentials)
            .and_then(|()| self.recheck_service(startup));
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.credential_receiving.as_mut().ok_or(NormalRootStartupErrorV1::Service)?.before, before,
        );
        if matches!(self.credential_receiving.as_ref().and_then(|stage| stage.before.as_ref()), Some(Err(_)))
            && self.service_post_is_armed_v1(PostPurpose::Credentials) {
            let after = self.observe_service_post_once_v1(startup, PostPurpose::Credentials);
            self.native_refusal_original_v1().park_empty_result_v1(
                &mut self.credential_receiving.as_mut().ok_or(NormalRootStartupErrorV1::Service)?.after, after,
            );
        }
        self.require_startup_credentials_receiving()
    }

    pub(crate) fn require_startup_credentials_receiving(&self) -> Result<(), NormalRootStartupErrorV1> {
        let stage = self.credential_receiving.as_ref().ok_or(NormalRootStartupErrorV1::Service)?;
        if self.failure().is_some() || !matches!(stage.permit, Some(Ok(_)))
            || !matches!(stage.before, Some(Ok(()))) || stage.names.is_some() || stage.after.is_some()
        {
            return Err(NormalRootStartupErrorV1::Service);
        }
        Ok(())
    }

    pub(crate) fn finish_startup_credentials_once(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        names: Result<(), JournalError>,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let refusal = self.native_refusal_original_v1();
        let stage = self.credential_receiving.as_mut().ok_or(NormalRootStartupErrorV1::Service)?;
        if stage.names.is_some() || stage.after.is_some() {
            self.activation.latch_root_refusal_v1();
            return Err(NormalRootStartupErrorV1::Service);
        }
        refusal.park_empty_result_v1(&mut stage.names, names);
        // The independent selected post runs even after failed fixed names.
        let after = self.observe_service_post_once_v1(startup, PostPurpose::Credentials);
        let stage = self.credential_receiving.as_mut().ok_or(NormalRootStartupErrorV1::Service)?;
        refusal.park_empty_result_v1(&mut stage.after, after);
        if matches!(stage.names, Some(Ok(()))) && matches!(stage.after, Some(Ok(())))
            && stage.failure().is_none()
        {
            self.retire_service_post_after_positive_v1(PostPurpose::Credentials);
            Ok(())
        } else {
            self.activation.latch_root_refusal_v1();
            Err(NormalRootStartupErrorV1::Service)
        }
    }
}
