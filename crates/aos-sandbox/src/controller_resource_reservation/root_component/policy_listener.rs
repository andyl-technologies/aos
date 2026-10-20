//! Admits only the closed Root listener and fixed accepted-prelude reservoir.
//!
//! Variable phase bodies and current-cut replay have separate actual suppliers;
//! this prefix never promotes a handler Result to policy or signing authority.

use aos_sandbox_core::ResourceVector;

use crate::normal_root::{NormalRootStartupErrorV1, ProductionNormalRootStartupV1,
    RootPolicyListenerReceivingV1};

use super::{RootReceivingOriginalV1, root_journal::RootJournalDemandErrorV1};
use super::super::ResourceReservationErrorV1;

#[derive(Default)]
pub(super) struct RootPolicyListenerProvisionV1 {
    permit: Option<Result<ResourceVector, RootJournalDemandErrorV1>>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
}

impl RootPolicyListenerProvisionV1 {
    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(cause)) = &self.permit { return Some(cause); }
        if let Some(Err(cause)) = &self.before { return Some(cause); }
        None
    }
}

impl RootReceivingOriginalV1 {
    // Only the actual parked pre-body escrow calls this finite supplier. Its
    // cumulative native debt remains on the same permanent Root after D ends.
    pub(crate) fn prepay_policy_completion_tail_once_v2(
        &mut self,
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.require_active_policy_flight_v1()?;
        let demand = RootPolicyListenerReceivingV1::permanent_completion_tail_demand_v2()
            .ok_or(NormalRootStartupErrorV1::Service)?;
        self.debit_native_journal_representation_v1(demand)
            .map_err(|_| {
                self.native_receiving_refusal
                    .as_ref()
                    .map(|cause| {
                        NormalRootStartupErrorV1::ServiceReceiving(std::sync::Arc::clone(cause))
                    })
                    .unwrap_or(NormalRootStartupErrorV1::Service)
            })
    }

    pub(crate) fn arm_policy_completion_tail_post_v2(
        &self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<
        aos_sandbox_broker::receiving::RootPrearmedHistoryServicePostV1,
        aos_sandbox_broker::receiving::RootObservationErrorV1,
    > {
        self.activation
            .arm_history_service_post_v1(startup.native_startup_original_v1())
    }

    pub(crate) fn observe_policy_completion_tail_post_v2(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        post: &mut aos_sandbox_broker::receiving::RootPrearmedHistoryServicePostV1,
    ) -> Result<(), aos_sandbox_broker::receiving::RootObservationErrorV1> {
        self.activation
            .observe_history_service_post_once_v1(startup.native_startup_original_v1(), post)
    }

    // Only the same accepted listener calls this after its paid native-before
    // observation and before any body purpose. The cumulative listener prefix
    // remains charged when the distinct transient policy flight is disposed.
    pub(crate) fn require_policy_connection_escrow_v1(
        &self,
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.require_active_policy_flight_v1()?;
        let prefix = self
            .policy_listener_prefix()
            .ok_or(NormalRootStartupErrorV1::Service)?;
        let fixed = RootPolicyListenerReceivingV1::fixed_demand();
        prefix
            .checked_sub(fixed)
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        Ok(())
    }

    pub(crate) fn prepay_policy_listener_once(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.policy_listener_provision.is_some() || self.failure().is_some() {
            self.activation.latch_root_refusal_v1();
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.policy_listener_provision = Some(RootPolicyListenerProvisionV1::default());
        let permit = (|| {
            let error = || ResourceReservationErrorV1::EnrollmentUnavailable;
            let base = self.completed_startup_credential_demand().ok_or_else(error)?;
            let demand = base.checked_add(RootPolicyListenerReceivingV1::fixed_demand())
                .map_err(|_| error())?;
            self.require_receiving_demand_v1(demand).map_err(|_| error())?;
            Ok(demand)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.policy_listener_provision.as_mut().ok_or(NormalRootStartupErrorV1::Service)?.permit, permit,
        );
        if !self.policy_listener_provision.as_ref().is_some_and(|stage| matches!(stage.permit, Some(Ok(_)))) {
            self.activation.latch_root_refusal_v1();
            return Err(NormalRootStartupErrorV1::Service);
        }
        let before = self.recheck_service(startup);
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.policy_listener_provision.as_mut().ok_or(NormalRootStartupErrorV1::Service)?.before, before,
        );
        if self.policy_listener_prefix().is_some() { Ok(()) } else {
            self.activation.latch_root_refusal_v1();
            Err(NormalRootStartupErrorV1::Service)
        }
    }

    pub(super) fn policy_listener_prefix(&self) -> Option<ResourceVector> {
        let stage = self.policy_listener_provision.as_ref()?;
        if !matches!(stage.before, Some(Ok(()))) { return None; }
        stage.permit.as_ref()?.as_ref().ok().copied()
    }
}
