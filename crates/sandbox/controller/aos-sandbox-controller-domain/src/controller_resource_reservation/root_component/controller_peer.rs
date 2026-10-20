//! Pays the actual accepted Controller comparison from the same original RootR.

use aos_sandbox_model::ResourceVector;

use crate::normal_root::{
    NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1,
    RootControllerPeerReceivingV1,
};

use super::{RootReceivingOriginalV1, root_journal::RootJournalDemandErrorV1};
use super::super::{ResourceReservationErrorV1, service_interval::ObserverLifetime};
use super::service_observation::RootServicePostPurposeV1 as PostPurpose;


#[derive(Default)]
pub(super) struct RootControllerPeerProvisionV1 {
    permit: Option<Result<ResourceVector, RootJournalDemandErrorV1>>,
    before: Option<Result<(), Error>>,
    capture: Option<Result<(), Error>>,
    after: Option<Result<(), Error>>,
    settlement: Option<Result<(), Error>>,
    initial_traffic: Option<Result<(), ResourceReservationErrorV1>>,
    history_resident: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
}

impl RootControllerPeerProvisionV1 {
    pub(super) fn service_post_can_retire_v1(&self) -> bool {
        matches!(self.permit, Some(Ok(_))) && matches!(self.initial_traffic, Some(Ok(())))
            && matches!(self.before, Some(Ok(()))) && matches!(self.capture, Some(Ok(())))
            && matches!(self.after, Some(Ok(()))) && matches!(self.settlement, Some(Ok(())))
    }

    pub(super) fn may_arm_service_post_v1(&self) -> bool {
        matches!(self.permit, Some(Ok(_))) && self.before.is_none()
            && self.capture.is_none() && self.after.is_none()
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        macro_rules! cause {
            ($slot:expr) => { $slot.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)) };
        }
        cause!(self.permit).or_else(|| cause!(self.initial_traffic)).or_else(|| cause!(self.before))
            .or_else(|| cause!(self.capture)).or_else(|| cause!(self.after))
            .or_else(|| cause!(self.settlement))
            .or_else(|| cause!(self.history_resident))
    }
}

impl RootReceivingOriginalV1 {
    pub(crate) fn enter_history_peer_worker_once_v1(&mut self) -> Result<(), Error> {
        if self.completed_controller_peer_prefix().is_none()
            || !self.activation.controller_history_worker_idle_data_v1() {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        self.activation.enter_controller_history_worker_once_v1().map_err(Into::into)
    }

    pub(crate) fn finish_history_peer_worker_once_v1(&mut self) -> Result<(), Error> {
        if self.activation.controller_history_worker_idle_data_v1() {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        self.activation.finish_controller_history_worker_once_v1().map_err(Into::into)
    }

    pub(crate) fn refuse_history_peer_post_v1(&mut self) { self.activation.latch_root_refusal_v1(); }

    pub(crate) fn observe_armed_history_service_once_v1(&mut self,
        startup: &ProductionNormalRootStartupV1,
        post: &mut aos_sandbox_broker::receiving::RootPrearmedHistoryServicePostV1,
    ) -> Result<(), Error> {
        self.activation.observe_history_service_post_once_v1(startup.native_startup_original_v1(), post)
            .map_err(Into::into)
    }

    pub(crate) fn arm_history_peer_post_v1(&mut self, startup: &ProductionNormalRootStartupV1)
        -> Result<crate::normal_root::RootHistoryPeerPostV1, Error> {
        if self.failure().is_some() || self.completed_controller_peer_prefix().is_none()
            || !self.activation.controller_history_worker_idle_data_v1() {
            return Err(Error::Service);
        }
        let resident = (|| {
            let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
            let base = self.completed_controller_peer_prefix().ok_or_else(invalid)?;
            let resident = base.checked_add(crate::normal_root::RootHistoryPeerPostV1::additional_resident_demand_v1()?)
                .map_err(|_| invalid())?;
            self.require_receiving_demand_v1(resident)?;
            Ok(resident)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.controller_peer_stage()?.history_resident, resident,
        );
        if !matches!(self.controller_peer_stage()?.history_resident, Some(Ok(_))) {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        let before = self.activation.arm_history_service_post_v1(startup.native_startup_original_v1()).map_err(Error::from)?;
        let after = self.activation.arm_history_service_post_v1(startup.native_startup_original_v1()).map_err(Error::from)?;
        let traffic = self.debit_observer_traffic_v1(crate::normal_root::RootHistoryPeerPostV1::traffic_demand_v1()
            .map_err(|_| Error::Service)?);
        Ok(crate::normal_root::RootHistoryPeerPostV1::from_originals_v1(
            before, after, ObserverLifetime::begin(), traffic))
    }

    pub(crate) fn prepay_current_controller_peer_once(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<ObserverLifetime, Error> {
        if self.controller_peer_provision.is_some() || self.failure().is_some() {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        self.controller_peer_provision = Some(RootControllerPeerProvisionV1::default());
        let permit = (|| {
            let error = || ResourceReservationErrorV1::EnrollmentUnavailable;
            let base = self.policy_listener_prefix().ok_or_else(error)?;
            let demand = base.checked_add(crate::normal_root::root_history_post::without_traffic(
                RootControllerPeerReceivingV1::fixed_demand()?))
                .map_err(|_| error())?;
            self.require_receiving_demand_v1(demand).map_err(|_| error())?;
            Ok(demand)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.controller_peer_stage()?.permit, permit,
        );
        if !matches!(self.controller_peer_stage()?.permit, Some(Ok(_))) {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        let traffic = self.debit_observer_traffic_v1(crate::normal_root::RootHistoryPeerPostV1::initial_traffic_demand_v1()
            .map_err(|_| Error::Service)?);
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.controller_peer_stage()?.initial_traffic, traffic,
        );
        if !matches!(self.controller_peer_stage()?.initial_traffic, Some(Ok(()))) {
            return Err(Error::Service);
        }
        let before = self.arm_service_post_once_v1(startup, PostPurpose::InitialController)
            .and_then(|()| self.recheck_service(startup));
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.controller_peer_stage()?.before, before,
        );
        if !matches!(self.controller_peer_stage()?.before, Some(Ok(()))) {
            if self.service_post_is_armed_v1(PostPurpose::InitialController) {
                let after = self.observe_service_post_once_v1(startup, PostPurpose::InitialController);
                self.native_refusal_original_v1().park_empty_result_v1(
                    &mut self.controller_peer_stage()?.after, after,
                );
            }
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        Ok(ObserverLifetime::begin())
    }

    pub(crate) fn post_current_controller_peer_once(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        capture: Result<(), Error>,
    ) -> Result<(), Error> {
        if self.controller_peer_stage()?.capture.is_some() {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.controller_peer_stage()?.capture, capture,
        );
        let after = self.observe_service_post_once_v1(startup, PostPurpose::InitialController);
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.controller_peer_stage()?.after, after,
        );
        if self.controller_peer_stage()?.failure().is_none() {
            Ok(())
        } else {
            self.activation.latch_root_refusal_v1();
            Err(Error::Service)
        }
    }

    pub(crate) fn finish_current_controller_peer_once(
        &mut self,
        settlement: Result<(), Error>,
    ) -> Result<(), Error> {
        if self.controller_peer_stage()?.settlement.is_some()
            || !matches!(self.controller_peer_stage()?.capture, Some(Ok(())))
            || !matches!(self.controller_peer_stage()?.after, Some(Ok(())))
        {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.controller_peer_stage()?.settlement, settlement,
        );
        if self.completed_controller_peer_prefix().is_some() {
            self.retire_service_post_after_positive_v1(PostPurpose::InitialController);
            Ok(())
        } else {
            self.activation.latch_root_refusal_v1();
            Err(Error::Service)
        }
    }

    pub(super) fn completed_controller_peer_prefix(&self) -> Option<ResourceVector> {
        let stage = self.controller_peer_provision.as_ref()?;
        if !matches!(stage.before, Some(Ok(())))
            || !matches!(stage.capture, Some(Ok(())))
            || !matches!(stage.after, Some(Ok(())))
            || !matches!(stage.settlement, Some(Ok(())))
        {
            return None;
        }
        stage.permit.as_ref()?.as_ref().ok().copied()
    }

    pub(super) fn controller_peer_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let stage = self.controller_peer_provision.as_ref()?;
        if matches!(stage.permit, Some(Ok(_))) && matches!(stage.initial_traffic, Some(Ok(())))
            && matches!(stage.before, Some(Err(_))) {
            self.service_post_arm_failure_v1(PostPurpose::InitialController)
                .or_else(|| self.activation.currentness_failure_v1()).or_else(|| stage.failure())
        } else if matches!(stage.capture, Some(Ok(()))) && matches!(stage.after, Some(Err(_))) {
            self.service_post_failure_v1(PostPurpose::InitialController).or_else(|| stage.failure())
        } else { stage.failure() }
    }

    fn controller_peer_stage(&mut self) -> Result<&mut RootControllerPeerProvisionV1, Error> {
        self.controller_peer_provision.as_mut().ok_or(Error::Service)
    }
}

impl RootReceivingOriginalV1 {
    pub(super) fn require_controller_peer_disposal_v1(&self) -> Result<(), Error> {
        let stage = self.controller_peer_provision.as_ref().ok_or(Error::Service)?;
        if self.completed_controller_peer_prefix().is_none()
            || stage.failure().is_some() || !self.activation.controller_history_worker_idle_data_v1()
        {
            Err(Error::Service)
        } else {
            Ok(())
        }
    }
}
