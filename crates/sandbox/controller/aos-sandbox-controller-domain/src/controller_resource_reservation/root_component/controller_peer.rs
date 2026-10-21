//! Pays the actual accepted Controller comparison from the same original RootR.

use aos_sandbox_model::ResourceVector;

use crate::normal_root::{
    NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1, RootControllerPeerReceivingV1,
};

use super::super::{ResourceReservationErrorV1, service_interval::ObserverLifetime};
use super::RootReceivingOriginalV1;

impl RootReceivingOriginalV1 {
    pub(crate) fn enter_history_peer_worker_once_v1(&mut self) -> Result<(), Error> {
        if self.completed_controller_peer_prefix().is_none()
            || !self.activation.controller_history_worker_idle_data_v1()
        {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        self.activation
            .enter_controller_history_worker_once_v1()
            .map_err(Into::into)
    }

    pub(crate) fn finish_history_peer_worker_once_v1(&mut self) -> Result<(), Error> {
        if self.activation.controller_history_worker_idle_data_v1() {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        self.activation
            .finish_controller_history_worker_once_v1()
            .map_err(Into::into)
    }

    pub(crate) fn refuse_history_peer_post_v1(&mut self) {
        self.activation.latch_root_refusal_v1();
    }

    pub(crate) fn observe_armed_history_service_once_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        post: &mut aos_sandbox_broker::receiving::RootPrearmedHistoryServicePostV1,
    ) -> Result<(), Error> {
        self.activation
            .observe_history_service_post_once_v1(startup.native_startup_original_v1(), post)
            .map_err(Into::into)
    }

    pub(crate) fn arm_history_peer_post_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<crate::normal_root::RootHistoryPeerPostV1, Error> {
        if self.failure().is_some()
            || self.completed_controller_peer_prefix().is_none()
            || !self.activation.controller_history_worker_idle_data_v1()
        {
            return Err(Error::Service);
        }
        let resident = (|| {
            let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
            let base = self
                .completed_controller_peer_prefix()
                .ok_or_else(invalid)?;
            let resident = base
                .checked_add(
                    crate::normal_root::RootHistoryPeerPostV1::additional_resident_demand_v1()?,
                )
                .map_err(|_| invalid())?;
            self.require_receiving_demand_v1(resident)?;
            Ok(resident)
        })();
        self.native_refusal_original_v1()
            .park_empty_result_v1(&mut self.controller_history_resident, resident);
        if !matches!(self.controller_history_resident, Some(Ok(_))) {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        let before = self
            .activation
            .arm_history_service_post_v1(startup.native_startup_original_v1())
            .map_err(Error::from)?;
        let after = self
            .activation
            .arm_history_service_post_v1(startup.native_startup_original_v1())
            .map_err(Error::from)?;
        let traffic = self.debit_observer_traffic_v1(
            crate::normal_root::RootHistoryPeerPostV1::traffic_demand_v1()
                .map_err(|_| Error::Service)?,
        );
        Ok(
            crate::normal_root::RootHistoryPeerPostV1::from_originals_v1(
                before,
                after,
                ObserverLifetime::begin(),
                traffic,
            ),
        )
    }

    pub(crate) fn park_initial_controller_peer_once_v1<'startup>(
        &mut self,
        startup: &'startup ProductionNormalRootStartupV1,
    ) -> Result<RootControllerPeerReceivingV1<'startup>, Error> {
        if self.controller_peer_provision.is_some() || self.failure().is_some() {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        let listener = self
            .native_completed_listener
            .as_ref()
            .ok_or(Error::Service)?;
        let startup = startup
            .native_startup_original_v1()
            .borrow_selected_original_v1()
            .map_err(Error::from)?;
        let original = listener
            .borrow_initial_v1(&mut self.activation)
            .map_err(Error::from)?
            .park_controller_peer_once_v1(startup)
            .map_err(Error::from)?;
        self.controller_peer_provision = Some(original.financial_provision_original_v1());
        Ok(RootControllerPeerReceivingV1::from_startup_original_v1(
            original,
        ))
    }

    pub(crate) fn prepare_initial_controller_peer_once_v1(
        &mut self,
        peer: &mut aos_sandbox_policy::native::RootStartupControllerPeerOriginalV1<'_>,
        exclusion: &aos_sandbox_broker::receiving::RootUpperMutationGuardV1<'_>,
    ) -> Result<(), Error> {
        peer.require_provision_original_v1(
            self.controller_peer_provision
                .as_ref()
                .ok_or(Error::Service)?,
        )
        .map_err(Error::from)?;
        peer.prepare_once_v1(&mut self.activation, exclusion)
            .map_err(Into::into)
    }

    pub(crate) fn finish_initial_controller_post_once_v1(
        &mut self,
        peer: &mut aos_sandbox_policy::native::RootStartupControllerPeerOriginalV1<'_>,
        exclusion: &aos_sandbox_broker::receiving::RootUpperMutationGuardV1<'_>,
    ) -> Result<(), Error> {
        peer.require_provision_original_v1(
            self.controller_peer_provision
                .as_ref()
                .ok_or(Error::Service)?,
        )
        .map_err(Error::from)?;
        peer.finish_capture_post_once_v1(&mut self.activation, exclusion)
            .map_err(Into::into)
    }

    pub(crate) fn complete_initial_controller_peer_once_v1(
        &mut self,
        peer: &mut aos_sandbox_policy::native::RootStartupControllerPeerOriginalV1<'_>,
    ) -> Result<(), Error> {
        peer.require_provision_original_v1(
            self.controller_peer_provision
                .as_ref()
                .ok_or(Error::Service)?,
        )
        .map_err(Error::from)?;
        peer.complete_after_settlement_once_v1(&mut self.activation)
            .map_err(Into::into)
    }

    pub(super) fn completed_controller_peer_prefix(&self) -> Option<ResourceVector> {
        self.controller_peer_provision
            .as_ref()?
            .completed_prefix_data_v1(&self.activation)
            .ok()
    }

    pub(super) fn controller_peer_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.controller_peer_provision
            .as_ref()
            .and_then(|original| original.failure_v1())
            .or_else(|| {
                self.controller_history_resident
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
    }
}

impl RootReceivingOriginalV1 {
    pub(super) fn require_controller_peer_disposal_v1(&self) -> Result<(), Error> {
        let stage = self
            .controller_peer_provision
            .as_ref()
            .ok_or(Error::Service)?;
        if self.completed_controller_peer_prefix().is_none()
            || stage.failure_v1().is_some()
            || !self.activation.controller_history_worker_idle_data_v1()
        {
            Err(Error::Service)
        } else {
            Ok(())
        }
    }
}

impl RootReceivingOriginalV1 {
    pub(crate) fn initial_peer_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        type Producer<'a> = aos_sandbox_policy::native::RootStartupControllerPeerOriginalV1<'a>;
        type Provision = aos_sandbox_policy::native::RootControllerPeerProvisionOriginalV1;
        size_of::<(&mut Self, &ProductionNormalRootStartupV1)>()
            .checked_mul(3)?
            .checked_add(Self::initial_peer_disposal_control_bytes_v1()?)?
            .checked_add(
                size_of::<(
                    &mut Self,
                    &mut Producer<'_>,
                    &aos_sandbox_broker::receiving::RootUpperMutationGuardV1<'_>,
                )>()
                .checked_mul(6)?,
            )?
            .checked_add(size_of::<(&mut Self, &mut Producer<'_>)>().checked_mul(3)?)?
            .checked_add(
                size_of::<
                    Result<Producer<'_>, aos_sandbox_broker::receiving::RootObservationErrorV1>,
                >()
                .checked_mul(3)?,
            )?
            .checked_add(
                size_of::<Result<RootControllerPeerReceivingV1<'_>, Error>>().checked_mul(3)?,
            )?
            .checked_add(size_of::<Result<(), Error>>().checked_mul(12)?)?
            .checked_add(size_of::<Result<&Provision, Error>>().checked_mul(9)?)?
            .checked_add(size_of::<Option<&Provision>>().checked_mul(9)?)?
            .checked_add(size_of::<Provision>().checked_mul(3)?)?
            .checked_add(size_of::<Option<Provision>>().checked_mul(3)?)?
            .checked_add(
                size_of::<Option<Result<ResourceVector, ResourceReservationErrorV1>>>()
                    .checked_mul(3)?,
            )?
            .checked_add(size_of::<Option<&(dyn std::error::Error + 'static)>>().checked_mul(6)?)?
            .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
    }
}
