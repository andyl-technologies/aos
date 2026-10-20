//! Admits actual fixed issuer custody under the same completed Root prefix.

use aos_sandbox_core::ResourceDimension as D;

use crate::normal_root::{NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1};
use crate::policy_compiler::create_storage_current::{
    pins::RootCurrentPinsStateV1, ready::RootCurrentReadyStateV1,
    root_open::RootCurrentOpenStateV1,
};

use super::RootReceivingOriginalV1;
use super::current_provision::{RootCurrentProvisionV1, RootCurrentStageV1};
use super::super::ResourceReservationErrorV1;

pub(super) type RootCurrentPinsProvisionV1 = RootCurrentProvisionV1;

impl RootReceivingOriginalV1 {
    pub(crate) fn prepay_current_pins_once(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        root_open: &RootCurrentOpenStateV1,
        ready: &RootCurrentReadyStateV1,
    ) -> Result<(), Error> {
        if self.current_pins_provision.is_some() || self.failure().is_some() {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        self.current_pins_provision = Some(RootCurrentPinsProvisionV1::default());
        let permit = (|| {
            let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
            ready.raw_ready_bytes().map_err(|_| invalid())?;
            if root_open.completed_receiver().map_err(|_| invalid())?
                != self.current_root_open_original_pair().map_err(|_| invalid())?
            {
                return Err(invalid().into());
            }
            let base = self.current_ready_provision.as_ref()
                .and_then(|stage| stage.completed_prefix()).ok_or_else(invalid)?;
            let additional = RootCurrentPinsStateV1::dominant_demand()?;
            let disposed = ready.completed_native_descriptor_peak_v1().map_err(|_| invalid())?;
            // The same original's closed, already disposed Ready native peak
            // can contain this sequential fixed credential stage. Keep that
            // peak fully charged in base; add only excess resident FD demand.
            // Raw Ready memory remains cumulative, with no future-drop credit.
            let additional = additional.with(D::OpenFiles,
                additional.get(D::OpenFiles).saturating_sub(disposed));
            let demand = base.checked_add(additional).map_err(|_| invalid())?;
            self.require_receiving_demand_v1(demand).map_err(|_| invalid())?;
            Ok(demand)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_pins_provision.as_mut().ok_or(Error::Service)?.permit, permit,
        );
        self.finish_current_provision_once(startup, RootCurrentStageV1::Pins)
    }
}
