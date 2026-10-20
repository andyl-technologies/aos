//! Prices one actual fixed RootOpen append over the same held authority prefix.

use crate::normal_root::{NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1};
use crate::policy_compiler::OriginalRootCreateStorageCurrentAttemptV1;

use super::RootReceivingOriginalV1;
use super::current_provision::{RootCurrentProvisionV1, RootCurrentStageV1};
use super::super::ResourceReservationErrorV1;

pub(super) type RootCurrentOpenProvisionV1 = RootCurrentProvisionV1;

impl RootReceivingOriginalV1 {
    pub(crate) fn prepay_current_root_open_once(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), Error> {
        if self.current_open_provision.is_some() || self.failure().is_some() {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        self.current_open_provision = Some(RootCurrentOpenProvisionV1::default());
        let permit = (|| {
            let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
            let previous = self.current_writers_receiving.as_ref().ok_or_else(invalid)?;
            let base = previous.completed_prefix().ok_or_else(invalid)?;
            let held = previous.authority_extent().ok_or_else(invalid)?;
            let additional = OriginalRootCreateStorageCurrentAttemptV1::root_open_append_demand(held)?;
            let demand = base.checked_add(additional).map_err(|_| invalid())?;
            self.require_receiving_demand_v1(demand).map_err(|_| invalid())?;
            Ok(demand)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_open_provision.as_mut().ok_or(Error::Service)?.permit, permit,
        );
        self.finish_current_provision_once(startup, RootCurrentStageV1::Open)
    }

    /// Returns comparison DATA from the actual delivered, recipient-bound enrollment.
    pub(crate) fn current_enrolled_node_data_v1(&self) -> Result<[u8; 16], Error> {
        if self.failure().is_some() || !matches!(self.recipient_binding, Some(Ok(()))) {
            return Err(Error::Service);
        }
        let original = self.original.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(Error::Service)?;
        Ok(original.identity.native_fields().node)
    }

    /// Reads partition DATA only from the same delivered, recipient-bound image.
    pub(crate) fn current_controller_baseline_partition_data_v1(&self)
        -> Result<(aos_sandbox_core::ResourceVector, aos_sandbox_core::ResourceVector,
            aos_sandbox_core::ResourceVector), Error>
    {
        if self.failure().is_some() || !matches!(self.recipient_binding, Some(Ok(()))) {
            return Err(Error::Service);
        }
        let original = self.original.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(Error::Service)?;
        original.policy.controller_baseline_partition_v1().map_err(|_| Error::Service)
    }

    pub(crate) fn current_root_open_original_pair(&self) -> Result<([u8; 16], [u8; 16]), Error> {
        if self.failure().is_some() || !matches!(self.recipient_binding, Some(Ok(()))) {
            return Err(Error::Service);
        }
        let original = self.original.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(Error::Service)?;
        Ok((original.recipient_invocation, original.identity.native_fields().invocation))
    }
}
