//! Admits the actual Root UseAuthorized append/readback/send under the same R.

use crate::normal_root::{NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1};
use crate::policy_compiler::{OriginalRootCreateStorageCurrentAttemptV1,
    create_storage_current::{controller_readonly::RootCurrentControllerReadonlyStateV1,
        root_open::RootCurrentOpenStateV1}};
use super::{RootReceivingOriginalV1,
    current_provision::{RootCurrentProvisionV1, RootCurrentStageV1}};
use super::super::ResourceReservationErrorV1;

impl RootReceivingOriginalV1 {
    pub(crate) fn prepay_current_use_authorized_once(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        root: &RootCurrentOpenStateV1,
        readonly: &RootCurrentControllerReadonlyStateV1,
    ) -> Result<(), Error> {
        if self.current_use_authorized_provision.is_some() || self.failure().is_some() {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        self.current_use_authorized_provision = Some(RootCurrentProvisionV1::default());
        let permit = (|| {
            let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
            readonly.require_complete_v1().map_err(|_| invalid())?;
            if root.completed_receiver().map_err(|_| invalid())?
                != self.current_root_open_original_pair().map_err(|_| invalid())?
            { return Err(invalid().into()); }
            let base = self.current_controller_readonly_provision.as_ref()
                .and_then(|stage| stage.semantic.completed_prefix()).ok_or_else(invalid)?;
            let held = self.current_writers_receiving.as_ref()
                .and_then(|stage| stage.authority_extent()).ok_or_else(invalid)?;
            let additional = OriginalRootCreateStorageCurrentAttemptV1::
                root_use_authorized_append_demand_v1(held)?;
            let complete = base.checked_add(additional).map_err(|_| invalid())?;
            self.require_receiving_demand_v1(complete)?;
            Ok(complete)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_use_authorized_provision.as_mut().ok_or(Error::Service)?.permit, permit,
        );
        self.finish_current_provision_once(startup, RootCurrentStageV1::UseAuthorized)
    }
}
