//! Funds actual Root3 from the SAME completed reserved/fresh-proof R prefix.

use crate::normal_root::{NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1};
use crate::policy_compiler::create_storage_current::{
    root_open::RootCurrentOpenStateV1, use_authorized::RootCurrentUseAuthorizedStateV1,
    use_reserved::RootCurrentUseReservedStateV1, use_admitted::RootCurrentUseAdmittedStateV1,
    source_current::RootCurrentSourceExchangeStateV1, cache_current::RootCurrentCacheProofStateV1,
};
use super::{RootReceivingOriginalV1, current_provision::{RootCurrentProvisionV1, RootCurrentStageV1}};
use super::super::ResourceReservationErrorV1;

impl RootReceivingOriginalV1 {
    pub(crate) fn prepay_current_use_admitted_once(&mut self,
        startup: &ProductionNormalRootStartupV1, root: &RootCurrentOpenStateV1,
        authorization: &RootCurrentUseAuthorizedStateV1, reserved: &RootCurrentUseReservedStateV1,
        source: &RootCurrentSourceExchangeStateV1, cache: &RootCurrentCacheProofStateV1,
    ) -> Result<(), Error> {
        if self.current_use_admitted_provision.is_some() || self.failure().is_some() {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        self.current_use_admitted_provision = Some(RootCurrentProvisionV1::default());
        let permit = (|| {
            let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
            let base = self.completed_use_current_prefix_v1(root, authorization, reserved, source, cache)
                .map_err(|_| invalid())?;
            let held = self.current_writers_receiving.as_ref()
                .and_then(|stage| stage.authority_extent()).ok_or_else(invalid)?;
            let additional = RootCurrentUseAdmittedStateV1::receiving_demand_v1(held, authorization, reserved)?;
            let complete = base.checked_add(additional).map_err(|_| invalid())?;
            self.require_receiving_demand_v1(complete)?;
            Ok(complete)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_use_admitted_provision.as_mut().ok_or(Error::Service)?.permit, permit,
        );
        self.finish_current_provision_once(startup, RootCurrentStageV1::UseAdmitted)
    }
}
