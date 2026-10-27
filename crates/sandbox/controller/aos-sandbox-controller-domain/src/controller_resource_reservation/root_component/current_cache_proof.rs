//! Pays the actual Root-first Cache exchange through the same original R.
//!
//! The complete fixed shape includes the transport and both strict direction
//! flights. No supplied vector, forwarded nonce, packet or other role's payer
//! can construct this once-only provision.

use crate::normal_root::{NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1};
use crate::policy_compiler::create_storage_current::{
    bundle_ownership::RootCurrentBundleOwnershipStateV1,
    cache_current::RootCurrentCacheProofStateV1,
    pins::RootCurrentPinsStateV1,
    root_open::RootCurrentOpenStateV1,
};
use super::{RootReceivingOriginalV1, current_provision::{RootCurrentProvisionV1, RootCurrentStageV1}};
use super::super::ResourceReservationErrorV1;

impl RootReceivingOriginalV1 {
    pub(crate) fn prepay_current_cache_current_once(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        root: &RootCurrentOpenStateV1,
        ownership: &RootCurrentBundleOwnershipStateV1,
        pins: &RootCurrentPinsStateV1,
    ) -> Result<(), Error> {
        if self.current_cache_proof_provision.is_some() || self.failure().is_some() {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        self.current_cache_proof_provision = Some(RootCurrentProvisionV1::default());
        let permit = (|| {
            let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
            ownership.require_complete_v1().map_err(|_| invalid())?;
            pins.require_complete().map_err(|_| invalid())?;
            startup.current_cache_signer_identity_data_v1().map_err(|_| invalid())?;
            if root.completed_receiver().map_err(|_| invalid())?
                != self.current_root_open_original_pair().map_err(|_| invalid())?
            {
                return Err(invalid().into());
            }
            let base = self.current_bundle_ownership_provision.as_ref()
                .and_then(|stage| stage.typed.completed_prefix()).ok_or_else(invalid)?;
            let additional = RootCurrentCacheProofStateV1::fixed_demand_v1()?;
            let complete = base.checked_add(additional).map_err(|_| invalid())?;
            self.require_receiving_demand_v1(complete).map_err(|_| invalid())?;
            Ok(complete)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_cache_proof_provision.as_mut().ok_or(Error::Service)?.permit, permit,
        );
        self.finish_current_provision_once(startup, RootCurrentStageV1::CacheCurrent)
    }
}
