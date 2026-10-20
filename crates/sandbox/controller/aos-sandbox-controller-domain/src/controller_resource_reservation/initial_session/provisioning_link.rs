//! Compares intrinsic initial Storage identity without lending its old payer.
//!
//! The actual completed Security borrower retains the Session/cookie/physical
//! transcript relation. This private comparison joins only its same C and
//! profile, and neither reenters initial acquisition nor constructs any loan.

use super::*;

impl ControllerInitialBrokerSessionReceivingV1 {
    pub(in crate::controller_resource_reservation) fn require_provisioning_owner_v1(
        &self,
        expected: &Arc<ControllerReceivingOriginalV1>,
        profile: &Arc<ProductionControllerNormalRootProfileV1>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.role != ControllerInitialBrokerSessionRoleV1::Storage
            || !Arc::ptr_eq(&self.original, expected)
            || !Arc::ptr_eq(&self.profile, profile) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }
}
