//! Borrows only original completed inventory Sessions for paid maintenance.

use super::*;
use aos_sandbox_broker_session_security::{
    DormantControllerInitialSessionCompletedBorrowV1, DormantControllerInitialSessionOpenV1,
};

macro_rules! maintenance_borrow {
    ($owner:ty) => {
        impl $owner {
            pub(in crate::controller_service) fn borrow_catalog_maintenance_session_v2<'held>(
                &'held mut self,
                capture: &'held DormantControllerInitialSessionOpenV1,
            ) -> Result<
                DormantControllerInitialSessionCompletedBorrowV1<'held>,
                BrokerSessionSecurityError,
            > {
                if self.0.pending.is_some()
                    || self.0.authority_effects.has_pending()
                    || self.0.has_pending_output_registration()
                    || self.0.git_coverage.is_some()
                {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                capture.borrow_completed_session_v1(&mut self.0.session)
            }
        }
    };
}

maintenance_borrow!(DormantMountLifecycleInventoryOwnerV1);
maintenance_borrow!(DormantNetworkLifecycleInventoryOwnerV1);
maintenance_borrow!(DormantStorageLifecycleInventoryOwnerV1);
