//! Lends the actual installed Host startup owner before Session authentication.
//!
//! This sealed broker route grants no effect or enrollment. The concrete
//! financial loan pays the cold native engine on its same captured Control.

use super::*;

impl<C: HostCatalog, S: HostStateStore, W: HostWorker> HostBroker<C, S, W> {
    pub(crate) fn borrow_control_cold_session_owner_v1(
        &mut self,
    ) -> Result<crate::plan::HostControlColdSessionOwnerV1> {
        let original = self.component_control.as_ref().ok_or(HostError::Fence(
            "Host cold cleanup has no captured startup Control",
        ))?;
        let resident = self
            .live_cleanup_source_v1()?
            .map(super::HostLiveCleanupOwnerV1::new_v1);
        Ok(
            crate::plan::HostControlColdSessionOwnerV1::from_original_v1(
                Arc::clone(original),
                resident,
            ),
        )
    }
}
