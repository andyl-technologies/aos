//! Lends the actual broker's catalog slot through the sealed composition.

use super::*;
use crate::catalog::{HostCatalogPublicationCallsiteV2, HostCatalogPublicationFailureViewV2};

impl<C: HostCatalog, S: HostStateStore, W: HostWorker> HostBroker<C, S, W> {
    /// Borrows the cumulative reached Control invoice after real catalog completion.
    ///
    /// The vector includes prior Control debt and every actual current/readback
    /// catalog width admitted by the publication kernel. It is comparison DATA,
    /// not spare capacity, a refund or a native completion grant. This method
    /// performs no IO, model decoding, admission or financial mutation.
    ///
    /// # Errors
    /// Refuses an unhealthy broker, absent or incomplete publication, poisoned
    /// Control custody, or an incomplete consumed Control invoice.
    #[doc(hidden)]
    pub fn completed_catalog_publication_receiving_data_v2(
        &self,
    ) -> Result<aos_sandbox_core::ResourceVector> {
        self.ensure_healthy()?;
        if !self.catalog_publication_v2.as_ref().is_some_and(|owner| owner.payload.completed) {
            return Err(HostError::Fence("Host catalog has no completed native publication"));
        }
        let control = self.component_control.as_ref().ok_or(HostError::Fence(
            "Host catalog requires installed component Control",
        ))?.lock().map_err(|_| HostError::Fence("Host catalog original Control is poisoned"))?;
        control.completed_catalog_control_demand_data_v2()
    }

    pub(crate) fn borrow_catalog_publication_v2(
        &mut self,
    ) -> Result<HostCatalogPublicationCallsiteV2<'_>> {
        self.ensure_healthy()?;
        if self.launch_original.is_some()
            || self
                .catalog_publication_v2
                .as_ref()
                .is_some_and(|owner| !owner.payload.completed)
        {
            return Err(HostError::Fence("Host catalog has occupied native custody"));
        }
        let control = self.component_control.as_ref().ok_or(HostError::Fence(
            "Host catalog requires installed component Control",
        ))?;
        Ok(HostCatalogPublicationCallsiteV2::from_original_v2(
            &mut self.catalog_publication_v2,
            control,
            &mut self.state_healthy,
        ))
    }

    pub(crate) fn catalog_publication_failure_view_v2(
        &self,
    ) -> HostCatalogPublicationFailureViewV2<'_> {
        HostCatalogPublicationFailureViewV2 {
            original: self.catalog_publication_v2.as_deref(),
            control: self.component_control.as_ref(),
        }
    }
}
