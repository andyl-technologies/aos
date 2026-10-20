//! Lends only the actual maintenance interval through Node's same C/Source pair.
//!
//! The executor returns a closed borrow of its actual protected Source after
//! current native comparison. Reconciler supplies its private C directly; no
//! raw Source getter, external work callback or replacement writer is exposed.

use super::*;

/// Borrows the executor's actual Source after the same paid native comparison.
#[doc(hidden)]
pub struct CatalogMaintenanceSourceBorrowV2<'source> {
    source: &'source mut ProtectedSourceDomainJournalOwnerV1,
}

impl ProtectedSourceDomainJournalOwnerV1 {
    /// Lends this actual current Source to its same paid maintenance original.
    ///
    /// # Errors
    /// Refuses changed C, Source, profile, funding, replay or original horizon.
    #[doc(hidden)]
    pub fn borrow_catalog_maintenance_source_v2<'source>(
        &'source mut self,
        original: &mut CatalogMaintenanceOriginalV2,
        controller: &Journal,
    ) -> Result<CatalogMaintenanceSourceBorrowV2<'source>, ResourceReservationErrorV1> {
        original.require_current_v2(controller, self)?;
        original
            .source_projection
            .require_same_projection_v2(self.journal_ref_v1())?;
        original.check_frontier_v2()?;
        Ok(CatalogMaintenanceSourceBorrowV2 { source: self })
    }
}

impl<'source> CatalogMaintenanceSourceBorrowV2<'source> {
    pub(crate) fn into_interval_v2<'original, 'controller>(
        self,
        original: &'original mut CatalogMaintenanceOriginalV2,
        controller: &'controller mut Journal,
    ) -> Result<
        ControllerCatalogMaintenanceLoanV2<'original, 'controller>,
        ResourceReservationErrorV1,
    >
    where
        'source: 'controller,
    {
        original.require_current_v2(controller, self.source)?;
        Ok(ControllerCatalogMaintenanceLoanV2 {
            owner: original,
            controller,
            source: self.source,
        })
    }
}
