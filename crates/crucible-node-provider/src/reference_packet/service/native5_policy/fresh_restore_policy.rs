//! Keeps fresh startup selected construction closed in the original-ready cut.
//!
//! The launch field is retained for exact Source binding13 comparison. A fresh
//! publisher requires its actual owner class and cannot reuse the active report.

use super::*;

impl Native5Policy {
    pub(in crate::reference_packet::service) fn with_fresh_restore_allocation_selection(
        self,
        selection: Option<
            super::super::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection,
        >,
    ) -> Result<Self, ProviderError> {
        if selection.is_some() {
            return Err(ProviderError::Correlation(
                "fresh report startup publisher unavailable",
            ));
        }
        Ok(self)
    }

    pub(crate) const fn fresh_restore_allocation_selection(
        &self,
    ) -> Option<super::super::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection>
    {
        None
    }
}
