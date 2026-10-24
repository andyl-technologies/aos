//! Original-supervised administration of the graph's exact Packed boundary.
//!
//! Each operation borrows the caller's same account and the guard retained by
//! the admitted graph. Buffer and descriptor loans stay in the bounded Packed
//! engine; this facade adds no independent allocation or replacement scope.

use super::*;
use crate::owned_decode::DecodeBudget;

impl StoreGraphPackedRepackAdmin<'_> {
    /// Authenticates physical accounting under the supplied original boundary.
    ///
    /// # Errors
    /// Refuses lost original or physical authority, corrupt placement/pack
    /// metadata, unavailable resources or actual filesystem failures.
    pub fn accounting_with_boundary(
        self,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<PackedStorageAccounting, StoreError> {
        self.authority
            .body()?
            .backend
            .accounting_with_boundary(original, &mut || {
                self.check_original_physical(original, boundary)
            })
    }

    /// Plans one exact Packed generation under the supplied original boundary.
    ///
    /// # Errors
    /// Refuses original or physical authority loss, malformed complete index
    /// inventory, insufficient original resources or filesystem failures.
    pub fn plan_repack_with_boundary(
        self,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<PackedRepackPlan, StoreError> {
        self.authority
            .body()?
            .backend
            .plan_repack_with_boundary(original, &mut || {
                self.check_original_physical(original, boundary)
            })
    }

    /// Replaces an exact Packed generation under the supplied original boundary.
    ///
    /// Open readers retain old inodes through the durable root replacement and
    /// obsolete-name cleanup. A failure retains its actual publication outcome.
    ///
    /// # Errors
    /// Refuses a stale plan, lost original or physical authority, corrupt input,
    /// exhausted resources, incomplete durable publication or cleanup failure.
    pub fn apply_repack_with_boundary(
        self,
        original: &DecodeBudget,
        plan: &PackedRepackPlan,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<PackedRepackReport, StoreError> {
        self.authority
            .body()?
            .backend
            .apply_repack_with_boundary(original, plan, &mut || {
                self.check_original_physical(original, boundary)
            })
    }

    fn check_original_physical(
        self,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        super::super::checked_reader::check(original, boundary)?;
        self.verify_physical_quota()?;
        original
            .verify_live()
            .map_err(|error| super::super::batch::admission_under(original, error))
    }
}
