//! Leased, authenticated page traversal through one bounded storage session.

use crucible_ram::RegionDescriptor;

use super::{LeasedRamRoot, RamStore, RamStoreError, RamVerificationReport, Work};

/// Borrows each freshly authenticated page in region and page-index order.
///
/// The bytes remain attached to their original decoding custody during the
/// callback. A visitor cannot retain this borrowed page after returning.
pub type RamPageVisitor<'visitor> =
    dyn FnMut(&RegionDescriptor, u64, &[u8]) -> Result<(), RamStoreError> + 'visitor;

// Shortens the callback object and reference together at each request reborrow.
pub(super) fn reborrow_visitor<'read, 'visitor: 'read>(
    visitor: &'read mut Option<&mut RamPageVisitor<'visitor>>,
) -> Option<&'read mut RamPageVisitor<'read>> {
    match visitor {
        Some(visitor) => Some(&mut **visitor),
        None => None,
    }
}

impl RamStore {
    /// Visits every selected page while retaining the root lease and original.
    ///
    /// A bounded depth-first walk authenticates every tree object and page from
    /// storage, including complete EOF, logical digest and valid-length checks.
    /// Packed storage retains one authenticated placement generation and one
    /// last-pack reader for this explicit session. It still rereads placement
    /// pages and actual content; this is not an immutable page-content cache.
    /// The session closes before its final original and physical authority cut.
    ///
    /// A Packed session holds namespace, live-generation and state read locks
    /// through each callback. A visitor must not synchronously publish or
    /// repack that same namespace, which requires conflicting write locks.
    ///
    /// This operation neither writes a guest mapping nor supplies random-page
    /// membership proofs. A failed traversal leaves any visitor output partial;
    /// callers must not publish restore readiness until the operation succeeds.
    ///
    /// # Errors
    /// Returns missing or corrupt content, invalid geometry, resource exhaustion,
    /// original cancellation, physical authority refusal, or visitor failure.
    pub fn visit_pages(
        &self,
        root: &LeasedRamRoot,
        original: &crate::owned_decode::DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
        visitor: &mut RamPageVisitor<'_>,
    ) -> Result<RamVerificationReport, RamStoreError> {
        self.admit_topology(root.record.topology())?;
        self.validate_root_catalogs(&root.record, &root.regions)?;
        let mut report = RamVerificationReport::default();
        let mut work = Work::new(self.limits, original, boundary)?;
        let mut pages = |region: &RegionDescriptor, index, bytes: &[u8]| {
            visitor(region, index, bytes)?;
            report.pages = report
                .pages
                .checked_add(1)
                .ok_or(RamStoreError::Limit("verified pages"))?;
            report.logical_bytes = report
                .logical_bytes
                .checked_add(bytes.len() as u64)
                .ok_or(RamStoreError::Limit("verified bytes"))?;
            Ok(())
        };
        super::bounded_read::read_inventory(
            self,
            root.object_id(),
            &root.record,
            &root.regions,
            &mut |_| Ok(()),
            Some(&mut pages),
            &mut work,
        )?;
        report.object_visits = work.visits;
        Ok(report)
    }
}
