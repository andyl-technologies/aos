//! Reconstructs probation order from actual sealed recovery registrations.
//!
//! This process-local scheduling cohort precedes later live admissions. It
//! preserves no pre-crash popularity or historical age and grants no native
//! authority; graph and permit validation still require original registry custody.

use super::NativeOwnerExecutor;
use std::io;

impl NativeOwnerExecutor {
    /// Orders actual verified recovery bodies before subsequent cache admissions.
    ///
    /// # Errors
    /// Refuses another worker, repeated initialization, unavailable bounded
    /// storage or an exhausted allocation clock.
    pub(super) fn register_recovered_sealed_order(&mut self) -> io::Result<()> {
        self.check_physical_worker()?;
        if !self.recovered_sealed_order.is_empty() {
            return Err(io::Error::other(
                "sealed recovery order already initialized",
            ));
        }
        let count = self
            .adopted_inline
            .len()
            .checked_add(self.verified_manifests.len())
            .ok_or_else(|| io::Error::other("sealed recovery cohort overflows"))?;
        self.recovered_sealed_order
            .try_reserve_exact(count)
            .map_err(io::Error::other)?;

        let incarnations = self
            .adopted_inline
            .iter()
            .map(|body| body.incarnation())
            .chain(
                self.verified_manifests
                    .iter()
                    .map(|manifest| manifest.body().retained().body().incarnation()),
            );
        for incarnation in incarnations {
            if self
                .recovered_sealed_order
                .iter()
                .any(|(registered, _)| registered == incarnation)
            {
                continue;
            }
            self.allocation_order = self
                .allocation_order
                .checked_add(1)
                .ok_or_else(|| io::Error::other("sealed recovery order exhausted"))?;
            self.recovered_sealed_order
                .push((*incarnation, self.allocation_order));
        }
        Ok(())
    }

    /// Looks up scheduling data for an independently validated original body.
    ///
    /// # Errors
    /// Refuses a body absent from this worker's actual completed recovery cohort.
    pub(in crate::host_cache::owner) fn recovered_sealed_order(
        &self,
        incarnation: &[u8; 32],
    ) -> io::Result<u64> {
        self.check_physical_worker()?;
        self.recovered_sealed_order
            .iter()
            .find_map(|(registered, order)| (registered == incarnation).then_some(*order))
            .ok_or_else(|| io::Error::other("sealed body has no original recovery order"))
    }
}
