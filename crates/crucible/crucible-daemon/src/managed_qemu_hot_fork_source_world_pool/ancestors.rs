//! Ancestor checkout: leasing the deepest published root below a parent.
//!
//! A branch attempt whose own parent has no retained root may still start
//! hot from a published-boundary root at a strict ancestor `C` of that
//! parent, replaying the recorded suffix inside the forked child. Ancestry is
//! a lookup relation over root provenance, not a key: one root at `C` serves
//! every eligible descendant, and its key keeps naming `C`.
//!
//! ```text
//! candidates = published-boundary roots
//!            with the parent's lineage, scenario, and executor profile
//!            that can lease a child now
//!            whose provenance configuration C has parent.def
//!            and is a strict schedule prefix of the parent
//!            and that the caller's suffix policy accepts
//! checkout   = deepest candidate, through the ordinary lease path
//! ```
//!
//! Genesis and exact-checkpoint sources are never ancestors: genesis would
//! route every branch to an unproven deep replay inside a child, and exact
//! sources are keyed by their checkpoint rather than a published boundary.

use crucible_engine::Configuration;

use super::*;
use crate::QemuHotForkSourceWorldBoundary;

/// One leased ancestor root and the identity it was checked out under.
#[must_use = "return the source lease after complete child reconciliation or abandon it"]
pub(crate) struct QemuHotForkAncestorCheckout {
    lease: QemuHotForkSourceWorldLease,
    key: QemuHotForkSourceWorldKey,
    provenance: QemuPublishedRootProvenance,
}

impl QemuHotForkAncestorCheckout {
    /// Returns the lease, key, and provenance.
    pub(crate) fn into_parts(
        self,
    ) -> (
        QemuHotForkSourceWorldLease,
        QemuHotForkSourceWorldKey,
        QemuPublishedRootProvenance,
    ) {
        (self.lease, self.key, self.provenance)
    }
}

impl<D, R> ManagedQemuHotForkSourceWorldPool<D, R>
where
    D: HotCheckpointTemplateDemotionSink<ManagedQemuHotForkSourceWorld>,
    R: HotCheckpointFallbackRetentionStore,
{
    /// Leases the deepest eligible published root below `parent`.
    ///
    /// `key` is the attempt's own published key at `parent`; candidates must
    /// share its lineage, scenario, and executor profile. `eligible` is the
    /// caller's suffix policy over each candidate's provenance. The chosen
    /// root is checked out through [`Self::checkout_lease_for`], so fork-rate
    /// admission, child reservation, and identity checks are unchanged.
    ///
    /// # Errors
    ///
    /// Returns the ordinary lease checkout failures for the chosen root.
    pub(super) fn checkout_ancestor_lease_for(
        &mut self,
        provider: u64,
        key: &QemuHotForkSourceWorldKey,
        parent: &Configuration,
        eligible: &dyn Fn(&QemuPublishedRootProvenance) -> bool,
    ) -> Result<Option<QemuHotForkAncestorCheckout>, ManagedQemuHotForkSourceWorldCheckoutError>
    {
        if key.boundary() != QemuHotForkSourceWorldBoundary::PublishedBoundary {
            return Ok(None);
        }
        let deepest = self
            .worlds
            .values()
            .filter(|world| {
                world.key().boundary() == QemuHotForkSourceWorldBoundary::PublishedBoundary
                    && world.key().shares_basis_with(key)
                    && world.lease_available()
            })
            .filter_map(|world| {
                let provenance = world.published_root_provenance()?;
                strict_ancestor_of(provenance.configuration(), parent)
                    .then_some((world.key(), provenance))
            })
            .filter(|(_key, provenance)| eligible(provenance))
            .max_by_key(|(_key, provenance)| provenance.configuration().schedule.len())
            .map(|(key, provenance)| (key.clone(), provenance.clone()));
        let Some((ancestor, provenance)) = deepest else {
            return Ok(None);
        };

        Ok(self
            .checkout_lease_for(provider, &ancestor)?
            .map(|lease| QemuHotForkAncestorCheckout {
                lease,
                key: ancestor,
                provenance,
            }))
    }
}

/// Returns whether `ancestor` is a strict schedule prefix of `parent`.
fn strict_ancestor_of(ancestor: &Configuration, parent: &Configuration) -> bool {
    ancestor.def == parent.def
        && ancestor.schedule.len() < parent.schedule.len()
        && parent.schedule.starts_with(&ancestor.schedule)
}
