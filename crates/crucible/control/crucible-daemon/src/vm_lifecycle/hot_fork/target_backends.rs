//! Moves the existing Source backend set through one Target's scoped work.
//!
//! The Source mutex covers only these metadata moves. The genuine checkout,
//! Source resource guard, existing node supervisors and cached Originals remain
//! retained; an empty replacement header is never a usable or retired Source.

use super::*;
use crate::qemu_lifecycle_launcher::TargetConstructionStorage;

/// Keeps the same backend map and prepared-token vector outside the Source lock.
///
/// The fields cannot be assembled by a Target caller. This contains no new
/// native permission: operations still require the retained Source's actual
/// template tokens, resource guard and existing operational supervision.
pub(crate) struct TargetSourceBackends {
    source: crate::qemu_resource_guard::QemuGenerationStorageSelection,
    pub(crate) nodes: QemuNodeSet,
    pub(crate) prepared: Vec<QemuNodeSetPreparedHotForkTemplate>,
}

impl ProductionVmHotForkSourceWorld {
    /// Moves only already-owned headers after the actual checkout was checked.
    ///
    /// The caller holds its genuine Target Pending and exact Source checkout.
    /// Native/template validation happens after this metadata borrow ends; a
    /// refusal retains this complete value in Pending rather than restoring an
    /// unauthenticated Source or constructing another owner.
    pub(crate) fn take_target_source_backends(
        &mut self,
        storage: &TargetConstructionStorage,
    ) -> Option<TargetSourceBackends> {
        if self.target_backends_lent
            || self.prepared.is_empty()
            || !self.matches_target_construction_storage(storage)
        {
            return None;
        }
        let lifecycle = self.lifecycle.as_deref_mut()?;
        // These are metadata observations only. They issue no work or Cleanup.
        if self.prepared.iter().any(|prepared| {
            !lifecycle.inner.backend().contains(prepared.node())
                || !lifecycle.node_leases.contains_key(prepared.node())
        }) {
            return None;
        }
        self.target_backends_lent = true;
        Some(TargetSourceBackends {
            source: storage.source_selection(),
            nodes: std::mem::take(lifecycle.inner.backend_mut()),
            prepared: std::mem::take(&mut self.prepared),
        })
    }

    /// Restores exactly the temporarily lent backend set without physical work.
    ///
    /// A foreign registry, changed placeholder or unavailable Source returns the
    /// same value. No failure drops its nodes or prepared tokens under this lock.
    pub(crate) fn return_target_source_backends(
        &mut self,
        storage: &TargetConstructionStorage,
        mut backends: TargetSourceBackends,
    ) -> Result<TargetSourceBackends, TargetSourceBackends> {
        if !self.target_backends_lent
            || !self.prepared.is_empty()
            || !self.matches_target_construction_storage(storage)
            || !backends.source.same_selection(&storage.source_selection())
        {
            return Err(backends);
        }
        let Some(lifecycle) = self.lifecycle.as_deref_mut() else {
            return Err(backends);
        };
        if !lifecycle.inner.backend().is_empty() {
            return Err(backends);
        }
        // The placeholder was created above and no Source operation is allowed
        // while lent. Swaps dispose nothing and preserve all original capacity.
        std::mem::swap(lifecycle.inner.backend_mut(), &mut backends.nodes);
        std::mem::swap(&mut self.prepared, &mut backends.prepared);
        self.target_backends_lent = false;
        // Even the empty headers and nonissuing Weak leave this lock alive.
        // The caller destroys this returned shell after dropping its guard.
        Ok(backends)
    }
}
