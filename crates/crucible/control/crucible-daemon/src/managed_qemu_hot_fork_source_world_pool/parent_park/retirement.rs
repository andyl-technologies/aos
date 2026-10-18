//! Uses the same Park record while its actual Source is canonically retained.
//!
//! Selection is nonissuing. Every operation borrows the genuine passed Source,
//! and actual closed-request/membership facts latch independently of errors.
//! No source-allocation strong or Weak edge lives in a production gate.

use super::*;
use std::error::Error;
use std::fmt;

impl ManagedParentParkGate {
    pub(crate) fn matches_selection(&self, selection: &crate::PreparedSourceSelector) -> bool {
        match &self.body.source {
            ParkSourceSelection::Main(actual) => actual.same_role(selection),
            #[cfg(test)]
            ParkSourceSelection::Component(_) => false,
        }
    }

    pub(super) fn matches_source(
        &self,
        _owner: &Arc<Mutex<ProductionVmHotForkSourceWorld>>,
        source: &ProductionVmHotForkSourceWorld,
    ) -> bool {
        match &self.body.source {
            ParkSourceSelection::Main(selection) => source
                .prepared_source_selector()
                .as_ref()
                .is_some_and(|actual| actual.same_role(selection)),
            #[cfg(test)]
            ParkSourceSelection::Component(actual) => {
                crate::vm_lifecycle::unissued_component_source(source)
                    && Weak::ptr_eq(actual, &Arc::downgrade(_owner))
            }
        }
    }

    #[cfg(test)]
    pub(in crate::managed_qemu_hot_fork_source_world_pool) fn matches_component_owner(
        &self,
        owner: &Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    ) -> bool {
        matches!(&self.body.source, ParkSourceSelection::Component(actual) if Weak::ptr_eq(actual, &Arc::downgrade(owner)))
    }

    pub(crate) fn is_physically_returned(&self) -> bool {
        self.body.physically_returned.load(Ordering::Acquire)
    }

    pub(super) fn has_settlement_failure(&self) -> bool {
        self.body.host_return_after.get().is_some() || self.body.cleanup_after.get().is_some()
    }

    pub(super) fn return_native(
        &self,
        owner: &Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    ) -> Result<QmpParentParkResult, ManagedParentParkError> {
        self.step(owner, true, |source| {
            let mut receipt = source.return_parent_park_retained(&self.body.node)?;
            // These facts come only from the actual same-connection closed
            // request and the Node's independent membership return operation.
            if receipt.closed_request.is_some() && receipt.host_memberships_returned {
                self.body.physically_returned.store(true, Ordering::Release);
            }
            if let Some(first) = receipt.host_return_after.take() {
                let _ = self.body.host_return_after.set(first);
            }
            if let Some(post) = receipt.cleanup_after.take() {
                let _ = self.body.cleanup_after.set(post);
            }
            Ok(receipt)
        })
    }

    /// Runs only the already-entered Park cleanup against its same actual Source.
    pub(crate) fn retry_retirement(
        &self,
        owner: &Arc<Mutex<ProductionVmHotForkSourceWorld>>,
    ) -> bool {
        if self.is_physically_returned() {
            return true;
        }
        // The Source selects its existing Cleanup. A refused caller post stays
        // raw in this record and cannot erase factual return or renew work.
        let _observed = self.return_native(owner);
        self.is_physically_returned()
    }

    pub(crate) fn first_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.body
            .first
            .get()
            .map(|first| first as &dyn Error)
            .or_else(|| {
                self.body
                    .original_after
                    .get()
                    .map(|first| first as &dyn Error)
            })
            .or_else(|| {
                self.body
                    .host_return_after
                    .get()
                    .map(|first| first as &dyn Error)
            })
            .or_else(|| {
                self.body
                    .cleanup_after
                    .get()
                    .map(|first| first as &dyn Error)
            })
    }

    pub(crate) fn visit_history(
        &self,
        mut apply: impl FnMut(&'static str, &(dyn Error + 'static)) -> fmt::Result,
    ) -> fmt::Result {
        if let Some(first) = self.body.first.get() {
            apply("managed Park first", first)?;
        }
        if let Some(post) = self.body.original_after.get() {
            apply("managed Park caller post", post)?;
        }
        if let Some(first) = self.body.host_return_after.get() {
            apply("managed Park membership post", first)?;
        }
        if let Some(post) = self.body.cleanup_after.get() {
            apply("managed Park Cleanup post", post)?;
        }
        Ok(())
    }
}

impl fmt::Debug for ManagedParentParkGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedParentParkGate")
            .field("physically_returned", &self.is_physically_returned())
            .field("first", &self.body.first.get())
            .field("original_after", &self.body.original_after.get())
            .finish_non_exhaustive()
    }
}
