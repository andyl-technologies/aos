//! Publishes an exact pre-reserved Main cleanup owner without drain contention.

use super::*;

pub(super) struct CleanupReservation {
    queue: Weak<LifecycleCleanupQueue>,
    index: usize,
    epoch: u64,
    observed: ProductionVmCleanupStage,
    first_failure: Option<SchedulerError>,
}

impl LifecycleCleanupHandle {
    pub(crate) fn owner(&self) -> Result<Arc<LifecycleCleanupQueue>, LifecycleApiError> {
        self.queue
            .upgrade()
            .ok_or_else(|| refusal("containing Main cleanup owner is absent"))
    }

    /// Moves the selected body charge into its exact cell before body birth.
    pub(crate) fn reserve_for_world(
        &self,
        controls: AuthenticatedNativeWorldControlLease,
    ) -> Result<
        Box<dyn ProductionVmCleanupReservation>,
        (AuthenticatedNativeWorldControlLease, LifecycleApiError),
    > {
        self.reserve_with(controls, |cell, controls| cell.controls = Some(controls))
    }

    fn reserve_with<T>(
        &self,
        input: T,
        attach: impl FnOnce(&mut CleanupCell, T),
    ) -> Result<Box<dyn ProductionVmCleanupReservation>, (T, LifecycleApiError)> {
        let queue = match self.queue.upgrade() {
            Some(queue) => queue,
            None => return Err((input, refusal("containing Main cleanup owner is absent"))),
        };
        for (index, slot) in queue.slots.iter().enumerate() {
            if !slot.claim(CleanupPhase::Free, CleanupPhase::Reserving) {
                continue;
            }
            let epoch = initialize_reserved_slot(slot, input, attach)?;
            return Ok(Box::new(CleanupReservation {
                queue: Weak::clone(&self.queue),
                index,
                epoch,
                observed: ProductionVmCleanupStage::BodyRetained,
                first_failure: None,
            }));
        }
        Err((input, refusal("prepaid cleanup ownership is occupied")))
    }
}

impl ProductionVmCleanupReservation for CleanupReservation {
    fn retain(
        self: Box<Self>,
        owner: ProductionVmCleanupOwner,
    ) -> Result<
        Box<dyn ProductionVmCleanupHandoff>,
        (
            Box<dyn ProductionVmCleanupReservation>,
            ProductionVmCleanupOwner,
        ),
    > {
        let Some(queue) = self.queue.upgrade() else {
            return Err((self, owner));
        };
        let Some(slot) = queue.slots.get(self.index) else {
            return Err((self, owner));
        };
        self.publish_owner(slot, owner)
            .map(|receipt| receipt as Box<dyn ProductionVmCleanupHandoff>)
    }

    fn complete(self: Box<Self>) -> Result<(), LifecycleApiError> {
        let queue = self
            .queue
            .upgrade()
            .ok_or_else(|| refusal("containing Main cleanup owner is absent"))?;
        let slot = queue
            .slots
            .get(self.index)
            .ok_or_else(|| refusal("cleanup reservation cell is absent"))?;
        if !slot.claim(CleanupPhase::Reserved, CleanupPhase::Completing) {
            return Err(refusal(
                "cleanup completion is stale or already transferred",
            ));
        }
        let mut cell = match slot.cell.lock() {
            Ok(cell) => cell,
            Err(_) => {
                slot.publish(CleanupPhase::DestructionRefused);
                return Err(refusal("cleanup completion ownership is poisoned"));
            }
        };
        if cell.epoch != self.epoch || cell.owner.is_some() {
            slot.publish(CleanupPhase::DestructionRefused);
            return Err(refusal("cleanup completion has unknown containing custody"));
        }
        // The caller destroyed its actual owner outside every queue lock.
        slot.body_destroyed_epoch
            .store(cell.epoch, Ordering::Release);
        let returned = close_controls_retaining_failure(&mut cell);
        publish_return(slot, &cell, returned.is_ok());
        returned
    }
}

/// Initializes the already claimed cell before constructing its token/body.
fn initialize_reserved_slot<T>(
    slot: &CleanupSlot,
    input: T,
    attach: impl FnOnce(&mut CleanupCell, T),
) -> Result<u64, (T, LifecycleApiError)> {
    if !slot.is(CleanupPhase::Reserving) {
        return Err((
            input,
            refusal("cleanup cell was not reserved before initialization"),
        ));
    }
    let mut cell = match slot.cell.lock() {
        Ok(cell) => cell,
        Err(_) => {
            slot.publish(CleanupPhase::DestructionRefused);
            return Err((input, refusal("cleanup reservation ownership is poisoned")));
        }
    };
    if cell.owner.is_some() || cell.controls.is_some() {
        slot.publish(CleanupPhase::DestructionRefused);
        return Err((input, refusal("free cleanup cell retains unknown custody")));
    }
    let epoch = match cell.epoch.checked_add(1) {
        Some(epoch) => epoch,
        None => {
            slot.publish(CleanupPhase::DestructionRefused);
            return Err((input, refusal("cleanup reservation epoch exhausted")));
        }
    };
    cell.epoch = epoch;
    cell.first_failure = None;
    cell.handoff = false;
    attach(&mut cell, input);
    drop(cell);
    slot.publish(CleanupPhase::Reserved);
    Ok(epoch)
}

impl CleanupReservation {
    /// Moves into the same claimed epoch; the containing handle selects slot.
    fn publish_owner(
        self: Box<Self>,
        slot: &CleanupSlot,
        owner: ProductionVmCleanupOwner,
    ) -> Result<
        Box<Self>,
        (
            Box<dyn ProductionVmCleanupReservation>,
            ProductionVmCleanupOwner,
        ),
    > {
        if !slot.claim(CleanupPhase::Reserved, CleanupPhase::Publishing) {
            return Err((self, owner));
        }
        // No legitimate queue operation locks Reserved/Publishing cells. The
        // sole move-only token owns this publication, without a capacity search.
        let mut cell = match slot.cell.lock() {
            Ok(cell) => cell,
            Err(_) => {
                slot.publish(CleanupPhase::DestructionRefused);
                return Err((self, owner));
            }
        };
        if cell.epoch != self.epoch || cell.owner.is_some() {
            slot.publish(CleanupPhase::DestructionRefused);
            return Err((self, owner));
        }
        cell.owner = Some(owner);
        cell.handoff = true;
        drop(cell);
        slot.publish(CleanupPhase::Queued);
        Ok(self)
    }

    fn observe_slot(
        &mut self,
        slot: &CleanupSlot,
    ) -> Result<ProductionVmCleanupStage, LifecycleApiError> {
        if self.observed == ProductionVmCleanupStage::Complete {
            return Ok(self.observed);
        }
        if slot.completed_epoch.load(Ordering::Acquire) >= self.epoch {
            self.observed = ProductionVmCleanupStage::Complete;
            return Ok(self.observed);
        }
        if slot.body_destroyed_epoch.load(Ordering::Acquire) >= self.epoch {
            self.observed = ProductionVmCleanupStage::BodyDestroyed;
        }
        if !slot.claim(CleanupPhase::Closed, CleanupPhase::Completing) {
            return Ok(self.observed);
        }
        let mut cell = match slot.cell.lock() {
            Ok(cell) => cell,
            Err(_) => {
                slot.publish(CleanupPhase::DestructionRefused);
                return Err(refusal("closed cleanup handoff custody is poisoned"));
            }
        };
        if cell.epoch != self.epoch {
            drop(cell);
            slot.publish(CleanupPhase::Closed);
            return Err(refusal("closed cleanup handoff epoch is stale"));
        }
        if cell.owner.is_some() || cell.controls.is_some() || !cell.handoff {
            slot.publish(CleanupPhase::DestructionRefused);
            return Err(refusal("cleanup closure retains unknown physical custody"));
        }
        self.first_failure = cell.first_failure.take();
        // Latch before publication can admit another epoch. The same Box owns
        // both the historical cause and its actual completed physical fact.
        self.observed = ProductionVmCleanupStage::Complete;
        slot.completed_epoch.store(self.epoch, Ordering::Release);
        drop(cell);
        slot.publish(CleanupPhase::Free);
        Ok(self.observed)
    }
}

impl ProductionVmCleanupHandoff for CleanupReservation {
    fn retry(&mut self) -> Result<ProductionVmCleanupStage, LifecycleApiError> {
        if self.observed == ProductionVmCleanupStage::Complete {
            return Ok(self.observed);
        }
        let queue = self
            .queue
            .upgrade()
            .ok_or_else(|| refusal("containing Main cleanup owner is absent"))?;
        let slot = queue
            .slots
            .get(self.index)
            .ok_or_else(|| refusal("cleanup handoff cell is absent"))?;
        let attempted = retry_slot(slot, Some(self.epoch));
        let observed = self.observe_slot(slot)?;
        if observed == ProductionVmCleanupStage::Complete {
            return Ok(observed);
        }
        attempted?;
        Ok(observed)
    }

    fn stage(&mut self) -> Result<ProductionVmCleanupStage, LifecycleApiError> {
        if self.observed == ProductionVmCleanupStage::Complete {
            return Ok(self.observed);
        }
        let queue = self
            .queue
            .upgrade()
            .ok_or_else(|| refusal("containing Main cleanup owner is absent"))?;
        let slot = queue
            .slots
            .get(self.index)
            .ok_or_else(|| refusal("cleanup handoff cell is absent"))?;
        self.observe_slot(slot)
    }

    fn first_failure(&self) -> Option<&SchedulerError> {
        self.first_failure.as_ref()
    }

    fn take_first_failure(&mut self) -> Option<SchedulerError> {
        self.first_failure.take()
    }
}

#[cfg(test)]
mod tests;
