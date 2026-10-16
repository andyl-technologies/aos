//! Publishes an exact pre-reserved Main cleanup owner without drain contention.

use super::*;

pub(super) struct CleanupReservation {
    queue: Weak<LifecycleCleanupQueue>,
    index: usize,
    epoch: u64,
    observed: ProductionVmCleanupStage,
    first_failure: Option<crate::ProductionVmConstructionCleanupError>,
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
        Box<
            dyn ProductionVmCleanupReservation<
                Failure = crate::ProductionVmConstructionCleanupError,
            >,
        >,
        (AuthenticatedNativeWorldControlLease, LifecycleApiError),
    > {
        self.reserve_with(controls, |cell, controls| cell.controls = Some(controls))
    }

    fn reserve_with<T>(
        &self,
        input: T,
        attach: impl FnOnce(&mut CleanupCell, T),
    ) -> Result<
        Box<
            dyn ProductionVmCleanupReservation<
                Failure = crate::ProductionVmConstructionCleanupError,
            >,
        >,
        (T, LifecycleApiError),
    > {
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
    type Failure = crate::ProductionVmConstructionCleanupError;

    fn retain(
        self: Box<Self>,
        owner: Box<
            dyn ProductionVmCleanupOwner<Failure = crate::ProductionVmConstructionCleanupError>,
        >,
    ) -> Result<
        Box<dyn ProductionVmCleanupHandoff<Failure = crate::ProductionVmConstructionCleanupError>>,
        (
            Box<
                dyn ProductionVmCleanupReservation<
                    Failure = crate::ProductionVmConstructionCleanupError,
                >,
            >,
            Box<
                dyn ProductionVmCleanupOwner<Failure = crate::ProductionVmConstructionCleanupError>,
            >,
        ),
    > {
        let Some(queue) = self.queue.upgrade() else {
            return Err((self, owner));
        };
        let Some(slot) = queue.slots.get(self.index) else {
            return Err((self, owner));
        };
        self.publish_owner(slot, owner).map(|receipt| {
            receipt
                as Box<
                    dyn ProductionVmCleanupHandoff<
                        Failure = crate::ProductionVmConstructionCleanupError,
                    >,
                >
        })
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
        owner: Box<
            dyn ProductionVmCleanupOwner<Failure = crate::ProductionVmConstructionCleanupError>,
        >,
    ) -> Result<
        Box<Self>,
        (
            Box<
                dyn ProductionVmCleanupReservation<
                    Failure = crate::ProductionVmConstructionCleanupError,
                >,
            >,
            Box<
                dyn ProductionVmCleanupOwner<Failure = crate::ProductionVmConstructionCleanupError>,
            >,
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
    type Failure = crate::ProductionVmConstructionCleanupError;

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

    fn first_failure(&self) -> Option<&crate::ProductionVmConstructionCleanupError> {
        self.first_failure.as_ref()
    }

    fn take_first_failure(&mut self) -> Option<crate::ProductionVmConstructionCleanupError> {
        self.first_failure.take()
    }
}

#[cfg(test)]
mod tests;

/// Exercises the canonical cell and receipt without constructing a Main issuer.
#[cfg(test)]
pub(crate) fn component_owner_history_for_test(
    owner: Box<dyn ProductionVmCleanupOwner<Failure = crate::ProductionVmConstructionCleanupError>>,
    observe_retained: impl FnOnce(),
) -> crate::ProductionVmConstructionCleanupError {
    let slot = CleanupSlot {
        phase: AtomicU8::new(CleanupPhase::Queued as u8),
        body_destroyed_epoch: AtomicU64::new(0),
        completed_epoch: AtomicU64::new(0),
        cell: Mutex::new(CleanupCell {
            epoch: 1,
            owner: Some(owner),
            controls: None,
            first_failure: None,
            handoff: true,
        }),
    };
    let mut receipt = CleanupReservation {
        queue: Weak::new(),
        index: 0,
        epoch: 1,
        observed: ProductionVmCleanupStage::BodyRetained,
        first_failure: None,
    };

    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _retained = slot.cell.lock().unwrap();
        panic!("component control poisons the real cleanup cell");
    }));
    assert!(poisoned.is_err());
    assert!(slot.cell.is_poisoned());

    assert!(retry_slot(&slot, Some(1)).is_err());
    assert_eq!(
        receipt.observe_slot(&slot).unwrap(),
        ProductionVmCleanupStage::BodyRetained
    );
    observe_retained();
    retry_slot(&slot, Some(1)).unwrap();
    assert_eq!(
        receipt.observe_slot(&slot).unwrap(),
        ProductionVmCleanupStage::Complete
    );
    assert!(slot.cell.lock().unwrap().owner.is_none());
    assert_eq!(slot.body_destroyed_epoch.load(Ordering::Acquire), 1);
    receipt.take_first_failure().unwrap()
}

#[cfg(test)]
impl LifecycleCleanupHandle {
    /// Creates only an unavailable canonical token for refused-handoff controls.
    ///
    /// Its empty Weak can never authenticate a queue, select a cell or publish
    /// an owner. This fixture issues no Main, World or cleanup authority.
    pub(crate) fn unavailable_reservation_for_test() -> Box<
        dyn ProductionVmCleanupReservation<
            Failure = <crate::ProductionVmConstructionCustody as ProductionVmCleanupOwner>::Failure,
        >,
    > {
        Box::new(CleanupReservation {
            queue: Weak::new(),
            index: usize::MAX,
            epoch: 0,
            observed: ProductionVmCleanupStage::BodyRetained,
            first_failure: None,
        })
    }
}
