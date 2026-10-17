//! Publishes an exact pre-reserved Main cleanup owner without drain contention.

use super::*;

pub(super) struct CleanupReservation {
    queue: Weak<LifecycleCleanupQueue>,
    index: usize,
    epoch: u64,
    observed: ProductionVmCleanupStage,
    first_failure: Option<crate::ProductionVmConstructionCleanupError>,
}

/// Retains an original World reservation and its exact preborn Main cell.
///
/// Only successful reservation beneath the real Main creates this move-only
/// bundle. Its private cell selection supplies no process, Source, cleanup or
/// physical-return authority. Publication moves its existing reservation Box;
/// retaining the selection creates no replacement allocation or queue owner.
#[must_use = "retain the same reservation or move it into its owning cleanup path"]
pub struct WorldLifecycleCleanupReservation {
    reservation: Box<
        dyn ProductionVmCleanupReservation<Failure = crate::ProductionVmConstructionCleanupError>,
    >,
    cell: ReservedWorldCell,
}

struct ReservedWorldCell {
    queue: Weak<LifecycleCleanupQueue>,
    index: usize,
    epoch: u64,
}

impl WorldLifecycleCleanupReservation {
    /// Copies only the original nonissuing Main-cell selection.
    ///
    /// The startup consumer verifies this selection before its first effect.
    /// Copying it neither admits Service work nor occupies another role.
    pub(crate) fn service_preclaim(&self) -> ServiceMainPreclaim {
        ServiceMainPreclaim {
            queue: Weak::clone(&self.cell.queue),
            index: self.cell.index,
            epoch: self.cell.epoch,
        }
    }

    /// Checks the original empty preclaim before allocating its paid bodies.
    pub(crate) fn is_preclaimed(&self) -> bool {
        let Some(queue) = self.cell.queue.upgrade() else {
            return false;
        };
        let Some(slot) = queue.slots.get(self.cell.index) else {
            return false;
        };
        borrow_reserved_cell(slot, self.cell.epoch).is_some_and(|cell| cell.controls.is_none())
    }

    /// Checks retained cell custody without publishing, returning or renewing it.
    pub(crate) fn is_reserved(&self) -> bool {
        let Some(queue) = self.cell.queue.upgrade() else {
            return false;
        };
        let Some(slot) = queue.slots.get(self.cell.index) else {
            return false;
        };
        let Some(cell) = borrow_reserved_cell(slot, self.cell.epoch) else {
            return false;
        };
        cell.controls.is_some()
    }

    /// Attaches the same delivered body lease to the original preclaimed cell.
    ///
    /// No allocation, Original entry or physical preparation occurs here.
    /// Refusal returns the SAME lease to the already prepaid receiver.
    pub(crate) fn attach_controls(
        &self,
        controls: AuthenticatedNativeWorldControlLease,
    ) -> Result<(), AuthenticatedNativeWorldControlLease> {
        let Some(queue) = self.cell.queue.upgrade() else {
            return Err(controls);
        };
        let Some(slot) = queue.slots.get(self.cell.index) else {
            return Err(controls);
        };
        let Some(mut cell) = borrow_reserved_cell(slot, self.cell.epoch) else {
            return Err(controls);
        };
        if cell.controls.is_some() {
            return Err(controls);
        }
        cell.controls = Some(controls);
        Ok(())
    }

    /// Moves the original neutral reservation Box without a replacement wrapper.
    pub(crate) fn into_reservation(
        self,
    ) -> Box<
        dyn ProductionVmCleanupReservation<Failure = crate::ProductionVmConstructionCleanupError>,
    > {
        self.reservation
    }
}

fn borrow_reserved_cell(
    slot: &CleanupSlot,
    epoch: u64,
) -> Option<std::sync::MutexGuard<'_, CleanupCell>> {
    if !slot.is(CleanupPhase::Reserved) {
        return None;
    }
    let cell = slot.cell.try_lock().ok()?;
    if cell.epoch != epoch
        || cell.owner.is_some()
        || cell.handoff
        || !slot.is(CleanupPhase::Reserved)
    {
        return None;
    }
    Some(cell)
}

impl LifecycleCleanupHandle {
    pub(crate) fn owner(&self) -> Result<Arc<LifecycleCleanupQueue>, LifecycleApiError> {
        self.queue
            .upgrade()
            .ok_or_else(|| refusal("containing Main cleanup owner is absent"))
    }

    /// Reserves the same Main-paid constructor cell before World admission.
    pub(crate) fn reserve_for_source(
        &self,
    ) -> Result<WorldLifecycleCleanupReservation, crucible_qemu::QemuVmRealizationError> {
        let queue =
            self.queue
                .upgrade()
                .ok_or(crucible_qemu::QemuVmRealizationError::CleanupRetained {
                    operation: "retain actual Main Source cleanup queue",
                })?;
        queue._pool.verify_retained_main().map_err(|first| {
            crucible_qemu::QemuVmRealizationError::ModelCopy {
                source: Box::new(crucible_qemu::OriginalActorAccountError::NativePurpose(
                    first,
                )),
            }
        })?;
        for (index, slot) in queue.slots.iter().enumerate() {
            if !slot.claim(CleanupPhase::Free, CleanupPhase::Reserving) {
                continue;
            }
            let epoch = initialize_reserved_slot(slot, (), |_, ()| {}).map_err(|(_, first)| {
                crucible_qemu::QemuVmRealizationError::ModelCopy {
                    source: Box::new(first),
                }
            })?;
            return Ok(WorldLifecycleCleanupReservation {
                reservation: Box::new(CleanupReservation {
                    queue: Weak::clone(&self.queue),
                    index,
                    epoch,
                    observed: ProductionVmCleanupStage::BodyRetained,
                    first_failure: None,
                }),
                cell: ReservedWorldCell {
                    queue: Weak::clone(&self.queue),
                    index,
                    epoch,
                },
            });
        }
        Err(crucible_qemu::QemuVmRealizationError::CleanupRetained {
            operation: "reserve occupied Main Source cleanup cell",
        })
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

/// Selects the original Main role without issuing Service or World authority.
///
/// The actual reservation remains its sole token. This inline, move-only key
/// supplies no budget, operation, cleanup clock, cell reservation or body lease.
pub(crate) struct ServiceMainPreclaim {
    queue: Weak<LifecycleCleanupQueue>,
    index: usize,
    epoch: u64,
}

/// Preserves an exact pre-Service selection or retained-Main refusal inline.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ServiceMainPreclaimError {
    /// The original preclaimed role cannot be authenticated before Service.
    #[error("{0}")]
    Role(&'static str),
    /// The actual containing Main refused retained-custody verification.
    #[error(transparent)]
    Main(#[from] crucible_linux_resource::host_services::process_birth::ServiceBirthError),
}

impl ServiceMainPreclaim {
    /// Compares original queue allocation, index and epoch without a new grant.
    pub(crate) fn same_role(&self, other: &Self) -> bool {
        Weak::ptr_eq(&self.queue, &other.queue)
            && self.index == other.index
            && self.epoch == other.epoch
    }

    /// Checks retained Main and its same empty preclaim before startup effects.
    ///
    /// This check supplies no live Service operation. The startup driver must
    /// separately enter and check its genuine admission Original before work.
    pub(crate) fn verify_before_service(&self) -> Result<(), ServiceMainPreclaimError> {
        let queue = self.queue.upgrade().ok_or(ServiceMainPreclaimError::Role(
            "pre-Service containing Main is unavailable",
        ))?;
        queue._pool.verify_retained_main()?;
        let slot = queue
            .slots
            .get(self.index)
            .ok_or(ServiceMainPreclaimError::Role(
                "pre-Service Main role is absent",
            ))?;
        let cell = borrow_reserved_cell(slot, self.epoch).ok_or(ServiceMainPreclaimError::Role(
            "pre-Service Main role is stale, borrowed or uncertain",
        ))?;
        if cell.controls.is_some() {
            return Err(ServiceMainPreclaimError::Role(
                "pre-Service Main role already entered World construction",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod service_main_preclaim_tests {
    use super::*;

    fn unavailable(index: usize, epoch: u64) -> ServiceMainPreclaim {
        ServiceMainPreclaim {
            queue: Weak::new(),
            index,
            epoch,
        }
    }

    #[test]
    fn unavailable_preclaim_remains_a_refusal_after_identity_comparison() {
        let first = unavailable(3, 7);
        let same = unavailable(3, 7);
        assert!(first.same_role(&same));
        assert!(!first.same_role(&unavailable(4, 7)));
        assert!(!first.same_role(&unavailable(3, 8)));

        for key in [first, same] {
            assert!(matches!(
                key.verify_before_service(),
                Err(ServiceMainPreclaimError::Role(
                    "pre-Service containing Main is unavailable"
                ))
            ));
        }
    }
}
