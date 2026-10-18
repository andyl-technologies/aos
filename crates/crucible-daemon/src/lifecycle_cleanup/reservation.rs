//! Publishes an exact pre-reserved Main cleanup owner without drain contention.

use super::*;

pub(super) struct CleanupReservation {
    queue: Weak<LifecycleCleanupQueue>,
    index: usize,
    epoch: u64,
    observed: ProductionVmCleanupStage,
    first_failure: Option<crate::ProductionVmConstructionCleanupError>,
    terminal_history: Option<crate::ProductionVmConstructionPostBody>,
    report_reference: bool,
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
        dyn ProductionVmCleanupReservation<
                Failure = crate::ProductionVmConstructionCleanupError,
                PostBody = crate::ProductionVmConstructionPostBody,
                ReturnDestination = crate::lifecycle_cleanup::SourceBodyReturn,
            >,
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
        slot.is(CleanupPhase::Reserved)
            && !!slot.work_is_open()
            && borrow_reserved_cell(slot, self.cell.epoch)
                .is_some_and(|cell| cell.controls.is_none())
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
        cell.controls_bound = true;
        Ok(())
    }

    /// Moves the original neutral reservation Box without a replacement wrapper.
    pub(crate) fn into_reservation(
        self,
    ) -> Box<
        dyn ProductionVmCleanupReservation<
                Failure = crate::ProductionVmConstructionCleanupError,
                PostBody = crate::ProductionVmConstructionPostBody,
                ReturnDestination = crate::lifecycle_cleanup::SourceBodyReturn,
            >,
    > {
        self.reservation
    }
}

pub(super) fn borrow_reserved_cell(
    slot: &CleanupSlot,
    epoch: u64,
) -> Option<std::sync::MutexGuard<'_, CleanupCell>> {
    if !(slot.is(CleanupPhase::Reserved) || slot.is(CleanupPhase::RetryingPrepared)) {
        return None;
    }
    let cell = slot.cell.try_lock().ok()?;
    if cell.epoch != epoch
        || cell.owner.is_some()
        || cell.handoff
        || !(slot.is(CleanupPhase::Reserved) || slot.is(CleanupPhase::RetryingPrepared))
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
}

impl ProductionVmCleanupReservation for CleanupReservation {
    type Failure = crate::ProductionVmConstructionCleanupError;
    type PostBody = crate::ProductionVmConstructionPostBody;
    type ReturnDestination = SourceBodyReturn;

    fn prepare_return(
        mut self: Box<Self>,
    ) -> Result<
        SourceBodyReturn,
        Box<
            dyn ProductionVmCleanupReservation<
                    Failure = Self::Failure,
                    PostBody = Self::PostBody,
                    ReturnDestination = SourceBodyReturn,
                >,
        >,
    > {
        let Some(queue) = self.queue.upgrade() else {
            return Err(self);
        };
        let Some(slot) = queue.slots.get(self.index) else {
            return Err(self);
        };
        let mut cell = match slot.cell.lock() {
            Ok(cell) => cell,
            Err(_) => return Err(self),
        };
        if slot.epoch.load(Ordering::Acquire) != self.epoch
            || cell.epoch != self.epoch
            || !(slot.is(CleanupPhase::Reserved) || slot.is(CleanupPhase::RetryingPrepared))
            || cell.owner.is_some()
            || cell.handoff
            || slot.external_return_reserved.load(Ordering::Acquire)
            || self.report_reference
            || !report_refs::register(slot, self.epoch)
        {
            return Err(self);
        }
        self.report_reference = true;
        slot.external_return_reserved.store(true, Ordering::Release);
        let index = self.index;
        let epoch = self.epoch;
        drop(cell);
        Ok(SourceBodyReturn::new(queue, index, epoch, self))
    }

    fn retain(
        self: Box<Self>,
        owner: Box<
            dyn ProductionVmCleanupOwner<
                    Failure = crate::ProductionVmConstructionCleanupError,
                    PostBody = crate::ProductionVmConstructionPostBody,
                >,
        >,
    ) -> Result<
        Box<
            dyn ProductionVmCleanupHandoff<
                    Failure = crate::ProductionVmConstructionCleanupError,
                    PostBody = crate::ProductionVmConstructionPostBody,
                >,
        >,
        (
            Box<
                dyn ProductionVmCleanupReservation<
                        Failure = crate::ProductionVmConstructionCleanupError,
                        PostBody = crate::ProductionVmConstructionPostBody,
                        ReturnDestination = crate::lifecycle_cleanup::SourceBodyReturn,
                    >,
            >,
            Box<
                dyn ProductionVmCleanupOwner<
                        Failure = crate::ProductionVmConstructionCleanupError,
                        PostBody = crate::ProductionVmConstructionPostBody,
                    >,
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
                            PostBody = crate::ProductionVmConstructionPostBody,
                        >,
                >
        })
    }

    fn retain_returned(
        self: Box<Self>,
        owner: Box<
            dyn ProductionVmCleanupOwner<
                    Failure = crate::ProductionVmConstructionCleanupError,
                    PostBody = crate::ProductionVmConstructionPostBody,
                >,
        >,
    ) -> Result<
        Box<
            dyn ProductionVmCleanupHandoff<
                    Failure = crate::ProductionVmConstructionCleanupError,
                    PostBody = crate::ProductionVmConstructionPostBody,
                >,
        >,
        (
            Box<
                dyn ProductionVmCleanupReservation<
                        Failure = crate::ProductionVmConstructionCleanupError,
                        PostBody = crate::ProductionVmConstructionPostBody,
                        ReturnDestination = crate::lifecycle_cleanup::SourceBodyReturn,
                    >,
            >,
            Box<
                dyn ProductionVmCleanupOwner<
                        Failure = crate::ProductionVmConstructionCleanupError,
                        PostBody = crate::ProductionVmConstructionPostBody,
                    >,
            >,
        ),
    > {
        let Some(queue) = self.queue.upgrade() else {
            return Err((self, owner));
        };
        let Some(slot) = queue.slots.get(self.index) else {
            return Err((self, owner));
        };
        self.publish_returned_owner(slot, owner).map(|receipt| {
            receipt
                as Box<
                    dyn ProductionVmCleanupHandoff<
                            Failure = crate::ProductionVmConstructionCleanupError,
                            PostBody = crate::ProductionVmConstructionPostBody,
                        >,
                >
        })
    }
}

impl CleanupReservation {
    pub(super) fn cancel_return_registration(&mut self, slot: &CleanupSlot) {
        if self.report_reference {
            self.report_reference = false;
            report_refs::release(slot, self.epoch, false);
        }
    }

    /// Moves into the same claimed epoch; the containing handle selects slot.
    fn publish_owner(
        self: Box<Self>,
        slot: &CleanupSlot,
        owner: Box<
            dyn ProductionVmCleanupOwner<
                    Failure = crate::ProductionVmConstructionCleanupError,
                    PostBody = crate::ProductionVmConstructionPostBody,
                >,
        >,
    ) -> Result<
        Box<Self>,
        (
            Box<
                dyn ProductionVmCleanupReservation<
                        Failure = crate::ProductionVmConstructionCleanupError,
                        PostBody = crate::ProductionVmConstructionPostBody,
                        ReturnDestination = crate::lifecycle_cleanup::SourceBodyReturn,
                    >,
            >,
            Box<
                dyn ProductionVmCleanupOwner<
                        Failure = crate::ProductionVmConstructionCleanupError,
                        PostBody = crate::ProductionVmConstructionPostBody,
                    >,
            >,
        ),
    > {
        self.publish_owner_mode(slot, owner, false)
    }

    fn publish_returned_owner(
        self: Box<Self>,
        slot: &CleanupSlot,
        owner: Box<
            dyn ProductionVmCleanupOwner<
                    Failure = crate::ProductionVmConstructionCleanupError,
                    PostBody = crate::ProductionVmConstructionPostBody,
                >,
        >,
    ) -> Result<
        Box<Self>,
        (
            Box<
                dyn ProductionVmCleanupReservation<
                        Failure = crate::ProductionVmConstructionCleanupError,
                        PostBody = crate::ProductionVmConstructionPostBody,
                        ReturnDestination = crate::lifecycle_cleanup::SourceBodyReturn,
                    >,
            >,
            Box<
                dyn ProductionVmCleanupOwner<
                        Failure = crate::ProductionVmConstructionCleanupError,
                        PostBody = crate::ProductionVmConstructionPostBody,
                    >,
            >,
        ),
    > {
        self.publish_owner_mode(slot, owner, true)
    }

    fn publish_owner_mode(
        mut self: Box<Self>,
        slot: &CleanupSlot,
        owner: Box<
            dyn ProductionVmCleanupOwner<
                    Failure = crate::ProductionVmConstructionCleanupError,
                    PostBody = crate::ProductionVmConstructionPostBody,
                >,
        >,
        returned: bool,
    ) -> Result<
        Box<Self>,
        (
            Box<
                dyn ProductionVmCleanupReservation<
                        Failure = crate::ProductionVmConstructionCleanupError,
                        PostBody = crate::ProductionVmConstructionPostBody,
                        ReturnDestination = crate::lifecycle_cleanup::SourceBodyReturn,
                    >,
            >,
            Box<
                dyn ProductionVmCleanupOwner<
                        Failure = crate::ProductionVmConstructionCleanupError,
                        PostBody = crate::ProductionVmConstructionPostBody,
                    >,
            >,
        ),
    > {
        if slot.epoch.load(Ordering::Acquire) != self.epoch {
            return Err((self, owner));
        }
        let was_quarantined =
            returned && slot.claim(CleanupPhase::DestructionRefused, CleanupPhase::Publishing);
        let claimed = was_quarantined
            || slot.claim(CleanupPhase::Reserved, CleanupPhase::Publishing)
            || (returned && slot.claim(CleanupPhase::RetryingPrepared, CleanupPhase::Publishing));
        if !claimed {
            return Err((self, owner));
        }
        // The external token is unique. Reserved/RetryingPrepared control
        // borrows contain only fixed metadata moves; no prepared mutex, IO,
        // user callback or destructor is awaited while holding this mutex.
        let (mut cell, poisoned) = match slot.cell.lock() {
            Ok(cell) => (cell, false),
            Err(poison) if returned => (poison.into_inner(), true),
            Err(_) => {
                slot.publish(CleanupPhase::DestructionRefused);
                return Err((self, owner));
            }
        };
        if cell.epoch != self.epoch
            || cell.owner.is_some()
            || cell.handoff
            || slot.external_return_reserved.load(Ordering::Acquire)
        {
            slot.publish(CleanupPhase::DestructionRefused);
            return Err((self, owner));
        }
        if !report_refs::register(slot, self.epoch) {
            slot.publish(CleanupPhase::DestructionRefused);
            return Err((self, owner));
        }
        self.report_reference = true;
        slot.request_retirement();
        cell.owner = Some(owner);
        cell.handoff = true;
        if poisoned {
            crate::ProductionVmConstructionCleanupError::retain_first(
                &mut cell.first_failure,
                crate::ProductionVmConstructionCleanupError::Poisoned,
            );
        }
        drop(cell);
        if poisoned || was_quarantined {
            slot.publish(CleanupPhase::DestructionRefused);
        } else if !slot.claim(CleanupPhase::Publishing, CleanupPhase::Queued) {
            // A concurrently observed callback unwind may quarantine the same
            // Main role. Custody is accepted, but that fact must not reopen it.
            slot.publish(CleanupPhase::DestructionRefused);
        }
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
        if slot.controls_closed_epoch.load(Ordering::Acquire) >= self.epoch {
            self.observed = ProductionVmCleanupStage::Complete;
            let mut cell = slot
                .cell
                .try_lock()
                .map_err(|_| refusal("completed handoff history is borrowed or poisoned"))?;
            if cell.epoch != self.epoch || cell.owner.is_some() || cell.controls.is_some() {
                return Err(refusal("completed handoff retains a different actual body"));
            }
            if self.first_failure.is_none() {
                self.first_failure = cell.first_failure.take();
            }
        }
        Ok(self.observed)
    }
}

impl ProductionVmCleanupHandoff for CleanupReservation {
    type Failure = crate::ProductionVmConstructionCleanupError;
    type PostBody = crate::ProductionVmConstructionPostBody;

    fn retry(&mut self) -> Result<ProductionVmCleanupStage, LifecycleApiError> {
        if self.terminal_history.is_some() {
            return Ok(ProductionVmCleanupStage::Complete);
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

    fn retain_post_body(&mut self) -> bool {
        if self.terminal_history.is_some() {
            return true;
        }
        if !self.report_reference {
            return false;
        }
        let key = ServiceMainPreclaim {
            queue: Weak::clone(&self.queue),
            index: self.index,
            epoch: self.epoch,
        };
        match terminal::take_terminal_body(&key) {
            Ok(body) => {
                // The same one report reference moves into the actual terminal
                // body. No cache or strong queue edge remains in Main's cell.
                self.report_reference = false;
                self.observed = ProductionVmCleanupStage::Complete;
                self.terminal_history = Some(body);
                true
            }
            Err(_) => false,
        }
    }

    fn retained_post_body(&self) -> Option<&Self::PostBody> {
        self.terminal_history.as_ref()
    }

    fn dispose(mut self: Box<Self>) {
        let terminal = self.terminal_history.take();
        dispose_receipt_before_terminal(self, terminal);
    }

    fn into_post_body(
        mut self: Box<Self>,
    ) -> Result<
        Self::PostBody,
        Box<dyn ProductionVmCleanupHandoff<Failure = Self::Failure, PostBody = Self::PostBody>>,
    > {
        if let Some(mut body) = self.terminal_history.take() {
            if let Some(first) = self.first_failure.take() {
                body.retain_cleanup_first(first);
            }
            // Deallocate the original token before exposing the role-bearing
            // terminal value to a caller that may immediately dispose it.
            drop(self);
            return Ok(body);
        }
        if !self.report_reference {
            return Err(self);
        }
        let key = ServiceMainPreclaim {
            queue: Weak::clone(&self.queue),
            index: self.index,
            epoch: self.epoch,
        };
        match terminal::take_terminal_body(&key) {
            Ok(mut body) => {
                if let Some(first) = self.first_failure.take() {
                    body.retain_cleanup_first(first);
                }
                self.report_reference = false;
                Ok(body)
            }
            Err(_) => Err(self),
        }
    }
}

/// Keeps the role-bearing tail alive across the actual original Box drop.
///
/// The generic primitive also permits a nonissuing component drop-order control.
fn dispose_receipt_before_terminal<T, P>(receipt: Box<T>, terminal: Option<P>) {
    drop(receipt);
    drop(terminal);
}

#[cfg(test)]
mod tests;

/// Exercises the canonical cell and receipt without constructing a Main issuer.
#[cfg(test)]
pub(crate) fn component_owner_history_for_test(
    owner: Box<
        dyn ProductionVmCleanupOwner<
                Failure = crate::ProductionVmConstructionCleanupError,
                PostBody = crate::ProductionVmConstructionPostBody,
            >,
    >,
    observe_retained: impl FnOnce(),
) -> crate::ProductionVmConstructionCleanupError {
    let slot = CleanupSlot::unissued_for_test(1, CleanupPhase::Queued);
    {
        let mut cell = slot.cell.lock().unwrap();
        cell.owner = Some(owner);
        cell.handoff = true;
    }
    let mut receipt = CleanupReservation {
        queue: Weak::new(),
        index: 0,
        epoch: 1,
        observed: ProductionVmCleanupStage::BodyRetained,
        first_failure: None,
        terminal_history: None,
        report_reference: false,
    };

    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _retained = slot.cell.lock().unwrap();
        panic!("component control poisons the real cleanup cell");
    }));
    assert!(poisoned.is_err());
    assert!(slot.cell.is_poisoned());

    assert!(super::driver::retry_body_and_controls(&slot, 1).is_err());
    assert_eq!(
        receipt.observe_slot(&slot).unwrap(),
        ProductionVmCleanupStage::BodyRetained
    );
    observe_retained();
    super::driver::retry_body_and_controls(&slot, 1).unwrap();
    assert_eq!(
        receipt.observe_slot(&slot).unwrap(),
        ProductionVmCleanupStage::Complete
    );
    assert!(slot.cell.lock().unwrap().owner.is_none());
    assert_eq!(slot.body_destroyed_epoch.load(Ordering::Acquire), 1);
    receipt.first_failure.take().unwrap()
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
            PostBody = <crate::ProductionVmConstructionCustody as ProductionVmCleanupOwner>::PostBody, ReturnDestination = crate::lifecycle_cleanup::SourceBodyReturn>,
    >{
        Box::new(CleanupReservation {
            queue: Weak::new(),
            index: usize::MAX,
            epoch: 0,
            observed: ProductionVmCleanupStage::BodyRetained,
            first_failure: None,
            terminal_history: None,
            report_reference: false,
        })
    }
}

/// Selects the original Main role without issuing Service or World authority.
///
/// The actual reservation remains its sole token. This inline, move-only key
/// supplies no budget, operation, cleanup clock, cell reservation or body lease.
#[derive(Debug)]
pub(crate) struct ServiceMainPreclaim {
    pub(super) queue: Weak<LifecycleCleanupQueue>,
    pub(super) index: usize,
    pub(super) epoch: u64,
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
        if !slot.is(CleanupPhase::Reserved) || !slot.work_is_open() {
            return Err(ServiceMainPreclaimError::Role(
                "pre-Service role has entered retirement",
            ));
        }
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

/// Allocates only the original Main-paid token inside the locked producer cut.
pub(super) fn new_world_reservation(
    queue: &Weak<LifecycleCleanupQueue>,
    index: usize,
    epoch: u64,
) -> WorldLifecycleCleanupReservation {
    WorldLifecycleCleanupReservation {
        reservation: Box::new(CleanupReservation {
            queue: Weak::clone(queue),
            index,
            epoch,
            observed: ProductionVmCleanupStage::BodyRetained,
            first_failure: None,
            terminal_history: None,
            report_reference: false,
        }),
        cell: ReservedWorldCell {
            queue: Weak::clone(queue),
            index,
            epoch,
        },
    }
}

impl Drop for CleanupReservation {
    fn drop(&mut self) {
        if self.terminal_history.is_some()
            && let Some(queue) = self.queue.upgrade()
            && let Some(slot) = queue.slots.get(self.index)
            && slot.epoch.load(Ordering::Acquire) == self.epoch
        {
            // The used history guard extracts the terminal before disposing
            // this Box. A raw caller bypassing that order cannot refund a role
            // while this allocation is still alive. Terminal disposal requires
            // TerminalOwned, so it cannot reverse this quarantine afterward.
            slot.publish(CleanupPhase::DestructionRefused);
        }
        let key = ServiceMainPreclaim {
            queue: Weak::clone(&self.queue),
            index: self.index,
            epoch: self.epoch,
        };
        // No raw cause outlives the token's actual report pin.
        drop(self.first_failure.take());
        if self.report_reference {
            terminal::return_report_reference(&key, false);
            self.report_reference = false;
        }
        if let Some(queue) = key.queue.upgrade()
            && let Some(slot) = queue.slots.get(key.index)
            && slot.epoch.load(Ordering::Acquire) == key.epoch
        {
            slot.request_retirement();
        }
    }
}
