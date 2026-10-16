//! Retains complete lifecycle owners in Main-prepaid, epoch-bound cleanup cells.
//!
//! Main owns the queue outside the shared factory graph. Factories and handoff
//! reservations are weak, including when a Target retains its parent Source.
//! Atomic phase arbitration keeps publication independent of queue scans. A cell
//! returns only after actual owner destruction and containing-body charge return.

use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use crucible::SchedulerError;
use crucible_api::{
    LifecycleApiError, ProductionVmCleanupHandoff, ProductionVmCleanupOwner,
    ProductionVmCleanupReservation, ProductionVmCleanupStage,
};
use crucible_linux_resource::host_services::process_birth::{
    AuthenticatedNativePoolPurpose, AuthenticatedNativeWorldControlLease,
};

mod reservation;
use reservation::CleanupReservation;
#[cfg(test)]
pub(crate) use reservation::component_owner_history_for_test;

/// Owns fixed cleanup storage beneath the actual containing Main pool.
pub(crate) struct LifecycleCleanupQueue {
    slots: Vec<CleanupSlot>,
    _pool: AuthenticatedNativePoolPurpose,
}

/// Lends nonowning access without a queue -> owner -> factory cycle.
#[derive(Clone)]
pub(crate) struct LifecycleCleanupHandle {
    queue: Weak<LifecycleCleanupQueue>,
}

struct CleanupSlot {
    phase: AtomicU8,
    body_destroyed_epoch: AtomicU64,
    completed_epoch: AtomicU64,
    cell: Mutex<CleanupCell>,
}

struct CleanupCell {
    epoch: u64,
    owner: Option<
        Box<dyn ProductionVmCleanupOwner<Failure = crate::ProductionVmConstructionCleanupError>>,
    >,
    controls: Option<AuthenticatedNativeWorldControlLease>,
    first_failure: Option<crate::ProductionVmConstructionCleanupError>,
    handoff: bool,
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum CleanupPhase {
    Free,
    Reserving,
    Reserved,
    Publishing,
    Queued,
    Retrying,
    Destroying,
    OwnerDestroyed,
    Closed,
    Completing,
    DestructionRefused,
}

impl CleanupSlot {
    fn claim(&self, from: CleanupPhase, to: CleanupPhase) -> bool {
        self.phase
            .compare_exchange(from as u8, to as u8, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn publish(&self, phase: CleanupPhase) {
        self.phase.store(phase as u8, Ordering::Release);
    }

    fn is(&self, phase: CleanupPhase) -> bool {
        self.phase.load(Ordering::Acquire) == phase as u8
    }
}

impl LifecycleCleanupQueue {
    /// Prices all actual cells and simultaneously retained reservation bodies.
    ///
    /// The producer derives the count from occupied Source/primary/auxiliary
    /// roles and includes this extent in the SAME Main before queue birth.
    pub(crate) fn control_bytes(slots: usize) -> Result<u64, LifecycleApiError> {
        if slots == 0 {
            return Err(refusal("cleanup ownership capacity is absent"));
        }
        let cells = std::alloc::Layout::array::<CleanupSlot>(slots)
            .map_err(|_| refusal("cleanup cell extent overflows"))?;
        let handles = std::alloc::Layout::array::<CleanupReservation>(slots)
            .map_err(|_| refusal("cleanup reservation extent overflows"))?;
        let (shared, _) = std::alloc::Layout::new::<(usize, usize)>()
            .extend(std::alloc::Layout::new::<Self>())
            .map_err(|_| refusal("cleanup shared owner extent overflows"))?;
        let bytes = shared
            .pad_to_align()
            .size()
            .checked_add(cells.size())
            .and_then(|bytes| bytes.checked_add(handles.size()))
            .ok_or_else(|| refusal("cleanup containing extent overflows"))?;
        u64::try_from(bytes).map_err(|_| refusal("cleanup extent is not representable"))
    }

    /// Constructs the one queue after the real containing producer paid it.
    pub(crate) fn new_prepaid(
        pool: AuthenticatedNativePoolPurpose,
        slots: usize,
    ) -> Result<Arc<Self>, LifecycleApiError> {
        Self::control_bytes(slots)?;
        let mut cells = Vec::new();
        cells
            .try_reserve_exact(slots)
            .map_err(|_| refusal("cleanup cell allocation refused"))?;
        cells.resize_with(slots, || CleanupSlot {
            phase: AtomicU8::new(CleanupPhase::Free as u8),
            body_destroyed_epoch: AtomicU64::new(0),
            completed_epoch: AtomicU64::new(0),
            cell: Mutex::new(CleanupCell {
                epoch: 0,
                owner: None,
                controls: None,
                first_failure: None,
                handoff: false,
            }),
        });
        Ok(Arc::new(Self {
            slots: cells,
            _pool: pool,
        }))
    }

    pub(crate) fn handle(self: &Arc<Self>) -> LifecycleCleanupHandle {
        LifecycleCleanupHandle {
            queue: Arc::downgrade(self),
        }
    }

    /// Retries each retained owner once through its existing saved Cleanup.
    ///
    /// Reserved/publishing cells are never locked by a drain. Callbacks retain
    /// their actual owner in the claimed cell; recursive drains observe Retrying
    /// and return pending. Actual owner destruction happens outside every mutex.
    pub(crate) fn retry_pending(&self) -> Result<(), LifecycleApiError> {
        let mut refused = false;
        for slot in &self.slots {
            // Closed handoffs await their actual receipt's acknowledgement.
            // Global drain cannot discard that epoch's first failure or make
            // a dormant receipt accidentally select a later owner.
            refused |= retry_slot(slot, None).is_err() || !slot.is(CleanupPhase::Free);
        }
        if refused {
            Err(refusal("lifecycle cleanup remains owned or pending"))
        } else {
            Ok(())
        }
    }

    /// Refuses retirement without borrowing any publication-owned cell.
    pub(crate) fn verify_empty(&self) -> Result<(), LifecycleApiError> {
        if self.slots.iter().all(|slot| slot.is(CleanupPhase::Free)) {
            Ok(())
        } else {
            Err(refusal("cleanup ownership has not physically returned"))
        }
    }
}

/// Drives one claimed cell; an exact receipt never visits its siblings.
fn retry_slot(slot: &CleanupSlot, expected_epoch: Option<u64>) -> Result<(), LifecycleApiError> {
    if slot.is(CleanupPhase::Free) || slot.is(CleanupPhase::Closed) {
        return Ok(());
    }
    if slot.claim(CleanupPhase::OwnerDestroyed, CleanupPhase::Completing) {
        let (mut cell, poisoned) = match slot.cell.lock() {
            Ok(cell) => (cell, false),
            Err(poison) => (poison.into_inner(), true),
        };
        if expected_epoch.is_some_and(|expected| expected != cell.epoch) {
            drop(cell);
            slot.publish(CleanupPhase::OwnerDestroyed);
            return Err(refusal("cleanup handoff epoch is stale"));
        }
        if poisoned {
            slot.publish(CleanupPhase::DestructionRefused);
            return Err(refusal("cleanup charge-return ownership is poisoned"));
        }
        let returned = close_controls_retaining_failure(&mut cell);
        publish_return(slot, returned.is_ok());
        return returned;
    }
    if !slot.claim(CleanupPhase::Queued, CleanupPhase::Retrying) {
        return Err(refusal("exact cleanup ownership remains pending"));
    }
    let (mut cell, poisoned) = match slot.cell.lock() {
        Ok(cell) => (cell, false),
        Err(poison) => (poison.into_inner(), true),
    };
    if expected_epoch.is_some_and(|expected| expected != cell.epoch) {
        drop(cell);
        slot.publish(CleanupPhase::Queued);
        return Err(refusal("cleanup handoff epoch is stale"));
    }
    if poisoned {
        if cell.owner.is_none() {
            slot.publish(CleanupPhase::DestructionRefused);
            return Err(refusal("poisoned cleanup cell has no retained owner"));
        }
        cell.first_failure.get_or_insert_with(|| {
            SchedulerError::BoundaryViolation {
                message: String::from("retained lifecycle cleanup cell was poisoned"),
            }
            .into()
        });
        slot.cell.clear_poison();
    }
    let Some(owner) = cell.owner.as_mut() else {
        slot.publish(CleanupPhase::DestructionRefused);
        return Err(refusal("cleanup cell lost its actual owner"));
    };
    let attempted =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| owner.retry_cleanup()));
    let error = match attempted {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(error),
        Err(_) => Some(
            SchedulerError::BoundaryViolation {
                message: String::from("retained lifecycle cleanup panicked"),
            }
            .into(),
        ),
    };
    if let Some(error) = error {
        crate::ProductionVmConstructionCleanupError::retain_first(&mut cell.first_failure, error);
        drop(cell);
        slot.publish(CleanupPhase::Queued);
        return Err(refusal("exact lifecycle cleanup remains retained"));
    }
    let epoch = cell.epoch;
    let owner = cell.owner.take();
    drop(cell);
    slot.publish(CleanupPhase::Destroying);

    let destroyed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(owner)));
    let mut cell = match slot.cell.lock() {
        Ok(cell) => cell,
        Err(_) => {
            slot.publish(CleanupPhase::DestructionRefused);
            return Err(refusal("cleanup destruction ownership is poisoned"));
        }
    };
    if cell.epoch != epoch || cell.owner.is_some() || !slot.is(CleanupPhase::Destroying) {
        slot.publish(CleanupPhase::DestructionRefused);
        return Err(refusal("cleanup destruction epoch or owner changed"));
    }
    if destroyed.is_err() {
        cell.first_failure.get_or_insert_with(|| {
            SchedulerError::BoundaryViolation {
                message: String::from("retained lifecycle destruction panicked"),
            }
            .into()
        });
        drop(cell);
        slot.publish(CleanupPhase::DestructionRefused);
        return Err(refusal("actual cleanup body destruction is uncertain"));
    }
    slot.body_destroyed_epoch.store(epoch, Ordering::Release);
    let returned = close_controls_retaining_failure(&mut cell);
    publish_return(slot, returned.is_ok());
    returned
}

/// Keeps handoff history occupied until its same receipt takes custody of it.
fn publish_return(slot: &CleanupSlot, returned: bool) {
    if !returned {
        slot.publish(CleanupPhase::OwnerDestroyed);
    } else {
        slot.publish(CleanupPhase::Closed);
    }
}

/// Keeps an actual body-charge refusal separate from the body's closure fact.
fn close_controls_retaining_failure(cell: &mut CleanupCell) -> Result<(), LifecycleApiError> {
    let returned = close_controls(cell);
    if let Err(cause) = &returned {
        cell.first_failure.get_or_insert_with(|| {
            SchedulerError::BoundaryViolation {
                message: cause.to_string(),
            }
            .into()
        });
    }
    returned
}

/// Returns the same body assignment only after actual containing destruction.
fn close_controls(cell: &mut CleanupCell) -> Result<(), LifecycleApiError> {
    if cell.owner.is_some() {
        return Err(refusal("containing owner has not been destroyed"));
    }
    if let Some(controls) = cell.controls.as_mut() {
        controls
            .close_after_owner_destruction()
            .map_err(|_| refusal("containing World body return is uncertain"))?;
    }
    drop(cell.controls.take());
    Ok(())
}

fn refusal(message: &'static str) -> LifecycleApiError {
    LifecycleApiError::LoopFactory {
        message: String::from(message),
    }
}
