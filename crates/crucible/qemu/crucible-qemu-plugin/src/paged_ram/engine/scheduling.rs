//! Queues operational placement on genuine pauses without waiting on control I/O.
//!
//! The native single-slot mailbox retains the process-lifetime owner's callback.
//! Repeated policy updates coalesce; their original operation start remains
//! fixed until completed work or proven cancellation releases the receipt.

use super::*;

mod checkpoint;

#[derive(Default)]
pub(super) struct PlacementQueue {
    pub(super) receipt: Option<QueuedPlacement>,
    pub(super) capture: checkpoint::PlacementCapture,
    dispatching: bool,
}

type Schedule = extern "C" fn(PhysicalCallback, *mut c_void) -> c_int;
type Cancel = extern "C" fn() -> c_int;

pub(super) struct QueuedPlacement {
    operation: Arc<dyn SourceOperation>,
    pub(super) generation: u64,
    completed_work: Arc<AtomicU64>,
}

fn native_scheduler() -> Result<(Schedule, Cancel), RamError> {
    // SAFETY: these symbols have matching scalar GPL-private declarations.
    unsafe {
        Ok((
            std::mem::transmute::<*mut c_void, Schedule>(symbol(
                b"qemu_plugin_crucible_ram_schedule_placement_v1\0",
            )?),
            std::mem::transmute::<*mut c_void, Cancel>(symbol(
                b"qemu_plugin_crucible_ram_cancel_placement_v1\0",
            )?),
        ))
    }
}

fn prepare_placement_receipt(
    queue: &mut PlacementQueue,
    operations: &dyn SourceOperationFactory,
    generation: u64,
) -> Result<(), RamError> {
    if let Some(queued) = queue.receipt.as_mut() {
        queued.generation = generation;
    } else {
        queue.receipt = Some(QueuedPlacement {
            operation: Arc::from(operations.begin(SourceOperationClass::Quiescence)?),
            generation,
            completed_work: Arc::new(AtomicU64::new(0)),
        });
    }
    Ok(())
}

impl PausedPagingOwner {
    pub(super) fn schedule_reclaim(&self, generation: u64) -> Result<(), RamError> {
        let (schedule, _) = native_scheduler()?;
        let mut queued = self
            .queued_operation
            .lock()
            .map_err(|_| RamError::Invariant("placement queue unavailable"))?;
        queued.capture.require_open()?;
        prepare_placement_receipt(&mut queued, self.operations.as_ref(), generation)?;

        // The operational registry retains this owner until successful queue
        // cancellation. Child rebind occurs only after parent actors joined
        // and native fork admission proved the mailbox empty.
        let status = schedule(queued_placement, (self as *const Self).cast_mut().cast());
        if status != 0 {
            let error = RamError::Native {
                operation: "enqueue paused RAM placement",
                status,
            };
            self.retain_operational_failure(SourceOperationClass::Quiescence, &error);
            return Err(error);
        }
        Ok(())
    }

    /// Revokes queued placement before any fork barrier or worker join.
    ///
    /// # Errors
    /// Refuses an executing callback or unavailable queue; no cyclic wait occurs.
    pub(crate) fn cancel_scheduled_reclaim(&self) -> Result<(), RamError> {
        let (_, cancel) = native_scheduler()?;
        let mut queued = self
            .queued_operation
            .lock()
            .map_err(|_| RamError::Invariant("placement queue unavailable"))?;
        queued.capture.require_open()?;
        let status = cancel();
        if status != 0 {
            return Err(RamError::Native {
                operation: "cancel paused RAM placement",
                status,
            });
        }
        // Native cancellation proves mailbox disposition, not original
        // operation completion. A refused completion keeps this same receipt.
        finish_queued_receipt(&mut queued.receipt, None, || Ok(()))?;
        Ok(())
    }

    pub(super) fn execute_scheduled_before_resume(&self) -> Result<bool, RamError> {
        let (_, cancel) = native_scheduler()?;
        {
            let queued = self
                .queued_operation
                .lock()
                .map_err(|_| RamError::Invariant("placement queue unavailable"))?;
            queued.capture.require_open()?;
            if queued.receipt.is_none() {
                return Ok(false);
            }
            // Keep the same gate through the actual cancellation effect.
            let status = cancel();
            if status != 0 {
                return Err(RamError::Native {
                    operation: "claim placement before resume",
                    status,
                });
            }
        }
        self.run_queued_placement()?;
        if self
            .queued_operation
            .lock()
            .map_err(|_| RamError::Invariant("placement queue unavailable"))?
            .receipt
            .is_some()
        {
            return Err(RamError::Native {
                operation: "placement remains pending before guest resume",
                status: -libc::EAGAIN,
            });
        }
        Ok(true)
    }

    fn run_queued_placement(&self) -> Result<(), RamError> {
        {
            let mut queued = self
                .queued_operation
                .lock()
                .map_err(|_| RamError::Invariant("placement queue unavailable"))?;
            queued.require_dispatch()?;
            if queued.receipt.is_none() {
                return Ok(());
            }
            if queued.dispatching {
                return Err(RamError::Invariant("placement dispatch already retained"));
            }
            // Native mailbox state does not cover synchronous before-resume
            // dispatch. Publish this actual borrower before cloning its work.
            queued.dispatching = true;
        }
        let work = self.run_queued_placement_inner();
        finish_placement_dispatch(&self.queued_operation, work)
    }

    fn run_queued_placement_inner(&self) -> Result<(), RamError> {
        let (operation, generation, completed_work) = {
            let queued = self
                .queued_operation
                .lock()
                .map_err(|_| RamError::Invariant("placement queue unavailable"))?;
            queued.require_dispatch()?;
            let Some(queued) = queued.receipt.as_ref() else {
                return Ok(());
            };
            (
                queued.operation.clone(),
                queued.generation,
                queued.completed_work.clone(),
            )
        };
        if self.failed.load(Ordering::Acquire) {
            return Err(RamError::Invariant("failed placement authority"));
        }
        operation.wait_slice()?;
        let placement = self
            .activate_resident_with_operation(Some(operation.clone()), completed_work.clone())
            .and_then(|()| self.reclaim_with_operation(Some(operation.clone()), completed_work));
        if let Err(error) = placement {
            if matches!(&error, RamError::Native { status, .. }
                if *status == -libc::EAGAIN || *status == -libc::EBUSY)
            {
                let (schedule, _) = native_scheduler()?;
                let queued = self
                    .queued_operation
                    .lock()
                    .map_err(|_| RamError::Invariant("placement queue unavailable"))?;
                if queued.capture.is_held() {
                    // The unfinished accepted receipt stays held; native
                    // disposition restores it after the capture transaction.
                    return Ok(());
                }
                let status = schedule(queued_placement, (self as *const Self).cast_mut().cast());
                if status == 0 {
                    return Ok(());
                }
                return Err(RamError::Native {
                    operation: "retry paused placement",
                    status,
                });
            }
            return Err(error);
        }
        operation.wait_slice()?;

        let mut queued = self
            .queued_operation
            .lock()
            .map_err(|_| RamError::Invariant("placement queue unavailable"))?;
        queued.finish_receipt(generation, || self.complete_placement_receipt(generation))?;
        Ok(())
    }
}

// The initiating work failure remains primary when final ownership is
// poisoned. An unavailable final owner leaves dispatching retained; only a
// successful work result may return the cleanup refusal as its first cause.
fn finish_placement_dispatch(
    queue: &Mutex<PlacementQueue>,
    work: Result<(), RamError>,
) -> Result<(), RamError> {
    match queue.lock() {
        Ok(mut queue) => {
            queue.dispatching = false;
            work
        }
        Err(_) => match work {
            Err(first) => Err(first),
            Ok(()) => Err(RamError::Invariant("placement queue unavailable")),
        },
    }
}

// The caller owns the actual queue mutex. Original completion and evidence
// publication both succeed before it removes the sole queued receipt. A later
// failure can leave a terminal operation retained, which requires containment;
// it never becomes an empty queue proving successful settlement.
fn finish_queued_receipt(
    queued: &mut Option<QueuedPlacement>,
    generation: Option<u64>,
    publish: impl FnOnce() -> Result<(), RamError>,
) -> Result<(), RamError> {
    let Some(receipt) = queued.as_ref() else {
        return Ok(());
    };
    if generation.is_some_and(|expected| expected != receipt.generation) {
        return Ok(());
    }
    receipt.operation.complete()?;
    publish()?;
    queued.take();
    Ok(())
}

extern "C" fn queued_placement(opaque: *mut c_void) -> c_int {
    // SAFETY: native mailbox custody and the operational registry retain this
    // exact owner through callback completion or proven cancellation.
    let owner = unsafe { &*opaque.cast::<PausedPagingOwner>() };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        owner.run_queued_placement()
    })) {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => {
            owner.retain_operational_failure(SourceOperationClass::Quiescence, &error);
            -libc::EIO
        }
        Err(_) => {
            owner.retain_operational_failure(
                SourceOperationClass::Quiescence,
                &RamError::Invariant("paused placement callback panicked"),
            );
            -libc::EIO
        }
    }
}

#[cfg(test)]
mod tests;
