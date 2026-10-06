//! Queues operational placement on genuine pauses without waiting on control I/O.
//!
//! The native single-slot mailbox retains the process-lifetime owner's callback.
//! Repeated policy updates coalesce; their original operation start remains
//! fixed until completed work or proven cancellation releases the receipt.

use super::*;

type Schedule = extern "C" fn(PhysicalCallback, *mut c_void) -> c_int;
type Cancel = extern "C" fn() -> c_int;

pub(super) struct QueuedPlacement {
    operation: Arc<dyn SourceOperation>,
    generation: u64,
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

impl PausedPagingOwner {
    pub(super) fn schedule_reclaim(&self, generation: u64) -> Result<(), RamError> {
        let (schedule, _) = native_scheduler()?;
        let mut queued = self
            .queued_operation
            .lock()
            .map_err(|_| RamError::Invariant("placement queue unavailable"))?;
        if let Some(queued) = queued.as_mut() {
            queued.generation = generation;
        } else {
            *queued = Some(QueuedPlacement {
                operation: Arc::from(self.operations.begin(SourceOperationClass::Quiescence)?),
                generation,
                completed_work: Arc::new(AtomicU64::new(0)),
            });
        }

        // The operational registry retains this owner until successful queue
        // cancellation. Child rebind occurs only after parent actors joined
        // and native fork admission proved the mailbox empty.
        let status = schedule(queued_placement, (self as *const Self).cast_mut().cast());
        if status != 0 {
            self.failed.store(true, Ordering::Release);
            return Err(RamError::Native {
                operation: "enqueue paused RAM placement",
                status,
            });
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
        let status = cancel();
        if status != 0 {
            return Err(RamError::Native {
                operation: "cancel paused RAM placement",
                status,
            });
        }
        let receipt = queued.take();
        drop(queued);
        if let Some(receipt) = receipt {
            receipt.operation.complete()?;
        }
        Ok(())
    }

    pub(super) fn execute_scheduled_before_resume(&self) -> Result<bool, RamError> {
        let queued = self
            .queued_operation
            .lock()
            .map_err(|_| RamError::Invariant("placement queue unavailable"))?
            .is_some();
        if !queued {
            return Ok(false);
        }
        let (_, cancel) = native_scheduler()?;
        let status = cancel();
        if status != 0 {
            return Err(RamError::Native {
                operation: "claim placement before resume",
                status,
            });
        }
        self.run_queued_placement()?;
        if self
            .queued_operation
            .lock()
            .map_err(|_| RamError::Invariant("placement queue unavailable"))?
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
        let (operation, generation, completed_work) = {
            let queued = self
                .queued_operation
                .lock()
                .map_err(|_| RamError::Invariant("placement queue unavailable"))?;
            let Some(queued) = queued.as_ref() else {
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

        let receipt = {
            let mut queued = self
                .queued_operation
                .lock()
                .map_err(|_| RamError::Invariant("placement queue unavailable"))?;
            if queued
                .as_ref()
                .is_some_and(|queued| queued.generation == generation)
            {
                queued.take()
            } else {
                None
            }
        };
        if let Some(receipt) = receipt {
            receipt.operation.complete()?;
        }
        Ok(())
    }
}

extern "C" fn queued_placement(opaque: *mut c_void) -> c_int {
    // SAFETY: native mailbox custody and the operational registry retain this
    // exact owner through callback completion or proven cancellation.
    let owner = unsafe { &*opaque.cast::<PausedPagingOwner>() };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        owner.run_queued_placement()
    })) {
        Ok(Ok(())) => 0,
        _ => {
            owner.failed.store(true, Ordering::Release);
            -libc::EIO
        }
    }
}
