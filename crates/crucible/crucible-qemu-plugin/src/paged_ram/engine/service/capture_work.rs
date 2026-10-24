//! Retains a claimed kernel fault, original operation and scratch until settlement.
//!
//! The single fault actor claims one event at a time. An unsuccessful request
//! stays in the preallocated body, including its original operation claim. A
//! stopped thread or a zero live-token count cannot substitute for settlement.
//! This owner does not issue a capture acknowledgement: the native capture loan,
//! policy mailbox disposition and source-version fence remain separate joins.
//!
//! SPDX-License-Identifier: GPL-2.0-or-later

use std::ops::{Deref, DerefMut};
use std::sync::{Mutex, MutexGuard, TryLockError};

mod eviction;
mod pause;
pub(in crate::paged_ram::engine) mod physical_end;
use pause::FaultPause;

use super::*;
use crate::paged_ram::kernel::{FaultReceipt, Registration};
use crucible_ram::{MetadataBudget, MetadataReservation};

/// Keeps one sequential request and its actual authentication scratch together.
pub(super) struct ClaimedFault {
    event: FaultEvent,
    operation: Option<Box<dyn SourceOperation>>,
}

/// Owns the physical buffer even when no operation could be admitted.
pub(in crate::paged_ram::engine) struct FaultWork {
    claimed: Option<ClaimedFault>,
    receipt: FaultReceipt,
    scratch: [u8; PAGE_BYTES],
    eviction: Option<eviction::EvictionJournal>,
    failed: bool,
}

impl FaultWork {
    /// Retains every consumed kernel byte before decoding or operation admission.
    ///
    /// # Errors
    /// Refuses unresolved custody or retains a malformed/failed kernel read.
    pub(super) fn read_fault(
        &mut self,
        registration: &Registration,
    ) -> Result<Option<FaultEvent>, RamError> {
        if self.unresolved() {
            return Err(RamError::Invariant("fault request remains unsettled"));
        }
        match registration.read_fault(&mut self.receipt) {
            Ok(event) => Ok(event),
            Err(error) => {
                self.fail();
                Err(RamError::from(error))
            }
        }
    }

    /// Publishes the consumed kernel event before any fallible admission.
    ///
    /// # Errors
    /// Refuses an unsettled request or retains the original admission refusal.
    pub(super) fn claim(
        &mut self,
        event: FaultEvent,
        operations: &dyn SourceOperationFactory,
    ) -> Result<(), RamError> {
        if self.claimed.is_some() || self.eviction.is_some() || self.failed {
            return Err(RamError::Invariant("fault request remains unsettled"));
        }
        self.claimed = Some(ClaimedFault {
            event,
            operation: None,
        });
        let operation = match operations.begin(SourceOperationClass::PageIn) {
            Ok(operation) => operation,
            Err(error) => {
                let error = RamError::from(error);
                self.fail();
                return Err(error);
            }
        };
        let claim = self
            .claimed
            .as_mut()
            .ok_or("claimed fault disappeared during admission")?;
        claim.operation = Some(operation);
        Ok(())
    }

    /// Borrows the same operation and physical buffer through synchronous work.
    ///
    /// # Errors
    /// Refuses missing request or original operation custody.
    pub(super) fn request(
        &mut self,
    ) -> Result<(FaultEvent, &dyn SourceOperation, &mut [u8; PAGE_BYTES]), RamError> {
        let claim = self.claimed.as_ref().ok_or("fault request absent")?;
        let operation = claim
            .operation
            .as_deref()
            .ok_or("fault operation was not admitted")?;
        Ok((claim.event, operation, &mut self.scratch))
    }

    /// Completes the original operation before removing its settled request.
    ///
    /// # Errors
    /// Refuses prior uncertainty or retains original completion refusal.
    pub(super) fn settled(&mut self) -> Result<(), RamError> {
        if self.failed
            || self.eviction.is_some()
            || self
                .claimed
                .as_ref()
                .is_none_or(|claim| claim.operation.is_none())
        {
            return Err(RamError::Invariant("fault request cannot be settled"));
        }
        let operation = self
            .claimed
            .as_ref()
            .and_then(|claim| claim.operation.as_deref())
            .ok_or("fault operation disappeared before completion")?;
        if let Err(error) = operation.complete() {
            let error = RamError::from(error);
            self.fail();
            return Err(error);
        }
        self.claimed.take();
        self.receipt.clear_after_settlement();
        self.scratch.fill(0);
        Ok(())
    }

    /// Borrows the paid buffer only between fully settled requests/evictions.
    ///
    /// # Errors
    /// Refuses unresolved physical effects, a consumed event or prior failure.
    pub(in crate::paged_ram::engine) fn idle_scratch(
        &mut self,
    ) -> Result<&mut [u8; PAGE_BYTES], RamError> {
        if self.unresolved() {
            return Err(RamError::Invariant("fault work remains unsettled"));
        }
        Ok(&mut self.scratch)
    }

    /// Marks uncertainty without duplicating the actor's actual first cause.
    ///
    /// The existing actor/placement failure owner retains that cause. This flag
    /// keeps custody closed even after the actor has physically returned.
    pub(super) fn fail(&mut self) {
        self.failed = true;
    }

    fn unresolved(&self) -> bool {
        self.claimed.is_some() || self.receipt.retained() || self.eviction.is_some() || self.failed
    }
}

// The lock-independent pause gate and locked request share one admitted
// allocation. Requesting a pause cannot wait behind backing I/O in `work`.
struct FaultWorkAllocation {
    pause: FaultPause,
    lifecycle: std::sync::atomic::AtomicU8,
    placement: AtomicBool,
    scratch_returned: AtomicBool,
    end_pending: AtomicBool,
    end_failed: AtomicBool,
    end: Mutex<physical_end::PhysicalEndCustody>,
    dispatch: PlacementDispatchJournal,
    work: Mutex<FaultWork>,
}

/// Retains actual placement call history independently of signed late failures.
///
/// These facts never issue Source or native physical-return authority. In
/// particular, a negative end records uncertainty rather than continued physical
/// exclusion. The existing body owns this inline history through failed Drop.
#[derive(Default)]
pub(in crate::paged_ram::engine) struct PlacementDispatchJournal {
    pub(in crate::paged_ram::engine) runner_entered: AtomicBool,
    pub(in crate::paged_ram::engine) runner_returned: AtomicBool,
    pub(in crate::paged_ram::engine) runner_status: std::sync::atomic::AtomicI32,
    pub(in crate::paged_ram::engine) callback_entered: AtomicBool,
    pub(in crate::paged_ram::engine) callback_returned: AtomicBool,
    pub(in crate::paged_ram::engine) callback_post_failed: AtomicBool,
    pub(in crate::paged_ram::engine) callback_status: std::sync::atomic::AtomicI32,
    pub(in crate::paged_ram::engine) begin_entered: AtomicBool,
    pub(in crate::paged_ram::engine) begin_returned: AtomicBool,
    pub(in crate::paged_ram::engine) begin_status: std::sync::atomic::AtomicI32,
    pub(in crate::paged_ram::engine) token: AtomicU64,
    pub(in crate::paged_ram::engine) end_entered: AtomicBool,
    pub(in crate::paged_ram::engine) end_returned: AtomicBool,
    pub(in crate::paged_ram::engine) end_status: std::sync::atomic::AtomicI32,
    pub(in crate::paged_ram::engine) action_completed: AtomicBool,
    pub(in crate::paged_ram::engine) settled: AtomicBool,
    first_negative: std::sync::atomic::AtomicI32,
}

impl PlacementDispatchJournal {
    /// Starts new bookkeeping only after the preceding real dispatch settled.
    ///
    /// # Errors
    /// Refuses to erase an actual incomplete/failed native invocation.
    pub(in crate::paged_ram::engine) fn reset(&self) -> Result<(), RamError> {
        if self.unresolved() {
            return Err(RamError::Invariant(
                "prior placement dispatch remains unsettled",
            ));
        }
        for flag in [
            &self.runner_entered,
            &self.runner_returned,
            &self.callback_entered,
            &self.callback_returned,
            &self.callback_post_failed,
            &self.begin_entered,
            &self.begin_returned,
            &self.end_entered,
            &self.end_returned,
            &self.action_completed,
            &self.settled,
        ] {
            flag.store(false, Ordering::Release);
        }
        for status in [
            &self.runner_status,
            &self.callback_status,
            &self.begin_status,
            &self.end_status,
            &self.first_negative,
        ] {
            status.store(0, Ordering::Release);
        }
        self.token.store(0, Ordering::Release);
        Ok(())
    }

    /// Saves the first signed refusal while later actual statuses stay separate.
    pub(in crate::paged_ram::engine) fn record_first_negative(&self, status: i32) {
        if status < 0 {
            let _ = self.first_negative.compare_exchange(
                0,
                status,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
    }

    /// Allows only bounded refusal retries before any physical-end attempt.
    ///
    /// A zero token after completed end is not pre-entry evidence. Unknown
    /// partial end and late runner posts cannot authorize replay.
    pub(in crate::paged_ram::engine) fn retry_before_action(
        &self,
        status: i32,
        token: u64,
    ) -> bool {
        token == 0
            && !self.callback_post_failed.load(Ordering::Acquire)
            && !self.end_entered.load(Ordering::Acquire)
            && !self.action_completed.load(Ordering::Acquire)
            && matches!(status, value if value == -libc::EAGAIN || value == -libc::EBUSY)
    }

    /// Reports unfinished bookkeeping, never continuing physical exclusion.
    pub(in crate::paged_ram::engine) fn unresolved(&self) -> bool {
        self.runner_entered.load(Ordering::Acquire) && !self.settled.load(Ordering::Acquire)
    }
}

/// Keeps fault-consumption deferral closed until the actual scratch loan returns.
///
/// Dropping this admission does not reopen a failed physical transaction. It
/// owns no allocation; the retained inline gate/body keeps its existing credit.
pub(in crate::paged_ram::engine) struct PlacementWork<'a> {
    work: MutexGuard<'a, FaultWork>,
    returned: &'a AtomicBool,
}

impl Deref for PlacementWork<'_> {
    type Target = FaultWork;

    fn deref(&self) -> &Self::Target {
        &self.work
    }
}

impl DerefMut for PlacementWork<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.work
    }
}

impl PlacementWork<'_> {
    /// Returns settled scratch custody while retaining physical-end deferral.
    ///
    /// Only the actual same-token native return receipt can reopen the gate.
    ///
    /// # Errors
    /// Refuses unresolved event/Original/journal custody and leaves admission shut.
    pub(in crate::paged_ram::engine) fn return_at_boundary(self) -> Result<(), RamError> {
        if self.work.unresolved() {
            return Err(RamError::Invariant(
                "placement fault work remains unsettled",
            ));
        }
        let Self { work, returned } = self;
        drop(work);
        returned.store(true, Ordering::Release);
        Ok(())
    }
}

/// Keeps the paid body separate from its credit through physical destruction.
pub(in crate::paged_ram::engine) struct FaultWorkOwner {
    body: Option<Box<FaultWorkAllocation>>,
    reservation: Option<MetadataReservation>,
}

impl FaultWorkOwner {
    /// Reserves the actual fixed body before allocating it or claiming a fault.
    ///
    /// # Errors
    /// Refuses insufficient same-owner metadata or an unrepresentable extent.
    pub(in crate::paged_ram::engine) fn prepare(budget: &MetadataBudget) -> Result<Self, RamError> {
        let extent = Self::required_metadata_bytes()?;
        let reservation = budget.reserve_bytes(extent)?;
        let end = physical_end::PhysicalEndCustody::new()?;
        let body = Box::new(FaultWorkAllocation {
            pause: FaultPause::default(),
            lifecycle: std::sync::atomic::AtomicU8::new(physical_end::LIFECYCLE_IDLE),
            placement: AtomicBool::new(false),
            scratch_returned: AtomicBool::new(false),
            end_pending: AtomicBool::new(false),
            end_failed: AtomicBool::new(false),
            end: Mutex::new(end),
            dispatch: PlacementDispatchJournal::default(),
            work: Mutex::new(FaultWork {
                claimed: None,
                receipt: FaultReceipt::default(),
                scratch: [0; PAGE_BYTES],
                eviction: None,
                failed: false,
            }),
        });
        Ok(Self {
            body: Some(body),
            reservation: Some(reservation),
        })
    }

    /// Returns the exact declared extent of this component's distinct allocation.
    ///
    /// # Errors
    /// Refuses an extent that cannot be represented by the metadata account.
    pub(in crate::paged_ram::engine) fn required_metadata_bytes() -> Result<u64, RamError> {
        u64::try_from(std::mem::size_of::<FaultWorkAllocation>())
            .map_err(|_| RamError::Invariant("fault work metadata extent overflow"))
    }

    /// Requests a worker-boundary pause for an already authenticated transaction.
    ///
    /// This scalar is never an issuer. The checkpoint-only native callback must
    /// authenticate and retain its actual context before calling this method.
    ///
    /// # Errors
    /// Refuses zero/reused epochs, a different held pause or uncertain ingress.
    pub(in crate::paged_ram::engine) fn request_pause(&self, epoch: u64) -> Result<(), RamError> {
        self.body
            .as_ref()
            .ok_or("fault work body absent")?
            .pause
            .request(epoch)
    }

    /// Inspects acknowledgement without borrowing a busy fault request body.
    ///
    /// This describes only the fault actor's boundary. Native worker membership,
    /// source-version fencing, policy/mailbox and original loan checks remain
    /// necessary before a checkpoint transaction can report readiness.
    pub(in crate::paged_ram::engine) fn pause_acknowledged(&self, epoch: u64) -> bool {
        self.body
            .as_ref()
            .is_some_and(|body| body.pause.acknowledged(epoch))
    }

    /// Reopens consumption after authenticated disposition of this held epoch.
    ///
    /// # Errors
    /// Refuses a different epoch or a worker that has not acknowledged its cut.
    pub(in crate::paged_ram::engine) fn release_pause(&self, epoch: u64) -> Result<(), RamError> {
        self.body
            .as_ref()
            .ok_or("fault work body absent")?
            .pause
            .release(epoch)
    }

    pub(in crate::paged_ram::engine) fn request_ordinary_pause(
        &self,
        identity: u64,
    ) -> Result<(), RamError> {
        self.body
            .as_ref()
            .ok_or("fault work body absent")?
            .pause
            .request_ordinary(identity)
    }

    pub(in crate::paged_ram::engine) fn ordinary_pause_acknowledged(&self, identity: u64) -> bool {
        self.body
            .as_ref()
            .is_some_and(|body| body.pause.ordinary_acknowledged(identity))
    }

    pub(in crate::paged_ram::engine) fn return_ordinary_pause(
        &self,
        identity: u64,
    ) -> Result<(), RamError> {
        self.body
            .as_ref()
            .ok_or("fault work body absent")?
            .pause
            .return_ordinary(identity)
    }

    /// Acknowledges the actor cut between completion and the next kernel read.
    ///
    /// Only the fault actor calls this while holding its actual request body.
    ///
    /// # Errors
    /// Refuses absent body ownership or unresolved consumed-event custody.
    pub(super) fn acknowledge_pause_at_boundary(&self, work: &FaultWork) -> Result<bool, RamError> {
        self.body
            .as_ref()
            .ok_or("fault work body absent")?
            .pause
            .boundary(work.unresolved())
    }

    /// Checks actual request/journal custody after physical actor join.
    ///
    /// # Errors
    /// Refuses a busy body or any unresolved fault/eviction before fork transfer.
    pub(in crate::paged_ram::engine) fn check_settled(&self) -> Result<(), RamError> {
        let body = self.body.as_ref().ok_or("fault work body absent")?;
        if body.lifecycle.load(Ordering::Acquire) != physical_end::LIFECYCLE_IDLE
            || body.placement.load(Ordering::Acquire)
            || body.end_pending.load(Ordering::Acquire)
            || body.end_failed.load(Ordering::Acquire)
            || body.dispatch.unresolved()
            || body.end.try_lock().map_or(true, |custody| custody.unresolved())
            || self.try_lock()?.unresolved()
        {
            return Err(RamError::Invariant("fault work remains unsettled"));
        }
        Ok(())
    }

    /// Defers the actor only for an actual same-service physical placement.
    ///
    /// The inline flag prevents legitimate loan contention from killing the
    /// actor. Only the real mutex and settled journal admit scratch use. A busy
    /// or unresolved request refuses without waiting under Native/BQL locks.
    ///
    /// # Errors
    /// Refuses a foreign native/service owner, held capture, contention or
    /// unsettled kernel effects. After admission, refusal retains the gate.
    pub(in crate::paged_ram::engine) fn placement_work<'a>(
        &'a self,
        placement: &super::super::placement::PhysicalPlacement<'_>,
    ) -> Result<PlacementWork<'a>, RamError> {
        if !std::ptr::eq(self, &placement.service.capture_work) {
            return Err(RamError::Invariant("placement fault-work owner changed"));
        }
        let status = (placement.service.native.validate)(placement.token, placement.generation);
        if status != 0 {
            return Err(RamError::Native {
                operation: "placement scratch physical owner",
                status,
            });
        }
        let body = self.body.as_ref().ok_or("fault work body absent")?;
        if body.pause.held() {
            return Err(RamError::Invariant("capture retains fault work"));
        }
        body.placement
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| RamError::Invariant("placement fault work remains held"))?;
        body.scratch_returned.store(false, Ordering::Release);
        let work = self.try_lock()?;
        if body.pause.held() || work.unresolved() {
            return Err(RamError::Invariant(
                "placement fault work remains unsettled",
            ));
        }
        Ok(PlacementWork {
            work,
            returned: &body.scratch_returned,
        })
    }

    /// Borrows the fixed actual-run history without issuing physical authority.
    ///
    /// # Errors
    /// Refuses an absent paid body before a native operation can be invoked.
    pub(in crate::paged_ram::engine) fn placement_dispatch(
        &self,
    ) -> Result<&PlacementDispatchJournal, RamError> {
        Ok(&self.body.as_ref().ok_or("fault work body absent")?.dispatch)
    }

    /// Borrows event custody unless actual physical placement has deferred it.
    ///
    /// # Errors
    /// Refuses poison or contention outside the authenticated placement gate.
    pub(super) fn try_lock_for_fault(&self) -> Result<Option<MutexGuard<'_, FaultWork>>, RamError> {
        let body = self.body.as_ref().ok_or("fault work body absent")?;
        if body.placement.load(Ordering::Acquire) {
            return Ok(None);
        }
        match body.work.try_lock() {
            Ok(_work) if body.placement.load(Ordering::Acquire) => Ok(None),
            Ok(work) => Ok(Some(work)),
            Err(TryLockError::WouldBlock) if body.placement.load(Ordering::Acquire) => Ok(None),
            Err(_) => Err(RamError::Invariant("fault work custody unavailable")),
        }
    }

    /// Borrows the unique fault actor's body without waiting on another owner.
    ///
    /// # Errors
    /// Refuses contention, poisoned custody or an absent body.
    pub(in crate::paged_ram::engine) fn try_lock(
        &self,
    ) -> Result<MutexGuard<'_, FaultWork>, RamError> {
        self.body
            .as_ref()
            .ok_or("fault work body absent")?
            .work
            .try_lock()
            .map_err(|_| RamError::Invariant("fault work custody unavailable"))
    }
}

impl Drop for FaultWorkOwner {
    fn drop(&mut self) {
        let unresolved = self.body.as_ref().is_some_and(|body| {
            body.pause.held()
                || body.lifecycle.load(Ordering::Acquire) != physical_end::LIFECYCLE_IDLE
                || body.placement.load(Ordering::Acquire)
                || body.end_pending.load(Ordering::Acquire)
                || body.end_failed.load(Ordering::Acquire)
                || body.dispatch.unresolved()
                || body.end.try_lock().map_or(true, |custody| custody.unresolved())
                || body.work.try_lock().map_or(true, |work| work.unresolved())
        });
        if unresolved {
            // No caller here proves physical process retirement. Preserve the
            // existing allocation and original claim, with its same credit.
            // Kernel teardown at real process exit is the final containment cut.
            if let Some(body) = self.body.take() {
                std::mem::forget(body);
            }
            if let Some(reservation) = self.reservation.take() {
                std::mem::forget(reservation);
            }
            return;
        }
        drop(self.body.take());
        drop(self.reservation.take());
    }
}

#[cfg(test)]
mod tests;
