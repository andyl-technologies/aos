//! Retains a claimed kernel fault, original operation and scratch until settlement.
//!
//! The single fault actor claims one event at a time. An unsuccessful request
//! stays in the preallocated body, including its original operation claim. A
//! stopped thread or a zero live-token count cannot substitute for settlement.
//! This owner does not issue a capture acknowledgement: the native capture loan,
//! policy mailbox disposition and source-version fence remain separate joins.
//!
//! SPDX-License-Identifier: GPL-2.0-or-later

use std::sync::{Mutex, MutexGuard};

mod pause;
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
pub(super) struct FaultWork {
    claimed: Option<ClaimedFault>,
    receipt: FaultReceipt,
    scratch: [u8; PAGE_BYTES],
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
        if self.claimed.is_some() || self.failed {
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

    /// Marks uncertainty without duplicating the actor's actual first cause.
    ///
    /// ActorLifetime retains that cause; this fixed flag keeps request custody
    /// closed until physical retirement even if the worker has already returned.
    pub(super) fn fail(&mut self) {
        self.failed = true;
    }

    fn unresolved(&self) -> bool {
        self.claimed.is_some() || self.receipt.retained() || self.failed
    }
}

// The lock-independent pause gate and locked request share one admitted
// allocation. Requesting a pause cannot wait behind backing I/O in `work`.
struct FaultWorkAllocation {
    pause: FaultPause,
    work: Mutex<FaultWork>,
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
        let body = Box::new(FaultWorkAllocation {
            pause: FaultPause::default(),
            work: Mutex::new(FaultWork {
                claimed: None,
                receipt: FaultReceipt::default(),
                scratch: [0; PAGE_BYTES],
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

    /// Borrows the unique fault actor's body without waiting on another owner.
    ///
    /// # Errors
    /// Refuses contention, poisoned custody or an absent body.
    pub(super) fn try_lock(&self) -> Result<MutexGuard<'_, FaultWork>, RamError> {
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
            body.pause.held() || body.work.try_lock().map_or(true, |work| work.unresolved())
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
