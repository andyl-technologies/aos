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

use super::*;
use crucible_ram::{MetadataBudget, MetadataReservation};

/// Keeps one sequential request and its actual authentication scratch together.
pub(super) struct ClaimedFault {
    event: FaultEvent,
    operation: Option<Box<dyn SourceOperation>>,
}

/// Owns the physical buffer even when no operation could be admitted.
pub(super) struct FaultWork {
    claimed: Option<ClaimedFault>,
    scratch: [u8; PAGE_BYTES],
    failed: bool,
}

impl FaultWork {
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
        self.claimed.is_some() || self.failed
    }
}

/// Keeps the paid body separate from its credit through physical destruction.
pub(in crate::paged_ram::engine) struct FaultWorkOwner {
    body: Option<Box<Mutex<FaultWork>>>,
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
        let body = Box::new(Mutex::new(FaultWork {
            claimed: None,
            scratch: [0; PAGE_BYTES],
            failed: false,
        }));
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
        u64::try_from(std::mem::size_of::<Mutex<FaultWork>>())
            .map_err(|_| RamError::Invariant("fault work metadata extent overflow"))
    }

    /// Borrows the unique fault actor's body without waiting on another owner.
    ///
    /// # Errors
    /// Refuses contention, poisoned custody or an absent body.
    pub(super) fn try_lock(&self) -> Result<MutexGuard<'_, FaultWork>, RamError> {
        self.body
            .as_ref()
            .ok_or("fault work body absent")?
            .try_lock()
            .map_err(|_| RamError::Invariant("fault work custody unavailable"))
    }
}

impl Drop for FaultWorkOwner {
    fn drop(&mut self) {
        let unresolved = self
            .body
            .as_ref()
            .is_some_and(|body| body.try_lock().map_or(true, |work| work.unresolved()));
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
