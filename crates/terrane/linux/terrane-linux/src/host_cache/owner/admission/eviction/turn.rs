//! Borrows the original worker throughout each encoded cache namespace exchange.

use super::{EncodedAllocation, invalid};
use crate::{
    host_cache::owner::{
        consumer::state as policy, publication::residence, recovery, retention::NativeOwnerExecutor,
    },
    publisher_local::{
        client::{EncodedCacheReceipt, PublisherRunningContext},
        wire::{BodyKey, Operation},
    },
};
use std::{fs::File, io, sync::Arc};

/// Selects an original allocation's exclusive namespace transition.
pub(super) enum Transition<'turn> {
    /// Inspects and retires the actual canonical members.
    Retire,
    /// Restores the exact previously acknowledged retirement.
    Restore(&'turn Arc<EncodedCacheReceipt>),
    /// Finishes the exact previously acknowledged retirement.
    Finish(&'turn Arc<EncodedCacheReceipt>),
}

/// Retains exclusive execution, original native allocation and synchronized phase.
pub(crate) struct PublisherEncodedCacheTurn<'turn> {
    executor: &'turn mut NativeOwnerExecutor,
    unit: &'turn EncodedAllocation,
    running: Arc<PublisherRunningContext>,
    generation: u64,
    transition: Transition<'turn>,
}

impl<'turn> PublisherEncodedCacheTurn<'turn> {
    /// Validates native custody before marking this original physical turn in flight.
    ///
    /// # Errors
    /// Refuses protection, changed originals, stale Running context, snapshot,
    /// quota or an unrelated pending acknowledgment.
    pub(super) fn begin(
        executor: &'turn mut NativeOwnerExecutor,
        unit: &'turn EncodedAllocation,
        transition: Transition<'turn>,
    ) -> io::Result<Self> {
        let running = executor.admission_context()?;
        running.check_current().map_err(io::Error::other)?;
        if matches!(transition, Transition::Retire) {
            unit.check_canonical(executor)?;
        } else {
            unit.check_held(executor, false)?;
        }
        if !matches!(transition, Transition::Restore(_)) {
            unit.check_unprotected(executor)?;
        }
        let generation = {
            let mut owner = executor
                .custody()
                .lock()
                .map_err(|_| invalid("encoded turn custody poisoned"))?;
            policy::check_ready(executor, &owner)?;
            policy::check_bootstrap(&owner, &running)?;
            match &transition {
                Transition::Retire => {}
                Transition::Restore(original) | Transition::Finish(original) => {
                    original.check_original(running.publisher_session(), unit.body_key())?;
                }
            }
            owner.preparation.recheck()?;
            recovery::check_charge(&owner, 0)?;
            owner.faulted = true;
            owner.generation
        };
        Ok(Self {
            executor,
            unit,
            running,
            generation,
            transition,
        })
    }

    /// Borrows only the original unit's registered key in its current physical phase.
    ///
    /// # Errors
    /// Refuses another worker, context, phase, original receipt or snapshot.
    pub(crate) fn key(
        &self,
        context: &PublisherRunningContext,
        operation: Operation,
        receipt: Option<&Arc<EncodedCacheReceipt>>,
    ) -> io::Result<BodyKey> {
        self.executor.check_physical_worker()?;
        if !std::ptr::eq(context, self.running.as_ref()) {
            return Err(invalid("encoded turn changed original Running context"));
        }
        let valid = match (&self.transition, operation, receipt) {
            (Transition::Retire, Operation::InspectBody | Operation::Retire, None) => true,
            (Transition::Restore(actual), Operation::Restore, Some(expected))
            | (Transition::Finish(actual), Operation::FinishRetirement, Some(expected)) => {
                Arc::ptr_eq(actual, expected)
            }
            _ => false,
        };
        let owner = self
            .executor
            .custody()
            .lock()
            .map_err(|_| invalid("encoded turn custody poisoned"))?;
        residence::check_snapshot(&owner)?;
        policy::check_bootstrap(&owner, &self.running)?;
        if !valid || !owner.faulted || owner.generation != self.generation {
            return Err(invalid("encoded turn lost original physical phase"));
        }
        Ok(self.unit.body_key().clone())
    }

    /// Checks actual returned descriptors outside the publisher client's mutex.
    ///
    /// # Errors
    /// Refuses another phase, missing members, changed canonical bytes or inodes.
    pub(crate) fn check_received(
        &self,
        context: &PublisherRunningContext,
        files: &[File],
    ) -> io::Result<()> {
        self.key(context, Operation::InspectBody, None)?;
        self.unit.check_received(self.executor, files)
    }
}
