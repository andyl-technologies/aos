//! Binds cache transitions to the real physical executor and exact native unit.

use super::{
    super::{invalid, residence},
    graph::Unit,
};
use crate::{
    host_cache::owner::{consumer::state as policy, retention::NativeOwnerExecutor},
    publisher_local::{
        client::{PeerPublishedObject, PendingCacheBody, PublisherRunningContext},
        wire::Operation,
    },
};
use std::{io, sync::Arc};
use terrane::host::cache::HostDomainLocation;

/// Selects one actual cache transition; pending variants retain original replies.
pub(super) enum Transition {
    Retire,
    Restore(Arc<PendingCacheBody>),
    Finish(Arc<PendingCacheBody>),
}

/// Retains validated original resources before this physical command starts effects.
pub(in crate::host_cache::owner) struct CachePermit<'unit> {
    unit: &'unit Unit,
    running: Arc<PublisherRunningContext>,
    generation: u64,
    transition: Transition,
}

impl<'unit> CachePermit<'unit> {
    /// Checks actual synchronized custody before marking the physical turn in flight.
    ///
    /// # Errors
    /// Refuses foreign or changed jobs, protected/shared retirement, stale snapshot
    /// and pending receipts that differ from the actual original body/session.
    pub(super) fn begin(
        executor: &NativeOwnerExecutor,
        unit: &'unit Unit,
        transition: Transition,
    ) -> io::Result<Self> {
        let running = executor.admission_context()?;
        running.check_current().map_err(io::Error::other)?;
        let mut owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("cache permit custody poisoned"))?;
        policy::check_ready(executor, &owner)?;
        policy::check_bootstrap(&owner, &running)?;
        if !matches!(transition, Transition::Restore(_))
            && (unit.protected || !unit.shared_chunks.is_empty())
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "cache unit retains protection or shared residences",
            ));
        }
        for member in &unit.members {
            if !executor
                .publication_jobs()
                .iter()
                .any(|job| Arc::ptr_eq(job, member))
            {
                return Err(invalid("cache unit lost original publication registry"));
            }
            let job = member
                .lock()
                .map_err(|_| invalid("cache permit job poisoned"))?;
            let body = residence::registered_body(&owner, &job)?;
            if !Arc::ptr_eq(&job.custody, executor.custody())
                || body.claim().descriptor() != unit.body.claim().descriptor()
                || body.incarnation() != unit.body.incarnation()
                || job.cached.is_none()
            {
                return Err(invalid(
                    "cache permit differs from original cached allocation",
                ));
            }
        }
        match &transition {
            Transition::Retire => {}
            Transition::Restore(pending) | Transition::Finish(pending) => {
                pending.check_original(running.publisher_session(), &unit.body)?
            }
        }
        owner.preparation.recheck()?;
        crate::host_cache::owner::recovery::check_charge(&owner, 0)?;
        let generation = owner.generation;
        // Only this validated, retained permit can authorize the subsequent
        // in-flight RPC while the mutable executor borrow excludes other work.
        owner.faulted = true;
        Ok(Self {
            unit,
            running,
            generation,
            transition,
        })
    }

    /// Checks the original physical turn before borrowing its actual body for RPC.
    ///
    /// # Errors
    /// Refuses changed Running context, snapshot, phase, receipt or physical owner.
    pub(in crate::host_cache::owner) fn body(
        &self,
        executor: &NativeOwnerExecutor,
        context: &PublisherRunningContext,
        pending: Option<&Arc<PendingCacheBody>>,
        operation: Operation,
    ) -> io::Result<Arc<PeerPublishedObject<HostDomainLocation>>> {
        executor.check_physical_worker()?;
        if !std::ptr::eq(context, self.running.as_ref()) {
            return Err(invalid("cache retirement changed original Running context"));
        }
        let phase_matches = match (&self.transition, pending, operation) {
            (Transition::Retire, None, Operation::Retire) => true,
            (Transition::Restore(actual), Some(expected), Operation::Restore)
            | (Transition::Finish(actual), Some(expected), Operation::FinishRetirement) => {
                Arc::ptr_eq(actual, expected)
            }
            _ => false,
        };
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("cache turn custody poisoned"))?;
        residence::check_snapshot(&owner)?;
        if !phase_matches || !owner.faulted || owner.generation != self.generation {
            return Err(invalid("cache retirement lost its original physical phase"));
        }
        policy::check_bootstrap(&owner, &self.running)?;
        Ok(Arc::clone(&self.unit.body))
    }
}
