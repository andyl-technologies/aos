//! Dispatches retained preserving workers beneath the original service actor.
//!
//! The map owns every native field before callbacks run. Errors leave the same
//! owner retained; only authentic queue reclamation permits its removal.

use crate::node_observed_executor::InstalledNodeCatalog;
use crucible_campaign::ExecutionId;
use std::{
    collections::BTreeMap,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::atomic::{AtomicBool, Ordering},
};

use super::super::{ActorStorage, Command, NodeObservationService, NodeObservationServiceError};
use super::{
    NodePreservingDebugRequest, NodePreservingDebugResumeRequest, NodePreservingDebugState,
    Reservation, worker::Worker,
};

pub(in crate::node_observed_executor::service) type Workers = BTreeMap<ExecutionId, Worker>;

impl NodeObservationService {
    pub(super) fn preserving_prepare(
        &self,
        request: NodePreservingDebugRequest,
    ) -> Result<super::NodePreservingDebugRecord, NodeObservationServiceError> {
        if self.stopping.load(Ordering::Acquire) {
            return Err(NodeObservationServiceError::Unavailable);
        }
        let reservation = self.preserving_debug.reserve_prepare(&request)?;
        let record = reservation.record.clone();
        if reservation.original_dispatch {
            let queued = self.send(Command::PreservingDebugPrepare {
                request,
                reservation: Box::new(reservation),
                ledger: self.preserving_debug.clone(),
            });
            if let Err(error) = queued {
                self.preserving_debug
                    .refuse_preparation(&record, &error.to_string())?;
                return Err(error);
            }
        }
        Ok(record)
    }

    pub(super) fn preserving_resume(
        &self,
        request: NodePreservingDebugResumeRequest,
    ) -> Result<super::NodePreservingDebugRecord, NodeObservationServiceError> {
        if self.stopping.load(Ordering::Acquire) {
            return Err(NodeObservationServiceError::Unavailable);
        }
        let reservation = self.preserving_debug.reserve_resume(&request)?;
        let record = reservation.record.clone();
        if reservation.original_dispatch {
            let queued = self.send(Command::PreservingDebugResume {
                request,
                reservation: Box::new(reservation),
                ledger: self.preserving_debug.clone(),
            });
            if let Err(error) = queued {
                self.preserving_debug
                    .refuse_preparation(&record, &error.to_string())?;
                return Err(error);
            }
        }
        Ok(record)
    }
}

pub(in crate::node_observed_executor::service) fn prepare(
    request: NodePreservingDebugRequest,
    reservation: Reservation,
    owned: &mut Workers,
    current_worlds: usize,
    maximum_worlds: usize,
    storage: &ActorStorage,
) {
    let execution = match super::super::conditional_preparation::execution_id(&request.execution) {
        Ok(execution) => execution,
        Err(_) => return,
    };
    if owned.contains_key(&execution)
        || current_worlds.saturating_add(owned.len()) >= maximum_worlds
    {
        let _ = storage.preserving_debug.complete(
            &reservation,
            NodePreservingDebugState::Unknown {
                reason: "original preserving actor capacity or ownership refused".into(),
            },
            None,
        );
        return;
    }
    let original = reservation.record.clone();
    match Worker::new(request, reservation, storage) {
        Ok(worker) => {
            owned.insert(execution, worker);
        }
        // The original durable claim remains non-dispatchable even when local
        // record/owner reservation cannot be allocated.
        Err(error) => {
            // No native field exists yet. The immutable original claim still
            // forbids dispatch, and status must remain explicit about refusal.
            let _ = storage
                .preserving_debug
                .refuse_preparation(&original, &error.to_string());
        }
    }
}

pub(in crate::node_observed_executor::service) fn resume(
    request: NodePreservingDebugResumeRequest,
    reservation: Reservation,
    owned: &mut Workers,
    storage: &ActorStorage,
) {
    let execution = match super::super::conditional_preparation::execution_id(&request.execution) {
        Ok(execution) => execution,
        Err(_) => return,
    };
    let Some(worker) = owned.get_mut(&execution) else {
        let _ = storage.preserving_debug.complete(
            &reservation,
            NodePreservingDebugState::Unknown {
                reason: "stored preserving status has no current native stopped owner".into(),
            },
            None,
        );
        return;
    };
    if let Err(error) = worker.resume(request, reservation, storage) {
        worker.fail(error);
    }
}

pub(in crate::node_observed_executor::service) fn poll(
    owned: &mut Workers,
    catalog: &mut InstalledNodeCatalog,
    storage: &ActorStorage,
    stopping: &AtomicBool,
) {
    for worker in owned.values_mut() {
        match catch_unwind(AssertUnwindSafe(|| {
            worker.poll(catalog, storage, stopping.load(Ordering::Acquire))
        })) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => worker.fail(error),
            Err(_) => {
                worker.fail("preserving native callback unwound; original complete world retained");
                stopping.store(true, Ordering::Release);
            }
        }
        if !worker.published
            && let Some(outcome) = &worker.outcome
        {
            match catch_unwind(AssertUnwindSafe(|| {
                storage.preserving_debug.complete(
                    &worker.reservation,
                    outcome.clone(),
                    worker.capture(),
                )
            })) {
                Ok(Ok(_)) => worker.published = true,
                Ok(Err(_)) => {}
                Err(_) => stopping.store(true, Ordering::Release),
            }
        }
    }
    owned.retain(|_, worker| !(worker.released() && worker.published));
}
