//! Keeps the same role occupied through destruction of its actual terminal leaves.
//!
//! Native and Service return precede this transfer. The original Main-paid
//! prepared Box, Service phase and raw reports move without allocation. Their
//! destruction runs outside every queue mutex; only observed success can make
//! the exact epoch reusable.

use std::any::Any;

use super::prepared_service::PreparedSourceProjection;
use super::*;
use crate::packaged_qemu_executor::RetainedServiceStart;

pub(super) struct TerminalCustody {
    pub(super) key: ServiceMainPreclaim,
    pub(super) queue: Arc<LifecycleCleanupQueue>,
    pub(super) prepared: Option<Box<dyn Any + Send>>,
    pub(super) projection: Option<PreparedSourceProjection>,
    pub(super) history_projection: Option<PreparedSourceProjection>,
    pub(super) service: Option<RetainedServiceStart>,
    pub(super) control_failure:
        Option<crucible_linux_resource::host_services::process_birth::ServiceBirthError>,
    pub(super) prepared_cleanup_first: Option<crate::ProductionVmConstructionCleanupError>,
    pub(super) cleanup_first: Option<crate::ProductionVmConstructionCleanupError>,
    pub(super) access: Option<ServiceMainPreclaimError>,
    pub(super) receiver: Option<prepared_service::ServiceMainReceiver>,
}

impl TerminalCustody {
    pub(super) fn first_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.service
            .as_ref()
            .and_then(RetainedServiceStart::first)
            .map(|first| first as &dyn std::error::Error)
            .or_else(|| {
                self.service
                    .as_ref()
                    .and_then(RetainedServiceStart::adopted_semantic_shutdown_failure)
                    .map(|first| first as &dyn std::error::Error)
            })
            .or_else(|| {
                self.prepared
                    .as_ref()
                    .zip(self.projection)
                    .and_then(|(owner, project)| project(owner.as_ref()))
            })
            .or_else(|| self.service.as_ref().and_then(first_service_tail_failure))
            .or_else(|| {
                self.prepared_cleanup_first
                    .as_ref()
                    .map(|first| first as &dyn std::error::Error)
            })
            .or_else(|| {
                self.cleanup_first
                    .as_ref()
                    .map(|first| first as &dyn std::error::Error)
            })
            .or_else(|| {
                self.control_failure
                    .as_ref()
                    .map(|first| first as &dyn std::error::Error)
            })
            .or_else(|| {
                self.access
                    .as_ref()
                    .map(|first| first as &dyn std::error::Error)
            })
    }
}

/// Projects stored Service causes while their actual actor/body remains retained.
pub(super) fn visit_service_history(
    start: &RetainedServiceStart,
    apply: &mut impl FnMut(&'static str, &(dyn std::error::Error + 'static)),
) {
    if let Some(first) = start.first() {
        apply("Service initiation", first);
    }
    if let Some(first) = start.admission_post_failure() {
        apply("Service admission postcheck", first);
    }
    if let Some(first) = start.admission_completion_failure() {
        apply("Service admission completion", first);
    }
    if let Some(first) = start.projection_post_failure() {
        apply("Service projection postcheck", first);
    }
    if let Some(first) = start.imported_genesis_post_failure() {
        apply("imported genesis projection postcheck", first);
    }
    if let Some(first) = start.cleanup_failure() {
        apply("Service cleanup", first);
    }
    if let Some(first) = start.adopted_semantic_shutdown_failure() {
        apply("receiving semantic shutdown", first);
    }
    start.visit_retained_completion_history(&mut *apply);
    start.visit_watchdog_history(&mut *apply);
    if let Some(history) = start.imported_return() {
        visit_imported_return_history(
            history,
            [
                "imported initiation",
                "imported launch postcheck",
                "imported completion",
                "imported return postcheck",
            ],
            apply,
        );
    }
    if let Some(history) = start.adopted_retirement_return() {
        visit_imported_return_history(
            history,
            [
                "receiving maintenance initiation",
                "receiving maintenance launch postcheck",
                "receiving maintenance completion",
                "receiving maintenance return postcheck",
            ],
            apply,
        );
    }
}

/// Selects an actual supplemental failure after initiating causes were checked.
pub(super) fn first_service_tail_failure(
    start: &RetainedServiceStart,
) -> Option<&(dyn std::error::Error + 'static)> {
    start
        .admission_post_failure()
        .map(|first| first as &dyn std::error::Error)
        .or_else(|| {
            start
                .admission_completion_failure()
                .map(|first| first as &dyn std::error::Error)
        })
        .or_else(|| {
            start
                .projection_post_failure()
                .map(|first| first as &dyn std::error::Error)
        })
        .or_else(|| {
            start
                .imported_genesis_post_failure()
                .map(|first| first as &dyn std::error::Error)
        })
        .or_else(|| {
            start
                .cleanup_failure()
                .map(|first| first as &dyn std::error::Error)
        })
        .or_else(|| {
            start
                .retained_completion_failure()
                .map(|first| first as &dyn std::error::Error)
        })
        .or_else(|| start.watchdog_first_failure())
        .or_else(|| {
            start
                .imported_return()
                .and_then(first_imported_return_failure)
        })
        .or_else(|| {
            start
                .adopted_retirement_return()
                .and_then(first_imported_return_failure)
        })
}

fn first_imported_return_failure(
    history: &crate::imported_checkpoint::ImportedCheckpointReturn,
) -> Option<&(dyn std::error::Error + 'static)> {
    history
        .first
        .as_ref()
        .map(|first| first as &dyn std::error::Error)
        .or_else(|| {
            history
                .launch_post
                .as_ref()
                .map(|first| first as &dyn std::error::Error)
        })
        .or_else(|| {
            history
                .completion
                .as_ref()
                .map(|first| first as &dyn std::error::Error)
        })
        .or_else(|| {
            history
                .return_post
                .as_ref()
                .map(|first| first as &dyn std::error::Error)
        })
}

fn visit_imported_return_history(
    history: &crate::imported_checkpoint::ImportedCheckpointReturn,
    labels: [&'static str; 4],
    apply: &mut impl FnMut(&'static str, &(dyn std::error::Error + 'static)),
) {
    if let Some(first) = &history.first {
        apply(labels[0], first);
    }
    if let Some(first) = &history.launch_post {
        apply(labels[1], first);
    }
    if let Some(first) = &history.completion {
        apply(labels[2], first);
    }
    if let Some(first) = &history.return_post {
        apply(labels[3], first);
    }
}

impl TerminalCustody {
    pub(super) fn visit_history(
        &self,
        apply: &mut impl FnMut(&'static str, &(dyn std::error::Error + 'static)),
    ) {
        if let Some(start) = &self.service {
            visit_service_history(start, apply);
        }
        if let (Some(owner), Some(project)) = (&self.prepared, self.history_projection)
            && let Some(history) = project(owner.as_ref())
        {
            apply("Source preparation", history);
        }
        if let Some(first) = &self.prepared_cleanup_first {
            apply("prepared body cleanup", first);
        }
        if let Some(first) = &self.cleanup_first {
            apply("published body cleanup", first);
        }
        if let Some(first) = &self.control_failure {
            apply("containing controls", first);
        }
        if let Some(first) = &self.access {
            apply("Source role access", first);
        }
    }
}

/// Moves existing terminal fields only after all locks and factual checks pass.
pub(super) fn take_terminal_body(
    key: &ServiceMainPreclaim,
) -> Result<ProductionVmConstructionPostBody, PreparedSourceRefusal> {
    let queue = key
        .queue
        .upgrade()
        .ok_or(PreparedSourceRefusal::RoleUnavailable)?;
    let slot = queue
        .slots
        .get(key.index)
        .ok_or(PreparedSourceRefusal::RoleUnavailable)?;
    let mut prepared = slot
        .prepared
        .try_lock()
        .map_err(|_| PreparedSourceRefusal::Borrowed)?;
    let mut service = slot
        .service
        .try_lock()
        .map_err(|_| PreparedSourceRefusal::Borrowed)?;
    let mut cell = slot
        .cell
        .try_lock()
        .map_err(|_| PreparedSourceRefusal::Borrowed)?;
    if cell.epoch != key.epoch
        || prepared.epoch != key.epoch
        || service.epoch != key.epoch
        || slot.epoch.load(Ordering::Acquire) != key.epoch
        || !slot.is(CleanupPhase::TerminalReady)
    {
        return Err(PreparedSourceRefusal::Pending);
    }
    if service.role.is_none()
        || cell.retirement_input.is_some()
        || cell.retirement_input_reserved
        || cell.panic_payload.is_some()
        || prepared.panic_payload.is_some()
        || service.panic_payload.is_some()
        || service.queued_owner.is_some()
        || service.queued_owner_borrowed
        || cell.owner.is_some()
        || cell.controls.is_some()
        || prepared.pending_post_body.is_some()
        || !prepared.body_closed
        || !prepared.post_body_taken
        || slot.external_receivers.load(Ordering::Acquire) != 0
        || service.transport_receiver.is_some()
        || service.completed_transport_sequence != service.transport_sequence
        || service
            .start
            .as_ref()
            .is_some_and(|start| !start.is_released())
    {
        return Err(PreparedSourceRefusal::Pending);
    }
    if cell.post_body.is_some() {
        return Err(PreparedSourceRefusal::Pending);
    }
    let Some(body) = service.return_body.as_ref() else {
        return Err(PreparedSourceRefusal::Pending);
    };
    if !body.native_returns_observed() || body.terminal.is_some() {
        return Err(PreparedSourceRefusal::Pending);
    }
    if !slot.claim(CleanupPhase::TerminalReady, CleanupPhase::TerminalOwned) {
        return Err(PreparedSourceRefusal::Pending);
    }

    if slot.report_references.load(Ordering::Acquire) != 1 {
        let _restored = slot.claim(CleanupPhase::TerminalOwned, CleanupPhase::TerminalReady);
        return Err(PreparedSourceRefusal::Pending);
    }

    // Every validation precedes these infallible moves. This transfer consumes
    // the caller's already counted report reference; it creates no second one.
    let Some(mut body) = service.return_body.take() else {
        slot.publish(CleanupPhase::DestructionRefused);
        return Err(PreparedSourceRefusal::DestructionUncertain);
    };
    service.role = None;
    cell.handoff = false;
    cell.controls_bound = false;
    cell.owner_cleanup_complete = false;
    cell.owner_post_body_taken = false;
    body.terminal = Some(TerminalCustody {
        key: key.copy_selection(),
        queue: Arc::clone(&queue),
        prepared: prepared.owner.take(),
        projection: prepared.projection.take(),
        history_projection: prepared.history_projection.take(),
        service: service.start.take(),
        cleanup_first: cell.first_failure.take(),
        prepared_cleanup_first: prepared.cleanup_failure.take(),
        control_failure: cell.control_failure.take(),
        access: None,
        receiver: None,
    });
    Ok(body)
}

/// Releases one actual outside report only after its owned leaves were dropped.
pub(super) fn return_report_reference(key: &ServiceMainPreclaim, terminal_disposed: bool) {
    let Some(queue) = key.queue.upgrade() else {
        return;
    };
    let Some(slot) = queue.slots.get(key.index) else {
        return;
    };
    report_refs::release(slot, key.epoch, terminal_disposed);
}

/// Destroys a validated payload outside locks, retaining the same panic on refusal.
///
/// Callers exclusively own Destroying or TerminalOwned and have checked that
/// this epoch holds no earlier panic. They cannot repeat this cut after refusal.
/// The actual queue remains alive across terminal destruction through its
/// existing Arc; no detached payload or freshly allocated owner is introduced.
pub(super) fn destroy_payload<T>(slot: &CleanupSlot, payload: T) -> bool {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(payload))) {
        Ok(()) => true,
        Err(payload) => {
            let mut cell = match slot.cell.lock() {
                Ok(cell) => cell,
                Err(poison) => poison.into_inner(),
            };
            cell.panic_payload = Some(payload);
            slot.publish(CleanupPhase::DestructionRefused);
            false
        }
    }
}
