//! Anchors the one active Attached retirement body in the existing Main cell.
//!
//! No new registry or worker exists here. The once-issued Main identifies this
//! inline slot; all factory and Source links return only to Main purposes or
//! weak queue handles, never a strong reference to the permanent actor.

use super::*;
use crate::packaged_qemu_executor::retirement::{
    AttachedRetirementFailure, AttachedRetirementReport,
};
use crate::packaged_qemu_executor::{
    PackagedQemuExecutorJoinError, PackagedQemuExecutorRetirementError, RetainedAttachedRetirement,
};
use crucible_host_resources::host_services::process_birth::AuthenticatedNativeSlotPurpose;
use crucible_host_resources::host_supervision::HostOperationGuard;

/// Keeps service-first and independent cleanup history in the priced actor body.
///
/// These cells contain diagnostics, not another executor owner or queue edge.
/// Later cleanup phases retain their own first causes; an independent post can
/// arrive without replacing prior cleanup history or the service failure.
pub(super) struct AttachedRetirementHistory {
    first: OnceLock<PackagedQemuExecutorJoinError>,
    cleanup: PackagedQemuExecutorRetirementError,
}

impl AttachedRetirementHistory {
    pub(super) const fn new() -> Self {
        Self {
            first: OnceLock::new(),
            cleanup: PackagedQemuExecutorRetirementError::new(),
        }
    }

    fn record_first(&self, first: PackagedQemuExecutorJoinError) {
        self.first.get_or_init(|| first);
    }

    fn record_cleanup(&self, cleanup: AttachedRetirementReport) {
        self.cleanup.retain(cleanup);
    }

    fn report(&'static self) -> Option<PackagedQemuExecutorJoinError> {
        if let Some(first) = self.first.get() {
            Some(PackagedQemuExecutorJoinError::RetainedAttached {
                first,
                cleanup: self.cleanup.has_failure().then_some(&self.cleanup),
                post: self.cleanup.original_post(),
            })
        } else {
            self.cleanup.has_failure().then_some(
                PackagedQemuExecutorJoinError::RetainedAttachedCleanup {
                    cleanup: &self.cleanup,
                    post: self.cleanup.original_post(),
                },
            )
        }
    }
}

fn admitted_actor(
    main: &Arc<AuthenticatedNativeSlotPurpose>,
) -> Result<&'static ProcessActor, PackagedQemuExecutorJoinError> {
    let actor = ACTOR
        .get()
        .ok_or(PackagedQemuExecutorJoinError::AttachedPending)?;
    if actor
        .executor
        .get()
        .is_none_or(|actual| !Arc::ptr_eq(actual, main))
    {
        return Err(PackagedQemuExecutorJoinError::AttachedPending);
    }
    Ok(actor)
}

pub(crate) fn install_attached_retirement(
    main: &Arc<AuthenticatedNativeSlotPurpose>,
    body: RetainedAttachedRetirement,
) -> Result<(), (RetainedAttachedRetirement, &'static str)> {
    let Ok(actor) = admitted_actor(main) else {
        return Err((body, "attached owner belongs to another Main"));
    };
    let Ok(mut slot) = actor.construction.try_lock() else {
        return Err((body, "Main constructor cell is busy or poisoned"));
    };
    if slot.is_some()
        || actor.construction_first.get().is_some()
        || actor
            .attached_started
            .swap(true, std::sync::atomic::Ordering::AcqRel)
    {
        return Err((
            body,
            "same Main already owns a constructor or Attached service",
        ));
    }
    *slot = Some(RetainedExecutorConstruction::Attached(body));
    Ok(())
}

pub(crate) fn mark_attached_returned(
    main: &Arc<AuthenticatedNativeSlotPurpose>,
    first: Option<PackagedQemuExecutorJoinError>,
) -> Result<(), PackagedQemuExecutorJoinError> {
    let actor = admitted_actor(main)?;
    if let Some(first) = first {
        actor.attached_history.record_first(first);
    }
    let mut slot = actor
        .construction
        .try_lock()
        .map_err(|_| PackagedQemuExecutorJoinError::AttachedPending)?;
    let Some(RetainedExecutorConstruction::Attached(body)) = slot.as_mut() else {
        return Err(PackagedQemuExecutorJoinError::AttachedPending);
    };
    body.mark_service_returned();
    Ok(())
}

pub(crate) fn retained_attached_report(
    main: &Arc<AuthenticatedNativeSlotPurpose>,
) -> PackagedQemuExecutorJoinError {
    let Ok(actor) = admitted_actor(main) else {
        return PackagedQemuExecutorJoinError::AttachedPending;
    };
    actor
        .attached_history
        .report()
        .unwrap_or(PackagedQemuExecutorJoinError::AttachedPending)
}

pub(crate) fn retry_attached_retirement(
    main: &Arc<AuthenticatedNativeSlotPurpose>,
) -> Result<(), PackagedQemuExecutorJoinError> {
    let actor = admitted_actor(main)?;
    let original = match main.retained_cleanup() {
        Ok(original) => original,
        Err(source) => {
            actor
                .attached_history
                .record_cleanup(AttachedRetirementReport::from_admission(source));
            return Err(retained_attached_report(main));
        }
    };
    retry_attached_retirement_original(main, &original)
}

pub(crate) fn retry_attached_retirement_original(
    main: &Arc<AuthenticatedNativeSlotPurpose>,
    original: &HostOperationGuard,
) -> Result<(), PackagedQemuExecutorJoinError> {
    let actor = admitted_actor(main)?;
    let mut slot = actor
        .construction
        .try_lock()
        .map_err(|_| PackagedQemuExecutorJoinError::AttachedPending)?;
    let Some(RetainedExecutorConstruction::Attached(body)) = slot.as_mut() else {
        return actor.attached_history.report().map_or(Ok(()), Err);
    };
    let work = body.retry(main, original);
    let first_post = body.post_refusal();
    match work {
        Err(AttachedRetirementFailure::Report(report)) => actor
            .attached_history
            .record_cleanup(report.with_first_post(first_post)),
        Ok(()) | Err(AttachedRetirementFailure::Pending) => {
            if let Some(post) = first_post {
                actor
                    .attached_history
                    .record_cleanup(AttachedRetirementReport::from_post(post));
            }
        }
    }
    if !body.physically_retired() {
        return Err(retained_attached_report(main));
    }
    let returned = slot.take();
    drop(slot);
    // Only physical closure permits destruction. No body destructor runs while
    // the actor cell is locked or while listener execution borrows the service.
    drop(returned);
    actor.attached_history.report().map_or(Ok(()), Err)
}

/// Checks live admission only for the new service thread, never custody handoff.
pub(crate) fn verify_attached_start(
    main: &Arc<AuthenticatedNativeSlotPurpose>,
) -> Result<(), PackagedQemuExecutorJoinError> {
    admitted_actor(main)?
        .verify()
        .map_err(PackagedQemuExecutorJoinError::MainStartAdmission)
}

#[cfg(test)]
#[path = "attached_retirement/tests.rs"]
mod tests;
