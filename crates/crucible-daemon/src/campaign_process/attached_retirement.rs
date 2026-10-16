//! Anchors the one active Attached retirement body in the existing Main cell.
//!
//! No new registry or worker exists here. The once-issued Main identifies this
//! inline slot; all factory and Source links return only to Main purposes or
//! weak queue handles, never a strong reference to the permanent actor.

use super::*;
use crate::packaged_qemu_executor::{PackagedQemuExecutorJoinError, RetainedAttachedRetirement};
use crucible_linux_resource::host_services::process_birth::AuthenticatedNativeSlotPurpose;
use crucible_linux_resource::host_supervision::HostOperationGuard;

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
        actor.attached_first.get_or_init(|| first);
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
        .attached_first
        .get()
        .map_or(PackagedQemuExecutorJoinError::AttachedPending, |first| {
            PackagedQemuExecutorJoinError::RetainedAttached {
                first,
                post: actor.attached_post.get().copied(),
            }
        })
}

pub(crate) fn retry_attached_retirement(
    main: &Arc<AuthenticatedNativeSlotPurpose>,
) -> Result<(), PackagedQemuExecutorJoinError> {
    let original = main
        .retained_cleanup()
        .map_err(PackagedQemuExecutorJoinError::MainCleanupAdmission)?;
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
        return actor.attached_first.get().map_or(Ok(()), |first| {
            Err(PackagedQemuExecutorJoinError::RetainedAttached {
                first,
                post: actor.attached_post.get().copied(),
            })
        });
    };
    let work = body.retry(main, original);
    if let Err(first) = work {
        actor.attached_first.get_or_init(|| first);
    }
    if let Some(post) = body.post_refusal() {
        actor.attached_post.get_or_init(|| post);
    }
    if !body.physically_retired() {
        return Err(retained_attached_report(main));
    }
    let returned = slot.take();
    drop(slot);
    // Only physical closure permits destruction. No body destructor runs while
    // the actor cell is locked or while listener execution borrows the service.
    drop(returned);
    actor.attached_first.get().map_or(Ok(()), |first| {
        Err(PackagedQemuExecutorJoinError::RetainedAttached {
            first,
            post: actor.attached_post.get().copied(),
        })
    })
}

/// Checks live admission only for the new service thread, never custody handoff.
pub(crate) fn verify_attached_start(
    main: &Arc<AuthenticatedNativeSlotPurpose>,
) -> Result<(), PackagedQemuExecutorJoinError> {
    admitted_actor(main)?
        .verify()
        .map_err(PackagedQemuExecutorJoinError::MainStartAdmission)
}
