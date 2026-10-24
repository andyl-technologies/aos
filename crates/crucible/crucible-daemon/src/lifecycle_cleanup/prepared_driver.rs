//! Runs cleanup against the same Main-owned prepared allocation.
//!
//! Safe monomorphized callbacks are installed with the original typed Box. The
//! prepared mutex owns that Box across every call, including unwind. No control
//! or Service mutex is held while invoking backend cleanup.

use std::any::Any;

use super::*;

#[derive(Clone, Copy)]
pub(super) struct PreparedBodyOperations {
    retry: fn(&mut (dyn Any + Send)) -> PreparedAttempt,
    take_post_body: fn(&mut (dyn Any + Send)) -> PreparedTransfer,
}

enum PreparedAttempt {
    Closed,
    Refused(crate::ProductionVmConstructionCleanupError),
    WrongType,
}

enum PreparedTransfer {
    Transferred(Option<ProductionVmConstructionPostBody>),
    Refused(crate::ProductionVmConstructionCleanupError),
    WrongType,
}

impl PreparedBodyOperations {
    pub(super) fn for_owner<T>() -> Self
    where
        T: ProductionVmCleanupOwner<
                Failure = crate::ProductionVmConstructionCleanupError,
                PostBody = ProductionVmConstructionPostBody,
            > + 'static,
    {
        Self {
            retry: retry::<T>,
            take_post_body: take_post_body::<T>,
        }
    }
}

fn retry<T>(owner: &mut (dyn Any + Send)) -> PreparedAttempt
where
    T: ProductionVmCleanupOwner<
            Failure = crate::ProductionVmConstructionCleanupError,
            PostBody = ProductionVmConstructionPostBody,
        > + 'static,
{
    let Some(owner) = owner.downcast_mut::<T>() else {
        return PreparedAttempt::WrongType;
    };
    match owner.retry_cleanup() {
        Ok(()) => PreparedAttempt::Closed,
        Err(first) => PreparedAttempt::Refused(first),
    }
}

fn take_post_body<T>(owner: &mut (dyn Any + Send)) -> PreparedTransfer
where
    T: ProductionVmCleanupOwner<
            Failure = crate::ProductionVmConstructionCleanupError,
            PostBody = ProductionVmConstructionPostBody,
        > + 'static,
{
    let Some(owner) = owner.downcast_mut::<T>() else {
        return PreparedTransfer::WrongType;
    };
    match owner.take_post_body() {
        Ok(body) => PreparedTransfer::Transferred(body),
        Err(first) => PreparedTransfer::Refused(first),
    }
}

/// Retries only the same owned body under its already exclusive prepared borrow.
///
/// Raw failures remain in that allocation. This cut transfers no PostBody and
/// closes no containing controls, native return or Service obligation.
pub(super) fn retry_body_in_place(
    slot: &CleanupSlot,
    prepared: &mut prepared_service::PreparedCell,
) -> Result<(), &'static str> {
    if prepared.panic_payload.is_some() {
        slot.publish(CleanupPhase::DestructionRefused);
        return Err("prepared cleanup retains its actual panic payload");
    }
    let Some(operations) = prepared.operations else {
        slot.publish(CleanupPhase::DestructionRefused);
        return Err("prepared owner lost its typed cleanup operations");
    };
    if !prepared.body_closed {
        let attempted = {
            let Some(owner) = prepared.owner.as_mut() else {
                return Err("prepared body disappeared before cleanup");
            };
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                (operations.retry)(owner.as_mut())
            }))
        };
        match attempted {
            Ok(PreparedAttempt::Closed) => prepared.body_closed = true,
            Ok(PreparedAttempt::Refused(first)) => {
                crate::ProductionVmConstructionCleanupError::retain_first(
                    &mut prepared.cleanup_failure,
                    first,
                );
                return Err("same prepared body retains cleanup");
            }
            Ok(PreparedAttempt::WrongType) => {
                slot.publish(CleanupPhase::DestructionRefused);
                return Err("prepared cleanup identity is uncertain");
            }
            Err(payload) => {
                prepared.panic_payload = Some(payload);
                slot.publish(CleanupPhase::DestructionRefused);
                return Err("prepared cleanup retains its actual panic payload");
            }
        }
    }
    Ok(())
}

/// Closes only fields owned by the prepared body, preserving its Main-paid shell.
///
/// The caller exclusively arbitrates the role before entry. Backend cleanup
/// may use the independent control or Service locks, so neither is held here.
/// A successful empty transfer cannot stand in for a native return obligation.
pub(super) fn retry_prepared(slot: &CleanupSlot, epoch: u64) -> Result<(), LifecycleApiError> {
    let mut prepared = slot
        .prepared
        .try_lock()
        .map_err(|_| refusal("same prepared body is borrowed or poisoned"))?;
    if prepared.epoch != epoch {
        return Err(refusal("same prepared cleanup epoch is stale"));
    }
    if prepared.owner.is_none() {
        return Ok(());
    }
    let Some(operations) = prepared.operations else {
        slot.publish(CleanupPhase::DestructionRefused);
        return Err(refusal("prepared owner lost its typed cleanup operations"));
    };
    retry_body_in_place(slot, &mut prepared).map_err(refusal)?;
    if !prepared.post_body_taken {
        let transfer = {
            let Some(owner) = prepared.owner.as_mut() else {
                return Err(refusal(
                    "prepared body disappeared before obligation transfer",
                ));
            };
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                (operations.take_post_body)(owner.as_mut())
            }))
        };
        match transfer {
            Ok(PreparedTransfer::Transferred(body)) => {
                prepared.pending_post_body = body;
                prepared.post_body_taken = true;
            }
            Ok(PreparedTransfer::Refused(first)) => {
                crate::ProductionVmConstructionCleanupError::retain_first(
                    &mut prepared.cleanup_failure,
                    first,
                );
                return Err(refusal("prepared postbody obligations remain retained"));
            }
            Ok(PreparedTransfer::WrongType) => {
                slot.publish(CleanupPhase::DestructionRefused);
                return Err(refusal(
                    "prepared obligation transfer identity is uncertain",
                ));
            }
            Err(payload) => {
                prepared.panic_payload = Some(payload);
                slot.publish(CleanupPhase::DestructionRefused);
                return Err(refusal(
                    "prepared obligation transfer retains its panic payload",
                ));
            }
        }
    }
    let mut cell = slot
        .cell
        .try_lock()
        .map_err(|_| refusal("prepared obligation destination is borrowed or poisoned"))?;
    if cell.epoch != epoch {
        slot.publish(CleanupPhase::DestructionRefused);
        return Err(refusal("prepared obligation destination changed epoch"));
    }
    if let Some(incoming) = prepared.pending_post_body.as_ref()
        && cell
            .post_body
            .as_ref()
            .is_some_and(|body| !body.can_append(incoming))
    {
        return Err(refusal(
            "same role retains two independently occupied obligations",
        ));
    }
    if let Some(incoming) = prepared.pending_post_body.take() {
        match cell.post_body.as_mut() {
            Some(body) => {
                if let Err(incoming) = body.append(incoming) {
                    prepared.pending_post_body = Some(incoming);
                    return Err(refusal("same prepared obligations could not be merged"));
                }
            }
            None => cell.post_body = Some(incoming),
        }
    }
    if cell.owner.is_none()
        && !cell.handoff
        && slot.body_destroyed_epoch.load(Ordering::Acquire) < epoch
        && !cell
            .post_body
            .as_ref()
            .is_some_and(|body| body.has_source_return() || body.has_target_return())
    {
        // The transferred tombstone contains no external Loop. Keep the pure
        // same-role return destination open; its empty/history transfer proves
        // neither that external body destruction happened nor native return.
        prepared.body_closed = false;
        prepared.post_body_taken = false;
        return Err(refusal(
            "same external body has not returned to its original role",
        ));
    }
    Ok(())
}
