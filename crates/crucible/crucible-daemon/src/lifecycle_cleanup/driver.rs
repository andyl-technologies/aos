//! Orders actual body closure, containing credit, native return and Service release.
//!
//! Atomic role phases arbitrate each attempt. Backend body callbacks retain
//! their actual owner in its existing cell, and no accounting mutex surrounds
//! those callbacks. Destruction happens outside queue locks before body credit.

use super::*;

/// Restores a borrowed phase on every ordinary early-return cut.
///
/// Irreversible progress publishes a different phase. That phase is never
/// overwritten by this guard, including a retained unwind/corruption refusal.
struct PhaseAttempt<'a> {
    slot: &'a CleanupSlot,
    before: CleanupPhase,
    borrowed: CleanupPhase,
}

impl<'a> PhaseAttempt<'a> {
    fn claim(slot: &'a CleanupSlot, before: CleanupPhase, borrowed: CleanupPhase) -> Option<Self> {
        slot.claim(before, borrowed).then_some(Self {
            slot,
            before,
            borrowed,
        })
    }
}

impl Drop for PhaseAttempt<'_> {
    fn drop(&mut self) {
        let _restored = self.slot.claim(self.borrowed, self.before);
    }
}

pub(super) fn retry_slot(
    slot: &CleanupSlot,
    expected_epoch: Option<u64>,
) -> Result<(), LifecycleApiError> {
    if slot.is(CleanupPhase::Free) {
        return Ok(());
    }
    let epoch = slot.epoch.load(Ordering::Acquire);
    if expected_epoch.is_some_and(|expected| expected != epoch) {
        return Err(refusal("cleanup driver epoch is stale"));
    }
    if slot.is(CleanupPhase::Reserved) {
        if !slot.retirement_requested.load(Ordering::Acquire) {
            return Err(refusal("prepared work has not entered retirement"));
        }
        let _attempt =
            PhaseAttempt::claim(slot, CleanupPhase::Reserved, CleanupPhase::RetryingPrepared)
                .ok_or_else(|| refusal("same prepared retirement is already borrowed"))?;
        let attempted = prepared_driver::retry_prepared(slot, epoch);
        if slot.is(CleanupPhase::DestructionRefused) {
            return attempted;
        }
        if attempted.is_err() {
            let _restored = slot.claim(CleanupPhase::RetryingPrepared, CleanupPhase::Reserved);
            return attempted;
        }
        let can_close = {
            let cell = slot
                .cell
                .try_lock()
                .map_err(|_| refusal("prepared body closure is borrowed or poisoned"))?;
            cell.epoch == epoch
                && !slot.external_return_reserved.load(Ordering::Acquire)
                && cell.owner.is_none()
                && cell
                    .post_body
                    .as_ref()
                    .is_some_and(|body| body.has_source_return() || body.has_target_return())
        };
        if !can_close {
            // A transferred Pending is only a Main-paid history tombstone.
            // The actual external lifecycle still owns its return obligation.
            let _restored = slot.claim(CleanupPhase::RetryingPrepared, CleanupPhase::Reserved);
            return Err(refusal(
                "same external lifecycle return remains outstanding",
            ));
        }
        if !slot.claim(CleanupPhase::RetryingPrepared, CleanupPhase::OwnerDestroyed) {
            return Err(refusal(
                "same returned body was published during prepared cleanup",
            ));
        }
        slot.body_destroyed_epoch.store(epoch, Ordering::Release);
    }
    retry_body_and_controls(slot, epoch)?;
    if let Some(_attempt) =
        PhaseAttempt::claim(slot, CleanupPhase::PostBodyPending, CleanupPhase::Returning)
    {
        let attempted = retry_post_body(slot, epoch);
        if !slot.is(CleanupPhase::DestructionRefused) {
            slot.publish(if attempted.is_ok() {
                CleanupPhase::TerminalReady
            } else {
                CleanupPhase::PostBodyPending
            });
        }
        return attempted;
    }
    if slot.is(CleanupPhase::TerminalReady)
        || slot.is(CleanupPhase::TerminalOwned)
        || slot.is(CleanupPhase::TerminalDisposing)
    {
        return Ok(());
    }
    Err(refusal("same lifecycle retirement remains pending"))
}

/// Closes actual owned bodies and containing controls without claiming native return.
///
/// Native/Service settlement remains a separate operation in the caller. The
/// component file controls use this same primitive without supplying a Main role.
pub(super) fn retry_body_and_controls(
    slot: &CleanupSlot,
    epoch: u64,
) -> Result<(), LifecycleApiError> {
    if let Some(_attempt) = PhaseAttempt::claim(slot, CleanupPhase::Queued, CleanupPhase::Retrying)
    {
        let attempted = retry_queued_body(slot, epoch);
        if attempted.is_err() {
            return attempted;
        }
    }
    if let Some(_attempt) =
        PhaseAttempt::claim(slot, CleanupPhase::OwnerDestroyed, CleanupPhase::Completing)
    {
        let attempted = close_controls(slot, epoch);
        if attempted.is_err() {
            if !slot.is(CleanupPhase::DestructionRefused) {
                slot.publish(CleanupPhase::OwnerDestroyed);
            }
            return attempted;
        }
        slot.controls_closed_epoch.store(epoch, Ordering::Release);
        slot.publish(CleanupPhase::PostBodyPending);
    }
    Ok(())
}

fn retry_queued_body(slot: &CleanupSlot, epoch: u64) -> Result<(), LifecycleApiError> {
    queued_owner::retry(slot, epoch)
}

fn close_controls(slot: &CleanupSlot, epoch: u64) -> Result<(), LifecycleApiError> {
    {
        let service = slot
            .service
            .try_lock()
            .map_err(|_| refusal("queued body ownership is borrowed or poisoned"))?;
        if service.epoch != epoch || service.queued_owner.is_some() || service.queued_owner_borrowed
        {
            return Err(refusal(
                "containing credit still retains its actual queued body",
            ));
        }
    }
    // A Target's Main-paid pending owner may depend on actual Loop body
    // destruction. Its own in-place closure therefore follows that cut, while
    // all World-paid fields still precede containing credit return.
    let prepared_present = slot
        .prepared
        .try_lock()
        .map_err(|_| refusal("prepared body closure is borrowed or poisoned"))?
        .owner
        .is_some();
    if prepared_present {
        prepared_driver::retry_prepared(slot, epoch)?;
    }
    let mut cell = slot
        .cell
        .lock()
        .map_err(|_| refusal("containing World credit metadata is poisoned"))?;
    if cell.epoch != epoch || cell.owner.is_some() || cell.incoming_post_body.is_some() {
        slot.publish(CleanupPhase::DestructionRefused);
        return Err(refusal("containing World credit retains an actual body"));
    }
    let world_return = cell
        .post_body
        .as_ref()
        .is_some_and(ProductionVmConstructionPostBody::has_world_return);
    if cell.controls_bound != cell.controls.is_some() || cell.controls_bound != world_return {
        return Err(refusal(
            "actual World loan and containing-body lease are not paired",
        ));
    }
    if let (Some(controls), Some(body)) = (cell.controls.as_ref(), cell.post_body.as_ref()) {
        if !body.matches_world_controls(controls) {
            return Err(refusal(
                "postbody World loan differs from its actual containing lease",
            ));
        }
    }
    if let Some(controls) = cell.controls.as_mut()
        && let Err(first) = controls.close_after_owner_destruction()
    {
        cell.control_failure.get_or_insert(first);
        return Err(refusal("same containing World credit remains retained"));
    }
    drop(cell.controls.take());
    Ok(())
}

fn retry_post_body(slot: &CleanupSlot, epoch: u64) -> Result<(), LifecycleApiError> {
    // This same preborn Service cell retains native obligations through callbacks.
    // The control mutex is released before any saved-cleanup effect, so exact
    // body/Input delivery never waits on native or Service cleanup under it.
    let mut service = slot
        .service
        .try_lock()
        .map_err(|_| refusal("same Service return is borrowed or poisoned"))?;
    if service.epoch != epoch || service.queued_owner.is_some() || service.queued_owner_borrowed {
        return Err(refusal(
            "same native return retains another epoch or queued body",
        ));
    }
    let Some(role) = service.role else {
        slot.publish(CleanupPhase::DestructionRefused);
        return Err(refusal("actual prepared role metadata is absent"));
    };
    if service.return_body.is_none() {
        let mut cell = slot
            .cell
            .try_lock()
            .map_err(|_| refusal("same native return metadata is borrowed or poisoned"))?;
        if cell.epoch != epoch || cell.owner.is_some() || cell.controls.is_some() {
            slot.publish(CleanupPhase::DestructionRefused);
            return Err(refusal(
                "native return still owns a body or containing credit",
            ));
        }
        service.return_body = cell.post_body.take();
    }
    let Some(body) = service.return_body.as_mut() else {
        return Err(refusal("same role has no actual native return obligation"));
    };
    let matches_role = match role {
        PreparedRole::Source => body.has_source_return() && !body.has_target_return(),
        PreparedRole::Target => body.has_target_return() && !body.has_source_return(),
    };
    if !matches_role {
        return Err(refusal(
            "postbody owners differ from the actual prepared role",
        ));
    }
    let returned = body.retry_returns();
    if body.worlds_physically_returned() {
        slot.worlds_returned_epoch.store(epoch, Ordering::Release);
    }
    let native_returned = match role {
        PreparedRole::Source => slot.worlds_returned_epoch.load(Ordering::Acquire) >= epoch,
        PreparedRole::Target => body.targets_physically_returned(),
    };
    if !(body.has_source_return() || body.has_target_return()) || !returned {
        return Err(refusal(
            "same native return or observer remains outstanding",
        ));
    }
    let no_world = body.world_never_entered();
    if !transport_receiver::retry_transport_return(slot, &mut service, epoch) {
        return Err(refusal(
            "same transport receiver return remains unacknowledged",
        ));
    }
    if service.epoch != epoch {
        return Err(refusal("same Service retirement input epoch changed"));
    }
    if no_world || native_returned {
        {
            // The Service mutex precedes control metadata. Adoption moves existing
            // fields only; actual alias cleanup runs after releasing the cell lock.
            let mut cell = slot
                .cell
                .try_lock()
                .map_err(|_| refusal("receiving input transfer is borrowed or poisoned"))?;
            if cell.epoch != epoch {
                return Err(refusal("same receiving input epoch changed"));
            }
            if cell.retirement_input.is_some() {
                let Some(start) = service.start.as_mut() else {
                    return Err(refusal("same receiving input has no Source Service phase"));
                };
                start
                    .adopt_retirement_input(&mut cell.retirement_input)
                    .map_err(refusal)?;
            }
        }
        if let Some(start) = service.start.as_mut() {
            let closed = if no_world {
                start.retry_adopted_aliases_before_world_cleanup()
            } else {
                start.retry_adopted_aliases_after_world_cleanup()
            };
            if !closed {
                return Err(refusal(
                    "same receiving aliases or explicit receiver return remain pending",
                ));
            }
        }
    } else {
        let cell = slot
            .cell
            .try_lock()
            .map_err(|_| refusal("receiving input proof is borrowed or poisoned"))?;
        if cell.retirement_input.is_some() {
            return Err(refusal(
                "receiving input still waits for its actual World return",
            ));
        }
    }
    if service.epoch != epoch || slot.external_receivers.load(Ordering::Acquire) != 0 {
        return Err(refusal(
            "same Service external receivers remain outstanding",
        ));
    }
    if service.panic_payload.is_some() {
        slot.publish(CleanupPhase::DestructionRefused);
        return Err(refusal("same Service retains its actual panic payload"));
    }
    if let Some(start) = service.start.as_mut() {
        if slot.export_abandoned.load(Ordering::Acquire) {
            start.abandon_imported_export();
        }
        let attempted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if no_world {
                start.retry_before_world_cleanup()
            } else {
                start.retry_after_world_cleanup()
            }
        }));
        match attempted {
            Ok(true) if start.is_released() => {}
            Ok(_) => return Err(refusal("same Service retains its actual cleanup phase")),
            Err(payload) => {
                service.panic_payload = Some(payload);
                slot.publish(CleanupPhase::DestructionRefused);
                return Err(refusal("same Service cleanup retains its panic payload"));
            }
        }
    }
    Ok(())
}
