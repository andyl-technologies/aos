//! Borrows the same queued body without holding publication locks through effects.
//!
//! The existing Service cell stores its original Box between attempts. One
//! scoped guard temporarily owns that Box while the role is exclusively Retrying;
//! every early return/unwind restores it before the outer phase guard can make
//! another pass eligible. Callbacks and destructors hold neither queue mutex.

use super::*;

type Owner = dyn ProductionVmCleanupOwner<
        Failure = crate::ProductionVmConstructionCleanupError,
        PostBody = ProductionVmConstructionPostBody,
    >;

struct QueuedOwner<'a> {
    slot: &'a CleanupSlot,
    owner: Option<Box<Owner>>,
}

impl<'a> QueuedOwner<'a> {
    fn borrow(slot: &'a CleanupSlot, epoch: u64) -> Result<Self, LifecycleApiError> {
        let mut service = slot
            .service
            .try_lock()
            .map_err(|_| refusal("queued owner storage is borrowed or poisoned"))?;
        if service.epoch != epoch
            || service.queued_owner_borrowed
            || service.panic_payload.is_some()
        {
            slot.publish(CleanupPhase::DestructionRefused);
            return Err(refusal("same queued owner storage is stale or uncertain"));
        }
        let (mut cell, poisoned) = match slot.cell.lock() {
            Ok(cell) => (cell, false),
            Err(poison) => (poison.into_inner(), true),
        };
        if cell.epoch != epoch
            || cell.panic_payload.is_some()
            || (service.queued_owner.is_some() && cell.owner.is_some())
        {
            slot.publish(CleanupPhase::DestructionRefused);
            return Err(refusal("same queued owner custody is contradictory"));
        }
        if service.queued_owner.is_none() {
            service.queued_owner = cell.owner.take();
        }
        let Some(owner) = service.queued_owner.take() else {
            slot.publish(CleanupPhase::DestructionRefused);
            return Err(refusal("same queued body is absent"));
        };
        service.queued_owner_borrowed = true;
        drop(cell);
        drop(service);
        let borrowed = Self {
            slot,
            owner: Some(owner),
        };
        if poisoned {
            // Preserve the existing canonical primitive's read-poison history.
            // The actual owner is already guarded before history is merged.
            slot.cell.clear_poison();
            record_first(slot, crate::ProductionVmConstructionCleanupError::Poisoned);
        }
        Ok(borrowed)
    }

    fn into_destruction(mut self) -> Result<Box<Owner>, Self> {
        let Some(owner) = self.owner.take() else {
            self.slot.publish(CleanupPhase::DestructionRefused);
            return Err(self);
        };
        let mut service = match self.slot.service.lock() {
            Ok(service) => service,
            Err(poison) => {
                self.slot.publish(CleanupPhase::DestructionRefused);
                poison.into_inner()
            }
        };
        service.queued_owner_borrowed = false;
        drop(service);
        Ok(owner)
    }
}

impl Drop for QueuedOwner<'_> {
    fn drop(&mut self) {
        let Some(owner) = self.owner.take() else {
            return;
        };
        let mut service = match self.slot.service.lock() {
            Ok(service) => service,
            Err(poison) => {
                self.slot.publish(CleanupPhase::DestructionRefused);
                poison.into_inner()
            }
        };
        // Only this move-only guard can fill its borrowed slot. Epoch reuse and
        // other drivers are excluded by Retrying/borrowed until this restore.
        service.queued_owner = Some(owner);
        service.queued_owner_borrowed = false;
    }
}

pub(super) fn retry(slot: &CleanupSlot, epoch: u64) -> Result<(), LifecycleApiError> {
    let mut borrowed = QueuedOwner::borrow(slot, epoch)?;
    let complete = {
        let cell = control(slot);
        cell.owner_cleanup_complete
    };
    if !complete {
        if !slot.is(CleanupPhase::Retrying) {
            return Err(refusal("same queued body entered quarantine"));
        }
        let Some(owner) = borrowed.owner.as_mut() else {
            return Err(refusal("same queued body borrow is absent"));
        };
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| owner.retry_cleanup())) {
            Ok(Ok(())) => control(slot).owner_cleanup_complete = true,
            Ok(Err(crate::ProductionVmConstructionCleanupError::SharedAliasesPending)) => {
                // Actual allocation aliases retain healthy body custody. This
                // exact storage state reports neither a failure nor closure.
                return Err(refusal("same shared Source allocation remains borrowed"));
            }
            Ok(Err(first)) => {
                record_first(slot, first);
                return Err(refusal("same actual lifecycle retains cleanup"));
            }
            Err(payload) => {
                control(slot).panic_payload = Some(payload);
                slot.publish(CleanupPhase::DestructionRefused);
                return Err(refusal("same actual lifecycle retains its cleanup panic"));
            }
        }
    }
    let transferred = {
        let cell = control(slot);
        cell.owner_post_body_taken
    };
    if !transferred {
        if !slot.is(CleanupPhase::Retrying) {
            return Err(refusal("same postbody transfer entered quarantine"));
        }
        let Some(owner) = borrowed.owner.as_mut() else {
            return Err(refusal("same queued owner disappeared before transfer"));
        };
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| owner.take_post_body())) {
            Ok(Ok(incoming)) => {
                let mut cell = control(slot);
                cell.incoming_post_body = incoming;
                cell.owner_post_body_taken = true;
            }
            Ok(Err(first)) => {
                record_first(slot, first);
                return Err(refusal(
                    "same actual lifecycle retains postbody obligations",
                ));
            }
            Err(payload) => {
                control(slot).panic_payload = Some(payload);
                slot.publish(CleanupPhase::DestructionRefused);
                return Err(refusal("same actual lifecycle retains its transfer panic"));
            }
        }
    }
    {
        let mut cell = control(slot);
        if let Some(incoming) = cell.incoming_post_body.as_ref()
            && cell
                .post_body
                .as_ref()
                .is_some_and(|body| !body.can_append(incoming))
        {
            return Err(refusal(
                "same actual lifecycle retains independent postbody owners",
            ));
        }
        if let Some(incoming) = cell.incoming_post_body.take() {
            match cell.post_body.as_mut() {
                Some(body) => {
                    if let Err(incoming) = body.append(incoming) {
                        cell.incoming_post_body = Some(incoming);
                        return Err(refusal("same queued postbody owners could not be merged"));
                    }
                }
                None => cell.post_body = Some(incoming),
            }
        }
    }
    if !slot.claim(CleanupPhase::Retrying, CleanupPhase::Destroying) {
        return Err(refusal(
            "same queued body entered quarantine before destruction",
        ));
    }
    let owner = match borrowed.into_destruction() {
        Ok(owner) => owner,
        Err(_borrowed) => return Err(refusal("actual queued body was absent before destruction")),
    };
    // Every obligation already resides in Main. The actual body is destroyed
    // outside both control and Service mutexes, including its nested fields.
    if !terminal::destroy_payload(slot, owner) {
        return Err(refusal("actual queued body destruction retains its panic"));
    }
    let cell = control(slot);
    if cell.epoch != epoch || cell.owner.is_some() {
        slot.publish(CleanupPhase::DestructionRefused);
        return Err(refusal("actual queued body destruction metadata changed"));
    }
    slot.body_destroyed_epoch.store(epoch, Ordering::Release);
    drop(cell);
    if !slot.claim(CleanupPhase::Destroying, CleanupPhase::OwnerDestroyed) {
        return Err(refusal(
            "actual body died while its role entered quarantine",
        ));
    }
    Ok(())
}

fn control(slot: &CleanupSlot) -> std::sync::MutexGuard<'_, CleanupCell> {
    match slot.cell.lock() {
        Ok(cell) => cell,
        Err(poison) => {
            slot.publish(CleanupPhase::DestructionRefused);
            poison.into_inner()
        }
    }
}

fn record_first(slot: &CleanupSlot, first: crate::ProductionVmConstructionCleanupError) {
    let previous = control(slot).first_failure.take();
    // Combining finite histories can destroy later owned leaves. Do so outside
    // both publication locks while the scoped guard still owns the real body.
    let merged = match previous {
        Some(previous) => previous.with_later_failure(first),
        None => first,
    };
    control(slot).first_failure = Some(merged);
}
