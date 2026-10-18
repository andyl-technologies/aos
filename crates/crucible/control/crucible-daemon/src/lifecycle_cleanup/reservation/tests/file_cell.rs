//! Exercises the real file/body primitive without fabricating a native Main role.
//!
//! These fixtures have no containing queue, World loan, Target return or Service.
//! Their completion records only actual file destruction and empty controls. The
//! production native driver continues to reject absent role/return metadata.

use super::*;

pub(super) fn begin_file_epoch(slot: &CleanupSlot) -> Result<u64, LifecycleApiError> {
    require_file_only(slot)?;
    let mut service = slot.service.lock().unwrap();
    let mut cell = slot.cell.lock().unwrap();
    if !slot.is(CleanupPhase::Reserving)
        || !service.is_empty()
        || cell.owner.is_some()
        || cell.panic_payload.is_some()
        || cell.first_failure.is_some()
        || slot.report_references.load(Ordering::Acquire) != 0
    {
        return Err(refusal("file cell retains its previous epoch"));
    }
    let epoch = cell
        .epoch
        .checked_add(1)
        .ok_or_else(|| refusal("file cell epoch exhausted"))?;
    service.epoch = epoch;
    cell.epoch = epoch;
    cell.handoff = false;
    cell.owner_cleanup_complete = false;
    cell.owner_post_body_taken = false;
    slot.retirement_requested.store(false, Ordering::Release);
    slot.terminal_disposed.store(false, Ordering::Release);
    slot.epoch.store(epoch, Ordering::Release);
    slot.publish(CleanupPhase::Reserved);
    Ok(epoch)
}

fn require_file_only(slot: &CleanupSlot) -> Result<(), LifecycleApiError> {
    let service = slot.service.lock().unwrap();
    let prepared = slot.prepared.lock().unwrap();
    let cell = slot.cell.lock().unwrap();
    if service.role.is_some()
        || service.start.is_some()
        || service.return_body.is_some()
        || prepared.owner.is_some()
        || cell.controls_bound
        || cell.controls.is_some()
        || cell.post_body.is_some()
        || cell.incoming_post_body.is_some()
        || slot.worlds_returned_epoch.load(Ordering::Acquire) != 0
    {
        return Err(refusal(
            "file fixture contains native or Main-owned authority",
        ));
    }
    Ok(())
}

pub(super) fn retry_file_cell(
    slot: &CleanupSlot,
    expected: Option<u64>,
) -> Result<(), LifecycleApiError> {
    require_file_only(slot)?;
    let epoch = slot.epoch.load(Ordering::Acquire);
    if expected.is_some_and(|expected| expected != epoch) {
        return Err(refusal("component file epoch changed"));
    }
    if slot.completed_epoch.load(Ordering::Acquire) >= epoch {
        return Ok(());
    }
    super::super::super::driver::retry_body_and_controls(slot, epoch)?;
    if slot.controls_closed_epoch.load(Ordering::Acquire) < epoch {
        return Err(refusal("actual file body or controls remain retained"));
    }
    require_file_only(slot)?;
    slot.publish(CleanupPhase::Closed);
    Ok(())
}

pub(super) fn dispose_file_receipt(
    receipt: &mut CleanupReservation,
    slot: &CleanupSlot,
) -> Result<(), LifecycleApiError> {
    require_file_only(slot)?;
    if !slot.is(CleanupPhase::Closed)
        || receipt.observed != ProductionVmCleanupStage::Complete
        || slot.body_destroyed_epoch.load(Ordering::Acquire) < receipt.epoch
        || slot.controls_closed_epoch.load(Ordering::Acquire) < receipt.epoch
        || slot.report_references.load(Ordering::Acquire) != usize::from(receipt.report_reference)
    {
        return Err(refusal(
            "component file receipt has not observed physical closure",
        ));
    }
    // Actual reports die before this component header can be reused. There is
    // no Main credit or native-return journal in this unissued file fixture.
    drop(receipt.first_failure.take());
    let remaining = slot.cell.lock().unwrap().first_failure.take();
    drop(remaining);
    // publish_owner registers a real nonissuing report pin even in this
    // queue-free fixture. Return that pin only after its leaves are destroyed.
    receipt.cancel_return_registration(slot);
    assert_eq!(slot.report_references.load(Ordering::Acquire), 0);
    receipt.terminal_history = Some(ProductionVmConstructionPostBody::history_only());
    slot.completed_epoch.store(receipt.epoch, Ordering::Release);
    slot.publish(CleanupPhase::Free);
    Ok(())
}
