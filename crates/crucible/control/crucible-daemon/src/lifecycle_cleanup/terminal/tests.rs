//! Unissued terminal storage controls; no Main or native return is fabricated.

use super::*;
use std::fs::File;
use std::os::fd::AsRawFd;

struct FileOwner {
    file: File,
    slot: Weak<CleanupSlot>,
    dropped: Arc<AtomicBool>,
    outside_locks: Arc<AtomicBool>,
}

impl Drop for FileOwner {
    fn drop(&mut self) {
        if let Some(slot) = self.slot.upgrade() {
            self.outside_locks.store(
                available(&slot.prepared) && available(&slot.service) && available(&slot.cell),
                Ordering::Release,
            );
        }
        self.dropped.store(true, Ordering::Release);
    }
}

fn available<T>(mutex: &Mutex<T>) -> bool {
    match mutex.try_lock() {
        Ok(_) | Err(std::sync::TryLockError::Poisoned(_)) => true,
        Err(std::sync::TryLockError::WouldBlock) => false,
    }
}

fn slot(epoch: u64) -> Arc<CleanupSlot> {
    let slot = Arc::new(CleanupSlot::unissued_for_test(
        epoch,
        CleanupPhase::TerminalOwned,
    ));
    slot.report_references.store(1, Ordering::Release);
    {
        let mut prepared = slot.prepared.lock().unwrap();
        prepared.epoch = epoch;
        prepared.body_closed = true;
        prepared.post_body_taken = true;
    }
    slot
}

fn fields(slot: &Arc<CleanupSlot>) -> (TerminalFields, Arc<AtomicBool>, Arc<AtomicBool>) {
    let dropped = Arc::new(AtomicBool::new(false));
    let outside = Arc::new(AtomicBool::new(false));
    let owner = Box::new(FileOwner {
        file: tempfile::tempfile().unwrap(),
        slot: Arc::downgrade(slot),
        dropped: dropped.clone(),
        outside_locks: outside.clone(),
    });
    (
        TerminalFields {
            role: None,
            metadata_return: None,
            prepared: Some(owner),
            projection: None,
            history_projection: None,
            service: None,
            control_failure: None,
            prepared_cleanup_first: None,
            cleanup_first: Some(crate::ProductionVmConstructionCleanupError::Retained(
                "first",
            )),
            access: Some(ServiceMainPreclaimError::Role("original access")),
            receiver: None,
            panic_payload: None,
        },
        dropped,
        outside,
    )
}

fn owner(fields: &TerminalFields) -> &FileOwner {
    fields.prepared.as_ref().unwrap().downcast_ref().unwrap()
}

#[test]
fn deferred_terminal_keeps_same_box_file_and_history_until_disposal_outside_locks() {
    let slot = slot(17);
    let (mut retained, dropped, outside) = fields(&slot);
    let address = std::ptr::from_ref(owner(&retained));
    let descriptor = owner(&retained).file.as_raw_fd();
    let mut body = ProductionVmConstructionPostBody::history_only();

    for _ in 0..3 {
        assert!(return_terminal_fields(&slot, 17, &mut body, retained).is_ok());
        report_refs::release(&slot, 17, false);
        assert!(slot.is(CleanupPhase::TerminalReady));
        assert_eq!(slot.report_references.load(Ordering::Acquire), 0);
        assert!(!dropped.load(Ordering::Acquire));
        assert_eq!(slot.completed_epoch.load(Ordering::Acquire), 0);
        assert_eq!(slot.worlds_returned_epoch.load(Ordering::Acquire), 0);
        assert!(slot.service.lock().unwrap().role.is_none());

        // Only the field/pin primitive is exercised. This unissued header has
        // no containing Main, native return or Service completion authority.
        assert!(report_refs::register(&slot, 17));
        assert!(slot.claim(CleanupPhase::TerminalReady, CleanupPhase::TerminalOwned));
        {
            let mut prepared = slot.prepared.lock().unwrap();
            let mut service = slot.service.lock().unwrap();
            let mut cell = slot.cell.lock().unwrap();
            retained = TerminalFields::take(&mut prepared, &mut service, &mut cell);
            body = service.return_body.take().unwrap();
        }
        assert_eq!(std::ptr::from_ref(owner(&retained)), address);
        assert_eq!(owner(&retained).file.as_raw_fd(), descriptor);
        assert!(matches!(
            retained.access.as_ref(),
            Some(ServiceMainPreclaimError::Role("original access"))
        ));
        assert!(matches!(
            retained.cleanup_first.as_ref(),
            Some(crate::ProductionVmConstructionCleanupError::Retained(
                "first"
            ))
        ));
    }

    drop(retained);
    drop(body);
    report_refs::release(&slot, 17, false);
    assert!(dropped.load(Ordering::Acquire));
    assert!(outside.load(Ordering::Acquire));
    assert!(!slot.is(CleanupPhase::Free));
}

#[test]
fn stale_terminal_return_preserves_the_actual_outside_payload() {
    let slot = slot(23);
    let (retained, dropped, outside) = fields(&slot);
    let address = std::ptr::from_ref(owner(&retained));
    let mut body = ProductionVmConstructionPostBody::history_only();
    let retained = match return_terminal_fields(&slot, 22, &mut body, retained) {
        Err(retained) => retained,
        Ok(()) => panic!("stale terminal must not replace another epoch"),
    };
    assert_eq!(std::ptr::from_ref(owner(&retained)), address);
    assert!(!dropped.load(Ordering::Acquire));
    assert!(slot.prepared.lock().unwrap().owner.is_none());
    assert!(slot.is(CleanupPhase::TerminalOwned));
    drop(retained);
    assert!(outside.load(Ordering::Acquire));
}

#[test]
fn failed_metadata_callback_retains_its_actual_panic_file_and_blocks_disposal() {
    let slot = slot(31);
    let (mut retained, dropped, _) = fields(&slot);
    let panic_file = tempfile::tempfile().unwrap();
    let descriptor = panic_file.as_raw_fd();
    retained.panic_payload =
        Some(std::panic::catch_unwind(|| -> () { std::panic::panic_any(panic_file) }).unwrap_err());
    let mut body = ProductionVmConstructionPostBody::history_only();

    assert!(return_terminal_fields(&slot, 31, &mut body, retained).is_ok());
    report_refs::release(&slot, 31, false);
    assert!(slot.is(CleanupPhase::DestructionRefused));
    assert!(!dropped.load(Ordering::Acquire));
    let prepared = slot.prepared.lock().unwrap();
    assert_eq!(
        prepared
            .panic_payload
            .as_ref()
            .unwrap()
            .downcast_ref::<File>()
            .unwrap()
            .as_raw_fd(),
        descriptor,
    );
    assert!(prepared.owner.is_some());
    assert_eq!(slot.completed_epoch.load(Ordering::Acquire), 0);
}

#[test]
fn external_terminal_transfer_bars_late_report_enrollment() {
    let slot = slot(41);
    for phase in [CleanupPhase::TerminalOwned, CleanupPhase::TerminalDisposing] {
        slot.publish(phase);
        assert!(!report_refs::register(&slot, 41));
        assert_eq!(slot.report_references.load(Ordering::Acquire), 1);
    }
    assert_eq!(slot.completed_epoch.load(Ordering::Acquire), 0);
}

#[test]
fn poisoned_metadata_retains_the_same_body_without_reopening_disposal() {
    let slot = slot(51);
    let (retained, dropped, _) = fields(&slot);
    let address = std::ptr::from_ref(owner(&retained));
    let poison_slot = Arc::clone(&slot);
    let poisoner = std::thread::spawn(move || {
        let _guard = poison_slot.prepared.lock().unwrap();
        panic!("poison only the unissued metadata control");
    });
    assert!(poisoner.join().is_err());
    let mut body = ProductionVmConstructionPostBody::history_only();

    assert!(return_terminal_fields(&slot, 51, &mut body, retained).is_ok());
    report_refs::release(&slot, 51, false);
    assert!(slot.is(CleanupPhase::DestructionRefused));
    assert!(slot.prepared.is_poisoned());
    assert!(!dropped.load(Ordering::Acquire));
    let prepared = slot
        .prepared
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let retained_owner = prepared
        .owner
        .as_ref()
        .unwrap()
        .downcast_ref::<FileOwner>()
        .unwrap();
    assert_eq!(std::ptr::from_ref(retained_owner), address);
    assert_eq!(slot.completed_epoch.load(Ordering::Acquire), 0);
}

#[test]
fn outward_report_pin_preserves_same_file_and_history_after_previous_pin_returns() {
    // This is the existing unissued metadata/file fixture, not a Main or Source.
    let slot = slot(61);
    let (retained, dropped, outside) = fields(&slot);
    let address = std::ptr::from_ref(owner(&retained));
    let descriptor = owner(&retained).file.as_raw_fd();
    let mut body = ProductionVmConstructionPostBody::history_only();
    assert!(return_terminal_fields(&slot, 61, &mut body, retained).is_ok());

    // The outward error pins its exact epoch before the previous report drops.
    assert!(report_refs::register(&slot, 61));
    assert_eq!(slot.report_references.load(Ordering::Acquire), 2);
    assert!(!report_refs::register(&slot, 62));
    assert_eq!(slot.report_references.load(Ordering::Acquire), 2);
    report_refs::release(&slot, 61, false);
    assert_eq!(slot.report_references.load(Ordering::Acquire), 1);
    assert!(slot.is(CleanupPhase::TerminalReady));
    assert_eq!(slot.completed_epoch.load(Ordering::Acquire), 0);
    assert!(!dropped.load(Ordering::Acquire));
    {
        let prepared = slot.prepared.lock().unwrap();
        let actual = prepared
            .owner
            .as_ref()
            .unwrap()
            .downcast_ref::<FileOwner>()
            .unwrap();
        assert_eq!(std::ptr::from_ref(actual), address);
        assert_eq!(actual.file.as_raw_fd(), descriptor);
        assert!(matches!(
            slot.cell.lock().unwrap().first_failure.as_ref(),
            Some(crate::ProductionVmConstructionCleanupError::Retained(
                "first"
            ))
        ));
    }

    // Dropping the outward report still does not destroy the canonical payload.
    report_refs::release(&slot, 61, false);
    assert_eq!(slot.report_references.load(Ordering::Acquire), 0);
    assert!(!dropped.load(Ordering::Acquire));
    assert!(!slot.is(CleanupPhase::Free));
    assert!(report_refs::register(&slot, 61));
    assert!(slot.claim(CleanupPhase::TerminalReady, CleanupPhase::TerminalOwned));
    let retained = {
        let mut prepared = slot.prepared.lock().unwrap();
        let mut service = slot.service.lock().unwrap();
        let mut cell = slot.cell.lock().unwrap();
        body = service.return_body.take().unwrap();
        TerminalFields::take(&mut prepared, &mut service, &mut cell)
    };
    assert_eq!(std::ptr::from_ref(owner(&retained)), address);
    drop(retained);
    drop(body);
    assert!(dropped.load(Ordering::Acquire));
    assert!(outside.load(Ordering::Acquire));
    report_refs::release(&slot, 61, true);
    assert!(slot.is(CleanupPhase::Free));
    assert_eq!(slot.completed_epoch.load(Ordering::Acquire), 61);
    assert_eq!(slot.worlds_returned_epoch.load(Ordering::Acquire), 0);
}
