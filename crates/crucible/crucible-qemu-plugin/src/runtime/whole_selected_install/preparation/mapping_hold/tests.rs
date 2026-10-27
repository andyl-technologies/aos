//! Source-first mapping callback controls; native window certificates are modeled.

#![expect(
    clippy::unwrap_used,
    reason = "These controls panic on failed invariants."
)]

use super::*;
use std::cell::Cell;

thread_local! {
    static SOURCE: Cell<NativeMappingHold> = Cell::new(NativeMappingHold::default());
    static SOURCE_STATUS: Cell<c_int> = const { Cell::new(0) };
    static DESTINATION: Cell<usize> = const { Cell::new(0) };
    static READS: Cell<u32> = const { Cell::new(0) };
    static AUTHENTICATIONS: Cell<u32> = const { Cell::new(0) };
    static STALE_POST: Cell<bool> = const { Cell::new(false) };
}

extern "C" fn read(destination: *mut NativeMappingHold) -> c_int {
    if let Some(apis) = super::coupled::active_apis() {
        return (apis.read)(destination);
    }
    let count = READS.get() + 1;
    READS.set(count);
    let status = SOURCE_STATUS.get();
    if status != 0 || (STALE_POST.get() && count == 2) {
        return if status != 0 { status } else { -libc::ESTALE };
    }
    if count > 2 {
        return -libc::ESTALE;
    }
    // SAFETY: The real caller provides one initialized exclusive tuple144.
    unsafe { destination.write(SOURCE.get()) };
    0
}

extern "C" fn authenticate(destination: *const QemuPluginHotForkBarrierStatus) -> c_int {
    if let Some(apis) = super::coupled::active_apis() {
        return (apis.authenticate_status)(destination);
    }
    AUTHENTICATIONS.set(AUTHENTICATIONS.get() + 1);
    if READS.get() == 0 || destination as usize != DESTINATION.get() || destination.is_null() {
        return -libc::ESTALE;
    }
    0
}

pub(in super::super) fn modeled_apis() -> MappingHoldApis {
    MappingHoldApis {
        read,
        authenticate_status: authenticate,
    }
}

fn valid_tuple() -> NativeMappingHold {
    NativeMappingHold {
        phase: 1,
        plugin_id: 17,
        process: u64::from(std::process::id()),
        actual_tid: current_tid().unwrap(),
        loader_tid: current_tid().unwrap(),
        deadline_ns: super::super::super::monotonic_ns().unwrap() + 5_000_000_000,
        callback: super::super::super::closed_barrier as *const () as usize,
        userdata: std::ptr::dangling_mut(),
        constructor: std::ptr::dangling(),
        cpu: std::ptr::dangling(),
        permit: std::ptr::without_provenance(2),
        engine: std::ptr::dangling_mut(),
        ring_count: 6,
        action: HOLD,
        ..NativeMappingHold::default()
    }
}

#[test]
fn mapping_tuple_refuses_wrong_family_thread_deadline_and_six_census_before_engine_guard() {
    let apis = modeled_apis();
    let original = valid_tuple();
    let mut invalid = Vec::new();
    let mut changed = original;
    changed.phase = 2;
    invalid.push(changed);
    changed = original;
    changed.actual_tid += 1;
    invalid.push(changed);
    changed = original;
    changed.process += 1;
    invalid.push(changed);
    changed = original;
    changed.ring_count = 9;
    invalid.push(changed);
    changed = original;
    changed.action = 2;
    invalid.push(changed);
    changed = original;
    changed.callback += 1;
    invalid.push(changed);
    changed = original;
    changed.deadline_ns = 1;
    invalid.push(changed);
    changed = original;
    changed.engine = std::ptr::null_mut();
    invalid.push(changed);

    ENGINE.with_borrow_mut(|_guard| {
        for changed in invalid {
            SOURCE.set(changed);
            READS.set(0);
            assert_eq!(apis.capture(HOLD).unwrap_err(), -libc::ESTALE);
        }
        SOURCE_STATUS.set(-libc::ENOTSUP);
        READS.set(0);
        assert_eq!(apis.capture(HOLD).unwrap_err(), -libc::ENOTSUP);
        SOURCE_STATUS.set(0);
    });
}

#[test]
fn status_identity_checks_foreign_pointer_without_dereference_or_engine_loan() {
    let apis = modeled_apis();
    SOURCE.set(valid_tuple());
    READS.set(0);
    DESTINATION.set(1);
    ENGINE.with_borrow_mut(|_guard| {
        apis.capture(HOLD).unwrap();
        assert_eq!(
            apis.authenticate(std::ptr::null_mut()).unwrap_err(),
            -libc::ESTALE
        );
        assert_eq!(
            apis.authenticate(std::ptr::without_provenance_mut(usize::MAX))
                .unwrap_err(),
            -libc::ESTALE
        );
        assert_eq!(READS.get(), 1);
    });
}

pub(in super::super) fn failure_control_requested() -> bool {
    matches!(
        std::env::var("RFC0025_MAPPING_HOLD_CONTROL").as_deref(),
        Ok("stale-post" | "foreign-status" | "native-stale")
    )
}

pub(in super::super) fn exercise(original: &Arc<SharedCallbackCustody>, birth: NativePreparation) {
    if super::coupled::requested() {
        super::coupled::exercise(original, birth);
        return;
    }
    let mut status = QemuPluginHotForkBarrierStatus::default();
    let destination = std::ptr::from_mut(&mut status);
    let tuple = NativeMappingHold {
        plugin_id: birth.plugin_id,
        process: birth.process,
        actual_tid: birth.actual_tid,
        loader_tid: birth.loader_tid,
        deadline_ns: birth.deadline_ns,
        userdata: birth.userdata,
        constructor: birth.constructor,
        cpu: birth.cpu,
        engine: super::super::tests::bound_engine_for_mapping_control(),
        setup_digest: birth.setup_digest,
        ..valid_tuple()
    };
    SOURCE.set(tuple);
    SOURCE_STATUS.set(0);
    DESTINATION.set(destination as usize);
    READS.set(0);
    AUTHENTICATIONS.set(0);
    let mode = std::env::var("RFC0025_MAPPING_HOLD_CONTROL").unwrap_or_default();
    if mode == "foreign-status" {
        DESTINATION.set(1);
        let setup = original.setup.get().unwrap();
        let _mapping_guard = setup.mapped_region().unwrap();
        ENGINE.with_borrow_mut(|_engine_guard| {
            assert_eq!(hold_on_rr(HOLD, destination, birth.userdata), -libc::ESTALE);
        });
        assert_eq!(READS.get(), 1);
        assert_eq!(AUTHENTICATIONS.get(), 1);
        assert_eq!(status, QemuPluginHotForkBarrierStatus::default());
        assert!(original.failed.load(Ordering::Acquire));
        return;
    }
    STALE_POST.set(mode == "stale-post");
    let result = hold_on_rr(HOLD, destination, birth.userdata);
    assert_eq!(READS.get(), 2);
    ENGINE.with_borrow(|slot| {
        let engine = slot.as_ref().unwrap();
        assert_eq!(engine.mapping_hold_journal.tuple, Some(tuple));
        let snapshot = engine.mapping_hold_journal.snapshot.unwrap();
        assert_eq!(snapshot.ring_count(), 6);
        assert_eq!(snapshot.held_rings(), 6);
        assert!(snapshot.quiescent());
        assert!(snapshot.mapping_excluded());
        assert!(engine.mapping_hold_journal.prepared_status.is_some());
    });
    if mode == "stale-post" {
        assert_eq!(result, -libc::ESTALE);
        assert_eq!(AUTHENTICATIONS.get(), 1);
        assert_eq!(status, QemuPluginHotForkBarrierStatus::default());
        assert!(original.failed.load(Ordering::Acquire));
    } else {
        assert_eq!(result, 0);
        assert_eq!(AUTHENTICATIONS.get(), 2);
        assert_eq!(status.schema_version, 7);
        assert_eq!(status.struct_size, 88);
        assert_eq!(status.ring_count, 6);
        assert_eq!(status.rings_held, 6);
        assert_eq!(status.ring_producers_in_flight, 0);
        assert_eq!(status.ring_consumers_in_flight, 0);
        assert_eq!(status.in_flight, 0);
        assert_eq!(status.worker_mask, 0);
        assert_eq!(status.parked_worker_mask, 0);
        assert_eq!(status.pending_worker_mask, 0);
        assert_eq!(status.worker_operations_in_flight, 0);
        assert!(!original.failed.load(Ordering::Acquire));
    }
}
