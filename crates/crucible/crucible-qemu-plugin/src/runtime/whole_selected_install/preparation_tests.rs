//! Actual same-map construction controls with an explicitly modeled native permit.

#![expect(
    clippy::unwrap_used,
    reason = "These controls panic on failed invariants."
)]

use std::cell::Cell;

use super::*;
use return_observation::{
    NativePreparationReturn, crucible_qemu_plugin_preparation_observation_v1,
};

thread_local! {
    static TUPLE: Cell<NativePreparation> = Cell::new(NativePreparation::default());
    static RETURN: Cell<NativePreparationReturn> = Cell::new(NativePreparationReturn::default());
    static RETURN_READS: Cell<usize> = const { Cell::new(0) };
    static STATUS: Cell<c_int> = const { Cell::new(0) };
    static BOUND: Cell<usize> = const { Cell::new(0) };
    static FAMILIES: Cell<u8> = const { Cell::new(0) };
    static READS: Cell<usize> = const { Cell::new(0) };
}

extern "C" fn register(_: u64, callback: PreparationCallback, userdata: *mut c_void) -> c_int {
    assert_eq!(callback as usize, prepare_on_rr as *const () as usize);
    assert!(!userdata.is_null());
    0
}

extern "C" fn read(destination: *mut NativePreparation) -> c_int {
    let status = STATUS.get();
    if status != 0 {
        return status;
    }
    READS.set(READS.get() + 1);
    // SAFETY: Capture supplies one initialized, exclusively borrowed tuple128.
    unsafe { destination.write(TUPLE.get()) };
    0
}

extern "C" fn read_return(destination: *mut NativePreparationReturn) -> c_int {
    RETURN_READS.set(RETURN_READS.get() + 1);
    let status = STATUS.get();
    if status != 0 {
        return status;
    }
    // SAFETY: The caller supplies one initialized, exclusively borrowed tuple144.
    unsafe { destination.write(RETURN.get()) };
    0
}

extern "C" fn bind(userdata: *mut c_void) -> c_int {
    assert!(READS.get() >= 2);
    assert!(!userdata.is_null());
    assert_ne!(userdata, TUPLE.get().userdata);
    assert_eq!(BOUND.replace(userdata as usize), 0);
    0
}

fn family(index: u8, userdata: *mut c_void) {
    assert_eq!(BOUND.get(), userdata as usize);
    assert_eq!(FAMILIES.get() & (1 << index), 0);
    FAMILIES.set(FAMILIES.get() | (1 << index));
}

extern "C" fn network(callback: Option<crate::QemuNetTxCbFn>, userdata: *mut c_void) {
    assert_eq!(
        callback.unwrap() as usize,
        closed_network as *const () as usize
    );
    family(0, userdata);
}

extern "C" fn block(
    submit: Option<crate::QemuBlkSubmitCbFn>,
    poll: Option<crate::QemuBlkPollCbFn>,
    userdata: *mut c_void,
) {
    assert_eq!(
        submit.unwrap() as usize,
        closed_block_submit as *const () as usize
    );
    assert_eq!(
        poll.unwrap() as usize,
        closed_block_poll as *const () as usize
    );
    family(1, userdata);
}

extern "C" fn event(
    poll: Option<crate::QemuBlkEventPollCbFn>,
    commit: Option<crate::QemuBlkEventCommitCbFn>,
    save: Option<crate::QemuBlkTransportSaveCbFn>,
    restore: Option<crate::QemuBlkTransportRestoreCbFn>,
    userdata: *mut c_void,
) {
    assert_eq!(
        poll.unwrap() as usize,
        closed_event_poll as *const () as usize
    );
    assert_eq!(
        commit.unwrap() as usize,
        closed_event_commit as *const () as usize
    );
    assert_eq!(save.unwrap() as usize, closed_save as *const () as usize);
    assert_eq!(
        restore.unwrap() as usize,
        closed_restore as *const () as usize
    );
    family(2, userdata);
}

extern "C" fn wait(callback: Option<crate::QemuBlkWaitCbFn>, userdata: *mut c_void) {
    assert_eq!(
        callback.unwrap() as usize,
        closed_wait as *const () as usize
    );
    family(3, userdata);
}

extern "C" fn ninep(
    start: Option<crate::QemuNinePBurstCbFn>,
    submit: Option<crate::QemuNinePSubmitCbFn>,
    poll: Option<crate::QemuNinePPollCbFn>,
    done: Option<crate::QemuNinePBurstCbFn>,
    userdata: *mut c_void,
) {
    assert_eq!(start.unwrap() as usize, closed_burst as *const () as usize);
    assert_eq!(
        submit.unwrap() as usize,
        closed_ninep_submit as *const () as usize
    );
    assert_eq!(
        poll.unwrap() as usize,
        closed_ninep_poll as *const () as usize
    );
    assert_eq!(done.unwrap() as usize, closed_burst as *const () as usize);
    family(4, userdata);
}

pub(super) fn modeled_apis() -> PreparationApis {
    PreparationApis {
        register,
        read,
        bind,
        read_return,
        mapping_hold: Some(mapping_hold::tests::modeled_apis()),
        network,
        block,
        block_event: event,
        block_wait: wait,
        ninep,
    }
}

fn tuple() -> NativePreparation {
    NativePreparation {
        phase: 1,
        plugin_id: 17,
        process: u64::from(std::process::id()),
        actual_tid: current_tid().unwrap(),
        loader_tid: current_tid().unwrap(),
        deadline_ns: super::super::monotonic_ns().unwrap() + 5_000_000_000,
        callback: prepare_on_rr as *const () as usize,
        userdata: std::ptr::dangling_mut(),
        constructor: std::ptr::dangling(),
        cpu: std::ptr::dangling(),
        permit: std::ptr::dangling(),
        ..NativePreparation::default()
    }
}

#[test]
fn preparation_tuple_rejects_wrong_context_and_expired_original_deadline() {
    let apis = modeled_apis();
    let original = tuple();
    TUPLE.set(original);
    assert_eq!(apis.capture().unwrap(), original);

    let mut invalid = Vec::new();
    let mut changed = original;
    changed.actual_tid += 1;
    invalid.push(changed);
    changed = original;
    changed.process += 1;
    invalid.push(changed);
    changed = original;
    changed.phase = 2;
    invalid.push(changed);
    changed = original;
    changed.cpu_index = 1;
    invalid.push(changed);
    changed = original;
    changed.callback += 1;
    invalid.push(changed);
    changed = original;
    changed.deadline_ns = 1;
    invalid.push(changed);
    changed = original;
    changed.permit = std::ptr::null();
    invalid.push(changed);
    for changed in invalid {
        TUPLE.set(changed);
        assert_eq!(apis.capture().unwrap_err(), -libc::ESTALE);
    }

    STATUS.set(-libc::ENOTSUP);
    assert_eq!(apis.capture().unwrap_err(), -libc::ENOTSUP);
    STATUS.set(0);
}

pub(super) fn exercise_preparation(original: Arc<SharedCallbackCustody>) {
    let loader_tid = original.loader_tid;
    std::thread::spawn(move || {
        assert_ne!(current_tid().unwrap(), loader_tid);
        let userdata = Arc::as_ptr(&original).cast_mut().cast();
        TUPLE.set(NativePreparation {
            plugin_id: original.plugin_id,
            loader_tid,
            userdata,
            constructor: original.constructor_identity.load(Ordering::Acquire) as *const c_void,
            cpu: original.cpu_identities[0].load(Ordering::Acquire) as *const c_void,
            setup_digest: original.setup_digest,
            ..tuple()
        });
        assert_eq!(prepare_on_rr(userdata), 0);
        assert_eq!(FAMILIES.get(), 31);
        let birth = TUPLE.get();
        RETURN.set(NativePreparationReturn {
            phase: 2,
            cpu_index: birth.cpu_index,
            plugin_id: birth.plugin_id,
            process: birth.process,
            actual_tid: birth.actual_tid,
            loader_tid: birth.loader_tid,
            deadline_ns: birth.deadline_ns,
            callback: birth.callback,
            userdata: birth.userdata,
            constructor: birth.constructor,
            cpu: birth.cpu,
            permit: birth.permit,
            engine: BOUND.get() as *mut c_void,
            setter_mask: 31,
            setup_digest: birth.setup_digest,
            ..NativePreparationReturn::default()
        });
        let before = RETURN_READS.get();
        let observed = crucible_qemu_plugin_preparation_observation_v1(userdata);
        assert_eq!(RETURN_READS.get(), before + 1);
        assert_eq!(observed.status, 0);
        assert_eq!(observed.process, birth.process);
        assert_eq!(observed.actual_tid, birth.actual_tid);
        assert_eq!(observed.loader_tid, birth.loader_tid);
        assert_eq!(observed.observed_mask, 15);
        assert_eq!(observed.family_mask, 31);
        assert_eq!(observed.setup_digest, birth.setup_digest);
        assert_eq!(observed.reserved, 0);

        let mut changed = RETURN.get();
        changed.engine = std::ptr::dangling_mut();
        assert_eq!(
            return_observation::compare_retained_for_test(&original, changed, userdata)
                .unwrap_err(),
            -libc::ESTALE
        );
        changed = RETURN.get();
        changed.permit = std::ptr::null();
        assert_eq!(
            return_observation::compare_retained_for_test(&original, changed, userdata)
                .unwrap_err(),
            -libc::ESTALE
        );
        assert!(!original.failed.load(Ordering::Acquire));
        ENGINE.with_borrow(|engine| {
            let engine = engine.as_ref().unwrap();
            assert!(Arc::ptr_eq(&engine._original, &original));
            assert_eq!(engine._block.vm_slot(), original.args.slot());
            assert_eq!(engine._ninep.vm_slot(), original.args.slot());
            assert_eq!(
                engine._network_tx.next_seq(),
                original.args.network_tx_next_seq()
            );
            assert_eq!(engine._block.next_request_id(), 0);
            assert_eq!(engine._ninep.next_request_id(), 0);
        });
        mapping_hold::tests::exercise(&original, birth);
    })
    .join()
    .unwrap();
}

pub(super) fn exercise_refusal(original: &Arc<SharedCallbackCustody>) {
    // The caller holds real original mapping/Ready/journal guards. Holding the
    // RR-local RefCell too makes premature constructor access observable.
    ENGINE.with_borrow_mut(|_held| {
        STATUS.set(-libc::ESTALE);
        let before = RETURN_READS.get();
        let refused = crucible_qemu_plugin_preparation_observation_v1(
            Arc::as_ptr(original).cast_mut().cast(),
        );
        assert_eq!(RETURN_READS.get(), before + 1);
        assert_eq!(refused.status, -libc::ESTALE);
        assert_eq!(refused.process, 0);
        assert_eq!(refused.observed_mask, 0);
        assert_eq!(refused.family_mask, 0);
        assert_eq!(refused.setup_digest, [0; 32]);
        assert_eq!(
            prepare_on_rr(Arc::as_ptr(original).cast_mut().cast()),
            -libc::ESTALE
        );
        assert!(original.failed.load(Ordering::Acquire));
        STATUS.set(0);
    });
}

#[test]
fn return_observation_rejects_changed_revoked_source_context_before_engine_access() {
    let apis = modeled_apis();
    let birth = tuple();
    let original = NativePreparationReturn {
        phase: 2,
        plugin_id: birth.plugin_id,
        process: birth.process,
        actual_tid: birth.actual_tid,
        loader_tid: birth.loader_tid,
        deadline_ns: birth.deadline_ns,
        callback: birth.callback,
        userdata: birth.userdata,
        constructor: birth.constructor,
        cpu: birth.cpu,
        permit: birth.permit,
        engine: std::ptr::dangling_mut(),
        setter_mask: 31,
        ..NativePreparationReturn::default()
    };
    RETURN.set(original);
    assert_eq!(return_observation::capture(&apis).unwrap(), original);

    let mut invalid = Vec::new();
    let mut changed = original;
    changed.phase = 1;
    invalid.push(changed);
    changed = original;
    changed.actual_tid += 1;
    invalid.push(changed);
    changed = original;
    changed.process += 1;
    invalid.push(changed);
    changed = original;
    changed.setter_mask = 15;
    invalid.push(changed);
    changed = original;
    changed.reserved = 1;
    invalid.push(changed);
    changed = original;
    changed.deadline_ns = 1;
    invalid.push(changed);
    changed = original;
    changed.engine = std::ptr::null_mut();
    invalid.push(changed);

    // A held real RR RefCell makes any premature engine inspection fail. These
    // refusals must depend on the fresh native read before inspecting that cell.
    ENGINE.with_borrow_mut(|_held| {
        for changed in invalid {
            RETURN.set(changed);
            assert_eq!(
                return_observation::capture(&apis).unwrap_err(),
                -libc::ESTALE
            );
        }
        STATUS.set(-libc::ENOTSUP);
        assert_eq!(
            return_observation::capture(&apis).unwrap_err(),
            -libc::ENOTSUP
        );
        STATUS.set(0);
    });
}

pub(super) fn bound_engine_for_mapping_control() -> *mut c_void {
    BOUND.get() as *mut c_void
}
