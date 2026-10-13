//! Actual same-map construction controls with an explicitly modeled native permit.

#![expect(
    clippy::unwrap_used,
    reason = "These controls panic on failed invariants."
)]

use std::cell::Cell;

use super::*;

thread_local! {
    static TUPLE: Cell<NativePreparation> = Cell::new(NativePreparation::default());
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
    })
    .join()
    .unwrap();
}

pub(super) fn exercise_refusal(original: &Arc<SharedCallbackCustody>) {
    // The caller holds real original mapping/Ready/journal guards. Holding the
    // RR-local RefCell too makes premature constructor access observable.
    ENGINE.with_borrow_mut(|_held| {
        STATUS.set(-libc::ESTALE);
        assert_eq!(
            prepare_on_rr(Arc::as_ptr(original).cast_mut().cast()),
            -libc::ESTALE
        );
        assert!(original.failed.load(Ordering::Acquire));
        STATUS.set(0);
    });
}
