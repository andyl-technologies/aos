//! QEMU registration and callback stubs for live callback tests.

use super::*;

pub(super) extern "C" fn test_register_vcpu_init(
    _plugin_id: QemuPluginId,
    _callback: crate::QemuVcpuSimpleCbFn,
    _userdata: *mut c_void,
) {
}

pub(super) extern "C" fn test_register_vcpu_idle_resume(
    _idle_callback: Option<crate::QemuVcpuIdleResumeCbFn>,
    _resume_callback: Option<crate::QemuVcpuIdleResumeCbFn>,
    _userdata: *mut c_void,
) {
}

pub(super) extern "C" fn test_register_control_boundary(
    _callback: Option<crate::QemuVcpuIdleResumeCbFn>,
    _userdata: *mut std::ffi::c_void,
) {
}

pub(super) extern "C" fn test_register_sim_dispatch(
    _publish: Option<crate::QemuSimShmemPublishIcountCbFn>,
    _ceiling: Option<crate::QemuSimShmemMaxAdvanceIcountCbFn>,
    _userdata: *mut c_void,
) {
}

pub(super) extern "C" fn test_register_time_advance_cb(
    _callback: Option<crate::QemuTimeAdvanceCompletionCbFn>,
    _userdata: *mut c_void,
) -> std::os::raw::c_int {
    0
}

pub(super) extern "C" fn test_register_net_tx(
    _callback: Option<crate::QemuNetTxCbFn>,
    _userdata: *mut c_void,
) {
}

pub(super) extern "C" fn test_register_block(
    _submit: Option<crate::QemuBlkSubmitCbFn>,
    _poll: Option<crate::QemuBlkPollCbFn>,
    _userdata: *mut c_void,
) {
}

pub(super) extern "C" fn test_register_block_event(
    _poll: Option<crate::QemuBlkEventPollCbFn>,
    _commit: Option<crate::QemuBlkEventCommitCbFn>,
    _save: Option<crate::QemuBlkTransportSaveCbFn>,
    _restore: Option<crate::QemuBlkTransportRestoreCbFn>,
    _userdata: *mut c_void,
) {
}

pub(super) extern "C" fn test_register_block_wait(
    _wait: Option<crate::QemuBlkWaitCbFn>,
    _userdata: *mut c_void,
) {
}

pub(super) extern "C" fn test_register_ninep(
    _burst_start: Option<crate::QemuNinePBurstCbFn>,
    _submit: Option<crate::QemuNinePSubmitCbFn>,
    _poll: Option<crate::QemuNinePPollCbFn>,
    _burst_done: Option<crate::QemuNinePBurstCbFn>,
    _userdata: *mut c_void,
) {
}

pub(super) extern "C" fn test_register_accelerator(
    _submit: Option<crate::QemuAcceleratorSubmitCbFn>,
    _poll: Option<crate::QemuAcceleratorPollCbFn>,
    _wait: Option<crate::QemuAcceleratorWaitCbFn>,
    _restore_begin: Option<crate::QemuAcceleratorRestoreBeginCbFn>,
    _restore: Option<crate::QemuAcceleratorRestoreCbFn>,
    _restore_commit: Option<crate::QemuAcceleratorRestoreCommitCbFn>,
    _restore_abort: Option<crate::QemuAcceleratorRestoreAbortCbFn>,
    _cancel: Option<crate::QemuAcceleratorCancelCbFn>,
    _userdata: *mut std::ffi::c_void,
) {
}

pub(super) extern "C" fn test_net_inject(
    payload: *const u8,
    payload_len: usize,
) -> std::os::raw::c_int {
    if payload.is_null() && payload_len != 0 {
        return 1;
    }
    TEST_RX_INJECT_COUNT.fetch_add(1, Ordering::SeqCst);
    TEST_RX_LAST_LEN.store(payload_len as u64, Ordering::SeqCst);
    TEST_RX_INJECT_STATUS.load(Ordering::SeqCst) as std::os::raw::c_int
}

pub(super) extern "C" fn test_reentrant_net_inject(
    payload: *const u8,
    payload_len: usize,
) -> std::os::raw::c_int {
    let injection_status = test_net_inject(payload, payload_len);
    if injection_status != 0 {
        return injection_status;
    }
    let state = TEST_REENTRANT_RX_STATE.load(Ordering::Acquire);
    if state.is_null() {
        return 1;
    }
    crucible_qemu_plugin_live_publish_icount_cb(TEST_ICOUNT_RAW.get(), state.cast());
    let tx_payload = b"flush-tx";
    let status = crucible_qemu_plugin_live_network_tx_cb(
        tx_payload.as_ptr(),
        tx_payload.len(),
        TEST_ICOUNT_RAW.get(),
        state.cast(),
    );
    if status != 0 {
        return status;
    }
    0
}

pub(super) extern "C" fn test_queue_idle_advance(target_virtual_ns: i64) -> std::os::raw::c_int {
    LAST_QUEUED_ADVANCE_NS.set(target_virtual_ns);
    TEST_QUEUED_ADVANCE_STATUS.get()
}

pub(super) extern "C" fn test_queue_idle_advance_with_synchronous_completion(
    target_virtual_ns: i64,
) -> std::os::raw::c_int {
    let state = TEST_SYNCHRONOUS_COMPLETION_STATE.load(Ordering::Acquire);
    if state.is_null() {
        return -libc::ENODEV;
    }

    // SAFETY: the test retains the boxed state until it clears this pointer
    // after the enqueue callback returns.
    let completion = unsafe { state.as_ref() }.and_then(|state| {
        state
            .complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, target_virtual_ns))
            .ok()
    });
    TEST_SYNCHRONOUS_COMPLETION_SUCCEEDED.store(completion.is_some(), Ordering::Release);
    0
}

pub(super) extern "C" fn test_queue_idle_advance_with_nested_producer(
    _target_virtual_ns: i64,
) -> std::os::raw::c_int {
    let state = TEST_NESTED_PRODUCER_STATE.load(Ordering::Acquire);
    if state.is_null() {
        return -libc::ENODEV;
    }

    // SAFETY: the test retains the boxed state until it clears this pointer
    // after the enqueue callback returns.
    let nested_result = unsafe { state.as_ref() }
        .map(|state| state.arm_and_enqueue_idle_advance_or_defer(0, 9, 18, None));
    TEST_NESTED_PRODUCER_DEFERRED.store(nested_result == Some(Ok(false)), Ordering::Release);
    0
}
