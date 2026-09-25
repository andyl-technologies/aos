//! Live QEMU callback integration tests.

use super::*;

use std::cell::Cell;
use std::ffi::CString;
use std::fs::File;
use std::io::Write as _;
use std::os::fd::{FromRawFd as _, IntoRawFd as _};
use std::sync::atomic::AtomicU8;

use crucible_shmem::{
    KIND_VM, RegionConfig, RegionHeader, RegionLayout, STATUS_IDLE, STATUS_RUNNING,
    authorize_advance_ceiling,
};

mod block_wait;
mod fault_event_control;
mod preemption;
mod preflight_cases;

pub(super) extern "C" fn test_icount_raw() -> u64 {
    TEST_ICOUNT_RAW.get()
}

extern "C" fn test_sim_tick_observed() -> i64 {
    TEST_SIM_TICK.get()
}

thread_local! {
    static TEST_CLOCK_DEADLINE_PS: Cell<i64> = const { Cell::new(-1) };
    static LAST_QUEUED_ADVANCE_TICK: Cell<i64> = const { Cell::new(-1) };
    static TEST_QUEUED_ADVANCE_STATUS: Cell<std::os::raw::c_int> = const { Cell::new(0) };
    static TEST_REQUEST_VMSTOP_CALLS: Cell<u64> = const { Cell::new(0) };
    static TEST_REQUEST_VMSTOP_STATUS: Cell<std::os::raw::c_int> = const { Cell::new(0) };
    static TEST_ICOUNT_RAW: Cell<u64> = const { Cell::new(0) };
    pub(super) static TEST_SIM_TICK: Cell<i64> = const { Cell::new(0) };
    static TEST_IDLE_WAKE_WAIT_CALLS: Cell<u64> = const { Cell::new(0) };
    static TEST_IDLE_WAKE_WAIT_STATUS: Cell<std::os::raw::c_int> = const { Cell::new(1) };
    static TEST_FINGERPRINT_CAPTURE_COUNT: Cell<u64> = const { Cell::new(0) };
    pub(crate) static TEST_FINGERPRINT_CAPTURE_SEED: Cell<u64> = const { Cell::new(0x10) };
}
static TEST_RX_INJECT_COUNT: AtomicU64 = AtomicU64::new(0);
static TEST_RX_LAST_LEN: AtomicU64 = AtomicU64::new(0);
static TEST_RX_INJECT_STATUS: AtomicU64 = AtomicU64::new(0);
static TEST_REENTRANT_RX_STATE: AtomicPtr<LiveVcpuTimeCallbackState> =
    AtomicPtr::new(std::ptr::null_mut());
static TEST_SYNCHRONOUS_COMPLETION_STATE: AtomicPtr<LiveVcpuTimeCallbackState> =
    AtomicPtr::new(std::ptr::null_mut());
static TEST_SYNCHRONOUS_COMPLETION_SUCCEEDED: AtomicBool = AtomicBool::new(false);
static TEST_NESTED_PRODUCER_STATE: AtomicPtr<LiveVcpuTimeCallbackState> =
    AtomicPtr::new(std::ptr::null_mut());
static TEST_NESTED_PRODUCER_DEFERRED: AtomicBool = AtomicBool::new(false);

fn wait_for_fingerprint_sample(
    slot: &FingerprintSampleSlot,
    capture_request: u32,
) -> crucible_shmem::FingerprintSample {
    let acknowledged = capture_request.wrapping_add(1);
    for _attempt in 0..100_000 {
        if slot.capture_request_generation() == acknowledged {
            return slot
                .snapshot()
                .unwrap_or_else(|| panic!("acknowledged fingerprint sample must be visible"));
        }
        std::thread::yield_now();
    }
    panic!("fingerprint digest worker did not publish the requested sample");
}

extern "C" fn test_fingerprint_read_vcpu_regs(
    _vcpu_id: u32,
    register_bytes: *mut u8,
    capacity: usize,
    register_len: *mut usize,
    retired_icount: *mut u64,
) -> std::os::raw::c_int {
    if register_bytes.is_null()
        || capacity == 0
        || register_len.is_null()
        || retired_icount.is_null()
    {
        return 1;
    }

    // SAFETY: the callback contract supplies writable output storage checked above.
    unsafe {
        register_bytes.write(0xA5);
        register_len.write(1);
        retired_icount.write(7);
    }
    0
}

extern "C" fn test_fingerprint_read_rr_cursor(
    cursor: *mut crate::QemuRoundRobinCursor,
) -> std::os::raw::c_int {
    if cursor.is_null() {
        return 1;
    }

    // SAFETY: the callback contract supplies one writable cursor checked above.
    unsafe {
        cursor.write(crate::QemuRoundRobinCursor {
            current_vcpu: 0,
            cursor_position: 7,
            rr_switch_quantum: 4_096,
        });
    }
    0
}

extern "C" fn test_fingerprint_capture(
    out: *mut crate::fingerprint_sampler::QemuFingerprintMaterialFds,
) -> std::os::raw::c_int {
    if out.is_null() {
        return 1;
    }

    let seed = TEST_FINGERPRINT_CAPTURE_SEED.get() as u8;
    TEST_FINGERPRINT_CAPTURE_COUNT.set(TEST_FINGERPRINT_CAPTURE_COUNT.get() + 1);
    let ram = test_sealed_fingerprint_memfd(seed);
    let device = test_sealed_fingerprint_memfd(seed.wrapping_add(1));
    let (Ok(ram), Ok(device)) = (ram, device) else {
        return 1;
    };
    let mut schema = [0_u8; crucible_shmem::FINGERPRINT_DIGEST_BYTES];
    for (index, byte) in schema.iter_mut().enumerate() {
        *byte = 0xC0_u8.wrapping_add(index as u8);
    }
    // SAFETY: `out` names the live aggregate output checked above.
    unsafe {
        out.write(crate::fingerprint_sampler::QemuFingerprintMaterialFds {
            ram_fd: ram.into_raw_fd(),
            ram_material_length: 1,
            ram_bytes: 1,
            device_fd: device.into_raw_fd(),
            device_material_length: 1,
            device_bytes: 1,
            device_schema_digest: schema,
            device_schema_sections: 1,
        });
    }
    0
}

fn test_sealed_fingerprint_memfd(seed: u8) -> std::io::Result<File> {
    let name = CString::new("crucible-live-callback-test")
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    // SAFETY: `name` is NUL-terminated and the flags request a sealable memfd.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        ) as std::os::raw::c_int
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the successful syscall transfers one owned descriptor.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(&[seed])?;
    // SAFETY: `file` owns `fd`, and `lseek` does not retain it.
    if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    // SAFETY: `file` owns `fd`, and `fcntl` does not retain it.
    if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(file)
}

mod fingerprint_capture;
use fingerprint_capture::test_clock_deadline_ps;

fn test_live_state(
    plugin_id: QemuPluginId,
    vcpu_count: u32,
    initial_raw_icount: u64,
    slot: &NodeSlot,
) -> Result<LiveVcpuTimeCallbackState, LiveVcpuTimeCallbackError> {
    test_live_state_with_fault_commands(
        plugin_id,
        vcpu_count,
        initial_raw_icount,
        slot,
        Box::new(TestFaultCommandBridge::empty()),
    )
}

fn test_live_state_with_fault_commands(
    plugin_id: QemuPluginId,
    vcpu_count: u32,
    initial_raw_icount: u64,
    slot: &NodeSlot,
    fault_commands: Box<dyn LiveFaultCommandControl>,
) -> Result<LiveVcpuTimeCallbackState, LiveVcpuTimeCallbackError> {
    let layout = RegionLayout::for_config(RegionConfig::new(1, 2))
        .unwrap_or_else(|error| panic!("test region layout should validate: {error}"));
    let header = Box::leak(Box::new(RegionHeader::new(layout)));
    let (teardown_sender, teardown_receiver) = mpsc::channel();
    std::mem::forget(teardown_receiver);
    test_live_state_with_teardown_and_fault_commands(
        plugin_id,
        vcpu_count,
        initial_raw_icount,
        header,
        slot,
        teardown_sender,
        fault_commands,
    )
}

// crucible-lint: allow rust-allow -- test factory carries the complete live callback state boundary.
#[allow(clippy::too_many_arguments)]
fn test_live_state_with_teardown(
    plugin_id: QemuPluginId,
    vcpu_count: u32,
    initial_raw_icount: u64,
    header: &RegionHeader,
    slot: &NodeSlot,
    teardown_sender: mpsc::Sender<LiveRuntimeTeardownTrigger>,
) -> Result<LiveVcpuTimeCallbackState, LiveVcpuTimeCallbackError> {
    test_live_state_with_teardown_and_fault_commands(
        plugin_id,
        vcpu_count,
        initial_raw_icount,
        header,
        slot,
        teardown_sender,
        Box::new(TestFaultCommandBridge::empty()),
    )
}

// crucible-lint: allow rust-allow -- test factory carries the complete live callback state boundary.
#[allow(clippy::too_many_arguments)]
fn test_live_state_with_teardown_and_fault_commands(
    _plugin_id: QemuPluginId,
    vcpu_count: u32,
    initial_raw_icount: u64,
    header: &RegionHeader,
    slot: &NodeSlot,
    teardown_sender: mpsc::Sender<LiveRuntimeTeardownTrigger>,
    fault_commands: Box<dyn LiveFaultCommandControl>,
) -> Result<LiveVcpuTimeCallbackState, LiveVcpuTimeCallbackError> {
    let exact_deadline = ExactDeadlineReader::require(Some(test_clock_deadline_ps))
        .unwrap_or_else(|error| panic!("test deadline capability should validate: {error}"));
    let queued_idle_advance = QueuedIdleAdvance::require(Some(test_queue_idle_advance))
        .unwrap_or_else(|error| panic!("test queued advance should validate: {error}"));
    LiveVcpuTimeCallbackState::new(
        test_icount_raw,
        test_force_vcpu_exit,
        QemuIdleWakeWait::test_stub(test_wait_idle_wake),
        test_request_vmstop,
        test_support::test_preemption_injector(),
        vcpu_count,
        initial_raw_icount,
        exact_deadline,
        queued_idle_advance,
        test_support::test_virtual_timer_witness(),
        fault_commands,
        header,
        slot,
        Arc::new(LiveCallbackQuiescence::new()),
        LiveRuntimeTeardownRouter::new(teardown_sender),
    )
}

extern "C" fn test_force_vcpu_exit() {}

extern "C" fn test_wait_idle_wake(
    _vcpu_index: u32,
    _wake_signal: *mut u32,
    _expected: u32,
) -> std::os::raw::c_int {
    TEST_IDLE_WAKE_WAIT_CALLS.set(TEST_IDLE_WAKE_WAIT_CALLS.get() + 1);
    TEST_IDLE_WAKE_WAIT_STATUS.get()
}

extern "C" fn test_force_vcpu_tb_exit() -> i32 {
    0
}

extern "C" fn test_request_vmstop() -> std::os::raw::c_int {
    TEST_REQUEST_VMSTOP_CALLS.set(TEST_REQUEST_VMSTOP_CALLS.get() + 1);
    TEST_REQUEST_VMSTOP_STATUS.get()
}

#[test]
fn shared_shutdown_resume_signal_is_one_shot_and_defers_done_to_worker() {
    let layout = RegionLayout::for_config(RegionConfig::new(1, 2))
        .unwrap_or_else(|error| panic!("test region layout should validate: {error}"));
    let header = RegionHeader::new(layout);
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 1, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let (sender, receiver) = mpsc::channel();
    let state = test_live_state_with_teardown(70, 1, 0, &header, &slot, sender)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .on_vcpu_init(0)
        .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));
    state
        .halted_vcpus
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .mark_halted(0)
        .unwrap_or_else(|error| panic!("test vCPU should enter halted state: {error}"));
    header
        .request_shutdown([&slot])
        .unwrap_or_else(|error| panic!("shutdown request should publish: {error}"));

    state
        .on_vcpu_resume(0, 0)
        .unwrap_or_else(|error| panic!("resume should signal shutdown: {error}"));
    state
        .on_vcpu_resume(0, 0)
        .unwrap_or_else(|error| panic!("repeated resume should be coalesced: {error}"));

    assert!(matches!(
        receiver.try_recv(),
        Ok(LiveRuntimeTeardownTrigger::SharedShutdown(_))
    ));
    assert!(matches!(
        receiver.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    assert_ne!(slot.snapshot().status, crucible_shmem::STATUS_DONE);
}

#[test]
fn busy_at_ceiling_publish_callback_signals_shared_shutdown_without_publication() {
    let layout = RegionLayout::for_config(RegionConfig::new(1, 2))
        .unwrap_or_else(|error| panic!("test region layout should validate: {error}"));
    let header = RegionHeader::new(layout);
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 1, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let (sender, receiver) = mpsc::channel();
    let state = Box::new(
        test_live_state_with_teardown(73, 1, 0, &header, &slot, sender)
            .unwrap_or_else(|error| panic!("live callback state should build: {error}")),
    );
    let userdata = std::ptr::from_ref(state.as_ref()).cast_mut().cast();
    header
        .request_shutdown([&slot])
        .unwrap_or_else(|error| panic!("shutdown request should publish: {error}"));

    crucible_qemu_plugin_live_publish_icount_cb(1, userdata);

    assert!(matches!(
        receiver.try_recv(),
        Ok(LiveRuntimeTeardownTrigger::SharedShutdown(_))
    ));
    assert_ne!(slot.snapshot().status, crucible_shmem::STATUS_DONE);
    assert_eq!(slot.snapshot().current_icount, 0);
}

#[test]
fn shared_shutdown_idle_signal_is_one_shot_and_defers_done_to_worker() {
    let layout = RegionLayout::for_config(RegionConfig::new(1, 2))
        .unwrap_or_else(|error| panic!("test region layout should validate: {error}"));
    let header = RegionHeader::new(layout);
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 1, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let (sender, receiver) = mpsc::channel();
    let state = test_live_state_with_teardown(71, 1, 0, &header, &slot, sender)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .on_vcpu_init(0)
        .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));
    header
        .request_shutdown([&slot])
        .unwrap_or_else(|error| panic!("shutdown request should publish: {error}"));

    state
        .on_vcpu_idle(0, 0)
        .unwrap_or_else(|error| panic!("idle should signal shutdown: {error}"));

    assert!(matches!(
        receiver.try_recv(),
        Ok(LiveRuntimeTeardownTrigger::SharedShutdown(_))
    ));
    assert_ne!(slot.snapshot().status, crucible_shmem::STATUS_DONE);
}

#[test]
fn shared_shutdown_signal_is_fail_loud_when_teardown_worker_disconnected() {
    let layout = RegionLayout::for_config(RegionConfig::new(1, 2))
        .unwrap_or_else(|error| panic!("test region layout should validate: {error}"));
    let header = RegionHeader::new(layout);
    let slot = NodeSlot::new(KIND_VM);
    let (sender, receiver) = mpsc::channel();
    drop(receiver);
    let state = test_live_state_with_teardown(72, 1, 0, &header, &slot, sender)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .on_vcpu_init(0)
        .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));
    state
        .halted_vcpus
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .mark_halted(0)
        .unwrap_or_else(|error| panic!("test vCPU should enter halted state: {error}"));
    header
        .request_shutdown([&slot])
        .unwrap_or_else(|error| panic!("shutdown request should publish: {error}"));

    assert_eq!(
        state.on_vcpu_resume(0, 0),
        Err(LiveVcpuTimeCallbackError::TeardownWorkerUnavailable)
    );
    assert_ne!(slot.snapshot().status, crucible_shmem::STATUS_DONE);
}

#[test]
fn live_state_dispatches_vcpu_init_publish_and_ceiling() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 600, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = test_live_state(41, 2, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));

    state
        .on_vcpu_init(0)
        .unwrap_or_else(|error| panic!("vCPU 0 should initialize: {error}"));
    state
        .on_vcpu_init(1)
        .unwrap_or_else(|error| panic!("vCPU 1 should initialize: {error}"));
    state
        .publish_current_icount(5)
        .unwrap_or_else(|error| panic!("sim icount should publish: {error}"));
    assert_eq!(state.max_advance_icount(), Ok(12));
    assert_eq!(slot.snapshot().current_icount, 250);
    assert!(state.initialized_vcpus[0].load(Ordering::Acquire));
    assert!(state.initialized_vcpus[1].load(Ordering::Acquire));
}

#[test]
fn busy_max_advance_acknowledges_pause_without_advancing_or_pumping_work() {
    TEST_REQUEST_VMSTOP_CALLS.set(0);
    TEST_REQUEST_VMSTOP_STATUS.set(0);
    let layout = RegionLayout::for_config(RegionConfig::new(1, 2))
        .unwrap_or_else(|error| panic!("test region layout should validate: {error}"));
    let header = RegionHeader::new(layout);
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 600, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let (sender, receiver) = mpsc::channel();
    std::mem::forget(receiver);
    let state = test_live_state_with_teardown(74, 1, 0, &header, &slot, sender)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    header
        .request_pause([&slot])
        .unwrap_or_else(|error| panic!("pause request should publish: {error}"));

    assert_eq!(state.max_advance_icount(), Ok(0));
    let paused = slot.snapshot();
    assert_eq!(paused.status, STATUS_IDLE);
    assert_eq!(paused.current_icount, 0);
    assert_eq!(paused.idle_wake_icount, 0);
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 1);

    header.clear_pause();
    assert_eq!(state.max_advance_icount(), Ok(12));
    assert_eq!(slot.snapshot().current_icount, 0);
}

#[test]
fn drained_control_boundary_acknowledges_pause_without_resuming_halted_vcpu() {
    TEST_REQUEST_VMSTOP_CALLS.set(0);
    TEST_REQUEST_VMSTOP_STATUS.set(0);
    let layout = RegionLayout::for_config(RegionConfig::new(1, 2))
        .unwrap_or_else(|error| panic!("test region layout should validate: {error}"));
    let header = RegionHeader::new(layout);
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 12, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let (sender, receiver) = mpsc::channel();
    std::mem::forget(receiver);
    let (fault_commands, fault_command_observation) = TestFaultCommandBridge::observed();
    let state = test_live_state_with_teardown_and_fault_commands(
        78,
        1,
        0,
        &header,
        &slot,
        sender,
        Box::new(fault_commands),
    )
    .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .on_vcpu_init(0)
        .unwrap_or_else(|error| panic!("test vCPU should initialize: {error}"));
    state
        .halted_vcpus
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .mark_halted(0)
        .unwrap_or_else(|error| panic!("test vCPU should halt: {error}"));
    state.all_halted_idle_handled.store(true, Ordering::Release);

    slot.request_control_boundary(0, None)
        .unwrap_or_else(|error| panic!("ordinary control request should publish: {error}"));
    state
        .on_vcpu_resume(0, 0)
        .unwrap_or_else(|error| panic!("control-only resume should be inert: {error}"));
    assert!(
        state
            .halted_vcpus
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_halted(0)
            .unwrap_or_else(|error| panic!("halt state should remain readable: {error}"))
    );
    assert_eq!(slot.snapshot().status, STATUS_IDLE);
    state
        .on_control_boundary(0)
        .unwrap_or_else(|error| panic!("ordinary control wake should be inert: {error}"));
    assert_eq!(slot.snapshot().control_boundary_ack, 3);
    assert!(!state.all_halted_idle_handled.load(Ordering::Acquire));
    header
        .request_pause([&slot])
        .unwrap_or_else(|error| panic!("pause request should publish: {error}"));
    state.all_halted_idle_handled.store(true, Ordering::Release);
    slot.request_control_boundary(0, None)
        .unwrap_or_else(|error| panic!("pause control request should publish: {error}"));
    state
        .on_vcpu_resume(0, 0)
        .unwrap_or_else(|error| panic!("early pause resume should defer to control wake: {error}"));
    assert_eq!(slot.snapshot().control_boundary_ack, 4);
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 0);
    state
        .on_control_boundary(0)
        .unwrap_or_else(|error| panic!("control wake should acknowledge pause: {error}"));

    assert!(
        state
            .halted_vcpus
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_halted(0)
            .unwrap_or_else(|error| panic!("halt state should remain readable: {error}"))
    );
    assert_eq!(slot.snapshot().status, STATUS_IDLE);
    assert_eq!(slot.snapshot().control_boundary_ack, 5);
    assert!(state.all_halted_idle_handled.load(Ordering::Acquire));
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 1);
    assert_eq!(
        *fault_command_observation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
        TestFaultCommandObservation {
            pumped_frontier: Some(0),
            boundary_dispatched: true,
            publications_drained: true,
        }
    );
}

#[test]
fn drained_control_boundary_pumps_fault_commands_before_fingerprint_and_ack() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 7, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = test_live_state(79, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    let _borrowed_bridge = state
        .fault_commands
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let request = slot
        .request_control_boundary(0, None)
        .unwrap_or_else(|error| panic!("control request should publish: {error}"));

    assert_eq!(
        state.on_control_boundary(7),
        Err(LiveVcpuTimeCallbackError::FaultCommandStateBorrowed)
    );
    let snapshot = slot.snapshot();
    assert_eq!(snapshot.current_icount, 0);
    assert_eq!(snapshot.control_boundary_ack, request);
}

#[test]
fn busy_pause_publishes_exact_boundary_before_vmstop_rejection_is_reported() {
    TEST_REQUEST_VMSTOP_CALLS.set(0);
    TEST_REQUEST_VMSTOP_STATUS.set(-7);
    let layout = RegionLayout::for_config(RegionConfig::new(1, 2))
        .unwrap_or_else(|error| panic!("test region layout should validate: {error}"));
    let header = RegionHeader::new(layout);
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 12, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let (sender, receiver) = mpsc::channel();
    std::mem::forget(receiver);
    let state = test_live_state_with_teardown(75, 1, 0, &header, &slot, sender)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    header
        .request_pause([&slot])
        .unwrap_or_else(|error| panic!("pause request should publish: {error}"));

    assert_eq!(
        state.max_advance_icount(),
        Err(LiveVcpuTimeCallbackError::CheckpointVmStopRejected {
            boundary: "max-advance",
            status: -7,
        })
    );
    let paused = slot.snapshot();
    assert_eq!(paused.status, STATUS_IDLE);
    assert_eq!(paused.current_icount, 0);
    assert_eq!(paused.idle_wake_icount, 0);
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 1);
    TEST_REQUEST_VMSTOP_STATUS.set(0);
}

#[test]
fn duplicate_checkpoint_vmstop_admission_is_idempotent() {
    TEST_REQUEST_VMSTOP_STATUS.set(-114);
    let slot = NodeSlot::new(KIND_VM);
    let state = test_live_state(76, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));

    state
        .request_checkpoint_vmstop("block-wait")
        .unwrap_or_else(|error| {
            panic!("an already-admitted exact stop satisfies the handoff: {error}")
        });
    TEST_REQUEST_VMSTOP_STATUS.set(0);
}

#[test]
fn selectable_stop_is_admitted_after_exact_sim_publication() {
    TEST_REQUEST_VMSTOP_CALLS.set(0);
    TEST_REQUEST_VMSTOP_STATUS.set(0);
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 500, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = Box::new(
        test_live_state(79, 1, 0, &slot)
            .unwrap_or_else(|error| panic!("live callback state should build: {error}")),
    );
    let handoff = state.selectable_vmstop_handoff();
    assert_eq!(handoff.defer(test_force_vcpu_tb_exit), Ok(true));
    assert!(handoff.is_pending());
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 0);

    let userdata = std::ptr::from_ref(state.as_ref()).cast_mut().cast();
    crucible_qemu_plugin_live_publish_icount_cb(9, userdata);

    let paused = slot.snapshot();
    assert_eq!(paused.current_icount, 450);
    assert_eq!(paused.idle_wake_icount, 450);
    assert_eq!(paused.status, STATUS_IDLE);
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 1);
    assert!(!handoff.is_pending());
}

#[test]
fn campaign_marker_stop_is_admitted_after_one_retired_doorbell_instruction() {
    TEST_REQUEST_VMSTOP_CALLS.set(0);
    TEST_REQUEST_VMSTOP_STATUS.set(0);
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 500, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = Box::new(
        test_live_state(79, 1, 0, &slot)
            .unwrap_or_else(|error| panic!("live callback state should build: {error}")),
    );
    let handoff = state.selectable_vmstop_handoff();
    let trap_raw_icount = 8;
    assert_eq!(
        handoff.defer_campaign_marker(test_force_vcpu_tb_exit),
        Ok(true)
    );

    let userdata = std::ptr::from_ref(state.as_ref()).cast_mut().cast();
    crucible_qemu_plugin_live_publish_icount_cb(trap_raw_icount + 1, userdata);

    let paused = slot.snapshot();
    assert_eq!(paused.current_icount, (trap_raw_icount + 1) * 50);
    assert_eq!(paused.idle_wake_icount, (trap_raw_icount + 1) * 50);
    assert_eq!(paused.status, STATUS_IDLE);
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 1);
    assert!(!handoff.is_pending());
}

#[test]
fn rejected_exact_selectable_stop_restores_the_handoff() {
    TEST_REQUEST_VMSTOP_CALLS.set(0);
    TEST_REQUEST_VMSTOP_STATUS.set(-7);
    let slot = NodeSlot::new(KIND_VM);
    let state = test_live_state(80, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    let handoff = state.selectable_vmstop_handoff();
    assert_eq!(handoff.defer(test_force_vcpu_tb_exit), Ok(true));

    assert_eq!(
        state.request_selectable_vmstop_if_pending(0),
        Err(LiveVcpuTimeCallbackError::CheckpointVmStopRejected {
            boundary: "selectable-sim-publication",
            status: -7,
        })
    );
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 1);
    assert!(handoff.is_pending());
    assert_eq!(slot.snapshot().status, STATUS_IDLE);
    TEST_REQUEST_VMSTOP_STATUS.set(0);
}

#[test]
fn final_device_completion_publishes_pause_before_vmstop_handoff() {
    TEST_REQUEST_VMSTOP_CALLS.set(0);
    TEST_REQUEST_VMSTOP_STATUS.set(0);
    TEST_ICOUNT_RAW.set(9);
    let layout = RegionLayout::for_config(RegionConfig::new(1, 2))
        .unwrap_or_else(|error| panic!("test region layout should validate: {error}"));
    let header = RegionHeader::new(layout);
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 500, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let (sender, receiver) = mpsc::channel();
    std::mem::forget(receiver);
    let state = test_live_state_with_teardown(77, 1, 0, &header, &slot, sender)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    header
        .request_pause([&slot])
        .unwrap_or_else(|error| panic!("pause request should publish: {error}"));
    slot.mark_device_io_active();

    state
        .publish_device_completion_pause_if_quiesced("block-poll")
        .unwrap_or_else(|error| panic!("active device should defer pause: {error}"));
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 0);
    slot.clear_device_io_active();
    state
        .publish_device_completion_pause_if_quiesced("block-poll")
        .unwrap_or_else(|error| panic!("final completion should hand off pause: {error}"));

    let paused = slot.snapshot();
    assert_eq!(paused.status, STATUS_IDLE);
    assert_eq!(paused.current_icount, 450);
    assert_eq!(paused.idle_wake_icount, 450);
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 1);
    TEST_ICOUNT_RAW.set(0);
}

#[test]
fn every_live_callback_entry_rejects_work_after_quiescence() {
    let _runtime_state = crate::runtime::isolate_runtime_state_for_test();
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 12, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = Box::new(
        test_live_state(71, 1, 0, &slot)
            .unwrap_or_else(|error| panic!("live callback state should build: {error}")),
    );
    let state_pointer = std::ptr::from_ref(state.as_ref()).cast_mut();
    LIVE_VCPU_TIME_STATE.store(state_pointer, Ordering::Release);
    state.quiescence.close();
    let userdata = state_pointer.cast::<c_void>();
    let before = slot.snapshot();

    crucible_qemu_plugin_live_vcpu_init_cb(0, userdata);
    crucible_qemu_plugin_live_vcpu_idle_cb(0, 0, userdata);
    crucible_qemu_plugin_live_vcpu_resume_cb(0, 0, userdata);
    crucible_qemu_plugin_live_publish_icount_cb(9, userdata);
    assert_eq!(crucible_qemu_plugin_live_max_advance_icount_cb(userdata), 0);
    crucible_qemu_plugin_live_time_advance_completion_cb(0, 0, userdata);
    assert_eq!(
        crucible_qemu_plugin_live_network_tx_cb(std::ptr::null(), 0, 0, userdata),
        -1
    );
    assert_eq!(
        devices::crucible_qemu_plugin_live_block_submit_cb(
            0,
            0,
            0,
            0,
            std::ptr::null(),
            0,
            userdata,
        ),
        -1
    );
    assert_eq!(
        devices::crucible_qemu_plugin_live_block_poll_cb(0, 0, std::ptr::null_mut(), 0, userdata,),
        -1
    );
    crucible_qemu_plugin_live_block_wait_cb(0, userdata);
    devices::crucible_qemu_plugin_live_ninep_burst_start_cb(userdata);
    assert_eq!(
        devices::crucible_qemu_plugin_live_ninep_submit_cb(0, std::ptr::null(), 0, 0, userdata,),
        -1
    );
    assert_eq!(
        devices::crucible_qemu_plugin_live_ninep_poll_cb(0, std::ptr::null_mut(), 0, userdata,),
        -1
    );
    devices::crucible_qemu_plugin_live_ninep_burst_done_cb(userdata);

    let after = slot.snapshot();
    assert_eq!(after, before);
    LIVE_VCPU_TIME_STATE.store(std::ptr::null_mut(), Ordering::Release);
}

#[test]
fn block_transport_restore_callback_returns_failure_for_invalid_input() {
    let _runtime_state = crate::runtime::isolate_runtime_state_for_test();
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 12, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = Box::new(
        test_live_state(72, 1, 0, &slot)
            .unwrap_or_else(|error| panic!("live callback state should build: {error}")),
    );
    let userdata = std::ptr::from_ref(state.as_ref())
        .cast_mut()
        .cast::<c_void>();

    assert_eq!(
        devices::crucible_qemu_plugin_live_block_transport_restore_cb(
            std::ptr::null(),
            1,
            0,
            0,
            userdata,
        ),
        -1
    );
    assert_eq!(
        devices::crucible_qemu_plugin_live_block_transport_restore_cb(
            std::ptr::null(),
            0,
            0,
            0,
            std::ptr::null_mut(),
        ),
        -1
    );
}

#[test]
fn live_time_completion_clamps_dispatch_then_commits_logical_idle_offset() {
    TEST_ICOUNT_RAW.set(4);
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 1000, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = test_live_state(43, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .publish_current_icount(4)
        .unwrap_or_else(|error| panic!("raw progress should publish: {error}"));

    let queued = crate::QueuedIdleAdvance::require(Some(test_queue_idle_advance))
        .unwrap_or_else(|error| panic!("queued advance should build: {error}"));
    let pending = queued
        .enqueue(500)
        .unwrap_or_else(|error| panic!("idle advance should queue: {error}"));
    state
        .arm_idle_advance(4, 500, pending, None)
        .unwrap_or_else(|error| panic!("pending idle advance should arm: {error}"));
    assert_eq!(state.max_advance_icount(), Ok(4));

    TEST_ICOUNT_RAW.set(5);
    assert!(matches!(
        state.max_advance_icount(),
        Err(
            LiveVcpuTimeCallbackError::GuestProgressWhileIdleAdvancePending {
                expected_raw_icount: 4,
                observed_raw_icount: 5,
            }
        )
    ));
    TEST_ICOUNT_RAW.set(4);
    state
        .publish_current_icount(4)
        .unwrap_or_else(|error| panic!("repeated raw boundary should be a no-op: {error}"));
    assert!(matches!(
        state.publish_current_icount(5),
        Err(
            LiveVcpuTimeCallbackError::GuestProgressWhileIdleAdvancePending {
                expected_raw_icount: 4,
                observed_raw_icount: 5,
            }
        )
    ));
    assert_eq!(slot.snapshot().current_icount, 200);

    let committed = state
        .complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 500))
        .unwrap_or_else(|error| panic!("matching completion should commit: {error}"));
    assert_eq!(committed, 500);
    assert_eq!(slot.snapshot().current_icount, 500);

    state
        .publish_current_icount(5)
        .unwrap_or_else(|error| panic!("post-jump raw progress should publish: {error}"));
    assert_eq!(slot.snapshot().current_icount, 550);
}

#[test]
fn fault_advanced_tick_controls_publication_and_raw_ceiling() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 600, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let mut state = test_live_state_with_fault_commands(
        51,
        1,
        0,
        &slot,
        Box::new(TestFaultCommandBridge::advancing_to(508)),
    )
    .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state.sim_tick_observed = Some(test_sim_tick_observed);
    TEST_ICOUNT_RAW.set(10);
    TEST_SIM_TICK.set(500);

    state
        .publish_current_icount(10)
        .unwrap_or_else(|error| panic!("fault-advanced tick should publish: {error}"));
    assert_eq!(slot.snapshot().current_icount, 508);
    assert_eq!(state.last_raw_icount.load(Ordering::Acquire), 10);
    assert_eq!(state.logical_icount_offset.load(Ordering::Acquire), 8);
    assert_eq!(state.max_advance_icount(), Ok(11));

    TEST_SIM_TICK.set(601);
    assert!(matches!(
        state.publish_current_icount(10),
        Err(LiveVcpuTimeCallbackError::IcountBeyondCeiling {
            current_icount: 601,
            ceiling_icount: 600,
        })
    ));
    assert_eq!(slot.snapshot().current_icount, 508);
}

#[test]
fn max_advance_translates_logical_ceiling_to_raw_after_idle_jump() {
    // QEMU's sim-loop budget clamp compares max_advance_icount() against raw
    // retired instructions (`qemu_plugin_icount_raw()`), while the scheduler
    // ceiling is a logical icount that includes the accumulated idle-jump offset
    // (`logical = raw + offset`). The reported limit must therefore be in raw
    // units so the clamp stops the guest exactly at the logical authorization.
    // A live idle jump exposed this: the clamp used the raw count against a
    // logical ceiling, letting the guest retire instructions past the ceiling.
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 5000, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = test_live_state(51, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .publish_current_icount(30)
        .unwrap_or_else(|error| panic!("raw progress should publish: {error}"));

    // Busy path: no idle-jump offset yet, so the raw limit is the ceiling.
    assert_eq!(state.max_advance_icount(), Ok(100));

    let queued = crate::QueuedIdleAdvance::require(Some(test_queue_idle_advance))
        .unwrap_or_else(|error| panic!("queued advance should build: {error}"));
    let pending = queued
        .enqueue(4000)
        .unwrap_or_else(|error| panic!("idle advance should queue: {error}"));
    state
        .arm_idle_advance(30, 4000, pending, None)
        .unwrap_or_else(|error| panic!("pending idle advance should arm: {error}"));
    state
        .complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 4000))
        .unwrap_or_else(|error| panic!("matching completion should commit: {error}"));

    // The jump advanced the logical clock to 80 (raw 30 + offset 50) without
    // retiring instructions. The raw execution limit is ceiling(100) minus the
    // offset(50) = 50, so the guest may retire only 20 more raw instructions
    // (50 - 30) to reach logical 100 = the ceiling, and no further.
    assert_eq!(slot.snapshot().current_icount, 4000);
    assert_eq!(state.max_advance_icount(), Ok(50));
    let userdata = std::ptr::from_ref(&state).cast_mut().cast();
    assert_eq!(crucible_qemu_plugin_live_logical_ceiling_cb(userdata), 5000);
}

#[test]
fn device_io_without_a_pinned_deadline_freezes_at_the_current_icount() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 5000, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = test_live_state(52, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .publish_current_icount(30)
        .unwrap_or_else(|error| panic!("raw progress should publish: {error}"));

    slot.mark_device_io_active();
    assert_eq!(slot.device_completion_deadline_icount(), 0);
    assert_eq!(state.max_advance_icount(), Ok(30));
}

#[test]
fn device_io_advances_to_the_deadline_only_after_it_is_pinned() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 5000, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = test_live_state(53, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .publish_current_icount(30)
        .unwrap_or_else(|error| panic!("raw progress should publish: {error}"));

    slot.mark_device_io_active();
    assert_eq!(state.max_advance_icount(), Ok(30));
    slot.store_device_completion_deadline_icount(2250);
    assert_eq!(state.max_advance_icount(), Ok(45));
}

#[test]
fn live_idle_callback_queues_then_commits_only_from_normal_loop_completion() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 10, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = test_live_state(46, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .on_vcpu_init(0)
        .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));

    state
        .on_vcpu_idle(0, 0)
        .unwrap_or_else(|error| panic!("idle callback should queue the jump: {error}"));
    let pending_snapshot = slot.snapshot();
    assert_eq!(pending_snapshot.current_icount, 0);
    assert_eq!(pending_snapshot.status, STATUS_IDLE);

    state
        .complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 10))
        .unwrap_or_else(|error| panic!("completion should commit the jump: {error}"));
    assert_eq!(slot.snapshot().current_icount, 10);
    assert_eq!(slot.snapshot().status, STATUS_RUNNING);

    state
        .on_vcpu_resume(0, 0)
        .unwrap_or_else(|error| panic!("resume should preserve logical time: {error}"));
    assert_eq!(slot.snapshot().current_icount, 10);
}

#[test]
fn live_idle_callback_parks_when_an_advance_still_owns_the_qemu_barrier() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 10, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = test_live_state(54, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .on_vcpu_init(0)
        .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));
    TEST_CLOCK_DEADLINE_PS.set(-1);
    TEST_QUEUED_ADVANCE_STATUS.set(-libc::EBUSY);

    let result = state.on_vcpu_idle(0, 0);
    TEST_QUEUED_ADVANCE_STATUS.set(0);

    result.unwrap_or_else(|error| panic!("busy QEMU barrier should defer the idle vCPU: {error}"));
    assert!(
        state
            .try_pending_idle_advance()
            .unwrap_or_else(|error| panic!("pending state should remain readable: {error}"))
            .is_none()
    );
    assert!(
        !state.all_halted_idle_handled.load(Ordering::Acquire),
        "a QEMU barrier deferral must re-arm the all-halted retry edge"
    );
}

mod logical_restore;
#[test]
fn live_idle_callback_queues_the_exact_timer_deadline() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 56, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = test_live_state(47, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .on_vcpu_init(0)
        .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));
    TEST_CLOCK_DEADLINE_PS.set(56);
    LAST_QUEUED_ADVANCE_TICK.set(-1);

    state
        .on_vcpu_idle(0, 0)
        .unwrap_or_else(|error| panic!("idle callback should queue exact timer: {error}"));
    assert_eq!(LAST_QUEUED_ADVANCE_TICK.get(), 56);
    assert_eq!(slot.snapshot().current_icount, 0);
    state
        .complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 56))
        .unwrap_or_else(|error| panic!("exact timer completion should commit: {error}"));
    assert_eq!(slot.snapshot().current_icount, 56);
    TEST_CLOCK_DEADLINE_PS.set(-1);
}

#[test]
fn live_idle_callback_publishes_next_idle_without_authorizing_its_deadline() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, AdvanceStopCondition::NextAuthenticatedIdle)
        .unwrap_or_else(|error| panic!("next-idle advance should publish: {error}"));
    let state = test_live_state(147, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .on_vcpu_init(0)
        .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));
    TEST_CLOCK_DEADLINE_PS.set(56);
    TEST_IDLE_WAKE_WAIT_CALLS.set(0);
    TEST_IDLE_WAKE_WAIT_STATUS.set(1);
    LAST_QUEUED_ADVANCE_TICK.set(-1);

    state
        .on_vcpu_idle(0, 0)
        .unwrap_or_else(|error| panic!("next-idle callback should wait: {error}"));

    let snapshot = slot.snapshot();
    assert_eq!(TEST_IDLE_WAKE_WAIT_CALLS.get(), 1);
    assert_eq!(LAST_QUEUED_ADVANCE_TICK.get(), -1);
    assert_eq!(snapshot.current_icount, 0);
    assert_eq!(snapshot.status, STATUS_IDLE);
    assert_eq!(snapshot.idle_wake_icount, 56);
    assert!(!state.idle_advance_is_pending());
    TEST_CLOCK_DEADLINE_PS.set(-1);
}

#[test]
fn live_max_advance_rejects_an_unknown_stop_condition() {
    let slot = NodeSlot::new(KIND_VM);
    let state = test_live_state(148, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));

    // SAFETY: `NodeSlot` has a public fixed wire layout, and this test stores
    // through the aligned AtomicU8 field at its published current-ABI offset.
    let stop_condition = unsafe {
        &*(std::ptr::from_ref(&slot)
            .cast::<u8>()
            .add(crucible_shmem::NODE_SLOT_ADVANCE_STOP_CONDITION_OFFSET)
            .cast::<AtomicU8>())
    };
    stop_condition.store(0xff, Ordering::Release);

    assert!(matches!(
        state.max_advance_icount(),
        Err(LiveVcpuTimeCallbackError::IdleHotLoop {
            source: IdleHotLoopError::AdvanceStopCondition {
                source: NodeSlotError::InvalidAdvanceStopCondition { encoded: 0xff }
            }
        })
    ));
    assert!(matches!(
        test_live_state(149, 1, 0, &slot),
        Err(LiveVcpuTimeCallbackError::IdleHotLoop {
            source: IdleHotLoopError::AdvanceStopCondition {
                source: NodeSlotError::InvalidAdvanceStopCondition { encoded: 0xff }
            }
        })
    ));
}

#[test]
fn live_idle_wait_always_returns_for_a_fresh_qemu_rescan() {
    TEST_CLOCK_DEADLINE_PS.set(56);

    for status in [0, 1, 2, 3, 9] {
        let slot = NodeSlot::new(KIND_VM);
        let ceiling = authorize_advance_ceiling(0, 0, None)
            .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
        slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
            .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
        let state = test_live_state(80 + status as u64, 1, 0, &slot)
            .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
        state
            .on_vcpu_init(0)
            .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));

        TEST_IDLE_WAKE_WAIT_CALLS.set(0);
        TEST_IDLE_WAKE_WAIT_STATUS.set(status);
        LAST_QUEUED_ADVANCE_TICK.set(-1);
        state
            .on_vcpu_idle(0, 0)
            .unwrap_or_else(|error| panic!("idle wait status {status} should rescan: {error}"));

        assert_eq!(TEST_IDLE_WAKE_WAIT_CALLS.get(), 1);
        assert_eq!(LAST_QUEUED_ADVANCE_TICK.get(), -1);
        assert!(!state.idle_advance_is_pending());
        assert!(!state.all_halted_idle_handled.load(Ordering::Acquire));
        assert_eq!(slot.snapshot().current_icount, 0);
    }

    TEST_IDLE_WAKE_WAIT_STATUS.set(1);
    TEST_CLOCK_DEADLINE_PS.set(-1);
}

#[test]
fn live_idle_wait_rejects_contract_failures_without_postwait_work() {
    TEST_CLOCK_DEADLINE_PS.set(56);

    for status in [4, 5, 6, 7, 8, 99] {
        let slot = NodeSlot::new(KIND_VM);
        let ceiling = authorize_advance_ceiling(0, 0, None)
            .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
        slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
            .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
        let state = test_live_state(90 + status as u64, 1, 0, &slot)
            .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
        state
            .on_vcpu_init(0)
            .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));

        TEST_IDLE_WAKE_WAIT_CALLS.set(0);
        TEST_IDLE_WAKE_WAIT_STATUS.set(status);
        LAST_QUEUED_ADVANCE_TICK.set(-1);
        assert_eq!(
            state.on_vcpu_idle(0, 0),
            Err(LiveVcpuTimeCallbackError::IdleWakeWaitRejected { status })
        );

        assert_eq!(TEST_IDLE_WAKE_WAIT_CALLS.get(), 1);
        assert_eq!(LAST_QUEUED_ADVANCE_TICK.get(), -1);
        assert!(!state.idle_advance_is_pending());
        assert!(!state.all_halted_idle_handled.load(Ordering::Acquire));
        assert_eq!(slot.snapshot().current_icount, 0);
    }

    TEST_IDLE_WAKE_WAIT_STATUS.set(1);
    TEST_CLOCK_DEADLINE_PS.set(-1);
}

#[test]
fn live_idle_callback_waits_for_every_vcpu_to_halt() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 56, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = test_live_state(73, 4, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    for vcpu_index in 0..4 {
        state
            .on_vcpu_init(vcpu_index)
            .unwrap_or_else(|error| panic!("vCPU {vcpu_index} should initialize: {error}"));
    }
    TEST_CLOCK_DEADLINE_PS.set(56);
    LAST_QUEUED_ADVANCE_TICK.set(-1);

    for vcpu_index in 0..3 {
        state
            .on_vcpu_idle(vcpu_index, 0)
            .unwrap_or_else(|error| panic!("partial halt set should remain runnable: {error}"));
        assert_eq!(LAST_QUEUED_ADVANCE_TICK.get(), -1);
    }
    state
        .on_vcpu_idle(3, 0)
        .unwrap_or_else(|error| panic!("final vCPU halt should queue exact timer: {error}"));
    assert_eq!(LAST_QUEUED_ADVANCE_TICK.get(), 56);
    assert_eq!(slot.snapshot().status, STATUS_IDLE);

    state
        .complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 56))
        .unwrap_or_else(|error| panic!("all-halted completion should commit: {error}"));
    assert_eq!(slot.snapshot().current_icount, 56);
    TEST_CLOCK_DEADLINE_PS.set(-1);
}

#[test]
fn live_time_completion_rejects_missing_or_mismatched_pending_state() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = test_live_state(44, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));

    assert!(matches!(
        state.complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 20)),
        Err(LiveVcpuTimeCallbackError::IdleAdvanceCompletionWithoutPending)
    ));
    let queued = crate::QueuedIdleAdvance::require(Some(test_queue_idle_advance))
        .unwrap_or_else(|error| panic!("queued advance should build: {error}"));
    let pending = queued
        .enqueue(20)
        .unwrap_or_else(|error| panic!("idle advance should queue: {error}"));
    assert!(matches!(
        state.arm_idle_advance(0, 9, pending, None),
        Err(LiveVcpuTimeCallbackError::IdleAdvancePendingTargetMismatch { .. })
    ));
    assert_eq!(slot.snapshot().current_icount, 0);

    let pending = queued
        .enqueue(8)
        .unwrap_or_else(|error| panic!("matching idle advance should queue: {error}"));
    state
        .arm_idle_advance(0, 8, pending, None)
        .unwrap_or_else(|error| panic!("matching idle advance should arm: {error}"));
    assert!(matches!(
        state.complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 14)),
        Err(LiveVcpuTimeCallbackError::IdleAdvanceCompletion { .. })
    ));
    assert_eq!(slot.snapshot().current_icount, 0);
    state
        .complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 8))
        .unwrap_or_else(|error| panic!("retained pending advance should still complete: {error}"));
    assert_eq!(slot.snapshot().current_icount, 8);
}

#[test]
fn live_idle_advance_publishes_pending_state_before_enqueue_completion() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let mut state = test_live_state(45, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state.queued_idle_advance =
        QueuedIdleAdvance::require(Some(test_queue_idle_advance_with_synchronous_completion))
            .unwrap_or_else(|error| panic!("test queued advance should validate: {error}"));
    let state = Box::new(state);

    TEST_SYNCHRONOUS_COMPLETION_SUCCEEDED.store(false, Ordering::Release);
    TEST_SYNCHRONOUS_COMPLETION_STATE.store(
        std::ptr::from_ref(state.as_ref()).cast_mut(),
        Ordering::Release,
    );
    let enqueue_result = state.arm_and_enqueue_idle_advance_or_defer(0, 8, None);
    TEST_SYNCHRONOUS_COMPLETION_STATE.store(std::ptr::null_mut(), Ordering::Release);

    assert_eq!(enqueue_result, Ok(true));
    assert!(TEST_SYNCHRONOUS_COMPLETION_SUCCEEDED.load(Ordering::Acquire));
    assert!(!state.idle_advance_is_pending());
    assert_eq!(slot.snapshot().current_icount, 8);
}

#[test]
fn live_idle_advance_rolls_back_exact_prepublication_after_busy_enqueue() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = test_live_state(46, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));

    TEST_QUEUED_ADVANCE_STATUS.set(-libc::EBUSY);
    let enqueue_result = state.arm_and_enqueue_idle_advance_or_defer(0, 8, None);
    TEST_QUEUED_ADVANCE_STATUS.set(0);

    assert_eq!(enqueue_result, Ok(false));
    assert!(!state.idle_advance_is_pending());
    assert!(
        state
            .pending_idle_advance
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_none()
    );
    assert_eq!(slot.snapshot().current_icount, 0);
}

#[test]
fn live_idle_advance_defers_a_second_producer_during_enqueue() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let mut state = test_live_state(47, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state.queued_idle_advance =
        QueuedIdleAdvance::require(Some(test_queue_idle_advance_with_nested_producer))
            .unwrap_or_else(|error| panic!("test queued advance should validate: {error}"));
    let state = Box::new(state);

    TEST_NESTED_PRODUCER_DEFERRED.store(false, Ordering::Release);
    TEST_NESTED_PRODUCER_STATE.store(
        std::ptr::from_ref(state.as_ref()).cast_mut(),
        Ordering::Release,
    );
    let enqueue_result = state.arm_and_enqueue_idle_advance_or_defer(0, 8, None);
    TEST_NESTED_PRODUCER_STATE.store(std::ptr::null_mut(), Ordering::Release);

    assert_eq!(enqueue_result, Ok(true));
    assert!(TEST_NESTED_PRODUCER_DEFERRED.load(Ordering::Acquire));
    assert!(state.idle_advance_is_pending());
    state
        .complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 8))
        .unwrap_or_else(|error| panic!("outer advance should still complete: {error}"));
    assert_eq!(slot.snapshot().current_icount, 8);
}

#[test]
fn live_pending_advance_rejects_idle_resume_and_allows_read_only_reentrant_publication() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = test_live_state(48, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .on_vcpu_init(0)
        .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));
    state
        .halted_vcpus
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .mark_halted(0)
        .unwrap_or_else(|error| panic!("test vCPU should enter halted state: {error}"));
    let queued = crate::QueuedIdleAdvance::require(Some(test_queue_idle_advance))
        .unwrap_or_else(|error| panic!("queued advance should build: {error}"));
    let pending = queued
        .enqueue(8)
        .unwrap_or_else(|error| panic!("idle advance should queue: {error}"));
    state
        .arm_idle_advance(0, 8, pending, None)
        .unwrap_or_else(|error| panic!("pending idle advance should arm: {error}"));
    let pending_snapshot = slot.snapshot();

    assert_eq!(
        state.on_vcpu_resume(0, 0),
        Err(LiveVcpuTimeCallbackError::ResumeWhileIdleAdvancePending)
    );
    state
        .on_vcpu_idle(0, 0)
        .unwrap_or_else(|error| panic!("competing idle producer should defer: {error}"));
    assert!(!state.all_halted_idle_handled.load(Ordering::Acquire));
    assert!(state.idle_advance_is_pending());
    let pending_guard = match state.pending_idle_advance.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    state.publish_current_icount(0).unwrap_or_else(|error| {
        panic!("read-only publication should use the atomic pending coordinate: {error}")
    });
    drop(pending_guard);
    assert_eq!(slot.snapshot(), pending_snapshot);

    state
        .complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 8))
        .unwrap_or_else(|error| panic!("retained pending advance should complete: {error}"));
    assert_eq!(slot.snapshot().current_icount, 8);
}

#[test]
fn nested_fault_command_pump_uses_published_scheduler_state() {
    let slot = NodeSlot::new(KIND_VM);
    let state = test_live_state(71, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    let bridge_guard = state
        .fault_commands
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    state
        .fault_command_pump_active
        .store(true, Ordering::Release);

    assert!(matches!(state.pump_fault_commands(0), Ok(true)));

    assert!(state.fault_command_pump_active.load(Ordering::Acquire));
    state
        .fault_command_pump_active
        .store(false, Ordering::Release);
    drop(bridge_guard);
}

#[test]
fn nested_newer_icount_publication_supersedes_only_its_older_caller() {
    assert_eq!(raw_icount_publication_is_superseded(10, 12, 13), Ok(true));
    assert_eq!(raw_icount_publication_is_superseded(10, 12, 12), Ok(false));
    assert_eq!(
        raw_icount_publication_is_superseded(13, 12, 13),
        Err(LiveVcpuTimeCallbackError::IcountRegressed {
            previous_icount: 13,
            current_icount: 12,
        })
    );
}

#[test]
fn live_state_calibrates_raw_progress_against_restored_logical_time() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 1000, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    slot.publish_reached_icount(500)
        .unwrap_or_else(|error| panic!("restored logical time should publish: {error}"));

    let state = test_live_state(45, 1, 4, &slot)
        .unwrap_or_else(|error| panic!("live callback state should calibrate: {error}"));
    state
        .publish_current_icount(5)
        .unwrap_or_else(|error| panic!("raw progress should preserve idle offset: {error}"));
    assert_eq!(slot.snapshot().current_icount, 550);

    assert!(matches!(
        test_live_state(45, 1, 12, &slot),
        Err(LiveVcpuTimeCallbackError::InitialRawIcountBeyondLogical {
            raw_icount: 12,
            logical_icount: 550,
        })
    ));
}

#[test]
fn live_state_rejects_bad_init_and_regressing_or_excess_progress() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 400, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let state = test_live_state(42, 2, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));

    assert!(matches!(
        state.on_vcpu_init(2),
        Err(LiveVcpuTimeCallbackError::VcpuOutOfRange {
            vcpu_index: 2,
            vcpu_count: 2,
        })
    ));
    state
        .on_vcpu_init(0)
        .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));
    state
        .publish_current_icount(4)
        .unwrap_or_else(|error| panic!("progress should publish: {error}"));
    assert!(matches!(
        state.publish_current_icount(3),
        Err(LiveVcpuTimeCallbackError::IcountRegressed {
            previous_icount: 4,
            current_icount: 3,
        })
    ));
    assert!(matches!(
        state.publish_current_icount(9),
        Err(LiveVcpuTimeCallbackError::IcountBeyondCeiling {
            current_icount: 450,
            ceiling_icount: 400,
        })
    ));
}

mod registration_stubs;
use registration_stubs::*;
