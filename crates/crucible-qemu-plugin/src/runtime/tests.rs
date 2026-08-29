//! Live runtime installation, control-worker, and teardown tests.

use super::*;

use std::cell::Cell;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize};

use crucible_protocol::{
    HostMsg, PluginHandshakeConfig, SETUP_ACK_STATUS_READY, SETUP_ACK_STATUS_SETUP_FAILED,
    SetupDescriptorFds, control_encode_host_msg, read_control_frame,
};
use crucible_shmem::{KIND_VM, NodeSlot, RegionConfig, RegionHeader, RegionLayout, STATUS_DONE};

mod support;
use support::*;

mod coverage_cases;
mod reservation_cases;

struct PanickingPostRegistrationFatalPolicy;

struct TestFatalTermination(PluginRuntimeInstallError);

impl PostRegistrationFatalPolicy for PanickingPostRegistrationFatalPolicy {
    fn terminate(&self, error: PluginRuntimeInstallError) -> ! {
        std::panic::panic_any(TestFatalTermination(error));
    }
}

struct TestPostRegistrationPanicGuard;

static CONTROL_WORKER_SHUTDOWN_FAILURE: AtomicI32 = AtomicI32::new(-1);
static CONTROL_WORKER_SHUTDOWN_CALLS: AtomicUsize = AtomicUsize::new(0);
static CONTROL_WORKER_DONE_BEFORE_SHUTDOWN: AtomicBool = AtomicBool::new(false);
static CONTROL_WORKER_SLOT_ADDRESS: AtomicUsize = AtomicUsize::new(0);
static CONTROL_WORKER_TEST_LOCK: Mutex<()> = Mutex::new(());

extern "C" fn record_control_worker_shutdown(failure: i32) {
    CONTROL_WORKER_SHUTDOWN_CALLS.fetch_add(1, Ordering::SeqCst);
    CONTROL_WORKER_SHUTDOWN_FAILURE.store(failure, Ordering::SeqCst);
    let address = CONTROL_WORKER_SLOT_ADDRESS.load(Ordering::SeqCst);
    if address != 0 {
        // SAFETY: each synchronous worker test retains its boxed slot until
        // this callback returns and publishes that exact address.
        let slot = unsafe { &*(address as *const NodeSlot) };
        CONTROL_WORKER_DONE_BEFORE_SHUTDOWN
            .store(slot.snapshot().status == STATUS_DONE, Ordering::SeqCst);
    }
}

#[test]
fn callback_teardown_route_moves_to_the_replacement_child_worker() {
    let (template_sender, template_receiver) = mpsc::channel();
    let router = LiveRuntimeTeardownRouter::new(template_sender);
    let callback_route = Arc::clone(&router);

    callback_route
        .send(LiveRuntimeTeardownTrigger::RunControlFault {
            diagnostic: String::from("template"),
        })
        .unwrap_or_else(|()| panic!("template route should remain connected"));
    assert!(matches!(
        template_receiver.recv(),
        Ok(LiveRuntimeTeardownTrigger::RunControlFault { diagnostic })
            if diagnostic == "template"
    ));

    let (child_sender, child_receiver) = mpsc::channel();
    router
        .replace(child_sender)
        .unwrap_or_else(|()| panic!("quiescent route replacement should succeed"));
    assert!(matches!(
        template_receiver.try_recv(),
        Err(mpsc::TryRecvError::Disconnected)
    ));

    callback_route
        .send(LiveRuntimeTeardownTrigger::RunControlFault {
            diagnostic: String::from("child"),
        })
        .unwrap_or_else(|()| panic!("retained callback route should reach child worker"));
    assert!(matches!(
        child_receiver.recv(),
        Ok(LiveRuntimeTeardownTrigger::RunControlFault { diagnostic })
            if diagnostic == "child"
    ));
}

#[test]
fn run_control_worker_consumes_quit_marks_done_then_requests_clean_shutdown() {
    let _test_lock = CONTROL_WORKER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (mut host, plugin) = running_plugin_control_pair();
    let (handle, _header, slot, _wake_owner, _wake_peer) = control_worker_teardown_handle();
    CONTROL_WORKER_SLOT_ADDRESS.store(std::ptr::from_ref(slot.as_ref()) as usize, Ordering::SeqCst);
    CONTROL_WORKER_SHUTDOWN_FAILURE.store(-1, Ordering::SeqCst);
    CONTROL_WORKER_SHUTDOWN_CALLS.store(0, Ordering::SeqCst);
    CONTROL_WORKER_DONE_BEFORE_SHUTDOWN.store(false, Ordering::SeqCst);
    host.write_all(&control_encode_host_msg(&HostMsg::Quit))
        .unwrap_or_else(|error| panic!("host Quit should write: {error}"));

    run_control_worker(plugin, handle, record_control_worker_shutdown);

    assert_eq!(slot.snapshot().status, STATUS_DONE);
    assert_eq!(CONTROL_WORKER_SHUTDOWN_FAILURE.load(Ordering::SeqCst), 0);
    assert_eq!(CONTROL_WORKER_SHUTDOWN_CALLS.load(Ordering::SeqCst), 1);
    assert!(CONTROL_WORKER_DONE_BEFORE_SHUTDOWN.load(Ordering::SeqCst));
}

#[test]
fn run_control_worker_rejects_unsolicited_run_frame_with_fail_loud_shutdown() {
    let _test_lock = CONTROL_WORKER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (mut host, plugin) = running_plugin_control_pair();
    let (handle, _header, slot, _wake_owner, _wake_peer) = control_worker_teardown_handle();
    CONTROL_WORKER_SLOT_ADDRESS.store(std::ptr::from_ref(slot.as_ref()) as usize, Ordering::SeqCst);
    CONTROL_WORKER_SHUTDOWN_FAILURE.store(-1, Ordering::SeqCst);
    CONTROL_WORKER_SHUTDOWN_CALLS.store(0, Ordering::SeqCst);
    CONTROL_WORKER_DONE_BEFORE_SHUTDOWN.store(false, Ordering::SeqCst);
    host.write_all(&control_encode_host_msg(&HostMsg::HelloAck {
        proto_version: 2,
        abi_version: 1,
        slot_index: 0,
        node_count: 1,
    }))
    .unwrap_or_else(|error| panic!("unsolicited RUN frame should write: {error}"));

    run_control_worker(plugin, handle, record_control_worker_shutdown);

    assert_eq!(slot.snapshot().status, STATUS_DONE);
    assert_eq!(CONTROL_WORKER_SHUTDOWN_FAILURE.load(Ordering::SeqCst), 1);
    assert_eq!(CONTROL_WORKER_SHUTDOWN_CALLS.load(Ordering::SeqCst), 1);
    assert!(CONTROL_WORKER_DONE_BEFORE_SHUTDOWN.load(Ordering::SeqCst));
}

#[test]
fn shared_shutdown_worker_defers_done_and_clean_qemu_shutdown_until_callback_drain() {
    let _test_lock = CONTROL_WORKER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (handle, header, slot, _wake_owner, _wake_peer) = control_worker_teardown_handle();
    let quiescence = Arc::clone(&handle.quiescence);
    let in_flight = quiescence
        .enter()
        .unwrap_or_else(|| panic!("callback admission should begin open"));
    header
        .request_shutdown([slot.as_ref()])
        .unwrap_or_else(|error| panic!("shared shutdown should publish: {error}"));
    let proof = PluginShutdownRequested::from_region_header(&header)
        .unwrap_or_else(|error| panic!("shared shutdown proof should build: {error}"));
    let (sender, receiver) = mpsc::channel();
    let workers = LiveWorkerQuiescence::new(WORKER_REQUIRED);

    CONTROL_WORKER_SLOT_ADDRESS.store(std::ptr::from_ref(slot.as_ref()) as usize, Ordering::SeqCst);
    CONTROL_WORKER_SHUTDOWN_FAILURE.store(-1, Ordering::SeqCst);
    CONTROL_WORKER_SHUTDOWN_CALLS.store(0, Ordering::SeqCst);
    CONTROL_WORKER_DONE_BEFORE_SHUTDOWN.store(false, Ordering::SeqCst);
    sender
        .send(LiveRuntimeTeardownTrigger::SharedShutdown(proof))
        .unwrap_or_else(|_error| panic!("shared shutdown should reach worker"));
    let worker = std::thread::spawn(move || {
        run_teardown_worker(receiver, handle, record_control_worker_shutdown, workers);
    });

    wait_until_callback_admission_closed(&quiescence);
    assert!(quiescence.enter().is_none());
    assert_ne!(slot.snapshot().status, STATUS_DONE);
    assert_eq!(CONTROL_WORKER_SHUTDOWN_CALLS.load(Ordering::SeqCst), 0);

    drop(in_flight);
    worker
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));

    assert_eq!(slot.snapshot().status, STATUS_DONE);
    assert_eq!(CONTROL_WORKER_SHUTDOWN_FAILURE.load(Ordering::SeqCst), 0);
    assert_eq!(CONTROL_WORKER_SHUTDOWN_CALLS.load(Ordering::SeqCst), 1);
    assert!(CONTROL_WORKER_DONE_BEFORE_SHUTDOWN.load(Ordering::SeqCst));
}

#[test]
fn quit_selected_first_keeps_receiver_live_for_admitted_callback_shutdown_signal() {
    let _test_lock = CONTROL_WORKER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (mut host, plugin) = running_plugin_control_pair();
    let (handle, header, slot, _wake_owner, _wake_peer) = control_worker_teardown_handle();
    let quiescence = Arc::clone(&handle.quiescence);
    let in_flight = quiescence
        .enter()
        .unwrap_or_else(|| panic!("callback admission should begin open"));
    header
        .request_shutdown([slot.as_ref()])
        .unwrap_or_else(|error| panic!("shared shutdown should publish: {error}"));
    let shared_proof = PluginShutdownRequested::from_region_header(&header)
        .unwrap_or_else(|error| panic!("shared shutdown proof should build: {error}"));
    let (sender, receiver) = mpsc::channel();
    let workers = LiveWorkerQuiescence::new(WORKER_REQUIRED);

    CONTROL_WORKER_SLOT_ADDRESS.store(std::ptr::from_ref(slot.as_ref()) as usize, Ordering::SeqCst);
    CONTROL_WORKER_SHUTDOWN_FAILURE.store(-1, Ordering::SeqCst);
    CONTROL_WORKER_SHUTDOWN_CALLS.store(0, Ordering::SeqCst);
    CONTROL_WORKER_DONE_BEFORE_SHUTDOWN.store(false, Ordering::SeqCst);

    let teardown_workers = Arc::clone(&workers);
    let worker = std::thread::spawn(move || {
        run_teardown_worker(
            receiver,
            handle,
            record_control_worker_shutdown,
            teardown_workers,
        );
    });
    let reader_sender = sender.clone();
    let reader = std::thread::spawn(move || run_control_reader(plugin, reader_sender, workers));
    host.write_all(&control_encode_host_msg(&HostMsg::Quit))
        .unwrap_or_else(|error| panic!("host Quit should write: {error}"));
    let quit_delivered = reader
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    assert!(quit_delivered);

    // Quit is the only trigger delivered before admission closes, so it must
    // be the worker's selected trigger. The receiver must remain connected
    // while that worker drains this already-admitted callback.
    wait_until_callback_admission_closed(&quiescence);
    assert!(quiescence.enter().is_none());
    assert_ne!(slot.snapshot().status, STATUS_DONE);
    sender
        .send(LiveRuntimeTeardownTrigger::SharedShutdown(shared_proof))
        .unwrap_or_else(|_error| {
            panic!("admitted callback shutdown signal should reach the draining worker")
        });
    assert_eq!(CONTROL_WORKER_SHUTDOWN_CALLS.load(Ordering::SeqCst), 0);

    drop(in_flight);
    worker
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));

    assert_eq!(slot.snapshot().status, STATUS_DONE);
    assert_eq!(CONTROL_WORKER_SHUTDOWN_FAILURE.load(Ordering::SeqCst), 0);
    assert_eq!(CONTROL_WORKER_SHUTDOWN_CALLS.load(Ordering::SeqCst), 1);
    assert!(CONTROL_WORKER_DONE_BEFORE_SHUTDOWN.load(Ordering::SeqCst));
}

#[test]
fn shared_selected_first_keeps_receiver_live_for_subsequent_quit_delivery() {
    let _test_lock = CONTROL_WORKER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (mut host, plugin) = running_plugin_control_pair();
    let (handle, header, slot, _wake_owner, _wake_peer) = control_worker_teardown_handle();
    let quiescence = Arc::clone(&handle.quiescence);
    let in_flight = quiescence
        .enter()
        .unwrap_or_else(|| panic!("callback admission should begin open"));
    header
        .request_shutdown([slot.as_ref()])
        .unwrap_or_else(|error| panic!("shared shutdown should publish: {error}"));
    let shared_proof = PluginShutdownRequested::from_region_header(&header)
        .unwrap_or_else(|error| panic!("shared shutdown proof should build: {error}"));
    let (sender, receiver) = mpsc::channel();
    let workers = LiveWorkerQuiescence::new(WORKER_REQUIRED);

    CONTROL_WORKER_SLOT_ADDRESS.store(std::ptr::from_ref(slot.as_ref()) as usize, Ordering::SeqCst);
    CONTROL_WORKER_SHUTDOWN_FAILURE.store(-1, Ordering::SeqCst);
    CONTROL_WORKER_SHUTDOWN_CALLS.store(0, Ordering::SeqCst);
    CONTROL_WORKER_DONE_BEFORE_SHUTDOWN.store(false, Ordering::SeqCst);

    sender
        .send(LiveRuntimeTeardownTrigger::SharedShutdown(shared_proof))
        .unwrap_or_else(|_error| panic!("shared shutdown should reach worker"));
    let teardown_workers = Arc::clone(&workers);
    let worker = std::thread::spawn(move || {
        run_teardown_worker(
            receiver,
            handle,
            record_control_worker_shutdown,
            teardown_workers,
        );
    });
    let reader_sender = sender.clone();
    let reader = std::thread::spawn(move || run_control_reader(plugin, reader_sender, workers));

    // Shared shutdown is queued before the worker starts, so admission closure
    // proves that it was selected. The lifecycle reader must still deliver a
    // later Quit without observing a disconnected teardown receiver.
    wait_until_callback_admission_closed(&quiescence);
    assert!(quiescence.enter().is_none());
    assert_ne!(slot.snapshot().status, STATUS_DONE);
    host.write_all(&control_encode_host_msg(&HostMsg::Quit))
        .unwrap_or_else(|error| panic!("host Quit should write: {error}"));
    let quit_delivered = reader
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    assert!(quit_delivered);
    assert_eq!(CONTROL_WORKER_SHUTDOWN_CALLS.load(Ordering::SeqCst), 0);

    drop(in_flight);
    worker
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));

    assert_eq!(slot.snapshot().status, STATUS_DONE);
    assert_eq!(CONTROL_WORKER_SHUTDOWN_FAILURE.load(Ordering::SeqCst), 0);
    assert_eq!(CONTROL_WORKER_SHUTDOWN_CALLS.load(Ordering::SeqCst), 1);
    assert!(CONTROL_WORKER_DONE_BEFORE_SHUTDOWN.load(Ordering::SeqCst));
}

#[test]
fn closing_run_control_unblocks_reader_and_delivers_fail_loud_trigger() {
    let (host, plugin) = running_plugin_control_pair();
    let (sender, receiver) = mpsc::channel();
    let workers = LiveWorkerQuiescence::new(WORKER_REQUIRED);
    let reader = std::thread::spawn(move || run_control_reader(plugin, sender, workers));

    host.shutdown(std::net::Shutdown::Both)
        .unwrap_or_else(|error| panic!("control shutdown should succeed: {error}"));
    let trigger = receiver
        .recv()
        .unwrap_or_else(|error| panic!("reader should deliver a control fault: {error}"));
    let delivered = reader
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    assert!(delivered);

    assert!(matches!(
        trigger,
        LiveRuntimeTeardownTrigger::RunControlFault { .. }
    ));
}

#[test]
fn held_run_control_reader_parks_before_delivering_its_trigger() {
    let (mut host, plugin) = running_plugin_control_pair();
    let (sender, receiver) = mpsc::channel();
    let workers = LiveWorkerQuiescence::new(WORKER_REQUIRED);
    let held = workers.hold();
    assert!(held.held);

    let reader_workers = Arc::clone(&workers);
    let reader = std::thread::spawn(move || run_control_reader(plugin, sender, reader_workers));
    host.write_all(&control_encode_host_msg(&HostMsg::Quit))
        .unwrap_or_else(|error| panic!("host Quit should write: {error}"));

    assert!(
        receiver
            .recv_timeout(std::time::Duration::from_millis(20))
            .is_err(),
        "held reader must not deliver a teardown trigger"
    );
    let mut parked = false;
    for _attempt in 0..100_000 {
        let snapshot = workers.snapshot();
        if snapshot.parked_mask & WORKER_RUN_CONTROL != 0 {
            assert_eq!(snapshot.operations_in_flight, 0);
            parked = true;
            break;
        }
        std::thread::yield_now();
    }
    assert!(parked, "reader should park before delivery");

    workers.release();
    let trigger = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap_or_else(|error| panic!("released reader should deliver: {error}"));
    assert!(matches!(trigger, LiveRuntimeTeardownTrigger::HostQuit(_)));
    assert!(
        reader
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    );
}

fn wait_until_callback_admission_closed(quiescence: &LiveCallbackQuiescence) {
    for _attempt in 0..100_000 {
        if quiescence.is_closed() {
            return;
        }
        std::thread::yield_now();
    }
    panic!("teardown worker did not close callback admission");
}

fn running_plugin_control_pair() -> (UnixStream, ControlLifecycleStream<UnixStream>) {
    let (mut host, plugin_socket) = UnixStream::pair()
        .unwrap_or_else(|error| panic!("control socket pair should open: {error}"));
    let mut plugin = ControlLifecycleStream::connected_unix_stream(plugin_socket)
        .unwrap_or_else(|error| panic!("plugin lifecycle should connect: {error}"));
    host.write_all(&control_encode_host_msg(&HostMsg::HelloAck {
        proto_version: 2,
        abi_version: 1,
        slot_index: 0,
        node_count: 1,
    }))
    .unwrap_or_else(|error| panic!("HelloAck should write: {error}"));
    plugin
        .plugin_start_handshake(PluginHandshakeConfig {
            proto_version: 2,
            abi_version: 1,
        })
        .unwrap_or_else(|error| panic!("plugin handshake should complete: {error}"));
    let _hello = read_control_frame(&mut host)
        .unwrap_or_else(|error| panic!("plugin Hello should read: {error}"));
    let shmem = File::open("/dev/null")
        .unwrap_or_else(|error| panic!("shmem fixture should open: {error}"));
    let wake =
        File::open("/dev/null").unwrap_or_else(|error| panic!("wake fixture should open: {error}"));
    crucible_protocol::send_setup_with_descriptors(
        host.as_raw_fd(),
        4096,
        SetupDescriptorFds {
            shmem_fd: shmem.as_raw_fd(),
            wake_fd: wake.as_raw_fd(),
            plugin_setup_plan_fd: shmem.as_raw_fd(),
        },
    )
    .unwrap_or_else(|error| panic!("setup descriptors should send: {error}"));
    let _setup = plugin
        .plugin_recv_setup_with_descriptors()
        .unwrap_or_else(|error| panic!("setup descriptors should receive: {error}"));
    plugin
        .plugin_send_ready_setup_ack()
        .unwrap_or_else(|error| panic!("ready setup ack should send: {error}"));
    let _ack = read_control_frame(&mut host)
        .unwrap_or_else(|error| panic!("ready setup ack should read: {error}"));
    plugin
        .enter_run_via_shared_memory()
        .unwrap_or_else(|error| panic!("plugin lifecycle should enter RUN: {error}"));
    (host, plugin)
}

fn control_worker_teardown_handle() -> (
    LiveControlTeardownHandle,
    Box<RegionHeader>,
    Box<NodeSlot>,
    UnixStream,
    UnixStream,
) {
    let layout = RegionLayout::for_config(RegionConfig::new(1, 2, 0))
        .unwrap_or_else(|error| panic!("test layout should validate: {error}"));
    let header = Box::new(RegionHeader::new(layout));
    let slot = Box::new(NodeSlot::new(KIND_VM));
    let (wake_fd, wake_peer) =
        UnixStream::pair().unwrap_or_else(|error| panic!("wake socket pair should open: {error}"));
    let handle = LiveControlTeardownHandle {
        quiescence: Arc::new(LiveCallbackQuiescence::new()),
        header_address: std::ptr::from_ref(header.as_ref()) as usize,
        slot_address: std::ptr::from_ref(slot.as_ref()) as usize,
        wake_fd: wake_fd.as_raw_fd(),
    };
    (handle, header, slot, wake_fd, wake_peer)
}

impl TestPostRegistrationPanicGuard {
    fn install(stage: PostRegistrationStage) -> Self {
        TEST_POST_REGISTRATION_PANIC_STAGE.store(stage as u8, Ordering::Relaxed);
        Self
    }
}

impl Drop for TestPostRegistrationPanicGuard {
    fn drop(&mut self) {
        TEST_POST_REGISTRATION_PANIC_STAGE.store(u8::MAX, Ordering::Relaxed);
    }
}

fn install_expecting_post_registration_fatal<R>(
    plugin_id: QemuPluginId,
    fixture: &LiveInstallFixture,
    capabilities: LiveInstallCapabilities,
    callback_registrar: &R,
    reservation: &mut PluginRuntimeReservation,
) -> PluginRuntimeInstallError
where
    R: OwnedCallbackRegistrar,
{
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        install_live_runtime_with_fatal_policy(
            plugin_id,
            fixture.args(),
            test_state(),
            capabilities,
            callback_registrar,
            reservation,
            &PanickingPostRegistrationFatalPolicy,
        )
    }));
    match result {
        Ok(Ok(_runtime)) => panic!("post-registration failure unexpectedly activated runtime"),
        Ok(Err(error)) => {
            panic!("post-registration failure returned to QEMU instead of terminating: {error}")
        }
        Err(payload) => match payload.downcast::<TestFatalTermination>() {
            Ok(termination) => termination.0,
            Err(payload) => std::panic::resume_unwind(payload),
        },
    }
}

struct SuccessfulCallbackRegistrar;

static CALLBACK_MODEL_REGISTERED_PLUGIN_ID: AtomicU64 = AtomicU64::new(0);

impl OwnedCallbackRegistrar for SuccessfulCallbackRegistrar {
    fn preflight(&self, _args: &PluginArgs) -> Result<(), OwnedCallbackRegistrationError> {
        Ok(())
    }

    fn register(
        &self,
        args: &PluginArgs,
        mut state: Pin<&mut OwnedCallbackRuntimeState>,
    ) -> Result<OwnedCallbackRegistrationMask, OwnedCallbackRegistrationError> {
        state.as_mut().allow_missing_fault_command_state_for_test();
        Ok(OwnedCallbackRegistrationMask::required_for(args))
    }
}

fn coverage_callback_model_apis() -> crate::QemuBasicBlockCoverageApis {
    crate::QemuBasicBlockCoverageApis::new(
        coverage_callback_model_register_tb_trans_cb,
        coverage_callback_model_register_tb_exec_cond_cb,
        coverage_callback_model_tb_vaddr,
        coverage_callback_model_tb_n_insns,
        coverage_callback_model_tb_get_insn,
        coverage_callback_model_insn_size,
        coverage_callback_model_icount_at_tb_entry,
        coverage_callback_model_register_flush_cb,
        coverage_callback_model_scoreboard_new,
        coverage_callback_model_scoreboard_free,
        coverage_callback_model_u64_set,
    )
}

extern "C" fn coverage_callback_model_register_tb_trans_cb(
    plugin_id: QemuPluginId,
    callback: Option<crate::QemuVcpuTbTransCbFn>,
) {
    assert!(callback.is_some());
    CALLBACK_MODEL_REGISTERED_PLUGIN_ID.store(plugin_id, Ordering::SeqCst);
}

extern "C" fn coverage_callback_model_register_tb_exec_cond_cb(
    _tb: *mut crate::QemuPluginTb,
    _callback: Option<crate::QemuVcpuTbExecCbFn>,
    _flags: std::os::raw::c_int,
    _condition: std::os::raw::c_int,
    _entry: crate::QemuPluginU64,
    _immediate: u64,
    _userdata: *mut std::os::raw::c_void,
) {
}

extern "C" fn coverage_callback_model_scoreboard_new(
    _element_size: usize,
) -> *mut crate::QemuPluginScoreboard {
    std::ptr::NonNull::dangling().as_ptr()
}

extern "C" fn coverage_callback_model_scoreboard_free(_score: *mut crate::QemuPluginScoreboard) {}

extern "C" fn coverage_callback_model_u64_set(
    _entry: crate::QemuPluginU64,
    _vcpu_index: std::os::raw::c_uint,
    _value: u64,
) {
}

extern "C" fn coverage_callback_model_tb_vaddr(_tb: *const crate::QemuPluginTb) -> u64 {
    0
}

extern "C" fn coverage_callback_model_tb_n_insns(_tb: *const crate::QemuPluginTb) -> usize {
    0
}

extern "C" fn coverage_callback_model_tb_get_insn(
    _tb: *const crate::QemuPluginTb,
    _index: usize,
) -> *mut crate::QemuPluginInsn {
    std::ptr::null_mut()
}

extern "C" fn coverage_callback_model_insn_size(_insn: *const crate::QemuPluginInsn) -> usize {
    0
}

extern "C" fn coverage_callback_model_icount_at_tb_entry(
    _tb_insns: u64,
    entry_icount: *mut u64,
) -> std::os::raw::c_int {
    if entry_icount.is_null() {
        return -1;
    }
    // SAFETY: this test stub just validated the output pointer.
    unsafe { *entry_icount = 0 };
    0
}

extern "C" fn coverage_callback_model_register_flush_cb(
    _plugin_id: QemuPluginId,
    _callback: crate::QemuPluginSimpleCbFn,
) {
}

#[derive(Clone, Copy)]
struct RegisteredLiveVcpuTimeCallbacks {
    publish: crate::QemuSimShmemPublishIcountCbFn,
    ceiling: crate::QemuSimShmemMaxAdvanceIcountCbFn,
    userdata: usize,
}

static REGISTERED_LIVE_VCPU_TIME_CALLBACKS: Mutex<Option<RegisteredLiveVcpuTimeCallbacks>> =
    Mutex::new(None);
static LIVE_VCPU_INIT_REGISTRATIONS: AtomicU64 = AtomicU64::new(0);
static LIVE_IDLE_RESUME_REGISTRATIONS: AtomicU64 = AtomicU64::new(0);
static LIVE_SIM_DISPATCH_REGISTRATIONS: AtomicU64 = AtomicU64::new(0);
static LIVE_TIME_ADVANCE_COMPLETION_REGISTRATIONS: AtomicU64 = AtomicU64::new(0);
static LIVE_NETWORK_TX_REGISTRATIONS: AtomicU64 = AtomicU64::new(0);
static LIVE_BLOCK_REGISTRATIONS: AtomicU64 = AtomicU64::new(0);
static LIVE_BLOCK_WAIT_REGISTRATIONS: AtomicU64 = AtomicU64::new(0);
static LIVE_NINEP_REGISTRATIONS: AtomicU64 = AtomicU64::new(0);

fn live_registration_counts() -> [u64; 8] {
    [
        LIVE_VCPU_INIT_REGISTRATIONS.load(Ordering::SeqCst),
        LIVE_IDLE_RESUME_REGISTRATIONS.load(Ordering::SeqCst),
        LIVE_SIM_DISPATCH_REGISTRATIONS.load(Ordering::SeqCst),
        LIVE_TIME_ADVANCE_COMPLETION_REGISTRATIONS.load(Ordering::SeqCst),
        LIVE_NETWORK_TX_REGISTRATIONS.load(Ordering::SeqCst),
        LIVE_BLOCK_REGISTRATIONS.load(Ordering::SeqCst),
        LIVE_BLOCK_WAIT_REGISTRATIONS.load(Ordering::SeqCst),
        LIVE_NINEP_REGISTRATIONS.load(Ordering::SeqCst),
    ]
}

struct LiveVcpuTimeThenTestCompletionRegistrar {
    live: LiveVcpuTimeCallbackRegistrar,
}

impl OwnedCallbackRegistrar for LiveVcpuTimeThenTestCompletionRegistrar {
    fn preflight(&self, args: &PluginArgs) -> Result<(), OwnedCallbackRegistrationError> {
        self.live.preflight(args)
    }

    fn register(
        &self,
        args: &PluginArgs,
        mut state: Pin<&mut OwnedCallbackRuntimeState>,
    ) -> Result<OwnedCallbackRegistrationMask, OwnedCallbackRegistrationError> {
        let vcpu = self.live.register(args, state.as_mut())?;
        assert_eq!(vcpu, OwnedCallbackRegistrationMask::base_required());
        Ok(OwnedCallbackRegistrationMask::required_for(args))
    }
}

extern "C" fn capture_vcpu_init_registration(
    plugin_id: QemuPluginId,
    callback: crate::QemuVcpuSimpleCbFn,
) {
    LIVE_VCPU_INIT_REGISTRATIONS.fetch_add(1, Ordering::SeqCst);
    callback(plugin_id, 0);
}

extern "C" fn capture_vcpu_idle_resume_registration(
    idle_callback: Option<crate::QemuVcpuIdleResumeCbFn>,
    resume_callback: Option<crate::QemuVcpuIdleResumeCbFn>,
    userdata: *mut std::ffi::c_void,
) {
    assert!(idle_callback.is_some());
    assert!(resume_callback.is_some());
    assert!(!userdata.is_null());
    LIVE_IDLE_RESUME_REGISTRATIONS.fetch_add(1, Ordering::SeqCst);
}

extern "C" fn capture_control_boundary_registration(
    callback: Option<crate::QemuVcpuIdleResumeCbFn>,
    userdata: *mut std::ffi::c_void,
) {
    assert!(callback.is_some());
    assert!(!userdata.is_null());
}

extern "C" fn capture_sim_dispatch_registration(
    publish: Option<crate::QemuSimShmemPublishIcountCbFn>,
    ceiling: Option<crate::QemuSimShmemMaxAdvanceIcountCbFn>,
    userdata: *mut std::ffi::c_void,
) {
    let Some(publish) = publish else {
        panic!("live registrar must install the sim publish callback");
    };
    let Some(ceiling) = ceiling else {
        panic!("live registrar must install the sim ceiling callback");
    };
    LIVE_SIM_DISPATCH_REGISTRATIONS.fetch_add(1, Ordering::SeqCst);
    let mut capture = REGISTERED_LIVE_VCPU_TIME_CALLBACKS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let current = capture.get_or_insert(RegisteredLiveVcpuTimeCallbacks {
        publish,
        ceiling,
        userdata: userdata as usize,
    });
    assert_eq!(current.userdata, userdata as usize);
    current.publish = publish;
    current.ceiling = ceiling;
}

extern "C" fn capture_time_advance_completion_registration(
    callback: Option<crate::QemuTimeAdvanceCompletionCbFn>,
    userdata: *mut std::ffi::c_void,
) -> std::os::raw::c_int {
    assert!(callback.is_some());
    assert!(!userdata.is_null());
    LIVE_TIME_ADVANCE_COMPLETION_REGISTRATIONS.fetch_add(1, Ordering::SeqCst);
    0
}

extern "C" fn capture_network_tx_registration(
    callback: Option<crate::QemuNetTxCbFn>,
    userdata: *mut std::ffi::c_void,
) {
    assert!(callback.is_some());
    assert!(!userdata.is_null());
    LIVE_NETWORK_TX_REGISTRATIONS.fetch_add(1, Ordering::SeqCst);
}

extern "C" fn capture_block_registration(
    submit: Option<crate::QemuBlkSubmitCbFn>,
    poll: Option<crate::QemuBlkPollCbFn>,
    userdata: *mut std::ffi::c_void,
) {
    assert!(submit.is_some());
    assert!(poll.is_some());
    assert!(!userdata.is_null());
    LIVE_BLOCK_REGISTRATIONS.fetch_add(1, Ordering::SeqCst);
}

extern "C" fn capture_block_event_registration(
    poll: Option<crate::QemuBlkEventPollCbFn>,
    commit: Option<crate::QemuBlkEventCommitCbFn>,
    save: Option<crate::QemuBlkTransportSaveCbFn>,
    restore: Option<crate::QemuBlkTransportRestoreCbFn>,
    userdata: *mut std::ffi::c_void,
) {
    assert!(poll.is_some());
    assert!(commit.is_some());
    assert!(save.is_some());
    assert!(restore.is_some());
    assert!(!userdata.is_null());
}

extern "C" fn capture_block_wait_registration(
    wait: Option<crate::QemuBlkWaitCbFn>,
    userdata: *mut std::ffi::c_void,
) {
    assert!(wait.is_some());
    assert!(!userdata.is_null());
    LIVE_BLOCK_WAIT_REGISTRATIONS.fetch_add(1, Ordering::SeqCst);
}

extern "C" fn capture_ninep_registration(
    burst_start: Option<crate::QemuNinePBurstCbFn>,
    submit: Option<crate::QemuNinePSubmitCbFn>,
    poll: Option<crate::QemuNinePPollCbFn>,
    burst_done: Option<crate::QemuNinePBurstCbFn>,
    userdata: *mut std::ffi::c_void,
) {
    assert!(burst_start.is_some());
    assert!(submit.is_some());
    assert!(poll.is_some());
    assert!(burst_done.is_some());
    assert!(!userdata.is_null());
    LIVE_NINEP_REGISTRATIONS.fetch_add(1, Ordering::SeqCst);
}

extern "C" fn capture_accelerator_registration(
    submit: Option<crate::QemuAcceleratorSubmitCbFn>,
    poll: Option<crate::QemuAcceleratorPollCbFn>,
    wait: Option<crate::QemuAcceleratorWaitCbFn>,
    restore_begin: Option<crate::QemuAcceleratorRestoreBeginCbFn>,
    restore: Option<crate::QemuAcceleratorRestoreCbFn>,
    restore_commit: Option<crate::QemuAcceleratorRestoreCommitCbFn>,
    restore_abort: Option<crate::QemuAcceleratorRestoreAbortCbFn>,
    cancel: Option<crate::QemuAcceleratorCancelCbFn>,
    userdata: *mut std::ffi::c_void,
) {
    assert!(submit.is_some());
    assert!(poll.is_some());
    assert!(wait.is_some());
    assert!(restore_begin.is_some());
    assert!(restore.is_some());
    assert!(restore_commit.is_some());
    assert!(restore_abort.is_some());
    assert!(cancel.is_some());
    assert!(!userdata.is_null());
}

extern "C" fn live_network_inject_ok(
    _payload: *const u8,
    _payload_len: usize,
) -> std::os::raw::c_int {
    0
}

struct RecordingSuccessfulCallbackRegistrar {
    state_address: Cell<usize>,
    wake_fd: Cell<i32>,
}

impl RecordingSuccessfulCallbackRegistrar {
    const fn new() -> Self {
        Self {
            state_address: Cell::new(0),
            wake_fd: Cell::new(-1),
        }
    }
}

impl OwnedCallbackRegistrar for RecordingSuccessfulCallbackRegistrar {
    fn preflight(&self, _args: &PluginArgs) -> Result<(), OwnedCallbackRegistrationError> {
        Ok(())
    }

    fn register(
        &self,
        args: &PluginArgs,
        mut state: Pin<&mut OwnedCallbackRuntimeState>,
    ) -> Result<OwnedCallbackRegistrationMask, OwnedCallbackRegistrationError> {
        state.as_mut().allow_missing_fault_command_state_for_test();
        let userdata = state.as_mut().userdata();
        let state = state.as_ref().get_ref();
        self.state_address.set(userdata as usize);
        self.wake_fd.set(state.setup.wake_fd().as_raw_fd());
        Ok(OwnedCallbackRegistrationMask::required_for(args))
    }
}

struct LateFailingCallbackRegistrar;

impl OwnedCallbackRegistrar for LateFailingCallbackRegistrar {
    fn preflight(&self, _args: &PluginArgs) -> Result<(), OwnedCallbackRegistrationError> {
        Ok(())
    }

    fn register(
        &self,
        _args: &PluginArgs,
        _state: Pin<&mut OwnedCallbackRuntimeState>,
    ) -> Result<OwnedCallbackRegistrationMask, OwnedCallbackRegistrationError> {
        Err(OwnedCallbackRegistrationError::AdaptersUnavailable {
            families: REQUIRED_OWNED_CALLBACK_FAMILIES,
        })
    }
}

struct PartiallyFailingCallbackRegistrar {
    state_address: Cell<usize>,
    wake_fd: Cell<i32>,
}

impl PartiallyFailingCallbackRegistrar {
    const fn new() -> Self {
        Self {
            state_address: Cell::new(0),
            wake_fd: Cell::new(-1),
        }
    }
}

impl OwnedCallbackRegistrar for PartiallyFailingCallbackRegistrar {
    fn preflight(&self, _args: &PluginArgs) -> Result<(), OwnedCallbackRegistrationError> {
        Ok(())
    }

    fn register(
        &self,
        _args: &PluginArgs,
        mut state: Pin<&mut OwnedCallbackRuntimeState>,
    ) -> Result<OwnedCallbackRegistrationMask, OwnedCallbackRegistrationError> {
        let userdata = state.as_mut().userdata();
        let state = state.as_ref().get_ref();
        self.state_address.set(userdata as usize);
        assert_eq!(userdata.cast_const(), std::ptr::from_ref(state).cast());
        self.wake_fd.set(state.setup.wake_fd().as_raw_fd());
        Err(OwnedCallbackRegistrationError::AdaptersUnavailable {
            families: REQUIRED_OWNED_CALLBACK_FAMILIES,
        })
    }
}

struct PartiallyPanickingCallbackRegistrar {
    state_address: Cell<usize>,
    wake_fd: Cell<i32>,
}

impl PartiallyPanickingCallbackRegistrar {
    const fn new() -> Self {
        Self {
            state_address: Cell::new(0),
            wake_fd: Cell::new(-1),
        }
    }
}

impl OwnedCallbackRegistrar for PartiallyPanickingCallbackRegistrar {
    fn preflight(&self, _args: &PluginArgs) -> Result<(), OwnedCallbackRegistrationError> {
        Ok(())
    }

    fn register(
        &self,
        _args: &PluginArgs,
        mut state: Pin<&mut OwnedCallbackRuntimeState>,
    ) -> Result<OwnedCallbackRegistrationMask, OwnedCallbackRegistrationError> {
        let userdata = state.as_mut().userdata();
        let state = state.as_ref().get_ref();
        self.state_address.set(userdata as usize);
        self.wake_fd.set(state.setup.wake_fd().as_raw_fd());
        panic!("injected panic after partial callback registration")
    }
}

#[test]
fn live_install_retains_active_state_only_after_complete_ordered_sequence() {
    let _runtime_state = isolate_runtime_state_for_test();
    reset_capability_call_counts();
    let fixture = LiveInstallFixture::new();
    let host = fixture.spawn_host(SETUP_ACK_STATUS_READY);
    let mut reservation =
        reserve_runtime().unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));
    let runtime = install_live_runtime(
        41,
        fixture.args(),
        test_state(),
        test_capabilities(),
        &SuccessfulCallbackRegistrar,
        &mut reservation,
    )
    .unwrap_or_else(|error| panic!("live install should complete: {error}"));

    assert_eq!(runtime.plugin_id(), 41);
    assert_eq!(runtime.args().slot(), 0);
    assert_eq!(runtime.lifecycle_phase(), PluginLifecyclePhase::Active);
    assert!(runtime._retained_control.is_some());
    let manifest = registered_resource_manifest()
        .unwrap_or_else(|| panic!("plugin resource manifest should be sealed before readiness"));
    let (device, inode, length, node_count, control_fd, _sender_wake_fd) =
        fixture.resource_manifest_basis();
    assert_eq!(manifest.schema_version, PLUGIN_RESOURCE_MANIFEST_VERSION);
    assert_eq!(
        manifest.struct_size,
        std::mem::size_of::<crate::QemuPluginResourceManifest>() as u32
    );
    assert_eq!(manifest.worker_mask, WORKER_REQUIRED);
    assert_eq!(manifest.process_generation, 1);
    assert_eq!(manifest.plugin_id, 41);
    assert_eq!(manifest.resource_mask, PLUGIN_RESOURCE_REQUIRED);
    assert_eq!(manifest.callback_mask, PLUGIN_CALLBACK_REQUIRED);
    assert_eq!(manifest.shmem_device, device);
    assert_eq!(manifest.shmem_inode, inode);
    assert_eq!(manifest.shmem_length, length);
    assert_eq!(manifest.slot_index, 0);
    assert_eq!(manifest.node_count, node_count);
    assert_eq!(manifest.control_fd, control_fd);
    assert_eq!(manifest.wake_fd, registered_wake_fd());
    let control_socket_cookie = hot_fork_control_socket_cookie(manifest.control_fd)
        .unwrap_or_else(|error| panic!("control socket identity should resolve: {error}"));
    let wake_eventfd_id = hot_fork_wake_eventfd_id(manifest.wake_fd)
        .unwrap_or_else(|error| panic!("wake eventfd identity should resolve: {error}"));
    let exact_endpoint_plan = crate::QemuPluginHotForkChildPlan {
        control_fd: manifest.control_fd,
        wake_fd: manifest.wake_fd,
        control_socket_cookie,
        wake_eventfd_id,
        ..crate::QemuPluginHotForkChildPlan::default()
    };
    assert!(hot_fork_child_endpoint_identity_matches(
        &exact_endpoint_plan
    ));
    assert!(!hot_fork_child_endpoint_identity_matches(
        &crate::QemuPluginHotForkChildPlan {
            control_socket_cookie: control_socket_cookie + 1,
            ..exact_endpoint_plan
        }
    ));
    assert!(!hot_fork_child_endpoint_identity_matches(
        &crate::QemuPluginHotForkChildPlan {
            wake_eventfd_id: wake_eventfd_id + 1,
            ..exact_endpoint_plan
        }
    ));
    assert_eq!(
        invoke_hot_fork_child_runtime(
            crate::QEMU_PLUGIN_HOT_FORK_CHILD_INITIALIZE,
            Some(&crate::QemuPluginHotForkChildPlan::default()),
        ),
        Err(-libc::EPROTO)
    );
    let child = invoke_hot_fork_child_runtime(crate::QEMU_PLUGIN_HOT_FORK_CHILD_QUERY, None)
        .unwrap_or_else(|status| panic!("hot-fork child query should succeed: {status}"));
    assert_eq!(
        child.schema_version,
        crate::QEMU_PLUGIN_HOT_FORK_CHILD_STATUS_VERSION
    );
    assert_eq!(
        child.struct_size,
        std::mem::size_of::<crate::QemuPluginHotForkChildStatus>() as u32
    );
    assert_eq!(
        std::mem::size_of::<crate::QemuPluginHotForkChildPlan>(),
        112
    );
    assert_eq!(
        std::mem::size_of::<crate::QemuPluginHotForkChildStatus>(),
        96
    );
    assert_eq!(
        std::mem::offset_of!(crate::QemuPluginHotForkChildPlan, template_generation),
        16
    );
    assert_eq!(
        std::mem::offset_of!(
            crate::QemuPluginHotForkChildPlan,
            plugin_endpoint_generation
        ),
        32
    );
    assert_eq!(
        std::mem::offset_of!(crate::QemuPluginHotForkChildPlan, control_socket_cookie),
        56
    );
    assert_eq!(
        std::mem::offset_of!(crate::QemuPluginHotForkChildPlan, shmem_device),
        72
    );
    assert_eq!(
        std::mem::offset_of!(crate::QemuPluginHotForkChildPlan, private_ring_fd),
        96
    );
    assert_eq!(
        std::mem::offset_of!(crate::QemuPluginHotForkChildStatus, template_generation),
        16
    );
    assert_eq!(
        std::mem::offset_of!(
            crate::QemuPluginHotForkChildStatus,
            plugin_endpoint_generation
        ),
        32
    );
    assert_eq!(
        std::mem::offset_of!(crate::QemuPluginHotForkChildStatus, control_socket_cookie),
        48
    );
    assert_eq!(
        std::mem::offset_of!(crate::QemuPluginHotForkChildStatus, worker_mask),
        64
    );
    assert_eq!(child.flags, 0);
    assert_eq!(child.phase, u32::from(CHILD_RUNTIME_TEMPLATE));
    assert_eq!(child.template_generation, 0);
    assert_eq!(child.private_ring_generation, 0);
    assert_eq!(child.plugin_endpoint_generation, 0);
    assert_eq!(child.plugin_barrier_generation, 0);
    assert_eq!(child.control_socket_cookie, 0);
    assert_eq!(child.wake_eventfd_id, 0);
    assert_eq!(child.worker_mask, WORKER_REQUIRED);
    assert_eq!(child.parked_worker_mask, 0);
    assert_eq!(child.pending_worker_mask, 0);
    assert_eq!(child.worker_operations_in_flight, 0);
    let held = invoke_hot_fork_barrier(crate::QEMU_PLUGIN_HOT_FORK_BARRIER_HOLD)
        .unwrap_or_else(|status| panic!("hot-fork barrier hold should succeed: {status}"));
    assert_eq!(
        held.schema_version,
        crate::QEMU_PLUGIN_HOT_FORK_BARRIER_STATUS_VERSION
    );
    assert_eq!(held.reserved, 0);
    assert_eq!(held.in_flight, 0);
    assert_eq!(
        held.flags,
        crate::QEMU_PLUGIN_HOT_FORK_BARRIER_FLAG_HELD
            | crate::QEMU_PLUGIN_HOT_FORK_BARRIER_FLAG_MAPPING_DONTFORK
    );
    assert!(held.ring_count > 0);
    assert_eq!(held.rings_held, held.ring_count);
    assert_eq!(held.ring_producers_in_flight, 0);
    assert_eq!(held.ring_consumers_in_flight, 0);
    assert_eq!(held.worker_mask, WORKER_REQUIRED);
    assert_eq!(held.parked_worker_mask, 0);
    assert_eq!(held.pending_worker_mask, 0);
    assert_eq!(held.worker_operations_in_flight, 0);
    let queried = invoke_hot_fork_barrier(crate::QEMU_PLUGIN_HOT_FORK_BARRIER_QUERY)
        .unwrap_or_else(|status| panic!("hot-fork barrier query should succeed: {status}"));
    assert_eq!(queried, held);
    let released = invoke_hot_fork_barrier(crate::QEMU_PLUGIN_HOT_FORK_BARRIER_RELEASE)
        .unwrap_or_else(|status| panic!("hot-fork barrier release should succeed: {status}"));
    assert_eq!(released.flags, 0);
    assert_eq!(released.in_flight, 0);
    assert_eq!(released.ring_count, held.ring_count);
    assert_eq!(released.rings_held, 0);
    assert_eq!(released.ring_producers_in_flight, 0);
    assert_eq!(released.ring_consumers_in_flight, 0);
    assert_eq!(released.worker_mask, WORKER_REQUIRED);
    assert_eq!(released.parked_worker_mask, 0);
    assert_eq!(released.pending_worker_mask, 0);
    assert_eq!(released.worker_operations_in_flight, 0);
    let teardown_handle = runtime
        ._callbacks
        .control_teardown_handle(0)
        .unwrap_or_else(|error| panic!("control teardown handle should validate: {error}"));
    assert!(!teardown_handle.quiescence.is_closed());
    (test_capabilities().request_shutdown)(0);
    let callback_state_address = runtime._callbacks.state_address_for_test();
    let runtime = (runtime,);
    assert_eq!(
        runtime.0._callbacks.state_address_for_test(),
        callback_state_address
    );
    assert_eq!(
        runtime.0._callbacks.registration_mask().bits(),
        OwnedCallbackRegistrationMask::BASE_REQUIRED
    );
    reservation.publish(runtime.0);
    assert!(active_runtime_is_published());
    join_host(host);
}

#[test]
fn live_install_seals_the_optional_fingerprint_worker() {
    let _runtime_state = isolate_runtime_state_for_test();
    reset_capability_call_counts();
    let fixture = LiveInstallFixture::new();
    let host = fixture.spawn_host(SETUP_ACK_STATUS_READY);
    let mut reservation =
        reserve_runtime().unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));
    let runtime = install_live_runtime(
        42,
        fixture.fingerprint_args(),
        test_state(),
        test_capabilities(),
        &SuccessfulCallbackRegistrar,
        &mut reservation,
    )
    .unwrap_or_else(|error| panic!("fingerprint runtime should complete: {error}"));

    let manifest = registered_resource_manifest()
        .unwrap_or_else(|| panic!("fingerprint resource manifest should be sealed"));
    assert_eq!(manifest.worker_mask, WORKER_REQUIRED | WORKER_FINGERPRINT);
    assert_eq!(
        manifest.resource_mask & PLUGIN_RESOURCE_FINGERPRINT,
        PLUGIN_RESOURCE_FINGERPRINT
    );
    let held = invoke_hot_fork_barrier(crate::QEMU_PLUGIN_HOT_FORK_BARRIER_HOLD)
        .unwrap_or_else(|status| panic!("fingerprint worker hold should succeed: {status}"));
    assert_eq!(held.worker_mask, WORKER_REQUIRED | WORKER_FINGERPRINT);
    assert_eq!(held.parked_worker_mask, 0);
    assert_eq!(held.pending_worker_mask, 0);
    assert_eq!(held.worker_operations_in_flight, 0);

    drop(runtime);
    host.join()
        .unwrap_or_else(|_panic| panic!("fingerprint setup host should join"));
}

#[test]
fn live_vcpu_time_slice_registers_idle_resume_and_normal_loop_completion() {
    let _runtime_state = isolate_runtime_state_for_test();
    *REGISTERED_LIVE_VCPU_TIME_CALLBACKS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    LIVE_IDLE_RESUME_REGISTRATIONS.store(0, Ordering::SeqCst);
    LIVE_TIME_ADVANCE_COMPLETION_REGISTRATIONS.store(0, Ordering::SeqCst);
    LIVE_NETWORK_TX_REGISTRATIONS.store(0, Ordering::SeqCst);
    let fixture = LiveInstallFixture::new();
    let host = fixture.spawn_host(SETUP_ACK_STATUS_READY);
    let execution_model = crate::QemuPluginExecutionModel::validate(
        1,
        crate::QemuTcgThreading::SingleThreadedRoundRobin,
    )
    .unwrap_or_else(|error| panic!("test execution model should validate: {error}"));
    let state = test_state();
    let registrar = LiveVcpuTimeThenTestCompletionRegistrar {
        live: LiveVcpuTimeCallbackRegistrar::new(
            51,
            execution_model,
            crate::QemuPluginTargetArchitecture::X86_64,
            LiveVcpuTimeCallbackCapabilities {
                icount_raw: test_icount_raw,
                force_vcpu_exit: test_force_vcpu_exit,
                request_vmstop: test_request_vmstop,
                inject_preemption: Some(test_inject_preemption),
                clock_deadline_ns: Some(test_deadline),
                advance_time_ns: Some(test_direct_advance),
                register_vcpu_init: Some(capture_vcpu_init_registration),
                register_vcpu_idle_resume: Some(capture_vcpu_idle_resume_registration),
                register_control_boundary: Some(capture_control_boundary_registration),
                register_sim_shmem_dispatch: Some(capture_sim_dispatch_registration),
                register_time_advance_cb: Some(capture_time_advance_completion_registration),
                register_net_tx: Some(capture_network_tx_registration),
                net_inject: Some(live_network_inject_ok),
                register_block: Some(capture_block_registration),
                register_block_event: Some(capture_block_event_registration),
                register_block_wait: Some(capture_block_wait_registration),
                register_ninep: Some(capture_ninep_registration),
                register_accelerator: Some(capture_accelerator_registration),
                fault_commands: crate::fault_command::QemuFaultCommandApis::test_stub(),
                request_shutdown: test_request_shutdown,
            },
        ),
    };
    let mut reservation =
        reserve_runtime().unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));
    let runtime = install_live_runtime(
        51,
        fixture.args(),
        state,
        test_capabilities(),
        &registrar,
        &mut reservation,
    )
    .unwrap_or_else(|error| panic!("live callback slice should install: {error}"));

    let callbacks = REGISTERED_LIVE_VCPU_TIME_CALLBACKS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .unwrap_or_else(|| panic!("live callback registrations should be captured"));
    let userdata = callbacks.userdata as *mut std::ffi::c_void;
    assert_ne!(callbacks.userdata, 0);
    assert_eq!((callbacks.ceiling)(userdata), 1);
    (callbacks.publish)(1, userdata);
    assert_eq!(LIVE_IDLE_RESUME_REGISTRATIONS.load(Ordering::SeqCst), 1);
    assert_eq!(
        LIVE_TIME_ADVANCE_COMPLETION_REGISTRATIONS.load(Ordering::SeqCst),
        1
    );
    assert_eq!(LIVE_NETWORK_TX_REGISTRATIONS.load(Ordering::SeqCst), 1);
    assert_eq!(
        runtime._callbacks.registration_mask(),
        OwnedCallbackRegistrationMask::required_for(&fixture.args())
    );

    drop(runtime);
    join_host(host);
}

#[test]
fn late_callback_failure_sends_nonzero_setup_ack_then_invokes_fatal_policy() {
    let _runtime_state = isolate_runtime_state_for_test();
    let fixture = LiveInstallFixture::new();
    let host = fixture.spawn_host(SETUP_ACK_STATUS_SETUP_FAILED);
    let mut reservation =
        reserve_runtime().unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));
    let error = install_expecting_post_registration_fatal(
        42,
        &fixture,
        test_capabilities(),
        &LateFailingCallbackRegistrar,
        &mut reservation,
    );

    assert!(matches!(
        error,
        PluginRuntimeInstallError::OwnedCallbacks { .. }
    ));
    join_host(host);
}

#[test]
fn partial_callback_failure_retains_the_pinned_userdata_owner() {
    let _runtime_state = isolate_runtime_state_for_test();
    let fixture = LiveInstallFixture::new();
    let host = fixture.spawn_host(SETUP_ACK_STATUS_SETUP_FAILED);
    let registrar = PartiallyFailingCallbackRegistrar::new();
    let mut reservation =
        reserve_runtime().unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));
    let error = install_expecting_post_registration_fatal(
        44,
        &fixture,
        test_capabilities(),
        &registrar,
        &mut reservation,
    );

    assert!(matches!(
        error,
        PluginRuntimeInstallError::OwnedCallbacks { .. }
    ));
    assert_ne!(registrar.state_address.get(), 0);
    // SAFETY: `F_GETFD` only observes whether the registrar-recorded
    // descriptor remains owned by the intentionally leaked pinned state.
    assert!(unsafe { libc::fcntl(registrar.wake_fd.get(), libc::F_GETFD) } >= 0);
    join_host(host);
}

#[test]
fn partial_callback_panic_retains_userdata_and_sends_one_failure_ack() {
    let _runtime_state = isolate_runtime_state_for_test();
    let fixture = LiveInstallFixture::new();
    let host = fixture.spawn_host(SETUP_ACK_STATUS_SETUP_FAILED);
    let registrar = PartiallyPanickingCallbackRegistrar::new();
    let mut reservation =
        reserve_runtime().unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));
    let error = install_expecting_post_registration_fatal(
        45,
        &fixture,
        test_capabilities(),
        &registrar,
        &mut reservation,
    );

    assert!(matches!(
        error,
        PluginRuntimeInstallError::CallbackRegistrationPanicked
    ));
    assert_ne!(registrar.state_address.get(), 0);
    // SAFETY: `F_GETFD` observes that the panic path retained the pinned
    // owner before invoking the fatal policy.
    assert!(unsafe { libc::fcntl(registrar.wake_fd.get(), libc::F_GETFD) } >= 0);
    join_host(host);
}

#[test]
fn callback_capability_failure_is_fatal_after_registration_begins() {
    let _runtime_state = isolate_runtime_state_for_test();
    let fixture = LiveInstallFixture::new();
    let host = fixture.spawn_host(SETUP_ACK_STATUS_SETUP_FAILED);
    let mut capabilities = test_capabilities();
    capabilities.clock_deadline_ns = None;
    let mut reservation =
        reserve_runtime().unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));

    let error = install_expecting_post_registration_fatal(
        46,
        &fixture,
        capabilities,
        &SuccessfulCallbackRegistrar,
        &mut reservation,
    );

    assert!(matches!(
        error,
        PluginRuntimeInstallError::Registration { .. }
    ));
    join_host(host);
}

extern "C" fn reject_hot_fork_barrier_registration(
    _plugin_id: QemuPluginId,
    _callback: Option<crate::QemuPluginHotForkBarrierCbFn>,
    _userdata: *mut std::ffi::c_void,
) -> i32 {
    -libc::EBUSY
}

extern "C" fn reject_hot_fork_child_runtime_registration(
    _plugin_id: QemuPluginId,
    _callback: Option<crate::QemuPluginHotForkChildRuntimeCbFn>,
    _userdata: *mut std::ffi::c_void,
) -> i32 {
    -libc::EPROTONOSUPPORT
}

#[test]
fn hot_fork_barrier_registration_failure_is_fatal_after_callbacks_exist() {
    let _runtime_state = isolate_runtime_state_for_test();
    let fixture = LiveInstallFixture::new();
    let host = fixture.spawn_host(SETUP_ACK_STATUS_SETUP_FAILED);
    let mut capabilities = test_capabilities();
    capabilities.register_hot_fork_barrier = reject_hot_fork_barrier_registration;
    let mut reservation =
        reserve_runtime().unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));

    let error = install_expecting_post_registration_fatal(
        48,
        &fixture,
        capabilities,
        &SuccessfulCallbackRegistrar,
        &mut reservation,
    );

    assert!(matches!(
        error,
        PluginRuntimeInstallError::HotForkBarrierRejected { status }
            if status == -libc::EBUSY
    ));
    join_host(host);
}

#[test]
fn hot_fork_child_runtime_registration_failure_is_fatal_after_callbacks_exist() {
    let _runtime_state = isolate_runtime_state_for_test();
    let fixture = LiveInstallFixture::new();
    let host = fixture.spawn_host(SETUP_ACK_STATUS_SETUP_FAILED);
    let mut capabilities = test_capabilities();
    capabilities.register_hot_fork_child_runtime = reject_hot_fork_child_runtime_registration;
    let mut reservation =
        reserve_runtime().unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));

    let error = install_expecting_post_registration_fatal(
        49,
        &fixture,
        capabilities,
        &SuccessfulCallbackRegistrar,
        &mut reservation,
    );

    assert!(matches!(
        error,
        PluginRuntimeInstallError::HotForkChildRuntimeRejected { status }
            if status == -libc::EPROTONOSUPPORT
    ));
    join_host(host);
}

#[test]
fn finalize_panic_is_fatal_without_dropping_userdata_or_sending_a_second_ack() {
    let _runtime_state = isolate_runtime_state_for_test();
    let _panic_stage = TestPostRegistrationPanicGuard::install(PostRegistrationStage::Finalize);
    let fixture = LiveInstallFixture::new();
    let host = fixture.spawn_host(SETUP_ACK_STATUS_READY);
    let registrar = RecordingSuccessfulCallbackRegistrar::new();
    let mut reservation =
        reserve_runtime().unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));

    let error = install_expecting_post_registration_fatal(
        47,
        &fixture,
        test_capabilities(),
        &registrar,
        &mut reservation,
    );

    assert!(matches!(
        error,
        PluginRuntimeInstallError::PostRegistrationPanicked { stage: "Finalize" }
    ));
    assert_ne!(registrar.state_address.get(), 0);
    // SAFETY: `F_GETFD` observes that the whole post-registration unwind
    // scope retained the pinned owner before invoking the fatal policy.
    assert!(unsafe { libc::fcntl(registrar.wake_fd.get(), libc::F_GETFD) } >= 0);
    join_host(host);
}

#[test]
fn enabled_whitebox_without_process_symbols_fails_before_control_or_qemu_side_effects() {
    let _runtime_state = isolate_runtime_state_for_test();
    reset_capability_call_counts();
    let registrations_before = live_registration_counts();
    let fixture = LiveInstallFixture::new();
    let mut reservation =
        reserve_runtime().unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));
    let state = test_state();
    let capabilities = test_capabilities();
    let callback_registrar = FailClosedOwnedCallbackRegistrar::production(
        43,
        state.lifecycle_core().execution_model(),
        crate::QemuPluginTargetArchitecture::X86_64,
        &capabilities,
    );
    let error = install_live_runtime(
        43,
        fixture.whitebox_args(),
        state,
        capabilities,
        &callback_registrar,
        &mut reservation,
    )
    .err()
    .unwrap_or_else(|| panic!("missing white-box ABI must fail preflight"));

    assert!(matches!(
        error,
        PluginRuntimeInstallError::OwnedCallbacks {
            source: OwnedCallbackRegistrationError::LiveVcpuTime {
                source: LiveVcpuTimeCallbackError::WhiteboxCallback { .. },
            },
        }
    ));
    fixture.assert_control_silent();
    assert_eq!(live_registration_counts(), registrations_before);
    assert_eq!(time_control_request_count(), 0);
    assert_eq!(wake_registration_count(), 0);
    drop(reservation);
    assert!(reserve_runtime().is_ok());
}

#[test]
fn production_registrar_installs_default_block_ninep_and_network_families() {
    let _runtime_state = isolate_runtime_state_for_test();
    *REGISTERED_LIVE_VCPU_TIME_CALLBACKS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    let registrations_before = live_registration_counts();
    let fixture = LiveInstallFixture::new();
    let host = fixture.spawn_host(SETUP_ACK_STATUS_READY);
    let state = test_state();
    let mut capabilities = test_capabilities();
    capabilities.register_vcpu_init = Some(capture_vcpu_init_registration);
    capabilities.register_vcpu_idle_resume = Some(capture_vcpu_idle_resume_registration);
    capabilities.register_sim_shmem_dispatch = Some(capture_sim_dispatch_registration);
    capabilities.register_time_advance_cb = Some(capture_time_advance_completion_registration);
    capabilities.register_net_tx = Some(capture_network_tx_registration);
    capabilities.net_inject = Some(live_network_inject_ok);
    capabilities.register_block = Some(capture_block_registration);
    capabilities.register_block_wait = Some(capture_block_wait_registration);
    capabilities.register_ninep = Some(capture_ninep_registration);
    let callback_registrar = FailClosedOwnedCallbackRegistrar::production(
        54,
        state.lifecycle_core().execution_model(),
        crate::QemuPluginTargetArchitecture::X86_64,
        &capabilities,
    );
    let mut reservation =
        reserve_runtime().unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));

    let runtime = install_live_runtime(
        54,
        fixture.args(),
        state,
        capabilities,
        &callback_registrar,
        &mut reservation,
    )
    .unwrap_or_else(|error| panic!("default production callbacks should install: {error}"));

    assert_eq!(
        runtime._callbacks.registration_mask(),
        OwnedCallbackRegistrationMask::base_required()
    );
    let registrations_after = live_registration_counts();
    for (before, after) in registrations_before.into_iter().zip(registrations_after) {
        assert_eq!(after, before + 1);
    }
    drop(runtime);
    join_host(host);
}

#[test]
fn missing_live_vcpu_time_capability_fails_preflight_before_control_io() {
    let _runtime_state = isolate_runtime_state_for_test();
    reset_capability_call_counts();
    let fixture = LiveInstallFixture::new();
    let state = test_state();
    let mut capabilities = test_capabilities();
    capabilities.register_sim_shmem_dispatch = None;
    let callback_registrar = FailClosedOwnedCallbackRegistrar::production(
        52,
        state.lifecycle_core().execution_model(),
        crate::QemuPluginTargetArchitecture::X86_64,
        &capabilities,
    );
    let mut reservation =
        reserve_runtime().unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));

    let error = install_live_runtime(
        52,
        fixture.args(),
        state,
        capabilities,
        &callback_registrar,
        &mut reservation,
    )
    .err()
    .unwrap_or_else(|| panic!("missing live callback capability must fail preflight"));

    assert!(matches!(
        error,
        PluginRuntimeInstallError::OwnedCallbacks {
            source: OwnedCallbackRegistrationError::LiveVcpuTime {
                source: LiveVcpuTimeCallbackError::CapabilityUnavailable {
                    symbol: crate::QEMU_PLUGIN_REGISTER_SIM_SHMEM_DISPATCH_CB_SYMBOL,
                },
            },
        }
    ));
    fixture.assert_control_silent();
    assert_eq!(time_control_request_count(), 0);
    assert_eq!(wake_registration_count(), 0);
}

#[test]
fn missing_live_network_capability_fails_preflight_before_control_io() {
    let _runtime_state = isolate_runtime_state_for_test();
    reset_capability_call_counts();
    let fixture = LiveInstallFixture::new();
    let state = test_state();
    let mut capabilities = test_capabilities();
    capabilities.net_inject = None;
    let callback_registrar = FailClosedOwnedCallbackRegistrar::production(
        53,
        state.lifecycle_core().execution_model(),
        crate::QemuPluginTargetArchitecture::X86_64,
        &capabilities,
    );
    let mut reservation =
        reserve_runtime().unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));

    let error = install_live_runtime(
        53,
        fixture.args(),
        state,
        capabilities,
        &callback_registrar,
        &mut reservation,
    )
    .err()
    .unwrap_or_else(|| panic!("missing live network capability must fail preflight"));

    assert!(matches!(
        error,
        PluginRuntimeInstallError::OwnedCallbacks {
            source: OwnedCallbackRegistrationError::LiveVcpuTime {
                source: LiveVcpuTimeCallbackError::NetworkRx {
                    source: crate::NetworkRxError::CapabilityUnavailable {
                        symbol: crate::QEMU_PLUGIN_NET_INJECT_SYMBOL,
                    },
                },
            },
        }
    ));
    fixture.assert_control_silent();
    assert_eq!(time_control_request_count(), 0);
    assert_eq!(wake_registration_count(), 0);
}

#[test]
fn missing_live_ninep_capability_prevents_every_qemu_registration() {
    let _runtime_state = isolate_runtime_state_for_test();
    reset_capability_call_counts();
    let registrations_before = live_registration_counts();
    let fixture = LiveInstallFixture::new();
    let state = test_state();
    let mut capabilities = test_capabilities();
    capabilities.register_ninep = None;
    let callback_registrar = FailClosedOwnedCallbackRegistrar::production(
        55,
        state.lifecycle_core().execution_model(),
        crate::QemuPluginTargetArchitecture::X86_64,
        &capabilities,
    );
    let mut reservation =
        reserve_runtime().unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));

    let error = install_live_runtime(
        55,
        fixture.args(),
        state,
        capabilities,
        &callback_registrar,
        &mut reservation,
    )
    .err()
    .unwrap_or_else(|| panic!("missing live 9p capability must fail preflight"));

    assert!(matches!(
        error,
        PluginRuntimeInstallError::OwnedCallbacks {
            source: OwnedCallbackRegistrationError::LiveVcpuTime {
                source: LiveVcpuTimeCallbackError::CapabilityUnavailable {
                    symbol: crate::QEMU_PLUGIN_REGISTER_9P_CB_SYMBOL,
                },
            },
        }
    ));
    fixture.assert_control_silent();
    assert_eq!(live_registration_counts(), registrations_before);
    assert_eq!(time_control_request_count(), 0);
    assert_eq!(wake_registration_count(), 0);
}

#[test]
fn handshake_failure_marks_the_singleton_failed_before_second_install_attempt() {
    let _runtime_state = isolate_runtime_state_for_test();
    let fixture = LiveInstallFixture::new();
    let host = fixture.spawn_mismatched_handshake_host();
    let mut reservation =
        reserve_runtime().unwrap_or_else(|error| panic!("test runtime should reserve: {error}"));

    let error = install_live_runtime(
        48,
        fixture.args(),
        test_state(),
        test_capabilities(),
        &SuccessfulCallbackRegistrar,
        &mut reservation,
    )
    .err()
    .unwrap_or_else(|| panic!("mismatched handshake must fail install"));

    assert!(matches!(
        error,
        PluginRuntimeInstallError::Registration { .. }
    ));
    drop(reservation);
    assert_eq!(RUNTIME_STATE.load(Ordering::Acquire), RUNTIME_FAILED);
    assert!(matches!(
        reserve_runtime(),
        Err(PluginRuntimeInstallError::RuntimeAlreadyReserved)
    ));
    join_host(host);
}
