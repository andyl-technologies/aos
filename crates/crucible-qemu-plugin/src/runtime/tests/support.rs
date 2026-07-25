//! Socket, shared-memory, and QEMU-capability fixtures for live install tests.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

use crucible_protocol::{
    CONTROL_PROTOCOL_VERSION, HostHandshakeConfig, PluginMsg, SetupDescriptorFds,
    control_decode_plugin_msg, host_accept_handshake, read_control_frame,
    send_setup_with_descriptors,
};
use crucible_shmem::{
    ABI_VERSION, DEFAULT_QUEUE_CAPACITY, RegionAllocation, RegionConfig, authorize_advance_ceiling,
};

use crate::{PluginArgs, PluginStatePartition};

use super::super::LiveInstallCapabilities;

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);
static TIME_CONTROL_REQUESTS: AtomicU64 = AtomicU64::new(0);
static WAKE_REGISTRATIONS: AtomicU64 = AtomicU64::new(0);
static TIME_CONTROL_TOKEN: u8 = 1;

pub(super) struct LiveInstallFixture {
    plugin: UnixStream,
    host: UnixStream,
    region_file: File,
    wake_file: File,
    _wake_peer: Option<File>,
    region_len: u64,
    node_count: u32,
    path: PathBuf,
}

impl LiveInstallFixture {
    pub(super) fn new() -> Self {
        let (host, plugin) = UnixStream::pair()
            .unwrap_or_else(|error| panic!("control socket pair should open: {error}"));
        let allocation =
            RegionAllocation::new_model(RegionConfig::new(1, DEFAULT_QUEUE_CAPACITY, 0))
                .unwrap_or_else(|error| panic!("test region should allocate: {error}"));
        let node_count = allocation.layout().node_count;
        let slot = allocation
            .node_slot(0)
            .unwrap_or_else(|| panic!("test VM slot should exist"));
        let ceiling = authorize_advance_ceiling(0, 1, None)
            .unwrap_or_else(|error| panic!("boot ceiling should authorize: {error}"));
        slot.publish_scheduler_ceiling(ceiling)
            .unwrap_or_else(|error| panic!("boot ceiling should publish: {error}"));
        let bytes = allocation
            .setup_region_bytes()
            .unwrap_or_else(|error| panic!("test region should serialize: {error}"));
        let path = temp_path();
        let mut region_file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap_or_else(|error| panic!("test region file should open: {error}"));
        region_file
            .write_all(&bytes)
            .unwrap_or_else(|error| panic!("test region should write: {error}"));
        region_file
            .flush()
            .unwrap_or_else(|error| panic!("test region should flush: {error}"));
        let (wake_file, wake_peer) = wake_counter();
        Self {
            plugin,
            host,
            region_file,
            wake_file,
            _wake_peer: wake_peer,
            region_len: bytes.len() as u64,
            node_count,
            path,
        }
    }

    pub(super) fn args(&self) -> PluginArgs {
        PluginArgs::parse(&format!("simfd={},slot=0", self.plugin.as_raw_fd()))
            .unwrap_or_else(|error| panic!("test plugin args should parse: {error}"))
    }

    pub(super) fn coverage_args(&self) -> PluginArgs {
        PluginArgs::parse(&format!(
            "simfd={},slot=0,coverage=on",
            self.plugin.as_raw_fd()
        ))
        .unwrap_or_else(|error| panic!("test coverage plugin args should parse: {error}"))
    }

    pub(super) fn whitebox_args(&self) -> PluginArgs {
        PluginArgs::parse(&format!(
            "simfd={},slot=0,whitebox=on,whitebox_setup=x86-port-00e7-unclaimed-v1",
            self.plugin.as_raw_fd()
        ))
        .unwrap_or_else(|error| panic!("test white-box plugin args should parse: {error}"))
    }

    pub(super) fn spawn_host(&self, expected_status: u8) -> thread::JoinHandle<()> {
        let mut host = self
            .host
            .try_clone()
            .unwrap_or_else(|error| panic!("host stream should clone: {error}"));
        let region = self
            .region_file
            .try_clone()
            .unwrap_or_else(|error| panic!("region file should clone: {error}"));
        let wake = self
            .wake_file
            .try_clone()
            .unwrap_or_else(|error| panic!("wake file should clone: {error}"));
        let region_len = self.region_len;
        let node_count = self.node_count;
        thread::spawn(move || {
            host_accept_handshake(
                &mut host,
                HostHandshakeConfig {
                    proto_version: CONTROL_PROTOCOL_VERSION,
                    abi_version: ABI_VERSION,
                    slot_index: 0,
                    node_count,
                },
            )
            .unwrap_or_else(|error| panic!("host handshake should complete: {error}"));
            send_setup_with_descriptors(
                host.as_raw_fd(),
                region_len,
                SetupDescriptorFds {
                    shmem_fd: region.as_raw_fd(),
                    wake_fd: wake.as_raw_fd(),
                },
            )
            .unwrap_or_else(|error| panic!("host setup should send: {error}"));
            let frame = read_control_frame(&mut host)
                .unwrap_or_else(|error| panic!("setup ack should read: {error}"));
            let PluginMsg::SetupAck { status } = control_decode_plugin_msg(&frame)
                .unwrap_or_else(|error| panic!("setup ack should decode: {error}"))
            else {
                panic!("plugin should return setup acknowledgement");
            };
            assert_eq!(status, expected_status);
            host.set_nonblocking(true)
                .unwrap_or_else(|error| panic!("host stream should become nonblocking: {error}"));
            let mut extra = [0_u8; 1];
            match host.read(&mut extra) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Ok(0) => {}
                Ok(count) => panic!("plugin sent {count} unexpected bytes after SetupAck"),
                Err(error) => panic!("checking for a duplicate SetupAck failed: {error}"),
            }
        })
    }

    pub(super) fn spawn_mismatched_handshake_host(&self) -> thread::JoinHandle<()> {
        let mut host = self
            .host
            .try_clone()
            .unwrap_or_else(|error| panic!("host stream should clone: {error}"));
        thread::spawn(move || {
            host_accept_handshake(
                &mut host,
                HostHandshakeConfig {
                    proto_version: CONTROL_PROTOCOL_VERSION,
                    abi_version: ABI_VERSION,
                    slot_index: 1,
                    node_count: 2,
                },
            )
            .unwrap_or_else(|error| panic!("mismatched host handshake should complete: {error}"));
        })
    }

    pub(super) fn assert_control_silent(&self) {
        let mut host = self
            .host
            .try_clone()
            .unwrap_or_else(|error| panic!("host stream should clone: {error}"));
        host.set_nonblocking(true)
            .unwrap_or_else(|error| panic!("host stream should become nonblocking: {error}"));
        let mut byte = [0_u8; 1];
        match host.read(&mut byte) {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok(0) => panic!("plugin control endpoint closed during reversible preflight"),
            Ok(count) => panic!("plugin wrote {count} unexpected preflight bytes"),
            Err(error) => panic!("checking preflight control silence failed: {error}"),
        }
    }
}

impl Drop for LiveInstallFixture {
    fn drop(&mut self) {
        let _result = std::fs::remove_file(&self.path);
    }
}

pub(super) fn test_state() -> PluginStatePartition {
    let model = crate::QemuPluginExecutionModel::validate(
        1,
        crate::QemuTcgThreading::SingleThreadedRoundRobin,
    )
    .unwrap_or_else(|error| panic!("test execution model should validate: {error}"));
    crate::install_required_runtime_api_scaffold(
        model,
        Some(test_deadline),
        Some(test_direct_advance),
        Some(test_inject_preemption),
        Some(test_read_vcpu_regs),
        Some(test_rr_cursor),
        Some(test_icount_raw),
        Some(test_force_vcpu_exit),
        Some(test_register_wake_fd),
        Some(test_register_tcg_exec_cb),
    )
    .unwrap_or_else(|error| panic!("test runtime capabilities should validate: {error}"))
}

pub(super) const fn test_capabilities() -> LiveInstallCapabilities {
    LiveInstallCapabilities {
        icount_raw: test_icount_raw,
        inject_preemption: Some(test_inject_preemption),
        request_time_control: Some(test_request_time_control),
        clock_deadline_ns: Some(test_deadline),
        advance_time_ns: Some(test_direct_advance),
        register_time_advance_cb: Some(test_register_time_advance_cb),
        register_wake_fd: test_register_wake_fd,
        request_shutdown: test_request_shutdown,
        basic_block_coverage: None,
        register_vcpu_init: Some(test_register_vcpu_init),
        register_vcpu_idle_resume: Some(test_register_vcpu_idle_resume),
        register_sim_shmem_dispatch: Some(test_register_sim_shmem_dispatch),
        register_net_tx: Some(test_register_net_tx),
        net_send: Some(test_net_send),
        net_flush: Some(test_net_flush),
        register_block: Some(test_register_block),
        register_block_wait: Some(test_register_block_wait),
        register_ninep: Some(test_register_ninep),
    }
}

pub(super) fn reset_capability_call_counts() {
    TIME_CONTROL_REQUESTS.store(0, Ordering::SeqCst);
    WAKE_REGISTRATIONS.store(0, Ordering::SeqCst);
}

pub(super) fn time_control_request_count() -> u64 {
    TIME_CONTROL_REQUESTS.load(Ordering::SeqCst)
}

pub(super) fn wake_registration_count() -> u64 {
    WAKE_REGISTRATIONS.load(Ordering::SeqCst)
}

pub(super) fn join_host(host: thread::JoinHandle<()>) {
    if let Err(payload) = host.join() {
        std::panic::resume_unwind(payload);
    }
}

fn temp_path() -> PathBuf {
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "crucible-plugin-runtime-{}-{id}",
        std::process::id()
    ))
}

#[cfg(target_os = "linux")]
fn wake_counter() -> (File, Option<File>) {
    // SAFETY: `eventfd` has no pointer arguments and returns a new descriptor.
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
    if fd < 0 {
        panic!(
            "test wake eventfd should open: {}",
            std::io::Error::last_os_error()
        );
    }
    // SAFETY: the successful eventfd result is uniquely owned here.
    (unsafe { File::from_raw_fd(fd) }, None)
}

#[cfg(not(target_os = "linux"))]
fn wake_counter() -> (File, Option<File>) {
    let mut fds = [-1; 2];
    // SAFETY: `fds` has room for both descriptors returned by `pipe`.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        panic!(
            "test wake pipe should open: {}",
            std::io::Error::last_os_error()
        );
    }
    // SAFETY: successful `pipe` returned distinct uniquely owned descriptors.
    let read_end = unsafe { File::from_raw_fd(fds[0]) };
    // SAFETY: successful `pipe` returned distinct uniquely owned descriptors.
    let write_end = unsafe { File::from_raw_fd(fds[1]) };
    (read_end, Some(write_end))
}

extern "C" fn test_request_time_control() -> *const std::ffi::c_void {
    TIME_CONTROL_REQUESTS.fetch_add(1, Ordering::SeqCst);
    (&TIME_CONTROL_TOKEN as *const u8).cast()
}

pub(super) extern "C" fn test_deadline() -> i64 {
    100
}

pub(super) extern "C" fn test_direct_advance(_target: i64) -> std::os::raw::c_int {
    0
}

extern "C" fn test_register_time_advance_cb(
    _callback: Option<crate::QemuTimeAdvanceCompletionCbFn>,
    _userdata: *mut std::os::raw::c_void,
) -> std::os::raw::c_int {
    0
}

pub(super) extern "C" fn test_request_shutdown(_failure: std::os::raw::c_int) {}

pub(super) extern "C" fn test_inject_preemption(
    _at: u64,
    _deadline: u64,
    _ceiling: u64,
    _kind: u32,
    _arg0: u32,
    _arg1: u32,
    _arg2: u32,
) -> i32 {
    0
}

extern "C" fn test_read_vcpu_regs(
    _vcpu: u32,
    _bytes: *mut u8,
    _capacity: usize,
    _len: *mut usize,
    _retired: *mut u64,
) -> i32 {
    0
}

extern "C" fn test_rr_cursor(_cursor: *mut crate::QemuRoundRobinCursor) -> i32 {
    0
}

pub(super) extern "C" fn test_icount_raw() -> u64 {
    0
}

extern "C" fn test_force_vcpu_exit() {}

extern "C" fn test_register_wake_fd(_fd: i32) -> i32 {
    WAKE_REGISTRATIONS.fetch_add(1, Ordering::SeqCst);
    0
}

extern "C" fn test_register_tcg_exec_cb(
    _callback: Option<crate::QemuTcgExecCbFn>,
    _userdata: *mut std::ffi::c_void,
) {
}

extern "C" fn test_register_vcpu_init(
    _plugin_id: crate::QemuPluginId,
    _callback: crate::QemuVcpuSimpleCbFn,
) {
}

extern "C" fn test_register_vcpu_idle_resume(
    _idle_callback: Option<crate::QemuVcpuIdleResumeCbFn>,
    _resume_callback: Option<crate::QemuVcpuIdleResumeCbFn>,
    _userdata: *mut std::ffi::c_void,
) {
}

extern "C" fn test_register_sim_shmem_dispatch(
    _publish_callback: Option<crate::QemuSimShmemPublishIcountCbFn>,
    _ceiling_callback: Option<crate::QemuSimShmemMaxAdvanceIcountCbFn>,
    _userdata: *mut std::ffi::c_void,
) {
}

extern "C" fn test_register_net_tx(
    _callback: Option<crate::QemuNetTxCbFn>,
    _userdata: *mut std::ffi::c_void,
) {
}

extern "C" fn test_net_send(_payload: *const u8, _payload_len: usize) -> std::os::raw::c_int {
    0
}

extern "C" fn test_net_flush() -> std::os::raw::c_int {
    0
}

extern "C" fn test_register_block(
    _submit: Option<crate::QemuBlkSubmitCbFn>,
    _poll: Option<crate::QemuBlkPollCbFn>,
    _userdata: *mut std::ffi::c_void,
) {
}

extern "C" fn test_register_block_wait(
    _wait: Option<crate::QemuBlkWaitCbFn>,
    _userdata: *mut std::ffi::c_void,
) {
}

extern "C" fn test_register_ninep(
    _burst_start: Option<crate::QemuNinePBurstCbFn>,
    _submit: Option<crate::QemuNinePSubmitCbFn>,
    _poll: Option<crate::QemuNinePPollCbFn>,
    _burst_done: Option<crate::QemuNinePBurstCbFn>,
    _userdata: *mut std::ffi::c_void,
) {
}
