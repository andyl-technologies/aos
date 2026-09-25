//! QEMU plugin ABI installation and callback ownership.
//!
//! QEMU loads this crate as a `cdylib` and looks up the exported install
//! symbol:
//!
//! ```text
//! qemu_plugin_install(id, info, argc, argv)
//! ```
//!
//! This module keeps that raw ABI boundary narrow, validates the execution model,
//! and admits the complete set of required runtime exports before registration.
//! Under the required single-threaded round-robin TCG model, QEMU serializes
//! registered vCPU-thread callbacks so plugin callback state is not accessed
//! concurrently.

use std::ffi::CStr;
#[cfg(unix)]
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::raw::{c_char, c_int, c_uint, c_void};
#[cfg(unix)]
use std::os::unix::net::UnixStream;

use crate::{
    ExactDeadlineError, ExactDeadlineReader, QemuAdvanceTimeTicksFn, QemuArmVirtualTimerWitnessFn,
    QemuClockDeadlineFn, QemuInjectPreemptionFn, QemuQueryVirtualTimerWitnessFn,
    QemuReadRrCursorFn, QemuReadVcpuRegsFn, QemuRegisterTimeAdvanceCbFn, QemuRequestTimeControlFn,
    QueuedIdleAdvance, QueuedIdleAdvanceError,
};
use crate::{PLUGIN_ARG_SIMFD, PluginArgs, PluginArgsParseError};
use crate::{PluginPreemptionInjector, PreemptionError};
use crate::{PluginVcpuIntrospector, VcpuIntrospectionError};

/// QEMU plugin identifier type passed to the install entry point.
pub type QemuPluginId = u64;

#[repr(C)]
#[derive(Clone, Copy)]
struct QemuPluginApiVersionRange {
    min: c_int,
    cur: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct QemuPluginSystemInfo {
    smp_vcpus: c_int,
    max_vcpus: c_int,
}

/// Minimal QEMU `qemu_info_t` layout consumed by the install boundary.
///
/// This mirrors the prefix and single `system` union member installed by AOS
/// QEMU 11.1.1. The install boundary copies only scalar ABI-version and vCPU-count
/// fields while QEMU guarantees the pointer is live during `qemu_plugin_install`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct QemuPluginInfo {
    target_name: *const c_char,
    version: QemuPluginApiVersionRange,
    system_emulation: bool,
    system: QemuPluginSystemInfo,
}

/// Guest instruction-set architecture reported by QEMU at plugin install.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QemuPluginTargetArchitecture {
    /// The `x86_64-softmmu` target.
    X86_64,
    /// The `aarch64-softmmu` target.
    Aarch64,
}

/// QEMU install return value meaning the plugin loaded successfully.
pub const QEMU_PLUGIN_INSTALL_OK: c_int = 0;
/// QEMU install return value meaning plugin registration failed.
pub const QEMU_PLUGIN_INSTALL_ERROR: c_int = -1;
/// QEMU plugin API version exported by AOS QEMU 11.1.1.
pub const QEMU_PLUGIN_API_VERSION: c_int = 7;
/// QEMU plugin API symbol used to read raw instruction count.
pub const QEMU_PLUGIN_ICOUNT_RAW_SYMBOL: &str = "qemu_plugin_icount_raw";
/// QEMU plugin API symbol used to request current-vCPU exit.
pub const QEMU_PLUGIN_FORCE_VCPU_EXIT_SYMBOL: &str = "qemu_plugin_force_vcpu_exit";
/// QEMU plugin API symbol used to enter the native paused runstate.
pub const QEMU_PLUGIN_REQUEST_VMSTOP_SYMBOL: &str = "qemu_plugin_request_vmstop";
/// QEMU plugin API symbol used to register the setup wake fd with QEMU.
pub const QEMU_PLUGIN_REGISTER_WAKE_FD_SYMBOL: &str = "qemu_plugin_register_wake_fd";
/// QEMU plugin API symbol used to seal the fixed resource manifest.
pub const QEMU_PLUGIN_REGISTER_RESOURCE_MANIFEST_SYMBOL: &str =
    "qemu_plugin_crucible_register_resource_manifest";
/// QEMU plugin API symbol used to register the reversible hot-fork callback barrier.
pub const QEMU_PLUGIN_REGISTER_HOT_FORK_BARRIER_SYMBOL: &str =
    "qemu_plugin_crucible_register_hot_fork_barrier";
/// QEMU plugin API symbol used to register fork-child runtime reconstruction.
pub const QEMU_PLUGIN_REGISTER_HOT_FORK_CHILD_RUNTIME_SYMBOL: &str =
    "qemu_plugin_crucible_register_hot_fork_child_runtime";
/// QEMU plugin API symbol used to request a clean or fail-loud process shutdown.
pub const QEMU_PLUGIN_REQUEST_SHUTDOWN_SYMBOL: &str = "qemu_plugin_request_shutdown";
/// QEMU plugin API symbol that binds the immutable process generation.
pub const QEMU_PLUGIN_SET_PROCESS_GENERATION_SYMBOL: &str =
    "qemu_plugin_crucible_lifecycle_set_process_generation";
/// QEMU plugin API symbol used to register shmem block submit/poll callbacks.
pub const QEMU_PLUGIN_REGISTER_BLK_CB_SYMBOL: &str = "qemu_plugin_register_blk_cb";
/// QEMU plugin API symbol used to register asynchronous block transport events.
pub const QEMU_PLUGIN_REGISTER_BLK_EVENT_CB_SYMBOL: &str = "qemu_plugin_register_blk_event_cb";
/// QEMU plugin API symbol used to register the blocked-device wait callback.
pub const QEMU_PLUGIN_REGISTER_BLK_WAIT_CB_SYMBOL: &str = "qemu_plugin_register_blk_wait_cb";
/// QEMU plugin API symbol used to register shmem 9p burst/submit/poll callbacks.
pub const QEMU_PLUGIN_REGISTER_9P_CB_SYMBOL: &str = "qemu_plugin_register_9p_cb";
/// QEMU accelerator callback registration export.
pub const QEMU_PLUGIN_REGISTER_ACCELERATOR_CB_SYMBOL: &str = "qemu_plugin_register_accelerator_cb";
/// QEMU plugin API symbol used to register the standard vCPU-init callback.
pub const QEMU_PLUGIN_REGISTER_VCPU_INIT_CB_SYMBOL: &str = "qemu_plugin_register_vcpu_init_cb";
/// QEMU plugin API symbol used to register Crucible all-idle/resume callbacks.
pub const QEMU_PLUGIN_REGISTER_VCPU_IDLE_RESUME_CB_SYMBOL: &str =
    "qemu_plugin_register_vcpu_idle_resume_cb";
/// QEMU plugin API symbol used to register exact drained-control boundaries.
pub const QEMU_PLUGIN_REGISTER_CONTROL_BOUNDARY_CB_SYMBOL: &str =
    "qemu_plugin_register_control_boundary_cb";
/// QEMU plugin API symbol used to connect the sim loop to shared-memory time state.
pub const QEMU_PLUGIN_REGISTER_SIM_SHMEM_DISPATCH_CB_SYMBOL: &str =
    "qemu_plugin_register_sim_shmem_dispatch_cb";
/// Minimum supported vCPU count under single-threaded round-robin TCG.
pub const MIN_SUPPORTED_VCPU_COUNT: u32 = 1;
const QEMU_PLUGIN_CLOCK_DEADLINE_SYMBOL_C: &[u8] = b"qemu_plugin_clock_deadline_ns\0";
const QEMU_PLUGIN_ADVANCE_TIME_TICKS_SYMBOL_C: &[u8] = b"qemu_plugin_advance_time_ticks\0";
const QEMU_PLUGIN_REGISTER_TIME_ADVANCE_CB_SYMBOL_C: &[u8] =
    b"qemu_plugin_register_time_advance_cb\0";
const QEMU_PLUGIN_CRUCIBLE_ARM_VIRTUAL_TIMER_WITNESS_SYMBOL_C: &[u8] =
    b"qemu_plugin_crucible_arm_virtual_timer_witness\0";
const QEMU_PLUGIN_CRUCIBLE_QUERY_VIRTUAL_TIMER_WITNESS_SYMBOL_C: &[u8] =
    b"qemu_plugin_crucible_query_virtual_timer_witness\0";
const QEMU_PLUGIN_CRUCIBLE_WAIT_IDLE_WAKE_SYMBOL_C: &[u8] =
    b"qemu_plugin_crucible_wait_idle_wake\0";
const QEMU_PLUGIN_INJECT_PREEMPTION_SYMBOL_C: &[u8] = b"qemu_plugin_inject_preemption\0";
const QEMU_PLUGIN_READ_VCPU_REGS_SYMBOL_C: &[u8] = b"qemu_plugin_read_vcpu_regs\0";
const QEMU_PLUGIN_RR_CURSOR_SYMBOL_C: &[u8] = b"qemu_plugin_rr_cursor\0";
const QEMU_PLUGIN_ICOUNT_RAW_SYMBOL_C: &[u8] = b"qemu_plugin_icount_raw\0";
const QEMU_PLUGIN_FORCE_VCPU_EXIT_SYMBOL_C: &[u8] = b"qemu_plugin_force_vcpu_exit\0";
const QEMU_PLUGIN_REQUEST_VMSTOP_SYMBOL_C: &[u8] = b"qemu_plugin_request_vmstop\0";
const QEMU_PLUGIN_REGISTER_WAKE_FD_SYMBOL_C: &[u8] = b"qemu_plugin_register_wake_fd\0";
const QEMU_PLUGIN_REGISTER_RESOURCE_MANIFEST_SYMBOL_C: &[u8] =
    b"qemu_plugin_crucible_register_resource_manifest\0";
const QEMU_PLUGIN_REGISTER_HOT_FORK_BARRIER_SYMBOL_C: &[u8] =
    b"qemu_plugin_crucible_register_hot_fork_barrier\0";
const QEMU_PLUGIN_REGISTER_HOT_FORK_CHILD_RUNTIME_SYMBOL_C: &[u8] =
    b"qemu_plugin_crucible_register_hot_fork_child_runtime\0";
const QEMU_PLUGIN_REQUEST_SHUTDOWN_SYMBOL_C: &[u8] = b"qemu_plugin_request_shutdown\0";
const QEMU_PLUGIN_SET_PROCESS_GENERATION_SYMBOL_C: &[u8] =
    b"qemu_plugin_crucible_lifecycle_set_process_generation\0";
const QEMU_PLUGIN_REGISTER_VCPU_TB_TRANS_CB_SYMBOL_C: &[u8] =
    b"qemu_plugin_register_vcpu_tb_trans_cb\0";
const QEMU_PLUGIN_REGISTER_VCPU_TB_EXEC_COND_CB_SYMBOL_C: &[u8] =
    b"qemu_plugin_register_vcpu_tb_exec_cond_cb\0";
const QEMU_PLUGIN_SCOREBOARD_NEW_SYMBOL_C: &[u8] = b"qemu_plugin_scoreboard_new\0";
const QEMU_PLUGIN_SCOREBOARD_FREE_SYMBOL_C: &[u8] = b"qemu_plugin_scoreboard_free\0";
const QEMU_PLUGIN_U64_SET_SYMBOL_C: &[u8] = b"qemu_plugin_u64_set\0";
const QEMU_PLUGIN_NUM_VCPUS_SYMBOL_C: &[u8] = b"qemu_plugin_num_vcpus\0";
const QEMU_PLUGIN_ICOUNT_AT_TB_ENTRY_SYMBOL_C: &[u8] = b"qemu_plugin_icount_at_tb_entry\0";
const QEMU_PLUGIN_REGISTER_FLUSH_CB_SYMBOL_C: &[u8] = b"qemu_plugin_register_flush_cb\0";
const QEMU_PLUGIN_TB_VADDR_SYMBOL_C: &[u8] = b"qemu_plugin_tb_vaddr\0";
const QEMU_PLUGIN_TB_N_INSNS_SYMBOL_C: &[u8] = b"qemu_plugin_tb_n_insns\0";
const QEMU_PLUGIN_TB_GET_INSN_SYMBOL_C: &[u8] = b"qemu_plugin_tb_get_insn\0";
const QEMU_PLUGIN_INSN_SIZE_SYMBOL_C: &[u8] = b"qemu_plugin_insn_size\0";
const QEMU_PLUGIN_REGISTER_BLK_CB_SYMBOL_C: &[u8] = b"qemu_plugin_register_blk_cb\0";
const QEMU_PLUGIN_REGISTER_BLK_EVENT_CB_SYMBOL_C: &[u8] = b"qemu_plugin_register_blk_event_cb\0";
const QEMU_PLUGIN_REGISTER_BLK_WAIT_CB_SYMBOL_C: &[u8] = b"qemu_plugin_register_blk_wait_cb\0";
const QEMU_PLUGIN_REGISTER_9P_CB_SYMBOL_C: &[u8] = b"qemu_plugin_register_9p_cb\0";
const QEMU_PLUGIN_REGISTER_ACCELERATOR_CB_SYMBOL_C: &[u8] =
    b"qemu_plugin_register_accelerator_cb\0";
const QEMU_PLUGIN_REGISTER_VCPU_INIT_CB_SYMBOL_C: &[u8] = b"qemu_plugin_register_vcpu_init_cb\0";
const QEMU_PLUGIN_REGISTER_VCPU_IDLE_RESUME_CB_SYMBOL_C: &[u8] =
    b"qemu_plugin_register_vcpu_idle_resume_cb\0";
const QEMU_PLUGIN_REGISTER_CONTROL_BOUNDARY_CB_SYMBOL_C: &[u8] =
    b"qemu_plugin_register_control_boundary_cb\0";
const QEMU_PLUGIN_REGISTER_SIM_SHMEM_DISPATCH_CB_SYMBOL_C: &[u8] =
    b"qemu_plugin_register_sim_shmem_dispatch_cb\0";
const QEMU_PLUGIN_REQUEST_TIME_CONTROL_SYMBOL_C: &[u8] = b"qemu_plugin_request_time_control\0";
const QEMU_PLUGIN_SINGLE_THREADED_RR_SYMBOL_C: &[u8] = b"qemu_plugin_crucible_single_threaded_rr\0";
/// QEMU capability required to observe the callback serialization mode.
pub const QEMU_PLUGIN_SINGLE_THREADED_RR_SYMBOL: &str = "qemu_plugin_crucible_single_threaded_rr";
/// QEMU callback-serialization proof returning one only for single-threaded RR.
pub type QemuSingleThreadedRrFn = extern "C" fn() -> c_int;

/// The TCG threading mode relevant to plugin callback serialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuTcgThreading {
    /// QEMU serializes all vCPU callbacks onto one host thread.
    SingleThreadedRoundRobin,
    /// QEMU may execute vCPU callbacks concurrently and is unsupported.
    MultiThreadedTcg,
}

/// Validated QEMU execution model for the plugin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuPluginExecutionModel {
    smp_vcpus: u32,
    threading: QemuTcgThreading,
}

impl QemuPluginExecutionModel {
    /// Validates the vCPU count and TCG threading mode.
    ///
    /// # Errors
    ///
    /// Returns [`QemuPluginAbiError::NoVcpus`] when `smp_vcpus` is zero, or
    /// [`QemuPluginAbiError::MultiThreadedTcg`] when MTTCG would invalidate the
    /// plugin's single-threaded callback-state invariant.
    pub const fn validate(
        smp_vcpus: u32,
        threading: QemuTcgThreading,
    ) -> Result<Self, QemuPluginAbiError> {
        if smp_vcpus < MIN_SUPPORTED_VCPU_COUNT {
            return Err(QemuPluginAbiError::NoVcpus);
        }
        if matches!(threading, QemuTcgThreading::MultiThreadedTcg) {
            return Err(QemuPluginAbiError::MultiThreadedTcg);
        }
        Ok(Self {
            smp_vcpus,
            threading,
        })
    }

    /// Returns the number of guest vCPUs in this QEMU process.
    #[must_use]
    pub const fn smp_vcpus(self) -> u32 {
        self.smp_vcpus
    }

    /// Returns the validated TCG threading mode.
    #[must_use]
    pub const fn threading(self) -> QemuTcgThreading {
        self.threading
    }

    /// Returns whether the current process uses the degenerate single-vCPU case.
    #[must_use]
    pub const fn is_single_vcpu(self) -> bool {
        self.smp_vcpus == 1
    }
}

/// A callback family owned by the QEMU plugin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PluginDeviceCallbackKind {
    /// Guest network transmit interception.
    NetworkTx,
    /// Guest network receive injection.
    NetworkRx,
    /// Block-device submit interception.
    BlockSubmit,
    /// Block-device completion polling.
    BlockPoll,
    /// 9p request submit interception.
    Virtio9pSubmit,
    /// 9p completion polling.
    Virtio9pPoll,
    /// Optional white-box guest doorbell trap.
    WhiteboxDoorbell,
}

/// All device and channel callback families the plugin owns.
pub const OWNED_DEVICE_CALLBACK_KINDS: [PluginDeviceCallbackKind; 7] = [
    PluginDeviceCallbackKind::NetworkTx,
    PluginDeviceCallbackKind::NetworkRx,
    PluginDeviceCallbackKind::BlockSubmit,
    PluginDeviceCallbackKind::BlockPoll,
    PluginDeviceCallbackKind::Virtio9pSubmit,
    PluginDeviceCallbackKind::Virtio9pPoll,
    PluginDeviceCallbackKind::WhiteboxDoorbell,
];

/// QEMU raw-icount reader exported by `crucible-plugin-icount-raw`.
pub type QemuIcountRawFn = extern "C" fn() -> u64;
/// QEMU current-vCPU exit request exported by `crucible-plugin-vcpu-exit`.
pub type QemuForceVcpuExitFn = extern "C" fn();
/// QEMU native VM-stop request exported by the checkpoint-handoff patch.
pub type QemuRequestVmstopFn = extern "C" fn() -> c_int;
/// QEMU wake-fd registration exported by `crucible-plugin-wake-fd`.
pub type QemuRegisterWakeFdFn = extern "C" fn(c_int) -> c_int;

/// Fixed-layout scalar plugin resource manifest consumed by patched QEMU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct QemuPluginResourceManifest {
    /// Manifest schema version, currently two.
    pub schema_version: u32,
    /// Exact C ABI structure size.
    pub struct_size: u32,
    /// Nonzero host-supervised QEMU process generation.
    pub process_generation: u64,
    /// Nonzero QEMU plugin identity.
    pub plugin_id: u64,
    /// Closed plugin-owned resource-class mask.
    pub resource_mask: u64,
    /// Closed callback-registration-class mask.
    pub callback_mask: u64,
    /// Closed process-lifetime worker-class mask.
    pub worker_mask: u64,
    /// Shared-memory backing device number captured before mmap.
    pub shmem_device: u64,
    /// Shared-memory backing inode captured before mmap.
    pub shmem_inode: u64,
    /// Exact shared-memory mapping length.
    pub shmem_length: u64,
    /// Assigned VM slot index.
    pub slot_index: u32,
    /// Shared-memory topology node count.
    pub node_count: u32,
    /// Plugin control-socket descriptor number.
    pub control_fd: i32,
    /// QEMU-registered wake descriptor number.
    pub wake_fd: i32,
}

/// QEMU function that validates and seals the plugin resource manifest.
pub type QemuRegisterResourceManifestFn = extern "C" fn(*const QemuPluginResourceManifest) -> c_int;
/// Hot-fork barrier callback action that acquires the reversible hold.
pub const QEMU_PLUGIN_HOT_FORK_BARRIER_HOLD: u32 = 1;
/// Hot-fork barrier callback action that observes the current state.
pub const QEMU_PLUGIN_HOT_FORK_BARRIER_QUERY: u32 = 2;
/// Hot-fork barrier callback action that releases the reversible hold.
pub const QEMU_PLUGIN_HOT_FORK_BARRIER_RELEASE: u32 = 3;
/// Current fixed-layout callback, ring, worker, and mapping barrier schema.
pub const QEMU_PLUGIN_HOT_FORK_BARRIER_STATUS_VERSION: u32 = 6;
/// Callback-barrier status flag indicating that the reversible hold is active.
pub const QEMU_PLUGIN_HOT_FORK_BARRIER_FLAG_HELD: u32 = 1_u32 << 0;
/// Callback-barrier status flag indicating permanent teardown closure.
pub const QEMU_PLUGIN_HOT_FORK_BARRIER_FLAG_TEARDOWN: u32 = 1_u32 << 1;
/// Callback-barrier status flag indicating the source mapping is `MADV_DONTFORK`.
pub const QEMU_PLUGIN_HOT_FORK_BARRIER_FLAG_MAPPING_DONTFORK: u32 = 1_u32 << 2;

/// Fixed-layout status copied from the plugin callback-admission owner.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct QemuPluginHotForkBarrierStatus {
    /// Status schema version, currently six.
    pub schema_version: u32,
    /// Exact C ABI structure size.
    pub struct_size: u32,
    /// Closed flag mask describing held, teardown, and mapping-disposition state.
    pub flags: u32,
    /// Reserved field that must remain zero.
    pub reserved: u32,
    /// Exact callbacks admitted but not yet returned at the snapshot instant.
    pub in_flight: u64,
    /// Exact number of SPSC rings in the validated shared-memory layout.
    pub ring_count: u64,
    /// Number of rings whose reversible producer and consumer barriers are held.
    pub rings_held: u64,
    /// Checked aggregate of admitted producer publications still in flight.
    pub ring_producers_in_flight: u64,
    /// Checked aggregate of admitted consumer operations still in flight.
    pub ring_consumers_in_flight: u64,
    /// Exact sealed process-lifetime worker-class mask.
    pub worker_mask: u64,
    /// Worker classes currently parked at an operation boundary.
    pub parked_worker_mask: u64,
    /// Parked worker classes retaining one dequeued item in thread-local state.
    pub pending_worker_mask: u64,
    /// Checked count of worker operations admitted before the hold.
    pub worker_operations_in_flight: u64,
}

/// Plugin callback that changes or observes the callback-admission barrier.
pub type QemuPluginHotForkBarrierCbFn =
    extern "C" fn(u32, *mut QemuPluginHotForkBarrierStatus, *mut c_void) -> c_int;
/// QEMU function that registers the process-lifetime hot-fork barrier callback.
pub type QemuRegisterHotForkBarrierFn =
    extern "C" fn(QemuPluginId, Option<QemuPluginHotForkBarrierCbFn>, *mut c_void) -> c_int;
/// Fork-child runtime callback action that installs process-private resources.
pub const QEMU_PLUGIN_HOT_FORK_CHILD_INITIALIZE: u32 = 1;
/// Fork-child runtime callback action that observes reconstruction progress.
pub const QEMU_PLUGIN_HOT_FORK_CHILD_QUERY: u32 = 2;
/// Fork-child runtime callback action that releases reconstructed workers.
pub const QEMU_PLUGIN_HOT_FORK_CHILD_RELEASE: u32 = 3;
/// Current fixed-layout fork-child runtime plan schema.
pub const QEMU_PLUGIN_HOT_FORK_CHILD_PLAN_VERSION: u32 = 3;
/// Current fixed-layout fork-child runtime status schema.
pub const QEMU_PLUGIN_HOT_FORK_CHILD_STATUS_VERSION: u32 = 3;
/// Child status flag indicating that callback admission remains held.
pub const QEMU_PLUGIN_HOT_FORK_CHILD_FLAG_CALLBACKS_HELD: u32 = 1_u32 << 0;
/// Child status flag indicating that the private shared-memory mapping exists.
pub const QEMU_PLUGIN_HOT_FORK_CHILD_FLAG_MAPPING_INSTALLED: u32 = 1_u32 << 1;
/// Child status flag indicating that every replacement worker is parked.
pub const QEMU_PLUGIN_HOT_FORK_CHILD_FLAG_WORKERS_READY: u32 = 1_u32 << 2;
/// Child status flag indicating that ordinary callback and worker admission is active.
pub const QEMU_PLUGIN_HOT_FORK_CHILD_FLAG_ACTIVE: u32 = 1_u32 << 3;
/// Child status flag indicating a terminal reconstruction failure.
pub const QEMU_PLUGIN_HOT_FORK_CHILD_FLAG_FAILED: u32 = 1_u32 << 4;

/// Exact staged-resource basis supplied to a fork-child runtime.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct QemuPluginHotForkChildPlan {
    /// Plan schema version, currently three.
    pub schema_version: u32,
    /// Exact C ABI structure size.
    pub struct_size: u32,
    /// Closed flag mask; version three requires zero.
    pub flags: u32,
    /// Reserved field that must remain zero.
    pub reserved: u32,
    /// Exact process generation retained by the fork template.
    pub parent_process_generation: u64,
    /// Exact successor process generation assigned to this child.
    pub child_process_generation: u64,
    /// Exact template transaction generation that admitted every staged resource.
    pub template_generation: u64,
    /// Exact branch-private ring mutation generation.
    pub private_ring_generation: u64,
    /// Exact replacement endpoint-pair mutation generation.
    pub plugin_endpoint_generation: u64,
    /// Exact quiescent plugin-barrier generation captured at endpoint staging.
    pub plugin_barrier_generation: u64,
    /// Exact sealed worker mask copied from the template manifest.
    pub worker_mask: u64,
    /// Linux `SO_COOKIE` identity of the replacement control socket.
    pub control_socket_cookie: u64,
    /// Linux `/proc/self/fdinfo` identity of the replacement wake eventfd.
    pub wake_eventfd_id: u64,
    /// Device number of the branch-private shared-memory backing object.
    pub shmem_device: u64,
    /// Inode number of the branch-private shared-memory backing object.
    pub shmem_inode: u64,
    /// Exact branch-private shared-memory mapping length.
    pub shmem_length: u64,
    /// Authenticated template setup-region VMA start address.
    pub source_mapping_start: u64,
    /// Exact authenticated template setup-region VMA length.
    pub source_mapping_length: u64,
    /// Exact authenticated template setup-region file offset; version three requires zero.
    pub source_mapping_offset: u64,
    /// Descriptor carrying the branch-private shared-memory object.
    pub private_ring_fd: i32,
    /// Replacement control socket at the template manifest descriptor number.
    pub control_fd: i32,
    /// Replacement wake eventfd at the template manifest descriptor number.
    pub wake_fd: i32,
    /// Reserved descriptor field that must remain negative one.
    pub reserved_fd: i32,
}

/// Exact process-local progress reported by the fork-child runtime callback.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct QemuPluginHotForkChildStatus {
    /// Status schema version, currently three.
    pub schema_version: u32,
    /// Exact C ABI structure size.
    pub struct_size: u32,
    /// Closed callback, mapping, worker, active, and failure flag mask.
    pub flags: u32,
    /// Closed internal child-runtime phase.
    pub phase: u32,
    /// Exact process generation inherited from the fork template.
    pub parent_process_generation: u64,
    /// Exact successor process generation installed in this child.
    pub child_process_generation: u64,
    /// Exact template transaction generation installed in this child.
    pub template_generation: u64,
    /// Exact branch-private ring generation installed in this child.
    pub private_ring_generation: u64,
    /// Exact replacement endpoint generation installed in this child.
    pub plugin_endpoint_generation: u64,
    /// Exact plugin-barrier generation authorizing this child transition.
    pub plugin_barrier_generation: u64,
    /// Linux `SO_COOKIE` identity of the installed control socket.
    pub control_socket_cookie: u64,
    /// Linux eventfd identity of the installed wake descriptor.
    pub wake_eventfd_id: u64,
    /// Authenticated template setup-region VMA start used for installation.
    pub source_mapping_start: u64,
    /// Exact authenticated template setup-region VMA length.
    pub source_mapping_length: u64,
    /// Exact authenticated template setup-region file offset.
    pub source_mapping_offset: u64,
    /// Exact sealed process-lifetime worker-class mask.
    pub worker_mask: u64,
    /// Replacement worker classes parked at their held operation boundary.
    pub parked_worker_mask: u64,
    /// Parked replacement workers retaining one dequeued item.
    pub pending_worker_mask: u64,
    /// Replacement worker operations admitted before their hold.
    pub worker_operations_in_flight: u64,
}

/// Plugin callback that initializes, observes, or releases the fork-child runtime.
pub type QemuPluginHotForkChildRuntimeCbFn = extern "C" fn(
    u32,
    *const QemuPluginHotForkChildPlan,
    *mut QemuPluginHotForkChildStatus,
    *mut c_void,
) -> c_int;
/// QEMU function that registers the process-lifetime fork-child runtime callback.
pub type QemuRegisterHotForkChildRuntimeFn =
    extern "C" fn(QemuPluginId, Option<QemuPluginHotForkChildRuntimeCbFn>, *mut c_void) -> c_int;
/// QEMU shutdown request function; nonzero selects the fail-loud host-error path.
pub type QemuRequestShutdownFn = extern "C" fn(c_int);
/// QEMU immutable process-generation provisioning function.
pub type QemuSetProcessGenerationFn = extern "C" fn(u64) -> c_int;
/// Block submit callback body passed to QEMU's shmem block driver.
pub type QemuBlkSubmitCbFn =
    extern "C" fn(u64, u32, u32, u64, *const u8, usize, *mut c_void) -> c_int;
/// Block completion poll callback body passed to QEMU's shmem block driver.
pub type QemuBlkPollCbFn = extern "C" fn(u64, u32, *mut u8, usize, *mut c_void) -> i64;
/// Asynchronous block transport-event poll callback body.
pub type QemuBlkEventPollCbFn = extern "C" fn(*mut u8, usize, *mut c_void) -> i64;
/// Commit callback for an event accepted by QEMU after exact validation.
pub type QemuBlkEventCommitCbFn = extern "C" fn(*mut c_void) -> c_int;
/// VMState size-query/save callback for the permissive transport continuation.
pub type QemuBlkTransportSaveCbFn = extern "C" fn(*mut u8, usize, *mut c_void) -> i64;
/// VMState restore callback paired with QEMU's allocator state.
pub type QemuBlkTransportRestoreCbFn =
    extern "C" fn(*const u8, usize, u64, u32, *mut c_void) -> c_int;
/// Block device-wait callback body passed to QEMU's shmem block driver.
pub type QemuBlkWaitCbFn = extern "C" fn(u32, *mut c_void);
/// QEMU shmem block callback registration exported by `crucible-blk-shmem`.
pub type QemuRegisterBlkCbFn =
    extern "C" fn(Option<QemuBlkSubmitCbFn>, Option<QemuBlkPollCbFn>, *mut c_void);
/// QEMU asynchronous block event registration export.
pub type QemuRegisterBlkEventCbFn = extern "C" fn(
    Option<QemuBlkEventPollCbFn>,
    Option<QemuBlkEventCommitCbFn>,
    Option<QemuBlkTransportSaveCbFn>,
    Option<QemuBlkTransportRestoreCbFn>,
    *mut c_void,
);
/// QEMU shmem block wait registration exported by the device-completion patch.
pub type QemuRegisterBlkWaitCbFn = extern "C" fn(Option<QemuBlkWaitCbFn>, *mut c_void);
/// 9p burst callback body passed to QEMU's virtio-9p device.
pub type QemuNinePBurstCbFn = extern "C" fn(*mut c_void);
/// 9p submit callback body passed to QEMU's virtio-9p device.
pub type QemuNinePSubmitCbFn = extern "C" fn(u32, *const u8, usize, usize, *mut c_void) -> c_int;
/// 9p completion poll callback body passed to QEMU's virtio-9p device.
pub type QemuNinePPollCbFn = extern "C" fn(u32, *mut u8, usize, *mut c_void) -> i64;
/// QEMU shmem 9p callback registration exported by `crucible-dev-cb-api`.
pub type QemuRegisterNinePCbFn = extern "C" fn(
    Option<QemuNinePBurstCbFn>,
    Option<QemuNinePSubmitCbFn>,
    Option<QemuNinePPollCbFn>,
    Option<QemuNinePBurstCbFn>,
    *mut c_void,
);
/// Accelerator submit callback body passed to QEMU's deterministic device.
pub type QemuAcceleratorSubmitCbFn = extern "C" fn(
    u64,
    *const u8,
    u16,
    u16,
    u16,
    u64,
    *const u8,
    usize,
    usize,
    *mut c_void,
) -> c_int;
/// Accelerator completion callback body passed to QEMU's deterministic device.
pub type QemuAcceleratorPollCbFn = extern "C" fn(u64, *mut u16, *mut u8, usize, *mut c_void) -> i64;
/// Accelerator wait notification passed to QEMU's deterministic device.
pub type QemuAcceleratorWaitCbFn = extern "C" fn(u64, *mut c_void);
/// Accelerator pending-request restore callback.
pub type QemuAcceleratorRestoreCbFn =
    extern "C" fn(u64, *const u8, u16, u16, u16, u64, usize, *mut c_void) -> c_int;
/// Accelerator restore-transaction begin callback.
pub type QemuAcceleratorRestoreBeginCbFn = extern "C" fn(u32, *mut c_void) -> c_int;
/// Accelerator restore-transaction commit callback.
pub type QemuAcceleratorRestoreCommitCbFn = extern "C" fn(*mut c_void) -> c_int;
/// Accelerator restore-transaction abort callback.
pub type QemuAcceleratorRestoreAbortCbFn = extern "C" fn(*mut c_void);
/// Accelerator pending-request cancellation callback.
pub type QemuAcceleratorCancelCbFn = extern "C" fn(u64, *mut c_void) -> c_int;
/// QEMU deterministic accelerator callback registration export.
pub type QemuRegisterAcceleratorCbFn = extern "C" fn(
    Option<QemuAcceleratorSubmitCbFn>,
    Option<QemuAcceleratorPollCbFn>,
    Option<QemuAcceleratorWaitCbFn>,
    Option<QemuAcceleratorRestoreBeginCbFn>,
    Option<QemuAcceleratorRestoreCbFn>,
    Option<QemuAcceleratorRestoreCommitCbFn>,
    Option<QemuAcceleratorRestoreAbortCbFn>,
    Option<QemuAcceleratorCancelCbFn>,
    *mut c_void,
);
/// Standard QEMU vCPU lifecycle callback body.
pub(crate) type QemuVcpuSimpleCbFn = extern "C" fn(c_uint, *mut c_void);
/// Standard QEMU vCPU-init callback registration function.
pub(crate) type QemuRegisterVcpuInitCbFn =
    extern "C" fn(QemuPluginId, QemuVcpuSimpleCbFn, *mut c_void);
/// Crucible all-vCPUs-idle or resume callback body.
pub type QemuVcpuIdleResumeCbFn = extern "C" fn(c_uint, u64, *mut c_void);
/// QEMU registration function for Crucible all-idle and resume callbacks.
pub type QemuRegisterVcpuIdleResumeCbFn =
    extern "C" fn(Option<QemuVcpuIdleResumeCbFn>, Option<QemuVcpuIdleResumeCbFn>, *mut c_void);
/// QEMU registration function for exact drained-control boundaries.
pub type QemuRegisterControlBoundaryCbFn =
    extern "C" fn(Option<QemuVcpuIdleResumeCbFn>, *mut c_void);
/// Sim-loop callback that publishes the raw aggregate instruction count.
pub type QemuSimShmemPublishIcountCbFn = extern "C" fn(u64, *mut c_void);
/// Sim-loop callback that reads the scheduler-published instruction ceiling.
pub type QemuSimShmemMaxAdvanceIcountCbFn = extern "C" fn(*mut c_void) -> u64;
/// QEMU registration function for sim-loop shared-memory time dispatch.
pub type QemuRegisterSimShmemDispatchCbFn = extern "C" fn(
    Option<QemuSimShmemPublishIcountCbFn>,
    Option<QemuSimShmemMaxAdvanceIcountCbFn>,
    *mut c_void,
);

/// Required runtime APIs added by the T-PATCH-11 QEMU patch group.
#[derive(Clone, Copy, Debug)]
pub struct PluginRuntimeApis {
    icount_raw: QemuIcountRawFn,
    force_vcpu_exit: QemuForceVcpuExitFn,
    idle_wake_wait: crate::QemuIdleWakeWait,
    register_wake_fd: QemuRegisterWakeFdFn,
}

impl PluginRuntimeApis {
    /// Requires every T-PATCH-11 runtime export before install succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`QemuPluginAbiError::RuntimeApiCapability`] naming the first
    /// missing QEMU symbol.
    pub fn require(
        icount_raw: Option<QemuIcountRawFn>,
        force_vcpu_exit: Option<QemuForceVcpuExitFn>,
        wait_idle_wake: Option<crate::QemuCrucibleWaitIdleWakeFn>,
        register_wake_fd: Option<QemuRegisterWakeFdFn>,
    ) -> Result<Self, QemuPluginAbiError> {
        Ok(Self {
            icount_raw: require_runtime_api(icount_raw, QEMU_PLUGIN_ICOUNT_RAW_SYMBOL)?,
            force_vcpu_exit: require_runtime_api(
                force_vcpu_exit,
                QEMU_PLUGIN_FORCE_VCPU_EXIT_SYMBOL,
            )?,
            idle_wake_wait: crate::QemuIdleWakeWait::from_required_pointer(require_runtime_api(
                wait_idle_wake,
                crate::QEMU_PLUGIN_CRUCIBLE_WAIT_IDLE_WAKE_SYMBOL,
            )?),
            register_wake_fd: require_runtime_api(
                register_wake_fd,
                QEMU_PLUGIN_REGISTER_WAKE_FD_SYMBOL,
            )?,
        })
    }

    /// Returns the raw icount reader.
    #[must_use]
    pub const fn icount_raw(self) -> QemuIcountRawFn {
        self.icount_raw
    }

    /// Returns the current-vCPU exit requester.
    #[must_use]
    pub const fn force_vcpu_exit(self) -> QemuForceVcpuExitFn {
        self.force_vcpu_exit
    }

    /// Returns QEMU's one-shot BQL-releasing idle wake wait.
    #[must_use]
    pub(crate) const fn idle_wake_wait(self) -> crate::QemuIdleWakeWait {
        self.idle_wake_wait
    }

    /// Returns QEMU's wake-fd registration function.
    #[must_use]
    pub const fn register_wake_fd(self) -> QemuRegisterWakeFdFn {
        self.register_wake_fd
    }
}

/// An error produced while validating the QEMU plugin ABI installation.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum QemuPluginAbiError {
    /// QEMU passed a negative argument count.
    #[error("QEMU plugin install argc {argc} is negative")]
    NegativeArgc {
        /// Rejected `argc` value.
        argc: c_int,
    },
    /// QEMU passed arguments but no argument vector.
    #[error("QEMU plugin install argv is null for argc {argc}")]
    MissingArgv {
        /// Positive `argc` value.
        argc: c_int,
    },
    /// QEMU did not provide plugin information.
    #[error("QEMU plugin install info pointer is null")]
    MissingInfo,
    /// QEMU did not provide a target architecture name.
    #[error("QEMU plugin target name pointer is null")]
    MissingTargetName,
    /// QEMU's target architecture name was not valid UTF-8.
    #[error("QEMU plugin target name is not valid UTF-8")]
    InvalidTargetNameUtf8,
    /// QEMU loaded the plugin for an architecture Crucible does not support.
    #[error("QEMU plugin target architecture `{target}` is unsupported")]
    UnsupportedTargetArchitecture {
        /// Rejected QEMU target name.
        target: String,
    },
    /// One plugin argument pointer was null.
    #[error("QEMU plugin install argv[{index}] is null")]
    NullArgvEntry {
        /// Index of the null argument pointer.
        index: usize,
    },
    /// One plugin argument was not valid UTF-8.
    #[error("QEMU plugin install argv[{index}] is not valid UTF-8")]
    InvalidArgvUtf8 {
        /// Index of the non-UTF-8 argument.
        index: usize,
    },
    /// QEMU's plugin arguments failed Crucible's fail-closed parser.
    #[error("QEMU plugin install arguments are invalid: {source}")]
    PluginArgs {
        /// Underlying argument parser error.
        source: PluginArgsParseError,
    },
    /// QEMU's supported plugin API range does not include this plugin.
    #[error("QEMU plugin API range {min}..={cur} does not include required version {required}")]
    UnsupportedPluginApi {
        /// Minimum API version supported by QEMU.
        min: c_int,
        /// Current API version supported by QEMU.
        cur: c_int,
        /// Plugin API version exported by this crate.
        required: c_int,
    },
    /// QEMU reported zero guest vCPUs.
    #[error("QEMU plugin execution model has no vCPUs")]
    NoVcpus,
    /// QEMU loaded the plugin outside system emulation.
    #[error("QEMU plugin requires system emulation")]
    NotSystemEmulation,
    /// QEMU is using multi-threaded TCG, which can re-enter plugin state concurrently.
    #[error("QEMU plugin requires single-threaded round-robin TCG, not MTTCG")]
    MultiThreadedTcg,
    /// The required exact deadline capability is unavailable.
    #[error("QEMU plugin exact deadline capability failed")]
    ExactDeadlineCapability {
        /// Underlying exact deadline error.
        source: ExactDeadlineError,
    },
    /// The required queued idle-advance capability is unavailable.
    #[error("QEMU plugin queued idle-advance capability failed")]
    QueuedIdleAdvanceCapability {
        /// Underlying queued idle-advance error.
        source: QueuedIdleAdvanceError,
    },
    /// The required commanded preemption-injection capability is unavailable.
    #[error("QEMU plugin preemption-injection capability failed")]
    PreemptionInjectionCapability {
        /// Underlying preemption injection error.
        source: PreemptionError,
    },
    /// The required vCPU introspection capability is unavailable.
    #[error("QEMU plugin vCPU introspection capability failed")]
    VcpuIntrospectionCapability {
        /// Underlying vCPU introspection error.
        source: VcpuIntrospectionError,
    },
    /// The required closed QEMU fault registry is unavailable or malformed.
    #[error("QEMU plugin fault-command capability failed: {source}")]
    FaultCommandCapability {
        /// Underlying fault bridge capability error.
        source: crate::FaultCommandBridgeError,
    },
    /// A required T-PATCH-11 runtime API export is unavailable.
    #[error("QEMU plugin runtime API capability {symbol} is unavailable")]
    RuntimeApiCapability {
        /// Missing QEMU symbol.
        symbol: &'static str,
    },
    /// QEMU rejected the launch-provisioned process generation.
    #[error("QEMU rejected process generation {generation} with status {status}")]
    ProcessGenerationProvision {
        /// Generation supplied by the launch profile.
        generation: u64,
        /// Negative errno status returned by QEMU.
        status: c_int,
    },
}

fn require_runtime_api<T>(symbol: Option<T>, name: &'static str) -> Result<T, QemuPluginAbiError> {
    symbol.ok_or(QemuPluginAbiError::RuntimeApiCapability { symbol: name })
}

/// Validates raw install arguments without dereferencing them.
///
/// # Errors
///
/// Returns [`QemuPluginAbiError`] when the `info` pointer is null, `argc` is
/// negative, or `argv` is null while `argc` is positive.
pub fn validate_install_boundary(
    info: *const QemuPluginInfo,
    argc: c_int,
    argv: *mut *mut c_char,
) -> Result<(), QemuPluginAbiError> {
    if info.is_null() {
        return Err(QemuPluginAbiError::MissingInfo);
    }
    if argc < 0 {
        return Err(QemuPluginAbiError::NegativeArgc { argc });
    }
    if argc > 0 && argv.is_null() {
        return Err(QemuPluginAbiError::MissingArgv { argc });
    }
    Ok(())
}

/// Parses the QEMU plugin argument vector into Crucible's typed launch args.
///
/// QEMU exposes comma-separated `-plugin` options to plugins as an argument
/// vector. This helper accepts both QEMU's split vector form and the testable
/// single-string form by joining argv entries with commas before feeding the
/// existing fail-closed parser.
///
/// # Errors
///
/// Returns [`QemuPluginAbiError`] when `argc`/`argv` violate the raw ABI
/// boundary, an argv entry is null or non-UTF-8, or the parsed plugin arguments
/// omit required Crucible keys such as `simfd` and `slot`.
///
/// # Safety
///
/// For positive `argc`, `argv` must point to at least `argc` live pointers to
/// NUL-terminated C strings for the duration of this call. Null pointer shapes
/// are rejected, but pointer provenance and allocation extent cannot be checked.
pub(crate) unsafe fn parse_install_plugin_args(
    argc: c_int,
    argv: *mut *mut c_char,
) -> Result<PluginArgs, QemuPluginAbiError> {
    if argc < 0 {
        return Err(QemuPluginAbiError::NegativeArgc { argc });
    }
    if argc > 0 && argv.is_null() {
        return Err(QemuPluginAbiError::MissingArgv { argc });
    }

    let argc = usize::try_from(argc).map_err(|_error| QemuPluginAbiError::NegativeArgc { argc })?;
    if argc == 0 {
        return Err(QemuPluginAbiError::PluginArgs {
            source: PluginArgsParseError::MissingRequiredKey {
                key: PLUGIN_ARG_SIMFD,
            },
        });
    }

    let mut raw_args = Vec::with_capacity(argc);
    for index in 0..argc {
        let arg = unsafe {
            // SAFETY: `argv` is non-null for positive `argc`, and QEMU provides
            // at least `argc` entries for the duration of `qemu_plugin_install`.
            *argv.add(index)
        };
        if arg.is_null() {
            return Err(QemuPluginAbiError::NullArgvEntry { index });
        }
        let arg = unsafe {
            // SAFETY: QEMU plugin argv entries are NUL-terminated C strings.
            CStr::from_ptr(arg)
        };
        let arg = arg
            .to_str()
            .map_err(|_error| QemuPluginAbiError::InvalidArgvUtf8 { index })?;
        raw_args.push(arg);
    }

    PluginArgs::parse(&raw_args.join(","))
        .map_err(|source| QemuPluginAbiError::PluginArgs { source })
}

/// Extracts and validates the execution model from QEMU install information.
///
/// # Errors
///
/// Returns [`QemuPluginAbiError::UnsupportedPluginApi`] when QEMU's API range
/// excludes [`QEMU_PLUGIN_API_VERSION`]. Returns
/// [`QemuPluginAbiError::NoVcpus`] or
/// [`QemuPluginAbiError::MultiThreadedTcg`] when the execution model violates
/// the plugin's single-threaded round-robin TCG contract.
fn execution_model_from_qemu_info(
    info: &QemuPluginInfo,
    threading: QemuTcgThreading,
) -> Result<QemuPluginExecutionModel, QemuPluginAbiError> {
    validate_qemu_plugin_api_range(info)?;
    if !info.system_emulation {
        return Err(QemuPluginAbiError::NotSystemEmulation);
    }
    let smp_vcpus =
        u32::try_from(info.system.smp_vcpus).map_err(|_error| QemuPluginAbiError::NoVcpus)?;
    QemuPluginExecutionModel::validate(smp_vcpus, threading)
}

/// Required QEMU exports admitted by the sole runtime installation path.
#[derive(Clone, Copy)]
pub(crate) struct RequiredRuntimeApiSymbols {
    pub(crate) clock_deadline_ns: Option<QemuClockDeadlineFn>,
    pub(crate) advance_time_ticks: Option<QemuAdvanceTimeTicksFn>,
    pub(crate) inject_preemption: Option<QemuInjectPreemptionFn>,
    pub(crate) read_vcpu_regs: Option<QemuReadVcpuRegsFn>,
    pub(crate) read_rr_cursor: Option<QemuReadRrCursorFn>,
    pub(crate) icount_raw: Option<QemuIcountRawFn>,
    pub(crate) force_vcpu_exit: Option<QemuForceVcpuExitFn>,
    pub(crate) wait_idle_wake: Option<crate::QemuCrucibleWaitIdleWakeFn>,
    pub(crate) register_wake_fd: Option<QemuRegisterWakeFdFn>,
}

/// Builds runtime state after requiring every deterministic QEMU export.
///
/// # Errors
///
/// Returns [`QemuPluginAbiError`] when any required deterministic plugin export
/// or runtime API export is unavailable.
pub(crate) fn admit_required_runtime_apis(
    symbols: RequiredRuntimeApiSymbols,
) -> Result<PluginRuntimeApis, QemuPluginAbiError> {
    let _exact_deadline_reader = ExactDeadlineReader::require(symbols.clock_deadline_ns)
        .map_err(|source| QemuPluginAbiError::ExactDeadlineCapability { source })?;
    let _queued_idle_advance = QueuedIdleAdvance::require(symbols.advance_time_ticks)
        .map_err(|source| QemuPluginAbiError::QueuedIdleAdvanceCapability { source })?;
    let _preemption_injector = PluginPreemptionInjector::require(symbols.inject_preemption)
        .map_err(|source| QemuPluginAbiError::PreemptionInjectionCapability { source })?;
    let _vcpu_introspector =
        PluginVcpuIntrospector::require(symbols.read_vcpu_regs, symbols.read_rr_cursor)
            .map_err(|source| QemuPluginAbiError::VcpuIntrospectionCapability { source })?;
    let runtime_apis = PluginRuntimeApis::require(
        symbols.icount_raw,
        symbols.force_vcpu_exit,
        symbols.wait_idle_wake,
        symbols.register_wake_fd,
    )?;

    Ok(runtime_apis)
}

/// Resolves QEMU's required exact-deadline export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_clock_deadline_symbol() -> Option<QemuClockDeadlineFn> {
    // SAFETY: The symbol name is a static NUL-terminated byte string. `dlsym`
    // returns either null or a process symbol address. QEMU's patch defines this
    // symbol with the exact `extern "C" fn() -> i64` ABI used by
    // `QemuClockDeadlineFn`; callers fail closed when the symbol is absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_CLOCK_DEADLINE_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for
        // `qemu_plugin_clock_deadline_ns`, whose patched QEMU declaration is
        // `int64_t qemu_plugin_clock_deadline_ns(void)`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuClockDeadlineFn>(symbol) })
    }
}

/// Resolves QEMU's required exact-deadline export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_clock_deadline_symbol() -> Option<QemuClockDeadlineFn> {
    None
}

/// Resolves QEMU's required queued idle-advance export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_advance_time_ticks_symbol() -> Option<QemuAdvanceTimeTicksFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. QEMU's patch defines this symbol
    // with the exact `extern "C" fn(i64) -> c_int` ABI used by
    // `QemuAdvanceTimeTicksFn`; callers fail closed when absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_ADVANCE_TIME_TICKS_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for
        // `qemu_plugin_advance_time_ticks`, whose patched QEMU
        // declaration is `int qemu_plugin_advance_time_ticks(int64_t)`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuAdvanceTimeTicksFn>(symbol) })
    }
}

/// Resolves QEMU's required queued idle-advance export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_advance_time_ticks_symbol() -> Option<QemuAdvanceTimeTicksFn> {
    None
}

/// Resolves QEMU's required queued-advance completion registration export.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_register_time_advance_cb_symbol() -> Option<QemuRegisterTimeAdvanceCbFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. QEMU's patch defines this symbol
    // with the exact `extern "C"` registration ABI used by
    // `QemuRegisterTimeAdvanceCbFn`; callers fail closed when absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_REGISTER_TIME_ADVANCE_CB_SYMBOL_C
                .as_ptr()
                .cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for
        // `qemu_plugin_register_time_advance_cb`, whose patched QEMU declaration
        // accepts the matching callback and userdata pointer and returns `int`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuRegisterTimeAdvanceCbFn>(symbol) })
    }
}

/// Resolves QEMU's required virtual-timer witness arm export.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_arm_virtual_timer_witness_symbol() -> Option<QemuArmVirtualTimerWitnessFn> {
    // SAFETY: the static name is NUL-terminated. A non-null symbol is interpreted
    // with the exact patched-QEMU declaration documented by the Rust type.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_CRUCIBLE_ARM_VIRTUAL_TIMER_WITNESS_SYMBOL_C
                .as_ptr()
                .cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: patched QEMU exports this exact C function signature.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuArmVirtualTimerWitnessFn>(symbol) })
    }
}

/// Resolves QEMU's required virtual-timer witness arm export.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_arm_virtual_timer_witness_symbol() -> Option<QemuArmVirtualTimerWitnessFn>
{
    None
}

/// Resolves QEMU's required completed virtual-timer witness query export.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_query_virtual_timer_witness_symbol() -> Option<QemuQueryVirtualTimerWitnessFn> {
    // SAFETY: the static name is NUL-terminated. A non-null symbol is interpreted
    // with the exact patched-QEMU declaration documented by the Rust type.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_CRUCIBLE_QUERY_VIRTUAL_TIMER_WITNESS_SYMBOL_C
                .as_ptr()
                .cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: patched QEMU exports this exact C function signature.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuQueryVirtualTimerWitnessFn>(symbol) })
    }
}

/// Resolves QEMU's required completed virtual-timer witness query export.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_query_virtual_timer_witness_symbol()
-> Option<QemuQueryVirtualTimerWitnessFn> {
    None
}

/// Resolves QEMU's required queued-advance completion registration export.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_register_time_advance_cb_symbol() -> Option<QemuRegisterTimeAdvanceCbFn> {
    None
}

/// Resolves QEMU's one-shot idle wake wait from the loaded process.
#[cfg(unix)]
#[must_use]
pub(crate) fn resolve_qemu_crucible_wait_idle_wake_symbol()
-> Option<crate::QemuCrucibleWaitIdleWakeFn> {
    // SAFETY: dlsym receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. Patched QEMU declares this name
    // with the exact QemuCrucibleWaitIdleWakeFn ABI.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_CRUCIBLE_WAIT_IDLE_WAKE_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: the non-null symbol was resolved under the exact exported
        // name whose C declaration matches QemuCrucibleWaitIdleWakeFn.
        Some(unsafe {
            std::mem::transmute::<*mut c_void, crate::QemuCrucibleWaitIdleWakeFn>(symbol)
        })
    }
}

/// Resolves no QEMU idle wake wait outside Unix QEMU environments.
#[cfg(not(unix))]
#[must_use]
pub(crate) const fn resolve_qemu_crucible_wait_idle_wake_symbol()
-> Option<crate::QemuCrucibleWaitIdleWakeFn> {
    None
}

/// Resolves QEMU's required commanded-preemption export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_inject_preemption_symbol() -> Option<QemuInjectPreemptionFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. QEMU's patch defines this symbol
    // with the exact
    // `extern "C" fn(u64, u64, u64, c_uint, u32, u32, u32) -> c_int` ABI used
    // by `QemuInjectPreemptionFn`; callers fail closed when absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_INJECT_PREEMPTION_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for
        // `qemu_plugin_inject_preemption`, whose patched QEMU declaration
        // matches `QemuInjectPreemptionFn`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuInjectPreemptionFn>(symbol) })
    }
}

/// Resolves QEMU's required commanded-preemption export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_inject_preemption_symbol() -> Option<QemuInjectPreemptionFn> {
    None
}

/// Resolves QEMU's required per-vCPU register export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_read_vcpu_regs_symbol() -> Option<QemuReadVcpuRegsFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. QEMU's patch defines this symbol
    // with the exact `QemuReadVcpuRegsFn` ABI used by the safe wrapper; callers
    // fail closed when absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_READ_VCPU_REGS_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for `qemu_plugin_read_vcpu_regs`,
        // whose patched QEMU declaration matches `QemuReadVcpuRegsFn`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuReadVcpuRegsFn>(symbol) })
    }
}

/// Resolves QEMU's required per-vCPU register export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_read_vcpu_regs_symbol() -> Option<QemuReadVcpuRegsFn> {
    None
}

/// Resolves QEMU's required round-robin cursor export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_rr_cursor_symbol() -> Option<QemuReadRrCursorFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. QEMU's patch defines this symbol
    // with the exact `QemuReadRrCursorFn` ABI used by the safe wrapper; callers
    // fail closed when absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_RR_CURSOR_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for `qemu_plugin_rr_cursor`,
        // whose patched QEMU declaration matches `QemuReadRrCursorFn`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuReadRrCursorFn>(symbol) })
    }
}

/// Resolves QEMU's required round-robin cursor export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_rr_cursor_symbol() -> Option<QemuReadRrCursorFn> {
    None
}

/// Resolves QEMU's raw-icount read export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_icount_raw_symbol() -> Option<QemuIcountRawFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. QEMU's patch defines this symbol
    // with the exact `extern "C" fn() -> u64` ABI used by
    // `QemuIcountRawFn`; callers fail closed when absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_ICOUNT_RAW_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for `qemu_plugin_icount_raw`,
        // whose patched QEMU declaration is `uint64_t qemu_plugin_icount_raw(void)`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuIcountRawFn>(symbol) })
    }
}

/// Resolves QEMU's raw-icount read export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_icount_raw_symbol() -> Option<QemuIcountRawFn> {
    None
}

/// Resolves QEMU's current-vCPU exit export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_force_vcpu_exit_symbol() -> Option<QemuForceVcpuExitFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. QEMU's patch defines this symbol
    // with the exact `extern "C" fn()` ABI used by `QemuForceVcpuExitFn`;
    // callers fail closed when absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_FORCE_VCPU_EXIT_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for
        // `qemu_plugin_force_vcpu_exit`, whose patched QEMU declaration is
        // `void qemu_plugin_force_vcpu_exit(void)`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuForceVcpuExitFn>(symbol) })
    }
}

/// Resolves QEMU's current-vCPU exit export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_force_vcpu_exit_symbol() -> Option<QemuForceVcpuExitFn> {
    None
}

/// Resolves QEMU's native VM-stop request export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_request_vmstop_symbol() -> Option<QemuRequestVmstopFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name. The QEMU
    // patch defines the symbol with the exact `extern "C" fn() -> c_int` ABI.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_REQUEST_VMSTOP_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: the non-null symbol has the declaration documented above.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuRequestVmstopFn>(symbol) })
    }
}

/// Resolves QEMU's native VM-stop request export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_request_vmstop_symbol() -> Option<QemuRequestVmstopFn> {
    None
}

/// Resolves QEMU's immutable process-generation provisioning export.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_set_process_generation_symbol() -> Option<QemuSetProcessGenerationFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name. The QEMU
    // patch exports the exact `extern "C" fn(u64) -> c_int` ABI.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_SET_PROCESS_GENERATION_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: the non-null symbol has the declaration documented above.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuSetProcessGenerationFn>(symbol) })
    }
}

/// Resolves QEMU's immutable process-generation provisioning export.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_set_process_generation_symbol() -> Option<QemuSetProcessGenerationFn> {
    None
}

/// Resolves QEMU's wake-fd registration export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_register_wake_fd_symbol() -> Option<QemuRegisterWakeFdFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. QEMU's patch defines this symbol
    // with the exact `extern "C" fn(c_int) -> c_int` ABI used by
    // `QemuRegisterWakeFdFn`; callers fail closed when absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_REGISTER_WAKE_FD_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for
        // `qemu_plugin_register_wake_fd`, whose patched QEMU declaration is
        // `int qemu_plugin_register_wake_fd(int)`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuRegisterWakeFdFn>(symbol) })
    }
}

/// Resolves QEMU's wake-fd registration export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_register_wake_fd_symbol() -> Option<QemuRegisterWakeFdFn> {
    None
}

/// Resolves QEMU's fixed plugin resource-manifest registration export.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_register_resource_manifest_symbol() -> Option<QemuRegisterResourceManifestFn> {
    let symbol = resolve_process_symbol(QEMU_PLUGIN_REGISTER_RESOURCE_MANIFEST_SYMBOL_C);
    if symbol.is_null() {
        None
    } else {
        // SAFETY: the non-null address was resolved by the exact patched-QEMU
        // symbol whose C structure and return type match this ABI declaration.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuRegisterResourceManifestFn>(symbol) })
    }
}

/// Returns no resource-manifest registration export on non-Unix hosts.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_register_resource_manifest_symbol()
-> Option<QemuRegisterResourceManifestFn> {
    None
}

/// Resolves QEMU's reversible hot-fork callback-barrier registration export.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_register_hot_fork_barrier_symbol() -> Option<QemuRegisterHotForkBarrierFn> {
    let symbol = resolve_process_symbol(QEMU_PLUGIN_REGISTER_HOT_FORK_BARRIER_SYMBOL_C);
    if symbol.is_null() {
        None
    } else {
        // SAFETY: the non-null address was resolved by the exact patched-QEMU
        // symbol whose callback and argument types match this ABI declaration.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuRegisterHotForkBarrierFn>(symbol) })
    }
}

/// Returns no hot-fork barrier registration export on non-Unix hosts.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_register_hot_fork_barrier_symbol() -> Option<QemuRegisterHotForkBarrierFn>
{
    None
}

/// Resolves QEMU's fork-child runtime registration export.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_register_hot_fork_child_runtime_symbol()
-> Option<QemuRegisterHotForkChildRuntimeFn> {
    let symbol = resolve_process_symbol(QEMU_PLUGIN_REGISTER_HOT_FORK_CHILD_RUNTIME_SYMBOL_C);
    if symbol.is_null() {
        None
    } else {
        // SAFETY: the non-null address was resolved by the exact patched-QEMU
        // symbol whose callback and argument types match this ABI declaration.
        Some(unsafe {
            std::mem::transmute::<*mut c_void, QemuRegisterHotForkChildRuntimeFn>(symbol)
        })
    }
}

/// Returns no fork-child runtime registration export on non-Unix hosts.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_register_hot_fork_child_runtime_symbol()
-> Option<QemuRegisterHotForkChildRuntimeFn> {
    None
}

/// Resolves QEMU's plugin-initiated shutdown export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_request_shutdown_symbol() -> Option<QemuRequestShutdownFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or the patched QEMU function declared as `void (int)`.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_REQUEST_SHUTDOWN_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: the non-null address was resolved by the exact QEMU export
        // name whose C argument and return types match this Rust alias.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuRequestShutdownFn>(symbol) })
    }
}

/// Resolves QEMU's plugin-initiated shutdown export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_request_shutdown_symbol() -> Option<QemuRequestShutdownFn> {
    None
}

#[cfg(unix)]
fn resolve_process_symbol(symbol_name: &'static [u8]) -> *mut c_void {
    // SAFETY: every caller supplies a static NUL-terminated symbol name. The
    // returned address is checked for null and converted only to the exact ABI
    // type declared by QEMU 11's public plugin header.
    unsafe { libc::dlsym(libc::RTLD_DEFAULT, symbol_name.as_ptr().cast()) }
}

/// Resolves the complete QEMU API for live basic-block coverage.
///
/// # Errors
///
/// Returns [`QemuPluginAbiError::RuntimeApiCapability`] when any required
/// translation, execution, metadata, exact-icount, or flush symbol is absent.
#[cfg(unix)]
pub(crate) fn resolve_qemu_basic_block_coverage_apis()
-> Result<crate::QemuBasicBlockCoverageApis, QemuPluginAbiError> {
    let register_tb_trans_cb =
        resolve_process_symbol(QEMU_PLUGIN_REGISTER_VCPU_TB_TRANS_CB_SYMBOL_C);
    let register_tb_exec_cond_cb =
        resolve_process_symbol(QEMU_PLUGIN_REGISTER_VCPU_TB_EXEC_COND_CB_SYMBOL_C);
    let tb_vaddr = resolve_process_symbol(QEMU_PLUGIN_TB_VADDR_SYMBOL_C);
    let tb_n_insns = resolve_process_symbol(QEMU_PLUGIN_TB_N_INSNS_SYMBOL_C);
    let tb_get_insn = resolve_process_symbol(QEMU_PLUGIN_TB_GET_INSN_SYMBOL_C);
    let insn_size = resolve_process_symbol(QEMU_PLUGIN_INSN_SIZE_SYMBOL_C);
    let icount_at_tb_entry = resolve_process_symbol(QEMU_PLUGIN_ICOUNT_AT_TB_ENTRY_SYMBOL_C);
    let register_flush_cb = resolve_process_symbol(QEMU_PLUGIN_REGISTER_FLUSH_CB_SYMBOL_C);
    let scoreboard_new = resolve_process_symbol(QEMU_PLUGIN_SCOREBOARD_NEW_SYMBOL_C);
    let scoreboard_free = resolve_process_symbol(QEMU_PLUGIN_SCOREBOARD_FREE_SYMBOL_C);
    let u64_set = resolve_process_symbol(QEMU_PLUGIN_U64_SET_SYMBOL_C);
    let num_vcpus = resolve_process_symbol(QEMU_PLUGIN_NUM_VCPUS_SYMBOL_C);
    let require = |symbol: *mut c_void, name| {
        if symbol.is_null() {
            Err(QemuPluginAbiError::RuntimeApiCapability { symbol: name })
        } else {
            Ok(symbol)
        }
    };
    let register_tb_trans_cb = require(
        register_tb_trans_cb,
        crate::QEMU_PLUGIN_REGISTER_VCPU_TB_TRANS_CB_SYMBOL,
    )?;
    let register_tb_exec_cond_cb = require(
        register_tb_exec_cond_cb,
        crate::QEMU_PLUGIN_REGISTER_VCPU_TB_EXEC_COND_CB_SYMBOL,
    )?;
    let tb_vaddr = require(tb_vaddr, crate::QEMU_PLUGIN_TB_VADDR_SYMBOL)?;
    let tb_n_insns = require(tb_n_insns, crate::QEMU_PLUGIN_TB_N_INSNS_SYMBOL)?;
    let tb_get_insn = require(tb_get_insn, crate::QEMU_PLUGIN_TB_GET_INSN_SYMBOL)?;
    let insn_size = require(insn_size, crate::QEMU_PLUGIN_INSN_SIZE_SYMBOL)?;
    let icount_at_tb_entry = require(
        icount_at_tb_entry,
        crate::QEMU_PLUGIN_ICOUNT_AT_TB_ENTRY_SYMBOL,
    )?;
    let register_flush_cb = require(
        register_flush_cb,
        crate::QEMU_PLUGIN_REGISTER_FLUSH_CB_SYMBOL,
    )?;
    let scoreboard_new = require(scoreboard_new, crate::QEMU_PLUGIN_SCOREBOARD_NEW_SYMBOL)?;
    let scoreboard_free = require(scoreboard_free, crate::QEMU_PLUGIN_SCOREBOARD_FREE_SYMBOL)?;
    let u64_set = require(u64_set, crate::QEMU_PLUGIN_U64_SET_SYMBOL)?;
    let num_vcpus = require(num_vcpus, crate::QEMU_PLUGIN_NUM_VCPUS_SYMBOL)?;

    // SAFETY: all non-null addresses were resolved by their exact QEMU 11.1.1
    // public-plugin symbol names and are converted to matching `extern "C"`
    // function-pointer types.
    Ok(unsafe {
        crate::QemuBasicBlockCoverageApis::new(
            std::mem::transmute::<*mut c_void, crate::QemuRegisterVcpuTbTransCbFn>(
                register_tb_trans_cb,
            ),
            std::mem::transmute::<*mut c_void, crate::QemuRegisterVcpuTbExecCondCbFn>(
                register_tb_exec_cond_cb,
            ),
            std::mem::transmute::<*mut c_void, crate::QemuTbVaddrFn>(tb_vaddr),
            std::mem::transmute::<*mut c_void, crate::QemuTbNInsnsFn>(tb_n_insns),
            std::mem::transmute::<*mut c_void, crate::QemuTbGetInsnFn>(tb_get_insn),
            std::mem::transmute::<*mut c_void, crate::QemuInsnSizeFn>(insn_size),
            std::mem::transmute::<*mut c_void, crate::QemuIcountAtTbEntryFn>(icount_at_tb_entry),
            std::mem::transmute::<*mut c_void, crate::QemuRegisterFlushCbFn>(register_flush_cb),
            std::mem::transmute::<*mut c_void, crate::QemuPluginScoreboardNewFn>(scoreboard_new),
            std::mem::transmute::<*mut c_void, crate::QemuPluginScoreboardFreeFn>(scoreboard_free),
            std::mem::transmute::<*mut c_void, crate::QemuPluginU64SetFn>(u64_set),
            std::mem::transmute::<*mut c_void, crate::QemuPluginNumVcpusFn>(num_vcpus),
        )
    })
}

/// Reports that live basic-block coverage is unavailable off Unix.
///
/// # Errors
///
/// Always returns [`QemuPluginAbiError::RuntimeApiCapability`] because the
/// process-symbol lookup used by the live QEMU plugin is Unix-only.
#[cfg(not(unix))]
pub(crate) const fn resolve_qemu_basic_block_coverage_apis()
-> Result<crate::QemuBasicBlockCoverageApis, QemuPluginAbiError> {
    Err(QemuPluginAbiError::RuntimeApiCapability {
        symbol: crate::QEMU_PLUGIN_REGISTER_VCPU_TB_TRANS_CB_SYMBOL,
    })
}

/// Resolves QEMU's shmem block callback registration export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_register_blk_cb_symbol() -> Option<QemuRegisterBlkCbFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. QEMU's patch defines this symbol
    // with the exact `QemuRegisterBlkCbFn` ABI; callers fail closed when absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_REGISTER_BLK_CB_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for
        // `qemu_plugin_register_blk_cb`, whose patched QEMU declaration
        // matches `QemuRegisterBlkCbFn`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuRegisterBlkCbFn>(symbol) })
    }
}

/// Resolves QEMU's shmem block callback registration export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_register_blk_cb_symbol() -> Option<QemuRegisterBlkCbFn> {
    None
}

/// Resolves QEMU's asynchronous block transport-event registration export.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_register_blk_event_cb_symbol() -> Option<QemuRegisterBlkEventCbFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name. The atomic
    // Crucible integration patch exports this exact function-pointer ABI, and
    // live install fails closed if the symbol is absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_REGISTER_BLK_EVENT_CB_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: the non-null symbol has the exact patched-QEMU declaration
        // represented by `QemuRegisterBlkEventCbFn`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuRegisterBlkEventCbFn>(symbol) })
    }
}

/// Reports that asynchronous block event registration is unavailable off Unix.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_register_blk_event_cb_symbol() -> Option<QemuRegisterBlkEventCbFn> {
    None
}

/// Resolves QEMU's shmem block device-wait registration export.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_register_blk_wait_cb_symbol() -> Option<QemuRegisterBlkWaitCbFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. The atomic Crucible integration
    // patch defines the exact `QemuRegisterBlkWaitCbFn` ABI; callers fail closed
    // when it is absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_REGISTER_BLK_WAIT_CB_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: the non-null address is the exact block-wait registration
        // symbol whose C declaration matches `QemuRegisterBlkWaitCbFn`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuRegisterBlkWaitCbFn>(symbol) })
    }
}

/// Reports that QEMU's shmem block device-wait registration is unavailable.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_register_blk_wait_cb_symbol() -> Option<QemuRegisterBlkWaitCbFn> {
    None
}

/// Resolves QEMU's deterministic accelerator registration export.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_register_accelerator_cb_symbol() -> Option<QemuRegisterAcceleratorCbFn> {
    // SAFETY: the static name is NUL terminated; the atomic Crucible
    // integration patch exports the exact C declaration represented by
    // `QemuRegisterAcceleratorCbFn`.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_REGISTER_ACCELERATOR_CB_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: the resolved non-null symbol has the exact patched-QEMU ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuRegisterAcceleratorCbFn>(symbol) })
    }
}

/// Reports that accelerator registration is unavailable off Unix.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_register_accelerator_cb_symbol() -> Option<QemuRegisterAcceleratorCbFn> {
    None
}

/// Resolves QEMU's shmem 9p callback registration export from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_register_9p_cb_symbol() -> Option<QemuRegisterNinePCbFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. QEMU's patch defines this symbol
    // with the exact `QemuRegisterNinePCbFn` ABI; callers fail closed when absent.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_REGISTER_9P_CB_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: Non-null `symbol` was resolved for
        // `qemu_plugin_register_9p_cb`, whose patched QEMU declaration
        // matches `QemuRegisterNinePCbFn`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuRegisterNinePCbFn>(symbol) })
    }
}

/// Resolves QEMU's shmem 9p callback registration export from the loaded process.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_register_9p_cb_symbol() -> Option<QemuRegisterNinePCbFn> {
    None
}

/// Resolves QEMU's standard vCPU-init callback registration export.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_register_vcpu_init_cb_symbol() -> Option<QemuRegisterVcpuInitCbFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. QEMU 11.1.1 declares this name
    // with the exact `QemuRegisterVcpuInitCbFn` ABI.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_REGISTER_VCPU_INIT_CB_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: the non-null address was resolved by the exact standard QEMU
        // API name whose declaration matches `QemuRegisterVcpuInitCbFn`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuRegisterVcpuInitCbFn>(symbol) })
    }
}

/// Resolves no vCPU-init registration export outside Unix QEMU environments.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_register_vcpu_init_cb_symbol() -> Option<QemuRegisterVcpuInitCbFn> {
    None
}

/// Resolves QEMU's Crucible all-idle/resume callback registration export.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_register_vcpu_idle_resume_cb_symbol() -> Option<QemuRegisterVcpuIdleResumeCbFn>
{
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name. The
    // Crucible patch declares this symbol with the exact callback ABI above.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_REGISTER_VCPU_IDLE_RESUME_CB_SYMBOL_C
                .as_ptr()
                .cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: the exact patched API name establishes the function type.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuRegisterVcpuIdleResumeCbFn>(symbol) })
    }
}

/// Resolves no all-idle/resume registration export outside Unix QEMU environments.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_register_vcpu_idle_resume_cb_symbol()
-> Option<QemuRegisterVcpuIdleResumeCbFn> {
    None
}

/// Resolves QEMU's exact drained-control-boundary callback registration export.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_register_control_boundary_cb_symbol() -> Option<QemuRegisterControlBoundaryCbFn>
{
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name. The
    // Crucible patch declares this symbol with the exact callback ABI above.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_REGISTER_CONTROL_BOUNDARY_CB_SYMBOL_C
                .as_ptr()
                .cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: the exact patched API name establishes the function type.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuRegisterControlBoundaryCbFn>(symbol) })
    }
}

/// Resolves no control-boundary registration export outside Unix QEMU environments.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_register_control_boundary_cb_symbol()
-> Option<QemuRegisterControlBoundaryCbFn> {
    None
}

/// Resolves QEMU's sim-loop shared-memory dispatch registration export.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_register_sim_shmem_dispatch_cb_symbol()
-> Option<QemuRegisterSimShmemDispatchCbFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name. The
    // Crucible patch declares this symbol with the exact callback ABI above.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_REGISTER_SIM_SHMEM_DISPATCH_CB_SYMBOL_C
                .as_ptr()
                .cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: the exact patched API name establishes the function type.
        Some(unsafe {
            std::mem::transmute::<*mut c_void, QemuRegisterSimShmemDispatchCbFn>(symbol)
        })
    }
}

/// Resolves no sim-loop shmem registration export outside Unix QEMU environments.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_register_sim_shmem_dispatch_cb_symbol()
-> Option<QemuRegisterSimShmemDispatchCbFn> {
    None
}

/// Resolves QEMU's virtual-time ownership request from the loaded process.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_request_time_control_symbol() -> Option<QemuRequestTimeControlFn> {
    // SAFETY: `dlsym` receives a static NUL-terminated symbol name and returns
    // either null or a process symbol address. QEMU declares this symbol as a
    // no-argument function returning a borrowed opaque pointer.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_REQUEST_TIME_CONTROL_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: the non-null symbol was resolved by its exact QEMU API name,
        // whose declaration is `const void *qemu_plugin_request_time_control(void)`.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuRequestTimeControlFn>(symbol) })
    }
}

/// Resolves no time-control request outside Unix QEMU plugin environments.
#[cfg(not(unix))]
#[must_use]
pub const fn resolve_qemu_request_time_control_symbol() -> Option<QemuRequestTimeControlFn> {
    None
}

/// Resolves QEMU's observable single-threaded round-robin mode proof.
#[cfg(unix)]
#[must_use]
pub fn resolve_qemu_single_threaded_rr_symbol() -> Option<QemuSingleThreadedRrFn> {
    // SAFETY: the symbol name is static and NUL-terminated. A non-null result
    // is invoked only with the required `int fn(void)` ABI.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            QEMU_PLUGIN_SINGLE_THREADED_RR_SYMBOL_C.as_ptr().cast(),
        )
    };
    if symbol.is_null() {
        None
    } else {
        // SAFETY: the required export has the exact ABI above.
        Some(unsafe { std::mem::transmute::<*mut c_void, QemuSingleThreadedRrFn>(symbol) })
    }
}

#[cfg(not(unix))]
const fn resolve_qemu_single_threaded_rr_symbol() -> Option<QemuSingleThreadedRrFn> {
    None
}

fn observed_execution_model<F>(
    info: &QemuPluginInfo,
    resolve_single_threaded_rr: F,
) -> Result<QemuPluginExecutionModel, QemuPluginAbiError>
where
    F: FnOnce() -> Option<QemuSingleThreadedRrFn>,
{
    let execution_model =
        execution_model_from_qemu_info(info, QemuTcgThreading::SingleThreadedRoundRobin)?;
    let single_threaded_rr =
        resolve_single_threaded_rr().ok_or(QemuPluginAbiError::RuntimeApiCapability {
            symbol: QEMU_PLUGIN_SINGLE_THREADED_RR_SYMBOL,
        })?;
    if single_threaded_rr() != 1 {
        return Err(QemuPluginAbiError::MultiThreadedTcg);
    }
    Ok(execution_model)
}

/// Duplicates the inherited control descriptor into an owned Unix stream.
///
/// # Errors
///
/// Returns the operating-system error from `fcntl(F_DUPFD_CLOEXEC)` when the
/// inherited descriptor is invalid or cannot be duplicated.
#[cfg(unix)]
pub(crate) fn duplicate_control_stream(fd: c_int) -> std::io::Result<UnixStream> {
    // SAFETY: `fcntl(F_DUPFD_CLOEXEC)` accepts an integer descriptor and either
    // fails without creating a resource or returns a new live owned descriptor.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a successful `F_DUPFD_CLOEXEC` return is a new descriptor whose
    // ownership is transferred exactly once into `OwnedFd`.
    let owned = unsafe { OwnedFd::from_raw_fd(duplicate) };
    Ok(UnixStream::from(owned))
}

#[cfg(unix)]
struct OwnedInstallBoundary {
    args: PluginArgs,
    execution_model: QemuPluginExecutionModel,
    target_architecture: QemuPluginTargetArchitecture,
}

#[cfg(unix)]
/// Copies QEMU-owned install inputs into process-owned Rust values.
///
/// # Safety
///
/// `info` and the positive-length `argv` vector must satisfy the same lifetime,
/// layout, and NUL-termination contract as [`qemu_plugin_install`].
unsafe fn copy_install_boundary(
    info: *const QemuPluginInfo,
    argc: c_int,
    argv: *mut *mut c_char,
) -> Result<OwnedInstallBoundary, QemuPluginAbiError> {
    validate_install_boundary(info, argc, argv)?;
    // SAFETY: the caller guarantees the positive-length QEMU argument vector is
    // live and contains NUL-terminated entries for this install call.
    let args = unsafe { parse_install_plugin_args(argc, argv) }?;
    // SAFETY: boundary shape validation rejected null. QEMU's plugin ABI
    // guarantees a live info object; only scalar data is copied into owned state.
    let info = unsafe { &*info };
    let execution_model = observed_execution_model(info, resolve_qemu_single_threaded_rr_symbol)?;
    let target_architecture = target_architecture_from_qemu_info(info)?;
    Ok(OwnedInstallBoundary {
        args,
        execution_model,
        target_architecture,
    })
}

fn target_architecture_from_qemu_info(
    info: &QemuPluginInfo,
) -> Result<QemuPluginTargetArchitecture, QemuPluginAbiError> {
    if info.target_name.is_null() {
        return Err(QemuPluginAbiError::MissingTargetName);
    }
    // SAFETY: QEMU guarantees `target_name` is a live NUL-terminated string for
    // the duration of the install callback.
    let target = unsafe { CStr::from_ptr(info.target_name) }
        .to_str()
        .map_err(|_source| QemuPluginAbiError::InvalidTargetNameUtf8)?;
    match target {
        "x86_64" => Ok(QemuPluginTargetArchitecture::X86_64),
        "aarch64" => Ok(QemuPluginTargetArchitecture::Aarch64),
        _ => Err(QemuPluginAbiError::UnsupportedTargetArchitecture {
            target: target.to_owned(),
        }),
    }
}

#[cfg(unix)]
fn install_owned_boundary(
    plugin_id: QemuPluginId,
    boundary: OwnedInstallBoundary,
    reservation: &mut crate::runtime::PluginRuntimeReservation,
) -> Result<crate::PluginRuntimeOwner, crate::runtime::PluginLiveBoundaryError> {
    let clock_deadline_ns = resolve_qemu_clock_deadline_symbol();
    let advance_time_ticks = resolve_qemu_advance_time_ticks_symbol();
    let register_time_advance_cb = resolve_qemu_register_time_advance_cb_symbol();
    let arm_virtual_timer_witness = resolve_qemu_arm_virtual_timer_witness_symbol();
    let query_virtual_timer_witness = resolve_qemu_query_virtual_timer_witness_symbol();
    let inject_preemption = resolve_qemu_inject_preemption_symbol();
    let read_vcpu_regs = resolve_qemu_read_vcpu_regs_symbol();
    let read_rr_cursor = resolve_qemu_rr_cursor_symbol();
    let icount_raw = resolve_qemu_icount_raw_symbol();
    let force_vcpu_exit = resolve_qemu_force_vcpu_exit_symbol();
    let wait_idle_wake = resolve_qemu_crucible_wait_idle_wake_symbol();
    let request_vmstop = resolve_qemu_request_vmstop_symbol();
    let register_wake_fd = resolve_qemu_register_wake_fd_symbol();
    let register_resource_manifest = require_runtime_api(
        resolve_qemu_register_resource_manifest_symbol(),
        QEMU_PLUGIN_REGISTER_RESOURCE_MANIFEST_SYMBOL,
    )?;
    let register_hot_fork_barrier = require_runtime_api(
        resolve_qemu_register_hot_fork_barrier_symbol(),
        QEMU_PLUGIN_REGISTER_HOT_FORK_BARRIER_SYMBOL,
    )?;
    let register_hot_fork_child_runtime = require_runtime_api(
        resolve_qemu_register_hot_fork_child_runtime_symbol(),
        QEMU_PLUGIN_REGISTER_HOT_FORK_CHILD_RUNTIME_SYMBOL,
    )?;
    let request_shutdown = resolve_qemu_request_shutdown_symbol();
    let set_process_generation = resolve_qemu_set_process_generation_symbol();
    let register_vcpu_init = resolve_qemu_register_vcpu_init_cb_symbol();
    let register_vcpu_idle_resume = resolve_qemu_register_vcpu_idle_resume_cb_symbol();
    let register_control_boundary = resolve_qemu_register_control_boundary_cb_symbol();
    let register_sim_shmem_dispatch = resolve_qemu_register_sim_shmem_dispatch_cb_symbol();
    let register_net_tx = crate::resolve_qemu_register_net_tx_cb_symbol();
    let net_inject = crate::resolve_qemu_net_inject_symbol();
    let register_block = resolve_qemu_register_blk_cb_symbol();
    let register_block_event = resolve_qemu_register_blk_event_cb_symbol();
    let register_block_wait = resolve_qemu_register_blk_wait_cb_symbol();
    let register_ninep = resolve_qemu_register_9p_cb_symbol();
    let register_accelerator = resolve_qemu_register_accelerator_cb_symbol();
    let fault_commands = crate::fault_command::QemuFaultCommandApis::resolve()
        .map_err(|source| QemuPluginAbiError::FaultCommandCapability { source })?;
    let runtime_apis = admit_required_runtime_apis(RequiredRuntimeApiSymbols {
        clock_deadline_ns,
        advance_time_ticks,
        inject_preemption,
        read_vcpu_regs,
        read_rr_cursor,
        icount_raw,
        force_vcpu_exit,
        wait_idle_wake,
        register_wake_fd,
    })?;
    let request_shutdown =
        require_runtime_api(request_shutdown, QEMU_PLUGIN_REQUEST_SHUTDOWN_SYMBOL)?;
    let request_vmstop = require_runtime_api(request_vmstop, QEMU_PLUGIN_REQUEST_VMSTOP_SYMBOL)?;
    let set_process_generation = require_runtime_api(
        set_process_generation,
        QEMU_PLUGIN_SET_PROCESS_GENERATION_SYMBOL,
    )?;
    let generation_status = set_process_generation(boundary.args.process_generation());
    if generation_status != 0 {
        return Err(QemuPluginAbiError::ProcessGenerationProvision {
            generation: boundary.args.process_generation(),
            status: generation_status,
        }
        .into());
    }
    let basic_block_coverage = if boundary.args.coverage().is_on() {
        Some(resolve_qemu_basic_block_coverage_apis()?)
    } else {
        None
    };
    let capabilities = crate::runtime::LiveInstallCapabilities {
        icount_raw: runtime_apis.icount_raw(),
        force_vcpu_exit: runtime_apis.force_vcpu_exit(),
        idle_wake_wait: runtime_apis.idle_wake_wait(),
        request_vmstop,
        inject_preemption,
        request_time_control: resolve_qemu_request_time_control_symbol(),
        clock_deadline_ns,
        advance_time_ticks,
        register_time_advance_cb,
        arm_virtual_timer_witness,
        query_virtual_timer_witness,
        register_wake_fd: runtime_apis.register_wake_fd(),
        register_resource_manifest,
        register_hot_fork_barrier,
        register_hot_fork_child_runtime,
        request_shutdown,
        basic_block_coverage,
        register_vcpu_init,
        register_vcpu_idle_resume,
        register_control_boundary,
        register_sim_shmem_dispatch,
        register_net_tx,
        net_inject,
        register_block,
        register_block_event,
        register_block_wait,
        register_ninep,
        register_accelerator,
        fault_commands,
    };
    let callback_registrar = crate::runtime::FailClosedOwnedCallbackRegistrar::production(
        plugin_id,
        boundary.execution_model,
        boundary.target_architecture,
        &capabilities,
    );
    crate::runtime::install_live_runtime(
        plugin_id,
        boundary.args,
        capabilities,
        &callback_registrar,
        reservation,
    )
    .map_err(Into::into)
}

fn validate_qemu_plugin_api_range(info: &QemuPluginInfo) -> Result<(), QemuPluginAbiError> {
    if info.version.min > QEMU_PLUGIN_API_VERSION || info.version.cur < QEMU_PLUGIN_API_VERSION {
        return Err(QemuPluginAbiError::UnsupportedPluginApi {
            min: info.version.min,
            cur: info.version.cur,
            required: QEMU_PLUGIN_API_VERSION,
        });
    }
    Ok(())
}

/// QEMU plugin API version exported for QEMU's loader compatibility check.
#[unsafe(no_mangle)]
pub static qemu_plugin_version: c_int = QEMU_PLUGIN_API_VERSION;

/// QEMU `cdylib` install entry point.
///
/// The install path validates the raw ABI shape and execution model, requires
/// every deterministic QEMU capability, and executes the typed control/setup
/// sequence. It fails closed at callback registration until every plugin-owned
/// device adapter is live; only a fully registered runtime may acknowledge
/// readiness and be retained for process lifetime.
///
/// # Safety
///
/// `info` must point to a live QEMU 11.1.1 `qemu_info_t` for the duration of
/// this call. When `argc` is positive, `argv` must point to at least `argc`
/// live pointers to NUL-terminated C strings for the same duration.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qemu_plugin_install(
    id: QemuPluginId,
    info: *const QemuPluginInfo,
    argc: c_int,
    argv: *mut *mut c_char,
) -> c_int {
    #[cfg(unix)]
    {
        run_install_trampoline(|| {
            let mut reservation = crate::runtime::reserve_runtime()?;
            // SAFETY: the exported function's caller contract guarantees the
            // QEMU info and argv allocations remain live for this call.
            let boundary = unsafe { copy_install_boundary(info, argc, argv) }?;
            let runtime = install_owned_boundary(id, boundary, &mut reservation)?;
            reservation.publish(runtime);
            Ok(())
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (id, info, argc, argv);
        QEMU_PLUGIN_INSTALL_ERROR
    }
}

#[cfg(unix)]
fn run_install_trampoline<F>(install: F) -> c_int
where
    F: FnOnce() -> Result<(), crate::runtime::PluginLiveBoundaryError>,
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(install)) {
        Ok(Ok(())) => QEMU_PLUGIN_INSTALL_OK,
        Ok(Err(error)) => {
            crate::runtime::emit_install_failure_diagnostic(&error);
            QEMU_PLUGIN_INSTALL_ERROR
        }
        Err(_panic) => {
            use std::io::Write as _;

            let _write_result = std::io::stderr()
                .lock()
                .write_all(b"crucible-qemu-plugin: install panicked; registration aborted\n");
            QEMU_PLUGIN_INSTALL_ERROR
        }
    }
}

#[cfg(test)]
mod tests;
