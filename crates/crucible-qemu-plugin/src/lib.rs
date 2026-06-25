//! `crucible-qemu-plugin` owns the in-VM QEMU plugin.
//!
//! Spec index: RFC-0010 files 11, 12.
//!
//! This L2 crate builds the `cdylib` loaded by QEMU. Later tasks will add the
//! QEMU TCG plugin entry points, time-control hooks, and device callbacks
//! specified by its indexed RFC-0010 files. It is an unsafe-boundary crate
//! because the plugin speaks QEMU's C ABI and may read guest memory.
//!
//! Module map: `abi` owns the raw QEMU plugin `cdylib` entry point and inert
//! callback scaffold; `args` owns fail-closed `-plugin` argument parsing;
//! `boot_barrier` owns the initial scheduler-ceiling futex wait before first
//! guest instruction;
//! `handshake` owns plugin-side control-protocol version negotiation and slot
//! cross-checking;
//! `inertness` owns plugin-side sim-off load and effect assertions;
//! `deadline` owns exact virtual-clock deadline introspection; `device_io` owns
//! the virtual-time hold for in-flight device I/O; `idle_loop` owns the idle
//! callback hot-loop state machine; `inbound` owns inbound frame polling and
//! deterministic injection ordering; `network_rx` owns idle-context guest network
//! receive injection through QEMU's lossless queue; `network_tx` owns guest
//! network transmit interception and outbound ring enqueueing; `registration` owns
//! the fail-stop registration sequencer; `setup` owns descriptor mapping and setup
//! acknowledgement; `shmem_ordering` owns the plugin-side shared-memory access
//! funnel and cross-process atomic ordering contract; `teardown` owns shutdown
//! trigger proofs and post-trigger shmem sealing; `time_control` owns clock
//! ownership, authorized virtual-time advancement, and the time-control ordering
//! contract; `block_io` owns guest
//! block submit/poll request routing through the reserved block executor;
//! `ninep_io` owns raw 9p submit/poll/burst routing through the reserved 9p
//! executor; `whitebox_doorbell` owns optional white-box trap planning, guest
//! memory reads, marker stamping, host-to-guest input delivery gates, and the
//! optional app-controlled randomness request/reply path;
//! `round_robin` owns fixed-quantum vCPU rotation and per-vCPU halt tracking;
//! `preemption` owns scheduler-commanded vCPU switch and interrupt injection;
//! `vcpu_introspection` owns side-effect-free per-vCPU register and RR cursor
//! reads for N-vCPU fingerprinting;
//! `coverage` owns optional TCG-exec coverage planning and observational
//! basic-block map updates. Future modules will add live device callback behavior
//! and QEMU-facing helpers.
//!
//! Unsafe boundary discipline: exported C ABI entry points validate raw QEMU
//! pointers and delegate to safe Rust shims for time-control, callback
//! registration, and memory access. The setup path owns descriptor and mmap
//! lifetimes with typed tokens, and guest memory is represented as opaque ranges
//! read or written only through QEMU plugin API adapters.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod abi;
pub mod args;
pub mod block_io;
pub mod boot_barrier;
pub mod coverage;
pub mod deadline;
pub mod device_io;
pub mod handshake;
pub mod idle_loop;
pub mod inbound;
pub mod inertness;
pub mod network_rx;
pub mod network_tx;
pub mod ninep_io;
pub mod preemption;
pub mod registration;
pub mod round_robin;
pub mod setup;
pub mod shmem_ordering;
pub mod teardown;
pub mod time_control;
pub mod vcpu_introspection;
pub mod whitebox_doorbell;

pub use abi::{
    InertDeviceCallback, MIN_SUPPORTED_VCPU_COUNT, OWNED_DEVICE_CALLBACK_KINDS,
    PluginDeviceCallbackKind, PluginLifecycleCore, PluginLifecyclePhase, PluginRuntimeApis,
    PluginStatePartition, QEMU_PLUGIN_API_VERSION, QEMU_PLUGIN_FORCE_VCPU_EXIT_SYMBOL,
    QEMU_PLUGIN_ICOUNT_RAW_SYMBOL, QEMU_PLUGIN_INSTALL_ERROR, QEMU_PLUGIN_INSTALL_OK,
    QEMU_PLUGIN_INSTALL_SYMBOL, QEMU_PLUGIN_MAIN_LOOP_WAIT_SYMBOL,
    QEMU_PLUGIN_REGISTER_9P_CB_SYMBOL, QEMU_PLUGIN_REGISTER_BLK_CB_SYMBOL,
    QEMU_PLUGIN_REGISTER_ENTRYPOINT_SYMBOL, QEMU_PLUGIN_REGISTER_WAKE_FD_SYMBOL,
    QEMU_PLUGIN_VERSION_SYMBOL, QemuBlkPollCbFn, QemuBlkSubmitCbFn, QemuForceVcpuExitFn,
    QemuIcountRawFn, QemuMainLoopWaitFn, QemuNinePBurstCbFn, QemuNinePPollCbFn,
    QemuNinePSubmitCbFn, QemuPluginAbiError, QemuPluginExecutionModel, QemuPluginId,
    QemuPluginInfo, QemuRegisterBlkCbFn, QemuRegisterNinePCbFn, QemuRegisterTcgExecCbFn,
    QemuRegisterWakeFdFn, QemuTcgExecCbFn, QemuTcgThreading, RegisteredDeviceCallbacks,
    execution_model_from_qemu_info, install_inert_scaffold, install_inert_scaffold_from_qemu_info,
    install_required_deadline_scaffold, install_required_deadline_scaffold_from_qemu_info,
    install_required_preemption_scaffold, install_required_preemption_scaffold_from_qemu_info,
    install_required_runtime_api_scaffold, install_required_runtime_api_scaffold_from_qemu_info,
    install_required_time_capability_scaffold,
    install_required_time_capability_scaffold_from_qemu_info,
    install_required_vcpu_introspection_scaffold,
    install_required_vcpu_introspection_scaffold_from_qemu_info, qemu_plugin_install,
    qemu_plugin_version, resolve_qemu_advance_virtual_time_direct_symbol,
    resolve_qemu_clock_deadline_symbol, resolve_qemu_force_vcpu_exit_symbol,
    resolve_qemu_icount_raw_symbol, resolve_qemu_inject_preemption_symbol,
    resolve_qemu_main_loop_wait_symbol, resolve_qemu_read_vcpu_regs_symbol,
    resolve_qemu_register_9p_cb_symbol, resolve_qemu_register_blk_cb_symbol,
    resolve_qemu_register_tcg_exec_cb_symbol, resolve_qemu_register_wake_fd_symbol,
    resolve_qemu_rr_cursor_symbol, validate_install_boundary,
};
pub use args::{
    PLUGIN_ARG_COVERAGE, PLUGIN_ARG_SHMEMFD, PLUGIN_ARG_SIMFD, PLUGIN_ARG_SLOT, PLUGIN_ARG_WAKEFD,
    PLUGIN_ARG_WHITEBOX, PluginArgs, PluginArgsParseError, PluginInheritedFds, PluginSwitch,
};
pub use block_io::{
    BlockGuestCompletion, BlockGuestCompletionError, BlockInboundRing, BlockIoError,
    BlockOperation, BlockOutboundRing, BlockPoll, BlockRequest, BlockRequestToken, BlockResponse,
    BlockResponseStatus, BlockSubmit, BlockWireError, PluginBlockIo, handle_block_poll_callback,
    handle_block_submit_callback,
};
pub use boot_barrier::{
    BOOT_BARRIER_FIRST_GUEST_ICOUNT, BootBarrierError, BootBarrierRelease, BootBarrierWait,
    PluginBootBarrier,
};
pub use coverage::{
    CoverageBlockEvent, CoverageCallback, CoverageCapabilities, CoverageError, CoverageMap,
    CoverageObservation, CoverageRegistrationPlan, CoverageSink, CoverageSinkError,
    DEFAULT_COVERAGE_MAP_ENTRIES, PluginCoverage, QEMU_PLUGIN_REGISTER_TCG_EXEC_CB_SYMBOL,
    crucible_qemu_plugin_coverage_exec_cb, fold_basic_block_pc, handle_coverage_exec_callback,
};
pub use deadline::{
    ClockDeadlineSource, DeadlineFallbackPolicy, ExactDeadlineError, ExactDeadlineIntrospection,
    ExactDeadlineReader, ExactDeadlineReport, PerVcpuDeadlineReport,
    QEMU_PLUGIN_CLOCK_DEADLINE_SYMBOL, QemuClockDeadlineFn, aggregate_multi_vcpu_deadline,
};
pub use device_io::{
    DeviceIoBurstState, DeviceIoFreezeError, DeviceIoRequestOutcome, DeviceIoRequestRelease,
    DeviceIoRequestToken, PluginDeviceIoFreeze,
};
pub use handshake::{
    PluginControlHandshake, PluginHandshakeError, perform_plugin_handshake,
    plugin_handshake_config, validate_plugin_handshake,
};
pub use idle_loop::{
    IdleHotLoopError, IdleHotLoopResult, IdleParkRequest, IdleWaitOutcome, IdleWakeCause,
    IdleWakePlan, PluginIdleHotLoop, compute_idle_wake_plan, timer_deadline_icount,
};
pub use inbound::{InboundFrameBatch, InboundFrameError, InboundFrameRing, PluginInboundFrames};
pub use inertness::{
    PluginInertnessError, PluginInertnessObservation, PluginInertnessReport,
    PluginPatchCapabilityCalls, PluginSimulationMode, assert_plugin_inert,
};
pub use network_rx::{
    LosslessNetworkRxQueue, NetworkRxError, NetworkRxInjection, NetworkRxQueueError,
    NetworkRxQueueOperation, PluginNetworkRx, QEMU_PLUGIN_NET_CAN_RECEIVE_SYMBOL,
    QEMU_PLUGIN_NET_FLUSH_SYMBOL, QEMU_PLUGIN_NET_SEND_SYMBOL, QemuLosslessNetworkRxQueue,
    QemuPluginNetCanReceiveFn, QemuPluginNetFlushFn, QemuPluginNetSendFn,
    handle_network_rx_idle_callback, resolve_qemu_net_can_receive_symbol,
    resolve_qemu_net_flush_symbol, resolve_qemu_net_send_symbol,
};
pub use network_tx::{
    NetworkTxEnqueue, NetworkTxError, NetworkTxRing, PluginNetworkTx,
    QEMU_PLUGIN_REGISTER_NET_TX_CB_SYMBOL, QemuNetTxCbFn, QemuRegisterNetTxCbFn,
    handle_network_tx_callback, resolve_qemu_register_net_tx_cb_symbol,
};
pub use ninep_io::{
    NinePGuestCompletion, NinePGuestCompletionError, NinePInboundRing, NinePIoError,
    NinePOutboundRing, NinePPoll, NinePRequest, NinePRequestToken, NinePResponse, NinePSubmit,
    PluginNinePIo, handle_9p_burst_done_callback, handle_9p_burst_start_callback,
    handle_9p_poll_callback, handle_9p_submit_callback,
};
pub use preemption::{
    PluginPreemptionApplication, PluginPreemptionDecision, PluginPreemptionInjector,
    PluginPreemptionKind, PreemptionError, PreemptionWindow, QEMU_PLUGIN_INJECT_PREEMPTION_SYMBOL,
    QEMU_PREEMPTION_KIND_INTERRUPT_AT, QEMU_PREEMPTION_KIND_VCPU_SWITCH,
    QEMU_PREEMPTION_UNUSED_ARG, QemuInjectPreemptionFn, QemuPreemptionCommand,
};
pub use registration::{
    PluginCallbackCapabilities, PluginRegistrationFailure, PluginRegistrationReady,
    PluginRegistrationSequence, PluginRegistrationSequenceError,
};
pub use round_robin::{
    RoundRobinConfig, RoundRobinError, RoundRobinRunState, RoundRobinTurn, VcpuHaltTracker,
    compute_all_halted_idle_wake_plan,
};
pub use setup::PluginReadySetupAck;
#[cfg(unix)]
pub use setup::{
    ArmedWakeFd, PluginSetupCompletion, PluginSetupError, PluginSetupFailureStage,
    RegisteredWakeFd, WakeFdArmError, WakeFdRegisterError, prepare_setup_completion,
    receive_and_prepare_setup_completion, receive_setup_with_descriptors, send_ready_setup_ack,
};
pub use shmem_ordering::PluginShmemOrdering;
pub use teardown::{
    PluginHostQuit, PluginQemuShutdown, PluginQemuShutdownError, PluginShmemAccess,
    PluginShutdownRequested, PluginTeardown, PluginTeardownComplete, PluginTeardownError,
    PluginTeardownTrigger,
};
pub use time_control::{
    CANONICAL_TIME_CONTROL_REGISTRATION_ORDER, MAX_PLUGIN_ICOUNT_SHIFT, PluginClockAdvance,
    PluginClockAdvanceSource, PluginClockError, PluginRegistrationStep, PluginTimeControlOwnership,
    PluginVirtualClock, QEMU_PLUGIN_ADVANCE_VIRTUAL_TIME_DIRECT_SYMBOL,
    QEMU_PLUGIN_HAS_TIME_CONTROL_SYMBOL, QEMU_PLUGIN_REQUEST_TIME_CONTROL_SYMBOL,
    QEMU_PLUGIN_UPDATE_NS_SYMBOL, QemuAdvanceVirtualTimeDirectFn, SchedulerAuthorizedIdleJump,
    SchedulerCeiling, SynchronousIdleAdvance, SynchronousIdleAdvanceError, SynchronousIdleDrain,
    TimeControlRegistrationError, TimeControlRegistrationPlan,
};
pub use vcpu_introspection::{
    MAX_VCPU_REGISTER_FILE_BYTES, PLUGIN_REGISTER_DIGEST_BYTES, PluginNvcpuFingerprintInputs,
    PluginRoundRobinCursor, PluginVcpuIntrospector, PluginVcpuRegisterDigest,
    QEMU_PLUGIN_CRUCIBLE_GET_VCPU_REGISTERS_SYMBOL, QEMU_PLUGIN_CRUCIBLE_READ_VCPU_REGISTER_SYMBOL,
    QEMU_PLUGIN_CRUCIBLE_RR_CURRENT_VCPU_SYMBOL, QEMU_PLUGIN_CRUCIBLE_RR_CURSOR_POSITION_SYMBOL,
    QEMU_PLUGIN_CRUCIBLE_RR_SWITCH_QUANTUM_SYMBOL, QEMU_PLUGIN_READ_VCPU_REGS_SYMBOL,
    QEMU_PLUGIN_RR_CURSOR_SYMBOL, QemuReadRrCursorFn, QemuReadVcpuRegsFn, QemuRoundRobinCursor,
    VcpuIntrospectionError, digest_register_file,
};
pub use whitebox_doorbell::{
    AppRandomDecisionError, AppRandomDecisionRecord, AppRandomDecisionSource,
    AppRandomDecodeDiagnostic, AppRandomDecodeDiagnosticKind, AppRandomDoorbellError,
    AppRandomDoorbellOutcome, AppRandomDoorbellRequest, AppRandomDoorbellService,
    GuestMemoryAddressSpace, GuestMemoryRange, GuestMemoryReadError, GuestMemoryReader,
    PluginWhiteboxDoorbell, QEMU_PLUGIN_DOORBELL_MEM_CB_SYMBOL,
    QEMU_PLUGIN_DOORBELL_TRANSLATION_SYMBOL, QEMU_PLUGIN_GET_HWADDR_SYMBOL,
    QEMU_PLUGIN_GUEST_MEMORY_READ_SYMBOL, QEMU_PLUGIN_GUEST_MEMORY_WRITE_SYMBOL,
    QEMU_PLUGIN_HWADDR_PHYS_ADDR_SYMBOL, QEMU_PLUGIN_IO_ADDRESS_QUERY_SYMBOL,
    QEMU_PLUGIN_READ_REGISTER_SYMBOL, QEMU_PLUGIN_REGISTER_DOORBELL_TRAP_SYMBOL,
    WHITEBOX_APP_RANDOM_MAX_WIDTH_BYTES, WHITEBOX_DOORBELL_FRAME_HEADER_LEN,
    WHITEBOX_DOORBELL_FRAME_MAGIC, WHITEBOX_DOORBELL_KIND_RANDOM_REQUEST,
    WHITEBOX_DOORBELL_PROTOCOL_VERSION, WhiteboxDoorbellCapabilities, WhiteboxDoorbellError,
    WhiteboxDoorbellFrame, WhiteboxDoorbellRegistrationPlan, WhiteboxDoorbellTrap,
    WhiteboxDoorbellTrapEvent, WhiteboxGuestInput, WhiteboxGuestInputCapability,
    WhiteboxGuestInputInjection, WhiteboxGuestInputOutcome, WhiteboxGuestInputWriteError,
    WhiteboxGuestInputWriter, WhiteboxMarker, WhiteboxMarkerSink, WhiteboxMarkerSinkError,
    handle_whitebox_app_random_callback, handle_whitebox_doorbell_callback,
    handle_whitebox_guest_input_callback,
};
