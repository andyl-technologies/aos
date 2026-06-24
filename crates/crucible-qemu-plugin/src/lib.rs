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
//! `deadline` owns exact virtual-clock deadline introspection; `device_io` owns
//! the virtual-time hold for in-flight device I/O; `idle_loop` owns the idle
//! callback hot-loop state machine; `inbound` owns inbound frame polling and
//! deterministic injection ordering; `network_rx` owns idle-context guest network
//! receive injection through QEMU's lossless queue; `network_tx` owns guest
//! network transmit interception and outbound ring enqueueing; `registration` owns
//! the fail-stop registration sequencer; `setup` owns descriptor mapping and setup
//! acknowledgement; `time_control` owns clock ownership, authorized virtual-time
//! advancement, and the time-control ordering contract. Future modules will add
//! live device callback behavior and QEMU-facing helpers.
//!
//! Unsafe boundary discipline: exported C ABI entry points validate raw QEMU
//! pointers and delegate to safe Rust shims for time-control, callback
//! registration, and memory access.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod abi;
pub mod args;
pub mod deadline;
pub mod device_io;
pub mod idle_loop;
pub mod inbound;
pub mod network_rx;
pub mod network_tx;
pub mod registration;
pub mod setup;
pub mod time_control;

pub use abi::{
    InertDeviceCallback, MIN_SUPPORTED_VCPU_COUNT, OWNED_DEVICE_CALLBACK_KINDS,
    PluginDeviceCallbackKind, PluginLifecycleCore, PluginLifecyclePhase, PluginStatePartition,
    QEMU_PLUGIN_API_VERSION, QEMU_PLUGIN_INSTALL_ERROR, QEMU_PLUGIN_INSTALL_OK,
    QEMU_PLUGIN_INSTALL_SYMBOL, QEMU_PLUGIN_REGISTER_ENTRYPOINT_SYMBOL, QEMU_PLUGIN_VERSION_SYMBOL,
    QemuPluginAbiError, QemuPluginExecutionModel, QemuPluginId, QemuPluginInfo, QemuTcgThreading,
    RegisteredDeviceCallbacks, execution_model_from_qemu_info, install_inert_scaffold,
    install_inert_scaffold_from_qemu_info, install_required_deadline_scaffold,
    install_required_deadline_scaffold_from_qemu_info, install_required_time_capability_scaffold,
    install_required_time_capability_scaffold_from_qemu_info, qemu_plugin_install,
    qemu_plugin_version, resolve_qemu_advance_virtual_time_direct_symbol,
    resolve_qemu_clock_deadline_symbol, validate_install_boundary,
};
pub use args::{
    PLUGIN_ARG_COVERAGE, PLUGIN_ARG_SHMEMFD, PLUGIN_ARG_SIMFD, PLUGIN_ARG_SLOT, PLUGIN_ARG_WAKEFD,
    PLUGIN_ARG_WHITEBOX, PluginArgs, PluginArgsParseError, PluginInheritedFds, PluginSwitch,
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
pub use idle_loop::{
    IdleHotLoopError, IdleHotLoopResult, IdleParkRequest, IdleWaitOutcome, IdleWakeCause,
    IdleWakePlan, PluginIdleHotLoop, compute_idle_wake_plan, timer_deadline_icount,
};
pub use inbound::{InboundFrameBatch, InboundFrameError, InboundFrameRing, PluginInboundFrames};
pub use network_rx::{
    LosslessNetworkRxQueue, NetworkRxError, NetworkRxInjection, NetworkRxQueueError,
    NetworkRxQueueOperation, PluginNetworkRx, QEMU_PLUGIN_NET_CAN_RECEIVE_SYMBOL,
    QEMU_PLUGIN_NET_FLUSH_SYMBOL, QEMU_PLUGIN_NET_SEND_SYMBOL, QemuLosslessNetworkRxQueue,
    QemuPluginNetFlushFn, QemuPluginNetSendFn, handle_network_rx_idle_callback,
};
pub use network_tx::{
    NetworkTxEnqueue, NetworkTxError, NetworkTxRing, PluginNetworkTx, handle_network_tx_callback,
};
pub use registration::{
    PluginCallbackCapabilities, PluginRegistrationFailure, PluginRegistrationReady,
    PluginRegistrationSequence, PluginRegistrationSequenceError,
};
#[cfg(unix)]
pub use setup::{
    ArmedWakeFd, PluginSetupCompletion, PluginSetupError, WakeFdArmError, prepare_setup_completion,
    send_ready_setup_ack,
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
