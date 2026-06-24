//! `crucible-qemu-plugin` owns the in-VM QEMU plugin.
//!
//! Spec index: RFC-0010 files 11, 12.
//!
//! This L2 crate builds the `cdylib` loaded by QEMU. Later tasks will add the
//! QEMU TCG plugin entry points, time-control hooks, and device callbacks
//! specified by its indexed RFC-0010 files. It is an unsafe-boundary crate
//! because the plugin speaks QEMU's C ABI and may read guest memory.
//!
//! Module map: the crate root currently reserves the plugin ABI boundary;
//! `args` owns fail-closed `-plugin` argument parsing; `deadline` owns exact
//! virtual-clock deadline introspection; `registration` owns the fail-stop
//! registration sequencer; `setup` owns descriptor mapping and setup
//! acknowledgement; `time_control` owns the time-control ordering contract.
//! Future modules will add entry points, device callbacks, and QEMU-facing
//! helpers.
//!
//! Unsafe boundary discipline: exported C ABI entry points validate raw QEMU
//! pointers and delegate to safe Rust shims for time-control, callback
//! registration, and memory access.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod args;
pub mod deadline;
pub mod registration;
pub mod setup;
pub mod time_control;

pub use args::{
    PLUGIN_ARG_COVERAGE, PLUGIN_ARG_SHMEMFD, PLUGIN_ARG_SIMFD, PLUGIN_ARG_SLOT, PLUGIN_ARG_WAKEFD,
    PLUGIN_ARG_WHITEBOX, PluginArgs, PluginArgsParseError, PluginInheritedFds, PluginSwitch,
};
pub use deadline::{
    ClockDeadlineSource, DeadlineFallbackPolicy, ExactDeadlineError, ExactDeadlineIntrospection,
    ExactDeadlineReport, PerVcpuDeadlineReport, QEMU_PLUGIN_CLOCK_DEADLINE_SYMBOL,
    aggregate_multi_vcpu_deadline,
};
pub use registration::{
    PluginRegistrationFailure, PluginRegistrationReady, PluginRegistrationSequence,
    PluginRegistrationSequenceError,
};
#[cfg(unix)]
pub use setup::{
    ArmedWakeFd, PluginSetupCompletion, PluginSetupError, WakeFdArmError, prepare_setup_completion,
    send_ready_setup_ack,
};
pub use time_control::{
    CANONICAL_TIME_CONTROL_REGISTRATION_ORDER, PluginRegistrationStep,
    TimeControlRegistrationError, TimeControlRegistrationPlan,
};
