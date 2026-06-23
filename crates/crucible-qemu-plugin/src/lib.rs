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
//! future modules will split entry points, time control, device callbacks, and
//! QEMU-facing helpers.
//!
//! Unsafe boundary discipline: exported C ABI entry points validate raw QEMU
//! pointers and delegate to safe Rust shims for time-control, callback
//! registration, and memory access.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod deadline;
pub mod time_control;

pub use deadline::{
    ClockDeadlineSource, DeadlineFallbackPolicy, ExactDeadlineError, ExactDeadlineIntrospection,
    ExactDeadlineReport, QEMU_PLUGIN_CLOCK_DEADLINE_SYMBOL,
};
pub use time_control::{
    CANONICAL_TIME_CONTROL_REGISTRATION_ORDER, PluginRegistrationStep,
    TimeControlRegistrationError, TimeControlRegistrationPlan,
};
