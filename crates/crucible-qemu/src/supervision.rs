//! Host supervision runtimes for live QEMU nodes.
//!
//! This module owns the production host-side runtimes that bridge synchronous
//! scheduler node steps to real-time child I/O. It is a host-nondeterminism
//! boundary: its members map shared memory and bound child liveness with host
//! time, but never fold host timing into virtual-time ordering state.

mod host_io_runtime;

pub use host_io_runtime::{QemuLiveHostIoRuntime, QemuLiveHostIoRuntimeError};
