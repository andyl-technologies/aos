//! `crucible-daemon` owns the long-lived host process.
//!
//! Spec index: RFC-0010 files 20, 21.
//!
//! This L4 crate will host sessions and serve the API over a transport as
//! specified by its indexed RFC-0010 files. It may later contain host-facing
//! diagnostics, but any run-affecting choice must enter through the engine's
//! deterministic decision stream.
//!
//! Module map: [`control_responsiveness`] forwards daemon-routed
//! acknowledgement evidence to the API's quantum-counted control-responsive
//! contract; future modules will split session hosting, API transport, and
//! diagnostics.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod control_responsiveness;

pub use control_responsiveness::{
    DAEMON_CONTROL_RESPONSIVE_QUANTUM_BOUND, DaemonControlResponsiveRoute,
    validate_daemon_control_responsiveness,
};
