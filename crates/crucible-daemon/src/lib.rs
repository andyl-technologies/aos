//! `crucible-daemon` owns the long-lived host process.
//!
//! This L4 crate will host sessions and serve the API over a transport as
//! specified by RFC-0010 files 20, 21, and 27. It may later contain host-facing
//! diagnostics, but any run-affecting choice must enter through the engine's
//! deterministic decision stream.

#![forbid(unsafe_code)]
