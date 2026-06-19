//! `crucible-protocol` owns the host/plugin wire protocol.
//!
//! This L1 crate will hold the framed IPC messages, version fields,
//! encode/decode routines, and golden vectors specified by RFC-0010 files 14
//! and 27. It operates over owned buffers and does not own the shared-memory
//! transport or scheduler semantics.

#![forbid(unsafe_code)]
