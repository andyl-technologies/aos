//! `crucible-protocol` owns the host/plugin wire protocol.
//!
//! Spec index: RFC-0010 files 14.
//!
//! This L1 crate will hold the framed IPC messages, version fields,
//! encode/decode routines, and golden vectors specified by its indexed RFC-0010
//! file. It operates over owned buffers and does not own the shared-memory
//! transport or scheduler semantics.

#![forbid(unsafe_code)]
