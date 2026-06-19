//! `crucible-session` owns the live session actor.
//!
//! This L4 crate will drive one live runtime state, accept control requests at
//! quantum boundaries, and expose the session semantics specified by RFC-0010
//! files 20 and 27. It contains no raw QEMU or shared-memory access.

#![forbid(unsafe_code)]
