//! `crucible-guest` owns the optional in-guest white-box agent.
//!
//! This L2 crate will contain the additive doorbell client described by
//! RFC-0010 files 16 and 27. It is never required for core black-box operation
//! and is an unsafe-boundary crate because future code may issue trapped guest
//! instructions and touch ABI memory directly.

#![deny(unsafe_op_in_unsafe_fn)]
