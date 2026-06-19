//! `crucible-guest` owns the optional in-guest white-box agent.
//!
//! Spec index: RFC-0010 files 16.
//!
//! This L2 crate will contain the additive doorbell client described by
//! its indexed RFC-0010 file. It is never required for core black-box operation
//! and is an unsafe-boundary crate because future code may issue trapped guest
//! instructions and touch ABI memory directly.
//!
//! Module map: the crate root currently reserves the optional guest-agent
//! boundary; future modules will split doorbell transport from guest ABI
//! accessors.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
