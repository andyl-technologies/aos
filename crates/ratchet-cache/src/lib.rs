//! Unsafe cache-engine primitives for RFC-0007.
//!
//! `ratchet-cache` is the language-agnostic cache engine band described in
//! RFC-0007. It owns the operations that cannot live inside the safe
//! `ratchet-oracle` crate, including memory-mapped content-addressed stores,
//! out-of-core value spill, and future demand-graph storage backends.
//!
//! The current crate contains read-only file mapping and content-addressed
//! blob-pack building blocks used by later persistent packfile adapters.
//! Higher-level cache formats remain in `ratchet-oracle` until they move
//! behind this unsafe fence.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod blob_index;
pub mod blob_pack;
pub mod store;
