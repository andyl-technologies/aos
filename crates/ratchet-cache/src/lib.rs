//! Unsafe cache-engine primitives for RFC-0007.
//!
//! `ratchet-cache` is the language-agnostic cache engine band described in
//! RFC-0007. It owns the operations that cannot live inside the safe
//! `ratchet-oracle` crate, including memory-mapped content-addressed stores,
//! out-of-core value spill, and future demand-graph storage backends.
//!
//! The current crate contains read-only file mapping, content-addressed
//! blob-pack building blocks, hash-to-offset sidecars, fixed-record frontend
//! artifact sidecars, fixed-record node metadata sidecars, and variable-length
//! node trace logs — each fronted by a shared in-memory newest-record-wins index
//! so lookups do not rescan the append log — plus schema-version sidecars and
//! owned-path lifecycle
//! helpers, staged file-replacement helpers, advisory filesystem lock helpers,
//! and process-local cache-root lock slots used by later persistent cache
//! adapters. Higher-level cache formats remain in `ratchet-oracle` until they
//! move behind this unsafe fence.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod artifact_index;
pub mod blob_index;
pub mod blob_pack;
pub mod file_lock;
pub mod file_replace;
pub mod node_metadata;
pub mod node_trace_log;
pub mod owned_paths;
pub mod root_locks;
pub mod schema;
pub mod sidecar_index;
pub mod store;
