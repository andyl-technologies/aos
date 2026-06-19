//! `crucible-protocol` owns the host/plugin wire protocol.
//!
//! Spec index: RFC-0010 files 14.
//!
//! This L1 crate will hold the framed IPC messages, version fields,
//! encode/decode routines, and golden vectors specified by its indexed RFC-0010
//! file. It operates over owned buffers and does not own the shared-memory
//! transport or scheduler semantics.
//!
//! Module map: the crate root currently reserves the host/plugin protocol
//! boundary; future modules will split frame headers, message bodies, codecs,
//! and golden vectors.
//!
//! Wire-format sketch:
//!
//! ```text
//! frame-header(version, kind, length)
//! payload-bytes
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
