//! `crucible-device` owns deterministic I/O sub-node models.
//!
//! Spec index: RFC-0010 files 15.
//!
//! This L1 crate will contain the disk, 9p, and network sub-node models from
//! its indexed RFC-0010 file. It computes deterministic completion events over
//! owned state; the L3 scheduler decides when those completions are resolved.
//!
//! Module map: the crate root currently reserves the deterministic device
//! boundary; future modules will split disk, 9p, and network sub-node models.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
