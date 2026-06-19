//! `crucible-device` owns deterministic I/O sub-node models.
//!
//! This L1 crate will contain the disk, 9p, and network sub-node models from
//! RFC-0010 files 15 and 27. It computes deterministic completion events over
//! owned state; the L3 scheduler decides when those completions are resolved.

#![forbid(unsafe_code)]
