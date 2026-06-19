//! `crucible-assert` owns Crucible's assertion vocabulary as data.
//!
//! Spec index: RFC-0010 files 18.
//!
//! This L0 crate will hold the property kinds and serializable assertion types
//! specified by its indexed RFC-0010 file. It deliberately does not evaluate
//! assertions against an event log; evaluation belongs to the L3 engine.

#![forbid(unsafe_code)]
