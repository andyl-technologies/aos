//! `crucible` owns the pure engine.
//!
//! This L3 crate is the future home of the scenario model, scheduler, temporal
//! graph, fault engine, assertion evaluation, event log, and backend trait from
//! RFC-0010 files 05, 06, 07, 08, 17, 18, 19, and 27. It must remain a safe
//! reduction island with all QEMU and FFI details below it.

#![forbid(unsafe_code)]
