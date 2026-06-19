//! `crucible-harness` owns cross-crate determinism gate scaffolding.
//!
//! This test-only workspace member will host the fingerprint comparator,
//! divergence bisector, replay-oracle checker, ABI golden-vector runner, and
//! adversarial-host driver described by RFC-0010 files 24 and 27. It is not an
//! L0-L4 runtime layer and is not a shipped crate.

#![forbid(unsafe_code)]
