//! Checked deferred operation graphs emitted by recursive Nix modules.
//!
//! [`module_graph`] validates operation identities, typed dependencies, handler
//! artifacts, lifetimes, and semantic revisions before activation. This crate
//! performs no downloads or host mutations.

#![forbid(unsafe_code)]

pub mod module_graph;
