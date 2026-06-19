//! `crucible` is the CLI entry point for the Crucible control plane.
//!
//! Spec index: RFC-0010 files 23.
//!
//! This L4 binary crate will remain a thin client over `crucible-api` and
//! `crucible-session` as specified by RFC-0010 file 23.
//!
//! Module map: the binary root owns argument dispatch only; future command
//! modules will remain transport clients over the session and API crates.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

fn main() {}
