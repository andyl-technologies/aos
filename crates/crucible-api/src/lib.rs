//! `crucible-api` owns the versioned programmatic API surface.
//!
//! Spec index: RFC-0010 files 21.
//!
//! This L4 crate will define the session lifecycle, stepping, query, and
//! temporal-graph API types described by RFC-0010 file 21. It is a
//! safe boundary over versioned data and dispatch shapes.

#![forbid(unsafe_code)]
