//! `crucible-api` owns the versioned programmatic API surface.
//!
//! This L4 crate will define the session lifecycle, stepping, query, and
//! temporal-graph API types described by RFC-0010 files 21 and 27. It is a
//! safe boundary over versioned data and dispatch shapes.

#![forbid(unsafe_code)]
