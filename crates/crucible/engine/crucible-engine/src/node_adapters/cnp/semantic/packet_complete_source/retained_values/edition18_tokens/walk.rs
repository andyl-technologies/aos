//! Adapts the shared pure literal walker to the original retained token codec.
//!
//! This alias retains the original no-growth mode, error type and field layout.
//! Its existing construction quotes and Source custody remain independent of
//! the worker stream's operational limits.

pub(super) use crate::node_adapters::cnp::source_birth_derivation::literal_value::walk::{
    BorrowedToken18, Frame,
};

pub(super) type Walker<'a> =
    crate::node_adapters::cnp::source_birth_derivation::literal_value::walk::Walker<'a, false>;
