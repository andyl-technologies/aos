//! Adapts the shared pure literal walker to the original retained token codec.
//!
//! This alias retains the original no-growth mode, error type and field layout.
//! Its existing construction quotes and Source custody remain independent of
//! the worker stream's operational limits.

pub(super) use crucible_source_birth_data::source_birth::literal_value::walk::{
    BorrowedToken18, Frame,
};

pub(super) type Walker<'a> =
    crucible_source_birth_data::source_birth::literal_value::walk::Walker<'a, false>;
