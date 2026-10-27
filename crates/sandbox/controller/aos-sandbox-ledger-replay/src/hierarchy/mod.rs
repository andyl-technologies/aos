//! Owns canonical project ancestry, digest-linked history and their codecs.
//!
//! Graph/history constructors validate bounded Source model invariants. These
//! saved models and passive decode destinations confer no native writer, paid
//! receiving origin, current ancestry loan, Root grant or effect authority.

/// Encodes and decodes the sole canonical ancestry and history formats.
pub mod codec;
/// Validates and reduces project-local ancestry graphs.
pub mod graph;
/// Preserves bounded digest-linked operation history and idempotency replay.
pub mod history;
