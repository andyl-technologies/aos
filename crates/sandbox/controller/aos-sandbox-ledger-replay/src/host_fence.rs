//! Owns canonical Host fence DATA without native custody or acquisition authority.
//!
//! The existing native owners retain typed acquisition exceptions, physical
//! snapshots, currentness, financial intervals and independent owed posts.

/// Retains the exact HostState fence codec and deny-only predicates.
pub mod currentness;
/// Retains the exact failed-Create Effect-fence codec and deny-only predicates.
pub mod execution;
/// Retains the existing reserved settlement-witness denial predicates.
pub mod settlement_admission;
