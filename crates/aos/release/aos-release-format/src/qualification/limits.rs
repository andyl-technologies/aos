//! Fixed admission limits shared by every qualification profile.
//!
//! These values are deliberately constants rather than contract fields: a
//! contract may tighten obligations through its profiles, but it cannot make
//! rollout health evidence older or an operational exercise staler than the
//! pipeline accepts.

/// Maximum age of a rollout-health observation when a channel range advances.
pub const ROLLOUT_FRESHNESS_SECONDS: u64 = 600;

/// Maximum age of any non-rollout observation or exercise at admission (30 days).
pub const EXERCISE_MAX_AGE_SECONDS: u64 = 2_592_000;

/// Minimum observation window a profile with qualified (A3) claims may require.
///
/// Signed profile overrides may relax a profile's soak, but never below this.
pub const MINIMUM_QUALIFIED_SOAK_SECONDS: u64 = 86_400;

/// Cumulative partition count of the final rollout ring.
pub const FINAL_RING_PARTITIONS: u16 = 256;
