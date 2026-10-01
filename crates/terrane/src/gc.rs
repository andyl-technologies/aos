//! Owns resumable local collection and fenced backend effects from specification 17.

/// Publishes and renews whole collector leases through native selected transactions.
#[cfg(feature = "std")]
pub mod lease;
