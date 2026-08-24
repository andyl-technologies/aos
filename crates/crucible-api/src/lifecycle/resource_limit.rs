//! Typed lifecycle API resource-limit coordinates.

/// Exact coordinates for one refused lifecycle resource reservation.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
#[error(
    "lifecycle resource limit: field={field} current={current} requested={requested} configured={configured} hard={hard}"
)]
pub struct LifecycleResourceLimit {
    /// Closed resource-policy field name.
    pub field: &'static str,
    /// Usage retained before the refused reservation.
    pub current: u64,
    /// Additional usage requested by the operation.
    pub requested: u64,
    /// Scenario-authored ceiling.
    pub configured: u64,
    /// Compiled hard ceiling.
    pub hard: u64,
}
