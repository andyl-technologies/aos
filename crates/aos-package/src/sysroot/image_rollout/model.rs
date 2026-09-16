//! Package-owned request model for the native image rollout provider.

use serde::{Deserialize, Serialize};

/// Maximum retention interval accepted by the native rollout backend.
pub(crate) const MAX_RETENTION_MILLIS: u64 = 30 * 24 * 60 * 60 * 1_000;

/// Pins every immutable component used to authenticate one boot image.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct RolloutImageIdentity {
    /// Pins the immutable system toplevel.
    pub(crate) toplevel: String,
    /// Pins the signed UKI source identity.
    pub(crate) uki: String,
    /// Pins the exact native ability executor carried by the image.
    pub(crate) executor: String,
    /// Pins the compatible nonempty persistent state format.
    pub(crate) state_format: String,
}

/// Supplies one exact desired single-host rollout.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct AbRolloutRequest {
    /// Names the strategy implemented by this provider.
    pub(crate) strategy: String,
    /// Limits preparation to one candidate beside one retained predecessor.
    pub(crate) concurrency: u32,
    /// Identifies the currently admitted image.
    pub(crate) predecessor: RolloutImageIdentity,
    /// Identifies the candidate to prepare and select.
    pub(crate) candidate: RolloutImageIdentity,
    /// Gives the restart-stable deadline through which both images remain retained.
    pub(crate) retention_expires_at_millis: u64,
}

/// Carries one rollout-state operation plus checked lower-provider evidence.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AbRolloutTerminalRequest {
    /// Retains the exact provider-neutral rollout request.
    pub(crate) rollout: AbRolloutRequest,
    /// Supplies a boot entry resolved by the selected boot-selection provider.
    #[serde(default)]
    pub(crate) entry: Option<String>,
    /// Retains the typed result returned by the selected boot-storage provider.
    #[serde(default)]
    pub(crate) platform: Option<serde_json::Value>,
}
