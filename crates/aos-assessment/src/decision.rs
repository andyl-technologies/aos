//! Shared interpretation of upstream version-discovery evidence.

use serde::{Deserialize, Serialize};

/// Separately records what fresh upstream evidence proves.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiscoveryDecision {
    /// No acceptable newer candidate exists in the maintained stream.
    Current,
    /// At least one acceptable newer candidate exists.
    UpdateAvailable,
    /// Evidence is missing, stale, incomplete, or contradictory.
    Unknown,
    /// A supply-chain or identity conflict prevents selection.
    Quarantined,
}
