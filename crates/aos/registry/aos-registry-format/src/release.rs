//! Portable coordinates for planned registry release entries.

use serde::{Deserialize, Serialize};

/// One package-platform entry that must appear in the prepared registry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryReleaseEntry {
    /// Stable entry id from the enclosing release plan.
    pub id: String,
    /// Registry package name.
    pub name: String,
    /// Package version written into the catalog.
    pub version: String,
    /// Exact Nix target platform.
    pub platform: String,
    /// Exact named derivation output.
    #[serde(default = "default_output_name")]
    pub output: String,
    /// Exact realized store output expected in the catalog or named-output map.
    pub store_path: String,
}

fn default_output_name() -> String {
    "out".to_string()
}
