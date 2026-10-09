//! Installed payload records shared by profile storage and image verification.
//!
//! Records use the existing profile metadata JSON format; moving the Rust types
//! does not change field names, defaults, or strictness. Image verification reads
//! the same inventory contract without depending on package installation policy.
//!
//! ```json
//! {"store_path":"/nix/store/00000000000000000000000000000000-example","pushed_at":0,"pushed_by":"apm","is_root":true,"last_accessed":0,"access_count":0,"apm":null}
//! ```

use aos_registry_format::manifest::{AttestationMeta, NativeArtifactMeta};
use serde::{Deserialize, Serialize};

/// Metadata stored in the profile's `meta/{hash}.json` for each installed path.
///
/// The base fields (`store_path` through `access_count`) are shared with the
/// cache server's per-path metadata so that `aos gc` can read both uniformly.
/// The optional `apm` section extends this with package manager state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPackageRecord {
    /// Full store path this metadata record describes.
    pub store_path: String,
    /// Unix timestamp when the path was pushed/installed.
    pub pushed_at: i64,
    /// Who created the record (`"apm"` for installs; a token name on the
    /// cache server).
    pub pushed_by: String,
    /// Optional Unix expiry timestamp (cache-server semantics; unset by apm).
    #[serde(default)]
    pub expires_at: Option<i64>,
    /// Whether the path is a GC root (protected from garbage collection).
    pub is_root: bool,
    /// Unix timestamp of the last recorded access.
    pub last_accessed: i64,
    /// Number of recorded accesses.
    pub access_count: u64,
    /// Package-manager extension; `None` for records written by the cache
    /// server.
    #[serde(default)]
    pub apm: Option<PackageInventoryDetails>,
}

/// APM-specific metadata extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageInventoryDetails {
    /// Package name as known to the registry.
    pub name: String,
    /// Installed package version.
    pub version: String,
    /// `true` if the user explicitly installed this package.
    pub explicit: bool,
    /// Registry this package was installed from.
    pub registry: String,
    /// ISO 8601 timestamp of installation.
    pub installed_at: String,
    /// Prevent this package from being upgraded.
    pub held: bool,
    /// Source derivation store path associated with this installed package.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_drv: String,
    /// NAR hash for the source derivation.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_nar_hash: String,
    /// Authenticated native package deployment envelope directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment: Option<NativeArtifactMeta>,
    /// Authenticated module-generated reference directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module_documentation: Option<NativeArtifactMeta>,
    /// Authenticated native package qualification companion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qualification: Option<NativeArtifactMeta>,
    /// Runtime integrity, attestation, and provenance facts captured at install time.
    #[serde(default, skip_serializing_if = "AttestationMeta::is_empty")]
    pub attestation: AttestationMeta,
}
