//! Data models shared by the D1 read layer, the JSON read API, and rendering.
//!
//! These are pure serde structs — no `worker` types — so they compile and test
//! on native. They mirror the native hub's row/detail structs
//! (`aos_registry_hub::db::{PackageRow, ReleaseRow, …}`) and the
//! `aos.registry.v1` read shapes, restricted to the read path the Worker
//! serves. The read layer (`crate::reads`, wasm32-only) projects
//! `core::Database` rows onto these; the JSON API serializes them directly; the
//! renderer ([`crate::render`]) reads them to build HTML.
//!
//! The JSON read API is a **simple JSON shape**, not full Connect framing: it
//! returns these structs as plain `application/json` at `/-/api/...` paths.
//! Full `aos.registry.v1` Connect-JSON envelope framing is native-only for now
//! (it shares the hub's `connectrpc` service impls, which are not on the
//! Workers target); see the crate README.

use serde::{Deserialize, Serialize};

/// One registry's identity and read-relevant configuration.
///
/// Projected from `core::Database` rows by `crate::reads` (wasm32-only).
/// `trust_keys` is the raw JSON-array string as stored
/// (`["name:Ed25519:b64", …]`); the renderer parses it for fingerprint display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Registry {
    /// The registry's row id.
    pub id: i64,
    /// The URL-path slug.
    pub slug: String,
    /// The upstream surface URL (`https://…` or `file://…`).
    pub source_url: String,
    /// JSON array of trust-anchor key lines, as stored.
    pub trust_keys: String,
    /// Whether the indexer fails closed on an unsigned surface (`0`/`1`).
    pub require_signatures: i64,
    /// `public` | `internal` | `private` (this Worker serves only `public`).
    pub visibility: String,
    /// The registry's R2 key prefix within the hub bucket.
    pub prefix: String,
}

/// Index freshness and surface metadata for one registry.
///
/// Projected from `core::Database::index_status` by `crate::reads`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IndexInfo {
    /// `fresh` | `indexing` | `stale` | `failed` | `partial`.
    pub state: String,
    /// The last error, when `state` is `stale` or `failed`.
    pub error: Option<String>,
    /// The surface commit the index was built from.
    pub last_indexed_commit: Option<String>,
    /// The registry's display name from its committed `registry.toml`.
    pub name: Option<String>,
    /// The registry's description.
    pub description: Option<String>,
    /// Unix time of the last successful index.
    pub indexed_at: Option<i64>,
}

/// One row of a registry's package list.
///
/// Mirrors `aos_registry_hub::db::PackageRow`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageRow {
    /// The package name.
    pub name: String,
    /// The one-line description.
    pub description: String,
    /// The SPDX license expression.
    pub license: String,
    /// The newest indexed version, when any.
    pub latest: Option<String>,
}

/// One package's full detail (header + versions × platforms).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageDetail {
    /// The package name.
    pub name: String,
    /// The one-line description.
    pub description: String,
    /// The upstream homepage, when set.
    pub homepage: Option<String>,
    /// The SPDX license expression.
    pub license: String,
    /// The package maintainer.
    pub maintainer: String,
    /// Whether the package ships sysroot images.
    pub sysroot: bool,
    /// Versions, newest first.
    pub versions: Vec<VersionDetail>,
}

/// One version of a package, with its per-platform builds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionDetail {
    /// The semver version string.
    pub version: String,
    /// The previous version this one supersedes, when recorded.
    pub previous: Option<String>,
    /// Per-platform builds.
    pub platforms: Vec<PlatformDetail>,
}

/// One platform build of a package version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformDetail {
    /// The target platform (e.g. `x86_64-linux`).
    pub platform: String,
    /// The output store path.
    pub store_path: String,
    /// The NAR hash (`sha256:…`).
    pub nar_hash: String,
    /// The NAR size in bytes.
    pub nar_size: i64,
    /// The total closure size in bytes.
    pub closure_size: i64,
}

/// One channel and its 256-bucket partition map.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelSummary {
    /// The channel name.
    pub name: String,
    /// The observed frontier release, when any.
    pub frontier: Option<String>,
    /// The 256-bucket map; `partitions[bucket]` is the release the bucket
    /// points at, or `None` for an unmapped bucket.
    pub partitions: Vec<Option<String>>,
}

/// One verified release tag.
///
/// Mirrors `aos_registry_hub::db::ReleaseRow`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseRow {
    /// The semver string.
    pub semver: String,
    /// The signed tag object id.
    pub tag_oid: String,
    /// The commit the tag points at.
    pub commit_oid: String,
    /// The verified signer identity, when resolved.
    pub signer: Option<String>,
    /// Unix tagging time, when recorded.
    pub tagged_at: Option<i64>,
    /// Whether the release's pack is present on the surface (`0`/`1`).
    pub pack_present: i64,
}
