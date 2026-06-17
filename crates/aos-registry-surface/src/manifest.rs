//! The registry package-manifest (`package.toml`) schema.
//!
//! These are the pure, deserialize-only structs describing a registry's
//! `packages/<letter>/<name>.toml` documents: the `[package]` header, its
//! `[[versions]]`, and each version's per-platform artifacts and pre-compiled
//! images. They carry no I/O and no dependency on the package manager itself,
//! so they live in this wasm-clean surface crate (RFC-0004 Phase 5) and are
//! shared by `aos-package` (which re-exports them and provides the directory
//! parsers), the registry hub's `Database`/indexer, and the Cloudflare Worker.
//!
//! ```toml
//! [package]
//! name = "curl"
//! description = "command-line URL transfer tool"
//! license = "curl"
//! maintainer = "aos-core"
//!
//! [[versions]]
//! version = "8.7.1"
//!
//! [versions.platforms.x86_64-linux]
//! store_path = "/aos/store/…-curl-8.7.1"
//! nar_hash = "sha256:…"
//! nar_size = 1234
//! closure_size = 5678
//! source_drv = "/aos/store/…-curl-8.7.1.drv"
//! source_nar_hash = "sha256:…"
//! ```

use std::collections::HashMap;

use serde::Deserialize;

/// Top-level package TOML file from a registry.
#[derive(Debug, Clone, Deserialize)]
pub struct PackageToml {
    /// The `[package]` header with name and descriptive metadata.
    pub package: PackageHeader,
    /// All published `[[versions]]` entries, oldest layout order preserved.
    #[serde(default)]
    pub versions: Vec<VersionEntry>,
}

/// The `[package]` header section of a package TOML file.
#[derive(Debug, Clone, Deserialize)]
pub struct PackageHeader {
    /// Package name; must match the TOML file's basename.
    pub name: String,
    /// One-line human-readable description, searched by `apm search`.
    pub description: String,
    /// Optional upstream homepage URL.
    #[serde(default)]
    pub homepage: Option<String>,
    /// SPDX-style license identifier.
    pub license: String,
    /// Maintainer name or team handle.
    pub maintainer: String,
    /// Whether this package is a system toplevel (sysroot).
    #[serde(default)]
    pub sysroot: bool,
}

/// One `[[versions]]` entry of a package TOML file.
#[derive(Debug, Clone, Deserialize)]
pub struct VersionEntry {
    /// Version string; semver when possible, calver otherwise.
    pub version: String,
    /// Previous version in the version chain (for sysroot packages).
    #[serde(default)]
    pub previous: Option<String>,
    /// Per-platform artifacts, keyed by platform triple
    /// (e.g. `x86_64-linux`).
    #[serde(default)]
    pub platforms: HashMap<String, PlatformEntry>,
}

/// A `[versions.platforms.<platform>]` artifact entry.
#[derive(Debug, Clone, Deserialize)]
pub struct PlatformEntry {
    /// Absolute store path of the built output.
    pub store_path: String,
    /// NAR hash of the output (`sha256:...`).
    pub nar_hash: String,
    /// Uncompressed NAR size in bytes.
    pub nar_size: u64,
    /// Total uncompressed size of the runtime closure in bytes.
    pub closure_size: u64,
    /// Store path of the derivation that produced the output.
    pub source_drv: String,
    /// NAR hash of the source derivation closure.
    pub source_nar_hash: String,
    /// Store path hashes of direct runtime references.
    #[serde(default)]
    pub references: Vec<String>,
    /// Pre-compiled images (only for sysroot packages).
    #[serde(default)]
    pub images: Vec<ImageEntry>,
}

/// A pre-compiled image entry within a platform entry.
#[derive(Debug, Clone, Deserialize)]
pub struct ImageEntry {
    /// Image format identifier (e.g. `qcow2`).
    pub format: String,
    /// Absolute store path of the image artifact.
    pub store_path: String,
    /// NAR hash of the image (`sha256:...`).
    pub nar_hash: String,
    /// Uncompressed NAR size of the image in bytes.
    pub nar_size: u64,
}

// ---------------------------------------------------------------------------
// Committed root config (`registry.toml`)
// ---------------------------------------------------------------------------

use anyhow::{bail, Context, Result};
use serde::Serialize;

/// The committed `registry.toml` root configuration.
///
/// Lives at the repository root; carries the registry's display metadata, the
/// flat `[[caches]]` list, and the optional nestable `[cache_stack]`
/// expression (RFC-0004). A pure, deserialize-only schema with no I/O, so the
/// wasm-clean indexer and the Cloudflare Worker share it with `aos-package`'s
/// native git-CLI path (which re-exports it).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryRootConfig {
    /// The `[registry]` metadata table.
    pub registry: RegistryRootMeta,
    /// Committed `[[caches]]` entries: binary caches every consumer of this
    /// registry should use.
    #[serde(default)]
    pub caches: Vec<CacheEntry>,
    /// Optional committed `[cache_stack]` expression: the nestable
    /// try/mirror cache stack (RFC-0004). Carried as a raw [`toml::Value`]
    /// so stack-unaware tooling round-trips it untouched while the hub
    /// parses it into its own model; absent for registries that only use the
    /// flat `[[caches]]` list. The section, when present, flattens to the
    /// same priority list `[[caches]]` would carry, keeping old clients
    /// working unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_stack: Option<toml::Value>,
}

/// Registry metadata in `registry.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryRootMeta {
    /// Canonical registry name.
    pub name: String,
    /// Optional one-line human-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// Optional longer README-style preamble (a paragraph or three), shown
    /// above the registry home. Blank lines separate paragraphs.
    #[serde(default)]
    pub readme: Option<String>,
}

/// A binary cache entry in `registry.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    /// Base URL of the binary cache.
    pub url: String,
    /// Cache selection priority — higher is tried first (default 100).
    #[serde(default = "default_cache_priority")]
    pub priority: u32,
}

/// Serde default for [`CacheEntry::priority`].
fn default_cache_priority() -> u32 {
    100
}

// ---------------------------------------------------------------------------
// Committed trust roster (`keys.toml`)
// ---------------------------------------------------------------------------

/// The `keys.toml` schema version this build reads and writes.
pub const KEYS_TOML_SCHEMA: u32 = 1;

/// A currently active registry signing key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterKey {
    /// Human-chosen stable identifier used by revocation entries.
    pub id: String,
    /// Key in `registry:Ed25519:<base64>` form.
    pub key: String,
}

/// A planned retired key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokedKey {
    /// Identifier of the roster key being revoked.
    pub id: String,
    /// Optional human-readable revocation reason.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Trust roster stored as the committed tree file `keys.toml`.
///
/// A pure, serde-only schema (no I/O, no key parsing) so the wasm-clean
/// indexer can deserialize a committed roster and extend its trusted set;
/// `aos-package` re-exports this and layers the native load/validate/pin
/// helpers on top.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeysToml {
    /// Schema version; must equal [`KEYS_TOML_SCHEMA`].
    #[serde(default = "default_schema")]
    pub schema: u32,
    /// Currently active signing keys (`[[keys]]` in the file).
    #[serde(default, rename = "keys")]
    pub active: Vec<RosterKey>,
    /// Keys declared revoked (`[[revoked]]` in the file).
    #[serde(default)]
    pub revoked: Vec<RevokedKey>,
}

impl Default for KeysToml {
    fn default() -> Self {
        Self {
            schema: KEYS_TOML_SCHEMA,
            active: Vec::new(),
            revoked: Vec::new(),
        }
    }
}

/// Serde default for [`KeysToml::schema`].
fn default_schema() -> u32 {
    KEYS_TOML_SCHEMA
}

// ---------------------------------------------------------------------------
// Package name validation and document parsing
// ---------------------------------------------------------------------------

/// Validate a registry package name for path and schema safety.
///
/// Package names form the `packages/<bucket>/<name>.toml` path and embed in
/// store path names, require an alphanumeric leading character so bucketing
/// stays stable, and reject anything that could be interpreted as a path,
/// shell word, or TOML delimiter.
///
/// # Errors
///
/// Returns an error when `name` is empty, starts with a non-alphanumeric
/// character, or contains any byte outside ASCII letters, digits, `+`, `.`,
/// `_`, `=`, and `-`.
pub fn validate_package_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("package name must not be empty");
    }

    if !name
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_alphanumeric())
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '_' | '=' | '-'))
    {
        bail!(
            "invalid package name '{name}': use only ASCII letters, digits, '+', '.', '_', '=' and '-', starting with a letter or digit"
        );
    }

    Ok(())
}

/// Return the registry package bucket for a validated package name.
///
/// Package metadata files live under `packages/<bucket>/<name>.toml`, where
/// the bucket is the lowercase first ASCII character of the package name.
/// Call [`validate_package_name`] before using this for path construction.
#[must_use]
pub fn package_name_bucket(name: &str) -> String {
    name.chars()
        .next()
        .map(|ch| ch.to_ascii_lowercase().to_string())
        .unwrap_or_else(|| "_".to_string())
}

/// Parse a whole committed package TOML document, validating its declared name.
///
/// Unlike a flatten-to-newest install resolver, this returns the complete
/// file: every version and every platform entry, exactly as committed —
/// the unflattened view the registry hub's indexer needs.
///
/// # Errors
///
/// Returns an error if `content` is not valid package TOML or the declared
/// package name is not path-safe.
pub fn parse_package_file(content: &str) -> Result<PackageToml> {
    let toml: PackageToml = toml::from_str(content).context("invalid package TOML")?;
    validate_package_name(&toml.package.name)?;
    Ok(toml)
}
