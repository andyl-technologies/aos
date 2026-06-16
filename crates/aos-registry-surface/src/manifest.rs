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
