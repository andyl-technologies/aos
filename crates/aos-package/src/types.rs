//! On-disk data contracts and well-known paths for `apm`/`apr`.
//!
//! This module defines the serde schemas that the package manager reads and
//! writes, grouped by where they live on disk:
//!
//! - **Registry metadata** — [`PackageMeta`] (a package version entry from a
//!   registry's package TOML), the `store/` realisation graph (the `store/{hash}`
//!   adjacency-list files), and [`SysrootImageEntry`].
//! - **Registry configuration** — [`RegistryConfig`] / [`RegistryFile`]
//!   (`registries.d/*.toml`), with [`TrackingMode`], [`Transport`],
//!   [`SigningConfig`], [`SigningKeySource`], [`RegistryUploadAuthConfig`],
//!   and the mutable [`RegistryState`] appended by `apm update`.
//! - **Registry root config** — [`RegistryRootConfig`] (`registry.toml`
//!   committed inside a registry repo) and its [`CacheEntry`] list.
//! - **Profile state** — [`InstalledMeta`] / [`ApmMeta`] (per-path
//!   `meta/{hash}.json` in a profile) and the system-generation records
//!   [`ConfigGeneration`] / [`ConfigGenerationState`]
//!   (`/var/lib/profiles/system/state.json`).
//! - **Settings and scopes** — [`ApmSettings`] (`apm.conf`) and
//!   [`ProfileScope`], which maps the user/system scopes onto their config,
//!   cache, registry-clone, and trusted-key directories.
//!
//! These types are the crate's stable data contracts: changing a field name
//! or default changes what is written to (or accepted from) disk.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Current registry package metadata format understood by this crate.
pub const PACKAGE_META_FORMAT: u32 = 1;

/// Registry feature flag for RFC-0001 package attestation metadata.
pub const FEATURE_ATTESTATION_V1: &str = "attestation-v1";

/// Registry feature flag for canonical RFC-0016 package documentation.
pub const FEATURE_PACKAGE_DOCUMENTATION_V1: &str = "package-documentation-v1";

/// Registry feature flag for opaque provider-owned image artifact contracts.
pub const FEATURE_IMAGE_ARTIFACT_CONTRACT_V1: &str = "image-artifact-contract-v1";

/// Registry feature flag for an authenticated RFC-0022 ability manifest.
pub const FEATURE_ABILITIES_V1: &str = "abilities-v1";

/// Registry feature flag for RFC-0022 structured effect activation.
pub const FEATURE_ABILITY_EFFECTS_V1: &str = "ability-effects-v1";

/// Names the retained derivation output containing an ability manifest.
pub const PACKAGE_CONTRACT_OUTPUT: &str = "contract";

const SUPPORTED_PACKAGE_FEATURES: &[&str] = &[
    FEATURE_ATTESTATION_V1,
    FEATURE_PACKAGE_DOCUMENTATION_V1,
    FEATURE_IMAGE_ARTIFACT_CONTRACT_V1,
    FEATURE_ABILITIES_V1,
    FEATURE_ABILITY_EFFECTS_V1,
];

// ---------------------------------------------------------------------------
// Well-known paths
// ---------------------------------------------------------------------------

/// Base directory for per-user and system profiles.
const PROFILES_BASE: &str = "/var/lib/profiles";

/// Environment override for the profile root.
const PROFILES_BASE_ENV: &str = "AOS_PROFILE_ROOT";

/// Base directory for system-wide APM state.
const APM_STATE_DIR: &str = "/var/lib/apm";

/// Default system-wide APM configuration directory.
const DEFAULT_APM_SYSTEM_CONFIG_DIR: &str = "/etc/apm";

/// Environment override for the AOS root filesystem.
const AOS_ROOT_ENV: &str = "AOS_ROOT";

/// Validate a registry name before using it as an on-disk path component.
///
/// Registry names are used for files under `registries.d/`, local clone
/// directories, metadata caches, and trusted-key pins. Keep the accepted
/// syntax intentionally small so command-line input and hand-written config
/// cannot escape those directories.
///
/// # Errors
///
/// Returns an error when `name` is empty or contains any byte outside ASCII
/// letters, digits, `-`, and `_`.
pub fn validate_registry_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("registry name must not be empty");
    }

    if !name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        bail!("invalid registry name '{name}': use only ASCII letters, digits, '-' and '_'");
    }

    Ok(())
}

/// Validate a branch name before using it as a Git ref shorthand.
///
/// Branch names may include slash-separated components such as
/// `feature/host-workflow`, but they are restricted to a small ASCII subset
/// that is valid as a Git branch shorthand and safe to persist in registry
/// configuration.
///
/// # Errors
///
/// Returns an error when `name` is empty, is a reserved Git shorthand, or
/// contains characters or components that are invalid for registry branch
/// references.
pub fn validate_branch_name(name: &str) -> Result<()> {
    validate_git_ref_shorthand(name, "branch name", true)
}

/// Validate a rollout channel name before using it as a Git ref and path.
///
/// Channels are published as a single branch and as static partition files
/// under `channels/<name>/`, so channel names are limited to one safe ref
/// segment.
///
/// # Errors
///
/// Returns an error when `name` is empty, contains `/`, is a reserved Git
/// shorthand, or contains characters or components that are invalid for
/// registry channel references.
pub fn validate_channel_name(name: &str) -> Result<()> {
    validate_git_ref_shorthand(name, "channel name", false)
}

/// Validate an exact Git commit object id.
///
/// Registry commit tracking is persisted in config and passed to `git fetch`.
/// Accept full SHA-1 and SHA-256 object IDs only so abbreviated names,
/// refnames, and ref expressions cannot be confused with exact commits.
///
/// # Errors
///
/// Returns an error when `hash` is not exactly 40 or 64 ASCII hex digits.
pub fn validate_commit_hash(hash: &str) -> Result<()> {
    if (hash.len() == 40 || hash.len() == 64) && hash.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Ok(());
    }

    bail!("invalid commit hash '{hash}': expected 40 or 64 ASCII hex digits")
}

fn validate_git_ref_shorthand(name: &str, kind: &str, allow_slash: bool) -> Result<()> {
    if name.is_empty() {
        bail!("invalid {kind}: must not be empty");
    }

    let invalid_shape = name == "@"
        || name == "HEAD"
        || name.starts_with('-')
        || name.starts_with('/')
        || name.ends_with('/')
        || name.ends_with('.')
        || name.starts_with("refs/")
        || name.contains("..")
        || name.contains("@{")
        || name.contains("//");

    if invalid_shape {
        bail!("invalid {kind} '{name}': use a safe Git ref shorthand");
    }

    if !allow_slash && name.contains('/') {
        bail!("invalid {kind} '{name}': use a single safe Git ref segment");
    }

    for component in name.split('/') {
        if component.starts_with('.') || component.ends_with(".lock") {
            bail!("invalid {kind} '{name}': use safe Git ref components");
        }
    }

    if !name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '/'))
    {
        bail!("invalid {kind} '{name}': use only ASCII letters, digits, '.', '_', '-', and '/'");
    }

    Ok(())
}

// Package-name validation and bucketing moved to the wasm-clean
// `aos-registry-surface` crate (RFC-0004 Phase 5) so the registry hub's indexer
// and the Cloudflare Worker share the exact rules without pulling `aos-package`.
// Re-exported here so `aos_package::types::{validate_package_name,
// package_name_bucket}` paths are unchanged.
pub use aos_registry_surface::manifest::{package_name_bucket, validate_package_name};

/// Validate a platform/system name before using it as a package TOML key.
///
/// Platform names become keys under `[versions.platforms]`, for example
/// `x86_64-linux` or `aarch64-darwin`. Keep the accepted syntax to common Nix
/// system names so command-line input cannot inject TOML structure or create
/// ambiguous metadata.
///
/// # Errors
///
/// Returns an error when `name` is empty or contains any byte outside ASCII
/// letters, digits, `_`, and `-`.
pub fn validate_platform_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("platform name must not be empty");
    }

    if !name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        bail!("invalid platform name '{name}': use only ASCII letters, digits, '_' and '-'");
    }

    Ok(())
}

/// Validate a Git branch or tag name before passing it to Git commands.
///
/// APR maintainer commands accept branch names such as `release/2026.06`
/// and tag names such as `1.2.3`, but the names must still be safe Git
/// refname shorthand. This keeps the accepted syntax to a small ASCII
/// subset that covers semver tags, rollout channels, and slash-separated
/// maintainer refs while rejecting values that would be ambiguous at
/// command boundaries.
///
/// # Errors
///
/// Returns an error when `name` is empty, is a reserved Git shorthand, starts
/// with `-`, contains a path separator pattern that cannot be a Git ref,
/// contains ref-expression syntax, or contains characters outside the safe
/// shorthand set.
pub fn validate_git_ref_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("git ref name must not be empty");
    }

    if name.starts_with('-') {
        bail!("invalid git ref name '{name}': must not start with '-'");
    }

    if name == "@"
        || name == "HEAD"
        || name.starts_with('/')
        || name.ends_with('/')
        || name.ends_with('.')
        || name.starts_with("refs/")
        || name.contains("//")
        || name.contains("..")
        || name.contains("@{")
    {
        bail!("invalid git ref name '{name}'");
    }

    if !name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '/' | '+'))
    {
        bail!("invalid git ref name '{name}'");
    }

    for component in name.split('/') {
        if component.is_empty() || component.starts_with('.') || component.ends_with(".lock") {
            bail!("invalid git ref name '{name}'");
        }
    }

    Ok(())
}

/// Resolve the system-wide APM configuration directory from a raw
/// environment value.
///
/// Returns `value` when it is set to a non-empty *absolute* path, and
/// [`DEFAULT_APM_SYSTEM_CONFIG_DIR`] (`/etc/apm`) otherwise. Relative or
/// empty values are ignored rather than rejected so that a stray
/// `APM_SYSTEM_CONFIG_DIR=` in the environment cannot redirect system
/// configuration to an unexpected location.
///
/// This is the pure core of [`apm_system_config_dir`], split out so it can
/// be unit-tested without mutating process-global environment state.
fn resolve_system_config_dir(value: Option<&str>) -> PathBuf {
    if let Some(value) = value {
        let path = PathBuf::from(value);
        if !value.is_empty() && path.is_absolute() {
            return path;
        }
    }
    PathBuf::from(DEFAULT_APM_SYSTEM_CONFIG_DIR)
}

/// The system-wide APM configuration directory, honoring
/// `$APM_SYSTEM_CONFIG_DIR`.
///
/// Defaults to `/etc/apm`. When the `APM_SYSTEM_CONFIG_DIR` environment
/// variable is set to a non-empty absolute path, every derived system path
/// (`registries.d`, `trusted-keys.d`, …) is rooted there instead. This is
/// the supported way to point `apm`/`apr` at a writable fixture tree when
/// developing on non-AOS hosts.
///
/// The value is resolved once per process and cached; later environment
/// changes have no effect.
fn apm_system_config_dir() -> &'static Path {
    static DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        let value = std::env::var("APM_SYSTEM_CONFIG_DIR").ok();
        resolve_system_config_dir(value.as_deref())
    })
}

/// Resolve system-wide APM state from `$AOS_ROOT`.
///
/// With no root override, system state stays at [`APM_STATE_DIR`]
/// (`/var/lib/apm`). When `$AOS_ROOT` is a non-empty absolute path, system
/// state is rooted under `<AOS_ROOT>/var/lib/apm`, matching the existing
/// rootfs override used for Nix store and profile integration tests.
fn resolve_apm_state_dir(root: Option<&str>) -> PathBuf {
    if let Some(root) = root {
        let path = PathBuf::from(root);
        if !root.is_empty() && path.is_absolute() {
            return path.join("var/lib/apm");
        }
    }

    PathBuf::from(APM_STATE_DIR)
}

/// The system-wide APM state directory, honoring `$AOS_ROOT`.
fn apm_state_dir() -> &'static Path {
    static DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        let value = std::env::var(AOS_ROOT_ENV).ok();
        resolve_apm_state_dir(value.as_deref())
    })
}

/// Resolve the current user's home directory.
///
/// Uses a non-empty `$HOME` when set. Otherwise falls back to `/tmp` with a
/// warning on stderr — better than silently scattering user-scoped state
/// across process-relative paths. Never panics.
fn resolve_home() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home);
        }
    }
    // Last-resort fallback: construct from /tmp with a warning.  This is
    // better than silently scattering state into /tmp directly.
    eprintln!("warning: $HOME is not set; falling back to /tmp for user-scoped APM paths");
    PathBuf::from("/tmp")
}

/// Resolve an [XDG Base Directory] from a raw environment value.
///
/// Returns `value` if it is set to an *absolute* path (per the XDG
/// specification, relative paths are invalid and must be ignored). Otherwise
/// falls back to `home` joined with `default_rel` (e.g. `.config`).
///
/// This is the pure core of [`xdg_dir`], split out so it can be unit-tested
/// without mutating process-global environment state.
///
/// [XDG Base Directory]: https://specifications.freedesktop.org/basedir-spec/latest/
fn resolve_xdg(value: Option<&str>, home: &Path, default_rel: &str) -> PathBuf {
    if let Some(value) = value {
        let path = PathBuf::from(value);
        if path.is_absolute() {
            return path;
        }
    }
    home.join(default_rel)
}

/// Resolve an [XDG Base Directory] for the current user.
///
/// Reads the environment variable named by `env` and applies [`resolve_xdg`],
/// falling back to the user's home directory joined with `default_rel`.
///
/// [XDG Base Directory]: https://specifications.freedesktop.org/basedir-spec/latest/
fn xdg_dir(env: &str, default_rel: &str) -> PathBuf {
    let value = std::env::var(env).ok();
    resolve_xdg(value.as_deref(), &resolve_home(), default_rel)
}

/// `$XDG_CONFIG_HOME`, defaulting to `~/.config`.
fn xdg_config_home() -> PathBuf {
    xdg_dir("XDG_CONFIG_HOME", ".config")
}

/// `$XDG_DATA_HOME`, defaulting to `~/.local/share`.
fn xdg_data_home() -> PathBuf {
    xdg_dir("XDG_DATA_HOME", ".local/share")
}

/// `$XDG_CACHE_HOME`, defaulting to `~/.cache`.
fn xdg_cache_home() -> PathBuf {
    xdg_dir("XDG_CACHE_HOME", ".cache")
}

/// Resolve the profile root from an optional environment value.
///
/// Relative and empty overrides are ignored so profile state never lands under
/// a surprising process-relative path.
fn resolve_profiles_base(value: Option<&str>) -> PathBuf {
    if let Some(value) = value {
        let path = PathBuf::from(value);
        if path.is_absolute() {
            return path;
        }
    }

    PathBuf::from(PROFILES_BASE)
}

/// Base directory for per-user and system profiles.
fn profiles_base() -> PathBuf {
    let value = std::env::var(PROFILES_BASE_ENV).ok();
    resolve_profiles_base(value.as_deref())
}

// ---------------------------------------------------------------------------
// Package metadata — a package as described in a registry TOML file
// ---------------------------------------------------------------------------

/// A package version entry for a specific platform, as found in a registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMeta {
    /// Package name (the registry TOML file name and `apm install` argument).
    pub name: String,
    /// Package version string.
    pub version: String,
    /// One-line human-readable description.
    pub description: String,
    /// Upstream homepage URL, if recorded.
    #[serde(default)]
    pub homepage: Option<String>,
    /// SPDX-style license identifier or free-form license string.
    pub license: String,
    /// Maintainer contact recorded at publish time.
    pub maintainer: String,
    /// Target platform (e.g. `x86_64-linux`).
    pub platform: String,
    /// Full store path of the package output.
    pub store_path: String,
    /// Hash of the uncompressed NAR: `"sha256:..."`.
    pub nar_hash: String,
    /// Size of the uncompressed NAR in bytes.
    pub nar_size: u64,
    /// Store path hashes of direct runtime references.
    pub references: Vec<String>,
    /// Source derivation store path.
    pub source_drv: String,
    /// Hash of the source derivation NAR.
    pub source_nar_hash: String,
    /// Total NAR size of the full closure.
    pub closure_size: u64,
    /// Whether this package is a system toplevel (sysroot).
    #[serde(default)]
    pub sysroot: bool,
    /// Previous version in the version chain (for sysroot packages).
    #[serde(default)]
    pub previous: Option<String>,
    /// Pre-compiled images (only for sysroot packages).
    #[serde(default)]
    pub images: Vec<SysrootImageEntry>,
    /// Minimum package metadata format required to safely consume this entry.
    #[serde(
        default,
        rename = "min-format",
        skip_serializing_if = "Option::is_none"
    )]
    pub min_format: Option<u32>,
    /// Feature flags a consumer must understand before installing this entry.
    #[serde(
        default,
        rename = "requires-features",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub requires_features: Vec<String>,
    /// Canonical package documentation selected for this version/platform.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub documentation: Option<DocumentationArtifactMeta>,
    /// Authenticated RFC-0022 ability package companion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<PackageContractMeta>,
    /// Runtime integrity, attestation, and provenance facts for this package.
    #[serde(default, skip_serializing_if = "AttestationMeta::is_empty")]
    pub attestation: AttestationMeta,
}

// Shared package metadata schemas live in the wasm-clean registry-surface
// crate so the registry hub and package client consume one contract.
pub use aos_registry_surface::manifest::AttestationMeta;

pub use aos_registry_surface::manifest::{
    DocumentationArtifactMeta, PackageContractArtifactMeta, PackageContractClosureMemberMeta,
    PackageContractDocumentMeta, PackageContractMeta, PackageContractSelectorMeta,
};

/// Returns the top-level root segment of a dotted option path.
///
/// `"firewall.allowedTCPPorts"` → `"firewall"`; a path with no `.` is its own
/// root.
pub fn option_path_root(path: &str) -> &str {
    path.split('.').next().unwrap_or(path)
}

/// Returns whether package metadata must be backed by DSSE provenance.
///
/// Package documentation and package contracts require provenance.
pub(crate) fn package_requires_provenance(meta: &PackageMeta) -> bool {
    meta.documentation.is_some() || meta.contract.is_some()
}

/// Validate that a package metadata entry can be safely consumed.
///
/// # Errors
///
/// Returns an error when the entry requires a newer format, names an
/// unsupported feature, uses authenticated metadata without declaring its
/// feature gate, names invalid package requirements, or requests
/// `CAP_SYS_MODULE` inside the workload instead of using the host-fulfilled
/// `kernel-modules` permission.
pub fn validate_supported_package_meta(meta: &PackageMeta) -> Result<()> {
    validate_supported_package_meta_with(meta, PACKAGE_META_FORMAT, SUPPORTED_PACKAGE_FEATURES)
}

/// Validate a package metadata entry against an explicit format/feature set.
///
/// This helper models older clients in tests: a client that supports the
/// common gate fields but lacks the named feature must refuse the entry before
/// it can silently ignore privilege metadata.
///
/// # Errors
///
/// Returns an error when [`validate_supported_package_meta`] would reject the
/// entry for the supplied capabilities.
pub fn validate_supported_package_meta_with(
    meta: &PackageMeta,
    supported_format: u32,
    supported_features: &[&str],
) -> Result<()> {
    if let Some(min_format) = meta.min_format {
        if min_format > supported_format {
            bail!(
                "package '{}' requires package metadata format {min_format}, but this apm supports {supported_format}",
                meta.name
            );
        }
    }

    for feature in &meta.requires_features {
        if !supported_features.contains(&feature.as_str()) {
            bail!(
                "package '{}' requires unsupported registry feature '{feature}'",
                meta.name
            );
        }
    }

    if !meta.attestation.is_empty() {
        require_feature(meta, FEATURE_ATTESTATION_V1)?;
        validate_attestation_meta(&meta.attestation)
            .with_context(|| format!("invalid attestation metadata for '{}'", meta.name))?;
    }
    if let Some(documentation) = &meta.documentation {
        require_feature(meta, FEATURE_PACKAGE_DOCUMENTATION_V1)?;
        validate_documentation_artifact_meta(documentation).with_context(|| {
            format!("invalid package-documentation metadata for '{}'", meta.name)
        })?;
    }
    if let Some(ability) = &meta.contract {
        require_feature(meta, FEATURE_ABILITIES_V1)?;
        crate::package_contract::validate_package_contract_meta(ability)
            .with_context(|| format!("invalid package contract metadata for '{}'", meta.name))?;
    }
    if !meta.images.is_empty() {
        require_feature(meta, FEATURE_IMAGE_ARTIFACT_CONTRACT_V1)?;
    }
    for image in &meta.images {
        validate_image_entry(image, &meta.version, &meta.platform)
            .with_context(|| format!("invalid sysroot image metadata for '{}'", meta.name))?;
    }
    if package_requires_provenance(meta) && meta.attestation.provenance.is_none() {
        let reason = if meta.documentation.is_some() {
            "uses package-documentation metadata"
        } else if meta.contract.is_some() {
            "uses ability metadata"
        } else {
            "uses BPF-LSM metadata"
        };
        bail!(
            "package '{}' {reason} without attestation provenance",
            meta.name
        );
    }

    Ok(())
}

fn require_feature(meta: &PackageMeta, feature: &str) -> Result<()> {
    if meta
        .requires_features
        .iter()
        .any(|declared| declared == feature)
    {
        return Ok(());
    }

    bail!(
        "package '{}' uses registry feature '{feature}' without declaring it in requires-features",
        meta.name
    )
}

/// Validates a canonical package-documentation artifact locator.
///
/// Version 1 is a single regular-file NAR whose canonical JSON is at most 4
/// MiB and whose reference set is empty. The NAR may be slightly larger than
/// the document because of archive framing, but both are independently capped.
///
/// # Errors
///
/// Returns an error when the format is unsupported, the store/NAR identity is
/// malformed, either size is zero or exceeds the version-1 limit, the document
/// digest is malformed, or the object claims any store reference.
pub fn validate_documentation_artifact_meta(
    documentation: &DocumentationArtifactMeta,
) -> Result<()> {
    if documentation.format != aos_doc_model::DOCUMENT_FORMAT {
        bail!(
            "unsupported package-documentation format '{}'",
            documentation.format
        );
    }
    validate_absolute_path(&documentation.store_path, "documentation store path")?;
    if store_path_hash_component(&documentation.store_path).is_none() {
        bail!(
            "documentation store path is not a Nix-style store path: {}",
            documentation.store_path
        );
    }
    if !documentation.nar_hash.starts_with("sha256:")
        && !documentation.nar_hash.starts_with("sha256-")
    {
        bail!(
            "documentation '{}' has invalid NAR hash",
            documentation.store_path
        );
    }
    const LIMIT: u64 = aos_doc_model::MAX_DOCUMENT_BYTES as u64;
    if documentation.nar_size == 0 || documentation.nar_size > LIMIT {
        bail!(
            "documentation '{}' NAR size {} is outside 1..={LIMIT}",
            documentation.store_path,
            documentation.nar_size
        );
    }
    if documentation.document_size == 0 || documentation.document_size > LIMIT {
        bail!(
            "documentation '{}' JSON size {} is outside 1..={LIMIT}",
            documentation.store_path,
            documentation.document_size
        );
    }
    validate_sha256_hex(
        "documentation document_sha256",
        &documentation.document_sha256,
    )?;
    validate_sha256_hex(
        "documentation semantic_schema_sha256",
        &documentation.semantic_schema_sha256,
    )?;
    if !documentation.references.is_empty() {
        bail!(
            "documentation '{}' must have an empty reference set",
            documentation.store_path
        );
    }
    Ok(())
}

fn validate_sha256_hex(label: &str, digest: &str) -> Result<()> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        bail!("{label} must use sha256:<hex>");
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{label} is not a 32-byte hexadecimal digest");
    }
    Ok(())
}

fn validate_account_name(name: &str) -> Result<()> {
    let mut chars = name.chars();
    if !chars
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
        || !chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
    {
        bail!("invalid account artifact name '{name}'");
    }
    Ok(())
}

/// Validate runtime integrity, attestation, and provenance metadata.
///
/// # Errors
///
/// Returns an error when root-hash/signature fields are incomplete, hash fields
/// are malformed SHA-256 digests, or registry-served artifact references are
/// unsafe.
pub fn validate_attestation_meta(meta: &AttestationMeta) -> Result<()> {
    if meta.root_hash.is_some() != meta.root_hash_sig.is_some() {
        bail!("attestation root_hash and root_hash_sig must be declared together");
    }
    if meta.measurement.is_some() && meta.root_digest.is_none() && meta.root_hash.is_none() {
        bail!("attestation measurement requires root_digest or root_hash/root_hash_sig");
    }
    if let Some(root_digest) = &meta.root_digest {
        validate_sha256_digest("attestation root_digest", root_digest)?;
    }
    if let Some(root_hash) = &meta.root_hash {
        validate_sha256_digest("attestation root_hash", root_hash)?;
    }
    if let (Some(root_digest), Some(root_hash)) = (&meta.root_digest, &meta.root_hash)
        && canonical_sha256_digest(root_digest) != canonical_sha256_digest(root_hash)
    {
        bail!("attestation root_digest must match root_hash when both are declared");
    }
    if let Some(measurement) = &meta.measurement {
        validate_sha256_digest("attestation measurement", measurement)?;
    }
    if let Some(root_hash_sig) = &meta.root_hash_sig {
        validate_relative_artifact_path("attestation root_hash_sig", root_hash_sig, ".p7s")?;
    }
    if let Some(provenance) = &meta.provenance {
        validate_attestation_provenance_ref(provenance)?;
    }
    Ok(())
}

/// Validate a registry-hosted attestation provenance JSONL reference.
///
/// The package registry cache has reserved top-level trees for package
/// metadata, store-graph records, transport state, and transparency metadata.
/// Provenance statements may use the generated `provenance/` tree or a
/// custom artifact directory, but must not masquerade as those cache-owned
/// trees.
///
/// # Errors
///
/// Returns an error when `path` is not a safe relative `.jsonl` artifact path
/// or targets a cache-owned registry subtree.
pub fn validate_attestation_provenance_ref(path: &str) -> Result<()> {
    validate_relative_artifact_path("attestation provenance", path, ".jsonl")?;
    if matches!(
        Path::new(path).components().next(),
        Some(std::path::Component::Normal(part))
            if matches!(
                part.to_str(),
                Some("packages" | "store" | "repo.git" | "transparency")
            )
    ) {
        bail!("attestation provenance path '{path}' must not target a cache-owned subtree");
    }
    Ok(())
}

fn validate_sha256_digest(kind: &str, digest: &str) -> Result<()> {
    let hex = digest
        .strip_prefix("sha256:")
        .or_else(|| digest.strip_prefix("sha256-"))
        .with_context(|| format!("{kind} must start with sha256: or sha256-"))?;
    if hex.len() != 64 || !hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        bail!("{kind} must contain a 64-character SHA-256 digest");
    }
    Ok(())
}

fn canonical_sha256_digest(digest: &str) -> Option<String> {
    let hex = digest
        .strip_prefix("sha256:")
        .or_else(|| digest.strip_prefix("sha256-"))?;
    if hex.len() == 64 && hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Some(format!("sha256:{}", hex.to_ascii_lowercase()));
    }
    None
}

fn validate_relative_artifact_path(kind: &str, path: &str, suffix: &str) -> Result<()> {
    if !path.ends_with(suffix) {
        bail!("{kind} path '{path}' must be a relative *{suffix} path");
    }
    validate_relative_artifact_member_path(kind, path)
}

fn validate_relative_artifact_member_path(kind: &str, path: &str) -> Result<()> {
    if path.is_empty() || path.starts_with('/') || path.contains('\\') {
        bail!("{kind} path '{path}' must be a relative artifact path");
    }
    if !path.chars().all(|ch| {
        ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '/' | '+' | '=' | '@' | '-')
    }) {
        bail!("{kind} path '{path}' contains unsupported characters");
    }
    for component in Path::new(path).components() {
        match component {
            std::path::Component::Normal(part) if !part.is_empty() => {}
            _ => bail!("{kind} path '{path}' must not contain '.', '..', or prefixes"),
        }
    }
    Ok(())
}

pub(crate) fn validate_absolute_path(path: &str, kind: &str) -> Result<()> {
    if Path::new(path).is_absolute() {
        return Ok(());
    }
    bail!("{kind} must be an absolute path: {path}")
}

pub(crate) fn validate_credential_ciphertext(ciphertext: &str) -> Result<()> {
    if !ciphertext.is_empty()
        && ciphertext
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=' | '.' | '_' | '-'))
    {
        return Ok(());
    }
    bail!("credential ciphertext contains unsupported characters")
}

fn validate_image_entry(image: &SysrootImageEntry, release: &str, platform: &str) -> Result<()> {
    if image.format.is_empty()
        || !image
            .format
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        bail!("invalid image format '{}'", image.format);
    }
    validate_absolute_path(&image.store_path, "image store path")?;
    if !(image.nar_hash.starts_with("sha256:") || image.nar_hash.starts_with("sha256-")) {
        bail!("image '{}' has invalid NAR hash", image.store_path);
    }
    image.delivery.validate(&image.format, release, platform)?;
    Ok(())
}

fn store_path_hash_component(path: &str) -> Option<&str> {
    let basename = path.rsplit('/').next()?;
    let (hash, _) = basename.split_once('-')?;
    if hash.len() >= 2 && hash.chars().all(|ch| ch.is_ascii_alphanumeric()) {
        Some(hash)
    } else {
        None
    }
}

pub(crate) fn validate_security_label(label: &str) -> Result<()> {
    if label.is_empty()
        || !label
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        bail!("invalid security label '{label}'");
    }
    Ok(())
}

fn validate_display_ascii(kind: &str, value: &str) -> Result<()> {
    if value.is_empty() || !value.chars().all(|ch| ch.is_ascii_graphic() || ch == ' ') {
        bail!("invalid {kind} '{value}'");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Installed metadata — per-path JSON in profile `meta/{hash}.json`
// ---------------------------------------------------------------------------

/// Metadata stored in the profile's `meta/{hash}.json` for each installed path.
///
/// The base fields (`store_path` through `access_count`) are shared with the
/// cache server's per-path metadata so that `aos gc` can read both uniformly.
/// The optional `apm` section extends this with package manager state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledMeta {
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
    pub apm: Option<ApmMeta>,
}

/// APM-specific metadata extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApmMeta {
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
    /// Canonical documentation artifact captured at install time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub documentation: Option<DocumentationArtifactMeta>,
    /// Authenticated ability companion captured at install time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<PackageContractMeta>,
    /// Runtime integrity, attestation, and provenance facts captured at install time.
    #[serde(default, skip_serializing_if = "AttestationMeta::is_empty")]
    pub attestation: AttestationMeta,
}

// ---------------------------------------------------------------------------
// Registry configuration — from `registries.d/*.toml`
// ---------------------------------------------------------------------------

/// Parsed configuration for a single registry source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryConfig {
    /// Registry name; also names the config file, clone directory, and
    /// metadata cache directory.
    pub name: String,
    /// Registry URL; its scheme selects the [`Transport`].
    pub url: String,
    /// Resolution priority — higher wins when several registries provide the
    /// same package (default 500).
    #[serde(default = "default_priority")]
    pub priority: u32,
    /// Whether this registry participates in resolution and updates
    /// (default true).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Exact commit hash to pin to (mutually exclusive with branch/tag/version).
    #[serde(default)]
    pub commit: Option<String>,
    /// Branch name to track HEAD of (mutually exclusive with commit/tag/version).
    #[serde(default)]
    pub branch: Option<String>,
    /// Rollout channel to track via the channel partition overlay.
    #[serde(default)]
    pub channel: Option<String>,
    /// Exact tag name to pin to (mutually exclusive with commit/branch/version).
    #[serde(default)]
    pub tag: Option<String>,
    /// Semver version constraint on tags (mutually exclusive with commit/branch/tag).
    #[serde(default)]
    pub version: Option<String>,
    /// Legacy alias: old `pin` field is treated as `tag` for backward compatibility.
    #[serde(default)]
    pub pin: Option<String>,
    /// Maximum age, in seconds, since the last successful channel sync before a
    /// failed refresh is treated as stale. Defaults to 14 days for channels.
    #[serde(default)]
    pub max_staleness_seconds: Option<u64>,
    /// Client-side binary cache override/supplement entries. These are merged
    /// with the committed root registry.toml caches, then sorted by priority.
    #[serde(default)]
    pub caches: Vec<CacheEntry>,
    /// Producer-side internal cache staging policy.
    #[serde(default)]
    pub cache: RegistryCacheConfig,
    /// Producer-side defaults for `apr cache generate --upload-url` backend auth.
    #[serde(default)]
    pub upload_auth: Option<RegistryUploadAuthConfig>,
    /// Producer-side local signing-key sources keyed by committed keys.toml id.
    #[serde(default)]
    pub signing_keys: BTreeMap<String, SigningKeySource>,
    /// Signature-verification policy (`[registry.signing]`). Absent means
    /// verification is required — see [`SigningConfig`].
    #[serde(default)]
    pub signing: Option<SigningConfig>,
}

/// How to obtain a producer-side private signing key for a `keys.toml` id.
///
/// Configured as the value of an entry in `[registry.signing_keys]`. Three
/// forms are accepted:
///
/// ```toml
/// [registry.signing_keys]
/// alice = "/run/secrets/alice"                 # bare string: a key file path
/// bob   = { path = "/run/secrets/bob" }        # explicit path
/// carol = { command = "pass show apm/carol" }  # run a command for the key
/// ```
///
/// A command source is run via `sh -c` and must print the unencrypted
/// OpenSSH private key to stdout. The key is materialized just-in-time into
/// a private temporary file for the duration of a single signature and is
/// never persisted by the tool, so the key can live exclusively in a secrets
/// manager. The command runs with the invoking user's `PATH` (stashed in
/// `AOS_HOST_PATH` by the `aos`/`apm`/`apr` wrappers), not the tool's
/// hermetic `PATH`, so host-installed secret-manager CLIs resolve normally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SigningKeySource {
    /// A bare path string to an on-disk private key file.
    Path(String),
    /// A table selecting either a `path` or a `command`.
    Spec(SigningKeySpec),
}

/// The table form of a [`SigningKeySource`].
///
/// Exactly one of `path` or `command` must be set; the resolver rejects an
/// entry that sets both or neither.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningKeySpec {
    /// Path to an on-disk private key file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Command, run via `sh -c`, whose stdout is the private key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

impl SigningKeySource {
    /// The configured key file path, if this is a path source.
    ///
    /// Returns the inner string for the bare-string form and the `path`
    /// field for the table form (`None` for a command source).
    pub fn path(&self) -> Option<&str> {
        match self {
            Self::Path(path) => Some(path.as_str()),
            Self::Spec(spec) => spec.path.as_deref(),
        }
    }

    /// The configured key command, if this is a command source.
    pub fn command(&self) -> Option<&str> {
        match self {
            Self::Path(_) => None,
            Self::Spec(spec) => spec.command.as_deref(),
        }
    }
}

/// Serde default for [`RegistryConfig::priority`].
fn default_priority() -> u32 {
    500
}
/// Serde default for boolean fields that default to `true`.
fn default_true() -> bool {
    true
}

/// Default retention for producer-side static-cache staging.
pub const DEFAULT_REGISTRY_CACHE_MAX_AGE_DAYS: u64 = 30;

/// Producer-side internal static-cache staging policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryCacheConfig {
    /// Number of days to retain unused staged narinfo/NAR pairs. When unset,
    /// `apr cache gc` and automatic successful-run GC use 30 days.
    #[serde(default)]
    pub max_age_days: Option<u64>,
}

impl RegistryCacheConfig {
    /// Returns the configured retention period, defaulting to 30 days.
    pub fn max_age_days(&self) -> u64 {
        self.max_age_days
            .unwrap_or(DEFAULT_REGISTRY_CACHE_MAX_AGE_DAYS)
    }
}

/// Signing configuration embedded in a registry config.
///
/// Signature verification is fail-closed: a registry config *without* a
/// `[registry.signing]` section behaves as `required = true`. Writing an
/// explicit `required = false` is the only way to opt a registry out of
/// verification (intended for local development fixtures).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningConfig {
    /// Whether signature verification is enforced for this registry
    /// (default true; see the fail-closed note above).
    #[serde(default = "default_true")]
    pub required: bool,
    /// Bootstrap trust anchor in `"name:Ed25519:base64key"` format.
    ///
    /// This key seeds the trusted set on first contact, before the
    /// registry's committed `keys.toml` roster has been verified and
    /// pinned. Once roster keys are pinned into `trusted-keys.d`, the
    /// roster — not this field — is the authoritative trusted-key set.
    #[serde(default)]
    pub public_key: Option<String>,
    /// Provenance key ids authorized by the operator to introduce or replace
    /// shared-root ownership claims.
    ///
    /// An authenticated package signed by any other roster key may still be
    /// installed when it owns no shared roots. Root ownership is privileged
    /// and fails closed when this allowlist is empty.
    #[serde(default)]
    pub root_owner_signers: Vec<String>,
}

/// Producer-side defaults for registry uploads: destinations and backend
/// authentication.
///
/// This is read from `[registry.upload_auth]` in `registries.d/<name>.toml`
/// and written by `apr origin config`. CLI flags and their env bindings
/// override these defaults.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryUploadAuthConfig {
    /// Default upload destinations (`file://`, `s3://`, `sftp://`,
    /// `http://`), used by `apr origin upload`, `apr cache generate`, and
    /// `apr release` when no `--upload-url` flag is given.
    #[serde(default)]
    pub upload_urls: Vec<String>,
    /// AOS provisioning token for AOS cache backends.
    #[serde(default)]
    pub token: Option<String>,
    /// AOS cache view name (defaults to `"default"` when unset).
    #[serde(default)]
    pub view: Option<String>,
    /// Basic-auth username for generic HTTP backends.
    #[serde(default)]
    pub http_user: Option<String>,
    /// Basic-auth password for generic HTTP backends.
    #[serde(default)]
    pub http_password: Option<String>,
    /// Extra HTTP headers, each as a full `"Name: value"` string.
    #[serde(default)]
    pub headers: Vec<String>,
    /// AWS region for S3 backends.
    #[serde(default)]
    pub s3_region: Option<String>,
    /// AWS credentials profile name for S3 backends.
    #[serde(default)]
    pub s3_profile: Option<String>,
    /// Custom S3-compatible endpoint (MinIO, B2, ...).
    #[serde(default)]
    pub s3_endpoint: Option<String>,
    /// Path to an SSH private key for SFTP backends.
    #[serde(default)]
    pub ssh_key: Option<String>,
    /// SSH password for SFTP backends.
    #[serde(default)]
    pub ssh_password: Option<String>,
    /// Prompt for the SSH password interactively.
    #[serde(default)]
    pub ssh_ask_pass: bool,
}

impl RegistryUploadAuthConfig {
    /// Convert these config defaults into backend [`aos_cache::AuthOptions`],
    /// substituting the `"default"` view when none is configured.
    pub fn auth_options(&self) -> aos_cache::AuthOptions {
        aos_cache::AuthOptions {
            token: self.token.clone(),
            view: self.view.clone().unwrap_or_else(|| "default".to_string()),
            http_user: self.http_user.clone(),
            http_password: self.http_password.clone(),
            headers: self.headers.clone(),
            s3_region: self.s3_region.clone(),
            s3_profile: self.s3_profile.clone(),
            s3_endpoint: self.s3_endpoint.clone(),
            ssh_key: self.ssh_key.clone(),
            ssh_password: self.ssh_password.clone(),
            ssh_ask_pass: self.ssh_ask_pass,
        }
    }
}

/// Mutable state appended to a registry config file by `apm update`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegistryState {
    /// Commit hash the local clone was last synced to.
    #[serde(default)]
    pub last_commit: Option<String>,
    /// Channel tracking: monotonic semver floor — the highest release this
    /// host has verified; a channel pointing at anything older is refused
    /// (rollback-attack protection).
    #[serde(default)]
    pub last_roster_commit: Option<String>,
    #[serde(default)]
    pub floor: Option<String>,
    /// Channel tracking: this host's stable rollout partition bucket
    /// (0-255), derived from a registry-local salt on first channel sync.
    #[serde(default)]
    pub bucket: Option<u8>,
    /// Channel tracking: release versions kept locally as delta-fetch bases
    /// for future channel advances.
    #[serde(default)]
    pub retained: Vec<String>,
    /// ISO 8601 timestamp of the last successful sync.
    #[serde(default)]
    pub last_update: Option<String>,
    /// Highest accepted TUF root metadata version.
    #[serde(default)]
    pub tuf_root_version: Option<u64>,
    /// Highest accepted TUF targets metadata version.
    #[serde(default)]
    pub tuf_targets_version: Option<u64>,
    /// Highest accepted TUF snapshot metadata version.
    #[serde(default)]
    pub tuf_snapshot_version: Option<u64>,
    /// Highest accepted TUF timestamp metadata version.
    #[serde(default)]
    pub tuf_timestamp_version: Option<u64>,
}

// ---------------------------------------------------------------------------
// Transport detection
// ---------------------------------------------------------------------------

/// Transport type derived from the registry URL scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Default: `https://` or `http://` — uses git dumb-HTTP distribution.
    Http,
    /// `git://`, `git+https://`, `git+ssh://` — uses native git.
    Git,
}

/// How a registry tracks its upstream version.
///
/// Exactly one mode is active at a time; when no tracking field is set, the
/// default mode is used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrackingMode {
    /// Frozen to an exact commit hash.
    Commit(String),
    /// Track the HEAD of a named branch.
    Branch(String),
    /// Track a rollout channel using the channel partition overlay.
    Channel(String),
    /// Pinned to an exact tag name.
    Tag(String),
    /// Semver constraint applied to tags (e.g. `~2026.03`, `^2026`).
    Version(semver::VersionReq),
    /// No tracking field set -- use default branch HEAD.
    Default,
}

impl std::fmt::Display for TrackingMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrackingMode::Commit(h) => {
                write!(f, "commit:{}", h.chars().take(12).collect::<String>())
            }
            TrackingMode::Branch(b) => write!(f, "branch:{b}"),
            TrackingMode::Channel(c) => write!(f, "channel:{c}"),
            TrackingMode::Tag(t) => write!(f, "tag:{t}"),
            TrackingMode::Version(v) => write!(f, "version:{v}"),
            TrackingMode::Default => write!(f, "default"),
        }
    }
}

impl RegistryConfig {
    /// Determine the transport from the URL scheme.
    ///
    /// Returns `Git` for `git://`, `git+https://`, or `git+ssh://` URLs.
    /// Returns `Http` for all other URLs (including `https://` and
    /// `http://`).  Bare scheme-only URLs (e.g. `https://` with no host)
    /// are not rejected here — callers that need a reachable URL should
    /// validate separately via [`Self::validate_url`].
    pub fn transport(&self) -> Transport {
        if self.url.starts_with("git://")
            || self.url.starts_with("git+https://")
            || self.url.starts_with("git+ssh://")
        {
            Transport::Git
        } else {
            Transport::Http
        }
    }

    /// Basic validation that `self.url` has meaningful content after the
    /// scheme (i.e. it is not just `"https://"` or empty).
    ///
    /// # Errors
    ///
    /// Returns an error when the URL is empty or contains only a scheme with
    /// no host.
    pub fn validate_url(&self) -> Result<()> {
        if self.url.is_empty() {
            bail!("registry URL is empty");
        }
        // Strip the scheme prefix and check that something remains.
        let after_scheme = self
            .url
            .find("://")
            .map(|pos| &self.url[pos + 3..])
            .unwrap_or(&self.url);
        if after_scheme.is_empty() || after_scheme == "/" {
            bail!(
                "registry URL {:?} contains only a scheme with no host",
                self.url
            );
        }
        Ok(())
    }

    /// Resolve the tracking mode from the config fields.
    ///
    /// Validates that at most one of `commit`, `branch`, `channel`, `tag`, `version`
    /// (and legacy `pin`) is set.  The legacy `pin` field is treated as
    /// `tag` for backward compatibility.
    ///
    /// # Errors
    ///
    /// Returns an error when more than one tracking field is set, when a
    /// branch, channel, tag, or legacy pin is not safe to use as a Git ref,
    /// or when `version` is not a valid semver constraint.
    pub fn tracking_mode(&self) -> Result<TrackingMode> {
        // Merge legacy `pin` into `tag` if `tag` is not already set.
        let effective_tag = self.tag.clone().or_else(|| self.pin.clone());

        let mut count = 0u32;
        if self.commit.is_some() {
            count += 1;
        }
        if self.branch.is_some() {
            count += 1;
        }
        if self.channel.is_some() {
            count += 1;
        }
        if effective_tag.is_some() {
            count += 1;
        }
        if self.version.is_some() {
            count += 1;
        }

        if count > 1 {
            bail!(
                "registry '{}': only one of commit, branch, channel, tag, version \
                 may be set (found {})",
                self.name,
                count,
            );
        }

        if let Some(ref hash) = self.commit {
            validate_commit_hash(hash)
                .with_context(|| format!("registry '{}': invalid commit tracking", self.name))?;
            return Ok(TrackingMode::Commit(hash.clone()));
        }
        if let Some(ref branch) = self.branch {
            validate_branch_name(branch)
                .with_context(|| format!("registry '{}': invalid branch tracking", self.name))?;
            return Ok(TrackingMode::Branch(branch.clone()));
        }
        if let Some(ref channel) = self.channel {
            validate_channel_name(channel)
                .with_context(|| format!("registry '{}': invalid channel tracking", self.name))?;
            return Ok(TrackingMode::Channel(channel.clone()));
        }
        if let Some(ref tag) = effective_tag {
            validate_git_ref_name(tag)
                .with_context(|| format!("registry '{}': invalid tag tracking", self.name))?;
            return Ok(TrackingMode::Tag(tag.clone()));
        }
        if let Some(ref constraint) = self.version {
            let req = semver::VersionReq::parse(constraint).map_err(|e| {
                anyhow::anyhow!(
                    "registry '{}': invalid version constraint '{}': {}",
                    self.name,
                    constraint,
                    e,
                )
            })?;
            return Ok(TrackingMode::Version(req));
        }

        Ok(TrackingMode::Default)
    }
}

// ---------------------------------------------------------------------------
// APM settings — from `apm.conf`
// ---------------------------------------------------------------------------

/// User/system settings from `apm.conf`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApmSettings {
    /// Assume yes to all prompts (like `apt -y`).
    #[serde(default)]
    pub assume_yes: bool,
    /// Maximum number of parallel NAR downloads.
    #[serde(default = "default_parallel")]
    pub parallel_downloads: u32,
    /// Automatically run autoremove after remove.
    #[serde(default)]
    pub auto_autoremove: bool,
    /// Automatically run gc after autoremove.
    #[serde(default)]
    pub auto_gc: bool,
}

/// Serde default for [`ApmSettings::parallel_downloads`].
fn default_parallel() -> u32 {
    4
}

impl Default for ApmSettings {
    fn default() -> Self {
        Self {
            assume_yes: false,
            parallel_downloads: default_parallel(),
            auto_autoremove: false,
            auto_gc: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Profile scope
// ---------------------------------------------------------------------------

/// Target profile for APM operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileScope {
    /// Per-user profile at `/var/lib/profiles/per-user/$USER/`.
    User,
    /// System-wide scope (requires root).
    ///
    /// Sysroot generations live at `/var/lib/profiles/system/`; runtime APM
    /// package generations live at `/var/lib/profiles/system-packages/`.
    System,
}

impl ProfileScope {
    /// Lowercase human name for this scope (`"system"` or `"user"`).
    ///
    /// Used in diagnostics that name the scope a command searched, such as the
    /// unsynced-registry warning emitted by query commands.
    pub fn name(&self) -> &'static str {
        match self {
            ProfileScope::User => "user",
            ProfileScope::System => "system",
        }
    }

    /// The opposite scope.
    ///
    /// System scope returns [`ProfileScope::User`] and vice versa. Used to
    /// point an operator at the scope they probably meant when a query finds a
    /// registry unsynced in the current one.
    pub fn other(&self) -> ProfileScope {
        match self {
            ProfileScope::User => ProfileScope::System,
            ProfileScope::System => ProfileScope::User,
        }
    }

    /// Base path for profiles of this scope.
    ///
    /// User scope resolves to `<profiles>/per-user/$USER` (with `"unknown"`
    /// when `$USER` is unset); system scope to `<profiles>/system`. The
    /// profile root honors the `AOS_PROFILE_ROOT` environment override.
    pub fn profile_path(&self) -> PathBuf {
        match self {
            ProfileScope::User => {
                let user = std::env::var("USER").unwrap_or_else(|_| String::from("unknown"));
                profiles_base().join("per-user").join(user)
            }
            ProfileScope::System => profiles_base().join("system"),
        }
    }

    /// Base path for APM package-profile generations in this scope.
    ///
    /// The sysroot uses [`ProfileScope::profile_path`] for
    /// `/var/lib/profiles/system/state.json`, whose schema is
    /// [`ConfigGenerationState`]. Runtime system packages use a separate
    /// package-generation database so `apm install --system` cannot corrupt
    /// or replace the sysroot generation pointer.
    pub fn package_profile_path(&self) -> PathBuf {
        match self {
            ProfileScope::User => self.profile_path(),
            ProfileScope::System => profiles_base().join("system-packages"),
        }
    }

    /// Path for cached registry metadata.
    pub fn cache_path(&self) -> PathBuf {
        match self {
            ProfileScope::User => xdg_data_home().join("apm/remote"),
            ProfileScope::System => apm_state_dir().join("remote"),
        }
    }

    /// Path for NAR download cache.
    pub fn nar_cache_path(&self) -> PathBuf {
        match self {
            ProfileScope::User => xdg_cache_home().join("apm"),
            ProfileScope::System => apm_state_dir().join("cache"),
        }
    }

    /// Path for producer-side static-cache staging for one registry.
    ///
    /// Rooted under [`nar_cache_path`](Self::nar_cache_path) — the scope's
    /// regenerable-bytes location (`~/.cache/apm` for user,
    /// `/var/lib/apm/cache` for system) — with a `registry-static/` infix that
    /// keeps producer staging separate from the consumer NAR download cache.
    /// The per-registry leaf preserves the one-`StoreDir`-per-cache invariant.
    pub fn registry_cache_path(&self, registry: &str) -> PathBuf {
        self.nar_cache_path().join("registry-static").join(registry)
    }

    /// Path for registry config files.
    ///
    /// This is the read-only `/etc/apm` image seed (system) or `~/.config/apm`
    /// (user) — the lowest configuration layer. Use [`config_layers`] for the
    /// full ordered read set and [`writable_config_dir`] for the mutation
    /// target.
    ///
    /// [`config_layers`]: ProfileScope::config_layers
    /// [`writable_config_dir`]: ProfileScope::writable_config_dir
    pub fn config_dir(&self) -> PathBuf {
        match self {
            ProfileScope::User => xdg_config_home().join("apm"),
            ProfileScope::System => apm_system_config_dir().to_path_buf(),
        }
    }

    /// Ordered configuration layers, from lowest to highest precedence.
    ///
    /// `apm` loads `apm.conf` and `registries.d/*.toml` from each layer and
    /// merges them field by field, with higher layers overriding lower ones
    /// (see [`crate::config`]). The lowest layer is the read-only `/etc/apm`
    /// seed baked into the system image; the highest is the writable layer
    /// returned by [`ProfileScope::writable_config_dir`].
    ///
    /// - System scope: `[/etc/apm, /var/lib/apm/config]`.
    /// - User scope: `[/etc/apm, /var/lib/apm/config, ~/.config/apm]` — a user
    ///   invocation also sees system runtime deltas before applying its own.
    pub fn config_layers(&self) -> Vec<PathBuf> {
        let mut layers = vec![
            apm_system_config_dir().to_path_buf(),
            apm_state_dir().join("config"),
        ];
        if matches!(self, ProfileScope::User) {
            layers.push(xdg_config_home().join("apm"));
        }
        layers
    }

    /// Writable configuration layer where `apm` persists runtime config and
    /// state deltas.
    ///
    /// This is the highest-precedence entry of [`ProfileScope::config_layers`]:
    /// `/var/lib/apm/config` for system scope and `~/.config/apm` for user
    /// scope. The `/etc/apm` seed is never written — it is a read-only image
    /// layer whose tmpfs `/etc` upper is discarded on reboot.
    pub fn writable_config_dir(&self) -> PathBuf {
        match self {
            ProfileScope::User => xdg_config_home().join("apm"),
            ProfileScope::System => apm_state_dir().join("config"),
        }
    }

    /// Path for local registry git clones (both read-only and read-write).
    pub fn registries_path(&self) -> PathBuf {
        match self {
            ProfileScope::User => xdg_data_home().join("apm/registries"),
            ProfileScope::System => apm_state_dir().join("registries"),
        }
    }

    /// Directories searched for pinned trusted keys, in precedence order.
    ///
    /// The first directory is the writable store where new pins are persisted
    /// ([`crate::security::KeyStore`] writes its `.first()`); the rest are
    /// read-only anchors searched in order. For system scope the writable
    /// store is the persistent `/var/lib/apm/trusted-keys.d`, placed ahead of
    /// the read-only `/etc/apm/trusted-keys.d` image seed, so runtime pins
    /// survive a reboot while the seed still contributes trust anchors. The
    /// `/etc` seed is shared with user scope so user installs can trust
    /// system-provisioned keys.
    pub fn trusted_keys_dirs(&self) -> Vec<PathBuf> {
        match self {
            ProfileScope::User => vec![
                xdg_config_home().join("apm/trusted-keys.d"),
                apm_system_config_dir().join("trusted-keys.d"),
            ],
            ProfileScope::System => vec![
                apm_state_dir().join("trusted-keys.d"),
                apm_system_config_dir().join("trusted-keys.d"),
            ],
        }
    }
}

// ---------------------------------------------------------------------------
// Registry config file structure (for TOML deserialization)
// ---------------------------------------------------------------------------

/// Top-level structure of a `registries.d/*.toml` file.
#[derive(Debug, Deserialize)]
pub struct RegistryFile {
    /// The `[registry]` table.
    pub registry: RegistryFileInner,
}

/// The `[registry]` table of a `registries.d/*.toml` file.
///
/// Field for field this mirrors [`RegistryConfig`] (see that type for the
/// per-field semantics), plus the optional `[registry.state]` table that
/// `apm update` appends — config loading splits the two apart.
#[derive(Debug, Deserialize)]
pub struct RegistryFileInner {
    /// Registry name. Optional because a registry's identity is its config
    /// file name (`<stem>.toml`): the loader defaults `name` to the stem and,
    /// when this field is present, requires it to match. A minimal `/var`
    /// overlay (a `[registry.state]` or `enabled` delta on a seeded registry)
    /// carries no `name`.
    #[serde(default)]
    pub name: Option<String>,
    /// Registry URL. Optional at the schema level so the loader can merge
    /// layered fragments before validation: a pure `/var` overlay omits it and
    /// inherits the seed's `url`, while a merged result that still lacks a
    /// `url` is an orphaned delta the loader drops (see [`crate::config`]).
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default = "default_priority")]
    pub priority: u32,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub commit: Option<String>,
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub channel: Option<String>,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    /// Legacy field: treated as `tag` for backward compatibility.
    #[serde(default)]
    pub pin: Option<String>,
    #[serde(default)]
    pub max_staleness_seconds: Option<u64>,
    #[serde(default)]
    pub caches: Vec<CacheEntry>,
    #[serde(default)]
    pub cache: RegistryCacheConfig,
    #[serde(default)]
    pub upload_auth: Option<RegistryUploadAuthConfig>,
    #[serde(default)]
    pub signing_keys: BTreeMap<String, SigningKeySource>,
    #[serde(default)]
    pub signing: Option<SigningConfig>,
    /// Mutable sync state appended by `apm update` (not user-edited).
    #[serde(default)]
    pub state: Option<RegistryState>,
}

/// Top-level structure of `apm.conf`.
#[derive(Debug, Deserialize)]
pub struct ApmConfFile {
    /// The `[settings]` table; every field is optional.
    #[serde(default)]
    pub settings: ApmSettings,
}

// ---------------------------------------------------------------------------
// Registry root config — from `registry.toml` inside a registry repo
// ---------------------------------------------------------------------------

// The committed `registry.toml` root-config schema (`RegistryRootConfig`, its
// `[registry]` metadata, and the unified `[caches]` cache stack) moved to the
// wasm-clean `aos-registry-surface` crate (RFC-0004 Phase 5) so the registry
// hub's indexer and the Cloudflare Worker can deserialize a committed root
// config without pulling `aos-package` (which is native-only). Re-exported here
// so `aos_package::types::{RegistryRootConfig, RegistryRootMeta, CacheEntry,
// CachesConfig}` paths are unchanged. The `content_addressed` flag
// (RFC-0005/0009) lives on the canonical `RegistryRootMeta` in that crate.
pub use aos_registry_surface::manifest::{
    CacheEntry, CachesConfig, RegistryRootConfig, RegistryRootMeta,
};

// ---------------------------------------------------------------------------
// Sysroot image entry — a pre-compiled image attached to a sysroot package
// ---------------------------------------------------------------------------

// `SysrootImageEntry` and its provider-neutral artifact locator live in the
// wasm-clean registry surface so native and indexed consumers share one schema.
pub use aos_registry_surface::manifest::{
    ImageArtifactContractDocumentReference, ImageArtifactContractReference, ImageCompression,
    ImageDelivery, ImageStoreReference, ImageTarget, SysrootImageEntry,
};

/// The action required to re-activate a config-generation under a (possibly
/// changed) running image's `module_abi`.
///
/// Produced by [`ConfigGeneration::reactivation_plan`] and consumed by the
/// rollback path. The two arms are the two independent re-bind outcomes the
/// generations model permits: reactivation of retained material within one
/// ABI, or deterministic re-evaluation across an ABI boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReactivationPlan {
    /// Identical module ABI under any running image: re-activate the retained
    /// non-`@base` overlay, republish credentials and evidence, then commit the
    /// `current → gen-N` pointer. No eval and no reboot are required.
    DirectReactivate,
    /// Different ABI: direct activation is refused; the config-gen must be
    /// re-evaluated from its retained inputs against the rolled-back image's
    /// evaluator before it can be committed.
    CrossAbiReEval(CrossAbiReEvalInputs),
}

/// One module locator derived from an authenticated package contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageModule {
    /// Package identity declared by the contract document.
    pub package: String,
    /// Domain-separated semantic digest of the complete package document.
    pub document_digest: String,
    /// Exact artifact root containing the module.
    pub store_path: String,
    /// Authenticated NAR identity of the module artifact.
    pub nar_hash: String,
    /// Relative module entrypoint below the artifact root.
    pub entrypoint: String,
    /// Authority that supplied the authenticated package contract.
    pub origin: PackageModuleOrigin,
}

/// Trust origin of one authenticated package contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackageModuleOrigin {
    /// Selected from one authenticated registry release.
    Registry,
    /// Recovered from the immutable image package catalog.
    Image,
}

/// The retained eval inputs a cross-ABI re-activation must replay
/// using its retained inputs.
///
/// All retained store references are kept alive on `/var` by the per-generation
/// `gen-N/cfgsrc/<hash>` GC root, so the re-eval is satisfiable without any
/// network round-trip; because eval is pure and content-addressed, the
/// recomputation is deterministic and usually cache-hits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossAbiReEvalInputs {
    /// Exact ordered authenticated package modules the evaluator must read.
    pub package_modules: Vec<PackageModule>,
    /// Store path of the exact `host.nix` the config-gen was evaluated from.
    pub host_nix_ref: String,
    /// Content-address of the resolved instance facts (`facts.json`).
    pub facts_hash: String,
    /// Store path containing the exact facts bytes.
    pub facts_ref: String,
    /// The ABI the config-gen was originally pinned to.
    pub from_module_abi: u32,
    /// The running image ABI the config-gen must be re-evaluated against.
    pub to_module_abi: u32,
}

// ---------------------------------------------------------------------------
// Two-axis generations: image generation (substrate) and configuration generation (overlay).
// ---------------------------------------------------------------------------
//
// The generation model has two independent persisted axes: image substrate
// and derived configuration.

/// Opaque retained state emitted and interpreted by the selected boot provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootProviderState {
    /// Provider-owned schema identifier for the opaque evidence value.
    pub schema: String,
    /// Provider-owned retained state or checked observation evidence.
    pub evidence: serde_json::Value,
}

/// One authenticated image-generation independent of its boot implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageGeneration {
    /// Image-generation number (names the `image-gen-N/` directory).
    pub number: u32,
    /// Immutable locator for the selected provider's boot-artifact contract.
    pub boot_artifact_contract: String,
    /// Opaque generation state retained by the selected boot provider.
    pub boot_provider_state: BootProviderState,
    /// Store path of the sysroot toplevel this image was built from.
    pub toplevel: String,
    /// Sysroot package name used for provenance.
    pub package_name: String,
    /// Sysroot package version.
    pub version: String,
    /// Authenticated `/var` format contract carried by this image.
    pub state_version: String,
    /// Exact native ability executor store path carried by this image.
    pub native_executor_ref: String,
    /// Source registry the sysroot package was installed from.
    pub registry: String,
    /// Resolved kernel store path (kernel-change detection across generations).
    #[serde(default)]
    pub kernel_path: Option<String>,
    /// Store path of the base-lib + evaluator closure carried *inside* this
    /// image. The ABI artifact and GC-root target for
    /// `image-gen-N/baselib/<module_abi>`.
    pub evaluator_ref: String,
    /// The monotonic shared-option-schema ABI this image's base lib exports.
    /// Mirrors `AOS_MODULE_ABI` in this image's `/etc/os-release`.
    pub module_abi: u32,
    /// Canonical hash of the base-lib module ABI and option schema.
    pub base_lib_abi_hash: String,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
}

/// Describes the durable phase or terminal result of a qualified image rollout.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageRolloutStatus {
    /// The candidate is the counted next-boot selection.
    Staged,
    /// The candidate booted and is awaiting strict configuration health.
    CandidateBooted,
    /// The candidate passed strict activation and native ability health.
    Succeeded,
    /// The candidate failed boot or strict health and the prior image returned.
    HealthFailed,
}

/// Records one state-compatible, drained image rollout.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageRollout {
    /// Versioned schema for durable boot-side interpretation.
    pub schema: String,
    /// Image generation selected as the rollout candidate.
    pub candidate: u32,
    /// Known-good image generation retained for fallback.
    pub prior: u32,
    /// Exact `/var` format contract shared by candidate and prior.
    pub state_version: String,
    /// Current rollout phase or terminal result.
    pub status: ImageRolloutStatus,
}

impl ImageGeneration {
    /// Returns whether a config-gen satisfies this image's ABI portion of the
    /// reactivation gate.
    ///
    /// Equal ABI is sufficient for direct reactivation because retained config
    /// outputs contain only the non-`@base` overlay; the running image always
    /// supplies its own base layer.
    pub fn admits_pin(&self, pinned_abi: u32) -> bool {
        self.module_abi == pinned_abi
    }
}

/// Persistent state for the image-generation axis
/// stored at `/var/lib/profiles/image/state.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageGenerationState {
    /// Provider-neutral state schema written by this release.
    pub schema: String,
    /// The image-gen the live kernel booted (cross-checked against
    /// `/etc/os-release`, never trusted from the network).
    pub running: u32,
    /// A staged image-generation that has not yet been observed running.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<u32>,
    /// Opaque selected-provider state for selection, recovery, and boot evidence.
    pub boot_provider_state: BootProviderState,
    /// Qualified rollout currently crossing the reboot boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_rollout: Option<ImageRollout>,
    /// Most recently completed qualified rollout outcome.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_rollout: Option<ImageRollout>,
    /// All recorded image-generations, in creation order.
    #[serde(default)]
    pub generations: Vec<ImageGeneration>,
}

impl ImageGenerationState {
    /// Looks up the currently-running image-generation record, if recorded.
    pub fn running_generation(&self) -> Option<&ImageGeneration> {
        self.generations.iter().find(|g| g.number == self.running)
    }

    /// Validates the provider-neutral identity envelope and generation graph.
    ///
    /// Provider-owned evidence remains opaque here. The selected provider
    /// validates that evidence against its declared schema before acting on it.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported state schema, malformed contract or
    /// provider-schema identities, non-object provider evidence, duplicate
    /// generations, or state references to absent generations.
    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema != "aos.image-generation-state/v1" {
            bail!("unsupported image generation state schema {}", self.schema);
        }
        validate_boot_provider_state(&self.boot_provider_state)?;

        let mut generation_numbers = BTreeSet::new();
        for generation in &self.generations {
            if !generation_numbers.insert(generation.number) {
                bail!("duplicate image generation {}", generation.number);
            }
            crate::config_eval::materialize::validate_canonical_store_path(
                &generation.boot_artifact_contract,
            )
            .with_context(|| {
                format!(
                    "validating image generation {} boot-artifact contract",
                    generation.number
                )
            })?;
            validate_boot_provider_state(&generation.boot_provider_state)?;
        }

        if self.generations.is_empty() {
            if self.running != 0 || self.pending.is_some() {
                bail!(
                    "empty image state must use running generation zero and no pending generation"
                );
            }
            return Ok(());
        }
        if !generation_numbers.contains(&self.running) {
            bail!("running image generation {} is absent", self.running);
        }
        if let Some(pending) = self.pending
            && !generation_numbers.contains(&pending)
        {
            bail!("pending image generation {pending} is absent");
        }
        for rollout in self.active_rollout.iter().chain(&self.last_rollout) {
            if !generation_numbers.contains(&rollout.candidate)
                || !generation_numbers.contains(&rollout.prior)
            {
                bail!("image rollout references an absent generation");
            }
        }
        Ok(())
    }
}

fn validate_boot_provider_state(state: &BootProviderState) -> Result<()> {
    let schema = state.schema.as_bytes();
    if schema.is_empty()
        || schema.len() > 200
        || !schema.iter().all(|byte| byte.is_ascii_graphic())
        || !state.schema.contains('/')
    {
        bail!("boot-provider state schema is not a bounded portable identifier");
    }
    if !state.evidence.is_object() {
        bail!("boot-provider evidence must be a JSON object");
    }
    Ok(())
}

/// One config-generation: the materialized `/etc` overlay produced by
/// evaluating the installed set's config modules + `host.nix` against a
/// specific image generation's base library.
///
/// This is the on-disk authority for `/var/lib/profiles/system/state.json`.
/// Every binding needed to reactivate or re-evaluate the generation is
/// required by this schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigGeneration {
    /// Config-generation number naming the `gen-N/` directory selected by
    /// the checked activation transaction.
    pub number: u32,
    /// The [`ImageGeneration::number`] this config-gen was evaluated against.
    pub image_gen_parent: u32,
    /// The `module_abi` in effect at evaluation time.
    pub module_abi_pinned: u32,
    /// Content-address of the canonicalized manifest JSON (the *output*).
    pub manifest_hash: String,
    /// Exact evaluator order of authenticated package modules.
    pub package_modules: Vec<PackageModule>,
    /// Store path / content hash of the exact `host.nix` evaluated.
    pub host_nix_ref: String,
    /// Non-authoritative git commit `host.nix` came from (operator traceability).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_nix_commit: Option<String>,
    /// Content-address of the resolved instance facts (`facts.json`).
    pub facts_hash: String,
    /// Store path containing the exact facts bytes.
    pub facts_ref: String,
    /// Original base-library input store path.
    pub base_lib_ref: String,
    /// Original evaluator input store path.
    pub evaluator_ref: String,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
}

impl ConfigGeneration {
    /// Decides how this config-generation may be reactivated under a running
    /// image whose shared-option ABI is `running_abi`.
    ///
    /// # Errors
    ///
    /// Returns an error when retained inputs cannot be replayed.
    pub fn reactivation_plan(&self, running_abi: u32) -> Result<ReactivationPlan> {
        if self.module_abi_pinned == running_abi {
            return Ok(ReactivationPlan::DirectReactivate);
        }
        Ok(ReactivationPlan::CrossAbiReEval(CrossAbiReEvalInputs {
            package_modules: self.package_modules.clone(),
            host_nix_ref: self.host_nix_ref.clone(),
            facts_hash: self.facts_hash.clone(),
            facts_ref: self.facts_ref.clone(),
            from_module_abi: self.module_abi_pinned,
            to_module_abi: running_abi,
        }))
    }
}

/// Persistent state for the config-generation axis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigGenerationState {
    /// Number of the currently active generation (`0` = none yet).
    pub current: u32,
    /// Number the next created generation will receive.
    pub next: u32,
    /// All recorded config-generations, in creation order.
    #[serde(default)]
    pub generations: Vec<ConfigGeneration>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_attestation() -> AttestationMeta {
        AttestationMeta {
            root_digest: Some(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            ),
            root_hash: None,
            root_hash_sig: None,
            provenance: Some("attestation/test.provenance.jsonl".into()),
            measurement: Some(
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            ),
        }
    }

    #[test]
    fn registry_name_validation_accepts_path_safe_names() {
        for name in ["core", "aos-core", "aos_core", "AOS2026_core-1"] {
            validate_registry_name(name).unwrap();
        }
    }

    #[test]
    fn registry_name_validation_rejects_path_like_names() {
        for name in [
            "",
            "../escape",
            "aos/core",
            "aos.core",
            "aos core",
            "caf\u{00e9}",
        ] {
            let err = validate_registry_name(name).unwrap_err();
            assert!(err.to_string().contains("registry name"));
        }
    }

    #[test]
    fn branch_name_validation_accepts_git_workflow_names() {
        for name in [
            "stable",
            "feature/host-workflow",
            "release/2026.06",
            "user_name/issue-123",
        ] {
            validate_branch_name(name).unwrap();
        }
    }

    #[test]
    fn branch_name_validation_rejects_ambiguous_refnames() {
        for name in [
            "",
            "-feature",
            "HEAD",
            "@",
            "refs/heads/stable",
            "../stable",
            "stable..next",
            ".hidden",
            "feature/.hidden",
            "feature.lock",
            "feature//next",
            "feature next",
            "feature:next",
            "feature@{next",
            "feature\"next",
        ] {
            let err = validate_branch_name(name).unwrap_err();
            assert!(err.to_string().contains("branch name"));
        }
    }

    #[test]
    fn channel_name_validation_accepts_safe_single_segments() {
        for name in ["stable", "canary_2026-06", "AOS2026"] {
            validate_channel_name(name).unwrap();
        }
    }

    #[test]
    fn channel_name_validation_rejects_paths_or_ref_syntax() {
        for name in [
            "",
            "-canary",
            "../canary",
            "canary/prod",
            "canary..prod",
            "canary prod",
            "canary\"prod",
        ] {
            let err = validate_channel_name(name).unwrap_err();
            assert!(err.to_string().contains("channel name"));
        }
    }

    #[test]
    fn commit_hash_validation_accepts_full_object_ids() {
        validate_commit_hash("0123456789abcdef0123456789abcdef01234567").unwrap();
        validate_commit_hash("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap();
    }

    #[test]
    fn commit_hash_validation_rejects_refs_or_abbreviations() {
        for hash in [
            "",
            "abc123",
            "main",
            "HEAD",
            "feature..bad",
            "0123456789abcdef0123456789abcdef0123456g",
            "0123456789abcdef0123456789abcdef012345678",
        ] {
            let err = validate_commit_hash(hash).unwrap_err();
            assert!(err.to_string().contains("commit hash"));
        }
    }

    #[test]
    fn package_name_validation_accepts_nix_path_safe_names() {
        for name in [
            "curl",
            "python3.12",
            "libc++",
            "gcc-wrapper",
            "openssl_static",
            "drv-debug=true",
        ] {
            validate_package_name(name).unwrap();
        }
    }

    #[test]
    fn package_name_validation_rejects_path_like_names() {
        for name in [
            "",
            "../escape",
            ".hidden",
            "a/b",
            "a\\b",
            "a b",
            "bad:name",
            "drv?debug=true",
            "\"bad\"",
            "caf\u{00e9}",
        ] {
            let err = validate_package_name(name).unwrap_err();
            assert!(err.to_string().contains("package name"));
        }
    }

    #[test]
    fn platform_name_validation_accepts_nix_system_names() {
        for name in [
            "x86_64-linux",
            "aarch64-linux",
            "x86_64-darwin",
            "aarch64-darwin",
            "i686-linux",
            "wasm32-wasi",
        ] {
            validate_platform_name(name).unwrap();
        }
    }

    #[test]
    fn platform_name_validation_rejects_toml_or_path_like_names() {
        for name in [
            "",
            "../linux",
            "x86_64 linux",
            "x86_64.linux",
            "x86_64-linux]",
            "caf\u{00e9}-linux",
        ] {
            let err = validate_platform_name(name).unwrap_err();
            assert!(err.to_string().contains("platform name"));
        }
    }

    #[test]
    fn git_ref_name_validation_accepts_branch_and_tag_names() {
        for name in [
            "main",
            "release/2026.06",
            "feature/apr-apm-workflow",
            "v1.2.3",
            "1.2.3+build.5",
            "maintainer_key-1",
        ] {
            validate_git_ref_name(name).unwrap();
        }
    }

    #[test]
    fn git_ref_name_validation_rejects_option_or_ref_expression_names() {
        for name in [
            "",
            "-delete",
            "HEAD",
            "refs/tags/release",
            "/absolute",
            "trailing/",
            "double//slash",
            "bad..ref",
            "bad ref",
            "bad:ref",
            "bad^ref",
            "bad~ref",
            "bad?ref",
            "bad*ref",
            "bad[ref",
            "bad\\ref",
            "bad\"ref",
            ".hidden",
            "main/.hidden",
            "main.lock",
            "main/@{1}",
            "@",
            "trailing.",
            "caf\u{00e9}",
        ] {
            let err = validate_git_ref_name(name).unwrap_err();
            assert!(err.to_string().contains("git ref name"));
        }
    }

    #[test]
    fn package_name_bucket_uses_lowercase_first_character() {
        assert_eq!(package_name_bucket("curl"), "c");
        assert_eq!(package_name_bucket("Zlib"), "z");
        assert_eq!(package_name_bucket("7zip"), "7");
        assert_eq!(package_name_bucket(""), "_");
    }

    #[test]
    fn xdg_honors_absolute_override() {
        let home = Path::new("/home/alice");
        assert_eq!(
            resolve_xdg(Some("/custom/config"), home, ".config"),
            PathBuf::from("/custom/config"),
        );
    }

    #[test]
    fn xdg_falls_back_when_unset() {
        let home = Path::new("/home/alice");
        assert_eq!(
            resolve_xdg(None, home, ".local/share"),
            PathBuf::from("/home/alice/.local/share"),
        );
    }

    #[test]
    fn xdg_ignores_relative_override() {
        // Per the XDG spec, relative paths in the env var are invalid and must
        // be ignored in favour of the home-relative default.
        let home = Path::new("/home/alice");
        assert_eq!(
            resolve_xdg(Some("relative/cache"), home, ".cache"),
            PathBuf::from("/home/alice/.cache"),
        );
    }

    #[test]
    fn xdg_ignores_empty_override() {
        let home = Path::new("/home/alice");
        assert_eq!(
            resolve_xdg(Some(""), home, ".config"),
            PathBuf::from("/home/alice/.config"),
        );
    }

    #[test]
    fn system_config_dir_honors_absolute_override() {
        assert_eq!(
            resolve_system_config_dir(Some("/tmp/apm-fixture")),
            PathBuf::from("/tmp/apm-fixture"),
        );
    }

    #[test]
    fn system_state_dir_honors_absolute_aos_root() {
        assert_eq!(
            resolve_apm_state_dir(Some("/tmp/aos-fixture")),
            PathBuf::from("/tmp/aos-fixture/var/lib/apm"),
        );
    }

    #[test]
    fn profile_base_honors_absolute_override() {
        assert_eq!(
            resolve_profiles_base(Some("/tmp/aos-profiles")),
            PathBuf::from("/tmp/aos-profiles"),
        );
    }

    #[test]
    fn config_layers_run_seed_to_writable() {
        // Independent of the env-cached resolver values, the lowest layer is
        // always the read-only `/etc` seed and the highest is the scope's
        // writable layer.
        for scope in [ProfileScope::System, ProfileScope::User] {
            let layers = scope.config_layers();
            assert_eq!(
                layers.first(),
                Some(&ProfileScope::System.config_dir()),
                "lowest config layer must be the /etc seed",
            );
            assert_eq!(
                layers.last(),
                Some(&scope.writable_config_dir()),
                "highest config layer must be the writable dir",
            );
        }
    }

    #[test]
    fn system_config_layers_are_etc_then_var() {
        let layers = ProfileScope::System.config_layers();
        assert_eq!(layers.len(), 2);
        assert_ne!(layers[0], layers[1]);
    }

    #[test]
    fn user_config_layers_share_the_system_var_layer() {
        let layers = ProfileScope::User.config_layers();
        assert_eq!(layers.len(), 3);
        // The shared /var system layer sits between the /etc seed and the
        // user's own writable dir, so a user invocation sees system runtime
        // deltas.
        assert_eq!(layers[1], ProfileScope::System.writable_config_dir());
    }

    #[test]
    fn system_trusted_keys_writable_store_precedes_seed() {
        let dirs = ProfileScope::System.trusted_keys_dirs();
        assert_eq!(dirs.len(), 2);
        // The writable store is a sibling of the writable config dir (both
        // under /var/lib/apm) and precedes the read-only /etc seed anchor.
        assert_eq!(
            dirs[0].parent(),
            ProfileScope::System.writable_config_dir().parent(),
        );
        assert_eq!(
            dirs[1],
            ProfileScope::System.config_dir().join("trusted-keys.d"),
        );
    }

    #[test]
    fn system_config_dir_falls_back_when_unset() {
        assert_eq!(resolve_system_config_dir(None), PathBuf::from("/etc/apm"));
    }

    #[test]
    fn system_state_dir_falls_back_when_aos_root_unset() {
        assert_eq!(resolve_apm_state_dir(None), PathBuf::from("/var/lib/apm"));
    }

    #[test]
    fn system_config_dir_ignores_relative_override() {
        assert_eq!(
            resolve_system_config_dir(Some("relative/apm")),
            PathBuf::from("/etc/apm"),
        );
    }

    #[test]
    fn system_state_dir_ignores_relative_aos_root() {
        assert_eq!(
            resolve_apm_state_dir(Some("relative/root")),
            PathBuf::from("/var/lib/apm"),
        );
    }

    #[test]
    fn profile_base_ignores_relative_override() {
        assert_eq!(
            resolve_profiles_base(Some("relative/profiles")),
            PathBuf::from("/var/lib/profiles"),
        );
    }

    #[test]
    fn system_config_dir_ignores_empty_override() {
        assert_eq!(
            resolve_system_config_dir(Some("")),
            PathBuf::from("/etc/apm")
        );
    }

    #[test]
    fn system_state_dir_ignores_empty_aos_root() {
        assert_eq!(
            resolve_apm_state_dir(Some("")),
            PathBuf::from("/var/lib/apm")
        );
    }

    #[test]
    fn profile_base_ignores_empty_override() {
        assert_eq!(
            resolve_profiles_base(Some("")),
            PathBuf::from("/var/lib/profiles"),
        );
    }

    #[test]
    fn transport_detection_https() {
        let cfg = RegistryConfig {
            name: "test".into(),
            url: "https://registry.aos.dev/core".into(),
            priority: 500,
            enabled: true,
            commit: None,
            branch: None,
            channel: None,
            tag: None,
            version: None,
            pin: None,
            max_staleness_seconds: None,
            caches: Vec::new(),
            cache: Default::default(),
            upload_auth: None,
            signing_keys: Default::default(),
            signing: None,
        };
        assert_eq!(cfg.transport(), Transport::Http);
    }

    #[test]
    fn transport_detection_http() {
        let cfg = RegistryConfig {
            name: "test".into(),
            url: "http://local.dev/core".into(),
            priority: 500,
            enabled: true,
            commit: None,
            branch: None,
            channel: None,
            tag: None,
            version: None,
            pin: None,
            max_staleness_seconds: None,
            caches: Vec::new(),
            cache: Default::default(),
            upload_auth: None,
            signing_keys: Default::default(),
            signing: None,
        };
        assert_eq!(cfg.transport(), Transport::Http);
    }

    #[test]
    fn transport_detection_git_plus_https() {
        let cfg = RegistryConfig {
            name: "test".into(),
            url: "git+https://github.com/andyl/registry.git".into(),
            priority: 500,
            enabled: true,
            commit: None,
            branch: None,
            channel: None,
            tag: None,
            version: None,
            pin: None,
            max_staleness_seconds: None,
            caches: Vec::new(),
            cache: Default::default(),
            upload_auth: None,
            signing_keys: Default::default(),
            signing: None,
        };
        assert_eq!(cfg.transport(), Transport::Git);
    }

    #[test]
    fn transport_detection_git_native() {
        let cfg = RegistryConfig {
            name: "test".into(),
            url: "git://github.com/andyl/registry.git".into(),
            priority: 500,
            enabled: true,
            commit: None,
            branch: None,
            channel: None,
            tag: None,
            version: None,
            pin: None,
            max_staleness_seconds: None,
            caches: Vec::new(),
            cache: Default::default(),
            upload_auth: None,
            signing_keys: Default::default(),
            signing: None,
        };
        assert_eq!(cfg.transport(), Transport::Git);
    }

    #[test]
    fn transport_detection_git_ssh() {
        let cfg = RegistryConfig {
            name: "test".into(),
            url: "git+ssh://git@github.com/andyl/registry.git".into(),
            priority: 500,
            enabled: true,
            commit: None,
            branch: None,
            channel: None,
            tag: None,
            version: None,
            pin: None,
            max_staleness_seconds: None,
            caches: Vec::new(),
            cache: Default::default(),
            upload_auth: None,
            signing_keys: Default::default(),
            signing: None,
        };
        assert_eq!(cfg.transport(), Transport::Git);
    }

    #[test]
    fn profile_scope_system_paths() {
        let scope = ProfileScope::System;
        assert_eq!(
            scope.profile_path(),
            PathBuf::from("/var/lib/profiles/system")
        );
        assert_eq!(
            scope.package_profile_path(),
            PathBuf::from("/var/lib/profiles/system-packages")
        );
        assert_eq!(scope.cache_path(), PathBuf::from("/var/lib/apm/remote"));
        assert_eq!(
            scope.registry_cache_path("core"),
            PathBuf::from("/var/lib/apm/cache/registry-static/core"),
        );
        assert_eq!(scope.config_dir(), PathBuf::from("/etc/apm"));
    }

    #[test]
    fn default_settings() {
        let s = ApmSettings::default();
        assert!(!s.assume_yes);
        assert_eq!(s.parallel_downloads, 4);
        assert!(!s.auto_autoremove);
        assert!(!s.auto_gc);
    }

    #[test]
    fn parse_settings_toml() {
        let toml_str = r#"
[settings]
assume_yes = true
parallel_downloads = 8
auto_autoremove = true
auto_gc = false
"#;
        let conf: ApmConfFile = toml::from_str(toml_str).unwrap();
        assert!(conf.settings.assume_yes);
        assert_eq!(conf.settings.parallel_downloads, 8);
        assert!(conf.settings.auto_autoremove);
        assert!(!conf.settings.auto_gc);
    }

    #[test]
    fn parse_registry_cache_config() {
        let toml_str = r#"
[registry]
url = "https://registry.example.com/core"

[registry.cache]
max_age_days = 7
"#;
        let file: RegistryFile = toml::from_str(toml_str).unwrap();
        assert_eq!(file.registry.cache.max_age_days, Some(7));
        assert_eq!(RegistryCacheConfig::default().max_age_days(), 30);
    }

    #[test]
    fn parse_minimal_settings_toml() {
        let toml_str = "[settings]\n";
        let conf: ApmConfFile = toml::from_str(toml_str).unwrap();
        assert!(!conf.settings.assume_yes);
        assert_eq!(conf.settings.parallel_downloads, 4);
    }

    #[test]
    fn parse_registry_file_toml() {
        let toml_str = r#"
[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"
priority = 500
enabled = true
max_staleness_seconds = 604800

[[registry.caches]]
url = "https://client-cache.aos.dev"
priority = 1200

[registry.upload_auth]
token = "config-token"
view = "prod"
http_user = "cache-user"
http_password = "cache-pass"
headers = ["X-Registry: core"]
s3_region = "us-west-2"
s3_profile = "prod"
s3_endpoint = "https://minio.example"
ssh_key = "/etc/apm/cache_ed25519"
ssh_password = "ssh-pass"
ssh_ask_pass = true

[registry.signing]
required = true
public_key = "aos-core:Ed25519:base64keyhere"
root_owner_signers = ["release-2026"]
"#;
        let rf: RegistryFile = toml::from_str(toml_str).unwrap();
        assert_eq!(rf.registry.name.as_deref(), Some("aos-core"));
        assert_eq!(rf.registry.priority, 500);
        assert_eq!(rf.registry.max_staleness_seconds, Some(604800));
        assert_eq!(rf.registry.caches.len(), 1);
        assert_eq!(rf.registry.caches[0].url, "https://client-cache.aos.dev");
        assert_eq!(rf.registry.caches[0].priority, 1200);
        let upload_auth = rf.registry.upload_auth.unwrap();
        assert_eq!(upload_auth.token.as_deref(), Some("config-token"));
        assert_eq!(upload_auth.view.as_deref(), Some("prod"));
        assert_eq!(upload_auth.http_user.as_deref(), Some("cache-user"));
        assert_eq!(upload_auth.http_password.as_deref(), Some("cache-pass"));
        assert_eq!(upload_auth.headers, vec!["X-Registry: core"]);
        assert_eq!(upload_auth.s3_region.as_deref(), Some("us-west-2"));
        assert_eq!(upload_auth.s3_profile.as_deref(), Some("prod"));
        assert_eq!(
            upload_auth.s3_endpoint.as_deref(),
            Some("https://minio.example")
        );
        assert_eq!(
            upload_auth.ssh_key.as_deref(),
            Some("/etc/apm/cache_ed25519")
        );
        assert_eq!(upload_auth.ssh_password.as_deref(), Some("ssh-pass"));
        assert!(upload_auth.ssh_ask_pass);
        let signing = rf.registry.signing.unwrap();
        assert!(signing.required);
        assert_eq!(
            signing.public_key.as_deref(),
            Some("aos-core:Ed25519:base64keyhere")
        );
        assert_eq!(signing.root_owner_signers, vec!["release-2026"]);
    }

    #[test]
    fn registry_root_config_ignores_signing_field() {
        let toml_str = r#"
[registry]
name = "aos-core"
description = "core registry"

[caches]
endpoint = "https://cache.aos.dev"

[registry.signing]
public_key = "aos-core:Ed25519:base64keyhere"
"#;
        let cfg: RegistryRootConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.registry.name, "aos-core");
        assert_eq!(cfg.registry.description.as_deref(), Some("core registry"));
        let caches = cfg.cache_entries();
        assert_eq!(caches.len(), 1);
        assert_eq!(caches[0].url, "https://cache.aos.dev");
    }

    #[test]
    fn parse_registry_file_with_state() {
        let toml_str = r#"
[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"

[registry.state]
last_commit = "abc123"
last_roster_commit = "def456"
floor = "1.2.0"
bucket = 10
retained = ["1.0.0", "1.2.0"]
last_update = "2026-02-13T10:30:00Z"
"#;
        let rf: RegistryFile = toml::from_str(toml_str).unwrap();
        let state = rf.registry.state.unwrap();
        assert_eq!(state.last_commit.unwrap(), "abc123");
        assert_eq!(state.last_roster_commit.unwrap(), "def456");
        assert_eq!(state.floor.unwrap(), "1.2.0");
        assert_eq!(state.bucket.unwrap(), 10);
        assert_eq!(state.retained, vec!["1.0.0", "1.2.0"]);
    }

    #[test]
    fn installed_meta_round_trip() {
        let meta = InstalledMeta {
            store_path: "/var/lib/store/abc123-curl-8.5.0".into(),
            pushed_at: 1707800000,
            pushed_by: "apm".into(),
            expires_at: None,
            is_root: true,
            last_accessed: 1707800000,
            access_count: 0,
            apm: Some(ApmMeta {
                name: "curl".into(),
                version: "8.5.0".into(),
                explicit: true,
                registry: "aos-core".into(),
                installed_at: "2026-02-13T10:30:00Z".into(),
                held: false,
                source_drv: "/var/lib/store/src123-curl-8.5.0.drv".into(),
                source_nar_hash: "sha256:source".into(),
                documentation: None,
                contract: None,
                attestation: Default::default(),
            }),
        };
        let json = serde_json::to_string_pretty(&meta).unwrap();
        let parsed: InstalledMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.store_path, meta.store_path);
        let parsed_apm = parsed.apm.as_ref().unwrap();
        assert_eq!(
            parsed_apm.source_drv,
            "/var/lib/store/src123-curl-8.5.0.drv"
        );
        assert_eq!(parsed_apm.source_nar_hash, "sha256:source");
        let apm = parsed.apm.unwrap();
        assert_eq!(apm.name, "curl");
        assert!(apm.explicit);
        assert!(!apm.held);
    }

    #[test]
    fn installed_meta_without_apm_section() {
        // Cache server metadata (no apm section) should parse fine
        let json = r#"{
            "store_path": "/var/lib/store/abc123-curl-8.5.0",
            "pushed_at": 1706000000,
            "pushed_by": "ci-token",
            "expires_at": 1706604800,
            "is_root": true,
            "last_accessed": 1706500000,
            "access_count": 42
        }"#;
        let meta: InstalledMeta = serde_json::from_str(json).unwrap();
        assert!(meta.apm.is_none());
        assert_eq!(meta.access_count, 42);
    }
    fn attestation_package_meta(requires_features: Vec<&str>) -> PackageMeta {
        PackageMeta {
            name: "verity-app".into(),
            version: "1.0.0".into(),
            description: "Package root with verity attestation".into(),
            homepage: None,
            license: "MIT".into(),
            maintainer: "aos-team".into(),
            platform: "x86_64-linux".into(),
            store_path: "/var/lib/store/verityhash12-verity-app-1.0.0".into(),
            nar_hash: "sha256:abc123".into(),
            nar_size: 1024,
            references: Vec::new(),
            source_drv: String::new(),
            source_nar_hash: String::new(),
            closure_size: 1024,
            sysroot: false,
            previous: None,
            images: Vec::new(),
            min_format: Some(PACKAGE_META_FORMAT),
            requires_features: requires_features.into_iter().map(str::to_string).collect(),
            documentation: None,
            contract: None,
            attestation: AttestationMeta {
                root_digest: Some(
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .into(),
                ),
                root_hash: Some(
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .into(),
                ),
                root_hash_sig: Some("attestation/verity-app.roothash.p7s".into()),
                provenance: Some("attestation/verity-app.provenance.jsonl".into()),
                measurement: Some(
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .into(),
                ),
            },
        }
    }

    #[test]
    fn package_meta_requires_attestation_feature_gate() {
        let mut meta = attestation_package_meta(vec![FEATURE_ABILITIES_V1]);

        let err = validate_supported_package_meta(&meta).unwrap_err();
        assert!(err.to_string().contains(FEATURE_ATTESTATION_V1));

        meta.requires_features = vec![FEATURE_ATTESTATION_V1.into()];
        validate_supported_package_meta(&meta).unwrap();
    }

    #[test]
    fn package_meta_rejects_incomplete_attestation_root_hash() {
        let mut meta = attestation_package_meta(vec![FEATURE_ATTESTATION_V1]);
        meta.attestation.root_hash_sig = None;

        let err = validate_supported_package_meta(&meta).unwrap_err();
        assert!(format!("{err:#}").contains("root_hash and root_hash_sig"));
    }

    #[test]
    fn package_meta_rejects_attestation_measurement_without_root_digest() {
        let mut meta = attestation_package_meta(vec![FEATURE_ATTESTATION_V1]);
        meta.attestation.root_digest = None;
        meta.attestation.root_hash = None;
        meta.attestation.root_hash_sig = None;

        let err = validate_supported_package_meta(&meta).unwrap_err();
        assert!(format!("{err:#}").contains("measurement requires root_digest"));
    }

    #[test]
    fn package_meta_rejects_invalid_attestation_digest() {
        let mut meta = attestation_package_meta(vec![FEATURE_ATTESTATION_V1]);
        meta.attestation.root_hash = Some("sha256:not-a-digest".into());

        let err = validate_supported_package_meta(&meta).unwrap_err();
        assert!(format!("{err:#}").contains("64-character SHA-256 digest"));
    }

    #[test]
    fn package_meta_rejects_unsafe_attestation_artifact_paths() {
        let mut meta = attestation_package_meta(vec![FEATURE_ATTESTATION_V1]);
        meta.attestation.root_hash_sig = Some("../escape.p7s".into());

        let err = validate_supported_package_meta(&meta).unwrap_err();
        assert!(format!("{err:#}").contains("attestation root_hash_sig path"));
    }

    #[test]
    fn package_meta_rejects_cache_owned_provenance_path() {
        let mut meta = attestation_package_meta(vec![FEATURE_ATTESTATION_V1]);
        meta.attestation.provenance = Some("packages/w/web.provenance.jsonl".into());

        let err = validate_supported_package_meta(&meta).unwrap_err();
        assert!(
            format!("{err:#}").contains("must not target a cache-owned subtree"),
            "{err:#}",
        );
    }
    // -----------------------------------------------------------------------
    // TrackingMode tests
    // -----------------------------------------------------------------------

    fn base_cfg() -> RegistryConfig {
        RegistryConfig {
            name: "test".into(),
            url: "https://example.com".into(),
            priority: 500,
            enabled: true,
            commit: None,
            branch: None,
            channel: None,
            tag: None,
            version: None,
            pin: None,
            max_staleness_seconds: None,
            caches: Vec::new(),
            cache: Default::default(),
            upload_auth: None,
            signing_keys: Default::default(),
            signing: None,
        }
    }

    #[test]
    fn tracking_mode_default_when_nothing_set() {
        let cfg = base_cfg();
        assert_eq!(cfg.tracking_mode().unwrap(), TrackingMode::Default);
    }

    #[test]
    fn tracking_mode_commit() {
        let mut cfg = base_cfg();
        cfg.commit = Some("0123456789abcdef0123456789abcdef01234567".into());
        match cfg.tracking_mode().unwrap() {
            TrackingMode::Commit(h) => assert_eq!(h, "0123456789abcdef0123456789abcdef01234567"),
            other => panic!("expected Commit, got {:?}", other),
        }
    }

    #[test]
    fn tracking_mode_rejects_invalid_commit_hash() {
        let mut cfg = base_cfg();
        cfg.commit = Some("main".into());
        let err = cfg.tracking_mode().unwrap_err();
        assert!(err.to_string().contains("invalid commit tracking"));
    }

    #[test]
    fn tracking_mode_branch() {
        let mut cfg = base_cfg();
        cfg.branch = Some("stable".into());
        match cfg.tracking_mode().unwrap() {
            TrackingMode::Branch(b) => assert_eq!(b, "stable"),
            other => panic!("expected Branch, got {:?}", other),
        }
    }

    #[test]
    fn tracking_mode_rejects_invalid_branch_name() {
        let mut cfg = base_cfg();
        cfg.branch = Some("feature..bad".into());
        let err = cfg.tracking_mode().unwrap_err();
        assert!(err.to_string().contains("invalid branch tracking"));
    }

    #[test]
    fn tracking_mode_channel() {
        let mut cfg = base_cfg();
        cfg.channel = Some("stable".into());
        match cfg.tracking_mode().unwrap() {
            TrackingMode::Channel(c) => assert_eq!(c, "stable"),
            other => panic!("expected Channel, got {:?}", other),
        }
    }

    #[test]
    fn tracking_mode_rejects_invalid_channel_name() {
        let mut cfg = base_cfg();
        cfg.channel = Some("stable/canary".into());
        let err = cfg.tracking_mode().unwrap_err();
        assert!(err.to_string().contains("invalid channel tracking"));
    }

    #[test]
    fn tracking_mode_tag() {
        let mut cfg = base_cfg();
        cfg.tag = Some("v2026.03".into());
        match cfg.tracking_mode().unwrap() {
            TrackingMode::Tag(t) => assert_eq!(t, "v2026.03"),
            other => panic!("expected Tag, got {:?}", other),
        }
    }

    #[test]
    fn tracking_mode_rejects_invalid_tag_name() {
        let mut cfg = base_cfg();
        cfg.tag = Some("release..bad".into());
        let err = cfg.tracking_mode().unwrap_err();
        assert!(err.to_string().contains("invalid tag tracking"));
    }

    #[test]
    fn tracking_mode_version() {
        let mut cfg = base_cfg();
        cfg.version = Some("~2026.3".into());
        match cfg.tracking_mode().unwrap() {
            TrackingMode::Version(req) => {
                assert!(req.matches(&semver::Version::new(2026, 3, 5)));
                assert!(!req.matches(&semver::Version::new(2026, 4, 0)));
            }
            other => panic!("expected Version, got {:?}", other),
        }
    }

    #[test]
    fn tracking_mode_legacy_pin_as_tag() {
        let mut cfg = base_cfg();
        cfg.pin = Some("v2026.02".into());
        match cfg.tracking_mode().unwrap() {
            TrackingMode::Tag(t) => assert_eq!(t, "v2026.02"),
            other => panic!("expected Tag from legacy pin, got {:?}", other),
        }
    }

    #[test]
    fn tracking_mode_rejects_invalid_legacy_pin_name() {
        let mut cfg = base_cfg();
        cfg.pin = Some("release@{1}".into());
        let err = cfg.tracking_mode().unwrap_err();
        assert!(err.to_string().contains("invalid tag tracking"));
    }

    #[test]
    fn tracking_mode_tag_takes_precedence_over_pin() {
        let mut cfg = base_cfg();
        cfg.tag = Some("v2026.03".into());
        cfg.pin = Some("v2026.02".into());
        // tag and pin both contribute to the same "effective_tag" slot,
        // but tag wins. Only one slot is counted.
        match cfg.tracking_mode().unwrap() {
            TrackingMode::Tag(t) => assert_eq!(t, "v2026.03"),
            other => panic!("expected Tag, got {:?}", other),
        }
    }

    #[test]
    fn tracking_mode_error_multiple_set() {
        let mut cfg = base_cfg();
        cfg.branch = Some("main".into());
        cfg.tag = Some("v1.0".into());
        let err = cfg.tracking_mode().unwrap_err();
        assert!(err.to_string().contains("only one of"), "got: {err}");
    }

    #[test]
    fn tracking_mode_error_branch_and_channel() {
        let mut cfg = base_cfg();
        cfg.branch = Some("main".into());
        cfg.channel = Some("stable".into());
        let err = cfg.tracking_mode().unwrap_err();
        assert!(err.to_string().contains("only one of"), "got: {err}");
    }

    #[test]
    fn tracking_mode_error_commit_and_version() {
        let mut cfg = base_cfg();
        cfg.commit = Some("abc123".into());
        cfg.version = Some("^2026".into());
        let err = cfg.tracking_mode().unwrap_err();
        assert!(err.to_string().contains("only one of"), "got: {err}");
    }

    #[test]
    fn tracking_mode_invalid_version_constraint() {
        let mut cfg = base_cfg();
        cfg.version = Some("not a valid constraint!!!".into());
        let err = cfg.tracking_mode().unwrap_err();
        assert!(
            err.to_string().contains("invalid version constraint"),
            "got: {err}"
        );
    }

    #[test]
    fn tracking_mode_version_exact() {
        let mut cfg = base_cfg();
        cfg.version = Some("=2026.4.0".into());
        match cfg.tracking_mode().unwrap() {
            TrackingMode::Version(req) => {
                assert!(req.matches(&semver::Version::new(2026, 4, 0)));
                assert!(!req.matches(&semver::Version::new(2026, 4, 1)));
            }
            other => panic!("expected Version, got {:?}", other),
        }
    }

    #[test]
    fn tracking_mode_version_caret() {
        let mut cfg = base_cfg();
        cfg.version = Some("^2026".into());
        match cfg.tracking_mode().unwrap() {
            TrackingMode::Version(req) => {
                assert!(req.matches(&semver::Version::new(2026, 0, 0)));
                assert!(req.matches(&semver::Version::new(2026, 12, 99)));
                assert!(!req.matches(&semver::Version::new(2027, 0, 0)));
            }
            other => panic!("expected Version, got {:?}", other),
        }
    }

    #[test]
    fn tracking_mode_version_range() {
        let mut cfg = base_cfg();
        cfg.version = Some(">=2026.3, <2026.5".into());
        match cfg.tracking_mode().unwrap() {
            TrackingMode::Version(req) => {
                assert!(req.matches(&semver::Version::new(2026, 3, 0)));
                assert!(req.matches(&semver::Version::new(2026, 4, 9)));
                assert!(!req.matches(&semver::Version::new(2026, 5, 0)));
                assert!(!req.matches(&semver::Version::new(2026, 2, 0)));
            }
            other => panic!("expected Version, got {:?}", other),
        }
    }

    #[test]
    fn tracking_mode_display() {
        let mut cfg = base_cfg();
        cfg.branch = Some("stable".into());
        assert_eq!(cfg.tracking_mode().unwrap().to_string(), "branch:stable");

        cfg.branch = None;
        cfg.tag = Some("v2026.03".into());
        assert_eq!(cfg.tracking_mode().unwrap().to_string(), "tag:v2026.03");

        cfg.tag = None;
        assert_eq!(cfg.tracking_mode().unwrap().to_string(), "default");
    }

    #[test]
    fn parse_registry_file_with_tracking_fields() {
        let toml_str = r#"
[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"
branch = "stable"
"#;
        let rf: RegistryFile = toml::from_str(toml_str).unwrap();
        assert_eq!(rf.registry.branch.as_deref(), Some("stable"));
        assert!(rf.registry.tag.is_none());
        assert!(rf.registry.commit.is_none());
        assert!(rf.registry.version.is_none());
    }

    #[test]
    fn parse_registry_file_with_version_field() {
        let toml_str = r#"
[registry]
name = "test"
url = "https://example.com"
version = "~2026.3"
"#;
        let rf: RegistryFile = toml::from_str(toml_str).unwrap();
        assert_eq!(rf.registry.version.as_deref(), Some("~2026.3"));
    }

    #[test]
    fn parse_registry_file_backward_compat_pin() {
        // Old config files with `pin` should still parse
        let toml_str = r#"
[registry]
name = "test"
url = "https://example.com"
pin = "v2026.02"
"#;
        let rf: RegistryFile = toml::from_str(toml_str).unwrap();
        assert_eq!(rf.registry.pin.as_deref(), Some("v2026.02"));
    }

    #[test]
    fn profile_scope_name_and_other() {
        assert_eq!(ProfileScope::User.name(), "user");
        assert_eq!(ProfileScope::System.name(), "system");
        assert_eq!(ProfileScope::User.other(), ProfileScope::System);
        assert_eq!(ProfileScope::System.other(), ProfileScope::User);
    }

    // -----------------------------------------------------------------------
    // Two-axis generation records.
    // -----------------------------------------------------------------------

    /// A configuration generation carrying the two-axis fields round-trips through serde.
    /// and the new fields are emitted (and re-read) verbatim.
    #[test]
    fn config_gen_axis_fields_round_trip() {
        let g = ConfigGeneration {
            number: 7,
            created_at: "2026-06-01T00:00:00Z".into(),
            image_gen_parent: 2,
            module_abi_pinned: 2,
            manifest_hash: "sha256:beef".into(),
            package_modules: vec![PackageModule {
                package: "server".into(),
                document_digest: format!("sha256:{}", "a".repeat(64)),
                store_path: "/nix/store/src-cfg".into(),
                nar_hash: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                entrypoint: "module.nix".into(),
                origin: PackageModuleOrigin::Registry,
            }],
            host_nix_ref: "/nix/store/hn-host.nix".into(),
            host_nix_commit: Some("deadbeef".into()),
            facts_hash: "sha256:facts".into(),
            facts_ref: "/nix/store/fa-facts.json".into(),
            base_lib_ref: "/nix/store/bl-base-lib".into(),
            evaluator_ref: "/nix/store/ev-evaluator".into(),
        };
        let json = serde_json::to_string(&g).unwrap();
        assert!(json.contains("module_abi_pinned"));
        assert!(
            !json.contains("native_executor_ref"),
            "configuration generations cannot replace the image-owned native executor"
        );
        let parsed: ConfigGeneration = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.module_abi_pinned, 2);
        assert_eq!(parsed.host_nix_ref, "/nix/store/hn-host.nix");
    }

    /// The image-generation axis round-trips provider-neutral identity and opaque provider state.
    #[test]
    fn image_generation_state_round_trip() {
        let state = ImageGenerationState {
            schema: "aos.image-generation-state/v1".into(),
            running: 1,
            pending: Some(2),
            boot_provider_state: BootProviderState {
                schema: "aos.test.boot-state/v1".into(),
                evidence: serde_json::json!({"selected": 2}),
            },
            active_rollout: Some(ImageRollout {
                schema: "aos.image-rollout/v1".into(),
                candidate: 2,
                prior: 1,
                state_version: "7".into(),
                status: ImageRolloutStatus::Staged,
            }),
            last_rollout: None,
            generations: vec![
                ImageGeneration {
                    number: 1,
                    boot_artifact_contract:
                        "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-boot-contract-1".into(),
                    boot_provider_state: BootProviderState {
                        schema: "aos.test.boot-generation-state/v1".into(),
                        evidence: serde_json::json!({"installed-entry": "entry-1"}),
                    },
                    toplevel: "/nix/store/top1-server".into(),
                    package_name: "server".into(),
                    version: "2026.06.1".into(),
                    state_version: "7".into(),
                    native_executor_ref: "/nix/store/executor-1".into(),
                    registry: "core".into(),
                    kernel_path: Some("/nix/store/k1-linux".into()),
                    evaluator_ref: "/nix/store/bl1-aos-base-lib".into(),
                    module_abi: 1,
                    base_lib_abi_hash: "sha256:aa".into(),
                    created_at: "2026-06-01T00:00:00Z".into(),
                },
                ImageGeneration {
                    number: 2,
                    boot_artifact_contract:
                        "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-boot-contract-2".into(),
                    boot_provider_state: BootProviderState {
                        schema: "aos.test.boot-generation-state/v1".into(),
                        evidence: serde_json::json!({"installed-entry": "entry-2"}),
                    },
                    toplevel: "/nix/store/top2-server".into(),
                    package_name: "server".into(),
                    version: "2026.06.2".into(),
                    state_version: "7".into(),
                    native_executor_ref: "/nix/store/executor-2".into(),
                    registry: "core".into(),
                    kernel_path: Some("/nix/store/k2-linux".into()),
                    evaluator_ref: "/nix/store/bl2-aos-base-lib".into(),
                    module_abi: 2,
                    base_lib_abi_hash: "sha256:bb".into(),
                    created_at: "2026-06-02T00:00:00Z".into(),
                },
            ],
        };
        let json = serde_json::to_string(&state).unwrap();
        let parsed: ImageGenerationState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.running, 1);
        assert_eq!(parsed.pending, Some(2));
        assert_eq!(
            parsed.active_rollout.as_ref().map(|rollout| rollout.status),
            Some(ImageRolloutStatus::Staged)
        );
        let running = parsed.running_generation().unwrap();
        assert_eq!(running.module_abi, 1);
        assert!(running.admits_pin(1));
        assert!(!running.admits_pin(2));
        assert_eq!(
            parsed.generations[1].boot_provider_state.evidence["installed-entry"],
            "entry-2"
        );

        for required in ["state_version", "native_executor_ref"] {
            let mut incomplete = serde_json::to_value(&state).unwrap();
            incomplete["generations"][0]
                .as_object_mut()
                .unwrap()
                .remove(required);

            let error = serde_json::from_value::<ImageGenerationState>(incomplete)
                .expect_err("the final image-generation identity must be complete");
            assert!(error.to_string().contains(required));
        }
    }

    fn sample_documentation_artifact() -> DocumentationArtifactMeta {
        DocumentationArtifactMeta {
            format: aos_doc_model::DOCUMENT_FORMAT.to_string(),
            store_path: "/nix/store/0000000000000000000000000000000e-firewall-1.4.0-aos-docs.json"
                .to_string(),
            nar_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            nar_size: 1024,
            document_sha256:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            document_size: 900,
            semantic_schema_sha256:
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                    .to_string(),
            references: Vec::new(),
        }
    }

    #[test]
    fn documentation_artifact_is_feature_gated_and_retained() {
        let mut meta = sample_package_meta();
        meta.documentation = Some(sample_documentation_artifact());
        meta.attestation.provenance = Some("provenance/firewall.intoto.jsonl".to_string());
        meta.requires_features
            .push(FEATURE_ATTESTATION_V1.to_string());

        let error = validate_supported_package_meta(&meta).expect_err("missing feature");
        assert!(error.to_string().contains(FEATURE_PACKAGE_DOCUMENTATION_V1));

        meta.requires_features
            .push(FEATURE_PACKAGE_DOCUMENTATION_V1.to_string());
        validate_supported_package_meta(&meta).expect("valid documentation metadata");

        let installed = ApmMeta {
            name: meta.name.clone(),
            version: meta.version.clone(),
            explicit: true,
            registry: "core".to_string(),
            installed_at: "2026-08-28T00:00:00Z".to_string(),
            held: false,
            source_drv: meta.source_drv.clone(),
            source_nar_hash: meta.source_nar_hash.clone(),
            documentation: meta.documentation.clone(),
            contract: None,
            attestation: meta.attestation.clone(),
        };
        let encoded = serde_json::to_vec(&installed).expect("installed metadata");
        let decoded: ApmMeta = serde_json::from_slice(&encoded).expect("decode installed metadata");
        assert_eq!(decoded.documentation, meta.documentation);
    }

    #[test]
    fn documentation_artifact_rejects_references_and_oversize_objects() {
        let mut artifact = sample_documentation_artifact();
        artifact
            .references
            .push("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
        assert!(validate_documentation_artifact_meta(&artifact).is_err());

        artifact.references.clear();
        artifact.document_size = aos_doc_model::MAX_DOCUMENT_BYTES as u64 + 1;
        assert!(validate_documentation_artifact_meta(&artifact).is_err());
    }

    #[test]
    fn native_image_rollout_gate_rejects_pre_change_package_readers() {
        let mut meta = sample_package_meta();
        meta.name = "aos".to_string();
        meta.sysroot = true;
        meta.requires_features = vec![FEATURE_IMAGE_ARTIFACT_CONTRACT_V1.to_string()];

        validate_supported_package_meta(&meta)
            .expect("the current package reader understands native image rollouts");

        let pre_change_features = SUPPORTED_PACKAGE_FEATURES
            .iter()
            .copied()
            .filter(|feature| *feature != FEATURE_IMAGE_ARTIFACT_CONTRACT_V1)
            .collect::<Vec<_>>();
        let error =
            validate_supported_package_meta_with(&meta, PACKAGE_META_FORMAT, &pre_change_features)
                .expect_err("a pre-change package reader must reject the rollout gate");
        assert!(
            error
                .to_string()
                .contains(FEATURE_IMAGE_ARTIFACT_CONTRACT_V1)
        );
    }
    fn sample_package_meta() -> PackageMeta {
        PackageMeta {
            name: "firewall".to_string(),
            version: "1.4.0".to_string(),
            description: "host firewall".to_string(),
            homepage: None,
            license: "MIT".to_string(),
            maintainer: "aos".to_string(),
            platform: "x86_64-linux".to_string(),
            store_path: "/nix/store/0000000000000000000000000000000c-firewall-1.4.0".to_string(),
            nar_hash: "sha256:aa".to_string(),
            nar_size: 10,
            references: vec![],
            source_drv: "/nix/store/0000000000000000000000000000000d-firewall.drv".to_string(),
            source_nar_hash: "sha256:bb".to_string(),
            closure_size: 10,
            sysroot: false,
            previous: None,
            images: vec![],
            min_format: None,
            requires_features: vec![],
            documentation: None,
            contract: None,
            attestation: AttestationMeta::default(),
        }
    }
}
