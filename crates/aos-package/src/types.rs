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
//!   [`SystemGeneration`] / [`SystemGenerationState`]
//!   (`/var/lib/profiles/system/state.json`).
//! - **Settings and scopes** — [`ApmSettings`] (`apm.conf`) and
//!   [`ProfileScope`], which maps the user/system scopes onto their config,
//!   cache, registry-clone, and trusted-key directories.
//!
//! These types are the crate's stable data contracts: changing a field name
//! or default changes what is written to (or accepted from) disk.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Current registry package metadata format understood by this crate.
pub const PACKAGE_META_FORMAT: u32 = 1;

/// Registry feature flag for the RFC-0001 `expose` metadata schema.
pub const FEATURE_EXPOSE_V1: &str = "expose-v1";

/// Registry feature flag for RFC-0001 rendered expose artifacts.
pub const FEATURE_EXPOSE_ARTIFACT_V1: &str = "expose-artifact-v1";

/// Registry feature flag for the RFC-0001 permission manifest schema.
pub const FEATURE_PERMISSIONS_V1: &str = "permissions-v1";

/// Registry feature flag for RFC-0001 name-based package requirements.
pub const FEATURE_REQUIRES_V1: &str = "requires-v1";

/// Registry feature flag for RFC-0001 package config metadata.
pub const FEATURE_CONFIG_V1: &str = "config-v1";

/// Registry feature flag for RFC-0001 package config reload metadata.
pub const FEATURE_RELOAD_V1: &str = "reload-v1";

/// Registry feature flag for RFC-0001 typed package capability routing.
pub const FEATURE_CAPABILITY_ROUTES_V1: &str = "capability-routes-v1";

const SUPPORTED_PACKAGE_FEATURES: &[&str] = &[
    FEATURE_EXPOSE_V1,
    FEATURE_EXPOSE_ARTIFACT_V1,
    FEATURE_PERMISSIONS_V1,
    FEATURE_REQUIRES_V1,
    FEATURE_CONFIG_V1,
    FEATURE_RELOAD_V1,
    FEATURE_CAPABILITY_ROUTES_V1,
];

const SYSTEM_LOCATION_PREFIXES: &[&str] = &[
    "/boot", "/etc", "/lib", "/lib64", "/nix", "/sbin", "/usr", "/var",
];
const ENCRYPTED_CREDENTIAL_SOURCE_PREFIXES: &[&str] = &[
    "/usr/lib/credstore.encrypted",
    "/etc/credstore.encrypted",
    "/run/credstore.encrypted",
];
const PLAINTEXT_CREDENTIAL_SOURCE_PREFIXES: &[&str] =
    &["/usr/lib/credstore", "/etc/credstore", "/run/credstore"];

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

/// Validate a package name before using it in registry package paths.
///
/// Package names are used as filenames under
/// `packages/<first-letter>/<name>.toml` and are commonly derived from Nix
/// store path names. Accept the ASCII path-safe characters Nix permits in
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
pub fn package_name_bucket(name: &str) -> String {
    name.chars()
        .next()
        .map(|ch| ch.to_ascii_lowercase().to_string())
        .unwrap_or_else(|| "_".to_string())
}

/// Validate a platform/system name before using it as a package TOML key.
///
/// Platform names become keys under `[versions.platforms]`, for example
/// `x86_64-linux` or `aarch64-linux`. Keep the accepted syntax to common Nix
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
    /// Optional RFC-0001 service exposure metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expose: Option<ExposeMeta>,
    /// Store artifact carrying rendered RFC-0001 unit files and manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expose_artifact: Option<ExposeArtifactMeta>,
    /// Signed RFC-0001 permission manifest.
    #[serde(default, skip_serializing_if = "PermissionsMeta::is_empty")]
    pub permissions: PermissionsMeta,
}

/// RFC-0001 service exposure metadata carried by registry package metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExposeMeta {
    /// Systemd target that is the package activation handle.
    pub target: String,
    /// Unit files rendered for this package and pulled in by the target.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub units: Vec<String>,
    /// Container/root artifacts attached to the package.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub images: Vec<SysrootImageEntry>,
    /// Package names that must be installed atomically with this package.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<String>,
    /// Package-scoped config declarations and hot-reload policy.
    #[serde(default, skip_serializing_if = "ExposeConfigMeta::is_empty")]
    pub config: ExposeConfigMeta,
    /// Typed capabilities this package offers to other packages.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provides: Vec<ProvidedCapabilityMeta>,
    /// Typed capabilities this package consumes from other packages.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uses: Vec<RequiredCapabilityMeta>,
}

/// RFC-0001 package config metadata signed with exposure metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExposeConfigMeta {
    /// Structured config artifacts `apm` validates and materializes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<ConfigArtifactMeta>,
    /// TPM2/systemd credential declarations consumed by package units.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<CredentialMeta>,
}

impl ExposeConfigMeta {
    /// Returns whether the package declares no config inputs.
    pub fn is_empty(&self) -> bool {
        self.artifacts.is_empty() && self.credentials.is_empty()
    }

    /// Returns whether config metadata asks runtime reconciliation to touch units.
    pub fn has_unit_reconciliation(&self) -> bool {
        self.artifacts
            .iter()
            .any(|artifact| !artifact.units.is_empty())
    }
}

/// Structured config artifact materialized from host desired-package config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigArtifactMeta {
    /// Stable artifact name inside the package config namespace.
    pub name: String,
    /// Absolute `/etc` path where `apm` materializes the artifact.
    pub path: String,
    /// Serialization format for the materialized artifact.
    pub format: ConfigArtifactFormat,
    /// Field names that must be present in desired config.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
    /// Field names that may be present in desired config.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub optional: Vec<String>,
    /// Service units whose config changes should reconcile.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub units: Vec<String>,
    /// Whether changed content reloads, restarts, or leaves units untouched.
    #[serde(default, skip_serializing_if = "ConfigReloadPolicy::is_default")]
    pub reload: ConfigReloadPolicy,
}

/// Materialized config artifact serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigArtifactFormat {
    /// systemd-compatible `KEY=VALUE` environment file.
    Env,
    /// JSON object.
    Json,
    /// TOML table.
    Toml,
}

/// Config-change reconciliation policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigReloadPolicy {
    /// Restart affected units on content change.
    #[default]
    Restart,
    /// Reload affected units on content change, falling back to restart if unsupported.
    Reload,
    /// Materialize the artifact without service reconciliation.
    None,
}

impl ConfigReloadPolicy {
    fn is_default(policy: &Self) -> bool {
        *policy == Self::Restart
    }
}

/// TPM2/systemd credential declaration for an exposed package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialMeta {
    /// systemd credential name.
    pub name: String,
    /// Optional host-side credstore source path for fail-closed loading.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Optional inline systemd encrypted credential payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphertext: Option<String>,
    /// Service units expected to consume this credential.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub units: Vec<String>,
    /// Whether the credential is expected to be TPM2/systemd encrypted.
    #[serde(default, rename = "encrypted", skip_serializing_if = "is_false")]
    pub encrypted: bool,
}

/// Typed package capability kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityKind {
    /// A provider-owned directory exposed read-only to consumers.
    Directory,
    /// A provider service namespace joined by consumer units.
    Namespace,
    /// Socket/fd-passing capability routed through generated systemd drop-ins.
    Socket,
}

/// Capability a package exposes to other packages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvidedCapabilityMeta {
    /// Capability name unique within the provider package.
    pub name: String,
    /// Capability materialization kind.
    pub kind: CapabilityKind,
    /// Provider path for [`CapabilityKind::Directory`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Provider unit for [`CapabilityKind::Namespace`] or future socket routes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
}

/// Capability a package consumes from another installed package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredCapabilityMeta {
    /// Provider package name.
    pub provider: String,
    /// Capability name on the provider package.
    pub name: String,
    /// Expected capability kind.
    pub kind: CapabilityKind,
    /// Consumer unit that receives the generated route drop-in.
    pub unit: String,
}

/// Store metadata for rendered RFC-0001 exposure artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExposeArtifactMeta {
    /// Store path containing `units/` and `manifest.json`.
    pub store_path: String,
    /// NAR hash of the rendered expose artifact.
    pub nar_hash: String,
    /// Uncompressed NAR size of the rendered expose artifact in bytes.
    pub nar_size: u64,
}

/// Signed RFC-0001 package permission manifest.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionsMeta {
    /// Linux capabilities requested by the package.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    /// Package network mode; absent means the default private mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkPermission>,
    /// Device nodes requested by the package.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<String>,
    /// Host paths requested by the package.
    #[serde(default, rename = "host-paths", skip_serializing_if = "Vec::is_empty")]
    pub host_paths: Vec<HostPathPermission>,
    /// Whether the package requests cgroup controller delegation.
    #[serde(default, rename = "cgroup-delegate", skip_serializing_if = "is_false")]
    pub cgroup_delegate: bool,
    /// Whether the package requests host-root-equivalent users.
    #[serde(default, rename = "privileged-users", skip_serializing_if = "is_false")]
    pub privileged_users: bool,
    /// Host-fulfilled kernel modules requested by the package.
    #[serde(
        default,
        rename = "kernel-modules",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub kernel_modules: Vec<String>,
    /// Named syscall profile requested by the package.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syscalls: Option<SyscallProfile>,
    /// Generated SELinux/AppArmor label requested by the package.
    #[serde(
        default,
        rename = "security-label",
        skip_serializing_if = "Option::is_none"
    )]
    pub security_label: Option<String>,
    /// Computed package confinement summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confinement: Option<ConfinementMeta>,
}

impl PermissionsMeta {
    /// Returns whether the manifest carries no explicit permission requests.
    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
            && self.network.is_none()
            && self.devices.is_empty()
            && self.host_paths.is_empty()
            && !self.cgroup_delegate
            && !self.privileged_users
            && self.kernel_modules.is_empty()
            && self.syscalls.is_none()
            && self.security_label.is_none()
            && self.confinement.is_none()
    }

    /// Returns whether the manifest requests host-policy-admitted grants.
    pub fn requires_policy_admission(&self) -> bool {
        self.network
            .is_some_and(|network| network != NetworkPermission::Private)
            || !self.capabilities.is_empty()
            || !self.devices.is_empty()
            || !self.host_paths.is_empty()
            || self.cgroup_delegate
            || self.privileged_users
            || !self.kernel_modules.is_empty()
            || self
                .syscalls
                .is_some_and(|syscalls| syscalls != SyscallProfile::Restricted)
    }

    /// Returns whether this manifest needs host policy for a package name.
    pub fn requires_policy_admission_for_package(&self, package_name: &str) -> bool {
        self.requires_policy_admission()
            || self
                .security_label
                .as_ref()
                .is_some_and(|label| label != &format!("aos-pkg-{package_name}"))
    }

    /// Computes the RFC-0001 confinement summary from permission grants.
    pub fn computed_confinement(&self) -> ConfinementMeta {
        let network = self.network.unwrap_or(NetworkPermission::Private);
        let syscall_profile = self.syscalls.unwrap_or(SyscallProfile::Restricted);
        let mut holes = Vec::new();

        if network != NetworkPermission::Private {
            holes.push(format!("network:{}", network.as_manifest_str()));
        }
        holes.extend(
            self.capabilities
                .iter()
                .map(|capability| format!("capability:{capability}")),
        );
        holes.extend(self.devices.iter().map(|device| format!("device:{device}")));
        holes.extend(self.host_paths.iter().map(|host_path| {
            format!(
                "host-path:{}:{}",
                host_path.mode.as_manifest_str(),
                host_path.path
            )
        }));
        if self.cgroup_delegate {
            holes.push("cgroup-delegate".into());
        }
        if self.privileged_users {
            holes.push("privileged-users".into());
        }
        if syscall_profile != SyscallProfile::Restricted {
            holes.push(format!("syscalls:{}", syscall_profile.as_manifest_str()));
        }

        let root_equivalent = self
            .capabilities
            .iter()
            .any(|capability| capability == "CAP_SYS_ADMIN")
            || self.privileged_users
            || self.host_paths.iter().any(|host_path| {
                host_path.mode == HostPathMode::Rw && has_system_location_prefix(&host_path.path)
            });

        let class = if root_equivalent {
            ConfinementClass::Unconfined
        } else if holes.is_empty() {
            ConfinementClass::Sandboxed
        } else {
            ConfinementClass::SandboxedWithHoles
        };
        let label = if class == ConfinementClass::SandboxedWithHoles {
            format!("sandboxed-with-holes ({})", holes.join(", "))
        } else {
            class.as_manifest_str().to_string()
        };

        ConfinementMeta {
            class,
            label,
            holes,
        }
    }
}

/// Computed RFC-0001 package confinement summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfinementMeta {
    /// Coarse confinement class computed from generated unit permissions.
    pub class: ConfinementClass,
    /// Human-readable confinement label shown by package tools.
    pub label: String,
    /// Permission holes that prevent the package from being fully sandboxed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub holes: Vec<String>,
}

/// Coarse RFC-0001 package confinement class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfinementClass {
    /// Generated units have the default sandbox and no explicit holes.
    Sandboxed,
    /// Generated units keep the default sandbox but include explicit holes.
    SandboxedWithHoles,
    /// Generated units request root-equivalent or host-level privileges.
    Unconfined,
}

impl ConfinementClass {
    fn as_manifest_str(self) -> &'static str {
        match self {
            ConfinementClass::Sandboxed => "sandboxed",
            ConfinementClass::SandboxedWithHoles => "sandboxed-with-holes",
            ConfinementClass::Unconfined => "unconfined",
        }
    }
}

/// RFC-0001 package network mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkPermission {
    /// Inbound-only private namespace with host-owned socket activation.
    Private,
    /// Private namespace with an outbound veth path.
    PrivateOutbound,
    /// Host network namespace.
    Host,
}

impl NetworkPermission {
    fn as_manifest_str(self) -> &'static str {
        match self {
            NetworkPermission::Private => "private",
            NetworkPermission::PrivateOutbound => "private-outbound",
            NetworkPermission::Host => "host",
        }
    }
}

/// Host path permission requested by a package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPathPermission {
    /// Absolute host path to bind into the package.
    pub path: String,
    /// Whether the bind is read-only or read-write.
    pub mode: HostPathMode,
}

/// Host path access mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostPathMode {
    /// Read-only host path bind.
    ReadOnly,
    /// Read-write host path bind.
    Rw,
}

impl HostPathMode {
    fn as_manifest_str(self) -> &'static str {
        match self {
            HostPathMode::ReadOnly => "read-only",
            HostPathMode::Rw => "rw",
        }
    }
}

/// Named syscall profile pinned to systemd syscall groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SyscallProfile {
    /// Minimal syscall profile for tightly sandboxed services.
    Restricted,
    /// Systemd's `@system-service` syscall group profile.
    SystemService,
    /// Privileged syscall profile for infrastructure packages.
    Privileged,
}

impl SyscallProfile {
    fn as_manifest_str(self) -> &'static str {
        match self {
            SyscallProfile::Restricted => "restricted",
            SyscallProfile::SystemService => "system-service",
            SyscallProfile::Privileged => "privileged",
        }
    }
}

/// Named host policy tier for RFC-0001 permission admission.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyTier {
    /// Tightest policy tier.
    Restricted,
    /// Default policy tier.
    #[default]
    Baseline,
    /// Privileged policy tier.
    Privileged,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Validate that a package metadata entry can be safely consumed.
///
/// # Errors
///
/// Returns an error when the entry requires a newer format, names an
/// unsupported feature, uses RFC-0001 metadata without declaring its feature
/// gate, names invalid package requirements, or requests `CAP_SYS_MODULE`
/// inside the workload instead of using the host-fulfilled `kernel-modules`
/// permission.
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

    if meta.expose.is_some() {
        require_feature(meta, FEATURE_EXPOSE_V1)?;
    }
    if meta.expose_artifact.is_some() {
        require_feature(meta, FEATURE_EXPOSE_ARTIFACT_V1)?;
    }
    if !meta.permissions.is_empty() {
        require_feature(meta, FEATURE_PERMISSIONS_V1)?;
    }

    if let Some(expose) = &meta.expose {
        validate_expose_meta(expose)?;
        if !expose.requires.is_empty() {
            require_feature(meta, FEATURE_REQUIRES_V1)?;
        }
        if !expose.config.is_empty() {
            require_feature(meta, FEATURE_CONFIG_V1)?;
        }
        if expose.config.has_unit_reconciliation() {
            require_feature(meta, FEATURE_RELOAD_V1)?;
        }
        if !expose.provides.is_empty() || !expose.uses.is_empty() {
            require_feature(meta, FEATURE_CAPABILITY_ROUTES_V1)?;
        }
        for required in &expose.requires {
            validate_package_name(required)
                .with_context(|| format!("invalid requires entry in package '{}'", meta.name))?;
        }
    }
    if let Some(artifact) = &meta.expose_artifact {
        if meta.expose.is_none() {
            bail!(
                "package '{}' carries expose artifact metadata without expose metadata",
                meta.name
            );
        }
        validate_expose_artifact_meta(artifact)
            .with_context(|| format!("invalid expose artifact for package '{}'", meta.name))?;
    }

    validate_permissions_meta(&meta.name, &meta.permissions)?;

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

/// Validate an RFC-0001 exposure metadata block.
///
/// # Errors
///
/// Returns an error when the target/unit names, image metadata, or required
/// package names are malformed.
pub fn validate_expose_meta(expose: &ExposeMeta) -> Result<()> {
    validate_target_name(&expose.target)?;
    let mut unit_names = std::collections::BTreeSet::new();
    for unit in &expose.units {
        validate_unit_name(unit)?;
        unit_names.insert(unit.as_str());
    }
    for image in &expose.images {
        validate_image_entry(image)?;
    }
    for required in &expose.requires {
        validate_package_name(required)?;
    }
    validate_expose_config_meta(&expose.config)?;
    validate_capability_routes(expose)?;
    validate_expose_unit_references(expose, &unit_names)?;
    Ok(())
}

fn validate_expose_unit_references(
    expose: &ExposeMeta,
    unit_names: &std::collections::BTreeSet<&str>,
) -> Result<()> {
    for artifact in &expose.config.artifacts {
        for unit in &artifact.units {
            if !unit_names.contains(unit.as_str()) {
                bail!(
                    "config artifact '{}' references unknown expose unit '{}'",
                    artifact.name,
                    unit
                );
            }
        }
    }
    for credential in &expose.config.credentials {
        for unit in &credential.units {
            if !unit_names.contains(unit.as_str()) {
                bail!(
                    "credential '{}' references unknown expose unit '{}'",
                    credential.name,
                    unit
                );
            }
        }
    }
    for provided in &expose.provides {
        if let Some(unit) = &provided.unit
            && !unit_names.contains(unit.as_str())
        {
            bail!(
                "provided capability '{}' references unknown expose unit '{}'",
                provided.name,
                unit
            );
        }
    }
    for required in &expose.uses {
        if !required.unit.ends_with(".service") {
            bail!(
                "required capability '{}.{}' references non-service expose unit '{}'",
                required.provider,
                required.name,
                required.unit
            );
        }
        if !unit_names.contains(required.unit.as_str()) {
            bail!(
                "required capability '{}.{}' references unknown expose unit '{}'",
                required.provider,
                required.name,
                required.unit
            );
        }
    }
    Ok(())
}

/// Validate RFC-0001 package config metadata.
///
/// # Errors
///
/// Returns an error when an artifact, credential, field name, or target unit is
/// malformed.
pub fn validate_expose_config_meta(config: &ExposeConfigMeta) -> Result<()> {
    let mut artifact_names = std::collections::BTreeSet::new();
    let mut artifact_paths = std::collections::BTreeSet::new();
    for artifact in &config.artifacts {
        validate_config_artifact_name(&artifact.name)?;
        if !artifact_names.insert(&artifact.name) {
            bail!("duplicate config artifact name '{}'", artifact.name);
        }
        validate_config_artifact_path(&artifact.path)?;
        if !artifact_paths.insert(&artifact.path) {
            bail!("duplicate config artifact path '{}'", artifact.path);
        }
        let mut fields = std::collections::BTreeSet::new();
        for field in artifact.required.iter().chain(&artifact.optional) {
            validate_config_field_name(field)?;
            if !fields.insert(field) {
                bail!(
                    "config artifact '{}' declares field '{}' more than once",
                    artifact.name,
                    field
                );
            }
        }
        for unit in &artifact.units {
            validate_unit_name(unit)?;
        }
    }

    let mut credential_names = std::collections::BTreeSet::new();
    for credential in &config.credentials {
        validate_credential_name(&credential.name)?;
        if !credential_names.insert(&credential.name) {
            bail!("duplicate credential name '{}'", credential.name);
        }
        if let Some(source) = &credential.source {
            validate_credential_source_path(source, credential.encrypted)?;
        }
        if let Some(ciphertext) = &credential.ciphertext {
            if !credential.encrypted {
                bail!(
                    "credential '{}' declares ciphertext but is not encrypted",
                    credential.name
                );
            }
            if credential.source.is_some() {
                bail!(
                    "credential '{}' must not declare both source and ciphertext",
                    credential.name
                );
            }
            validate_credential_ciphertext(ciphertext)?;
        }
        for unit in &credential.units {
            validate_unit_name(unit)?;
            if !unit.ends_with(".service") {
                bail!(
                    "credential '{}' references non-service expose unit '{}'",
                    credential.name,
                    unit
                );
            }
        }
    }

    Ok(())
}

/// Validate rendered RFC-0001 expose artifact metadata.
///
/// # Errors
///
/// Returns an error when the store path is not absolute or the recorded NAR
/// fields are missing or malformed.
pub fn validate_expose_artifact_meta(artifact: &ExposeArtifactMeta) -> Result<()> {
    validate_absolute_path(&artifact.store_path, "expose artifact store path")?;
    if store_path_hash_component(&artifact.store_path).is_none() {
        bail!(
            "expose artifact store path is not a Nix-style store path: {}",
            artifact.store_path
        );
    }
    if !artifact.nar_hash.starts_with("sha256:") && !artifact.nar_hash.starts_with("sha256-") {
        bail!(
            "expose artifact '{}' has invalid NAR hash",
            artifact.store_path
        );
    }
    if artifact.nar_size == 0 {
        bail!(
            "expose artifact '{}' must record a non-zero NAR size",
            artifact.store_path
        );
    }
    Ok(())
}

/// Validate an RFC-0001 permission manifest.
///
/// # Errors
///
/// Returns an error when a manifest entry is malformed or asks for
/// `CAP_SYS_MODULE` inside the workload.
pub fn validate_permissions_meta(package_name: &str, permissions: &PermissionsMeta) -> Result<()> {
    for capability in &permissions.capabilities {
        validate_capability_name(capability)?;
        if capability == "CAP_SYS_MODULE" {
            bail!(
                "package '{package_name}' requests CAP_SYS_MODULE; load modules through kernel-modules instead"
            );
        }
    }
    for device in &permissions.devices {
        validate_absolute_path(device, "device")?;
    }
    for host_path in &permissions.host_paths {
        validate_absolute_path(&host_path.path, "host path")?;
    }
    for module in &permissions.kernel_modules {
        validate_kernel_module_name(module)?;
    }
    if let Some(label) = &permissions.security_label {
        validate_security_label(label)?;
    }
    if let Some(confinement) = &permissions.confinement {
        validate_confinement_meta(confinement)?;
        let computed = permissions.computed_confinement();
        if confinement != &computed {
            bail!(
                "package '{package_name}' permissions.confinement does not match computed confinement: expected class {:?}, label '{}', holes {:?}; got class {:?}, label '{}', holes {:?}",
                computed.class,
                computed.label,
                computed.holes,
                confinement.class,
                confinement.label,
                confinement.holes
            );
        }
    }
    Ok(())
}

pub(crate) fn validate_capability_name(capability: &str) -> Result<()> {
    if capability.starts_with("CAP_")
        && capability
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch == '_' || ch.is_ascii_digit())
    {
        return Ok(());
    }
    bail!("invalid capability name '{capability}'")
}

pub(crate) fn validate_kernel_module_name(module: &str) -> Result<()> {
    if module.is_empty()
        || !module
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        bail!("invalid kernel module name '{module}'");
    }
    Ok(())
}

pub(crate) fn validate_absolute_path(path: &str, kind: &str) -> Result<()> {
    if Path::new(path).is_absolute() {
        return Ok(());
    }
    bail!("{kind} must be an absolute path: {path}")
}

fn validate_config_artifact_name(name: &str) -> Result<()> {
    if !name.is_empty()
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.')
        && !name.contains("..")
    {
        return Ok(());
    }
    bail!("invalid config artifact name '{name}'")
}

fn validate_config_artifact_path(path: &str) -> Result<()> {
    validate_absolute_path(path, "config artifact path")?;
    let p = Path::new(path);
    if p.starts_with("/etc/aos/packages") && p.components().all(|c| c.as_os_str() != "..") {
        return Ok(());
    }
    bail!("config artifact path must be under /etc/aos/packages: {path}")
}

pub(crate) fn validate_config_field_name(field: &str) -> Result<()> {
    if !field.is_empty()
        && field.chars().enumerate().all(|(idx, ch)| {
            ch == '_' || ch.is_ascii_alphanumeric() && (idx > 0 || !ch.is_ascii_digit())
        })
    {
        return Ok(());
    }
    bail!("invalid config field name '{field}'")
}

pub(crate) fn validate_credential_name(name: &str) -> Result<()> {
    if !name.is_empty()
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.')
    {
        return Ok(());
    }
    bail!("invalid credential name '{name}'")
}

fn validate_credential_source_path(path: &str, encrypted: bool) -> Result<()> {
    validate_absolute_path(path, "credential source path")?;
    let p = Path::new(path);
    if p.components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        bail!("credential source path must not contain '..': {path}");
    }
    if !path.chars().all(|ch| {
        ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '-' | '+' | '=' | '@')
    }) {
        bail!("credential source path contains unsupported characters: {path:?}");
    }
    let allowed = if encrypted {
        ENCRYPTED_CREDENTIAL_SOURCE_PREFIXES
    } else {
        PLAINTEXT_CREDENTIAL_SOURCE_PREFIXES
    };
    if allowed
        .iter()
        .any(|prefix| path != *prefix && p.starts_with(prefix))
    {
        return Ok(());
    }
    if encrypted {
        bail!(
            "encrypted credential source path must be under /usr/lib/credstore.encrypted, /etc/credstore.encrypted, or /run/credstore.encrypted: {path}"
        );
    }
    bail!(
        "credential source path must be under /usr/lib/credstore, /etc/credstore, or /run/credstore: {path}"
    )
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

fn validate_capability_routes(expose: &ExposeMeta) -> Result<()> {
    let mut provided_names = std::collections::BTreeSet::new();
    for provided in &expose.provides {
        validate_capability_route_name(&provided.name)?;
        if !provided_names.insert(&provided.name) {
            bail!("duplicate provided capability '{}'", provided.name);
        }
        match provided.kind {
            CapabilityKind::Directory => {
                let Some(path) = provided.path.as_ref() else {
                    bail!(
                        "directory capability '{}' must declare a path",
                        provided.name
                    );
                };
                validate_absolute_path(path, "provided directory capability path")?;
                if provided.unit.is_some() {
                    bail!(
                        "directory capability '{}' must not declare a unit",
                        provided.name
                    );
                }
            }
            CapabilityKind::Namespace | CapabilityKind::Socket => {
                let Some(unit) = provided.unit.as_ref() else {
                    bail!(
                        "{:?} capability '{}' must declare a unit",
                        provided.kind,
                        provided.name
                    );
                };
                validate_unit_name(unit)?;
                if provided.path.is_some() {
                    bail!(
                        "{:?} capability '{}' must not declare a path",
                        provided.kind,
                        provided.name
                    );
                }
            }
        }
    }

    for required in &expose.uses {
        validate_package_name(&required.provider)?;
        validate_capability_route_name(&required.name)?;
        validate_unit_name(&required.unit)?;
    }

    Ok(())
}

fn validate_capability_route_name(name: &str) -> Result<()> {
    if !name.is_empty()
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.')
    {
        return Ok(());
    }
    bail!("invalid capability route name '{name}'")
}

fn validate_target_name(target: &str) -> Result<()> {
    validate_unit_name(target)?;
    if !target.starts_with("aos-pkg-") || !target.ends_with(".target") {
        bail!("expose target must be named aos-pkg-<name>.target: {target}");
    }
    Ok(())
}

pub(crate) fn validate_unit_name(unit: &str) -> Result<()> {
    let has_known_suffix = [
        ".automount",
        ".mount",
        ".path",
        ".service",
        ".slice",
        ".socket",
        ".target",
        ".timer",
    ]
    .iter()
    .any(|suffix| unit.ends_with(suffix));

    if unit.is_empty()
        || unit.contains('/')
        || unit.chars().any(char::is_whitespace)
        || !has_known_suffix
    {
        bail!("invalid systemd unit name '{unit}'");
    }
    Ok(())
}

fn validate_image_entry(image: &SysrootImageEntry) -> Result<()> {
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

fn validate_confinement_meta(confinement: &ConfinementMeta) -> Result<()> {
    validate_display_ascii("confinement label", &confinement.label)?;
    for hole in &confinement.holes {
        validate_display_ascii("confinement hole", hole)?;
    }
    Ok(())
}

fn validate_display_ascii(kind: &str, value: &str) -> Result<()> {
    if value.is_empty() || !value.chars().all(|ch| ch.is_ascii_graphic() || ch == ' ') {
        bail!("invalid {kind} '{value}'");
    }
    Ok(())
}

fn has_system_location_prefix(path: &str) -> bool {
    SYSTEM_LOCATION_PREFIXES
        .iter()
        .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}/")))
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
    /// RFC-0001 service exposure metadata captured at install time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expose: Option<ExposeMeta>,
    /// Rendered RFC-0001 expose artifact captured at install time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expose_artifact: Option<ExposeArtifactMeta>,
    /// RFC-0001 permission manifest captured at install time.
    #[serde(default, skip_serializing_if = "PermissionsMeta::is_empty")]
    pub permissions: PermissionsMeta,
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
    /// PCR policy public key used for signed-PCR credential encryption.
    #[serde(default)]
    pub credential_pcr_public_key: Option<String>,
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
            credential_pcr_public_key: None,
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
    /// [`SystemGenerationState`]. Runtime system packages use a separate
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

    /// Directories searched for provisioned Secure Boot db certificates, in
    /// precedence order.
    ///
    /// Mirrors [`ProfileScope::trusted_keys_dirs`]: a deployment bakes
    /// `trusted-sb-certs.d/<registry>.pem` alongside `trusted-keys.d`, giving
    /// `apm` the db cert to re-verify cataloged UKIs against at download time
    /// (RFC-0006 phase 4 trust-bootstrap symmetry).
    pub fn trusted_sb_certs_dirs(&self) -> Vec<PathBuf> {
        match self {
            ProfileScope::User => vec![
                xdg_config_home().join("apm/trusted-sb-certs.d"),
                apm_system_config_dir().join("trusted-sb-certs.d"),
            ],
            ProfileScope::System => vec![
                apm_system_config_dir().join("trusted-sb-certs.d"),
                apm_state_dir().join("trusted-sb-certs.d"),
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

/// Top-level structure of a registry's `registry.toml` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryRootConfig {
    /// The `[registry]` metadata table.
    pub registry: RegistryRootMeta,
    /// Committed `[[caches]]` entries: binary caches every consumer of this
    /// registry should use.
    #[serde(default)]
    pub caches: Vec<CacheEntry>,
}

/// Registry metadata in `registry.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryRootMeta {
    /// Canonical registry name.
    pub name: String,
    /// Optional human-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// Whether the producer records content addresses in the `store/`
    /// realisation graph (RFC-0005), so the registry serves both
    /// input-addressed and content-addressed consumers. Default `true`;
    /// set `false` for a pure input-addressed registry.
    #[serde(default = "default_content_addressed")]
    pub content_addressed: bool,
}

/// Serde default for [`RegistryRootMeta::content_addressed`].
fn default_content_addressed() -> bool {
    true
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
// Sysroot image entry — a pre-compiled image attached to a sysroot package
// ---------------------------------------------------------------------------

/// A single SBAT (Secure Boot Advanced Targeting) component record.
///
/// SBAT entries are read from a UKI's PE `.sbat` section: each line of that
/// CSV section names a boot component and the *generation* number that an
/// `sbat` revocation can compare against. The registry records these so the
/// fleet can enforce a per-component minimum generation (the *revocation
/// floor*) at download time, mirroring what firmware/loader SBAT enforces at
/// boot time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbatEntry {
    /// SBAT component identifier (the first CSV column, e.g. `aos`,
    /// `systemd`, `grub`).
    pub component: String,
    /// SBAT generation number for the component (the second CSV column).
    /// A higher number supersedes a lower one; the revocation floor is the
    /// minimum acceptable value.
    pub generation: u32,
}

/// A pre-compiled image format entry within a sysroot package version.
///
/// The trailing Secure Boot fields are populated only for signed UKIs/images
/// (see RFC-0006 phase 4). They are optional so that legacy and unsigned
/// publishes continue to parse: an entry with none of them set is treated as
/// "no Secure Boot claims recorded" and skips download-time SB validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SysrootImageEntry {
    /// Image format identifier (e.g. `qcow2`, `raw`), matched against
    /// `apm install --image <FMT>`.
    pub format: String,
    /// Store path containing the image file.
    pub store_path: String,
    /// Hash of the image's uncompressed NAR: `"sha256:..."`.
    pub nar_hash: String,
    /// Size of the image's uncompressed NAR in bytes.
    pub nar_size: u64,
    /// Lowercase hex SHA-256 of the signer leaf certificate found in the
    /// PE's Authenticode certificate table; the db cert this image must
    /// chain to. `None` for unsigned/legacy images.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sb_signer_cert_sha256: Option<String>,
    /// SBAT component/generation pairs read from the PE `.sbat` section.
    /// Empty when the image carries no `.sbat` section.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sbat: Vec<SbatEntry>,
    /// ukify/`systemd-measure`-predicted TPM PCR-11 value for this UKI
    /// (hex). See [`SysrootImageEntry`] callers and RFC-0006
    /// `registry-catalog.md` for the prediction-scope caveat: this records
    /// the UKI's own contribution, not the full sd-boot phase sequence.
    /// `None` when `systemd-measure` was unavailable at publish time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_pcr11: Option<String>,
}

// ---------------------------------------------------------------------------
// System generation state — persisted in /var/lib/profiles/system/state.json
// ---------------------------------------------------------------------------

/// Metadata about a single system generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemGeneration {
    /// Generation number (names the `gen-N/` directory).
    pub number: u32,
    /// Store path of the sysroot toplevel this generation activates.
    pub toplevel: String,
    /// Version of the sysroot package.
    pub version: String,
    /// Name of the sysroot package.
    pub package_name: String,
    /// Registry the sysroot package was installed from.
    pub registry: String,
    /// ISO 8601 timestamp when the generation was created.
    pub created_at: String,
    /// Resolved kernel store path, used to detect kernel changes across
    /// upgrades and rollbacks (`None` when the toplevel ships no kernel).
    #[serde(default)]
    pub kernel_path: Option<String>,
}

/// Persistent state for system generations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemGenerationState {
    /// Number of the currently active generation (`0` = none yet).
    pub current: u32,
    /// Number the next created generation will receive.
    pub next: u32,
    /// All recorded generations, in creation order.
    #[serde(default)]
    pub generations: Vec<SystemGeneration>,
}

#[cfg(test)]
mod tests {
    use super::*;

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
        for name in ["x86_64-linux", "aarch64-linux", "i686-linux", "wasm32-wasi"] {
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
credential_pcr_public_key = "/etc/aos/pcr-sign.pem"
"#;
        let conf: ApmConfFile = toml::from_str(toml_str).unwrap();
        assert!(conf.settings.assume_yes);
        assert_eq!(conf.settings.parallel_downloads, 8);
        assert!(conf.settings.auto_autoremove);
        assert!(!conf.settings.auto_gc);
        assert_eq!(
            conf.settings.credential_pcr_public_key.as_deref(),
            Some("/etc/aos/pcr-sign.pem")
        );
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
    }

    #[test]
    fn registry_root_config_ignores_signing_field() {
        let toml_str = r#"
[registry]
name = "aos-core"
description = "core registry"

[[caches]]
url = "https://cache.aos.dev"
priority = 1000

[registry.signing]
public_key = "aos-core:Ed25519:base64keyhere"
"#;
        let cfg: RegistryRootConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.registry.name, "aos-core");
        assert_eq!(cfg.registry.description.as_deref(), Some("core registry"));
        assert_eq!(cfg.caches.len(), 1);
        assert_eq!(cfg.caches[0].url, "https://cache.aos.dev");
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
                expose: None,
                expose_artifact: None,
                permissions: Default::default(),
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

    #[test]
    fn package_meta_round_trips_sandbox_schema() {
        let meta = PackageMeta {
            name: "webapp".into(),
            version: "1.0.0".into(),
            description: "Exposed web app".into(),
            homepage: None,
            license: "MIT".into(),
            maintainer: "aos-team".into(),
            platform: "x86_64-linux".into(),
            store_path: "/var/lib/store/webapphash11-webapp-1.0.0".into(),
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
            requires_features: vec![
                FEATURE_EXPOSE_V1.into(),
                FEATURE_EXPOSE_ARTIFACT_V1.into(),
                FEATURE_PERMISSIONS_V1.into(),
                FEATURE_REQUIRES_V1.into(),
            ],
            expose: Some(ExposeMeta {
                target: "aos-pkg-webapp.target".into(),
                units: vec!["webapp.service".into()],
                images: vec![SysrootImageEntry {
                    format: "dir".into(),
                    store_path: "/var/lib/store/webapproot-webapp-root".into(),
                    nar_hash: "sha256:root".into(),
                    nar_size: 2048,
                    sb_signer_cert_sha256: None,
                    sbat: Vec::new(),
                    expected_pcr11: None,
                }],
                requires: vec!["provider".into()],
                config: Default::default(),
                provides: Vec::new(),
                uses: Vec::new(),
            }),
            expose_artifact: Some(ExposeArtifactMeta {
                store_path: "/var/lib/store/exposehash11-expose-webapp".into(),
                nar_hash: "sha256:artifact".into(),
                nar_size: 128,
            }),
            permissions: PermissionsMeta {
                capabilities: vec!["CAP_NET_BIND_SERVICE".into()],
                network: Some(NetworkPermission::PrivateOutbound),
                host_paths: vec![HostPathPermission {
                    path: "/srv/webapp".into(),
                    mode: HostPathMode::ReadOnly,
                }],
                syscalls: Some(SyscallProfile::SystemService),
                confinement: Some(ConfinementMeta {
                    class: ConfinementClass::SandboxedWithHoles,
                    label: "sandboxed-with-holes (network:private-outbound, capability:CAP_NET_BIND_SERVICE, host-path:read-only:/srv/webapp, syscalls:system-service)"
                        .into(),
                    holes: vec![
                        "network:private-outbound".into(),
                        "capability:CAP_NET_BIND_SERVICE".into(),
                        "host-path:read-only:/srv/webapp".into(),
                        "syscalls:system-service".into(),
                    ],
                }),
                ..PermissionsMeta::default()
            },
        };

        validate_supported_package_meta(&meta).unwrap();
        let json = serde_json::to_string_pretty(&meta).unwrap();
        let parsed: PackageMeta = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.requires_features, meta.requires_features);
        assert_eq!(parsed.expose, meta.expose);
        assert_eq!(parsed.expose_artifact, meta.expose_artifact);
        assert_eq!(parsed.permissions, meta.permissions);
    }

    #[test]
    fn package_meta_requires_supported_feature_gate() {
        let meta = PackageMeta {
            name: "webapp".into(),
            version: "1.0.0".into(),
            description: "Exposed web app".into(),
            homepage: None,
            license: "MIT".into(),
            maintainer: "aos-team".into(),
            platform: "x86_64-linux".into(),
            store_path: "/var/lib/store/webapphash11-webapp-1.0.0".into(),
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
            requires_features: vec![FEATURE_PERMISSIONS_V1.into()],
            expose: None,
            expose_artifact: None,
            permissions: PermissionsMeta {
                network: Some(NetworkPermission::Host),
                ..PermissionsMeta::default()
            },
        };

        let err =
            validate_supported_package_meta_with(&meta, PACKAGE_META_FORMAT, &[]).unwrap_err();
        assert!(err.to_string().contains(FEATURE_PERMISSIONS_V1));
    }

    #[test]
    fn package_meta_rejects_mismatched_confinement() {
        let mut meta = PackageMeta {
            name: "webapp".into(),
            version: "1.0.0".into(),
            description: "Exposed web app".into(),
            homepage: None,
            license: "MIT".into(),
            maintainer: "aos-team".into(),
            platform: "x86_64-linux".into(),
            store_path: "/var/lib/store/webapphash11-webapp-1.0.0".into(),
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
            requires_features: vec![FEATURE_PERMISSIONS_V1.into()],
            expose: None,
            expose_artifact: None,
            permissions: PermissionsMeta {
                network: Some(NetworkPermission::Host),
                confinement: Some(ConfinementMeta {
                    class: ConfinementClass::Sandboxed,
                    label: "sandboxed".into(),
                    holes: Vec::new(),
                }),
                ..PermissionsMeta::default()
            },
        };

        let err = validate_supported_package_meta(&meta).unwrap_err();
        assert!(
            err.to_string()
                .contains("permissions.confinement does not match computed confinement"),
            "got: {err}"
        );

        meta.permissions.confinement = Some(meta.permissions.computed_confinement());
        validate_supported_package_meta(&meta).unwrap();
    }

    #[test]
    fn package_meta_requires_config_and_reload_feature_gates() {
        let mut meta = PackageMeta {
            name: "webapp".into(),
            version: "1.0.0".into(),
            description: "Exposed web app".into(),
            homepage: None,
            license: "MIT".into(),
            maintainer: "aos-team".into(),
            platform: "x86_64-linux".into(),
            store_path: "/var/lib/store/webapphash11-webapp-1.0.0".into(),
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
            requires_features: vec![FEATURE_EXPOSE_V1.into(), FEATURE_CONFIG_V1.into()],
            expose: Some(ExposeMeta {
                target: "aos-pkg-webapp.target".into(),
                units: vec!["webapp.service".into()],
                images: Vec::new(),
                requires: Vec::new(),
                config: ExposeConfigMeta {
                    artifacts: vec![ConfigArtifactMeta {
                        name: "env".into(),
                        path: "/etc/aos/packages/webapp/config.env".into(),
                        format: ConfigArtifactFormat::Env,
                        required: vec!["TOKEN".into()],
                        optional: Vec::new(),
                        units: vec!["webapp.service".into()],
                        reload: ConfigReloadPolicy::Reload,
                    }],
                    credentials: Vec::new(),
                },
                provides: Vec::new(),
                uses: Vec::new(),
            }),
            expose_artifact: None,
            permissions: PermissionsMeta::default(),
        };

        let err = validate_supported_package_meta(&meta).unwrap_err();
        assert!(err.to_string().contains(FEATURE_RELOAD_V1));

        meta.requires_features.push(FEATURE_RELOAD_V1.into());
        validate_supported_package_meta(&meta).unwrap();
    }

    #[test]
    fn package_meta_rejects_unknown_config_unit_references() {
        let meta = PackageMeta {
            name: "webapp".into(),
            version: "1.0.0".into(),
            description: "Exposed web app".into(),
            homepage: None,
            license: "MIT".into(),
            maintainer: "aos-team".into(),
            platform: "x86_64-linux".into(),
            store_path: "/var/lib/store/webapphash11-webapp-1.0.0".into(),
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
            requires_features: vec![
                FEATURE_EXPOSE_V1.into(),
                FEATURE_CONFIG_V1.into(),
                FEATURE_RELOAD_V1.into(),
            ],
            expose: Some(ExposeMeta {
                target: "aos-pkg-webapp.target".into(),
                units: vec!["webapp.service".into()],
                images: Vec::new(),
                requires: Vec::new(),
                config: ExposeConfigMeta {
                    artifacts: vec![ConfigArtifactMeta {
                        name: "env".into(),
                        path: "/etc/aos/packages/webapp/config.env".into(),
                        format: ConfigArtifactFormat::Env,
                        required: vec!["TOKEN".into()],
                        optional: Vec::new(),
                        units: vec!["missing.service".into()],
                        reload: ConfigReloadPolicy::Reload,
                    }],
                    credentials: Vec::new(),
                },
                provides: Vec::new(),
                uses: Vec::new(),
            }),
            expose_artifact: None,
            permissions: PermissionsMeta::default(),
        };

        let err = validate_supported_package_meta(&meta).unwrap_err();
        assert!(err.to_string().contains("unknown expose unit"));
    }

    #[test]
    fn expose_config_rejects_credential_non_service_units() {
        let config = ExposeConfigMeta {
            artifacts: Vec::new(),
            credentials: vec![CredentialMeta {
                name: "join-token".into(),
                source: None,
                ciphertext: None,
                units: vec!["webapp.socket".into()],
                encrypted: true,
            }],
        };

        let err = validate_expose_config_meta(&config).unwrap_err();
        assert!(err.to_string().contains("non-service expose unit"));
    }

    #[test]
    fn expose_config_rejects_credential_source_outside_credstore() {
        let config = ExposeConfigMeta {
            artifacts: Vec::new(),
            credentials: vec![CredentialMeta {
                name: "join-token".into(),
                source: Some("/etc/shadow".into()),
                ciphertext: None,
                units: vec!["webapp.service".into()],
                encrypted: true,
            }],
        };

        let err = validate_expose_config_meta(&config).unwrap_err();
        assert!(
            err.to_string()
                .contains("encrypted credential source path must be under")
        );
    }

    #[test]
    fn expose_config_rejects_credential_source_control_characters() {
        let config = ExposeConfigMeta {
            artifacts: Vec::new(),
            credentials: vec![CredentialMeta {
                name: "join-token".into(),
                source: Some(
                    "/usr/lib/credstore.encrypted/join-token\nPrivateNetwork=false".into(),
                ),
                ciphertext: None,
                units: vec!["webapp.service".into()],
                encrypted: true,
            }],
        };

        let err = validate_expose_config_meta(&config).unwrap_err();
        assert!(
            err.to_string()
                .contains("credential source path contains unsupported characters")
        );
    }

    #[test]
    fn expose_config_rejects_credential_ciphertext_without_encryption() {
        let config = ExposeConfigMeta {
            artifacts: Vec::new(),
            credentials: vec![CredentialMeta {
                name: "join-token".into(),
                source: None,
                ciphertext: Some("abcDEF0123+/=".into()),
                units: vec!["webapp.service".into()],
                encrypted: false,
            }],
        };

        let err = validate_expose_config_meta(&config).unwrap_err();
        assert!(err.to_string().contains("is not encrypted"));
    }

    #[test]
    fn expose_config_rejects_credential_source_and_ciphertext() {
        let config = ExposeConfigMeta {
            artifacts: Vec::new(),
            credentials: vec![CredentialMeta {
                name: "join-token".into(),
                source: Some("/usr/lib/credstore.encrypted/join-token".into()),
                ciphertext: Some("abcDEF0123+/=".into()),
                units: vec!["webapp.service".into()],
                encrypted: true,
            }],
        };

        let err = validate_expose_config_meta(&config).unwrap_err();
        assert!(err.to_string().contains("both source and ciphertext"));
    }

    #[test]
    fn expose_config_rejects_credential_ciphertext_control_characters() {
        let config = ExposeConfigMeta {
            artifacts: Vec::new(),
            credentials: vec![CredentialMeta {
                name: "join-token".into(),
                source: None,
                ciphertext: Some("abc\nPrivateNetwork=false".into()),
                units: vec!["webapp.service".into()],
                encrypted: true,
            }],
        };

        let err = validate_expose_config_meta(&config).unwrap_err();
        assert!(
            err.to_string()
                .contains("credential ciphertext contains unsupported characters")
        );
    }

    #[test]
    fn package_meta_requires_capability_route_feature_gate() {
        let mut meta = PackageMeta {
            name: "consumer".into(),
            version: "1.0.0".into(),
            description: "Consumer".into(),
            homepage: None,
            license: "MIT".into(),
            maintainer: "aos-team".into(),
            platform: "x86_64-linux".into(),
            store_path: "/var/lib/store/consumerhash-consumer-1.0.0".into(),
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
            requires_features: vec![FEATURE_EXPOSE_V1.into()],
            expose: Some(ExposeMeta {
                target: "aos-pkg-consumer.target".into(),
                units: vec!["consumer.service".into()],
                images: Vec::new(),
                requires: Vec::new(),
                config: Default::default(),
                provides: Vec::new(),
                uses: vec![RequiredCapabilityMeta {
                    provider: "provider".into(),
                    name: "data".into(),
                    kind: CapabilityKind::Directory,
                    unit: "consumer.service".into(),
                }],
            }),
            expose_artifact: None,
            permissions: PermissionsMeta::default(),
        };

        let err = validate_supported_package_meta(&meta).unwrap_err();
        assert!(err.to_string().contains(FEATURE_CAPABILITY_ROUTES_V1));

        meta.requires_features
            .push(FEATURE_CAPABILITY_ROUTES_V1.into());
        validate_supported_package_meta(&meta).unwrap();
    }

    #[test]
    fn package_meta_rejects_unknown_or_non_service_capability_units() {
        let mut meta = PackageMeta {
            name: "consumer".into(),
            version: "1.0.0".into(),
            description: "Consumer".into(),
            homepage: None,
            license: "MIT".into(),
            maintainer: "aos-team".into(),
            platform: "x86_64-linux".into(),
            store_path: "/var/lib/store/consumerhash-consumer-1.0.0".into(),
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
            requires_features: vec![
                FEATURE_EXPOSE_V1.into(),
                FEATURE_CAPABILITY_ROUTES_V1.into(),
            ],
            expose: Some(ExposeMeta {
                target: "aos-pkg-consumer.target".into(),
                units: vec!["consumer.service".into(), "consumer.target".into()],
                images: Vec::new(),
                requires: Vec::new(),
                config: Default::default(),
                provides: Vec::new(),
                uses: vec![RequiredCapabilityMeta {
                    provider: "provider".into(),
                    name: "data".into(),
                    kind: CapabilityKind::Directory,
                    unit: "missing.service".into(),
                }],
            }),
            expose_artifact: None,
            permissions: PermissionsMeta::default(),
        };

        let err = validate_supported_package_meta(&meta).unwrap_err();
        assert!(err.to_string().contains("unknown expose unit"));

        let expose = meta.expose.as_mut().unwrap();
        expose.uses[0].unit = "consumer.target".into();
        let err = validate_supported_package_meta(&meta).unwrap_err();
        assert!(err.to_string().contains("non-service expose unit"));
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
}
