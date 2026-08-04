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

/// Registry feature flag for RFC-0001 per-package network policy grants.
pub const FEATURE_NETWORK_POLICY_V1: &str = "network-policy-v1";

/// Registry feature flag for RFC-0001 generated MAC profile artifacts.
pub const FEATURE_MAC_PROFILE_V1: &str = "mac-profile-v1";

/// Registry feature flag for RFC-0001 generated eBPF network policy loaders.
pub const FEATURE_EBPF_NET_POLICY_V1: &str = "ebpf-net-policy-v1";

/// Registry feature flag for RFC-0001 fleet-managed BPF-LSM policy packages.
pub const FEATURE_BPF_LSM_POLICY_V1: &str = "bpf-lsm-policy-v1";

/// Registry feature flag for RFC-0001 package attestation metadata.
pub const FEATURE_ATTESTATION_V1: &str = "attestation-v1";

/// Registry feature flag for the second `config` package output and
/// its config-module metadata (`ConfigOutputMeta` + `ConfigModuleMeta`).
pub const FEATURE_CONFIG_MODULE_V1: &str = "config-module-v1";

/// Registry feature flag for slot-specific A/B UKI measurement metadata.
pub const FEATURE_UKI_SLOTS_V1: &str = "uki-slots-v1";

const SUPPORTED_PACKAGE_FEATURES: &[&str] = &[
    FEATURE_EXPOSE_V1,
    FEATURE_EXPOSE_ARTIFACT_V1,
    FEATURE_PERMISSIONS_V1,
    FEATURE_REQUIRES_V1,
    FEATURE_CONFIG_V1,
    FEATURE_RELOAD_V1,
    FEATURE_CAPABILITY_ROUTES_V1,
    FEATURE_NETWORK_POLICY_V1,
    FEATURE_MAC_PROFILE_V1,
    FEATURE_EBPF_NET_POLICY_V1,
    FEATURE_BPF_LSM_POLICY_V1,
    FEATURE_ATTESTATION_V1,
    FEATURE_CONFIG_MODULE_V1,
    FEATURE_UKI_SLOTS_V1,
];

const LANDLOCK_WRITABLE_TEMP_PREFIXES: &[&str] = &["/tmp", "/var/tmp"];
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

// Package-name validation and bucketing moved to the wasm-clean
// `aos-registry-surface` crate (RFC-0004 Phase 5) so the registry hub's indexer
// and the Cloudflare Worker share the exact rules without pulling `aos-package`.
// Re-exported here so `aos_package::types::{validate_package_name,
// package_name_bucket}` paths are unchanged.
pub use aos_registry_surface::manifest::{package_name_bucket, validate_package_name};

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
    /// Configuration-only module output and its declared interface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_module: Option<ConfigModuleMeta>,
    /// Signed RFC-0001 permission manifest.
    #[serde(default, skip_serializing_if = "PermissionsMeta::is_empty")]
    pub permissions: PermissionsMeta,
    /// Signed fleet BPF-LSM policy artifact metadata.
    #[serde(default, rename = "bpf_lsm", skip_serializing_if = "Option::is_none")]
    pub bpf_lsm: Option<BpfLsmPolicyMeta>,
    /// Runtime integrity, attestation, and provenance facts for this package.
    #[serde(default, skip_serializing_if = "AttestationMeta::is_empty")]
    pub attestation: AttestationMeta,
}

// The RFC-0001 package metadata schema types moved to the wasm-clean
// `aos-registry-surface` crate (RFC-0004 Phase 5) so the registry hub's indexer
// and the Cloudflare Worker share them with the apr/apm client. Re-exported here
// so `aos_package::types::{ExposeMeta, …}` paths are unchanged. The pure
// validation free functions below stay native to this crate; only the data
// contracts and their inherent helpers moved.
pub use aos_registry_surface::manifest::{
    AttestationMeta, BpfLsmPolicyArtifactMeta, BpfLsmPolicyMeta, CapabilityKind,
    ConfigArtifactFormat, ConfigArtifactMeta, ConfigReloadPolicy, ConfinementClass,
    ConfinementMeta, CredentialMeta, ExposeArtifactMeta, ExposeConfigMeta, ExposeMeta,
    HostPathMode, HostPathPermission, NetworkPermission, PermissionsMeta, ProvidedCapabilityMeta,
    RequiredCapabilityMeta, SyscallProfile,
};

// Configuration schema types are pure manifest data; they live in the
// wasm-clean `aos-registry-surface` crate alongside the rest of the package
// schema (so the hub indexer and the Worker share them) and are re-exported
// here so `aos_package::types::{ConfigModuleMeta, …}` paths are unchanged.
pub use aos_registry_surface::manifest::{
    ConfigModuleMeta, ConfigOptionDeclaration, ConfigOutputMeta, ModuleAbiCompat, OwnedRoot,
    RootContribution,
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
/// RFC-0001 exposure/permission/BPF-LSM metadata requires provenance via
/// [`rfc0001_metadata_requires_provenance`]; in addition, a configuration
/// `config_module` block is privileged metadata that independently forces
/// provenance.
pub(crate) fn package_requires_provenance(meta: &PackageMeta) -> bool {
    rfc0001_metadata_requires_provenance(
        meta.expose.as_ref(),
        meta.expose_artifact.as_ref(),
        &meta.permissions,
        meta.bpf_lsm.as_ref(),
    ) || meta.config_module.is_some()
}

/// Returns whether RFC-0001 metadata fields must be backed by DSSE provenance.
pub(crate) fn rfc0001_metadata_requires_provenance(
    expose: Option<&ExposeMeta>,
    expose_artifact: Option<&ExposeArtifactMeta>,
    permissions: &PermissionsMeta,
    bpf_lsm: Option<&BpfLsmPolicyMeta>,
) -> bool {
    expose.is_some()
        || expose_artifact.is_some()
        || !permissions.is_empty()
        || bpf_lsm.is_some_and(|bpf_lsm| !bpf_lsm.is_empty())
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
        require_feature(meta, FEATURE_NETWORK_POLICY_V1)?;
    }
    if meta.expose_artifact.is_some() {
        require_feature(meta, FEATURE_EXPOSE_ARTIFACT_V1)?;
    }
    if !meta.permissions.is_empty() {
        require_feature(meta, FEATURE_PERMISSIONS_V1)?;
        if meta.permissions.has_network_policy() {
            require_feature(meta, FEATURE_NETWORK_POLICY_V1)?;
        }
    }
    if let Some(bpf_lsm) = &meta.bpf_lsm {
        if !bpf_lsm.is_empty() {
            require_feature(meta, FEATURE_BPF_LSM_POLICY_V1)?;
            validate_bpf_lsm_policy_meta(bpf_lsm)
                .with_context(|| format!("invalid BPF-LSM policy metadata for '{}'", meta.name))?;
        }
    }
    if !meta.attestation.is_empty() {
        require_feature(meta, FEATURE_ATTESTATION_V1)?;
        validate_attestation_meta(&meta.attestation)
            .with_context(|| format!("invalid attestation metadata for '{}'", meta.name))?;
    }
    if let Some(config_module) = &meta.config_module {
        require_feature(meta, FEATURE_CONFIG_MODULE_V1)?;
        validate_config_module_meta(&meta.name, config_module)
            .with_context(|| format!("invalid config-module metadata for '{}'", meta.name))?;
    }
    if meta.images.iter().any(|image| !image.ukis.is_empty()) {
        require_feature(meta, FEATURE_UKI_SLOTS_V1)?;
    }
    for image in &meta.images {
        validate_image_entry(image)
            .with_context(|| format!("invalid sysroot image metadata for '{}'", meta.name))?;
    }
    if package_requires_provenance(meta) && meta.attestation.provenance.is_none() {
        let reason = if meta.config_module.is_some() {
            "uses config-module metadata"
        } else {
            "uses RFC-0001 exposed or permission metadata"
        };
        bail!(
            "package '{}' {reason} without attestation provenance",
            meta.name
        );
    }

    if let Some(expose) = &meta.expose {
        validate_expose_meta_for_package(&meta.name, expose)?;
        validate_attestation_expose_consistency(meta)?;
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
        if expose_uses_ebpf_net_policy(&meta.name, expose) {
            require_feature(meta, FEATURE_EBPF_NET_POLICY_V1)?;
        }
        if expose_uses_mac_profile(&meta.name, expose) {
            require_feature(meta, FEATURE_MAC_PROFILE_V1)?;
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

fn expose_uses_ebpf_net_policy(package_name: &str, expose: &ExposeMeta) -> bool {
    let unit = format!("aos-pkg-{package_name}-ebpf.service");
    expose.units.iter().any(|candidate| candidate == &unit)
}

fn expose_uses_mac_profile(package_name: &str, expose: &ExposeMeta) -> bool {
    let unit = format!("aos-pkg-{package_name}-mac.service");
    expose.units.iter().any(|candidate| candidate == &unit)
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

/// Validate an RFC-0001 exposure metadata block for a package.
///
/// # Errors
///
/// Returns an error when [`validate_expose_meta`] rejects the metadata or the
/// target is not the package-owned `aos-pkg-<package>.target` activation unit.
pub fn validate_expose_meta_for_package(package_name: &str, expose: &ExposeMeta) -> Result<()> {
    validate_package_name(package_name)?;
    validate_expose_meta(expose)?;
    let expected = format!("aos-pkg-{package_name}.target");
    if expose.target != expected {
        bail!(
            "expose target for package '{package_name}' must equal {expected}: {}",
            expose.target
        );
    }
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

/// Validates metadata for the second `config` package output.
///
/// Mirrors [`validate_expose_artifact_meta`]: the store path must be absolute
/// and Nix-style, and the NAR hash must be a recognized `sha256` digest. In
/// addition, every reference entry must be a bare store-path hash, and no
/// reference may name a `.drv` — the config output is pure data and must never
/// pull a derivation into its closure (publish lint, architecture.md §Stage-1).
///
/// # Errors
///
/// Returns an error when the store path is not an absolute Nix-style store path,
/// the NAR hash is missing or malformed, the NAR size is zero, or a reference is
/// not a bare store-path hash or names a derivation.
pub fn validate_config_output_meta(output: &ConfigOutputMeta) -> Result<()> {
    validate_absolute_path(&output.store_path, "config output store path")?;
    if store_path_hash_component(&output.store_path).is_none() {
        bail!(
            "config output store path is not a Nix-style store path: {}",
            output.store_path
        );
    }
    if !output.nar_hash.starts_with("sha256:") && !output.nar_hash.starts_with("sha256-") {
        bail!("config output '{}' has invalid NAR hash", output.store_path);
    }
    if output.nar_size == 0 {
        bail!(
            "config output '{}' must record a non-zero NAR size",
            output.store_path
        );
    }
    for reference in &output.references {
        if reference.contains(".drv") {
            bail!(
                "config output '{}' must not reference a derivation: {reference}",
                output.store_path
            );
        }
        if reference.contains('/')
            || reference.len() < 2
            || !reference.chars().all(|ch| ch.is_ascii_alphanumeric())
        {
            bail!(
                "config output '{}' reference is not a bare store-path hash: {reference}",
                output.store_path
            );
        }
    }
    Ok(())
}

/// Validates configuration-module metadata.
///
/// Checks the embedded [`ConfigOutputMeta`], the inclusive ABI band
/// (`min <= max`), the option paths, owned roots, and contributions for
/// well-formedness, and the capability tokens declared by the module.
///
/// # Errors
///
/// Returns an error when the config output is malformed, the ABI band is
/// inverted, an option path / root / capability token is empty or malformed, a
/// declared path is not package-private, beneath an owned root, or contained by
/// a contributed path, or a contribution targets a root the module also owns.
pub fn validate_config_module_meta(package_name: &str, module: &ConfigModuleMeta) -> Result<()> {
    validate_package_name(package_name).context("validating config-module package name")?;
    validate_config_output_meta(&module.config_output)?;
    if let Some(base_lib) = &module.evaluation_base_lib {
        validate_config_output_meta(base_lib)
            .context("validating config-module evaluation base lib")?;
    }

    if module.module_abi_compat.min > module.module_abi_compat.max {
        bail!(
            "config module module_abi_compat range is inverted: min {} > max {}",
            module.module_abi_compat.min,
            module.module_abi_compat.max
        );
    }

    let mut declared = std::collections::BTreeSet::new();
    for path in &module.declares {
        validate_option_path(path)?;
        if !declared.insert(path) {
            bail!("config module declares option path '{path}' more than once");
        }
    }
    if !module.declaration_schema.is_empty() {
        let schema_paths = module
            .declaration_schema
            .iter()
            .map(|declaration| declaration.path.as_str())
            .collect::<Vec<_>>();
        let declared_paths = module
            .declares
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        if schema_paths != declared_paths {
            bail!("config module declaration_schema paths must exactly match sorted declares");
        }
        for declaration in &module.declaration_schema {
            if declaration.type_signature.trim().is_empty() {
                bail!(
                    "config module declaration '{}' has an empty type signature",
                    declaration.path
                );
            }
        }
    }

    let mut required = std::collections::BTreeSet::new();
    for path in &module.requires {
        validate_option_path(path)?;
        if !required.insert(path) {
            bail!("config module requires option path '{path}' more than once");
        }
    }
    if module.requires.windows(2).any(|pair| pair[0] >= pair[1]) {
        bail!("config module requires paths must be sorted and deduplicated");
    }

    let mut owned = std::collections::BTreeSet::new();
    for owned_root in &module.owns_roots {
        validate_option_root("owned root", &owned_root.root)?;
        if !owned.insert(owned_root.root.as_str()) {
            bail!(
                "config module owns root '{}' more than once",
                owned_root.root
            );
        }
        let mut contributable = std::collections::BTreeSet::new();
        for path in &owned_root.contributable {
            validate_option_surface(path)?;
            if !contributable.insert(path) {
                bail!(
                    "owned root '{}' lists contributable sub-path '{path}' more than once",
                    owned_root.root
                );
            }
        }
    }

    let mut contributed = std::collections::BTreeMap::new();
    for contribution in &module.contributes {
        validate_option_root("contribution root", &contribution.root)?;
        if owned.contains(contribution.root.as_str()) {
            bail!(
                "config module both owns and contributes to root '{}'",
                contribution.root
            );
        }
        if contributed.contains_key(contribution.root.as_str()) {
            bail!(
                "config module contributes to root '{}' more than once",
                contribution.root
            );
        }
        if contribution.paths.is_empty() {
            bail!(
                "config module contribution to root '{}' lists no paths",
                contribution.root
            );
        }
        let mut contribution_paths = std::collections::BTreeSet::new();
        for path in &contribution.paths {
            validate_option_subpath(path)?;
            if !contribution_paths.insert(path.as_str()) {
                bail!(
                    "config module contribution to root '{}' lists path '{path}' more than once",
                    contribution.root
                );
            }
        }
        contributed.insert(contribution.root.as_str(), contribution_paths);
    }

    for path in declared {
        let path = path.as_str();
        let root = path.split_once('.').map_or(path, |(root, _)| root);
        let contribution_authorizes = contributed.get(root).is_some_and(|paths| {
            path.strip_prefix(root)
                .and_then(|suffix| suffix.strip_prefix('.'))
                .is_some_and(|relative| {
                    paths.iter().any(|allowed| {
                        relative == *allowed
                            || relative
                                .strip_prefix(*allowed)
                                .is_some_and(|suffix| suffix.starts_with('.'))
                    })
                })
        });
        if root != package_name && !owned.contains(root) && !contribution_authorizes {
            bail!(
                "config module declares option path '{path}' outside its owned roots or contributed paths"
            );
        }
    }

    let mut capabilities = std::collections::BTreeSet::new();
    for token in &module.provides_capabilities {
        validate_capability_token(token)?;
        if !capabilities.insert(token) {
            bail!("config module sets capability '{token}' more than once");
        }
    }

    Ok(())
}

/// Validate a dotted option path used as an inverted-index key.
fn validate_option_path(path: &str) -> Result<()> {
    if path.is_empty() {
        bail!("option path must not be empty");
    }
    if path.starts_with('.') || path.ends_with('.') || path.contains("..") {
        bail!("invalid option path '{path}': empty path segment");
    }
    if !path
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        bail!("invalid option path '{path}': use ASCII letters, digits, '.', '_', '-'");
    }
    Ok(())
}

/// Validate a single option-path root segment (no `.`).
fn validate_option_root(kind: &str, root: &str) -> Result<()> {
    if root.is_empty() || root.contains('.') {
        bail!("invalid {kind} '{root}': must be a single option-path segment");
    }
    if !root
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
    {
        bail!("invalid {kind} '{root}': use ASCII letters, digits, '_', '-'");
    }
    Ok(())
}

/// Validate an option sub-path relative to a shared root.
fn validate_option_subpath(path: &str) -> Result<()> {
    validate_option_path(path)
}

/// Validate an owner-declared contribution surface.
///
/// A wildcard is permitted only as an entire dotted segment. The surface is
/// interpreted as a subtree prefix after segment-aware wildcard matching.
fn validate_option_surface(path: &str) -> Result<()> {
    if path.is_empty() || path.starts_with('.') || path.ends_with('.') || path.contains("..") {
        bail!("invalid contribution surface '{path}': empty path segment");
    }
    for segment in path.split('.') {
        if segment == "*" {
            continue;
        }
        if segment.is_empty()
            || !segment
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
        {
            bail!(
                "invalid contribution surface '{path}': '*' must occupy a complete segment and other segments use ASCII letters, digits, '_', '-'"
            );
        }
    }
    Ok(())
}

/// Validate a capability token (a dotted option path).
fn validate_capability_token(token: &str) -> Result<()> {
    validate_option_path(token)
}

/// Validate signed BPF-LSM policy artifact metadata.
///
/// # Errors
///
/// Returns an error when names are malformed, artifact paths are not safe
/// package-relative paths, or program names are not BPF C identifiers.
pub fn validate_bpf_lsm_policy_meta(meta: &BpfLsmPolicyMeta) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for policy in &meta.policies {
        validate_policy_artifact_name(&policy.name)?;
        validate_relative_artifact_path("BPF-LSM policy", &policy.policy, ".json")?;
        validate_relative_artifact_path("BPF-LSM object", &policy.object, ".bpf.o")?;
        if !seen.insert(&policy.name) {
            bail!("duplicate BPF-LSM policy '{}'", policy.name);
        }
        if policy.programs.is_empty() {
            bail!(
                "BPF-LSM policy '{}' must name at least one program",
                policy.name
            );
        }
        let mut programs = std::collections::BTreeSet::new();
        for program in &policy.programs {
            validate_bpf_program_name(program)?;
            if !programs.insert(program) {
                bail!(
                    "BPF-LSM policy '{}' contains duplicate program '{}'",
                    policy.name,
                    program
                );
            }
        }
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

fn validate_attestation_expose_consistency(meta: &PackageMeta) -> Result<()> {
    let (Some(root_hash), Some(root_hash_sig), Some(expose)) = (
        meta.attestation.root_hash.as_deref(),
        meta.attestation.root_hash_sig.as_deref(),
        meta.expose.as_ref(),
    ) else {
        return Ok(());
    };
    let Some(attestation_root_hash) = canonical_sha256_digest(root_hash) else {
        return Ok(());
    };

    let mut saw_verity_image = false;
    for image in &expose.images {
        if image.root_hash.is_none() && image.root_hash_sig.is_none() {
            continue;
        }
        saw_verity_image = true;
        let image_root_hash = image.root_hash.as_deref().and_then(canonical_sha256_digest);
        if image_root_hash.as_deref() == Some(attestation_root_hash.as_str())
            && image.root_hash_sig.as_deref() == Some(root_hash_sig)
        {
            return Ok(());
        }
    }

    if saw_verity_image {
        bail!(
            "attestation root_hash/root_hash_sig for package '{}' must match a verity expose image",
            meta.name
        );
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

fn validate_policy_artifact_name(name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        bail!("invalid BPF-LSM policy name '{name}'");
    }
    Ok(())
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

fn validate_bpf_program_name(program: &str) -> Result<()> {
    let mut chars = program.chars();
    let Some(first) = chars.next() else {
        bail!("BPF program name must not be empty");
    };
    if !(first == '_' || first.is_ascii_alphabetic())
        || !chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
    {
        bail!("invalid BPF program name '{program}'");
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
    validate_tcp_ports("tcp-bind", &permissions.tcp_bind)?;
    validate_tcp_ports("tcp-connect", &permissions.tcp_connect)?;
    for device in &permissions.devices {
        validate_absolute_path(device, "device")?;
    }
    for host_path in &permissions.host_paths {
        validate_host_path_permission(host_path)?;
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

fn validate_tcp_ports(kind: &str, ports: &[u16]) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for port in ports {
        if *port == 0 {
            bail!("{kind} contains invalid TCP port 0");
        }
        if !seen.insert(port) {
            bail!("{kind} contains duplicate TCP port {port}");
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

fn validate_host_path_permission(host_path: &HostPathPermission) -> Result<()> {
    validate_absolute_path(&host_path.path, "host path")?;
    let path = Path::new(&host_path.path);
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        bail!("host path must not contain '..': {}", host_path.path);
    }
    if !host_path.path.chars().all(|ch| {
        ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '-' | '+' | '=' | '@')
    }) {
        bail!(
            "host path contains unsupported characters: {:?}",
            host_path.path
        );
    }
    if host_path.mode == HostPathMode::ReadOnly
        && LANDLOCK_WRITABLE_TEMP_PREFIXES
            .iter()
            .any(|prefix| path.starts_with(prefix))
    {
        bail!(
            "read-only host paths under /tmp or /var/tmp would be writable through the package Landlock temp grants: {}",
            host_path.path
        );
    }
    Ok(())
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
    validate_image_verity_entry(image)?;
    validate_image_uki_entries(image)?;
    Ok(())
}

fn validate_image_uki_entries(image: &SysrootImageEntry) -> Result<()> {
    if image.ukis.is_empty() {
        return Ok(());
    }
    let mut slots = std::collections::BTreeSet::new();
    let mut measurements = std::collections::BTreeSet::new();
    let mut signed_count = 0usize;
    for uki in &image.ukis {
        if !slots.insert(uki.slot) {
            bail!(
                "image '{}' repeats UKI slot {:?}",
                image.store_path,
                uki.slot
            );
        }
        validate_relative_artifact_path("slot UKI", &uki.path, ".efi")?;
        if uki.sb_signer_cert_sha256.is_some() != uki.expected_pcr11.is_some() {
            bail!(
                "image '{}' slot {:?} must record signer and PCR-11 together",
                image.store_path,
                uki.slot
            );
        }
        if let Some(cert) = &uki.sb_signer_cert_sha256 {
            signed_count += 1;
            if cert.len() != 64
                || !cert
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                bail!(
                    "image '{}' slot {:?} has invalid signer certificate digest",
                    image.store_path,
                    uki.slot
                );
            }
            if uki.sbat.is_empty() {
                bail!(
                    "image '{}' slot {:?} has a signer but no SBAT facts",
                    image.store_path,
                    uki.slot
                );
            }
        }
        if let Some(pcr11) = &uki.expected_pcr11 {
            if pcr11.len() != 64
                || !pcr11
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                bail!(
                    "image '{}' slot {:?} has invalid expected PCR-11",
                    image.store_path,
                    uki.slot
                );
            }
            measurements.insert(pcr11.as_str());
        }
    }
    if slots.len() != 2 || !slots.contains(&UkiSlot::A) || !slots.contains(&UkiSlot::B) {
        bail!(
            "image '{}' slot-specific UKI metadata must contain exactly slots a and b",
            image.store_path
        );
    }
    if signed_count != 0 && signed_count != 2 {
        bail!(
            "image '{}' mixes signed and unsigned slot UKIs",
            image.store_path
        );
    }
    if measurements.len() == 1 {
        bail!(
            "image '{}' records the same PCR-11 for both slots despite distinct measured command lines",
            image.store_path
        );
    }
    Ok(())
}

fn validate_image_verity_entry(image: &SysrootImageEntry) -> Result<()> {
    let verity_field_count = [
        image.root_image.as_ref(),
        image.root_verity.as_ref(),
        image.root_hash.as_ref(),
        image.root_hash_sig.as_ref(),
    ]
    .iter()
    .filter(|field| field.is_some())
    .count();
    let verity_format = matches!(image.format.as_str(), "ext4-verity" | "erofs-verity");

    if verity_field_count == 0 && !verity_format {
        return Ok(());
    }

    if !verity_format {
        bail!(
            "image '{}' declares dm-verity fields but format '{}' is not a verity root format",
            image.store_path,
            image.format
        );
    }
    if verity_field_count != 4 {
        bail!(
            "image '{}' must declare root_image, root_verity, root_hash, and root_hash_sig together",
            image.store_path
        );
    }

    let root_image = image
        .root_image
        .as_ref()
        .context("verity root_image missing after field-count validation")?;
    let root_verity = image
        .root_verity
        .as_ref()
        .context("verity root_verity missing after field-count validation")?;
    let root_hash = image
        .root_hash
        .as_ref()
        .context("verity root_hash missing after field-count validation")?;
    let root_hash_sig = image
        .root_hash_sig
        .as_ref()
        .context("verity root_hash_sig missing after field-count validation")?;

    validate_relative_artifact_member_path("verity root_image", root_image)?;
    validate_relative_artifact_path("verity root_verity", root_verity, ".verity")?;
    validate_sha256_digest("verity root_hash", root_hash)?;
    validate_relative_artifact_path("verity root_hash_sig", root_hash_sig, ".p7s")?;

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
    /// Configuration-only module metadata captured at install time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_module: Option<ConfigModuleMeta>,
    /// RFC-0001 permission manifest captured at install time.
    #[serde(default, skip_serializing_if = "PermissionsMeta::is_empty")]
    pub permissions: PermissionsMeta,
    /// Fleet BPF-LSM policy metadata captured at install time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bpf_lsm: Option<BpfLsmPolicyMeta>,
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

// `SbatEntry` (the UKI `.sbat` component/generation record) moved to the
// wasm-clean `aos-registry-surface` crate alongside the manifest `ImageEntry`
// that carries it (RFC-0004 Phase 5 / RFC-0006), so the parse path and the
// runtime `SysrootImageEntry` share one type. Re-exported here so
// `aos_package::types::SbatEntry` is unchanged.
// `SysrootImageEntry` (the pre-compiled image format entry within a sysroot
// package version) also moved to the wasm-clean `aos-registry-surface` crate
// (RFC-0004 Phase 5) so the parse path, the `ExposeMeta.images` schema, and the
// runtime image entry share one type. Re-exported here so
// `aos_package::types::SysrootImageEntry` is unchanged.
pub use aos_registry_surface::manifest::{SbatEntry, SysrootImageEntry, SysrootUkiEntry, UkiSlot};

/// The action required to re-activate a config-generation under a (possibly
/// changed) running image's `module_abi`.
///
/// Produced by [`ConfigGeneration::reactivation_plan`] and consumed by the
/// rollback path. The two arms are the two independent re-bind outcomes the
/// generations model permits: a free pointer switch within one ABI, or a
/// deterministic re-evaluation across an ABI boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReactivationPlan {
    /// Identical module ABI under any running image: re-activate the retained
    /// non-`@base` overlay with a pure `current → gen-N` pointer switch.
    /// No eval, no reboot.
    DirectReactivate,
    /// Different ABI: direct activation is refused; the config-gen must be
    /// re-evaluated from its retained inputs against the rolled-back image's
    /// evaluator before it can be committed.
    CrossAbiReEval(CrossAbiReEvalInputs),
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
    /// Exact ordered config-output module store paths the evaluator must read.
    pub config_module_paths: Vec<String>,
    /// Authenticated package identity corresponding to each ordered module.
    pub config_module_packages: Vec<String>,
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
// and derived configuration. Legacy bundled records are accepted only by the
// one-shot migration in `sysroot`; they are never a live authority.

/// A/B slot discriminant for an image generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageSlot {
    /// The `A` partition slot.
    A,
    /// The `B` partition slot.
    B,
}

/// One measured, signed image-generation: kernel + initrd + base lib +
/// evaluator + render-core, delivered as an A/B UKI and tracked in the TPM
/// PCR-11 policy recorded for an image generation.
///
/// It is **not** the authority of record — the ESP UKI set + the running
/// image's `/etc/os-release` are. The `/var` record is a userspace *index*
/// over what is installed in the ESP slots, used by APM to reason about A/B
/// state and retention. Persisted in `/var/lib/profiles/image/state.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageGeneration {
    /// Image-generation number (names the `image-gen-N/` directory).
    pub number: u32,
    /// A/B slot this UKI occupies.
    pub slot: ImageSlot,
    /// ESP-relative path of this generation's UKI, e.g.
    /// `EFI/Linux/aos-2026.06.1+3.efi` (the `+N` is the sd-boot boot-counting
    /// tries-suffix; see build-spec §5.2).
    pub uki_path: String,
    /// Store path of the sysroot toplevel this image was built from.
    pub toplevel: String,
    /// Sysroot package name (provenance, migrated from legacy state).
    pub package_name: String,
    /// Sysroot package version.
    pub version: String,
    /// Source registry the sysroot package was installed from.
    pub registry: String,
    /// Resolved kernel store path (kernel-change detection across A/B).
    #[serde(default)]
    pub kernel_path: Option<String>,
    /// Store path of the base-lib + evaluator closure carried *inside* this
    /// image. The ABI artifact and GC-root target for
    /// `image-gen-N/baselib/<module_abi>`.
    pub evaluator_ref: String,
    /// The monotonic shared-option-schema ABI this image's base lib exports.
    /// Mirrors `AOS_MODULE_ABI` in this image's `/etc/os-release`.
    pub module_abi: u32,
    /// SHA-256 of the base-lib closure, mirrored as `AOS_BASELIB_DIGEST` in
    /// `/etc/os-release` and measured into PCR-11 via the `.osrel` section.
    pub baselib_digest: String,
    /// dm-verity Merkle root over the erofs root that carries the base lib
    /// (F1), baked into the UKI `.cmdline` as `roothash=<hex>`. `None` for
    /// unsigned/VM (ext4) images.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_verity_roothash: Option<String>,
    /// ukify-predicted PCR-11 for this UKI (RFC-0006 phase 4). `None` when
    /// `systemd-measure` was unavailable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_pcr11: Option<String>,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
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
pub struct ImageGenerationState {
    /// The image-gen the live kernel booted (cross-checked against
    /// `/etc/os-release`, never trusted from the network).
    pub running: u32,
    /// The slot `bootctl set-default` currently points at — the *durable*
    /// next-boot selection (build-spec §5.2). Distinct from `running` during a
    /// staged-but-not-yet-rebooted upgrade or a pending rollback.
    pub default: u32,
    /// A staged image-gen whose UKI is in the ESP but has not been booted yet;
    /// cleared on its first successful boot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<u32>,
    /// All recorded image-generations, in creation order.
    #[serde(default)]
    pub generations: Vec<ImageGeneration>,
}

impl ImageGenerationState {
    /// Looks up the currently-running image-generation record, if recorded.
    pub fn running_generation(&self) -> Option<&ImageGeneration> {
        self.generations.iter().find(|g| g.number == self.running)
    }
}

/// One config-generation: the materialized `/etc` overlay produced by
/// evaluating the installed set's config modules + `host.nix` against a
/// specific image generation's base library.
///
/// This is the on-disk authority for `/var/lib/profiles/system/state.json`.
/// Every security-relevant binding is required: legacy bundled state must be
/// authenticated and migrated before this type will deserialize it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigGeneration {
    /// Config-generation number (names the `gen-N/` directory; the pointer
    /// `activate.sh.in` commits).
    pub number: u32,
    /// The [`ImageGeneration::number`] this config-gen was evaluated against.
    pub image_gen_parent: u32,
    /// The `module_abi` in effect at evaluation time.
    pub module_abi_pinned: u32,
    /// Content-address of the canonicalized manifest JSON (the *output*).
    pub manifest_hash: String,
    /// Store path of the config-module source closure (the eval *input*), or
    /// the canonical empty-closure hash for a host-only configuration.
    pub config_module_closure: String,
    /// Exact evaluator order of config-output module store paths.
    pub config_module_paths: Vec<String>,
    /// Authenticated package identity corresponding to each ordered module.
    pub config_module_packages: Vec<String>,
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
    /// Returns an error when the authenticated module/package vectors have
    /// different lengths. Both may be empty for a host-only configuration.
    pub fn reactivation_plan(&self, running_abi: u32) -> Result<ReactivationPlan> {
        if self.module_abi_pinned == running_abi {
            return Ok(ReactivationPlan::DirectReactivate);
        }
        if self.config_module_paths.len() != self.config_module_packages.len() {
            anyhow::bail!(
                "config-gen {} has {} retained modules but {} authenticated package identities",
                self.number,
                self.config_module_paths.len(),
                self.config_module_packages.len()
            );
        }
        Ok(ReactivationPlan::CrossAbiReEval(CrossAbiReEvalInputs {
            config_module_paths: self.config_module_paths.clone(),
            config_module_packages: self.config_module_packages.clone(),
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

[[caches]]
url = "https://cache.aos.dev"
priority = 1000

[registry.signing]
public_key = "aos-core:Ed25519:base64keyhere"
"#;
        let cfg: RegistryRootConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.registry.name, "aos-core");
        assert_eq!(cfg.registry.description.as_deref(), Some("core registry"));
        // Legacy `[[caches]]` array still parses via the backward-compat enum.
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
                expose: None,
                expose_artifact: None,
                config_module: None,
                permissions: Default::default(),
                bpf_lsm: None,
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
                FEATURE_ATTESTATION_V1.into(),
                FEATURE_EXPOSE_V1.into(),
                FEATURE_EXPOSE_ARTIFACT_V1.into(),
                FEATURE_PERMISSIONS_V1.into(),
                FEATURE_REQUIRES_V1.into(),
                FEATURE_NETWORK_POLICY_V1.into(),
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
                    ukis: Vec::new(),
                    root_image: None,
                    root_verity: None,
                    root_hash: None,
                    root_hash_sig: None,
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
            config_module: None,
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
            bpf_lsm: None,
            attestation: test_attestation(),
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
    fn permissions_reject_host_paths_with_unsupported_characters() {
        let permissions = PermissionsMeta {
            host_paths: vec![HostPathPermission {
                path: "/srv/my data".into(),
                mode: HostPathMode::Rw,
            }],
            ..PermissionsMeta::default()
        };

        let err = validate_permissions_meta("webapp", &permissions).unwrap_err();

        assert!(
            err.to_string()
                .contains("host path contains unsupported characters"),
            "{err:?}"
        );
    }

    #[test]
    fn permissions_reject_read_only_temp_host_paths() {
        let permissions = PermissionsMeta {
            host_paths: vec![HostPathPermission {
                path: "/tmp/package-cache".into(),
                mode: HostPathMode::ReadOnly,
            }],
            ..PermissionsMeta::default()
        };

        let err = validate_permissions_meta("webapp", &permissions).unwrap_err();

        assert!(
            err.to_string()
                .contains("read-only host paths under /tmp or /var/tmp"),
            "{err:?}"
        );
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
            requires_features: vec![FEATURE_PERMISSIONS_V1.into(), FEATURE_ATTESTATION_V1.into()],
            expose: None,
            expose_artifact: None,
            config_module: None,
            permissions: PermissionsMeta {
                network: Some(NetworkPermission::Host),
                ..PermissionsMeta::default()
            },
            bpf_lsm: None,
            attestation: test_attestation(),
        };

        let err =
            validate_supported_package_meta_with(&meta, PACKAGE_META_FORMAT, &[]).unwrap_err();
        assert!(err.to_string().contains(FEATURE_PERMISSIONS_V1));
    }

    #[test]
    fn package_meta_requires_network_policy_feature_gate() {
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
            requires_features: vec![FEATURE_ATTESTATION_V1.into(), FEATURE_PERMISSIONS_V1.into()],
            expose: None,
            expose_artifact: None,
            config_module: None,
            permissions: PermissionsMeta {
                tcp_connect: vec![443],
                ..PermissionsMeta::default()
            },
            bpf_lsm: None,
            attestation: test_attestation(),
        };

        let err = validate_supported_package_meta(&meta).unwrap_err();
        assert!(err.to_string().contains(FEATURE_NETWORK_POLICY_V1));

        meta.requires_features
            .push(FEATURE_NETWORK_POLICY_V1.into());
        validate_supported_package_meta(&meta).unwrap();
    }

    #[test]
    fn package_meta_requires_network_policy_feature_gate_for_expose() {
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
            requires_features: vec![FEATURE_ATTESTATION_V1.into(), FEATURE_EXPOSE_V1.into()],
            expose: Some(ExposeMeta {
                target: "aos-pkg-webapp.target".into(),
                units: vec!["webapp.service".into()],
                images: Vec::new(),
                requires: Vec::new(),
                config: Default::default(),
                provides: Vec::new(),
                uses: Vec::new(),
            }),
            expose_artifact: None,
            config_module: None,
            permissions: PermissionsMeta::default(),
            bpf_lsm: None,
            attestation: test_attestation(),
        };

        let err = validate_supported_package_meta(&meta).unwrap_err();
        assert!(err.to_string().contains(FEATURE_NETWORK_POLICY_V1));

        meta.requires_features
            .push(FEATURE_NETWORK_POLICY_V1.into());
        validate_supported_package_meta(&meta).unwrap();
    }

    #[test]
    fn package_meta_rejects_expose_target_bound_to_other_package() {
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
                FEATURE_ATTESTATION_V1.into(),
                FEATURE_EXPOSE_V1.into(),
                FEATURE_NETWORK_POLICY_V1.into(),
            ],
            expose: Some(ExposeMeta {
                target: "aos-pkg-other.target".into(),
                units: vec!["webapp.service".into()],
                images: Vec::new(),
                requires: Vec::new(),
                config: Default::default(),
                provides: Vec::new(),
                uses: Vec::new(),
            }),
            expose_artifact: None,
            config_module: None,
            permissions: PermissionsMeta::default(),
            bpf_lsm: None,
            attestation: test_attestation(),
        };

        let err = validate_supported_package_meta(&meta).unwrap_err();
        assert!(
            format!("{err:#}").contains("must equal aos-pkg-webapp.target"),
            "{err:#}"
        );
    }

    #[test]
    fn package_meta_rejects_invalid_network_policy_ports() {
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
            requires_features: vec![
                FEATURE_ATTESTATION_V1.into(),
                FEATURE_PERMISSIONS_V1.into(),
                FEATURE_NETWORK_POLICY_V1.into(),
            ],
            expose: None,
            expose_artifact: None,
            config_module: None,
            permissions: PermissionsMeta {
                tcp_bind: vec![0],
                ..PermissionsMeta::default()
            },
            bpf_lsm: None,
            attestation: test_attestation(),
        };

        let err = validate_supported_package_meta(&meta).unwrap_err();
        assert!(err.to_string().contains("invalid TCP port 0"));

        meta.permissions.tcp_bind = vec![8080, 8080];
        let err = validate_supported_package_meta(&meta).unwrap_err();
        assert!(err.to_string().contains("duplicate TCP port 8080"));
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
            requires_features: vec![FEATURE_ATTESTATION_V1.into(), FEATURE_PERMISSIONS_V1.into()],
            expose: None,
            expose_artifact: None,
            config_module: None,
            permissions: PermissionsMeta {
                network: Some(NetworkPermission::Host),
                confinement: Some(ConfinementMeta {
                    class: ConfinementClass::Sandboxed,
                    label: "sandboxed".into(),
                    holes: Vec::new(),
                }),
                ..PermissionsMeta::default()
            },
            bpf_lsm: None,
            attestation: test_attestation(),
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
            requires_features: vec![
                FEATURE_ATTESTATION_V1.into(),
                FEATURE_EXPOSE_V1.into(),
                FEATURE_CONFIG_V1.into(),
                FEATURE_NETWORK_POLICY_V1.into(),
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
                        units: vec!["webapp.service".into()],
                        reload: ConfigReloadPolicy::Reload,
                    }],
                    credentials: Vec::new(),
                },
                provides: Vec::new(),
                uses: Vec::new(),
            }),
            expose_artifact: None,
            config_module: None,
            permissions: PermissionsMeta::default(),
            bpf_lsm: None,
            attestation: test_attestation(),
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
                FEATURE_ATTESTATION_V1.into(),
                FEATURE_EXPOSE_V1.into(),
                FEATURE_NETWORK_POLICY_V1.into(),
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
            config_module: None,
            permissions: PermissionsMeta::default(),
            bpf_lsm: None,
            attestation: test_attestation(),
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
            requires_features: vec![
                FEATURE_ATTESTATION_V1.into(),
                FEATURE_EXPOSE_V1.into(),
                FEATURE_NETWORK_POLICY_V1.into(),
            ],
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
            config_module: None,
            permissions: PermissionsMeta::default(),
            bpf_lsm: None,
            attestation: test_attestation(),
        };

        let err = validate_supported_package_meta(&meta).unwrap_err();
        assert!(err.to_string().contains(FEATURE_CAPABILITY_ROUTES_V1));

        meta.requires_features
            .push(FEATURE_CAPABILITY_ROUTES_V1.into());
        validate_supported_package_meta(&meta).unwrap();
    }

    #[test]
    fn package_meta_requires_ebpf_network_policy_feature_gate() {
        let mut meta = PackageMeta {
            name: "webapp".into(),
            version: "1.0.0".into(),
            description: "Web application".into(),
            homepage: None,
            license: "MIT".into(),
            maintainer: "aos-team".into(),
            platform: "x86_64-linux".into(),
            store_path: "/var/lib/store/webhash-webapp-1.0.0".into(),
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
                FEATURE_ATTESTATION_V1.into(),
                FEATURE_EXPOSE_V1.into(),
                FEATURE_NETWORK_POLICY_V1.into(),
            ],
            expose: Some(ExposeMeta {
                target: "aos-pkg-webapp.target".into(),
                units: vec![
                    "webapp.service".into(),
                    "aos-pkg-webapp.slice".into(),
                    "aos-pkg-webapp-ebpf.service".into(),
                ],
                images: Vec::new(),
                requires: Vec::new(),
                config: Default::default(),
                provides: Vec::new(),
                uses: Vec::new(),
            }),
            expose_artifact: None,
            config_module: None,
            permissions: PermissionsMeta::default(),
            bpf_lsm: None,
            attestation: test_attestation(),
        };

        let err = validate_supported_package_meta(&meta).unwrap_err();
        assert!(err.to_string().contains(FEATURE_EBPF_NET_POLICY_V1));

        meta.requires_features
            .push(FEATURE_EBPF_NET_POLICY_V1.into());
        validate_supported_package_meta(&meta).unwrap();
    }

    fn bpf_lsm_package_meta(requires_features: Vec<&str>) -> PackageMeta {
        PackageMeta {
            name: "aos-ebpf-lsm-policy".into(),
            version: "0".into(),
            description: "Fleet BPF-LSM policy".into(),
            homepage: None,
            license: "MIT".into(),
            maintainer: "aos-team".into(),
            platform: "x86_64-linux".into(),
            store_path: "/var/lib/store/bpflsmhash12-aos-ebpf-lsm-policy-0".into(),
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
            expose: None,
            expose_artifact: None,
            config_module: None,
            permissions: PermissionsMeta::default(),
            bpf_lsm: Some(BpfLsmPolicyMeta {
                policies: vec![BpfLsmPolicyArtifactMeta {
                    name: "aos-lsm-task-audit".into(),
                    policy: "share/aos/ebpf-lsm/aos-task-audit.json".into(),
                    object: "lib/bpf/aos-ebpf-lsm-task-audit.bpf.o".into(),
                    programs: vec!["aos_lsm_file_mprotect".into()],
                }],
            }),
            attestation: AttestationMeta {
                root_digest: Some(
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .into(),
                ),
                root_hash: None,
                root_hash_sig: None,
                provenance: Some("attestation/aos-ebpf-lsm-policy.provenance.jsonl".into()),
                measurement: Some(
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .into(),
                ),
            },
        }
    }

    #[test]
    fn package_meta_requires_bpf_lsm_policy_feature_gate() {
        let mut meta =
            bpf_lsm_package_meta(vec![FEATURE_ATTESTATION_V1, FEATURE_EBPF_NET_POLICY_V1]);

        let err = validate_supported_package_meta(&meta).unwrap_err();
        assert!(err.to_string().contains(FEATURE_BPF_LSM_POLICY_V1));

        meta.requires_features = vec![
            FEATURE_ATTESTATION_V1.into(),
            FEATURE_BPF_LSM_POLICY_V1.into(),
        ];
        validate_supported_package_meta(&meta).unwrap();
    }

    #[test]
    fn package_meta_rejects_invalid_bpf_lsm_artifacts() {
        let mut meta =
            bpf_lsm_package_meta(vec![FEATURE_ATTESTATION_V1, FEATURE_BPF_LSM_POLICY_V1]);
        meta.bpf_lsm.as_mut().unwrap().policies[0].object = "../escape.bpf.o".into();

        let err = validate_supported_package_meta(&meta).unwrap_err();
        assert!(format!("{err:#}").contains("BPF-LSM object path"));
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
            expose: None,
            expose_artifact: None,
            config_module: None,
            permissions: PermissionsMeta::default(),
            bpf_lsm: None,
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
        let mut meta = attestation_package_meta(vec![FEATURE_PERMISSIONS_V1]);

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

    #[test]
    fn package_meta_accepts_attestation_matching_expose_verity_image() {
        let mut meta = attestation_package_meta(vec![
            FEATURE_ATTESTATION_V1,
            FEATURE_EXPOSE_V1,
            FEATURE_NETWORK_POLICY_V1,
        ]);
        meta.attestation.root_hash =
            Some("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into());
        meta.attestation.root_hash_sig = Some("root.roothash.p7s".into());
        meta.expose = Some(expose_meta_with_image(verity_image_entry()));

        validate_supported_package_meta(&meta).unwrap();
    }

    #[test]
    fn package_meta_rejects_attestation_that_diverges_from_expose_verity_image() {
        let mut meta = attestation_package_meta(vec![
            FEATURE_ATTESTATION_V1,
            FEATURE_EXPOSE_V1,
            FEATURE_NETWORK_POLICY_V1,
        ]);
        meta.attestation.root_hash_sig = Some("root.roothash.p7s".into());
        meta.expose = Some(expose_meta_with_image(verity_image_entry()));
        meta.attestation.root_hash =
            Some("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into());
        meta.attestation.root_digest =
            Some("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into());

        let err = validate_supported_package_meta(&meta).unwrap_err();
        assert!(format!("{err:#}").contains("must match a verity expose image"));
    }

    fn expose_meta_with_image(image: SysrootImageEntry) -> ExposeMeta {
        ExposeMeta {
            target: "aos-pkg-verity-app.target".into(),
            units: vec!["verity-app.service".into()],
            images: vec![image],
            requires: Vec::new(),
            config: Default::default(),
            provides: Vec::new(),
            uses: Vec::new(),
        }
    }

    fn verity_image_entry() -> SysrootImageEntry {
        SysrootImageEntry {
            format: "ext4-verity".into(),
            store_path: "/var/lib/store/verityimage-verity-app-root".into(),
            nar_hash: "sha256:root".into(),
            nar_size: 2048,
            sb_signer_cert_sha256: None,
            sbat: Vec::new(),
            expected_pcr11: None,
            ukis: Vec::new(),
            root_image: Some("root.img".into()),
            root_verity: Some("root.verity".into()),
            root_hash: Some(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            ),
            root_hash_sig: Some("root.roothash.p7s".into()),
        }
    }

    fn slot_uki(slot: UkiSlot, path: &str, pcr_byte: char) -> SysrootUkiEntry {
        SysrootUkiEntry {
            slot,
            path: path.into(),
            sb_signer_cert_sha256: Some("a".repeat(64)),
            sbat: vec![SbatEntry {
                component: "aos".into(),
                generation: 1,
            }],
            expected_pcr11: Some(pcr_byte.to_string().repeat(64)),
        }
    }

    #[test]
    fn ab_uki_metadata_requires_both_distinct_slot_measurements() {
        let mut image = verity_image_entry();
        image.ukis = vec![
            slot_uki(UkiSlot::A, "uki-a.efi", '1'),
            slot_uki(UkiSlot::B, "uki-b.efi", '2'),
        ];
        validate_image_uki_entries(&image).unwrap();

        image.ukis[1].expected_pcr11 = image.ukis[0].expected_pcr11.clone();
        let error = validate_image_uki_entries(&image).unwrap_err();
        assert!(error.to_string().contains("same PCR-11"));

        image.ukis.pop();
        let error = validate_image_uki_entries(&image).unwrap_err();
        assert!(error.to_string().contains("exactly slots a and b"));
    }

    #[test]
    fn expose_meta_accepts_complete_verity_image() {
        let expose = expose_meta_with_image(verity_image_entry());

        validate_expose_meta(&expose).unwrap();
    }

    #[test]
    fn expose_meta_rejects_partial_verity_image() {
        let mut image = verity_image_entry();
        image.root_hash_sig = None;
        let expose = expose_meta_with_image(image);

        let err = validate_expose_meta(&expose).unwrap_err();
        assert!(format!("{err:#}").contains("must declare root_image"));
    }

    #[test]
    fn expose_meta_rejects_verity_format_without_tuple() {
        let mut image = verity_image_entry();
        image.root_image = None;
        image.root_verity = None;
        image.root_hash = None;
        image.root_hash_sig = None;
        let expose = expose_meta_with_image(image);

        let err = validate_expose_meta(&expose).unwrap_err();
        assert!(format!("{err:#}").contains("must declare root_image"));
    }

    #[test]
    fn expose_meta_rejects_verity_fields_on_plain_image_format() {
        let mut image = verity_image_entry();
        image.format = "dir".into();
        let expose = expose_meta_with_image(image);

        let err = validate_expose_meta(&expose).unwrap_err();
        assert!(format!("{err:#}").contains("is not a verity root format"));
    }

    #[test]
    fn expose_meta_rejects_unsafe_verity_member_path() {
        let mut image = verity_image_entry();
        image.root_image = Some("../root.img".into());
        let expose = expose_meta_with_image(image);

        let err = validate_expose_meta(&expose).unwrap_err();
        assert!(format!("{err:#}").contains("verity root_image path"));
    }

    #[test]
    fn expose_meta_rejects_unsupported_verity_member_path_characters() {
        let mut image = verity_image_entry();
        image.root_image = Some("root image.img".into());
        let expose = expose_meta_with_image(image);

        let err = validate_expose_meta(&expose).unwrap_err();
        assert!(format!("{err:#}").contains("unsupported characters"));
    }

    #[test]
    fn package_meta_requires_mac_profile_feature_gate() {
        let mut meta = PackageMeta {
            name: "webapp".into(),
            version: "1.0.0".into(),
            description: "Web application".into(),
            homepage: None,
            license: "MIT".into(),
            maintainer: "aos-team".into(),
            platform: "x86_64-linux".into(),
            store_path: "/var/lib/store/webhash-webapp-1.0.0".into(),
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
                FEATURE_ATTESTATION_V1.into(),
                FEATURE_EXPOSE_V1.into(),
                FEATURE_NETWORK_POLICY_V1.into(),
            ],
            expose: Some(ExposeMeta {
                target: "aos-pkg-webapp.target".into(),
                units: vec![
                    "webapp.service".into(),
                    "aos-pkg-webapp.slice".into(),
                    "aos-pkg-webapp-mac.service".into(),
                ],
                images: Vec::new(),
                requires: Vec::new(),
                config: Default::default(),
                provides: Vec::new(),
                uses: Vec::new(),
            }),
            expose_artifact: None,
            config_module: None,
            permissions: PermissionsMeta::default(),
            bpf_lsm: None,
            attestation: test_attestation(),
        };

        let err = validate_supported_package_meta(&meta).unwrap_err();
        assert!(err.to_string().contains(FEATURE_MAC_PROFILE_V1));

        meta.requires_features.push(FEATURE_MAC_PROFILE_V1.into());
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
                FEATURE_ATTESTATION_V1.into(),
                FEATURE_EXPOSE_V1.into(),
                FEATURE_NETWORK_POLICY_V1.into(),
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
            config_module: None,
            permissions: PermissionsMeta::default(),
            bpf_lsm: None,
            attestation: test_attestation(),
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

    // ----------------------------------------------------------------------
    // Configuration-module metadata.
    // ----------------------------------------------------------------------

    fn sample_config_module() -> ConfigModuleMeta {
        ConfigModuleMeta {
            config_output: ConfigOutputMeta {
                store_path: "/nix/store/0000000000000000000000000000000a-firewall-config"
                    .to_string(),
                nar_hash: "sha256:deadbeef".to_string(),
                nar_size: 4096,
                references: vec!["0000000000000000000000000000000b".to_string()],
            },
            evaluation_base_lib: None,
            module_abi_compat: ModuleAbiCompat { min: 1, max: 2 },
            declares: vec![
                "firewall.allowedTCPPorts".to_string(),
                "firewall.enable".to_string(),
            ],
            declaration_schema: vec![],
            requires: vec![],
            owns_roots: vec![OwnedRoot {
                root: "firewall".to_string(),
                interface_abi: 1,
                contributable: vec!["allowedTCPPorts".to_string()],
            }],
            contributes: vec![RootContribution {
                root: "nginx".to_string(),
                interface_abi: 1,
                paths: vec!["virtualHosts".to_string()],
            }],
            provides_capabilities: vec!["system.capabilities.dns-resolver".to_string()],
        }
    }

    #[test]
    fn config_module_meta_toml_round_trip() {
        let module = sample_config_module();
        let serialized = toml::to_string(&module).expect("serialize");
        let parsed: ConfigModuleMeta = toml::from_str(&serialized).expect("deserialize");
        assert_eq!(parsed, module);
    }

    #[test]
    fn config_module_declares_only_owned_or_contributed_roots() {
        let mut module = sample_config_module();
        module.declares.push("foreign.enable".to_string());
        let error =
            validate_config_module_meta("firewall", &module).expect_err("foreign declaration");
        assert!(
            error
                .to_string()
                .contains("outside its owned roots or contributed paths"),
            "{error}"
        );
    }

    #[test]
    fn config_module_declaration_must_be_contained_by_contributed_path() {
        let mut module = sample_config_module();
        module.declares.push("nginx.enable".to_string());
        let error = validate_config_module_meta("firewall", &module)
            .expect_err("sibling path outside contribution");
        assert!(
            error
                .to_string()
                .contains("outside its owned roots or contributed paths"),
            "{error}"
        );

        module.declares.pop();
        module
            .declares
            .push("nginx.virtualHosts.demo.enable".to_string());
        validate_config_module_meta("firewall", &module).expect("descendant of contributed path");
    }

    #[test]
    fn owned_root_surface_wildcard_must_fill_a_complete_segment() {
        let mut module = sample_config_module();
        module.owns_roots[0].contributable = vec!["interfaces.*.addresses".to_string()];
        validate_config_module_meta("firewall", &module).expect("whole-segment wildcard");

        module.owns_roots[0].contributable = vec!["interfaces.eth*".to_string()];
        let error = validate_config_module_meta("firewall", &module)
            .expect_err("partial-segment wildcard must be rejected");
        assert!(error.to_string().contains("complete segment"), "{error}");
    }

    #[test]
    fn config_module_private_root_needs_no_owned_root_record() {
        let mut module = sample_config_module();
        module.owns_roots.clear();
        validate_config_module_meta("firewall", &module).expect("implicit package-private root");
    }

    #[test]
    fn config_module_requires_paths_are_sorted_unique_and_well_formed() {
        let mut module = sample_config_module();
        module.requires = vec!["nginx.enable".into(), "firewall.enable".into()];
        let error = validate_config_module_meta("firewall", &module)
            .expect_err("unsorted conservative requirements");
        assert!(
            error.to_string().contains("sorted and deduplicated"),
            "{error}"
        );

        module.requires = vec!["nginx..enable".into()];
        let error = validate_config_module_meta("firewall", &module)
            .expect_err("malformed conservative requirement");
        assert!(error.to_string().contains("option path"), "{error}");
    }

    #[test]
    fn config_module_meta_inside_package_round_trips_and_gates() {
        // A package carrying config_module must declare the feature and have
        // attestation provenance, else validation fails.
        let toml_str = r#"
name = "firewall"
version = "1.4.0"
description = "host firewall"
license = "MIT"
maintainer = "aos"
platform = "x86_64-linux"
store_path = "/nix/store/0000000000000000000000000000000c-firewall-1.4.0"
nar_hash = "sha256:aa"
nar_size = 10
references = []
source_drv = "/nix/store/0000000000000000000000000000000d-firewall.drv"
source_nar_hash = "sha256:bb"
closure_size = 10
requires-features = ["config-module-v1", "attestation-v1"]

[config_module.config_output]
store_path = "/nix/store/0000000000000000000000000000000a-firewall-config"
nar_hash = "sha256:cc"
nar_size = 2048

[config_module.module_abi_compat]
min = 1
max = 2

[config_module]
declares = ["firewall.allowedTCPPorts"]
provides_capabilities = []

[[config_module.owns_roots]]
root = "firewall"
interface_abi = 1
contributable = ["allowedTCPPorts"]

[attestation]
provenance = "provenance/firewall.jsonl"
"#;
        let meta: PackageMeta = toml::from_str(toml_str).expect("parse package meta");
        assert!(meta.config_module.is_some());
        validate_supported_package_meta(&meta).expect("valid config-module package");
    }

    #[test]
    fn config_module_without_feature_is_rejected() {
        let mut meta = sample_package_meta();
        meta.config_module = Some(sample_config_module());
        // Missing requires-features ⇒ feature gate refuses.
        let err = validate_supported_package_meta(&meta).expect_err("must refuse");
        assert!(err.to_string().contains("config-module-v1"), "{err}");
    }

    #[test]
    fn config_module_without_provenance_is_rejected() {
        let mut meta = sample_package_meta();
        meta.requires_features = vec![FEATURE_CONFIG_MODULE_V1.to_string()];
        meta.config_module = Some(sample_config_module());
        let err = validate_supported_package_meta(&meta).expect_err("must refuse");
        assert!(
            err.to_string().contains("without attestation provenance"),
            "{err}"
        );
    }

    #[test]
    fn config_output_rejects_drv_reference() {
        let mut output = sample_config_module().config_output;
        output.references = vec!["abc.drv".to_string()];
        let err = validate_config_output_meta(&output).expect_err("must refuse .drv ref");
        assert!(
            err.to_string().contains("must not reference a derivation"),
            "{err}"
        );
    }

    #[test]
    fn config_module_rejects_inverted_abi_band() {
        let mut module = sample_config_module();
        module.module_abi_compat = ModuleAbiCompat { min: 3, max: 1 };
        let err = validate_config_module_meta("firewall", &module).expect_err("inverted band");
        assert!(err.to_string().contains("inverted"), "{err}");
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
            config_module_closure: "/nix/store/src-cfg".into(),
            config_module_paths: vec!["/nix/store/src-cfg".into()],
            config_module_packages: vec!["server".into()],
            host_nix_ref: "/nix/store/hn-host.nix".into(),
            host_nix_commit: Some("deadbeef".into()),
            facts_hash: "sha256:facts".into(),
            facts_ref: "/nix/store/fa-facts.json".into(),
            base_lib_ref: "/nix/store/bl-base-lib".into(),
            evaluator_ref: "/nix/store/ev-evaluator".into(),
        };
        let json = serde_json::to_string(&g).unwrap();
        assert!(json.contains("module_abi_pinned"));
        let parsed: ConfigGeneration = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.module_abi_pinned, 2);
        assert_eq!(parsed.host_nix_ref, "/nix/store/hn-host.nix");
    }

    /// The image-gen axis state round-trips, including the A/B slot, the durable
    /// `default`/`pending` boot selection, and the verity/ABI fields.
    #[test]
    fn image_generation_state_round_trip() {
        let state = ImageGenerationState {
            running: 1,
            default: 1,
            pending: Some(2),
            generations: vec![
                ImageGeneration {
                    number: 1,
                    slot: ImageSlot::A,
                    uki_path: "EFI/Linux/aos-2026.06.1+3.efi".into(),
                    toplevel: "/nix/store/top1-server".into(),
                    package_name: "server".into(),
                    version: "2026.06.1".into(),
                    registry: "core".into(),
                    kernel_path: Some("/nix/store/k1-linux".into()),
                    evaluator_ref: "/nix/store/bl1-aos-base-lib".into(),
                    module_abi: 1,
                    baselib_digest: "sha256:aa".into(),
                    root_verity_roothash: Some("deadbeef".into()),
                    expected_pcr11: None,
                    created_at: "2026-06-01T00:00:00Z".into(),
                },
                ImageGeneration {
                    number: 2,
                    slot: ImageSlot::B,
                    uki_path: "EFI/Linux/aos-2026.06.2+3.efi".into(),
                    toplevel: "/nix/store/top2-server".into(),
                    package_name: "server".into(),
                    version: "2026.06.2".into(),
                    registry: "core".into(),
                    kernel_path: Some("/nix/store/k2-linux".into()),
                    evaluator_ref: "/nix/store/bl2-aos-base-lib".into(),
                    module_abi: 2,
                    baselib_digest: "sha256:bb".into(),
                    root_verity_roothash: None,
                    expected_pcr11: None,
                    created_at: "2026-06-02T00:00:00Z".into(),
                },
            ],
        };
        let json = serde_json::to_string(&state).unwrap();
        let parsed: ImageGenerationState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.running, 1);
        assert_eq!(parsed.pending, Some(2));
        let running = parsed.running_generation().unwrap();
        assert_eq!(running.module_abi, 1);
        assert!(running.admits_pin(1));
        assert!(!running.admits_pin(2));
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
            expose: None,
            expose_artifact: None,
            config_module: None,
            permissions: PermissionsMeta::default(),
            bpf_lsm: None,
            attestation: AttestationMeta::default(),
        }
    }
}
