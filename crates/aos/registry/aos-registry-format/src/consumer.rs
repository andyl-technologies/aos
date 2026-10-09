//! Portable registry package records, source configuration, and validation.

use std::collections::BTreeMap;
use std::path::Path;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Current registry package metadata format understood by this crate.
pub const PACKAGE_META_FORMAT: u32 = 1;

/// Registry feature flag for RFC-0001 package attestation metadata.
pub const FEATURE_ATTESTATION_V1: &str = "attestation-v1";

/// Registry feature flag for opaque provider-owned image artifact contracts.
pub const FEATURE_IMAGE_ARTIFACT_CONTRACT_V1: &str = "image-artifact-contract-v1";

const SUPPORTED_PACKAGE_FEATURES: &[&str] = &[
    FEATURE_ATTESTATION_V1,
    FEATURE_NATIVE_PACKAGE_MODULES_V1,
    FEATURE_IMAGE_ARTIFACT_CONTRACT_V1,
];

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
    crate::channel::validate_channel_name(name)
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
// `aos-registry-format` crate (RFC-0004 Phase 5) so the registry hub's indexer
// and the Cloudflare Worker share the exact rules without pulling `aos-package`.
// Re-exported here so `aos_package_manager::types::{validate_package_name,
// package_name_bucket}` paths are unchanged.
pub use crate::manifest::{package_name_bucket, validate_package_name};

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

/// A package version entry for a specific platform, as found in a registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Authenticated available named outputs and their output-specific evidence.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub named_outputs:
        std::collections::BTreeMap<String, crate::manifest::OutputMeta>,
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
    /// Authenticated native package deployment envelope directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment: Option<NativeArtifactMeta>,
    /// Retains the generated compatibility requirement for this package release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_requirement: Option<String>,
    /// Host operating system release compatibility requirement.
    #[serde(rename = "osVersion", default, skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    /// Exact and ranged native module dependencies projected from that same document.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub module_dependencies: Vec<crate::native_dependencies::ModuleDependency>,
    /// Authenticated module-generated reference directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module_documentation: Option<NativeArtifactMeta>,
    /// Authenticated native package qualification companion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qualification: Option<NativeArtifactMeta>,
    /// Runtime integrity, attestation, and provenance facts for this package.
    #[serde(default, skip_serializing_if = "AttestationMeta::is_empty")]
    pub attestation: AttestationMeta,
}

// Shared package metadata schemas live in the wasm-clean registry-surface
// crate so the registry hub and package client consume one contract.
pub use crate::manifest::AttestationMeta;

pub use crate::manifest::{FEATURE_NATIVE_PACKAGE_MODULES_V1, NativeArtifactMeta};

/// Returns the top-level root segment of a dotted option path.
///
/// `"firewall.allowedTCPPorts"` → `"firewall"`; a path with no `.` is its own
/// root.
pub fn option_path_root(path: &str) -> &str {
    path.split('.').next().unwrap_or(path)
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
    let supported_features = supported_package_features()?;
    let supported_features = supported_features
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();

    validate_supported_package_meta_with(meta, PACKAGE_META_FORMAT, &supported_features)
}

/// Returns the package features understood by the current registry reader.
///
/// # Errors
///
/// Returns an error if supported feature discovery fails.
pub fn supported_package_features() -> Result<Vec<String>> {
    Ok(SUPPORTED_PACKAGE_FEATURES
        .iter()
        .map(|feature| (*feature).to_owned())
        .collect())
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
    crate::native_dependencies::check_version_requirement(
        &meta.version,
        meta.version_requirement.as_deref(),
    )?;
    crate::native_dependencies::check_resolution_metadata(
        meta.os_version.as_deref(),
        &meta.module_dependencies,
    )?;
    if (meta.version_requirement.is_some()
        || meta.os_version.is_some()
        || !meta.module_dependencies.is_empty())
        && meta.deployment.is_none()
    {
        bail!("native resolution catalog lacks an authenticated deployment document");
    }
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
    let native_feature = meta
        .requires_features
        .iter()
        .any(|feature| feature == FEATURE_NATIVE_PACKAGE_MODULES_V1);
    if native_feature || meta.module_documentation.is_some() || meta.qualification.is_some() {
        if meta.deployment.is_none() {
            bail!("native package metadata is missing its deployment envelope");
        }
    }
    for artifact in [
        &meta.deployment,
        &meta.module_documentation,
        &meta.qualification,
    ]
    .into_iter()
    .flatten()
    {
        require_feature(meta, FEATURE_NATIVE_PACKAGE_MODULES_V1)?;
        artifact.validate()?;
    }
    if !meta.images.is_empty() {
        require_feature(meta, FEATURE_IMAGE_ARTIFACT_CONTRACT_V1)?;
    }
    for image in &meta.images {
        validate_image_entry(image, &meta.version, &meta.platform)
            .with_context(|| format!("invalid sysroot image metadata for '{}'", meta.name))?;
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

/// Mutable state appended to a registry config file by `apm update`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegistryState {
    /// Commit hash the local clone was last synced to.
    #[serde(default)]
    pub last_commit: Option<String>,
    /// Verified channel selected explicitly or discovered from symbolic HEAD.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_channel: Option<String>,
    /// Default channel retained across HEAD changes while tracking implicitly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_channel: Option<String>,
    /// Last verified trust-roster commit, independent of the selected release.
    #[serde(default)]
    pub last_roster_commit: Option<String>,
    /// Highest release verified by this host; older channel targets are refused.
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
    /// No tracking field set -- discover and verify the default release channel.
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
    /// `url` is an orphaned delta the loader drops (see the native configuration loader).
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

pub use crate::manifest::{
    CacheEntry, CachesConfig, RegistryRootConfig, RegistryRootMeta,
};

// ---------------------------------------------------------------------------
// Sysroot image entry — a pre-compiled image attached to a sysroot package
// ---------------------------------------------------------------------------

// `SysrootImageEntry` and its provider-neutral artifact locator live in the
// wasm-clean registry surface so native and indexed consumers share one schema.
pub use crate::manifest::{
    ImageArtifactContractDocumentReference, ImageArtifactContractReference, ImageCompression,
    ImageDelivery, ImageStoreReference, ImageTarget, SysrootImageEntry,
};
