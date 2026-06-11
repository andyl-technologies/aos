//! On-disk data contracts and well-known paths for `apm`/`apr`.
//!
//! This module defines the serde schemas that the package manager reads and
//! writes, grouped by where they live on disk:
//!
//! - **Registry metadata** — [`PackageMeta`] (a package version entry from a
//!   registry's package TOML), [`ClosureMeta`] (the `closures/{hash}`
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
}

// ---------------------------------------------------------------------------
// Closure metadata — parsed from `closures/{hash}` adjacency list files
// ---------------------------------------------------------------------------

/// Precomputed transitive closure for a store path.
///
/// Loaded from the registry's `closures/{hash}` file.  The file format is an
/// adjacency list: one line per store path in the closure, with the first
/// token being the node and remaining whitespace-separated tokens being its
/// direct dependencies.  The first line is always the root.
///
/// ```text
/// h7j3k8l2m9n4 r4q1m2kp8v3x xr5is7by89v3q
/// r4q1m2kp8v3x
/// xr5is7by89v3q q8mn2pv73w0x
/// q8mn2pv73w0x
/// ```
#[derive(Debug, Clone)]
pub struct ClosureMeta {
    /// The store path hash this closure belongs to (filename).
    pub root: String,
    /// All store path hashes in the transitive closure (self-inclusive),
    /// in the order they appear in the file.
    pub members: Vec<String>,
    /// Adjacency list: node → direct dependencies.
    pub deps: std::collections::HashMap<String, Vec<String>>,
}

impl ClosureMeta {
    /// Parse a closure file from its text content.
    ///
    /// Each non-empty line is `node [dep1 dep2 ...]`.  Blank lines and
    /// lines starting with `#` are skipped.
    pub fn parse(root_hash: &str, content: &str) -> Self {
        let mut members = Vec::new();
        let mut deps = std::collections::HashMap::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut tokens = line.split_whitespace();
            if let Some(node) = tokens.next() {
                let node_deps: Vec<String> = tokens.map(|s| s.to_string()).collect();
                members.push(node.to_string());
                deps.insert(node.to_string(), node_deps);
            }
        }

        Self {
            root: root_hash.to_string(),
            members,
            deps,
        }
    }

    /// Serialize the closure to the adjacency list text format.
    pub fn serialize(&self) -> String {
        let mut out = String::new();
        for member in &self.members {
            out.push_str(member);
            if let Some(member_deps) = self.deps.get(member) {
                for dep in member_deps {
                    out.push(' ');
                    out.push_str(dep);
                }
            }
            out.push('\n');
        }
        out
    }

    /// Get the direct dependencies of a node in this closure.
    pub fn direct_deps(&self, hash: &str) -> &[String] {
        self.deps.get(hash).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Check whether a store path hash is a member of this closure.
    pub fn contains(&self, hash: &str) -> bool {
        self.deps.contains_key(hash)
    }
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
    /// System-wide profile at `/var/lib/profiles/system/` (requires root).
    System,
}

impl ProfileScope {
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
    pub fn config_dir(&self) -> PathBuf {
        match self {
            ProfileScope::User => xdg_config_home().join("apm"),
            ProfileScope::System => apm_system_config_dir().to_path_buf(),
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
    /// The first directory is also where new pins are written; the system
    /// `trusted-keys.d` is shared by both scopes so user installs can trust
    /// system-provisioned keys.
    pub fn trusted_keys_dirs(&self) -> Vec<PathBuf> {
        match self {
            ProfileScope::User => vec![
                xdg_config_home().join("apm/trusted-keys.d"),
                apm_system_config_dir().join("trusted-keys.d"),
            ],
            ProfileScope::System => vec![
                apm_system_config_dir().join("trusted-keys.d"),
                apm_state_dir().join("trusted-keys.d"),
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
    pub name: String,
    pub url: String,
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

/// A pre-compiled image format entry within a sysroot package version.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
"#;
        let conf: ApmConfFile = toml::from_str(toml_str).unwrap();
        assert!(conf.settings.assume_yes);
        assert_eq!(conf.settings.parallel_downloads, 8);
        assert!(conf.settings.auto_autoremove);
        assert!(!conf.settings.auto_gc);
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
        assert_eq!(rf.registry.name, "aos-core");
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
}
