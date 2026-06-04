use std::path::PathBuf;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Well-known paths
// ---------------------------------------------------------------------------

/// Base directory for per-user and system profiles.
const PROFILES_BASE: &str = "/var/lib/profiles";

/// Base directory for system-wide APM state.
const APM_STATE_DIR: &str = "/var/lib/apm";

/// System-wide APM configuration directory.
const APM_SYSTEM_CONFIG_DIR: &str = "/etc/apm";

/// Resolve the current user's home directory.
///
/// Tries `$HOME` first, then falls back to `/etc/passwd` via
/// `std::env::home_dir` (deprecated but functional for this purpose).
/// Panics only if no home directory can be determined at all.
fn resolve_home() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home);
        }
    }
    // Last-resort fallback: construct from /tmp with a warning.  This is
    // better than silently scattering state into /tmp directly.
    eprintln!(
        "warning: $HOME is not set; falling back to /tmp for user-scoped APM paths"
    );
    PathBuf::from("/tmp")
}

// ---------------------------------------------------------------------------
// Package metadata — a package as described in a registry TOML file
// ---------------------------------------------------------------------------

/// A package version entry for a specific platform, as found in a registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMeta {
    pub name: String,
    pub version: String,
    pub description: String,
    #[serde(default)]
    pub homepage: Option<String>,
    pub license: String,
    pub maintainer: String,
    pub platform: String,
    pub store_path: String,
    /// Hash of the uncompressed NAR: `"sha256:..."`.
    pub nar_hash: String,
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
                let node_deps: Vec<String> =
                    tokens.map(|s| s.to_string()).collect();
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
        self.deps
            .get(hash)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
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
    pub store_path: String,
    pub pushed_at: i64,
    pub pushed_by: String,
    #[serde(default)]
    pub expires_at: Option<i64>,
    pub is_root: bool,
    pub last_accessed: i64,
    pub access_count: u64,
    #[serde(default)]
    pub apm: Option<ApmMeta>,
}

/// APM-specific metadata extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApmMeta {
    pub name: String,
    pub version: String,
    /// `true` if the user explicitly installed this package.
    pub explicit: bool,
    /// Registry this package was installed from.
    pub registry: String,
    /// ISO 8601 timestamp of installation.
    pub installed_at: String,
    /// Prevent this package from being upgraded.
    pub held: bool,
}

// ---------------------------------------------------------------------------
// Registry configuration — from `registries.d/*.toml`
// ---------------------------------------------------------------------------

/// Parsed configuration for a single registry source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryConfig {
    pub name: String,
    pub url: String,
    #[serde(default = "default_priority")]
    pub priority: u32,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Exact commit hash to pin to (mutually exclusive with branch/tag/version).
    #[serde(default)]
    pub commit: Option<String>,
    /// Branch name to track HEAD of (mutually exclusive with commit/tag/version).
    #[serde(default)]
    pub branch: Option<String>,
    /// Exact tag name to pin to (mutually exclusive with commit/branch/version).
    #[serde(default)]
    pub tag: Option<String>,
    /// Semver version constraint on tags (mutually exclusive with commit/branch/tag).
    #[serde(default)]
    pub version: Option<String>,
    /// Legacy alias: old `pin` field is treated as `tag` for backward compatibility.
    #[serde(default)]
    pub pin: Option<String>,
    #[serde(default)]
    pub signing: Option<SigningConfig>,
}

fn default_priority() -> u32 {
    500
}
fn default_true() -> bool {
    true
}

/// Signing configuration embedded in a registry config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningConfig {
    #[serde(default = "default_true")]
    pub required: bool,
    /// Key in `"name:Ed25519:base64key"` format.
    pub public_key: String,
}

/// Mutable state appended to a registry config file by `apm update`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegistryState {
    #[serde(default)]
    pub last_commit: Option<String>,
    #[serde(default)]
    pub last_creation_token: Option<u64>,
    #[serde(default)]
    pub last_update: Option<String>,
}

// ---------------------------------------------------------------------------
// Transport detection
// ---------------------------------------------------------------------------

/// Transport type derived from the registry URL scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Default: `https://` or `http://` — uses HTTP bundle distribution.
    HttpBundle,
    /// `git://`, `git+https://`, `git+ssh://` — uses native git.
    Git,
}

/// How a registry tracks its upstream version.
///
/// Exactly one mode is active at a time; when none of the four tracking
/// fields is set, the default mode (branch HEAD of "main") is used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrackingMode {
    /// Frozen to an exact commit hash.
    Commit(String),
    /// Track the HEAD of a named branch.
    Branch(String),
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
            TrackingMode::Commit(h) => write!(f, "commit:{}", &h[..h.len().min(12)]),
            TrackingMode::Branch(b) => write!(f, "branch:{b}"),
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
    /// Returns `HttpBundle` for all other URLs (including `https://` and
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
            Transport::HttpBundle
        }
    }

    /// Basic validation that `self.url` has meaningful content after the
    /// scheme (i.e. it is not just `"https://"` or empty).
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
    /// Validates that at most one of `commit`, `branch`, `tag`, `version`
    /// (and legacy `pin`) is set.  The legacy `pin` field is treated as
    /// `tag` for backward compatibility.
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
        if effective_tag.is_some() {
            count += 1;
        }
        if self.version.is_some() {
            count += 1;
        }

        if count > 1 {
            bail!(
                "registry '{}': only one of commit, branch, tag, version \
                 may be set (found {})",
                self.name,
                count,
            );
        }

        if let Some(ref hash) = self.commit {
            return Ok(TrackingMode::Commit(hash.clone()));
        }
        if let Some(ref branch) = self.branch {
            return Ok(TrackingMode::Branch(branch.clone()));
        }
        if let Some(ref tag) = effective_tag {
            return Ok(TrackingMode::Tag(tag.clone()));
        }
        if let Some(ref constraint) = self.version {
            let req = semver::VersionReq::parse(constraint)
                .map_err(|e| anyhow::anyhow!(
                    "registry '{}': invalid version constraint '{}': {}",
                    self.name,
                    constraint,
                    e,
                ))?;
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
    pub fn profile_path(&self) -> PathBuf {
        match self {
            ProfileScope::User => {
                let user =
                    std::env::var("USER").unwrap_or_else(|_| String::from("unknown"));
                PathBuf::from(PROFILES_BASE).join("per-user").join(user)
            }
            ProfileScope::System => PathBuf::from(PROFILES_BASE).join("system"),
        }
    }

    /// Path for cached registry metadata.
    pub fn cache_path(&self) -> PathBuf {
        match self {
            ProfileScope::User => {
                resolve_home().join(".local/share/apm/remote")
            }
            ProfileScope::System => PathBuf::from(APM_STATE_DIR).join("remote"),
        }
    }

    /// Path for NAR download cache.
    pub fn nar_cache_path(&self) -> PathBuf {
        match self {
            ProfileScope::User => resolve_home().join(".cache/apm"),
            ProfileScope::System => PathBuf::from(APM_STATE_DIR).join("cache"),
        }
    }

    /// Path for registry config files.
    pub fn config_dir(&self) -> PathBuf {
        match self {
            ProfileScope::User => resolve_home().join(".config/apm"),
            ProfileScope::System => PathBuf::from(APM_SYSTEM_CONFIG_DIR),
        }
    }

    /// Path for local registry git clones (both read-only and read-write).
    pub fn registries_path(&self) -> PathBuf {
        match self {
            ProfileScope::User => {
                resolve_home().join(".local/share/apm/registries")
            }
            ProfileScope::System => PathBuf::from(APM_STATE_DIR).join("registries"),
        }
    }

    /// Path for trusted key storage.
    pub fn trusted_keys_dirs(&self) -> Vec<PathBuf> {
        match self {
            ProfileScope::User => {
                let home = resolve_home();
                vec![
                    home.join(".config/apm/trusted-keys.d"),
                    PathBuf::from(APM_SYSTEM_CONFIG_DIR).join("trusted-keys.d"),
                ]
            }
            ProfileScope::System => vec![
                PathBuf::from(APM_SYSTEM_CONFIG_DIR).join("trusted-keys.d"),
                PathBuf::from(APM_STATE_DIR).join("trusted-keys.d"),
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
    pub registry: RegistryFileInner,
}

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
    pub tag: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    /// Legacy field: treated as `tag` for backward compatibility.
    #[serde(default)]
    pub pin: Option<String>,
    #[serde(default)]
    pub signing: Option<SigningConfig>,
    #[serde(default)]
    pub state: Option<RegistryState>,
}

/// Top-level structure of `apm.conf`.
#[derive(Debug, Deserialize)]
pub struct ApmConfFile {
    #[serde(default)]
    pub settings: ApmSettings,
}

// ---------------------------------------------------------------------------
// Registry root config — from `registry.toml` inside a registry repo
// ---------------------------------------------------------------------------

/// Top-level structure of a registry's `registry.toml` file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryRootConfig {
    pub registry: RegistryRootMeta,
    #[serde(default)]
    pub caches: Vec<CacheEntry>,
}

/// Registry metadata in `registry.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryRootMeta {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// A binary cache entry in `registry.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub url: String,
    #[serde(default = "default_cache_priority")]
    pub priority: u32,
}

fn default_cache_priority() -> u32 {
    100
}

// ---------------------------------------------------------------------------
// Sysroot image entry — a pre-compiled image attached to a sysroot package
// ---------------------------------------------------------------------------

/// A pre-compiled image format entry within a sysroot package version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SysrootImageEntry {
    pub format: String,
    pub store_path: String,
    pub nar_hash: String,
    pub nar_size: u64,
}

// ---------------------------------------------------------------------------
// System generation state — persisted in /var/lib/profiles/system/state.json
// ---------------------------------------------------------------------------

/// Metadata about a single system generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemGeneration {
    pub number: u32,
    pub toplevel: String,
    pub version: String,
    pub package_name: String,
    pub registry: String,
    pub created_at: String,
    #[serde(default)]
    pub kernel_path: Option<String>,
}

/// Persistent state for system generations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemGenerationState {
    pub current: u32,
    pub next: u32,
    #[serde(default)]
    pub generations: Vec<SystemGeneration>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_detection_https() {
        let cfg = RegistryConfig {
            name: "test".into(),
            url: "https://registry.aos.dev/core".into(),
            priority: 500,
            enabled: true,
            commit: None,
            branch: None,
            tag: None,
            version: None,
            pin: None,
            signing: None,
        };
        assert_eq!(cfg.transport(), Transport::HttpBundle);
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
            tag: None,
            version: None,
            pin: None,
            signing: None,
        };
        assert_eq!(cfg.transport(), Transport::HttpBundle);
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
            tag: None,
            version: None,
            pin: None,
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
            tag: None,
            version: None,
            pin: None,
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
            tag: None,
            version: None,
            pin: None,
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

[registry.signing]
required = true
public_key = "aos-core:Ed25519:base64keyhere"
"#;
        let rf: RegistryFile = toml::from_str(toml_str).unwrap();
        assert_eq!(rf.registry.name, "aos-core");
        assert_eq!(rf.registry.priority, 500);
        let signing = rf.registry.signing.unwrap();
        assert!(signing.required);
        assert_eq!(signing.public_key, "aos-core:Ed25519:base64keyhere");
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
last_creation_token = 2026020003
last_update = "2026-02-13T10:30:00Z"
"#;
        let rf: RegistryFile = toml::from_str(toml_str).unwrap();
        let state = rf.registry.state.unwrap();
        assert_eq!(state.last_commit.unwrap(), "abc123");
        assert_eq!(state.last_creation_token.unwrap(), 2026020003);
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
            }),
        };
        let json = serde_json::to_string_pretty(&meta).unwrap();
        let parsed: InstalledMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.store_path, meta.store_path);
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
            tag: None,
            version: None,
            pin: None,
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
        cfg.commit = Some("abc123def456".into());
        match cfg.tracking_mode().unwrap() {
            TrackingMode::Commit(h) => assert_eq!(h, "abc123def456"),
            other => panic!("expected Commit, got {:?}", other),
        }
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
    fn tracking_mode_tag() {
        let mut cfg = base_cfg();
        cfg.tag = Some("v2026.03".into());
        match cfg.tracking_mode().unwrap() {
            TrackingMode::Tag(t) => assert_eq!(t, "v2026.03"),
            other => panic!("expected Tag, got {:?}", other),
        }
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
        assert!(err.to_string().contains("invalid version constraint"), "got: {err}");
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
