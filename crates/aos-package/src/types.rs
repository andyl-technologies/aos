use std::path::PathBuf;

use serde::{Deserialize, Serialize};

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
    /// Hash of the compressed NAR (download): `"sha256:..."`.
    pub download_hash: String,
    pub download_size: u64,
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
    /// Tag pin (both transports).
    #[serde(default)]
    pub pin: Option<String>,
    /// Branch to track (git transport only).
    #[serde(default)]
    pub branch: Option<String>,
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

impl RegistryConfig {
    /// Determine the transport from the URL scheme.
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
                PathBuf::from("/var/lib/profiles/per-user").join(user)
            }
            ProfileScope::System => PathBuf::from("/var/lib/profiles/system"),
        }
    }

    /// Path for cached registry metadata.
    pub fn cache_path(&self) -> PathBuf {
        match self {
            ProfileScope::User => {
                let home =
                    std::env::var("HOME").unwrap_or_else(|_| String::from("/tmp"));
                PathBuf::from(home).join(".local/share/apm/remote")
            }
            ProfileScope::System => PathBuf::from("/var/lib/apm/remote"),
        }
    }

    /// Path for NAR download cache.
    pub fn nar_cache_path(&self) -> PathBuf {
        match self {
            ProfileScope::User => {
                let home =
                    std::env::var("HOME").unwrap_or_else(|_| String::from("/tmp"));
                PathBuf::from(home).join(".cache/apm")
            }
            ProfileScope::System => PathBuf::from("/var/lib/apm/cache"),
        }
    }

    /// Path for registry config files.
    pub fn config_dir(&self) -> PathBuf {
        match self {
            ProfileScope::User => {
                let home =
                    std::env::var("HOME").unwrap_or_else(|_| String::from("/tmp"));
                PathBuf::from(home).join(".config/apm")
            }
            ProfileScope::System => PathBuf::from("/etc/apm"),
        }
    }

    /// Path for local registry git clones (both read-only and read-write).
    pub fn registries_path(&self) -> PathBuf {
        match self {
            ProfileScope::User => {
                let home =
                    std::env::var("HOME").unwrap_or_else(|_| String::from("/tmp"));
                PathBuf::from(home).join(".local/share/apm/registries")
            }
            ProfileScope::System => PathBuf::from("/var/lib/apm/registries"),
        }
    }

    /// Path for trusted key storage.
    pub fn trusted_keys_dirs(&self) -> Vec<PathBuf> {
        match self {
            ProfileScope::User => {
                let home =
                    std::env::var("HOME").unwrap_or_else(|_| String::from("/tmp"));
                vec![
                    PathBuf::from(home).join(".config/apm/trusted-keys.d"),
                    PathBuf::from("/etc/apm/trusted-keys.d"),
                ]
            }
            ProfileScope::System => vec![
                PathBuf::from("/etc/apm/trusted-keys.d"),
                PathBuf::from("/var/lib/apm/trusted-keys.d"),
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
    pub pin: Option<String>,
    #[serde(default)]
    pub branch: Option<String>,
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
    #[serde(default)]
    pub signing: Option<RegistrySigningConfig>,
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

/// Signing configuration in `registry.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrySigningConfig {
    pub public_key: String,
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
    pub download_hash: String,
    pub download_size: u64,
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
            pin: None,
            branch: None,
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
            pin: None,
            branch: None,
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
            pin: None,
            branch: None,
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
            pin: None,
            branch: None,
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
            pin: None,
            branch: None,
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
}
