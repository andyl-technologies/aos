//! Native registry configuration scopes and settings.

use std::path::{Path, PathBuf};
use anyhow::Result;
use serde::{Deserialize, Serialize};

pub use aos_registry_format::consumer::*;

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
    /// Native image bootstrap and package configuration share the authoritative
    /// deployment journal at `/var/lib/profiles/system/`.
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

/// Top-level structure of `apm.conf`.
#[derive(Debug, Deserialize)]
pub struct ApmConfFile {
    /// The `[settings]` table; every field is optional.
    #[serde(default)]
    pub settings: ApmSettings,
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use aos_registry_format::consumer::supported_package_features;
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

    fn attestation_package_meta(requires_features: Vec<&str>) -> PackageMeta {
        PackageMeta {
            named_outputs: Default::default(),
            version_requirement: None,
            os_version: None,
            module_dependencies: Vec::new(),
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
            deployment: None,
            module_documentation: None,
            qualification: None,
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
    fn native_package_metadata_rejects_removed_projection_fields() {
        let meta = attestation_package_meta(vec![FEATURE_ATTESTATION_V1]);
        for field in ["contract", "documentation"] {
            let mut value = serde_json::to_value(&meta).unwrap();
            value
                .as_object_mut()
                .unwrap()
                .insert(field.into(), serde_json::json!({}));
            assert!(serde_json::from_value::<PackageMeta>(value).is_err());
        }
    }

    #[test]
    fn package_meta_requires_attestation_feature_gate() {
        let mut meta = attestation_package_meta(vec![]);

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

    #[test]
    fn native_image_rollout_gate_rejects_pre_change_package_readers() {
        let mut meta = sample_package_meta();
        meta.name = "aos".to_string();
        meta.sysroot = true;
        meta.requires_features = vec![FEATURE_IMAGE_ARTIFACT_CONTRACT_V1.to_string()];

        validate_supported_package_meta(&meta)
            .expect("the current package reader understands native image rollouts");

        let supported_features = supported_package_features().expect("supported package features");
        let pre_change_features = supported_features
            .iter()
            .map(String::as_str)
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
            named_outputs: Default::default(),
            version_requirement: None,
            os_version: None,
            module_dependencies: Vec::new(),
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
            deployment: None,
            module_documentation: None,
            qualification: None,
            attestation: AttestationMeta::default(),
        }
    }
}
