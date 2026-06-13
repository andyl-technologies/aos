//! Package registry loading, resolution, and synchronization.
//!
//! A registry is a git repository of per-package TOML metadata files plus
//! optional precomputed closure files, mirrored into a local cache directory
//! by `apm update`. This module ties the pieces together:
//!
//! - [`Registry`] loads one registry's cache and answers name, store-path
//!   hash, and closure lookups for a single platform.
//! - [`RegistrySet`] layers multiple registries by priority so the highest
//!   priority registry that offers a package wins.
//! - Submodules implement the moving parts: [`git`] (git/dumb-HTTP sync with
//!   signature and fast-forward verification), [`parse`] (package TOML
//!   schema), [`closures`] (precomputed closure files), [`channel`] and
//!   [`verify`] (channel rollout partitions and signed tag chains), [`keys`]
//!   (the committed `keys.toml` trust roster), [`fetch`] and [`pack`]
//!   (delta/full-pack object transfer), [`objectstore`] and [`static_upload`]
//!   (the producer-side static dumb-HTTP origin), [`nixcache`] (static Nix
//!   binary-cache generation), [`webgen`] (the static no-JS web surface),
//!   and [`state`] (persisted sync state).

pub mod channel;
pub mod closures;
pub mod fetch;
pub mod git;
pub mod keys;
pub mod nixcache;
pub mod objectstore;
pub mod pack;
pub mod parse;
pub mod state;
pub mod static_upload;
pub mod verify;
pub mod webgen;

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};

use super::types::{ClosureMeta, PackageMeta, RegistryConfig, TrackingMode};
use closures::load_closures;
use parse::parse_registry_matching;

/// A loaded registry with all its packages for the current platform.
#[derive(Debug)]
pub struct Registry {
    /// The registry configuration this instance was loaded from.
    pub config: RegistryConfig,
    /// Newest matching version of every package offered for the loaded
    /// platform, keyed by package name.
    pub packages: HashMap<String, PackageMeta>,
    /// Reverse index from store path hash to the exact package version that
    /// produced it (covers all versions, not just the newest).
    hash_index: HashMap<String, PackageMeta>,
    /// Precomputed closures keyed by store path hash.
    closures: HashMap<String, ClosureMeta>,
}

impl Registry {
    /// Load a registry from its local cache directory.
    ///
    /// The cache directory should contain a `packages/` subdirectory with
    /// the registry's TOML package files organized by first letter, and
    /// optionally a `closures/` directory with precomputed closure files.
    /// A missing or unreadable `closures/` directory is tolerated and simply
    /// yields no precomputed closures.
    ///
    /// # Errors
    ///
    /// Returns an error if the registry tracking config is invalid, the
    /// `packages/` directory cannot be read, or any package TOML file inside
    /// it fails to parse.
    pub fn load(cache_dir: &Path, config: &RegistryConfig, platform: &str) -> Result<Self> {
        let registry_dir = cache_dir.join(&config.name);
        let version_req = match config.tracking_mode()? {
            TrackingMode::Version(req) => Some(req),
            _ => None,
        };
        let (packages, hash_index) =
            parse_registry_matching(&registry_dir, platform, version_req.as_ref()).with_context(
                || {
                    format!(
                        "loading registry '{}' from {}",
                        config.name,
                        registry_dir.display()
                    )
                },
            )?;

        let closures = load_closures(&registry_dir).unwrap_or_default();

        Ok(Self {
            config: config.clone(),
            packages,
            hash_index,
            closures,
        })
    }

    /// Looks up the newest version of a package by name.
    pub fn get(&self, name: &str) -> Option<&PackageMeta> {
        self.packages.get(name)
    }

    /// Looks up a package version by its store path hash.
    ///
    /// Unlike [`Registry::get`], this resolves any published version whose
    /// output landed at that hash, which is what closure walking and rollback
    /// metadata rebuilds need.
    pub fn get_by_hash(&self, hash: &str) -> Option<&PackageMeta> {
        self.hash_index.get(hash)
    }

    /// Returns the precomputed closure for a store path hash, if available.
    pub fn get_closure(&self, hash: &str) -> Option<&ClosureMeta> {
        self.closures.get(hash)
    }

    /// Lists all package names offered by this registry (unordered).
    pub fn names(&self) -> Vec<&str> {
        self.packages.keys().map(|s| s.as_str()).collect()
    }

    /// Searches packages by a case-insensitive substring pattern.
    ///
    /// Matches against the package name, and also the description unless
    /// `names_only` is set.
    pub fn search(&self, pattern: &str, names_only: bool) -> Vec<&PackageMeta> {
        let pattern_lower = pattern.to_lowercase();
        self.packages
            .values()
            .filter(|meta| {
                let name_match = meta.name.to_lowercase().contains(&pattern_lower);
                if names_only {
                    name_match
                } else {
                    name_match || meta.description.to_lowercase().contains(&pattern_lower)
                }
            })
            .collect()
    }
}

/// Multi-registry resolver that wraps multiple registries sorted by priority.
#[derive(Debug)]
pub struct RegistrySet {
    registries: Vec<Registry>,
}

impl RegistrySet {
    /// Creates a new registry set from pre-loaded registries.
    ///
    /// Registries should already be sorted by priority (highest first);
    /// [`RegistrySet::resolve`] returns the first match in iteration order.
    pub fn new(registries: Vec<Registry>) -> Self {
        Self { registries }
    }

    /// Loads all enabled registries from the cache directory.
    ///
    /// Registries that fail to load (typically because they have not been
    /// synced yet) are skipped with a warning on stderr rather than failing
    /// the whole set.
    ///
    /// # Errors
    ///
    /// Currently never returns an error; the `Result` is kept for forward
    /// compatibility with stricter loading policies.
    pub fn load(cache_dir: &Path, configs: &[&RegistryConfig], platform: &str) -> Result<Self> {
        let mut registries = Vec::new();
        for config in configs {
            match Registry::load(cache_dir, config, platform) {
                Ok(r) => registries.push(r),
                Err(e) => {
                    // Log warning but continue — a missing cache just means
                    // the registry hasn't been synced yet.
                    eprintln!("warning: skipping registry '{}': {}", config.name, e);
                }
            }
        }
        Ok(Self::new(registries))
    }

    /// Resolves a package name to the package offered by the
    /// highest-priority registry, together with that registry.
    pub fn resolve(&self, name: &str) -> Option<(&Registry, &PackageMeta)> {
        for reg in &self.registries {
            if let Some(meta) = reg.get(name) {
                return Some((reg, meta));
            }
        }
        None
    }

    /// Resolves a store path hash within a specific registry.
    ///
    /// Used for registry-scoped closure walking: all dependencies of a
    /// package resolve from the same registry that provided it.
    pub fn resolve_hash_in(&self, registry_name: &str, hash: &str) -> Option<&PackageMeta> {
        self.registries
            .iter()
            .find(|r| r.config.name == registry_name)
            .and_then(|r| r.get_by_hash(hash))
    }

    /// Returns the precomputed closure for a store path hash within a
    /// specific registry.
    pub fn get_closure_in(&self, registry_name: &str, hash: &str) -> Option<&ClosureMeta> {
        self.registries
            .iter()
            .find(|r| r.config.name == registry_name)
            .and_then(|r| r.get_closure(hash))
    }

    /// Returns all versions of a package across registries (for `apm policy`).
    ///
    /// Returns entries from all registries, ordered by priority (highest first).
    pub fn all_versions(&self, name: &str) -> Vec<(&Registry, &PackageMeta)> {
        self.registries
            .iter()
            .filter_map(|reg| reg.get(name).map(|meta| (reg, meta)))
            .collect()
    }

    /// Returns a reference to a specific registry by name.
    pub fn get_registry(&self, name: &str) -> Option<&Registry> {
        self.registries.iter().find(|r| r.config.name == name)
    }

    /// Returns all registries in priority order (highest first).
    pub fn registries(&self) -> &[Registry] {
        &self.registries
    }
}

/// Re-export `store_path_hash` for use by other modules.
pub use parse::store_path_hash;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    use super::closures::{CURL_CLOSURE, ZLIB_CLOSURE};
    use super::parse::{CURL_TOML, MULTI_VERSION_TOML, ZLIB_TOML};

    /// Helper: create a registry in a temp directory from TOML test fixtures.
    ///
    /// Optionally writes closure files when `closure_files` is non-empty.
    pub(crate) fn make_registry(
        tmp: &TempDir,
        name: &str,
        priority: u32,
        toml_files: &[(&str, &str)],
    ) -> Registry {
        make_registry_with_closures(tmp, name, priority, toml_files, &[])
    }

    /// Helper: create a registry with both TOML and closure files.
    pub(crate) fn make_registry_with_closures(
        tmp: &TempDir,
        name: &str,
        priority: u32,
        toml_files: &[(&str, &str)],
        closure_files: &[(&str, &str)],
    ) -> Registry {
        let reg_dir = tmp.path().join(name);
        let pkg_dir = reg_dir.join("packages");
        for (pkg_name, content) in toml_files {
            let first_letter = &pkg_name[..1];
            let dir = pkg_dir.join(first_letter);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join(format!("{pkg_name}.toml")), content).unwrap();
        }

        if !closure_files.is_empty() {
            let closures_dir = reg_dir.join("closures");
            fs::create_dir_all(&closures_dir).unwrap();
            for (hash, content) in closure_files {
                fs::write(closures_dir.join(hash), content).unwrap();
            }
        }

        let config = RegistryConfig {
            name: name.to_string(),
            url: format!("https://registry.example.com/{name}"),
            priority,
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

        Registry::load(tmp.path(), &config, "x86_64-linux").unwrap()
    }

    #[test]
    fn registry_get_by_name() {
        let tmp = TempDir::new().unwrap();
        let reg = make_registry(&tmp, "test", 500, &[("curl", CURL_TOML)]);
        assert!(reg.get("curl").is_some());
        assert!(reg.get("nonexistent").is_none());
    }

    #[test]
    fn registry_get_by_hash() {
        let tmp = TempDir::new().unwrap();
        let reg = make_registry(&tmp, "test", 500, &[("curl", CURL_TOML)]);
        let meta = reg.get_by_hash("h7j3k8l2m9n4").unwrap();
        assert_eq!(meta.name, "curl");
    }

    #[test]
    fn registry_load_applies_version_tracking_constraint() {
        let tmp = TempDir::new().unwrap();
        let reg_dir = tmp.path().join("test");
        let pkg_dir = reg_dir.join("packages").join("t");
        fs::create_dir_all(&pkg_dir).unwrap();
        fs::write(pkg_dir.join("tool.toml"), MULTI_VERSION_TOML).unwrap();

        let config = RegistryConfig {
            name: "test".to_string(),
            url: "https://registry.example.com/test".to_string(),
            priority: 500,
            enabled: true,
            commit: None,
            branch: None,
            channel: None,
            tag: None,
            version: Some("^1.0".to_string()),
            pin: None,
            max_staleness_seconds: None,
            caches: Vec::new(),
            upload_auth: None,
            signing_keys: Default::default(),
            signing: None,
        };

        let reg = Registry::load(tmp.path(), &config, "x86_64-linux").unwrap();

        assert_eq!(reg.get("tool").unwrap().version, "1.0.0");
        assert!(reg.get_by_hash("oldhash111111").is_some());
        assert!(reg.get_by_hash("newhash222222").is_none());
    }

    #[test]
    fn registry_search() {
        let tmp = TempDir::new().unwrap();
        let reg = make_registry(
            &tmp,
            "test",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );

        let results = reg.search("curl", false);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "curl");

        // Search in description
        let results = reg.search("compression", false);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "zlib");

        // Names only — should not match description
        let results = reg.search("compression", true);
        assert!(results.is_empty());
    }

    #[test]
    fn registry_set_priority_resolution() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );
        let extra = make_registry(&tmp, "aos-extra", 400, &[("curl", CURL_TOML)]);

        let set = RegistrySet::new(vec![core, extra]);

        // Resolve picks highest priority
        let (reg, meta) = set.resolve("curl").unwrap();
        assert_eq!(reg.config.name, "aos-core");
        assert_eq!(meta.name, "curl");
    }

    #[test]
    fn registry_set_scoped_hash_resolution() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );
        let set = RegistrySet::new(vec![core]);

        // Scoped resolution within "aos-core"
        let meta = set.resolve_hash_in("aos-core", "r4q1m2kp8v3x").unwrap();
        assert_eq!(meta.name, "zlib");

        // Wrong registry name returns None
        assert!(set.resolve_hash_in("aos-extra", "r4q1m2kp8v3x").is_none());
    }

    #[test]
    fn registry_set_all_versions() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(&tmp, "aos-core", 500, &[("curl", CURL_TOML)]);
        let extra = make_registry(&tmp, "aos-extra", 400, &[("curl", CURL_TOML)]);

        let set = RegistrySet::new(vec![core, extra]);

        let versions = set.all_versions("curl");
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].0.config.name, "aos-core");
        assert_eq!(versions[1].0.config.name, "aos-extra");
    }

    #[test]
    fn registry_set_resolve_missing() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(&tmp, "aos-core", 500, &[("curl", CURL_TOML)]);
        let set = RegistrySet::new(vec![core]);

        assert!(set.resolve("nonexistent").is_none());
    }

    #[test]
    fn registry_loads_closures() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry_with_closures(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
            &[
                ("h7j3k8l2m9n4", CURL_CLOSURE),
                ("r4q1m2kp8v3x", ZLIB_CLOSURE),
            ],
        );

        // Closures are available.
        let curl_closure = core.get_closure("h7j3k8l2m9n4").unwrap();
        assert_eq!(curl_closure.members.len(), 5);
        assert_eq!(curl_closure.root, "h7j3k8l2m9n4");

        let zlib_closure = core.get_closure("r4q1m2kp8v3x").unwrap();
        assert_eq!(zlib_closure.members.len(), 1);

        // Missing closure returns None.
        assert!(core.get_closure("nonexistent").is_none());
    }

    #[test]
    fn registry_set_get_closure_in() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry_with_closures(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML)],
            &[("h7j3k8l2m9n4", CURL_CLOSURE)],
        );
        let set = RegistrySet::new(vec![core]);

        let closure = set.get_closure_in("aos-core", "h7j3k8l2m9n4");
        assert!(closure.is_some());
        assert_eq!(closure.unwrap().members.len(), 5);

        // Wrong registry.
        assert!(set.get_closure_in("aos-extra", "h7j3k8l2m9n4").is_none());
    }

    #[test]
    fn registry_without_closures_dir() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(&tmp, "aos-core", 500, &[("curl", CURL_TOML)]);

        // No closures dir — get_closure returns None.
        assert!(core.get_closure("h7j3k8l2m9n4").is_none());
    }
}
