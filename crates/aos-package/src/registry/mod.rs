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
pub mod verify;

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};

use super::types::{ClosureMeta, PackageMeta, RegistryConfig};
use closures::load_closures;
use parse::parse_registry;

/// A loaded registry with all its packages for the current platform.
#[derive(Debug)]
pub struct Registry {
    pub config: RegistryConfig,
    pub packages: HashMap<String, PackageMeta>,
    hash_index: HashMap<String, String>,
    /// Precomputed closures keyed by store path hash.
    closures: HashMap<String, ClosureMeta>,
}

impl Registry {
    /// Load a registry from its local cache directory.
    ///
    /// The cache directory should contain a `packages/` subdirectory with
    /// the registry's TOML package files organized by first letter, and
    /// optionally a `closures/` directory with precomputed closure files.
    pub fn load(cache_dir: &Path, config: &RegistryConfig, platform: &str) -> Result<Self> {
        let registry_dir = cache_dir.join(&config.name);
        let (packages, hash_index) =
            parse_registry(&registry_dir, platform).with_context(|| {
                format!(
                    "loading registry '{}' from {}",
                    config.name,
                    registry_dir.display()
                )
            })?;

        let closures = load_closures(&registry_dir).unwrap_or_default();

        Ok(Self {
            config: config.clone(),
            packages,
            hash_index,
            closures,
        })
    }

    /// Look up a package by name.
    pub fn get(&self, name: &str) -> Option<&PackageMeta> {
        self.packages.get(name)
    }

    /// Look up a package by store path hash.
    pub fn get_by_hash(&self, hash: &str) -> Option<&PackageMeta> {
        self.hash_index
            .get(hash)
            .and_then(|name| self.packages.get(name))
    }

    /// Get the precomputed closure for a store path hash, if available.
    pub fn get_closure(&self, hash: &str) -> Option<&ClosureMeta> {
        self.closures.get(hash)
    }

    /// List all package names.
    pub fn names(&self) -> Vec<&str> {
        self.packages.keys().map(|s| s.as_str()).collect()
    }

    /// Search packages by pattern (name + description).
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
    /// Create a new registry set from pre-loaded registries.
    /// Registries should already be sorted by priority (highest first).
    pub fn new(registries: Vec<Registry>) -> Self {
        Self { registries }
    }

    /// Load all enabled registries from the cache directory.
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

    /// Resolve a package name: returns the package from the highest-priority
    /// registry that offers it.
    pub fn resolve(&self, name: &str) -> Option<(&Registry, &PackageMeta)> {
        for reg in &self.registries {
            if let Some(meta) = reg.get(name) {
                return Some((reg, meta));
            }
        }
        None
    }

    /// Resolve a store path hash within a specific registry.
    ///
    /// Used for registry-scoped closure walking: all dependencies of a
    /// package resolve from the same registry that provided it.
    pub fn resolve_hash_in(&self, registry_name: &str, hash: &str) -> Option<&PackageMeta> {
        self.registries
            .iter()
            .find(|r| r.config.name == registry_name)
            .and_then(|r| r.get_by_hash(hash))
    }

    /// Get the precomputed closure for a store path hash within a specific
    /// registry.
    pub fn get_closure_in(&self, registry_name: &str, hash: &str) -> Option<&ClosureMeta> {
        self.registries
            .iter()
            .find(|r| r.config.name == registry_name)
            .and_then(|r| r.get_closure(hash))
    }

    /// Get all versions of a package across registries (for `apm policy`).
    ///
    /// Returns entries from all registries, ordered by priority (highest first).
    pub fn all_versions(&self, name: &str) -> Vec<(&Registry, &PackageMeta)> {
        self.registries
            .iter()
            .filter_map(|reg| reg.get(name).map(|meta| (reg, meta)))
            .collect()
    }

    /// Get a reference to a specific registry by name.
    pub fn get_registry(&self, name: &str) -> Option<&Registry> {
        self.registries.iter().find(|r| r.config.name == name)
    }

    /// Iterate over all registries.
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
    use super::parse::{CURL_TOML, ZLIB_TOML};

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
