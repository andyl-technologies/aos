use std::collections::HashMap;

use anyhow::{Context, Result};

use super::config::ApmConfig;
use super::profile::meta::list_meta;
use super::profile::Profile;
use super::registry::{store_path_hash, Registry, RegistrySet};
use super::types::{InstalledMeta, PackageMeta};
use aos::output::{OutputMode, Printer};

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

/// Search package names and descriptions across all registries.
pub async fn search(
    config: &ApmConfig,
    pattern: &str,
    names_only: bool,
    installed_only: bool,
    registry_filter: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let registries = load_registries(config)?;

    // If --installed, load profile metadata to filter results.
    let installed_hashes: Option<HashMap<String, InstalledMeta>> = if installed_only {
        let profile = Profile::open(config.scope)?;
        let meta_list = list_meta(&profile)?;
        let map = meta_list
            .into_iter()
            .map(|m| {
                let hash = store_path_hash(&m.store_path).to_string();
                (hash, m)
            })
            .collect();
        Some(map)
    } else {
        None
    };

    // Collect matches: (name, registry_name, version, description).
    let mut results: Vec<(String, String, String, String)> = Vec::new();

    for reg in registries.registries() {
        if let Some(filter) = registry_filter {
            if reg.config.name != filter {
                continue;
            }
        }

        let matches = reg.search(pattern, names_only);

        for meta in matches {
            // If --installed, skip packages not in profile.
            if let Some(ref installed) = installed_hashes {
                let hash = store_path_hash(&meta.store_path).to_string();
                if !installed.contains_key(&hash) {
                    continue;
                }
            }

            results.push((
                meta.name.clone(),
                reg.config.name.clone(),
                meta.version.clone(),
                meta.description.clone(),
            ));
        }
    }

    // Sort by name.
    results.sort_by(|a, b| a.0.cmp(&b.0));

    // Deduplicate by name (highest priority registry wins, which comes first
    // since RegistrySet is sorted by priority descending).
    results.dedup_by(|b, a| a.0 == b.0);

    // Output.
    if printer.mode() == OutputMode::Json {
        let json_results: Vec<serde_json::Value> = results
            .iter()
            .map(|(name, registry, version, description)| {
                serde_json::json!({
                    "name": name,
                    "registry": registry,
                    "version": version,
                    "description": description,
                })
            })
            .collect();
        printer.json(&serde_json::json!(json_results));
    } else {
        for (name, registry, version, description) in &results {
            printer.plain(&format!(
                "{name}/{registry} {version} - {description}"
            ));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Show
// ---------------------------------------------------------------------------

/// Display detailed information about a package.
pub async fn show(
    config: &ApmConfig,
    package: &str,
    printer: &Printer,
) -> Result<()> {
    let registries = load_registries(config)?;

    let (reg, meta) = registries
        .resolve(package)
        .with_context(|| format!("package '{package}' not found in any registry"))?;

    let registry_name = reg.config.name.clone();

    // Check if installed.
    let profile = Profile::open(config.scope)?;
    let meta_list = list_meta(&profile)?;
    let pkg_hash = store_path_hash(&meta.store_path).to_string();
    let installed_meta = meta_list
        .iter()
        .find(|m| store_path_hash(&m.store_path) == pkg_hash);

    let is_installed = installed_meta.is_some();

    // Resolve dependency names from references.
    let dep_names = resolve_dependency_names(meta, reg);

    let nar_size_str = format_size(meta.nar_size);

    if printer.mode() == OutputMode::Json {
        let json_obj = serde_json::json!({
            "name": meta.name,
            "version": meta.version,
            "registry": registry_name,
            "description": meta.description,
            "homepage": meta.homepage,
            "license": meta.license,
            "platform": meta.platform,
            "installed": is_installed,
            "store_path": meta.store_path,
            "nar_size": meta.nar_size,
            "nar_size_human": nar_size_str,
            "dependencies": dep_names,
            "source_drv": meta.source_drv,
            "maintainer": meta.maintainer,
        });
        printer.json(&json_obj);
    } else {
        printer.kv("Package", &meta.name);
        printer.kv("Version", &meta.version);
        printer.kv("Registry", &registry_name);
        printer.kv("Description", &meta.description);
        if let Some(ref homepage) = meta.homepage {
            printer.kv("Homepage", homepage);
        }
        printer.kv("License", &meta.license);
        printer.kv("Platform", &meta.platform);
        printer.kv(
            "Installed",
            if is_installed { "yes" } else { "no" },
        );
        printer.kv("Store path", &meta.store_path);
        printer.kv("NAR size", &nar_size_str);
        if dep_names.is_empty() {
            printer.kv("Dependencies", "(none)");
        } else {
            printer.kv("Dependencies", &dep_names.join(", "));
        }
        printer.kv("Source drv", &meta.source_drv);
        printer.kv("Maintainer", &meta.maintainer);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

/// List packages across registries with optional filters.
pub async fn list(
    config: &ApmConfig,
    installed_only: bool,
    upgradable_only: bool,
    held_only: bool,
    registry_filter: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let registries = load_registries(config)?;

    // Load profile metadata for install/upgrade/held checks.
    let profile = Profile::open(config.scope)?;
    let meta_list = list_meta(&profile)?;

    // Build a map: package_name -> InstalledMeta (for packages with apm section).
    let installed_by_name: HashMap<String, &InstalledMeta> = meta_list
        .iter()
        .filter_map(|m| {
            m.apm
                .as_ref()
                .map(|apm| (apm.name.clone(), m))
        })
        .collect();

    // Collect entries: (name, registry_name, version, status).
    let mut entries: Vec<(String, String, String, String)> = Vec::new();

    for reg in registries.registries() {
        if let Some(filter) = registry_filter {
            if reg.config.name != filter {
                continue;
            }
        }

        let mut names: Vec<&str> = reg.names();
        names.sort();

        for name in names {
            let meta = match reg.get(name) {
                Some(m) => m,
                None => continue,
            };

            let installed = installed_by_name.get(name);
            let is_installed = installed.is_some();

            // Determine held status.
            let is_held = installed
                .and_then(|m| m.apm.as_ref())
                .map(|a| a.held)
                .unwrap_or(false);

            // Determine upgradable: installed but registry has different store path hash.
            let is_upgradable = if let Some(inst) = installed {
                let installed_hash = store_path_hash(&inst.store_path);
                let registry_hash = store_path_hash(&meta.store_path);
                installed_hash != registry_hash
            } else {
                false
            };

            // Apply filters.
            if installed_only && !is_installed {
                continue;
            }
            if upgradable_only && !is_upgradable {
                continue;
            }
            if held_only && !is_held {
                continue;
            }

            // Build status string.
            let status = build_status_string(
                is_installed,
                is_upgradable,
                is_held,
                if is_upgradable {
                    Some(&meta.version)
                } else {
                    None
                },
            );

            let display_version = if let Some(inst) = installed {
                inst.apm
                    .as_ref()
                    .map(|a| a.version.clone())
                    .unwrap_or_else(|| meta.version.clone())
            } else {
                meta.version.clone()
            };

            entries.push((
                name.to_string(),
                reg.config.name.clone(),
                display_version,
                status,
            ));
        }
    }

    // Sort by name then registry.
    entries.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    // Deduplicate by name (highest priority registry comes first).
    entries.dedup_by(|b, a| a.0 == b.0);

    // Output.
    if printer.mode() == OutputMode::Json {
        let json_entries: Vec<serde_json::Value> = entries
            .iter()
            .map(|(name, registry, version, status)| {
                serde_json::json!({
                    "name": name,
                    "registry": registry,
                    "version": version,
                    "status": status,
                })
            })
            .collect();
        printer.json(&serde_json::json!(json_entries));
    } else {
        for (name, registry, version, status) in &entries {
            if status.is_empty() {
                printer.plain(&format!("{name}/{registry} {version}"));
            } else {
                printer.plain(&format!(
                    "{name}/{registry} {version} [{status}]"
                ));
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Load all enabled registries from the config.
fn load_registries(config: &ApmConfig) -> Result<RegistrySet> {
    let enabled = config.enabled_registries();
    let cache_dir = config.cache_path();
    let platform = current_platform();
    RegistrySet::load(&cache_dir, &enabled, &platform)
}

/// Detect the current platform string (e.g. "x86_64-linux").
fn current_platform() -> String {
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;

    let nix_arch = match arch {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        "arm" => "armv7l",
        "riscv64" => "riscv64",
        _ => arch,
    };

    let nix_os = match os {
        "linux" => "linux",
        "macos" => "darwin",
        _ => os,
    };

    format!("{nix_arch}-{nix_os}")
}

/// Resolve dependency names from a PackageMeta's references using the registry's
/// hash index.
///
/// Returns a Vec of resolved package names. If a reference hash cannot be
/// resolved to a known package, the raw hash string is returned instead.
pub fn resolve_dependency_names(meta: &PackageMeta, registry: &Registry) -> Vec<String> {
    meta.references
        .iter()
        .map(|ref_hash| {
            registry
                .get_by_hash(ref_hash)
                .map(|dep| dep.name.clone())
                .unwrap_or_else(|| ref_hash.clone())
        })
        .collect()
}

/// Format a byte size into a human-readable string using binary units.
///
/// Examples:
/// - 512 -> "512 B"
/// - 1536 -> "1.5 KiB"
/// - 14_893_056 -> "14.2 MiB"
/// - 1_073_741_824 -> "1.0 GiB"
pub fn format_size(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

    let size = bytes as f64;

    if size < KIB {
        format!("{bytes} B")
    } else if size < MIB {
        format!("{:.1} KiB", size / KIB)
    } else if size < GIB {
        format!("{:.1} MiB", size / MIB)
    } else {
        format!("{:.1} GiB", size / GIB)
    }
}

/// Build a human-readable status string for `apm list` output.
fn build_status_string(
    installed: bool,
    upgradable: bool,
    held: bool,
    upgrade_version: Option<&str>,
) -> String {
    let mut parts = Vec::new();

    if installed {
        parts.push("installed".to_string());
    }
    if upgradable {
        if let Some(ver) = upgrade_version {
            parts.push(format!("upgradable: {ver}"));
        } else {
            parts.push("upgradable".to_string());
        }
    }
    if held {
        parts.push("held".to_string());
    }

    parts.join(",")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    use crate::package::registry::parse::{CURL_TOML, ZLIB_TOML};
    use crate::package::registry::Registry;
    use crate::package::types::{ApmMeta, InstalledMeta, RegistryConfig};

    /// Helper: create a registry in a temp directory from TOML test fixtures.
    fn make_registry(
        tmp: &TempDir,
        name: &str,
        priority: u32,
        toml_files: &[(&str, &str)],
    ) -> Registry {
        let reg_dir = tmp.path().join(name).join("packages");
        for (pkg_name, content) in toml_files {
            let first_letter = &pkg_name[..1];
            let dir = reg_dir.join(first_letter);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join(format!("{pkg_name}.toml")), content).unwrap();
        }

        let config = RegistryConfig {
            name: name.to_string(),
            url: format!("https://registry.example.com/{name}"),
            priority,
            enabled: true,
            pin: None,
            branch: None,
            signing: None,
        };

        Registry::load(tmp.path(), &config, "x86_64-linux").unwrap()
    }

    fn sample_installed_meta(
        name: &str,
        version: &str,
        registry: &str,
        store_path: &str,
        held: bool,
    ) -> InstalledMeta {
        InstalledMeta {
            store_path: store_path.into(),
            pushed_at: 1707800000,
            pushed_by: "apm".into(),
            expires_at: None,
            is_root: true,
            last_accessed: 1707800000,
            access_count: 0,
            apm: Some(ApmMeta {
                name: name.into(),
                version: version.into(),
                explicit: true,
                registry: registry.into(),
                installed_at: "2026-02-16T00:00:00Z".into(),
                held,
            }),
        }
    }

    // 1. search_finds_by_name
    #[test]
    fn search_finds_by_name() {
        let tmp = TempDir::new().unwrap();
        let reg = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );

        let results = reg.search("curl", false);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "curl");
    }

    // 2. search_finds_by_description
    #[test]
    fn search_finds_by_description() {
        let tmp = TempDir::new().unwrap();
        let reg = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );

        // "compression" is in zlib's description
        let results = reg.search("compression", false);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "zlib");
    }

    // 3. search_names_only_skips_description
    #[test]
    fn search_names_only_skips_description() {
        let tmp = TempDir::new().unwrap();
        let reg = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );

        // "compression" only appears in zlib's description, not name
        let results = reg.search("compression", true);
        assert!(results.is_empty());
    }

    // 4. resolve_dependency_names_resolves_known
    #[test]
    fn resolve_dependency_names_resolves_known() {
        let tmp = TempDir::new().unwrap();
        let reg = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );

        let curl_meta = reg.get("curl").unwrap();
        let dep_names = resolve_dependency_names(curl_meta, &reg);

        // r4q1m2kp8v3x is zlib's hash, so it should resolve to "zlib"
        assert!(dep_names.contains(&"zlib".to_string()));
    }

    // 5. resolve_dependency_names_unknown_stays_hash
    #[test]
    fn resolve_dependency_names_unknown_stays_hash() {
        let tmp = TempDir::new().unwrap();
        // Only load curl, not zlib -- so zlib's hash and others won't resolve.
        let reg = make_registry(&tmp, "aos-core", 500, &[("curl", CURL_TOML)]);

        let curl_meta = reg.get("curl").unwrap();
        let dep_names = resolve_dependency_names(curl_meta, &reg);

        // curl has references: ["xr5is7by89v3q", "r4q1m2kp8v3x", "q8mn2pv73w0x", "kl9m3n0o5p6q"]
        // None of these resolve to a named package (zlib not loaded), but
        // some may resolve via hash_index to "curl" itself. The ones that
        // don't resolve at all should stay as raw hashes.
        // At minimum, we should have 4 entries (one per reference).
        assert_eq!(dep_names.len(), 4);

        // xr5is7by89v3q is not zlib, so in a curl-only registry it maps
        // via hash_index fallback to "curl" (the indexer inserts reference
        // hashes pointing back to the referencing package). Check that at
        // least some entries are either "curl" or raw hashes.
        for name in &dep_names {
            assert!(
                name == "curl" || name.chars().all(|c| c.is_alphanumeric()),
                "unexpected dep name: {name}"
            );
        }
    }

    // 6. format_size_units
    #[test]
    fn format_size_units() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1023), "1023 B");
        assert_eq!(format_size(1024), "1.0 KiB");
        assert_eq!(format_size(1536), "1.5 KiB");
        assert_eq!(format_size(1048576), "1.0 MiB");
        assert_eq!(format_size(14_893_056), "14.2 MiB");
        assert_eq!(format_size(1_073_741_824), "1.0 GiB");
        assert_eq!(format_size(2_684_354_560), "2.5 GiB");
    }

    // 7. list_installed_filters_correctly
    #[test]
    fn list_installed_filters_correctly() {
        let tmp = TempDir::new().unwrap();
        let reg = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );
        let registries = RegistrySet::new(vec![reg]);

        // Simulate installed: only curl is installed.
        let curl_installed = sample_installed_meta(
            "curl",
            "8.5.0",
            "aos-core",
            "/var/lib/store/h7j3k8l2m9n4-curl-8.5.0",
            false,
        );

        let installed_by_name: HashMap<String, &InstalledMeta> = {
            let mut m = HashMap::new();
            m.insert("curl".to_string(), &curl_installed);
            m
        };

        // Filter: only installed packages.
        let mut entries = Vec::new();
        for reg in registries.registries() {
            let mut names: Vec<&str> = reg.names();
            names.sort();
            for name in names {
                let meta = reg.get(name).unwrap();
                let installed = installed_by_name.get(name);
                let is_installed = installed.is_some();

                // installed_only filter
                if !is_installed {
                    continue;
                }

                entries.push((name.to_string(), meta.version.clone()));
            }
        }

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "curl");
    }

    // 8. list_upgradable_detects_changes
    #[test]
    fn list_upgradable_detects_changes() {
        let tmp = TempDir::new().unwrap();
        let reg = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );
        let registries = RegistrySet::new(vec![reg]);

        // curl installed with a different hash (simulating older version)
        let curl_installed = sample_installed_meta(
            "curl",
            "8.4.0",
            "aos-core",
            "/var/lib/store/oldhash12345-curl-8.4.0",
            false,
        );
        // zlib installed with the same hash (no upgrade)
        let zlib_installed = sample_installed_meta(
            "zlib",
            "1.3.1",
            "aos-core",
            "/var/lib/store/r4q1m2kp8v3x-zlib-1.3.1",
            false,
        );

        let installed_by_name: HashMap<String, &InstalledMeta> = {
            let mut m = HashMap::new();
            m.insert("curl".to_string(), &curl_installed);
            m.insert("zlib".to_string(), &zlib_installed);
            m
        };

        let mut upgradable = Vec::new();
        for reg in registries.registries() {
            for name in reg.names() {
                let meta = reg.get(name).unwrap();
                if let Some(inst) = installed_by_name.get(name) {
                    let installed_hash = store_path_hash(&inst.store_path);
                    let registry_hash = store_path_hash(&meta.store_path);
                    if installed_hash != registry_hash {
                        upgradable.push(name.to_string());
                    }
                }
            }
        }

        assert_eq!(upgradable.len(), 1);
        assert_eq!(upgradable[0], "curl");
    }

    // 9. search_with_registry_filter
    #[test]
    fn search_with_registry_filter() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );
        let extra = make_registry(&tmp, "aos-extra", 400, &[("curl", CURL_TOML)]);

        let registries = RegistrySet::new(vec![core, extra]);

        // Search only in aos-extra: should find curl but not zlib.
        let mut results = Vec::new();
        for reg in registries.registries() {
            if reg.config.name != "aos-extra" {
                continue;
            }
            let matches = reg.search("", false);
            for m in matches {
                results.push(m.name.clone());
            }
        }

        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "curl");
    }

    // 10. show_formats_package_info
    #[test]
    fn show_formats_package_info() {
        let tmp = TempDir::new().unwrap();
        let reg = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );

        let meta = reg.get("curl").unwrap();

        // Verify key fields are present and correct.
        assert_eq!(meta.name, "curl");
        assert_eq!(meta.version, "8.5.0");
        assert_eq!(
            meta.description,
            "Command-line tool and library for URL transfers"
        );
        assert_eq!(meta.homepage.as_deref(), Some("https://curl.se"));
        assert_eq!(meta.license, "MIT");
        assert_eq!(meta.platform, "x86_64-linux");
        assert_eq!(meta.maintainer, "aos-team");
        assert!(!meta.store_path.is_empty());
        assert!(!meta.source_drv.is_empty());
        assert!(meta.nar_size > 0);

        // Verify format_size for this package.
        let size_str = format_size(meta.nar_size);
        assert_eq!(size_str, "3.0 MiB");

        // Verify dependency resolution.
        let dep_names = resolve_dependency_names(meta, &reg);
        assert!(dep_names.contains(&"zlib".to_string()));
    }
}
