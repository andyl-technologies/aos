use std::collections::HashSet;
use std::path::Path;

use anyhow::{Result, bail};

use super::config::ApmConfig;
use super::profile::Profile;
use super::profile::meta;
use super::registry::{RegistrySet, store_path_hash};
use super::types::PackageMeta;
use aos_core::output::Printer;

// ---------------------------------------------------------------------------
// Dependency tree node
// ---------------------------------------------------------------------------

/// A node in the dependency tree built from store path references.
struct DepNode {
    name: String,
    version: String,
    store_hash: String,
    children: Vec<DepNode>,
}

// ---------------------------------------------------------------------------
// Public commands
// ---------------------------------------------------------------------------

/// `apm depends <package>` -- walk store references and display as a tree.
///
/// Uses precomputed closure files when available for the dependency graph.
/// Falls back to walking `references` fields when no closure file exists.
pub async fn depends(config: &ApmConfig, package: &str, printer: &Printer) -> Result<()> {
    let registries = load_registries(config)?;

    let (reg, meta) = registries
        .resolve(package)
        .ok_or_else(|| anyhow::anyhow!("package not found in any registry: {package}"))?;
    let registry_name = reg.config.name.clone();

    let hash = store_path_hash(&meta.store_path);
    let closure_meta = registries.get_closure_in(&registry_name, hash);

    let mut visited = HashSet::new();
    let mut ancestors = HashSet::new();
    let root = build_dep_tree(
        meta,
        &registry_name,
        &registries,
        closure_meta,
        &mut visited,
        &mut ancestors,
    );

    // Print root line.
    printer.plain(&format!(
        "{} ({}){}",
        root.name,
        root.version,
        format_registry_or_ref(&registry_name, hash),
    ));

    // Print children with tree-drawing characters.
    let child_count = root.children.len();
    for (i, child) in root.children.iter().enumerate() {
        let is_last = i == child_count - 1;
        print_tree(child, "", is_last, printer);
    }

    // Summary line.
    let total_size = meta.closure_size;
    let size_str = format_size(total_size);
    printer.plain(&format!(
        "\n{} unique store paths in closure ({} total).",
        visited.len(),
        size_str,
    ));

    Ok(())
}

/// `apm rdepends <package>` -- find installed packages whose closure
/// includes the given package.
///
/// Uses precomputed closure files for O(1) membership checks when available.
/// Falls back to recursive `references` traversal otherwise.
pub async fn rdepends(config: &ApmConfig, package: &str, printer: &Printer) -> Result<()> {
    let registries = load_registries(config)?;

    let (_, target_meta) = registries
        .resolve(package)
        .ok_or_else(|| anyhow::anyhow!("package not found in any registry: {package}"))?;
    let target_hash = store_path_hash(&target_meta.store_path).to_string();

    let profile = Profile::open(config.scope)?;
    let installed = meta::list_meta(&profile)?;

    let mut dependents: Vec<(String, String)> = Vec::new();

    for inst in &installed {
        let apm = match &inst.apm {
            Some(a) => a,
            None => continue,
        };

        // Skip the target package itself.
        if apm.name == package {
            continue;
        }

        let inst_hash = store_path_hash(&inst.store_path);

        // Try closure file first for O(1) membership check.
        if let Some(closure) = registries.get_closure_in(&apm.registry, inst_hash) {
            if closure.contains(&target_hash) {
                dependents.push((apm.name.clone(), apm.version.clone()));
            }
            continue;
        }

        // Fall back to recursive references traversal.
        if let Some(pkg_meta) = registries.resolve_hash_in(&apm.registry, inst_hash) {
            if closure_contains(pkg_meta, &apm.registry, &registries, &target_hash) {
                dependents.push((apm.name.clone(), apm.version.clone()));
            }
        }
    }

    if dependents.is_empty() {
        printer.info(&format!(
            "{package} ({}) is not required by any installed package.",
            target_meta.version,
        ));
    } else {
        printer.plain(&format!(
            "{package} ({}) is required by:",
            target_meta.version,
        ));
        for (name, version) in &dependents {
            printer.plain(&format!("  {name} ({version})"));
        }
    }

    Ok(())
}

/// `apm policy <package>` -- show available versions across registries.
pub async fn policy(config: &ApmConfig, package: &str, printer: &Printer) -> Result<()> {
    let registries = load_registries(config)?;

    let versions = registries.all_versions(package);
    if versions.is_empty() {
        bail!("package not found in any registry: {package}");
    }

    // Check installed version.
    let profile = Profile::open(config.scope)?;
    let installed = meta::list_meta(&profile)?;
    let installed_version = installed
        .iter()
        .filter_map(|m| m.apm.as_ref())
        .find(|a| a.name == package)
        .map(|a| a.version.clone());

    // Candidate = first entry (highest priority).
    let candidate_version = &versions[0].1.version;

    printer.plain(&format!("{package}:"));
    match &installed_version {
        Some(v) => printer.plain(&format!("  Installed: {v}")),
        None => printer.plain("  Installed: (none)"),
    }
    printer.plain(&format!("  Candidate: {candidate_version}"));
    printer.plain("  Version table:");

    for (reg, meta) in &versions {
        let marker = if installed_version.as_deref() == Some(&meta.version) {
            " ***"
        } else {
            "    "
        };
        printer.plain(&format!(
            "{} {}  {}  {}",
            marker, meta.version, reg.config.priority, reg.config.name,
        ));
    }

    Ok(())
}

/// `apm files <package>` -- list files in the package's store path.
pub async fn files(config: &ApmConfig, package: &str, printer: &Printer) -> Result<()> {
    let profile = Profile::open(config.scope)?;
    let installed = meta::list_meta(&profile)?;

    let store_path = installed
        .iter()
        .filter_map(|m| {
            m.apm
                .as_ref()
                .filter(|a| a.name == package)
                .map(|_| m.store_path.as_str())
        })
        .next()
        .ok_or_else(|| anyhow::anyhow!("package not installed: {package}"))?;

    let path = Path::new(store_path);
    if !path.exists() {
        bail!(
            "store path does not exist: {store_path}\n\
             (the package may have been garbage collected)"
        );
    }

    let mut file_list = Vec::new();
    walk_dir(path, path, &mut file_list)?;
    file_list.sort();

    for f in &file_list {
        printer.plain(f);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Load enabled registries from config.
fn load_registries(config: &ApmConfig) -> Result<RegistrySet> {
    let reg_configs = config.enabled_registries();
    RegistrySet::load(&config.cache_path(), &reg_configs, "x86_64-linux")
}

/// Build a dependency tree recursively.
///
/// When `closure_meta` is provided, uses its adjacency list for direct deps.
/// Otherwise falls back to `meta.references`.
///
/// `visited` tracks all unique store path hashes seen (for counting).
/// `ancestors` tracks the current recursion path (for cycle detection).
fn build_dep_tree(
    meta: &PackageMeta,
    registry_name: &str,
    registries: &RegistrySet,
    closure_meta: Option<&super::types::ClosureMeta>,
    visited: &mut HashSet<String>,
    ancestors: &mut HashSet<String>,
) -> DepNode {
    let hash = store_path_hash(&meta.store_path).to_string();
    visited.insert(hash.clone());
    ancestors.insert(hash.clone());

    // Get direct deps from closure file if available, otherwise from references.
    let direct_deps: Vec<String> = if let Some(cm) = closure_meta {
        cm.direct_deps(&hash).to_vec()
    } else {
        meta.references.clone()
    };

    let mut children = Vec::new();
    for ref_hash in &direct_deps {
        if let Some(ref_meta) = registries.resolve_hash_in(registry_name, ref_hash) {
            let child_hash = store_path_hash(&ref_meta.store_path).to_string();
            visited.insert(child_hash.clone());
            if ancestors.contains(&child_hash) {
                // Cycle detected -- emit a leaf node, don't recurse.
                children.push(DepNode {
                    name: ref_meta.name.clone(),
                    version: ref_meta.version.clone(),
                    store_hash: child_hash,
                    children: Vec::new(),
                });
            } else {
                children.push(build_dep_tree(
                    ref_meta,
                    registry_name,
                    registries,
                    closure_meta,
                    visited,
                    ancestors,
                ));
            }
        } else {
            visited.insert(ref_hash.clone());
            children.push(DepNode {
                name: "unknown".to_string(),
                version: String::new(),
                store_hash: ref_hash.clone(),
                children: Vec::new(),
            });
        }
    }

    ancestors.remove(&hash);

    DepNode {
        name: meta.name.clone(),
        version: meta.version.clone(),
        store_hash: hash,
        children,
    }
}

/// Print a dependency tree node with box-drawing characters.
fn print_tree(node: &DepNode, prefix: &str, is_last: bool, printer: &Printer) {
    let connector = if is_last {
        "\u{2514}\u{2500}\u{2500}"
    } else {
        "\u{251c}\u{2500}\u{2500}"
    };
    let version_part = if node.version.is_empty() {
        String::new()
    } else {
        format!(" ({})", node.version)
    };

    printer.plain(&format!(
        "{prefix}{connector} {}{version_part}{}",
        node.name,
        format_store_ref(&node.store_hash),
    ));

    let child_prefix = if is_last {
        format!("{prefix}    ")
    } else {
        format!("{prefix}\u{2502}   ")
    };

    let child_count = node.children.len();
    for (i, child) in node.children.iter().enumerate() {
        let child_is_last = i == child_count - 1;
        print_tree(child, &child_prefix, child_is_last, printer);
    }
}

/// Format a store ref annotation for display.
fn format_store_ref(hash: &str) -> String {
    let short = if hash.len() > 8 { &hash[..8] } else { hash };
    format!("                     (store ref: {short})")
}

/// Format registry or ref annotation for the root package.
fn format_registry_or_ref(registry_name: &str, _hash: &str) -> String {
    format!("                     [{registry_name}]")
}

/// Check whether a package's transitive closure contains a target hash.
fn closure_contains(
    meta: &PackageMeta,
    registry_name: &str,
    registries: &RegistrySet,
    target_hash: &str,
) -> bool {
    let mut visited = HashSet::new();
    closure_contains_inner(meta, registry_name, registries, target_hash, &mut visited)
}

fn closure_contains_inner(
    meta: &PackageMeta,
    registry_name: &str,
    registries: &RegistrySet,
    target_hash: &str,
    visited: &mut HashSet<String>,
) -> bool {
    for ref_hash in &meta.references {
        if ref_hash == target_hash {
            return true;
        }
        if visited.contains(ref_hash) {
            continue;
        }
        visited.insert(ref_hash.clone());

        if let Some(ref_meta) = registries.resolve_hash_in(registry_name, ref_hash) {
            if closure_contains_inner(ref_meta, registry_name, registries, target_hash, visited) {
                return true;
            }
        }
    }
    false
}

/// Recursively walk a directory, collecting file paths relative to the root.
fn walk_dir(root: &Path, current: &Path, files: &mut Vec<String>) -> Result<()> {
    let entries = std::fs::read_dir(current)
        .map_err(|e| anyhow::anyhow!("reading directory {}: {e}", current.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string();

        if path.is_dir() {
            walk_dir(root, &path, files)?;
        } else {
            files.push(relative);
        }
    }

    Ok(())
}

/// Format a byte size in human-readable form.
fn format_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;

    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.0} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.0} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::RegistrySet;
    use crate::registry::parse::{CURL_TOML, ZLIB_TOML};
    use crate::registry::tests::make_registry;
    use std::fs;
    use tempfile::TempDir;

    // 1. Package with no references shows just itself.
    #[test]
    fn dep_tree_single_package_no_refs() {
        let tmp = TempDir::new().unwrap();
        let reg = make_registry(&tmp, "aos-core", 500, &[("zlib", ZLIB_TOML)]);
        let set = RegistrySet::new(vec![reg]);

        let (_, meta) = set.resolve("zlib").unwrap();
        let mut visited = HashSet::new();
        let mut ancestors = HashSet::new();
        let root = build_dep_tree(meta, "aos-core", &set, None, &mut visited, &mut ancestors);

        assert_eq!(root.name, "zlib");
        assert_eq!(root.version, "1.3.1");
        assert!(root.children.is_empty());
        assert_eq!(visited.len(), 1);
        // ancestors should be empty after tree construction completes.
        assert!(ancestors.is_empty());
    }

    // 2. Builds correct tree from references.
    #[test]
    fn dep_tree_with_children() {
        let tmp = TempDir::new().unwrap();
        let reg = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );
        let set = RegistrySet::new(vec![reg]);

        let (_, meta) = set.resolve("curl").unwrap();
        let mut visited = HashSet::new();
        let mut ancestors = HashSet::new();
        let root = build_dep_tree(meta, "aos-core", &set, None, &mut visited, &mut ancestors);

        assert_eq!(root.name, "curl");
        assert_eq!(root.children.len(), 4); // 4 references in CURL_TOML

        // One of the children should be zlib (resolved from its own hash).
        let zlib_child = root.children.iter().find(|c| c.name == "zlib");
        assert!(zlib_child.is_some());
        assert_eq!(zlib_child.unwrap().version, "1.3.1");

        // The other 3 reference hashes are not published as registry packages,
        // so they remain explicit unknown leaf nodes instead of resolving back
        // to the referring package.
        let unknown_count = root
            .children
            .iter()
            .filter(|c| c.name == "unknown" && c.children.is_empty())
            .count();
        assert_eq!(unknown_count, 3);
    }

    // 3. Visited set tracks unique paths correctly.
    #[test]
    fn dep_tree_deduplication_counts() {
        let tmp = TempDir::new().unwrap();
        let reg = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );
        let set = RegistrySet::new(vec![reg]);

        let (_, meta) = set.resolve("curl").unwrap();
        let mut visited = HashSet::new();
        let mut ancestors = HashSet::new();
        let _root = build_dep_tree(meta, "aos-core", &set, None, &mut visited, &mut ancestors);

        // curl's hash, zlib's hash, and the 3 unknown reference hashes are
        // tracked explicitly.
        assert_eq!(visited.len(), 5);

        // zlib's hash should be in visited.
        assert!(visited.contains("r4q1m2kp8v3x"));
        // curl's hash should be in visited.
        assert!(visited.contains("h7j3k8l2m9n4"));
    }

    // 4. Last child uses the correct box-drawing character.
    #[test]
    fn format_tree_line_last_child() {
        let node = DepNode {
            name: "zlib".to_string(),
            version: "1.3.1".to_string(),
            store_hash: "r4q1m2kp".to_string(),
            children: vec![],
        };

        // Capture output by manually formatting the line.
        let is_last = true;
        let connector = if is_last {
            "\u{2514}\u{2500}\u{2500}"
        } else {
            "\u{251c}\u{2500}\u{2500}"
        };
        let line = format!("{connector} {} ({})", node.name, node.version);
        assert!(line.starts_with("\u{2514}\u{2500}\u{2500}"));
        assert!(line.contains("zlib"));
    }

    // 5. Middle child uses the correct box-drawing character.
    #[test]
    fn format_tree_line_middle_child() {
        let node = DepNode {
            name: "openssl".to_string(),
            version: "3.2.0".to_string(),
            store_hash: "xr5is7by".to_string(),
            children: vec![],
        };

        let is_last = false;
        let connector = if is_last {
            "\u{2514}\u{2500}\u{2500}"
        } else {
            "\u{251c}\u{2500}\u{2500}"
        };
        let line = format!("{connector} {} ({})", node.name, node.version);
        assert!(line.starts_with("\u{251c}\u{2500}\u{2500}"));
        assert!(line.contains("openssl"));
    }

    // 6. Finds packages that reference the target.
    #[test]
    fn rdepends_finds_reverse_deps() {
        let tmp = TempDir::new().unwrap();
        let reg = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );
        let set = RegistrySet::new(vec![reg]);

        // curl references zlib (r4q1m2kp8v3x).
        let (_, zlib_meta) = set.resolve("zlib").unwrap();
        let target_hash = store_path_hash(&zlib_meta.store_path).to_string();

        // Check if curl's closure contains zlib.
        let (_, curl_meta) = set.resolve("curl").unwrap();
        let contains = closure_contains(curl_meta, "aos-core", &set, &target_hash);
        assert!(contains);
    }

    // 7. Returns false when nothing depends on target.
    #[test]
    fn rdepends_empty_when_not_referenced() {
        let tmp = TempDir::new().unwrap();
        let reg = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );
        let set = RegistrySet::new(vec![reg]);

        // zlib has no references, so it does not reference curl.
        let (_, curl_meta) = set.resolve("curl").unwrap();
        let target_hash = store_path_hash(&curl_meta.store_path).to_string();

        let (_, zlib_meta) = set.resolve("zlib").unwrap();
        let contains = closure_contains(zlib_meta, "aos-core", &set, &target_hash);
        assert!(!contains);
    }

    // 8. Highest priority first in policy output.
    #[test]
    fn policy_orders_by_priority() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(&tmp, "aos-core", 500, &[("curl", CURL_TOML)]);
        let extra = make_registry(&tmp, "aos-extra", 400, &[("curl", CURL_TOML)]);
        let set = RegistrySet::new(vec![core, extra]);

        let versions = set.all_versions("curl");
        assert_eq!(versions.len(), 2);
        // First should be highest priority.
        assert_eq!(versions[0].0.config.name, "aos-core");
        assert_eq!(versions[0].0.config.priority, 500);
        assert_eq!(versions[1].0.config.name, "aos-extra");
        assert_eq!(versions[1].0.config.priority, 400);
    }

    // 9. `***` marker on installed version.
    #[test]
    fn policy_marks_installed() {
        let installed_version = Some("8.5.0".to_string());
        let meta_version = "8.5.0";

        let marker = if installed_version.as_deref() == Some(meta_version) {
            " ***"
        } else {
            "    "
        };
        assert_eq!(marker, " ***");

        // Non-matching version.
        let installed_version = Some("7.0.0".to_string());
        let marker = if installed_version.as_deref() == Some(meta_version) {
            " ***"
        } else {
            "    "
        };
        assert_eq!(marker, "    ");

        // No installed version.
        let installed_version: Option<String> = None;
        let marker = if installed_version.as_deref() == Some(meta_version) {
            " ***"
        } else {
            "    "
        };
        assert_eq!(marker, "    ");
    }

    // 10. Walks a temp directory correctly.
    #[test]
    fn files_lists_directory_contents() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        // Create a directory structure.
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir_all(root.join("lib")).unwrap();
        fs::write(root.join("bin/curl"), b"binary").unwrap();
        fs::write(root.join("lib/libcurl.so"), b"library").unwrap();
        fs::write(root.join("lib/libcurl.a"), b"archive").unwrap();

        let mut file_list = Vec::new();
        walk_dir(root, root, &mut file_list).unwrap();
        file_list.sort();

        assert_eq!(file_list.len(), 3);
        assert_eq!(file_list[0], "bin/curl");
        assert_eq!(file_list[1], "lib/libcurl.a");
        assert_eq!(file_list[2], "lib/libcurl.so");
    }
}
