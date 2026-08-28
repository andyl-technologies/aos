//! Dependency-inspection commands: `apm depends`, `rdepends`, `policy`,
//! and `files`.
//!
//! - **`depends`**: render a package's dependency graph as a tree. For
//!   registry packages the graph comes from precomputed closure files
//!   (falling back to `references` fields); for installed-only packages it
//!   is walked live from the store via `nix-store -q --references`.
//! - **`rdepends`**: the reverse query — which *installed* packages have the
//!   target anywhere in their closure. Uses closure files for O(1)
//!   membership, then registry reference traversal, then a live
//!   `nix-store -qR` walk as last resort.
//! - **`policy`**: apt-style version table — installed version(s),
//!   candidate, and every available version across registries by priority,
//!   including installed versions no longer available anywhere.
//! - **`files`**: list the files inside an installed package's store path.
//!
//! All tree builders deduplicate by store-path hash and break reference
//! cycles by emitting a leaf node instead of recursing.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::path::Path;

use anyhow::{Context, Result, bail};

use super::config::ApmConfig;
use super::profile::Profile;
use super::profile::meta;
use super::registry::{RegistrySet, store_path_hash};
use super::store;
use super::types::{InstalledMeta, PackageMeta};
use aos_core::output::{OutputMode, Printer};

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

impl DepNode {
    /// Recursively render the node for JSON output mode.
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": &self.name,
            "version": &self.version,
            "store_hash": &self.store_hash,
            "children": self.children.iter().map(DepNode::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Identity of one installed package, indexed by store-path hash when
/// building installed-only dependency trees.
#[derive(Clone)]
struct InstalledPackageRef {
    name: String,
    version: String,
    registry: String,
    store_path: String,
}

// ---------------------------------------------------------------------------
// Public commands
// ---------------------------------------------------------------------------

/// `apm depends <package>` -- walk store references and display as a tree.
///
/// Uses precomputed closure files when available for the dependency graph.
/// Falls back to walking `references` fields when no closure file exists.
/// A package that is installed (or absent from every registry) is rendered
/// from the live store's reference graph instead.
///
/// # Errors
///
/// Returns an error if registry caches or profile metadata cannot be
/// loaded, if `package` is neither installed nor in any registry, or if a
/// live `nix-store` reference query fails.
pub async fn depends(config: &ApmConfig, package: &str, printer: &Printer) -> Result<()> {
    let registries = load_registries(config)?;
    crate::query::warn_unsynced_scope(config, printer);
    let profile = Profile::open_readonly(config.scope);
    let installed = meta::list_meta(&profile)?;

    if has_installed_package(package, &installed) {
        return depends_installed(package, &installed, printer).await;
    }

    let Some((reg, meta)) = registries.resolve(package) else {
        return depends_installed(package, &installed, printer).await;
    };

    let registry_name = reg.config.name.clone();
    let hash = store_path_hash(&meta.store_path);
    let store_graph = registries
        .store_map_in(&registry_name)
        .filter(|m| m.is_present());

    let mut visited = HashSet::new();
    let mut ancestors = HashSet::new();
    let root = build_dep_tree(
        meta,
        &registry_name,
        &registries,
        store_graph,
        &mut visited,
        &mut ancestors,
    );

    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "package": package,
            "registry": registry_name,
            "installed": false,
            "tree": root.to_json(),
            "unique_store_paths": visited.len(),
            "closure_size": meta.closure_size,
        }));
        return Ok(());
    }

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
///
/// The target may be matched by any installed version's store hash; when
/// the package is not installed, the registry candidate's hash is used.
///
/// # Errors
///
/// Returns an error if registry caches or profile metadata cannot be
/// loaded, or if `package` is neither installed nor in any registry.
pub async fn rdepends(config: &ApmConfig, package: &str, printer: &Printer) -> Result<()> {
    let registries = load_registries(config)?;
    crate::query::warn_unsynced_scope(config, printer);

    let profile = Profile::open_readonly(config.scope);
    let installed = meta::list_meta(&profile)?;
    let (target_hashes, target_versions) =
        rdepends_target_hashes(package, &registries, &installed)?;

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

        // Walk the store/ graph edges when present (O(closure) membership).
        // Only treat the graph as authoritative for packages whose store
        // record actually exists: if `inst_hash` is absent (e.g. its record
        // was pruned by `apr unpublish` while the package is still installed),
        // fall through to the resolve/local-closure fallbacks below instead of
        // silently reporting no dependents.
        if let Some(graph) = registries
            .store_map_in(&apm.registry)
            .filter(|m| m.is_present())
            .filter(|m| m.get(inst_hash).is_some())
        {
            let mut seen = HashSet::new();
            let mut stack = vec![inst_hash.to_string()];
            let mut found = false;
            while let Some(h) = stack.pop() {
                if !seen.insert(h.clone()) {
                    continue;
                }
                if target_hashes.contains(&h) {
                    found = true;
                    break;
                }
                stack.extend(graph.direct_deps(&h));
            }
            if found {
                dependents.push((apm.name.clone(), apm.version.clone()));
            }
            continue;
        }

        // Fall back to recursive references traversal.
        if let Some(pkg_meta) = registries.resolve_hash_in(&apm.registry, inst_hash) {
            if closure_contains_any(pkg_meta, &apm.registry, &registries, &target_hashes) {
                dependents.push((apm.name.clone(), apm.version.clone()));
            }
            continue;
        }

        if installed_closure_contains_any(inst, &target_hashes)
            .await
            .unwrap_or(false)
        {
            dependents.push((apm.name.clone(), apm.version.clone()));
        }
    }
    dependents.sort();

    if printer.mode() == OutputMode::Json {
        let dependents_json = dependents
            .iter()
            .map(|(name, version)| {
                serde_json::json!({
                    "name": name,
                    "version": version,
                })
            })
            .collect::<Vec<_>>();
        let mut target_hashes = target_hashes.into_iter().collect::<Vec<_>>();
        target_hashes.sort();
        printer.json(&serde_json::json!({
            "package": package,
            "target_versions": target_versions,
            "target_hashes": target_hashes,
            "dependents": dependents_json,
        }));
        return Ok(());
    }

    if dependents.is_empty() {
        printer.info(&format!(
            "{package} ({target_versions}) is not required by any installed package.",
        ));
    } else {
        printer.plain(&format!("{package} ({target_versions}) is required by:"));
        for (name, version) in &dependents {
            printer.plain(&format!("  {name} ({version})"));
        }
    }

    Ok(())
}

/// `apm policy <package>` -- show available versions across registries.
///
/// Prints the installed version(s), the install candidate (the highest
/// priority registry's entry), the full version table, and any installed
/// versions that are no longer available from any registry.
///
/// # Errors
///
/// Returns an error if registry caches or profile metadata cannot be
/// loaded, or if `package` is neither installed nor in any registry.
pub async fn policy(config: &ApmConfig, package: &str, printer: &Printer) -> Result<()> {
    let registries = load_registries(config)?;
    crate::query::warn_unsynced_scope(config, printer);

    // Check installed version.
    let profile = Profile::open_readonly(config.scope);
    let installed = meta::list_meta(&profile)?;
    let installed_version = policy_installed_versions(package, &installed);
    let versions = registries.all_versions(package);
    if versions.is_empty() && installed_version.is_none() {
        bail!("package not found in any registry: {package}");
    }
    let unavailable_installed = policy_unavailable_installed(package, &installed, &versions);

    // Candidate = first entry (highest priority).
    let candidate_version = versions.first().map(|(_, meta)| meta.version.as_str());

    if printer.mode() == OutputMode::Json {
        let versions_json = versions
            .iter()
            .map(|(reg, meta)| {
                serde_json::json!({
                    "version": &meta.version,
                    "priority": reg.config.priority,
                    "registry": &reg.config.name,
                    "installed": policy_candidate_is_installed(
                        package,
                        &reg.config.name,
                        meta,
                        &installed,
                    ),
                })
            })
            .collect::<Vec<_>>();
        let unavailable_json = unavailable_installed
            .iter()
            .map(|(version, registry)| {
                serde_json::json!({
                    "version": version,
                    "registry": registry,
                })
            })
            .collect::<Vec<_>>();

        printer.json(&serde_json::json!({
            "package": package,
            "installed": installed_version,
            "candidate": candidate_version,
            "versions": versions_json,
            "unavailable_installed": unavailable_json,
        }));
        return Ok(());
    }

    let candidate_version = candidate_version.unwrap_or("(none)");

    printer.plain(&format!("{package}:"));
    match &installed_version {
        Some(v) => printer.plain(&format!("  Installed: {v}")),
        None => printer.plain("  Installed: (none)"),
    }
    printer.plain(&format!("  Candidate: {candidate_version}"));
    printer.plain("  Version table:");

    for (reg, meta) in &versions {
        let marker = if policy_candidate_is_installed(package, &reg.config.name, meta, &installed) {
            " ***"
        } else {
            "    "
        };
        printer.plain(&format!(
            "{} {}  {}  {}",
            marker, meta.version, reg.config.priority, reg.config.name,
        ));
    }

    for (version, registry_name) in &unavailable_installed {
        printer.plain(&format!(
            " *** {version}  -  {registry_name} (installed, unavailable)"
        ));
    }

    Ok(())
}

/// `apm files <package>` -- list files in the package's store path.
///
/// # Errors
///
/// Returns an error if `package` is not installed, the store path no longer
/// exists (e.g. garbage collected), or the directory walk fails.
pub async fn files(config: &ApmConfig, package: &str, printer: &Printer) -> Result<()> {
    let profile = Profile::open_readonly(config.scope);
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

    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!(file_list));
        return Ok(());
    }

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

/// Collect the store-path hashes identifying the rdepends target: every
/// installed version's hash, or (when not installed) the registry
/// candidate's hash. Also returns a display string of the version(s).
fn rdepends_target_hashes(
    package: &str,
    registries: &RegistrySet,
    installed: &[InstalledMeta],
) -> Result<(HashSet<String>, String)> {
    let mut hashes = HashSet::new();
    let mut versions = BTreeSet::new();

    for inst in installed {
        let Some(apm) = inst.apm.as_ref() else {
            continue;
        };
        if apm.name != package {
            continue;
        }

        hashes.insert(store_path_hash(&inst.store_path).to_string());
        versions.insert(apm.version.clone());
    }

    if !hashes.is_empty() {
        return Ok((hashes, versions.into_iter().collect::<Vec<_>>().join(", ")));
    }

    let (_, target_meta) = registries
        .resolve(package)
        .ok_or_else(|| anyhow::anyhow!("package not found in any registry: {package}"))?;
    hashes.insert(store_path_hash(&target_meta.store_path).to_string());
    Ok((hashes, target_meta.version.clone()))
}

/// `apm depends` for an installed package: build the tree from the live
/// store's reference graph, restricted to installed packages (unknown refs
/// become `unknown` leaves).
async fn depends_installed(
    package: &str,
    installed: &[InstalledMeta],
    printer: &Printer,
) -> Result<()> {
    let installed_by_hash = installed_apm_by_hash(installed);
    let root = installed_by_hash
        .values()
        .find(|entry| entry.name == package)
        .cloned()
        .with_context(|| {
            format!("package not found in any registry or installed profile: {package}")
        })?;
    let root_hash = store_path_hash(&root.store_path).to_string();
    let refs_by_hash = installed_direct_refs(&root_hash, &installed_by_hash).await?;

    let mut visited = HashSet::new();
    let mut ancestors = HashSet::new();
    let tree = build_installed_dep_tree(
        &root_hash,
        &refs_by_hash,
        &installed_by_hash,
        &mut visited,
        &mut ancestors,
    );

    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "package": package,
            "registry": &root.registry,
            "installed": true,
            "tree": tree.to_json(),
            "unique_store_paths": visited.len(),
        }));
        return Ok(());
    }

    printer.plain(&format!(
        "{} ({}){}",
        tree.name,
        tree.version,
        format_installed_registry_ref(&root.registry)
    ));

    let child_count = tree.children.len();
    for (i, child) in tree.children.iter().enumerate() {
        let is_last = i == child_count - 1;
        print_tree(child, "", is_last, printer);
    }

    printer.plain(&format!(
        "\n{} unique store paths in installed dependency tree.",
        visited.len(),
    ));

    Ok(())
}

/// BFS over `nix-store -q --references` starting at `root_hash`, collecting
/// each reachable installed package's direct reference hashes. Only hashes
/// belonging to installed packages are expanded further.
async fn installed_direct_refs(
    root_hash: &str,
    installed_by_hash: &HashMap<String, InstalledPackageRef>,
) -> Result<HashMap<String, Vec<String>>> {
    let mut refs_by_hash = HashMap::new();
    let mut queued = HashSet::from([root_hash.to_string()]);
    let mut queue = VecDeque::from([root_hash.to_string()]);

    while let Some(hash) = queue.pop_front() {
        let Some(installed) = installed_by_hash.get(&hash) else {
            continue;
        };

        let refs = store::direct_references(&installed.store_path).await?;
        let mut ref_hashes = Vec::new();
        for ref_hash in refs
            .iter()
            .map(|path| store_path_hash(path).to_string())
            .filter(|ref_hash| ref_hash != &hash)
        {
            if installed_by_hash.contains_key(&ref_hash) && queued.insert(ref_hash.clone()) {
                queue.push_back(ref_hash.clone());
            }
            ref_hashes.push(ref_hash);
        }
        refs_by_hash.insert(hash.clone(), ref_hashes);
    }

    Ok(refs_by_hash)
}

/// Whether an installed path's live closure (`nix-store -qR`) contains any
/// of the target hashes — the last-resort rdepends membership check.
async fn installed_closure_contains_any(
    installed: &InstalledMeta,
    target_hashes: &HashSet<String>,
) -> Result<bool> {
    let paths = store::closure_paths(&installed.store_path).await?;
    Ok(paths
        .iter()
        .map(|path| store_path_hash(path))
        .any(|hash| target_hashes.contains(hash)))
}

/// Index installed packages (those with APM metadata) by store-path hash.
fn installed_apm_by_hash(installed: &[InstalledMeta]) -> HashMap<String, InstalledPackageRef> {
    installed
        .iter()
        .filter_map(|inst| {
            let apm = inst.apm.as_ref()?;
            Some((
                store_path_hash(&inst.store_path).to_string(),
                InstalledPackageRef {
                    name: apm.name.clone(),
                    version: apm.version.clone(),
                    registry: apm.registry.clone(),
                    store_path: inst.store_path.clone(),
                },
            ))
        })
        .collect()
}

/// Whether any profile metadata entry names this package.
fn has_installed_package(package: &str, installed: &[InstalledMeta]) -> bool {
    installed.iter().any(|inst| {
        inst.apm
            .as_ref()
            .map(|apm| apm.name == package)
            .unwrap_or(false)
    })
}

/// Comma-joined sorted list of installed versions of `package`, if any.
fn policy_installed_versions(package: &str, installed: &[InstalledMeta]) -> Option<String> {
    let mut versions = BTreeSet::new();

    for inst in installed {
        let Some(apm) = inst.apm.as_ref() else {
            continue;
        };
        if apm.name == package {
            versions.insert(apm.version.clone());
        }
    }

    if versions.is_empty() {
        None
    } else {
        Some(versions.into_iter().collect::<Vec<_>>().join(", "))
    }
}

/// Recursively build the installed-only dependency tree from precollected
/// direct references. `ancestors` is the DFS path used to cut cycles
/// (cycle members become leaves); hashes without installed metadata render
/// as `unknown` nodes.
fn build_installed_dep_tree(
    hash: &str,
    refs_by_hash: &HashMap<String, Vec<String>>,
    installed_by_hash: &HashMap<String, InstalledPackageRef>,
    visited: &mut HashSet<String>,
    ancestors: &mut HashSet<String>,
) -> DepNode {
    visited.insert(hash.to_string());
    ancestors.insert(hash.to_string());

    let mut children = Vec::new();
    for ref_hash in refs_by_hash.get(hash).into_iter().flatten() {
        visited.insert(ref_hash.clone());
        if ancestors.contains(ref_hash) {
            children.push(installed_dep_leaf(ref_hash, installed_by_hash));
        } else if installed_by_hash.contains_key(ref_hash) {
            children.push(build_installed_dep_tree(
                ref_hash,
                refs_by_hash,
                installed_by_hash,
                visited,
                ancestors,
            ));
        } else {
            children.push(DepNode {
                name: "unknown".to_string(),
                version: String::new(),
                store_hash: ref_hash.clone(),
                children: Vec::new(),
            });
        }
    }

    ancestors.remove(hash);

    let Some(installed) = installed_by_hash.get(hash) else {
        return DepNode {
            name: "unknown".to_string(),
            version: String::new(),
            store_hash: hash.to_string(),
            children,
        };
    };

    DepNode {
        name: installed.name.clone(),
        version: installed.version.clone(),
        store_hash: hash.to_string(),
        children,
    }
}

/// Childless tree node for `hash`, named from installed metadata when known.
fn installed_dep_leaf(
    hash: &str,
    installed_by_hash: &HashMap<String, InstalledPackageRef>,
) -> DepNode {
    if let Some(installed) = installed_by_hash.get(hash) {
        DepNode {
            name: installed.name.clone(),
            version: installed.version.clone(),
            store_hash: hash.to_string(),
            children: Vec::new(),
        }
    } else {
        DepNode {
            name: "unknown".to_string(),
            version: String::new(),
            store_hash: hash.to_string(),
            children: Vec::new(),
        }
    }
}

/// Whether a registry candidate's exact store path is what is installed
/// (same name, registry, and store-path hash).
fn policy_candidate_is_installed(
    package: &str,
    registry_name: &str,
    candidate: &PackageMeta,
    installed: &[InstalledMeta],
) -> bool {
    let candidate_hash = store_path_hash(&candidate.store_path);

    installed.iter().any(|inst| {
        let Some(apm) = inst.apm.as_ref() else {
            return false;
        };
        apm.name == package
            && apm.registry == registry_name
            && store_path_hash(&inst.store_path) == candidate_hash
    })
}

/// Installed `(version, registry)` pairs of `package` whose store paths are
/// no longer offered by any registry (e.g. superseded or de-listed).
fn policy_unavailable_installed(
    package: &str,
    installed: &[InstalledMeta],
    versions: &[(&super::registry::Registry, &PackageMeta)],
) -> Vec<(String, String)> {
    let available_sources: HashSet<(String, String)> = versions
        .iter()
        .map(|(reg, meta)| {
            (
                reg.config.name.clone(),
                store_path_hash(&meta.store_path).to_string(),
            )
        })
        .collect();
    let mut unavailable = BTreeSet::new();

    for inst in installed {
        let Some(apm) = inst.apm.as_ref() else {
            continue;
        };
        if apm.name != package {
            continue;
        }

        let installed_source = (
            apm.registry.clone(),
            store_path_hash(&inst.store_path).to_string(),
        );
        if !available_sources.contains(&installed_source) {
            unavailable.insert((apm.version.clone(), apm.registry.clone()));
        }
    }

    unavailable.into_iter().collect()
}

/// Build a dependency tree recursively.
///
/// When a `store/` graph is provided, uses its dependency edges for direct
/// deps. Otherwise falls back to `meta.references` (legacy registries).
///
/// `visited` tracks all unique store path hashes seen (for counting).
/// `ancestors` tracks the current recursion path (for cycle detection).
fn build_dep_tree(
    meta: &PackageMeta,
    registry_name: &str,
    registries: &RegistrySet,
    store_graph: Option<&crate::registry::store::StoreMap>,
    visited: &mut HashSet<String>,
    ancestors: &mut HashSet<String>,
) -> DepNode {
    let hash = store_path_hash(&meta.store_path).to_string();
    visited.insert(hash.clone());
    ancestors.insert(hash.clone());

    // Get direct deps from the store/ graph if available, else from references.
    let direct_deps: Vec<String> = match store_graph {
        Some(graph) => graph.direct_deps(&hash),
        None => meta.references.clone(),
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
                    store_graph,
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

/// Format the root annotation for an installed package's tree.
fn format_installed_registry_ref(registry_name: &str) -> String {
    format!("                     [{registry_name}, installed]")
}

/// Check whether a package's transitive closure contains a target hash.
fn closure_contains_any(
    meta: &PackageMeta,
    registry_name: &str,
    registries: &RegistrySet,
    target_hashes: &HashSet<String>,
) -> bool {
    let mut visited = HashSet::new();
    closure_contains_any_inner(meta, registry_name, registries, target_hashes, &mut visited)
}

/// DFS over registry `references`, short-circuiting on a target hit;
/// `visited` prevents revisiting shared subgraphs.
fn closure_contains_any_inner(
    meta: &PackageMeta,
    registry_name: &str,
    registries: &RegistrySet,
    target_hashes: &HashSet<String>,
    visited: &mut HashSet<String>,
) -> bool {
    for ref_hash in &meta.references {
        if target_hashes.contains(ref_hash) {
            return true;
        }
        if visited.contains(ref_hash) {
            continue;
        }
        visited.insert(ref_hash.clone());

        if let Some(ref_meta) = registries.resolve_hash_in(registry_name, ref_hash) {
            if closure_contains_any_inner(
                ref_meta,
                registry_name,
                registries,
                target_hashes,
                visited,
            ) {
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

        let file_type = entry
            .file_type()
            .with_context(|| format!("reading file type for {}", path.display()))?;

        if file_type.is_dir() {
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
        let target_hashes = HashSet::from([target_hash]);
        let contains = closure_contains_any(curl_meta, "aos-core", &set, &target_hashes);
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
        let target_hashes = HashSet::from([target_hash]);
        let contains = closure_contains_any(zlib_meta, "aos-core", &set, &target_hashes);
        assert!(!contains);
    }

    #[test]
    fn rdepends_target_prefers_installed_lower_priority_duplicate() {
        let tmp = TempDir::new().unwrap();
        let high_tool_toml = r#"
[package]
name = "priority-tool"
description = "high priority tool"
license = "MIT"
maintainer = "test"

[[versions]]
version = "2.0.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh-priority-tool-2.0.0"
nar_hash = "sha256:high"
nar_size = 1
closure_size = 1
source_drv = ""
source_nar_hash = ""
references = []
"#;
        let low_tool_toml = r#"
[package]
name = "priority-tool"
description = "low priority tool"
license = "MIT"
maintainer = "test"

[[versions]]
version = "9.0.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/llllllllllllllllllllllllllllllll-priority-tool-9.0.0"
nar_hash = "sha256:low"
nar_size = 1
closure_size = 1
source_drv = ""
source_nar_hash = ""
references = []
"#;
        let low_client_toml = r#"
[package]
name = "priority-client"
description = "low priority client"
license = "MIT"
maintainer = "test"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/cccccccccccccccccccccccccccccccc-priority-client-1.0.0"
nar_hash = "sha256:client"
nar_size = 1
closure_size = 2
source_drv = ""
source_nar_hash = ""
references = ["llllllllllllllllllllllllllllllll"]
"#;
        let high = make_registry(
            &tmp,
            "high-priority",
            900,
            &[("priority-tool", high_tool_toml)],
        );
        let low = make_registry(
            &tmp,
            "low-priority",
            100,
            &[
                ("priority-tool", low_tool_toml),
                ("priority-client", low_client_toml),
            ],
        );
        let set = RegistrySet::new(vec![high, low]);
        let (_, latest) = set.resolve("priority-tool").unwrap();
        assert_eq!(latest.version, "2.0.0");

        let installed = vec![InstalledMeta {
            store_path: "/nix/store/llllllllllllllllllllllllllllllll-priority-tool-9.0.0".into(),
            pushed_at: 1707800000,
            pushed_by: "apm".into(),
            expires_at: None,
            is_root: true,
            last_accessed: 1707800000,
            access_count: 0,
            apm: Some(crate::types::ApmMeta {
                name: "priority-tool".into(),
                version: "9.0.0".into(),
                explicit: true,
                registry: "low-priority".into(),
                installed_at: "2026-06-09T00:00:00Z".into(),
                held: false,
                source_drv: String::new(),
                source_nar_hash: String::new(),
                expose: None,
                expose_artifact: None,
                config_module: None,
                documentation: None,
                permissions: Default::default(),
                bpf_lsm: None,
                attestation: Default::default(),
            }),
        }];

        let (target_hashes, target_versions) =
            rdepends_target_hashes("priority-tool", &set, &installed).unwrap();
        assert_eq!(target_versions, "9.0.0");
        assert!(target_hashes.contains("llllllllllllllllllllllllllllllll"));
        assert!(!target_hashes.contains("hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh"));

        let low_client = set
            .resolve_hash_in("low-priority", "cccccccccccccccccccccccccccccccc")
            .unwrap();
        assert!(closure_contains_any(
            low_client,
            "low-priority",
            &set,
            &target_hashes
        ));
    }

    #[test]
    fn depends_prefers_installed_package_name() {
        let installed = vec![InstalledMeta {
            store_path: "/nix/store/llllllllllllllllllllllllllllllll-priority-tool-9.0.0".into(),
            pushed_at: 1707800000,
            pushed_by: "apm".into(),
            expires_at: None,
            is_root: true,
            last_accessed: 1707800000,
            access_count: 0,
            apm: Some(crate::types::ApmMeta {
                name: "priority-tool".into(),
                version: "9.0.0".into(),
                explicit: true,
                registry: "low-priority".into(),
                installed_at: "2026-06-09T00:00:00Z".into(),
                held: false,
                source_drv: String::new(),
                source_nar_hash: String::new(),
                expose: None,
                expose_artifact: None,
                config_module: None,
                documentation: None,
                permissions: Default::default(),
                bpf_lsm: None,
                attestation: Default::default(),
            }),
        }];

        assert!(has_installed_package("priority-tool", &installed));
        assert!(!has_installed_package("other-tool", &installed));
    }

    #[test]
    fn policy_marker_uses_installed_registry_and_hash_for_same_version_duplicates() {
        let installed = vec![InstalledMeta {
            store_path: "/nix/store/llllllllllllllllllllllllllllllll-same-version-tool-1.0.0"
                .into(),
            pushed_at: 1707800000,
            pushed_by: "apm".into(),
            expires_at: None,
            is_root: true,
            last_accessed: 1707800000,
            access_count: 0,
            apm: Some(crate::types::ApmMeta {
                name: "same-version-tool".into(),
                version: "1.0.0".into(),
                explicit: true,
                registry: "low-priority".into(),
                installed_at: "2026-06-09T00:00:00Z".into(),
                held: false,
                source_drv: String::new(),
                source_nar_hash: String::new(),
                expose: None,
                expose_artifact: None,
                config_module: None,
                documentation: None,
                permissions: Default::default(),
                bpf_lsm: None,
                attestation: Default::default(),
            }),
        }];
        let high_candidate = PackageMeta {
            name: "same-version-tool".into(),
            version: "1.0.0".into(),
            platform: "x86_64-linux".into(),
            store_path: "/nix/store/hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh-same-version-tool-1.0.0"
                .into(),
            nar_hash: "sha256:high".into(),
            nar_size: 1,
            closure_size: 1,
            source_drv: String::new(),
            source_nar_hash: String::new(),
            references: Vec::new(),
            description: "high priority duplicate".into(),
            homepage: None,
            license: "MIT".into(),
            maintainer: "test".into(),
            images: Vec::new(),
            sysroot: false,
            previous: None,
            min_format: None,
            requires_features: Vec::new(),
            expose: None,
            expose_artifact: None,
            config_module: None,
            documentation: None,
            permissions: Default::default(),
            bpf_lsm: None,
            attestation: Default::default(),
        };
        let low_candidate = PackageMeta {
            name: "same-version-tool".into(),
            version: "1.0.0".into(),
            platform: "x86_64-linux".into(),
            store_path: "/nix/store/llllllllllllllllllllllllllllllll-same-version-tool-1.0.0"
                .into(),
            nar_hash: "sha256:low".into(),
            nar_size: 1,
            closure_size: 1,
            source_drv: String::new(),
            source_nar_hash: String::new(),
            references: Vec::new(),
            description: "low priority duplicate".into(),
            homepage: None,
            license: "MIT".into(),
            maintainer: "test".into(),
            images: Vec::new(),
            sysroot: false,
            previous: None,
            min_format: None,
            requires_features: Vec::new(),
            expose: None,
            expose_artifact: None,
            config_module: None,
            documentation: None,
            permissions: Default::default(),
            bpf_lsm: None,
            attestation: Default::default(),
        };

        assert_eq!(
            policy_installed_versions("same-version-tool", &installed).as_deref(),
            Some("1.0.0")
        );
        assert!(!policy_candidate_is_installed(
            "same-version-tool",
            "high-priority",
            &high_candidate,
            &installed,
        ));
        assert!(policy_candidate_is_installed(
            "same-version-tool",
            "low-priority",
            &low_candidate,
            &installed,
        ));
    }

    #[test]
    fn policy_lists_installed_versions_missing_from_registry() {
        let tmp = TempDir::new().unwrap();
        let tool_toml = r#"
[package]
name = "retired-tool"
description = "tool with retired old version"
license = "MIT"
maintainer = "test"

[[versions]]
version = "2.0.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn-retired-tool-2.0.0"
nar_hash = "sha256:new"
nar_size = 1
closure_size = 1
source_drv = ""
source_nar_hash = ""
references = []
"#;
        let registry = make_registry(&tmp, "test-reg", 500, &[("retired-tool", tool_toml)]);
        let set = RegistrySet::new(vec![registry]);
        let versions = set.all_versions("retired-tool");
        let installed = vec![
            InstalledMeta {
                store_path: "/nix/store/oooooooooooooooooooooooooooooooo-retired-tool-1.0.0".into(),
                pushed_at: 1707800000,
                pushed_by: "apm".into(),
                expires_at: None,
                is_root: true,
                last_accessed: 1707800000,
                access_count: 0,
                apm: Some(crate::types::ApmMeta {
                    name: "retired-tool".into(),
                    version: "1.0.0".into(),
                    explicit: true,
                    registry: "test-reg".into(),
                    installed_at: "2026-06-09T00:00:00Z".into(),
                    held: false,
                    source_drv: String::new(),
                    source_nar_hash: String::new(),
                    expose: None,
                    expose_artifact: None,
                    config_module: None,
                    documentation: None,
                    permissions: Default::default(),
                    bpf_lsm: None,
                    attestation: Default::default(),
                }),
            },
            InstalledMeta {
                store_path: "/nix/store/nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn-retired-tool-2.0.0".into(),
                pushed_at: 1707800001,
                pushed_by: "apm".into(),
                expires_at: None,
                is_root: true,
                last_accessed: 1707800001,
                access_count: 0,
                apm: Some(crate::types::ApmMeta {
                    name: "retired-tool".into(),
                    version: "2.0.0".into(),
                    explicit: true,
                    registry: "test-reg".into(),
                    installed_at: "2026-06-09T00:00:01Z".into(),
                    held: false,
                    source_drv: String::new(),
                    source_nar_hash: String::new(),
                    expose: None,
                    expose_artifact: None,
                    config_module: None,
                    documentation: None,
                    permissions: Default::default(),
                    bpf_lsm: None,
                    attestation: Default::default(),
                }),
            },
        ];

        assert_eq!(
            policy_unavailable_installed("retired-tool", &installed, &versions),
            vec![("1.0.0".to_string(), "test-reg".to_string())]
        );
    }

    #[test]
    fn installed_dep_tree_uses_profile_names_for_known_refs() {
        let root_hash = "rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr".to_string();
        let dep_hash = "dddddddddddddddddddddddddddddddd".to_string();
        let unknown_hash = "uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu".to_string();

        let installed_by_hash = HashMap::from([
            (
                root_hash.clone(),
                InstalledPackageRef {
                    name: "retired-tool".into(),
                    version: "1.0.0".into(),
                    registry: "test-reg".into(),
                    store_path: format!("/nix/store/{root_hash}-retired-tool-1.0.0"),
                },
            ),
            (
                dep_hash.clone(),
                InstalledPackageRef {
                    name: "retired-dep".into(),
                    version: "1.0.0".into(),
                    registry: "test-reg".into(),
                    store_path: format!("/nix/store/{dep_hash}-retired-dep-1.0.0"),
                },
            ),
        ]);
        let refs_by_hash = HashMap::from([
            (
                root_hash.clone(),
                vec![dep_hash.clone(), unknown_hash.clone()],
            ),
            (dep_hash.clone(), Vec::new()),
        ]);
        let mut visited = HashSet::new();
        let mut ancestors = HashSet::new();

        let tree = build_installed_dep_tree(
            &root_hash,
            &refs_by_hash,
            &installed_by_hash,
            &mut visited,
            &mut ancestors,
        );

        assert_eq!(tree.name, "retired-tool");
        assert_eq!(tree.children.len(), 2);
        assert_eq!(tree.children[0].name, "retired-dep");
        assert_eq!(tree.children[0].version, "1.0.0");
        assert_eq!(tree.children[1].name, "unknown");
        assert!(visited.contains(&root_hash));
        assert!(visited.contains(&dep_hash));
        assert!(visited.contains(&unknown_hash));
        assert!(ancestors.is_empty());
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

    #[test]
    fn files_lists_symlinks_without_following_directory_targets() {
        use std::os::unix::fs::symlink;

        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir_all(root.join("share/tool")).unwrap();
        fs::write(root.join("bin/tool"), b"binary").unwrap();
        fs::write(root.join("share/tool/payload.txt"), b"payload").unwrap();
        symlink("tool", root.join("bin/tool-link")).unwrap();
        symlink(".", root.join("share/tool/current")).unwrap();

        let mut file_list = Vec::new();
        walk_dir(root, root, &mut file_list).unwrap();
        file_list.sort();

        assert_eq!(
            file_list,
            vec![
                "bin/tool",
                "bin/tool-link",
                "share/tool/current",
                "share/tool/payload.txt",
            ]
        );
    }
}
