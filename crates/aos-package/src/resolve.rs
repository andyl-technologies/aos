//! Package and closure resolution against registry caches.
//!
//! Given a package name, resolution finds the owning registry (highest
//! priority wins, unless a registry filter is given) and computes the
//! package's full transitive closure — every store path that must exist for
//! the package to run. Closures are returned in dependency order (deps
//! before dependents, root last) so callers can import members sequentially
//! with `nix-store --import` without dangling references.
//!
//! Two closure strategies are used:
//!
//! 1. **`store/` realisation graph**: registries ship a per-path dependency
//!    record; resolution walks those edges from the root (RFC-0005).
//! 2. **BFS fallback**: a legacy registry with no `store/` graph is walked
//!    over the `references` field of each [`PackageMeta`] instead.
//!
//! In both cases, member hashes not present in the registry (e.g. system
//! libraries assumed installed) are silently skipped rather than treated as
//! errors.

use std::collections::HashSet;

use anyhow::{Context, Result};

use super::registry::{RegistrySet, store_path_hash};
use super::types::PackageMeta;
use aos_core::error::AosError;

// ---------------------------------------------------------------------------
// Resolved closure
// ---------------------------------------------------------------------------

/// A resolved package with its full transitive closure.
#[derive(Debug)]
pub struct ResolvedClosure {
    /// Name of the registry that provided the root package.
    pub registry_name: String,
    /// The explicitly-requested package.
    pub root: PackageMeta,
    /// All dependencies including root, in dependency order (deps before
    /// dependents).  The root is always the last element.
    pub closure: Vec<PackageMeta>,
    /// Sum of uncompressed `nar_size` across all closure members.
    pub total_nar_size: u64,
}

// ---------------------------------------------------------------------------
// Single-package resolution
// ---------------------------------------------------------------------------

/// Resolve a single package and its full closure from a registry.
///
/// If the registry publishes a `store/` realisation graph, resolution walks
/// its dependency edges from the root. A legacy registry with no graph falls
/// back to BFS over the `references` field of each `PackageMeta`.
///
/// With `registry_filter`, only that registry is searched; otherwise the
/// highest-priority registry providing `name` wins.
///
/// # Errors
///
/// Returns an error if `registry_filter` names a registry that is not
/// loaded, or [`AosError::PackageNotFound`] if no (matching) registry
/// provides `name`.
pub fn resolve_closure(
    registries: &RegistrySet,
    name: &str,
    registry_filter: Option<&str>,
) -> Result<ResolvedClosure> {
    // Step 1: find the root package.
    let (registry_name, root) = if let Some(filter) = registry_filter {
        let reg = registries
            .get_registry(filter)
            .with_context(|| format!("registry '{filter}' not found or not loaded"))?;
        let meta = reg.get(name).ok_or_else(|| AosError::PackageNotFound {
            name: name.to_string(),
        })?;
        (reg.config.name.clone(), meta.clone())
    } else {
        let (reg, meta) = registries
            .resolve(name)
            .ok_or_else(|| AosError::PackageNotFound {
                name: name.to_string(),
            })?;
        (reg.config.name.clone(), meta.clone())
    };

    // Step 2: walk the store/ graph when the registry publishes one;
    // otherwise fall back to references BFS for legacy registries.
    let has_graph = registries
        .store_map_in(&registry_name)
        .map(|m| m.is_present())
        .unwrap_or(false);
    if has_graph {
        resolve_via_store(registries, &registry_name, root)
    } else {
        resolve_via_bfs(registries, &registry_name, root)
    }
}

/// Build a `ResolvedClosure` by walking the `store/` graph's dependency edges
/// depth-first (post-order), resolving each member hash to its `PackageMeta`.
/// Members not published as packages (anonymous store paths, system libs) are
/// skipped - their bytes are still fetched via the narinfo closure at download
/// time and verified against the graph.
fn resolve_via_store(
    registries: &RegistrySet,
    registry_name: &str,
    root: PackageMeta,
) -> Result<ResolvedClosure> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut closure: Vec<PackageMeta> = Vec::new();
    let root_hash = store_path_hash(&root.store_path).to_string();

    visit_store_first(
        registries,
        registry_name,
        &root_hash,
        &mut seen,
        &mut closure,
    );

    // Ensure the root is last even if it had no graph record.
    if !closure
        .iter()
        .any(|m| store_path_hash(&m.store_path) == root_hash)
    {
        closure.push(root.clone());
    }

    let total_nar_size: u64 = closure.iter().map(|m| m.nar_size).sum();

    Ok(ResolvedClosure {
        registry_name: registry_name.to_string(),
        root,
        closure,
        total_nar_size,
    })
}

/// Depth-first post-order walk of the `store/` graph: append a member only
/// after its resolvable dependencies, so the result is dependency-ordered.
fn visit_store_first(
    registries: &RegistrySet,
    registry_name: &str,
    hash: &str,
    seen: &mut HashSet<String>,
    closure: &mut Vec<PackageMeta>,
) {
    if !seen.insert(hash.to_string()) {
        return;
    }
    let deps = registries
        .store_map_in(registry_name)
        .map(|m| m.direct_deps(hash))
        .unwrap_or_default();
    for dep in &deps {
        visit_store_first(registries, registry_name, dep, seen, closure);
    }
    if let Some(meta) = registries.resolve_hash_in(registry_name, hash) {
        closure.push(meta.clone());
    }
    // Unresolvable members (not published as packages) are skipped.
}

/// BFS fallback: walk `references` fields to build the closure.
fn resolve_via_bfs(
    registries: &RegistrySet,
    registry_name: &str,
    root: PackageMeta,
) -> Result<ResolvedClosure> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut closure: Vec<PackageMeta> = Vec::new();

    visit_dependencies_first(
        registries,
        registry_name,
        root.clone(),
        &mut seen,
        &mut closure,
    );

    let total_nar_size: u64 = closure.iter().map(|m| m.nar_size).sum();

    Ok(ResolvedClosure {
        registry_name: registry_name.to_string(),
        root,
        closure,
        total_nar_size,
    })
}

/// Depth-first post-order visit: append `current` to `closure` only after
/// all of its resolvable references have been appended, so the resulting
/// vector is in dependency order. Unresolvable references are marked seen
/// and skipped.
fn visit_dependencies_first(
    registries: &RegistrySet,
    registry_name: &str,
    current: PackageMeta,
    seen: &mut HashSet<String>,
    closure: &mut Vec<PackageMeta>,
) {
    let current_hash = store_path_hash(&current.store_path).to_string();
    if !seen.insert(current_hash) {
        return;
    }

    for ref_hash in &current.references {
        if let Some(dep) = registries.resolve_hash_in(registry_name, ref_hash) {
            visit_dependencies_first(registries, registry_name, dep.clone(), seen, closure);
        } else {
            seen.insert(ref_hash.clone());
        }
    }

    closure.push(current);
}

// ---------------------------------------------------------------------------
// Multi-package resolution
// ---------------------------------------------------------------------------

/// Resolve multiple packages, producing independent closures.
///
/// Does NOT deduplicate across closures -- that happens at download time
/// via [`collect_unique_metas`].
///
/// # Errors
///
/// Returns the first per-package resolution failure (see
/// [`resolve_closure`]), annotated with the failing package name.
pub fn resolve_multiple(
    registries: &RegistrySet,
    names: &[String],
    registry_filter: Option<&str>,
) -> Result<Vec<ResolvedClosure>> {
    let mut closures = Vec::with_capacity(names.len());
    for name in names {
        let c = resolve_closure(registries, name, registry_filter)
            .with_context(|| format!("resolving package '{name}'"))?;
        closures.push(c);
    }
    Ok(closures)
}

// ---------------------------------------------------------------------------
// Deduplication helper
// ---------------------------------------------------------------------------

/// Collect all unique `PackageMeta`s from multiple closures.
///
/// Deduplicates by store path hash.  The returned references are in the
/// order they are first encountered (stable iteration).
pub fn collect_unique_metas(closures: &[ResolvedClosure]) -> Vec<&PackageMeta> {
    let mut seen: HashSet<&str> = HashSet::new();
    let mut result: Vec<&PackageMeta> = Vec::new();

    for closure in closures {
        for meta in &closure.closure {
            let hash = store_path_hash(&meta.store_path);
            if seen.insert(hash) {
                result.push(meta);
            }
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    use crate::registry::RegistrySet;
    use crate::registry::parse::{CURL_TOML, ZLIB_TOML};
    use crate::registry::tests::{
        curl_store_record, make_registry, make_registry_with_store, zlib_store_record,
    };

    // 1. Resolving a single package with deps produces a closure containing
    //    both the root and its resolvable dependency.
    #[test]
    fn resolve_single_package() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );
        let set = RegistrySet::new(vec![core]);

        let resolved = resolve_closure(&set, "curl", None).unwrap();

        assert_eq!(resolved.registry_name, "aos-core");
        assert_eq!(resolved.root.name, "curl");
        // Closure should contain curl + zlib (zlib is a reference of curl).
        let names: Vec<&str> = resolved.closure.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"curl"));
        assert!(names.contains(&"zlib"));
        assert!(
            names.iter().position(|name| *name == "zlib")
                < names.iter().position(|name| *name == "curl")
        );
        assert!(resolved.total_nar_size > 0);
    }

    // 2. Resolving a package that doesn't exist returns PackageNotFound.
    #[test]
    fn resolve_package_not_found() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(&tmp, "aos-core", 500, &[("curl", CURL_TOML)]);
        let set = RegistrySet::new(vec![core]);

        let result = resolve_closure(&set, "nonexistent", None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.downcast_ref::<AosError>().is_some());
    }

    // 3. Registry filter restricts resolution to a specific registry.
    #[test]
    fn resolve_with_registry_filter() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(&tmp, "aos-core", 500, &[("curl", CURL_TOML)]);
        let extra = make_registry(&tmp, "aos-extra", 400, &[("curl", CURL_TOML)]);
        let set = RegistrySet::new(vec![core, extra]);

        // Filter to aos-extra: should find curl there.
        let resolved = resolve_closure(&set, "curl", Some("aos-extra")).unwrap();
        assert_eq!(resolved.registry_name, "aos-extra");

        // Filter to a non-existent registry: should error.
        let result = resolve_closure(&set, "curl", Some("nonexistent"));
        assert!(result.is_err());
    }

    // 4. resolve_multiple produces independent closures.
    #[test]
    fn resolve_multiple_packages() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );
        let set = RegistrySet::new(vec![core]);

        let names = vec!["curl".to_string(), "zlib".to_string()];
        let closures = resolve_multiple(&set, &names, None).unwrap();

        assert_eq!(closures.len(), 2);
        assert_eq!(closures[0].root.name, "curl");
        assert_eq!(closures[1].root.name, "zlib");
    }

    // 5. collect_unique_metas deduplicates across closures.
    #[test]
    fn collect_unique_deduplicates() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );
        let set = RegistrySet::new(vec![core]);

        let names = vec!["curl".to_string(), "zlib".to_string()];
        let closures = resolve_multiple(&set, &names, None).unwrap();

        // curl's closure includes zlib, and zlib's closure is just zlib itself.
        // collect_unique should return each package exactly once.
        let unique = collect_unique_metas(&closures);
        let unique_names: HashSet<&str> = unique.iter().map(|m| m.name.as_str()).collect();

        assert!(unique_names.contains("curl"));
        assert!(unique_names.contains("zlib"));
        // Ensure no duplicates: unique set and unique vec have same length.
        assert_eq!(unique.len(), unique_names.len());
    }

    // 6. Leaf package (no references) resolves to a closure of one.
    #[test]
    fn resolve_leaf_package() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(&tmp, "aos-core", 500, &[("zlib", ZLIB_TOML)]);
        let set = RegistrySet::new(vec![core]);

        let resolved = resolve_closure(&set, "zlib", None).unwrap();
        assert_eq!(resolved.closure.len(), 1);
        assert_eq!(resolved.closure[0].name, "zlib");
    }

    // 7. Unresolvable references are silently skipped (not an error).
    #[test]
    fn unresolvable_refs_skipped() {
        let tmp = TempDir::new().unwrap();
        // curl references zlib (r4q1m2kp8v3x) plus xr5is7by89v3q, q8mn2pv73w0x,
        // kl9m3n0o5p6q.  Only zlib is in the registry, so the others should
        // be silently skipped.
        let core = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );
        let set = RegistrySet::new(vec![core]);

        let resolved = resolve_closure(&set, "curl", None).unwrap();
        // Should still succeed.  Closure = curl + zlib (other refs skipped).
        assert_eq!(resolved.closure.len(), 2);
    }

    // 8. Empty package list resolves to empty closures.
    #[test]
    fn resolve_multiple_empty() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(&tmp, "aos-core", 500, &[("curl", CURL_TOML)]);
        let set = RegistrySet::new(vec![core]);

        let closures = resolve_multiple(&set, &[], None).unwrap();
        assert!(closures.is_empty());
    }

    // 9. collect_unique_metas on empty closures returns empty.
    #[test]
    fn collect_unique_empty() {
        let unique = collect_unique_metas(&[]);
        assert!(unique.is_empty());
    }

    // 10. NAR size is summed correctly across closure members.
    #[test]
    fn total_nar_size_computed() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );
        let set = RegistrySet::new(vec![core]);

        let resolved = resolve_closure(&set, "curl", None).unwrap();
        let expected: u64 = resolved.closure.iter().map(|m| m.nar_size).sum();
        assert_eq!(resolved.total_nar_size, expected);
        assert!(resolved.total_nar_size > 0);
    }

    // -----------------------------------------------------------------------
    // store/-graph-based resolution
    // -----------------------------------------------------------------------

    // 11. When a store/ graph is present, resolution walks its edges.
    #[test]
    fn resolve_uses_store_graph() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry_with_store(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
            &[curl_store_record(), zlib_store_record()],
        );
        let set = RegistrySet::new(vec![core]);

        let resolved = resolve_closure(&set, "curl", None).unwrap();
        assert_eq!(resolved.registry_name, "aos-core");
        assert_eq!(resolved.root.name, "curl");

        // curl's record names 4 deps, but only zlib is published as a
        // package - the other 3 are unresolvable and skipped.
        let names: Vec<&str> = resolved.closure.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"curl"));
        assert!(names.contains(&"zlib"));
        assert!(
            names.iter().position(|name| *name == "zlib")
                < names.iter().position(|name| *name == "curl")
        );
        assert!(resolved.total_nar_size > 0);
    }

    // 12. Leaf package with a store/ record resolves to just itself.
    #[test]
    fn resolve_leaf_with_store_graph() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry_with_store(
            &tmp,
            "aos-core",
            500,
            &[("zlib", ZLIB_TOML)],
            &[zlib_store_record()],
        );
        let set = RegistrySet::new(vec![core]);

        let resolved = resolve_closure(&set, "zlib", None).unwrap();
        assert_eq!(resolved.closure.len(), 1);
        assert_eq!(resolved.closure[0].name, "zlib");
    }

    // 13. A registry with no store/ graph falls back to references BFS.
    #[test]
    fn resolve_falls_back_to_bfs_for_legacy_registry() {
        let tmp = TempDir::new().unwrap();
        // No store/ records at all → legacy BFS over TOML references.
        let core = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );
        let set = RegistrySet::new(vec![core]);

        let resolved = resolve_closure(&set, "curl", None).unwrap();
        let names: Vec<&str> = resolved.closure.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"curl"));
        assert!(names.contains(&"zlib"));
    }
}
