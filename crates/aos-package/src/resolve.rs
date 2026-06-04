use std::collections::{HashSet, VecDeque};

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
/// If the registry has a precomputed closure file for the package, uses it
/// directly (O(n) lookups, no graph traversal).  Otherwise falls back to
/// BFS over the `references` field of each `PackageMeta`.
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

    let root_hash = store_path_hash(&root.store_path).to_string();

    // Step 2: Try precomputed closure file first.
    if let Some(closure_meta) = registries.get_closure_in(&registry_name, &root_hash) {
        return resolve_from_closure_file(registries, &registry_name, root, closure_meta);
    }

    // Step 3: Fall back to BFS over references.
    resolve_via_bfs(registries, &registry_name, root)
}

/// Build a `ResolvedClosure` from a precomputed closure file.
///
/// Looks up each member hash in the registry to get its `PackageMeta`.
/// Members that can't be resolved (e.g. system libraries) are skipped.
fn resolve_from_closure_file(
    registries: &RegistrySet,
    registry_name: &str,
    root: PackageMeta,
    closure_meta: &super::types::ClosureMeta,
) -> Result<ResolvedClosure> {
    let root_hash = store_path_hash(&root.store_path).to_string();
    let mut closure: Vec<PackageMeta> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Walk the closure members in file order (deps before dependents).
    for member_hash in &closure_meta.members {
        if !seen.insert(member_hash.clone()) {
            continue;
        }

        if *member_hash == root_hash {
            // Root is always included — use the already-resolved meta.
            closure.push(root.clone());
        } else if let Some(dep) = registries.resolve_hash_in(registry_name, member_hash) {
            closure.push(dep.clone());
        }
        // Skip unresolvable hashes (system libraries, etc.)
    }

    // Ensure root is in the closure even if not in the file.
    if !seen.contains(&root_hash) {
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

/// BFS fallback: walk `references` fields to build the closure.
fn resolve_via_bfs(
    registries: &RegistrySet,
    registry_name: &str,
    root: PackageMeta,
) -> Result<ResolvedClosure> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<PackageMeta> = VecDeque::new();
    let mut closure: Vec<PackageMeta> = Vec::new();

    // Seed with the root.
    let root_hash = store_path_hash(&root.store_path).to_string();
    seen.insert(root_hash);
    queue.push_back(root.clone());

    while let Some(current) = queue.pop_front() {
        for ref_hash in &current.references {
            if seen.contains(ref_hash.as_str()) {
                continue;
            }

            // Resolve within the same registry.  If a reference hash can't
            // be resolved, skip it -- it may be a system library or a
            // self-reference that doesn't correspond to a registry package.
            if let Some(dep) = registries.resolve_hash_in(registry_name, ref_hash) {
                // Guard against false matches: the hash_index may map an
                // unknown reference hash back to the referencing package
                // itself.  Deduplicate on the resolved package's actual
                // store path hash (not the ref_hash, which might be a
                // different hash that coincidentally resolved to an
                // already-seen package).
                let dep_hash = store_path_hash(&dep.store_path).to_string();
                if seen.insert(dep_hash) {
                    queue.push_back(dep.clone());
                }
            }

            // Mark this ref_hash as processed regardless of whether it
            // resolved to a new package, to avoid re-resolving it.
            seen.insert(ref_hash.clone());
        }

        closure.push(current);
    }

    let total_nar_size: u64 = closure.iter().map(|m| m.nar_size).sum();

    Ok(ResolvedClosure {
        registry_name: registry_name.to_string(),
        root,
        closure,
        total_nar_size,
    })
}

// ---------------------------------------------------------------------------
// Multi-package resolution
// ---------------------------------------------------------------------------

/// Resolve multiple packages, producing independent closures.
///
/// Does NOT deduplicate across closures -- that happens at download time
/// via [`collect_unique_metas`].
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
    use crate::registry::closures::{CURL_CLOSURE, ZLIB_CLOSURE};
    use crate::registry::parse::{CURL_TOML, ZLIB_TOML};
    use crate::registry::tests::{make_registry, make_registry_with_closures};

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
    // Closure-file-based resolution
    // -----------------------------------------------------------------------

    // 11. When closure files are present, resolution uses them instead of BFS.
    #[test]
    fn resolve_uses_closure_file() {
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
        let set = RegistrySet::new(vec![core]);

        let resolved = resolve_closure(&set, "curl", None).unwrap();
        assert_eq!(resolved.registry_name, "aos-core");
        assert_eq!(resolved.root.name, "curl");

        // Closure file has 5 members, but only curl and zlib are in the
        // registry — the other 3 hashes are unresolvable and skipped.
        let names: Vec<&str> = resolved.closure.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"curl"));
        assert!(names.contains(&"zlib"));
        assert!(resolved.total_nar_size > 0);
    }

    // 12. Leaf package with closure file resolves to just itself.
    #[test]
    fn resolve_leaf_with_closure_file() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry_with_closures(
            &tmp,
            "aos-core",
            500,
            &[("zlib", ZLIB_TOML)],
            &[("r4q1m2kp8v3x", ZLIB_CLOSURE)],
        );
        let set = RegistrySet::new(vec![core]);

        let resolved = resolve_closure(&set, "zlib", None).unwrap();
        assert_eq!(resolved.closure.len(), 1);
        assert_eq!(resolved.closure[0].name, "zlib");
    }

    // 13. Falls back to BFS when no closure file exists.
    #[test]
    fn resolve_falls_back_to_bfs() {
        let tmp = TempDir::new().unwrap();
        // Create registry with closure file only for zlib, not curl.
        let core = make_registry_with_closures(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
            &[("r4q1m2kp8v3x", ZLIB_CLOSURE)],
        );
        let set = RegistrySet::new(vec![core]);

        // curl has no closure file — should fall back to BFS.
        let resolved = resolve_closure(&set, "curl", None).unwrap();
        let names: Vec<&str> = resolved.closure.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"curl"));
        assert!(names.contains(&"zlib"));
    }
}
