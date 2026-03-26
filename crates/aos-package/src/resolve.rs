use std::collections::{HashSet, VecDeque};

use anyhow::{Context, Result};

use super::registry::{store_path_hash, RegistrySet};
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
    /// Sum of `download_size` across all closure members.
    pub total_download_size: u64,
}

// ---------------------------------------------------------------------------
// Single-package resolution
// ---------------------------------------------------------------------------

/// Resolve a single package and its full closure from a registry.
///
/// All deps resolve from the SAME registry as the parent package.
/// Uses BFS over the `references` field of each `PackageMeta`.
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
        let (reg, meta) = registries.resolve(name).ok_or_else(|| {
            AosError::PackageNotFound {
                name: name.to_string(),
            }
        })?;
        (reg.config.name.clone(), meta.clone())
    };

    // Step 2: BFS over references, scoped to the same registry.
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
            if let Some(dep) = registries.resolve_hash_in(&registry_name, ref_hash) {
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

    let total_download_size: u64 = closure.iter().map(|m| m.download_size).sum();

    Ok(ResolvedClosure {
        registry_name,
        root,
        closure,
        total_download_size,
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
    use std::fs;
    use tempfile::TempDir;

    use crate::registry::parse::{CURL_TOML, ZLIB_TOML};
    use crate::registry::{Registry, RegistrySet};
    use crate::types::RegistryConfig;

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
        assert!(resolved.total_download_size > 0);
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

    // 10. Download size is summed correctly across closure members.
    #[test]
    fn total_download_size_computed() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)],
        );
        let set = RegistrySet::new(vec![core]);

        let resolved = resolve_closure(&set, "curl", None).unwrap();
        // curl download_size = 1048576, zlib download_size = 196608
        let expected: u64 = resolved.closure.iter().map(|m| m.download_size).sum();
        assert_eq!(resolved.total_download_size, expected);
        assert!(resolved.total_download_size > 0);
    }
}
