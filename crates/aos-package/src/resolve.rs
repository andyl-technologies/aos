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

use anyhow::{Context, Result, bail};

use super::registry::{RegistrySet, store_path_hash};
use super::types::{ConfigModuleMeta, ModuleAbiCompat, PackageMeta};
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

/// Resolve multiple packages and package-level exposure dependencies.
///
/// Package roots are deduplicated by name while resolving. Store-path members
/// are still deduplicated later by [`collect_unique_metas`].
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
    let mut closures = Vec::new();
    let mut resolved = HashSet::new();
    let mut stack = Vec::new();

    for name in names {
        resolve_with_requires(
            registries,
            name,
            registry_filter,
            &mut resolved,
            &mut stack,
            &mut closures,
        )?;
    }
    Ok(closures)
}

fn resolve_with_requires(
    registries: &RegistrySet,
    name: &str,
    registry_filter: Option<&str>,
    resolved: &mut HashSet<String>,
    stack: &mut Vec<String>,
    closures: &mut Vec<ResolvedClosure>,
) -> Result<()> {
    if resolved.contains(name) {
        return Ok(());
    }

    if let Some(position) = stack.iter().position(|entry| entry == name) {
        let mut cycle = stack[position..].to_vec();
        cycle.push(name.to_string());
        bail!("package requires cycle: {}", cycle.join(" -> "));
    }

    stack.push(name.to_string());
    let closure = resolve_closure(registries, name, registry_filter)
        .with_context(|| format!("resolving package '{name}'"))?;

    let expose_dependencies = expose_dependencies(&closure.root);
    for required in &expose_dependencies {
        resolve_with_requires(
            registries,
            required,
            registry_filter,
            resolved,
            stack,
            closures,
        )
        .with_context(|| format!("resolving required package '{required}' for '{name}'"))?;
    }

    let popped = stack.pop();
    debug_assert_eq!(popped.as_deref(), Some(name));
    resolved.insert(name.to_string());
    closures.push(closure);
    Ok(())
}

fn expose_dependencies(meta: &PackageMeta) -> Vec<String> {
    let Some(expose) = meta.expose.as_ref() else {
        return Vec::new();
    };
    let mut dependencies = Vec::new();
    let mut seen = HashSet::new();
    for required in &expose.requires {
        if seen.insert(required.as_str()) {
            dependencies.push(required.clone());
        }
    }
    for route in &expose.uses {
        if route.provider != meta.name && seen.insert(route.provider.as_str()) {
            dependencies.push(route.provider.clone());
        }
    }
    dependencies
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
// Module-ABI pre-evaluation gate.
// ---------------------------------------------------------------------------

/// One config module presented to the [`module_abi`] resolver gate.
///
/// The full fixpoint resolver is not yet built; this carries the
/// minimum a gate needs — the package identity and its declared
/// [`ModuleAbiCompat`] band — so the gate can be wired ahead of the loop and
/// tested in isolation.
///
/// [`module_abi`]: enforce_module_abi_compat
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatedConfigModule<'a> {
    /// Provider package name.
    pub package: &'a str,
    /// Provider package version.
    pub version: &'a str,
    /// The module's base-lib ABI compatibility band.
    pub module_abi_compat: ModuleAbiCompat,
}

impl<'a> GatedConfigModule<'a> {
    /// Build a gate input from a package name/version and its [`ConfigModuleMeta`].
    pub fn from_meta(package: &'a str, version: &'a str, module: &ConfigModuleMeta) -> Self {
        Self {
            package,
            version,
            module_abi_compat: module.module_abi_compat,
        }
    }
}

/// Fail-closed `module_abi` compatibility gate, run **before** any eval.
///
/// For every configuration module `M` in the
/// resolved set, `M.module_abi_compat.min <= K <= M.module_abi_compat.max` must
/// hold, where `K` is the running image's `module_abi`. The first module whose
/// band excludes `K` aborts resolution before a manifest is produced, so an
/// ABI-incompatible module never reaches `entry.nix` (where a stale interface
/// would throw a misleading missing-option error the fixpoint would misread as
/// "fetch a provider"). This mirrors the fail-closed `enforce_totality` trust
/// gate: a terminal error here is a no-op on the live system, leaving the old
/// config generation live.
///
/// # Errors
///
/// Returns an error naming the first module whose compatibility band excludes
/// `image_abi`.
pub fn enforce_module_abi_compat(modules: &[GatedConfigModule<'_>], image_abi: u32) -> Result<()> {
    for module in modules {
        if !module.module_abi_compat.admits(image_abi) {
            bail!(
                "config module '{}@{}' requires module_abi in [{},{}], running image is {image_abi}",
                module.package,
                module.version,
                module.module_abi_compat.min,
                module.module_abi_compat.max,
            );
        }
    }
    Ok(())
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

    const PROVIDER_TOML: &str = r#"
[package]
name = "provider"
description = "Required provider"
license = "MIT"
maintainer = "aos-team"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/var/lib/store/providerhash-provider-1.0.0"
nar_hash = "sha256:provider"
nar_size = 1
closure_size = 1
source_drv = ""
source_nar_hash = ""
references = []
"#;

    const CONSUMER_TOML: &str = r#"
[package]
name = "consumer"
description = "Requires provider"
license = "MIT"
maintainer = "aos-team"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/var/lib/store/consumerhash-consumer-1.0.0"
nar_hash = "sha256:consumer"
nar_size = 1
closure_size = 1
source_drv = ""
source_nar_hash = ""
root_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
provenance = "attestation/consumer.provenance.jsonl"
measurement = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[versions.platforms.x86_64-linux.references]
hashes = []
min-format = 1
requires-features = ["attestation-v1", "expose-v1", "network-policy-v1", "requires-v1"]

[versions.platforms.x86_64-linux.expose]
target = "aos-pkg-consumer.target"
requires = ["provider"]
"#;

    const CONSUMER_USES_TOML: &str = r#"
[package]
name = "consumer-uses"
description = "Consumes provider capability"
license = "MIT"
maintainer = "aos-team"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/var/lib/store/consumeruseshash-consumer-uses-1.0.0"
nar_hash = "sha256:consumeruses"
nar_size = 1
closure_size = 1
source_drv = ""
source_nar_hash = ""
root_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
provenance = "attestation/consumer-uses.provenance.jsonl"
measurement = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[versions.platforms.x86_64-linux.references]
hashes = []
min-format = 1
requires-features = ["attestation-v1", "expose-v1", "network-policy-v1", "capability-routes-v1"]

[versions.platforms.x86_64-linux.expose]
target = "aos-pkg-consumer-uses.target"
units = ["consumer-uses.service"]

[[versions.platforms.x86_64-linux.expose.uses]]
provider = "provider"
name = "data"
kind = "directory"
unit = "consumer-uses.service"
"#;

    const CYCLE_A_TOML: &str = r#"
[package]
name = "cycle-a"
description = "Cycle A"
license = "MIT"
maintainer = "aos-team"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/var/lib/store/cycleahash-cycle-a-1.0.0"
nar_hash = "sha256:cyclea"
nar_size = 1
closure_size = 1
source_drv = ""
source_nar_hash = ""
root_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
provenance = "attestation/cycle-a.provenance.jsonl"
measurement = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[versions.platforms.x86_64-linux.references]
hashes = []
min-format = 1
requires-features = ["attestation-v1", "expose-v1", "network-policy-v1", "requires-v1"]

[versions.platforms.x86_64-linux.expose]
target = "aos-pkg-cycle-a.target"
requires = ["cycle-b"]
"#;

    const CYCLE_B_TOML: &str = r#"
[package]
name = "cycle-b"
description = "Cycle B"
license = "MIT"
maintainer = "aos-team"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/var/lib/store/cyclebhash-cycle-b-1.0.0"
nar_hash = "sha256:cycleb"
nar_size = 1
closure_size = 1
source_drv = ""
source_nar_hash = ""
root_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
provenance = "attestation/cycle-b.provenance.jsonl"
measurement = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[versions.platforms.x86_64-linux.references]
hashes = []
min-format = 1
requires-features = ["attestation-v1", "expose-v1", "network-policy-v1", "requires-v1"]

[versions.platforms.x86_64-linux.expose]
target = "aos-pkg-cycle-b.target"
requires = ["cycle-a"]
"#;

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

    #[test]
    fn resolve_multiple_pulls_in_expose_requires() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("consumer", CONSUMER_TOML), ("provider", PROVIDER_TOML)],
        );
        let set = RegistrySet::new(vec![core]);

        let closures = resolve_multiple(&set, &["consumer".to_string()], None).unwrap();
        let names: Vec<&str> = closures
            .iter()
            .map(|closure| closure.root.name.as_str())
            .collect();

        assert_eq!(names, vec!["provider", "consumer"]);
    }

    #[test]
    fn resolve_multiple_pulls_in_expose_uses_providers() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(
            &tmp,
            "aos-core",
            500,
            &[
                ("consumer-uses", CONSUMER_USES_TOML),
                ("provider", PROVIDER_TOML),
            ],
        );
        let set = RegistrySet::new(vec![core]);

        let closures = resolve_multiple(&set, &["consumer-uses".to_string()], None).unwrap();
        let names: Vec<&str> = closures
            .iter()
            .map(|closure| closure.root.name.as_str())
            .collect();

        assert_eq!(names, vec!["provider", "consumer-uses"]);
    }

    #[test]
    fn resolve_multiple_deduplicates_explicit_requires() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("consumer", CONSUMER_TOML), ("provider", PROVIDER_TOML)],
        );
        let set = RegistrySet::new(vec![core]);

        let closures = resolve_multiple(
            &set,
            &["consumer".to_string(), "provider".to_string()],
            None,
        )
        .unwrap();
        let names: Vec<&str> = closures
            .iter()
            .map(|closure| closure.root.name.as_str())
            .collect();

        assert_eq!(names, vec!["provider", "consumer"]);
    }

    #[test]
    fn resolve_multiple_rejects_requires_cycle() {
        let tmp = TempDir::new().unwrap();
        let core = make_registry(
            &tmp,
            "aos-core",
            500,
            &[("cycle-a", CYCLE_A_TOML), ("cycle-b", CYCLE_B_TOML)],
        );
        let set = RegistrySet::new(vec![core]);

        let err = resolve_multiple(&set, &["cycle-a".to_string()], None).unwrap_err();
        assert!(format!("{err:#}").contains("package requires cycle"));
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

    // ----------------------------------------------------------------------
    // Module-ABI gate.
    // ----------------------------------------------------------------------

    fn gated(package: &'static str, min: u32, max: u32) -> GatedConfigModule<'static> {
        GatedConfigModule {
            package,
            version: "1.0.0",
            module_abi_compat: ModuleAbiCompat { min, max },
        }
    }

    // 14. module_abi gate: table-driven admit/refuse decisions.
    #[test]
    fn module_abi_gate_admits_and_refuses() {
        struct Case {
            name: &'static str,
            modules: Vec<GatedConfigModule<'static>>,
            image_abi: u32,
            ok: bool,
        }
        let cases = [
            Case {
                name: "in-band",
                modules: vec![gated("a", 1, 2)],
                image_abi: 1,
                ok: true,
            },
            Case {
                name: "at-max",
                modules: vec![gated("a", 1, 2)],
                image_abi: 2,
                ok: true,
            },
            Case {
                name: "below-min",
                modules: vec![gated("a", 2, 3)],
                image_abi: 1,
                ok: false,
            },
            Case {
                name: "above-max",
                modules: vec![gated("a", 1, 2)],
                image_abi: 3,
                ok: false,
            },
            Case {
                name: "empty-set",
                modules: vec![],
                image_abi: 9,
                ok: true,
            },
            Case {
                name: "one-incompatible-of-many",
                modules: vec![gated("a", 1, 3), gated("b", 2, 2)],
                image_abi: 1,
                ok: false,
            },
        ];
        for case in cases {
            let result = enforce_module_abi_compat(&case.modules, case.image_abi);
            assert_eq!(result.is_ok(), case.ok, "case {}", case.name);
        }
    }

    // 15. The refusal message names the offending module and band.
    #[test]
    fn module_abi_gate_message_is_actionable() {
        let err =
            enforce_module_abi_compat(&[gated("firewall", 2, 4)], 1).expect_err("must refuse");
        let msg = err.to_string();
        assert!(msg.contains("firewall@1.0.0"), "{msg}");
        assert!(msg.contains("[2,4]"), "{msg}");
        assert!(msg.contains("running image is 1"), "{msg}");
    }
}
