//! Sysroot-lock check: detect when a package's closure diverges from the
//! current sysroot's closure.
//!
//! When installing a package, if its closure references a package by name
//! that's also in the current sysroot's closure but at a different store
//! path, the install is blocked with a warning. This prevents library
//! version skew between the sysroot and explicitly installed packages.

use std::collections::HashMap;

use crate::config::ApmConfig;
use crate::registry::store_path_hash;
use crate::sysroot;

// ---------------------------------------------------------------------------
// Store path parsing
// ---------------------------------------------------------------------------

/// Parsed components of a Nix store path reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreRef {
    /// The store-path hash (everything before the first hyphen).
    pub hash: String,
    /// Package name (may itself contain hyphens).
    pub name: String,
    /// Version string; empty when the basename has no version component.
    pub version: String,
}

/// Parse a store path reference like `"abc123-openssl-3.2.1"` into its
/// components: `(hash, name, version)`.
///
/// The format is `{hash}-{name}-{version}` where:
/// - `hash` is everything before the first hyphen
/// - `version` starts at the first hyphen-separated component (after the
///   hash) that begins with a digit
/// - `name` is everything between hash and version
///
/// Full store paths like `/nix/store/abc123-openssl-3.2.1` are handled
/// by stripping the directory prefix first.
///
/// Returns `None` if the reference cannot be parsed (e.g. no version
/// component found).
pub fn parse_store_ref(reference: &str) -> Option<StoreRef> {
    // Strip the store path prefix if present.
    let basename = reference.rsplit('/').next().unwrap_or(reference);

    // Split on hyphens: first component is the hash, rest form name-version.
    let parts: Vec<&str> = basename.splitn(2, '-').collect();
    if parts.len() < 2 {
        return None;
    }

    let hash = parts[0].to_string();
    let rest = parts[1];

    // Find where the version starts: the first hyphen-delimited component
    // that begins with a digit.
    let components: Vec<&str> = rest.split('-').collect();
    let mut version_start_idx = None;
    for (i, component) in components.iter().enumerate() {
        if component
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
        {
            version_start_idx = Some(i);
            break;
        }
    }

    match version_start_idx {
        Some(idx) if idx > 0 => {
            let name = components[..idx].join("-");
            let version = components[idx..].join("-");
            Some(StoreRef {
                hash,
                name,
                version,
            })
        }
        _ => {
            // No version component found, or version is the very first
            // component (no name). Treat the entire rest as the name with
            // no version.
            Some(StoreRef {
                hash,
                name: rest.to_string(),
                version: String::new(),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Sysroot-lock violation
// ---------------------------------------------------------------------------

/// A single sysroot-lock violation: a package name appears in both the
/// sysroot's closure and the to-be-installed package's closure, but at
/// different store paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysrootLockViolation {
    /// The conflicting package name.
    pub name: String,
    /// Version of the package in the sysroot's closure.
    pub sysroot_version: String,
    /// Store-path hash in the sysroot's closure.
    pub sysroot_hash: String,
    /// Version of the package in the to-be-installed closure.
    pub package_version: String,
    /// Store-path hash in the to-be-installed closure.
    pub package_hash: String,
}

/// Check whether a package's closure violates the sysroot-lock.
///
/// Compares `sysroot_references` (the sysroot's reference hashes) against
/// `package_references` (the to-be-installed package's reference hashes)
/// by resolving each to `(name, version, hash)` via `registry_packages`.
///
/// `registry_packages` maps store-path hashes to `(name, version, full_store_path)`.
///
/// Returns a list of violations (empty if the closures are compatible).
pub fn check_sysroot_lock(
    sysroot_references: &[String],
    package_references: &[String],
    registry_packages: &HashMap<String, (String, String, String)>,
) -> Vec<SysrootLockViolation> {
    // Build name -> (hash, version) maps for both closures.
    let sysroot_map = build_name_map(sysroot_references, registry_packages);
    let package_map = build_name_map(package_references, registry_packages);

    let mut violations = Vec::new();
    for (name, (pkg_hash, pkg_version)) in &package_map {
        if let Some((sys_hash, sys_version)) = sysroot_map.get(name) {
            if pkg_hash != sys_hash {
                violations.push(SysrootLockViolation {
                    name: name.clone(),
                    sysroot_version: sys_version.clone(),
                    sysroot_hash: sys_hash.clone(),
                    package_version: pkg_version.clone(),
                    package_hash: pkg_hash.clone(),
                });
            }
        }
    }

    // Sort by name for deterministic output.
    violations.sort_by(|a, b| a.name.cmp(&b.name));
    violations
}

/// Build a `name -> (hash, version)` map from a list of store-path reference
/// hashes, using the registry lookup table.
fn build_name_map(
    references: &[String],
    registry_packages: &HashMap<String, (String, String, String)>,
) -> HashMap<String, (String, String)> {
    let mut map = HashMap::new();
    for ref_hash in references {
        if let Some((name, version, store_path)) = registry_packages.get(ref_hash) {
            let hash = store_path_hash(store_path).to_string();
            map.insert(name.clone(), (hash, version.clone()));
        }
    }
    map
}

// ---------------------------------------------------------------------------
// Integration helpers
// ---------------------------------------------------------------------------

/// Parse the `--ignore-sysroot-lock` flag value.
///
/// - `None` → enforce the check (no bypasses)
/// - `Some("all")` or `Some("")` → bypass the entire check
/// - `Some("openssl,zlib")` → bypass only those names
#[derive(Debug, Clone)]
pub enum IgnoreSysrootLock {
    /// Enforce the check fully.
    Enforce,
    /// Bypass the entire check.
    All,
    /// Bypass specific package names only.
    Names(Vec<String>),
}

impl IgnoreSysrootLock {
    /// Parse from the CLI flag value.
    pub fn parse(value: Option<&str>) -> Self {
        match value {
            None => IgnoreSysrootLock::Enforce,
            Some("all") | Some("") => IgnoreSysrootLock::All,
            Some(names) => {
                let list: Vec<String> = names
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if list.is_empty() {
                    IgnoreSysrootLock::All
                } else {
                    IgnoreSysrootLock::Names(list)
                }
            }
        }
    }

    /// Filter violations according to this ignore policy.
    ///
    /// Returns the violations that are NOT ignored (i.e. still blocking).
    pub fn filter(&self, violations: Vec<SysrootLockViolation>) -> Vec<SysrootLockViolation> {
        match self {
            IgnoreSysrootLock::Enforce => violations,
            IgnoreSysrootLock::All => Vec::new(),
            IgnoreSysrootLock::Names(ignored) => violations
                .into_iter()
                .filter(|v| !ignored.contains(&v.name))
                .collect(),
        }
    }
}

/// Build the registry lookup table: `store_path_hash -> (name, version, store_path)`.
///
/// This is used by `check_sysroot_lock` to resolve reference hashes to
/// package names and versions. Failures to load the registry caches are
/// swallowed and yield an empty lookup (the lock check then finds no
/// violations).
pub fn build_registry_lookup(config: &ApmConfig) -> HashMap<String, (String, String, String)> {
    let reg_configs = config.enabled_registries();
    let cache_dir = config.cache_path();
    let platform = "x86_64-linux";

    let registries = match crate::registry::RegistrySet::load(&cache_dir, &reg_configs, platform) {
        Ok(r) => r,
        Err(_) => return HashMap::new(),
    };

    let mut lookup = HashMap::new();
    for reg in registries.registries() {
        for meta in reg.packages.values() {
            let hash = store_path_hash(&meta.store_path).to_string();
            lookup.insert(
                hash,
                (
                    meta.name.clone(),
                    meta.version.clone(),
                    meta.store_path.clone(),
                ),
            );
            // Also index reference hashes that might not have their own
            // package entry (transitive deps that are in the registry).
            for ref_hash in &meta.references {
                lookup.entry(ref_hash.clone()).or_insert_with(|| {
                    // Try to resolve via store path parsing.
                    // The ref_hash alone doesn't carry name/version, but
                    // if another package in the registry has this hash as
                    // its own store_path_hash, the main loop above will
                    // have already inserted it. This fallback handles the
                    // case where it hasn't been seen yet — we leave a
                    // placeholder that will be overwritten.
                    (ref_hash.clone(), String::new(), String::new())
                });
            }
        }
    }

    // Second pass: ensure package's own hashes win over reference fallbacks.
    for reg in registries.registries() {
        for meta in reg.packages.values() {
            let hash = store_path_hash(&meta.store_path).to_string();
            lookup.insert(
                hash,
                (
                    meta.name.clone(),
                    meta.version.clone(),
                    meta.store_path.clone(),
                ),
            );
        }
    }

    lookup
}

/// Get the current sysroot's reference list from the system generation state.
///
/// Returns `(references, sysroot package name, sysroot version)`, or `None`
/// if there is no active sysroot or the sysroot package cannot be found in
/// any registry.
pub fn get_sysroot_references(config: &ApmConfig) -> Option<(Vec<String>, String, String)> {
    let current = sysroot::running_image_generation().ok()?;

    // Load registries to get the sysroot package's references.
    let reg_configs = config.enabled_registries();
    let cache_dir = config.cache_path();
    let registries =
        crate::registry::RegistrySet::load(&cache_dir, &reg_configs, "x86_64-linux").ok()?;

    for reg in registries.registries() {
        if let Some(meta) = reg.packages.get(&current.package_name) {
            if meta.sysroot {
                return Some((
                    meta.references.clone(),
                    current.package_name.clone(),
                    current.version.clone(),
                ));
            }
        }
    }

    None
}

/// Format the sysroot-lock violation error message for display.
pub fn format_violation_error(
    violations: &[SysrootLockViolation],
    sysroot_name: &str,
    sysroot_version: &str,
) -> String {
    let mut msg = format!(
        "sysroot-lock violation -- package closure diverges from sysroot ({} {}):\n",
        sysroot_name, sysroot_version,
    );

    for v in violations {
        msg.push_str(&format!(
            "  {:<16} sysroot: {:<12} (/nix/store/{}...)  package: {:<12} (/nix/store/{}...)\n",
            v.name,
            v.sysroot_version,
            &v.sysroot_hash[..v.sysroot_hash.len().min(8)],
            v.package_version,
            &v.package_hash[..v.package_hash.len().min(8)],
        ));
    }

    let names: Vec<&str> = violations.iter().map(|v| v.name.as_str()).collect();
    msg.push_str("\nA system update may be needed. Run: apm upgrade --system\n");
    msg.push_str(&format!(
        "\nTo install anyway: apm install <pkg> --ignore-sysroot-lock={}\n",
        names.join(","),
    ));

    msg
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // parse_store_ref
    // -----------------------------------------------------------------------

    #[test]
    fn parse_store_ref_openssl() {
        let r = parse_store_ref("abc123-openssl-3.2.1").unwrap();
        assert_eq!(r.hash, "abc123");
        assert_eq!(r.name, "openssl");
        assert_eq!(r.version, "3.2.1");
    }

    #[test]
    fn parse_store_ref_libstdcpp() {
        let r = parse_store_ref("def456-libstdc++-14.3.0").unwrap();
        assert_eq!(r.hash, "def456");
        assert_eq!(r.name, "libstdc++");
        assert_eq!(r.version, "14.3.0");
    }

    #[test]
    fn parse_store_ref_linux() {
        let r = parse_store_ref("ghi789-linux-6.12.1").unwrap();
        assert_eq!(r.hash, "ghi789");
        assert_eq!(r.name, "linux");
        assert_eq!(r.version, "6.12.1");
    }

    #[test]
    fn parse_store_ref_glibc() {
        let r = parse_store_ref("jkl012-glibc-2.39").unwrap();
        assert_eq!(r.hash, "jkl012");
        assert_eq!(r.name, "glibc");
        assert_eq!(r.version, "2.39");
    }

    #[test]
    fn parse_store_ref_full_path() {
        let r = parse_store_ref("/nix/store/abc123-openssl-3.2.1").unwrap();
        assert_eq!(r.hash, "abc123");
        assert_eq!(r.name, "openssl");
        assert_eq!(r.version, "3.2.1");
    }

    #[test]
    fn parse_store_ref_var_lib_store() {
        let r = parse_store_ref("/var/lib/store/h7j3k8l2m9n4-curl-8.5.0").unwrap();
        assert_eq!(r.hash, "h7j3k8l2m9n4");
        assert_eq!(r.name, "curl");
        assert_eq!(r.version, "8.5.0");
    }

    #[test]
    fn parse_store_ref_no_version() {
        // A package with no version component: just a name.
        let r = parse_store_ref("abc123-bootstrap-tools").unwrap();
        assert_eq!(r.hash, "abc123");
        assert_eq!(r.name, "bootstrap-tools");
        assert_eq!(r.version, "");
    }

    #[test]
    fn parse_store_ref_multi_hyphen_name() {
        let r = parse_store_ref("abc123-my-cool-lib-1.2.3").unwrap();
        assert_eq!(r.hash, "abc123");
        assert_eq!(r.name, "my-cool-lib");
        assert_eq!(r.version, "1.2.3");
    }

    #[test]
    fn parse_store_ref_hash_only() {
        // Just a hash with no hyphen.
        let r = parse_store_ref("abc123");
        assert!(r.is_none());
    }

    // -----------------------------------------------------------------------
    // check_sysroot_lock
    // -----------------------------------------------------------------------

    fn make_lookup() -> HashMap<String, (String, String, String)> {
        let mut m = HashMap::new();
        // Sysroot versions.
        m.insert(
            "aaa111".to_string(),
            (
                "openssl".to_string(),
                "3.2.1".to_string(),
                "/nix/store/aaa111-openssl-3.2.1".to_string(),
            ),
        );
        m.insert(
            "ccc333".to_string(),
            (
                "zlib".to_string(),
                "1.3.0".to_string(),
                "/nix/store/ccc333-zlib-1.3.0".to_string(),
            ),
        );
        m.insert(
            "eee555".to_string(),
            (
                "glibc".to_string(),
                "2.39".to_string(),
                "/nix/store/eee555-glibc-2.39".to_string(),
            ),
        );
        // Package (newer) versions.
        m.insert(
            "bbb222".to_string(),
            (
                "openssl".to_string(),
                "3.3.0".to_string(),
                "/nix/store/bbb222-openssl-3.3.0".to_string(),
            ),
        );
        m.insert(
            "ddd444".to_string(),
            (
                "zlib".to_string(),
                "1.3.1".to_string(),
                "/nix/store/ddd444-zlib-1.3.1".to_string(),
            ),
        );
        m
    }

    #[test]
    fn check_sysroot_lock_no_violations() {
        let lookup = make_lookup();
        let sysroot_refs = vec![
            "aaa111".to_string(),
            "ccc333".to_string(),
            "eee555".to_string(),
        ];
        // Package uses the same openssl and zlib.
        let package_refs = vec!["aaa111".to_string(), "ccc333".to_string()];

        let violations = check_sysroot_lock(&sysroot_refs, &package_refs, &lookup);
        assert!(violations.is_empty());
    }

    #[test]
    fn check_sysroot_lock_detects_divergence() {
        let lookup = make_lookup();
        let sysroot_refs = vec![
            "aaa111".to_string(),
            "ccc333".to_string(),
            "eee555".to_string(),
        ];
        // Package uses newer openssl and zlib.
        let package_refs = vec!["bbb222".to_string(), "ddd444".to_string()];

        let violations = check_sysroot_lock(&sysroot_refs, &package_refs, &lookup);
        assert_eq!(violations.len(), 2);

        assert_eq!(violations[0].name, "openssl");
        assert_eq!(violations[0].sysroot_version, "3.2.1");
        assert_eq!(violations[0].sysroot_hash, "aaa111");
        assert_eq!(violations[0].package_version, "3.3.0");
        assert_eq!(violations[0].package_hash, "bbb222");

        assert_eq!(violations[1].name, "zlib");
        assert_eq!(violations[1].sysroot_version, "1.3.0");
        assert_eq!(violations[1].sysroot_hash, "ccc333");
        assert_eq!(violations[1].package_version, "1.3.1");
        assert_eq!(violations[1].package_hash, "ddd444");
    }

    #[test]
    fn check_sysroot_lock_partial_overlap() {
        let lookup = make_lookup();
        let sysroot_refs = vec![
            "aaa111".to_string(),
            "ccc333".to_string(),
            "eee555".to_string(),
        ];
        // Package uses newer openssl but same zlib, plus glibc is same.
        let package_refs = vec![
            "bbb222".to_string(),
            "ccc333".to_string(),
            "eee555".to_string(),
        ];

        let violations = check_sysroot_lock(&sysroot_refs, &package_refs, &lookup);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].name, "openssl");
    }

    #[test]
    fn check_sysroot_lock_no_overlap() {
        let lookup = make_lookup();
        let sysroot_refs = vec!["aaa111".to_string()];
        // Package has a ref that's not in the sysroot at all (and not in lookup as a known name).
        let package_refs = vec!["fff666".to_string()];

        let violations = check_sysroot_lock(&sysroot_refs, &package_refs, &lookup);
        assert!(violations.is_empty());
    }

    // -----------------------------------------------------------------------
    // IgnoreSysrootLock
    // -----------------------------------------------------------------------

    #[test]
    fn ignore_parse_none_is_enforce() {
        match IgnoreSysrootLock::parse(None) {
            IgnoreSysrootLock::Enforce => {}
            other => panic!("expected Enforce, got {:?}", other),
        }
    }

    #[test]
    fn ignore_parse_all() {
        match IgnoreSysrootLock::parse(Some("all")) {
            IgnoreSysrootLock::All => {}
            other => panic!("expected All, got {:?}", other),
        }
    }

    #[test]
    fn ignore_parse_empty_string_is_all() {
        match IgnoreSysrootLock::parse(Some("")) {
            IgnoreSysrootLock::All => {}
            other => panic!("expected All, got {:?}", other),
        }
    }

    #[test]
    fn ignore_parse_names() {
        match IgnoreSysrootLock::parse(Some("openssl,zlib")) {
            IgnoreSysrootLock::Names(names) => {
                assert_eq!(names, vec!["openssl".to_string(), "zlib".to_string()]);
            }
            other => panic!("expected Names, got {:?}", other),
        }
    }

    #[test]
    fn ignore_filter_enforce_keeps_all() {
        let ignore = IgnoreSysrootLock::Enforce;
        let violations = vec![SysrootLockViolation {
            name: "openssl".into(),
            sysroot_version: "3.2.1".into(),
            sysroot_hash: "aaa".into(),
            package_version: "3.3.0".into(),
            package_hash: "bbb".into(),
        }];
        let filtered = ignore.filter(violations);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn ignore_filter_all_removes_all() {
        let ignore = IgnoreSysrootLock::All;
        let violations = vec![
            SysrootLockViolation {
                name: "openssl".into(),
                sysroot_version: "3.2.1".into(),
                sysroot_hash: "aaa".into(),
                package_version: "3.3.0".into(),
                package_hash: "bbb".into(),
            },
            SysrootLockViolation {
                name: "zlib".into(),
                sysroot_version: "1.3.0".into(),
                sysroot_hash: "ccc".into(),
                package_version: "1.3.1".into(),
                package_hash: "ddd".into(),
            },
        ];
        let filtered = ignore.filter(violations);
        assert!(filtered.is_empty());
    }

    #[test]
    fn ignore_filter_names_removes_specific() {
        let ignore = IgnoreSysrootLock::Names(vec!["openssl".to_string()]);
        let violations = vec![
            SysrootLockViolation {
                name: "openssl".into(),
                sysroot_version: "3.2.1".into(),
                sysroot_hash: "aaa".into(),
                package_version: "3.3.0".into(),
                package_hash: "bbb".into(),
            },
            SysrootLockViolation {
                name: "zlib".into(),
                sysroot_version: "1.3.0".into(),
                sysroot_hash: "ccc".into(),
                package_version: "1.3.1".into(),
                package_hash: "ddd".into(),
            },
        ];
        let filtered = ignore.filter(violations);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "zlib");
    }

    // -----------------------------------------------------------------------
    // format_violation_error
    // -----------------------------------------------------------------------

    #[test]
    fn format_violation_error_message() {
        let violations = vec![SysrootLockViolation {
            name: "openssl".into(),
            sysroot_version: "3.2.1".into(),
            sysroot_hash: "aaa111bb".into(),
            package_version: "3.3.0".into(),
            package_hash: "bbb222cc".into(),
        }];

        let msg = format_violation_error(&violations, "server", "2026.03");
        assert!(msg.contains("sysroot-lock violation"));
        assert!(msg.contains("server 2026.03"));
        assert!(msg.contains("openssl"));
        assert!(msg.contains("3.2.1"));
        assert!(msg.contains("3.3.0"));
        assert!(msg.contains("apm upgrade --system"));
        assert!(msg.contains("--ignore-sysroot-lock=openssl"));
    }
}
