//! Loads declared Bazel production edges for structural integration audits.
//!
//! The source-built query exporter unions platform and feature branches. Its
//! JSON retains source ownership, production targets, and per-target edges:
//!
//! ```json
//! {
//!   "schema_version": 1,
//!   "selection": "union of all declared production platform/feature branches",
//!   "query_sha256": "...",
//!   "packages": [{
//!     "name": "example", "directory": "crates/example",
//!     "production_targets": ["//crates/example:lib"],
//!     "production_dependencies": []
//!   }],
//!   "target_dependencies": {"//crates/example:lib": []}
//! }
//! ```

// crucible-lint: allow rust-allow -- Each integration audit consumes part of the shared graph API.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Component, Path};

const SELECTION: &str = "union of all declared production platform/feature branches";

/// Holds validated source ownership and production package edges.
pub(crate) struct Architecture {
    packages: BTreeMap<String, Package>,
    compilations: Option<BTreeMap<String, CompilationTarget>>,
}

/// Describes one declared Rust compilation, before selecting platform branches.
#[derive(serde::Deserialize)]
pub(crate) struct CompilationTarget {
    /// Names the source package that owns the target.
    pub(crate) package: String,
    /// Names the actual Bazel Rust rule class.
    pub(crate) kind: String,
    /// Names the Rust crate after Bazel's default name normalization.
    pub(crate) crate_name: String,
    /// Holds package-relative source roots across every selector branch.
    pub(crate) crate_roots: BTreeSet<String>,
    /// Holds the union of explicitly compiled crate features.
    pub(crate) features: BTreeSet<String>,
    /// Holds declared target tags, including wildcard exclusions.
    pub(crate) tags: BTreeSet<String>,
    /// Identifies targets restricted to test-only dependents.
    pub(crate) test_only: bool,
}

#[derive(serde::Deserialize)]
struct Document {
    schema_version: u32,
    selection: String,
    query_sha256: String,
    packages: Vec<Package>,
    target_dependencies: BTreeMap<String, Vec<Edge>>,
    compilation_targets: Option<BTreeMap<String, CompilationTarget>>,
}

#[derive(serde::Deserialize)]
struct Package {
    name: String,
    directory: String,
    version: Option<String>,
    license: Option<String>,
    production_targets: BTreeSet<String>,
    production_dependencies: Option<BTreeSet<String>>,
}

#[derive(serde::Deserialize)]
struct Edge {
    packages: BTreeSet<String>,
}

impl Architecture {
    /// Returns the source package's declared version.
    ///
    /// # Errors
    ///
    /// Returns an error when ownership or version metadata is absent.
    pub(crate) fn package_version(&self, name: &str) -> io::Result<&str> {
        self.packages
            .get(name)
            .and_then(|package| package.version.as_deref())
            .filter(|version| !version.is_empty())
            .ok_or_else(|| io::Error::other("source package omitted its version"))
    }

    /// Returns the source package's explicit license expression.
    ///
    /// # Errors
    ///
    /// Returns an error when ownership or license metadata is absent.
    pub(crate) fn package_license(&self, name: &str) -> io::Result<&str> {
        self.packages
            .get(name)
            .and_then(|package| package.license.as_deref())
            .filter(|license| !license.is_empty())
            .ok_or_else(|| io::Error::other("source package omitted its license"))
    }

    /// Returns a package's validated repository-relative source directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the package has no declared source ownership.
    pub(crate) fn package_directory(&self, package: &str) -> io::Result<&Path> {
        self.packages
            .get(package)
            .map(|package| Path::new(&package.directory))
            .ok_or_else(|| io::Error::other("package has no declared source ownership"))
    }

    /// Iterates over a package's declared Rust compilations, including helpers.
    ///
    /// # Errors
    ///
    /// Returns an error for absent ownership or omitted artifact metadata.
    pub(crate) fn compilation_targets(
        &self,
        package: &str,
    ) -> io::Result<impl Iterator<Item = (&str, &CompilationTarget)>> {
        if !self.packages.contains_key(package) {
            return Err(io::Error::other(
                "artifact package has no declared ownership",
            ));
        }
        let targets = self
            .compilations
            .as_ref()
            .ok_or_else(|| io::Error::other("architecture omitted compilation target metadata"))?;
        Ok(targets
            .iter()
            .filter(move |(_, target)| target.package == package)
            .map(|(label, target)| (label.as_str(), target)))
    }

    /// Iterates over the declared source package names, including test support.
    pub(crate) fn package_names(&self) -> impl Iterator<Item = &str> {
        self.packages.keys().map(String::as_str)
    }

    /// Returns the union of a package's declared production dependency names.
    ///
    /// # Errors
    ///
    /// Returns an error if the package is absent or has no production graph.
    pub(crate) fn production_dependencies(&self, name: &str) -> io::Result<&BTreeSet<String>> {
        self.packages
            .get(name)
            .and_then(|package| package.production_dependencies.as_ref())
            .ok_or_else(|| {
                io::Error::other(format!("package {name} has no declared production graph"))
            })
    }
}

/// Loads the declared graph, retaining the Cargo oracle for Cargo-only tests.
///
/// # Errors
///
/// Returns an error for absent Bazel runtime data or invalid graph metadata.
pub(crate) fn load() -> io::Result<Option<Architecture>> {
    let Some(path) = std::env::var_os("AOS_BAZEL_ARCHITECTURE") else {
        if std::env::var_os("AOS_SOURCE_CATALOG").is_some() {
            return Err(io::Error::other(
                "Bazel audit omitted its declared architecture input",
            ));
        }
        return Ok(None);
    };

    parse(&fs::read_to_string(path)?).map(Some)
}

/// Parses graph metadata and checks package edges against their target records.
///
/// # Errors
///
/// Returns an error for malformed, incomplete, or inconsistent graph metadata.
pub(crate) fn parse(contents: &str) -> io::Result<Architecture> {
    let document: Document = serde_json::from_str(contents).map_err(io::Error::other)?;
    if document.schema_version != 1
        || document.selection != SELECTION
        || document.query_sha256.len() != 64
        || !document
            .query_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || document.packages.is_empty()
    {
        return Err(io::Error::other("invalid Bazel architecture identity"));
    }

    let mut packages = BTreeMap::new();
    let mut directories = BTreeSet::new();
    let mut targets = BTreeSet::new();
    for package in document.packages {
        let directory = Path::new(&package.directory);
        if package.name.is_empty()
            || !directory.starts_with("crates")
            || directory == Path::new("crates")
            || directory
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
            || !directories.insert(package.directory.clone())
        {
            return Err(io::Error::other(
                "invalid or duplicate architecture source ownership",
            ));
        }
        if package.production_targets.is_empty() != package.production_dependencies.is_none() {
            return Err(io::Error::other(
                "production target and dependency coverage disagree",
            ));
        }

        let mut dependencies = BTreeSet::new();
        for target in &package.production_targets {
            if !target.starts_with(&format!("//{}:", package.directory))
                || !targets.insert(target.clone())
            {
                return Err(io::Error::other(
                    "invalid or duplicate production target ownership",
                ));
            }
            let edges = document.target_dependencies.get(target).ok_or_else(|| {
                io::Error::other("production target omitted its dependency records")
            })?;
            for edge in edges {
                dependencies.extend(edge.packages.iter().cloned());
            }
        }
        if package
            .production_dependencies
            .as_ref()
            .is_some_and(|declared| declared != &dependencies)
        {
            return Err(io::Error::other(
                "production package edges differ from target records",
            ));
        }
        if packages.insert(package.name.clone(), package).is_some() {
            return Err(io::Error::other("duplicate architecture package name"));
        }
    }
    if document
        .target_dependencies
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
        != targets
    {
        return Err(io::Error::other(
            "architecture contains unowned production target records",
        ));
    }

    if let Some(compilations) = &document.compilation_targets {
        for (label, target) in compilations {
            let package = packages
                .get(&target.package)
                .ok_or_else(|| io::Error::other("artifact target has no source package"))?;
            if !label.starts_with(&format!("//{}:", package.directory))
                || target.crate_name.is_empty()
                || target.crate_roots.is_empty()
                || !matches!(
                    target.kind.as_str(),
                    "rust_library"
                        | "rust_binary"
                        | "rust_proc_macro"
                        | "rust_shared_library"
                        | "rust_static_library"
                )
                || target.crate_roots.iter().any(|root| {
                    !root.ends_with(".rs")
                        || Path::new(root)
                            .components()
                            .any(|part| !matches!(part, Component::Normal(_)))
                })
                || package.production_targets.contains(label) == target.test_only
            {
                return Err(io::Error::other("invalid architecture compilation target"));
            }
        }
        if !targets.iter().all(|label| compilations.contains_key(label)) {
            return Err(io::Error::other(
                "production target omitted artifact metadata",
            ));
        }
    }

    Ok(Architecture {
        packages,
        compilations: document.compilation_targets,
    })
}
