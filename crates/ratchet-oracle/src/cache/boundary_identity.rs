//! MEMO-2 source-Merkle boundary-identity map (RFC-0007, M2-record increment 1).
//!
//! Design:
//! `docs/rfcs/0007-nix-evaluator/design-notes/memo2-record-spec.md` §2 (and the
//! keying redirect in `memo2-applied-boundary-seeding-plan.md` §11).
//!
//! A MEMO-2 applied-package boundary record is keyed by a **source-Merkle
//! identity**: a package's identity is a blake3 fold of its own lowered-IR
//! fingerprint and, recursively, the identities of the packages named by its
//! static formal set (`{ mkDerivation, fetchurl, <dep>… }:`) — exactly the deps
//! `callPackage`'s `intersectAttrs (functionArgs fn) self` supplies. Because it
//! resolves each dependency to its **source file** and folds transitively, a
//! source edit anywhere in a package's dependency cone flips its identity
//! (soundness), while an unrelated package keeps its identity (partial-warm
//! replay). It requires **no evaluation and no forcing** — only parse-cache
//! fingerprints and static formal names.
//!
//! # Identity
//!
//! ```text
//! BoundaryIdentity(P) = blake3(
//!     DOMAIN ‖ FORMAT_VERSION ‖ crate_version
//!     ‖ LoweredIrFingerprint(P.nix)
//!     ‖ for f in sorted(formals(P)):
//!         dep_component(f)
//!     ‖ frameworkIdentity)                 # global; §2.4 soundness
//!
//! dep_component(f) =
//!     BoundaryIdentity(Q)   if f names a package Q         (recurse; DAG-memoized)
//!     "fw:" ‖ f             if f is a framework name       (per-name salt only)
//!     "ov:" ‖ f             if f is a shared-source override arg
//!     (nothing)            if f is unresolved but has an in-file default
//!                           (covered by LoweredIrFingerprint(P.nix))
//!     ⟂ DECLINE the whole boundary   if f is unresolved and has no default
//! ```
//!
//! `frameworkIdentity` is a source Merkle over the framework closure
//! (`lib/`, `stdenv/`, `pkgs/build-support/`): `mkDerivation`/`fetchurl`/`lib`
//! are constructed once at the top of `pkgs/default.nix` and captured — not
//! re-imported per boundary — so a boundary's impure slice does not cover them
//! (§2.4). Folding `frameworkIdentity` into every key means a framework edit
//! invalidates the whole set, correctly and in the key.
//!
//! # Scope of this module
//!
//! This is the first M2-record increment: the map builder only. It produces a
//! `name → BoundaryIdentity` map (plus the set of declined packages) for a
//! package-set root, with no admission flags, no record store, and no replay —
//! those are the following increments.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::compile::{Ir, IrData, IrId};

use super::parse::{FileParseMemo, lowered_ir_fingerprint};

/// Domain separator for the boundary-identity hash (never a hot-hash address).
const BOUNDARY_IDENTITY_DOMAIN: &[u8] = b"aos-nix.memo2.boundary-identity";
/// Format version; bump to invalidate every prior identity safely.
const BOUNDARY_IDENTITY_FORMAT_VERSION: u32 = 1;

/// Framework / plumbing names that `callPackage` supplies from `self` but which
/// are not package files (no source identity, "correctly global" hubs). Kept in
/// sync with the `self` plumbing in `pkgs/default.nix`; the same list the
/// M2-measure-2 analysis (`pkgs/_memo2-cone-analysis.nix`) uses.
const FRAMEWORK_NAMES: &[&str] = &[
    "mkDerivation",
    "fetchurl",
    "lib",
    "mkCargoPackage",
    "mkGoPackage",
    "mkBazelPackage",
    "fetchCargoDeps",
    "fetchCargoVendor",
    "fetchGoModules",
    "fetchBazelDeps",
    "bootstrapTools",
    "fakeHash",
    "stdenv",
    "nuke-references",
    "gcc",
    "glibc",
    "binutils",
    "cc",
    "gccUnwrapped",
    "getent",
    "bash",
    "coreutils",
    "gnumake",
    "sed",
    "grep",
    "findutils",
    "gawk",
    "diffutils",
    "tar",
    "gzip",
    "patch",
    "writeTextFile",
    "writeShellScriptBin",
    "runtimeShell",
    "runCommand",
];

/// Shared-source override arguments supplied per-package in `pkgs/default.nix`
/// (e.g. `callPackage ./kernel/linux.nix { inherit linuxSource; }`). They
/// resolve (so they are not declines) but name no package file.
const OVERRIDE_ARG_NAMES: &[&str] = &["linuxSource", "kubeSource", "kubeedgeSource"];

/// A durable source-Merkle identity for one package boundary.
///
/// Equal identity ⇒ byte-identical source dependency cone (plus framework
/// source), so — with the record's impure slice revalidated — an identical
/// derivation. See the module docs for the fold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BoundaryIdentity([u8; 32]);

impl BoundaryIdentity {
    /// Returns the raw 32-byte identity.
    pub const fn as_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Returns the identity as a lowercase hex string.
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}

/// The computed boundary-identity map for one package-set root.
#[derive(Clone, Debug, Default)]
pub struct BoundaryIdentityMap {
    /// Keyable package boundaries: `name → source-Merkle identity`.
    identities: BTreeMap<String, BoundaryIdentity>,
    /// Keyable boundaries by canonical source-file path — the lookup the
    /// evaluator uses at the apply seam, where an applied package lambda's
    /// module names its file (`ModuleSource::name`), not the package attr name.
    by_realpath: BTreeMap<PathBuf, BoundaryIdentity>,
    /// Packages that decline admission because a formal is unresolved and has no
    /// in-file default, or because a transitive dependency declines.
    declined: BTreeSet<String>,
    /// The global framework-source identity folded into every key (§2.4).
    framework_identity: [u8; 32],
}

impl BoundaryIdentityMap {
    /// Returns the boundary identity for `name`, or `None` if it is unknown or
    /// declined.
    pub fn identity(&self, name: &str) -> Option<BoundaryIdentity> {
        self.identities.get(name).copied()
    }

    /// Returns the boundary identity for the package whose source file is
    /// `path`, or `None` if the path is not a keyed package boundary.
    ///
    /// `path` is canonicalized before lookup so a relative or symlinked apply-time
    /// module path resolves to the same entry the builder recorded. A path that
    /// cannot be canonicalized is treated as a miss.
    pub fn identity_for_source_path(&self, path: &Path) -> Option<BoundaryIdentity> {
        let realpath = std::fs::canonicalize(path).ok()?;
        self.by_realpath.get(&realpath).copied()
    }

    /// Returns whether `name` declined admission.
    pub fn is_declined(&self, name: &str) -> bool {
        self.declined.contains(name)
    }

    /// Returns the number of keyable boundaries.
    pub fn keyed_len(&self) -> usize {
        self.identities.len()
    }

    /// Returns the number of declined boundaries.
    pub fn declined_len(&self) -> usize {
        self.declined.len()
    }

    /// Returns the global framework-source identity folded into every key.
    pub const fn framework_identity(&self) -> [u8; 32] {
        self.framework_identity
    }

    /// Iterates the keyed `(name, identity)` pairs in name order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, BoundaryIdentity)> {
        self.identities
            .iter()
            .map(|(name, id)| (name.as_str(), *id))
    }
}

/// A boundary-identity map build failed.
#[derive(Debug, thiserror::Error)]
pub enum BoundaryIdentityError {
    /// The package-set root could not be enumerated.
    #[error("failed to read package directory {path}: {source}")]
    ReadDir {
        /// The directory that could not be read.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// A framework-source directory could not be walked.
    #[error("failed to walk framework source {path}: {source}")]
    FrameworkWalk {
        /// The directory that could not be walked.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
}

/// Inputs for [`build_boundary_identity_map`].
#[derive(Clone, Debug)]
pub struct BoundaryIdentityConfig {
    /// The package-set root (the `pkgs/` directory `discoverPackages` scans).
    pub pkgs_root: PathBuf,
    /// Framework-source roots hashed into `frameworkIdentity` (§2.4), e.g.
    /// `lib/`, `stdenv/`, and `pkgs/build-support/`.
    pub framework_roots: Vec<PathBuf>,
    /// Directory backing the parse cache used to lower package files. Only
    /// lowered-IR fingerprints are read from it; no evaluation occurs.
    pub parse_cache_root: PathBuf,
}

/// One discovered package file's static facts.
#[derive(Clone, Debug)]
struct PackageFacts {
    /// The lowered-IR fingerprint of the file.
    fingerprint: [u8; 32],
    /// The formals of the file's top-level function, each with its default flag.
    formals: Vec<Formal>,
}

/// One formal argument name plus whether it carries an in-file default.
#[derive(Clone, Debug)]
struct Formal {
    /// The formal's name.
    name: String,
    /// Whether the formal has an in-file default expression.
    has_default: bool,
}

/// Builds the source-Merkle boundary-identity map for a package set.
///
/// Enumerates package files exactly as `discoverPackages` does, extracts each
/// file's lowered-IR fingerprint and top-level formal set from the parse cache
/// (no evaluation), computes the global `frameworkIdentity`, and folds the
/// per-package source-Merkle identities over the dependency DAG.
///
/// # Errors
///
/// Returns [`BoundaryIdentityError`] if the package-set root or a framework
/// source root cannot be read. A package file whose formals cannot be extracted
/// (not a top-level function) is skipped, not fatal.
pub fn build_boundary_identity_map(
    config: &BoundaryIdentityConfig,
) -> Result<BoundaryIdentityMap, BoundaryIdentityError> {
    let mut packages = Vec::new();
    discover_packages(&config.pkgs_root, &mut packages)?;

    let name_set: BTreeSet<String> = packages.iter().map(|(name, _)| name.clone()).collect();
    let framework_set: BTreeSet<&str> = FRAMEWORK_NAMES.iter().copied().collect();
    let override_set: BTreeSet<&str> = OVERRIDE_ARG_NAMES.iter().copied().collect();

    let framework_identity = framework_identity(&config.framework_roots)?;

    // Extract per-package facts. Files whose top-level is not a function (so no
    // formal set) are dropped from the keyable set.
    let mut memo = FileParseMemo::with_cache_root(&config.parse_cache_root);
    let mut facts: BTreeMap<String, PackageFacts> = BTreeMap::new();
    for (name, path) in &packages {
        if let Some(package_facts) = extract_package_facts(&mut memo, path) {
            facts.insert(name.clone(), package_facts);
        }
    }

    let classifier = FormalClassifier {
        packages: &name_set,
        framework: &framework_set,
        overrides: &override_set,
    };

    let mut map = fold_identities(&facts, &classifier, &framework_identity);

    // Index keyed boundaries by canonical source path for the apply-seam lookup.
    for (name, path) in &packages {
        if let Some(identity) = map.identities.get(name).copied() {
            if let Ok(realpath) = std::fs::canonicalize(path) {
                map.by_realpath.insert(realpath, identity);
            }
        }
    }
    Ok(map)
}

/// Folds every package's source-Merkle identity over the dependency DAG.
///
/// `identities` caches keyable results; `declined` accumulates packages that
/// cannot be keyed (an unresolved no-default formal, a dependency with no
/// extractable file, or a declining transitive dependency).
fn fold_identities(
    facts: &BTreeMap<String, PackageFacts>,
    classifier: &FormalClassifier<'_>,
    framework_identity: &[u8; 32],
) -> BoundaryIdentityMap {
    let mut map = BoundaryIdentityMap {
        framework_identity: *framework_identity,
        ..BoundaryIdentityMap::default()
    };
    let mut in_progress: BTreeSet<String> = BTreeSet::new();
    for name in facts.keys() {
        let _ = resolve_identity(
            name,
            facts,
            classifier,
            framework_identity,
            &mut map,
            &mut in_progress,
        );
    }
    map
}

/// The static resolution of one formal name.
enum Resolution {
    /// A dependency on another package boundary (a cone edge).
    Package,
    /// A framework/plumbing reference (per-name salt, no cone edge).
    Framework,
    /// A shared-source override argument.
    Override,
    /// Unresolved but carrying an in-file default (covered by the file
    /// fingerprint; contributes nothing to the key).
    InFileDefault,
    /// Unresolved and no default: the boundary declines.
    Decline,
}

/// Classifies formal names against the package, framework, and override sets.
struct FormalClassifier<'a> {
    packages: &'a BTreeSet<String>,
    framework: &'a BTreeSet<&'a str>,
    overrides: &'a BTreeSet<&'a str>,
}

impl FormalClassifier<'_> {
    fn classify(&self, formal: &Formal) -> Resolution {
        if self.framework.contains(formal.name.as_str()) {
            Resolution::Framework
        } else if self.packages.contains(formal.name.as_str()) {
            Resolution::Package
        } else if self.overrides.contains(formal.name.as_str()) {
            Resolution::Override
        } else if formal.has_default {
            Resolution::InFileDefault
        } else {
            Resolution::Decline
        }
    }
}

/// Resolves and memoizes one package's boundary identity, recursing into its
/// package dependencies. Returns `None` when the package declines.
///
/// The package dependency graph is a DAG (verified by the M2-measure-2 static
/// analysis), so a package is never encountered twice on one recursion path;
/// `in_progress` is a defensive guard that declines on any unexpected back-edge
/// rather than looping.
fn resolve_identity(
    name: &str,
    facts: &BTreeMap<String, PackageFacts>,
    classifier: &FormalClassifier<'_>,
    framework_identity: &[u8; 32],
    map: &mut BoundaryIdentityMap,
    in_progress: &mut BTreeSet<String>,
) -> Option<BoundaryIdentity> {
    if let Some(identity) = map.identities.get(name) {
        return Some(*identity);
    }
    if map.declined.contains(name) {
        return None;
    }
    let Some(package) = facts.get(name) else {
        // A formal named a package with no extractable file: cannot key.
        map.declined.insert(name.to_string());
        return None;
    };
    if !in_progress.insert(name.to_string()) {
        // Unexpected back-edge (the graph is a DAG); decline defensively.
        map.declined.insert(name.to_string());
        return None;
    }

    let mut hasher = blake3::Hasher::new();
    hasher.update(BOUNDARY_IDENTITY_DOMAIN);
    hasher.update(&BOUNDARY_IDENTITY_FORMAT_VERSION.to_le_bytes());
    hasher.update(env!("CARGO_PKG_VERSION").as_bytes());
    hasher.update(&package.fingerprint);

    // Formals are folded in canonical (sorted) name order.
    let mut formals = package.formals.clone();
    formals.sort_by(|a, b| a.name.cmp(&b.name));

    let mut declined = false;
    for formal in &formals {
        match classifier.classify(formal) {
            Resolution::Package => {
                match resolve_identity(
                    &formal.name,
                    facts,
                    classifier,
                    framework_identity,
                    map,
                    in_progress,
                ) {
                    Some(dep) => {
                        hasher.update(b"pkg:");
                        hasher.update(&dep.as_bytes());
                    }
                    None => {
                        declined = true;
                        break;
                    }
                }
            }
            Resolution::Framework => {
                hasher.update(b"fw:");
                hasher.update(formal.name.as_bytes());
            }
            Resolution::Override => {
                hasher.update(b"ov:");
                hasher.update(formal.name.as_bytes());
            }
            Resolution::InFileDefault => {}
            Resolution::Decline => {
                declined = true;
                break;
            }
        }
    }

    in_progress.remove(name);

    if declined {
        map.declined.insert(name.to_string());
        return None;
    }
    hasher.update(framework_identity);
    let identity = BoundaryIdentity(*hasher.finalize().as_bytes());
    map.identities.insert(name.to_string(), identity);
    Some(identity)
}

/// Recursively discovers package files exactly as `discoverPackages` does:
/// `.nix` files that are not `default.nix` and not underscore-prefixed, recursing
/// into non-underscore subdirectories. Appends `(name, path)` records.
fn discover_packages(
    dir: &Path,
    out: &mut Vec<(String, PathBuf)>,
) -> Result<(), BoundaryIdentityError> {
    let entries = std::fs::read_dir(dir).map_err(|source| BoundaryIdentityError::ReadDir {
        path: dir.to_path_buf(),
        source,
    })?;
    let mut subdirs = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| BoundaryIdentityError::ReadDir {
            path: dir.to_path_buf(),
            source,
        })?;
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if name.starts_with('_') {
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|source| BoundaryIdentityError::ReadDir {
                path: dir.to_path_buf(),
                source,
            })?;
        if file_type.is_dir() {
            subdirs.push(entry.path());
        } else if file_type.is_file() && name.ends_with(".nix") && name != "default.nix" {
            let package_name = name.trim_end_matches(".nix").to_string();
            out.push((package_name, entry.path()));
        }
    }
    subdirs.sort();
    for subdir in subdirs {
        discover_packages(&subdir, out)?;
    }
    Ok(())
}

/// Extracts one package file's lowered-IR fingerprint and top-level formals, or
/// `None` if the file cannot be parsed or its top-level is not a function.
fn extract_package_facts(memo: &mut FileParseMemo, path: &Path) -> Option<PackageFacts> {
    let parsed = memo.load_or_parse_file(path).ok()?;
    let ir = &parsed.parsed.ir;
    let fingerprint = lowered_ir_fingerprint(ir)
        .ok()?
        .as_durable_hash()
        .as_bytes();
    let formals = top_level_formals(ir)?;
    Some(PackageFacts {
        fingerprint,
        formals,
    })
}

/// Reads the formal set of a file's top-level function, unwrapping leading
/// `let … in` wrappers to reach the lambda. Returns `None` if the top-level is
/// not a `{ … }:` function.
fn top_level_formals(ir: &Ir) -> Option<Vec<Formal>> {
    let mut node_id = ir.root;
    // Unwrap `let … in <body>` chains to reach the lambda.
    loop {
        let node = ir.arena.node(node_id)?;
        match &node.data {
            IrData::Let { body, .. } => node_id = *body,
            IrData::Lambda { pattern, .. } => return formal_set_of(ir, *pattern),
            _ => return None,
        }
    }
}

/// Reads the formals of a `FormalSet` pattern node, or `None` for a plain
/// (single-identifier) pattern.
fn formal_set_of(ir: &Ir, pattern: IrId) -> Option<Vec<Formal>> {
    let pattern_node = ir.arena.node(pattern)?;
    let IrData::FormalSet { formals, .. } = &pattern_node.data else {
        return None;
    };
    let formal_ids = ir.arena.child_slice(*formals)?;
    let mut out = Vec::with_capacity(formal_ids.len());
    for formal_id in formal_ids {
        let formal_node = ir.arena.node(*formal_id)?;
        let IrData::Formal { name, default } = &formal_node.data else {
            continue;
        };
        let name_bytes = ir.symbols.resolve(*name)?;
        out.push(Formal {
            name: String::from_utf8_lossy(name_bytes).into_owned(),
            has_default: default.is_some(),
        });
    }
    Some(out)
}

/// Computes the global framework-source identity: a blake3 fold over every
/// `.nix` file under the framework roots, in canonical `(relative path, bytes)`
/// order. Any framework/stdenv source edit changes it, invalidating every
/// boundary key (§2.4).
fn framework_identity(roots: &[PathBuf]) -> Result<[u8; 32], BoundaryIdentityError> {
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    for root in roots {
        collect_nix_files(root, root, &mut files)?;
    }
    files.sort();
    let mut hasher = blake3::Hasher::new();
    hasher.update(BOUNDARY_IDENTITY_DOMAIN);
    hasher.update(b"framework");
    hasher.update(&BOUNDARY_IDENTITY_FORMAT_VERSION.to_le_bytes());
    for (rel, path) in files {
        let bytes =
            std::fs::read(&path).map_err(|source| BoundaryIdentityError::FrameworkWalk {
                path: path.clone(),
                source,
            })?;
        hasher.update(&(rel.len() as u64).to_le_bytes());
        hasher.update(rel.as_bytes());
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Recursively collects `.nix` files under `dir`, recording each as
/// `(path relative to base, absolute path)`.
fn collect_nix_files(
    base: &Path,
    dir: &Path,
    out: &mut Vec<(String, PathBuf)>,
) -> Result<(), BoundaryIdentityError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        // A configured framework root that is absent contributes nothing rather
        // than failing the whole build.
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(BoundaryIdentityError::FrameworkWalk {
                path: dir.to_path_buf(),
                source,
            });
        }
    };
    for entry in entries {
        let entry = entry.map_err(|source| BoundaryIdentityError::FrameworkWalk {
            path: dir.to_path_buf(),
            source,
        })?;
        let file_type =
            entry
                .file_type()
                .map_err(|source| BoundaryIdentityError::FrameworkWalk {
                    path: dir.to_path_buf(),
                    source,
                })?;
        let path = entry.path();
        if file_type.is_dir() {
            collect_nix_files(base, &path, out)?;
        } else if file_type.is_file() && path.extension().is_some_and(|ext| ext == "nix") {
            let rel = path
                .strip_prefix(base)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            out.push((rel, path));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
