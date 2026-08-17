//! MEMO-2 applied-package boundary admission recognition (M2-record incr. 2).
//!
//! Recognizes package-boundary applications at the apply seam against the
//! source-Merkle [`BoundaryIdentityMap`](crate::cache::boundary_identity) and
//! validates the recognition with a counter — no record store, no replay yet.
//!
//! The immutable map is built once and held in a process-wide cache keyed by the
//! package-set root, so every worker thread shares one instance with no
//! per-evaluator or per-worker rebuild (the parallel-worker "hold as `Arc`,
//! refcount-bump" requirement, satisfied by a single shared static). Collection
//! is opt-in behind `AOS_NIX_BOUNDARY_MEMO`, so a normal or production evaluation
//! never builds the map or touches these statics.
//!
//! The counter is emitted as one greppable JSON line to stderr on the
//! `AOS_NIX_EVAL_STATS` dump path:
//!
//! ```text
//! aos_nix_boundary_admission {"recognized_applications":812,"distinct_def_sites":248,
//!   "distinct_package_modules":248,"keyed_boundaries":265}
//! ```

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::cache::boundary_identity::{
    BoundaryIdentityConfig, BoundaryIdentityMap, build_boundary_identity_map,
};

use super::BoundaryMemoOptions;

/// Process-wide cache of the built map, keyed by package-set root. `None` inner
/// value records a build that produced no map (kept so a failed build is not
/// retried on every apply).
static MAP_CACHE: Mutex<Option<(PathBuf, Option<Arc<BoundaryIdentityMap>>)>> = Mutex::new(None);

/// Total applications recognized as keyed package boundaries.
static RECOGNIZED_APPLICATIONS: AtomicU64 = AtomicU64::new(0);
/// Distinct `(module, pattern)` boundary def-sites recognized.
static DEF_SITES: Mutex<Option<HashSet<u64>>> = Mutex::new(None);
/// Distinct package modules whose boundary was recognized (≈ packages reached).
static PACKAGE_MODULES: Mutex<Option<HashSet<u32>>> = Mutex::new(None);
/// Total keyable boundaries in the built map (the denominator for coverage).
static KEYED_BOUNDARIES: AtomicU64 = AtomicU64::new(0);

/// Returns the process-wide boundary-identity map for `config`, building it once
/// (keyed by package-set root) and sharing the `Arc` across every caller.
///
/// Returns `None` when no package-set root is configured or the build fails; a
/// failed build is cached as `None` so it is not retried per apply.
pub(super) fn boundary_map(
    config: &BoundaryMemoOptions,
    parse_cache_root: Option<&Path>,
) -> Option<Arc<BoundaryIdentityMap>> {
    let pkgs_root = config.pkgs_root.as_ref()?;
    let mut guard = MAP_CACHE.lock().ok()?;
    if let Some((cached_root, cached_map)) = guard.as_ref() {
        if cached_root == pkgs_root {
            return cached_map.clone();
        }
    }
    let cache_root = parse_cache_root.map_or_else(
        || std::env::temp_dir().join(format!("aos-nix-boundary-{}", std::process::id())),
        Path::to_path_buf,
    );
    let build_config = BoundaryIdentityConfig {
        pkgs_root: pkgs_root.clone(),
        framework_roots: config.framework_roots.clone(),
        parse_cache_root: cache_root,
    };
    let map = build_boundary_identity_map(&build_config)
        .ok()
        .map(Arc::new);
    if let Some(map) = &map {
        KEYED_BOUNDARIES.store(map.keyed_len() as u64, Ordering::Relaxed);
    }
    *guard = Some((pkgs_root.clone(), map.clone()));
    map
}

/// Records one recognized package-boundary application.
///
/// `def_site` is `(module.index() << 32) | pattern IrId`; `module_index` is the
/// applied lambda's module. A poisoned probe lock is a lost sample, silently
/// skipped — this is diagnostic instrumentation and must never perturb eval.
pub(super) fn note_boundary_application(module_index: u32, def_site: u64) {
    RECOGNIZED_APPLICATIONS.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut guard) = DEF_SITES.lock() {
        guard.get_or_insert_with(HashSet::new).insert(def_site);
    }
    if let Ok(mut guard) = PACKAGE_MODULES.lock() {
        guard.get_or_insert_with(HashSet::new).insert(module_index);
    }
}

/// Prints the boundary-admission recognition counters as one JSON line to
/// stderr, or does nothing when no boundary was recognized.
pub(super) fn emit_boundary_admission_report() {
    let applications = RECOGNIZED_APPLICATIONS.load(Ordering::Relaxed);
    if applications == 0 {
        return;
    }
    let def_sites = DEF_SITES
        .lock()
        .ok()
        .and_then(|guard| guard.as_ref().map(HashSet::len))
        .unwrap_or(0);
    let modules = PACKAGE_MODULES
        .lock()
        .ok()
        .and_then(|guard| guard.as_ref().map(HashSet::len))
        .unwrap_or(0);
    let keyed = KEYED_BOUNDARIES.load(Ordering::Relaxed);
    eprintln!(
        "aos_nix_boundary_admission {{\"recognized_applications\":{applications},\"distinct_def_sites\":{def_sites},\"distinct_package_modules\":{modules},\"keyed_boundaries\":{keyed}}}"
    );
}

/// Returns the process-wide count of recognized boundary applications (tests).
#[cfg(test)]
pub(super) fn recognized_applications() -> u64 {
    RECOGNIZED_APPLICATIONS.load(Ordering::Relaxed)
}
