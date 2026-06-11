//! View-local garbage collection driver.
//!
//! This module bundles the per-view GC steps — TTL expiry and eviction
//! scoring from [`crate::evict`], plus an optional "remove everything"
//! decommission mode — behind a single [`run_view_gc`] entry point. It is
//! consumed by the `aos` CLI for offline GC runs; the HTTP `POST /{view}/gc`
//! endpoint in [`crate::routes`] drives the same primitives directly.
//!
//! Note that this module only removes GC *roots* (symlinks and metadata).
//! Reclaiming the underlying store paths requires a subsequent
//! `nix-store --gc`, which is the caller's responsibility.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::config::ViewConfig;
use crate::evict;
use crate::store::NixStore;
use crate::views::ViewManager;

/// Result of a view-local GC operation.
pub struct GcResult {
    /// Hashes of roots removed because their TTL (`expires_at`) had passed.
    pub expired: Vec<String>,
    /// Eviction candidates scored by [`evict::score_candidates`], highest
    /// score (best to evict) first. Empty when `all` mode was requested.
    pub candidates: Vec<evict::EvictionCandidate>,
    /// In `all` (decommission) mode, the number of roots that were removed
    /// (or would be removed under `dry_run`). `None` otherwise.
    pub removed_all: Option<usize>,
}

/// Runs view-local garbage collection: TTL expiry, eviction scoring, and
/// optionally removal of all roots.
///
/// The steps are:
///
/// 1. Expire roots whose `expires_at` metadata has passed (always applied,
///    even under `dry_run`).
/// 2. If `all` is set, remove every remaining `bin/` root and its metadata
///    (decommission mode; skipped when `dry_run` is set) and return early.
/// 3. Otherwise, score the remaining roots as eviction candidates and
///    report them — nothing further is removed.
///
/// This does NOT run `nix-store --gc` — that is the caller's responsibility
/// (the binary crate handles it via its Nix runner). The `collect` flag is
/// accepted for interface symmetry but is informational only here.
///
/// # Errors
///
/// Returns an error if the Nix store database does not exist under `root`
/// (i.e. this is not an AOS server root), if it cannot be opened, or if
/// scanning roots or reading their metadata fails.
pub fn run_view_gc(
    root: PathBuf,
    view_name: &str,
    collect: bool,
    dry_run: bool,
    all: bool,
) -> Result<GcResult> {
    let db_path = root.join("var/nix/db/db.sqlite");

    if !db_path.exists() {
        bail!(
            "Nix store database not found at {}. Is this an AOS server?",
            db_path.display()
        );
    }

    let store = NixStore::open(&db_path).context("opening Nix store database")?;

    // Create a minimal ViewManager with just the target view.
    let view_config = ViewConfig {
        name: view_name.to_string(),
        ttl: None,
        source_ttl: None,
        source_mirror: true,
        anonymous_read: false,
        max_concurrent_builds: 4,
        max_store_size: None,
        max_paths: None,
    };
    let view_mgr = ViewManager::new(root.clone(), vec![view_config]);

    // Step 1: Expire TTL roots
    let expired = evict::expire_ttl_roots(&view_mgr, view_name)?;

    let mut removed_all = None;

    if all {
        // Remove ALL roots for this view (decommission mode)
        let roots = evict::scan_roots(&view_mgr, view_name)?;
        if !dry_run {
            for root_info in &roots {
                let link = view_mgr
                    .root()
                    .join("gcroots")
                    .join(view_name)
                    .join("bin")
                    .join(&root_info.hash);
                let meta = view_mgr
                    .root()
                    .join("meta")
                    .join(view_name)
                    .join("bin")
                    .join(format!("{}.json", root_info.hash));
                let _ = std::fs::remove_file(&link);
                let _ = std::fs::remove_file(&meta);
            }
        }
        removed_all = Some(roots.len());

        return Ok(GcResult {
            expired,
            candidates: Vec::new(),
            removed_all,
        });
    }

    // Step 2: Score and report eviction candidates
    let roots = evict::scan_roots(&view_mgr, view_name)?;
    let candidates = evict::score_candidates(&store, &roots)?;

    // Note: `collect` flag is informational here — the caller handles
    // the actual `nix-store --gc` invocation.
    let _ = collect;

    Ok(GcResult {
        expired,
        candidates,
        removed_all,
    })
}
