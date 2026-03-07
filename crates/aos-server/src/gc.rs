use std::path::PathBuf;

use anyhow::{bail, Context, Result};

use crate::config::ViewConfig;
use crate::evict;
use crate::store::NixStore;
use crate::views::ViewManager;

/// Result of a view-local GC operation.
pub struct GcResult {
    pub expired: Vec<String>,
    pub candidates: Vec<evict::EvictionCandidate>,
    pub removed_all: Option<usize>,
}

/// Run view-local garbage collection: TTL expiry, eviction scoring, and
/// optionally remove all roots.
///
/// This does NOT run `nix-store --gc` — that is the caller's responsibility
/// (the binary crate handles it via NixRunner).
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
