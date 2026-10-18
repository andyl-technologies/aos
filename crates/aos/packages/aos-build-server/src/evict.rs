//! Eviction policy: TTL expiry, closure scoring, and budget enforcement.
//!
//! These primitives decide *which GC roots to drop* when a view outgrows
//! its retention policy; actually reclaiming store space is left to a
//! later `nix-store --gc`. Three mechanisms are provided:
//!
//! - **TTL expiry** ([`expire_ttl_roots`]) — removes roots whose metadata
//!   `expires_at` has passed.
//! - **Score-based eviction** ([`score_candidates`],
//!   [`evict_until_budget`]) — ranks roots by `age_days * unique_size`,
//!   where *unique size* counts only closure paths not shared with any
//!   other root, then evicts highest-score-first until the view fits its
//!   `max_store_size` budget.
//! - **Source LRU** ([`evict_source_lru`]) — caps the number of `src/`
//!   roots, dropping the least recently accessed first.
//!
//! Access recency comes from the metadata maintained by
//! [`crate::access::update_access`].

use std::collections::HashSet;
use std::fs;

use anyhow::{Context, Result};

use crate::store::NixStore;
use crate::views::ViewManager;

/// Information about a push root for eviction scoring.
#[derive(Debug)]
pub struct RootInfo {
    /// Store hash (GC root symlink name).
    pub hash: String,
    /// Full store path the root points at.
    pub store_path: String,
    /// Unix timestamp of the last access (falls back to `pushed_at`, then 0).
    pub last_accessed: i64,
    /// Number of times the path's narinfo has been served.
    pub access_count: u64,
    /// Whether the metadata marks this as an explicitly pushed root
    /// (`is_root`), as opposed to a closure member rooted alongside it.
    pub is_root: bool,
}

/// Eviction candidate with computed score.
#[derive(Debug)]
pub struct EvictionCandidate {
    /// Store hash of the candidate root.
    pub hash: String,
    /// Full store path of the candidate root.
    pub store_path: String,
    /// Total NAR size (bytes) of closure paths unique to this root.
    pub unique_size: u64,
    /// Days since the root was last accessed.
    pub age_days: f64,
    /// Eviction score: `age_days * unique_size`. Higher = evict first.
    pub score: f64,
    /// Closure paths reclaimable only by evicting this root.
    pub unique_paths: Vec<String>,
}

/// Runs TTL-based expiry for a view.
///
/// Removes GC root symlinks and metadata files (in both `bin/` and `src/`)
/// for paths whose metadata `expires_at` has passed, and returns the list
/// of expired hashes. Roots without metadata or without an `expires_at`
/// field are kept forever.
///
/// # Errors
///
/// Returns an error if the system clock is before the Unix epoch, or if a
/// root directory or metadata file cannot be read or parsed.
pub fn expire_ttl_roots(views: &ViewManager, view: &str) -> Result<Vec<String>> {
    let mut expired = Vec::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock error")?
        .as_secs() as i64;

    for ns in &["bin", "src"] {
        let gcroot_dir = views.root().join("gcroots").join(view).join(ns);
        let meta_dir = views.root().join("meta").join(view).join(ns);

        if !gcroot_dir.exists() {
            continue;
        }

        let entries = fs::read_dir(&gcroot_dir)
            .with_context(|| format!("reading {}", gcroot_dir.display()))?;

        for entry in entries {
            let entry = entry?;
            let hash = entry.file_name().to_string_lossy().to_string();

            // Skip temp files
            if hash.starts_with('.') {
                continue;
            }

            let meta_path = meta_dir.join(format!("{hash}.json"));
            if !meta_path.exists() {
                continue;
            }

            let meta_str = fs::read_to_string(&meta_path)
                .with_context(|| format!("reading {}", meta_path.display()))?;
            let meta: serde_json::Value = serde_json::from_str(&meta_str)
                .with_context(|| format!("parsing {}", meta_path.display()))?;

            if let Some(expires_at) = meta.get("expires_at").and_then(|v| v.as_i64()) {
                if expires_at > 0 && expires_at < now {
                    // Expired — remove symlink and metadata
                    let _ = fs::remove_file(entry.path());
                    let _ = fs::remove_file(&meta_path);
                    tracing::info!(view = %view, ns = %ns, hash = %hash, "path expired by TTL");
                    expired.push(hash);
                }
            }
        }
    }

    Ok(expired)
}

/// Scans all `bin/` roots in a view and loads their metadata.
///
/// Roots with no metadata file get zeroed access fields. Returns an empty
/// list if the view has no `bin/` GC root directory.
///
/// # Errors
///
/// Returns an error if the root directory cannot be listed, a symlink
/// cannot be read, or an existing metadata file cannot be read or parsed.
pub fn scan_roots(views: &ViewManager, view: &str) -> Result<Vec<RootInfo>> {
    let mut roots = Vec::new();
    let gcroot_dir = views.root().join("gcroots").join(view).join("bin");
    let meta_dir = views.root().join("meta").join(view).join("bin");

    if !gcroot_dir.exists() {
        return Ok(roots);
    }

    let entries =
        fs::read_dir(&gcroot_dir).with_context(|| format!("reading {}", gcroot_dir.display()))?;

    for entry in entries {
        let entry = entry?;
        let hash = entry.file_name().to_string_lossy().to_string();
        if hash.starts_with('.') {
            continue;
        }

        let store_path = fs::read_link(entry.path())
            .with_context(|| format!("reading symlink {}", entry.path().display()))?
            .to_string_lossy()
            .to_string();

        let meta_path = meta_dir.join(format!("{hash}.json"));
        let (last_accessed, access_count, is_root) = if meta_path.exists() {
            let meta_str = fs::read_to_string(&meta_path)?;
            let meta: serde_json::Value = serde_json::from_str(&meta_str)?;
            (
                meta.get("last_accessed")
                    .or_else(|| meta.get("pushed_at"))
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0),
                meta.get("access_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                meta.get("is_root")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
            )
        } else {
            (0, 0, false)
        };

        roots.push(RootInfo {
            hash,
            store_path,
            last_accessed,
            access_count,
            is_root,
        });
    }

    Ok(roots)
}

/// Computes the runtime closure of a store path from the Nix SQLite DB.
///
/// Performs a breadth-first walk over the `Refs` table starting at
/// `store_path` (the result includes the path itself). Paths missing from
/// the database are included in the closure but not expanded further.
///
/// # Errors
///
/// Currently infallible in practice (DB lookup failures are treated as
/// leaf paths), but returns `Result` for interface stability.
pub fn compute_closure(store: &NixStore, store_path: &str) -> Result<HashSet<String>> {
    let mut closure = HashSet::new();
    let mut queue = vec![store_path.to_string()];

    while let Some(path) = queue.pop() {
        if !closure.insert(path.clone()) {
            continue; // already visited
        }
        if let Ok(Some(info)) = store.path_info(&path) {
            for ref_path in &info.refs {
                if !closure.contains(ref_path) {
                    queue.push(ref_path.clone());
                }
            }
        }
    }

    Ok(closure)
}

/// Computes the unique paths for a root: paths in its closure that are NOT
/// in any other root's closure.
///
/// Evicting the root makes exactly these paths reclaimable by GC; shared
/// paths remain pinned by the other roots.
pub fn compute_unique(
    root_closure: &HashSet<String>,
    all_other_closures: &HashSet<String>,
) -> HashSet<String> {
    root_closure
        .difference(all_other_closures)
        .cloned()
        .collect()
}

/// Scores eviction candidates and returns them sorted by score
/// (highest first).
///
/// Score = `age_days * unique_size_bytes`, so large roots that have not
/// been accessed in a long time are evicted first. Only roots marked
/// `is_root = true` are scored; if none are marked, every root is treated
/// as a candidate. Unique sizes are computed by diffing each root's
/// closure against the union of all other candidates' closures.
///
/// # Errors
///
/// Returns an error if the system clock is before the Unix epoch or a
/// closure computation fails.
pub fn score_candidates(store: &NixStore, roots: &[RootInfo]) -> Result<Vec<EvictionCandidate>> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock error")?
        .as_secs() as i64;

    // Only score push roots (is_root = true). If none are marked,
    // treat all roots as candidates.
    let candidates: Vec<&RootInfo> = {
        let push_roots: Vec<_> = roots.iter().filter(|r| r.is_root).collect();
        if push_roots.is_empty() {
            roots.iter().collect()
        } else {
            push_roots
        }
    };

    // Compute all closures.
    let mut closures: Vec<HashSet<String>> = Vec::new();
    for root in &candidates {
        let closure = compute_closure(store, &root.store_path)?;
        closures.push(closure);
    }

    // Compute union of all other closures for each root.
    let mut results = Vec::new();
    for (i, root) in candidates.iter().enumerate() {
        let mut all_others = HashSet::new();
        for (j, closure) in closures.iter().enumerate() {
            if i != j {
                all_others.extend(closure.iter().cloned());
            }
        }

        let unique = compute_unique(&closures[i], &all_others);
        let unique_size: u64 = unique
            .iter()
            .map(|p| {
                store
                    .path_info(p)
                    .ok()
                    .flatten()
                    .map(|info| info.nar_size as u64)
                    .unwrap_or(0)
            })
            .sum();

        let age_secs = (now - root.last_accessed).max(0) as f64;
        let age_days = age_secs / 86400.0;
        let score = age_days * unique_size as f64;

        results.push(EvictionCandidate {
            hash: root.hash.clone(),
            store_path: root.store_path.clone(),
            unique_size,
            age_days,
            score,
            unique_paths: unique.into_iter().collect(),
        });
    }

    results.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Ok(results)
}

/// Evicts least-recently-accessed source roots when they exceed a count
/// limit.
///
/// If the view holds more than `max_sources` roots in the `src/`
/// namespace, the oldest (by `last_accessed`, falling back to `pushed_at`)
/// are removed until the count fits. Returns the list of evicted source
/// hashes; with `dry_run` set, the same list is returned but nothing is
/// deleted.
///
/// # Errors
///
/// Returns an error if the source root directory or a metadata file cannot
/// be read or parsed.
pub fn evict_source_lru(
    views: &ViewManager,
    view: &str,
    max_sources: usize,
    dry_run: bool,
) -> Result<Vec<String>> {
    let gcroot_dir = views.root().join("gcroots").join(view).join("src");
    let meta_dir = views.root().join("meta").join(view).join("src");

    if !gcroot_dir.exists() {
        return Ok(Vec::new());
    }

    // Collect source roots with their last_accessed timestamps.
    let mut sources: Vec<(String, i64)> = Vec::new();

    let entries =
        fs::read_dir(&gcroot_dir).with_context(|| format!("reading {}", gcroot_dir.display()))?;

    for entry in entries {
        let entry = entry?;
        let hash = entry.file_name().to_string_lossy().to_string();
        if hash.starts_with('.') {
            continue;
        }

        let meta_path = meta_dir.join(format!("{hash}.json"));
        let last_accessed = if meta_path.exists() {
            let meta_str = fs::read_to_string(&meta_path)?;
            let meta: serde_json::Value = serde_json::from_str(&meta_str)?;
            meta.get("last_accessed")
                .or_else(|| meta.get("pushed_at"))
                .and_then(|v| v.as_i64())
                .unwrap_or(0)
        } else {
            0
        };

        sources.push((hash, last_accessed));
    }

    if sources.len() <= max_sources {
        return Ok(Vec::new());
    }

    // Sort by last_accessed ascending (oldest first).
    sources.sort_by_key(|&(_, ts)| ts);

    let to_evict = sources.len() - max_sources;
    tracing::info!(view = %view, total = sources.len(), max_sources, to_evict, dry_run, "evicting LRU source roots");
    let mut evicted = Vec::new();

    for (hash, _) in sources.into_iter().take(to_evict) {
        if !dry_run {
            let link = gcroot_dir.join(&hash);
            let meta_path = meta_dir.join(format!("{hash}.json"));
            if let Err(e) = fs::remove_file(&link) {
                tracing::warn!(view = %view, hash = %hash, error = %e, "failed to remove source GC root symlink");
            }
            if let Err(e) = fs::remove_file(&meta_path) {
                tracing::warn!(view = %view, hash = %hash, error = %e, "failed to remove source GC root metadata");
            }
        }
        evicted.push(hash);
    }

    Ok(evicted)
}

/// Evicts roots until the view is under the given max size (bytes).
///
/// The view's current size is approximated as the sum of the root paths'
/// NAR sizes; if it already fits, nothing happens. Otherwise candidates
/// from [`score_candidates`] are evicted highest-score-first — removing
/// both the candidate's root and the roots of its unique closure paths —
/// until the running total drops under `max_size`. Returns the evicted
/// candidates; with `dry_run` set, the same selection is returned but no
/// files are removed.
///
/// # Errors
///
/// Returns an error if scanning roots or scoring candidates fails.
pub fn evict_until_budget(
    store: &NixStore,
    views: &ViewManager,
    view: &str,
    max_size: u64,
    dry_run: bool,
) -> Result<Vec<EvictionCandidate>> {
    let roots = scan_roots(views, view)?;

    // Compute current view size (sum of all closure sizes).
    let mut total_size: u64 = 0;
    for root in &roots {
        if let Ok(Some(info)) = store.path_info(&root.store_path) {
            total_size += info.nar_size as u64;
        }
    }

    if total_size <= max_size {
        tracing::debug!(view = %view, total_size, max_size, "view already under budget");
        return Ok(Vec::new()); // already under budget
    }

    tracing::info!(view = %view, total_size, max_size, "eviction needed, scoring candidates");

    let candidates = score_candidates(store, &roots)?;
    let mut evicted = Vec::new();

    for candidate in candidates {
        if total_size <= max_size {
            break;
        }

        if !dry_run {
            // Remove GC root symlink and metadata.
            let link = views
                .root()
                .join("gcroots")
                .join(view)
                .join("bin")
                .join(&candidate.hash);
            let meta = views
                .root()
                .join("meta")
                .join(view)
                .join("bin")
                .join(format!("{}.json", candidate.hash));
            if let Err(e) = fs::remove_file(&link) {
                tracing::warn!(view = %view, hash = %candidate.hash, error = %e, "failed to remove evicted GC root symlink");
            }
            if let Err(e) = fs::remove_file(&meta) {
                tracing::warn!(view = %view, hash = %candidate.hash, error = %e, "failed to remove evicted GC root metadata");
            }

            // Also remove unique paths' roots.
            for path in &candidate.unique_paths {
                if let Some(hash) = ViewManager::store_path_hash(path) {
                    let link = views
                        .root()
                        .join("gcroots")
                        .join(view)
                        .join("bin")
                        .join(hash);
                    let meta = views
                        .root()
                        .join("meta")
                        .join(view)
                        .join("bin")
                        .join(format!("{hash}.json"));
                    if let Err(e) = fs::remove_file(&link) {
                        tracing::warn!(view = %view, hash = %hash, error = %e, "failed to remove unique path GC root symlink");
                    }
                    if let Err(e) = fs::remove_file(&meta) {
                        tracing::warn!(view = %view, hash = %hash, error = %e, "failed to remove unique path GC root metadata");
                    }
                }
            }
        }

        tracing::info!(
            view = %view,
            hash = %candidate.hash,
            score = candidate.score,
            unique_size = candidate.unique_size,
            age_days = candidate.age_days,
            dry_run,
            "eviction candidate selected"
        );
        total_size = total_size.saturating_sub(candidate.unique_size);
        evicted.push(candidate);
    }

    Ok(evicted)
}
