use std::collections::HashSet;
use std::fs;

use anyhow::{Context, Result};

use crate::store::NixStore;
use crate::views::ViewManager;

/// Information about a push root for eviction scoring.
#[derive(Debug)]
pub struct RootInfo {
    pub hash: String,
    pub store_path: String,
    pub last_accessed: i64,
    pub access_count: u64,
    pub is_root: bool,
}

/// Eviction candidate with computed score.
#[derive(Debug)]
pub struct EvictionCandidate {
    pub hash: String,
    pub store_path: String,
    pub unique_size: u64,
    pub age_days: f64,
    pub score: f64,
    pub unique_paths: Vec<String>,
}

/// Run TTL-based expiry for a view. Removes GC root symlinks and metadata
/// files for paths whose `expires_at` has passed.
/// Returns the list of expired hashes.
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

/// Scan all roots in a view and load their metadata.
pub fn scan_roots(views: &ViewManager, view: &str) -> Result<Vec<RootInfo>> {
    let mut roots = Vec::new();
    let gcroot_dir = views.root().join("gcroots").join(view).join("bin");
    let meta_dir = views.root().join("meta").join(view).join("bin");

    if !gcroot_dir.exists() {
        return Ok(roots);
    }

    let entries = fs::read_dir(&gcroot_dir)
        .with_context(|| format!("reading {}", gcroot_dir.display()))?;

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

/// Compute the runtime closure of a store path from the Nix SQLite DB.
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

/// Compute the unique paths for a root: paths in its closure that are NOT
/// in any other root's closure.
pub fn compute_unique(
    root_closure: &HashSet<String>,
    all_other_closures: &HashSet<String>,
) -> HashSet<String> {
    root_closure
        .difference(all_other_closures)
        .cloned()
        .collect()
}

/// Score eviction candidates and return them sorted by score (highest first).
/// Score = age_days * unique_size_bytes. Higher = evict first.
pub fn score_candidates(
    store: &NixStore,
    roots: &[RootInfo],
) -> Result<Vec<EvictionCandidate>> {
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

/// Evict least-recently-accessed source roots when they exceed a count limit.
/// Returns the list of evicted source hashes.
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

    let entries = fs::read_dir(&gcroot_dir)
        .with_context(|| format!("reading {}", gcroot_dir.display()))?;

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

/// Evict roots until the view is under the given max size (bytes).
/// Returns the list of evicted root hashes.
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
