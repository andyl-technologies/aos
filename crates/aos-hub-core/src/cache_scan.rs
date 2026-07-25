//! Cache surface re-scan: reconcile the D1 `cache_objects` index from the
//! bucket (the source of truth).
//!
//! A cache's bytes live authoritatively on its S3/R2 surface; the D1
//! `cache_objects` rows are a *derived, rebuildable* index that exists only so
//! metadata questions (search/mass-query, GC refcounting, quota/usage, browse)
//! are D1 queries rather than full-bucket walks. That index is normally kept
//! current by a write-through when a narinfo is written *through the facade* —
//! but the hub also mints presigned `PUT` URLs (for any machine path, narinfos
//! included), so `apr` can write objects **directly to the bucket**, bypassing
//! the write-through. Those objects then exist on the surface but are missing
//! from the index — drift.
//!
//! [`rescan_cache`] is the reconciliation the facade comment always promised
//! ("rebuildable by a re-scan"): it walks the surface (authoritative) and makes
//! the index match it — adding narinfos that drifted in and pruning rows whose
//! narinfo is gone. It is the cache analog of the registry indexer
//! ([`crate::indexer`]), which already re-derives a git surface's index from
//! the surface on the Cron schedule.

use std::collections::HashSet;

use anyhow::{Context, Result};

use crate::clock;
use crate::db::{Cache, Database};
use crate::fetch::SurfaceFetch;

/// What a [`rescan_cache`] pass changed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RescanStats {
    /// Narinfos found on the surface but missing from the index — parsed and
    /// inserted (objects that drifted in via a direct, facade-bypassing upload).
    pub added: usize,
    /// Index rows pruned because their narinfo is no longer on the surface.
    pub removed: usize,
    /// Narinfos present in both the surface and the index, left untouched.
    pub unchanged: usize,
}

/// Reconcile a cache's `cache_objects` index against its surface.
///
/// The surface (the bucket) is the source of truth. This lists every
/// root-level `<hash>.narinfo` on it, then:
///
/// - **adds** any narinfo missing from the index — fetched, parsed, upserted
///   (the drifted-in case: a presigned direct upload that bypassed the facade
///   write-through), and
/// - **prunes** any index row whose narinfo is no longer on the surface (the
///   drifted-out case: an object deleted straight from the bucket).
///
/// Only narinfos *absent* from the index are fetched, so a steady-state cache
/// costs one `list` and zero object reads. `refresh_cache_usage` is recomputed
/// at the end so quota/usage reflect the reconciled set.
///
/// # Errors
///
/// Returns an error when the surface cannot be listed (e.g. a store with no
/// enumeration support) or on a database failure. A single malformed narinfo is
/// skipped, not fatal.
pub async fn rescan_cache(
    db: &Database,
    fetch: &dyn SurfaceFetch,
    cache: &Cache,
) -> Result<RescanStats> {
    let now = clock::now_unix_secs();

    // The surface = truth: every root-level `<hash>.narinfo`. A non-root
    // `*.narinfo` (a slash in the stem) is not a Nix narinfo location.
    let paths = fetch.list().await.context("listing cache surface")?;
    let surface: HashSet<String> = paths
        .iter()
        .filter_map(|p| p.strip_suffix(".narinfo"))
        .filter(|h| !h.contains('/'))
        .map(str::to_string)
        .collect();

    // What the index currently holds (`-1` = all rows).
    let indexed: HashSet<String> = db
        .list_cache_objects(cache.id, -1)
        .await?
        .into_iter()
        .map(|o| o.store_hash)
        .collect();

    let mut stats = RescanStats::default();

    // Drifted in: on the surface, missing from the index.
    for hash in surface.difference(&indexed) {
        let path = format!("{hash}.narinfo");
        let Some(bytes) = fetch.fetch(&path).await? else {
            continue;
        };
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue;
        };
        if let Some(object) = crate::service::parse_cache_narinfo(cache.id, hash, text, now) {
            db.upsert_cache_object(&object).await?;
            stats.added += 1;
        }
    }

    // Drifted out: indexed, but the narinfo is gone from the surface.
    for hash in indexed.difference(&surface) {
        if db.delete_cache_object(cache.id, hash).await? {
            stats.removed += 1;
        }
    }

    stats.unchanged = indexed.intersection(&surface).count();
    db.refresh_cache_usage(cache.id).await?;
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::CacheObject;
    use std::collections::HashMap;

    /// A surface whose `list`/`fetch` come from in-memory maps.
    struct MockSurface {
        paths: Vec<String>,
        bodies: HashMap<String, Vec<u8>>,
    }

    #[async_trait::async_trait]
    impl SurfaceFetch for MockSurface {
        async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.bodies.get(path).cloned())
        }
        async fn list(&self) -> Result<Vec<String>> {
            Ok(self.paths.clone())
        }
        fn describe(&self) -> String {
            "mock".into()
        }
    }

    fn narinfo(hash: &str) -> Vec<u8> {
        format!(
            "StorePath: /nix/store/{hash}-foo-1.0\nURL: nar/{hash}.nar.zst\n\
             Compression: zstd\nNarHash: sha256:n\nNarSize: 1\nFileHash: sha256:f\nFileSize: 1\n"
        )
        .into_bytes()
    }

    #[tokio::test]
    async fn rescan_adds_surface_drift_and_prunes_missing() {
        let db = Database::open_in_memory().await.unwrap();
        let cache_id = db
            .create_cache(None, "c", "C", None, "c", None, "public", 40, "zstd", true)
            .await
            .unwrap();
        let cache = db.cache_by_id(cache_id).await.unwrap().unwrap();

        // Pre-seed the index with a row whose narinfo is NOT on the surface — it
        // must be pruned.
        db.upsert_cache_object(&CacheObject {
            cache_id,
            store_hash: "stale".into(),
            store_name: "stale-x".into(),
            nar_url: "nar/stale.nar.zst".into(),
            nar_hash: "sha256:s".into(),
            nar_size: 1,
            file_hash: "sha256:s".into(),
            file_size: 1,
            compression: "zstd".into(),
            deriver: None,
            refs: vec![],
            sig: None,
            ca: None,
            uploaded_at: 0,
            last_accessed_at: None,
        })
        .await
        .unwrap();

        // The surface (truth) holds two narinfos that drifted in directly, plus a
        // NAR (ignored by the index) — and not `stale`.
        let mut bodies = HashMap::new();
        bodies.insert("aaaa.narinfo".to_string(), narinfo("aaaa"));
        bodies.insert("bbbb.narinfo".to_string(), narinfo("bbbb"));
        let surface = MockSurface {
            paths: vec![
                "aaaa.narinfo".into(),
                "bbbb.narinfo".into(),
                "nar/aaaa.nar.zst".into(),
                "nix-cache-info".into(),
            ],
            bodies,
        };

        let stats = rescan_cache(&db, &surface, &cache).await.unwrap();
        assert_eq!(stats.added, 2, "both drifted-in narinfos indexed");
        assert_eq!(stats.removed, 1, "the stale row pruned");

        assert!(db.cache_object(cache_id, "aaaa").await.unwrap().is_some());
        assert!(db.cache_object(cache_id, "bbbb").await.unwrap().is_some());
        assert!(
            db.cache_object(cache_id, "stale").await.unwrap().is_none(),
            "pruned row is gone"
        );

        // A second pass is a no-op: everything now matches.
        let again = rescan_cache(&db, &surface, &cache).await.unwrap();
        assert_eq!(again.added, 0);
        assert_eq!(again.removed, 0);
        assert_eq!(again.unchanged, 2);
    }
}
