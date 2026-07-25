//! Storage migration: move a registry or cache surface between storage backends.
//!
//! A managed surface lives physically at `{binding.root}/{prefix}` (or the
//! deployment default at `{prefix}`). Changing where it lives means **copying
//! every object** to the new backend before the pointer is flipped — re-pointing
//! alone would strand the content at the old location. The bucket is the source
//! of truth, so the copy is driven by walking the *old* surface with
//! [`SurfaceFetch::list`] and re-homing each object under the *new* writer.
//!
//! This module owns only the backend-agnostic copy ([`copy_surface`]); the
//! service layer builds the old reader and new writer (by resolving the current
//! and target `{binding, prefix}` through the surface providers), runs the copy,
//! then flips the DB pointer and reconciles the derived index (re-index for a
//! registry, [`rescan_cache`](crate::cache_scan::rescan_cache) for a cache).
//!
//! ```text
//! old reader (current binding/prefix)        new writer (target binding/prefix)
//!        │  list() ──> [obj, obj, …]                    │
//!        │  fetch(obj) ─────────────────── write(obj) ──▶
//!        └──────────────── copy_surface ────────────────┘
//!                    then: flip pointer + reconcile index
//! ```
//!
//! **Object size:** [`copy_surface`] buffers each object in memory to copy it.
//! Git objects, narinfos, and typical NARs are modest; a very large NAR copied
//! on the memory-bounded Worker isolate is the known limit, to be lifted by a
//! streaming or server-side copy. The copy is **additive** (it writes the new
//! location; it does not delete the old), so a failed or partial migration never
//! destroys the source — the pointer is flipped only after a clean copy.

use anyhow::{bail, Context, Result};

use crate::cache_scan::rescan_cache;
use crate::db::{Cache, Database, RegistryRecord};
use crate::fetch::{SurfaceFetch, SurfaceProvider};
use crate::reindex::Reindexer;
use crate::surface_write::{SurfaceWrite, SurfaceWriteProvider};

/// What a [`copy_surface`] pass moved.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MigrateStats {
    /// Number of objects copied.
    pub objects: usize,
    /// Total bytes copied.
    pub bytes: u64,
}

/// Copy every object on the `from` surface to the `to` surface.
///
/// Walks `from` with [`SurfaceFetch::list`] (the source store is the truth) and
/// writes each object to `to` under the same surface-relative path, so it lands
/// under the target's prefix. Backend-agnostic: `from`/`to` may be any mix of
/// default-storage R2, an external S3/R2 binding, or the native filesystem.
///
/// Additive and non-destructive: the source is never modified, so the caller can
/// flip the storage pointer only after this returns `Ok`, and a failure leaves
/// the original surface fully intact.
///
/// # Errors
///
/// Returns an error if the source cannot be listed (a store without enumeration
/// support), or on any read/write/transport failure — the first failure aborts
/// the copy.
pub async fn copy_surface(from: &dyn SurfaceFetch, to: &dyn SurfaceWrite) -> Result<MigrateStats> {
    let paths = from.list().await.context("listing source surface")?;
    let mut stats = MigrateStats::default();
    for path in &paths {
        let Some(bytes) = from
            .fetch(path)
            .await
            .with_context(|| format!("reading {path} from source"))?
        else {
            // Listed but vanished between list and fetch — skip it.
            continue;
        };
        to.write(path, &bytes)
            .await
            .with_context(|| format!("writing {path} to destination"))?;
        stats.objects += 1;
        stats.bytes += bytes.len() as u64;
    }
    Ok(stats)
}

/// Migrate a registry's surface to a different storage backend.
///
/// Copies every object from the registry's current surface to the target
/// `{binding, same prefix}`, then flips the DB pointer and re-indexes from the
/// new surface. The prefix is preserved — only the backend moves — so the
/// logical layout is unchanged. `new_binding_id` is `None` for the deployment
/// default store. Non-destructive: the old surface is left intact, and the
/// pointer flips only after a clean copy, so a mid-copy failure leaves the
/// registry serving from its original storage.
///
/// An empty registry copies nothing and just re-points (the safe fast path
/// falls out naturally).
///
/// # Errors
///
/// [`bail`]s if the target is the registry's current binding (a no-op move);
/// otherwise returns an error on surface resolution, copy, or DB failure.
pub async fn migrate_registry_storage(
    db: &Database,
    surface: &dyn SurfaceProvider,
    surface_write: &dyn SurfaceWriteProvider,
    reindexer: &dyn Reindexer,
    registry: &RegistryRecord,
    new_binding_id: Option<i64>,
) -> Result<MigrateStats> {
    if new_binding_id == registry.storage_binding_id {
        bail!("registry is already on that storage");
    }
    let old_reader = surface
        .fetcher(registry)
        .await
        .context("opening current surface")?;
    let mut target = registry.clone();
    target.storage_binding_id = new_binding_id;
    let new_writer = surface_write
        .writer(&target)
        .await
        .context("opening target surface")?;
    let stats = copy_surface(old_reader.as_ref(), new_writer.as_ref()).await?;
    db.set_registry_storage(registry.id, new_binding_id, &registry.prefix)
        .await
        .context("flipping storage pointer")?;
    // Re-index from the new surface (the pointer is flipped); a reconcile
    // failure is non-fatal — the bytes and pointer are already correct.
    let _ = reindexer.reindex(&target).await;
    Ok(stats)
}

/// Migrate a cache's surface to a different storage backend.
///
/// The cache analog of [`migrate_registry_storage`]: copy every object to the
/// target `{binding, same prefix}`, flip the pointer, then reconcile the
/// `cache_objects` index against the new surface with [`rescan_cache`]. (The
/// index rows are backend-agnostic, so this is a consistency safety net rather
/// than a rebuild.) Non-destructive and empty-safe in the same way.
///
/// # Errors
///
/// [`bail`]s on a no-op move; otherwise errors on surface resolution, copy, or
/// DB failure.
pub async fn migrate_cache_storage(
    db: &Database,
    surface: &dyn SurfaceProvider,
    surface_write: &dyn SurfaceWriteProvider,
    cache: &Cache,
    new_binding_id: Option<i64>,
) -> Result<MigrateStats> {
    if new_binding_id == cache.storage_binding_id {
        bail!("cache is already on that storage");
    }
    let old_reader = surface
        .cache_fetcher(cache)
        .await
        .context("opening current surface")?;
    let mut target = cache.clone();
    target.storage_binding_id = new_binding_id;
    let new_writer = surface_write
        .cache_writer(&target)
        .await
        .context("opening target surface")?;
    let stats = copy_surface(old_reader.as_ref(), new_writer.as_ref()).await?;
    db.set_cache_storage(cache.id, new_binding_id, &cache.prefix)
        .await
        .context("flipping storage pointer")?;
    // Reconcile the index against the new surface (non-fatal).
    if let Ok(new_reader) = surface.cache_fetcher(&target).await {
        let _ = rescan_cache(db, new_reader.as_ref(), &target).await;
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct SrcSurface {
        paths: Vec<String>,
        bodies: HashMap<String, Vec<u8>>,
    }
    #[async_trait::async_trait]
    impl SurfaceFetch for SrcSurface {
        async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.bodies.get(path).cloned())
        }
        async fn list(&self) -> Result<Vec<String>> {
            Ok(self.paths.clone())
        }
        fn describe(&self) -> String {
            "src".into()
        }
    }

    #[derive(Default)]
    struct DstSurface {
        written: Mutex<HashMap<String, Vec<u8>>>,
    }
    #[async_trait::async_trait]
    impl SurfaceWrite for DstSurface {
        async fn write(&self, path: &str, bytes: &[u8]) -> Result<()> {
            self.written
                .lock()
                .unwrap()
                .insert(path.to_string(), bytes.to_vec());
            Ok(())
        }
        async fn delete(&self, _path: &str) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn copy_surface_moves_every_listed_object() {
        let mut bodies = HashMap::new();
        bodies.insert("HEAD".to_string(), b"ref: refs/heads/main".to_vec());
        bodies.insert("objects/ab/cd".to_string(), vec![0u8; 100]);
        let src = SrcSurface {
            paths: vec!["HEAD".into(), "objects/ab/cd".into()],
            bodies,
        };
        let dst = DstSurface::default();

        let stats = copy_surface(&src, &dst).await.unwrap();
        assert_eq!(stats.objects, 2);
        assert_eq!(stats.bytes, 20 + 100);

        let written = dst.written.lock().unwrap();
        assert_eq!(written.get("HEAD").unwrap(), b"ref: refs/heads/main");
        assert_eq!(written.get("objects/ab/cd").unwrap().len(), 100);
    }
}
