//! Physical placement copy support.
//!
//! Topology migrations create a destination placement, copy every object from
//! a selected source placement, verify it, and then promote explicit write
//! authority. This module owns only the backend-agnostic additive copy step;
//! it never mutates resource-global storage pointers because none exist.
//!
//! ```text
//! old reader (current binding/prefix)        new writer (target binding/prefix)
//!        │  list_page() ──> [obj, …]                    │
//!        │  fetch(obj) ─────────────────── write(obj) ──▶
//!        └──────────────── copy_surface ────────────────┘
//!                    then: verify + reconcile placement/authority
//! ```
//!
//! **Object size:** [`copy_surface`] buffers each object in memory to copy it.
//! Git objects, narinfos, and typical NARs are modest; a very large NAR copied
//! on the memory-bounded Worker isolate is the known limit, to be lifted by a
//! streaming or server-side copy. The copy is **additive** (it writes the new
//! location; it does not delete the old), so a failed or partial migration never
//! destroys the source.

use anyhow::{Context, Result};

use crate::fetch::{SurfaceFetch, SurfaceListingBudget};
use crate::surface_write::SurfaceWrite;

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
/// Walks `from` with [`SurfaceFetch::list_page`] (the source store is the truth) and
/// writes each object to `to` under the same surface-relative path, so it lands
/// under the target's prefix. Backend-agnostic: `from`/`to` may be any mix of
/// default-storage R2, an external S3/R2 binding, or the native filesystem.
///
/// Additive and non-destructive: the source is never modified, and a failure
/// leaves the original placement fully intact.
///
/// # Errors
///
/// Returns an error if the source cannot be listed (a store without enumeration
/// support), or on any read/write/transport failure — the first failure aborts
/// the copy.
pub async fn copy_surface(from: &dyn SurfaceFetch, to: &dyn SurfaceWrite) -> Result<MigrateStats> {
    let mut stats = MigrateStats::default();
    let mut budget = SurfaceListingBudget::default();
    let mut cursor: Option<String> = None;
    let mut prior_path: Option<String> = None;
    let mut pages = 0_usize;
    let page_limit = if cfg!(target_arch = "wasm32") {
        crate::fetch::WORKER_MAX_SURFACE_LIST_PAGE_OBJECTS
    } else {
        crate::fetch::MAX_SURFACE_LIST_PAGE_OBJECTS
    };
    loop {
        pages = pages
            .checked_add(1)
            .context("surface migration page count overflowed")?;
        let max_pages = if cfg!(target_arch = "wasm32") {
            crate::fetch::WORKER_MAX_SURFACE_LIST_PAGES
        } else {
            crate::fetch::MAX_SURFACE_LIST_PAGES
        };
        anyhow::ensure!(
            pages <= max_pages,
            "surface migration exceeded the page limit"
        );
        let page = from
            .list_page(cursor.as_deref(), page_limit)
            .await
            .context("listing source surface")?;
        page.validate(page_limit, cursor.as_deref())?;
        for path in &page.paths {
            anyhow::ensure!(
                prior_path.as_ref().is_none_or(|prior| prior < path),
                "surface listing keys are not globally increasing"
            );
            budget.record(path)?;
            prior_path = Some(path.clone());
            let Some(bytes) = from
                .fetch(path)
                .await
                .with_context(|| format!("reading {path} from source"))?
            else {
                continue;
            };
            to.write(path, &bytes)
                .await
                .with_context(|| format!("writing {path} to destination"))?;
            stats.objects = stats
                .objects
                .checked_add(1)
                .context("migration object count overflowed")?;
            stats.bytes = stats
                .bytes
                .checked_add(bytes.len() as u64)
                .context("migration byte count overflowed")?;
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
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
        async fn list_page(
            &self,
            cursor: Option<&str>,
            limit: usize,
        ) -> Result<crate::fetch::SurfaceListPage> {
            let start = cursor
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            let end = (start + limit).min(self.paths.len());
            Ok(crate::fetch::SurfaceListPage {
                paths: self.paths[start..end].to_vec(),
                evidence: Default::default(),
                next_cursor: (end < self.paths.len()).then(|| end.to_string()),
            })
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
