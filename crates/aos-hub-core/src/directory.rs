//! The global registry directory projection (RFC-0004 ch.14 Phase D).
//!
//! The instance home lists every public registry. Served live, that is a
//! `list_registries` plus a per-registry visibility/index fan-out — the N+1 that
//! makes the home's latency scale with the registry count. This module
//! materializes the **public** listing into a single KV value (the directory
//! projection) that the home reads in one [`KvStore`](crate::kv::KvStore) `get`,
//! with no database round-trip. The projection is [`rebuild`]t off the request
//! path (on publish via the [`Job::RebuildDirectory`](crate::jobs::Job) queue
//! job, or by the Cron indexer), so the per-registry fan-out runs there, once,
//! rather than on every home render.
//!
//! Only **public** registries go in the projection (it is an anonymous,
//! eventually-consistent listing); private/internal registries a caller can see
//! are still resolved per-request against the database and merged in by the home
//! handler. This is the one place the chapter accepts eventual consistency — a
//! directory.
//!
//! ```text
//! KV  dir:registries  ->  [ {slug, indexed}, … ]   (JSON, public registries)
//! ```

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::db::Database;
use crate::kv::KvStore;

/// The KV key the directory projection is stored under.
pub const DIRECTORY_KEY: &str = "dir:registries";

/// One public registry in the cached directory listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryEntry {
    /// The registry's canonical slug (the home's link target).
    pub slug: String,
    /// Whether the registry has an index-status record (the home's "index"
    /// column derives its display from this and the live status on rebuild).
    pub indexed: bool,
}

/// Rebuilds the public-registry directory from the database and stores it in KV.
///
/// Runs off the request path (a queue job or the Cron indexer), so its
/// per-registry `index_status` fan-out is paid once here rather than on every
/// home render. Returns the entries it stored.
///
/// # Errors
///
/// Returns an error if the registry list cannot be read or the KV write fails.
pub async fn rebuild(db: &Database, kv: &dyn KvStore) -> Result<Vec<DirectoryEntry>> {
    let registries = db.list_registries().await?;
    let mut entries = Vec::new();
    for registry in registries {
        // Public-only: the directory is the anonymous listing.
        if registry.visibility != "public" {
            continue;
        }
        let indexed = db.index_status(registry.id).await.ok().flatten().is_some();
        entries.push(DirectoryEntry {
            slug: registry.slug,
            indexed,
        });
    }
    let bytes = serde_json::to_vec(&entries)?;
    kv.put(DIRECTORY_KEY, &bytes, None).await?;
    Ok(entries)
}

/// Reads the cached directory projection, or `None` when it has not been built.
///
/// A `None` (cold projection) tells the home handler to fall back to a live
/// database listing for this render and trigger a [`rebuild`].
///
/// # Errors
///
/// Returns an error if the KV read fails. A corrupt/stale value (one that does
/// not deserialize) is reported as `None`, not an error, so a value-shape change
/// triggers a rebuild rather than wedging the home.
pub async fn read(kv: &dyn KvStore) -> Result<Option<Vec<DirectoryEntry>>> {
    match kv.get(DIRECTORY_KEY).await? {
        Some(bytes) => Ok(serde_json::from_slice(&bytes).ok()),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::{read, rebuild, DirectoryEntry};
    use crate::db::Database;
    use crate::kv::InMemoryKv;

    #[tokio::test]
    async fn rebuild_then_read_lists_public_registries() {
        let db = Database::open_in_memory().await.unwrap();
        let kv = InMemoryKv::new();
        // Cold projection reads as None.
        assert_eq!(read(&kv).await.unwrap(), None);
        // Create a public registry, rebuild, and read it back.
        db.register_registry("andyl/main", "https://example/", &[], false)
            .await
            .unwrap();
        let built = rebuild(&db, &kv).await.unwrap();
        assert_eq!(
            built,
            vec![DirectoryEntry {
                slug: "andyl/main".into(),
                indexed: true
            }]
        );
        let read_back = read(&kv).await.unwrap().unwrap();
        assert_eq!(read_back, built);
    }
}
