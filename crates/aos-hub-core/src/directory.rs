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

use crate::db::{Database, IndexStatus, RegistryRecord};
use crate::kv::KvStore;

/// The KV key the directory projection is stored under.
pub const DIRECTORY_KEY: &str = "dir:registries";

/// One public registry in the cached directory listing.
///
/// Carries exactly what the instance-home table renders (slug, source, and the
/// index state/name/description), so the home can be served from the projection
/// with no database round-trip — see [`DirectoryEntry::to_row`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryEntry {
    /// The registry's canonical slug (the home's link target).
    pub slug: String,
    /// The index state token (`fresh`/`empty`/`failed`/…, or `unregistered`
    /// when there is no index-status record).
    pub state: String,
    /// The indexed display name, if any (the home's "name" column + search).
    pub name: Option<String>,
    /// The indexed description, if any (home search).
    pub description: Option<String>,
}

impl DirectoryEntry {
    /// Reconstructs the `(RegistryRecord, Option<IndexStatus>)` row the home
    /// renderer ([`instance_home`](crate::web::browse_pages::instance_home))
    /// consumes, from the projection.
    ///
    /// Only the fields the renderer reads (`slug` and the index
    /// `state`/`name`/`description`) are populated; the rest carry inert
    /// defaults, since the home table never reads them. `state == "unregistered"`
    /// maps to no index-status record (the renderer's `None` arm).
    #[must_use]
    pub fn to_row(&self) -> (RegistryRecord, Option<IndexStatus>) {
        let record = RegistryRecord {
            id: 0,
            stable_id: "registry:00000000000000000000000000000000".to_string(),
            scope_key: "registry:00000000000000000000000000000000".to_string(),
            owner_scope_key: "instance".to_string(),
            slug: self.slug.clone(),
            trust_keys: Vec::new(),
            require_signatures: false,
            org_id: None,
            project_path: String::new(),
            visibility: "public".to_string(),
            crawl_policy: String::new(),
            llms_txt_body: None,
            resource_version: 1,
            updated_at: 0,
        };
        let status = if self.state == "unregistered" {
            None
        } else {
            Some(IndexStatus {
                state: self.state.clone(),
                error: None,
                last_indexed_commit: None,
                name: self.name.clone(),
                description: self.description.clone(),
                readme: None,
                indexed_at: None,
                generation: 0,
                content_digest: None,
            })
        };
        (record, status)
    }
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
        let status = db.index_status(registry.id).await.ok().flatten();
        entries.push(DirectoryEntry {
            slug: registry.slug,
            state: status
                .as_ref()
                .map(|s| s.state.clone())
                .unwrap_or_else(|| "unregistered".to_string()),
            name: status.as_ref().and_then(|s| s.name.clone()),
            description: status.as_ref().and_then(|s| s.description.clone()),
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
    use super::{read, rebuild};
    use crate::db::Database;
    use crate::kv::InMemoryKv;

    #[tokio::test]
    async fn rebuild_then_read_lists_public_registries() {
        let db = Database::open_in_memory().await.unwrap();
        let kv = InMemoryKv::new();
        // Cold projection reads as None.
        assert_eq!(read(&kv).await.unwrap(), None);
        // Create a public registry, rebuild, and read it back.
        let org = db.create_org("andyl", "Andyl").await.unwrap();
        db.create_managed_registry(org, "", "main", "public", &[], false)
            .await
            .unwrap();
        let built = rebuild(&db, &kv).await.unwrap();
        assert_eq!(built.len(), 1);
        assert_eq!(built[0].slug, "andyl/main");
        // A freshly-registered registry has an "empty" index-status record.
        assert_eq!(built[0].state, "empty");
        let read_back = read(&kv).await.unwrap().unwrap();
        assert_eq!(read_back, built);
        // The reconstructed row carries the slug the home renders.
        let (record, status) = built[0].to_row();
        assert_eq!(record.slug, "andyl/main");
        assert_eq!(status.unwrap().state, "empty");
    }
}
