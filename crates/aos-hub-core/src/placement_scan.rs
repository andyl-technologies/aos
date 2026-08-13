//! Durable physical-placement inventory execution.
//!
//! A placement is selectable only after the controller has enumerated its
//! backend and reconciled every active logical object with byte evidence from
//! that exact placement. Registry scans compare the physical keyset with the
//! publication catalog. Binary-cache scans reuse the generation-based cache
//! inventory transaction, which discovers and normalizes NAR metadata before
//! publishing its evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::{bail, Context as _, Result};
use base64::Engine as _;

use crate::clock;
use crate::db::{
    Database, PlacementScanPresence, SurfaceObjectRecord, SurfacePlacementRecord, SurfaceTarget,
    TopologyOperationRecord,
};
use crate::fetch::{
    SurfaceListingBudget, SurfaceProvider, MAX_SURFACE_LIST_PAGES, MAX_SURFACE_LIST_PAGE_OBJECTS,
    WORKER_MAX_SURFACE_LIST_PAGES, WORKER_MAX_SURFACE_LIST_PAGE_OBJECTS,
};

const CLAIM_LEASE_SECONDS: i64 = 600;

/// Executes reviewed physical-placement scan operations.
pub struct PlacementScanController {
    db: Arc<Database>,
    surfaces: Arc<dyn SurfaceProvider>,
}

impl PlacementScanController {
    /// Creates a placement scan controller over one database and surface provider.
    #[must_use]
    pub fn new(db: Arc<Database>, surfaces: Arc<dyn SurfaceProvider>) -> Self {
        Self { db, surfaces }
    }

    /// Claims and executes at most the requested number of due placement scans.
    ///
    /// # Errors
    ///
    /// Returns an error when operation inventory, claiming, scan execution, or
    /// terminal-state persistence fails.
    pub async fn run_due(&self, limit: usize) -> Result<usize> {
        let due = self
            .db
            .due_surface_placement_scan_operations(
                clock::now_unix_secs() - CLAIM_LEASE_SECONDS,
                limit,
            )
            .await?;
        let mut completed = 0;
        for operation in due {
            let Some(claimed) = self
                .db
                .claim_surface_placement_scan_operation(
                    &operation.operation_id,
                    operation.resource_version,
                    CLAIM_LEASE_SECONDS,
                )
                .await?
            else {
                continue;
            };
            if let Err(error) = self.run_claimed(&claimed).await {
                self.record_failure(&claimed, &error).await?;
            }
            completed += 1;
        }
        Ok(completed)
    }

    async fn run_claimed(&self, operation: &TopologyOperationRecord) -> Result<()> {
        let placement = self
            .db
            .surface_placement_by_operation_target(&operation.primary_target_stable_id)
            .await?
            .context("placement scan target no longer exists")?;
        if placement.resource_version != operation.primary_target_generation_key {
            bail!("placement scan target topology changed after scheduling");
        }

        let detail = if let Some(registry_id) = placement.registry_id {
            self.scan_registry_placement(&placement, registry_id)
                .await?
        } else if let Some(cache_id) = placement.cache_id {
            self.scan_cache_placement(&placement, cache_id).await?
        } else {
            bail!("placement scan target has no surface");
        };
        let now = clock::now_unix_secs();
        let total = detail
            .get("catalogObjects")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0);
        self.db
            .update_topology_operation(
                &operation.operation_id,
                operation.resource_version,
                "succeeded",
                total,
                Some(total),
                &detail.to_string(),
                None,
                operation.started_at.or(Some(now)),
                Some(now),
            )
            .await?;
        Ok(())
    }

    async fn scan_registry_placement(
        &self,
        placement: &SurfacePlacementRecord,
        registry_id: i64,
    ) -> Result<serde_json::Value> {
        let initial_observation = placement
            .observation_version
            .context("placement has no observation resource")?;
        let scanning = self
            .db
            .begin_surface_placement_scan(
                placement.id,
                placement.resource_version,
                initial_observation,
            )
            .await?;
        let scanning_observation = scanning
            .observation_version
            .context("scanning placement lost its observation resource")?;
        let objects = self
            .db
            .list_active_surface_objects(SurfaceTarget::Registry(registry_id))
            .await?;
        let catalog_objects = i64::try_from(objects.len()).context("catalog size overflowed")?;
        let mut catalog = objects
            .into_iter()
            .map(|object| (object.object_key.clone(), object))
            .collect::<BTreeMap<_, _>>();

        let fetch = self
            .surfaces
            .placement_fetcher(placement)
            .await
            .with_context(|| format!("opening placement '{}'", placement.name))?;
        let page_limit = if cfg!(target_arch = "wasm32") {
            WORKER_MAX_SURFACE_LIST_PAGE_OBJECTS
        } else {
            MAX_SURFACE_LIST_PAGE_OBJECTS
        };
        let max_pages = if cfg!(target_arch = "wasm32") {
            WORKER_MAX_SURFACE_LIST_PAGES
        } else {
            MAX_SURFACE_LIST_PAGES
        };
        let mut cursor = None;
        let mut prior_path: Option<String> = None;
        let mut listed = BTreeSet::new();
        let mut budget = SurfaceListingBudget::default();
        let mut pages = 0_usize;
        let mut unknown = 0_i64;
        let mut corrupt = 0_i64;
        let observed_at = clock::now_unix_secs();

        loop {
            pages = pages
                .checked_add(1)
                .context("placement scan page overflow")?;
            if pages > max_pages {
                bail!("placement scan exceeded the page limit");
            }
            let page = fetch
                .list_page(cursor.as_deref(), page_limit)
                .await
                .with_context(|| format!("listing placement '{}'", placement.name))?;
            page.validate(page_limit, cursor.as_deref())?;
            for path in page.paths {
                if prior_path.as_ref().is_some_and(|prior| prior >= &path) {
                    bail!("placement returned keys out of global order");
                }
                budget.record(&path)?;
                prior_path = Some(path.clone());
                listed.insert(path.clone());

                let Some(object) = catalog.remove(&path) else {
                    unknown += 1;
                    continue;
                };
                let evidence = fetch
                    .inventory_evidence(&path)
                    .await?
                    .with_context(|| format!("listed placement object '{path}' disappeared"))?;
                let valid = object_matches_evidence(&object, &evidence.sha256, evidence.size);
                if !valid {
                    corrupt += 1;
                }
                self.db
                    .record_surface_placement_scan_presence(
                        placement.id,
                        placement.resource_version,
                        scanning_observation,
                        &PlacementScanPresence {
                            surface_object_id: object.id,
                            state: if valid { "present" } else { "corrupt" }.to_string(),
                            observed_hash: Some(if valid {
                                object
                                    .content_hash
                                    .clone()
                                    .context("valid catalog object has no content hash")?
                            } else {
                                format!("sha256:{}", hex::encode(evidence.sha256))
                            }),
                            observed_size: Some(evidence.size),
                            etag: evidence.strong_etag,
                        },
                        observed_at,
                    )
                    .await?;
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }

        let missing = i64::try_from(catalog.len()).context("missing object count overflowed")?;
        for object in catalog.values() {
            self.db
                .record_surface_placement_scan_presence(
                    placement.id,
                    placement.resource_version,
                    scanning_observation,
                    &PlacementScanPresence {
                        surface_object_id: object.id,
                        state: "missing".to_string(),
                        observed_hash: None,
                        observed_size: None,
                        etag: None,
                    },
                    observed_at,
                )
                .await?;
        }

        let complete = unknown == 0 && corrupt == 0 && missing == 0;
        self.db
            .finish_surface_placement_scan(
                placement.id,
                placement.resource_version,
                scanning_observation,
                if complete { "ready" } else { "degraded" },
                if complete { "complete" } else { "partial" },
            )
            .await?;

        Ok(serde_json::json!({
            "phase": "complete",
            "catalogObjects": catalog_objects,
            "listedObjects": listed.len(),
            "unknownObjects": unknown,
            "missingObjects": missing,
            "corruptObjects": corrupt,
        }))
    }

    async fn scan_cache_placement(
        &self,
        placement: &SurfacePlacementRecord,
        cache_id: i64,
    ) -> Result<serde_json::Value> {
        let initial_observation = placement
            .observation_version
            .context("placement has no observation resource")?;
        let scanning = self
            .db
            .begin_surface_placement_scan(
                placement.id,
                placement.resource_version,
                initial_observation,
            )
            .await?;
        let scanning_observation = scanning
            .observation_version
            .context("scanning placement lost its observation resource")?;
        let cache = self
            .db
            .binary_cache_by_id(cache_id)
            .await?
            .context("placement cache no longer exists")?;
        let stats =
            crate::cache_scan::rescan_cache(&self.db, self.surfaces.as_ref(), &cache).await?;
        self.db
            .finish_surface_placement_scan(
                placement.id,
                placement.resource_version,
                scanning_observation,
                "ready",
                "complete",
            )
            .await?;
        Ok(serde_json::json!({
            "phase": "complete",
            "catalogObjects": i64::try_from(stats.added + stats.unchanged).unwrap_or(i64::MAX),
            "addedObjects": stats.added,
            "removedObjects": stats.removed,
            "unchangedObjects": stats.unchanged,
        }))
    }

    async fn record_failure(
        &self,
        claimed: &TopologyOperationRecord,
        error: &anyhow::Error,
    ) -> Result<()> {
        let current = self
            .db
            .topology_operation(&claimed.operation_id)
            .await?
            .context("claimed placement scan operation disappeared")?;
        if current.state != "running" {
            return Ok(());
        }
        let now = clock::now_unix_secs();
        let message = format!("{error:#}")
            .chars()
            .take(4 * 1024)
            .collect::<String>();
        self.db
            .update_topology_operation(
                &current.operation_id,
                current.resource_version,
                "failed",
                current.progress_current,
                current.progress_total,
                &current.detail_json,
                Some(&message),
                current.started_at.or(Some(now)),
                Some(now),
            )
            .await?;
        Ok(())
    }
}

fn object_matches_evidence(
    object: &SurfaceObjectRecord,
    digest: &[u8; 32],
    observed_size: i64,
) -> bool {
    object.size == Some(observed_size)
        && object
            .content_hash
            .as_deref()
            .is_some_and(|expected| sha256_hash_matches(expected, digest))
}

fn sha256_hash_matches(expected: &str, digest: &[u8; 32]) -> bool {
    let hex_digest = hex::encode(digest);
    if expected.len() == 64 && expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return expected.eq_ignore_ascii_case(&hex_digest);
    }
    if let Some(encoded) = expected.strip_prefix("sha256:") {
        return encoded.eq_ignore_ascii_case(&hex_digest);
    }
    expected
        .strip_prefix("sha256-")
        .is_some_and(|encoded| encoded == base64::engine::general_purpose::STANDARD.encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{
        NewSurfacePlacementSpec, NewTopologyOperation, NewTopologyOperationTarget,
        NewTopologyOperationTargetRef,
    };
    use crate::domain::Permission;
    use crate::fetch::{SurfaceFetch, SurfaceListPage};
    use sha2::{Digest as _, Sha256};

    struct EmptySurfaceProvider;

    struct EmptySurface;

    #[async_trait::async_trait]
    impl SurfaceProvider for EmptySurfaceProvider {
        async fn placement_fetcher(
            &self,
            _placement: &SurfacePlacementRecord,
        ) -> Result<Box<dyn SurfaceFetch>> {
            Ok(Box::new(EmptySurface))
        }
    }

    #[async_trait::async_trait]
    impl SurfaceFetch for EmptySurface {
        async fn fetch(&self, _path: &str) -> Result<Option<Vec<u8>>> {
            Ok(None)
        }

        async fn list_page(&self, _cursor: Option<&str>, _limit: usize) -> Result<SurfaceListPage> {
            Ok(SurfaceListPage {
                paths: Vec::new(),
                next_cursor: None,
            })
        }

        fn describe(&self) -> String {
            "empty test surface".into()
        }
    }

    #[test]
    fn evidence_matching_accepts_registry_digest_encodings() {
        let digest: [u8; 32] = Sha256::digest(b"placement").into();
        let hex = hex::encode(digest);
        let sri = base64::engine::general_purpose::STANDARD.encode(digest);
        for content_hash in [
            hex,
            format!("sha256:{}", hex::encode(digest)),
            format!("sha256-{sri}"),
        ] {
            let object = SurfaceObjectRecord {
                id: 1,
                registry_id: Some(1),
                cache_id: None,
                object_key: "HEAD".into(),
                content_hash: Some(content_hash),
                size: Some(9),
                object_kind: "mutable_pointer".into(),
                mutable_publication_id: Some("publication".into()),
                lifecycle_state: "active".into(),
                tombstoned_at: None,
                created_at: 0,
                updated_at: 0,
                resource_version: 1,
            };
            assert!(object_matches_evidence(&object, &digest, 9));
            assert!(!object_matches_evidence(&object, &digest, 8));
        }
    }

    #[tokio::test]
    async fn empty_registry_scan_makes_a_new_placement_ready() {
        let db = Arc::new(Database::open_in_memory().await.unwrap());
        let org_id = db
            .create_org("placement-scan", "Placement scan")
            .await
            .unwrap();
        let org = db.org_by_id(org_id).await.unwrap().unwrap();
        let registry_id = db
            .create_managed_registry(org_id, "", "system", "public", &[], false)
            .await
            .unwrap();
        let binding_id = db
            .create_topology_storage_binding(
                Some(org_id),
                &uuid::Uuid::new_v4().simple().to_string(),
                &org.stable_id,
                "primary",
                "r2",
                None,
                Some("test-bucket"),
                Some("registries/placement-scan/system"),
                Some("https"),
                Some("dns"),
                Some(b"storage.example.invalid"),
                Some(443),
                Some("auto"),
                Some("private"),
            )
            .await
            .unwrap();
        let placement = db
            .create_surface_placement(&NewSurfacePlacementSpec {
                surface: SurfaceTarget::Registry(registry_id),
                name: "primary".into(),
                storage_binding_id: binding_id,
                prefix: "registries/placement-scan/system".into(),
                kind: "complete".into(),
                desired_state: "active".into(),
                hash_range: None,
                desired_read_enabled: true,
                read_order: 0,
                requires_conditional_writes: false,
            })
            .await
            .unwrap();
        let operation = db
            .create_topology_operation(&NewTopologyOperation {
                operation_id: "scan-empty-registry".into(),
                operation_kind: "scan_placement".into(),
                control_permission: Permission::StorageManage,
                targets: vec![NewTopologyOperationTarget {
                    role: "primary".into(),
                    target: NewTopologyOperationTargetRef::Placement(placement.id),
                    generation_key: placement.resource_version,
                    configuration_digest: String::new(),
                }],
                detail_json: serde_json::json!({"phase":"pending"}).to_string(),
                progress_total: None,
            })
            .await
            .unwrap();

        let controller =
            PlacementScanController::new(Arc::clone(&db), Arc::new(EmptySurfaceProvider));
        assert_eq!(controller.run_due(1).await.unwrap(), 1);

        let operation = db
            .topology_operation(&operation.operation_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            operation.state, "succeeded",
            "scan failed: {:?}",
            operation.error
        );
        let placement = db.surface_placement(placement.id).await.unwrap().unwrap();
        assert_eq!(placement.state, "ready");
        assert_eq!(placement.completeness, "complete");
    }
}
