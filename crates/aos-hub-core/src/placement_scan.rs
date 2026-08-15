//! Durable physical-placement inventory execution.
//!
//! A placement is selectable only after the controller has enumerated its
//! backend and reconciled every active logical object with byte evidence from
//! that exact placement. Registry and binary-cache scans compare the physical
//! keyset with the existing logical catalog. Cache discovery and normalization
//! remain owned by the independently fenced cache-inventory controller.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;

use crate::clock;
use crate::db::{
    Database, MAX_PLACEMENT_SCAN_PRESENCE_BATCH, PlacementScanPresence, ReusablePlacementEvidence,
    SurfaceObjectRecord, SurfacePlacementRecord, SurfaceTarget, TopologyOperationRecord,
};
use crate::fetch::{
    MAX_SURFACE_LIST_PAGE_OBJECTS, MAX_SURFACE_LIST_PAGES, SurfaceListedEvidence,
    SurfaceListingBudget, SurfaceProvider, WORKER_MAX_SURFACE_LIST_PAGE_OBJECTS,
    WORKER_MAX_SURFACE_LIST_PAGES,
};

const CLAIM_LEASE_SECONDS: i64 = 600;
const CLAIM_HEARTBEAT_SECONDS: u64 = 60;

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
            .due_surface_placement_scan_operations(clock::now_unix_secs(), limit)
            .await?;
        let mut completed = 0;
        for operation in due {
            let claim_token = uuid::Uuid::new_v4().simple().to_string();
            let Some(claimed) = self
                .db
                .claim_surface_placement_scan_operation(
                    &operation.operation_id,
                    operation.resource_version,
                    &claim_token,
                    CLAIM_LEASE_SECONDS,
                )
                .await?
            else {
                continue;
            };
            if let Err(error) = self
                .run_claimed_with_heartbeat(&claimed, &claim_token)
                .await
            {
                self.record_failure(&claimed, &claim_token, &error).await?;
            }
            completed += 1;
        }
        Ok(completed)
    }

    async fn run_claimed_with_heartbeat(
        &self,
        operation: &TopologyOperationRecord,
        claim_token: &str,
    ) -> Result<()> {
        let mut scan = Box::pin(self.run_claimed(operation, claim_token));
        loop {
            let heartbeat = Box::pin(clock::sleep(std::time::Duration::from_secs(
                CLAIM_HEARTBEAT_SECONDS,
            )));
            match futures_util::future::select(scan, heartbeat).await {
                futures_util::future::Either::Left((result, _)) => return result,
                futures_util::future::Either::Right(((), pending_scan)) => {
                    self.db
                        .heartbeat_surface_placement_scan_operation(
                            &operation.operation_id,
                            operation.resource_version,
                            claim_token,
                            clock::now_unix_secs(),
                            CLAIM_LEASE_SECONDS,
                        )
                        .await?;
                    scan = pending_scan;
                }
            }
        }
    }

    async fn run_claimed(
        &self,
        operation: &TopologyOperationRecord,
        claim_token: &str,
    ) -> Result<()> {
        let placement = self
            .db
            .surface_placement_by_operation_target(&operation.primary_target_stable_id)
            .await?
            .context("placement scan target no longer exists")?;
        if placement.resource_version != operation.primary_target_generation_key {
            bail!("placement scan target topology changed after scheduling");
        }

        let detail = if let Some(registry_id) = placement.registry_id {
            self.scan_catalog_placement(
                &placement,
                SurfaceTarget::Registry(registry_id),
                operation,
                claim_token,
            )
            .await?
        } else if let Some(cache_id) = placement.cache_id {
            self.scan_catalog_placement(
                &placement,
                SurfaceTarget::BinaryCache(cache_id),
                operation,
                claim_token,
            )
            .await?
        } else {
            bail!("placement scan target has no surface");
        };
        let now = clock::now_unix_secs();
        let total = detail
            .get("catalogObjects")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0);
        let terminalized = self
            .db
            .finish_claimed_surface_placement_scan_operation(
                &operation.operation_id,
                operation.resource_version,
                claim_token,
                "succeeded",
                total,
                Some(total),
                &detail.to_string(),
                None,
                now,
            )
            .await?;
        if !terminalized {
            bail!("placement scan claim expired or was replaced before completion");
        }
        Ok(())
    }

    async fn scan_catalog_placement(
        &self,
        placement: &SurfacePlacementRecord,
        surface: SurfaceTarget,
        operation: &TopologyOperationRecord,
        claim_token: &str,
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
                &operation.operation_id,
                operation.resource_version,
                claim_token,
            )
            .await?;
        let scanning_observation = scanning
            .observation_version
            .context("scanning placement lost its observation resource")?;
        let reusable = self
            .db
            .reusable_placement_scan_evidence(placement.id)
            .await?
            .into_iter()
            .map(|evidence| (evidence.surface_object_id, evidence))
            .collect::<BTreeMap<_, _>>();
        let objects = self.db.list_active_surface_objects(surface).await?;
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
        let mut reused = 0_i64;
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
            let listed_evidence = page.evidence;
            let mut page_presences = Vec::with_capacity(page.paths.len());
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
                if let Some(presence) = reusable_listing_presence(
                    &object,
                    listed_evidence.get(&path),
                    reusable.get(&object.id),
                ) {
                    reused += 1;
                    page_presences.push((object.resource_version, presence));
                    continue;
                }
                let evidence = fetch
                    .inventory_evidence(&path)
                    .await?
                    .with_context(|| format!("listed placement object '{path}' disappeared"))?;
                let valid = object_matches_evidence(&object, &evidence.sha256, evidence.size);
                if !valid {
                    corrupt += 1;
                }
                page_presences.push((
                    object.resource_version,
                    PlacementScanPresence {
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
                ));
            }
            for presences in page_presences.chunks(MAX_PLACEMENT_SCAN_PRESENCE_BATCH) {
                self.db
                    .record_surface_placement_scan_presences(
                        placement.id,
                        placement.resource_version,
                        scanning_observation,
                        &operation.operation_id,
                        operation.resource_version,
                        claim_token,
                        presences,
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
        for objects in catalog
            .values()
            .collect::<Vec<_>>()
            .chunks(MAX_PLACEMENT_SCAN_PRESENCE_BATCH)
        {
            let missing_presences = objects
                .iter()
                .map(|object| {
                    (
                        object.resource_version,
                        PlacementScanPresence {
                            surface_object_id: object.id,
                            state: "missing".to_string(),
                            observed_hash: None,
                            observed_size: None,
                            etag: None,
                        },
                    )
                })
                .collect::<Vec<_>>();
            self.db
                .record_surface_placement_scan_presences(
                    placement.id,
                    placement.resource_version,
                    scanning_observation,
                    &operation.operation_id,
                    operation.resource_version,
                    claim_token,
                    &missing_presences,
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
                &operation.operation_id,
                operation.resource_version,
                claim_token,
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
            "strongVersionObjects": reused,
        }))
    }

    async fn record_failure(
        &self,
        claimed: &TopologyOperationRecord,
        claim_token: &str,
        error: &anyhow::Error,
    ) -> Result<()> {
        let current = self
            .db
            .topology_operation(&claimed.operation_id)
            .await?
            .context("claimed placement scan operation disappeared")?;
        if current.state != "running" || current.resource_version != claimed.resource_version {
            return Ok(());
        }
        let now = clock::now_unix_secs();
        let message = format!("{error:#}")
            .chars()
            .take(4 * 1024)
            .collect::<String>();
        self.db
            .finish_claimed_surface_placement_scan_operation(
                &current.operation_id,
                current.resource_version,
                claim_token,
                "failed",
                current.progress_current,
                current.progress_total,
                &current.detail_json,
                Some(&message),
                now,
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

fn reusable_listing_presence(
    object: &SurfaceObjectRecord,
    listed: Option<&SurfaceListedEvidence>,
    prior: Option<&ReusablePlacementEvidence>,
) -> Option<PlacementScanPresence> {
    let listed = listed?;
    let prior = prior?;
    if prior.state != "present"
        || object.content_hash.is_none()
        || prior.observed_hash != object.content_hash
        || prior.observed_size != object.size
        || object.size != Some(listed.size)
    {
        return None;
    }

    let listed_etag = crate::surface_write::strong_if_match_etag(&listed.strong_etag).ok()?;
    let prior_etag = crate::surface_write::strong_if_match_etag(prior.etag.as_deref()?).ok()?;
    if listed_etag != prior_etag {
        return None;
    }

    Some(PlacementScanPresence {
        surface_object_id: object.id,
        state: "present".into(),
        observed_hash: object.content_hash.clone(),
        observed_size: object.size,
        etag: Some(listed_etag),
    })
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::db::{
        NewSurfacePlacementSpec, NewTopologyOperation, NewTopologyOperationTarget,
        NewTopologyOperationTargetRef, SetSurfaceObject,
    };
    use crate::domain::Permission;
    use crate::fetch::{SurfaceFetch, SurfaceListPage};
    use sha2::{Digest as _, Sha256};

    struct EmptySurfaceProvider;

    struct EmptySurface;

    struct ListedSurfaceProvider {
        body_reads: Arc<AtomicUsize>,
    }

    struct ListedSurface {
        body_reads: Arc<AtomicUsize>,
    }

    struct LargeSurfaceProvider {
        paths: Arc<Vec<String>>,
    }

    struct LargeSurface {
        paths: Arc<Vec<String>>,
    }

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
                evidence: Default::default(),
                next_cursor: None,
            })
        }

        fn describe(&self) -> String {
            "empty test surface".into()
        }
    }

    #[async_trait::async_trait]
    impl SurfaceProvider for ListedSurfaceProvider {
        async fn placement_fetcher(
            &self,
            _placement: &SurfacePlacementRecord,
        ) -> Result<Box<dyn SurfaceFetch>> {
            Ok(Box::new(ListedSurface {
                body_reads: Arc::clone(&self.body_reads),
            }))
        }
    }

    #[async_trait::async_trait]
    impl SurfaceFetch for ListedSurface {
        async fn fetch(&self, _path: &str) -> Result<Option<Vec<u8>>> {
            self.body_reads.fetch_add(1, Ordering::SeqCst);
            anyhow::bail!("listed strong-version evidence should avoid a body read")
        }

        async fn list_page(&self, _cursor: Option<&str>, _limit: usize) -> Result<SurfaceListPage> {
            Ok(SurfaceListPage {
                paths: vec!["objects/aa/bb".into()],
                evidence: [(
                    "objects/aa/bb".into(),
                    SurfaceListedEvidence {
                        size: 7,
                        strong_etag: "provider-version".into(),
                    },
                )]
                .into_iter()
                .collect(),
                next_cursor: None,
            })
        }

        async fn inventory_evidence(
            &self,
            _path: &str,
        ) -> Result<Option<crate::fetch::SurfaceObjectEvidence>> {
            self.body_reads.fetch_add(1, Ordering::SeqCst);
            anyhow::bail!("listed strong-version evidence should avoid inventory streaming")
        }

        fn describe(&self) -> String {
            "listed test surface".into()
        }
    }

    #[async_trait::async_trait]
    impl SurfaceProvider for LargeSurfaceProvider {
        async fn placement_fetcher(
            &self,
            _placement: &SurfacePlacementRecord,
        ) -> Result<Box<dyn SurfaceFetch>> {
            Ok(Box::new(LargeSurface {
                paths: Arc::clone(&self.paths),
            }))
        }
    }

    #[async_trait::async_trait]
    impl SurfaceFetch for LargeSurface {
        async fn fetch(&self, _path: &str) -> Result<Option<Vec<u8>>> {
            Ok(Some(vec![b'x']))
        }

        async fn list_page(&self, _cursor: Option<&str>, limit: usize) -> Result<SurfaceListPage> {
            assert!(self.paths.len() <= limit);
            Ok(SurfaceListPage {
                paths: self.paths.as_ref().clone(),
                evidence: Default::default(),
                next_cursor: None,
            })
        }

        async fn inventory_evidence(
            &self,
            _path: &str,
        ) -> Result<Option<crate::fetch::SurfaceObjectEvidence>> {
            Ok(Some(crate::fetch::SurfaceObjectEvidence {
                sha256: Sha256::digest(b"x").into(),
                size: 1,
                strong_etag: None,
            }))
        }

        fn describe(&self) -> String {
            "large test surface".into()
        }
    }

    async fn scan_fixture(
        slug: &str,
        operation_id: &str,
    ) -> (
        Arc<Database>,
        SurfacePlacementRecord,
        TopologyOperationRecord,
    ) {
        let db = Arc::new(Database::open_in_memory().await.unwrap());
        let org_id = db.create_org(slug, "Placement scan").await.unwrap();
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
                Some(&format!("registries/{slug}/system")),
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
                prefix: format!("registries/{slug}/system"),
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
                operation_id: operation_id.into(),
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
        (db, placement, operation)
    }

    async fn cache_scan_fixture() -> (
        Arc<Database>,
        SurfacePlacementRecord,
        TopologyOperationRecord,
    ) {
        let db = Arc::new(Database::open_in_memory().await.unwrap());
        let org_id = db
            .create_org("placement-cache-scan", "Placement cache scan")
            .await
            .unwrap();
        let org = db.org_by_id(org_id).await.unwrap().unwrap();
        let cache_id = db
            .create_binary_cache(
                Some(org_id),
                "placement-cache",
                "Placement cache",
                "public",
                40,
                "zstd",
                true,
            )
            .await
            .unwrap();
        let binding_id = db
            .create_topology_storage_binding(
                Some(org_id),
                &uuid::Uuid::new_v4().simple().to_string(),
                &org.stable_id,
                "cache-primary",
                "r2",
                None,
                Some("test-bucket"),
                Some("caches/placement-cache"),
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
                surface: SurfaceTarget::BinaryCache(cache_id),
                name: "primary".into(),
                storage_binding_id: binding_id,
                prefix: "caches/placement-cache".into(),
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
                operation_id: "scan-cache-placement".into(),
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
        (db, placement, operation)
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

    #[test]
    fn listing_reuse_requires_the_exact_prior_provider_version() {
        let object = SurfaceObjectRecord {
            id: 7,
            registry_id: Some(1),
            cache_id: None,
            object_key: "objects/aa/bb".into(),
            content_hash: Some("ab".repeat(32)),
            size: Some(9),
            object_kind: "immutable".into(),
            mutable_publication_id: None,
            lifecycle_state: "active".into(),
            tombstoned_at: None,
            created_at: 0,
            updated_at: 0,
            resource_version: 1,
        };
        let listed = SurfaceListedEvidence {
            size: 9,
            strong_etag: "provider-version".into(),
        };
        let mut prior = ReusablePlacementEvidence {
            surface_object_id: object.id,
            state: "present".into(),
            observed_hash: object.content_hash.clone(),
            observed_size: object.size,
            etag: Some("\"provider-version\"".into()),
        };

        let reused = reusable_listing_presence(&object, Some(&listed), Some(&prior)).unwrap();
        assert_eq!(reused.observed_hash, object.content_hash);
        assert_eq!(reused.etag.as_deref(), Some("\"provider-version\""));

        prior.etag = Some("different-version".into());
        assert!(reusable_listing_presence(&object, Some(&listed), Some(&prior)).is_none());
    }

    #[tokio::test]
    async fn empty_registry_scan_makes_a_new_placement_ready() {
        let (db, placement, operation) =
            scan_fixture("placement-scan", "scan-empty-registry").await;

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

    #[tokio::test]
    async fn native_listing_pages_larger_than_a_presence_batch_complete() {
        let (db, placement, operation) =
            scan_fixture("placement-scan-large-page", "scan-large-page").await;
        let registry_id = placement.registry_id.unwrap();
        let digest = hex::encode(Sha256::digest(b"x"));
        let paths = (0..300)
            .map(|index| format!("objects/{index:04}"))
            .collect::<Vec<_>>();
        for path in &paths {
            db.create_surface_object(&SetSurfaceObject {
                surface: SurfaceTarget::Registry(registry_id),
                object_key: path.clone(),
                content_hash: Some(digest.clone()),
                size: Some(1),
                object_kind: "immutable".into(),
                mutable_publication_id: None,
            })
            .await
            .unwrap();
        }

        let controller = PlacementScanController::new(
            Arc::clone(&db),
            Arc::new(LargeSurfaceProvider {
                paths: Arc::new(paths),
            }),
        );
        assert_eq!(controller.run_due(1).await.unwrap(), 1);

        let operation = db
            .topology_operation(&operation.operation_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(operation.state, "succeeded", "{:?}", operation.error);
        let placement = db.surface_placement(placement.id).await.unwrap().unwrap();
        assert_eq!(placement.state, "ready");
        assert_eq!(placement.completeness, "complete");
    }

    #[tokio::test]
    async fn cache_scan_marks_a_missing_catalog_object_degraded() {
        let (db, placement, operation) = cache_scan_fixture().await;
        db.create_surface_object(&SetSurfaceObject {
            surface: SurfaceTarget::BinaryCache(placement.cache_id.unwrap()),
            object_key: "nar/missing.nar.zst".into(),
            content_hash: Some("44".repeat(32)),
            size: Some(1),
            object_kind: "immutable".into(),
            mutable_publication_id: None,
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
        assert_eq!(operation.state, "succeeded", "{:?}", operation.error);
        let placement = db.surface_placement(placement.id).await.unwrap().unwrap();
        assert_eq!(placement.state, "degraded");
        assert_eq!(placement.completeness, "partial");
    }

    #[tokio::test]
    async fn superseded_scan_cannot_fail_the_new_claim() {
        let (db, _placement, operation) = scan_fixture("placement-scan-fence", "scan-fence").await;
        let first_token = "first-scan-claim";
        let claimed = db
            .claim_surface_placement_scan_operation(
                &operation.operation_id,
                operation.resource_version,
                first_token,
                600,
            )
            .await
            .unwrap()
            .unwrap();
        let failed = db
            .update_topology_operation(
                &claimed.operation_id,
                claimed.resource_version,
                "failed",
                0,
                None,
                &claimed.detail_json,
                Some("first claimant failed"),
                claimed.started_at,
                Some(clock::now_unix_secs()),
            )
            .await
            .unwrap();
        let pending = db
            .mutate_topology_operation(
                &failed.operation_id,
                failed.resource_version,
                "retry",
                "scan-fence-retry",
            )
            .await
            .unwrap();
        let replacement = db
            .claim_surface_placement_scan_operation(
                &pending.operation_id,
                pending.resource_version,
                "replacement-scan-claim",
                600,
            )
            .await
            .unwrap()
            .unwrap();

        let controller =
            PlacementScanController::new(Arc::clone(&db), Arc::new(EmptySurfaceProvider));
        controller
            .record_failure(
                &claimed,
                first_token,
                &anyhow::anyhow!("superseded failure"),
            )
            .await
            .unwrap();

        let current = db
            .topology_operation(&claimed.operation_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.state, "running");
        assert_eq!(current.resource_version, replacement.resource_version);
        assert!(current.error.is_none());
    }

    #[tokio::test]
    async fn heartbeat_keeps_a_long_scan_exclusive_until_its_renewed_deadline() {
        let (db, _placement, operation) =
            scan_fixture("placement-scan-heartbeat", "scan-heartbeat").await;
        let token = "heartbeat-scan-claim";
        let claimed = db
            .claim_surface_placement_scan_operation(
                &operation.operation_id,
                operation.resource_version,
                token,
                600,
            )
            .await
            .unwrap()
            .unwrap();
        let heartbeat_at = clock::now_unix_secs() + 100;
        db.heartbeat_surface_placement_scan_operation(
            &claimed.operation_id,
            claimed.resource_version,
            token,
            heartbeat_at,
            600,
        )
        .await
        .unwrap();

        assert!(
            db.due_surface_placement_scan_operations(heartbeat_at + 599, 1)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            db.due_surface_placement_scan_operations(heartbeat_at + 600, 1)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(
            db.heartbeat_surface_placement_scan_operation(
                &claimed.operation_id,
                claimed.resource_version,
                "wrong-scan-claim",
                heartbeat_at,
                600,
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn scan_completion_rejects_a_concurrent_catalog_object() {
        let (db, placement, operation) =
            scan_fixture("placement-scan-catalog", "scan-catalog").await;
        let registry_id = placement.registry_id.unwrap();
        let first = db
            .create_surface_object(&SetSurfaceObject {
                surface: SurfaceTarget::Registry(registry_id),
                object_key: "objects/first".into(),
                content_hash: Some("11".repeat(32)),
                size: Some(1),
                object_kind: "immutable".into(),
                mutable_publication_id: None,
            })
            .await
            .unwrap();
        let token = "catalog-scan-claim";
        let claimed = db
            .claim_surface_placement_scan_operation(
                &operation.operation_id,
                operation.resource_version,
                token,
                600,
            )
            .await
            .unwrap()
            .unwrap();
        let scanning = db
            .begin_surface_placement_scan(
                placement.id,
                placement.resource_version,
                placement.observation_version.unwrap(),
                &claimed.operation_id,
                claimed.resource_version,
                token,
            )
            .await
            .unwrap();
        db.record_surface_placement_scan_presences(
            placement.id,
            placement.resource_version,
            scanning.observation_version.unwrap(),
            &claimed.operation_id,
            claimed.resource_version,
            token,
            &[(
                first.resource_version,
                PlacementScanPresence {
                    surface_object_id: first.id,
                    state: "present".into(),
                    observed_hash: first.content_hash,
                    observed_size: first.size,
                    etag: Some("first-version".into()),
                },
            )],
            clock::now_unix_secs(),
        )
        .await
        .unwrap();
        let concurrent = db
            .create_surface_object(&SetSurfaceObject {
                surface: SurfaceTarget::Registry(registry_id),
                object_key: "objects/concurrent".into(),
                content_hash: Some("22".repeat(32)),
                size: Some(1),
                object_kind: "immutable".into(),
                mutable_publication_id: None,
            })
            .await
            .unwrap();

        assert!(
            db.finish_surface_placement_scan(
                placement.id,
                placement.resource_version,
                scanning.observation_version.unwrap(),
                &claimed.operation_id,
                claimed.resource_version,
                token,
                "ready",
                "complete",
            )
            .await
            .is_err()
        );
        let placement = db.surface_placement(placement.id).await.unwrap().unwrap();
        assert_eq!(placement.state, "syncing");
        assert_eq!(placement.completeness, "unknown");

        db.record_surface_placement_scan_presences(
            placement.id,
            placement.resource_version,
            scanning.observation_version.unwrap(),
            &claimed.operation_id,
            claimed.resource_version,
            token,
            &[(
                concurrent.resource_version,
                PlacementScanPresence {
                    surface_object_id: concurrent.id,
                    state: "corrupt".into(),
                    observed_hash: Some("55".repeat(32)),
                    observed_size: concurrent.size,
                    etag: Some("concurrent-version".into()),
                },
            )],
            clock::now_unix_secs(),
        )
        .await
        .unwrap();
        assert!(
            db.finish_surface_placement_scan(
                placement.id,
                placement.resource_version,
                scanning.observation_version.unwrap(),
                &claimed.operation_id,
                claimed.resource_version,
                token,
                "ready",
                "complete",
            )
            .await
            .is_err()
        );
        let placement = db.surface_placement(placement.id).await.unwrap().unwrap();
        assert_eq!(placement.state, "syncing");
        db.finish_surface_placement_scan(
            placement.id,
            placement.resource_version,
            scanning.observation_version.unwrap(),
            &claimed.operation_id,
            claimed.resource_version,
            token,
            "degraded",
            "partial",
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn scan_presence_rejects_a_superseded_object_revision() {
        let (db, placement, operation) =
            scan_fixture("placement-scan-object-fence", "scan-object-fence").await;
        let object = db
            .create_surface_object(&SetSurfaceObject {
                surface: SurfaceTarget::Registry(placement.registry_id.unwrap()),
                object_key: "objects/superseded".into(),
                content_hash: Some("33".repeat(32)),
                size: Some(1),
                object_kind: "immutable".into(),
                mutable_publication_id: None,
            })
            .await
            .unwrap();
        let token = "object-fence-scan-claim";
        let claimed = db
            .claim_surface_placement_scan_operation(
                &operation.operation_id,
                operation.resource_version,
                token,
                600,
            )
            .await
            .unwrap()
            .unwrap();
        let scanning = db
            .begin_surface_placement_scan(
                placement.id,
                placement.resource_version,
                placement.observation_version.unwrap(),
                &claimed.operation_id,
                claimed.resource_version,
                token,
            )
            .await
            .unwrap();
        assert!(
            db.tombstone_surface_object(object.id, object.resource_version, clock::now_unix_secs())
                .await
                .unwrap()
        );

        assert!(
            db.record_surface_placement_scan_presences(
                placement.id,
                placement.resource_version,
                scanning.observation_version.unwrap(),
                &claimed.operation_id,
                claimed.resource_version,
                token,
                &[(
                    object.resource_version,
                    PlacementScanPresence {
                        surface_object_id: object.id,
                        state: "present".into(),
                        observed_hash: object.content_hash,
                        observed_size: object.size,
                        etag: Some("superseded-version".into()),
                    }
                )],
                clock::now_unix_secs(),
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn scan_presence_batch_rolls_back_when_one_object_is_superseded() {
        let (db, placement, operation) =
            scan_fixture("placement-scan-batch-fence", "scan-batch-fence").await;
        let registry_id = placement.registry_id.unwrap();
        let first = db
            .create_surface_object(&SetSurfaceObject {
                surface: SurfaceTarget::Registry(registry_id),
                object_key: "objects/first".into(),
                content_hash: Some("44".repeat(32)),
                size: Some(4),
                object_kind: "immutable".into(),
                mutable_publication_id: None,
            })
            .await
            .unwrap();
        let superseded = db
            .create_surface_object(&SetSurfaceObject {
                surface: SurfaceTarget::Registry(registry_id),
                object_key: "objects/superseded".into(),
                content_hash: Some("55".repeat(32)),
                size: Some(5),
                object_kind: "immutable".into(),
                mutable_publication_id: None,
            })
            .await
            .unwrap();
        let token = "batch-fence-scan-claim";
        let claimed = db
            .claim_surface_placement_scan_operation(
                &operation.operation_id,
                operation.resource_version,
                token,
                600,
            )
            .await
            .unwrap()
            .unwrap();
        let scanning = db
            .begin_surface_placement_scan(
                placement.id,
                placement.resource_version,
                placement.observation_version.unwrap(),
                &claimed.operation_id,
                claimed.resource_version,
                token,
            )
            .await
            .unwrap();
        assert!(
            db.tombstone_surface_object(
                superseded.id,
                superseded.resource_version,
                clock::now_unix_secs(),
            )
            .await
            .unwrap()
        );

        let presences = vec![
            (
                first.resource_version,
                PlacementScanPresence {
                    surface_object_id: first.id,
                    state: "present".into(),
                    observed_hash: first.content_hash,
                    observed_size: first.size,
                    etag: Some("first-version".into()),
                },
            ),
            (
                superseded.resource_version,
                PlacementScanPresence {
                    surface_object_id: superseded.id,
                    state: "present".into(),
                    observed_hash: superseded.content_hash,
                    observed_size: superseded.size,
                    etag: Some("superseded-version".into()),
                },
            ),
        ];
        assert!(
            db.record_surface_placement_scan_presences(
                placement.id,
                placement.resource_version,
                scanning.observation_version.unwrap(),
                &claimed.operation_id,
                claimed.resource_version,
                token,
                &presences,
                clock::now_unix_secs(),
            )
            .await
            .is_err()
        );
        assert!(
            db.reusable_placement_scan_evidence(placement.id)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn scan_reuses_matching_strong_provider_evidence_without_streaming() {
        let (db, placement, operation) = scan_fixture("placement-scan-reuse", "scan-reuse").await;
        let registry_id = placement.registry_id.unwrap();
        let digest = hex::encode(Sha256::digest(b"payload"));
        let object = db
            .create_surface_object(&SetSurfaceObject {
                surface: SurfaceTarget::Registry(registry_id),
                object_key: "objects/aa/bb".into(),
                content_hash: Some(digest.clone()),
                size: Some(7),
                object_kind: "immutable".into(),
                mutable_publication_id: None,
            })
            .await
            .unwrap();
        let seed_token = "seed-scan-claim";
        let claimed = db
            .claim_surface_placement_scan_operation(
                &operation.operation_id,
                operation.resource_version,
                seed_token,
                600,
            )
            .await
            .unwrap()
            .unwrap();
        let scanning = db
            .begin_surface_placement_scan(
                placement.id,
                placement.resource_version,
                placement.observation_version.unwrap(),
                &claimed.operation_id,
                claimed.resource_version,
                seed_token,
            )
            .await
            .unwrap();
        db.record_surface_placement_scan_presences(
            placement.id,
            placement.resource_version,
            scanning.observation_version.unwrap(),
            &claimed.operation_id,
            claimed.resource_version,
            seed_token,
            &[(
                object.resource_version,
                PlacementScanPresence {
                    surface_object_id: object.id,
                    state: "present".into(),
                    observed_hash: Some(digest),
                    observed_size: Some(7),
                    etag: Some("\"provider-version\"".into()),
                },
            )],
            clock::now_unix_secs(),
        )
        .await
        .unwrap();
        db.finish_surface_placement_scan(
            placement.id,
            placement.resource_version,
            scanning.observation_version.unwrap(),
            &claimed.operation_id,
            claimed.resource_version,
            seed_token,
            "ready",
            "complete",
        )
        .await
        .unwrap();
        let failed = db
            .finish_claimed_surface_placement_scan_operation(
                &claimed.operation_id,
                claimed.resource_version,
                seed_token,
                "failed",
                0,
                None,
                &claimed.detail_json,
                Some("seeded prior evidence"),
                clock::now_unix_secs(),
            )
            .await
            .unwrap();
        assert!(failed);
        let failed = db
            .topology_operation(&claimed.operation_id)
            .await
            .unwrap()
            .unwrap();
        db.mutate_topology_operation(
            &failed.operation_id,
            failed.resource_version,
            "retry",
            "scan-reuse-retry",
        )
        .await
        .unwrap();

        let body_reads = Arc::new(AtomicUsize::new(0));
        let controller = PlacementScanController::new(
            Arc::clone(&db),
            Arc::new(ListedSurfaceProvider {
                body_reads: Arc::clone(&body_reads),
            }),
        );
        assert_eq!(controller.run_due(1).await.unwrap(), 1);
        assert_eq!(body_reads.load(Ordering::SeqCst), 0);

        let operation = db
            .topology_operation(&operation.operation_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(operation.state, "succeeded", "{:?}", operation.error);
        assert!(operation.detail_json.contains("\"strongVersionObjects\":1"));
    }
}
