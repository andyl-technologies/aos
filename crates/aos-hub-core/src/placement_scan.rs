//! Durable physical-placement copy and inventory execution.
//!
//! A placement is selectable only after the controller has enumerated its
//! backend and reconciled every active logical object with byte evidence from
//! that exact placement. Registry and binary-cache scans compare the physical
//! keyset with the existing logical catalog. Replication and repair first make
//! an additive physical copy, then run that same exact inventory before the
//! destination becomes selectable. Cache discovery and normalization remain
//! owned by the independently fenced cache-inventory controller.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::{bail, Context as _, Result};
use base64::Engine as _;
use futures_util::TryStreamExt as _;

use crate::clock;
use crate::db::{
    Database, PlacementScanPresence, ReusablePlacementEvidence, SurfaceObjectRecord,
    SurfacePlacementRecord, SurfaceTarget, TopologyOperationRecord,
    MAX_PLACEMENT_SCAN_PRESENCE_BATCH,
};
use crate::fetch::{
    SurfaceFetch, SurfaceListedEvidence, SurfaceListingBudget, SurfaceProvider,
    MAX_SURFACE_LIST_PAGES, MAX_SURFACE_LIST_PAGE_OBJECTS, WORKER_MAX_SURFACE_LIST_PAGES,
    WORKER_MAX_SURFACE_LIST_PAGE_OBJECTS,
};
use crate::surface_write::{PartTag, SurfaceWrite, SurfaceWriteProvider};

const CLAIM_LEASE_SECONDS: i64 = 600;
const CLAIM_HEARTBEAT_SECONDS: u64 = 60;
const COPY_PART_BYTES: usize = 8 * 1024 * 1024;

/// Executes reviewed physical-placement copy and scan operations.
pub struct PlacementScanController {
    db: Arc<Database>,
    surfaces: Arc<dyn SurfaceProvider>,
    writes: Option<Arc<dyn SurfaceWriteProvider>>,
}

impl PlacementScanController {
    /// Creates a placement operation controller over one database and surface provider.
    #[must_use]
    pub fn new(db: Arc<Database>, surfaces: Arc<dyn SurfaceProvider>) -> Self {
        Self {
            db,
            surfaces,
            writes: None,
        }
    }

    /// Adds the physical write port required by replication and repair operations.
    #[must_use]
    pub fn with_writes(mut self, writes: Arc<dyn SurfaceWriteProvider>) -> Self {
        self.writes = Some(writes);
        self
    }

    /// Claims and executes at most the requested number of due placement operations.
    ///
    /// # Errors
    ///
    /// Returns an error when operation inventory, claiming, copy or scan
    /// execution, or terminal-state persistence fails.
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
            .context("placement operation target no longer exists")?;
        if placement.resource_version != operation.primary_target_generation_key {
            bail!("placement operation target topology changed after scheduling");
        }

        let copy_detail = match operation.operation_kind.as_str() {
            "scan_placement" => None,
            "replicate_placement" | "repair_placement" => {
                Some(self.copy_to_placement(operation, &placement).await?)
            }
            kind => bail!("unsupported physical placement operation '{kind}'"),
        };
        let mut detail = if let Some(registry_id) = placement.registry_id {
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
            bail!("placement operation target has no surface");
        };
        if let Some(copy_detail) = copy_detail {
            detail["copy"] = copy_detail;
        }
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

    async fn copy_to_placement(
        &self,
        operation: &TopologyOperationRecord,
        destination: &SurfacePlacementRecord,
    ) -> Result<serde_json::Value> {
        let source_target = self
            .db
            .topology_operation_targets(&operation.operation_id)
            .await?
            .into_iter()
            .find(|target| target.role == "source")
            .context("physical placement copy has no sealed source target")?;
        let source = self
            .db
            .surface_placement_by_operation_target(&source_target.stable_id)
            .await?
            .context("physical placement copy source no longer exists")?;
        if source.resource_version != source_target.generation_key {
            bail!("physical placement copy source topology changed after scheduling");
        }
        let writes = self
            .writes
            .as_ref()
            .context("physical placement copy has no configured write provider")?;
        let fetch = self.surfaces.placement_fetcher(&source).await?;
        let destination_fetch = self.surfaces.placement_fetcher(destination).await?;
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
        let destination_evidence = collect_listing_evidence(
            destination_fetch.as_ref(),
            page_limit,
            max_pages,
            "destination",
        )
        .await?;
        let writer = writes.placement_writer(destination).await?;
        let mut cursor = None;
        let mut prior_path: Option<String> = None;
        let mut budget = SurfaceListingBudget::default();
        let mut pages = 0_usize;
        let mut copied_objects = 0_i64;
        let mut copied_bytes = 0_u64;
        let mut reused_objects = 0_i64;
        loop {
            pages = pages
                .checked_add(1)
                .context("placement copy page overflow")?;
            if pages > max_pages {
                bail!("placement copy exceeded the page limit");
            }
            let page = fetch.list_page(cursor.as_deref(), page_limit).await?;
            page.validate(page_limit, cursor.as_deref())?;
            let source_evidence = page.evidence;
            for path in page.paths {
                if prior_path.as_ref().is_some_and(|prior| prior >= &path) {
                    bail!("placement copy source returned keys out of global order");
                }
                budget.record(&path)?;
                prior_path = Some(path.clone());
                if matching_listing_evidence(
                    source_evidence.get(&path),
                    destination_evidence.get(&path),
                )? {
                    reused_objects = reused_objects
                        .checked_add(1)
                        .context("placement copy reuse count overflow")?;
                    continue;
                }
                let size = copy_surface_object(fetch.as_ref(), writer.as_ref(), &path).await?;
                copied_objects = copied_objects
                    .checked_add(1)
                    .context("placement copy object count overflow")?;
                copied_bytes = copied_bytes
                    .checked_add(size)
                    .context("placement copy byte count overflow")?;
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        Ok(serde_json::json!({
            "source": source.name,
            "destination": destination.name,
            "copiedObjects": copied_objects,
            "copiedBytes": copied_bytes,
            "reusedObjects": reused_objects,
        }))
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
                let expected_size = u64::try_from(
                    object
                        .size
                        .context("placement catalog object has no expected size")?,
                )
                .context("placement catalog object has a negative size")?;
                let evidence = fetch
                    .inventory_evidence_bounded(&path, expected_size)
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

        // Completeness is defined against the logical catalog. Providers may
        // contain control-plane objects such as draft refs that deliberately
        // are not part of a published surface catalog. Keep reporting those
        // objects for audit and cleanup, but do not make a byte-complete
        // placement permanently ineligible for reads.
        let complete = corrupt == 0 && missing == 0;
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

async fn collect_listing_evidence(
    fetch: &dyn SurfaceFetch,
    page_limit: usize,
    max_pages: usize,
    role: &str,
) -> Result<BTreeMap<String, SurfaceListedEvidence>> {
    let mut cursor = None;
    let mut prior_path: Option<String> = None;
    let mut budget = SurfaceListingBudget::default();
    let mut evidence = BTreeMap::new();
    let mut pages = 0_usize;
    loop {
        pages = pages
            .checked_add(1)
            .with_context(|| format!("placement copy {role} page overflow"))?;
        if pages > max_pages {
            bail!("placement copy {role} exceeded the page limit");
        }
        let page = fetch.list_page(cursor.as_deref(), page_limit).await?;
        page.validate(page_limit, cursor.as_deref())?;
        for path in &page.paths {
            if prior_path.as_ref().is_some_and(|prior| prior >= path) {
                bail!("placement copy {role} returned keys out of global order");
            }
            budget.record(path)?;
            prior_path = Some(path.clone());
        }
        evidence.extend(page.evidence);
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    Ok(evidence)
}

fn matching_listing_evidence(
    source: Option<&SurfaceListedEvidence>,
    destination: Option<&SurfaceListedEvidence>,
) -> Result<bool> {
    let Some((source, destination)) = source.zip(destination) else {
        return Ok(false);
    };
    if source.size != destination.size {
        return Ok(false);
    }
    let source_etag = crate::surface_write::strong_if_match_etag(&source.strong_etag)?;
    let destination_etag = crate::surface_write::strong_if_match_etag(&destination.strong_etag)?;
    Ok(source_etag == destination_etag)
}

async fn copy_surface_object(
    fetch: &dyn SurfaceFetch,
    writer: &dyn SurfaceWrite,
    path: &str,
) -> Result<u64> {
    let read = fetch
        .fetch_stream(path, None)
        .await?
        .with_context(|| format!("placement copy source object '{path}' disappeared"))?;
    let expected = read.total;
    let mut stream = read.body.into_data_stream();
    if expected <= COPY_PART_BYTES as u64 {
        let capacity = usize::try_from(expected).context("placement copy object is too large")?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .context("allocating bounded placement copy object")?;
        while let Some(chunk) = stream.try_next().await? {
            let next = bytes
                .len()
                .checked_add(chunk.len())
                .context("placement copy object size overflowed")?;
            if next > capacity {
                bail!("placement copy source object '{path}' exceeded its declared size");
            }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.len() != capacity {
            bail!("placement copy source object '{path}' did not match its declared size");
        }
        writer.write(path, &bytes).await?;
        return Ok(expected);
    }
    if writer.multipart_protocol_version() != Some(1) {
        bail!("placement copy destination does not support multipart protocol v1");
    }

    let upload_id = writer.create_multipart(path).await?;
    let result: Result<(Vec<PartTag>, u64)> = async {
        let mut parts = Vec::new();
        let mut pending = Vec::with_capacity(COPY_PART_BYTES);
        let mut received = 0_u64;
        while let Some(chunk) = stream.try_next().await? {
            received = received
                .checked_add(u64::try_from(chunk.len())?)
                .context("placement copy object size overflowed")?;
            if received > expected {
                bail!("placement copy source object '{path}' exceeded its declared size");
            }
            let mut offset = 0;
            while offset < chunk.len() {
                let take = (COPY_PART_BYTES - pending.len()).min(chunk.len() - offset);
                pending.extend_from_slice(&chunk[offset..offset + take]);
                offset += take;
                if pending.len() == COPY_PART_BYTES {
                    let part_number = u32::try_from(parts.len() + 1)?;
                    parts.push(
                        writer
                            .upload_part(path, &upload_id, part_number, &pending)
                            .await?,
                    );
                    pending.clear();
                }
            }
        }
        if received != expected {
            bail!("placement copy source object '{path}' did not match its declared size");
        }
        if !pending.is_empty() {
            let part_number = u32::try_from(parts.len() + 1)?;
            parts.push(
                writer
                    .upload_part(path, &upload_id, part_number, &pending)
                    .await?,
            );
        }
        Ok((parts, received))
    }
    .await;
    match result {
        Ok((parts, received)) => {
            if let Err(error) = writer.complete_multipart(path, &upload_id, &parts).await {
                let _ = writer.abort_multipart(path, &upload_id).await;
                return Err(error);
            }
            writer.settle_multipart(path, &upload_id).await?;
            Ok(received)
        }
        Err(error) => {
            let _ = writer.abort_multipart(path, &upload_id).await;
            Err(error)
        }
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
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use super::*;
    use crate::db::{
        NewSurfacePlacementSpec, NewTopologyOperation, NewTopologyOperationTarget,
        NewTopologyOperationTargetRef, SetSurfaceObject,
    };
    use crate::domain::Permission;
    use crate::fetch::{SurfaceFetch, SurfaceListPage};
    use crate::surface_write::SurfaceWrite;
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

    #[derive(Clone, Default)]
    struct CopySurfaceProvider {
        objects: Arc<Mutex<HashMap<String, BTreeMap<String, Vec<u8>>>>>,
    }

    struct CopySurface {
        placement: String,
        objects: Arc<Mutex<HashMap<String, BTreeMap<String, Vec<u8>>>>>,
    }

    struct CopySurfaceWriter {
        placement: String,
        objects: Arc<Mutex<HashMap<String, BTreeMap<String, Vec<u8>>>>>,
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

    #[async_trait::async_trait]
    impl SurfaceProvider for CopySurfaceProvider {
        async fn placement_fetcher(
            &self,
            placement: &SurfacePlacementRecord,
        ) -> Result<Box<dyn SurfaceFetch>> {
            Ok(Box::new(CopySurface {
                placement: placement.name.clone(),
                objects: Arc::clone(&self.objects),
            }))
        }
    }

    #[async_trait::async_trait]
    impl SurfaceWriteProvider for CopySurfaceProvider {
        async fn placement_writer(
            &self,
            placement: &SurfacePlacementRecord,
        ) -> Result<Box<dyn SurfaceWrite>> {
            Ok(Box::new(CopySurfaceWriter {
                placement: placement.name.clone(),
                objects: Arc::clone(&self.objects),
            }))
        }

        async fn placement_deleter(
            &self,
            placement: &SurfacePlacementRecord,
            _expected_binding_resource_version: i64,
            _delete_credential_generation: i64,
        ) -> Result<Box<dyn SurfaceWrite>> {
            self.placement_writer(placement).await
        }
    }

    #[async_trait::async_trait]
    impl SurfaceFetch for CopySurface {
        async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
            Ok(self
                .objects
                .lock()
                .map_err(|_| anyhow::anyhow!("copy surface lock is poisoned"))?
                .get(&self.placement)
                .and_then(|objects| objects.get(path))
                .cloned())
        }

        async fn list_page(&self, _cursor: Option<&str>, limit: usize) -> Result<SurfaceListPage> {
            let entries = self
                .objects
                .lock()
                .map_err(|_| anyhow::anyhow!("copy surface lock is poisoned"))?
                .get(&self.placement)
                .map(|objects| {
                    objects
                        .iter()
                        .map(|(path, bytes)| {
                            (
                                path.clone(),
                                SurfaceListedEvidence {
                                    size: i64::try_from(bytes.len()).unwrap(),
                                    strong_etag: hex::encode(Sha256::digest(bytes)),
                                },
                            )
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            anyhow::ensure!(entries.len() <= limit, "test surface exceeded one page");
            Ok(SurfaceListPage {
                paths: entries.iter().map(|(path, _)| path.clone()).collect(),
                evidence: entries.into_iter().collect(),
                next_cursor: None,
            })
        }

        fn describe(&self) -> String {
            format!("copy test surface {}", self.placement)
        }
    }

    #[async_trait::async_trait]
    impl SurfaceWrite for CopySurfaceWriter {
        async fn write(&self, path: &str, bytes: &[u8]) -> Result<()> {
            self.objects
                .lock()
                .map_err(|_| anyhow::anyhow!("copy surface lock is poisoned"))?
                .entry(self.placement.clone())
                .or_default()
                .insert(path.to_string(), bytes.to_vec());
            Ok(())
        }

        async fn delete(&self, path: &str) -> Result<()> {
            if let Some(objects) = self
                .objects
                .lock()
                .map_err(|_| anyhow::anyhow!("copy surface lock is poisoned"))?
                .get_mut(&self.placement)
            {
                objects.remove(path);
            }
            Ok(())
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
            .create_topology_binding(
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
                binding_id: binding_id,
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
            .create_topology_binding(
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
                binding_id: binding_id,
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
    async fn replication_copies_then_verifies_the_destination() {
        let (db, source, _) = scan_fixture("placement-copy", "scan-copy-source").await;
        let registry_id = source.registry_id.unwrap();
        let body = b"ref: refs/heads/main\n".to_vec();
        db.create_surface_object(&SetSurfaceObject {
            surface: SurfaceTarget::Registry(registry_id),
            object_key: "HEAD".into(),
            content_hash: Some(hex::encode(Sha256::digest(&body))),
            size: Some(i64::try_from(body.len()).unwrap()),
            object_kind: "immutable".into(),
            mutable_publication_id: None,
        })
        .await
        .unwrap();
        let destination = db
            .create_surface_placement(&NewSurfacePlacementSpec {
                surface: SurfaceTarget::Registry(registry_id),
                name: "canonical".into(),
                binding_id: source.binding_id,
                prefix: "placement-copy/system".into(),
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
                operation_id: "replicate-copy-destination".into(),
                operation_kind: "replicate_placement".into(),
                control_permission: Permission::StorageManage,
                targets: vec![
                    NewTopologyOperationTarget {
                        role: "source".into(),
                        target: NewTopologyOperationTargetRef::Placement(source.id),
                        generation_key: source.resource_version,
                        configuration_digest: String::new(),
                    },
                    NewTopologyOperationTarget {
                        role: "primary".into(),
                        target: NewTopologyOperationTargetRef::Placement(destination.id),
                        generation_key: destination.resource_version,
                        configuration_digest: String::new(),
                    },
                ],
                detail_json: serde_json::json!({"phase":"pending"}).to_string(),
                progress_total: None,
            })
            .await
            .unwrap();
        let provider = CopySurfaceProvider::default();
        provider
            .objects
            .lock()
            .unwrap()
            .entry(source.name.clone())
            .or_default()
            .insert("HEAD".into(), body.clone());

        let controller = PlacementScanController::new(Arc::clone(&db), Arc::new(provider.clone()))
            .with_writes(Arc::new(provider.clone()));
        assert_eq!(controller.run_due(2).await.unwrap(), 2);

        let operation = db
            .topology_operation(&operation.operation_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(operation.state, "succeeded", "{:?}", operation.error);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&operation.detail_json).unwrap()["copy"]
                ["copiedObjects"],
            1
        );
        let destination = db.surface_placement(destination.id).await.unwrap().unwrap();
        assert_eq!(destination.state, "ready");
        assert_eq!(destination.completeness, "complete");
        assert_eq!(provider.objects.lock().unwrap()["canonical"]["HEAD"], body);

        let retry = db
            .create_topology_operation(&NewTopologyOperation {
                operation_id: "replicate-copy-destination-retry".into(),
                operation_kind: "replicate_placement".into(),
                control_permission: Permission::StorageManage,
                targets: vec![
                    NewTopologyOperationTarget {
                        role: "source".into(),
                        target: NewTopologyOperationTargetRef::Placement(source.id),
                        generation_key: source.resource_version,
                        configuration_digest: String::new(),
                    },
                    NewTopologyOperationTarget {
                        role: "primary".into(),
                        target: NewTopologyOperationTargetRef::Placement(destination.id),
                        generation_key: destination.resource_version,
                        configuration_digest: String::new(),
                    },
                ],
                detail_json: serde_json::json!({"phase":"pending"}).to_string(),
                progress_total: None,
            })
            .await
            .unwrap();
        assert_eq!(controller.run_due(1).await.unwrap(), 1);
        let retry = db
            .topology_operation(&retry.operation_id)
            .await
            .unwrap()
            .unwrap();
        let retry_detail = serde_json::from_str::<serde_json::Value>(&retry.detail_json).unwrap();
        assert_eq!(retry_detail["copy"]["copiedObjects"], 0);
        assert_eq!(retry_detail["copy"]["reusedObjects"], 1);
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
    async fn uncataloged_control_objects_do_not_degrade_a_complete_placement() {
        let (db, placement, operation) =
            scan_fixture("placement-scan-control-object", "scan-control-object").await;
        let registry_id = placement.registry_id.unwrap();
        let catalog_path = "objects/aa/cataloged";
        db.create_surface_object(&SetSurfaceObject {
            surface: SurfaceTarget::Registry(registry_id),
            object_key: catalog_path.into(),
            content_hash: Some(hex::encode(Sha256::digest(b"x"))),
            size: Some(1),
            object_kind: "immutable".into(),
            mutable_publication_id: None,
        })
        .await
        .unwrap();

        let controller = PlacementScanController::new(
            Arc::clone(&db),
            Arc::new(LargeSurfaceProvider {
                paths: Arc::new(vec![catalog_path.into(), "refs/hub/changes/draft".into()]),
            }),
        );
        assert_eq!(controller.run_due(1).await.unwrap(), 1);

        let operation = db
            .topology_operation(&operation.operation_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(operation.state, "succeeded", "{:?}", operation.error);
        let detail: serde_json::Value = serde_json::from_str(&operation.detail_json).unwrap();
        assert_eq!(detail["unknownObjects"], 1);
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

        assert!(db
            .due_surface_placement_scan_operations(heartbeat_at + 599, 1)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            db.due_surface_placement_scan_operations(heartbeat_at + 600, 1)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(db
            .heartbeat_surface_placement_scan_operation(
                &claimed.operation_id,
                claimed.resource_version,
                "wrong-scan-claim",
                heartbeat_at,
                600,
            )
            .await
            .is_err());
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

        assert!(db
            .finish_surface_placement_scan(
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
            .is_err());
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
        assert!(db
            .finish_surface_placement_scan(
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
            .is_err());
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
        assert!(db
            .tombstone_surface_object(object.id, object.resource_version, clock::now_unix_secs())
            .await
            .unwrap());

        assert!(db
            .record_surface_placement_scan_presences(
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
            .is_err());
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
        assert!(db
            .tombstone_surface_object(
                superseded.id,
                superseded.resource_version,
                clock::now_unix_secs(),
            )
            .await
            .unwrap());

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
        assert!(db
            .record_surface_placement_scan_presences(
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
            .is_err());
        assert!(db
            .reusable_placement_scan_evidence(placement.id)
            .await
            .unwrap()
            .is_empty());
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
