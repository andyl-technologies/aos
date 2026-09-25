//! Native client for bounded work executed beside an object store by Workers.
//!
//! The Native Hub signs an exact, short-lived plan and accepts only a matching
//! typed result. Placement and binding rows remain authoritative in SQL; the
//! caller rechecks their revisions before committing any derived state.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context as _, Result};
use aos_hub_core::db::{
    BindingRecord, BindingWriteRevisionRecord, Database, OciUploadChunkRecord,
    SurfacePlacementRecord,
};
use aos_hub_core::fetch::{
    DocumentationInspection, StreamedRead, SurfaceDeliveryHead, SurfaceFetch, SurfaceListPage,
    SurfaceListedEvidence, SurfaceObjectEvidence, SurfaceProvider,
};
use aos_hub_core::storage_work::{
    StorageCapabilities, StorageGitObjectProjection, StorageOciChunkSource, StorageWorkKey,
    StorageWorkOperation, StorageWorkOutcome, StorageWorkPlan, StorageWorkResult,
    MAX_DOCUMENTATION_ROWS, MAX_GIT_INSPECTION_BATCH, MAX_GIT_INSPECTION_CONTENT_BYTES,
    MAX_METADATA_BYTES, MAX_OCI_RANGE_BYTES, MAX_RESULT_BYTES, MAX_VERIFY_SOURCE_BYTES,
    STORAGE_CAPABILITIES_CHALLENGE, STORAGE_CAPABILITIES_PATH, STORAGE_WORK_PATH,
    STORAGE_WORK_SIGNATURE_HEADER,
};
use aos_hub_core::surface_write::{FrozenSurfaceAccess, SurfaceWrite, SurfaceWriteProvider};
use aos_registry_surface::{object, object_bundle};
use async_trait::async_trait;
use base64::Engine as _;
use futures_util::StreamExt as _;

/// Authenticated Native-to-Worker executor client.
pub struct RemoteStorageWorkClient {
    endpoint: String,
    capabilities_endpoint: String,
    deployment_id: String,
    key: StorageWorkKey,
    http: reqwest::Client,
}

impl RemoteStorageWorkClient {
    /// Creates a client for one explicit HTTPS Worker authority.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid URL, weak key, or HTTP client setup.
    pub fn new(worker_origin: &str, deployment_id: String, key: &[u8]) -> Result<Self> {
        let origin = url::Url::parse(worker_origin).context("parsing storage Worker origin")?;
        anyhow::ensure!(
            origin.scheme() == "https"
                && origin.path() == "/"
                && origin.query().is_none()
                && origin.fragment().is_none()
                && origin.username().is_empty()
                && origin.password().is_none(),
            "storage Worker URL must be an HTTPS origin"
        );
        anyhow::ensure!(!deployment_id.is_empty(), "deployment identity is required");
        let endpoint = format!(
            "{}{}",
            origin.origin().ascii_serialization(),
            STORAGE_WORK_PATH
        );
        let capabilities_endpoint = format!(
            "{}{}",
            origin.origin().ascii_serialization(),
            STORAGE_CAPABILITIES_PATH
        );
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .context("building storage Worker client")?;
        Ok(Self {
            endpoint,
            capabilities_endpoint,
            deployment_id,
            key: StorageWorkKey::new(key)?,
            http,
        })
    }

    /// Confirms that the paired Worker has the expected deployment and R2 contract.
    ///
    /// # Errors
    ///
    /// Returns an error if the Worker is unavailable, unauthenticated,
    /// mismatched, or missing a required operation or R2 binding.
    pub async fn check_ready(&self) -> Result<()> {
        let signature = self.key.sign_body(STORAGE_CAPABILITIES_CHALLENGE)?;
        let response = self
            .http
            .post(&self.capabilities_endpoint)
            .header(STORAGE_WORK_SIGNATURE_HEADER, signature)
            .body(STORAGE_CAPABILITIES_CHALLENGE.to_vec())
            .send()
            .await
            .context("probing the hybrid storage Worker")?;
        anyhow::ensure!(
            response.status() == reqwest::StatusCode::OK,
            "hybrid storage Worker returned HTTP {} during readiness probe",
            response.status()
        );
        let body = read_bounded_response(response, 4096).await?;
        let capabilities: StorageCapabilities =
            serde_json::from_slice(&body).context("decoding storage Worker capabilities")?;
        validate_capabilities(&self.deployment_id, &capabilities)
    }

    /// Builds one short-lived plan from the selected SQL placement and binding.
    ///
    /// # Errors
    ///
    /// Returns an error if the placement and binding differ, the binding is
    /// unsupported, or the resulting selector is invalid.
    pub fn plan_for_placement(
        &self,
        placement: &SurfacePlacementRecord,
        binding: &BindingRecord,
        operation: StorageWorkOperation,
        now: i64,
    ) -> Result<StorageWorkPlan> {
        anyhow::ensure!(
            placement.binding_id == binding.id
                && binding.kind == "deployment_r2"
                && binding.is_instance_default,
            "storage work requires the selected deployment R2 binding"
        );
        let plan = StorageWorkPlan {
            version: 1,
            plan_id: uuid::Uuid::new_v4().simple().to_string(),
            deployment_id: self.deployment_id.clone(),
            issued_at: now,
            expires_at: now
                .checked_add(30)
                .context("storage work expiry overflowed")?,
            placement_id: placement.id,
            placement_resource_version: placement.resource_version,
            binding_id: binding.id,
            binding_resource_version: binding.resource_version,
            binding_kind: binding.kind.clone(),
            placement_prefix: placement.prefix.clone(),
            operation,
        };
        plan.validate(&self.deployment_id, now)?;
        Ok(plan)
    }

    /// Executes one bounded plan and checks its response against the issued fence.
    ///
    /// This method returns only compact metadata or digest evidence. It never
    /// has a fallback that downloads the source object into Native.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale plan, Worker failure, oversized response,
    /// malformed result, or mismatched placement and object identity.
    pub async fn execute(&self, plan: &StorageWorkPlan) -> Result<StorageWorkResult> {
        let now = aos_hub_core::clock::now_unix_secs();
        plan.validate(&self.deployment_id, now)?;
        let body = serde_json::to_vec(plan).context("encoding storage work plan")?;
        let signature = self.key.sign_body(&body)?;
        let request_bytes = body.len();
        let started = Instant::now();

        let mut request = self
            .http
            .post(&self.endpoint)
            .header("content-type", "application/json")
            .header(STORAGE_WORK_SIGNATURE_HEADER, signature)
            .body(body);
        if matches!(&plan.operation, StorageWorkOperation::ComposeOciBlob { .. })
            || matches!(
                &plan.operation,
                StorageWorkOperation::InspectSha256 { max_source_bytes, .. }
                    if *max_source_bytes > 64 * 1024 * 1024
            )
        {
            request = request.timeout(Duration::from_secs(10 * 60));
        }
        let response = request.send().await.context("sending storage work plan")?;
        if response.status() == reqwest::StatusCode::PAYLOAD_TOO_LARGE {
            return Err(StorageWorkResultTooLarge.into());
        }
        if response.status() != reqwest::StatusCode::OK {
            bail!("storage Worker returned HTTP {}", response.status());
        }
        let body = read_bounded_response(response, MAX_RESULT_BYTES).await?;
        let response_bytes = body.len();
        let result: StorageWorkResult =
            serde_json::from_slice(&body).context("decoding storage work result")?;
        validate_result(plan, &result)?;
        tracing::info!(
            plan_id = %plan.plan_id,
            operation = plan.operation.kind(),
            request_bytes,
            response_bytes,
            source_bytes = result.source_bytes,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "hybrid storage boundary"
        );
        Ok(result)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("storage Worker result exceeds its limit")]
struct StorageWorkResultTooLarge;

async fn read_bounded_response(response: reqwest::Response, maximum: usize) -> Result<Vec<u8>> {
    anyhow::ensure!(
        response
            .content_length()
            .is_none_or(|length| length <= maximum as u64),
        "storage Worker result exceeds the response limit"
    );
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("reading storage Worker response")?;
        let length = body
            .len()
            .checked_add(chunk.len())
            .context("storage Worker response size overflowed")?;
        anyhow::ensure!(
            length <= maximum,
            "storage Worker result exceeds the response limit"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn validate_capabilities(deployment_id: &str, capabilities: &StorageCapabilities) -> Result<()> {
    anyhow::ensure!(
        capabilities.version == 1
            && capabilities.deployment_id == deployment_id
            && capabilities.binding_kind == "deployment_r2"
            && capabilities.max_result_bytes == MAX_RESULT_BYTES
            && capabilities.max_verify_source_bytes == MAX_VERIFY_SOURCE_BYTES
            && [
                "head",
                "list_page",
                "inspect_sha256",
                "inspect_git_object",
                "inspect_git_objects",
                "inspect_metadata",
                "inspect_documentation",
                "inspect_oci_range",
                "compose_oci_blob",
                "delete_oci_staging"
            ]
            .iter()
            .all(|required| capabilities
                .operations
                .iter()
                .any(|actual| actual == required)),
        "hybrid storage Worker protocol, deployment, or R2 binding mismatch"
    );
    Ok(())
}

fn validate_result(plan: &StorageWorkPlan, result: &StorageWorkResult) -> Result<()> {
    anyhow::ensure!(
        result.plan_id == plan.plan_id
            && result.placement_id == plan.placement_id
            && result.placement_resource_version == plan.placement_resource_version
            && result.binding_id == plan.binding_id
            && result.binding_resource_version == plan.binding_resource_version,
        "storage Worker result does not match the issued fence"
    );
    match (&plan.operation, &result.outcome) {
        (
            StorageWorkOperation::Head { .. }
            | StorageWorkOperation::InspectSha256 { .. }
            | StorageWorkOperation::InspectMetadata { .. }
            | StorageWorkOperation::InspectOciRange { .. },
            StorageWorkOutcome::NotFound,
        ) => {
            anyhow::ensure!(
                result.source_bytes == 0,
                "missing object reported source bytes"
            );
        }
        (StorageWorkOperation::InspectGitObject { .. }, StorageWorkOutcome::NotFound) => {
            anyhow::ensure!(
                result.source_bytes <= object_bundle::MAX_BUNDLE_BYTES as u64,
                "missing Git object reported excessive source bytes"
            );
        }
        (StorageWorkOperation::InspectGitObjects { oids }, StorageWorkOutcome::NotFound) => {
            anyhow::ensure!(
                result.source_bytes
                    <= oids.len() as u64
                        * (object_bundle::MAX_BUNDLE_BYTES as u64
                            + object::MAX_PUBLISHED_LOOSE_OBJECT_BYTES),
                "missing Git batch reported excessive source bytes"
            );
        }
        (StorageWorkOperation::Head { path }, StorageWorkOutcome::Head { object }) => {
            aos_hub_core::surface_write::strong_if_match_etag(&object.etag)?;
            anyhow::ensure!(
                result.source_bytes == 0 && object.key == plan.object_key(path)?,
                "storage Worker head result names another object"
            );
        }
        (
            StorageWorkOperation::ListPage {
                prefix,
                cursor: requested_cursor,
                limit,
            },
            StorageWorkOutcome::ListPage { objects, cursor },
        ) => {
            let key_prefix = plan.object_key(prefix)?;
            anyhow::ensure!(
                result.source_bytes == 0
                    && objects.len() <= *limit
                    && objects
                        .iter()
                        .all(|object| object.key.starts_with(&key_prefix))
                    && objects.windows(2).all(|pair| pair[0].key < pair[1].key)
                    && objects.iter().all(|object| {
                        aos_hub_core::surface_write::strong_if_match_etag(&object.etag).is_ok()
                    })
                    && (cursor.is_none() || !objects.is_empty())
                    && (cursor.is_none() || cursor != requested_cursor),
                "storage Worker list result escaped its prefix or page limit"
            );
        }
        (
            StorageWorkOperation::InspectSha256 {
                path,
                expected_sha256,
                max_source_bytes,
            },
            StorageWorkOutcome::Sha256Evidence { object, sha256 },
        ) => {
            aos_hub_core::surface_write::strong_if_match_etag(&object.etag)?;
            anyhow::ensure!(
                object.key == plan.object_key(path)?
                    && result.source_bytes == object.size
                    && result.source_bytes <= *max_source_bytes
                    && expected_sha256
                        .as_ref()
                        .map_or(true, |expected| { sha256.eq_ignore_ascii_case(expected) }),
                "storage Worker verification result does not match the selected object"
            );
        }
        (
            StorageWorkOperation::ComposeOciBlob {
                path,
                expected_size,
                expected_sha256,
                ..
            },
            StorageWorkOutcome::OciBlobComposed { object, sha256 },
        ) => {
            aos_hub_core::surface_write::strong_if_match_etag(&object.etag)?;
            anyhow::ensure!(
                object.key == plan.object_key(path)?
                    && object.size == *expected_size
                    && result.source_bytes == *expected_size
                    && sha256 == expected_sha256,
                "storage Worker OCI composition did not match its signed plan"
            );
        }
        (StorageWorkOperation::DeleteOciStaging { .. }, StorageWorkOutcome::OciStagingDeleted) => {
            anyhow::ensure!(
                result.source_bytes == 0,
                "storage Worker staging deletion returned source bytes"
            );
        }
        (
            StorageWorkOperation::InspectGitObject { oid },
            StorageWorkOutcome::GitObject {
                source,
                oid: returned_oid,
                object_kind,
                content_base64,
            },
        ) => {
            let projection = StorageGitObjectProjection {
                source: source.clone(),
                oid: returned_oid.clone(),
                object_kind: object_kind.clone(),
                content_base64: content_base64.clone(),
            };
            validate_git_projection(plan, oid, &projection)?;
            anyhow::ensure!(
                result.source_bytes >= source.size
                    && result.source_bytes <= source.size + object_bundle::MAX_BUNDLE_BYTES as u64,
                "storage Worker Git result reported invalid source bytes"
            );
        }
        (
            StorageWorkOperation::InspectGitObjects { oids },
            StorageWorkOutcome::GitObjects { objects },
        ) => {
            anyhow::ensure!(
                objects.len() == oids.len()
                    && result.source_bytes
                        <= oids.len() as u64
                            * (object_bundle::MAX_BUNDLE_BYTES as u64
                                + object::MAX_PUBLISHED_LOOSE_OBJECT_BYTES),
                "storage Worker Git batch omitted objects or exceeded its source limit"
            );
            let mut sources = BTreeMap::new();
            for (oid, projection) in oids.iter().zip(objects) {
                validate_git_projection(plan, oid, projection)?;
                if let Some((size, etag)) = sources.insert(
                    projection.source.key.as_str(),
                    (projection.source.size, projection.source.etag.as_str()),
                ) {
                    anyhow::ensure!(
                        size == projection.source.size && etag == projection.source.etag,
                        "storage Worker Git batch reported conflicting source snapshots"
                    );
                }
            }
            let minimum_bytes = sources.values().try_fold(0_u64, |sum, (size, _)| {
                sum.checked_add(*size)
                    .context("Git batch source byte count overflowed")
            })?;
            anyhow::ensure!(
                result.source_bytes >= minimum_bytes,
                "storage Worker Git batch understated its source reads"
            );
        }
        (
            StorageWorkOperation::InspectMetadata { path },
            StorageWorkOutcome::Metadata {
                source,
                content_base64,
            },
        ) => {
            aos_hub_core::surface_write::strong_if_match_etag(&source.etag)?;
            anyhow::ensure!(
                source.key == plan.object_key(path)?
                    && source.size <= MAX_METADATA_BYTES as u64
                    && result.source_bytes == source.size,
                "storage Worker metadata result names another or oversized object"
            );
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(content_base64)
                .context("decoding Worker metadata document")?;
            anyhow::ensure!(
                bytes.len() as u64 == source.size,
                "storage Worker metadata body does not match its source size"
            );
        }
        (
            StorageWorkOperation::InspectDocumentation {
                artifact, cursor, ..
            },
            StorageWorkOutcome::Documentation { page },
        ) => {
            let max_source_bytes = artifact
                .nar_size
                .checked_add(MAX_METADATA_BYTES as u64)
                .context("documentation source byte limit overflowed")?;
            let page_rows = page
                .search
                .len()
                .checked_add(page.options.len())
                .context("documentation page row count overflowed")?;
            let end = cursor
                .checked_add(page_rows)
                .context("documentation page cursor overflowed")?;
            anyhow::ensure!(
                result.source_bytes >= artifact.nar_size
                    && result.source_bytes <= max_source_bytes
                    && page.total_rows <= MAX_DOCUMENTATION_ROWS
                    && *cursor <= page.total_rows
                    && end <= page.total_rows
                    && (page_rows > 0 || page.total_rows == 0)
                    && page.next_cursor == (end < page.total_rows).then_some(end)
                    && page.identity.semantic_schema_sha256 == artifact.semantic_schema_sha256
                    && page.identity.system_module_nar_hash == artifact.system_module_nar_hash,
                "storage Worker documentation projection disagrees with the signed artifact"
            );
        }
        (
            StorageWorkOperation::InspectOciRange { path, start, end },
            StorageWorkOutcome::OciRange {
                source,
                start: returned_start,
                end: returned_end,
                content_base64,
            },
        ) => {
            aos_hub_core::surface_write::strong_if_match_etag(&source.etag)?;
            let expected = end - start + 1;
            anyhow::ensure!(
                source.key == plan.object_key(path)?
                    && returned_start == start
                    && returned_end == end
                    && *end < source.size
                    && result.source_bytes == expected
                    && result.source_bytes <= MAX_OCI_RANGE_BYTES as u64,
                "storage Worker OCI result names another object or range"
            );
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(content_base64)
                .context("decoding Worker OCI range")?;
            anyhow::ensure!(
                bytes.len() as u64 == expected,
                "storage Worker OCI range body has the wrong length"
            );
        }
        _ => bail!("storage Worker returned the wrong result kind"),
    }
    Ok(())
}

fn validate_git_projection(
    plan: &StorageWorkPlan,
    oid: &str,
    projection: &StorageGitObjectProjection,
) -> Result<()> {
    let oid_value = object::Oid::from_hex(oid)?;
    let shard_path = object_bundle::shard_path(&oid[..2])?;
    let loose_path = oid_value.loose_path();
    let is_shard = projection.source.key == plan.object_key(&shard_path)?;
    let is_loose = projection.source.key == plan.object_key(&loose_path)?;
    let source_limit = if is_shard {
        object_bundle::MAX_BUNDLE_BYTES as u64
    } else {
        object::MAX_PUBLISHED_LOOSE_OBJECT_BYTES
    };
    aos_hub_core::surface_write::strong_if_match_etag(&projection.source.etag)?;
    anyhow::ensure!(
        projection.oid == oid && (is_shard || is_loose) && projection.source.size <= source_limit,
        "storage Worker Git projection names another source or object"
    );
    let content = base64::engine::general_purpose::STANDARD
        .decode(&projection.content_base64)
        .context("decoding Worker Git object content")?;
    anyhow::ensure!(
        content.len() <= MAX_GIT_INSPECTION_CONTENT_BYTES
            && object::hash_object(
                object::ObjectKind::parse(&projection.object_kind)?,
                &content
            ) == oid_value,
        "storage Worker Git projection does not match the requested OID"
    );
    Ok(())
}

/// Native R2 reader whose provider I/O runs through bounded Worker plans.
pub struct HybridSurfaceProvider {
    db: Arc<Database>,
    work: Arc<RemoteStorageWorkClient>,
}

impl HybridSurfaceProvider {
    /// Creates a provider over the authoritative SQL database and Worker client.
    #[must_use]
    pub fn new(db: Arc<Database>, work: Arc<RemoteStorageWorkClient>) -> Self {
        Self { db, work }
    }
}

#[async_trait]
impl SurfaceProvider for HybridSurfaceProvider {
    fn storage_local_git_inspection(&self) -> bool {
        true
    }

    fn storage_local_sha256(&self) -> bool {
        true
    }

    async fn placement_fetcher(
        &self,
        placement: &SurfacePlacementRecord,
    ) -> Result<Box<dyn SurfaceFetch>> {
        let binding = self
            .db
            .binding(placement.binding_id)
            .await?
            .context("hybrid placement references a missing storage binding")?;
        anyhow::ensure!(
            binding.kind == "deployment_r2" && binding.is_instance_default,
            "hybrid R2 reader does not support this binding kind"
        );
        Ok(Box::new(HybridSurfaceFetch {
            db: Arc::clone(&self.db),
            placement: placement.clone(),
            binding,
            work: Arc::clone(&self.work),
        }))
    }
}

struct HybridSurfaceFetch {
    db: Arc<Database>,
    placement: SurfacePlacementRecord,
    binding: BindingRecord,
    work: Arc<RemoteStorageWorkClient>,
}

impl HybridSurfaceFetch {
    async fn inspect_git_batch(
        &self,
        oids: Vec<object::Oid>,
    ) -> Result<BTreeMap<object::Oid, Option<(object::ObjectKind, Vec<u8>)>>> {
        let mut pending = VecDeque::from([oids]);
        let mut decoded = BTreeMap::new();
        while let Some(batch) = pending.pop_front() {
            let plan = self.work.plan_for_placement(
                &self.placement,
                &self.binding,
                StorageWorkOperation::InspectGitObjects {
                    oids: batch.iter().map(object::Oid::to_hex).collect(),
                },
                aos_hub_core::clock::now_unix_secs(),
            )?;
            let outcome = match self.execute(&plan).await {
                Ok(result) => result.outcome,
                Err(error)
                    if batch.len() > 1
                        && error.downcast_ref::<StorageWorkResultTooLarge>().is_some() =>
                {
                    split_git_batch(&mut pending, batch);
                    continue;
                }
                Err(error) => return Err(error),
            };
            match outcome {
                StorageWorkOutcome::GitObjects { objects } => {
                    for (oid, projection) in batch.into_iter().zip(objects) {
                        let kind = object::ObjectKind::parse(&projection.object_kind)?;
                        let content = base64::engine::general_purpose::STANDARD
                            .decode(projection.content_base64)
                            .context("decoding Git batch projection")?;
                        decoded.insert(oid, Some((kind, content)));
                    }
                }
                StorageWorkOutcome::NotFound if batch.len() > 1 => {
                    split_git_batch(&mut pending, batch);
                }
                StorageWorkOutcome::NotFound => {
                    decoded.insert(batch[0], None);
                }
                _ => bail!("storage Worker returned an unexpected Git batch result"),
            }
        }
        Ok(decoded)
    }

    async fn execute(&self, plan: &StorageWorkPlan) -> Result<StorageWorkResult> {
        let result = self.work.execute(plan).await?;
        let placement = self
            .db
            .surface_placement(self.placement.id)
            .await?
            .context("storage placement was removed during Worker execution")?;
        let binding = self
            .db
            .binding(self.binding.id)
            .await?
            .context("storage binding was removed during Worker execution")?;
        anyhow::ensure!(
            placement.resource_version == plan.placement_resource_version
                && placement.binding_id == plan.binding_id
                && placement.prefix == plan.placement_prefix
                && binding.resource_version == plan.binding_resource_version
                && binding.kind == plan.binding_kind,
            "storage placement or binding changed during Worker execution"
        );
        Ok(result)
    }

    async fn head(
        &self,
        path: &str,
    ) -> Result<Option<aos_hub_core::storage_work::StorageObjectIdentity>> {
        let plan = self.work.plan_for_placement(
            &self.placement,
            &self.binding,
            StorageWorkOperation::Head { path: path.into() },
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let result = self.execute(&plan).await?;
        match result.outcome {
            StorageWorkOutcome::NotFound => Ok(None),
            StorageWorkOutcome::Head { object } => Ok(Some(object)),
            _ => bail!("storage Worker returned an unexpected head result"),
        }
    }
}

#[async_trait]
impl SurfaceFetch for HybridSurfaceFetch {
    fn describe(&self) -> String {
        format!("hybrid Worker placement {}", self.placement.id)
    }

    async fn delivery_head(&self, path: &str) -> Result<Option<SurfaceDeliveryHead>> {
        Ok(self.head(path).await?.map(|object| SurfaceDeliveryHead {
            size: object.size,
            strong_etag: object.etag,
        }))
    }

    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
        anyhow::ensure!(
            aos_hub_core::storage_work::admitted_metadata_path(path),
            "hybrid object bodies require a typed Worker inspection plan"
        );
        let plan = self.work.plan_for_placement(
            &self.placement,
            &self.binding,
            StorageWorkOperation::InspectMetadata { path: path.into() },
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let result = self.execute(&plan).await?;
        match result.outcome {
            StorageWorkOutcome::NotFound => Ok(None),
            StorageWorkOutcome::Metadata { content_base64, .. } => Ok(Some(
                base64::engine::general_purpose::STANDARD
                    .decode(content_base64)
                    .context("decoding metadata from storage Worker")?,
            )),
            _ => bail!("storage Worker returned an unexpected metadata result"),
        }
    }

    async fn fetch_bounded(&self, path: &str, max_bytes: usize) -> Result<Option<Vec<u8>>> {
        // Metadata comes from the Worker's bounded inspection result. The
        // default implementation streams the body, which hybrid forbids.
        let Some(bytes) = self.fetch(path).await? else {
            return Ok(None);
        };
        anyhow::ensure!(
            bytes.len() <= max_bytes,
            "hybrid metadata object '{path}' exceeds the {max_bytes} byte semantic limit"
        );
        Ok(Some(bytes))
    }

    fn storage_local_git_inspection(&self) -> bool {
        true
    }

    fn storage_local_sha256(&self) -> bool {
        true
    }

    fn storage_local_documentation_inspection(&self) -> bool {
        true
    }

    async fn inspect_package_documentation(
        &self,
        package_name: &str,
        package_version: &str,
        platform: &str,
        artifact: &aos_registry_surface::manifest::DocumentationArtifactMeta,
    ) -> Result<DocumentationInspection> {
        let mut cursor = 0;
        let mut total_rows = None;
        let mut complete: Option<DocumentationInspection> = None;
        for _ in 0..1024 {
            let plan = self.work.plan_for_placement(
                &self.placement,
                &self.binding,
                StorageWorkOperation::InspectDocumentation {
                    package_name: package_name.into(),
                    package_version: package_version.into(),
                    platform: platform.into(),
                    artifact: artifact.clone(),
                    cursor,
                },
                aos_hub_core::clock::now_unix_secs(),
            )?;
            let result = self.execute(&plan).await?;
            let StorageWorkOutcome::Documentation { page } = result.outcome else {
                bail!("storage Worker returned an unexpected documentation result");
            };
            anyhow::ensure!(
                total_rows.is_none_or(|expected| expected == page.total_rows)
                    && complete
                        .as_ref()
                        .is_none_or(|value| value.identity == page.identity),
                "documentation pages describe different verified documents"
            );
            total_rows = Some(page.total_rows);
            let assembled = complete.get_or_insert_with(|| DocumentationInspection {
                identity: page.identity.clone(),
                search: Vec::new(),
                options: Vec::new(),
            });
            assembled.search.extend(page.search);
            assembled.options.extend(page.options);
            if let Some(next_cursor) = page.next_cursor {
                cursor = next_cursor;
                continue;
            }
            anyhow::ensure!(
                assembled.search.len() + assembled.options.len() == page.total_rows,
                "documentation pages omitted index rows"
            );
            return complete.context("documentation inspection returned no pages");
        }
        bail!("documentation inspection exceeded its page limit")
    }

    async fn inspect_git_object(
        &self,
        oid: object::Oid,
    ) -> Result<Option<(object::ObjectKind, Vec<u8>)>> {
        let plan = self.work.plan_for_placement(
            &self.placement,
            &self.binding,
            StorageWorkOperation::InspectGitObject { oid: oid.to_hex() },
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let result = self.execute(&plan).await?;
        match result.outcome {
            StorageWorkOutcome::NotFound => Ok(None),
            StorageWorkOutcome::GitObject {
                object_kind,
                content_base64,
                ..
            } => {
                let kind = object::ObjectKind::parse(&object_kind)?;
                let content = base64::engine::general_purpose::STANDARD
                    .decode(content_base64)
                    .context("decoding Git projection from storage Worker")?;
                Ok(Some((kind, content)))
            }
            _ => bail!("storage Worker returned an unexpected Git inspection result"),
        }
    }

    async fn inspect_git_objects(
        &self,
        oids: &[object::Oid],
    ) -> Result<Vec<Option<(object::ObjectKind, Vec<u8>)>>> {
        let mut sorted = oids.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        let groups = futures_util::future::try_join_all(
            sorted
                .chunks(MAX_GIT_INSPECTION_BATCH)
                .map(|chunk| self.inspect_git_batch(chunk.to_vec())),
        )
        .await?;
        let decoded: BTreeMap<_, _> = groups.into_iter().flat_map(BTreeMap::into_iter).collect();

        oids.iter()
            .map(|oid| {
                decoded
                    .get(oid)
                    .cloned()
                    .context("Git batch omitted a requested object")
            })
            .collect()
    }

    async fn inspect_oci_range(
        &self,
        path: &str,
        (start, end): (u64, u64),
    ) -> Result<Option<StreamedRead>> {
        anyhow::ensure!(
            aos_hub_core::storage_work::admitted_oci_blob_path(path),
            "hybrid range reads require a canonical OCI blob"
        );
        let plan = self.work.plan_for_placement(
            &self.placement,
            &self.binding,
            StorageWorkOperation::InspectOciRange {
                path: path.into(),
                start,
                end,
            },
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let result = self.execute(&plan).await?;
        match result.outcome {
            StorageWorkOutcome::NotFound => Ok(None),
            StorageWorkOutcome::OciRange {
                source,
                content_base64,
                ..
            } => Ok(Some(StreamedRead {
                body: axum::body::Body::from(
                    base64::engine::general_purpose::STANDARD
                        .decode(content_base64)
                        .context("decoding OCI range from storage Worker")?,
                ),
                total: source.size,
                range: Some((start, end)),
                strong_etag: Some(source.etag),
                snapshot_lease_id: None,
            })),
            _ => bail!("storage Worker returned an unexpected OCI range result"),
        }
    }

    async fn fetch_stream(
        &self,
        _path: &str,
        _range: Option<(u64, u64)>,
    ) -> Result<Option<StreamedRead>> {
        bail!("hybrid object delivery must terminate at the Worker")
    }

    async fn size(&self, path: &str) -> Result<Option<u64>> {
        Ok(self.head(path).await?.map(|object| object.size))
    }

    async fn list_page(&self, cursor: Option<&str>, limit: usize) -> Result<SurfaceListPage> {
        let plan = self.work.plan_for_placement(
            &self.placement,
            &self.binding,
            StorageWorkOperation::ListPage {
                prefix: String::new(),
                cursor: cursor.map(str::to_owned),
                limit,
            },
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let result = self.execute(&plan).await?;
        let StorageWorkOutcome::ListPage { objects, cursor } = result.outcome else {
            bail!("storage Worker returned an unexpected listing result");
        };
        let mut entries = Vec::with_capacity(objects.len());
        for object in objects {
            let relative = aos_hub_core::keymap::relative_key(&self.placement.prefix, &object.key)
                .context("storage Worker listed an object outside its placement")?;
            if relative.is_empty() {
                continue;
            }
            entries.push((
                relative,
                SurfaceListedEvidence {
                    size: i64::try_from(object.size)
                        .context("storage Worker object size exceeds i64")?,
                    strong_etag: object.etag,
                },
            ));
        }
        let paths = entries.iter().map(|(path, _)| path.clone()).collect();
        let evidence: std::collections::BTreeMap<_, _> = entries.into_iter().collect();
        anyhow::ensure!(
            cursor.is_none() || !evidence.is_empty(),
            "storage Worker returned an empty non-terminal page"
        );
        Ok(SurfaceListPage {
            paths,
            evidence,
            next_cursor: cursor,
        })
    }

    async fn inventory_strong_etag(&self, path: &str) -> Result<Option<String>> {
        Ok(self.head(path).await?.map(|object| object.etag))
    }

    async fn inventory_size(&self, path: &str) -> Result<Option<i64>> {
        self.head(path)
            .await?
            .map(|object| i64::try_from(object.size).context("R2 object size exceeds i64"))
            .transpose()
    }

    async fn inventory_evidence_bounded(
        &self,
        path: &str,
        maximum_bytes: u64,
    ) -> Result<Option<SurfaceObjectEvidence>> {
        let maximum_bytes = maximum_bytes.min(MAX_VERIFY_SOURCE_BYTES);
        let plan = self.work.plan_for_placement(
            &self.placement,
            &self.binding,
            StorageWorkOperation::InspectSha256 {
                path: path.into(),
                expected_sha256: None,
                max_source_bytes: maximum_bytes,
            },
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let result = self.execute(&plan).await?;
        match result.outcome {
            StorageWorkOutcome::NotFound => Ok(None),
            StorageWorkOutcome::Sha256Evidence { object, sha256 } => {
                let digest = hex::decode(sha256).context("decoding Worker object digest")?;
                let digest: [u8; 32] = digest
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Worker object digest has the wrong length"))?;
                Ok(Some(SurfaceObjectEvidence {
                    sha256: digest,
                    size: i64::try_from(object.size).context("R2 object size exceeds i64")?,
                    strong_etag: Some(object.etag),
                }))
            }
            _ => bail!("storage Worker returned an unexpected hash result"),
        }
    }
}

fn split_git_batch(pending: &mut VecDeque<Vec<object::Oid>>, batch: Vec<object::Oid>) {
    let midpoint = batch.len() / 2;
    pending.push_front(batch[midpoint..].to_vec());
    pending.push_front(batch[..midpoint].to_vec());
}

/// Storage-local writes authorized by the hybrid Native control plane.
pub struct HybridSurfaceWrites {
    db: Arc<Database>,
    work: Arc<RemoteStorageWorkClient>,
}

impl HybridSurfaceWrites {
    /// Creates a writer that composes OCI blobs through signed Worker work.
    #[must_use]
    pub fn new(db: Arc<Database>, work: Arc<RemoteStorageWorkClient>) -> Self {
        Self { db, work }
    }
}

#[async_trait]
impl SurfaceWriteProvider for HybridSurfaceWrites {
    async fn compose_oci_blob(
        &self,
        destination: &SurfacePlacementRecord,
        revision: &BindingWriteRevisionRecord,
        staging: Option<&SurfacePlacementRecord>,
        path: &str,
        chunks: &[OciUploadChunkRecord],
        expected_digest: aos_oci_types::Sha256Digest,
        expected_size: u64,
    ) -> Result<Option<SurfaceObjectEvidence>> {
        anyhow::ensure!(
            destination.binding_id == revision.binding_id,
            "OCI destination differs from its frozen write revision"
        );
        let staging_prefix = match staging {
            Some(staging) => {
                anyhow::ensure!(
                    staging.binding_id == destination.binding_id,
                    "OCI staging and destination use different R2 bindings"
                );
                staging.prefix.clone()
            }
            None if chunks.is_empty() && expected_size == 0 => String::new(),
            None => bail!("OCI staging placement is missing"),
        };
        let binding = self
            .db
            .binding(destination.binding_id)
            .await?
            .context("OCI destination binding is missing")?;
        let chunks = chunks
            .iter()
            .map(|chunk| StorageOciChunkSource {
                path: chunk.staging_object_key.clone(),
                size: chunk.byte_size,
                sha256: chunk.digest.encoded(),
            })
            .collect();
        let plan = self.work.plan_for_placement(
            destination,
            &binding,
            StorageWorkOperation::ComposeOciBlob {
                path: path.to_string(),
                staging_prefix,
                chunks,
                expected_size,
                expected_sha256: expected_digest.encoded(),
            },
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let result = self.work.execute(&plan).await?;
        let StorageWorkOutcome::OciBlobComposed { object, sha256 } = result.outcome else {
            bail!("storage Worker returned no OCI composition evidence");
        };
        anyhow::ensure!(
            sha256 == expected_digest.encoded(),
            "storage Worker composed a different OCI digest"
        );
        let digest = hex::decode(sha256)?;
        let digest: [u8; 32] = digest
            .try_into()
            .map_err(|_| anyhow::anyhow!("storage Worker returned an invalid OCI digest"))?;
        Ok(Some(SurfaceObjectEvidence {
            sha256: digest,
            size: i64::try_from(object.size)?,
            strong_etag: Some(object.etag),
        }))
    }

    async fn placement_writer(
        &self,
        _placement: &SurfacePlacementRecord,
    ) -> Result<Box<dyn SurfaceWrite>> {
        bail!("hybrid writes require a Worker upload ticket")
    }

    async fn placement_writer_at_revision(
        &self,
        placement: &SurfacePlacementRecord,
        revision: &BindingWriteRevisionRecord,
    ) -> Result<Box<dyn SurfaceWrite>> {
        anyhow::ensure!(
            placement.binding_id == revision.binding_id,
            "hybrid staging writer differs from its frozen binding revision"
        );
        let binding = self
            .db
            .binding(placement.binding_id)
            .await?
            .context("hybrid staging binding is missing")?;
        anyhow::ensure!(
            binding.kind == "deployment_r2" && binding.is_instance_default,
            "hybrid staging cleanup requires deployment R2"
        );
        Ok(Box::new(HybridOciStagingWriter {
            placement: placement.clone(),
            binding,
            work: Arc::clone(&self.work),
        }))
    }

    async fn placement_deleter(
        &self,
        _placement: &SurfacePlacementRecord,
        _expected_binding_resource_version: i64,
        _delete_credential_generation: i64,
    ) -> Result<Box<dyn SurfaceWrite>> {
        bail!("hybrid deletes require a conditional Worker work plan")
    }

    async fn frozen_placement_deleter(
        &self,
        _access: &FrozenSurfaceAccess,
    ) -> Result<Box<dyn SurfaceWrite>> {
        bail!("hybrid deletes require a conditional Worker work plan")
    }
}

struct HybridOciStagingWriter {
    placement: SurfacePlacementRecord,
    binding: BindingRecord,
    work: Arc<RemoteStorageWorkClient>,
}

#[async_trait]
impl SurfaceWrite for HybridOciStagingWriter {
    async fn write(&self, _path: &str, _bytes: &[u8]) -> Result<()> {
        bail!("hybrid OCI staging writes require Worker upload admission")
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let plan = self.work.plan_for_placement(
            &self.placement,
            &self.binding,
            StorageWorkOperation::DeleteOciStaging { path: path.into() },
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let result = self.work.execute(&plan).await?;
        anyhow::ensure!(
            matches!(result.outcome, StorageWorkOutcome::OciStagingDeleted),
            "storage Worker did not acknowledge OCI staging deletion"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_hub_core::storage_work::StorageObjectIdentity;

    #[test]
    fn oci_composition_result_matches_the_signed_destination_and_digest() {
        let digest = "a".repeat(64);
        let path = format!("oci/blobs/sha256/{digest}");
        let plan = StorageWorkPlan {
            version: 1,
            plan_id: "b".repeat(32),
            deployment_id: "deployment-1".into(),
            issued_at: 100,
            expires_at: 130,
            placement_id: 4,
            placement_resource_version: 2,
            binding_id: 3,
            binding_resource_version: 1,
            binding_kind: "deployment_r2".into(),
            placement_prefix: "registry".into(),
            operation: StorageWorkOperation::ComposeOciBlob {
                path: path.clone(),
                staging_prefix: "staging".into(),
                chunks: vec![StorageOciChunkSource {
                    path: "oci/uploads/session/chunks/0-attempt".into(),
                    size: 4,
                    sha256: "b".repeat(64),
                }],
                expected_size: 4,
                expected_sha256: digest.clone(),
            },
        };
        let mut result = StorageWorkResult {
            plan_id: plan.plan_id.clone(),
            placement_id: plan.placement_id,
            placement_resource_version: plan.placement_resource_version,
            binding_id: plan.binding_id,
            binding_resource_version: plan.binding_resource_version,
            source_bytes: 4,
            outcome: StorageWorkOutcome::OciBlobComposed {
                object: StorageObjectIdentity {
                    key: plan.object_key(&path).unwrap(),
                    size: 4,
                    etag: "r2-etag".into(),
                },
                sha256: digest,
            },
        };
        assert!(validate_result(&plan, &result).is_ok());

        if let StorageWorkOutcome::OciBlobComposed { sha256, .. } = &mut result.outcome {
            *sha256 = "c".repeat(64);
        }
        assert!(validate_result(&plan, &result).is_err());
        if let StorageWorkOutcome::OciBlobComposed { object, sha256 } = &mut result.outcome {
            *sha256 = "a".repeat(64);
            object.key = "another/blob".into();
        }
        assert!(validate_result(&plan, &result).is_err());
    }

    #[test]
    fn readiness_rejects_another_deployment_or_missing_operation() {
        let mut capabilities = StorageCapabilities {
            version: 1,
            deployment_id: "deployment-1".into(),
            binding_kind: "deployment_r2".into(),
            operations: vec![
                "head".into(),
                "list_page".into(),
                "inspect_sha256".into(),
                "inspect_git_object".into(),
                "inspect_git_objects".into(),
                "inspect_metadata".into(),
                "inspect_documentation".into(),
                "inspect_oci_range".into(),
                "compose_oci_blob".into(),
                "delete_oci_staging".into(),
            ],
            max_result_bytes: MAX_RESULT_BYTES,
            max_verify_source_bytes: MAX_VERIFY_SOURCE_BYTES,
        };
        assert!(validate_capabilities("deployment-1", &capabilities).is_ok());
        assert!(validate_capabilities("deployment-2", &capabilities).is_err());
        capabilities.operations.pop();
        assert!(validate_capabilities("deployment-1", &capabilities).is_err());
    }

    #[test]
    fn documentation_result_is_bound_to_the_signed_artifact() {
        let semantic = format!("sha256:{}", "a".repeat(64));
        let artifact = aos_registry_surface::manifest::DocumentationArtifactMeta {
            format: aos_doc_model::DOCUMENT_FORMAT.into(),
            store_path: "/nix/store/abcdf-package-docs".into(),
            nar_hash: format!("sha256:{}", "b".repeat(64)),
            nar_size: 1024,
            document_sha256: format!("sha256:{}", "c".repeat(64)),
            document_size: 512,
            semantic_schema_sha256: semantic.clone(),
            system_module_nar_hash: None,
            references: Vec::new(),
        };
        let plan = StorageWorkPlan {
            version: 1,
            plan_id: "a".repeat(32),
            deployment_id: "deployment-1".into(),
            issued_at: 100,
            expires_at: 130,
            placement_id: 4,
            placement_resource_version: 2,
            binding_id: 3,
            binding_resource_version: 1,
            binding_kind: "deployment_r2".into(),
            placement_prefix: "registry".into(),
            operation: StorageWorkOperation::InspectDocumentation {
                package_name: "example".into(),
                package_version: "1.0.0".into(),
                platform: "x86_64-linux".into(),
                artifact,
                cursor: 0,
            },
        };
        let mut result = StorageWorkResult {
            plan_id: plan.plan_id.clone(),
            placement_id: plan.placement_id,
            placement_resource_version: plan.placement_resource_version,
            binding_id: plan.binding_id,
            binding_resource_version: plan.binding_resource_version,
            source_bytes: 1536,
            outcome: StorageWorkOutcome::Documentation {
                page: aos_hub_core::storage_work::StorageDocumentationPage {
                    identity: aos_doc_model::DocumentationIdentity {
                        semantic_schema_sha256: semantic,
                        runtime_nar_hash: format!("sha256:{}", "d".repeat(64)),
                        config_module_nar_hash: None,
                        system_module_nar_hash: None,
                        expose_artifact_nar_hash: None,
                        source_nar_hash: format!("sha256:{}", "e".repeat(64)),
                    },
                    search: Vec::new(),
                    options: Vec::new(),
                    total_rows: 0,
                    next_cursor: None,
                },
            },
        };
        assert!(validate_result(&plan, &result).is_ok());

        if let StorageWorkOutcome::Documentation { page } = &mut result.outcome {
            page.identity.semantic_schema_sha256 = format!("sha256:{}", "f".repeat(64));
        }
        assert!(validate_result(&plan, &result).is_err());

        if let StorageWorkOutcome::Documentation { page } = &mut result.outcome {
            page.identity.semantic_schema_sha256 = format!("sha256:{}", "a".repeat(64));
        }
        result.source_bytes = 1024 + MAX_METADATA_BYTES as u64 + 1;
        assert!(validate_result(&plan, &result).is_err());

        result.source_bytes = 1536;
        if let StorageWorkOutcome::Documentation { page } = &mut result.outcome {
            page.next_cursor = Some(1);
        }
        assert!(validate_result(&plan, &result).is_err());
    }

    #[test]
    fn rejects_result_for_another_placement_or_object() {
        let plan = StorageWorkPlan {
            version: 1,
            plan_id: "a".repeat(32),
            deployment_id: "deployment-1".into(),
            issued_at: 100,
            expires_at: 130,
            placement_id: 4,
            placement_resource_version: 2,
            binding_id: 3,
            binding_resource_version: 1,
            binding_kind: "deployment_r2".into(),
            placement_prefix: "registry/".into(),
            operation: StorageWorkOperation::Head {
                path: "HEAD".into(),
            },
        };
        let mut result = StorageWorkResult {
            plan_id: plan.plan_id.clone(),
            placement_id: plan.placement_id,
            placement_resource_version: plan.placement_resource_version,
            binding_id: plan.binding_id,
            binding_resource_version: plan.binding_resource_version,
            source_bytes: 0,
            outcome: StorageWorkOutcome::Head {
                object: StorageObjectIdentity {
                    key: "registry/HEAD".into(),
                    size: 5,
                    etag: "\"etag\"".into(),
                },
            },
        };
        assert!(validate_result(&plan, &result).is_ok());
        result.placement_resource_version += 1;
        assert!(validate_result(&plan, &result).is_err());
        result.placement_resource_version -= 1;
        if let StorageWorkOutcome::Head { object } = &mut result.outcome {
            object.key = "another/HEAD".into();
        }
        assert!(validate_result(&plan, &result).is_err());
    }

    #[test]
    fn git_projection_is_rehashed_and_scoped_to_one_source() {
        let content = b"selected git content";
        let oid = object::hash_object(object::ObjectKind::Blob, content).to_hex();
        let plan = StorageWorkPlan {
            version: 1,
            plan_id: "a".repeat(32),
            deployment_id: "deployment-1".into(),
            issued_at: 100,
            expires_at: 130,
            placement_id: 4,
            placement_resource_version: 2,
            binding_id: 3,
            binding_resource_version: 1,
            binding_kind: "deployment_r2".into(),
            placement_prefix: "registry/".into(),
            operation: StorageWorkOperation::InspectGitObject { oid: oid.clone() },
        };
        let mut result = StorageWorkResult {
            plan_id: plan.plan_id.clone(),
            placement_id: plan.placement_id,
            placement_resource_version: plan.placement_resource_version,
            binding_id: plan.binding_id,
            binding_resource_version: plan.binding_resource_version,
            source_bytes: 128,
            outcome: StorageWorkOutcome::GitObject {
                source: StorageObjectIdentity {
                    key: format!(
                        "registry/{}",
                        object::Oid::from_hex(&oid).unwrap().loose_path()
                    ),
                    size: 128,
                    etag: "\"strong-etag\"".into(),
                },
                oid,
                object_kind: "blob".into(),
                content_base64: base64::engine::general_purpose::STANDARD.encode(content),
            },
        };
        assert!(validate_result(&plan, &result).is_ok());
        if let StorageWorkOutcome::GitObject { content_base64, .. } = &mut result.outcome {
            *content_base64 = base64::engine::general_purpose::STANDARD.encode(b"wrong");
        }
        assert!(validate_result(&plan, &result).is_err());
    }

    #[test]
    fn git_batch_rejects_swapped_or_corrupt_projections() {
        let first: &[u8] = b"first";
        let second: &[u8] = b"second";
        let first_oid = object::hash_object(object::ObjectKind::Blob, first).to_hex();
        let second_oid = object::hash_object(object::ObjectKind::Blob, second).to_hex();
        let oids = if first_oid < second_oid {
            vec![(first_oid, first), (second_oid, second)]
        } else {
            vec![(second_oid, second), (first_oid, first)]
        };
        let plan = StorageWorkPlan {
            version: 1,
            plan_id: "a".repeat(32),
            deployment_id: "deployment-1".into(),
            issued_at: 100,
            expires_at: 130,
            placement_id: 4,
            placement_resource_version: 2,
            binding_id: 3,
            binding_resource_version: 1,
            binding_kind: "deployment_r2".into(),
            placement_prefix: "registry/".into(),
            operation: StorageWorkOperation::InspectGitObjects {
                oids: oids.iter().map(|(oid, _)| oid.clone()).collect(),
            },
        };
        let objects = oids
            .iter()
            .map(|(oid, bytes)| StorageGitObjectProjection {
                source: StorageObjectIdentity {
                    key: format!(
                        "registry/{}",
                        object::Oid::from_hex(oid).unwrap().loose_path()
                    ),
                    size: 100,
                    etag: "\"strong-etag\"".into(),
                },
                oid: oid.clone(),
                object_kind: "blob".into(),
                content_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
            })
            .collect();
        let mut result = StorageWorkResult {
            plan_id: plan.plan_id.clone(),
            placement_id: plan.placement_id,
            placement_resource_version: plan.placement_resource_version,
            binding_id: plan.binding_id,
            binding_resource_version: plan.binding_resource_version,
            source_bytes: 200,
            outcome: StorageWorkOutcome::GitObjects { objects },
        };
        assert!(validate_result(&plan, &result).is_ok());
        if let StorageWorkOutcome::GitObjects { objects } = &mut result.outcome {
            objects.swap(0, 1);
        }
        assert!(validate_result(&plan, &result).is_err());
        if let StorageWorkOutcome::GitObjects { objects } = &mut result.outcome {
            objects.swap(0, 1);
            objects[1].content_base64 = base64::engine::general_purpose::STANDARD.encode(b"wrong");
        }
        assert!(validate_result(&plan, &result).is_err());
    }

    #[test]
    fn metadata_projection_requires_the_selected_object_and_exact_size() {
        let plan = StorageWorkPlan {
            version: 1,
            plan_id: "a".repeat(32),
            deployment_id: "deployment-1".into(),
            issued_at: 100,
            expires_at: 130,
            placement_id: 4,
            placement_resource_version: 2,
            binding_id: 3,
            binding_resource_version: 1,
            binding_kind: "deployment_r2".into(),
            placement_prefix: "registry/".into(),
            operation: StorageWorkOperation::InspectMetadata {
                path: "HEAD".into(),
            },
        };
        let mut result = StorageWorkResult {
            plan_id: plan.plan_id.clone(),
            placement_id: plan.placement_id,
            placement_resource_version: plan.placement_resource_version,
            binding_id: plan.binding_id,
            binding_resource_version: plan.binding_resource_version,
            source_bytes: 3,
            outcome: StorageWorkOutcome::Metadata {
                source: StorageObjectIdentity {
                    key: "registry/HEAD".into(),
                    size: 3,
                    etag: "\"strong-etag\"".into(),
                },
                content_base64: base64::engine::general_purpose::STANDARD.encode(b"abc"),
            },
        };
        assert!(validate_result(&plan, &result).is_ok());
        if let StorageWorkOutcome::Metadata { source, .. } = &mut result.outcome {
            source.key = "registry/other".into();
        }
        assert!(validate_result(&plan, &result).is_err());
        if let StorageWorkOutcome::Metadata { source, .. } = &mut result.outcome {
            source.key = "registry/HEAD".into();
            source.size = 4;
        }
        assert!(validate_result(&plan, &result).is_err());
    }

    #[test]
    fn oci_projection_requires_the_exact_range_and_source() {
        let path = format!("oci/blobs/sha256/{}", "a".repeat(64));
        let plan = StorageWorkPlan {
            version: 1,
            plan_id: "a".repeat(32),
            deployment_id: "deployment-1".into(),
            issued_at: 100,
            expires_at: 130,
            placement_id: 4,
            placement_resource_version: 2,
            binding_id: 3,
            binding_resource_version: 1,
            binding_kind: "deployment_r2".into(),
            placement_prefix: "registry/".into(),
            operation: StorageWorkOperation::InspectOciRange {
                path: path.clone(),
                start: 10,
                end: 12,
            },
        };
        let mut result = StorageWorkResult {
            plan_id: plan.plan_id.clone(),
            placement_id: plan.placement_id,
            placement_resource_version: plan.placement_resource_version,
            binding_id: plan.binding_id,
            binding_resource_version: plan.binding_resource_version,
            source_bytes: 3,
            outcome: StorageWorkOutcome::OciRange {
                source: StorageObjectIdentity {
                    key: format!("registry/{path}"),
                    size: 100,
                    etag: "\"strong-etag\"".into(),
                },
                start: 10,
                end: 12,
                content_base64: base64::engine::general_purpose::STANDARD.encode(b"abc"),
            },
        };
        assert!(validate_result(&plan, &result).is_ok());
        if let StorageWorkOutcome::OciRange { end, .. } = &mut result.outcome {
            *end = 13;
        }
        assert!(validate_result(&plan, &result).is_err());
    }
}
