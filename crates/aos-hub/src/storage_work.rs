//! Native client for bounded work executed beside an object store by Workers.
//!
//! The Native Hub signs an exact, short-lived plan and accepts only a matching
//! typed result. Placement and binding rows remain authoritative in SQL; the
//! caller rechecks their revisions before committing any derived state.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use aos_hub_core::db::{
    BindingRecord, BindingWriteRevisionRecord, Database, SurfacePlacementRecord,
};
use aos_hub_core::fetch::{
    StreamedRead, SurfaceFetch, SurfaceListPage, SurfaceListedEvidence, SurfaceObjectEvidence,
    SurfaceProvider,
};
use aos_hub_core::storage_work::{
    StorageCapabilities, StorageWorkKey, StorageWorkOperation, StorageWorkOutcome, StorageWorkPlan,
    StorageWorkResult, MAX_RESULT_BYTES, MAX_VERIFY_SOURCE_BYTES, STORAGE_CAPABILITIES_CHALLENGE,
    STORAGE_CAPABILITIES_PATH, STORAGE_WORK_PATH, STORAGE_WORK_SIGNATURE_HEADER,
};
use aos_hub_core::surface_write::{FrozenSurfaceAccess, SurfaceWrite, SurfaceWriteProvider};
use async_trait::async_trait;
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

        let response = self
            .http
            .post(&self.endpoint)
            .header("content-type", "application/json")
            .header(STORAGE_WORK_SIGNATURE_HEADER, signature)
            .body(body)
            .send()
            .await
            .context("sending storage work plan")?;
        if response.status() != reqwest::StatusCode::OK {
            bail!("storage Worker returned HTTP {}", response.status());
        }
        let body = read_bounded_response(response, MAX_RESULT_BYTES).await?;
        let result: StorageWorkResult =
            serde_json::from_slice(&body).context("decoding storage work result")?;
        validate_result(plan, &result)?;
        Ok(result)
    }
}

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
            && ["head", "list_page", "inspect_sha256"]
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
            StorageWorkOperation::Head { .. } | StorageWorkOperation::InspectSha256 { .. },
            StorageWorkOutcome::NotFound,
        ) => {
            anyhow::ensure!(
                result.source_bytes == 0,
                "missing object reported source bytes"
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
        _ => bail!("storage Worker returned the wrong result kind"),
    }
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

    async fn fetch(&self, _path: &str) -> Result<Option<Vec<u8>>> {
        bail!("hybrid object bodies require a typed Worker inspection plan")
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

/// A temporary fail-closed writer until ticketed Worker writes are connected.
pub struct UnavailableHybridSurfaceWrites;

#[async_trait]
impl SurfaceWriteProvider for UnavailableHybridSurfaceWrites {
    async fn placement_writer(
        &self,
        _placement: &SurfacePlacementRecord,
    ) -> Result<Box<dyn SurfaceWrite>> {
        bail!("hybrid writes require a Worker upload ticket")
    }

    async fn placement_writer_at_revision(
        &self,
        _placement: &SurfacePlacementRecord,
        _revision: &BindingWriteRevisionRecord,
    ) -> Result<Box<dyn SurfaceWrite>> {
        bail!("hybrid writes require a Worker upload ticket")
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

#[cfg(test)]
mod tests {
    use super::*;
    use aos_hub_core::storage_work::StorageObjectIdentity;

    #[test]
    fn readiness_rejects_another_deployment_or_missing_operation() {
        let mut capabilities = StorageCapabilities {
            version: 1,
            deployment_id: "deployment-1".into(),
            binding_kind: "deployment_r2".into(),
            operations: vec!["head".into(), "list_page".into(), "inspect_sha256".into()],
            max_result_bytes: MAX_RESULT_BYTES,
            max_verify_source_bytes: MAX_VERIFY_SOURCE_BYTES,
        };
        assert!(validate_capabilities("deployment-1", &capabilities).is_ok());
        assert!(validate_capabilities("deployment-2", &capabilities).is_err());
        capabilities.operations.pop();
        assert!(validate_capabilities("deployment-1", &capabilities).is_err());
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
}
