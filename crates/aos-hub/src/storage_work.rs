//! Native client for bounded work executed beside an object store by Workers.
//!
//! The Native Hub signs an exact, short-lived plan and accepts only a matching
//! typed result. Placement and binding rows remain authoritative in SQL; the
//! caller rechecks their revisions before committing any derived state.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Context as _, Result};
use aos_hub_core::db::{
    BindingCredentialRevisionRecord, BindingRecord, BindingWriteRevisionRecord, Database,
    OciUploadChunkRecord, SurfacePlacementRecord,
};
use aos_hub_core::fetch::{
    DocumentationInspection, StreamedRead, SurfaceDeliveryHead, SurfaceFetch,
    SurfaceInventoryHashChunk, SurfaceListPage, SurfaceListedEvidence, SurfaceObjectEvidence,
    SurfaceProvider,
};
use aos_hub_core::secret_version::{verify_secret_fingerprint, SecretVersionResolver};
use aos_hub_core::storage_work::{
    StorageBindingAcknowledgement, StorageBindingControl, StorageBindingPublication,
    StorageBindingSnapshot, StorageCapabilities, StorageCredentialMaterial,
    StorageCredentialSelector, StorageGitObjectProjection,
    StorageOciChunkSource, StorageWorkKey, StorageWorkOperation, StorageWorkOutcome,
    StorageWorkPlan, StorageWorkResult, MAX_BINDING_CONTROL_BYTES,
    MAX_DOCUMENTATION_ROWS, MAX_GIT_INSPECTION_BATCH, MAX_GIT_INSPECTION_CONTENT_BYTES,
    MAX_METADATA_BYTES, MAX_METADATA_INSPECTION_BATCH, MAX_OCI_HASH_RANGE_BYTES,
    MAX_OCI_RANGE_BYTES, MAX_RESULT_BYTES, MAX_VERIFY_SOURCE_BYTES, STORAGE_BINDING_CONTROL_PATH,
    STORAGE_CAPABILITIES_CHALLENGE, STORAGE_CAPABILITIES_PATH,
    STORAGE_WORK_PATH,
    STORAGE_WORK_SIGNATURE_HEADER,
};
use aos_hub_core::surface_write::{
    FrozenSurfaceAccess, MultipartAbortOutcome, PartTag, SurfaceDeleteOutcome,
    SurfaceDeletePrecondition, SurfaceWrite, SurfaceWriteProvider,
};
use aos_hub_core::topology_probe::{
    StorageCredentialProbeEvidence, StorageCredentialProbeProvider,
};
use aos_registry_surface::{object, object_bundle};
use async_trait::async_trait;
use base64::Engine as _;
use futures_util::{StreamExt as _, TryStreamExt as _};
use sha2::Digest as _;
use tokio::sync::{Mutex, Semaphore};
use zeroize::Zeroizing;

mod authority;
mod binding_cohorts;
mod binding_custody;

pub use authority::StorageAuthorityControlSynchronization;
mod control;
mod external_delete;
mod external_observation;
mod frozen;
mod frozen_head;
mod mirror_guard;
mod mirror_inspection;
#[cfg(test)]
mod live_metadata_batch_fixture;
mod mirror_membership;
#[cfg(test)]
mod result_acceptance_tests;
#[cfg(test)]
mod mirror_candidate;
mod oci_projection;
mod telemetry;
mod tree_projection;

// Limit each index walk's simultaneous cross-cloud inspection requests.
const MAX_PARALLEL_GIT_INSPECTION_BATCHES: usize = 8;
// Indexing, inventory, and replication can run together while uploads use the
// same Worker. Keep their combined request pressure below the executor's
// capacity, including time spent reading each response.
const MAX_IN_FLIGHT_STORAGE_PLANS: usize = 4;
const MAX_READ_WORK_ATTEMPTS: usize = 3;

fn retryable_read_operation(operation: &StorageWorkOperation) -> bool {
    if let StorageWorkOperation::MirrorTransferBatch { items } = operation {
        return items.iter().all(|item| matches!(item.step,
            aos_hub_core::mirror_work::MirrorStep::VerifyStage
            | aos_hub_core::mirror_work::MirrorStep::Status { .. }));
    }
    if matches!(operation, StorageWorkOperation::MirrorTransfer { step: aos_hub_core::mirror_work::MirrorStep::VerifyStage | aos_hub_core::mirror_work::MirrorStep::Status { .. }, .. }) { return true; }
    matches!(
        operation,
        StorageWorkOperation::Head { .. }
            | StorageWorkOperation::InspectMirrorPack { .. }
            | StorageWorkOperation::InspectMirrorMembership { .. }
            | StorageWorkOperation::InspectStoredGitPack { .. }
            | StorageWorkOperation::FilterStoredGitPackTree { .. }
            | StorageWorkOperation::ListPage { .. }
            | StorageWorkOperation::InspectSha256 { .. }
            | StorageWorkOperation::InspectGitObject { .. }
            | StorageWorkOperation::InspectGitObjects { .. }
            | StorageWorkOperation::FilterGitTreeEntries { .. }
            | StorageWorkOperation::InspectMetadata { .. }
            | StorageWorkOperation::InspectMetadataObjects { .. }
            | StorageWorkOperation::InspectDocumentation { .. }
            | StorageWorkOperation::InspectDocumentationContent { .. }
            | StorageWorkOperation::InspectOciRange { .. }
            | StorageWorkOperation::HashOciRange { .. }
    )
}

fn retryable_worker_status(status: reqwest::StatusCode) -> bool {
    matches!(
        status,
        reqwest::StatusCode::INTERNAL_SERVER_ERROR
            | reqwest::StatusCode::BAD_GATEWAY
            | reqwest::StatusCode::SERVICE_UNAVAILABLE
            | reqwest::StatusCode::GATEWAY_TIMEOUT
    )
}

/// Authenticated Native-to-Worker executor client.
pub struct RemoteStorageWorkClient {
    endpoint: String,
    capabilities_endpoint: String,
    binding_control_endpoint: String,
    frozen_cleanup_endpoint: String,
    deployment_id: String,
    key: StorageWorkKey,
    mirror_profiles: Option<crate::direct_upload::authority::NativeDirectUploadAcceptances>,
    mirror_guard_key: Option<StorageWorkKey>,
    #[cfg(test)]
    controlled_mirror: Option<mirror_candidate::ControlledMirrorAuthority>,
    http: reqwest::Client,
    semantic_observation_http: reqwest::Client,
    in_flight: Semaphore,
    binding_publication_gate: Mutex<()>,
    binding_custody_cohorts: binding_cohorts::BindingCustodyCohorts,
    published_bindings: RwLock<BTreeMap<i64, StorageBindingSnapshot>>,
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
        let binding_control_endpoint = format!(
            "{}{}",
            origin.origin().ascii_serialization(),
            STORAGE_BINDING_CONTROL_PATH
        );
        let frozen_cleanup_endpoint = format!(
            "{}{}",
            origin.origin().ascii_serialization(),
            aos_hub_core::storage_work::binding_custody::STORAGE_FROZEN_CLEANUP_CUSTODY_PATH
        );
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .context("building storage Worker client")?;
        Ok(Self {
            endpoint,
            capabilities_endpoint,
            binding_control_endpoint,
            frozen_cleanup_endpoint,
            deployment_id,
            key: StorageWorkKey::new(key)?,
            mirror_profiles: None,
            mirror_guard_key: None,
            #[cfg(test)]
            controlled_mirror: None,
            http,
            semantic_observation_http: external_observation::http_client()?,
            in_flight: Semaphore::new(MAX_IN_FLIGHT_STORAGE_PLANS),
            binding_publication_gate: Mutex::new(()),
            binding_custody_cohorts: binding_cohorts::BindingCustodyCohorts::default(),
            published_bindings: RwLock::new(BTreeMap::new()),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_controlled_http(mut self, http: reqwest::Client) -> Self {
        self.http = http;
        self
    }

    /// Installs independently verified prerequisite provider/runtime profiles.
    ///
    /// Mirror producer acceptance is checked separately for each workflow;
    /// direct acceptance alone never grants mirror effect authority.
    pub fn with_mirror_profiles(mut self, profiles: crate::direct_upload::authority::NativeDirectUploadAcceptances) -> Self {
        self.mirror_profiles = Some(profiles);
        self
    }

    /// Installs the independent metadata readback role for mirror final guards.
    ///
    /// # Errors
    /// Returns an error for a weak key or reuse of the producer work key.
    pub fn with_mirror_guard_key(mut self, key: &[u8]) -> Result<Self> {
        let guard = StorageWorkKey::new(key)?;
        let separation = b"aos.hub.mirror-guard-role-separation.v1";
        anyhow::ensure!(
            self.key.verify_body(&guard.sign_body(separation)?, separation).is_err(),
            "mirror guard role must differ from producer work authority"
        );
        self.mirror_guard_key = Some(guard);
        Ok(self)
    }

    /// Resolves the exact current managed prerequisite profile commitment.
    ///
    /// # Errors
    /// Returns an error for missing, expired or ambiguous managed acceptance.
    pub(crate) fn mirror_managed_profile_digest(&self) -> Result<String> {
        #[cfg(test)]
        if let Some(candidate) = &self.controlled_mirror {
            return Ok(candidate.profile_digest.clone());
        }

        let profiles = self.mirror_profiles.as_ref().context("mirror requires independently accepted managed provider/runtime evidence")?
            .profiles(&self.deployment_id, &self.executor_origin()?, u64::try_from(aos_hub_core::clock::now_unix_secs())?)?;
        let managed = profiles.iter().filter(|profile| matches!(profile, aos_hub_core::direct_upload::DirectProtectedProfile::Managed { .. })).collect::<Vec<_>>();
        anyhow::ensure!(managed.len() == 1, "mirror requires exactly one accepted managed profile");
        managed[0].digest()
    }

    /// Confirms that the paired Worker has the expected deployment and R2 contract.
    ///
    /// # Errors
    ///
    /// Returns an error if the Worker is unavailable, unauthenticated,
    /// mismatched, or missing a required operation or R2 binding.
    pub async fn check_ready(&self) -> Result<()> {
        self.capabilities().await.map(|_| ())
    }

    /// Confirms storage readiness and the console bundle used by Native pages.
    ///
    /// Hybrid serving requires this probe because the Worker serves console
    /// assets locally, using the immutable URLs rendered by Native.
    ///
    /// # Errors
    ///
    /// Returns an error for a failed storage probe or a missing or different
    /// Worker console bundle identity.
    pub async fn check_console_ready(&self) -> Result<()> {
        let capabilities = self.capabilities().await?;
        validate_console_asset_version(&capabilities)
    }

    async fn capabilities(&self) -> Result<StorageCapabilities> {
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
        validate_capabilities(&self.deployment_id, &capabilities)?;
        Ok(capabilities)
    }

    pub(crate) async fn supports_live_metadata_batch(&self) -> Result<bool> {
        let capabilities = self.capabilities().await?;
        let advertised = |kind: &str| capabilities.operations.iter().any(|value| value == kind);
        anyhow::ensure!(
            advertised("inspect_mirror_live_metadata_v1"),
            "storage Worker does not advertise live metadata queries"
        );
        Ok(advertised(aos_hub_core::storage_work::live_metadata_batch::OPERATION))
    }

    /// Publishes one frozen external binding and its exact credential heads.
    ///
    /// The separate operator process supplies material through this bounded
    /// control. Native service plans use metadata-only adoption of the durable
    /// acknowledgement; no provider object body passes through this interface.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid binding coordinates, an unresolved or
    /// mismatched credential, Worker rejection, or transport failure.
    pub async fn publish_binding_snapshot(
        &self,
        binding: &BindingRecord,
        credentials: &[BindingCredentialRevisionRecord],
        resolver: &dyn SecretVersionResolver,
        now: i64,
    ) -> Result<StorageBindingSnapshot> {
        let gate = self.binding_custody_cohorts.gate(binding.id)?;
        let mut custody = gate.lock().await;
        custody.verified = None;
        self.publish_binding_snapshot_locked(binding, credentials, resolver, now)
            .await
    }

    async fn publish_binding_snapshot_locked(
        &self,
        binding: &BindingRecord,
        credentials: &[BindingCredentialRevisionRecord],
        resolver: &dyn SecretVersionResolver,
        now: i64,
    ) -> Result<StorageBindingSnapshot> {
        let snapshot = StorageBindingSnapshot::from_binding(
            self.deployment_id.clone(),
            binding,
            credentials,
            now,
            now.checked_add(60 * 60)
                .context("binding snapshot expiry overflowed")?,
        )?;
        let mut materials = Vec::with_capacity(snapshot.credentials.len());
        for reference in &snapshot.credentials {
            let secret = resolver.resolve(&reference.secret_version_ref).await?;
            verify_secret_fingerprint(&secret, &reference.fingerprint)?;
            materials.push(StorageCredentialMaterial {
                selector: StorageCredentialSelector {
                    purpose: reference.purpose.clone(),
                    generation: reference.generation,
                },
                value_base64: base64::engine::general_purpose::STANDARD
                    .encode(secret.expose_bytes()),
            });
        }
        let control = StorageBindingControl::Publish {
            publication: StorageBindingPublication {
                snapshot: snapshot.clone(),
                materials,
            },
        };
        control.validate(&self.deployment_id, now)?;
        let expected_revision = snapshot.revision()?;
        self.send_binding_control(&control, &expected_revision)
            .await?;
        self.published_bindings
            .write()
            .map_err(|_| anyhow::anyhow!("published binding state is poisoned"))?
            .insert(binding.id, snapshot.clone());
        Ok(snapshot)
    }

    /// Hydrates one SQL binding from operator-resolved exact credential versions.
    ///
    /// Native placement reads use [`Self::ensure_remote_binding_snapshot`].
    ///
    /// # Errors
    ///
    /// Returns an error when SQL changed during publication, a secret cannot
    /// be resolved, or the Worker cannot acknowledge the exact snapshot.
    pub async fn ensure_binding_snapshot(
        &self,
        db: &Database,
        binding: &BindingRecord,
        resolver: &dyn SecretVersionResolver,
    ) -> Result<()> {
        let _gate = self.binding_publication_gate.lock().await;
        let gate = self.binding_custody_cohorts.gate(binding.id)?;
        let mut custody = gate.lock().await;
        custody.verified = None;
        let current_binding = db
            .binding(binding.id)
            .await?
            .context("external storage binding disappeared")?;
        anyhow::ensure!(
            current_binding.resource_version == binding.resource_version
                && current_binding.stable_id == binding.stable_id,
            "external storage binding changed before publication"
        );
        let credentials = db.list_current_binding_credentials(binding.id).await?;
        let now = aos_hub_core::clock::now_unix_secs();
        let desired = StorageBindingSnapshot::from_binding(
            self.deployment_id.clone(),
            &current_binding,
            &credentials,
            now,
            now.checked_add(60 * 60)
                .context("binding snapshot expiry overflowed")?,
        )?;
        let published = self
            .published_bindings
            .read()
            .map_err(|_| anyhow::anyhow!("published binding state is poisoned"))?
            .get(&binding.id)
            .cloned();
        if let Some(published) = &published {
            if published.expires_at > now.saturating_add(60)
                && published.binding_resource_version == desired.binding_resource_version
                && published.binding_spec_revision()? == desired.binding_spec_revision()?
                && published.credentials == desired.credentials
            {
                return Ok(());
            }
        }

        // The replay fence uses Unix seconds. A changed binding in the same
        // second needs a fresh issue time before the Worker can admit it.
        if published.is_some_and(|snapshot| snapshot.issued_at >= now) {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let now = aos_hub_core::clock::now_unix_secs();

        let snapshot = self
            .publish_binding_snapshot_locked(&current_binding, &credentials, resolver, now)
            .await?;
        let latest = async {
            let binding = db
                .binding(binding.id)
                .await?
                .context("external storage binding disappeared after publication")?;
            let credentials = db.list_current_binding_credentials(binding.id).await?;
            StorageBindingSnapshot::from_binding(
                self.deployment_id.clone(),
                &binding,
                &credentials,
                snapshot.issued_at,
                snapshot.expires_at,
            )
        }
        .await;
        if !matches!(&latest, Ok(current) if current == &snapshot) {
            let revision = snapshot.revision()?;
            let revoke_at =
                aos_hub_core::clock::now_unix_secs().max(snapshot.issued_at.saturating_add(1));
            let revoke = self
                .revoke_binding_snapshot_locked(binding.id, &revision, revoke_at)
                .await;
            self.published_bindings
                .write()
                .map_err(|_| anyhow::anyhow!("published binding state is poisoned"))?
                .remove(&binding.id);
            revoke.context("revoking a binding changed during publication")?;
            latest.context("rechecking a published binding")?;
            anyhow::bail!("external storage binding changed during publication");
        }
        Ok(())
    }

    /// Returns the exact metadata snapshot acknowledged by this client instance.
    ///
    /// This local receipt establishes no provider readiness or mutation permission.
    /// Callers must recheck current SQL and obtain fresh remote authority before
    /// using it to configure or qualify an external executor.
    ///
    /// # Errors
    /// Returns an error if the snapshot has not been acknowledged or local state
    /// is poisoned.
    pub fn acknowledged_binding_snapshot(&self, binding_id: i64) -> Result<StorageBindingSnapshot> {
        self.published_bindings
            .read()
            .map_err(|_| anyhow::anyhow!("published binding state is poisoned"))?
            .get(&binding_id)
            .cloned()
            .context("external binding snapshot has not been acknowledged")
    }

    /// Returns this client's immutable paired deployment audience.
    #[must_use]
    pub fn deployment_id(&self) -> &str {
        &self.deployment_id
    }

    /// Returns the configured protected executor origin for an operator receipt.
    ///
    /// # Errors
    /// Rejects an invalid endpoint or a non-HTTPS executor.
    pub fn executor_origin(&self) -> Result<String> {
        let endpoint = url::Url::parse(&self.endpoint)?;
        anyhow::ensure!(endpoint.scheme() == "https", "operator executor must use HTTPS");
        Ok(endpoint.origin().ascii_serialization())
    }

    fn validate_published_binding_snapshot(
        &self,
        binding: &BindingRecord,
        credentials: &[BindingCredentialRevisionRecord],
        expected_revision: &str,
    ) -> Result<()> {
        let published = self
            .published_bindings
            .read()
            .map_err(|_| anyhow::anyhow!("published binding state is poisoned"))?
            .get(&binding.id)
            .cloned()
            .context("external binding snapshot disappeared during Worker execution")?;
        anyhow::ensure!(
            published.revision()? == expected_revision,
            "external binding snapshot changed during Worker execution"
        );
        let current = StorageBindingSnapshot::from_binding(
            self.deployment_id.clone(),
            binding,
            credentials,
            published.issued_at,
            published.expires_at,
        )?;
        anyhow::ensure!(
            current == published,
            "external binding credentials changed during Worker execution"
        );
        Ok(())
    }

    /// Withdraws one exact external binding revision from the Worker.
    ///
    /// # Errors
    ///
    /// Returns an error when the signed revocation is stale, the Worker does
    /// not acknowledge the exact revision, or the control channel fails.
    pub async fn revoke_binding_snapshot(
        &self,
        binding_id: i64,
        revision: &str,
        now: i64,
    ) -> Result<()> {
        let gate = self.binding_custody_cohorts.gate(binding_id)?;
        let mut custody = gate.lock().await;
        custody.verified = None;
        custody.retry_after = None;
        self.revoke_binding_snapshot_locked(binding_id, revision, now)
            .await
    }

    // Callers hold the binding custody gate, including adoption race recovery.
    async fn revoke_binding_snapshot_locked(
        &self,
        binding_id: i64,
        revision: &str,
        now: i64,
    ) -> Result<()> {
        let control = StorageBindingControl::Revoke {
            deployment_id: self.deployment_id.clone(),
            binding_id,
            revision: revision.to_owned(),
            issued_at: now,
            expires_at: now
                .checked_add(30)
                .context("binding revocation expiry overflowed")?,
        };
        control.validate(&self.deployment_id, now)?;
        self.send_binding_control(&control, revision).await?;
        let mut published = self
            .published_bindings
            .write()
            .map_err(|_| anyhow::anyhow!("published binding state is poisoned"))?;
        if published
            .get(&binding_id)
            .is_some_and(|snapshot| snapshot.revision().ok().as_deref() == Some(revision))
        {
            published.remove(&binding_id);
        }
        Ok(())
    }

    async fn send_binding_control(
        &self,
        control: &StorageBindingControl,
        expected_revision: &str,
    ) -> Result<()> {
        let body = Zeroizing::new(serde_json::to_vec(control)?);
        anyhow::ensure!(
            body.len() <= MAX_BINDING_CONTROL_BYTES,
            "binding control body exceeds its limit"
        );
        let signature = self.key.sign_body(body.as_slice())?;
        let response = self
            .http
            .post(&self.binding_control_endpoint)
            .header("content-type", "application/json")
            .header(STORAGE_WORK_SIGNATURE_HEADER, signature)
            .body(body.to_vec())
            .send()
            .await
            .context("sending binding control to storage Worker")?;
        anyhow::ensure!(
            response.status() == reqwest::StatusCode::OK,
            "storage Worker rejected binding control with HTTP {}",
            response.status()
        );
        let response_body = read_bounded_response(response, 4096).await?;
        let acknowledgement: StorageBindingAcknowledgement =
            serde_json::from_slice(&response_body).context("decoding binding acknowledgement")?;
        anyhow::ensure!(
            acknowledgement.revision == expected_revision,
            "storage Worker acknowledged another binding revision"
        );
        Ok(())
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
            placement.binding_id == binding.id,
            "storage work binding differs from its placement"
        );
        let snapshot = if binding.kind == "deployment_r2" && binding.is_instance_default {
            None
        } else {
            anyhow::ensure!(
                matches!(binding.kind.as_str(), "s3" | "r2") && !binding.is_instance_default,
                "storage work requires an admitted object-store binding"
            );
            Some(
                self.published_bindings
                    .read()
                    .map_err(|_| anyhow::anyhow!("published binding state is poisoned"))?
                    .get(&binding.id)
                    .cloned()
                    .context("external binding snapshot has not been acknowledged")?,
            )
        };
        let credential_references = if let Some(snapshot) = &snapshot {
            if snapshot.access_mode == "public" {
                Vec::new()
            } else {
                operation
                    .credential_purposes()
                    .iter()
                    .map(|purpose| {
                        let reference = snapshot
                            .credentials
                            .iter()
                            .find(|reference| reference.purpose == *purpose)
                            .with_context(|| {
                                format!("external binding lacks {purpose} credential")
                            })?;
                        Ok(StorageCredentialSelector {
                            purpose: reference.purpose.clone(),
                            generation: reference.generation,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?
            }
        } else {
            Vec::new()
        };
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
            binding_snapshot_revision: snapshot
                .as_ref()
                .map(StorageBindingSnapshot::revision)
                .transpose()?,
            credential_references,
            placement_prefix: placement.prefix.clone(),
            operation,
        };
        plan.validate(&self.deployment_id, now)?;
        if let Some(snapshot) = &snapshot {
            snapshot.authorizes(&plan, &self.deployment_id, now)?;
        }
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
        let _permit = self
            .in_flight
            .acquire()
            .await
            .context("hybrid storage work executor closed")?;
        let now = aos_hub_core::clock::now_unix_secs();
        plan.validate(&self.deployment_id, now)?;
        let body = serde_json::to_vec(plan).context("encoding storage work plan")?;
        let signature = self.key.sign_body(&body)?;
        let endpoint = self.endpoint.clone();
        #[cfg(test)]
        let (signature, endpoint) = match &self.controlled_mirror {
            Some(candidate) => {
                if matches!(&plan.operation, StorageWorkOperation::InspectMirrorMembership { .. }) {
                    let signature = aos_hub_core::mirror_candidate::query::sign(&candidate.key, plan)?;
                    let origin = self.executor_origin()?;
                    (signature, format!("{origin}{}", aos_hub_core::mirror_candidate::query::MIRROR_CANDIDATE_QUERY_PATH))
                } else {
                let signature = aos_hub_core::mirror_candidate::sign_mirror_candidate_plan(
                    &candidate.key, plan,
                )?;
                let origin = self.executor_origin()?;
                (signature, format!("{origin}{}", aos_hub_core::mirror_candidate::MIRROR_CANDIDATE_PATH))
                }
            }
            None => (signature, endpoint.clone()),
        };

        let request_bytes = body.len();
        let started = Instant::now();
        let mut exchange = telemetry::ExchangeTelemetry::new(plan);

        // A lost response may follow a committed mutation; retry only reads.
        let max_attempts = if retryable_read_operation(&plan.operation) {
            MAX_READ_WORK_ATTEMPTS
        } else {
            1
        };
        let mut attempt = 0;
        let response = loop {
            attempt += 1;
            plan.validate(&self.deployment_id, aos_hub_core::clock::now_unix_secs())
                .inspect_err(|_| exchange.finish("invalid_plan"))?;
            let mut request = self
                .http
                .post(&endpoint)
                .header("content-type", "application/json")
                .header(STORAGE_WORK_SIGNATURE_HEADER, signature.clone())
                .body(body.clone());
            if matches!(&plan.operation, StorageWorkOperation::ComposeOciBlob { .. }
                | StorageWorkOperation::InspectMirrorPack { .. }
                | StorageWorkOperation::InspectMirrorMembership { .. }
                | StorageWorkOperation::InspectStoredGitPack { .. }
                | StorageWorkOperation::FilterStoredGitPackTree { .. }
                | StorageWorkOperation::InspectMirrorTreeInventory { .. })
                || matches!(&plan.operation, StorageWorkOperation::MirrorTransferBatch { items }
                    if items.iter().any(|item| matches!(item.step, aos_hub_core::mirror_work::MirrorStep::VerifyStage)))
                || matches!(&plan.operation, StorageWorkOperation::MirrorTransfer { step: aos_hub_core::mirror_work::MirrorStep::VerifyStage, .. })
                || matches!(
                    &plan.operation,
                    StorageWorkOperation::InspectSha256 { max_source_bytes, .. }
                        if *max_source_bytes > 64 * 1024 * 1024
                )
            {
                request = request.timeout(Duration::from_secs(10 * 60));
            }
            exchange.offer_plan(request_bytes);
            let response = match request.send().await {
                Ok(response) => response,
                Err(error) if attempt < max_attempts => {
                    tracing::warn!(
                        plan_id = %plan.plan_id,
                        operation = plan.operation.kind(),
                        attempt,
                        error = %error,
                        "retrying read-only hybrid storage transport"
                    );
                    tokio::time::sleep(Duration::from_millis(100 * attempt as u64)).await;
                    continue;
                }
                Err(error) => {
                    exchange.finish("transport_failed");
                    tracing::warn!(
                        plan_id = %plan.plan_id,
                        operation = plan.operation.kind(),
                        request_bytes,
                        attempts = attempt,
                        elapsed_ms = started.elapsed().as_millis() as u64,
                        error = %error,
                        "hybrid storage boundary transport failed"
                    );
                    return Err(error).context("sending storage work plan");
                }
            };
            if attempt < max_attempts && retryable_worker_status(response.status()) {
                exchange.discard_status_response();
                tracing::warn!(
                    plan_id = %plan.plan_id,
                    operation = plan.operation.kind(),
                    attempt,
                    http_status = response.status().as_u16(),
                    "retrying read-only hybrid storage work"
                );
                tokio::time::sleep(Duration::from_millis(100 * attempt as u64)).await;
                continue;
            }
            break response;
        };
        let status = response.status();
        if status != reqwest::StatusCode::OK {
            tracing::warn!(
                plan_id = %plan.plan_id,
                operation = plan.operation.kind(),
                request_bytes,
                attempts = attempt,
                http_status = status.as_u16(),
                elapsed_ms = started.elapsed().as_millis() as u64,
                "hybrid storage boundary rejected"
            );
        }
        if status == reqwest::StatusCode::PAYLOAD_TOO_LARGE {
            exchange.discard_status_response();
            exchange.finish("response_too_large");
            return Err(StorageWorkResultTooLarge.into());
        }
        if status != reqwest::StatusCode::OK {
            exchange.discard_status_response();
            exchange.finish("http_rejected");
            bail!("storage Worker returned HTTP {status}");
        }
        let body =
            read_observed_response(response, plan.operation.maximum_result_bytes(), |length| {
                exchange.observe_body(length);
            })
            .await
            .inspect_err(|_| exchange.finish("response_read_failed"))?;
        let response_bytes = body.len();
        let result: StorageWorkResult = serde_json::from_slice(&body)
            .context("decoding storage work result")
            .inspect_err(|_| exchange.finish("malformed_result"))?;
        validate_result(plan, &result).inspect_err(|_| exchange.finish("invalid_result"))?;
        validate_result_acceptance_at(plan, &result, aos_hub_core::clock::now_unix_secs())
            .inspect_err(|_| exchange.finish("expired_result"))?;
        exchange.finish("success");
        tracing::info!(
            plan_id = %plan.plan_id,
            operation = plan.operation.kind(),
            request_bytes,
            attempts = attempt,
            response_bytes,
            source_bytes = result.source_bytes,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "hybrid storage boundary"
        );
        Ok(result)
    }
}

/// Hybrid controller adapter that probes exact Worker-held credential material.
pub struct HybridStorageCredentialProbeProvider {
    work: Arc<RemoteStorageWorkClient>,
    db: Arc<Database>,
}

impl HybridStorageCredentialProbeProvider {
    /// Creates the controller-owned hybrid credential probe adapter.
    #[must_use]
    pub fn new(work: Arc<RemoteStorageWorkClient>, db: Arc<Database>) -> Self {
        Self { work, db }
    }
}

#[async_trait]
impl StorageCredentialProbeProvider for HybridStorageCredentialProbeProvider {
    async fn probe(
        &self,
        binding: &BindingRecord,
        credential: &BindingCredentialRevisionRecord,
        operation_id: &str,
        probe_token: &str,
    ) -> Result<StorageCredentialProbeEvidence> {
        anyhow::ensure!(
            credential.binding_id == binding.id,
            "credential probe binding mismatch"
        );
        let check = || async {
            let current_binding = self
                .db
                .binding(binding.id)
                .await?
                .context("probe binding absent")?;
            let current_credential = self
                .db
                .current_binding_credential(binding.id, &credential.purpose)
                .await?
                .context("probe credential absent")?;
            let now = aos_hub_core::clock::now_unix_secs();
            let current = StorageBindingSnapshot::for_credential_probe(
                self.work.deployment_id.clone(), &current_binding, &current_credential, now,
            )?;
            let original = StorageBindingSnapshot::for_credential_probe(
                self.work.deployment_id.clone(), binding, credential, now,
            )?;
            anyhow::ensure!(
                current_credential == *credential && current == original,
                "probe SQL originals changed"
            );
            Ok::<(), anyhow::Error>(())
        };
        check().await?;
        let evidence = self
            .work
            .probe_retained_credential(binding, credential, operation_id, probe_token)
            .await?;
        check().await?;
        Ok(evidence)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("storage Worker result exceeds its limit")]
struct StorageWorkResultTooLarge;

async fn read_bounded_response(response: reqwest::Response, maximum: usize) -> Result<Vec<u8>> {
    read_observed_response(response, maximum, |_| {}).await
}

async fn read_observed_response(
    response: reqwest::Response,
    maximum: usize,
    mut observe_chunk: impl FnMut(usize),
) -> Result<Vec<u8>> {
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
        observe_chunk(chunk.len());
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

fn validate_console_asset_version(capabilities: &StorageCapabilities) -> Result<()> {
    anyhow::ensure!(
        capabilities.console_asset_version.as_deref()
            == Some(aos_hub_core::web::assets::asset_version()),
        "hybrid Worker console bundle is missing or differs from the Native bundle"
    );
    Ok(())
}

/// Checks retained legacy storage capabilities against the Native contract.
///
/// This observational facade does not authenticate the challenge response or
/// establish deployment authorization. The caller must retain the independently
/// correlated transport acceptance and original challenge.
///
/// # Errors
/// Returns an error for changed deployment, protocol, limits, required operations
/// or the console asset version compiled into Native.
#[cfg(feature = "test-support")]
pub fn validate_capabilities_for_test(
    deployment_id: &str,
    capabilities: &StorageCapabilities,
) -> Result<()> {
    validate_capabilities(deployment_id, capabilities)?;
    validate_console_asset_version(capabilities)
}

fn validate_capabilities(deployment_id: &str, capabilities: &StorageCapabilities) -> Result<()> {
    anyhow::ensure!(
        capabilities.version == 1
            && capabilities.deployment_id == deployment_id
            && capabilities.binding_kind == "deployment_r2"
            && capabilities.r2_gc_incarnation_v1
            && capabilities.max_result_bytes == MAX_RESULT_BYTES
            && capabilities.max_verify_source_bytes == MAX_VERIFY_SOURCE_BYTES
            && [
                "head",
                "list_page",
                "inspect_sha256",
                "inspect_git_object",
                "inspect_git_objects",
                "filter_git_tree_entries_v1",
                "inspect_metadata",
                "inspect_metadata_objects",
                "inspect_documentation",
                "inspect_documentation_content",
                "inspect_oci_range",
                "hash_oci_range",
                "copy_object",
                "compose_oci_blob",
                "stage_oci_manifest",
                "delete_oci_staging",
                "delete_if_matches",
                "put_metadata",
                "put_probe",
                "delete_probe",
                "create_multipart",
                "complete_multipart",
                "abort_multipart",
                "credential_probe"
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

/// Checks retained storage-result correlation, semantics and byte budgets.
///
/// This observational check does not authenticate a reply, establish its live
/// acceptance time or grant execution permission. Transport evidence must bind
/// the exact accepted request and response independently.
///
/// # Errors
/// Returns an error for changed fences, invalid outcomes or exceeded costs.
#[cfg(feature = "test-support")]
pub fn validate_result_for_test(plan: &StorageWorkPlan, result: &StorageWorkResult) -> Result<()> {
    validate_result(plan, result)
}

// Live acceptance is separate from pure retained-result validation. A cached
// page retains its original short plan; a cold immutable verification has one
// finite horizon derived from the original issue time, never from reply arrival.
fn validate_result_acceptance_at(
    plan: &StorageWorkPlan,
    result: &StorageWorkResult,
    now: i64,
) -> Result<()> {
    if matches!(
        plan.operation,
        StorageWorkOperation::InspectMirrorLiveMetadataBatch { .. }
    ) {
        plan.validate(&plan.deployment_id, now)?;
        anyhow::ensure!(now < plan.expires_at, "live metadata batch reply expired");
        return Ok(());
    }
    if !matches!(
        plan.operation,
        StorageWorkOperation::InspectMirrorMembership { .. }
            | StorageWorkOperation::InspectMirrorTreeInventory { .. }
    ) {
        return Ok(());
    }

    if result.source_bytes == 0 {
        plan.validate(&plan.deployment_id, now)?;
        return Ok(());
    }

    let cutoff = plan
        .issued_at
        .checked_add(600)
        .context("immutable verification cutoff overflow")?;
    anyhow::ensure!(
        now >= plan.issued_at && now < cutoff,
        "immutable verification response expired or clock regressed"
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
            StorageWorkOperation::InspectMirrorLiveMetadata { target },
            StorageWorkOutcome::MirrorLiveMetadata {
                sha256,
                size,
                content_base64,
            },
        ) => {
            let item = aos_hub_core::storage_work::live_metadata_batch::LiveMetadataObservation {
                target_digest: aos_hub_core::storage_work::live_metadata_batch::target_digest(target)?,
                source_bytes: Some(result.source_bytes),
                outcome: aos_hub_core::storage_work::live_metadata_batch::LiveMetadataOutcome::Found {
                    sha256: sha256.clone(),
                    size: *size,
                    content_base64: content_base64.clone(),
                },
            };
            aos_hub_core::storage_work::live_metadata_batch::validate_observations(
                std::slice::from_ref(target),
                &[item],
                result.source_bytes,
            )?;
        }
        (StorageWorkOperation::InspectMirrorLiveMetadata { .. }, StorageWorkOutcome::NotFound) => {
            anyhow::ensure!(result.source_bytes == 0, "live absence reports body bytes");
        }
        (
            StorageWorkOperation::InspectMirrorLiveMetadataBatch { targets },
            StorageWorkOutcome::MirrorLiveMetadataBatch { items },
        ) => {
            aos_hub_core::storage_work::live_metadata_batch::validate_observations(
                targets,
                items,
                result.source_bytes,
            )?;
            anyhow::ensure!(
                serde_json::to_vec(result)?.len() <= MAX_RESULT_BYTES,
                "live metadata batch result exceeds the aggregate bound"
            );
        }
        (
            StorageWorkOperation::InspectMirrorMembership { query },
            StorageWorkOutcome::MirrorMembership { projection },
        ) => {
            projection.validate(query)?;
            let total = projection.pair.pack.size + projection.pair.index.size;
            anyhow::ensure!(
                result.source_bytes == 0 || result.source_bytes == total,
                "membership accounting is neither a cache hit nor a complete pair read"
            );
        }
        (
            StorageWorkOperation::InspectMirrorTreeInventory { query },
            StorageWorkOutcome::NotFound,
        ) => {
            anyhow::ensure!(
                matches!(
                    query.source,
                    aos_hub_core::mirror_tree_inventory::MirrorTreeInventorySource::Loose { .. }
                ) && query.cursor.is_none()
                    && result.source_bytes == 0,
                "inventory absence changed authority"
            );
        }
        (
            StorageWorkOperation::InspectMirrorTreeInventory { query },
            StorageWorkOutcome::MirrorTreeInventory { projection },
        ) => {
            projection.validate(query)?;
            let total = projection.source.source_bytes();
            anyhow::ensure!(
                result.source_bytes == 0 || result.source_bytes == total,
                "inventory source accounting is neither a cache hit nor one complete pair read"
            );
        }
        (StorageWorkOperation::FilterStoredGitPackTree { query },
            StorageWorkOutcome::GitPackTreeProjection { projection }) => {
            projection.validate(query)?;
            anyhow::ensure!(result.source_bytes == projection.pair.pack.size + projection.pair.index.size,
                "pack tree source-byte accounting differs");
        }
        (StorageWorkOperation::MirrorTransferBatch { items }, StorageWorkOutcome::MirrorBatch { items: results }) => {
            aos_hub_core::mirror_batch::validate_results(items, results, result.source_bytes)?;
        }
        (StorageWorkOperation::InspectMirrorPack { inspection },
            StorageWorkOutcome::GitPackProjection { projection }) => {
            projection.validate(&inspection.index_path, &inspection.selections)?;
            anyhow::ensure!(result.source_bytes == projection.pack.size + projection.index.size,
                "pack projection source-byte accounting differs");
        }
        (StorageWorkOperation::InspectStoredGitPack { index_path, selections, .. },
            StorageWorkOutcome::GitPackProjection { projection }) => {
            projection.validate(index_path, selections)?;
            anyhow::ensure!(result.source_bytes == projection.pack.size + projection.index.size,
                "pack projection source-byte accounting differs");
        }
        (StorageWorkOperation::MirrorTransfer { original, step }, StorageWorkOutcome::MirrorProgress { progress }) => {
            progress.validate(original)?;
            let maximum = match step {
                aos_hub_core::mirror_work::MirrorStep::UploadParts { maximum_parts, .. }
                | aos_hub_core::mirror_work::MirrorStep::CopyParts { maximum_parts, .. } => u64::from(*maximum_parts) * aos_hub_core::mirror_work::MIRROR_PART_BYTES,
                aos_hub_core::mirror_work::MirrorStep::VerifyStage => original.verification.size(),
                _ => 0,
            };
            anyhow::ensure!(result.source_bytes <= maximum, "mirror result exceeds its issued source-byte budget");
            if let aos_hub_core::mirror_work::MirrorStep::Acknowledge { commit_digest } = step {
                anyhow::ensure!(progress.commit_digest(original)? == *commit_digest, "mirror acknowledgement changed final proof");
            }
        }
        (
            StorageWorkOperation::Head { .. }
            | StorageWorkOperation::InspectSha256 { .. }
            | StorageWorkOperation::InspectMetadata { .. }
            | StorageWorkOperation::InspectOciRange { .. }
            | StorageWorkOperation::HashOciRange { .. },
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
        (StorageWorkOperation::FilterGitTreeEntries { .. }, StorageWorkOutcome::NotFound) => {
            anyhow::ensure!(
                result.source_bytes <= object_bundle::MAX_BUNDLE_BYTES as u64,
                "missing tree reported excessive source bytes"
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
            StorageWorkOperation::DeleteIfMatches { expected_etag, .. },
            StorageWorkOutcome::ObjectDeleted { etag },
        ) => {
            anyhow::ensure!(
                result.source_bytes == 0 && etag == expected_etag,
                "storage Worker deleted a different object identity"
            );
        }
        (
            StorageWorkOperation::DeleteIfMatches { .. },
            StorageWorkOutcome::NotFound | StorageWorkOutcome::DeletePreconditionFailed,
        )
        | (StorageWorkOperation::PutMetadata { .. }, StorageWorkOutcome::MetadataWritten)
        | (
            StorageWorkOperation::PutProbe { .. } | StorageWorkOperation::DeleteProbe { .. },
            StorageWorkOutcome::ProbeAcknowledged,
        ) => {
            anyhow::ensure!(
                result.source_bytes == 0,
                "storage Worker returned source bytes"
            );
        }
        (
            StorageWorkOperation::CreateMultipart { .. },
            StorageWorkOutcome::MultipartCreated { upload_id },
        ) => {
            anyhow::ensure!(
                result.source_bytes == 0
                    && !upload_id.is_empty()
                    && upload_id.len() <= 1024
                    && upload_id
                        .bytes()
                        .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\'),
                "storage Worker returned an invalid multipart upload identity"
            );
        }
        (
            StorageWorkOperation::CompleteMultipart { path, .. },
            StorageWorkOutcome::MultipartCompleted { object },
        ) => {
            aos_hub_core::surface_write::strong_if_match_etag(&object.etag)?;
            anyhow::ensure!(
                result.source_bytes == 0 && object.key == plan.object_key(path)?,
                "storage Worker completed a different multipart object"
            );
        }
        (
            StorageWorkOperation::AbortMultipart { .. },
            StorageWorkOutcome::MultipartAborted { .. },
        ) => {
            anyhow::ensure!(
                result.source_bytes == 0,
                "storage Worker multipart abort returned source bytes"
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
            StorageWorkOperation::InspectMetadataObjects { .. },
            StorageWorkOutcome::MetadataObjects { page },
        ) => page.validate(plan, result.source_bytes)?,
        (
            StorageWorkOperation::FilterGitTreeEntries { oid, names, cursor },
            StorageWorkOutcome::GitTreeEntries { source, page },
        ) => tree_projection::validate(
            plan,
            oid,
            names,
            cursor.as_ref(),
            source,
            page,
            result.source_bytes,
        )?,
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
            StorageWorkOperation::InspectDocumentationContent {
                package_name,
                package_version,
                platform,
                artifact,
            },
            StorageWorkOutcome::DocumentationContent { document },
        ) => {
            anyhow::ensure!(
                result.source_bytes >= artifact.nar_size
                    && result.source_bytes
                        <= artifact
                            .nar_size
                            .checked_add(MAX_METADATA_BYTES as u64)
                            .context("documentation content source limit overflowed")?,
                "documentation content source accounting exceeded its admitted limit"
            );
            aos_hub_core::indexer::validate_package_documentation_content(
                document,
                package_name,
                package_version,
                platform,
                artifact,
            )?;
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
        (
            StorageWorkOperation::HashOciRange {
                path,
                start,
                end,
                total,
                strong_etag,
                expected_provider_version,
                ..
            },
            StorageWorkOutcome::OciRangeHashed {
                source,
                start: returned_start,
                end: returned_end,
                sha256_state,
            },
        ) => {
            sha256_state.validate()?;
            anyhow::ensure!(
                source.key == plan.object_key(path)?
                    && source.size == *total
                    && source.etag == strong_etag.as_str()
                    && source.provider_version.as_ref() == expected_provider_version.as_ref()
                    && source
                        .provider_version
                        .as_deref()
                        .is_none_or(aos_hub_core::storage_work::valid_provider_version)
                    && returned_start == start
                    && returned_end == end
                    && sha256_state.total_bytes == end.saturating_add(1)
                    && result.source_bytes == end - start + 1
                    && result.source_bytes <= MAX_OCI_HASH_RANGE_BYTES as u64,
                "storage Worker OCI hash did not match the signed range or object"
            );
        }
        (
            StorageWorkOperation::CopyObject {
                source_prefix,
                path,
                expected_size,
                expected_etag,
                ..
            },
            StorageWorkOutcome::ObjectCopied {
                source,
                destination,
            },
        ) => {
            aos_hub_core::surface_write::strong_if_match_etag(&destination.etag)?;
            anyhow::ensure!(
                source.key == aos_hub_core::keymap::r2_key(source_prefix, path)
                    && source.size == *expected_size
                    && source.etag == expected_etag.as_str()
                    && destination.key == plan.object_key(path)?
                    && destination.size == *expected_size
                    && result.source_bytes == *expected_size,
                "storage Worker copied a different source or destination object"
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
    pub fn new(
        db: Arc<Database>,
        work: Arc<RemoteStorageWorkClient>,
    ) -> Self {
        Self { db, work }
    }
}

#[async_trait]
impl SurfaceProvider for HybridSurfaceProvider {
    fn storage_local_documentation_inspection(&self) -> bool {
        true
    }

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
        if !binding.is_instance_default {
            self.work
                .ensure_remote_binding_snapshot(&self.db, &binding)
                .await?;
        }
        Ok(Box::new(HybridSurfaceFetch {
            db: Arc::clone(&self.db),
            placement: placement.clone(),
            binding,
            work: Arc::clone(&self.work),
        }))
    }

    async fn frozen_placement_fetcher(
        &self,
        access: &FrozenSurfaceAccess,
    ) -> Result<Box<dyn SurfaceFetch>> {
        Ok(Box::new(
            frozen::FrozenR2Surface::open(Arc::clone(&self.db), Arc::clone(&self.work), access)
                .await?,
        ))
    }

    async fn claimed_placement_fetcher(
        &self,
        access: &FrozenSurfaceAccess,
        claim: &aos_hub_core::db::OciGcPlacementActionClaim,
    ) -> Result<Box<dyn SurfaceFetch>> {
        let binding = self
            .db
            .binding(access.binding_id)
            .await?
            .context("frozen hybrid binding disappeared")?;
        if binding.kind == "deployment_r2" {
            return self.frozen_placement_fetcher(access).await;
        }

        Ok(Box::new(
            frozen_head::FrozenClaimSurface::open(
                Arc::clone(&self.db),
                Arc::clone(&self.work),
                access,
                claim,
            )
            .await?,
        ))
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
        let missing = decoded.iter().filter_map(|(oid, value)| value.is_none().then_some(*oid))
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            decoded.extend(self.inspect_packed_git(&missing).await?);
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
        if let Some(expected_revision) = &plan.binding_snapshot_revision {
            let credentials = self.db.list_current_binding_credentials(binding.id).await?;
            self.work.validate_published_binding_snapshot(
                &binding,
                &credentials,
                expected_revision,
            )?;
        }
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
            StorageWorkOutcome::NotFound => {
                // Live pointers and release packs are delivered fresh by the
                // public Worker; they cannot acquire a persisted mirror HEAD.
                if aos_hub_core::hybrid_ingress::live::live_path(path) {
                    return Ok(None);
                }
                if let Some(registry_id) = self.placement.registry_id {
                    if crate::mirror::hybrid::fetch_through(&self.db, &self.work, registry_id, path).await? {
                        let refreshed = self.work.plan_for_placement(&self.placement, &self.binding,
                            StorageWorkOperation::Head { path: path.into() }, aos_hub_core::clock::now_unix_secs())?;
                        return match self.execute(&refreshed).await?.outcome {
                            StorageWorkOutcome::Head { object } => Ok(Some(object)),
                            _ => anyhow::bail!("positive pull-through import has no exact delivery HEAD"),
                        };
                    }
                }
                Ok(None)
            }
            StorageWorkOutcome::Head { object } => Ok(Some(object)),
            _ => bail!("storage Worker returned an unexpected head result"),
        }
    }
}

#[async_trait]
impl SurfaceFetch for HybridSurfaceFetch {
    fn storage_local_tree_projection(&self) -> bool {
        true
    }

    async fn inspect_git_tree_entries(
        &self,
        oid: object::Oid,
        names: &[String],
        cursor: Option<&aos_hub_core::tree_projection::GitTreeCursor>,
    ) -> Result<Option<aos_hub_core::tree_projection::GitTreeEntriesPage>> {
        tree_projection::inspect(self, oid, names, cursor).await
    }

    fn describe(&self) -> String {
        format!("hybrid Worker placement {}", self.placement.id)
    }

    async fn delivery_head(&self, path: &str) -> Result<Option<SurfaceDeliveryHead>> {
        Ok(self.head(path).await?.map(|object| SurfaceDeliveryHead {
            size: object.size,
            strong_etag: object.etag,
        }))
    }

    async fn live_delivery(
        &self,
        path: &str,
    ) -> Result<Option<aos_hub_core::hybrid_ingress::live::HybridLiveDeliveryTarget>> {
        let Some(registry_id) = self.placement.registry_id else {
            return Ok(None);
        };
        let target =
            crate::mirror::hybrid::live_delivery(&self.db, &self.work, registry_id, path).await?;
        Ok(target.filter(|target| {
            target.placement_id == self.placement.id
                && target.placement_resource_version == self.placement.resource_version
                && target.binding_id == self.binding.id
                && target.binding_resource_version == self.binding.resource_version
                && target.write_spec_version == self.placement.write_spec_version
                && target.placement_prefix == self.placement.prefix
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
            StorageWorkOutcome::NotFound => {
                if let Some(registry_id) = self.placement.registry_id {
                    if aos_hub_core::hybrid_ingress::live::live_path(path) {
                        return crate::mirror::hybrid::live_metadata(
                            &self.db, &self.work, registry_id, path,
                        )
                        .await;
                    }
                    if crate::mirror::hybrid::fetch_through(&self.db, &self.work, registry_id, path).await? {
                        let refreshed = self.work.plan_for_placement(&self.placement, &self.binding,
                            StorageWorkOperation::InspectMetadata { path: path.into() }, aos_hub_core::clock::now_unix_secs())?;
                        let StorageWorkOutcome::Metadata { content_base64, .. } = self.execute(&refreshed).await?.outcome else {
                            anyhow::bail!("positive pull-through import lacks bounded metadata");
                        };
                        return Ok(Some(base64::engine::general_purpose::STANDARD.decode(content_base64)?));
                    }
                }
                Ok(None)
            }
            StorageWorkOutcome::Metadata { content_base64, .. } => Ok(Some(
                base64::engine::general_purpose::STANDARD
                    .decode(content_base64)
                    .context("decoding metadata from storage Worker")?,
            )),
            _ => bail!("storage Worker returned an unexpected metadata result"),
        }
    }

    async fn fetch_metadata_batch(&self, paths: &[String]) -> Result<Vec<Option<Vec<u8>>>> {
        let mut requested = paths.to_vec();
        requested.sort();
        requested.dedup();
        let mut observations = BTreeMap::new();
        for batch in requested.chunks(MAX_METADATA_INSPECTION_BATCH) {
            let mut cursor = 0;
            loop {
                let plan = self.work.plan_for_placement(
                    &self.placement,
                    &self.binding,
                    StorageWorkOperation::InspectMetadataObjects {
                        paths: batch.to_vec(),
                        cursor,
                    },
                    aos_hub_core::clock::now_unix_secs(),
                )?;
                let result = self.execute(&plan).await?;
                let StorageWorkOutcome::MetadataObjects { page } = result.outcome else {
                    bail!("storage Worker returned an unexpected metadata batch result");
                };
                for object in page.objects {
                    let bytes = object
                        .document
                        .map(|document| {
                            base64::engine::general_purpose::STANDARD
                                .decode(document.content_base64)
                                .context("decoding batched metadata from storage Worker")
                        })
                        .transpose()?;
                    observations.insert(object.path, bytes);
                }
                let Some(next) = page.next_cursor else {
                    break;
                };
                cursor = next;
            }
        }
        // Stored observations retain their batch transport. Only missing live
        // metadata gets a fresh bounded query; bulk sources never enter this port.
        let missing_live: Vec<_> = requested
            .iter()
            .filter(|path| {
                observations.get(*path).is_some_and(Option::is_none)
                    && aos_hub_core::hybrid_ingress::live::live_path(path)
            })
            .cloned()
            .collect();
        if let Some(registry_id) = self.placement.registry_id {
            if !missing_live.is_empty() {
                let returned = crate::mirror::hybrid::live_metadata_batch(
                    &self.db,
                    &self.work,
                    registry_id,
                    &missing_live,
                )
                .await?;
                for (path, bytes) in missing_live.into_iter().zip(returned) {
                    observations.insert(path, bytes);
                }
            }
        }
        paths
            .iter()
            .map(|path| {
                observations
                    .get(path)
                    .cloned()
                    .with_context(|| format!("storage Worker omitted metadata path '{path}'"))
            })
            .collect()
    }

    async fn fetch_bounded(&self, path: &str, max_bytes: usize) -> Result<Option<Vec<u8>>> {
        control::fetch_bounded(self, path, max_bytes).await
    }

    async fn oci_document_projection(
        &self,
        path: &str,
        descriptor: &aos_oci_types::Descriptor,
        admission: Option<&aos_hub_core::hybrid_ingress::HybridOciManifestAdmission>,
    ) -> Result<Option<aos_hub_core::oci_projection::guard::VerifiedOciProjection>> {
        self.read_oci_projection(path, descriptor, admission).await
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

    async fn package_documentation_content(
        &self,
        package_name: &str,
        package_version: &str,
        platform: &str,
        artifact: &aos_registry_surface::manifest::DocumentationArtifactMeta,
    ) -> Result<aos_doc_model::PackageDocumentation> {
        let plan = self.work.plan_for_placement(
            &self.placement,
            &self.binding,
            StorageWorkOperation::InspectDocumentationContent {
                package_name: package_name.into(),
                package_version: package_version.into(),
                platform: platform.into(),
                artifact: artifact.clone(),
            },
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let result = self.execute(&plan).await?;
        let StorageWorkOutcome::DocumentationContent { document } = result.outcome else {
            bail!("storage Worker returned an unexpected documentation content result");
        };
        Ok(document)
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
            StorageWorkOutcome::NotFound => {
                Ok(self.inspect_packed_git(&[oid]).await?.remove(&oid).flatten())
            }
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
        let batches = sorted
            .chunks(MAX_GIT_INSPECTION_BATCH)
            .map(|chunk| chunk.to_vec())
            .collect::<Vec<_>>();
        let groups = futures_util::stream::iter(batches)
            .map(|batch| self.inspect_git_batch(batch))
            .buffer_unordered(MAX_PARALLEL_GIT_INSPECTION_BATCHES)
            .try_collect::<Vec<_>>()
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

    async fn inventory_hash_chunk_bounded(
        &self,
        path: &str,
        offset: u64,
        expected_total: u64,
        maximum_bytes: u64,
        strong_etag: &str,
        expected_provider_version: Option<&str>,
        sha256_state: aos_hub_core::db::OciSha256State,
    ) -> Result<Option<SurfaceInventoryHashChunk>> {
        sha256_state.validate()?;
        anyhow::ensure!(
            aos_hub_core::storage_work::admitted_oci_blob_path(path)
                && maximum_bytes > 0
                && offset < expected_total
                && sha256_state.total_bytes == offset,
            "hybrid OCI inventory hash request is invalid"
        );
        let length = maximum_bytes.min(MAX_OCI_HASH_RANGE_BYTES as u64);
        let end = offset
            .checked_add(length - 1)
            .context("hybrid OCI hash range overflowed")?
            .min(expected_total - 1);
        let plan = self.work.plan_for_placement(
            &self.placement,
            &self.binding,
            StorageWorkOperation::HashOciRange {
                expected_provider_version: expected_provider_version.map(str::to_string),
                path: path.into(),
                start: offset,
                end,
                total: expected_total,
                strong_etag: strong_etag.into(),
                sha256_state,
            },
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let result = self.execute(&plan).await?;
        match result.outcome {
            StorageWorkOutcome::NotFound => Ok(None),
            StorageWorkOutcome::OciRangeHashed {
                source,
                start,
                end,
                sha256_state,
            } => Ok(Some(SurfaceInventoryHashChunk {
                total: source.size,
                range: (start, end),
                strong_etag: source.etag,
                provider_version: source.provider_version,
                sha256_state,
            })),
            _ => bail!("storage Worker returned an unexpected OCI hash result"),
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
        self.list_page_with_prefix("", cursor, limit).await
    }

    async fn list_page_with_prefix(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<SurfaceListPage> {
        anyhow::ensure!(
            (1..=1000).contains(&limit),
            "hybrid listing page limit is invalid"
        );
        let mut page_limit = limit;
        let result = loop {
            let plan = self.work.plan_for_placement(
                &self.placement,
                &self.binding,
                StorageWorkOperation::ListPage {
                    prefix: prefix.to_owned(),
                    cursor: cursor.map(str::to_owned),
                    limit: page_limit,
                },
                aos_hub_core::clock::now_unix_secs(),
            )?;
            match self.execute(&plan).await {
                Ok(result) => break result,
                Err(error)
                    if page_limit > 1
                        && error.downcast_ref::<StorageWorkResultTooLarge>().is_some() =>
                {
                    page_limit = page_limit.div_ceil(2);
                }
                Err(error) => return Err(error),
            }
        };
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
                    provider_version: object.provider_version,
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

    async fn inventory_head(
        &self,
        path: &str,
    ) -> Result<Option<aos_hub_core::fetch::SurfaceInventoryHead>> {
        self.head(path)
            .await?
            .map(|object| {
                anyhow::ensure!(
                    self.binding.kind != "deployment_r2"
                        || object
                            .provider_version
                            .as_deref()
                            .is_some_and(aos_hub_core::storage_work::valid_provider_version),
                    "R2 inventory HEAD has no valid provider upload version"
                );
                Ok(aos_hub_core::fetch::SurfaceInventoryHead {
                    size: i64::try_from(object.size).context("R2 object size exceeds i64")?,
                    strong_etag: Some(object.etag),
                    provider_version: object.provider_version,
                })
            })
            .transpose()
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
                    provider_version: object.provider_version,
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

    async fn recheck_copy_placements(
        &self,
        source: &SurfacePlacementRecord,
        destination: &SurfacePlacementRecord,
        binding: &BindingRecord,
    ) -> Result<()> {
        let current_source = self
            .db
            .surface_placement(source.id)
            .await?
            .context("hybrid copy source placement disappeared")?;
        let current_destination = self
            .db
            .surface_placement(destination.id)
            .await?
            .context("hybrid copy destination placement disappeared")?;
        let current_binding = self
            .db
            .binding(binding.id)
            .await?
            .context("hybrid copy binding disappeared")?;
        anyhow::ensure!(
            current_source.resource_version == source.resource_version
                && current_source.binding_id == binding.id
                && current_source.prefix == source.prefix
                && current_destination.resource_version == destination.resource_version
                && current_destination.binding_id == binding.id
                && current_destination.prefix == destination.prefix
                && current_binding.resource_version == binding.resource_version,
            "hybrid placement copy topology changed during storage work"
        );
        Ok(())
    }
}

#[async_trait]
impl SurfaceWriteProvider for HybridSurfaceWrites {
    async fn copy_placement_object(
        &self,
        source: &SurfacePlacementRecord,
        destination: &SurfacePlacementRecord,
        path: &str,
        listed_source: Option<&SurfaceListedEvidence>,
    ) -> Result<Option<u64>> {
        anyhow::ensure!(
            source.id != destination.id
                && source.binding_id == destination.binding_id
                && source.registry_id == destination.registry_id
                && source.cache_id == destination.cache_id,
            "hybrid placement copy crosses a surface, binding, or write fence"
        );
        let listed = listed_source.context("hybrid placement copy lacks source evidence")?;
        let expected_size = u64::try_from(listed.size)
            .context("hybrid placement copy source has a negative size")?;
        let expected_etag = aos_hub_core::surface_write::strong_if_match_etag(&listed.strong_etag)?;
        let binding = self
            .db
            .binding(destination.binding_id)
            .await?
            .context("hybrid placement copy binding disappeared")?;
        anyhow::ensure!(
            binding.kind == "deployment_r2" && binding.is_instance_default,
            "hybrid placement copy requires the deployment R2 binding"
        );
        let revision = self
            .db
            .placement_publication_write_revision(destination.id)
            .await?
            .context("hybrid placement copy destination lacks a validated writer")?;
        anyhow::ensure!(
            revision.binding_id == binding.id && revision.writes_supported,
            "hybrid placement copy destination write revision is invalid"
        );
        self.recheck_copy_placements(source, destination, &binding)
            .await?;

        let plan = self.work.plan_for_placement(
            destination,
            &binding,
            StorageWorkOperation::CopyObject {
                source_placement_id: source.id,
                source_placement_resource_version: source.resource_version,
                source_prefix: source.prefix.clone(),
                path: path.into(),
                expected_size,
                expected_etag,
            },
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let result = self.work.execute(&plan).await?;
        self.recheck_copy_placements(source, destination, &binding)
            .await?;
        let current_revision = self
            .db
            .placement_publication_write_revision(destination.id)
            .await?
            .context("hybrid placement copy destination writer disappeared")?;
        anyhow::ensure!(
            revision == current_revision,
            "hybrid placement copy destination writer changed"
        );
        anyhow::ensure!(
            matches!(result.outcome, StorageWorkOutcome::ObjectCopied { .. }),
            "storage Worker returned no placement copy evidence"
        );
        Ok(Some(expected_size))
    }

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
            provider_version: object.provider_version,
            sha256: digest,
            size: i64::try_from(object.size)?,
            strong_etag: Some(object.etag),
        }))
    }

    async fn placement_writer(
        &self,
        placement: &SurfacePlacementRecord,
    ) -> Result<Box<dyn SurfaceWrite>> {
        anyhow::ensure!(
            (placement.cache_id.is_some() || placement.registry_id.is_some())
                && placement.effective_write_enabled,
            "hybrid multipart placement is not writable"
        );
        let binding = self
            .db
            .binding(placement.binding_id)
            .await?
            .context("hybrid multipart binding is missing")?;
        anyhow::ensure!(
            binding.kind == "deployment_r2" && binding.is_instance_default,
            "hybrid multipart requires deployment R2"
        );
        Ok(Box::new(HybridR2MultipartWriter {
            placement: placement.clone(),
            binding,
            work: Arc::clone(&self.work),
        }))
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
        let persisted_revision = self
            .db
            .binding_write_revision(revision.binding_id, revision.revision)
            .await?
            .context("hybrid staging write revision is missing")?;
        anyhow::ensure!(
            &persisted_revision == revision && revision.writes_supported,
            "hybrid staging write revision changed or cannot write"
        );
        let binding = self
            .db
            .binding(placement.binding_id)
            .await?
            .context("hybrid staging binding is missing")?;
        if matches!(binding.kind.as_str(), "s3" | "r2") && !binding.is_instance_default {
            return Ok(Box::new(
                external_delete::ExternalProbeWriter::open(
                    Arc::clone(&self.db),
                    Arc::clone(&self.work),
                    placement,
                    &binding,
                    revision,
                )
                .await?,
            ));
        }
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
        placement: &SurfacePlacementRecord,
        expected_binding_resource_version: i64,
        delete_credential_generation: i64,
    ) -> Result<Box<dyn SurfaceWrite>> {
        let binding = self
            .db
            .binding(placement.binding_id)
            .await?
            .context("hybrid delete binding disappeared")?;
        if !binding.is_instance_default {
            return Ok(Box::new(
                external_delete::ExternalCurrentDeleter::open(
                    Arc::clone(&self.db),
                    Arc::clone(&self.work),
                    placement,
                    expected_binding_resource_version,
                    delete_credential_generation,
                )
                .await?,
            ));
        }
        anyhow::ensure!(
            delete_credential_generation == 1,
            "invalid deployment R2 delete generation"
        );
        let current = self
            .db
            .surface_placement(placement.id)
            .await?
            .context("hybrid deletion placement disappeared")?;
        anyhow::ensure!(
            current.binding_id == placement.binding_id
                && current.prefix == placement.prefix
                && current.resource_version == placement.resource_version,
            "hybrid deletion placement changed"
        );
        let binding = self
            .db
            .binding(placement.binding_id)
            .await?
            .context("hybrid deletion binding disappeared")?;
        anyhow::ensure!(
            binding.kind == "deployment_r2"
                && binding.is_instance_default
                && binding.resource_version == expected_binding_resource_version,
            "hybrid deletion binding changed or is unsupported"
        );
        Ok(Box::new(HybridR2MultipartWriter {
            placement: current,
            binding,
            work: Arc::clone(&self.work),
        }))
    }

    async fn frozen_placement_deleter(
        &self,
        access: &FrozenSurfaceAccess,
    ) -> Result<Box<dyn SurfaceWrite>> {
        Ok(Box::new(
            frozen::FrozenR2Surface::open(Arc::clone(&self.db), Arc::clone(&self.work), access)
                .await?,
        ))
    }

    async fn claimed_placement_deleter(
        &self,
        access: &FrozenSurfaceAccess,
        claim: &aos_hub_core::db::OciGcPlacementActionClaim,
    ) -> Result<Box<dyn SurfaceWrite>> {
        anyhow::ensure!(
            *access == claim.frozen_access(),
            "hybrid delete access differs from claim"
        );
        let binding = self
            .db
            .binding(access.binding_id)
            .await?
            .context("hybrid claimed delete binding disappeared")?;
        if binding.kind == "deployment_r2" {
            return self.frozen_placement_deleter(access).await;
        }
        Ok(Box::new(
            external_delete::ExternalClaimDeleter::open(
                Arc::clone(&self.db),
                Arc::clone(&self.work),
                access,
                claim,
            )
            .await?,
        ))
    }
}

struct HybridR2MultipartWriter {
    placement: SurfacePlacementRecord,
    binding: BindingRecord,
    work: Arc<RemoteStorageWorkClient>,
}

#[async_trait]
impl SurfaceWrite for HybridR2MultipartWriter {
    fn multipart_protocol_version(&self) -> Option<u32> {
        Some(1)
    }

    fn abandoned_multipart_lifetime_secs(&self) -> Option<u64> {
        Some(7 * 24 * 60 * 60)
    }

    fn expected_multipart_etag(&self, parts: &[PartTag]) -> Result<Option<String>> {
        aos_hub_core::surface_write::md5_multipart_etag(parts)
    }

    async fn write(&self, path: &str, bytes: &[u8]) -> Result<()> {
        if aos_hub_core::storage_work::admitted_narinfo_path(path) {
            return write_hybrid_metadata(&self.work, &self.placement, &self.binding, path, bytes)
                .await;
        }
        write_hybrid_probe(&self.work, &self.placement, &self.binding, path, bytes).await
    }

    async fn delete(&self, path: &str) -> Result<()> {
        delete_hybrid_probe(&self.work, &self.placement, &self.binding, path).await
    }

    async fn delete_if_matches(
        &self,
        path: &str,
        expected: &SurfaceDeletePrecondition,
    ) -> Result<SurfaceDeleteOutcome> {
        anyhow::ensure!(
            path.starts_with(".aos-internal/conditional-delete-probes/"),
            "hybrid deletion requires a durable claim"
        );
        let claim_id = uuid::Uuid::new_v4().simple().to_string();
        self.delete_if_matches_claimed(path, expected, &claim_id)
            .await
    }

    async fn delete_if_matches_claimed(
        &self,
        path: &str,
        expected: &SurfaceDeletePrecondition,
        claim_id: &str,
    ) -> Result<SurfaceDeleteOutcome> {
        let etag = expected
            .etag
            .as_ref()
            .context("hybrid deletion requires a strong ETag")?;
        let size = expected
            .size
            .context("hybrid deletion requires a reviewed size")?;
        let plan = self.work.plan_for_placement(
            &self.placement,
            &self.binding,
            StorageWorkOperation::DeleteIfMatches {
                path: path.into(),
                claim_id: claim_id.into(),
                expected_etag: etag.clone(),
                expected_size: u64::try_from(size)?,
                delete_binding_write_revision: None,
                expected_hash: expected.content_hash.clone(),
                expected_provider_version: expected.expected_provider_version.clone(),
            },
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let result = self.work.execute(&plan).await?;
        match result.outcome {
            StorageWorkOutcome::ObjectDeleted { etag } => {
                Ok(SurfaceDeleteOutcome::ConditionalDeleteAcknowledged { etag })
            }
            StorageWorkOutcome::NotFound => Ok(SurfaceDeleteOutcome::NotFound),
            StorageWorkOutcome::DeletePreconditionFailed => {
                Ok(SurfaceDeleteOutcome::PreconditionFailed {
                    detail: "R2 object identity changed".into(),
                })
            }
            _ => bail!("storage Worker returned an unexpected conditional deletion result"),
        }
    }

    async fn create_multipart(&self, path: &str) -> Result<String> {
        let plan = self.work.plan_for_placement(
            &self.placement,
            &self.binding,
            StorageWorkOperation::CreateMultipart { path: path.into() },
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let result = self.work.execute(&plan).await?;
        let StorageWorkOutcome::MultipartCreated { upload_id } = result.outcome else {
            bail!("storage Worker did not create the multipart upload");
        };
        Ok(upload_id)
    }

    async fn complete_multipart(
        &self,
        path: &str,
        upload_id: &str,
        parts: &[PartTag],
    ) -> Result<String> {
        let plan = self.work.plan_for_placement(
            &self.placement,
            &self.binding,
            StorageWorkOperation::CompleteMultipart {
                path: path.into(),
                upload_id: upload_id.into(),
                parts: parts.to_vec(),
            },
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let result = self.work.execute(&plan).await?;
        let StorageWorkOutcome::MultipartCompleted { object } = result.outcome else {
            bail!("storage Worker did not complete the multipart upload");
        };
        Ok(object.etag)
    }

    async fn abort_multipart(&self, path: &str, upload_id: &str) -> Result<MultipartAbortOutcome> {
        let plan = self.work.plan_for_placement(
            &self.placement,
            &self.binding,
            StorageWorkOperation::AbortMultipart {
                path: path.into(),
                upload_id: upload_id.into(),
            },
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let result = self.work.execute(&plan).await?;
        let StorageWorkOutcome::MultipartAborted { outcome } = result.outcome else {
            bail!("storage Worker did not abort the multipart upload");
        };
        Ok(outcome)
    }
}

struct HybridOciStagingWriter {
    placement: SurfacePlacementRecord,
    binding: BindingRecord,
    work: Arc<RemoteStorageWorkClient>,
}

#[async_trait]
impl SurfaceWrite for HybridOciStagingWriter {
    async fn write(&self, path: &str, bytes: &[u8]) -> Result<()> {
        write_hybrid_probe(&self.work, &self.placement, &self.binding, path, bytes).await
    }

    async fn delete(&self, path: &str) -> Result<()> {
        if path.starts_with(".aos-internal/conditional-delete-probes/") {
            return delete_hybrid_probe(&self.work, &self.placement, &self.binding, path).await;
        }
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

async fn write_hybrid_metadata(
    work: &RemoteStorageWorkClient,
    placement: &SurfacePlacementRecord,
    binding: &BindingRecord,
    path: &str,
    bytes: &[u8],
) -> Result<()> {
    anyhow::ensure!(
        bytes.len() <= aos_hub_core::storage_work::MAX_METADATA_BYTES,
        "hybrid metadata body is too large"
    );
    let plan = work.plan_for_placement(
        placement,
        binding,
        StorageWorkOperation::PutMetadata {
            path: path.into(),
            content_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
            sha256: hex::encode(sha2::Sha256::digest(bytes)),
        },
        aos_hub_core::clock::now_unix_secs(),
    )?;
    let result = work.execute(&plan).await?;
    anyhow::ensure!(
        matches!(result.outcome, StorageWorkOutcome::MetadataWritten),
        "storage Worker did not acknowledge metadata write"
    );
    Ok(())
}

async fn write_hybrid_probe(
    work: &RemoteStorageWorkClient,
    placement: &SurfacePlacementRecord,
    binding: &BindingRecord,
    path: &str,
    bytes: &[u8],
) -> Result<()> {
    anyhow::ensure!(bytes.len() <= 4 * 1024, "hybrid probe body is too large");
    let plan = work.plan_for_placement(
        placement,
        binding,
        StorageWorkOperation::PutProbe {
            path: path.into(),
            content_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
        },
        aos_hub_core::clock::now_unix_secs(),
    )?;
    let result = work.execute(&plan).await?;
    anyhow::ensure!(
        matches!(result.outcome, StorageWorkOutcome::ProbeAcknowledged),
        "storage Worker did not acknowledge probe write"
    );
    Ok(())
}

async fn delete_hybrid_probe(
    work: &RemoteStorageWorkClient,
    placement: &SurfacePlacementRecord,
    binding: &BindingRecord,
    path: &str,
) -> Result<()> {
    let plan = work.plan_for_placement(
        placement,
        binding,
        StorageWorkOperation::DeleteProbe { path: path.into() },
        aos_hub_core::clock::now_unix_secs(),
    )?;
    let result = work.execute(&plan).await?;
    anyhow::ensure!(
        matches!(result.outcome, StorageWorkOutcome::ProbeAcknowledged),
        "storage Worker did not acknowledge probe cleanup"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_hub_core::storage_work::{StorageCredentialReference, StorageObjectIdentity};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn retries_transient_read_work_without_replaying_mutations() {
        let issued_at = aos_hub_core::clock::now_unix_secs();
        let mut plan = StorageWorkPlan {
            version: 1,
            plan_id: "a".repeat(32),
            deployment_id: "deployment-1".into(),
            issued_at,
            expires_at: issued_at + 30,
            placement_id: 4,
            placement_resource_version: 2,
            binding_id: 3,
            binding_resource_version: 1,
            binding_kind: "deployment_r2".into(),
            binding_snapshot_revision: None,
            credential_references: Vec::new(),
            placement_prefix: "registry".into(),
            operation: StorageWorkOperation::Head {
                path: "object".into(),
            },
        };
        let result = StorageWorkResult {
            plan_id: plan.plan_id.clone(),
            placement_id: plan.placement_id,
            placement_resource_version: plan.placement_resource_version,
            binding_id: plan.binding_id,
            binding_resource_version: plan.binding_resource_version,
            source_bytes: 0,
            outcome: StorageWorkOutcome::NotFound,
        };
        let response_body = serde_json::to_vec(&result).unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let server_attempts = Arc::clone(&attempts);
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move || {
                let attempts = Arc::clone(&server_attempts);
                let response_body = response_body.clone();
                async move {
                    let attempt = attempts.fetch_add(1, Ordering::SeqCst) + 1;
                    if attempt % 2 == 1 {
                        (axum::http::StatusCode::INTERNAL_SERVER_ERROR, Vec::new())
                    } else {
                        (axum::http::StatusCode::OK, response_body)
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await });

        let mut client = RemoteStorageWorkClient::new(
            "https://worker.example",
            plan.deployment_id.clone(),
            b"hybrid-storage-test-key-with-thirty-two-bytes",
        )
        .unwrap();
        client.endpoint = format!("http://{address}/");
        assert!(client.execute(&plan).await.is_ok());
        assert_eq!(attempts.load(Ordering::SeqCst), 2);

        plan.operation = StorageWorkOperation::CreateMultipart {
            path: "object".into(),
        };
        assert!(client.execute(&plan).await.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        server.abort();
    }

    #[test]
    fn external_plan_names_only_the_acknowledged_snapshot_and_required_credential() {
        let client = RemoteStorageWorkClient::new(
            "https://worker.example",
            "deployment-1".into(),
            b"hybrid-storage-test-key-with-thirty-two-bytes",
        )
        .unwrap();
        let binding = BindingRecord {
            id: 7,
            kind: "s3".into(),
            stable_id: "external-7".into(),
            resource_version: 3,
            ..BindingRecord::default()
        };
        let placement = SurfacePlacementRecord {
            id: 11,
            registry_id: Some(1),
            cache_id: None,
            name: "primary".into(),
            binding_id: binding.id,
            prefix: "registry".into(),
            derived_role: "primary".into(),
            state: "active".into(),
            completeness: "complete".into(),
            hash_range_start: None,
            hash_range_end: None,
            mutable_publication_id: None,
            effective_read_enabled: true,
            effective_write_enabled: false,
            read_order: 0,
            created_at: 0,
            updated_at: 0,
            resource_version: 2,
            kind: "complete".into(),
            desired_state: "active".into(),
            desired_read_enabled: true,
            write_spec_version: 1,
            requires_conditional_writes: false,
            observed_at: None,
            observation_version: None,
            watermark_resource_version: None,
            watermark_pending_publication_id: None,
            write_authority_id: None,
            authority_desired_placement_id: None,
            authority_observed_placement_id: None,
            authority_desired_write_spec_version: None,
            authority_observed_write_spec_version: None,
            authority_desired_binding_write_revision: None,
            authority_observed_binding_write_revision: None,
            authority_desired_generation: None,
            authority_observed_generation: None,
            authority_reconciliation_state: None,
        };
        let snapshot = StorageBindingSnapshot {
            version: 1,
            deployment_id: "deployment-1".into(),
            binding_id: binding.id,
            binding_resource_version: binding.resource_version,
            binding_stable_id: binding.stable_id.clone(),
            binding_kind: binding.kind.clone(),
            object_bucket: "bucket".into(),
            object_prefix: "tenant".into(),
            endpoint_scheme: "https".into(),
            endpoint_host_kind: "dns".into(),
            endpoint_host_bytes: b"s3.example.test".to_vec(),
            endpoint_port: Some(443),
            signing_region: "us-west-1".into(),
            access_mode: "private".into(),
            credentials: vec![StorageCredentialReference {
                purpose: "read".into(),
                generation: 2,
                secret_version_ref: "secret://test/binding/read/v2".into(),
                fingerprint: "a".repeat(64),
            }],
            issued_at: 100,
            expires_at: 200,
        };
        let operation = || StorageWorkOperation::Head {
            path: "object".into(),
        };
        assert!(client
            .plan_for_placement(&placement, &binding, operation(), 101)
            .is_err());

        client
            .published_bindings
            .write()
            .unwrap()
            .insert(binding.id, snapshot.clone());
        let plan = client
            .plan_for_placement(&placement, &binding, operation(), 101)
            .unwrap();
        assert_eq!(
            plan.binding_snapshot_revision,
            Some(snapshot.revision().unwrap())
        );
        assert_eq!(
            plan.credential_references,
            vec![StorageCredentialSelector {
                purpose: "read".into(),
                generation: 2,
            }]
        );
        assert!(client
            .plan_for_placement(
                &placement,
                &binding,
                StorageWorkOperation::ListPage {
                    prefix: "".into(),
                    cursor: None,
                    limit: 1,
                },
                101,
            )
            .is_err());
        assert!(client
            .plan_for_placement(&placement, &binding, operation(), 201)
            .is_err());
    }

    #[test]
    fn completed_external_work_rechecks_sql_credentials_and_binding_coordinates() {
        let client = RemoteStorageWorkClient::new(
            "https://worker.example",
            "deployment-1".into(),
            b"hybrid-storage-test-key-with-thirty-two-bytes",
        )
        .unwrap();
        let binding = BindingRecord {
            id: 7,
            kind: "s3".into(),
            stable_id: "external-7".into(),
            object_bucket: Some("bucket".into()),
            object_prefix: Some("tenant".into()),
            endpoint_scheme: Some("https".into()),
            endpoint_host_kind: Some("dns".into()),
            endpoint_host_bytes: Some(b"s3.example.test".to_vec()),
            endpoint_port: Some(443),
            signing_region: Some("us-west-1".into()),
            access_mode: Some("private".into()),
            resource_version: 3,
            ..BindingRecord::default()
        };
        let credential = BindingCredentialRevisionRecord {
            binding_id: binding.id,
            purpose: "read".into(),
            generation: 2,
            secret_version_ref: "secret://test/binding/read/v2".into(),
            validation_state: "valid".into(),
            validated_at: Some(100),
            validation_error: None,
            credential_fingerprint: "a".repeat(64),
            created_by: "fleet".into(),
            created_at: 100,
            head_resource_version: 2,
        };
        let snapshot = StorageBindingSnapshot::from_binding(
            "deployment-1".into(),
            &binding,
            &[credential.clone()],
            100,
            200,
        )
        .unwrap();
        let revision = snapshot.revision().unwrap();
        client
            .published_bindings
            .write()
            .unwrap()
            .insert(binding.id, snapshot);

        assert!(client
            .validate_published_binding_snapshot(&binding, &[credential.clone()], &revision)
            .is_ok());
        let mut rotated = credential.clone();
        rotated.generation += 1;
        assert!(client
            .validate_published_binding_snapshot(&binding, &[rotated], &revision)
            .is_err());
        let mut moved = binding.clone();
        moved.object_prefix = Some("other-tenant".into());
        assert!(client
            .validate_published_binding_snapshot(&moved, &[credential], &revision)
            .is_err());
    }

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
            binding_snapshot_revision: None,
            credential_references: Vec::new(),
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
                    provider_version: None,
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
            r2_gc_incarnation_v1: true,
            version: 1,
            deployment_id: "deployment-1".into(),
            binding_kind: "deployment_r2".into(),
            console_asset_version: Some(aos_hub_core::web::assets::asset_version().into()),
            operations: vec![
                "head".into(),
                "list_page".into(),
                "inspect_sha256".into(),
                "inspect_git_object".into(),
                "inspect_git_objects".into(),
                "filter_git_tree_entries_v1".into(),
                "inspect_metadata".into(),
                "inspect_metadata_objects".into(),
                "inspect_documentation".into(),
                "inspect_documentation_content".into(),
                "inspect_oci_range".into(),
                "hash_oci_range".into(),
                "copy_object".into(),
                "compose_oci_blob".into(),
                "stage_oci_manifest".into(),
                "delete_oci_staging".into(),
                "delete_if_matches".into(),
                "put_metadata".into(),
                "put_probe".into(),
                "delete_probe".into(),
                "create_multipart".into(),
                "complete_multipart".into(),
                "abort_multipart".into(),
                "credential_probe".into(),
            ],
            max_result_bytes: MAX_RESULT_BYTES,
            max_verify_source_bytes: MAX_VERIFY_SOURCE_BYTES,
        };
        assert!(validate_capabilities("deployment-1", &capabilities).is_ok());
        assert!(validate_console_asset_version(&capabilities).is_ok());

        let mut another_bundle = capabilities.clone();
        another_bundle.console_asset_version = Some("another-bundle".into());
        assert!(validate_capabilities("deployment-1", &another_bundle).is_ok());
        assert!(validate_console_asset_version(&another_bundle).is_err());

        let mut storage_only = capabilities.clone();
        storage_only.console_asset_version = None;
        let encoded = serde_json::to_vec(&storage_only).unwrap();
        let decoded: StorageCapabilities = serde_json::from_slice(&encoded).unwrap();
        assert!(validate_capabilities("deployment-1", &decoded).is_ok());
        assert!(validate_console_asset_version(&decoded).is_err());

        assert!(validate_capabilities("deployment-2", &capabilities).is_err());
        let mut without_incarnation_guard = capabilities.clone();
        without_incarnation_guard.r2_gc_incarnation_v1 = false;
        assert!(validate_capabilities("deployment-1", &without_incarnation_guard).is_err());
        let mut older = capabilities.clone();
        older
            .operations
            .retain(|operation| operation != "inspect_metadata_objects");
        assert!(validate_capabilities("deployment-1", &older).is_err());
        let mut without_manifest_staging = capabilities.clone();
        without_manifest_staging
            .operations
            .retain(|operation| operation != "stage_oci_manifest");
        assert!(validate_capabilities("deployment-1", &without_manifest_staging).is_err());
        let mut without_tree_projection = capabilities.clone();
        without_tree_projection
            .operations
            .retain(|operation| operation != "filter_git_tree_entries_v1");
        assert!(validate_capabilities("deployment-1", &without_tree_projection).is_err());
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
            binding_snapshot_revision: None,
            credential_references: Vec::new(),
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
            binding_snapshot_revision: None,
            credential_references: Vec::new(),
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
                    provider_version: None,
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
    fn placement_copy_result_requires_the_frozen_source_and_destination() {
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
            binding_snapshot_revision: None,
            credential_references: Vec::new(),
            placement_prefix: "registry/".into(),
            operation: StorageWorkOperation::CopyObject {
                source_placement_id: 5,
                source_placement_resource_version: 2,
                source_prefix: "source/".into(),
                path: "web/blob".into(),
                expected_size: 8,
                expected_etag: "\"source-etag\"".into(),
            },
        };
        let mut result = StorageWorkResult {
            plan_id: plan.plan_id.clone(),
            placement_id: plan.placement_id,
            placement_resource_version: plan.placement_resource_version,
            binding_id: plan.binding_id,
            binding_resource_version: plan.binding_resource_version,
            source_bytes: 8,
            outcome: StorageWorkOutcome::ObjectCopied {
                source: StorageObjectIdentity {
                    provider_version: None,
                    key: "source/web/blob".into(),
                    size: 8,
                    etag: "\"source-etag\"".into(),
                },
                destination: StorageObjectIdentity {
                    provider_version: None,
                    key: "registry/web/blob".into(),
                    size: 8,
                    etag: "\"destination-etag\"".into(),
                },
            },
        };
        assert!(validate_result(&plan, &result).is_ok());

        if let StorageWorkOutcome::ObjectCopied { source, .. } = &mut result.outcome {
            source.etag = "\"another-source\"".into();
        }
        assert!(validate_result(&plan, &result).is_err());

        if let StorageWorkOutcome::ObjectCopied {
            source,
            destination,
        } = &mut result.outcome
        {
            source.etag = "\"source-etag\"".into();
            destination.key = "another/web/blob".into();
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
            binding_snapshot_revision: None,
            credential_references: Vec::new(),
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
                    provider_version: None,
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
            binding_snapshot_revision: None,
            credential_references: Vec::new(),
            placement_prefix: "registry/".into(),
            operation: StorageWorkOperation::InspectGitObjects {
                oids: oids.iter().map(|(oid, _)| oid.clone()).collect(),
            },
        };
        let objects = oids
            .iter()
            .map(|(oid, bytes)| StorageGitObjectProjection {
                source: StorageObjectIdentity {
                    provider_version: None,
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
            binding_snapshot_revision: None,
            credential_references: Vec::new(),
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
                    provider_version: None,
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
            binding_snapshot_revision: None,
            credential_references: Vec::new(),
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
                    provider_version: None,
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

    #[test]
    fn oci_inventory_hash_result_requires_the_frozen_range_and_etag() {
        let path = format!("oci/blobs/sha256/{}", "a".repeat(64));
        let mut next_state = aos_hub_core::db::OciSha256State::initial();
        next_state.update(b"abc").unwrap();
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
            binding_snapshot_revision: None,
            credential_references: Vec::new(),
            placement_prefix: "registry/".into(),
            operation: StorageWorkOperation::HashOciRange {
                expected_provider_version: Some("upload-v1".into()),
                path: path.clone(),
                start: 0,
                end: 2,
                total: 3,
                strong_etag: "\"strong-etag\"".into(),
                sha256_state: aos_hub_core::db::OciSha256State::initial(),
            },
        };
        let mut result = StorageWorkResult {
            plan_id: plan.plan_id.clone(),
            placement_id: plan.placement_id,
            placement_resource_version: plan.placement_resource_version,
            binding_id: plan.binding_id,
            binding_resource_version: plan.binding_resource_version,
            source_bytes: 3,
            outcome: StorageWorkOutcome::OciRangeHashed {
                source: StorageObjectIdentity {
                    provider_version: Some("upload-v1".into()),
                    key: format!("registry/{path}"),
                    size: 3,
                    etag: "\"strong-etag\"".into(),
                },
                start: 0,
                end: 2,
                sha256_state: next_state,
            },
        };
        assert!(validate_result(&plan, &result).is_ok());
        if let StorageWorkOutcome::OciRangeHashed { source, .. } = &mut result.outcome {
            source.provider_version = Some("upload-v2".into());
        }
        assert!(validate_result(&plan, &result).is_err());
        if let StorageWorkOutcome::OciRangeHashed { source, .. } = &mut result.outcome {
            source.provider_version = Some("upload-v1".into());
        }
        if let StorageWorkOutcome::OciRangeHashed { source, .. } = &mut result.outcome {
            source.etag = "\"another-etag\"".into();
        }
        assert!(validate_result(&plan, &result).is_err());
    }
}
