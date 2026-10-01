//! Metadata-only external conditional deletion under current or frozen SQL scope.

use std::sync::Arc;

use anyhow::{bail, Context as _, Result};
use aos_hub_core::{
    db::{BindingRecord, Database, OciGcPlacementActionClaim, SurfacePlacementRecord},
    storage_authority::external_object::ExternalObjectOutcome,
    storage_work::{
        binding_custody::*, StorageFrozenCleanupOperation, StorageWorkOperation,
        StorageWorkOutcome, STORAGE_WORK_SIGNATURE_HEADER,
    },
    surface_write::{
        FrozenSurfaceAccess, SurfaceDeleteOutcome, SurfaceDeletePrecondition, SurfaceWrite,
    },
};
use async_trait::async_trait;

use super::{read_bounded_response, RemoteStorageWorkClient};

pub(super) struct ExternalCurrentDeleter {
    db: Arc<Database>,
    work: Arc<RemoteStorageWorkClient>,
    placement: SurfacePlacementRecord,
    binding: BindingRecord,
    delete_generation: i64,
    binding_write_revision: i64,
}

impl ExternalCurrentDeleter {
    /// Opens a deleter for the current validated SQL delete credential.
    ///
    /// # Errors
    /// Returns an error if the binding, placement, revision, or credential changes
    /// while the protected Worker snapshot is checked.
    pub(super) async fn open(
        db: Arc<Database>,
        work: Arc<RemoteStorageWorkClient>,
        placement: &SurfacePlacementRecord,
        binding_resource_version: i64,
        delete_generation: i64,
    ) -> Result<Self> {
        let binding = db
            .binding(placement.binding_id)
            .await?
            .context("external delete binding absent")?;
        anyhow::ensure!(
            !binding.is_instance_default
                && matches!(binding.kind.as_str(), "s3" | "r2")
                && binding.resource_version == binding_resource_version,
            "external delete binding changed"
        );
        let state = db
            .binding_write_state(binding.id)
            .await?
            .context("external delete write state absent")?;
        let binding_write_revision = state
            .current_write_revision
            .context("external delete immutable revision absent")?;
        let surface = Self {
            db,
            work,
            placement: placement.clone(),
            binding,
            delete_generation,
            binding_write_revision,
        };
        surface.recheck().await?;
        surface
            .work
            .ensure_remote_binding_snapshot(&surface.db, &surface.binding)
            .await?;
        surface.recheck().await?;
        Ok(surface)
    }

    async fn recheck(&self) -> Result<()> {
        let placement = self
            .db
            .surface_placement(self.placement.id)
            .await?
            .context("external delete placement absent")?;
        let binding = self
            .db
            .binding(self.binding.id)
            .await?
            .context("external delete binding absent")?;
        let credential = self
            .db
            .current_binding_credential(binding.id, "delete")
            .await?
            .context("external delete credential absent")?;
        let state = self
            .db
            .binding_write_state(binding.id)
            .await?
            .context("external delete write state absent")?;
        anyhow::ensure!(
            placement.resource_version == self.placement.resource_version
                && placement.binding_id == self.binding.id
                && placement.prefix == self.placement.prefix
                && binding.resource_version == self.binding.resource_version
                && credential.generation == self.delete_generation
                && credential.validation_state == "valid"
                && state.current_write_revision == Some(self.binding_write_revision),
            "external delete SQL authority changed"
        );
        Ok(())
    }
}

#[async_trait]
impl SurfaceWrite for ExternalCurrentDeleter {
    fn conditional_delete_requires_provider_version(&self) -> bool {
        true
    }

    async fn write(&self, _path: &str, _bytes: &[u8]) -> Result<()> {
        bail!("external deleter does not authorize writes")
    }

    async fn delete(&self, _path: &str) -> Result<()> {
        bail!("external deletion requires an exact conditional claim")
    }

    async fn delete_if_matches(
        &self,
        path: &str,
        expected: &SurfaceDeletePrecondition,
    ) -> Result<SurfaceDeleteOutcome> {
        self.delete_if_matches_claimed(path, expected, &uuid::Uuid::new_v4().simple().to_string())
            .await
    }

    async fn delete_if_matches_claimed(
        &self,
        path: &str,
        expected: &SurfaceDeletePrecondition,
        claim_id: &str,
    ) -> Result<SurfaceDeleteOutcome> {
        self.recheck().await?;
        let expected = versioned_precondition(expected)?;
        let plan = self.work.plan_for_placement(
            &self.placement,
            &self.binding,
            StorageWorkOperation::DeleteIfMatches {
                path: path.into(),
                claim_id: claim_id.into(),
                expected_etag: expected.etag,
                expected_size: expected.bytes.parse()?,
                expected_hash: expected.content_hash,
                expected_provider_version: Some(expected.provider_version),
                delete_binding_write_revision: Some(self.binding_write_revision),
            },
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let result = self.work.execute(&plan).await?;
        self.recheck().await?;
        match result.outcome {
            StorageWorkOutcome::ObjectDeleted { etag } => {
                Ok(SurfaceDeleteOutcome::ConditionalDeleteAcknowledged { etag })
            }
            StorageWorkOutcome::NotFound => Ok(SurfaceDeleteOutcome::NotFound),
            StorageWorkOutcome::DeletePreconditionFailed => {
                Ok(SurfaceDeleteOutcome::PreconditionFailed {
                    detail: "external provider incarnation changed".into(),
                })
            }
            _ => bail!("external conditional delete returned another effect"),
        }
    }
}

/// Requires an exact physical version, strong ETag, and reviewed length.
///
/// # Errors
/// Returns an error for missing, malformed, or oversized inventory evidence.
pub(super) fn versioned_precondition(
    expected: &SurfaceDeletePrecondition,
) -> Result<aos_hub_core::storage_authority::external_object::deletion::ExternalDeletePrecondition>
{
    let value =
        aos_hub_core::storage_authority::external_object::deletion::ExternalDeletePrecondition {
            provider_version: expected
                .expected_provider_version
                .clone()
                .context("external deletion needs an actual provider version")?,
            etag: expected
                .etag
                .clone()
                .context("external deletion needs a strong ETag")?,
            bytes: u64::try_from(
                expected
                    .size
                    .context("external deletion needs reviewed size")?,
            )?
            .to_string(),
            content_hash: expected.content_hash.clone(),
        };
    value.validate()?;
    Ok(value)
}

pub(super) struct ExternalClaimDeleter {
    db: Arc<Database>,
    work: Arc<RemoteStorageWorkClient>,
    claim: OciGcPlacementActionClaim,
}

impl ExternalClaimDeleter {
    /// Opens a deleter for one exact retained SQL cleanup claim.
    ///
    /// # Errors
    /// Returns an error when access differs from the claim or its credential hold
    /// and protected snapshot no longer authorize frozen cleanup.
    pub(super) async fn open(
        db: Arc<Database>,
        work: Arc<RemoteStorageWorkClient>,
        access: &FrozenSurfaceAccess,
        claim: &OciGcPlacementActionClaim,
    ) -> Result<Self> {
        access.validate()?;
        anyhow::ensure!(
            *access == claim.frozen_access(),
            "external delete access differs from SQL claim"
        );
        work.frozen_cleanup_request(&db, claim).await?;
        Ok(Self {
            db,
            work,
            claim: claim.clone(),
        })
    }
}

#[async_trait]
impl SurfaceWrite for ExternalClaimDeleter {
    fn conditional_delete_requires_provider_version(&self) -> bool {
        true
    }

    async fn write(&self, _path: &str, _bytes: &[u8]) -> Result<()> {
        bail!("frozen external deletion does not authorize writes")
    }

    async fn delete(&self, _path: &str) -> Result<()> {
        bail!("frozen external deletion requires original preconditions")
    }

    async fn delete_if_matches_claimed(
        &self,
        path: &str,
        expected: &SurfaceDeletePrecondition,
        claim_id: &str,
    ) -> Result<SurfaceDeleteOutcome> {
        let expected = versioned_precondition(expected)?;
        anyhow::ensure!(
            path == self.claim.object_key
                && claim_id == self.claim.action_id
                && Some(&expected.provider_version)
                    == self.claim.expected_provider_version.as_ref()
                && Some(&expected.etag) == self.claim.expected_strong_etag.as_ref()
                && expected.bytes == self.claim.expected_size.to_string()
                && expected.content_hash.as_deref()
                    == Some(self.claim.expected_hash.to_string().as_str()),
            "frozen external deletion differs from reviewed claim"
        );
        self.work.frozen_cleanup_delete(&self.db, &self.claim).await
    }
}

impl RemoteStorageWorkClient {
    async fn frozen_cleanup_delete(
        &self,
        db: &Database,
        claim: &OciGcPlacementActionClaim,
    ) -> Result<SurfaceDeleteOutcome> {
        let _permit = self
            .in_flight
            .acquire()
            .await
            .context("storage Worker concurrency gate closed")?;
        let mut original = self.frozen_cleanup_request(db, claim).await?;
        original.operation = StorageFrozenCleanupOperation::DeleteIfMatches;
        let request = StorageFrozenDeleteCustodyRequest {
            claim: original,
            expected_provider_version: claim
                .expected_provider_version
                .clone()
                .context("frozen external delete lacks provider incarnation")?,
        };
        let signed = sign_storage_frozen_delete_custody(&self.key, &request)?;
        let mut endpoint = url::Url::parse(&self.endpoint)?;
        endpoint.set_path(STORAGE_FROZEN_DELETE_CUSTODY_PATH);
        let response = self
            .semantic_observation_http
            .post(endpoint)
            .header(STORAGE_WORK_SIGNATURE_HEADER, signed.signature)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(signed.body)
            .send()
            .await?;
        anyhow::ensure!(
            response.status() == reqwest::StatusCode::OK,
            "frozen external deletion refused"
        );
        let signature = response
            .headers()
            .get(STORAGE_WORK_SIGNATURE_HEADER)
            .context("frozen delete reply MAC absent")?
            .to_str()?
            .to_owned();
        let body = read_bounded_response(response, MAX_BINDING_CUSTODY_BYTES).await?;
        let now = aos_hub_core::clock::now_unix_secs();
        let reply = verify_storage_frozen_delete_custody_reply(
            &self.key, &signature, &body, &request, now,
        )?;
        let current = db
            .active_oci_gc_placement_action_claim(&claim.action_id, &claim.claim_token, now)
            .await?
            .context("frozen delete claim expired")?;
        anyhow::ensure!(current == *claim, "frozen delete SQL claim changed");
        self.check_frozen_snapshot(db, &request.claim).await?;
        match reply.outcome {
            ExternalObjectOutcome::DeleteAcknowledged { etag, .. } => {
                Ok(SurfaceDeleteOutcome::ConditionalDeleteAcknowledged { etag })
            }
            ExternalObjectOutcome::DeleteAbsent => Ok(SurfaceDeleteOutcome::NotFound),
            ExternalObjectOutcome::DeletePreconditionFailed => {
                Ok(SurfaceDeleteOutcome::PreconditionFailed {
                    detail: "external provider incarnation changed".into(),
                })
            }
            _ => bail!("frozen external delete returned another operation"),
        }
    }
}

/// Limits capability discovery to the existing reserved, four-KiB probe.
pub(super) struct ExternalProbeWriter {
    db: Arc<Database>,
    work: Arc<RemoteStorageWorkClient>,
    placement: SurfacePlacementRecord,
    binding: BindingRecord,
    revision: aos_hub_core::db::BindingWriteRevisionRecord,
}

impl ExternalProbeWriter {
    /// Opens a writer restricted to the retained reserved capability probe.
    ///
    /// # Errors
    /// Returns an error if the original placement, binding, or current immutable
    /// write revision changes while the protected snapshot is checked.
    pub(super) async fn open(
        db: Arc<Database>,
        work: Arc<RemoteStorageWorkClient>,
        placement: &SurfacePlacementRecord,
        binding: &BindingRecord,
        revision: &aos_hub_core::db::BindingWriteRevisionRecord,
    ) -> Result<Self> {
        let writer = Self {
            db,
            work,
            placement: placement.clone(),
            binding: binding.clone(),
            revision: revision.clone(),
        };
        writer.recheck().await?;
        writer
            .work
            .ensure_remote_binding_snapshot(&writer.db, &writer.binding)
            .await?;
        writer.recheck().await?;
        Ok(writer)
    }

    async fn recheck(&self) -> Result<()> {
        let placement = self
            .db
            .surface_placement(self.placement.id)
            .await?
            .context("external probe placement absent")?;
        let binding = self
            .db
            .binding(self.binding.id)
            .await?
            .context("external probe binding absent")?;
        let revision = self
            .db
            .binding_write_revision(self.binding.id, self.revision.revision)
            .await?
            .context("external probe revision absent")?;
        let state = self
            .db
            .binding_write_state(self.binding.id)
            .await?
            .context("external probe write state absent")?;
        anyhow::ensure!(
            placement.resource_version == self.placement.resource_version
                && placement.binding_id == binding.id
                && placement.prefix == self.placement.prefix
                && binding.resource_version == self.binding.resource_version
                && revision == self.revision
                && revision.writes_supported
                && state.current_write_revision == Some(revision.revision),
            "external probe SQL authority changed"
        );
        Ok(())
    }
}

#[async_trait]
impl SurfaceWrite for ExternalProbeWriter {
    async fn write(&self, path: &str, bytes: &[u8]) -> Result<()> {
        anyhow::ensure!(
            aos_hub_core::storage_work::admitted_probe_path(path) && bytes.len() <= 4096,
            "external probe writer refuses ordinary objects or oversized bodies"
        );
        self.recheck().await?;
        super::write_hybrid_probe(&self.work, &self.placement, &self.binding, path, bytes).await?;
        self.recheck().await
    }

    async fn delete(&self, path: &str) -> Result<()> {
        anyhow::ensure!(
            aos_hub_core::storage_work::admitted_probe_path(path),
            "external probe cleanup refuses ordinary objects"
        );
        self.recheck().await?;
        let fetch = super::HybridSurfaceFetch {
            db: Arc::clone(&self.db),
            placement: self.placement.clone(),
            binding: self.binding.clone(),
            work: Arc::clone(&self.work),
        };
        let Some(object) = fetch.head(path).await? else {
            return Ok(());
        };
        anyhow::ensure!(
            object.size <= 4096,
            "external probe cleanup size exceeds its bound"
        );
        let credential = self
            .db
            .current_binding_credential(self.binding.id, "delete")
            .await?
            .context("external probe delete credential absent")?;
        let deleter = ExternalCurrentDeleter::open(
            Arc::clone(&self.db),
            Arc::clone(&self.work),
            &self.placement,
            self.binding.resource_version,
            credential.generation,
        )
        .await?;
        let expected = SurfaceDeletePrecondition {
            etag: Some(object.etag),
            content_hash: None,
            size: Some(i64::try_from(object.size)?),
            expected_provider_version: object.provider_version,
        };
        match deleter.delete_if_matches(path, &expected).await? {
            SurfaceDeleteOutcome::ConditionalDeleteAcknowledged { .. }
            | SurfaceDeleteOutcome::NotFound => self.recheck().await,
            SurfaceDeleteOutcome::PreconditionFailed { .. } => {
                bail!("external probe cleanup incarnation changed")
            }
            SurfaceDeleteOutcome::Deleted { .. } => {
                bail!("external probe cleanup lacks conditional provider acknowledgement")
            }
        }
    }
}
