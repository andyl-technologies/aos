//! Accounting for storage-verified direct OCI sources without fabricated hash state.

use super::*;
use crate::direct_upload::{
    DirectActorKind, DirectActorSlot, DirectSessionState, DirectUploadAdmission, DirectUploadTarget,
};

impl Database {
    /// Builds quota release after independent direct abort settlement, including overdue uploads.
    ///
    /// The caller must atomically retain the matching positive abort receipt.
    ///
    /// # Errors
    /// Returns an error for changed upload ownership or non-active streaming state.
    pub fn abort_direct_oci_upload_statements(
        upload: &OciUploadRecord,
        now: i64,
    ) -> Result<Vec<CheckedStatement>> {
        if upload.state != "active" || upload.uploaded_size != 0 || upload.sha256.total_bytes != 0 {
            bail!("direct OCI abort original state differs");
        }
        Ok(release_upload_statements(
            &upload.id,
            Some(&upload.writer_id),
            Some(&upload.token_id),
            Some(upload.resource_version),
            now,
            "cancelled",
            false,
            false,
            true,
        ))
    }

    // Direct source scalars are trusted only alongside the exact independently
    // guarded terminal receipt. A cold database cannot substitute streaming state.
    pub(super) async fn validate_direct_oci_source(&self, upload: &OciUploadRecord) -> Result<()> {
        let (Some(digest), Some(bytes)) = (
            upload.authenticated_source_sha256,
            upload.authenticated_source_bytes,
        ) else {
            if upload.authenticated_source_sha256.is_some()
                || upload.authenticated_source_bytes.is_some()
            {
                bail!("partial authenticated OCI source");
            }
            return Ok(());
        };
        if upload.state != "complete"
            || upload.uploaded_size != 0
            || upload.sha256.total_bytes != 0
            || upload.expected_digest != Some(digest)
            || upload.final_digest != Some(digest)
            || upload.expected_size != Some(bytes)
        {
            bail!("authenticated OCI source differs from terminal upload");
        }
        let rows = self
            .backend
            .query(
                "SELECT deployment_id, session_id FROM direct_upload_sessions
             WHERE oci_upload_id = ?1 AND target_kind = 'oci_blob' AND state = 'committed'
               AND source_sha256 = ?2 AND declared_size = ?3",
                &vals![
                    upload.id,
                    digest.encoded(),
                    checked_u64(bytes, "direct OCI size")?
                ],
            )
            .await?;
        if rows.len() != 1 {
            bail!("authenticated OCI source has no unique committed direct receipt");
        }
        let session = self
            .direct_upload_session(&rows[0].get::<String>(0)?, &rows[0].get::<String>(1)?)
            .await?
            .context("authenticated OCI source original absent")?;
        let receipt = session
            .completion_evidence
            .as_ref()
            .context("authenticated OCI final receipt absent")?;
        if session.state != DirectSessionState::Committed
            || session.admission.principal_id != upload.writer_id
            || upload.writer_id != upload.token_id
            || !matches!(&session.admission.intent.target, DirectUploadTarget::OciBlob { upload_id } if upload_id == &upload.id)
            || receipt.sha256 != digest.encoded()
            || receipt.byte_size.get() != bytes
            || receipt.placements.len() != 1
            || session.final_guards.len() != 1
            || upload.materialization_placement_id
                != Some(i64::try_from(receipt.placements[0].placement_id.get())?)
            || upload.materialization_binding_id
                != Some(i64::try_from(receipt.placements[0].binding_id.get())?)
        {
            bail!("authenticated OCI source receipt provenance differs");
        }
        Ok(())
    }

    /// Resolves an original bodyless allocation for its exact authenticated actor.
    ///
    /// # Errors
    /// Returns an error for absent originals, changed owner or retained upload drift.
    pub async fn direct_oci_upload_for_actor(
        &self,
        deployment: &str,
        actor: &DirectActorSlot,
        upload_id: &str,
        now: i64,
    ) -> Result<OciUploadRecord> {
        self.direct_oci_upload_original(deployment, actor, upload_id, Some(now))
            .await
    }

    /// Resolves retained ownership for status and independently settled abort recovery.
    ///
    /// This lookup does not renew the upload horizon or authorize storage effects.
    ///
    /// # Errors
    /// Returns an error for absent originals, changed owner or retained upload drift.
    pub async fn direct_oci_upload_for_actor_recovery(
        &self,
        deployment: &str,
        actor: &DirectActorSlot,
        upload_id: &str,
    ) -> Result<OciUploadRecord> {
        self.direct_oci_upload_original(deployment, actor, upload_id, None)
            .await
    }

    async fn direct_oci_upload_original(
        &self,
        deployment: &str,
        actor: &DirectActorSlot,
        upload_id: &str,
        admission_now: Option<i64>,
    ) -> Result<OciUploadRecord> {
        let principal = actor.principal_id(deployment)?;
        let kind = match actor.kind {
            DirectActorKind::User => "user",
            DirectActorKind::ServiceAccount => "service_account",
        };
        let row = self
            .backend
            .query_opt(
                "SELECT allocation.registry_id, allocation.repository_id,
                allocation.registry_stable_id, allocation.repository_name,
                allocation.source_sha256, allocation.declared_size
             FROM direct_oci_allocations allocation
             JOIN registries registry ON registry.id = allocation.registry_id
               AND registry.stable_id = allocation.registry_stable_id
             JOIN oci_repositories repository ON repository.id = allocation.repository_id
               AND repository.registry_id = registry.id
               AND repository.name = allocation.repository_name
             WHERE allocation.deployment_id = ?1 AND allocation.principal_id = ?2
               AND allocation.actor_kind = ?3 AND allocation.actor_id = ?4
               AND allocation.actor_incarnation = ?5 AND allocation.upload_id = ?6
               AND repository.lifecycle_state = 'active'",
                &vals![
                    deployment,
                    principal,
                    kind,
                    i64::try_from(actor.numeric_id.get())?,
                    actor.incarnation,
                    upload_id
                ],
            )
            .await?
            .context("original direct OCI allocation unavailable")?;
        let upload = self
            .backend
            .query_opt(
                &format!(
                    "SELECT {OCI_UPLOAD_COLUMNS} FROM oci_upload_sessions
                WHERE id = ?1 AND writer_id = ?2 AND token_id = ?2"
                ),
                &vals![upload_id, principal],
            )
            .await?
            .context("retained direct OCI upload unavailable")?;
        let upload = row_to_oci_upload(&upload)?;
        self.validate_direct_oci_source(&upload).await?;
        if admission_now.is_some_and(|now| upload.state == "active" && upload.expires_at <= now) {
            bail!("direct OCI allocation expired");
        }
        if upload.registry_id != row.get::<i64>(0)?
            || upload.repository_id != row.get::<i64>(1)?
            || upload.expected_digest.map(|digest| digest.encoded()) != Some(row.get::<String>(4)?)
            || upload.expected_size != Some(parse_size(row.get(5)?)?)
            || upload.publication_id.is_some()
        {
            bail!("direct OCI allocation differs from original upload");
        }
        Ok(upload)
    }

    /// Reserves the full declared direct source length before provider staging.
    ///
    /// Exact retries reuse the same reservation. Native streaming progress and
    /// resumable SHA-256 state remain unchanged.
    ///
    /// # Errors
    /// Returns an error for stale upload state, missing allocation, quota or persistence.
    pub async fn reserve_direct_oci_source(
        &self,
        upload: &OciUploadRecord,
        now: i64,
    ) -> Result<()> {
        let size = checked_u64(
            upload.expected_size.context("direct OCI size absent")?,
            "direct OCI size",
        )?;
        let row = self
            .backend
            .query_opt(
                "SELECT reserved_bytes FROM oci_quota_reservations
             WHERE id = ?1 AND state = 'reserved'",
                &vals![upload.quota_reservation_id],
            )
            .await?
            .context("direct OCI reservation absent")?;
        if row.get::<i64>(0)? == size {
            return Ok(());
        }
        let statements = vec![
            Statement::new(
                "UPDATE org_usage SET used_bytes = used_bytes + ?2, updated_at = ?3
                 WHERE org_id = (SELECT reservation.org_id FROM oci_quota_reservations reservation
                   JOIN oci_upload_sessions upload ON upload.quota_reservation_id = reservation.id
                   JOIN direct_oci_allocations allocation ON allocation.upload_id = upload.id
                   WHERE upload.id = ?1 AND upload.resource_version = ?4
                     AND upload.state = 'active' AND upload.expires_at > ?3
                     AND upload.uploaded_size = 0 AND upload.sha256_total_bytes = 0
                     AND reservation.state = 'reserved' AND reservation.reserved_bytes = 0
                     AND allocation.declared_size = ?2)
                   AND ((SELECT max_bytes FROM org_quotas quota WHERE quota.org_id = org_usage.org_id) IS NULL
                     OR org_usage.used_bytes + ?2 <= (SELECT max_bytes FROM org_quotas quota
                       WHERE quota.org_id = org_usage.org_id))",
                vals![upload.id, size, now, upload.resource_version],
            ).expecting(1),
            Statement::new(
                "UPDATE oci_quota_reservations SET reserved_bytes = ?2, updated_at = ?3
                 WHERE id = ?1 AND state = 'reserved' AND reserved_bytes = 0",
                vals![upload.quota_reservation_id, size, now],
            ).expecting(1),
        ];
        self.backend.checked_batch(&statements).await
    }

    /// Builds new writer presence or atomically verifies exact existing deduplicated bytes.
    ///
    /// The fresh independent final guard remains mandatory in the caller. Exact
    /// existing physical evidence does not charge another logical blob or invent
    /// a new provider observation on an idempotent digest allocation.
    ///
    /// # Errors
    /// Returns an error for invalid identity, size or persistence failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn direct_oci_object_presence_statements(
        &self,
        registry_id: i64,
        placement_id: i64,
        digest: Sha256Digest,
        byte_size: u64,
        etag: &str,
        now: i64,
        object_id: i64,
    ) -> Result<Vec<CheckedStatement>> {
        let size = checked_u64(byte_size, "direct OCI size")?;
        let existing = self.backend.query_opt(
            "SELECT object.id FROM surface_objects object
             JOIN object_placements presence ON presence.surface_object_id = object.id
             WHERE object.id = ?1 AND object.registry_id = ?2 AND object.object_key = ?3
               AND object.lifecycle_state = 'active' AND object.content_hash = ?4 AND object.size = ?5
               AND presence.placement_id = ?6 AND presence.state = 'present'
               AND presence.observed_hash = ?4 AND presence.observed_size = ?5 AND presence.etag = ?7",
            &vals![object_id, registry_id, oci_blob_object_key(digest), digest.encoded(), size, placement_id, etag],
        ).await?;
        if existing.is_none() {
            return Self::record_oci_uploaded_object_statements(
                registry_id,
                placement_id,
                digest,
                byte_size,
                etag,
                now,
                object_id,
            );
        }
        Ok(vec![Statement::new(
            "UPDATE surface_objects SET resource_version = resource_version
             WHERE id = ?1 AND registry_id = ?2 AND object_key = ?3 AND object_kind = 'immutable'
               AND lifecycle_state = 'active' AND content_hash = ?4 AND size = ?5
               AND NOT EXISTS (SELECT 1 FROM oci_gc_registry_locks registry_lock WHERE registry_lock.registry_id = ?2)
               AND NOT EXISTS (SELECT 1 FROM oci_registry_purge_fences purge WHERE purge.registry_id = ?2 AND purge.state = 'collecting')
               AND NOT EXISTS (SELECT 1 FROM oci_blobs blob WHERE blob.registry_id = ?2 AND blob.digest = ?8 AND blob.lifecycle_state <> 'active')
               AND EXISTS (SELECT 1 FROM object_placements presence
                 WHERE presence.surface_object_id = ?1 AND presence.registry_id = ?2
                   AND presence.placement_id = ?6 AND presence.state = 'present'
                   AND presence.observed_hash = ?4 AND presence.observed_size = ?5 AND presence.etag = ?7
                   AND presence.catalog_object_resource_version = surface_objects.resource_version)",
            vals![object_id, registry_id, oci_blob_object_key(digest), digest.encoded(), size, placement_id, etag, digest.to_string()],
        ).expecting(1)])
    }

    /// Builds source attestation, digest ownership and ordinary OCI final accounting.
    ///
    /// The caller independently verifies fresh final guard records. Every
    /// source field is also checked against the original Native direct session.
    /// Target statements and session terminal receipt must share one transaction.
    ///
    /// # Errors
    /// Returns an error for inconsistent original source or invalid accounting inputs.
    pub fn complete_direct_oci_upload_statements(
        upload: &OciUploadRecord,
        admission: &DirectUploadAdmission,
        surface_object_id: i64,
        placement_id: i64,
        now: i64,
    ) -> Result<Vec<CheckedStatement>> {
        let placement = admission
            .placements
            .first()
            .context("direct OCI placement absent")?;
        if admission.placements.len() != 1
            || i64::try_from(placement.placement_id.get())? != placement_id
        {
            bail!("direct OCI materialization placement differs");
        }
        let size = checked_u64(admission.intent.byte_size.get(), "direct OCI size")?;
        let digest = Sha256Digest::parse(&format!("sha256:{}", admission.intent.expected_sha256))?;
        if upload.state != "active"
            || upload.uploaded_size != 0
            || upload.sha256.total_bytes != 0
            || upload.expected_size != Some(admission.intent.byte_size.get())
            || upload.expected_digest != Some(digest)
        {
            bail!("direct OCI source conflicts with original logical allocation");
        }
        let completing_version = upload
            .resource_version
            .checked_add(1)
            .context("direct OCI resource version exhausted")?;
        let mut statements = vec![
            Statement::new(
                "INSERT INTO oci_blob_claims(registry_id, digest, upload_id, claimed_at)
                 SELECT registry_id, ?2, id, ?3 FROM oci_upload_sessions
                 WHERE id = ?1 AND state = 'active' AND resource_version = ?4
                   AND expires_at > ?3 AND expected_digest = ?2 AND expected_size = ?5
                   AND NOT EXISTS (SELECT 1 FROM oci_blobs blob
                     WHERE blob.registry_id = oci_upload_sessions.registry_id
                       AND blob.digest = ?2 AND blob.lifecycle_state = 'active')
                 ON CONFLICT(registry_id, digest) DO NOTHING",
                vals![upload.id, digest.to_string(), now, upload.resource_version, size],
            ).unchecked(),
            Statement::new(
                "UPDATE oci_upload_sessions SET state = 'completing', final_digest = ?2,
                    authenticated_source_sha256 = ?3, authenticated_source_bytes = ?4,
                    materialization_placement_id = ?5,
                    materialization_placement_resource_version = ?6,
                    materialization_binding_id = ?7, materialization_binding_write_revision = ?8,
                    resource_version = resource_version + 1
                 WHERE id = ?1 AND writer_id = ?9 AND token_id = ?9
                   AND state = 'active' AND resource_version = ?10 AND expires_at > ?11
                   AND uploaded_size = 0 AND sha256_total_bytes = 0
                   AND expected_digest = ?2 AND expected_size = ?4
                   AND EXISTS (SELECT 1 FROM direct_upload_sessions session
                     WHERE session.session_id = ?12 AND session.oci_upload_id = oci_upload_sessions.id
                       AND session.logical_fingerprint = ?13 AND session.source_sha256 = ?3
                       AND session.declared_size = ?4 AND session.state = 'staged_verified')
                   AND EXISTS (SELECT 1 FROM oci_quota_reservations reservation
                     WHERE reservation.id = oci_upload_sessions.quota_reservation_id
                       AND reservation.state = 'reserved' AND reservation.reserved_bytes = ?4)
                   AND (EXISTS (SELECT 1 FROM oci_blob_claims claim
                     WHERE claim.upload_id = oci_upload_sessions.id AND claim.digest = ?2)
                     OR EXISTS (SELECT 1 FROM oci_blobs blob
                       WHERE blob.registry_id = oci_upload_sessions.registry_id
                         AND blob.digest = ?2 AND blob.lifecycle_state = 'active'))",
                vals![upload.id, digest.to_string(), admission.intent.expected_sha256, size,
                    placement_id, i64::try_from(placement.placement_resource_version.get())?,
                    i64::try_from(placement.binding_id.get())?,
                    i64::try_from(placement.binding_write_revision.get())?,
                    admission.principal_id, upload.resource_version, now,
                    admission.session_id, admission.logical_fingerprint],
            ).expecting(1),
        ];
        statements.extend(Self::complete_oci_upload_statements(&CompleteOciUpload {
            upload_id: upload.id.clone(),
            writer_id: upload.writer_id.clone(),
            token_id: upload.token_id.clone(),
            expected_resource_version: completing_version,
            digest,
            byte_size: admission.intent.byte_size.get(),
            surface_object_id,
            placement_id,
            now,
        })?);
        Ok(statements)
    }
}
