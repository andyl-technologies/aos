//! OCI accounting for complete bytes verified by the Native storage backend.
//!
//! Native provider progress and its verified source commit with ordinary OCI
//! accounting. Worker guard records remain required for Worker-coordinated uploads.

use super::*;

impl Database {
    pub(super) async fn native_direct_oci_source_matches(
        &self,
        upload: &OciUploadRecord,
    ) -> Result<bool> {
        let (Some(digest), Some(bytes)) = (
            upload.authenticated_source_sha256,
            upload.authenticated_source_bytes,
        ) else {
            return Ok(false);
        };
        Ok(self
            .backend
            .query_opt(
                "SELECT 1 FROM native_direct_uploads session
             WHERE session.oci_upload_id = ?1 AND session.state = 'committed'
               AND session.principal_id = ?2 AND session.principal_id = ?3
               AND session.source_sha256 = ?4 AND session.verified_sha256 = ?4
               AND session.declared_size = ?5 AND session.verified_size = ?5
               AND session.materialization_placement_id = ?6
               AND session.materialization_binding_id = ?7",
                &vals![
                    upload.id,
                    upload.writer_id,
                    upload.token_id,
                    digest.encoded(),
                    checked_u64(bytes, "native direct OCI size")?,
                    upload.materialization_placement_id,
                    upload.materialization_binding_id
                ],
            )
            .await?
            .is_some())
    }

    /// Builds OCI completion bound to a Native journal's verified complete object.
    ///
    /// The caller verifies the provider's complete SHA-256 and size before storing
    /// the source. The journal's terminal transition and these statements must be
    /// executed in one checked transaction, with the journal update first.
    ///
    /// # Errors
    /// Rejects changed source, nonempty streamed state, invalid placement pins or
    /// an upload outside its original active lifetime.
    #[allow(clippy::too_many_arguments)]
    pub fn complete_native_direct_oci_upload_statements(
        upload: &OciUploadRecord,
        deployment: &str,
        session_id: &str,
        surface_object_id: i64,
        placement_id: i64,
        placement_resource_version: i64,
        binding_id: i64,
        binding_write_revision: i64,
        now: i64,
    ) -> Result<Vec<CheckedStatement>> {
        let digest = upload
            .expected_digest
            .context("native direct OCI digest absent")?;
        let bytes = upload
            .expected_size
            .context("native direct OCI size absent")?;
        let size = checked_u64(bytes, "native direct OCI size")?;
        anyhow::ensure!(
            upload.state == "active"
                && upload.uploaded_size == 0
                && upload.sha256.total_bytes == 0
                && upload.writer_id == upload.token_id
                && upload.expires_at > now
                && placement_id > 0
                && placement_resource_version > 0
                && binding_id > 0
                && binding_write_revision > 0,
            "native direct OCI original source or placement differs"
        );
        let completing_version = upload
            .resource_version
            .checked_add(1)
            .context("native OCI version exhausted")?;
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
                    materialization_placement_id = ?5, materialization_placement_resource_version = ?6,
                    materialization_binding_id = ?7, materialization_binding_write_revision = ?8,
                    resource_version = resource_version + 1
                 WHERE id = ?1 AND writer_id = ?9 AND token_id = ?9
                   AND state = 'active' AND resource_version = ?10 AND expires_at > ?11
                   AND uploaded_size = 0 AND sha256_total_bytes = 0
                   AND expected_digest = ?2 AND expected_size = ?4
                   AND EXISTS (SELECT 1 FROM native_direct_uploads session
                     WHERE session.deployment_id = ?12 AND session.session_id = ?13
                       AND session.oci_upload_id = oci_upload_sessions.id AND session.principal_id = ?9
                       AND session.state = 'committed' AND session.source_sha256 = ?3
                       AND session.verified_sha256 = ?3 AND session.declared_size = ?4 AND session.verified_size = ?4
                       AND session.materialization_placement_id = ?5 AND session.materialization_binding_id = ?7)
                   AND EXISTS (SELECT 1 FROM oci_quota_reservations reservation
                     WHERE reservation.id = oci_upload_sessions.quota_reservation_id
                       AND reservation.state = 'reserved' AND reservation.reserved_bytes = ?4)
                   AND (EXISTS (SELECT 1 FROM oci_blob_claims claim
                     WHERE claim.upload_id = oci_upload_sessions.id AND claim.digest = ?2)
                     OR EXISTS (SELECT 1 FROM oci_blobs blob
                       WHERE blob.registry_id = oci_upload_sessions.registry_id AND blob.digest = ?2
                         AND blob.lifecycle_state = 'active'))",
                vals![upload.id, digest.to_string(), digest.encoded(), size, placement_id, placement_resource_version,
                    binding_id, binding_write_revision, upload.writer_id, upload.resource_version, now, deployment, session_id],
            ).expecting(1),
        ];
        statements.extend(Self::complete_oci_upload_statements(&CompleteOciUpload {
            upload_id: upload.id.clone(),
            writer_id: upload.writer_id.clone(),
            token_id: upload.token_id.clone(),
            expected_resource_version: completing_version,
            digest,
            byte_size: bytes,
            surface_object_id,
            placement_id,
            now,
        })?);
        Ok(statements)
    }
}
