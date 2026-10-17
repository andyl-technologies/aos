//! Pre-effect reservation of the actual external OCI staging writer.
//!
//! The existing upload columns retain the chosen writer before the first
//! provider Create. Current checked IAM and writer rows share the transaction;
//! retries preserve its choice and never infer physical settlement.

use super::*;
use crate::db::SurfacePlacementRecord;
use crate::storage_authority::external_object::oci::{OciUploadOriginal, OciWriterOriginal};

impl Database {
    pub(crate) async fn reserve_external_oci_staging(
        &self,
        upload: &OciUploadRecord,
        placement: &SurfacePlacementRecord,
        writer: &OciWriterOriginal,
        mut current_iam: Vec<CheckedStatement>,
        grant_expires_at: i64,
        now: i64,
    ) -> Result<OciUploadRecord> {
        OciUploadOriginal::from_record(upload)?;
        writer.validate()?;
        anyhow::ensure!(placement.id == writer.placement_id.get()
            && placement.resource_version == writer.placement_resource_version.get()
            && placement.write_spec_version == writer.write_spec_version.get()
            && placement.effective_write_enabled && placement.observation_version.is_some(),
            "external OCI staging placement is not the actual ready writer");
        anyhow::ensure!(!current_iam.is_empty() && now > 0 && grant_expires_at > now
            && upload.expires_at > now && upload.state == "active",
            "external OCI staging requires current checked business authority");
        let selected = (
            Some(writer.placement_id.get()),
            Some(writer.placement_resource_version.get()),
            Some(writer.binding_id.get()),
            Some(writer.binding_write_revision.get()),
        );
        let prior = (upload.staging_placement_id, upload.staging_placement_resource_version,
            upload.staging_binding_id, upload.staging_binding_write_revision);
        let fresh = prior == (None, None, None, None);
        anyhow::ensure!(fresh || prior == selected,
            "external OCI staging cannot replace its frozen writer");

        // Match the existing OCI catalogue lock order after current IAM:
        // registry, binding, immutable credential/write state, authority,
        // placement and its observations, then the exact upload reservation.
        current_iam.extend(self.external_oci_writer_statements(upload.registry_id, placement, writer)?);
        current_iam.push(Statement::new(
            "UPDATE oci_upload_sessions
             SET staging_placement_id = ?1, staging_placement_resource_version = ?2,
               staging_binding_id = ?3, staging_binding_write_revision = ?4,
               resource_version = resource_version + ?5
             WHERE id = ?6 AND writer_id = ?7 AND token_id = ?8
               AND registry_id = ?9 AND repository_id = ?10
               AND resource_version = ?11 AND state = 'active' AND expires_at > ?12
               AND uploaded_size = ?13 AND quota_reservation_id = ?14
               AND EXISTS (SELECT 1 FROM oci_quota_reservations reservation
                 WHERE reservation.id = ?14 AND reservation.state = 'reserved')
               AND ((?5 = 1 AND staging_placement_id IS NULL
                 AND staging_placement_resource_version IS NULL AND staging_binding_id IS NULL
                 AND staging_binding_write_revision IS NULL)
                 OR (?5 = 0 AND staging_placement_id = ?1
                   AND staging_placement_resource_version = ?2 AND staging_binding_id = ?3
                   AND staging_binding_write_revision = ?4))",
            vals![writer.placement_id.get(), writer.placement_resource_version.get(),
                writer.binding_id.get(), writer.binding_write_revision.get(), i64::from(fresh),
                upload.id, upload.writer_id, upload.token_id, upload.registry_id,
                upload.repository_id, upload.resource_version, now,
                checked_u64(upload.uploaded_size, "OCI staging offset")?, upload.quota_reservation_id],
        ).expecting(1));

        self.backend.checked_batch(&current_iam).await?;
        anyhow::ensure!(crate::clock::now_unix_secs() < grant_expires_at,
            "external OCI grant expired while reserving its writer");
        let retained = self.oci_upload(&upload.id, &upload.writer_id, &upload.token_id,
            crate::clock::now_unix_secs()).await?.context("external OCI reservation disappeared")?;
        anyhow::ensure!((retained.staging_placement_id, retained.staging_placement_resource_version,
            retained.staging_binding_id, retained.staging_binding_write_revision) == selected
            && retained.resource_version == upload.resource_version + i64::from(fresh),
            "external OCI reservation changed after writer commit");
        Ok(retained)
    }

    pub(crate) fn external_oci_writer_statements(
        &self,
        registry_id: i64,
        placement: &SurfacePlacementRecord,
        writer: &OciWriterOriginal,
    ) -> Result<Vec<CheckedStatement>> {
        writer.validate()?;
        anyhow::ensure!(placement.id == writer.placement_id.get()
            && placement.resource_version == writer.placement_resource_version.get()
            && placement.write_spec_version == writer.write_spec_version.get()
            && placement.effective_write_enabled, "external OCI current writer differs");
        Ok(vec![
            Statement::new("UPDATE oci_registry_state SET updated_at = updated_at
                WHERE registry_id = ?1
                  AND NOT EXISTS (SELECT 1 FROM oci_gc_registry_locks lock
                    WHERE lock.registry_id = ?1)
                  AND NOT EXISTS (SELECT 1 FROM oci_registry_purge_fences fence
                    WHERE fence.registry_id = ?1 AND fence.state = 'collecting')",
                vals![registry_id]).expecting(1),
            Statement::new("UPDATE bindings SET resource_version = resource_version
                WHERE id = ?1 AND stable_id = ?2 AND resource_version = ?3
                  AND is_instance_default = 0 AND kind IN ('s3', 'r2')",
                vals![writer.binding_id.get(), writer.binding_stable_id,
                    writer.binding_resource_version.get()]).expecting(1),
            Statement::new("UPDATE binding_write_state SET updated_at = updated_at
                WHERE binding_id = ?1 AND current_write_revision = ?2",
                vals![writer.binding_id.get(), writer.binding_write_revision.get()]).expecting(1),
            Statement::new("UPDATE binding_write_revisions SET created_at = created_at
                WHERE binding_id = ?1 AND revision = ?2 AND writes_supported = 1
                  AND EXISTS (SELECT 1 FROM binding_credential_revisions credential
                    WHERE credential.binding_id = ?1
                      AND credential.purpose = binding_write_revisions.write_credential_purpose
                      AND credential.generation = binding_write_revisions.write_credential_generation
                      AND credential.secret_version_ref = binding_write_revisions.write_credential_version_ref
                      AND credential.validation_state = 'valid')",
                vals![writer.binding_id.get(), writer.binding_write_revision.get()]).expecting(1),
            Statement::new("UPDATE binding_write_observations SET validated_at = validated_at
                WHERE binding_id = ?1 AND revision = ?2 AND state = 'valid'",
                vals![writer.binding_id.get(), writer.binding_write_revision.get()]).expecting(1),
            Statement::new("UPDATE surface_write_authorities SET updated_at = updated_at
                WHERE id = ?1 AND incarnation_id = ?2 AND registry_id = ?3
                  AND cache_id IS NULL AND resource_version = ?4
                  AND mode = 'single_writer' AND reconciliation_state = 'ready'
                  AND desired_placement_id = ?5 AND observed_placement_id = ?5
                  AND desired_write_spec_version = ?6 AND observed_write_spec_version = ?6
                  AND desired_binding_write_revision = ?7 AND observed_binding_write_revision = ?7
                  AND desired_generation = ?8 AND observed_generation = ?8",
                vals![writer.authority_id.get(), writer.authority_incarnation,
                    registry_id, writer.authority_resource_version.get(),
                    writer.placement_id.get(), writer.write_spec_version.get(),
                    writer.binding_write_revision.get(), writer.authority_generation.get()]).expecting(1),
            Statement::new("UPDATE surface_placements SET updated_at = updated_at
                WHERE id = ?1 AND registry_id = ?2 AND cache_id IS NULL
                  AND binding_id = ?3 AND resource_version = ?4 AND write_spec_version = ?5
                  AND prefix = ?6 AND kind = 'complete' AND desired_state = 'active'
                  AND binding_grant_state = 'active'
                  AND EXISTS (SELECT 1 FROM surface_placement_observations observation
                    WHERE observation.placement_id = ?1
                      AND observation.observation_version = ?8
                      AND observation.state = 'ready' AND observation.completeness = 'complete')
                  AND EXISTS (SELECT 1 FROM surface_placement_write_capabilities capability
                    WHERE capability.placement_id = ?1
                      AND capability.placement_write_spec_version = ?5
                      AND capability.binding_id = ?3 AND capability.binding_write_revision = ?7)",
                vals![writer.placement_id.get(), registry_id, writer.binding_id.get(),
                    writer.placement_resource_version.get(), writer.write_spec_version.get(),
                    writer.placement_prefix, writer.binding_write_revision.get(),
                    placement.observation_version.context("OCI staging observation missing")?]).expecting(1),

        ])
    }

    /// Retains physical facts only under the actual checked current OCI claim.
    pub(crate) async fn record_external_oci_uploaded_object(
        &self, preparation: &crate::storage_authority::external_object::oci::materialization::ExternalOciMaterialization,
        observed_etag: &str,
    ) -> Result<OciUploadedObjectEvidence> {
        let registry_id = preparation.upload.registry_id;
        let placement_id = preparation.writer.placement_id.get();
        let byte_size = preparation.upload.uploaded_size;
        let existing = self.oci_uploaded_object_evidence(registry_id, placement_id,
            preparation.digest, byte_size, observed_etag).await?;
        let mut statements = preparation.checked_statements(self).await?;
        if let Some(existing) = existing {
            // Existing positive facts are reusable only while both the real
            // claim and this exact catalogue presence survive the transaction.
            statements.push(Statement::new("UPDATE object_placements SET observed_at = observed_at
                WHERE surface_object_id = ?1 AND placement_id = ?2 AND registry_id = ?3
                  AND state = 'present' AND observed_hash = ?4 AND observed_size = ?5
                  AND etag = ?6 AND EXISTS (SELECT 1 FROM surface_objects object
                    WHERE object.id = ?1 AND object.registry_id = ?3 AND object.lifecycle_state = 'active'
                      AND object.content_hash = ?4 AND object.size = ?5
                      AND object.resource_version = object_placements.catalog_object_resource_version)",
                vals![existing.surface_object_id, placement_id, registry_id,
                    preparation.digest.encoded(), checked_u64(byte_size, "OCI positive size")?, observed_etag])
                .expecting(1));
            self.backend.checked_batch(&statements).await?;
            return Ok(existing);
        }
        statements.extend(Self::record_oci_uploaded_object_statements(registry_id, placement_id,
            preparation.digest, byte_size, observed_etag, crate::clock::now_unix_secs(),
            portable_relational_id(Uuid::new_v4()))?);
        self.backend.checked_batch(&statements).await?;
        self.oci_uploaded_object_evidence(registry_id, placement_id, preparation.digest,
            byte_size, observed_etag).await?.context("external OCI positive catalogue disappeared")
    }

}
