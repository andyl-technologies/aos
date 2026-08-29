//! Digest-claim outcome recovery for durable OCI upload finalization.
//!
//! A claim transaction can return an ambiguous transport error after commit.
//! This module probes the frozen session and digest owner so exact retries can
//! distinguish owned materialization from an already-present shared blob.

use super::*;

impl Database {
    /// Recovers the durable result of one exact upload claim attempt.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted state.
    pub(super) async fn oci_upload_claim_outcome(
        &self,
        input: &ClaimOciUpload,
    ) -> Result<Option<OciBlobClaimOutcome>> {
        let row = self
            .backend
            .query_opt(
                "SELECT
                   CASE WHEN EXISTS (SELECT 1 FROM oci_blob_claims claim
                     WHERE claim.upload_id = upload.id AND claim.digest = ?4)
                     THEN 'claimed'
                   WHEN EXISTS (SELECT 1 FROM oci_blobs stored_blob
                     WHERE stored_blob.registry_id = upload.registry_id
                       AND stored_blob.digest = ?4
                       AND stored_blob.lifecycle_state = 'active')
                     THEN 'present'
                   ELSE NULL END
                 FROM oci_upload_sessions upload
                 WHERE upload.id = ?1 AND upload.writer_id = ?2 AND upload.token_id = ?3
                   AND upload.state = 'completing' AND upload.final_digest = ?4
                   AND upload.materialization_placement_id = ?5
                   AND upload.materialization_placement_resource_version = ?6
                   AND upload.materialization_binding_id = ?7
                   AND upload.materialization_binding_write_revision = ?8",
                &vals![
                    input.upload_id,
                    input.writer_id,
                    input.token_id,
                    input.digest.to_string(),
                    input.materialization_placement_id,
                    input.materialization_placement_resource_version,
                    input.materialization_binding_id,
                    input.materialization_binding_write_revision
                ],
            )
            .await?;
        row.map(|row| match row.get::<Option<String>>(0)?.as_deref() {
            Some("claimed") => Ok(Some(OciBlobClaimOutcome::Claimed)),
            Some("present") => Ok(Some(OciBlobClaimOutcome::AlreadyPresent)),
            None => Ok(None),
            Some(_) => bail!("persisted OCI upload claim outcome is invalid"),
        })
        .transpose()
        .map(Option::flatten)
    }
}
