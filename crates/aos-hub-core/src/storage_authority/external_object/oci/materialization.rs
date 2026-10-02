//! Current checked OCI business authority for bounded external materialization.
//!
//! Only the real OCI resolver creates this preparation. Every new phase locks
//! the same current IAM, writer and digest claim rows before signing a control.
//! The upload deadline and initial actor identity never change on retry.

use anyhow::{ensure, Context as _, Result};
use aos_oci_types::Sha256Digest;
use crate::{backend::{CheckedStatement, Statement}, db::{Database, OciUploadRecord,
    OciUploadChunkRecord}, value::ToValue as _};
use super::{OciActorOriginal, OciWriterOriginal};

/// Holds actual claimed upload and checked current phase authority.
#[derive(Clone)]
pub struct ExternalOciMaterialization {
    /// Exact existing completing upload, never a manufactured copy session.
    pub upload: OciUploadRecord,
    /// Actual current same-account OCI grant.
    pub actor: OciActorOriginal,
    /// Frozen current write authority and physical target.
    pub writer: OciWriterOriginal,
    /// Entire ordered SQL chunk list, bounded before projection into source pages.
    pub chunks: Vec<OciUploadChunkRecord>,
    /// Exact claimed canonical whole-blob digest.
    pub digest: Sha256Digest,
    current_iam: Vec<CheckedStatement>,
}

impl ExternalOciMaterialization {
    pub(crate) fn new(upload: OciUploadRecord, actor: OciActorOriginal,
        writer: OciWriterOriginal, chunks: Vec<OciUploadChunkRecord>, digest: Sha256Digest,
        current_iam: Vec<CheckedStatement>) -> Result<Self> {
        ensure!(!current_iam.is_empty(), "external OCI composition lacks current checked IAM");
        let value = Self { upload, actor, writer, chunks, digest, current_iam };
        value.validate()?;
        Ok(value)
    }

    /// Checks real claim, ordered SQL chunks and portable whole-upload digest.
    ///
    /// # Errors
    /// Refuses stale claim identity, missing writer pins, gaps or excessive input.
    pub fn validate(&self) -> Result<()> {
        super::OciUploadOriginal::from_record(&self.upload)?;
        self.actor.validate()?;
        self.writer.validate()?;
        ensure!(self.upload.state == "completing" && self.upload.final_digest == Some(self.digest)
            && self.upload.sha256.final_digest()? == self.digest
            && self.upload.sha256.total_bytes == self.upload.uploaded_size
            && self.upload.materialization_placement_id == Some(self.writer.placement_id.get())
            && self.upload.materialization_placement_resource_version == Some(self.writer.placement_resource_version.get())
            && self.upload.materialization_binding_id == Some(self.writer.binding_id.get())
            && self.upload.materialization_binding_write_revision == Some(self.writer.binding_write_revision.get())
            && self.chunks.len() <= super::MAX_EXTERNAL_OCI_SOURCE_CHUNKS,
            "external OCI materialization differs from real claimed upload");
        let mut offset = 0_u64;
        for (ordinal, chunk) in self.chunks.iter().enumerate() {
            ensure!(chunk.ordinal as usize == ordinal && chunk.byte_offset == offset
                && chunk.byte_size > 0 && chunk.byte_size <= super::MAX_EXTERNAL_OCI_CHUNK_BYTES,
                "external OCI SQL source list is not contiguous and bounded");
            offset = offset.checked_add(chunk.byte_size).context("OCI source offset overflow")?;
        }
        ensure!(offset == self.upload.uploaded_size, "external OCI SQL sources differ from full claim");
        Ok(())
    }

    /// Rechecks exact business authority before one new bounded provider phase.
    ///
    /// Metadata readback alone grants no new provider permission. This method
    /// checks current IAM and real SQL claim inside one atomic checked batch.
    ///
    /// # Errors
    /// Refuses expiry, changed actor/writer/claim or an unresolved SQL outcome.
    pub async fn check_current(&self, db: &Database) -> Result<()> {
        self.validate()?;
        let deadline = self.actor.expires_at.get().min(self.upload.expires_at);
        let now = crate::clock::now_unix_secs();
        ensure!(now < deadline, "external OCI original business deadline expired");
        let statements = self.checked_statements(db).await?;
        let remaining = deadline.checked_sub(crate::clock::now_unix_secs())
            .filter(|seconds| *seconds > 0)
            .context("external OCI business deadline expired during writer lookup")?;
        let transaction = Box::pin(db.backend.checked_batch(&statements));
        let timeout = Box::pin(crate::clock::sleep(std::time::Duration::from_secs(u64::try_from(remaining)?)));
        match futures_util::future::select(transaction, timeout).await {
            futures_util::future::Either::Left((result, _)) => result?,
            futures_util::future::Either::Right(_) => anyhow::bail!("external OCI authority SQL outcome unresolved"),
        }
        ensure!(crate::clock::now_unix_secs() < deadline, "external OCI business permission expired while checking SQL");
        Ok(())
    }
    /// Builds the same current IAM, writer and real claim fences for a final
    /// catalogue transaction. This preparation alone commits no SQL authority.
    pub(crate) async fn checked_statements(&self, db: &Database) -> Result<Vec<CheckedStatement>> {
        self.validate()?;
        let now = crate::clock::now_unix_secs();
        ensure!(now < self.actor.expires_at.get() && now < self.upload.expires_at,
            "external OCI final business authority expired");
        let placement = db.surface_placement(self.writer.placement_id.get()).await?
            .context("external OCI writer placement disappeared")?;
        let mut statements = self.current_iam.clone();
        statements.extend(db.external_oci_writer_statements(self.upload.registry_id, &placement, &self.writer)?);
        statements.push(Statement::new("UPDATE oci_upload_sessions SET resource_version = resource_version
            WHERE id = ?1 AND registry_id = ?2 AND repository_id = ?3 AND writer_id = ?4 AND token_id = ?5
              AND resource_version = ?6 AND state = 'completing' AND expires_at > ?7
              AND final_digest = ?8 AND uploaded_size = ?9 AND quota_reservation_id = ?10
              AND materialization_placement_id = ?11 AND materialization_placement_resource_version = ?12
              AND materialization_binding_id = ?13 AND materialization_binding_write_revision = ?14
              AND EXISTS (SELECT 1 FROM oci_blob_claims claim
                WHERE claim.upload_id = oci_upload_sessions.id AND claim.digest = ?8)",
            vec![
                self.upload.id.to_value(),
                self.upload.registry_id.to_value(),
                self.upload.repository_id.to_value(),
                self.upload.writer_id.to_value(),
                self.upload.token_id.to_value(),
                self.upload.resource_version.to_value(),
                now.to_value(),
                self.digest.to_string().to_value(),
                i64::try_from(self.upload.uploaded_size)?.to_value(),
                self.upload.quota_reservation_id.to_value(),
                self.writer.placement_id.get().to_value(),
                self.writer.placement_resource_version.get().to_value(),
                self.writer.binding_id.get().to_value(),
                self.writer.binding_write_revision.get().to_value(),
            ]).expecting(1));
        ensure!(crate::clock::now_unix_secs() < self.actor.expires_at.get()
            && crate::clock::now_unix_secs() < self.upload.expires_at,
            "external OCI business authority expired during writer lookup");
        Ok(statements)
    }

}
