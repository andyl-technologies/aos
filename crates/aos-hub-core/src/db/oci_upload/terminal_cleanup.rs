//! Opaque cleanup selection from actual terminal upload and immutable chunk SQL.
//!
//! This claim authorizes only the retained private chunk. It is unrelated to a
//! GC plan, never changes chunk history, and cannot reopen an upload's window.

use super::*;

/// Holds one terminal upload and its exact persisted private chunk.
///
/// Only the database constructs this value. Providers must recheck it after
/// waits and separately require current, qualified physical Delete authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OciTerminalChunkCleanupClaim {
    upload: OciUploadRecord,
    chunk: OciUploadChunkRecord,
}

impl OciTerminalChunkCleanupClaim {
    /// Returns the actual terminal upload snapshot.
    pub fn upload(&self) -> &OciUploadRecord {
        &self.upload
    }

    /// Returns the immutable SQL chunk, including its full private key.
    pub fn chunk(&self) -> &OciUploadChunkRecord {
        &self.chunk
    }

    /// Rechecks the exact terminal upload and chunk without renewing write permission.
    ///
    /// # Errors
    /// Refuses changed terminal state, locators, resource version or chunk bytes.
    pub async fn check_current(&self, db: &Database) -> Result<()> {
        let upload = db
            .oci_upload(
                &self.upload.id,
                &self.upload.writer_id,
                &self.upload.token_id,
                crate::clock::now_unix_secs(),
            )
            .await?
            .context("terminal OCI cleanup upload disappeared")?;
        let chunk = db
            .oci_upload_chunk(&self.upload.id, self.chunk.ordinal)
            .await?
            .context("terminal OCI cleanup chunk disappeared")?;
        anyhow::ensure!(
            upload == self.upload && chunk == self.chunk,
            "terminal OCI cleanup SQL original changed"
        );
        Ok(())
    }
}

impl Database {
    /// Constructs cleanup authority from one exact terminal SQL candidate.
    ///
    /// This does not grant provider permission or infer absence. SQL chunk rows
    /// remain retained after their physical deletion and all-upload cleanup CAS.
    ///
    /// # Errors
    /// Refuses a nonterminal, changed, cleared or foreign upload/chunk candidate.
    pub async fn claim_terminal_oci_chunk_cleanup(
        &self,
        candidate: &OciUploadCleanupRecord,
        chunk: &OciUploadChunkRecord,
    ) -> Result<OciTerminalChunkCleanupClaim> {
        let upload = &candidate.upload;
        anyhow::ensure!(
            matches!(upload.state.as_str(), "complete" | "cancelled" | "failed")
                && upload.cleanup_state == "pending"
                && upload.finished_at.is_some()
                && upload.staging_placement_id.is_some()
                && upload.staging_placement_resource_version.is_some()
                && upload.staging_binding_id.is_some()
                && upload.staging_binding_write_revision.is_some()
                && candidate.chunks.iter().any(|retained| retained == chunk),
            "OCI terminal cleanup requires its exact retained SQL chunk"
        );
        let claim = OciTerminalChunkCleanupClaim {
            upload: upload.clone(),
            chunk: chunk.clone(),
        };
        claim.check_current(self).await?;
        Ok(claim)
    }
}
