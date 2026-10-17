//! Current SQL writer and reservation fences after upstream control awaits.
//!
//! This check grants no IAM permission. The OCI handler independently rechecks
//! the actual actor before handing this staging permit to the Worker.

use anyhow::{Context as _, Result, ensure};

use super::{Database, ExternalOciStagePreparation};
use crate::{backend::Statement, value::ToValue as _};

#[cfg(test)]
mod tests;

impl ExternalOciStagePreparation {
    /// Checks the full ready writer and unchanged real upload reservation.
    ///
    /// This atomic check follows original discovery and rejects a changed
    /// authority incarnation or generation even when placement pins match.
    /// The caller separately authenticates current Publish permission.
    ///
    /// # Errors
    /// Refuses expiry, changed SQL writer or upload, or an unresolved transaction.
    pub async fn check_current_writer(&self, db: &Database) -> Result<()> {
        self.validate()?;
        let deadline = self.actor.expires_at.get().min(self.upload.expires_at);
        let now = crate::clock::now_unix_secs();
        ensure!(now < deadline, "external OCI staging original expired");
        let placement = db
            .surface_placement(self.writer.placement_id.get())
            .await?
            .context("external OCI staging placement disappeared")?;
        let mut statements =
            db.external_oci_writer_statements(self.upload.registry_id, &placement, &self.writer)?;
        statements.push(
            Statement::new(
                "UPDATE oci_upload_sessions SET resource_version = resource_version
             WHERE id = ?1 AND registry_id = ?2 AND repository_id = ?3
               AND writer_id = ?4 AND token_id = ?5 AND state = 'active'
               AND resource_version = ?6 AND expires_at > ?7
               AND uploaded_size = ?8 AND quota_reservation_id = ?9
               AND staging_placement_id = ?10 AND staging_placement_resource_version = ?11
               AND staging_binding_id = ?12 AND staging_binding_write_revision = ?13
               AND EXISTS (SELECT 1 FROM oci_quota_reservations reservation
                 WHERE reservation.id = ?9 AND reservation.state = 'reserved')",
                vec![
                    self.upload.id.to_value(),
                    self.upload.registry_id.to_value(),
                    self.upload.repository_id.to_value(),
                    self.upload.writer_id.to_value(),
                    self.upload.token_id.to_value(),
                    self.upload.resource_version.to_value(),
                    now.to_value(),
                    i64::try_from(self.upload.uploaded_size)?.to_value(),
                    self.upload.quota_reservation_id.to_value(),
                    self.writer.placement_id.get().to_value(),
                    self.writer.placement_resource_version.get().to_value(),
                    self.writer.binding_id.get().to_value(),
                    self.writer.binding_write_revision.get().to_value(),
                ],
            )
            .expecting(1),
        );

        let remaining = deadline
            .checked_sub(crate::clock::now_unix_secs())
            .filter(|seconds| *seconds > 0)
            .context("external OCI staging authority expired during SQL lookup")?;
        let transaction = Box::pin(db.backend.checked_batch(&statements));
        let timeout = Box::pin(crate::clock::sleep(std::time::Duration::from_secs(
            u64::try_from(remaining)?,
        )));
        match futures_util::future::select(transaction, timeout).await {
            futures_util::future::Either::Left((result, _)) => result?,
            futures_util::future::Either::Right(_) => {
                anyhow::bail!("external OCI staging SQL outcome unresolved")
            }
        }
        ensure!(
            crate::clock::now_unix_secs() < deadline,
            "external OCI staging permission expired during SQL check"
        );
        Ok(())
    }
}
