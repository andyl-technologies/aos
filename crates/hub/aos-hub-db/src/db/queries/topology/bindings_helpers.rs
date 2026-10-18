//! Bindings helpers in the topology capability.

use super::*;

impl Database {
    /// Ensures the binding has a nullable, versioned write-state singleton.
    pub(in crate::db) async fn ensure_binding_write_state(&self, binding_id: i64) -> Result<()> {
        if self
            .backend
            .query_opt(
                "SELECT 1 FROM binding_write_state WHERE binding_id = ?1",
                &vals![binding_id],
            )
            .await?
            .is_some()
        {
            return Ok(());
        }
        let inserted = self
            .backend
            .execute(
                "INSERT INTO binding_write_state
                 (binding_id, current_write_revision, updated_at)
                 SELECT id, NULL, ?2 FROM bindings WHERE id = ?1",
                &vals![binding_id, unix_now()],
            )
            .await;
        match inserted {
            Ok(1) => Ok(()),
            Ok(_) => bail!("binding does not exist"),
            Err(error) => {
                if self
                    .backend
                    .query_opt(
                        "SELECT 1 FROM binding_write_state
                         WHERE binding_id = ?1",
                        &vals![binding_id],
                    )
                    .await?
                    .is_some()
                {
                    Ok(())
                } else {
                    Err(error)
                }
            }
        }
    }
}
