//! Lifecycle helpers in the runtime capability.

use super::*;

impl Database {
    /// Rejects databases from a different migration lineage before changing data.
    pub(in crate::db) async fn require_schema_identity(&self) -> Result<()> {
        let rows = self
            .backend
            .query("SELECT identity FROM hub_schema_identity", &[])
            .await
            .context("database predates the first stable production baseline")?;
        anyhow::ensure!(
            rows.len() == 1,
            "Hub schema identity ledger must contain exactly one row"
        );
        let identity: String = rows[0].get(0)?;
        anyhow::ensure!(
            identity == SCHEMA_IDENTITY,
            "unsupported Hub schema identity '{identity}'; expected '{SCHEMA_IDENTITY}'"
        );
        Ok(())
    }

    /// The SQL dialect of the underlying backend.
    pub(in crate::db) fn dialect(&self) -> Dialect {
        self.backend.dialect()
    }

    pub(in crate::db) async fn migrate(&self) -> Result<()> {
        // The driver admits lineage before even creating bookkeeping tables,
        // under the same connection/lock used for the canonical forward writes.
        self.backend.migrate_schema().await?;
        self.backfill_mirror_import_index().await?;
        self.backfill_binding_identity_reservations().await?;
        Ok(())
    }

    /// Returns the current maximum `id` in `table`, or `0` when it is empty.
    ///
    /// Used to allocate surrogate ids client-side before a batch insert, so the
    /// batch carries no mid-flight `last_insert_rowid` round-trip (the seam the
    /// native backends and Worker HubDb share). `table` must be a trusted
    /// literal — it is interpolated directly into the query.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub(in crate::db) async fn max_id(&self, table: &str) -> Result<i64> {
        let row = self
            .backend
            .query_opt(&format!("SELECT COALESCE(MAX(id), 0) FROM {table}"), &[])
            .await?
            .context("COALESCE(MAX(id), 0) returned no row")?;
        row.get(0)
    }
}
