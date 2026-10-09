//! Database-authoritative clock reads and transactional lease predicates.

use anyhow::{Context as _, Result, bail};
use aos_assessment::time::Timestamp;

use crate::db::Database;

impl Database {
    /// Reads the database clock for assessment admission and execution.
    ///
    /// # Errors
    /// Returns an error when SQL is unavailable or its clock is outside the
    /// portable assessment timestamp range.
    pub async fn assessment_database_time(&self) -> Result<Timestamp> {
        let sql = format!("SELECT {}", self.backend.dialect().unix_time_expression());
        let row = self
            .backend
            .query_opt(&sql, &[])
            .await?
            .context("database clock is absent")?;
        let seconds: i64 = row.get(0)?;
        if seconds < 0 {
            bail!("database clock predates the assessment epoch");
        }
        Timestamp::from_unix_seconds(seconds as u64)
    }
}
