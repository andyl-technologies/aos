//! Projects reads in the tenancy capability.

use super::*;

impl Database {
    /// List an org's projects, ordered by materialized path.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_projects(&self, org_id: i64) -> Result<Vec<ProjectRecord>> {
        let rows = self
            .backend
            .query(
                "SELECT id, stable_id, scope_key, owner_scope_key, org_id, path, name,
                        created_at, resource_version, updated_at FROM projects
             WHERE org_id = ?1 ORDER BY path",
                &vals![org_id],
            )
            .await?;
        rows.iter()
            .map(|row| {
                Ok(ProjectRecord {
                    id: row.get(0)?,
                    stable_id: row.get(1)?,
                    scope_key: row.get(2)?,
                    owner_scope_key: row.get(3)?,
                    org_id: row.get(4)?,
                    path: row.get(5)?,
                    name: row.get(6)?,
                    created_at: row.get(7)?,
                    resource_version: row.get(8)?,
                    updated_at: row.get(9)?,
                })
            })
            .collect()
    }
}
