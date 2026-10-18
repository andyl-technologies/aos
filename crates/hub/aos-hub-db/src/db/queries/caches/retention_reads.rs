//! Retention reads in the caches capability.

use super::*;

impl Database {
    /// Lists every artifact in the exact current verified catalog revision.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_current_catalog_retention_artifacts(
        &self,
        registry_id: i64,
    ) -> Result<Vec<ReleaseSnapshotArtifact>> {
        let rows = self
            .backend
            .query(
                "SELECT artifact.package_name, artifact.package_version,
                        artifact.platform, artifact.artifact_kind,
                        artifact.store_path, artifact.store_hash
                 FROM registry_catalog_artifacts artifact
                 JOIN registry_index index_state
                   ON index_state.registry_id = artifact.registry_id
                  AND index_state.state = 'fresh'
                  AND index_state.last_indexed_commit = artifact.source_revision
                 WHERE artifact.registry_id = ?1
                 ORDER BY artifact.package_name, artifact.package_version,
                          artifact.platform, artifact.artifact_kind,
                          artifact.store_path, artifact.store_hash",
                &vals![registry_id],
            )
            .await?;
        rows.iter()
            .map(|row| {
                Ok(ReleaseSnapshotArtifact {
                    package_name: row.get(0)?,
                    package_version: row.get(1)?,
                    platform: row.get(2)?,
                    artifact_kind: row.get(3)?,
                    store_path: row.get(4)?,
                    store_hash: row.get(5)?,
                })
            })
            .collect()
    }
}
