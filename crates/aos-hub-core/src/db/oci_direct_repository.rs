//! Direct repository creation fenced by the originally authorized registry.
//!
//! Each write uses the captured stable registry identity and active organization.
//! The final checked row count rolls every catalog write back on target mismatch.
//! Ordinary Distribution repository creation retains its existing behavior.

use super::*;

impl Database {
    /// Creates a direct repository only inside its original active registry.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid time, changed registry identity, inactive
    /// organization/repository, an occupied GC fence, or database failure.
    pub(crate) async fn ensure_direct_oci_repository(
        &self,
        registry_id: i64,
        registry_stable_id: &str,
        name: &RepositoryName,
        now: i64,
    ) -> Result<OciRepositoryRecord> {
        if now <= 0 {
            bail!("OCI repository creation timestamp is invalid");
        }
        let repository_id = portable_relational_id(Uuid::new_v4());
        self.backend
            .checked_batch(&[
                Statement::new(
                    "INSERT INTO oci_repositories
                   (id, registry_id, name, visibility, lifecycle_state,
                    resource_version, created_at, updated_at)
                 SELECT ?1, registry.id, ?3, 'inherit', 'active', 1, ?4, ?4
                 FROM registries registry
                 JOIN orgs org ON org.id = registry.org_id
                 WHERE registry.id = ?2 AND registry.stable_id = ?5
                   AND org.deleted_at IS NULL
                   AND NOT EXISTS (SELECT 1 FROM oci_repositories existing
                     WHERE existing.registry_id = registry.id
                       AND existing.name = ?3)
                 ON CONFLICT(registry_id, name) DO NOTHING",
                    vals![
                        repository_id,
                        registry_id,
                        name.as_str(),
                        now,
                        registry_stable_id
                    ],
                )
                .unchecked(),
                Statement::new(
                    "INSERT INTO oci_repository_metadata
                       (repository_id, registry_id, description,
                        resource_version, updated_at)
                     SELECT repository.id, repository.registry_id, '', 1, ?3
                     FROM oci_repositories repository
                     JOIN registries registry ON registry.id = repository.registry_id
                     JOIN orgs org ON org.id = registry.org_id
                     WHERE repository.registry_id = ?1 AND repository.name = ?2
                       AND repository.lifecycle_state = 'active'
                       AND registry.stable_id = ?4 AND org.deleted_at IS NULL
                     ON CONFLICT(repository_id) DO NOTHING",
                    vals![registry_id, name.as_str(), now, registry_stable_id],
                )
                .unchecked(),
                Statement::new(
                    "INSERT INTO oci_registry_state
                       (registry_id, mutation_epoch, charged_bytes,
                        charged_objects, updated_at)
                     SELECT ?1, 0, 0, 0, ?2
                     WHERE EXISTS (SELECT 1 FROM registries registry
                       JOIN orgs org ON org.id = registry.org_id
                       WHERE registry.id = ?1 AND registry.stable_id = ?3
                         AND org.deleted_at IS NULL)
                     ON CONFLICT(registry_id) DO NOTHING",
                    vals![registry_id, now, registry_stable_id],
                )
                .unchecked(),
                Statement::new(
                    "UPDATE oci_registry_state
                     SET mutation_epoch = mutation_epoch + 1, updated_at = ?2
                     WHERE registry_id = ?1
                       AND EXISTS (SELECT 1 FROM registries registry
                         JOIN orgs org ON org.id = registry.org_id
                         JOIN oci_repositories repository ON repository.registry_id = registry.id
                         WHERE registry.id = ?1 AND registry.stable_id = ?3
                           AND org.deleted_at IS NULL AND repository.name = ?4
                           AND repository.lifecycle_state = 'active')
                       AND NOT EXISTS (SELECT 1 FROM oci_gc_registry_locks registry_lock
                         WHERE registry_lock.registry_id = ?1)
                       AND NOT EXISTS (SELECT 1 FROM oci_registry_purge_fences purge_fence
                         WHERE purge_fence.registry_id = ?1 AND purge_fence.state = 'collecting')",
                    vals![registry_id, now, registry_stable_id, name.as_str()],
                )
                .expecting(1),
            ])
            .await
            .context("creating OCI repository under its original registry identity")?;
        self.oci_repository(registry_id, name)
            .await?
            .context("new OCI repository did not become active")
    }
}
