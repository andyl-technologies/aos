//! Organizations reads in the tenancy capability.

use super::*;

impl Database {
    /// List the registries owned by one org, ordered by slug.
    ///
    /// Unlike [`Database::list_registries`], this does **not** filter by the
    /// owning org's soft-delete state — it is the admin/export view, so it
    /// returns an org's registries even while the org is tombstoned during its
    /// offboarding grace window.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_registries_including_org(&self, org_id: i64) -> Result<Vec<RegistryRecord>> {
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {REGISTRY_COLUMNS} FROM registries WHERE org_id = ?1 ORDER BY slug"
                ),
                &vals![org_id],
            )
            .await?;
        rows.iter().map(row_to_registry).collect()
    }

    /// List all active organizations, ordered by slug.
    ///
    /// Soft-deleted orgs are excluded (see [`Database::org_by_slug`]).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_orgs(&self) -> Result<Vec<OrgRecord>> {
        let rows = self
            .backend
            .query(
                "SELECT id, stable_id, slug, name, created_at, resource_version, updated_at FROM orgs
             WHERE deleted_at IS NULL ORDER BY slug",
                &[],
            )
            .await?;
        rows.iter().map(row_to_org).collect()
    }

    /// List orgs whose grace window has elapsed (`purge_after <= now`).
    ///
    /// These are the orgs the purge job ([`Database::hard_purge_org`]) hard
    /// deletes. Returns the admin-visible records (soft-deleted orgs are
    /// otherwise hidden).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_purgeable_orgs(&self, now: i64) -> Result<Vec<OrgRecord>> {
        let rows = self
            .backend
            .query(
                "SELECT id, stable_id, slug, name, created_at, resource_version, updated_at FROM orgs
             WHERE deleted_at IS NOT NULL AND purge_after IS NOT NULL AND purge_after <= ?1
             ORDER BY slug",
                &vals![now],
            )
            .await?;
        rows.iter().map(row_to_org).collect()
    }

    /// Look up an active organization by slug.
    ///
    /// Soft-deleted orgs (those with `deleted_at` set) are **excluded** so a
    /// tombstoned org stops resolving on every serving path. Use
    /// [`Database::org_by_slug_including_deleted`] for the admin/restore path
    /// that must still see them during the grace window.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn org_by_slug(&self, slug: &str) -> Result<Option<OrgRecord>> {
        self.backend
            .query_opt(
                "SELECT id, stable_id, slug, name, created_at, resource_version, updated_at FROM orgs
                 WHERE slug = ?1 AND deleted_at IS NULL",
                &vals![slug],
            )
            .await
            .context("loading org by slug")?
            .map(|row| row_to_org(&row))
            .transpose()
    }

    /// Looks up an active organization by its non-reusable stable scope key.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn org_by_stable_id(&self, stable_id: &str) -> Result<Option<OrgRecord>> {
        self.backend
            .query_opt(
                "SELECT id, stable_id, slug, name, created_at, resource_version, updated_at
                 FROM orgs WHERE stable_id = ?1 AND deleted_at IS NULL",
                &vals![stable_id],
            )
            .await
            .context("loading org by stable id")?
            .map(|row| row_to_org(&row))
            .transpose()
    }

    /// Look up an organization by id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn org_by_id(&self, id: i64) -> Result<Option<OrgRecord>> {
        self.backend
            .query_opt(
                "SELECT id, stable_id, slug, name, created_at, resource_version, updated_at FROM orgs WHERE id = ?1",
                &vals![id],
            )
            .await
            .context("loading org by id")?
            .map(|row| row_to_org(&row))
            .transpose()
    }
}
