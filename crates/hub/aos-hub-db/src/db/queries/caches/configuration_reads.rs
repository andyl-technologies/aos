//! Configuration reads in the caches capability.

use super::*;

impl Database {
    /// Look up a cache by its URL slug.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn binary_cache_by_slug(&self, slug: &str) -> Result<Option<BinaryCache>> {
        self.backend
            .query_opt(
                &format!("SELECT {BINARY_CACHE_COLUMNS} FROM binary_caches WHERE slug = ?1"),
                &vals![slug],
            )
            .await
            .context("loading cache by slug")?
            .map(|row| row_to_binary_cache(&row))
            .transpose()
    }

    /// Looks up a cache by its immutable non-reusable identity.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn binary_cache_by_stable_id(&self, stable_id: &str) -> Result<Option<BinaryCache>> {
        self.backend
            .query_opt(
                &format!("SELECT {BINARY_CACHE_COLUMNS} FROM binary_caches WHERE stable_id = ?1"),
                &vals![stable_id],
            )
            .await
            .context("loading cache by stable id")?
            .map(|row| row_to_binary_cache(&row))
            .transpose()
    }

    /// Look up a cache by its database id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn binary_cache_by_id(&self, id: i64) -> Result<Option<BinaryCache>> {
        self.backend
            .query_opt(
                &format!("SELECT {BINARY_CACHE_COLUMNS} FROM binary_caches WHERE id = ?1"),
                &vals![id],
            )
            .await
            .context("loading cache by id")?
            .map(|row| row_to_binary_cache(&row))
            .transpose()
    }

    /// List all servable caches.
    ///
    /// Excludes soft-deleted caches and caches owned by a soft-deleted org (the
    /// registry-parallel of [`Database::list_registries`]); instance-level
    /// caches (`org_id IS NULL`) always pass.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_binary_caches(&self) -> Result<Vec<BinaryCache>> {
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {BINARY_CACHE_COLUMNS} FROM binary_caches c
                     WHERE c.deleted_at IS NULL
                       AND (c.org_id IS NULL
                            OR NOT EXISTS (
                                SELECT 1 FROM orgs o
                                WHERE o.id = c.org_id AND o.deleted_at IS NOT NULL))
                     ORDER BY c.slug"
                ),
                &[],
            )
            .await?;
        rows.iter().map(row_to_binary_cache).collect()
    }

    /// Lists caches, including tombstoned caches, that still own write fences.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_binary_caches_with_write_tickets(&self) -> Result<Vec<BinaryCache>> {
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {BINARY_CACHE_COLUMNS} FROM binary_caches c
                 WHERE EXISTS (SELECT 1 FROM cache_write_tickets ticket
                   WHERE ticket.cache_id = c.id AND (ticket.active_cache_slot = 1 OR
                     (ticket.state = 'completed'
                       AND ticket.covered_inventory_generation IS NULL)))
                 ORDER BY c.slug"
                ),
                &[],
            )
            .await?;
        rows.iter().map(row_to_binary_cache).collect()
    }

    /// List the caches owned by one org, ordered by slug (admin/export view; does
    /// not filter by the org's soft-delete state).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_binary_caches_for_org(&self, org_id: i64) -> Result<Vec<BinaryCache>> {
        let rows = self
            .backend
            .query(
                &format!("SELECT {BINARY_CACHE_COLUMNS} FROM binary_caches WHERE org_id = ?1 ORDER BY slug"),
                &vals![org_id],
            )
            .await?;
        rows.iter().map(row_to_binary_cache).collect()
    }
}
