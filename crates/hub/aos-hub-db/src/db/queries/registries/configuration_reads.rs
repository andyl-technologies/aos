//! Configuration reads in the registries capability.

use super::*;

impl Database {
    /// Look up a registry by slug.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn registry_by_slug(&self, slug: &str) -> Result<Option<RegistryRecord>> {
        self.backend
            .query_opt(
                &format!("SELECT {REGISTRY_COLUMNS} FROM registries WHERE slug = ?1"),
                &vals![slug],
            )
            .await
            .context("loading registry by slug")?
            .map(|row| row_to_registry(&row))
            .transpose()
    }

    /// Looks up a registry by its immutable stable identity.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn registry_by_stable_id(&self, stable_id: &str) -> Result<Option<RegistryRecord>> {
        self.backend
            .query_opt(
                &format!("SELECT {REGISTRY_COLUMNS} FROM registries WHERE stable_id = ?1"),
                &vals![stable_id],
            )
            .await
            .context("loading registry by stable id")?
            .map(|row| row_to_registry(&row))
            .transpose()
    }

    /// Look up a registry by its database id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn registry_by_id(&self, registry_id: i64) -> Result<Option<RegistryRecord>> {
        self.backend
            .query_opt(
                &format!("SELECT {REGISTRY_COLUMNS} FROM registries WHERE id = ?1"),
                &vals![registry_id],
            )
            .await
            .context("loading registry by id")?
            .map(|row| row_to_registry(&row))
            .transpose()
    }

    /// Lists population targets supplied by one registry.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_registry_population_targets(
        &self,
        registry_id: i64,
    ) -> Result<Vec<CachePopulationTargetRecord>> {
        self.backend.query(&format!("SELECT {POPULATION_COLUMNS} FROM cache_population_targets WHERE registry_id = ?1 ORDER BY cache_id, trigger_kind"), &vals![registry_id]).await?.iter().map(row_to_cache_population_target).collect()
    }

    /// Lists one registry's publications in stable newest-first order.
    ///
    /// The optional cursor is exclusive and must identify a publication in the
    /// same registry and state-filtered inventory.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid state or cursor, malformed persisted
    /// data, or a database failure.
    pub async fn list_registry_publications_page(
        &self,
        registry_id: i64,
        state: Option<&str>,
        page_size: u32,
        before_ordinal: Option<i64>,
    ) -> Result<RegistryPublicationPage> {
        let state = state.unwrap_or("");
        if !state.is_empty()
            && !matches!(
                state,
                "preparing" | "writing_pointers" | "ready" | "failed" | "retired"
            )
        {
            bail!("invalid publication state filter '{state}'");
        }
        if let Some(ordinal) = before_ordinal {
            let belongs = self
                .backend
                .query_opt(
                    "SELECT 1 FROM registry_publications
                     WHERE registry_id = ?1 AND ordinal = ?2
                       AND (?3 = '' OR state = ?3)",
                    &vals![registry_id, ordinal, state],
                )
                .await?
                .is_some();
            if !belongs {
                bail!("publication page token does not belong to this inventory");
            }
        }
        let limit = if page_size == 0 {
            50_i64
        } else {
            i64::from(page_size.min(200))
        };
        let rows = self
            .backend
            .query(
                "SELECT publication_id, registry_id, ordinal, generation,
                        manifest_digest, refs_digest, default_commit,
                        parent_publication_id, state, created_at, completed_at,
                        retired_at
                 FROM registry_publications
                 WHERE registry_id = ?1 AND (?2 = '' OR state = ?2)
                   AND (?3 IS NULL OR ordinal < ?3)
                 ORDER BY ordinal DESC LIMIT ?4",
                &vals![registry_id, state, before_ordinal, limit + 1],
            )
            .await?;
        let mut records = rows
            .iter()
            .map(|row| {
                Ok(RegistryPublicationRecord {
                    publication_id: row.get(0)?,
                    registry_id: row.get(1)?,
                    ordinal: row.get(2)?,
                    generation: row.get(3)?,
                    manifest_digest: row.get(4)?,
                    refs_digest: row.get(5)?,
                    default_commit: row.get(6)?,
                    parent_publication_id: row.get(7)?,
                    state: row.get(8)?,
                    created_at: row.get(9)?,
                    completed_at: row.get(10)?,
                    retired_at: row.get(11)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let next_cursor = if records.len() > limit as usize {
            records.pop();
            records.last().map(|record| record.ordinal)
        } else {
            None
        };
        Ok(RegistryPublicationPage {
            records,
            next_cursor,
        })
    }

    /// List all registered registries that are servable.
    ///
    /// Registries owned by a soft-deleted org are excluded (a tombstoned org
    /// stops serving every one of its registries); unowned phase-1 registries
    /// (`org_id IS NULL`) always pass.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_registries(&self) -> Result<Vec<RegistryRecord>> {
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {REGISTRY_COLUMNS} FROM registries r
                 WHERE r.org_id IS NULL
                    OR NOT EXISTS (
                        SELECT 1 FROM orgs o
                        WHERE o.id = r.org_id AND o.deleted_at IS NOT NULL
                    )
                 ORDER BY r.slug"
                ),
                &[],
            )
            .await?;
        rows.iter().map(row_to_registry).collect()
    }
}
