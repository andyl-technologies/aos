//! Configuration mutations in the caches capability.

use super::*;

impl Database {
    /// The committed cache-stack expression for a registry, parsed.
    ///
    /// Returns the stored stack ([`aos_registry_format::stack::StackNode`]) when the
    /// registry's committed `registry.toml` carried a `[caches]` stack at index
    /// time, or `None` when it declared no cache stack.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, or when the stored stack JSON
    /// fails to parse (an internal-consistency error — the indexer only ever
    /// stores well-formed JSON).
    pub async fn registry_cache_stack(
        &self,
        registry_id: i64,
    ) -> Result<Option<aos_registry_format::stack::StackNode>> {
        let json: Option<String> = self
            .backend
            .query_opt(
                "SELECT cache_stack FROM registry_index WHERE registry_id = ?1",
                &vals![registry_id],
            )
            .await
            .context("loading registry cache stack")?
            .map(|row| row.get::<Option<String>>(0))
            .transpose()?
            .flatten();
        match json {
            Some(json) => Ok(Some(aos_registry_format::stack::StackNode::from_json(
                &json,
            )?)),
            None => Ok(None),
        }
    }

    // -- managed caches ------------------------------------------------------

    /// Create a managed cache; returns its new id.
    ///
    /// `org_id` is `None` for an instance-level standalone cache.
    /// Storage is not selected here. Zero or more explicit placements may be
    /// attached after creation, and writes remain disabled until a reconciled
    /// authority names exactly one complete placement.
    ///
    /// # Errors
    ///
    /// Returns an error for a duplicate slug or database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_binary_cache(
        &self,
        org_id: Option<i64>,
        slug: &str,
        name: &str,
        visibility: &str,
        priority: i64,
        compression: &str,
        want_mass_query: bool,
    ) -> Result<i64> {
        if org_id.is_none() {
            aos_hub_model::domain::iam::validate_org_slug(slug).map_err(|error| {
                anyhow::anyhow!("invalid standalone cache slug '{slug}': {error}")
            })?;
        }
        if self.binary_cache_by_slug(slug).await?.is_some() {
            bail!("a cache already exists at '{slug}'");
        }
        // Resource locators are unique across registries and caches so browse
        // links and control-plane lookup cannot become ambiguous.
        if self.registry_by_slug(slug).await?.is_some() {
            bail!(
                "a registry already exists at '{slug}' (slugs are unique across registries and caches)"
            );
        }
        let created_at = unix_now();
        let owner_scope_key = match org_id {
            Some(org_id) => {
                self.org_by_id(org_id)
                    .await?
                    .with_context(|| format!("no org with id {org_id}"))?
                    .stable_id
            }
            None => "instance".to_string(),
        };
        let incarnation = uuid::Uuid::new_v4();
        let cache_id = portable_relational_id(incarnation);
        let stable_id = format!("cache:{}", incarnation.simple());
        self.backend
            .checked_batch(&[
                Statement::new(
                    "INSERT INTO authorization_scopes
                     (scope_key, kind, org_id, parent_scope_key, resource_stable_id, created_at)
                     VALUES (?1, 'binary_cache', ?2, ?3, ?1, ?4)",
                    vals![stable_id, org_id, owner_scope_key, created_at],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO authorization_scope_ancestors
                     (descendant_scope_key, ancestor_scope_key, depth)
                     VALUES (?1, ?1, 0)",
                    vals![stable_id],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO authorization_scope_ancestors
                     (descendant_scope_key, ancestor_scope_key, depth)
                     SELECT ?1, ancestor_scope_key, depth + 1
                       FROM authorization_scope_ancestors
                      WHERE descendant_scope_key = ?2",
                    vals![stable_id, owner_scope_key],
                )
                .unchecked(),
                Statement::new(
                    "INSERT INTO binary_caches
                     (id, stable_id, org_id, slug, name, visibility,
                      priority, compression, want_mass_query, created_at, scope_key,
                      owner_scope_key)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?2, ?11)",
                    vals![
                        cache_id,
                        stable_id,
                        org_id,
                        slug,
                        name,
                        visibility,
                        priority,
                        compression,
                        want_mass_query,
                        created_at,
                        owner_scope_key,
                    ],
                )
                .expecting(1),
            ])
            .await?;
        self.initialize_new_cache_gc_topology(cache_id, created_at)
            .await
            .context("initializing cache GC topology")?;
        Ok(cache_id)
    }

    /// Update a cache's mutable fields. Returns `false` if no cache has `id`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_binary_cache(
        &self,
        id: i64,
        name: &str,
        visibility: &str,
        priority: i64,
        compression: &str,
        want_mass_query: bool,
    ) -> Result<bool> {
        let n = self
            .backend
            .execute(
                "UPDATE binary_caches SET name = ?2, visibility = ?3, priority = ?4,
                 compression = ?5, want_mass_query = ?6
                 WHERE id = ?1",
                &vals![id, name, visibility, priority, compression, want_mass_query],
            )
            .await?;
        Ok(n > 0)
    }

    /// Soft-delete a cache (tombstone with a purge deadline). Returns `false` if
    /// no live cache has `id`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn soft_delete_binary_cache(&self, id: i64, purge_after: i64) -> Result<bool> {
        let n = self
            .backend
            .execute(
                "UPDATE binary_caches SET deleted_at = ?2, purge_after = ?3
                 WHERE id = ?1 AND deleted_at IS NULL
                   AND NOT EXISTS (SELECT 1 FROM cache_write_tickets ticket
                     WHERE ticket.cache_id = ?1 AND (ticket.active_cache_slot = 1 OR
                       (ticket.state = 'completed'
                         AND ticket.covered_inventory_generation IS NULL)))",
                &vals![id, unix_now(), purge_after],
            )
            .await?;
        Ok(n > 0)
    }

    /// Hard-delete a cache row, cascading its links/policy/roots/objects/usage/runs.
    ///
    /// Does not remove the cache's surface content on the storage backend (that
    /// lives outside SQL). Returns
    /// `false` if no cache has `id`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delete_binary_cache(&self, id: i64) -> Result<bool> {
        let Some(scope_key) = self
            .backend
            .query_opt(
                "SELECT scope_key FROM binary_caches WHERE id = ?1",
                &vals![id],
            )
            .await?
            .map(|row| row.get::<String>(0))
            .transpose()?
        else {
            return Ok(false);
        };
        self.backend
            .checked_batch(&[
                Statement::new(
                    "DELETE FROM binary_caches WHERE id = ?1 AND scope_key = ?2
                       AND NOT EXISTS (SELECT 1 FROM cache_write_tickets ticket
                         WHERE ticket.cache_id = ?1 AND (ticket.active_cache_slot = 1 OR
                           (ticket.state = 'completed'
                             AND ticket.covered_inventory_generation IS NULL)))",
                    vals![id, scope_key],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE authorization_scopes SET retired_at = ?2
                      WHERE scope_key = ?1 AND kind = 'binary_cache' AND retired_at IS NULL",
                    vals![scope_key, unix_now()],
                )
                .expecting(1),
            ])
            .await?;
        Ok(true)
    }
}
