//! Organizations mutations in the tenancy capability.

use super::*;

impl Database {
    // -- tenancy: orgs and projects -----------------------------------------

    /// Create an organization; returns its new id.
    ///
    /// The `slug` is validated against the canonical single-segment ruleset
    /// ([`aos_hub_model::domain::iam::validate_org_slug`]) as a persistence-layer
    /// backstop: an org slug is a single URL/scope path segment, so it may
    /// not contain `/` or any out-of-charset character. This prevents any
    /// caller — RPC, console, or CLI — from writing a slug that
    /// [`aos_hub_model::domain::Scope::parse`] would later normalize into an
    /// unintended ancestor scope (sec CR-2).
    ///
    /// # Errors
    ///
    /// Returns an error when `slug` fails validation, and on database
    /// failure, including a unique-constraint violation when `slug` is
    /// already taken.
    pub async fn create_org(&self, slug: &str, name: &str) -> Result<i64> {
        aos_hub_model::domain::iam::validate_org_slug(slug)
            .map_err(|e| anyhow::anyhow!("invalid org slug '{slug}': {e}"))?;
        let org_id = self.max_id("orgs").await? + 1;
        let consumer_scope_key = format!("org:{}", uuid::Uuid::new_v4().simple());
        let now = unix_now();
        self.backend
            .checked_batch(&[
                Statement::new(
                    "INSERT INTO orgs (id, stable_id, slug, name, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                    vals![org_id, consumer_scope_key, slug, name, now],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO org_usage (org_id, used_bytes, object_count, updated_at)
                     VALUES (?1, 0, 0, 0)",
                    vals![org_id],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO authorization_scopes
                     (scope_key, kind, org_id, parent_scope_key, resource_stable_id, created_at)
                     VALUES (?1, 'organization', ?2, 'instance', ?1, ?3)",
                    vals![consumer_scope_key, org_id, now],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO authorization_scope_ancestors
                     (descendant_scope_key, ancestor_scope_key, depth)
                     VALUES (?1, ?1, 0)",
                    vals![consumer_scope_key],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO authorization_scope_ancestors
                     (descendant_scope_key, ancestor_scope_key, depth)
                     SELECT ?1, ancestor_scope_key, depth + 1
                       FROM authorization_scope_ancestors
                      WHERE descendant_scope_key = 'instance'",
                    vals![consumer_scope_key],
                )
                .unchecked(),
            ])
            .await?;
        Ok(org_id)
    }

    /// Soft-delete an org, opening a `grace_secs` grace window.
    ///
    /// Stamps `deleted_at = now` and `purge_after = now + grace_secs`. The org
    /// immediately stops serving (the serving queries exclude soft-deleted
    /// orgs), but its data persists until the purge job hard-deletes it past
    /// `purge_after`. Returns `Ok(false)` when the org is unknown, already
    /// soft-deleted, or still owns an outstanding descendant write fence.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn soft_delete_org(&self, org_id: i64, grace_secs: i64) -> Result<bool> {
        let now = unix_now();
        let n = self
            .backend
            .execute(
                "UPDATE orgs SET deleted_at = ?2, purge_after = ?3
             WHERE id = ?1 AND deleted_at IS NULL
               AND NOT EXISTS (SELECT 1 FROM cache_write_tickets ticket
                 JOIN binary_caches cache ON cache.id = ticket.cache_id
                 WHERE cache.org_id = ?1 AND (ticket.active_cache_slot = 1 OR
                   (ticket.state = 'completed'
                     AND ticket.covered_inventory_generation IS NULL)))",
                &vals![org_id, now, now + grace_secs],
            )
            .await?;
        Ok(n > 0)
    }

    /// Restore a soft-deleted org within its grace window.
    ///
    /// Clears `deleted_at`/`purge_after`, returning the org to active serving.
    /// Returns `Ok(false)` when the org is unknown or was not soft-deleted.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn restore_org(&self, org_id: i64) -> Result<bool> {
        let n = self
            .backend
            .execute(
                "UPDATE orgs SET deleted_at = NULL, purge_after = NULL
             WHERE id = ?1 AND deleted_at IS NOT NULL",
                &vals![org_id],
            )
            .await?;
        Ok(n > 0)
    }

    /// Hard-delete an org row, cascading to everything it owns.
    ///
    /// The org's `ON DELETE CASCADE` foreign keys remove its projects,
    /// registries, service accounts, memberships, bindings, quotas, usage, and
    /// the rest of its SQL system of record. Bucket/LocalFs content removal is
    /// a *separate* step (the caller deletes the binding root dir), since the
    /// surface lives outside SQL. Returns `Ok(false)` when the org is unknown.
    ///
    /// SECURITY: the delete re-asserts the exact predicate
    /// [`Database::list_purgeable_orgs`] selects on — still soft-deleted and
    /// past its grace window — rather than deleting on `id` alone. The purge job
    /// lists purgeable orgs and then deletes them one by one with no transaction
    /// spanning the list and the delete, while [`Database::restore_org`] can
    /// clear `deleted_at`/`purge_after` concurrently (via the `org restore`
    /// CLI). Were the delete unconditional, a restore landing in that window
    /// would be silently destroyed, cascading away the now-active org's
    /// projects, registries, members, tokens, and bindings. Re-checking the
    /// predicate makes the delete a no-op (returning `Ok(false)`) for any org
    /// restored after it was listed. The caller passes the *same* `now` it gave
    /// [`Database::list_purgeable_orgs`] (see
    /// the hub's `export::purge_expired_orgs`), so one
    /// consistent timestamp spans the list and every delete in a purge tick.
    /// The same checked transaction fences and releases every storage-binding,
    /// boundary, endpoint, and gateway grant pin; records exact revocation
    /// events for every active grant; deletes the organization; and removes all
    /// grant tombstones for its non-reusable stable scope. Recreating the slug
    /// creates a different stable scope and cannot inherit prior authority.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn hard_purge_org(&self, org_id: i64, now: i64) -> Result<bool> {
        let org = self
            .backend
            .query_opt(
                "SELECT stable_id FROM orgs WHERE id = ?1 AND deleted_at IS NOT NULL
                   AND purge_after IS NOT NULL AND purge_after <= ?2",
                &vals![org_id, now],
            )
            .await?;
        let Some(org) = org else {
            return Ok(false);
        };
        let scope: String = org.get(0)?;
        let grants = self
            .backend
            .query(
                "SELECT 'binding', b.stable_id, 0, g.grant_generation,
                        g.resource_version
                   FROM binding_consumer_scopes g
                   JOIN bindings b ON b.id = g.binding_id
                  WHERE g.consumer_scope_key = ?1 AND g.state = 'active'
                 UNION ALL
                 SELECT 'network_policy', g.boundary_id, 0, g.grant_generation,
                        g.resource_version
                   FROM network_policy_consumer_scopes g
                  WHERE g.consumer_scope_key = ?1 AND g.state = 'active'
                 UNION ALL
                 SELECT 'endpoint', g.endpoint_id, g.endpoint_generation,
                        g.grant_generation, g.resource_version
                   FROM endpoint_route_scopes g
                  WHERE g.consumer_scope_key = ?1 AND g.state = 'active'
                 UNION ALL
                 SELECT 'gateway', g.gateway_id, g.generation,
                        g.grant_generation, g.resource_version
                   FROM gateway_revision_route_scopes g
                  WHERE g.consumer_scope_key = ?1 AND g.state = 'active'",
                &vals![scope],
            )
            .await?;
        let request_id = format!("org-purge:{org_id}:{now}");
        let guard = "EXISTS (SELECT 1 FROM orgs WHERE id = ?1 AND stable_id = ?2
                       AND deleted_at IS NOT NULL AND purge_after IS NOT NULL
                       AND purge_after <= ?3)";
        let mut statements = Vec::new();
        statements.push(
            Statement::new(
                format!(
                    "UPDATE network_policy_revision_lifecycle
                 SET consumer_version = consumer_version + 1
                 WHERE state = 'active' AND {guard}
                   AND EXISTS (SELECT 1 FROM network_policy_serving_pins p
                     WHERE p.boundary_id = network_policy_revision_lifecycle.boundary_id
                       AND p.revision = network_policy_revision_lifecycle.revision
                       AND p.consumer_scope_key = ?2)"
                ),
                vals![org_id, scope, now],
            )
            .unchecked(),
        );
        for table in [
            "binding_scope_grant_pins",
            "endpoint_scope_grant_pins",
            "gateway_scope_grant_pins",
            "network_policy_serving_pins",
        ] {
            statements.push(
                Statement::new(
                    format!("DELETE FROM {table} WHERE consumer_scope_key = ?2 AND {guard}"),
                    vals![org_id, scope, now],
                )
                .unchecked(),
            );
        }
        for row in &grants {
            let kind: String = row.get(0)?;
            let stable_id: String = row.get(1)?;
            let generation: i64 = row.get(2)?;
            let grant_generation: i64 = row.get(3)?;
            let resource_version: i64 = row.get(4)?;
            let event_id = format!("grant-event:{}", uuid::Uuid::new_v4().simple());
            statements.push(
                Statement::new(
                    format!(
                        "INSERT INTO consumer_scope_grant_events
                     (event_id, resource_kind, resource_stable_id, resource_generation_key,
                      consumer_scope_key, grant_generation, transition, previous_state,
                      resulting_state, actor_id, occurred_at, request_id)
                     SELECT ?4, ?5, ?6, ?7, ?2, ?8, 'revoked', 'active', 'revoked',
                            'system:org-purge', ?3, ?9
                      WHERE {guard}
                        AND EXISTS (
                          SELECT 1 FROM binding_consumer_scopes g
                          JOIN bindings b ON b.id = g.binding_id
                           WHERE ?5 = 'binding' AND b.stable_id = ?6
                             AND ?7 = 0 AND g.consumer_scope_key = ?2
                             AND g.grant_generation = ?8 AND g.resource_version = ?10
                             AND g.state = 'active'
                          UNION ALL
                          SELECT 1 FROM network_policy_consumer_scopes g
                           WHERE ?5 = 'network_policy' AND g.boundary_id = ?6
                             AND ?7 = 0 AND g.consumer_scope_key = ?2
                             AND g.grant_generation = ?8 AND g.resource_version = ?10
                             AND g.state = 'active'
                          UNION ALL
                          SELECT 1 FROM endpoint_route_scopes g
                           WHERE ?5 = 'endpoint' AND g.endpoint_id = ?6
                             AND g.endpoint_generation = ?7 AND g.consumer_scope_key = ?2
                             AND g.grant_generation = ?8 AND g.resource_version = ?10
                             AND g.state = 'active'
                          UNION ALL
                          SELECT 1 FROM gateway_revision_route_scopes g
                           WHERE ?5 = 'gateway' AND g.gateway_id = ?6
                             AND g.generation = ?7 AND g.consumer_scope_key = ?2
                             AND g.grant_generation = ?8 AND g.resource_version = ?10
                             AND g.state = 'active')"
                    ),
                    vals![
                        org_id,
                        scope,
                        now,
                        event_id,
                        kind,
                        stable_id,
                        generation,
                        grant_generation,
                        request_id,
                        resource_version
                    ],
                )
                .expecting(1),
            );
        }
        statements.push(
            Statement::new(
                "DELETE FROM memberships
                  WHERE principal_kind = 'service_account'
                    AND principal_id IN (
                      SELECT id FROM service_accounts WHERE org_id = ?1)",
                vals![org_id],
            )
            .unchecked(),
        );
        statements.push(
            Statement::new(
                "DELETE FROM tokens
                  WHERE owner_kind = 'service_account'
                    AND owner_id IN (
                      SELECT id FROM service_accounts WHERE org_id = ?1)",
                vals![org_id],
            )
            .unchecked(),
        );
        // An operation whose primary target belongs to another organization
        // can still be authorized by a secondary target in this organization.
        // Purging only the secondary row through its scope FK would silently
        // weaken the surviving operation's authorization requirement, so
        // remove the whole cross-organization operation before its scope is
        // cascaded away.
        statements.push(
            Statement::new(
                format!(
                    "DELETE FROM topology_operations
                      WHERE {guard}
                        AND EXISTS (
                          SELECT 1 FROM operation_secondary_targets target
                          JOIN authorization_scopes auth
                            ON auth.scope_key = target.authorization_scope_key
                          WHERE target.operation_id = topology_operations.operation_id
                            AND auth.org_id = ?1)"
                ),
                vals![org_id, scope, now],
            )
            .unchecked(),
        );
        statements.push(
            Statement::new(
                "DELETE FROM orgs WHERE id = ?1 AND stable_id = ?2 AND deleted_at IS NOT NULL
               AND purge_after IS NOT NULL AND purge_after <= ?3
               AND NOT EXISTS (SELECT 1 FROM cache_write_tickets ticket
                 JOIN binary_caches cache ON cache.id = ticket.cache_id
                 WHERE cache.org_id = ?1 AND (ticket.active_cache_slot = 1 OR
                   (ticket.state = 'completed'
                     AND ticket.covered_inventory_generation IS NULL)))",
                vals![org_id, scope, now],
            )
            .expecting(1),
        );
        for table in [
            "binding_consumer_scopes",
            "network_policy_consumer_scopes",
            "endpoint_route_scopes",
            "gateway_revision_route_scopes",
        ] {
            statements.push(
                Statement::new(
                    format!(
                        "UPDATE {table} SET state = 'revoked', revoked_by = 'system:org-purge',
                     revoked_at = ?2, resource_version = resource_version + 1
                     WHERE consumer_scope_key = ?1 AND state = 'active'"
                    ),
                    vals![scope, now],
                )
                .unchecked(),
            );
            statements.push(
                Statement::new(
                    format!("DELETE FROM {table} WHERE consumer_scope_key = ?1"),
                    vals![scope],
                )
                .unchecked(),
            );
        }
        self.backend.checked_batch(&statements).await?;
        Ok(true)
    }

    // -- offboarding: ownership transfer + user deletion (v13) --------------

    /// The org slugs where `user_id` is the *sole* `Owner`.
    ///
    /// An org's human owners are non-deleted users holding the `owner` role at
    /// the org's own immutable scope (`scope_key == org.stable_id`). This
    /// returns the slugs of orgs for which `user_id` is the only human owner —
    /// exactly the orgs whose
    /// ownership must be transferred before the user can be deleted (RFC-0004
    /// offboarding). Soft-deleted orgs are skipped (they are en route to purge
    /// anyway).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn sole_owned_orgs(&self, user_id: i64) -> Result<Vec<String>> {
        // Orgs where the user is an owner at the org scope.
        let rows = self
            .backend
            .query(
                "SELECT o.id, o.slug FROM orgs o
             JOIN memberships m
               ON m.scope_key = o.stable_id
              AND m.principal_kind = 'user'
              AND m.principal_id = ?1
              AND m.role = 'owner'
             JOIN users owner_user ON owner_user.id = m.principal_id
             WHERE o.deleted_at IS NULL AND owner_user.deleted_at IS NULL",
                &vals![user_id],
            )
            .await?;
        let mut sole = Vec::new();
        for row in &rows {
            let org_slug: String = row.get(1)?;
            let owner_count: i64 = self
                .backend
                .query_opt(
                    "SELECT COUNT(*) FROM memberships m
                     JOIN orgs o ON o.stable_id = m.scope_key
                     JOIN users owner_user ON owner_user.id = m.principal_id
                     WHERE o.slug = ?1 AND m.principal_kind = 'user'
                       AND m.role = 'owner' AND owner_user.deleted_at IS NULL",
                    &vals![org_slug],
                )
                .await?
                .context("owner count query returned no row")?
                .get(0)?;
            if owner_count <= 1 {
                sole.push(org_slug);
            }
        }
        Ok(sole)
    }

    /// Creates an organization attributed to an immutable control plan.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identity, duplicate slug/plan, or database
    /// failure.
    pub async fn create_org_from_plan(&self, slug: &str, name: &str, plan_id: &str) -> Result<i64> {
        aos_hub_model::domain::iam::validate_org_slug(slug)
            .map_err(|error| anyhow::anyhow!("invalid org slug '{slug}': {error}"))?;
        let org_id = self.max_id("orgs").await? + 1;
        let consumer_scope_key = format!("org:{}", uuid::Uuid::new_v4().simple());
        let now = unix_now();
        self.backend
            .checked_batch(&[
                Statement::new(
                    "INSERT INTO orgs
                     (id, stable_id, slug, name, created_at, updated_at, creation_plan_id)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)",
                    vals![org_id, consumer_scope_key, slug, name, now, plan_id],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO org_usage (org_id, used_bytes, object_count, updated_at)
                     VALUES (?1, 0, 0, 0)",
                    vals![org_id],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO authorization_scopes
                     (scope_key, kind, org_id, parent_scope_key, resource_stable_id, created_at)
                     VALUES (?1, 'organization', ?2, 'instance', ?1, ?3)",
                    vals![consumer_scope_key, org_id, now],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO authorization_scope_ancestors
                     (descendant_scope_key, ancestor_scope_key, depth)
                     VALUES (?1, ?1, 0)",
                    vals![consumer_scope_key],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO authorization_scope_ancestors
                     (descendant_scope_key, ancestor_scope_key, depth)
                     SELECT ?1, ancestor_scope_key, depth + 1
                       FROM authorization_scope_ancestors
                      WHERE descendant_scope_key = 'instance'",
                    vals![consumer_scope_key],
                )
                .unchecked(),
            ])
            .await?;
        Ok(org_id)
    }

    /// Returns whether an organization was created by the exact control plan.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn org_matches_creation_plan(&self, org_id: i64, plan_id: &str) -> Result<bool> {
        Ok(self
            .backend
            .query_opt(
                "SELECT 1 FROM orgs WHERE id = ?1 AND creation_plan_id = ?2",
                &vals![org_id, plan_id],
            )
            .await?
            .is_some())
    }

    /// Updates organization profile metadata under an exact resource version.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn update_org_profile(
        &self,
        org_id: i64,
        display_name: &str,
        expected_resource_version: i64,
        plan_id: &str,
    ) -> Result<bool> {
        Ok(self
            .backend
            .execute(
                "UPDATE orgs SET name = ?2, resource_version = resource_version + 1,
                 updated_at = ?3, mutation_plan_id = ?5
                 WHERE id = ?1 AND deleted_at IS NULL AND resource_version = ?4",
                &vals![
                    org_id,
                    display_name,
                    unix_now(),
                    expected_resource_version,
                    plan_id
                ],
            )
            .await?
            == 1)
    }

    /// Soft-deletes an organization under an exact resource version.
    ///
    /// Returns `false` while any descendant registry or cache still has an
    /// outstanding write fence, including an inventory-uncovered cache write.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn soft_delete_org_at_version(
        &self,
        org_id: i64,
        grace_secs: i64,
        expected_resource_version: i64,
        plan_id: &str,
    ) -> Result<bool> {
        let now = unix_now();
        Ok(self
            .backend
            .execute(
                "UPDATE orgs SET deleted_at = ?2, purge_after = ?3,
                 resource_version = resource_version + 1, updated_at = ?2,
                 mutation_plan_id = ?5 WHERE id = ?1 AND deleted_at IS NULL
                 AND resource_version = ?4
                 AND NOT EXISTS (SELECT 1 FROM cache_write_tickets ticket
                   JOIN binary_caches cache ON cache.id = ticket.cache_id
                   WHERE cache.org_id = ?1 AND (ticket.active_cache_slot = 1 OR
                     (ticket.state = 'completed'
                       AND ticket.covered_inventory_generation IS NULL)))",
                &vals![
                    org_id,
                    now,
                    now + grace_secs,
                    expected_resource_version,
                    plan_id
                ],
            )
            .await?
            == 1)
    }

    /// Returns whether the latest organization mutation used the exact plan.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn org_matches_mutation_plan(&self, org_id: i64, plan_id: &str) -> Result<bool> {
        Ok(self
            .backend
            .query_opt(
                "SELECT 1 FROM orgs WHERE id = ?1 AND mutation_plan_id = ?2",
                &vals![org_id, plan_id],
            )
            .await?
            .is_some())
    }

    /// Look up an organization by slug, *including* soft-deleted ones.
    ///
    /// The admin-visible variant of [`Database::org_by_slug`]: it resolves an
    /// org even after it has been soft-deleted, so the restore and export
    /// paths can act on it during its grace window.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn org_by_slug_including_deleted(&self, slug: &str) -> Result<Option<OrgRecord>> {
        self.backend
            .query_opt(
                "SELECT id, stable_id, slug, name, created_at, resource_version, updated_at FROM orgs WHERE slug = ?1",
                &vals![slug],
            )
            .await
            .context("loading org by slug (incl. deleted)")?
            .map(|row| row_to_org(&row))
            .transpose()
    }

    /// Resolves one canonical, live authorization scope to its owner tuple.
    ///
    /// The returned values are `(kind, org_id, project_id)`. Instance scope has
    /// no organization or project; organization scope has only `org_id`; exact
    /// project scope has both identifiers.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn authorization_scope_owner(
        &self,
        scope_key: &str,
    ) -> Result<Option<(String, Option<i64>, Option<i64>)>> {
        self.backend
            .query_opt(
                "SELECT a.kind, a.org_id, p.id
                   FROM authorization_scopes a
                   LEFT JOIN orgs o ON o.id = a.org_id
                   LEFT JOIN projects p ON p.scope_key = a.scope_key
                  WHERE a.scope_key = ?1 AND a.retired_at IS NULL
                    AND a.kind IN ('instance', 'organization', 'project')
                    AND (a.kind = 'instance' OR o.deleted_at IS NULL)",
                &vals![scope_key],
            )
            .await?
            .map(|row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .transpose()
    }

    // -- operations: quotas, usage, signup policy, offboarding (v13) ---------

    /// Set (or replace) an org's quota caps.
    ///
    /// Each cap is optional: pass `None` to leave that dimension unlimited.
    /// Upserts the single `org_quotas` row.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn set_org_quota(&self, org_id: i64, quota: &OrgQuota) -> Result<()> {
        self.backend.execute(
            "INSERT INTO org_quotas (org_id, max_bytes, max_objects, max_registries, max_tokens)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(org_id) DO UPDATE SET
                 max_bytes = excluded.max_bytes,
                 max_objects = excluded.max_objects,
                 max_registries = excluded.max_registries,
                 max_tokens = excluded.max_tokens",
            &vals![
                org_id,
                quota.max_bytes,
                quota.max_objects,
                quota.max_registries,
                quota.max_tokens,
            ],
        ).await?;
        Ok(())
    }

    /// Look up an org's quota caps.
    ///
    /// Returns [`OrgQuota::default`] (all dimensions unlimited) when the org
    /// has no `org_quotas` row.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn org_quota(&self, org_id: i64) -> Result<OrgQuota> {
        let row = self
            .backend
            .query_opt(
                "SELECT max_bytes, max_objects, max_registries, max_tokens
             FROM org_quotas WHERE org_id = ?1",
                &vals![org_id],
            )
            .await?;
        match row {
            Some(row) => Ok(OrgQuota {
                max_bytes: row.get(0)?,
                max_objects: row.get(1)?,
                max_registries: row.get(2)?,
                max_tokens: row.get(3)?,
            }),
            None => Ok(OrgQuota::default()),
        }
    }

    /// Look up an org's current usage totals.
    ///
    /// Returns [`OrgUsage::default`] (all zero) when the org has no
    /// `org_usage` row yet.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn org_usage(&self, org_id: i64) -> Result<OrgUsage> {
        let row = self
            .backend
            .query_opt(
                "SELECT used_bytes, object_count, updated_at FROM org_usage WHERE org_id = ?1",
                &vals![org_id],
            )
            .await?;
        match row {
            Some(row) => Ok(OrgUsage {
                used_bytes: row.get(0)?,
                object_count: row.get(1)?,
                updated_at: row.get(2)?,
            }),
            None => Ok(OrgUsage::default()),
        }
    }

    /// Add `delta_bytes`/`delta_objects` to an org's running usage totals.
    ///
    /// Upserts the `org_usage` row, creating it on first use. Called by the
    /// typed upload path after a successful write of a new object. The totals are
    /// approximate (see [`OrgUsage`]).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn add_org_usage(
        &self,
        org_id: i64,
        delta_bytes: i64,
        delta_objects: i64,
    ) -> Result<()> {
        self.backend
            .execute(
                "INSERT INTO org_usage (org_id, used_bytes, object_count, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(org_id) DO UPDATE SET
                 used_bytes = org_usage.used_bytes + excluded.used_bytes,
                 object_count = org_usage.object_count + excluded.object_count,
                 updated_at = excluded.updated_at",
                &vals![org_id, delta_bytes, delta_objects, unix_now()],
            )
            .await?;
        Ok(())
    }

    /// Atomically check an org's quota and, if the write fits, reserve it.
    ///
    /// In a single transaction this reads the org's `max_bytes`/`max_objects`
    /// caps and current usage, decides whether applying `delta_bytes` (which
    /// may be negative on a shrinking overwrite) and `delta_objects` keeps both
    /// dimensions within their caps, and — only when it fits — updates
    /// `org_usage` by the deltas. Returns `true` when the reservation was made,
    /// `false` when it would exceed a cap (no update performed).
    ///
    /// Folding the check and the update into one transaction closes the
    /// check-then-write TOCTOU window that a separate `would_exceed_quota`
    /// followed by `add_org_usage` left open: two concurrent uploads can no
    /// longer both observe headroom and then both consume it. Usage is clamped
    /// at zero so a negative delta never drives the stored total below zero.
    ///
    /// A `NULL`/absent cap is unlimited for that dimension. An org with no
    /// `org_usage` row is treated as zero usage and a row is inserted.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn reserve_org_usage(
        &self,
        org_id: i64,
        delta_bytes: i64,
        delta_objects: i64,
    ) -> Result<bool> {
        // Optimistic concurrency in place of the interactive transaction (so
        // this runs on HubDb): read caps + current usage, check the cap in Rust
        // (kept out of SQL to stay dialect-portable — no GREATEST/MAX scalar),
        // then write the new totals behind a compare-and-set guard. A
        // concurrent reservation that moved usage since the read fails the CAS
        // (0 rows) and we re-read and retry, so the quota cannot be oversold.
        const MAX_ATTEMPTS: usize = 8;
        let now = unix_now();
        for _ in 0..MAX_ATTEMPTS {
            let caps = self
                .backend
                .query_opt(
                    "SELECT max_bytes, max_objects FROM org_quotas WHERE org_id = ?1",
                    &vals![org_id],
                )
                .await?;
            let (max_bytes, max_objects): (Option<i64>, Option<i64>) = match caps {
                Some(row) => (row.get(0)?, row.get(1)?),
                None => (None, None),
            };
            let usage = self
                .backend
                .query_opt(
                    "SELECT used_bytes, object_count FROM org_usage WHERE org_id = ?1",
                    &vals![org_id],
                )
                .await?;
            let (used_bytes, object_count, row_exists): (i64, i64, bool) = match usage {
                Some(row) => (row.get(0)?, row.get(1)?, true),
                None => (0, 0, false),
            };

            let new_bytes = used_bytes.saturating_add(delta_bytes).max(0);
            let new_objects = object_count.saturating_add(delta_objects).max(0);

            if max_bytes.is_some_and(|max| new_bytes > max)
                || max_objects.is_some_and(|max| new_objects > max)
            {
                return Ok(false);
            }

            // It fits: reserve, but only if usage is unchanged since the read.
            let affected =
                if row_exists {
                    self.backend.execute(
                    "UPDATE org_usage SET used_bytes = ?2, object_count = ?3, updated_at = ?4
                     WHERE org_id = ?1 AND used_bytes = ?5 AND object_count = ?6",
                    &vals![org_id, new_bytes, new_objects, now, used_bytes, object_count],
                ).await?
                } else {
                    self.backend
                        .execute(
                            "INSERT INTO org_usage (org_id, used_bytes, object_count, updated_at)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(org_id) DO NOTHING",
                            &vals![org_id, new_bytes, new_objects, now],
                        )
                        .await?
                };
            if affected == 1 {
                return Ok(true);
            }
            // Raced with a concurrent reservation; re-read and retry.
        }
        bail!("reserve_org_usage: too much write contention on org {org_id}")
    }

    /// The number of registries owned by an org.
    ///
    /// Used by the registry-create quota gate.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn org_registry_count(&self, org_id: i64) -> Result<i64> {
        self.backend
            .query_opt(
                "SELECT COUNT(*) FROM registries WHERE org_id = ?1",
                &vals![org_id],
            )
            .await?
            .context("registry count query returned no row")?
            .get(0)
    }

    /// Whether an org exists and is not soft-deleted.
    ///
    /// The serving paths consult this to stop serving a tombstoned org's
    /// registries without disclosing their existence.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn org_is_active(&self, org_id: i64) -> Result<bool> {
        let row = self
            .backend
            .query_opt(
                "SELECT 1 FROM orgs WHERE id = ?1 AND deleted_at IS NULL",
                &vals![org_id],
            )
            .await?;
        Ok(row.is_some())
    }

    /// Transfer org ownership from one user to another at the org scope.
    ///
    /// Grants `to_user` the `owner` role at `org.stable_id` and revokes `from_user`'s
    /// owner grant there, in one transaction. The recipient need not have been
    /// a member previously. Returns an error when the org is unknown.
    ///
    /// # Errors
    ///
    /// Returns an error when no org has `org_id`, or on database failure.
    pub async fn transfer_org_ownership(
        &self,
        org_id: i64,
        from_user: i64,
        to_user: i64,
    ) -> Result<()> {
        if from_user == to_user {
            bail!("ownership transfer requires two distinct users");
        }
        let org = self
            .org_by_id(org_id)
            .await?
            .with_context(|| format!("no org with id {org_id}"))?;
        let now = unix_now();
        // Two self-contained writes with all values known up front: a batch,
        // so this commits atomically on both native SQL and Worker HubDb.
        self.backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE authorization_scopes
                        SET owner_guard_version = owner_guard_version + 1
                      WHERE scope_key = ?3
                        AND EXISTS (SELECT 1 FROM users recipient
                                     WHERE recipient.id = ?2 AND recipient.deleted_at IS NULL)
                        AND EXISTS (SELECT 1 FROM memberships source_owner
                                    JOIN users source_user
                                      ON source_user.id = source_owner.principal_id
                                   WHERE source_owner.scope_key = ?3
                                     AND source_owner.principal_kind = 'user'
                                     AND source_owner.principal_id = ?1
                                     AND source_owner.role = 'owner'
                                     AND source_user.deleted_at IS NULL)",
                    vals![from_user, to_user, org.stable_id],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO memberships
                 (principal_kind, principal_id, scope_key, role, created_at)
                 VALUES ('user', ?1, ?2, 'owner', ?3)
                 ON CONFLICT(principal_kind, principal_id, scope_key)
                 DO UPDATE SET role = excluded.role",
                    vals![to_user, org.stable_id, now].to_vec(),
                )
                .unchecked(),
                Statement::new(
                    "DELETE FROM memberships
                 WHERE principal_kind = 'user' AND principal_id = ?1 AND scope_key = ?2",
                    vals![from_user, org.stable_id].to_vec(),
                )
                .expecting(1),
            ])
            .await?;
        Ok(())
    }
}
