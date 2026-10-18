//! Configuration helpers in the registries capability.

use super::*;

impl Database {
    pub(in crate::db) fn registry_image_presence_statements(
        registry_id: i64,
        placement_id: i64,
        objects: &[VerifiedRegistryImageObject],
        observed_at: i64,
    ) -> Result<Vec<CheckedStatement>> {
        let generation = observed_at.max(1);
        let mut statements = Vec::with_capacity(objects.len().saturating_mul(3) + 2);
        for object in objects {
            if object.byte_size <= 0 {
                bail!("verified registry image object size must be positive");
            }
            let is_snapshot =
                object.strong_etag == format!("\"snapshot-sha256-{}\"", object.sha256);
            if is_snapshot {
                statements.push(
                    Statement::new(
                        "INSERT INTO image_snapshots(digest, byte_size, state, created_at)
                     VALUES (?1, ?2, 'live', ?3)
                     ON CONFLICT(digest) DO UPDATE SET
                       state = 'live'
                     WHERE image_snapshots.byte_size = excluded.byte_size",
                        vals![object.sha256, object.byte_size, observed_at].to_vec(),
                    )
                    .unchecked(),
                );
                statements.push(
                    Statement::new(
                        "DELETE FROM image_snapshot_references
                     WHERE digest = ?1 AND registry_id = ?2
                       AND placement_id = ?3 AND object_key = ?4",
                        vals![object.sha256, registry_id, placement_id, object.object_key].to_vec(),
                    )
                    .unchecked(),
                );
                statements.push(
                    Statement::new(
                        "INSERT INTO image_snapshot_references
                       (digest, registry_id, placement_id, object_key)
                     SELECT digest, ?2, ?3, ?4 FROM image_snapshots
                     WHERE digest = ?1 AND byte_size = ?5",
                        vals![
                            object.sha256,
                            registry_id,
                            placement_id,
                            object.object_key,
                            object.byte_size
                        ]
                        .to_vec(),
                    )
                    .expecting(1),
                );
            }
            statements.push(
                Statement::new(
                    "DELETE FROM object_placements
                 WHERE registry_id = ?1 AND placement_id = ?2
                   AND surface_object_id IN (
                     SELECT id FROM surface_objects
                     WHERE registry_id = ?1 AND object_key = ?3)",
                    vals![registry_id, placement_id, object.object_key].to_vec(),
                )
                .unchecked(),
            );
            statements.push(
                Statement::new(
                    "INSERT INTO object_placements
                 (surface_object_id, cache_id, registry_id, placement_id,
                  state, observed_hash, observed_size, etag,
                  observed_inventory_generation, observed_at,
                  catalog_object_resource_version)
                 SELECT root.surface_object_id, NULL, root.registry_id, placement.id,
                        'present', ?4, ?5, ?6, ?7, ?7,
                        object.resource_version
                 FROM registry_image_roots root
                 JOIN surface_objects object
                   ON object.id = root.surface_object_id
                  AND object.registry_id = root.registry_id
                 JOIN surface_placements placement
                   ON placement.id = ?2 AND placement.registry_id = root.registry_id
                 WHERE root.registry_id = ?1 AND object.object_key = ?3
                   AND root.expected_hash = ?4 AND root.expected_size = ?5
                   AND object.content_hash = ?4 AND object.size = ?5
                   AND (?8 = 0 OR EXISTS (
                     SELECT 1 FROM image_snapshot_references reference
                     WHERE reference.digest = ?4 AND reference.registry_id = ?1
                       AND reference.placement_id = ?2 AND reference.object_key = ?3))
                 ",
                    vals![
                        registry_id,
                        placement_id,
                        object.object_key,
                        object.sha256,
                        object.byte_size,
                        object.strong_etag,
                        generation,
                        is_snapshot
                    ]
                    .to_vec(),
                )
                .expecting(1),
            );
        }
        statements.push(
            Statement::new(
                "DELETE FROM image_snapshot_references
             WHERE registry_id = ?1 AND NOT EXISTS (
               SELECT 1 FROM registry_image_roots root
               JOIN surface_objects object ON object.id = root.surface_object_id
               WHERE root.registry_id = image_snapshot_references.registry_id
                 AND object.object_key = image_snapshot_references.object_key
                 AND root.expected_hash = image_snapshot_references.digest)",
                vals![registry_id].to_vec(),
            )
            .unchecked(),
        );
        statements.push(
            Statement::new(
                "UPDATE image_snapshots SET state = 'collectible'
             WHERE NOT EXISTS (
               SELECT 1 FROM image_snapshot_references reference
               WHERE reference.digest = image_snapshots.digest)",
                Vec::new(),
            )
            .unchecked(),
        );
        Ok(statements)
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::db) async fn create_managed_registry_with_plan(
        &self,
        org_id: i64,
        project_path: &str,
        name: &str,
        visibility: &str,
        trust_keys: &[String],
        require_signatures: bool,
        crawl_policy: &str,
        creation_plan_id: Option<&str>,
    ) -> Result<i64> {
        let org = self
            .org_by_id(org_id)
            .await?
            .with_context(|| format!("no org with id {org_id}"))?;
        let slug = canonical_slug(&org.slug, project_path, name);
        let owner_scope_key = if project_path.is_empty() {
            org.stable_id.clone()
        } else {
            self.backend
                .query_opt(
                    "SELECT scope_key FROM projects WHERE org_id = ?1 AND path = ?2",
                    &vals![org_id, project_path],
                )
                .await?
                .with_context(|| format!("no project '{project_path}' in org '{}'", org.slug))?
                .get(0)?
        };
        if self.registry_by_slug(&slug).await?.is_some() {
            bail!("a registry already exists at '{slug}'");
        }
        // Resource locators are unique across registries and caches.
        if self.binary_cache_by_slug(&slug).await?.is_some() {
            bail!(
                "a cache already exists at '{slug}' (slugs are unique across registries and caches)"
            );
        }
        // Per-org registry-count quota (NULL/unset = unlimited).
        if let Some(max_registries) = self.org_quota(org_id).await?.max_registries {
            if self.org_registry_count(org_id).await? >= max_registries {
                bail!("org registry quota of {max_registries} reached");
            }
        }
        let incarnation = uuid::Uuid::new_v4();
        let id = portable_relational_id(incarnation);
        let stable_id = format!("registry:{}", incarnation.simple());
        let now = unix_now();
        self.backend
            .checked_batch(&[
                Statement::new(
                    "INSERT INTO authorization_scopes
                     (scope_key, kind, org_id, parent_scope_key, resource_stable_id, created_at)
                     VALUES (?1, 'registry', ?2, ?3, ?1, ?4)",
                    vals![stable_id, org_id, owner_scope_key, now],
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
                    "INSERT INTO registries
                     (id, stable_id, slug, trust_keys, require_signatures, created_at,
                      org_id, project_path, visibility, scope_key, owner_scope_key,
                      crawl_policy, creation_plan_id)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?2, ?10, ?11, ?12)",
                    vals![
                        id,
                        stable_id,
                        slug,
                        serde_json::to_string(trust_keys)?,
                        require_signatures,
                        now,
                        org_id,
                        project_path,
                        visibility,
                        owner_scope_key,
                        crawl_policy,
                        creation_plan_id,
                    ],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO registry_index (registry_id, state) VALUES (?1, 'empty')",
                    vals![id],
                )
                .expecting(1),
            ])
            .await?;
        // A freshly-created registry has nothing published yet, so it starts in
        // the terminal `empty` state — not `indexing` (which reads as work in
        // progress). The indexer's transient-error guard protects this state, so
        // a flaky `info/refs` read can't bump an empty registry to `pending`; the
        // first successful surface read after a publish moves it to `fresh`.
        Ok(id)
    }
}
