//! Placements reads in the topology capability.

use super::*;

impl Database {
    /// Lists placements belonging to one surface in selection order.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_surface_placements(
        &self,
        surface: SurfaceTarget,
    ) -> Result<Vec<SurfacePlacementRecord>> {
        let (registry_id, cache_id) = surface.ids();
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {PLACEMENT_COLUMNS} FROM surface_placement_effective
             WHERE registry_id = ?1 OR cache_id = ?2
             ORDER BY read_order, name"
                ),
                &vals![registry_id, cache_id],
            )
            .await?;
        rows.iter().map(row_to_surface_placement).collect()
    }

    /// Lists placements that may safely serve one read in deterministic order.
    ///
    /// Every returned placement is read-enabled, ready or degraded, complete,
    /// and non-archive. Registry pointer reads additionally require the
    /// placement watermark to equal the registry's authoritative current
    /// publication. Mutable and immutable reads both require exact `present`
    /// hash-and-size evidence. Missing, incomplete, or tombstoned inventory
    /// fails closed. The returned plan distinguishes an unknown object from a
    /// miss that contradicts authoritative current object inventory.
    ///
    /// Results are ordered by `read_order`, placement name, then database id.
    ///
    /// # Errors
    ///
    /// Returns an error when a current-publication read targets a cache, an
    /// object key is invalid, or the database query fails.
    pub async fn readable_surface_placements(
        &self,
        surface: SurfaceTarget,
        requirement: PlacementReadRequirement<'_>,
    ) -> Result<PlacementReadPlan> {
        let (registry_id, cache_id) = surface.ids();
        let eligibility = "p.effective_read_enabled = 1
            AND p.state IN ('ready', 'degraded')
            AND p.kind = 'complete'
            AND p.completeness = 'complete'
            AND p.derived_role <> 'archive'";
        let (sql, values) = match requirement {
            PlacementReadRequirement::RegistryCurrentPublication(object_key) => {
                let Some(registry_id) = registry_id else {
                    bail!("current-publication placement reads require a registry");
                };
                validate_key_bytes(object_key, "surface object key", 512)?;
                (
                    format!(
                        "SELECT {PLACEMENT_COLUMNS},
                           CASE WHEN {eligibility}
                             AND p.mutable_publication_id IS NOT NULL
                             AND p.mutable_publication_id = (
                               SELECT ps.current_publication_id
                               FROM registry_publication_state ps
                               WHERE ps.registry_id = ?1)
                             AND EXISTS (SELECT 1 FROM surface_objects o
                               JOIN registry_publication_state ps
                                 ON ps.registry_id = o.registry_id
                               JOIN object_placements op
                                 ON op.surface_object_id = o.id
                                AND op.placement_id = p.id
                               WHERE o.registry_id = ?1 AND o.object_key = ?2
                                 AND o.object_kind = 'mutable_pointer'
                                 AND o.lifecycle_state = 'active'
                                 AND o.mutable_publication_id = ps.current_publication_id
                                 AND o.content_hash IS NOT NULL AND o.size IS NOT NULL
                                 AND op.state = 'present'
                                 AND op.observed_hash = o.content_hash
                                 AND op.observed_size = o.size)
                           THEN 1 ELSE 0 END,
                           CASE WHEN EXISTS (SELECT 1 FROM surface_objects o
                             JOIN registry_publication_state ps
                               ON ps.registry_id = o.registry_id
                             WHERE o.registry_id = ?1 AND o.object_key = ?2
                               AND o.object_kind = 'mutable_pointer'
                               AND o.lifecycle_state = 'active'
                               AND o.mutable_publication_id = ps.current_publication_id)
                           THEN 1 ELSE 0 END
                         FROM surface_placement_effective p
                         WHERE p.registry_id = ?1
                         ORDER BY p.read_order, p.name, p.id"
                    ),
                    vals![registry_id, object_key],
                )
            }
            PlacementReadRequirement::ImmutableObject(object_key) => {
                validate_key_bytes(object_key, "surface object key", 512)?;
                (
                    format!(
                        "SELECT {PLACEMENT_COLUMNS},
                           CASE WHEN {eligibility} AND EXISTS (SELECT 1 FROM surface_objects o
                                 JOIN object_placements op
                                   ON op.surface_object_id = o.id
                                  AND op.placement_id = p.id
                                 WHERE (o.registry_id = ?1 OR o.cache_id = ?2)
                                   AND o.object_key = ?3
                                   AND o.object_kind = 'immutable'
                                   AND o.lifecycle_state = 'active'
                                   AND o.content_hash IS NOT NULL
                                   AND o.size IS NOT NULL
                                   AND op.state = 'present'
                                   AND op.observed_hash = o.content_hash
                                   AND op.observed_size = o.size)
                           THEN 1 ELSE 0 END,
                           CASE WHEN EXISTS (SELECT 1 FROM surface_objects o
                             WHERE (o.registry_id = ?1 OR o.cache_id = ?2)
                               AND o.object_key = ?3
                               AND o.object_kind = 'immutable'
                               AND o.lifecycle_state = 'active')
                           THEN 1 ELSE 0 END
                         FROM surface_placement_effective p
                         WHERE (p.registry_id = ?1 OR p.cache_id = ?2)
                         ORDER BY p.read_order, p.name, p.id"
                    ),
                    vals![registry_id, cache_id, object_key],
                )
            }
            PlacementReadRequirement::Untracked => (
                format!(
                    "SELECT {PLACEMENT_COLUMNS},
                       CASE WHEN {eligibility} THEN 1 ELSE 0 END,
                       0
                     FROM surface_placement_effective p
                     WHERE (p.registry_id = ?1 OR p.cache_id = ?2)
                     ORDER BY p.read_order, p.name, p.id"
                ),
                vals![registry_id, cache_id],
            ),
        };
        let rows = self.backend.query(&sql, &values).await?;
        let candidates = rows
            .iter()
            .filter_map(|row| match row.get::<bool>(PLACEMENT_COLUMN_COUNT) {
                Ok(true) => Some(row_to_surface_placement(row)),
                Ok(false) => None,
                Err(error) => Some(Err(error)),
            })
            .collect::<Result<Vec<_>>>()?;
        let miss_is_inconsistent = rows
            .first()
            .map(|row| row.get::<bool>(PLACEMENT_COLUMN_COUNT + 1))
            .transpose()?
            .unwrap_or(false);
        let has_policy_only_shards = rows
            .iter()
            .map(row_to_surface_placement)
            .collect::<Result<Vec<_>>>()?
            .iter()
            .any(|placement| placement.kind == "shard");
        Ok(PlacementReadPlan {
            has_configured_placements: !rows.is_empty(),
            has_policy_only_shards,
            candidates,
            miss_is_inconsistent,
        })
    }

    /// Lists confirmed placement equivalences for one surface.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn list_placement_equivalences(
        &self,
        surface: SurfaceTarget,
    ) -> Result<Vec<PlacementEquivalenceRecord>> {
        let (registry_id, cache_id) = surface.ids();
        self.backend
            .query(
                "SELECT equivalence.id, a.name, b.name, equivalence.evidence_digest,
                        equivalence.state, equivalence.creation_token,
                        equivalence.confirmed_at, equivalence.resource_version
                 FROM placement_equivalences equivalence
                 JOIN surface_placements a ON a.id = equivalence.placement_a_id
                 JOIN surface_placements b ON b.id = equivalence.placement_b_id
                 WHERE a.registry_id = ?1 OR a.cache_id = ?2
                 ORDER BY equivalence.id",
                &vals![registry_id, cache_id],
            )
            .await?
            .iter()
            .map(|row| {
                Ok(PlacementEquivalenceRecord {
                    id: row.get(0)?,
                    surface,
                    placement_a: row.get(1)?,
                    placement_b: row.get(2)?,
                    evidence_digest: row.get(3)?,
                    state: row.get(4)?,
                    creation_token: row.get(5)?,
                    confirmed_at: row.get(6)?,
                    resource_version: row.get(7)?,
                })
            })
            .collect()
    }
}
