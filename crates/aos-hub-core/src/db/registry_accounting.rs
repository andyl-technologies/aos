//! Shared logical accounting for positively verified registry publications.
//!
//! A versioned origin is written only by a fresh publication placeholder or
//! standalone mirror insertion. Legacy catalogue rows never acquire an inferred
//! charge from placement, hash, time or provider observations.

use anyhow::{Context as _, Result, ensure};

use crate::backend::CheckedStatement;

use super::Database;

impl Database {
    /// Checks whether a registry object has a known logical accounting origin.
    ///
    /// This read grants no provider permission. Completion rechecks the origin,
    /// current owner and retained ledger under row locks in its checked batch.
    ///
    /// # Errors
    /// Refuses absent, inactive, non-registry or unknown legacy objects, changed
    /// charge ownership, malformed accounting records or database failure.
    pub async fn verified_registry_object_accounting_eligibility(
        &self,
        object_id: i64,
    ) -> Result<()> {
        let row = self.backend.query_opt(
            "SELECT registry.org_id, object.accounting_origin_version
               FROM surface_objects object JOIN registries registry ON registry.id = object.registry_id
              WHERE object.id = ?1 AND object.cache_id IS NULL AND object.lifecycle_state = 'active'",
            &vals![object_id],
        ).await?.context("verified registry accounting object is absent")?;
        let org_id: Option<i64> = row.get(0)?;
        let origin: Option<i64> = row.get(1)?;
        ensure!(
            origin.is_none_or(|version| version == 7),
            "registry accounting origin is invalid"
        );
        match self.surface_object_usage(object_id).await? {
            Some(charge) => ensure!(charge.org_id == org_id, "registry charge owner changed"),
            None => ensure!(
                origin == Some(7),
                "registry accounting origin is unknown; explicit reset or import is required"
            ),
        }
        Ok(())
    }

    /// Builds accounting and presence for an ordinary verified publication copy.
    ///
    /// The organization, quota, totals, registry, publication, catalogue and
    /// physical placement rows are locked before eligibility is rechecked. All
    /// charge and copy mutations execute together in the caller's checked batch.
    ///
    /// # Errors
    /// Refuses unknown accounting origins, changed object or placement identity,
    /// inconsistent ownership, invalid receipt fields or database failure.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn verified_registry_publication_presence_statements(
        &self,
        publication_id: &str,
        object_id: i64,
        placement_id: i64,
        hash: &str,
        size: i64,
        etag: Option<&str>,
        now: i64,
        fence: Option<(i64, i64)>,
    ) -> Result<Vec<CheckedStatement>> {
        self.verified_registry_object_accounting_eligibility(object_id)
            .await?;
        let row = self.backend.query_opt(
            "SELECT registry.id, registry.org_id, registry.resource_version,
                    object.resource_version, placement.binding_id,
                    placement.resource_version, binding.resource_version
               FROM surface_objects object JOIN registries registry ON registry.id = object.registry_id
               JOIN surface_placements placement ON placement.registry_id = registry.id
               JOIN bindings binding ON binding.id = placement.binding_id
              WHERE object.id = ?1 AND placement.id = ?2 AND object.lifecycle_state = 'active'",
            &vals![object_id, placement_id],
        ).await?.context("verified publication target disappeared")?;
        let registry_id: i64 = row.get(0)?;
        let org_id: Option<i64> = row.get(1)?;
        let registry_version: i64 = row.get(2)?;
        let object_version: i64 = row.get(3)?;
        let binding_id: i64 = row.get(4)?;
        let placement_version: i64 = row.get(5)?;
        let binding_version: i64 = row.get(6)?;
        ensure!(
            fence.is_none_or(|pins| pins == (placement_version, binding_version)),
            "verified publication placement changed"
        );
        let charge = self.surface_object_usage(object_id).await?;

        let mut statements = Self::verified_registry_accounting_owner_locks(org_id);
        statements.extend([
            CheckedStatement::exact(
                "UPDATE registries SET updated_at = updated_at WHERE id = ?1 AND resource_version = ?2",
                vals![registry_id, registry_version], 1,
            ),
            CheckedStatement::exact(
                "UPDATE registry_publication_state SET resource_version = resource_version WHERE registry_id = ?1",
                vals![registry_id], 1,
            ),
            CheckedStatement::exact(
                "UPDATE registry_publications SET mutation_version = mutation_version
                  WHERE publication_id = ?1 AND registry_id = ?2 AND state IN ('preparing', 'writing_pointers')",
                vals![publication_id, registry_id], 1,
            ),
            CheckedStatement::exact(
                "UPDATE surface_objects SET updated_at = updated_at
                  WHERE id = ?1 AND registry_id = ?2 AND resource_version = ?3 AND lifecycle_state = 'active'",
                vals![object_id, registry_id, object_version], 1,
            ),
            CheckedStatement::exact(
                "UPDATE bindings SET updated_at = updated_at WHERE id = ?1 AND resource_version = ?2",
                vals![binding_id, binding_version], 1,
            ),
            CheckedStatement::exact(
                "UPDATE surface_placements SET updated_at = updated_at
                  WHERE id = ?1 AND registry_id = ?2 AND resource_version = ?3 AND binding_id = ?4",
                vals![placement_id, registry_id, placement_version, binding_id], 1,
            ),
            CheckedStatement::exact(
                "UPDATE registry_publication_objects SET expected_size = expected_size
                  WHERE publication_id = ?1 AND surface_object_id = ?2 AND registry_id = ?3
                    AND expected_hash = ?4 AND expected_size = ?5",
                vals![publication_id, object_id, registry_id, hash, size], 1,
            ),
        ]);
        statements.extend(
            self.verified_registry_object_usage_statements(
                object_id,
                org_id,
                charge.as_ref(),
                size,
                now,
            )
            .await?,
        );
        statements.extend(Self::registry_publication_object_presence_statements(
            publication_id,
            object_id,
            placement_id,
            hash,
            size,
            etag,
            now,
            Some((placement_version, binding_version)),
        )?);
        Ok(statements)
    }

    pub(crate) fn verified_registry_accounting_owner_locks(
        org_id: Option<i64>,
    ) -> Vec<CheckedStatement> {
        let Some(org_id) = org_id else {
            return Vec::new();
        };
        vec![
            CheckedStatement::exact(
                "UPDATE orgs SET updated_at = updated_at WHERE id = ?1",
                vals![org_id],
                1,
            ),
            // Materializing an unlimited cap row makes a concurrent first cap
            // insertion serialize with verification instead of racing absence.
            CheckedStatement::unchecked(
                "INSERT INTO org_quotas(org_id) VALUES (?1) ON CONFLICT(org_id) DO NOTHING",
                vals![org_id],
            ),
            CheckedStatement::exact(
                "UPDATE org_quotas SET max_bytes = max_bytes WHERE org_id = ?1",
                vals![org_id],
                1,
            ),
            CheckedStatement::exact(
                "UPDATE org_usage SET updated_at = updated_at WHERE org_id = ?1",
                vals![org_id],
                1,
            ),
        ]
    }

    pub(crate) fn verified_registry_object_accounting_fence(
        object_id: i64,
        org_id: Option<i64>,
    ) -> CheckedStatement {
        CheckedStatement::exact(
            "UPDATE surface_objects SET updated_at = updated_at
              WHERE id = ?1 AND cache_id IS NULL AND lifecycle_state = 'active'
                AND EXISTS (SELECT 1 FROM registries registry WHERE registry.id = surface_objects.registry_id
                  AND (registry.org_id = CAST(?2 AS BIGINT)
                    OR (registry.org_id IS NULL AND CAST(?2 AS BIGINT) IS NULL)))
                AND (accounting_origin_version = 7 OR EXISTS
                  (SELECT 1 FROM surface_object_usage charge WHERE charge.surface_object_id = surface_objects.id
                    AND (charge.org_id = CAST(?2 AS BIGINT)
                      OR (charge.org_id IS NULL AND CAST(?2 AS BIGINT) IS NULL))))",
            vals![object_id, org_id], 1,
        )
    }
}
