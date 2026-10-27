//! Integration mutations in the caches capability.

use super::*;

impl Database {
    /// Creates or version-updates one registry-to-cache population effect.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed selectors, invalid vocabulary, a policy
    /// on another cache, missing resources, stale version, or database failure.
    pub async fn set_cache_population_target(
        &self,
        input: &SetCachePopulationTarget,
    ) -> Result<CachePopulationTargetRecord> {
        validate_json_object(&input.selector_json, "population selector")?;
        if !matches!(
            input.trigger_kind.as_str(),
            "release" | "manual" | "continuous"
        ) {
            bail!(
                "invalid population trigger '{}', expected release, manual, or continuous",
                input.trigger_kind
            );
        }
        if !matches!(
            input.validation_gate.as_str(),
            "none" | "presence" | "integrity"
        ) {
            bail!(
                "invalid population validation gate '{}'",
                input.validation_gate
            );
        }
        let now = unix_now();
        let affected = if let Some(version) = input.expected_version {
            self.backend
                .execute(
                    "UPDATE cache_population_targets SET required = ?4,
                    placement_policy_revision_id = ?5,
                    placement_policy_revision_state = CASE WHEN ?5 IS NULL
                      THEN NULL ELSE 'published' END, selector_json = ?6,
                    validation_gate = ?7, enabled = ?8,
                    resource_version = resource_version + 1, updated_at = ?9
                 WHERE cache_id = ?1 AND registry_id = ?2 AND trigger_kind = ?3
                   AND resource_version = ?10
                   AND (?5 IS NULL OR EXISTS (SELECT 1 FROM placement_policy_revisions
                       WHERE id = ?5 AND cache_id = ?1 AND state = 'published'))",
                    &vals![
                        input.cache_id,
                        input.registry_id,
                        input.trigger_kind,
                        input.required,
                        input.placement_policy_revision_id,
                        input.selector_json,
                        input.validation_gate,
                        input.enabled,
                        now,
                        version
                    ],
                )
                .await?
        } else {
            self.backend
                .execute(
                    "INSERT INTO cache_population_targets (cache_id, registry_id,
                    trigger_kind, required, placement_policy_revision_id,
                    placement_policy_revision_state, selector_json,
                    validation_gate, enabled, created_at, updated_at)
                 SELECT c.id, r.id, ?3, ?4, ?5,
                        CASE WHEN ?5 IS NULL THEN NULL ELSE 'published' END,
                        ?6, ?7, ?8, ?9, ?9
                 FROM binary_caches c CROSS JOIN registries r WHERE c.id = ?1 AND r.id = ?2
                   AND (?5 IS NULL OR EXISTS (SELECT 1 FROM placement_policy_revisions
                       WHERE id = ?5 AND cache_id = c.id AND state = 'published'))",
                    &vals![
                        input.cache_id,
                        input.registry_id,
                        input.trigger_kind,
                        input.required,
                        input.placement_policy_revision_id,
                        input.selector_json,
                        input.validation_gate,
                        input.enabled,
                        now
                    ],
                )
                .await?
        };
        if affected != 1 {
            bail!("population target is missing, duplicated, stale, or topologically incompatible");
        }
        self.cache_population_target(input.cache_id, input.registry_id, &input.trigger_kind)
            .await?
            .context("population target disappeared")
    }

    /// Returns one population target.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn cache_population_target(
        &self,
        cache_id: i64,
        registry_id: i64,
        trigger_kind: &str,
    ) -> Result<Option<CachePopulationTargetRecord>> {
        let rows = self.backend.query(&format!("SELECT {POPULATION_COLUMNS} FROM cache_population_targets WHERE cache_id = ?1 AND registry_id = ?2 AND trigger_kind = ?3"), &vals![cache_id, registry_id, trigger_kind]).await?;
        rows.first().map(row_to_cache_population_target).transpose()
    }

    /// Deletes a population target at an expected version.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delete_cache_population_target(
        &self,
        id: i64,
        expected_version: i64,
    ) -> Result<bool> {
        Ok(self
            .backend
            .execute(
                "DELETE FROM cache_population_targets WHERE id = ?1 AND resource_version = ?2",
                &vals![id, expected_version],
            )
            .await?
            == 1)
    }
}
