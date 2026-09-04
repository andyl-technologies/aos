//! Bounded OCI GC run, candidate, action, purge, and metrics projections.

use anyhow::{bail, Context, Result};
use aos_oci_types::{MediaType, RepositoryName, Sha256Digest};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::{
    OciGcBlockerRecord, OciGcCandidateRecord, OciGcGenerationRecord, OciGcMetrics, OciGcPage,
    OciGcPlacementActionRecord, OciOperationsMetrics, OciRegistryPurgeBlockers,
    OCI_GC_MAX_INVENTORY_AGE_SECONDS, OCI_GC_MAX_PAGE_SIZE, OCI_OPERATIONS_STUCK_SECONDS,
};
use crate::db::{validate_key_bytes, Database};
use crate::value::Row;

const CURSOR_VERSION: u8 = 1;
const CURSOR_MAX_BYTES: usize = 2_048;
const MAX_BLOCKERS: i64 = 1_000;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CursorEnvelope {
    version: u8,
    registry_id: i64,
    selector_digest: String,
    mutation_epoch: i64,
    after_primary: String,
    after_secondary: String,
}

struct PageContext {
    registry_id: i64,
    mutation_epoch: i64,
    selector: String,
    after_primary: Option<String>,
    after_secondary: Option<String>,
}

impl Database {
    pub(super) async fn oci_gc_generation_by_plan_key(
        &self,
        registry_id: i64,
        actor_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<OciGcGenerationRecord>> {
        self.backend
            .query_opt(
                &format!(
                    "SELECT {GC_RUN_COLUMNS} FROM oci_gc_runs
                     WHERE registry_id = ?1 AND actor_id = ?2
                       AND plan_idempotency_key = ?3"
                ),
                &vals![registry_id, actor_id, idempotency_key],
            )
            .await?
            .as_ref()
            .map(row_to_generation)
            .transpose()
    }

    /// Returns one run only when it belongs to the authenticated planning actor.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed persisted data or database failure.
    pub async fn oci_gc_generation_for_actor(
        &self,
        generation_id: &str,
        actor_id: &str,
    ) -> Result<Option<OciGcGenerationRecord>> {
        validate_key_bytes(generation_id, "OCI GC generation id", 64)?;
        validate_key_bytes(actor_id, "OCI GC actor id", 128)?;
        self.backend
            .query_opt(
                &format!(
                    "SELECT {GC_RUN_COLUMNS} FROM oci_gc_runs
                     WHERE id = ?1 AND actor_id = ?2"
                ),
                &vals![generation_id, actor_id],
            )
            .await?
            .as_ref()
            .map(row_to_generation)
            .transpose()
    }

    /// Returns one exact registry-scoped OCI GC run.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed persisted data or database failure.
    pub async fn oci_gc_generation(
        &self,
        registry_id: i64,
        generation_id: &str,
    ) -> Result<Option<OciGcGenerationRecord>> {
        validate_key_bytes(generation_id, "OCI GC generation id", 64)?;
        self.backend
            .query_opt(
                &format!(
                    "SELECT {GC_RUN_COLUMNS} FROM oci_gc_runs
                     WHERE registry_id = ?1 AND id = ?2"
                ),
                &vals![registry_id, generation_id],
            )
            .await?
            .as_ref()
            .map(row_to_generation)
            .transpose()
    }

    /// Lists registry-scoped GC runs in newest-first keyset order.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid selectors/cursors, malformed persisted
    /// data, an absent registry, or database failure.
    pub async fn list_oci_gc_generations(
        &self,
        registry_id: i64,
        state: Option<&str>,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<OciGcPage<OciGcGenerationRecord>> {
        validate_run_state_filter(state)?;
        let sql_limit = validate_page_size(limit)?;
        let selector = format!("gc.run.list\0{}", state.unwrap_or("*"));
        let context = self
            .oci_gc_registry_page_context(registry_id, &selector, cursor)
            .await?;
        let rows = if let Some(after_time) = context.after_primary.as_deref() {
            let after_time = after_time
                .parse::<i64>()
                .context("OCI GC run cursor time is malformed")?;
            let after_id = context
                .after_secondary
                .as_deref()
                .context("OCI GC run cursor id is absent")?;
            self.backend
                .query(
                    &format!(
                        "SELECT {GC_RUN_COLUMNS} FROM oci_gc_runs
                         WHERE registry_id = ?1 AND (?2 IS NULL OR state = ?2)
                           AND (created_at < ?3 OR (created_at = ?3 AND id < ?4))
                         ORDER BY created_at DESC, id DESC LIMIT ?5"
                    ),
                    &vals![registry_id, state, after_time, after_id, sql_limit],
                )
                .await?
        } else {
            self.backend
                .query(
                    &format!(
                        "SELECT {GC_RUN_COLUMNS} FROM oci_gc_runs
                         WHERE registry_id = ?1 AND (?2 IS NULL OR state = ?2)
                         ORDER BY created_at DESC, id DESC LIMIT ?3"
                    ),
                    &vals![registry_id, state, sql_limit],
                )
                .await?
        };
        let items = rows
            .iter()
            .map(row_to_generation)
            .collect::<Result<Vec<_>>>()?;
        finish_page(items, limit, &context, |item| {
            (item.created_at.to_string(), item.id.clone())
        })
    }

    /// Returns the bounded durable blocker set for one run.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identity, malformed data, an excessive
    /// blocker set, or database failure.
    pub async fn list_oci_gc_blockers(
        &self,
        generation_id: &str,
    ) -> Result<Vec<OciGcBlockerRecord>> {
        validate_key_bytes(generation_id, "OCI GC generation id", 64)?;
        let rows = self
            .backend
            .query(
                "SELECT run_id, blocker_kind, digest, detail
                 FROM oci_gc_blockers WHERE run_id = ?1
                 ORDER BY ordinal LIMIT ?2",
                &vals![generation_id, MAX_BLOCKERS + 1],
            )
            .await?;
        if rows.len() > MAX_BLOCKERS as usize {
            bail!("OCI GC blocker set exceeds the bounded read limit");
        }
        rows.iter().map(row_to_blocker).collect()
    }

    /// Lists registry-global candidates for one durable run.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid selectors/cursors, malformed data, an
    /// absent run, or database failure.
    pub async fn list_oci_gc_candidates(
        &self,
        generation_id: &str,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<OciGcPage<OciGcCandidateRecord>> {
        validate_key_bytes(generation_id, "OCI GC generation id", 64)?;
        let sql_limit = validate_page_size(limit)?;
        let context = self
            .oci_gc_run_page_context(generation_id, "gc.candidate.list", cursor)
            .await?;
        let rows = if let Some(after) = context.after_primary.as_deref() {
            self.backend
                .query(
                    &format!(
                        "SELECT {GC_CANDIDATE_COLUMNS} FROM oci_gc_candidates candidate
                         WHERE candidate.run_id = ?1 AND candidate.digest > ?2
                         ORDER BY candidate.digest LIMIT ?3"
                    ),
                    &vals![generation_id, after, sql_limit],
                )
                .await?
        } else {
            self.backend
                .query(
                    &format!(
                        "SELECT {GC_CANDIDATE_COLUMNS} FROM oci_gc_candidates candidate
                         WHERE candidate.run_id = ?1
                         ORDER BY candidate.digest LIMIT ?2"
                    ),
                    &vals![generation_id, sql_limit],
                )
                .await?
        };
        let mut items = Vec::with_capacity(rows.len());
        for row in &rows {
            let mut item = row_to_candidate(row)?;
            let repository_rows = self
                .backend
                .query(
                    "SELECT repository_name
                     FROM oci_gc_candidate_repositories
                     WHERE run_id = ?1 AND digest = ?2
                     ORDER BY repository_name, repository_id LIMIT ?3",
                    &vals![
                        item.generation_id,
                        item.digest.to_string(),
                        i64::try_from(super::OCI_GC_MAX_OBJECTS + 1)?
                    ],
                )
                .await?;
            if repository_rows.len() > super::OCI_GC_MAX_OBJECTS {
                bail!("OCI GC candidate repository set exceeds the bounded read limit");
            }
            item.repositories = repository_rows
                .iter()
                .map(|repository| -> Result<_> {
                    RepositoryName::parse(&repository.get::<String>(0)?).map_err(Into::into)
                })
                .collect::<Result<Vec<_>>>()?;
            items.push(item);
        }
        finish_page(items, limit, &context, |item| {
            (item.digest.to_string(), String::new())
        })
    }

    /// Lists exact physical placement actions for one durable run.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid selectors/cursors, malformed data, an
    /// absent run, or database failure.
    pub async fn list_oci_gc_placement_actions(
        &self,
        generation_id: &str,
        state: Option<&str>,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<OciGcPage<OciGcPlacementActionRecord>> {
        validate_action_state_filter(state)?;
        let sql_limit = validate_page_size(limit)?;
        let selector = format!("gc.action.list\0{}", state.unwrap_or("*"));
        let context = self
            .oci_gc_run_page_context(generation_id, &selector, cursor)
            .await?;
        let rows = if let Some(after) = context.after_primary.as_deref() {
            self.backend
                .query(
                    &format!(
                        "SELECT {GC_ACTION_COLUMNS} FROM oci_gc_placement_actions action
                         JOIN oci_gc_placement_snapshots snapshot
                           ON snapshot.run_id = action.run_id
                          AND snapshot.placement_id = action.placement_id
                         WHERE action.run_id = ?1
                           AND (?2 IS NULL OR action.state = ?2) AND action.id > ?3
                         ORDER BY action.id LIMIT ?4"
                    ),
                    &vals![generation_id, state, after, sql_limit],
                )
                .await?
        } else {
            self.backend
                .query(
                    &format!(
                        "SELECT {GC_ACTION_COLUMNS} FROM oci_gc_placement_actions action
                         JOIN oci_gc_placement_snapshots snapshot
                           ON snapshot.run_id = action.run_id
                          AND snapshot.placement_id = action.placement_id
                         WHERE action.run_id = ?1
                           AND (?2 IS NULL OR action.state = ?2)
                         ORDER BY action.id LIMIT ?3"
                    ),
                    &vals![generation_id, state, sql_limit],
                )
                .await?
        };
        let items = rows.iter().map(row_to_action).collect::<Result<Vec<_>>>()?;
        finish_page(items, limit, &context, |item| {
            (item.id.clone(), String::new())
        })
    }

    /// Computes fail-closed blockers for deleting one registry identity.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid time, negative persisted counts, or
    /// database failure.
    pub async fn oci_registry_purge_blockers(
        &self,
        registry_id: i64,
        now: i64,
    ) -> Result<OciRegistryPurgeBlockers> {
        if registry_id <= 0 || now < 0 {
            bail!("OCI registry purge blocker selector is invalid");
        }
        let oldest = now.saturating_sub(OCI_GC_MAX_INVENTORY_AGE_SECONDS);
        let row = self
            .backend
            .query_opt(
                "SELECT
                   (SELECT COUNT(*) FROM oci_repositories WHERE registry_id = ?1),
                   (SELECT COUNT(*) FROM oci_blobs WHERE registry_id = ?1),
                   (SELECT COUNT(*) FROM oci_upload_sessions
                     WHERE registry_id = ?1 AND state IN('active', 'completing'))
                    + (SELECT COUNT(*) FROM oci_publication_sessions
                        WHERE registry_id = ?1 AND state IN('preparing', 'committing'))
                    + (SELECT COUNT(*) FROM oci_leases
                        WHERE registry_id = ?1 AND expires_at > ?2),
                   (SELECT COUNT(*) FROM oci_gc_runs
                     WHERE registry_id = ?1 AND state IN('planned', 'applying'))
                    + (SELECT COUNT(*) FROM oci_gc_placement_actions action
                        WHERE action.registry_id = ?1
                          AND action.state IN('pending', 'claimed', 'failed'))
                    + (SELECT COUNT(*) FROM oci_untracked_repair_plans repair
                        WHERE repair.registry_id = ?1
                          AND repair.state IN('planned', 'pending', 'claimed', 'failed')),
                   (SELECT COUNT(*) FROM oci_provider_inventory_entries entry
                     JOIN oci_provider_inventory_heads head
                       ON head.generation_id = entry.generation_id
                      AND head.placement_id = entry.placement_id
                    WHERE entry.registry_id = ?1 AND entry.deleted_at IS NULL
                      AND entry.classification = 'tracked'),
                   (SELECT COUNT(*) FROM oci_provider_inventory_entries entry
                     JOIN oci_provider_inventory_heads head
                       ON head.generation_id = entry.generation_id
                      AND head.placement_id = entry.placement_id
                    WHERE entry.registry_id = ?1 AND entry.deleted_at IS NULL
                      AND entry.classification = 'untracked'),
                   (SELECT COUNT(*) FROM surface_placements placement
                     WHERE placement.registry_id = ?1 AND NOT EXISTS (
                       SELECT 1 FROM oci_provider_inventory_heads head
                       JOIN oci_provider_inventory_generations inventory
                         ON inventory.id = head.generation_id
                        AND inventory.registry_id = head.registry_id
                        AND inventory.placement_id = head.placement_id
                       JOIN oci_registry_state registry_state
                         ON registry_state.registry_id = inventory.registry_id
                       JOIN surface_placement_observations observation
                         ON observation.placement_id = placement.id
                       JOIN bindings binding ON binding.id = placement.binding_id
                       JOIN binding_write_state write_state
                         ON write_state.binding_id = binding.id
                       WHERE head.placement_id = placement.id
                         AND inventory.state = 'complete'
                         AND inventory.observed_at >= ?3
                         AND inventory.captured_mutation_epoch = registry_state.mutation_epoch
                         AND inventory.placement_resource_version = placement.resource_version
                         AND inventory.placement_write_spec_version = placement.write_spec_version
                         AND inventory.placement_observation_version = observation.observation_version
                         AND inventory.binding_resource_version = binding.resource_version
                         AND inventory.binding_write_revision = write_state.current_write_revision
                         AND (NOT EXISTS (SELECT 1 FROM oci_registry_purge_fences purge
                                WHERE purge.registry_id = placement.registry_id
                                  AND purge.state = 'collecting')
                           OR EXISTS (SELECT 1 FROM oci_registry_purge_fences purge
                                WHERE purge.registry_id = placement.registry_id
                                  AND purge.state = 'collecting'
                                  AND inventory.purge_fence_resource_version =
                                    purge.resource_version
                                  AND inventory.started_at >= purge.created_at
                                  AND inventory.observed_at >= purge.created_at
                                  AND inventory.object_count = 0
                                  AND NOT EXISTS (SELECT 1
                                    FROM oci_provider_inventory_generations failed
                                    WHERE failed.placement_id = placement.id
                                      AND failed.state = 'failed'
                                      AND failed.started_at > inventory.started_at))))),
                   (SELECT COUNT(*) FROM image_snapshot_references
                     WHERE registry_id = ?1)
                    + (SELECT COUNT(*) FROM oci_gc_snapshot_lease_holds
                        WHERE registry_id = ?1)
                 FROM registries WHERE id = ?1",
                &vals![registry_id, now, oldest],
            )
            .await?
            .context("OCI registry does not exist")?;
        Ok(OciRegistryPurgeBlockers {
            repositories: count(&row, 0, "repository")?,
            catalog_objects: count(&row, 1, "catalog object")?,
            active_sessions: count(&row, 2, "active session")?,
            gc_work: count(&row, 3, "GC work")?,
            tracked_provider_objects: count(&row, 4, "tracked provider object")?,
            untracked_provider_objects: count(&row, 5, "untracked provider object")?,
            stale_or_missing_inventories: count(&row, 6, "stale inventory")?,
            snapshot_references: count(&row, 7, "snapshot reference")?,
        })
    }

    /// Returns bounded aggregate OCI GC operational counters.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid time, malformed counts, or database failure.
    pub async fn oci_gc_metrics(&self, now: i64) -> Result<OciGcMetrics> {
        if now < 0 {
            bail!("OCI GC metrics time is invalid");
        }
        let oldest = now.saturating_sub(OCI_GC_MAX_INVENTORY_AGE_SECONDS);
        let row = self
            .backend
            .query_opt(
                "SELECT
                   (SELECT COUNT(*) FROM oci_gc_runs WHERE state = 'planned'),
                   (SELECT COUNT(*) FROM oci_gc_runs WHERE state = 'applying'),
                   (SELECT COUNT(*) FROM oci_gc_runs WHERE state = 'complete'),
                   (SELECT COUNT(*) FROM oci_gc_runs WHERE state IN('failed', 'aborted')),
                   (SELECT COALESCE(SUM(planned_bytes), 0) FROM oci_gc_runs
                     WHERE state IN('planned', 'applying')),
                   (SELECT COALESCE(SUM(byte_size), 0) FROM oci_gc_candidates
                     WHERE state = 'complete'),
                   (SELECT COUNT(*) FROM oci_gc_placement_actions WHERE state = 'failed'),
                   (SELECT COUNT(*) FROM oci_gc_blockers blocker
                     JOIN oci_gc_runs blocker_run ON blocker_run.id = blocker.run_id
                     WHERE blocker_run.state = 'planned'),
                   (SELECT COUNT(*) FROM surface_placements placement
                     WHERE placement.registry_id IS NOT NULL
                       AND placement.desired_state <> 'offline'
                       AND NOT EXISTS (SELECT 1 FROM oci_provider_inventory_heads head
                       JOIN oci_provider_inventory_generations inventory
                         ON inventory.id = head.generation_id
                       WHERE head.placement_id = placement.id
                         AND inventory.state = 'complete'
                         AND inventory.observed_at >= ?1))",
                &vals![oldest],
            )
            .await?
            .context("OCI GC metrics aggregate disappeared")?;
        Ok(OciGcMetrics {
            planned_runs: count(&row, 0, "planned run")?,
            applying_runs: count(&row, 1, "applying run")?,
            completed_runs: count(&row, 2, "completed run")?,
            failed_runs: count(&row, 3, "failed run")?,
            planned_bytes: count(&row, 4, "planned byte")?,
            finalized_bytes: count(&row, 5, "finalized byte")?,
            failed_actions: count(&row, 6, "failed action")?,
            blockers: count(&row, 7, "blocker")?,
            stale_inventories: count(&row, 8, "stale inventory")?,
        })
    }

    /// Returns global low-cardinality OCI storage and recovery metrics.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid time, malformed persisted counters, or
    /// database failure.
    pub async fn oci_operations_metrics(&self, now: i64) -> Result<OciOperationsMetrics> {
        if now < 0 {
            bail!("OCI operations metrics time is invalid");
        }
        let stuck_before = now.saturating_sub(OCI_OPERATIONS_STUCK_SECONDS);
        let row = self
            .backend
            .query_opt(
                "SELECT
                   (SELECT COUNT(*) FROM oci_repository_objects),
                   (SELECT COALESCE(SUM(stored_blob.byte_size), 0)
                      FROM oci_repository_objects link JOIN oci_blobs stored_blob
                        ON stored_blob.registry_id = link.registry_id
                       AND stored_blob.digest = link.digest),
                   (SELECT COUNT(*) FROM (SELECT DISTINCT registry_id, digest
                      FROM oci_repository_objects) linked),
                   (SELECT COALESCE(SUM(stored_blob.byte_size), 0)
                      FROM (SELECT DISTINCT registry_id, digest
                        FROM oci_repository_objects) linked JOIN oci_blobs stored_blob
                        ON stored_blob.registry_id = linked.registry_id
                       AND stored_blob.digest = linked.digest),
                   (SELECT COUNT(*) FROM oci_provider_inventory_heads head
                      JOIN oci_provider_inventory_entries entry
                        ON entry.generation_id = head.generation_id
                     WHERE entry.deleted_at IS NULL),
                   (SELECT COALESCE(SUM(entry.byte_size), 0)
                      FROM oci_provider_inventory_heads head
                      JOIN oci_provider_inventory_entries entry
                        ON entry.generation_id = head.generation_id
                     WHERE entry.deleted_at IS NULL),
                   (SELECT COUNT(*) FROM oci_upload_sessions WHERE state = 'active'),
                   (SELECT COUNT(*) FROM oci_upload_sessions WHERE state = 'completing'),
                   (SELECT COUNT(*) FROM oci_upload_sessions WHERE state = 'complete'),
                   (SELECT COUNT(*) FROM oci_upload_sessions WHERE state = 'failed'),
                   (SELECT COUNT(*) FROM oci_upload_sessions WHERE state = 'cancelled'),
                   (SELECT COUNT(*) FROM oci_upload_sessions
                     WHERE state IN('active', 'completing') AND expires_at <= ?1),
                   (SELECT COUNT(*) FROM oci_publication_sessions WHERE state = 'preparing'),
                   (SELECT COUNT(*) FROM oci_publication_sessions WHERE state = 'committing'),
                   (SELECT COUNT(*) FROM oci_publication_sessions WHERE state = 'ready'),
                   (SELECT COUNT(*) FROM oci_publication_sessions WHERE state = 'aborted'),
                   (SELECT COUNT(*) FROM oci_publication_sessions WHERE state = 'failed'),
                   (SELECT COUNT(*) FROM oci_publication_sessions
                     WHERE state IN('preparing', 'committing') AND created_at <= ?2),
                   (SELECT COALESCE(SUM(committed_at - created_at), 0)
                      FROM oci_publication_sessions
                     WHERE state = 'ready' AND committed_at IS NOT NULL),
                   (SELECT COUNT(*) FROM oci_publication_sessions
                     WHERE state = 'ready' AND committed_at IS NOT NULL),
                   (SELECT COUNT(*) FROM surface_placements placement
                      JOIN surface_placement_observations observation
                        ON observation.placement_id = placement.id
                     WHERE placement.registry_id IS NOT NULL
                       AND placement.desired_state <> 'offline'
                       AND observation.state = 'ready'
                       AND observation.completeness = 'complete'
                       AND EXISTS (SELECT 1 FROM oci_provider_inventory_heads head
                         JOIN oci_provider_inventory_generations inventory
                           ON inventory.id = head.generation_id
                         WHERE head.placement_id = placement.id
                           AND inventory.state = 'complete')),
                   (SELECT COUNT(*) FROM surface_placements placement
                      LEFT JOIN surface_placement_observations observation
                        ON observation.placement_id = placement.id
                     WHERE placement.registry_id IS NOT NULL
                       AND placement.desired_state <> 'offline'
                       AND NOT (observation.placement_id IS NOT NULL
                         AND observation.state = 'ready'
                         AND observation.completeness = 'complete'
                         AND EXISTS (SELECT 1 FROM oci_provider_inventory_heads head
                           JOIN oci_provider_inventory_generations inventory
                             ON inventory.id = head.generation_id
                           WHERE head.placement_id = placement.id
                             AND inventory.state = 'complete'))),
                   (SELECT MIN(inventory.observed_at)
                      FROM oci_provider_inventory_heads head
                      JOIN oci_provider_inventory_generations inventory
                        ON inventory.id = head.generation_id
                     WHERE inventory.state = 'complete'),
                   (SELECT COUNT(*) FROM oci_provider_inventory_generations
                     WHERE state = 'failed'),
                   (SELECT COALESCE(SUM(takeover_count), 0)
                      FROM oci_provider_inventory_generations),
                   (SELECT COUNT(*) FROM oci_gc_placement_actions
                     WHERE requeue_actor_id IS NOT NULL),
                   (SELECT COUNT(*) FROM oci_provider_inventory_heads head
                      JOIN oci_provider_inventory_entries entry
                        ON entry.generation_id = head.generation_id
                      LEFT JOIN surface_objects object
                        ON object.id = entry.surface_object_id
                     WHERE entry.deleted_at IS NULL
                       AND (entry.object_digest <> entry.observed_hash
                         OR (entry.classification = 'tracked'
                           AND object.content_hash <> substr(entry.observed_hash, 8))))",
                &vals![now, stuck_before],
            )
            .await?
            .context("OCI operations metrics aggregate disappeared")?;
        let oldest_inventory: Option<i64> = row.get(22)?;
        let max_inventory_age_seconds = oldest_inventory
            .map(|observed| {
                u64::try_from(now.saturating_sub(observed))
                    .context("OCI provider inventory observation is in the future")
            })
            .transpose()?
            .unwrap_or(0);
        Ok(OciOperationsMetrics {
            catalog_logical_objects: count(&row, 0, "logical catalog object")?,
            catalog_logical_bytes: count(&row, 1, "logical catalog byte")?,
            catalog_unique_objects: count(&row, 2, "unique catalog object")?,
            catalog_unique_bytes: count(&row, 3, "unique catalog byte")?,
            provider_inventory_objects: count(&row, 4, "provider inventory object")?,
            provider_inventory_bytes: count(&row, 5, "provider inventory byte")?,
            uploads_active: count(&row, 6, "active upload")?,
            uploads_completing: count(&row, 7, "completing upload")?,
            uploads_complete: count(&row, 8, "complete upload")?,
            uploads_failed: count(&row, 9, "failed upload")?,
            uploads_cancelled: count(&row, 10, "cancelled upload")?,
            uploads_expired_nonterminal: count(&row, 11, "expired upload")?,
            publications_preparing: count(&row, 12, "preparing publication")?,
            publications_committing: count(&row, 13, "committing publication")?,
            publications_ready: count(&row, 14, "ready publication")?,
            publications_aborted: count(&row, 15, "aborted publication")?,
            publications_failed: count(&row, 16, "failed publication")?,
            publications_stuck_nonterminal: count(&row, 17, "stuck publication")?,
            publication_ready_latency_seconds_sum: count(&row, 18, "publication latency")?,
            publication_ready_latency_count: count(&row, 19, "publication latency count")?,
            placements_ready: count(&row, 20, "ready placement")?,
            placements_unhealthy: count(&row, 21, "unhealthy placement")?,
            max_inventory_age_seconds,
            failed_inventory_generations: count(&row, 23, "failed inventory")?,
            inventory_takeover_count: count(&row, 24, "inventory takeover")?,
            gc_requeue_count: count(&row, 25, "GC requeue")?,
            digest_mismatches: count(&row, 26, "digest mismatch")?,
        })
    }

    async fn oci_gc_registry_page_context(
        &self,
        registry_id: i64,
        selector: &str,
        cursor: Option<&str>,
    ) -> Result<PageContext> {
        let epoch = self
            .backend
            .query_opt(
                "SELECT COALESCE(state.mutation_epoch, 0)
                 FROM registries registry LEFT JOIN oci_registry_state state
                   ON state.registry_id = registry.id WHERE registry.id = ?1",
                &vals![registry_id],
            )
            .await?
            .context("OCI registry does not exist")?
            .get(0)?;
        page_context(registry_id, epoch, selector, cursor)
    }

    async fn oci_gc_run_page_context(
        &self,
        generation_id: &str,
        selector: &str,
        cursor: Option<&str>,
    ) -> Result<PageContext> {
        let row = self
            .backend
            .query_opt(
                "SELECT registry_id, captured_mutation_epoch FROM oci_gc_runs WHERE id = ?1",
                &vals![generation_id],
            )
            .await?
            .context("OCI GC generation does not exist")?;
        page_context(row.get(0)?, row.get(1)?, selector, cursor)
    }
}

const GC_RUN_COLUMNS: &str = "id, registry_id, actor_id, state,
    captured_mutation_epoch, applied_mutation_epoch, policy_resource_version,
    policy_digest, root_set_digest, placement_inventory_digest, topology_digest,
    plan_digest, confirmation_hash, inventory_object_count, inventory_byte_size,
    reachable_object_count, planned_bytes, planned_objects,
    deleted_object_count, deleted_byte_size, placement_action_count, expires_at,
    created_at, applied_at, finished_at, last_error, resource_version";

const GC_CANDIDATE_COLUMNS: &str = "candidate.run_id, candidate.digest,
    candidate.media_type, candidate.byte_size, candidate.object_key,
    candidate.eligible_at, candidate.state, candidate.finalized_at,
    candidate.last_error, candidate.resource_version";

pub(super) const GC_ACTION_COLUMNS: &str = "action.id, action.run_id,
    action.registry_id, action.digest, action.object_key, action.expected_hash,
    action.expected_size, action.expected_strong_etag,
    action.inventory_entry_present, action.inventory_generation_id,
    snapshot.inventory_digest, snapshot.inventory_observed_at,
    action.placement_id, snapshot.placement_name, snapshot.placement_prefix,
    snapshot.placement_resource_version, snapshot.placement_write_spec_version,
    snapshot.placement_observation_version, snapshot.binding_id,
    snapshot.binding_resource_version, snapshot.binding_write_revision,
    snapshot.delete_credential_purpose, snapshot.delete_credential_generation,
    snapshot.delete_capability_fingerprint,
    snapshot.delete_capability_resource_version, action.state,
    action.attempt_count, action.max_attempts, action.next_attempt_at,
    action.last_error, action.confirmed_at, action.resource_version";

fn row_to_generation(row: &Row) -> Result<OciGcGenerationRecord> {
    Ok(OciGcGenerationRecord {
        id: row.get(0)?,
        registry_id: row.get(1)?,
        actor_id: row.get(2)?,
        state: row.get(3)?,
        captured_mutation_epoch: row.get(4)?,
        applied_mutation_epoch: row.get(5)?,
        policy_resource_version: row.get(6)?,
        policy_digest: Sha256Digest::parse(&row.get::<String>(7)?)?,
        root_set_digest: Sha256Digest::parse(&row.get::<String>(8)?)?,
        placement_inventory_digest: Sha256Digest::parse(&row.get::<String>(9)?)?,
        topology_digest: Sha256Digest::parse(&row.get::<String>(10)?)?,
        plan_digest: Sha256Digest::parse(&row.get::<String>(11)?)?,
        confirmation_hash: Sha256Digest::parse(&row.get::<String>(12)?)?,
        inventory_object_count: count(row, 13, "inventory object")?,
        inventory_byte_size: count(row, 14, "inventory byte")?,
        reachable_object_count: count(row, 15, "reachable object")?,
        planned_bytes: count(row, 16, "planned byte")?,
        planned_objects: count(row, 17, "planned object")?,
        deleted_object_count: count(row, 18, "deleted object")?,
        deleted_byte_size: count(row, 19, "deleted byte")?,
        placement_action_count: count(row, 20, "placement action")?,
        expires_at: row.get(21)?,
        created_at: row.get(22)?,
        applied_at: row.get(23)?,
        finished_at: row.get(24)?,
        last_error: row.get(25)?,
        resource_version: row.get(26)?,
    })
}

fn row_to_blocker(row: &Row) -> Result<OciGcBlockerRecord> {
    Ok(OciGcBlockerRecord {
        generation_id: row.get(0)?,
        kind: row.get(1)?,
        digest: row
            .get::<Option<String>>(2)?
            .map(|digest| Sha256Digest::parse(&digest))
            .transpose()?,
        detail: row.get(3)?,
    })
}

fn row_to_candidate(row: &Row) -> Result<OciGcCandidateRecord> {
    let generation_id: String = row.get(0)?;
    let repositories = Vec::new();
    Ok(OciGcCandidateRecord {
        generation_id,
        digest: Sha256Digest::parse(&row.get::<String>(1)?)?,
        media_type: MediaType::parse(&row.get::<String>(2)?)?,
        byte_size: count(row, 3, "candidate byte")?,
        object_key: row.get(4)?,
        repositories,
        eligible_at: row.get(5)?,
        state: row.get(6)?,
        finalized_at: row.get(7)?,
        last_error: row.get(8)?,
        resource_version: row.get(9)?,
    })
}

pub(super) fn row_to_action(row: &Row) -> Result<OciGcPlacementActionRecord> {
    Ok(OciGcPlacementActionRecord {
        id: row.get(0)?,
        generation_id: row.get(1)?,
        registry_id: row.get(2)?,
        digest: Sha256Digest::parse(&row.get::<String>(3)?)?,
        object_key: row.get(4)?,
        expected_hash: Sha256Digest::parse(&row.get::<String>(5)?)?,
        expected_size: count(row, 6, "placement action expected byte")?,
        expected_strong_etag: row.get(7)?,
        inventory_entry_present: row.get::<i64>(8)? == 1,
        inventory_generation_id: row.get(9)?,
        inventory_digest: Sha256Digest::parse(&row.get::<String>(10)?)?,
        inventory_observed_at: row.get(11)?,
        placement_id: row.get(12)?,
        placement_name: row.get(13)?,
        placement_prefix: row.get(14)?,
        placement_resource_version: row.get(15)?,
        placement_write_spec_version: row.get(16)?,
        placement_observation_version: row.get(17)?,
        binding_id: row.get(18)?,
        binding_resource_version: row.get(19)?,
        binding_write_revision: row.get(20)?,
        delete_credential_purpose: row.get(21)?,
        delete_credential_generation: row.get(22)?,
        delete_capability_fingerprint: row.get(23)?,
        delete_capability_resource_version: row.get(24)?,
        state: row.get(25)?,
        attempt_count: u32::try_from(row.get::<i64>(26)?)
            .context("persisted OCI GC attempt count is negative")?,
        max_attempts: u32::try_from(row.get::<i64>(27)?)
            .context("persisted OCI GC max attempts is negative")?,
        next_attempt_at: row.get(28)?,
        last_error: row.get(29)?,
        confirmed_at: row.get(30)?,
        resource_version: row.get(31)?,
    })
}

fn validate_page_size(limit: u32) -> Result<i64> {
    if limit == 0 || limit > OCI_GC_MAX_PAGE_SIZE {
        bail!("OCI GC page size must be between 1 and {OCI_GC_MAX_PAGE_SIZE}");
    }
    Ok(i64::from(limit) + 1)
}

fn validate_run_state_filter(state: Option<&str>) -> Result<()> {
    if state.is_some_and(|value| {
        !matches!(
            value,
            "planned" | "applying" | "complete" | "aborted" | "failed"
        )
    }) {
        bail!("OCI GC run state selector is invalid");
    }
    Ok(())
}

fn validate_action_state_filter(state: Option<&str>) -> Result<()> {
    if state.is_some_and(|value| {
        !matches!(value, "pending" | "claimed" | "confirmed_absent" | "failed")
    }) {
        bail!("OCI GC action state selector is invalid");
    }
    Ok(())
}

fn page_context(
    registry_id: i64,
    mutation_epoch: i64,
    selector: &str,
    cursor: Option<&str>,
) -> Result<PageContext> {
    let Some(encoded) = cursor else {
        return Ok(PageContext {
            registry_id,
            mutation_epoch,
            selector: selector.into(),
            after_primary: None,
            after_secondary: None,
        });
    };
    if encoded.is_empty() || encoded.len() > CURSOR_MAX_BYTES {
        bail!("OCI GC cursor has an invalid size");
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .context("OCI GC cursor is not canonical base64url")?;
    if URL_SAFE_NO_PAD.encode(&bytes) != encoded {
        bail!("OCI GC cursor is not canonical base64url");
    }
    let envelope =
        serde_json::from_slice::<CursorEnvelope>(&bytes).context("OCI GC cursor is malformed")?;
    if envelope.version != CURSOR_VERSION
        || envelope.registry_id != registry_id
        || envelope.mutation_epoch != mutation_epoch
        || envelope.selector_digest != selector_digest(selector)
        || envelope.after_primary.is_empty()
        || envelope.after_primary.len() > 512
        || envelope.after_secondary.len() > 512
    {
        bail!("OCI GC cursor is stale or belongs to another selector");
    }
    Ok(PageContext {
        registry_id,
        mutation_epoch,
        selector: selector.into(),
        after_primary: Some(envelope.after_primary),
        after_secondary: (!envelope.after_secondary.is_empty()).then_some(envelope.after_secondary),
    })
}

fn finish_page<T>(
    mut items: Vec<T>,
    limit: u32,
    context: &PageContext,
    key: impl FnOnce(&T) -> (String, String),
) -> Result<OciGcPage<T>> {
    let has_more = items.len() > limit as usize;
    if has_more {
        items.pop();
    }
    let next_cursor = if has_more {
        let last = items
            .last()
            .context("OCI GC page lost its keyset boundary")?;
        let (after_primary, after_secondary) = key(last);
        Some(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&CursorEnvelope {
            version: CURSOR_VERSION,
            registry_id: context.registry_id,
            selector_digest: selector_digest(&context.selector),
            mutation_epoch: context.mutation_epoch,
            after_primary,
            after_secondary,
        })?))
    } else {
        None
    };
    Ok(OciGcPage {
        items,
        next_cursor,
        captured_mutation_epoch: context.mutation_epoch,
    })
}

fn selector_digest(selector: &str) -> String {
    Sha256Digest::digest(selector.as_bytes()).to_string()
}

fn count(row: &Row, index: usize, kind: &str) -> Result<u64> {
    u64::try_from(row.get::<i64>(index)?)
        .with_context(|| format!("persisted {kind} count is negative"))
}
