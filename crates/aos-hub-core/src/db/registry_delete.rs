//! Atomic retirement of a registry's logical Hub state.
//!
//! Registry deletion removes SQL topology, publication, and derived-delivery
//! records while intentionally retaining bytes in the configured storage
//! provider. Restrictive composite foreign keys encode useful live-state
//! invariants, so retirement dismantles the owned graph from leaves to roots
//! in one checked transaction. Active publication work and cache-retention
//! roots fail closed before that transaction begins.

use anyhow::{bail, Context, Result};

use super::{sanitize_log_text, unix_now, Database, NewTopologyEvent};
use crate::backend::{CheckedStatement, Statement};

impl Database {
    /// Deletes a quiescent registry identity and records the transition atomically.
    ///
    /// Physical provider objects are not deleted. The registry must have no
    /// active publication, upload, legacy publish lease, or retained cache root.
    /// Terminal publication history and owned topology are retired with the
    /// registry so restrictive foreign keys cannot leave a half-deleted graph.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry is not quiescent, history
    /// serialization fails, or the checked transaction cannot commit. Returns
    /// `Ok(false)` when the registry no longer matches `expected_version`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn delete_registry_at_version(
        &self,
        registry_id: i64,
        expected_version: i64,
        change_id: &str,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
    ) -> Result<bool> {
        let Some(current) = self.registry_by_id(registry_id).await? else {
            return Ok(false);
        };
        if current.resource_version != expected_version {
            return Ok(false);
        }

        let blocked = self
            .backend
            .query_opt(
                "SELECT
                   EXISTS (SELECT 1 FROM registry_publications
                     WHERE registry_id = ?1
                       AND state IN ('preparing', 'writing_pointers')),
                   EXISTS (SELECT 1 FROM registry_publication_multipart_uploads
                     WHERE registry_id = ?1 AND active_object_slot = 1),
                   EXISTS (SELECT 1 FROM publish_leases WHERE registry_id = ?1),
                   EXISTS (SELECT 1 FROM cache_root_reasons WHERE registry_id = ?1)",
                &vals![registry_id],
            )
            .await?
            .context("registry deletion preflight returned no row")?;
        let active_publication: i64 = blocked.get(0)?;
        let active_multipart: i64 = blocked.get(1)?;
        let active_legacy_publish: i64 = blocked.get(2)?;
        let retained_cache_roots: i64 = blocked.get(3)?;
        if active_publication != 0 || active_multipart != 0 || active_legacy_publish != 0 {
            bail!("registry has an active publication or upload");
        }
        if retained_cache_roots != 0 {
            bail!("registry still supplies retained binary-cache roots");
        }

        let now = unix_now();
        let old_json = serde_json::to_string(&serde_json::json!({
            "stableId": &current.stable_id,
            "slug": &current.slug,
            "visibility": &current.visibility,
            "crawlPolicy": &current.crawl_policy,
            "llmsTxtBody": &current.llms_txt_body,
            "trustKeys": &current.trust_keys,
            "resourceVersion": expected_version,
        }))?;
        let event_id = uuid::Uuid::new_v4().simple().to_string();
        let payload_json = serde_json::to_string(&serde_json::json!({
            "changeId": change_id,
            "registryId": &current.stable_id,
            "slug": &current.slug,
            "resourceVersion": expected_version,
        }))?;
        let event = NewTopologyEvent {
            event_id: &event_id,
            event_name: "registry.deleted",
            owner_scope_key: &current.scope_key,
            resource_kind: "registry",
            resource_stable_id: &current.stable_id,
            resource_generation_key: expected_version,
            actor_kind,
            actor_id,
            actor_label,
            payload_json: &payload_json,
            occurred_at: now,
        };
        let summary = format!("delete registry identity '{}'", current.slug);

        let result = self
            .backend
            .checked_batch(&[
                // Reassert quiescence while taking the registry row's write
                // lock. Publication admission must retain the same parent row,
                // so it cannot race new work behind this teardown fence.
                Statement::new(
                    "UPDATE registries SET updated_at = updated_at
                     WHERE id = ?1 AND scope_key = ?2 AND resource_version = ?3
                       AND NOT EXISTS (SELECT 1 FROM registry_publications
                         WHERE registry_id = ?1
                           AND state IN ('preparing', 'writing_pointers'))
                       AND NOT EXISTS (
                         SELECT 1 FROM registry_publication_multipart_uploads
                         WHERE registry_id = ?1 AND active_object_slot = 1)
                       AND NOT EXISTS (SELECT 1 FROM publish_leases
                         WHERE registry_id = ?1)
                       AND NOT EXISTS (SELECT 1 FROM cache_root_reasons
                         WHERE registry_id = ?1)",
                    vals![registry_id, current.scope_key, expected_version],
                )
                .expecting(1),
                // Lock every owned route and placement before cancelling
                // logical work. Operation admission takes the same target-row
                // locks, so a creator either commits before cancellation or
                // observes the deleted target and rolls back.
                Statement::new(
                    "UPDATE delivery_routes SET updated_at = updated_at
                     WHERE registry_id = ?1",
                    vals![registry_id],
                )
                .unchecked(),
                Statement::new(
                    "UPDATE surface_placements SET updated_at = updated_at
                     WHERE registry_id = ?1",
                    vals![registry_id],
                )
                .unchecked(),
                Statement::new(
                    "INSERT INTO change_requests
                     (change_id, actor_kind, actor_id, actor_label, scope, status,
                      summary, created_at, applied_at)
                     SELECT ?1, ?2, ?3, ?4, scope_key, 'applied', ?6, ?7, ?7
                       FROM registries WHERE id = ?5 AND resource_version = ?8",
                    vals![
                        change_id,
                        actor_kind,
                        actor_id,
                        sanitize_log_text(actor_label),
                        registry_id,
                        summary,
                        now,
                        expected_version
                    ],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO change_request_revisions
                     (change_id, object_type, object_id, op, old_json, new_json, seq)
                     VALUES (?1, 'registry', ?2, 'delete', ?3, NULL, 0)",
                    vals![change_id, current.stable_id, old_json],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO audit_log
                     (outbox_event_id, change_id, actor_kind, actor_id, actor_label,
                      action, scope, detail, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, 'registry.deleted', ?6, ?7, ?8)",
                    vals![
                        event_id,
                        change_id,
                        actor_kind,
                        actor_id,
                        sanitize_log_text(actor_label),
                        current.scope_key,
                        payload_json,
                        now
                    ],
                )
                .expecting(1),
                Self::topology_event_statement(&event),
                Statement::new(
                    "UPDATE topology_operations
                     SET state = 'cancelled', started_at = COALESCE(started_at, ?3),
                         finished_at = ?3, error = 'registry deleted',
                         resource_version = resource_version + 1
                     WHERE state IN ('pending', 'running') AND (
                       authorization_scope_key = ?1
                       OR (primary_target_kind = 'registry'
                         AND primary_target_stable_id = ?2)
                       OR (primary_target_kind = 'delivery_route'
                         AND primary_target_stable_id IN (
                           SELECT id FROM delivery_routes WHERE registry_id = ?4))
                       OR EXISTS (SELECT 1 FROM operation_secondary_targets target
                         WHERE target.operation_id = topology_operations.operation_id
                           AND target.authorization_scope_key = ?1))",
                    vals![current.scope_key, current.stable_id, now, registry_id],
                )
                .unchecked(),
                // Route and delivery evidence must disappear before the
                // configuration and manifest identities that they pin.
                Statement::new(
                    "DELETE FROM network_boundary_serving_pins
                     WHERE target_kind = 'route' AND target_stable_id IN (
                       SELECT id FROM delivery_routes WHERE registry_id = ?1)",
                    vals![registry_id],
                )
                .unchecked(),
                Statement::new(
                    "DELETE FROM delivery_endpoint_scope_grant_pins
                     WHERE target_kind = 'route' AND target_stable_id IN (
                       SELECT id FROM delivery_routes WHERE registry_id = ?1)",
                    vals![registry_id],
                )
                .unchecked(),
                Statement::new(
                    "DELETE FROM storage_gateway_scope_grant_pins
                     WHERE target_kind = 'route' AND target_stable_id IN (
                       SELECT id FROM delivery_routes WHERE registry_id = ?1)",
                    vals![registry_id],
                )
                .unchecked(),
                delete("direct_delivery_route_evidence", registry_id),
                Statement::new(
                    "DELETE FROM delivery_route_access_observations
                     WHERE delivery_route_id IN (
                       SELECT id FROM delivery_routes WHERE registry_id = ?1)",
                    vals![registry_id],
                )
                .unchecked(),
                delete("delivery_route_observations", registry_id),
                delete("canonical_routes", registry_id),
                delete("registry_cache_stack_entries", registry_id),
                delete("consumer_cache_publication_intents", registry_id),
                delete("delivery_route_heads", registry_id),
                delete("delivery_route_configurations", registry_id),
                delete("delivery_routes", registry_id),
                delete("placement_delivery_manifest_heads", registry_id),
                delete("placement_delivery_manifests", registry_id),
                // Policy tables use restrictive composite keys. Retire their
                // leaves before removing revisions, policies, or placements.
                delete("placement_policy_complete_members", registry_id),
                delete("placement_policy_shard_members", registry_id),
                delete("placement_policy_replica_groups", registry_id),
                Statement::new(
                    "DELETE FROM placement_policy_build_events
                     WHERE policy_revision_id IN (
                       SELECT id FROM placement_policy_revisions WHERE registry_id = ?1)",
                    vals![registry_id],
                )
                .unchecked(),
                Statement::new(
                    "DELETE FROM placement_policy_publications
                     WHERE policy_revision_id IN (
                       SELECT id FROM placement_policy_revisions WHERE registry_id = ?1)",
                    vals![registry_id],
                )
                .unchecked(),
                Statement::new(
                    "DELETE FROM placement_policy_heads
                     WHERE policy_id IN (
                       SELECT id FROM placement_policies WHERE registry_id = ?1)",
                    vals![registry_id],
                )
                .unchecked(),
                delete("placement_policy_revisions", registry_id),
                delete("placement_policies", registry_id),
                // Terminal publication rows are logical Hub state. Active
                // work was rejected by the preflight before this transaction.
                Statement::new(
                    "DELETE FROM registry_publication_multipart_parts
                     WHERE upload_id IN (
                       SELECT upload_id FROM registry_publication_multipart_uploads
                       WHERE registry_id = ?1)",
                    vals![registry_id],
                )
                .unchecked(),
                Statement::new(
                    "DELETE FROM registry_publication_multipart_backends
                     WHERE upload_id IN (
                       SELECT upload_id FROM registry_publication_multipart_uploads
                       WHERE registry_id = ?1)",
                    vals![registry_id],
                )
                .unchecked(),
                delete("registry_publication_multipart_uploads", registry_id),
                Statement::new(
                    "DELETE FROM registry_publication_object_evidence
                     WHERE publication_id IN (
                       SELECT publication_id FROM registry_publications
                       WHERE registry_id = ?1)",
                    vals![registry_id],
                )
                .unchecked(),
                delete("registry_publication_placements", registry_id),
                delete("registry_publication_objects", registry_id),
                delete("registry_placement_publication_watermarks", registry_id),
                delete("registry_index_publication_state", registry_id),
                delete("object_placements", registry_id),
                delete("surface_objects", registry_id),
                delete("registry_publication_state", registry_id),
                Statement::new(
                    "UPDATE registry_publications SET parent_publication_id = NULL
                     WHERE registry_id = ?1 AND parent_publication_id IS NOT NULL",
                    vals![registry_id],
                )
                .unchecked(),
                delete("registry_publications", registry_id),
                // Index snapshots and zero-root retention refreshes otherwise
                // restrict cascades from releases and subscriptions.
                delete("cache_root_release_provenance", registry_id),
                delete("release_artifact_snapshot_heads", registry_id),
                delete("release_artifacts", registry_id),
                delete("release_artifact_snapshots", registry_id),
                delete("cache_retention_refresh_heads", registry_id),
                Statement::new(
                    "UPDATE cache_retention_refreshes
                     SET parent_refresh_id = NULL, expected_parent_refresh_id = NULL
                     WHERE registry_id = ?1 AND (
                       parent_refresh_id IS NOT NULL
                       OR expected_parent_refresh_id IS NOT NULL)",
                    vals![registry_id],
                )
                .unchecked(),
                delete("cache_retention_refreshes", registry_id),
                delete("cache_retention_subscriptions", registry_id),
                delete("surface_write_authorities", registry_id),
                delete("surface_placements", registry_id),
                Statement::new(
                    "DELETE FROM registries WHERE id = ?1 AND scope_key = ?2
                       AND resource_version = ?3",
                    vals![registry_id, current.scope_key, expected_version],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE authorization_scopes SET retired_at = ?2
                      WHERE scope_key = ?1 AND kind = 'registry' AND retired_at IS NULL",
                    vals![current.scope_key, now],
                )
                .expecting(1),
            ])
            .await;
        if let Err(error) = result {
            if self
                .registry_by_id(registry_id)
                .await?
                .map_or(true, |record| record.resource_version != expected_version)
            {
                return Ok(false);
            }
            return Err(error);
        }
        Ok(true)
    }
}

/// Builds a registry-owned-row deletion statement for a trusted table name.
fn delete(table: &'static str, registry_id: i64) -> CheckedStatement {
    Statement::new(
        format!("DELETE FROM {table} WHERE registry_id = ?1"),
        vals![registry_id],
    )
    .unchecked()
}
