//! Atomic retirement of a registry's logical Hub state.
//!
//! Registry deletion removes SQL topology, publication, and derived-delivery
//! records only after transactional OCI GC proves every provider placement
//! empty. Restrictive composite foreign keys encode useful live-state
//! invariants, so retirement dismantles the owned graph from leaves to roots
//! in one checked transaction. Active publication work and cache-retention
//! roots fail closed before that transaction begins.
//!
//! The reviewed deletion operation (see
//! [`registry_delete_controller`](crate::registry_delete_controller)) drives
//! the automatic preconditions and then calls
//! [`Database::commit_registry_deletion`]. A precondition that changes between
//! its readiness check and this transaction is reported as
//! [`RegistryDeletionOutcome::Blocked`] with the exact blocker breakdown rather
//! than as an opaque checked-batch failure.

use anyhow::{Context, Result};

use super::{
    sanitize_log_text, unix_now, Database, NewTopologyEvent, RegistryDeletionReadiness,
    RegistryRecord,
};
use crate::backend::{CheckedStatement, Statement};

/// Result of one final registry deletion attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryDeletionOutcome {
    /// The registry and its owned graph were retired atomically.
    Deleted,
    /// The registry disappeared or no longer matches the reviewed version.
    Stale,
    /// A deletion precondition does not hold; nothing was changed.
    Blocked(Box<RegistryDeletionReadiness>),
}

/// The claimed deletion operation completed by the deletion transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryDeletionOperationCompletion<'a> {
    /// Deletion operation id.
    pub operation_id: &'a str,
    /// Operation resource version observed under the claim.
    pub expected_version: i64,
    /// Opaque claim token held by the executing controller.
    pub claim_token: &'a str,
    /// Terminal operation detail recorded with the deletion.
    pub detail_json: &'a str,
    /// Terminal progress, equal to the operation's total work units.
    pub progress_total: i64,
}

/// Attribution and fences for one final registry deletion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryDeletionCommit<'a> {
    /// Registry database id.
    pub registry_id: i64,
    /// Registry resource version bound by the reviewed plan.
    pub expected_version: i64,
    /// Reviewed plan id recorded as the change request.
    pub change_id: &'a str,
    /// Actor kind recorded in history.
    pub actor_kind: &'a str,
    /// Actor database id recorded in history.
    pub actor_id: Option<i64>,
    /// Actor label recorded in history.
    pub actor_label: &'a str,
    /// Deletion operation that succeeds atomically with the deletion.
    pub operation: Option<RegistryDeletionOperationCompletion<'a>>,
}

impl Database {
    /// Deletes a quiescent registry identity and records the transition atomically.
    ///
    /// This is the pre-operation form of [`Database::commit_registry_deletion`]
    /// retained for transaction-level tests.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry is not quiescent, history
    /// serialization fails, or the checked transaction cannot commit. Returns
    /// `Ok(false)` when the registry no longer matches `expected_version`.
    #[cfg(test)]
    pub(crate) async fn delete_registry_at_version(
        &self,
        registry_id: i64,
        expected_version: i64,
        change_id: &str,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
    ) -> Result<bool> {
        let outcome = self
            .commit_registry_deletion(&RegistryDeletionCommit {
                registry_id,
                expected_version,
                change_id,
                actor_kind,
                actor_id,
                actor_label,
                operation: None,
            })
            .await?;
        match outcome {
            RegistryDeletionOutcome::Deleted => Ok(true),
            RegistryDeletionOutcome::Stale => Ok(false),
            RegistryDeletionOutcome::Blocked(readiness) => {
                anyhow::bail!("{}", readiness.failure_message())
            }
        }
    }

    /// Deletes a quiescent registry identity and records the transition atomically.
    ///
    /// Physical provider deletion is performed before this call by reviewed
    /// OCI GC actions. The registry must have no logical catalog identity,
    /// provider-inventory key, active work, snapshot attribution, legacy
    /// publish lease, or retained cache root, and every placement must hold a
    /// complete empty inventory collected under the registry's purge fence.
    /// Terminal publication history and owned topology are retired with the
    /// registry so restrictive foreign keys cannot leave a half-deleted graph.
    /// When `commit.operation` is set, that claimed operation succeeds in the
    /// same transaction.
    ///
    /// # Errors
    ///
    /// Returns an error when history serialization fails or the transaction
    /// fails for a reason other than a changed precondition. A precondition
    /// that does not hold, before or inside the transaction, is reported as
    /// [`RegistryDeletionOutcome::Blocked`].
    pub async fn commit_registry_deletion(
        &self,
        commit: &RegistryDeletionCommit<'_>,
    ) -> Result<RegistryDeletionOutcome> {
        let registry_id = commit.registry_id;
        let Some(current) = self.registry_by_id(registry_id).await? else {
            return Ok(RegistryDeletionOutcome::Stale);
        };
        if current.resource_version != commit.expected_version {
            return Ok(RegistryDeletionOutcome::Stale);
        }

        let now = unix_now();
        let readiness = self
            .registry_deletion_readiness(registry_id, now)
            .await?
            .context("registry disappeared during deletion preflight")?;
        if !readiness.is_deletable() {
            return Ok(RegistryDeletionOutcome::Blocked(Box::new(readiness)));
        }
        self.execute_registry_deletion(&current, commit, now).await
    }

    /// Runs the guarded deletion batch after a passing readiness preflight.
    ///
    /// Every readiness predicate is re-asserted inside the transaction, so a
    /// precondition that changed after the preflight rejects the batch and is
    /// reported as [`RegistryDeletionOutcome::Blocked`].
    async fn execute_registry_deletion(
        &self,
        current: &RegistryRecord,
        commit: &RegistryDeletionCommit<'_>,
        now: i64,
    ) -> Result<RegistryDeletionOutcome> {
        let RegistryDeletionCommit {
            registry_id,
            expected_version,
            change_id,
            actor_kind,
            actor_id,
            actor_label,
            operation,
        } = *commit;

        let oldest_inventory = now.saturating_sub(super::OCI_GC_MAX_INVENTORY_AGE_SECONDS);
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

        let mut statements = vec![
            // Reassert quiescence while taking the registry row's write
            // lock. Publication admission must retain the same parent row,
            // so it cannot race new work behind this teardown fence. An
            // expired or aborted GC plan cannot be applied, so it and its
            // never-claimed actions are retired below instead of blocking.
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
                     WHERE registry_id = ?1)
                   AND NOT EXISTS (SELECT 1 FROM oci_repositories
                     WHERE registry_id = ?1)
                   AND NOT EXISTS (SELECT 1 FROM oci_blobs
                     WHERE registry_id = ?1)
                   AND NOT EXISTS (SELECT 1 FROM oci_upload_sessions
                     WHERE registry_id = ?1 AND state IN('active', 'completing'))
                   AND NOT EXISTS (SELECT 1 FROM oci_publication_sessions
                     WHERE registry_id = ?1 AND state IN('preparing', 'committing'))
                   AND NOT EXISTS (SELECT 1 FROM oci_leases
                     WHERE registry_id = ?1 AND expires_at > ?4)
                   AND NOT EXISTS (SELECT 1 FROM oci_gc_runs
                     WHERE registry_id = ?1
                       AND (state = 'applying'
                         OR (state = 'planned' AND expires_at > ?4)))
                   AND NOT EXISTS (SELECT 1 FROM oci_gc_placement_actions action
                     WHERE action.registry_id = ?1
                       AND action.state IN('pending', 'claimed', 'failed')
                       AND NOT EXISTS (SELECT 1 FROM oci_gc_runs action_run
                         WHERE action_run.id = action.run_id
                           AND action_run.state IN('planned', 'aborted')))
                   AND NOT EXISTS (SELECT 1 FROM oci_untracked_repair_plans
                     WHERE registry_id = ?1
                       AND state IN('planned', 'pending', 'claimed', 'failed'))
                   AND NOT EXISTS (SELECT 1 FROM image_snapshot_references
                     WHERE registry_id = ?1)
                   AND NOT EXISTS (SELECT 1 FROM oci_gc_snapshot_lease_holds
                     WHERE registry_id = ?1)
                   AND EXISTS (SELECT 1 FROM oci_registry_purge_fences purge_fence
                     WHERE purge_fence.registry_id = ?1 AND purge_fence.state = 'collecting'
                       AND purge_fence.registry_resource_version = ?3
                       AND purge_fence.captured_mutation_epoch =
                         (SELECT mutation_epoch FROM oci_registry_state
                          WHERE registry_id = ?1))
                   AND NOT EXISTS (SELECT 1
                     FROM oci_provider_inventory_entries entry
                     JOIN oci_provider_inventory_heads head
                       ON head.generation_id = entry.generation_id
                      AND head.placement_id = entry.placement_id
                     WHERE entry.registry_id = ?1 AND entry.deleted_at IS NULL)
                   AND NOT EXISTS (SELECT 1
                     FROM oci_provider_inventory_generations inventory
                     WHERE inventory.registry_id = ?1
                       AND inventory.state IN('collecting', 'sealing'))
                   AND NOT EXISTS (SELECT 1 FROM surface_placements placement
                     WHERE placement.registry_id = ?1 AND NOT EXISTS (
                       SELECT 1 FROM oci_provider_inventory_heads head
                       JOIN oci_provider_inventory_generations inventory
                         ON inventory.id = head.generation_id
                       JOIN oci_registry_state registry_state
                         ON registry_state.registry_id = inventory.registry_id
                       JOIN surface_placement_observations observation
                         ON observation.placement_id = placement.id
                       JOIN bindings binding ON binding.id = placement.binding_id
                       JOIN binding_write_state write_state
                         ON write_state.binding_id = binding.id
                       WHERE head.placement_id = placement.id
                         AND inventory.state = 'complete'
                         AND inventory.observed_at >= ?5
                         AND inventory.captured_mutation_epoch =
                           registry_state.mutation_epoch
                         AND inventory.placement_resource_version =
                           placement.resource_version
                         AND inventory.placement_write_spec_version =
                           placement.write_spec_version
                         AND inventory.placement_observation_version =
                           observation.observation_version
                         AND inventory.binding_resource_version =
                           binding.resource_version
                         AND inventory.binding_write_revision =
                           write_state.current_write_revision
                         AND inventory.purge_fence_resource_version =
                           (SELECT resource_version FROM oci_registry_purge_fences purge_fence
                            WHERE purge_fence.registry_id = ?1 AND purge_fence.state = 'collecting')
                         AND inventory.object_count = 0
                         AND inventory.started_at >=
                           (SELECT created_at FROM oci_registry_purge_fences purge_fence
                            WHERE purge_fence.registry_id = ?1 AND purge_fence.state = 'collecting')
                         AND inventory.observed_at >=
                           (SELECT created_at FROM oci_registry_purge_fences purge_fence
                            WHERE purge_fence.registry_id = ?1 AND purge_fence.state = 'collecting')
                         AND NOT EXISTS (SELECT 1
                           FROM oci_provider_inventory_generations failed
                           WHERE failed.placement_id = placement.id
                             AND failed.state = 'failed'
                             AND failed.started_at > inventory.started_at)))",
                vals![
                    registry_id,
                    current.scope_key,
                    expected_version,
                    now,
                    oldest_inventory
                ],
            )
            .expecting(1),
        ];
        if let Some(operation) = operation {
            statements.extend(operation_success_statements(&operation, now));
        }
        statements.extend([
            // Lock every owned route and placement before cancelling
            // logical work. Operation admission takes the same target-row
            // locks, so a creator either commits before cancellation or
            // observes the deleted target and rolls back.
            Statement::new(
                "UPDATE routes SET updated_at = updated_at
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
                   OR (primary_target_kind = 'route'
                     AND primary_target_stable_id IN (
                       SELECT id FROM routes WHERE registry_id = ?4))
                   OR EXISTS (SELECT 1 FROM operation_secondary_targets target
                     WHERE target.operation_id = topology_operations.operation_id
                       AND target.authorization_scope_key = ?1))",
                vals![current.scope_key, current.stable_id, now, registry_id],
            )
            .unchecked(),
            // Route and delivery evidence must disappear before the
            // configuration and manifest identities that they pin.
            Statement::new(
                "DELETE FROM network_policy_serving_pins
                 WHERE target_kind = 'route' AND target_stable_id IN (
                   SELECT id FROM routes WHERE registry_id = ?1)",
                vals![registry_id],
            )
            .unchecked(),
            Statement::new(
                "DELETE FROM endpoint_scope_grant_pins
                 WHERE target_kind = 'route' AND target_stable_id IN (
                   SELECT id FROM routes WHERE registry_id = ?1)",
                vals![registry_id],
            )
            .unchecked(),
            Statement::new(
                "DELETE FROM gateway_scope_grant_pins
                 WHERE target_kind = 'route' AND target_stable_id IN (
                   SELECT id FROM routes WHERE registry_id = ?1)",
                vals![registry_id],
            )
            .unchecked(),
            delete("direct_route_evidence", registry_id),
            Statement::new(
                "DELETE FROM route_access_observations
                 WHERE route_id IN (
                   SELECT id FROM routes WHERE registry_id = ?1)",
                vals![registry_id],
            )
            .unchecked(),
            delete("route_observations", registry_id),
            delete("route_advertisements", registry_id),
            delete("registry_cache_stack_entries", registry_id),
            delete("consumer_cache_publication_intents", registry_id),
            delete("route_heads", registry_id),
            delete("route_configurations", registry_id),
            delete("routes", registry_id),
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
            // Reviewed OCI GC history is self-contained and may be retired
            // only after the atomic empty-provider assertion above.
            delete("oci_gc_runs", registry_id),
            delete("oci_untracked_repair_plans", registry_id),
            delete("oci_provider_inventory_heads", registry_id),
            delete("oci_provider_inventory_generations", registry_id),
            delete("oci_admin_mutations", registry_id),
            delete("oci_upload_sessions", registry_id),
            delete("oci_publication_sessions", registry_id),
            delete("oci_quota_reservations", registry_id),
            delete("oci_retention_policies", registry_id),
            delete("oci_gc_generations", registry_id),
            delete("oci_uploads", registry_id),
            delete("oci_publications", registry_id),
            delete("oci_registry_state", registry_id),
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
        ]);
        let result = self.backend.checked_batch(&statements).await;
        let Err(error) = result else {
            return Ok(RegistryDeletionOutcome::Deleted);
        };

        // The guard statement re-asserts every readiness predicate inside the
        // transaction. When it rejects the batch, report the precondition
        // that changed instead of the opaque affected-row mismatch.
        if self
            .registry_by_id(registry_id)
            .await?
            .is_none_or(|record| record.resource_version != expected_version)
        {
            return Ok(RegistryDeletionOutcome::Stale);
        }
        match self.registry_deletion_readiness(registry_id, unix_now()).await? {
            Some(readiness) if !readiness.is_deletable() => {
                Ok(RegistryDeletionOutcome::Blocked(Box::new(readiness)))
            }
            Some(_) => Err(error).context("registry deletion transaction failed"),
            None => Ok(RegistryDeletionOutcome::Stale),
        }
    }
}

/// Marks the claimed deletion operation succeeded inside the deletion batch.
///
/// The update precedes the statement that cancels the registry's live
/// operations, so the deletion operation is terminal before that sweep and is
/// never cancelled by its own success.
fn operation_success_statements(
    operation: &RegistryDeletionOperationCompletion<'_>,
    now: i64,
) -> [CheckedStatement; 2] {
    [
        Statement::new(
            "UPDATE topology_operations
             SET state = 'succeeded', progress_current = ?3, progress_total = ?3,
                 detail_json = ?4, error = NULL, finished_at = ?5,
                 resource_version = resource_version + 1
             WHERE operation_id = ?1 AND resource_version = ?2
               AND operation_kind = 'delete_registry' AND state = 'running'
               AND EXISTS (SELECT 1 FROM placement_scan_claims claim
                 WHERE claim.operation_id = ?1 AND claim.claim_token = ?6
                   AND claim.operation_resource_version = ?2)",
            vals![
                operation.operation_id,
                operation.expected_version,
                operation.progress_total,
                operation.detail_json,
                now,
                operation.claim_token
            ],
        )
        .expecting(1),
        Statement::new(
            "DELETE FROM placement_scan_claims WHERE operation_id = ?1",
            vals![operation.operation_id],
        )
        .unchecked(),
    ]
}

/// Builds a registry-owned-row deletion statement for a trusted table name.
fn delete(table: &'static str, registry_id: i64) -> CheckedStatement {
    Statement::new(
        format!("DELETE FROM {table} WHERE registry_id = ?1"),
        vals![registry_id],
    )
    .unchecked()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{NewRegistryPublication, PrepareRegistryDeletion};

    #[tokio::test]
    async fn precondition_changed_inside_the_transaction_is_reported_as_blocked() {
        let db = Database::open_in_memory().await.unwrap();
        let registry_id = db.register_registry("racing", &[], false).await.unwrap();
        let registry = db.registry_by_id(registry_id).await.unwrap().unwrap();
        let now = unix_now();
        db.prepare_registry_deletion(&PrepareRegistryDeletion {
            registry_id,
            expected_version: registry.resource_version,
            operation_id: &"e".repeat(64),
            actor_id: "operator",
            now,
        })
        .await
        .unwrap();
        let readiness = db
            .registry_deletion_readiness(registry_id, now)
            .await
            .unwrap()
            .unwrap();
        assert!(readiness.is_deletable(), "{readiness:?}");

        // Publication admission races in after the passing preflight. The
        // guarded batch rejects it and the outcome names the new blocker
        // instead of surfacing an affected-row mismatch.
        db.create_registry_publication(&NewRegistryPublication {
            publication_id: "racing-publication".into(),
            registry_id,
            generation: "racing-generation".into(),
            manifest_digest: "c".repeat(64),
            refs_digest: "d".repeat(64),
            default_commit: None,
            parent_publication_id: None,
        })
        .await
        .unwrap();
        let change_id = uuid::Uuid::new_v4().to_string();
        let commit = RegistryDeletionCommit {
            registry_id,
            expected_version: registry.resource_version,
            change_id: &change_id,
            actor_kind: "user",
            actor_id: None,
            actor_label: "operator",
            operation: None,
        };
        let outcome = db
            .execute_registry_deletion(&registry, &commit, unix_now())
            .await
            .unwrap();

        let RegistryDeletionOutcome::Blocked(blocked) = outcome else {
            panic!("expected a blocked outcome, got {outcome:?}");
        };
        assert_eq!(blocked.blockers.active_publications, 1);
        assert!(blocked.failure_message().contains("active publication"));
        assert!(db.registry_by_id(registry_id).await.unwrap().is_some());
        assert!(db.changeset(&change_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn changed_registry_version_is_stale_rather_than_blocked() {
        let db = Database::open_in_memory().await.unwrap();
        let registry_id = db.register_registry("versioned", &[], false).await.unwrap();
        let registry = db.registry_by_id(registry_id).await.unwrap().unwrap();

        let outcome = db
            .commit_registry_deletion(&RegistryDeletionCommit {
                registry_id,
                expected_version: registry.resource_version + 1,
                change_id: "stale-change",
                actor_kind: "user",
                actor_id: None,
                actor_label: "operator",
                operation: None,
            })
            .await
            .unwrap();

        assert_eq!(outcome, RegistryDeletionOutcome::Stale);
    }
}
