//! Durable state transitions of the reviewed registry deletion operation.
//!
//! A deletion operation is a `delete_registry` row in `topology_operations`.
//! Controllers claim it through the generic operation lease table
//! (`placement_scan_claims`, keyed by operation id), advance it one bounded
//! pass at a time, and release the lease with a detail checkpoint so the next
//! pass can resume on any runtime. Success is recorded only by the final
//! deletion transaction itself; see
//! [`Database::commit_registry_deletion`](super::Database::commit_registry_deletion).
//!
//! The operation owns at most one purge fence: the fence whose idempotency key
//! is the operation id. A failed operation releases that fence in the same
//! transaction, and a cancelled operation's fence is released by the next
//! controller pass, so an abandoned deletion never leaves registry writers
//! blocked. A fence acquired through the separate purge-fence review is reused
//! but never released here.

use anyhow::{bail, Context, Result};

use super::{
    row_to_topology_operation, unix_now, validate_json_value, validate_key_bytes, Database,
    TopologyOperationRecord, OPERATION_COLUMNS,
};
use crate::backend::Statement;

/// Operation kind of reviewed registry deletion.
pub const REGISTRY_DELETION_OPERATION_KIND: &str = "delete_registry";

/// Maximum planned GC runs one preparation step abandons.
const MAX_ABANDONED_GC_RUNS: usize = 250;

/// Input for abandoning never-applied GC plans and acquiring the purge fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrepareRegistryDeletion<'a> {
    /// Registry being deleted.
    pub registry_id: i64,
    /// Registry resource version bound by the reviewed plan.
    pub expected_version: i64,
    /// Deletion operation that owns any fence it acquires.
    pub operation_id: &'a str,
    /// Reviewing actor recorded as the fence owner.
    pub actor_id: &'a str,
    /// Preparation time in Unix seconds.
    pub now: i64,
}

/// Effects of one deletion preparation step.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PreparedRegistryDeletion {
    /// Planned OCI GC runs marked aborted by this step.
    pub abandoned_gc_runs: Vec<String>,
    /// Whether this step acquired a new purge fence.
    pub fence_acquired: bool,
}

impl Database {
    /// Lists deletion operations eligible for a controller claim.
    ///
    /// An operation is due while pending, or while running without a live
    /// controller lease.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn due_registry_deletion_operations(
        &self,
        now: i64,
        limit: usize,
    ) -> Result<Vec<TopologyOperationRecord>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        self.backend
            .query(
                &format!(
                    "SELECT {OPERATION_COLUMNS} FROM topology_operations operation
                     WHERE operation.operation_kind = 'delete_registry'
                       AND (operation.state = 'pending'
                         OR (operation.state = 'running' AND NOT EXISTS (
                           SELECT 1 FROM placement_scan_claims claim
                           WHERE claim.operation_id = operation.operation_id
                             AND claim.lease_expires_at > ?1)))
                     ORDER BY operation.created_at, operation.operation_id LIMIT ?2"
                ),
                &vals![now, i64::try_from(limit)?],
            )
            .await?
            .iter()
            .map(row_to_topology_operation)
            .collect()
    }

    /// Releases purge fences still owned by terminal deletion operations.
    ///
    /// A failed operation releases its fence transactionally; this sweep
    /// covers operations cancelled through the operation API, which cannot
    /// know about the fence.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn release_orphaned_registry_deletion_fences(&self, now: i64) -> Result<u64> {
        let released = self
            .backend
            .execute(
                "UPDATE oci_registry_purge_fences
                 SET state = 'aborted', aborted_at = ?1,
                     resource_version = resource_version + 1
                 WHERE state = 'collecting' AND EXISTS (
                   SELECT 1 FROM topology_operations operation
                   WHERE operation.operation_id = oci_registry_purge_fences.idempotency_key
                     AND operation.operation_kind = 'delete_registry'
                     AND operation.state IN('failed', 'cancelled'))",
                &vals![now],
            )
            .await?;
        Ok(u64::try_from(released)?)
    }

    /// Claims one due deletion operation under CAS.
    ///
    /// Returns `Ok(None)` when another controller won the claim.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid lease or database failure.
    pub async fn claim_registry_deletion_operation(
        &self,
        operation_id: &str,
        expected_version: i64,
        claim_token: &str,
        lease_seconds: i64,
    ) -> Result<Option<TopologyOperationRecord>> {
        validate_key_bytes(claim_token, "registry deletion claim token", 64)?;
        if lease_seconds <= 0 {
            bail!("registry deletion claim lease must be positive");
        }
        let now = unix_now();
        let lease_expires_at = now
            .checked_add(lease_seconds)
            .context("registry deletion claim deadline overflowed")?;
        let claimed_version = expected_version
            .checked_add(1)
            .context("registry deletion claim version overflowed")?;
        let result = self
            .backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE topology_operations
                     SET state = 'running',
                         started_at = CASE WHEN state = 'pending' THEN ?3 ELSE started_at END,
                         resource_version = resource_version + 1
                     WHERE operation_id = ?1 AND operation_kind = 'delete_registry'
                       AND resource_version = ?2
                       AND (state = 'pending' OR (state = 'running' AND NOT EXISTS (
                         SELECT 1 FROM placement_scan_claims claim
                         WHERE claim.operation_id = topology_operations.operation_id
                           AND claim.lease_expires_at > ?3)))",
                    vals![operation_id, expected_version, now],
                )
                .expecting(1),
                Statement::new(
                    "DELETE FROM placement_scan_claims WHERE operation_id = ?1",
                    vals![operation_id],
                )
                .unchecked(),
                Statement::new(
                    "INSERT INTO placement_scan_claims
                       (operation_id, claim_token, operation_resource_version,
                        heartbeat_at, lease_expires_at)
                     SELECT operation_id, ?3, resource_version, ?4, ?5
                     FROM topology_operations
                     WHERE operation_id = ?1 AND resource_version = ?2
                       AND state = 'running'",
                    vals![
                        operation_id,
                        claimed_version,
                        claim_token,
                        now,
                        lease_expires_at
                    ],
                )
                .expecting(1),
            ])
            .await;
        if let Err(error) = result {
            // A competing claim, a live lease, or a concurrent cancellation
            // means this controller does not own the pass.
            let live_claim = self
                .backend
                .query_opt(
                    "SELECT 1 FROM placement_scan_claims
                     WHERE operation_id = ?1 AND lease_expires_at > ?2",
                    &vals![operation_id, now],
                )
                .await?
                .is_some();
            let claimable = self
                .topology_operation(operation_id)
                .await?
                .is_some_and(|operation| {
                    operation.resource_version == expected_version
                        && matches!(operation.state.as_str(), "pending" | "running")
                });
            if live_claim || !claimable {
                return Ok(None);
            }
            return Err(error).context("persisting registry deletion claim");
        }
        self.topology_operation(operation_id).await
    }

    /// Records progress and releases the claim so the next pass can resume.
    ///
    /// Returns `false` without mutation when the claim was lost, for example
    /// because the operation was cancelled.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed detail or database failure.
    pub async fn checkpoint_registry_deletion_operation(
        &self,
        operation_id: &str,
        expected_version: i64,
        claim_token: &str,
        progress_current: i64,
        detail_json: &str,
    ) -> Result<bool> {
        validate_json_value(detail_json, "registry deletion detail")?;
        let result = self
            .backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE topology_operations
                     SET detail_json = ?4,
                         progress_current = CASE WHEN progress_current > ?5
                           THEN progress_current ELSE ?5 END,
                         resource_version = resource_version + 1
                     WHERE operation_id = ?1 AND resource_version = ?2
                       AND state = 'running'
                       AND (progress_total IS NULL OR progress_total >= ?5)
                       AND EXISTS (SELECT 1 FROM placement_scan_claims claim
                         WHERE claim.operation_id = ?1 AND claim.claim_token = ?3
                           AND claim.operation_resource_version = ?2)",
                    vals![
                        operation_id,
                        expected_version,
                        claim_token,
                        detail_json,
                        progress_current
                    ],
                )
                .expecting(1),
                Statement::new(
                    "DELETE FROM placement_scan_claims
                     WHERE operation_id = ?1 AND claim_token = ?2",
                    vals![operation_id, claim_token],
                )
                .expecting(1),
            ])
            .await;
        Ok(result.is_ok())
    }

    /// Fails one claimed deletion operation and releases the fence it owns.
    ///
    /// Returns `false` without mutation when the claim was lost.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed detail or database failure.
    pub async fn fail_registry_deletion_operation(
        &self,
        operation_id: &str,
        expected_version: i64,
        claim_token: &str,
        detail_json: &str,
        error: &str,
    ) -> Result<bool> {
        validate_json_value(detail_json, "registry deletion detail")?;
        let now = unix_now();
        let result = self
            .backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE topology_operations
                     SET state = 'failed', detail_json = ?4, error = ?5, finished_at = ?6,
                         resource_version = resource_version + 1
                     WHERE operation_id = ?1 AND resource_version = ?2
                       AND state = 'running'
                       AND EXISTS (SELECT 1 FROM placement_scan_claims claim
                         WHERE claim.operation_id = ?1 AND claim.claim_token = ?3
                           AND claim.operation_resource_version = ?2)",
                    vals![
                        operation_id,
                        expected_version,
                        claim_token,
                        detail_json,
                        error,
                        now
                    ],
                )
                .expecting(1),
                Statement::new(
                    "DELETE FROM placement_scan_claims WHERE operation_id = ?1",
                    vals![operation_id],
                )
                .unchecked(),
                // Reopen registry writers. Only the fence this operation
                // acquired is released; a separately reviewed fence remains.
                Statement::new(
                    "UPDATE oci_registry_purge_fences
                     SET state = 'aborted', aborted_at = ?2,
                         resource_version = resource_version + 1
                     WHERE idempotency_key = ?1 AND state = 'collecting'",
                    vals![operation_id, now],
                )
                .unchecked(),
            ])
            .await;
        Ok(result.is_ok())
    }

    /// Abandons never-applied GC plans and acquires the purge fence.
    ///
    /// A planned GC run has, by construction, no apply in progress: apply
    /// moves it to `applying` atomically, and the abort statement requires the
    /// exact planned version. Each abandoned run is recorded as `aborted` with
    /// the deleting operation named in its error. The fence is acquired under
    /// the same quiescence guard as a reviewed purge-fence Begin and is owned
    /// by the operation. A fence that is already held is reused.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry changed, a blocker appeared, a GC
    /// run was applied concurrently, or the database fails. Every such case
    /// leaves state unchanged and is retried by the next pass.
    pub async fn prepare_registry_deletion(
        &self,
        input: &PrepareRegistryDeletion<'_>,
    ) -> Result<PreparedRegistryDeletion> {
        validate_key_bytes(input.operation_id, "registry deletion operation id", 64)?;
        validate_key_bytes(input.actor_id, "registry deletion actor", 128)?;
        if input.registry_id <= 0 || input.expected_version < 1 || input.now <= 0 {
            bail!("registry deletion preparation input is invalid");
        }

        let planned_runs = self
            .backend
            .query(
                "SELECT id, resource_version FROM oci_gc_runs
                 WHERE registry_id = ?1 AND state = 'planned'
                 ORDER BY id LIMIT ?2",
                &vals![input.registry_id, i64::try_from(MAX_ABANDONED_GC_RUNS)?],
            )
            .await?
            .iter()
            .map(|row| Ok((row.get::<String>(0)?, row.get::<i64>(1)?)))
            .collect::<Result<Vec<_>>>()?;
        let abandon_reason = format!("abandoned by registry deletion {}", input.operation_id);
        let mut statements = planned_runs
            .iter()
            .map(|(run_id, version)| {
                Statement::new(
                    "UPDATE oci_gc_runs SET state = 'aborted', finished_at = ?3,
                         last_error = ?4, resource_version = resource_version + 1
                     WHERE id = ?1 AND resource_version = ?2 AND state = 'planned'",
                    vals![run_id, *version, input.now, abandon_reason],
                )
                .expecting(1)
            })
            .collect::<Vec<_>>();

        let fence_held = self
            .backend
            .query_opt(
                "SELECT 1 FROM oci_registry_purge_fences
                 WHERE registry_id = ?1 AND state = 'collecting'",
                &vals![input.registry_id],
            )
            .await?
            .is_some();
        if !fence_held {
            let captured_mutation_epoch: i64 = self
                .backend
                .query_opt(
                    "SELECT COALESCE(registry_state.mutation_epoch, 0)
                     FROM registries registry
                     LEFT JOIN oci_registry_state registry_state
                       ON registry_state.registry_id = registry.id
                     WHERE registry.id = ?1 AND registry.resource_version = ?2",
                    &vals![input.registry_id, input.expected_version],
                )
                .await?
                .context("registry changed before its purge fence was acquired")?
                .get(0)?;
            statements.extend(fence_statements(input, captured_mutation_epoch));
        }
        if statements.is_empty() {
            return Ok(PreparedRegistryDeletion::default());
        }

        self.backend
            .checked_batch(&statements)
            .await
            .context("abandoning planned GC runs or acquiring the purge fence")?;
        Ok(PreparedRegistryDeletion {
            abandoned_gc_runs: planned_runs.into_iter().map(|(run_id, _)| run_id).collect(),
            fence_acquired: !fence_held,
        })
    }
}

/// Acquires an operation-owned purge fence under the reviewed Begin guard.
fn fence_statements(
    input: &PrepareRegistryDeletion<'_>,
    captured_mutation_epoch: i64,
) -> [crate::backend::CheckedStatement; 4] {
    [
        Statement::new(
            "INSERT INTO oci_registry_state
               (registry_id, mutation_epoch, charged_bytes, charged_objects, updated_at)
             SELECT id, 0, 0, 0, ?2 FROM registries WHERE id = ?1
             ON CONFLICT(registry_id) DO NOTHING",
            vals![input.registry_id, input.now],
        )
        .unchecked(),
        Statement::new(
            "DELETE FROM oci_registry_purge_fences
             WHERE registry_id = ?1 AND state = 'aborted'",
            vals![input.registry_id],
        )
        .unchecked(),
        // The same quiescence predicates as a reviewed purge-fence Begin. The
        // planned-run predicate observes the abandonment statements earlier in
        // this batch.
        Statement::new(
            "UPDATE registries SET updated_at = updated_at
             WHERE id = ?1 AND resource_version = ?2
               AND EXISTS (SELECT 1 FROM oci_registry_state registry_state
                 WHERE registry_state.registry_id = ?1
                   AND registry_state.mutation_epoch = ?3)
               AND NOT EXISTS (SELECT 1 FROM oci_repositories WHERE registry_id = ?1)
               AND NOT EXISTS (SELECT 1 FROM oci_blobs WHERE registry_id = ?1)
               AND NOT EXISTS (
                 SELECT 1 FROM staged_release_objects staged_object
                 JOIN staged_release_revisions staged_revision
                   ON staged_revision.registry_id = staged_object.registry_id
                  AND staged_revision.stage_id = staged_object.stage_id
                  AND staged_revision.revision = staged_object.revision
                 WHERE staged_object.registry_id = ?1
                   AND staged_object.object_key LIKE 'oci/blobs/sha256/%'
                   AND (staged_revision.retire_after IS NULL
                     OR staged_revision.retire_after > ?4))
               AND NOT EXISTS (SELECT 1 FROM oci_upload_sessions
                 WHERE registry_id = ?1 AND state IN('active', 'completing'))
               AND NOT EXISTS (SELECT 1 FROM oci_publication_sessions
                 WHERE registry_id = ?1 AND state IN('preparing', 'committing'))
               AND NOT EXISTS (SELECT 1 FROM oci_gc_runs
                 WHERE registry_id = ?1 AND state IN('planned', 'applying'))
               AND NOT EXISTS (SELECT 1 FROM oci_untracked_repair_plans
                 WHERE registry_id = ?1
                   AND state IN('planned', 'pending', 'claimed', 'failed'))
               AND NOT EXISTS (SELECT 1 FROM oci_registry_purge_fences
                 WHERE registry_id = ?1 AND state = 'collecting')",
            vals![
                input.registry_id,
                input.expected_version,
                captured_mutation_epoch,
                input.now
            ],
        )
        .expecting(1),
        Statement::new(
            "INSERT INTO oci_registry_purge_fences
               (registry_id, actor_id, idempotency_key,
                registry_resource_version, captured_mutation_epoch,
                state, created_at, aborted_at, resource_version)
             SELECT ?1, ?2, ?3, ?4, ?5, 'collecting', ?6, NULL, 1
             FROM oci_registry_state registry_state
             WHERE registry_state.registry_id = ?1
               AND registry_state.mutation_epoch = ?5",
            vals![
                input.registry_id,
                input.actor_id,
                input.operation_id,
                input.expected_version,
                captured_mutation_epoch,
                input.now
            ],
        )
        .expecting(1),
    ]
}
