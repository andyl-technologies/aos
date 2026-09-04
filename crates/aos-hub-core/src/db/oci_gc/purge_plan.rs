//! Reviewed begin/abort transitions for the registry purge/write fence.
//!
//! The fence excludes Hub writers before provider enumeration. It is distinct
//! from final registry deletion: operators first review and apply a Begin plan,
//! reconcile every provider placement under that exact fence, and only then
//! invoke the existing terminal registry deletion transaction. Abort is also a
//! reviewed action so writer admission cannot be reopened by an untracked call.

use anyhow::{bail, Context, Result};
use aos_oci_types::Sha256Digest;
use serde::Serialize;
use uuid::Uuid;

use super::{OciRegistryPurgeBlockers, OciRegistryPurgeFenceRecord};
use crate::backend::Statement;
use crate::db::{validate_key_bytes, Database};

/// Reviewed registry purge-fence transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OciRegistryPurgeFenceAction {
    /// Acquires the writer fence before complete provider enumeration.
    Begin,
    /// Releases the exact current fence without deleting registry identity.
    Abort,
}

impl OciRegistryPurgeFenceAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Begin => "begin",
            Self::Abort => "abort",
        }
    }
}

/// Input for one actor-bound reviewed purge-fence plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanOciRegistryPurgeFence {
    /// Registry whose writer fence will change.
    pub registry_id: i64,
    /// Begin or Abort action.
    pub action: OciRegistryPurgeFenceAction,
    /// Authenticated actor identity.
    pub actor_id: String,
    /// Stable plan response-loss key.
    pub idempotency_key: String,
    /// Registry resource version for Begin or current fence version for Abort.
    pub expected_resource_version: i64,
    /// Planning time in Unix seconds.
    pub now: i64,
}

/// Input for applying one reviewed purge-fence plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOciRegistryPurgeFence {
    /// Durable reviewed plan identity.
    pub plan_id: String,
    /// Authenticated actor that created the plan.
    pub actor_id: String,
    /// Stable apply response-loss key.
    pub idempotency_key: String,
    /// Exact reviewed confirmation digest.
    pub confirmation_hash: Sha256Digest,
    /// Expected plan optimistic-concurrency version.
    pub expected_resource_version: i64,
    /// Apply time in Unix seconds.
    pub now: i64,
}

/// Durable reviewed purge-fence plan and operation status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciRegistryPurgeFencePlanRecord {
    /// Stable plan and operation id.
    pub id: String,
    /// Registry whose fence is reviewed.
    pub registry_id: i64,
    /// Begin or Abort action.
    pub action: OciRegistryPurgeFenceAction,
    /// Authenticated plan owner.
    pub actor_id: String,
    /// Reviewed registry/fence resource version.
    pub expected_resource_version: i64,
    /// Registry mutation epoch frozen by review.
    pub captured_mutation_epoch: i64,
    /// Canonical reviewed confirmation digest.
    pub confirmation_hash: Sha256Digest,
    /// `planned`, `applied`, or `failed`.
    pub state: String,
    /// Review expiry in Unix seconds.
    pub expires_at: i64,
    /// Creation time.
    pub created_at: i64,
    /// Apply time.
    pub applied_at: Option<i64>,
    /// Terminal time.
    pub finished_at: Option<i64>,
    /// Sanitized terminal failure detail.
    pub last_error: Option<String>,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
}

/// Current reviewed plan, fence, and exact purge-readiness blockers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciRegistryPurgeFenceStatus {
    /// Actor-bound reviewed operation.
    pub plan: OciRegistryPurgeFencePlanRecord,
    /// Current fence, absent only after legacy cleanup or registry deletion.
    pub fence: Option<OciRegistryPurgeFenceRecord>,
    /// Exact logical/provider/snapshot blockers for terminal deletion.
    pub blockers: OciRegistryPurgeBlockers,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PurgeFenceConfirmation<'a> {
    registry_id: i64,
    action: OciRegistryPurgeFenceAction,
    actor_id: &'a str,
    expected_resource_version: i64,
    captured_mutation_epoch: i64,
    expires_at: i64,
}

impl Database {
    /// Creates one reviewed Begin or Abort purge-fence plan.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identity, stale registry/fence version,
    /// actor mismatch, idempotency conflict, or database failure.
    pub async fn plan_oci_registry_purge_fence(
        &self,
        input: &PlanOciRegistryPurgeFence,
    ) -> Result<OciRegistryPurgeFencePlanRecord> {
        validate_key_bytes(&input.actor_id, "OCI purge-fence actor", 128)?;
        validate_key_bytes(
            &input.idempotency_key,
            "OCI purge-fence plan idempotency key",
            128,
        )?;
        if input.registry_id <= 0 || input.expected_resource_version < 1 || input.now <= 0 {
            bail!("OCI purge-fence plan identity is invalid");
        }
        if let Some(existing) = self
            .oci_registry_purge_fence_plan_by_idempotency(
                input.registry_id,
                &input.actor_id,
                &input.idempotency_key,
            )
            .await?
        {
            if existing.action == input.action
                && existing.expected_resource_version == input.expected_resource_version
            {
                return Ok(existing);
            }
            bail!("OCI purge-fence plan idempotency conflict");
        }

        let captured_mutation_epoch = match input.action {
            OciRegistryPurgeFenceAction::Begin => self
                .backend
                .query_opt(
                    "SELECT COALESCE(registry_state.mutation_epoch, 0)
                     FROM registries registry
                     LEFT JOIN oci_registry_state registry_state
                       ON registry_state.registry_id = registry.id
                     WHERE registry.id = ?1 AND registry.resource_version = ?2
                       AND NOT EXISTS (SELECT 1 FROM oci_registry_purge_fences fence
                         WHERE fence.registry_id = registry.id
                           AND fence.state = 'collecting')",
                    &vals![input.registry_id, input.expected_resource_version],
                )
                .await?
                .context("registry is stale or already purge-fenced")?
                .get(0)?,
            OciRegistryPurgeFenceAction::Abort => self
                .backend
                .query_opt(
                    "SELECT registry_state.mutation_epoch
                     FROM oci_registry_purge_fences fence
                     JOIN oci_registry_state registry_state
                       ON registry_state.registry_id = fence.registry_id
                     WHERE fence.registry_id = ?1 AND fence.actor_id = ?2
                       AND fence.state = 'collecting' AND fence.resource_version = ?3",
                    &vals![
                        input.registry_id,
                        input.actor_id,
                        input.expected_resource_version
                    ],
                )
                .await?
                .context("current purge fence is stale or owned by another actor")?
                .get(0)?,
        };
        let id = format!("ocipf-{}", Uuid::new_v4().simple());
        let expires_at = input.now.saturating_add(super::OCI_GC_PLAN_TTL_SECONDS);
        let confirmation_hash =
            Sha256Digest::digest(&serde_json::to_vec(&PurgeFenceConfirmation {
                registry_id: input.registry_id,
                action: input.action,
                actor_id: &input.actor_id,
                expected_resource_version: input.expected_resource_version,
                captured_mutation_epoch,
                expires_at,
            })?);
        self.backend
            .checked_batch(&[Statement::new(
                "INSERT INTO oci_registry_purge_fence_plans
                   (id, registry_id, action, actor_id, plan_idempotency_key,
                    apply_idempotency_key, expected_resource_version,
                    captured_mutation_epoch, confirmation_hash, state,
                    expires_at, created_at, applied_at, finished_at, last_error,
                    resource_version)
                 VALUES(?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, ?8, 'planned',
                        ?9, ?10, NULL, NULL, NULL, 1)",
                vals![
                    id,
                    input.registry_id,
                    input.action.as_str(),
                    input.actor_id,
                    input.idempotency_key,
                    input.expected_resource_version,
                    captured_mutation_epoch,
                    confirmation_hash.to_string(),
                    expires_at,
                    input.now
                ],
            )
            .expecting(1)])
            .await?;
        self.oci_registry_purge_fence_plan_for_actor(&id, &input.actor_id)
            .await?
            .context("OCI purge-fence plan disappeared after creation")
    }

    /// Returns one reviewed purge-fence plan only to its authenticated actor.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed persisted state or database failure.
    pub async fn oci_registry_purge_fence_plan_for_actor(
        &self,
        plan_id: &str,
        actor_id: &str,
    ) -> Result<Option<OciRegistryPurgeFencePlanRecord>> {
        self.backend
            .query_opt(
                &format!("{PURGE_FENCE_PLAN_COLUMNS} WHERE plan.id = ?1 AND plan.actor_id = ?2"),
                &vals![plan_id, actor_id],
            )
            .await?
            .as_ref()
            .map(row_to_purge_fence_plan)
            .transpose()
    }

    /// Applies one reviewed purge-fence transition atomically.
    ///
    /// # Errors
    ///
    /// Returns an error for ownership, expiry, confirmation, CAS, registry
    /// quiescence, epoch, current-fence, idempotency, or database failure.
    pub async fn apply_oci_registry_purge_fence(
        &self,
        input: &ApplyOciRegistryPurgeFence,
    ) -> Result<OciRegistryPurgeFencePlanRecord> {
        validate_key_bytes(&input.plan_id, "OCI purge-fence plan id", 64)?;
        validate_key_bytes(&input.actor_id, "OCI purge-fence actor", 128)?;
        validate_key_bytes(
            &input.idempotency_key,
            "OCI purge-fence apply idempotency key",
            128,
        )?;
        if input.expected_resource_version < 1 || input.now <= 0 {
            bail!("OCI purge-fence apply identity is invalid");
        }
        let plan = self
            .oci_registry_purge_fence_plan_for_actor(&input.plan_id, &input.actor_id)
            .await?
            .context("OCI purge-fence plan does not exist for this actor")?;
        if plan.state == "applied" {
            let replay = self
                .backend
                .query_opt(
                    "SELECT apply_idempotency_key FROM oci_registry_purge_fence_plans
                     WHERE id = ?1 AND actor_id = ?2",
                    &vals![input.plan_id, input.actor_id],
                )
                .await?
                .and_then(|row| row.get::<Option<String>>(0).ok())
                .flatten();
            if replay.as_deref() == Some(input.idempotency_key.as_str()) {
                return Ok(plan);
            }
            bail!("OCI purge-fence apply idempotency conflict");
        }
        if plan.state != "planned"
            || plan.expires_at <= input.now
            || plan.resource_version != input.expected_resource_version
            || plan.confirmation_hash != input.confirmation_hash
        {
            bail!("OCI purge-fence reviewed plan is stale or mismatched");
        }
        let mut statements = vec![Statement::new(
            "INSERT INTO oci_registry_state
               (registry_id, mutation_epoch, charged_bytes, charged_objects, updated_at)
             SELECT id, 0, 0, 0, ?2 FROM registries WHERE id = ?1
             ON CONFLICT(registry_id) DO NOTHING",
            vals![plan.registry_id, input.now],
        )
        .unchecked()];
        match plan.action {
            OciRegistryPurgeFenceAction::Begin => {
                statements.extend([
                    Statement::new(
                        "DELETE FROM oci_registry_purge_fences
                         WHERE registry_id = ?1 AND state = 'aborted'",
                        vals![plan.registry_id],
                    )
                    .unchecked(),
                    Statement::new(
                        "UPDATE registries SET updated_at = updated_at
                         WHERE id = ?1 AND resource_version = ?2
                           AND EXISTS (SELECT 1 FROM oci_registry_state registry_state
                             WHERE registry_state.registry_id = ?1
                               AND registry_state.mutation_epoch = ?3)
                           AND NOT EXISTS (SELECT 1 FROM oci_repositories
                             WHERE registry_id = ?1)
                           AND NOT EXISTS (SELECT 1 FROM oci_blobs WHERE registry_id = ?1)
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
                            plan.registry_id,
                            plan.expected_resource_version,
                            plan.captured_mutation_epoch
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
                            plan.registry_id,
                            input.actor_id,
                            plan.id,
                            plan.expected_resource_version,
                            plan.captured_mutation_epoch,
                            input.now
                        ],
                    )
                    .expecting(1),
                ]);
            }
            OciRegistryPurgeFenceAction::Abort => statements.push(
                Statement::new(
                    "UPDATE oci_registry_purge_fences
                     SET state = 'aborted', aborted_at = ?5,
                         resource_version = resource_version + 1
                     WHERE registry_id = ?1 AND actor_id = ?2
                       AND state = 'collecting' AND resource_version = ?3
                       AND EXISTS (SELECT 1 FROM oci_registry_state registry_state
                         WHERE registry_state.registry_id = ?1
                           AND registry_state.mutation_epoch = ?4)",
                    vals![
                        plan.registry_id,
                        input.actor_id,
                        plan.expected_resource_version,
                        plan.captured_mutation_epoch,
                        input.now
                    ],
                )
                .expecting(1),
            ),
        }
        statements.push(
            Statement::new(
                "UPDATE oci_registry_purge_fence_plans
                 SET state = 'applied', apply_idempotency_key = ?4,
                     applied_at = ?5, finished_at = ?5,
                     resource_version = resource_version + 1
                 WHERE id = ?1 AND actor_id = ?2 AND state = 'planned'
                   AND resource_version = ?3 AND expires_at > ?5
                   AND confirmation_hash = ?6",
                vals![
                    input.plan_id,
                    input.actor_id,
                    input.expected_resource_version,
                    input.idempotency_key,
                    input.now,
                    input.confirmation_hash.to_string()
                ],
            )
            .expecting(1),
        );
        self.backend.checked_batch(&statements).await?;
        self.oci_registry_purge_fence_plan_for_actor(&input.plan_id, &input.actor_id)
            .await?
            .context("OCI purge-fence plan disappeared after apply")
    }

    /// Returns actor-bound reviewed state plus exact current purge readiness.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown actor plan, invalid time, malformed
    /// persisted state, or database failure.
    pub async fn oci_registry_purge_fence_status_for_actor(
        &self,
        plan_id: &str,
        actor_id: &str,
        now: i64,
    ) -> Result<Option<OciRegistryPurgeFenceStatus>> {
        if now < 0 {
            bail!("OCI purge-fence status time is invalid");
        }
        let Some(plan) = self
            .oci_registry_purge_fence_plan_for_actor(plan_id, actor_id)
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(OciRegistryPurgeFenceStatus {
            fence: self.oci_registry_purge_fence(plan.registry_id).await?,
            blockers: self
                .oci_registry_purge_blockers(plan.registry_id, now)
                .await?,
            plan,
        }))
    }

    async fn oci_registry_purge_fence_plan_by_idempotency(
        &self,
        registry_id: i64,
        actor_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<OciRegistryPurgeFencePlanRecord>> {
        self.backend
            .query_opt(
                &format!(
                    "{PURGE_FENCE_PLAN_COLUMNS}
                     WHERE plan.registry_id = ?1 AND plan.actor_id = ?2
                       AND plan.plan_idempotency_key = ?3"
                ),
                &vals![registry_id, actor_id, idempotency_key],
            )
            .await?
            .as_ref()
            .map(row_to_purge_fence_plan)
            .transpose()
    }
}

const PURGE_FENCE_PLAN_COLUMNS: &str = "SELECT plan.id, plan.registry_id, plan.action,
       plan.actor_id, plan.expected_resource_version, plan.captured_mutation_epoch,
       plan.confirmation_hash, plan.state, plan.expires_at, plan.created_at,
       plan.applied_at, plan.finished_at, plan.last_error, plan.resource_version
     FROM oci_registry_purge_fence_plans plan";

fn row_to_purge_fence_plan(row: &crate::value::Row) -> Result<OciRegistryPurgeFencePlanRecord> {
    let action = match row.get::<String>(2)?.as_str() {
        "begin" => OciRegistryPurgeFenceAction::Begin,
        "abort" => OciRegistryPurgeFenceAction::Abort,
        _ => bail!("persisted OCI purge-fence action is invalid"),
    };
    Ok(OciRegistryPurgeFencePlanRecord {
        id: row.get(0)?,
        registry_id: row.get(1)?,
        action,
        actor_id: row.get(3)?,
        expected_resource_version: row.get(4)?,
        captured_mutation_epoch: row.get(5)?,
        confirmation_hash: Sha256Digest::parse(&row.get::<String>(6)?)?,
        state: row.get(7)?,
        expires_at: row.get(8)?,
        created_at: row.get(9)?,
        applied_at: row.get(10)?,
        finished_at: row.get(11)?,
        last_error: row.get(12)?,
        resource_version: row.get(13)?,
    })
}
