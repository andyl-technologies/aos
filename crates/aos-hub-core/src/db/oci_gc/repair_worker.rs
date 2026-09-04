//! Exact provider execution and evidence for reviewed untracked-object repair.
//!
//! Planning freezes one current-head provider identity. Applying pins any
//! immutable delete credential, and this module is the only authority that can
//! claim the physical action or turn a provider response into durable absence
//! evidence. A successful repair invalidates the old inventory head for
//! scheduling purposes by marking its reviewed entry deleted; a fresh complete
//! inventory is still required before registry purge can converge.

use anyhow::{bail, Context, Result};
use aos_oci_types::Sha256Digest;

use super::{oci_gc_deletion_evidence_digest, OciGcDeleteOutcome, OciUntrackedRepairPlanRecord};
use crate::backend::Statement;
use crate::db::{sanitize_log_text, validate_key_bytes, Database};

/// Exact reviewed untracked-object repair claimed by one provider worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciUntrackedRepairClaim {
    /// Complete non-secret reviewed provider identity and operation state.
    pub repair: OciUntrackedRepairPlanRecord,
    /// Opaque receipt required by the terminal response.
    pub claim_token: String,
    /// Claim lease expiry in Unix seconds.
    pub lease_expires_at: i64,
    /// Current provider-attempt count after this claim.
    pub attempt_count: u32,
    /// Maximum automatic attempts before operator intervention.
    pub max_attempts: u32,
}

/// Exact successful provider response for an untracked delete repair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordOciUntrackedRepairSuccess {
    /// Reviewed plan and durable operation id.
    pub plan_id: String,
    /// Opaque receipt returned by claim.
    pub claim_token: String,
    /// Stable response-loss retry identity.
    pub response_idempotency_key: String,
    /// `Deleted` or `AlreadyAbsent` provider outcome.
    pub outcome: OciGcDeleteOutcome,
    /// Strong entity tag used by conditional delete.
    pub conditional_etag: Option<String>,
    /// Provider request identity retained for audit.
    pub provider_request_id: Option<String>,
    /// Canonical complete response-evidence digest.
    pub evidence_digest: Sha256Digest,
    /// Provider absence confirmation time.
    pub confirmed_at: i64,
}

/// Failed provider response for a claimed untracked delete repair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordOciUntrackedRepairFailure {
    /// Reviewed plan and durable operation id.
    pub plan_id: String,
    /// Opaque receipt returned by claim.
    pub claim_token: String,
    /// Sanitized provider failure detail.
    pub error: String,
    /// Whether automatic retry is safe for this exact frozen identity.
    pub retryable: bool,
    /// Retry delay in seconds.
    pub backoff_seconds: i64,
    /// Failure observation time.
    pub failed_at: i64,
}

impl Database {
    /// Claims one bounded, currently executable untracked delete repair.
    ///
    /// The selector examines at most 100 due rows and skips stale topology,
    /// revoked credentials, stale inventory, and other blocked earlier work.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed worker/lease identity, corrupt persisted
    /// evidence, or a database failure.
    pub async fn claim_oci_untracked_repair(
        &self,
        worker_id: &str,
        claim_token: &str,
        now: i64,
        lease_seconds: i64,
    ) -> Result<Option<OciUntrackedRepairClaim>> {
        validate_key_bytes(worker_id, "OCI untracked repair worker", 128)?;
        validate_key_bytes(claim_token, "OCI untracked repair claim token", 64)?;
        if now < 0 || !(1..=3_600).contains(&lease_seconds) {
            bail!("OCI untracked repair claim lease is invalid");
        }
        let candidates = self
            .backend
            .query(
                "SELECT repair.id, repair.resource_version
                 FROM oci_untracked_repair_plans repair
                 WHERE repair.repair_kind = 'delete'
                   AND ((repair.state = 'pending' AND repair.next_attempt_at <= ?1)
                     OR (repair.state = 'claimed' AND repair.lease_expires_at <= ?1))
                   AND EXISTS (SELECT 1 FROM oci_registry_state registry_state
                     JOIN oci_provider_inventory_heads head
                       ON head.registry_id = registry_state.registry_id
                     JOIN oci_provider_inventory_entries entry
                       ON entry.generation_id = head.generation_id
                      AND entry.placement_id = head.placement_id
                     JOIN surface_placements placement
                       ON placement.id = repair.placement_id
                      AND placement.registry_id = repair.registry_id
                     JOIN surface_placement_observations observation
                       ON observation.placement_id = placement.id
                     JOIN bindings binding ON binding.id = repair.binding_id
                     LEFT JOIN binding_credential_revisions credential
                       ON credential.binding_id = repair.binding_id
                      AND credential.purpose = repair.delete_credential_purpose
                      AND credential.generation = repair.delete_credential_generation
                     WHERE registry_state.registry_id = repair.registry_id
                       AND registry_state.mutation_epoch = repair.captured_mutation_epoch
                       AND head.placement_id = repair.placement_id
                       AND head.generation_id = repair.inventory_generation_id
                       AND entry.object_key = repair.object_key
                       AND entry.classification = 'untracked'
                       AND entry.deleted_at IS NULL
                       AND entry.object_digest = repair.object_digest
                       AND entry.observed_hash = repair.observed_hash
                       AND entry.byte_size = repair.byte_size
                       AND entry.strong_etag = repair.strong_etag
                       AND placement.name = repair.placement_name
                       AND placement.prefix = repair.placement_prefix
                       AND placement.resource_version = repair.placement_resource_version
                       AND placement.write_spec_version = repair.placement_write_spec_version
                       AND observation.observation_version >=
                         repair.placement_observation_version
                       AND observation.state = 'ready'
                       AND observation.completeness = 'complete'
                       AND binding.resource_version = repair.binding_resource_version
                       AND ((repair.delete_credential_purpose IS NULL
                             AND repair.delete_credential_generation IS NULL
                             AND binding.kind = 'local_fs')
                         OR (credential.validation_state = 'valid'
                           AND EXISTS (SELECT 1
                             FROM oci_untracked_repair_credential_holds hold
                             WHERE hold.plan_id = repair.id
                               AND hold.binding_id = repair.binding_id
                               AND hold.purpose = repair.delete_credential_purpose
                               AND hold.generation = repair.delete_credential_generation))))
                 ORDER BY repair.next_attempt_at, repair.created_at, repair.id LIMIT 100",
                &vals![now],
            )
            .await?;
        for candidate in candidates {
            let plan_id: String = candidate.get(0)?;
            let expected_version: i64 = candidate.get(1)?;
            let lease_expires_at = now.saturating_add(lease_seconds);
            let claimed = self
                .backend
                .checked_batch(&[Statement::new(
                    "UPDATE oci_untracked_repair_plans
                     SET state = 'claimed', worker_id = ?2, claim_token = ?3,
                         lease_expires_at = ?4, attempt_count = attempt_count + 1,
                         resource_version = resource_version + 1
                     WHERE id = ?1 AND resource_version = ?5
                       AND ((state = 'pending' AND next_attempt_at <= ?6)
                         OR (state = 'claimed' AND lease_expires_at <= ?6))
                       AND EXISTS (SELECT 1 FROM oci_registry_state registry_state
                         JOIN oci_provider_inventory_heads head
                           ON head.registry_id = registry_state.registry_id
                         JOIN oci_provider_inventory_entries entry
                           ON entry.generation_id = head.generation_id
                          AND entry.placement_id = head.placement_id
                         JOIN surface_placements placement
                           ON placement.id = oci_untracked_repair_plans.placement_id
                          AND placement.registry_id =
                            oci_untracked_repair_plans.registry_id
                         JOIN surface_placement_observations observation
                           ON observation.placement_id = placement.id
                         JOIN bindings binding
                           ON binding.id = oci_untracked_repair_plans.binding_id
                         LEFT JOIN binding_credential_revisions credential
                           ON credential.binding_id = binding.id
                          AND credential.purpose =
                            oci_untracked_repair_plans.delete_credential_purpose
                          AND credential.generation =
                            oci_untracked_repair_plans.delete_credential_generation
                         WHERE registry_state.registry_id =
                                 oci_untracked_repair_plans.registry_id
                           AND registry_state.mutation_epoch =
                             oci_untracked_repair_plans.captured_mutation_epoch
                           AND head.placement_id =
                             oci_untracked_repair_plans.placement_id
                           AND head.generation_id =
                             oci_untracked_repair_plans.inventory_generation_id
                           AND entry.object_key = oci_untracked_repair_plans.object_key
                           AND entry.classification = 'untracked'
                           AND entry.deleted_at IS NULL
                           AND placement.name = oci_untracked_repair_plans.placement_name
                           AND placement.prefix = oci_untracked_repair_plans.placement_prefix
                           AND placement.resource_version =
                             oci_untracked_repair_plans.placement_resource_version
                           AND placement.write_spec_version =
                             oci_untracked_repair_plans.placement_write_spec_version
                           AND observation.observation_version >=
                             oci_untracked_repair_plans.placement_observation_version
                           AND observation.state = 'ready'
                           AND observation.completeness = 'complete'
                           AND binding.resource_version =
                             oci_untracked_repair_plans.binding_resource_version
                           AND ((oci_untracked_repair_plans.delete_credential_purpose IS NULL
                                 AND oci_untracked_repair_plans.delete_credential_generation IS NULL
                                 AND binding.kind = 'local_fs')
                             OR (credential.validation_state = 'valid'
                               AND EXISTS (SELECT 1
                                 FROM oci_untracked_repair_credential_holds hold
                                 WHERE hold.plan_id = oci_untracked_repair_plans.id
                                   AND hold.binding_id =
                                     oci_untracked_repair_plans.binding_id
                                   AND hold.purpose =
                                     oci_untracked_repair_plans.delete_credential_purpose
                                   AND hold.generation =
                                     oci_untracked_repair_plans.delete_credential_generation))))",
                    vals![
                        plan_id,
                        worker_id,
                        claim_token,
                        lease_expires_at,
                        expected_version,
                        now
                    ],
                )
                .expecting(1)])
                .await;
            if claimed.is_err() {
                continue;
            }
            let repair = self
                .oci_untracked_repair_plan(&plan_id)
                .await?
                .context("claimed OCI untracked repair disappeared")?;
            let attempts = self
                .backend
                .query_opt(
                    "SELECT attempt_count, max_attempts
                     FROM oci_untracked_repair_plans WHERE id = ?1",
                    &vals![plan_id],
                )
                .await?
                .context("claimed OCI untracked repair attempt state disappeared")?;
            return Ok(Some(OciUntrackedRepairClaim {
                repair,
                claim_token: claim_token.to_string(),
                lease_expires_at,
                attempt_count: u32::try_from(attempts.get::<i64>(0)?)?,
                max_attempts: u32::try_from(attempts.get::<i64>(1)?)?,
            }));
        }
        Ok(None)
    }

    /// Records canonical conditional-delete evidence and terminalizes a repair.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale claim, conflicting replay, malformed or
    /// mismatched evidence, stale current-head inventory, or database failure.
    pub async fn record_oci_untracked_repair_success(
        &self,
        input: &RecordOciUntrackedRepairSuccess,
    ) -> Result<OciUntrackedRepairPlanRecord> {
        validate_key_bytes(&input.plan_id, "OCI untracked repair id", 64)?;
        validate_key_bytes(&input.claim_token, "OCI untracked repair claim token", 64)?;
        validate_key_bytes(
            &input.response_idempotency_key,
            "OCI untracked repair response key",
            128,
        )?;
        if input.confirmed_at < 0
            || input.provider_request_id.as_ref().is_some_and(|value| {
                value.is_empty() || value.len() > 255 || value.chars().any(char::is_control)
            })
            || (input.outcome == OciGcDeleteOutcome::Deleted && input.conditional_etag.is_none())
        {
            bail!("OCI untracked repair deletion evidence is malformed");
        }
        let canonical = oci_gc_deletion_evidence_digest(
            &input.plan_id,
            &input.response_idempotency_key,
            input.outcome,
            input.conditional_etag.as_deref(),
            input.provider_request_id.as_deref(),
            input.confirmed_at,
        )?;
        if canonical != input.evidence_digest {
            bail!("OCI untracked repair evidence digest conflicts with its payload");
        }
        if let Some(existing) = self.oci_untracked_repair_plan(&input.plan_id).await? {
            if existing.state == "confirmed_absent" {
                let response_key = self
                    .backend
                    .query_opt(
                        "SELECT response_idempotency_key
                         FROM oci_untracked_repair_plans WHERE id = ?1",
                        &vals![input.plan_id],
                    )
                    .await?
                    .and_then(|row| row.get::<Option<String>>(0).ok())
                    .flatten();
                let exact = response_key.as_deref()
                    == Some(input.response_idempotency_key.as_str())
                    && existing.outcome
                        == Some(match input.outcome {
                            OciGcDeleteOutcome::Deleted => {
                                super::OciUntrackedRepairOutcome::Deleted
                            }
                            OciGcDeleteOutcome::AlreadyAbsent => {
                                super::OciUntrackedRepairOutcome::AlreadyAbsent
                            }
                        })
                    && existing.provider_request_id == input.provider_request_id
                    && existing.conditional_etag == input.conditional_etag
                    && existing.evidence_digest == Some(input.evidence_digest)
                    && existing.confirmed_at == Some(input.confirmed_at);
                if exact {
                    return Ok(existing);
                }
                bail!("OCI untracked repair response replay conflicts with evidence");
            }
            if input.outcome == OciGcDeleteOutcome::Deleted
                && input.conditional_etag.as_deref() != Some(existing.strong_etag.as_str())
            {
                bail!("OCI untracked repair conditional tag conflicts with review");
            }
        }
        let outcome = match input.outcome {
            OciGcDeleteOutcome::Deleted => "deleted",
            OciGcDeleteOutcome::AlreadyAbsent => "already_absent",
        };
        self.backend
            .checked_batch(&[
                Statement::new(
                    "INSERT INTO oci_untracked_repair_evidence
                       (plan_id, outcome, provider_request_id, conditional_etag,
                        evidence_digest, confirmed_at)
                     SELECT id, ?3, ?4, ?5, ?6, ?7
                     FROM oci_untracked_repair_plans
                     WHERE id = ?1 AND claim_token = ?2 AND state = 'claimed'
                       AND lease_expires_at > ?7
                     ON CONFLICT(plan_id) DO NOTHING",
                    vals![
                        input.plan_id,
                        input.claim_token,
                        outcome,
                        input.provider_request_id,
                        input.conditional_etag,
                        input.evidence_digest.to_string(),
                        input.confirmed_at
                    ],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE oci_provider_inventory_entries SET deleted_at = ?3
                     WHERE generation_id = (SELECT inventory_generation_id
                       FROM oci_untracked_repair_plans WHERE id = ?1)
                       AND placement_id = (SELECT placement_id
                         FROM oci_untracked_repair_plans WHERE id = ?1)
                       AND object_key = (SELECT object_key
                         FROM oci_untracked_repair_plans WHERE id = ?1)
                       AND classification = 'untracked' AND deleted_at IS NULL
                       AND EXISTS (SELECT 1 FROM oci_untracked_repair_plans repair
                         WHERE repair.id = ?1 AND repair.claim_token = ?2
                           AND repair.state = 'claimed')",
                    vals![input.plan_id, input.claim_token, input.confirmed_at],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE oci_untracked_repair_plans
                     SET state = 'confirmed_absent', worker_id = NULL,
                         claim_token = NULL, lease_expires_at = NULL,
                         response_idempotency_key = ?3, finished_at = ?4,
                         last_error = NULL, resource_version = resource_version + 1
                     WHERE id = ?1 AND claim_token = ?2 AND state = 'claimed'
                       AND EXISTS (SELECT 1 FROM oci_untracked_repair_evidence evidence
                         WHERE evidence.plan_id = ?1 AND evidence.outcome = ?5
                           AND evidence.evidence_digest = ?6
                           AND evidence.confirmed_at = ?4)",
                    vals![
                        input.plan_id,
                        input.claim_token,
                        input.response_idempotency_key,
                        input.confirmed_at,
                        outcome,
                        input.evidence_digest.to_string()
                    ],
                )
                .expecting(1),
                Statement::new(
                    "DELETE FROM oci_untracked_repair_credential_holds
                     WHERE plan_id = ?1",
                    vals![input.plan_id],
                )
                .unchecked(),
            ])
            .await?;
        self.oci_untracked_repair_plan(&input.plan_id)
            .await?
            .context("OCI untracked repair disappeared after success")
    }

    /// Records a retryable or terminal failure for an exact repair claim.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed failure identity, a stale claim, or a
    /// database failure.
    pub async fn record_oci_untracked_repair_failure(
        &self,
        input: &RecordOciUntrackedRepairFailure,
    ) -> Result<OciUntrackedRepairPlanRecord> {
        validate_key_bytes(&input.plan_id, "OCI untracked repair id", 64)?;
        validate_key_bytes(&input.claim_token, "OCI untracked repair claim token", 64)?;
        if input.failed_at < 0 || input.backoff_seconds < 0 || input.backoff_seconds > 86_400 {
            bail!("OCI untracked repair failure timing is invalid");
        }
        let error = sanitize_log_text(&input.error);
        let next_attempt_at = input.failed_at.saturating_add(input.backoff_seconds);
        self.backend
            .checked_batch(&[Statement::new(
                "UPDATE oci_untracked_repair_plans
                 SET state = CASE WHEN ?4 = 1 AND attempt_count < max_attempts
                              THEN 'pending' ELSE 'failed' END,
                     worker_id = NULL, claim_token = NULL, lease_expires_at = NULL,
                     next_attempt_at = ?5, last_error = ?3,
                     finished_at = CASE WHEN ?4 = 1 AND attempt_count < max_attempts
                                   THEN NULL ELSE ?6 END,
                     resource_version = resource_version + 1
                 WHERE id = ?1 AND claim_token = ?2 AND state = 'claimed'",
                vals![
                    input.plan_id,
                    input.claim_token,
                    error,
                    i64::from(input.retryable),
                    next_attempt_at,
                    input.failed_at
                ],
            )
            .expecting(1)])
            .await?;
        self.oci_untracked_repair_plan(&input.plan_id)
            .await?
            .context("OCI untracked repair disappeared after failure")
    }
}
