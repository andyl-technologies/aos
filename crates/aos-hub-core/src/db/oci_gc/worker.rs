//! Exact placement-action claim, evidence, retry, and logical finalization.

use anyhow::{bail, Context, Result};
use aos_oci_types::{MediaType, RepositoryName, Sha256Digest};
use serde::Serialize;

use super::{OciGcCandidateRecord, OciGcPlacementActionRecord};
use crate::backend::Statement;
use crate::db::{sanitize_log_text, validate_key_bytes, Database};

/// Exact immutable placement access frozen by a reviewed GC plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciGcPlacementActionClaim {
    /// Stable placement-action job id.
    pub action_id: String,
    /// Stable GC run and operation id.
    pub generation_id: String,
    /// Registry owning the immutable object.
    pub registry_id: i64,
    /// Repositories linked before tombstoning.
    pub repositories: Vec<RepositoryName>,
    /// Exact immutable OCI digest.
    pub digest: Sha256Digest,
    /// Persisted OCI media type.
    pub media_type: MediaType,
    /// Canonical provider key.
    pub object_key: String,
    /// Exact expected provider content hash.
    pub expected_hash: Sha256Digest,
    /// Exact expected provider byte length.
    pub expected_size: u64,
    /// Strong entity tag frozen by provider enumeration.
    pub expected_strong_etag: Option<String>,
    /// Whether the sealed inventory contained the exact canonical key.
    pub inventory_entry_present: bool,
    /// Frozen placement id.
    pub placement_id: i64,
    /// Frozen placement name.
    pub placement_name: String,
    /// Frozen provider prefix.
    pub placement_prefix: String,
    /// Frozen placement optimistic-concurrency version.
    pub placement_resource_version: i64,
    /// Frozen placement writer-spec version.
    pub placement_write_spec_version: i64,
    /// Frozen placement ready/complete observation version.
    pub placement_observation_version: i64,
    /// Frozen binding id.
    pub binding_id: i64,
    /// Frozen binding optimistic-concurrency version.
    pub binding_resource_version: i64,
    /// Frozen immutable binding writer revision.
    pub binding_write_revision: i64,
    /// Frozen delete credential purpose, absent for local filesystem IO.
    pub delete_credential_purpose: Option<String>,
    /// Frozen delete credential generation, absent for local filesystem IO.
    pub delete_credential_generation: Option<i64>,
    /// Frozen observed conditional-delete semantics.
    pub delete_capability_fingerprint: String,
    /// Frozen capability audit version.
    pub delete_capability_resource_version: i64,
    /// Exact provider inventory generation.
    pub inventory_generation_id: String,
    /// Canonical complete provider inventory digest.
    pub inventory_digest: Sha256Digest,
    /// Provider enumeration observation time.
    pub inventory_observed_at: i64,
    /// Opaque claim receipt.
    pub claim_token: String,
    /// Claim lease expiry in Unix seconds.
    pub lease_expires_at: i64,
    /// Current provider-attempt count.
    pub attempt_count: u32,
    /// Maximum automatic attempts before maintenance requeue.
    pub max_attempts: u32,
    /// Action optimistic-concurrency version after claim.
    pub resource_version: i64,
}

/// Provider absence outcome accepted as deletion evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OciGcDeleteOutcome {
    /// Conditional delete succeeded against the exact frozen entity tag.
    Deleted,
    /// Exact frozen provider address was already absent.
    AlreadyAbsent,
}

impl OciGcDeleteOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Deleted => "deleted",
            Self::AlreadyAbsent => "already_absent",
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalDeletionEvidence<'a> {
    action_id: &'a str,
    response_idempotency_key: &'a str,
    outcome: &'a str,
    conditional_etag: Option<&'a str>,
    provider_request_id: Option<&'a str>,
    confirmed_at: i64,
}

/// Computes the canonical digest independently verified for deletion evidence.
///
/// # Errors
///
/// Returns an error when JSON serialization fails.
pub fn oci_gc_deletion_evidence_digest(
    action_id: &str,
    response_idempotency_key: &str,
    outcome: OciGcDeleteOutcome,
    conditional_etag: Option<&str>,
    provider_request_id: Option<&str>,
    confirmed_at: i64,
) -> Result<Sha256Digest> {
    Ok(Sha256Digest::digest(&serde_json::to_vec(
        &CanonicalDeletionEvidence {
            action_id,
            response_idempotency_key,
            outcome: outcome.as_str(),
            conditional_etag,
            provider_request_id,
            confirmed_at,
        },
    )?))
}

/// Idempotent successful provider response for one claimed action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordOciGcDeletionSuccess {
    /// Claimed action id.
    pub action_id: String,
    /// Exact opaque claim receipt.
    pub claim_token: String,
    /// Stable provider-response retry identity.
    pub response_idempotency_key: String,
    /// Exact absence outcome.
    pub outcome: OciGcDeleteOutcome,
    /// Strong conditional entity tag used for deletion.
    pub conditional_etag: Option<String>,
    /// Provider request identity, when supplied.
    pub provider_request_id: Option<String>,
    /// Canonical controller digest of the complete provider response.
    pub evidence_digest: Sha256Digest,
    /// Provider confirmation time in Unix seconds.
    pub confirmed_at: i64,
}

/// Failed provider response for one claimed action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordOciGcDeletionFailure {
    /// Claimed action id.
    pub action_id: String,
    /// Exact opaque claim receipt.
    pub claim_token: String,
    /// Sanitized provider failure detail.
    pub error: String,
    /// Whether the controller may retry before exhausting the reviewed limit.
    pub retryable: bool,
    /// Failure time in Unix seconds.
    pub now: i64,
}

/// Actor-bound idempotent maintenance requeue of one exhausted action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequeueOciGcPlacementAction {
    /// Failed action id.
    pub action_id: String,
    /// Authenticated operator actor id.
    pub actor_id: String,
    /// Actor-scoped retry identity.
    pub idempotency_key: String,
    /// Expected failed-action resource version.
    pub expected_resource_version: i64,
    /// Requeue time in Unix seconds.
    pub now: i64,
}

impl Database {
    /// Claims one exact, fully fenced OCI placement deletion action.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid worker identity/lease, stale reviewed
    /// roots or topology, malformed persisted data, or database failure.
    pub async fn claim_oci_gc_placement_action(
        &self,
        worker_id: &str,
        claim_token: &str,
        now: i64,
        lease_seconds: i64,
    ) -> Result<Option<OciGcPlacementActionClaim>> {
        validate_key_bytes(worker_id, "OCI GC worker id", 128)?;
        validate_key_bytes(claim_token, "OCI GC claim token", 64)?;
        if now < 0 || !(1..=3_600).contains(&lease_seconds) {
            bail!("OCI GC claim time or lease is invalid");
        }
        let candidates = self
            .backend
            .query(
                "SELECT action.id, action.resource_version
                 FROM oci_gc_placement_actions action
                 JOIN oci_gc_runs run ON run.id = action.run_id
                 WHERE run.state = 'applying'
                   AND EXISTS (SELECT 1 FROM oci_gc_registry_locks registry_lock
                     JOIN oci_registry_state registry_state
                       ON registry_state.registry_id = registry_lock.registry_id
                     JOIN oci_gc_candidates candidate
                       ON candidate.run_id = run.id AND candidate.digest = action.digest
                     JOIN oci_gc_placement_snapshots snapshot
                       ON snapshot.run_id = run.id AND snapshot.placement_id = action.placement_id
                     JOIN surface_placements placement
                       ON placement.id = snapshot.placement_id
                      AND placement.registry_id = snapshot.registry_id
                     JOIN surface_placement_observations observation
                       ON observation.placement_id = placement.id
                     JOIN bindings binding ON binding.id = snapshot.binding_id
                     JOIN binding_write_revisions frozen_revision
                       ON frozen_revision.binding_id = snapshot.binding_id
                      AND frozen_revision.revision = snapshot.binding_write_revision
                     LEFT JOIN binding_credential_revisions delete_credential
                       ON delete_credential.binding_id = snapshot.binding_id
                      AND delete_credential.purpose = snapshot.delete_credential_purpose
                      AND delete_credential.generation = snapshot.delete_credential_generation
                     WHERE registry_lock.registry_id = run.registry_id
                       AND registry_lock.run_id = run.id
                       AND registry_state.mutation_epoch = run.applied_mutation_epoch
                       AND candidate.state = 'deleting'
                       AND placement.name = snapshot.placement_name
                       AND placement.prefix = snapshot.placement_prefix
                       AND placement.resource_version = snapshot.placement_resource_version
                       AND placement.write_spec_version = snapshot.placement_write_spec_version
                       AND observation.observation_version >= snapshot.placement_observation_version
                       AND observation.state = 'ready'
                       AND observation.completeness = 'complete'
                       AND binding.resource_version = snapshot.binding_resource_version
                       AND ((snapshot.delete_credential_purpose IS NULL
                             AND snapshot.delete_credential_generation IS NULL
                             AND binding.kind = 'local_fs')
                         OR delete_credential.validation_state = 'valid'))
                   AND NOT EXISTS (SELECT 1 FROM oci_tags tag
                     WHERE tag.registry_id = action.registry_id AND tag.digest = action.digest)
                   AND NOT EXISTS (SELECT 1 FROM oci_release_roots root
                     WHERE root.registry_id = action.registry_id AND root.index_digest = action.digest)
                   AND NOT EXISTS (SELECT 1 FROM oci_release_evidence evidence
                     WHERE evidence.registry_id = action.registry_id
                       AND evidence.referrer_digest = action.digest
                       AND evidence.verification = 'verified')
                   AND NOT EXISTS (SELECT 1 FROM oci_leases lease
                     WHERE lease.registry_id = action.registry_id AND lease.digest = action.digest
                       AND lease.expires_at > ?1)
                   AND NOT EXISTS (SELECT 1 FROM oci_upload_sessions upload
                     WHERE upload.registry_id = action.registry_id
                       AND upload.state IN('active', 'completing')
                       AND (upload.expected_digest = action.digest
                         OR upload.final_digest = action.digest))
                   AND NOT EXISTS (SELECT 1 FROM oci_publication_sessions publication
                     LEFT JOIN oci_publication_objects object
                       ON object.publication_id = publication.id AND object.digest = action.digest
                     WHERE publication.registry_id = action.registry_id
                       AND publication.state IN('preparing', 'committing')
                       AND (publication.root_digest = action.digest OR object.digest IS NOT NULL))
                   AND ((action.state = 'pending' AND action.next_attempt_at <= ?1)
                     OR (action.state = 'claimed' AND action.lease_expires_at <= ?1))
                 ORDER BY action.next_attempt_at, action.run_id, action.id LIMIT 100",
                &vals![now],
            )
            .await?;
        for candidate in candidates {
            let action_id: String = candidate.get(0)?;
            let resource_version: i64 = candidate.get(1)?;
            let lease_expires_at = now.saturating_add(lease_seconds);
            let claimed = self
                .backend
                .checked_batch(&[Statement::new(
                    "UPDATE oci_gc_placement_actions
                     SET state = 'claimed', worker_id = ?2, claim_token = ?3,
                         lease_expires_at = ?4, attempt_count = attempt_count + 1,
                         resource_version = resource_version + 1
                     WHERE id = ?1 AND resource_version = ?5
                       AND ((state = 'pending' AND next_attempt_at <= ?6)
                         OR (state = 'claimed' AND lease_expires_at <= ?6))
                       AND EXISTS (SELECT 1 FROM oci_gc_runs run
                         JOIN oci_gc_registry_locks registry_lock
                           ON registry_lock.registry_id = run.registry_id
                          AND registry_lock.run_id = run.id
                         JOIN oci_registry_state registry_state
                           ON registry_state.registry_id = run.registry_id
                         JOIN oci_gc_candidates candidate
                           ON candidate.run_id = run.id
                          AND candidate.digest = oci_gc_placement_actions.digest
                         JOIN oci_gc_placement_snapshots snapshot
                           ON snapshot.run_id = run.id
                          AND snapshot.placement_id =
                            oci_gc_placement_actions.placement_id
                         JOIN surface_placements placement
                           ON placement.id = snapshot.placement_id
                          AND placement.registry_id = snapshot.registry_id
                         JOIN surface_placement_observations observation
                           ON observation.placement_id = placement.id
                         JOIN bindings binding ON binding.id = snapshot.binding_id
                         JOIN binding_write_revisions frozen_revision
                           ON frozen_revision.binding_id = snapshot.binding_id
                          AND frozen_revision.revision = snapshot.binding_write_revision
                         LEFT JOIN binding_credential_revisions delete_credential
                           ON delete_credential.binding_id = snapshot.binding_id
                          AND delete_credential.purpose =
                            snapshot.delete_credential_purpose
                          AND delete_credential.generation =
                            snapshot.delete_credential_generation
                         WHERE run.id = oci_gc_placement_actions.run_id
                           AND run.state = 'applying'
                           AND registry_state.mutation_epoch = run.applied_mutation_epoch
                           AND candidate.state = 'deleting'
                           AND placement.name = snapshot.placement_name
                           AND placement.prefix = snapshot.placement_prefix
                           AND placement.resource_version = snapshot.placement_resource_version
                           AND placement.write_spec_version = snapshot.placement_write_spec_version
                           AND observation.observation_version >=
                             snapshot.placement_observation_version
                           AND observation.state = 'ready'
                           AND observation.completeness = 'complete'
                           AND binding.resource_version = snapshot.binding_resource_version
                           AND ((snapshot.delete_credential_purpose IS NULL
                                 AND snapshot.delete_credential_generation IS NULL
                                 AND binding.kind = 'local_fs')
                             OR (delete_credential.validation_state = 'valid'
                               AND EXISTS (SELECT 1 FROM oci_gc_credential_holds hold
                                 WHERE hold.run_id = run.id
                                   AND hold.binding_id = snapshot.binding_id
                                   AND hold.purpose = snapshot.delete_credential_purpose
                                   AND hold.generation =
                                     snapshot.delete_credential_generation)))
                           AND NOT EXISTS (SELECT 1 FROM oci_tags tag
                             WHERE tag.registry_id = oci_gc_placement_actions.registry_id
                               AND tag.digest = oci_gc_placement_actions.digest)
                           AND NOT EXISTS (SELECT 1 FROM oci_release_roots root
                             WHERE root.registry_id = oci_gc_placement_actions.registry_id
                               AND root.index_digest = oci_gc_placement_actions.digest)
                           AND NOT EXISTS (SELECT 1 FROM oci_release_evidence evidence
                             WHERE evidence.registry_id = oci_gc_placement_actions.registry_id
                               AND evidence.referrer_digest = oci_gc_placement_actions.digest
                               AND evidence.verification = 'verified')
                           AND NOT EXISTS (SELECT 1 FROM oci_leases lease
                             WHERE lease.registry_id = oci_gc_placement_actions.registry_id
                               AND lease.digest = oci_gc_placement_actions.digest
                               AND lease.expires_at > ?6)
                           AND NOT EXISTS (SELECT 1 FROM oci_upload_sessions upload
                             WHERE upload.registry_id = oci_gc_placement_actions.registry_id
                               AND upload.state IN('active', 'completing')
                               AND (upload.expected_digest = oci_gc_placement_actions.digest
                                 OR upload.final_digest = oci_gc_placement_actions.digest))
                           AND NOT EXISTS (SELECT 1
                             FROM oci_publication_sessions publication
                             JOIN oci_publication_objects object
                               ON object.publication_id = publication.id
                             WHERE publication.registry_id = oci_gc_placement_actions.registry_id
                               AND publication.state IN('preparing', 'committing')
                               AND object.digest = oci_gc_placement_actions.digest))
                           AND NOT EXISTS (SELECT 1
                             FROM oci_publication_sessions publication
                             WHERE publication.registry_id = oci_gc_placement_actions.registry_id
                               AND publication.state IN('preparing', 'committing')
                               AND publication.root_digest = oci_gc_placement_actions.digest)",
                    vals![
                        action_id,
                        worker_id,
                        claim_token,
                        lease_expires_at,
                        resource_version,
                        now
                    ],
                )
                .expecting(1)])
                .await;
            if claimed.is_err() {
                continue;
            }
            return self
                .oci_gc_action_claim(&action_id, claim_token)
                .await?
                .map(Some)
                .context("OCI GC action disappeared after claim");
        }
        Ok(None)
    }

    /// Records idempotent exact-delete or already-absent provider evidence.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale claim, evidence replay conflict, weak or
    /// mismatched entity tag, malformed input, or database failure.
    pub async fn record_oci_gc_placement_action_success(
        &self,
        input: &RecordOciGcDeletionSuccess,
    ) -> Result<OciGcPlacementActionRecord> {
        validate_key_bytes(&input.action_id, "OCI GC action id", 64)?;
        validate_key_bytes(&input.claim_token, "OCI GC claim token", 64)?;
        validate_key_bytes(
            &input.response_idempotency_key,
            "OCI GC response idempotency key",
            128,
        )?;
        if input.confirmed_at < 0 {
            bail!("OCI GC evidence time is invalid");
        }
        let conditional_etag = input
            .conditional_etag
            .as_deref()
            .map(crate::surface_write::strong_if_match_etag)
            .transpose()?;
        if input.outcome == OciGcDeleteOutcome::Deleted && conditional_etag.is_none() {
            bail!("conditional deletion requires a strong entity tag");
        }
        let expected_evidence_digest = oci_gc_deletion_evidence_digest(
            &input.action_id,
            &input.response_idempotency_key,
            input.outcome,
            conditional_etag.as_deref(),
            input.provider_request_id.as_deref(),
            input.confirmed_at,
        )?;
        if input.evidence_digest != expected_evidence_digest {
            bail!("OCI GC deletion evidence digest is not canonical");
        }
        if let Some(existing) = self
            .backend
            .query_opt(
                "SELECT evidence.action_id, evidence.outcome,
                        evidence.conditional_etag, evidence.evidence_digest,
                        evidence.provider_request_id, evidence.confirmed_at
                 FROM oci_gc_deletion_evidence evidence
                 WHERE evidence.response_idempotency_key = ?1",
                &vals![input.response_idempotency_key],
            )
            .await?
        {
            if existing.get::<String>(0)? == input.action_id
                && existing.get::<String>(1)? == input.outcome.as_str()
                && existing.get::<Option<String>>(2)? == conditional_etag
                && existing.get::<String>(3)? == input.evidence_digest.to_string()
                && existing.get::<Option<String>>(4)? == input.provider_request_id
                && existing.get::<i64>(5)? == input.confirmed_at
            {
                return self
                    .oci_gc_placement_action(&input.action_id)
                    .await?
                    .context("OCI GC action disappeared after evidence replay");
            }
            bail!("OCI GC evidence idempotency conflict");
        }
        self.backend
            .checked_batch(&[
                Statement::new(
                    "INSERT INTO oci_gc_deletion_evidence
                       (action_id, response_idempotency_key, outcome,
                        conditional_etag, provider_request_id, evidence_digest,
                        confirmed_at)
                     SELECT action.id, ?3, ?4, ?5, ?6, ?7, ?8
                     FROM oci_gc_placement_actions action
                     WHERE action.id = ?1 AND action.state = 'claimed'
                       AND action.claim_token = ?2
                       AND (?4 = 'already_absent'
                         OR action.expected_strong_etag = ?5)",
                    vals![
                        input.action_id,
                        input.claim_token,
                        input.response_idempotency_key,
                        input.outcome.as_str(),
                        conditional_etag,
                        input.provider_request_id,
                        input.evidence_digest.to_string(),
                        input.confirmed_at
                    ],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE oci_gc_placement_actions
                     SET state = 'confirmed_absent', worker_id = NULL,
                         claim_token = NULL, lease_expires_at = NULL,
                         confirmed_at = ?3, last_error = NULL,
                         resource_version = resource_version + 1
                     WHERE id = ?1 AND state = 'claimed' AND claim_token = ?2",
                    vals![input.action_id, input.claim_token, input.confirmed_at],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE oci_provider_inventory_entries SET deleted_at = ?2
                     WHERE generation_id = (SELECT inventory_generation_id
                       FROM oci_gc_placement_actions WHERE id = ?1)
                       AND object_key = (SELECT object_key
                         FROM oci_gc_placement_actions WHERE id = ?1)
                       AND deleted_at IS NULL",
                    vals![input.action_id, input.confirmed_at],
                )
                .unchecked(),
            ])
            .await?;
        self.oci_gc_placement_action(&input.action_id)
            .await?
            .context("OCI GC action disappeared after success")
    }

    /// Records a bounded retry or terminal maintenance-required action failure.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale claim, invalid detail/time, or database
    /// failure.
    pub async fn record_oci_gc_placement_action_failure(
        &self,
        input: &RecordOciGcDeletionFailure,
    ) -> Result<OciGcPlacementActionRecord> {
        validate_key_bytes(&input.action_id, "OCI GC action id", 64)?;
        validate_key_bytes(&input.claim_token, "OCI GC claim token", 64)?;
        if input.now < 0 {
            bail!("OCI GC action failure time is invalid");
        }
        let error = sanitize_log_text(&input.error);
        let next_attempt_at = input.now.saturating_add(30);
        self.backend
            .checked_batch(&[Statement::new(
                "UPDATE oci_gc_placement_actions
                     SET state = CASE WHEN ?4 = 1 AND attempt_count < max_attempts
                           THEN 'pending' ELSE 'failed' END,
                         worker_id = NULL, claim_token = NULL,
                         lease_expires_at = NULL, last_error = ?3,
                         next_attempt_at = ?5,
                         resource_version = resource_version + 1
                     WHERE id = ?1 AND state = 'claimed' AND claim_token = ?2",
                vals![
                    input.action_id,
                    input.claim_token,
                    error,
                    i64::from(input.retryable),
                    next_attempt_at
                ],
            )
            .expecting(1)])
            .await?;
        self.oci_gc_placement_action(&input.action_id)
            .await?
            .context("OCI GC action disappeared after failure")
    }

    /// Requeues one exhausted action after an operator repairs exact access.
    ///
    /// The same reviewed placement identity remains frozen; deleted candidates
    /// are never made visible again.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale version, nonfailed action, inactive run,
    /// invalid time, or database failure.
    pub async fn requeue_oci_gc_placement_action(
        &self,
        input: &RequeueOciGcPlacementAction,
    ) -> Result<OciGcPlacementActionRecord> {
        validate_key_bytes(&input.action_id, "OCI GC action id", 64)?;
        validate_key_bytes(&input.actor_id, "OCI GC requeue actor id", 128)?;
        validate_key_bytes(
            &input.idempotency_key,
            "OCI GC requeue idempotency key",
            128,
        )?;
        if input.expected_resource_version <= 0 || input.now < 0 {
            bail!("OCI GC action requeue fence is invalid");
        }
        if let Some(existing) = self.oci_gc_placement_action(&input.action_id).await? {
            let replay = self
                .backend
                .query_opt(
                    "SELECT requeue_actor_id, requeue_idempotency_key,
                            requeue_expected_resource_version
                     FROM oci_gc_placement_actions WHERE id = ?1",
                    &vals![input.action_id],
                )
                .await?
                .context("OCI GC action disappeared during requeue replay")?;
            if replay.get::<Option<String>>(0)?.as_deref() == Some(&input.actor_id)
                && replay.get::<Option<String>>(1)?.as_deref() == Some(&input.idempotency_key)
                && replay.get::<Option<i64>>(2)? == Some(input.expected_resource_version)
            {
                return Ok(existing);
            }
        }
        self.backend
            .checked_batch(&[Statement::new(
                "UPDATE oci_gc_placement_actions
                     SET state = 'pending', attempt_count = 0,
                         next_attempt_at = ?5, last_error = NULL,
                         requeue_actor_id = ?3, requeue_idempotency_key = ?4,
                         requeue_expected_resource_version = ?2,
                         resource_version = resource_version + 1
                     WHERE id = ?1 AND resource_version = ?2 AND state = 'failed'
                       AND EXISTS (SELECT 1 FROM oci_gc_runs run
                         JOIN oci_gc_registry_locks registry_lock
                           ON registry_lock.run_id = run.id
                          AND registry_lock.registry_id = run.registry_id
                         WHERE run.id = oci_gc_placement_actions.run_id
                           AND run.state = 'applying')",
                vals![
                    input.action_id,
                    input.expected_resource_version,
                    input.actor_id,
                    input.idempotency_key,
                    input.now
                ],
            )
            .expecting(1)])
            .await?;
        self.oci_gc_placement_action(&input.action_id)
            .await?
            .context("OCI GC action disappeared after maintenance requeue")
    }

    /// Marks one candidate physically absent after every placement is proven absent.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid identity, incomplete action set, stale
    /// state, malformed persisted data, or database failure.
    pub async fn finalize_oci_gc_candidate(
        &self,
        generation_id: &str,
        digest: Sha256Digest,
        now: i64,
    ) -> Result<OciGcCandidateRecord> {
        validate_key_bytes(generation_id, "OCI GC generation id", 64)?;
        if now < 0 {
            bail!("OCI GC candidate finalization time is invalid");
        }
        if let Some(existing) = self.oci_gc_candidate(generation_id, digest).await? {
            if matches!(existing.state.as_str(), "physically_absent" | "complete") {
                return Ok(existing);
            }
        }
        self.backend
            .checked_batch(&[Statement::new(
                "UPDATE oci_gc_candidates
                     SET state = 'physically_absent',
                         resource_version = resource_version + 1
                     WHERE run_id = ?1 AND digest = ?2 AND state = 'deleting'
                       AND EXISTS (SELECT 1 FROM oci_gc_runs run
                         JOIN oci_gc_registry_locks registry_lock
                           ON registry_lock.run_id = run.id
                          AND registry_lock.registry_id = run.registry_id
                         WHERE run.id = ?1 AND run.state = 'applying')
                       AND NOT EXISTS (SELECT 1 FROM oci_gc_placement_actions action
                         WHERE action.run_id = ?1 AND action.digest = ?2
                           AND action.state <> 'confirmed_absent')",
                vals![generation_id, digest.to_string()],
            )
            .expecting(1)])
            .await?;
        self.oci_gc_candidate(generation_id, digest)
            .await?
            .context("OCI GC candidate disappeared after physical finalization")
    }

    /// Atomically removes catalog/quota identity after every candidate is absent.
    ///
    /// This transition also releases the registry-wide GC fence. Historical
    /// reviewed snapshots/actions/evidence remain self-contained.
    ///
    /// # Errors
    ///
    /// Returns an error until every action and candidate has exact absence
    /// evidence, when a root/link/epoch fence changed, or on database failure.
    pub async fn finalize_oci_gc_generation(
        &self,
        generation_id: &str,
        now: i64,
    ) -> Result<super::OciGcGenerationRecord> {
        validate_key_bytes(generation_id, "OCI GC generation id", 64)?;
        if now < 0 {
            bail!("OCI GC generation finalization time is invalid");
        }
        let run = self
            .backend
            .query_opt(
                "SELECT registry_id, applied_mutation_epoch, planned_bytes,
                        planned_objects, state
                 FROM oci_gc_runs WHERE id = ?1",
                &vals![generation_id],
            )
            .await?
            .context("OCI GC generation does not exist")?;
        let registry_id: i64 = run.get(0)?;
        let state: String = run.get(4)?;
        if state == "complete" {
            return self
                .oci_gc_generation(registry_id, generation_id)
                .await?
                .context("completed OCI GC generation disappeared");
        }
        if state != "applying" {
            bail!("OCI GC generation is not applying");
        }
        let applied_epoch: i64 = run
            .get::<Option<i64>>(1)?
            .context("applying OCI GC generation lacks an applied epoch")?;
        let planned_bytes: i64 = run.get(2)?;
        let planned_objects: i64 = run.get(3)?;
        let org_id = self
            .backend
            .query_opt(
                "SELECT org_id FROM registries WHERE id = ?1",
                &vals![registry_id],
            )
            .await?
            .context("OCI GC registry disappeared before finalization")?
            .get::<Option<i64>>(0)?;
        let org_usage_statement = if let Some(org_id) = org_id {
            Statement::new(
                "UPDATE org_usage
                 SET used_bytes = used_bytes - ?2,
                     object_count = object_count - ?3, updated_at = ?4
                 WHERE org_id = ?1 AND used_bytes >= ?2 AND object_count >= ?3",
                vals![org_id, planned_bytes, planned_objects, now],
            )
            .expecting(1)
        } else {
            Statement::new(
                "UPDATE oci_gc_runs SET resource_version = resource_version
                 WHERE id = ?1 AND EXISTS (SELECT 1 FROM registries registry
                   WHERE registry.id = ?2 AND registry.org_id IS NULL)",
                vals![generation_id, registry_id],
            )
            .expecting(1)
        };

        let statements = vec![
            Statement::new(
                "UPDATE oci_gc_runs SET resource_version = resource_version
                     WHERE id = ?1 AND registry_id = ?2 AND state = 'applying'
                       AND applied_mutation_epoch = ?3
                       AND EXISTS (SELECT 1 FROM oci_gc_registry_locks registry_lock
                         WHERE registry_lock.run_id = ?1
                           AND registry_lock.registry_id = ?2)
                       AND EXISTS (SELECT 1 FROM oci_registry_state registry_state
                         WHERE registry_state.registry_id = ?2
                           AND registry_state.mutation_epoch = ?3)
                       AND NOT EXISTS (SELECT 1 FROM oci_gc_candidates candidate
                         WHERE candidate.run_id = ?1
                           AND candidate.state <> 'physically_absent')
                       AND NOT EXISTS (SELECT 1 FROM oci_gc_placement_actions action
                         WHERE action.run_id = ?1
                           AND action.state <> 'confirmed_absent')
                       AND NOT EXISTS (SELECT 1 FROM oci_gc_candidates candidate
                         JOIN oci_repository_objects link
                           ON link.registry_id = candidate.registry_id
                          AND link.digest = candidate.digest
                         WHERE candidate.run_id = ?1)
                       AND NOT EXISTS (SELECT 1 FROM oci_gc_candidates candidate
                         JOIN oci_tags tag ON tag.registry_id = candidate.registry_id
                          AND tag.digest = candidate.digest
                         WHERE candidate.run_id = ?1)
                       AND NOT EXISTS (SELECT 1 FROM oci_gc_candidates candidate
                         JOIN oci_release_roots root
                           ON root.registry_id = candidate.registry_id
                          AND root.index_digest = candidate.digest
                         WHERE candidate.run_id = ?1)
                       AND NOT EXISTS (SELECT 1 FROM oci_gc_candidates candidate
                         JOIN oci_leases lease
                           ON lease.registry_id = candidate.registry_id
                          AND lease.digest = candidate.digest
                          AND lease.expires_at > ?4
                         WHERE candidate.run_id = ?1)
                       AND NOT EXISTS (SELECT 1 FROM oci_gc_candidates candidate
                         JOIN oci_upload_sessions upload
                           ON upload.registry_id = candidate.registry_id
                          AND upload.state IN('active', 'completing')
                          AND (upload.expected_digest = candidate.digest
                            OR upload.final_digest = candidate.digest)
                         WHERE candidate.run_id = ?1)
                       AND NOT EXISTS (SELECT 1 FROM oci_gc_candidates candidate
                         JOIN oci_publication_sessions publication
                           ON publication.registry_id = candidate.registry_id
                          AND publication.state IN('preparing', 'committing')
                         LEFT JOIN oci_publication_objects publication_object
                           ON publication_object.publication_id = publication.id
                          AND publication_object.digest = candidate.digest
                         WHERE candidate.run_id = ?1
                           AND (publication.root_digest = candidate.digest
                             OR publication_object.digest IS NOT NULL))
                       AND NOT EXISTS (SELECT 1 FROM oci_descriptor_edges edge
                         JOIN oci_gc_candidates target
                           ON target.run_id = ?1
                          AND target.registry_id = edge.registry_id
                          AND target.digest = edge.target_digest
                         LEFT JOIN oci_gc_candidates source
                           ON source.run_id = ?1
                          AND source.registry_id = edge.registry_id
                          AND source.digest = edge.manifest_digest
                         WHERE source.digest IS NULL)
                       AND NOT EXISTS (SELECT 1 FROM oci_manifests manifest
                         JOIN oci_gc_candidates target
                           ON target.run_id = ?1
                          AND target.registry_id = manifest.registry_id
                          AND (target.digest = manifest.subject_digest
                            OR target.digest = manifest.config_digest)
                         LEFT JOIN oci_gc_candidates source
                           ON source.run_id = ?1
                          AND source.registry_id = manifest.registry_id
                          AND source.digest = manifest.digest
                         WHERE source.digest IS NULL)",
                vals![generation_id, registry_id, applied_epoch, now],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO oci_gc_snapshot_lease_holds
                       (run_id, registry_id, snapshot_digest, retired_at)
                     SELECT DISTINCT ?1, ?2, reference.digest, ?3
                     FROM image_snapshot_references reference
                     JOIN oci_gc_candidates candidate
                       ON candidate.run_id = ?1
                      AND candidate.registry_id = reference.registry_id
                      AND candidate.object_key = reference.object_key
                     WHERE reference.registry_id = ?2
                       AND EXISTS (SELECT 1 FROM image_snapshot_leases lease
                         WHERE lease.digest = reference.digest
                           AND lease.expires_at > ?3)
                     ON CONFLICT(run_id, snapshot_digest) DO NOTHING",
                vals![generation_id, registry_id, now],
            )
            .unchecked(),
            Statement::new(
                "DELETE FROM image_snapshot_references
                     WHERE registry_id = ?2 AND EXISTS (
                       SELECT 1 FROM oci_gc_candidates candidate
                       WHERE candidate.run_id = ?1
                         AND candidate.registry_id = ?2
                         AND candidate.object_key = image_snapshot_references.object_key)",
                vals![generation_id, registry_id],
            )
            .unchecked(),
            Statement::new(
                "DELETE FROM object_placements WHERE registry_id = ?2
                       AND EXISTS (SELECT 1 FROM oci_gc_candidates candidate
                         WHERE candidate.run_id = ?1
                           AND candidate.surface_object_id =
                             object_placements.surface_object_id)",
                vals![generation_id, registry_id],
            )
            .unchecked(),
            Statement::new(
                "DELETE FROM oci_descriptor_edges WHERE registry_id = ?2
                       AND EXISTS (SELECT 1 FROM oci_gc_candidates candidate
                         WHERE candidate.run_id = ?1
                           AND candidate.digest =
                             oci_descriptor_edges.manifest_digest)",
                vals![generation_id, registry_id],
            )
            .unchecked(),
            Statement::new(
                "DELETE FROM oci_manifests WHERE registry_id = ?2
                       AND EXISTS (SELECT 1 FROM oci_gc_candidates candidate
                         WHERE candidate.run_id = ?1
                           AND candidate.digest = oci_manifests.digest)",
                vals![generation_id, registry_id],
            )
            .unchecked(),
            Statement::new(
                "DELETE FROM oci_blobs WHERE registry_id = ?2
                       AND EXISTS (SELECT 1 FROM oci_gc_candidates candidate
                         WHERE candidate.run_id = ?1
                           AND candidate.digest = oci_blobs.digest)",
                vals![generation_id, registry_id],
            )
            .unchecked(),
            Statement::new(
                "DELETE FROM surface_objects WHERE registry_id = ?2
                       AND EXISTS (SELECT 1 FROM oci_gc_candidates candidate
                         WHERE candidate.run_id = ?1
                           AND candidate.surface_object_id = surface_objects.id)",
                vals![generation_id, registry_id],
            )
            .unchecked(),
            // Catalog quota reservations are deterministic admission locks,
            // not durable accounting records. Once charged catalog identity
            // has been finalized, retaining committed rows would prevent a
            // later exact-byte re-admission from reserving quota again.
            Statement::new(
                "DELETE FROM oci_quota_reservations
                 WHERE registry_id = ?1 AND owner_kind = 'catalog'
                   AND state = 'committed'",
                vals![registry_id],
            )
            .unchecked(),
            Statement::new(
                "UPDATE oci_gc_candidates
                     SET state = 'complete', finalized_at = ?2,
                         resource_version = resource_version + 1
                     WHERE run_id = ?1 AND state = 'physically_absent'",
                vals![generation_id, now],
            )
            .expecting(u64::try_from(planned_objects)?),
            org_usage_statement,
            Statement::new(
                "UPDATE oci_registry_state
                     SET charged_bytes = charged_bytes - ?2,
                         charged_objects = charged_objects - ?3,
                         mutation_epoch = mutation_epoch + 1, updated_at = ?4
                     WHERE registry_id = ?1 AND mutation_epoch = ?5
                       AND charged_bytes >= ?2 AND charged_objects >= ?3",
                vals![
                    registry_id,
                    planned_bytes,
                    planned_objects,
                    now,
                    applied_epoch
                ],
            )
            .expecting(1),
            Statement::new(
                "UPDATE oci_gc_runs
                     SET state = 'complete', finished_at = ?2,
                         deleted_object_count = planned_objects,
                         deleted_byte_size = planned_bytes,
                         resource_version = resource_version + 1
                     WHERE id = ?1 AND state = 'applying'",
                vals![generation_id, now],
            )
            .expecting(1),
            Statement::new(
                "DELETE FROM oci_gc_credential_holds WHERE run_id = ?1",
                vals![generation_id],
            )
            .unchecked(),
            Statement::new(
                "DELETE FROM oci_gc_registry_locks
                     WHERE registry_id = ?2 AND run_id = ?1",
                vals![generation_id, registry_id],
            )
            .expecting(1),
        ];
        self.backend.checked_batch(&statements).await?;
        self.oci_gc_generation(registry_id, generation_id)
            .await?
            .context("OCI GC generation disappeared after finalization")
    }

    /// Performs one bounded crash-recovery sweep of ready candidates and runs.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid bounds/time or selector database failure.
    /// A per-run finalization fence failure leaves that run recoverable and
    /// does not starve later ready work in the same bounded sweep.
    pub async fn finalize_ready_oci_gc(
        &self,
        now: i64,
        limit: u32,
    ) -> Result<super::OciGcFinalizationSweep> {
        if now < 0 || limit == 0 || limit > 250 {
            bail!("OCI GC finalization sweep selector is invalid");
        }
        let candidate_rows = self
            .backend
            .query(
                "SELECT candidate.run_id, candidate.digest
                 FROM oci_gc_candidates candidate
                 JOIN oci_gc_runs run ON run.id = candidate.run_id
                 WHERE run.state = 'applying' AND candidate.state = 'deleting'
                   AND NOT EXISTS (SELECT 1 FROM oci_gc_placement_actions action
                     WHERE action.run_id = candidate.run_id
                       AND action.digest = candidate.digest
                       AND action.state <> 'confirmed_absent')
                 ORDER BY candidate.run_id, candidate.digest LIMIT ?1",
                &vals![i64::from(limit)],
            )
            .await?;
        let mut finalized_candidates = 0_u64;
        for row in &candidate_rows {
            if self
                .finalize_oci_gc_candidate(
                    &row.get::<String>(0)?,
                    Sha256Digest::parse(&row.get::<String>(1)?)?,
                    now,
                )
                .await
                .is_ok()
            {
                finalized_candidates = finalized_candidates.saturating_add(1);
            }
        }
        let remaining = usize::try_from(limit)?.saturating_sub(candidate_rows.len());
        let generation_rows = if remaining == 0 {
            Vec::new()
        } else {
            self.backend
                .query(
                    "SELECT run.id FROM oci_gc_runs run
                     WHERE run.state = 'applying'
                       AND NOT EXISTS (SELECT 1 FROM oci_gc_candidates candidate
                         WHERE candidate.run_id = run.id
                           AND candidate.state <> 'physically_absent')
                     ORDER BY run.applied_at, run.id LIMIT ?1",
                    &vals![i64::try_from(remaining)?],
                )
                .await?
        };
        let mut finalized_generations = 0_u64;
        for row in &generation_rows {
            if self
                .finalize_oci_gc_generation(&row.get::<String>(0)?, now)
                .await
                .is_ok()
            {
                finalized_generations = finalized_generations.saturating_add(1);
            }
        }
        Ok(super::OciGcFinalizationSweep {
            finalized_candidates,
            finalized_generations,
        })
    }

    /// Deletes drained snapshot lease-attribution holds after collector convergence.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid time/limit or database failure.
    pub async fn release_drained_oci_gc_snapshot_holds(&self, now: i64, limit: u32) -> Result<u64> {
        if now < 0 || limit == 0 || limit > 250 {
            bail!("OCI GC snapshot-hold release selector is invalid");
        }
        let rows = self
            .backend
            .query(
                "SELECT run_id, snapshot_digest
                 FROM oci_gc_snapshot_lease_holds hold
                 WHERE NOT EXISTS (SELECT 1 FROM image_snapshot_leases lease
                   WHERE lease.digest = hold.snapshot_digest
                     AND lease.expires_at > ?1)
                 ORDER BY run_id, snapshot_digest LIMIT ?2",
                &vals![now, i64::from(limit)],
            )
            .await?;
        let statements = rows
            .iter()
            .map(|row| -> Result<_> {
                Ok(Statement::new(
                    "DELETE FROM oci_gc_snapshot_lease_holds
                     WHERE run_id = ?1 AND snapshot_digest = ?2
                       AND NOT EXISTS (SELECT 1 FROM image_snapshot_leases lease
                         WHERE lease.digest = ?2 AND lease.expires_at > ?3)",
                    vals![row.get::<String>(0)?, row.get::<String>(1)?, now],
                )
                .expecting(1))
            })
            .collect::<Result<Vec<_>>>()?;
        self.backend.checked_batch(&statements).await?;
        Ok(u64::try_from(rows.len())?)
    }

    /// Aborts a bounded set of expired plans that never tombstoned objects.
    ///
    /// Applying runs are deliberately excluded and require physical recovery.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid time/limit or database failure.
    pub async fn abort_expired_oci_gc_plans(&self, now: i64, limit: u32) -> Result<u64> {
        if now < 0 || limit == 0 || limit > 250 {
            bail!("OCI GC expired-plan selector is invalid");
        }
        let rows = self
            .backend
            .query(
                "SELECT id, resource_version FROM oci_gc_runs
                 WHERE state = 'planned' AND expires_at <= ?1
                 ORDER BY expires_at, id LIMIT ?2",
                &vals![now, i64::from(limit)],
            )
            .await?;
        let statements = rows
            .iter()
            .map(|row| -> Result<_> {
                Ok(Statement::new(
                    "UPDATE oci_gc_runs SET state = 'aborted', finished_at = ?3,
                         last_error = 'review expired before apply',
                         resource_version = resource_version + 1
                     WHERE id = ?1 AND resource_version = ?2
                       AND state = 'planned' AND expires_at <= ?3",
                    vals![row.get::<String>(0)?, row.get::<i64>(1)?, now],
                )
                .expecting(1))
            })
            .collect::<Result<Vec<_>>>()?;
        self.backend.checked_batch(&statements).await?;
        Ok(u64::try_from(rows.len())?)
    }

    /// Returns one exact candidate including frozen repository impact.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed persisted data or database failure.
    pub async fn oci_gc_candidate(
        &self,
        generation_id: &str,
        digest: Sha256Digest,
    ) -> Result<Option<OciGcCandidateRecord>> {
        let row = self
            .backend
            .query_opt(
                "SELECT run_id, digest, media_type, byte_size, object_key,
                        eligible_at, state, finalized_at, last_error,
                        resource_version
                 FROM oci_gc_candidates WHERE run_id = ?1 AND digest = ?2",
                &vals![generation_id, digest.to_string()],
            )
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let repository_rows = self
            .backend
            .query(
                "SELECT repository_name FROM oci_gc_candidate_repositories
                 WHERE run_id = ?1 AND digest = ?2
                 ORDER BY repository_name, repository_id",
                &vals![generation_id, digest.to_string()],
            )
            .await?;
        let repositories = repository_rows
            .iter()
            .map(|repository| -> Result<_> {
                RepositoryName::parse(&repository.get::<String>(0)?).map_err(Into::into)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Some(OciGcCandidateRecord {
            generation_id: row.get(0)?,
            digest: Sha256Digest::parse(&row.get::<String>(1)?)?,
            media_type: MediaType::parse(&row.get::<String>(2)?)?,
            byte_size: u64::try_from(row.get::<i64>(3)?)
                .context("persisted OCI GC candidate size is negative")?,
            object_key: row.get(4)?,
            repositories,
            eligible_at: row.get(5)?,
            state: row.get(6)?,
            finalized_at: row.get(7)?,
            last_error: row.get(8)?,
            resource_version: row.get(9)?,
        }))
    }

    async fn oci_gc_action_claim(
        &self,
        action_id: &str,
        claim_token: &str,
    ) -> Result<Option<OciGcPlacementActionClaim>> {
        let row = self
            .backend
            .query_opt(
                "SELECT action.id, action.run_id, action.registry_id,
                        action.digest, candidate.media_type, action.object_key,
                        action.expected_hash, action.expected_size,
                        action.expected_strong_etag, snapshot.placement_id,
                        snapshot.placement_name, snapshot.placement_prefix,
                        snapshot.placement_resource_version,
                        snapshot.placement_write_spec_version,
                        snapshot.placement_observation_version,
                        snapshot.binding_id, snapshot.binding_resource_version,
                        snapshot.binding_write_revision,
                        snapshot.delete_credential_purpose,
                        snapshot.delete_credential_generation,
                        snapshot.delete_capability_fingerprint,
                        snapshot.delete_capability_resource_version,
                        snapshot.inventory_generation_id,
                        snapshot.inventory_digest, snapshot.inventory_observed_at,
                        action.claim_token, action.lease_expires_at,
                        action.attempt_count, action.max_attempts,
                        action.resource_version, action.inventory_entry_present
                 FROM oci_gc_placement_actions action
                 JOIN oci_gc_candidates candidate
                   ON candidate.run_id = action.run_id
                  AND candidate.digest = action.digest
                 JOIN oci_gc_placement_snapshots snapshot
                   ON snapshot.run_id = action.run_id
                  AND snapshot.placement_id = action.placement_id
                 WHERE action.id = ?1 AND action.state = 'claimed'
                   AND action.claim_token = ?2",
                &vals![action_id, claim_token],
            )
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let repository_rows = self
            .backend
            .query(
                "SELECT repository_name FROM oci_gc_candidate_repositories
                 WHERE run_id = ?1 AND digest = ?2
                 ORDER BY repository_name, repository_id",
                &vals![row.get::<String>(1)?, row.get::<String>(3)?],
            )
            .await?;
        let repositories = repository_rows
            .iter()
            .map(|repository| -> Result<_> {
                RepositoryName::parse(&repository.get::<String>(0)?).map_err(Into::into)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Some(OciGcPlacementActionClaim {
            action_id: row.get(0)?,
            generation_id: row.get(1)?,
            registry_id: row.get(2)?,
            repositories,
            digest: Sha256Digest::parse(&row.get::<String>(3)?)?,
            media_type: MediaType::parse(&row.get::<String>(4)?)?,
            object_key: row.get(5)?,
            expected_hash: Sha256Digest::parse(&row.get::<String>(6)?)?,
            expected_size: u64::try_from(row.get::<i64>(7)?)
                .context("persisted OCI GC expected size is negative")?,
            expected_strong_etag: row.get(8)?,
            inventory_entry_present: row.get::<i64>(30)? == 1,
            placement_id: row.get(9)?,
            placement_name: row.get(10)?,
            placement_prefix: row.get(11)?,
            placement_resource_version: row.get(12)?,
            placement_write_spec_version: row.get(13)?,
            placement_observation_version: row.get(14)?,
            binding_id: row.get(15)?,
            binding_resource_version: row.get(16)?,
            binding_write_revision: row.get(17)?,
            delete_credential_purpose: row.get(18)?,
            delete_credential_generation: row.get(19)?,
            delete_capability_fingerprint: row.get(20)?,
            delete_capability_resource_version: row.get(21)?,
            inventory_generation_id: row.get(22)?,
            inventory_digest: Sha256Digest::parse(&row.get::<String>(23)?)?,
            inventory_observed_at: row.get(24)?,
            claim_token: row.get(25)?,
            lease_expires_at: row.get(26)?,
            attempt_count: u32::try_from(row.get::<i64>(27)?)
                .context("persisted OCI GC attempt count is negative")?,
            max_attempts: u32::try_from(row.get::<i64>(28)?)
                .context("persisted OCI GC max attempts is negative")?,
            resource_version: row.get(29)?,
        }))
    }

    /// Returns one exact GC placement action by stable id.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed persisted data or database failure.
    pub async fn oci_gc_placement_action(
        &self,
        action_id: &str,
    ) -> Result<Option<OciGcPlacementActionRecord>> {
        self.backend
            .query_opt(
                &format!(
                    "SELECT {} FROM oci_gc_placement_actions action
                 JOIN oci_gc_placement_snapshots snapshot
                   ON snapshot.run_id = action.run_id
                  AND snapshot.placement_id = action.placement_id
                 WHERE action.id = ?1",
                    super::read::GC_ACTION_COLUMNS
                ),
                &vals![action_id],
            )
            .await?
            .as_ref()
            .map(super::read::row_to_action)
            .transpose()
    }
}
