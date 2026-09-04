//! Bounded mark, reviewed plan, and atomic tombstone transitions.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use anyhow::{Context, Result, bail};
use aos_oci_types::Sha256Digest;
use uuid::Uuid;

pub use super::plan_model::{ApplyOciGc, PlanOciGc};
use super::plan_model::{
    EffectivePolicy, FrozenAction, FrozenCandidate, FrozenPlacement, FrozenRoot, PlanBlocker,
    canonical_digest, digest_json, oci_gc_snapshot_guard_statement, policy_guard_statement,
    validate_apply_input, validate_plan_input,
};
use super::{
    OCI_GC_MAX_ACTIONS, OCI_GC_MAX_DEPTH, OCI_GC_MAX_EDGES, OCI_GC_MAX_INVENTORY_AGE_SECONDS,
    OCI_GC_MAX_OBJECTS, OCI_GC_MAX_PLACEMENTS, OCI_GC_PLAN_TTL_SECONDS, OciGcGenerationRecord,
};
use crate::backend::Statement;
use crate::db::{
    Database, OCI_RETENTION_DEFAULT_DELETED_TAG_HISTORY_SECONDS,
    OCI_RETENTION_DEFAULT_RECENT_MANUAL_TAG_REVISIONS, OCI_RETENTION_DEFAULT_RETAIN_REFERRERS,
    OCI_RETENTION_DEFAULT_UNTAGGED_GRACE_SECONDS, OciRetentionPolicyRecord, sanitize_log_text,
};

/// Qualifies a catalog-owned root source within its repository.
///
/// The durable root key intentionally excludes the nullable repository column,
/// so names such as `latest` must not collide when repositories retain the
/// same digest under the same tag or release name.
fn repository_root_source_id(repository_id: i64, source_id: &str) -> String {
    format!("{repository_id}:{source_id}")
}

impl Database {
    /// Produces one durable, actor-bound OCI GC plan.
    ///
    /// Hard safety failures are persisted as a terminal run with bounded
    /// blockers. An optimistic policy mismatch or malformed request returns an
    /// error without creating a misleading plan.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input, stale policy version, idempotency
    /// conflict, graph bounds, malformed catalog data, or database failure.
    pub async fn plan_oci_gc(&self, input: &PlanOciGc) -> Result<OciGcGenerationRecord> {
        validate_plan_input(input)?;
        if let Some(existing) = self
            .oci_gc_generation_by_plan_key(
                input.registry_id,
                &input.actor_id,
                &input.idempotency_key,
            )
            .await?
        {
            if existing.policy_resource_version != input.expected_resource_version {
                bail!("OCI GC plan idempotency conflict");
            }
            return Ok(existing);
        }

        let policy = self.effective_oci_gc_policy(input.registry_id).await?;
        if policy.resource_version != input.expected_resource_version {
            bail!("OCI retention policy resource version is stale");
        }
        let captured_epoch = self
            .ensure_oci_gc_registry_state(input.registry_id, input.now)
            .await?;
        let mut blockers = Vec::new();

        let pending_reconciliation = self
            .backend
            .query_opt(
                "SELECT root_digest FROM oci_admin_projection_reconciliations
                 WHERE registry_id = ?1 AND state IN('pending', 'failed')
                 ORDER BY root_digest LIMIT 1",
                &vals![input.registry_id],
            )
            .await?;
        if let Some(row) = pending_reconciliation {
            blockers.push(PlanBlocker {
                kind: "pending_projection_reconciliation",
                digest: Some(Sha256Digest::parse(&row.get::<String>(0)?)?),
                detail: "exact OCI config/layer projection reconciliation is incomplete".into(),
            });
        }
        if let Some(row) = self
            .backend
            .query_opt(
                "SELECT manifest.digest FROM oci_manifests manifest
                 JOIN oci_repository_objects link
                   ON link.registry_id = manifest.registry_id
                  AND link.digest = manifest.digest
                 WHERE manifest.registry_id = ?1 AND manifest.artifact_type IS NULL
                   AND manifest.config_digest IS NOT NULL
                   AND NOT EXISTS (SELECT 1 FROM oci_image_config_projections projection
                     WHERE projection.registry_id = manifest.registry_id
                       AND projection.repository_id = link.repository_id
                       AND projection.manifest_digest = manifest.digest)
                 ORDER BY manifest.digest LIMIT 1",
                &vals![input.registry_id],
            )
            .await?
        {
            blockers.push(PlanBlocker {
                kind: "missing_runnable_projection",
                digest: Some(Sha256Digest::parse(&row.get::<String>(0)?)?),
                detail: "a runnable manifest lacks its exact config/layer projection".into(),
            });
        }

        let placements = self
            .freeze_oci_gc_placements(input.registry_id, captured_epoch, input.now, &mut blockers)
            .await?;
        let mut roots = self
            .collect_oci_gc_hard_roots(input.registry_id, &policy, input.now)
            .await?;
        self.reconcile_oci_unreferenced_since(input.registry_id, input.now, &roots, &mut blockers)
            .await?;
        let grace_roots = self
            .collect_oci_gc_grace_roots(input.registry_id, &policy, input.now)
            .await?;
        let live = self
            .traverse_oci_gc_live_graph(
                input.registry_id,
                policy.retain_referrers,
                &mut roots,
                &grace_roots,
                &mut blockers,
            )
            .await?;
        let candidates = self
            .collect_oci_gc_candidates(input.registry_id, &policy, input.now, &live, &mut blockers)
            .await?;
        let actions = self
            .freeze_oci_gc_actions(input.registry_id, &placements, &candidates, &mut blockers)
            .await?;
        if actions.len() > OCI_GC_MAX_ACTIONS {
            bail!("OCI GC plan exceeds the {OCI_GC_MAX_ACTIONS}-action synchronous bound");
        }

        self.persist_oci_gc_plan(
            input,
            captured_epoch,
            &policy,
            &roots,
            &placements,
            &candidates,
            &actions,
            &blockers,
            live.len(),
        )
        .await
    }

    /// Applies one reviewed plan and atomically hides every candidate.
    ///
    /// The caller supplies no registry selector. Durable plan ownership is
    /// actor-bound, and the transaction revalidates policy, roots, epoch,
    /// topology, inventory, and conditional-delete capability before changing
    /// any catalog visibility.
    ///
    /// # Errors
    ///
    /// Returns an error for actor mismatch, expiry, confirmation mismatch,
    /// stale frozen state, idempotency conflict, blockers, or database failure.
    pub async fn apply_oci_gc(&self, input: &ApplyOciGc) -> Result<OciGcGenerationRecord> {
        validate_apply_input(input)?;
        let plan = self
            .oci_gc_generation_for_actor(&input.generation_id, &input.actor_id)
            .await?
            .context("OCI GC generation does not exist for this actor")?;
        if plan.state == "applying" || plan.state == "complete" {
            let replay = self
                .backend
                .query_opt(
                    "SELECT apply_idempotency_key FROM oci_gc_runs WHERE id = ?1",
                    &vals![input.generation_id],
                )
                .await?
                .and_then(|row| row.get::<Option<String>>(0).ok())
                .flatten();
            if replay.as_deref() == Some(input.idempotency_key.as_str()) {
                return Ok(plan);
            }
            bail!("OCI GC apply idempotency conflict");
        }
        if plan.state != "planned" {
            bail!("OCI GC generation is not applicable");
        }
        if plan.expires_at <= input.now {
            bail!("OCI GC plan has expired");
        }
        if plan.confirmation_hash != input.confirmation_hash {
            bail!("OCI GC confirmation hash does not match the reviewed plan");
        }
        if !self
            .list_oci_gc_blockers(&input.generation_id)
            .await?
            .is_empty()
        {
            bail!("OCI GC generation is blocked");
        }

        let current_policy = self.effective_oci_gc_policy(plan.registry_id).await?;
        let mut current_roots = self
            .collect_oci_gc_hard_roots(plan.registry_id, &current_policy, input.now)
            .await?;
        let current_grace_roots = self
            .collect_oci_gc_grace_roots(plan.registry_id, &current_policy, input.now)
            .await?;
        let mut current_blockers = Vec::new();
        self.traverse_oci_gc_live_graph(
            plan.registry_id,
            current_policy.retain_referrers,
            &mut current_roots,
            &current_grace_roots,
            &mut current_blockers,
        )
        .await?;
        if !current_blockers.is_empty() {
            bail!("OCI GC root graph became incomplete after review");
        }
        let current_root_digest = digest_json(&current_roots)?;
        if current_policy.resource_version != plan.policy_resource_version
            || digest_json(&current_policy)? != plan.policy_digest
            || current_root_digest != plan.root_set_digest
        {
            bail!("OCI GC policy or root set changed after review");
        }

        let candidate_rows = self
            .backend
            .query(
                "SELECT digest, surface_object_id, catalog_object_resource_version
                 FROM oci_gc_candidates WHERE run_id = ?1 ORDER BY digest",
                &vals![input.generation_id],
            )
            .await?;
        let mut statements = Vec::with_capacity(candidate_rows.len() * 5 + 8);
        statements.push(
            Statement::new(
                "INSERT INTO oci_gc_registry_locks(registry_id, run_id, acquired_at)
                 SELECT registry_id, id, ?2 FROM oci_gc_runs
                 WHERE id = ?1 AND state = 'planned'
                   AND NOT EXISTS (SELECT 1 FROM oci_gc_registry_locks registry_lock
                    WHERE registry_lock.registry_id = oci_gc_runs.registry_id)",
                vals![input.generation_id, input.now],
            )
            .expecting(1),
        );
        statements.push(
            Statement::new(
                "INSERT INTO oci_gc_credential_holds
                   (run_id, binding_id, purpose, generation)
                 SELECT DISTINCT snapshot.run_id, snapshot.binding_id,
                                 snapshot.delete_credential_purpose,
                                 snapshot.delete_credential_generation
                 FROM oci_gc_placement_snapshots snapshot
                 WHERE snapshot.run_id = ?1
                   AND snapshot.delete_credential_purpose IS NOT NULL
                   AND snapshot.delete_credential_generation IS NOT NULL
                 ON CONFLICT(run_id, binding_id, purpose, generation) DO NOTHING",
                vals![input.generation_id],
            )
            .unchecked(),
        );
        statements.push(
            Statement::new(
                "UPDATE oci_registry_state SET updated_at = updated_at
                 WHERE registry_id = ?1 AND mutation_epoch = ?2",
                vals![plan.registry_id, plan.captured_mutation_epoch],
            )
            .expecting(1),
        );
        statements.push(policy_guard_statement(
            plan.registry_id,
            plan.policy_resource_version,
        ));
        statements.extend(
            self.oci_gc_snapshot_guard_statements(&input.generation_id, input.now)
                .await?,
        );
        for row in &candidate_rows {
            let digest: String = row.get(0)?;
            let surface_object_id: i64 = row.get(1)?;
            let object_resource_version: i64 = row.get(2)?;
            statements.extend([
                Statement::new(
                    "UPDATE oci_registry_state SET updated_at = updated_at
                     WHERE registry_id = ?1 AND mutation_epoch = ?4
                       AND NOT EXISTS (SELECT 1 FROM oci_tags tag
                         WHERE tag.registry_id = ?1 AND tag.digest = ?2)
                       AND NOT EXISTS (SELECT 1 FROM oci_release_roots root
                         WHERE root.registry_id = ?1 AND root.index_digest = ?2)
                       AND NOT EXISTS (SELECT 1 FROM oci_release_evidence evidence
                         WHERE evidence.registry_id = ?1
                           AND evidence.referrer_digest = ?2
                           AND evidence.verification = 'verified')
                       AND NOT EXISTS (SELECT 1 FROM oci_leases lease
                         WHERE lease.registry_id = ?1 AND lease.digest = ?2
                           AND lease.expires_at > ?3)
                       AND NOT EXISTS (SELECT 1 FROM oci_upload_sessions upload
                         WHERE upload.registry_id = ?1
                           AND upload.state IN('active', 'completing')
                           AND (upload.expected_digest = ?2 OR upload.final_digest = ?2))
                       AND NOT EXISTS (SELECT 1
                         FROM oci_publication_sessions publication
                         JOIN oci_publication_objects object
                           ON object.publication_id = publication.id
                         WHERE publication.registry_id = ?1
                           AND publication.state IN('preparing', 'committing')
                           AND object.digest = ?2)
                       AND NOT EXISTS (SELECT 1 FROM oci_publication_sessions publication
                         WHERE publication.registry_id = ?1
                           AND publication.state IN('preparing', 'committing')
                           AND publication.root_digest = ?2)
                       AND NOT EXISTS (SELECT 1 FROM oci_descriptor_edges edge
                         WHERE edge.registry_id = ?1 AND edge.target_digest = ?2
                           AND NOT EXISTS (SELECT 1 FROM oci_gc_candidates source
                             WHERE source.run_id = ?5 AND source.registry_id = ?1
                               AND source.digest = edge.manifest_digest))
                       AND NOT EXISTS (SELECT 1 FROM oci_manifests manifest
                         WHERE manifest.registry_id = ?1
                           AND (manifest.config_digest = ?2 OR manifest.subject_digest = ?2)
                           AND NOT EXISTS (SELECT 1 FROM oci_gc_candidates source
                             WHERE source.run_id = ?5 AND source.registry_id = ?1
                               AND source.digest = manifest.digest))",
                    vals![
                        plan.registry_id,
                        digest,
                        input.now,
                        plan.captured_mutation_epoch,
                        input.generation_id
                    ],
                )
                .expecting(1),
                Statement::new(
                    "DELETE FROM oci_leases WHERE registry_id = ?1 AND digest = ?2
                       AND expires_at <= ?3",
                    vals![plan.registry_id, digest, input.now],
                )
                .unchecked(),
                Statement::new(
                    "DELETE FROM oci_repository_objects
                     WHERE registry_id = ?1 AND digest = ?2
                       AND NOT EXISTS (SELECT 1 FROM oci_tags tag
                         WHERE tag.registry_id = ?1 AND tag.digest = ?2)
                       AND NOT EXISTS (SELECT 1 FROM oci_release_roots root
                         WHERE root.registry_id = ?1 AND root.index_digest = ?2)",
                    vals![plan.registry_id, digest],
                )
                .unchecked(),
                Statement::new(
                    "UPDATE oci_blobs SET lifecycle_state = 'deleting', updated_at = ?3
                     WHERE registry_id = ?1 AND digest = ?2
                       AND lifecycle_state = 'active' AND surface_object_id = ?4",
                    vals![plan.registry_id, digest, input.now, surface_object_id],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE surface_objects
                     SET lifecycle_state = 'tombstoned', tombstoned_at = ?3,
                         updated_at = ?3, resource_version = resource_version + 1
                     WHERE id = ?1 AND registry_id = ?2
                       AND lifecycle_state = 'active' AND resource_version = ?4",
                    vals![
                        surface_object_id,
                        plan.registry_id,
                        input.now,
                        object_resource_version
                    ],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE oci_gc_candidates
                     SET state = 'deleting', resource_version = resource_version + 1
                     WHERE run_id = ?1 AND digest = ?2 AND state = 'planned'",
                    vals![input.generation_id, digest],
                )
                .expecting(1),
            ]);
        }
        statements.extend([
            Statement::new(
                "UPDATE oci_gc_runs SET state = 'applying', apply_idempotency_key = ?2,
                    applied_mutation_epoch = captured_mutation_epoch + 1,
                    applied_at = ?3, resource_version = resource_version + 1
                 WHERE id = ?1 AND actor_id = ?4 AND state = 'planned'
                   AND expires_at > ?3 AND confirmation_hash = ?5",
                vals![
                    input.generation_id,
                    input.idempotency_key,
                    input.now,
                    input.actor_id,
                    input.confirmation_hash.to_string()
                ],
            )
            .expecting(1),
            Statement::new(
                "UPDATE oci_registry_state
                 SET mutation_epoch = mutation_epoch + 1, updated_at = ?2
                 WHERE registry_id = ?1 AND mutation_epoch = ?3",
                vals![plan.registry_id, input.now, plan.captured_mutation_epoch],
            )
            .expecting(1),
        ]);
        self.backend.checked_batch(&statements).await?;
        self.oci_gc_generation(plan.registry_id, &input.generation_id)
            .await?
            .context("OCI GC generation disappeared after apply")
    }

    async fn effective_oci_gc_policy(&self, registry_id: i64) -> Result<EffectivePolicy> {
        let configured = self.oci_admin_retention_policy(registry_id).await?;
        Ok(match configured {
            Some(OciRetentionPolicyRecord {
                untagged_grace_seconds,
                deleted_tag_history_seconds,
                recent_manual_tag_revisions,
                retain_referrers,
                resource_version,
                ..
            }) => EffectivePolicy {
                untagged_grace_seconds,
                deleted_tag_history_seconds,
                recent_manual_tag_revisions,
                retain_referrers,
                resource_version,
            },
            None => EffectivePolicy {
                untagged_grace_seconds: OCI_RETENTION_DEFAULT_UNTAGGED_GRACE_SECONDS,
                deleted_tag_history_seconds: OCI_RETENTION_DEFAULT_DELETED_TAG_HISTORY_SECONDS,
                recent_manual_tag_revisions: OCI_RETENTION_DEFAULT_RECENT_MANUAL_TAG_REVISIONS,
                retain_referrers: OCI_RETENTION_DEFAULT_RETAIN_REFERRERS,
                resource_version: 0,
            },
        })
    }

    async fn ensure_oci_gc_registry_state(&self, registry_id: i64, now: i64) -> Result<i64> {
        self.backend
            .execute(
                "INSERT INTO oci_registry_state
                   (registry_id, mutation_epoch, charged_bytes, charged_objects, updated_at)
                 SELECT ?1, 0, 0, 0, ?2 FROM registries WHERE id = ?1
                 ON CONFLICT(registry_id) DO NOTHING",
                &vals![registry_id, now],
            )
            .await?;
        self.backend
            .query_opt(
                "SELECT mutation_epoch FROM oci_registry_state WHERE registry_id = ?1",
                &vals![registry_id],
            )
            .await?
            .context("OCI registry does not exist")?
            .get(0)
    }

    #[allow(clippy::too_many_arguments)]
    async fn persist_oci_gc_plan(
        &self,
        input: &PlanOciGc,
        captured_epoch: i64,
        policy: &EffectivePolicy,
        roots: &BTreeSet<FrozenRoot>,
        placements: &[FrozenPlacement],
        candidates: &[FrozenCandidate],
        actions: &[FrozenAction],
        blockers: &[PlanBlocker],
        reachable_object_count: usize,
    ) -> Result<OciGcGenerationRecord> {
        let generation_id = format!("ocigc-{}", Uuid::new_v4().simple());
        let expires_at = input.now.saturating_add(OCI_GC_PLAN_TTL_SECONDS);
        let policy_digest = digest_json(policy)?;
        let root_set_digest = digest_json(roots)?;
        let placement_inventory_digest = digest_json(
            &placements
                .iter()
                .map(|placement| {
                    (
                        placement.placement_id,
                        placement.inventory_generation_id.as_str(),
                        placement.inventory_digest.as_str(),
                        placement.inventory_observed_at,
                    )
                })
                .collect::<Vec<_>>(),
        )?;
        let topology_digest = digest_json(placements)?;
        let plan_digest = digest_json(&(
            policy,
            roots,
            placements,
            candidates,
            actions,
            blockers,
            captured_epoch,
        ))?;
        let confirmation_hash = digest_json(&(
            generation_id.as_str(),
            input.actor_id.as_str(),
            plan_digest.to_string(),
            expires_at,
        ))?;
        let blocked = !blockers.is_empty();
        let planned_bytes = if blocked {
            0
        } else {
            candidates.iter().try_fold(0_u64, |total, candidate| {
                total
                    .checked_add(candidate.byte_size)
                    .context("OCI GC planned bytes overflowed")
            })?
        };
        let planned_objects = if blocked { 0 } else { candidates.len() };
        let action_count = if blocked { 0 } else { actions.len() };
        let inventory_object_count = placements.iter().try_fold(0_u64, |total, placement| {
            total
                .checked_add(placement.inventory_object_count)
                .context("OCI GC inventory object count overflowed")
        })?;
        let inventory_byte_size = placements.iter().try_fold(0_u64, |total, placement| {
            total
                .checked_add(placement.inventory_byte_size)
                .context("OCI GC inventory byte size overflowed")
        })?;
        let planned_bytes = i64::try_from(planned_bytes).context("OCI GC bytes exceed int64")?;
        let planned_objects = i64::try_from(planned_objects)?;
        let action_count = i64::try_from(action_count)?;
        let inventory_object_count = i64::try_from(inventory_object_count)?;
        let inventory_byte_size = i64::try_from(inventory_byte_size)?;
        let reachable_object_count = i64::try_from(reachable_object_count)?;
        let last_error = blocked.then_some(sanitize_log_text(
            "OCI GC planning failed closed; inspect durable blockers",
        ));

        let mut statements = Vec::new();
        statements.push(
            Statement::new(
                "INSERT INTO oci_gc_runs
                   (id, registry_id, actor_id, plan_idempotency_key,
                    apply_idempotency_key, state, captured_mutation_epoch,
                    applied_mutation_epoch, policy_resource_version,
                    policy_digest, root_set_digest, placement_inventory_digest,
                    topology_digest, plan_digest, confirmation_hash,
                    inventory_object_count, inventory_byte_size,
                    reachable_object_count,
                    planned_bytes, planned_objects, placement_action_count,
                    deleted_object_count, deleted_byte_size,
                    expires_at, created_at, applied_at, finished_at, last_error,
                    resource_version)
                 SELECT ?1, ?2, ?3, ?4, NULL, ?5, ?6, NULL, ?7, ?8, ?9,
                        ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18,
                        ?19, 0, 0, ?20, ?21, NULL, ?22, ?23, 1
                 FROM registries registry WHERE registry.id = ?2
                   AND NOT EXISTS (SELECT 1 FROM oci_gc_runs run
                     WHERE run.registry_id = ?2 AND run.actor_id = ?3
                       AND run.plan_idempotency_key = ?4)",
                vals![
                    generation_id,
                    input.registry_id,
                    input.actor_id,
                    input.idempotency_key,
                    if blocked { "failed" } else { "planned" },
                    captured_epoch,
                    policy.resource_version,
                    policy_digest.to_string(),
                    root_set_digest.to_string(),
                    placement_inventory_digest.to_string(),
                    topology_digest.to_string(),
                    plan_digest.to_string(),
                    confirmation_hash.to_string(),
                    inventory_object_count,
                    inventory_byte_size,
                    reachable_object_count,
                    planned_bytes,
                    planned_objects,
                    action_count,
                    expires_at,
                    input.now,
                    blocked.then_some(input.now),
                    last_error
                ],
            )
            .expecting(1),
        );
        statements.push(
            Statement::new(
                "UPDATE oci_registry_state SET updated_at = updated_at
                 WHERE registry_id = ?1 AND mutation_epoch = ?2",
                vals![input.registry_id, captured_epoch],
            )
            .expecting(1),
        );
        statements.push(policy_guard_statement(
            input.registry_id,
            policy.resource_version,
        ));
        for root in roots {
            statements.push(
                Statement::new(
                    "INSERT INTO oci_gc_roots
                       (run_id, root_kind, digest, source_id, repository_id)
                     VALUES(?1, ?2, ?3, ?4, ?5)",
                    vals![
                        generation_id,
                        root.kind,
                        root.digest,
                        root.source_id,
                        root.repository_id
                    ],
                )
                .expecting(1),
            );
        }
        for (ordinal, blocker) in blockers.iter().enumerate() {
            statements.push(
                Statement::new(
                    "INSERT INTO oci_gc_blockers
                       (run_id, ordinal, blocker_kind, digest, detail)
                     VALUES(?1, ?2, ?3, ?4, ?5)",
                    vals![
                        generation_id,
                        i64::try_from(ordinal)?,
                        blocker.kind,
                        blocker.digest.map(|digest| digest.to_string()),
                        sanitize_log_text(&blocker.detail)
                    ],
                )
                .expecting(1),
            );
        }
        if !blocked {
            for placement in placements {
                statements.push(
                    Statement::new(
                        "INSERT INTO oci_gc_placement_snapshots
                           (run_id, registry_id, placement_id, placement_name,
                            placement_prefix, placement_resource_version,
                            placement_write_spec_version,
                            placement_observation_version, binding_id,
                            binding_resource_version, binding_write_revision,
                            delete_credential_purpose, delete_credential_generation,
                            delete_capability_fingerprint,
                            delete_capability_resource_version,
                            delete_capability_observed_at,
                            inventory_generation_id, inventory_digest,
                            inventory_observed_at)
                         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                                ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
                        vals![
                            generation_id,
                            input.registry_id,
                            placement.placement_id,
                            placement.placement_name,
                            placement.placement_prefix,
                            placement.placement_resource_version,
                            placement.placement_write_spec_version,
                            placement.placement_observation_version,
                            placement.binding_id,
                            placement.binding_resource_version,
                            placement.binding_write_revision,
                            placement.delete_credential_purpose,
                            placement.delete_credential_generation,
                            placement.delete_capability_fingerprint,
                            placement.delete_capability_resource_version,
                            placement.delete_capability_observed_at,
                            placement.inventory_generation_id,
                            placement.inventory_digest,
                            placement.inventory_observed_at
                        ],
                    )
                    .expecting(1),
                );
            }
            for candidate in candidates {
                statements.push(
                    Statement::new(
                        "INSERT INTO oci_gc_candidates
                           (run_id, registry_id, digest, media_type, byte_size,
                            object_key, surface_object_id,
                            catalog_object_resource_version, repository_count,
                            eligible_at, state, finalized_at, last_error,
                            resource_version)
                         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                                'planned', NULL, NULL, 1)",
                        vals![
                            generation_id,
                            input.registry_id,
                            candidate.digest,
                            candidate.media_type,
                            i64::try_from(candidate.byte_size)?,
                            candidate.object_key,
                            candidate.surface_object_id,
                            candidate.catalog_object_resource_version,
                            i64::try_from(candidate.repositories.len())?,
                            candidate.eligible_at
                        ],
                    )
                    .expecting(1),
                );
                for (repository_id, repository_name) in &candidate.repositories {
                    statements.push(
                        Statement::new(
                            "INSERT INTO oci_gc_candidate_repositories
                               (run_id, digest, repository_id, repository_name)
                             VALUES(?1, ?2, ?3, ?4)",
                            vals![
                                generation_id,
                                candidate.digest,
                                repository_id,
                                repository_name
                            ],
                        )
                        .expecting(1),
                    );
                }
            }
            for action in actions {
                statements.push(
                    Statement::new(
                        "INSERT INTO oci_gc_placement_actions
                           (id, run_id, registry_id, digest, placement_id,
                            object_key, expected_hash, expected_size,
                            expected_strong_etag, inventory_generation_id,
                            inventory_entry_present, state, worker_id, claim_token,
                            lease_expires_at, attempt_count, max_attempts,
                            next_attempt_at, last_error, confirmed_at,
                            resource_version)
                         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                                ?11, 'pending', NULL, NULL, NULL, 0, 8, ?12,
                                NULL, NULL, 1)",
                        vals![
                            action.id,
                            generation_id,
                            input.registry_id,
                            action.digest,
                            action.placement_id,
                            action.object_key,
                            action.expected_hash,
                            i64::try_from(action.expected_size)?,
                            action.expected_strong_etag,
                            action.inventory_generation_id,
                            i64::from(action.inventory_entry_present),
                            input.now
                        ],
                    )
                    .expecting(1),
                );
            }
            for placement in placements {
                statements.push(oci_gc_snapshot_guard_statement(
                    &generation_id,
                    placement.placement_id,
                    input.now,
                ));
            }
        }

        if let Err(error) = self.backend.checked_batch(&statements).await {
            if let Some(existing) = self
                .oci_gc_generation_by_plan_key(
                    input.registry_id,
                    &input.actor_id,
                    &input.idempotency_key,
                )
                .await?
            {
                if existing.policy_resource_version == input.expected_resource_version {
                    return Ok(existing);
                }
            }
            return Err(error);
        }
        self.oci_gc_generation(input.registry_id, &generation_id)
            .await?
            .context("OCI GC generation disappeared after planning")
    }
}

impl Database {
    async fn freeze_oci_gc_placements(
        &self,
        registry_id: i64,
        captured_epoch: i64,
        now: i64,
        blockers: &mut Vec<PlanBlocker>,
    ) -> Result<Vec<FrozenPlacement>> {
        let rows = self
            .backend
            .query(
                "SELECT placement.id, placement.name, placement.prefix,
                        placement.resource_version, placement.write_spec_version,
                        placement.desired_state, observation.state,
                        observation.completeness, observation.observation_version,
                        placement.binding_id, binding.resource_version,
                        write_state.current_write_revision,
                        capability.delete_credential_purpose,
                        capability.delete_credential_generation,
                        capability.capability_fingerprint, capability.state,
                        capability.resource_version, head.generation_id,
                        inventory.inventory_digest, inventory.observed_at,
                        inventory.captured_mutation_epoch,
                        inventory.placement_resource_version,
                        inventory.placement_write_spec_version,
                        inventory.placement_observation_version,
                        inventory.binding_resource_version,
                        inventory.binding_write_revision, inventory.state,
                        capability.observed_at, inventory.object_count,
                        inventory.byte_count, delete_credential.validation_state,
                        delete_credential_head.current_generation, binding.kind
                 FROM surface_placements placement
                 LEFT JOIN surface_placement_observations observation
                   ON observation.placement_id = placement.id
                 JOIN bindings binding ON binding.id = placement.binding_id
                 LEFT JOIN binding_write_state write_state
                   ON write_state.binding_id = binding.id
                 LEFT JOIN oci_conditional_delete_capabilities capability
                   ON capability.binding_id = placement.binding_id
                  AND capability.binding_write_revision = write_state.current_write_revision
                 LEFT JOIN binding_credential_revisions delete_credential
                   ON delete_credential.binding_id = capability.binding_id
                  AND delete_credential.purpose = capability.delete_credential_purpose
                  AND delete_credential.generation = capability.delete_credential_generation
                 LEFT JOIN binding_credential_heads delete_credential_head
                   ON delete_credential_head.binding_id = capability.binding_id
                  AND delete_credential_head.purpose = capability.delete_credential_purpose
                  AND delete_credential_head.current_generation =
                    capability.delete_credential_generation
                 LEFT JOIN oci_provider_inventory_heads head
                   ON head.placement_id = placement.id
                  AND head.registry_id = placement.registry_id
                 LEFT JOIN oci_provider_inventory_generations inventory
                   ON inventory.id = head.generation_id
                  AND inventory.registry_id = placement.registry_id
                  AND inventory.placement_id = placement.id
                 WHERE placement.registry_id = ?1
                 ORDER BY placement.name, placement.id LIMIT ?2",
                &vals![registry_id, i64::try_from(OCI_GC_MAX_PLACEMENTS + 1)?],
            )
            .await?;
        if rows.len() > OCI_GC_MAX_PLACEMENTS {
            bail!("OCI GC placement set exceeds the {OCI_GC_MAX_PLACEMENTS}-placement bound");
        }
        if rows.is_empty() {
            blockers.push(PlanBlocker {
                kind: "missing_placement_inventory",
                digest: None,
                detail: "registry has no provider-enumerated placement".into(),
            });
            return Ok(Vec::new());
        }
        let oldest_allowed = now.saturating_sub(OCI_GC_MAX_INVENTORY_AGE_SECONDS);
        let mut placements = Vec::with_capacity(rows.len());
        for row in &rows {
            let placement_id: i64 = row.get(0)?;
            let placement_name: String = row.get(1)?;
            let placement_prefix: String = row.get(2)?;
            let placement_resource_version: i64 = row.get(3)?;
            let placement_write_spec_version: i64 = row.get(4)?;
            let desired_state: String = row.get(5)?;
            let observation_state: Option<String> = row.get(6)?;
            let completeness: Option<String> = row.get(7)?;
            let observation_version: Option<i64> = row.get(8)?;
            let binding_id: i64 = row.get(9)?;
            let binding_resource_version: i64 = row.get(10)?;
            let binding_write_revision: Option<i64> = row.get(11)?;
            let credential_purpose: Option<String> = row.get(12)?;
            let credential_generation: Option<i64> = row.get(13)?;
            let capability_fingerprint: Option<String> = row.get(14)?;
            let capability_state: Option<String> = row.get(15)?;
            let capability_resource_version: Option<i64> = row.get(16)?;
            let inventory_generation_id: Option<String> = row.get(17)?;
            let inventory_digest: Option<String> = row.get(18)?;
            let inventory_observed_at: Option<i64> = row.get(19)?;
            let inventory_epoch: Option<i64> = row.get(20)?;
            let inventory_placement_version: Option<i64> = row.get(21)?;
            let inventory_write_spec: Option<i64> = row.get(22)?;
            let inventory_observation: Option<i64> = row.get(23)?;
            let inventory_binding_version: Option<i64> = row.get(24)?;
            let inventory_write_revision: Option<i64> = row.get(25)?;
            let inventory_state: Option<String> = row.get(26)?;
            let capability_observed_at: Option<i64> = row.get(27)?;
            let inventory_object_count: Option<i64> = row.get(28)?;
            let inventory_byte_size: Option<i64> = row.get(29)?;
            let delete_credential_state: Option<String> = row.get(30)?;
            let current_delete_credential_generation: Option<i64> = row.get(31)?;
            let binding_kind: String = row.get(32)?;

            if desired_state == "offline"
                || observation_state.as_deref() != Some("ready")
                || completeness.as_deref() != Some("complete")
                || observation_version.is_none()
            {
                blockers.push(PlanBlocker {
                    kind: "incomplete_placement_inventory",
                    digest: None,
                    detail: format!(
                        "placement '{placement_name}' is offline or lacks a ready/complete observation"
                    ),
                });
                continue;
            }
            let Some(binding_write_revision) = binding_write_revision else {
                blockers.push(PlanBlocker {
                    kind: "conditional_delete_unsupported",
                    digest: None,
                    detail: format!(
                        "placement '{placement_name}' has no immutable binding write revision"
                    ),
                });
                continue;
            };
            if capability_state.as_deref() != Some("valid")
                || capability_fingerprint.is_none()
                || capability_resource_version.is_none()
                || capability_observed_at.is_none_or(|observed| observed < oldest_allowed)
                || (credential_purpose.is_none() && binding_kind != "local_fs")
                || (credential_purpose.is_some()
                    && (delete_credential_state.as_deref() != Some("valid")
                        || current_delete_credential_generation != credential_generation))
            {
                blockers.push(PlanBlocker {
                    kind: "conditional_delete_unsupported",
                    digest: None,
                    detail: format!(
                        "placement '{placement_name}' lacks an observed conditional-delete capability"
                    ),
                });
                continue;
            }
            let exact_inventory = inventory_state.as_deref() == Some("complete")
                && inventory_epoch == Some(captured_epoch)
                && inventory_placement_version == Some(placement_resource_version)
                && inventory_write_spec == Some(placement_write_spec_version)
                && inventory_observation == observation_version
                && inventory_binding_version == Some(binding_resource_version)
                && inventory_write_revision == Some(binding_write_revision)
                && inventory_observed_at.is_some_and(|observed| observed >= oldest_allowed);
            if !exact_inventory || inventory_generation_id.is_none() || inventory_digest.is_none() {
                blockers.push(PlanBlocker {
                    kind: "stale_provider_inventory",
                    digest: None,
                    detail: format!(
                        "placement '{placement_name}' lacks a current epoch/topology-bound provider inventory"
                    ),
                });
                continue;
            }
            placements.push(FrozenPlacement {
                placement_id,
                placement_name,
                placement_prefix,
                placement_resource_version,
                placement_write_spec_version,
                placement_observation_version: observation_version
                    .context("ready placement observation version is absent")?,
                binding_id,
                binding_resource_version,
                binding_write_revision,
                delete_credential_purpose: credential_purpose,
                delete_credential_generation: credential_generation,
                delete_capability_fingerprint: capability_fingerprint
                    .context("valid delete capability fingerprint is absent")?,
                delete_capability_resource_version: capability_resource_version
                    .context("valid delete capability version is absent")?,
                delete_capability_observed_at: capability_observed_at
                    .context("valid delete capability observation time is absent")?,
                inventory_generation_id: inventory_generation_id
                    .context("complete inventory generation is absent")?,
                inventory_digest: inventory_digest
                    .context("complete inventory digest is absent")?,
                inventory_observed_at: inventory_observed_at
                    .context("complete inventory observation time is absent")?,
                inventory_object_count: u64::try_from(
                    inventory_object_count.context("complete inventory count is absent")?,
                )
                .context("complete inventory count is negative")?,
                inventory_byte_size: u64::try_from(
                    inventory_byte_size.context("complete inventory bytes are absent")?,
                )
                .context("complete inventory bytes are negative")?,
            });
        }
        Ok(placements)
    }

    async fn collect_oci_gc_hard_roots(
        &self,
        registry_id: i64,
        policy: &EffectivePolicy,
        now: i64,
    ) -> Result<BTreeSet<FrozenRoot>> {
        let mut roots = BTreeSet::new();
        for row in self
            .backend
            .query(
                "SELECT tag.digest, tag.repository_id, tag.name
                 FROM oci_tags tag WHERE tag.registry_id = ?1
                 ORDER BY tag.repository_id, tag.name LIMIT ?2",
                &vals![registry_id, i64::try_from(OCI_GC_MAX_OBJECTS + 1)?],
            )
            .await?
        {
            let repository_id = row.get(1)?;
            roots.insert(FrozenRoot {
                kind: "tag".into(),
                digest: canonical_digest(row.get(0)?)?,
                source_id: repository_root_source_id(repository_id, &row.get::<String>(2)?),
                repository_id: Some(repository_id),
            });
        }
        for row in self
            .backend
            .query(
                "SELECT evidence.referrer_digest, evidence.repository_id,
                        evidence.release_tag, evidence.evidence_kind
                 FROM oci_release_evidence evidence
                 JOIN oci_release_roots root
                   ON root.registry_id = evidence.registry_id
                  AND root.repository_id = evidence.repository_id
                  AND root.index_digest = evidence.root_digest
                  AND root.release_tag = evidence.release_tag
                 WHERE evidence.registry_id = ?1 AND evidence.verification = 'verified'
                 ORDER BY evidence.release_tag, evidence.evidence_kind,
                          evidence.referrer_digest LIMIT ?2",
                &vals![registry_id, i64::try_from(OCI_GC_MAX_OBJECTS + 1)?],
            )
            .await?
        {
            let repository_id = row.get(1)?;
            roots.insert(FrozenRoot {
                kind: "signed_release".into(),
                digest: canonical_digest(row.get(0)?)?,
                source_id: repository_root_source_id(
                    repository_id,
                    &format!("{}:{}", row.get::<String>(2)?, row.get::<String>(3)?),
                ),
                repository_id: Some(repository_id),
            });
        }
        for row in self
            .backend
            .query(
                "SELECT index_digest, repository_id, release_tag
                 FROM oci_release_roots WHERE registry_id = ?1
                 ORDER BY release_tag, repository_id, index_digest LIMIT ?2",
                &vals![registry_id, i64::try_from(OCI_GC_MAX_OBJECTS + 1)?],
            )
            .await?
        {
            let repository_id = row.get(1)?;
            roots.insert(FrozenRoot {
                kind: "signed_release".into(),
                digest: canonical_digest(row.get(0)?)?,
                source_id: repository_root_source_id(repository_id, &row.get::<String>(2)?),
                repository_id: Some(repository_id),
            });
        }
        for row in self
            .backend
            .query(
                "SELECT digest, id FROM oci_leases
                 WHERE registry_id = ?1 AND expires_at > ?2
                 ORDER BY digest, id LIMIT ?3",
                &vals![registry_id, now, i64::try_from(OCI_GC_MAX_OBJECTS + 1)?],
            )
            .await?
        {
            roots.insert(FrozenRoot {
                kind: "lease".into(),
                digest: canonical_digest(row.get(0)?)?,
                source_id: row.get(1)?,
                repository_id: None,
            });
        }
        for row in self
            .backend
            .query(
                "SELECT digest, upload_id FROM (
                   SELECT expected_digest AS digest, id AS upload_id
                   FROM oci_upload_sessions
                   WHERE registry_id = ?1 AND state IN('active', 'completing')
                     AND expected_digest IS NOT NULL
                   UNION
                   SELECT final_digest AS digest, id AS upload_id
                   FROM oci_upload_sessions
                   WHERE registry_id = ?1 AND state IN('active', 'completing')
                     AND final_digest IS NOT NULL
                 ) active_uploads ORDER BY digest, upload_id LIMIT ?2",
                &vals![registry_id, i64::try_from(OCI_GC_MAX_OBJECTS + 1)?],
            )
            .await?
        {
            roots.insert(FrozenRoot {
                kind: "upload".into(),
                digest: canonical_digest(row.get(0)?)?,
                source_id: row.get(1)?,
                repository_id: None,
            });
        }
        for row in self
            .backend
            .query(
                "SELECT object.digest, publication.id, publication.repository_id
                 FROM oci_publication_sessions publication
                 JOIN oci_publication_objects object
                   ON object.publication_id = publication.id
                 WHERE publication.registry_id = ?1
                   AND publication.state IN('preparing', 'committing')
                 ORDER BY object.digest, publication.id LIMIT ?2",
                &vals![registry_id, i64::try_from(OCI_GC_MAX_OBJECTS + 1)?],
            )
            .await?
        {
            roots.insert(FrozenRoot {
                kind: "publication".into(),
                digest: canonical_digest(row.get(0)?)?,
                source_id: row.get(1)?,
                repository_id: Some(row.get(2)?),
            });
        }
        for row in self
            .backend
            .query(
                "SELECT root_digest, id, repository_id
                 FROM oci_publication_sessions
                 WHERE registry_id = ?1 AND state IN('preparing', 'committing')
                 ORDER BY root_digest, id LIMIT ?2",
                &vals![registry_id, i64::try_from(OCI_GC_MAX_OBJECTS + 1)?],
            )
            .await?
        {
            roots.insert(FrozenRoot {
                kind: "publication".into(),
                digest: canonical_digest(row.get(0)?)?,
                source_id: row.get(1)?,
                repository_id: Some(row.get(2)?),
            });
        }
        self.collect_oci_gc_history_roots(registry_id, policy, now, &mut roots)
            .await?;
        if roots.len() > OCI_GC_MAX_OBJECTS {
            bail!("OCI GC hard-root set exceeds the {OCI_GC_MAX_OBJECTS}-object bound");
        }
        Ok(roots)
    }

    /// Stamps the first authoritative unreferenced observation in bounded
    /// batches. NULL remains fail-closed: current hard roots and rows not yet
    /// visited by reconciliation are protected from candidacy.
    async fn reconcile_oci_unreferenced_since(
        &self,
        registry_id: i64,
        now: i64,
        roots: &BTreeSet<FrozenRoot>,
        blockers: &mut Vec<PlanBlocker>,
    ) -> Result<()> {
        const RECONCILE_BATCH: usize = 100;
        let hard = roots
            .iter()
            .map(|root| root.digest.as_str())
            .collect::<BTreeSet<_>>();
        let mut cursor: Option<String> = None;
        let mut unreferenced = Vec::with_capacity(RECONCILE_BATCH + 1);
        while unreferenced.len() <= RECONCILE_BATCH {
            let rows = self
                .backend
                .query(
                    "SELECT digest FROM oci_blobs
                     WHERE registry_id = ?1 AND lifecycle_state = 'active'
                       AND unreferenced_since IS NULL
                       AND (?2 IS NULL OR digest > ?2)
                     ORDER BY digest LIMIT ?3",
                    &vals![
                        registry_id,
                        cursor.as_deref(),
                        i64::try_from(RECONCILE_BATCH + 1)?
                    ],
                )
                .await?;
            if rows.is_empty() {
                break;
            }
            for row in &rows {
                let digest: String = row.get(0)?;
                cursor = Some(digest.clone());
                if !hard.contains(digest.as_str()) {
                    unreferenced.push(digest);
                    if unreferenced.len() > RECONCILE_BATCH {
                        break;
                    }
                }
            }
            if rows.len() <= RECONCILE_BATCH || unreferenced.len() > RECONCILE_BATCH {
                break;
            }
        }
        for digest in unreferenced.iter().take(RECONCILE_BATCH) {
            self.backend
                .execute(
                    "UPDATE oci_blobs SET unreferenced_since = ?3, updated_at = ?3
                     WHERE registry_id = ?1 AND digest = ?2
                       AND lifecycle_state = 'active' AND unreferenced_since IS NULL",
                    &vals![registry_id, digest, now],
                )
                .await?;
        }
        if unreferenced.len() > RECONCILE_BATCH {
            blockers.push(PlanBlocker {
                kind: "pending_unreferenced_reconciliation".into(),
                digest: None,
                detail: "bounded unreferenced-time reconciliation requires another pass".into(),
            });
        }
        Ok(())
    }

    /// Returns every active object still inside grace (including fail-closed
    /// unknown history) so traversal protects its complete forward closure.
    async fn collect_oci_gc_grace_roots(
        &self,
        registry_id: i64,
        policy: &EffectivePolicy,
        now: i64,
    ) -> Result<BTreeSet<String>> {
        let grace = i64::try_from(policy.untagged_grace_seconds)
            .context("OCI untagged grace exceeds int64")?;
        let cutoff = now.saturating_sub(grace);
        let rows = self
            .backend
            .query(
                "SELECT stored_blob.digest FROM oci_blobs stored_blob
                 JOIN oci_manifests manifest
                   ON manifest.registry_id = stored_blob.registry_id
                  AND manifest.digest = stored_blob.digest
                 WHERE stored_blob.registry_id = ?1
                   AND stored_blob.lifecycle_state = 'active'
                   AND (stored_blob.unreferenced_since IS NULL
                     OR stored_blob.unreferenced_since > ?2)
                 ORDER BY stored_blob.digest LIMIT ?3",
                &vals![registry_id, cutoff, i64::try_from(OCI_GC_MAX_EDGES + 1)?],
            )
            .await?;
        if rows.len() > OCI_GC_MAX_EDGES {
            bail!("OCI grace-protected manifest frontier exceeds the graph bound");
        }
        rows.iter()
            .map(|row| canonical_digest(row.get(0)?))
            .collect()
    }

    async fn traverse_oci_gc_live_graph(
        &self,
        registry_id: i64,
        retain_referrers: bool,
        roots: &mut BTreeSet<FrozenRoot>,
        grace_roots: &BTreeSet<String>,
        blockers: &mut Vec<PlanBlocker>,
    ) -> Result<BTreeSet<String>> {
        for root in roots.iter() {
            let exists = self
                .backend
                .query_opt(
                    "SELECT 1 FROM oci_blobs stored_blob
                     WHERE stored_blob.registry_id = ?1 AND stored_blob.digest = ?2
                       AND stored_blob.lifecycle_state = 'active'
                       AND (?3 IS NULL OR EXISTS (SELECT 1 FROM oci_repository_objects link
                         WHERE link.registry_id = stored_blob.registry_id
                           AND link.repository_id = ?3
                           AND link.digest = stored_blob.digest))",
                    &vals![registry_id, root.digest, root.repository_id],
                )
                .await?
                .is_some();
            if !exists {
                blockers.push(PlanBlocker {
                    kind: "stale_root_identity",
                    digest: Some(Sha256Digest::parse(&root.digest)?),
                    detail: format!(
                        "{} root '{}' lacks an active catalog identity or repository link",
                        root.kind, root.source_id
                    ),
                });
            }
        }
        let rows = self
            .backend
            .query(
                "SELECT manifest.digest, manifest.descriptor_count,
                        edge.edge_role, edge.target_digest,
                        CASE WHEN target.digest IS NULL THEN 0 ELSE 1 END
                 FROM oci_manifests manifest
                 JOIN oci_blobs manifest_blob
                   ON manifest_blob.registry_id = manifest.registry_id
                  AND manifest_blob.digest = manifest.digest
                  AND manifest_blob.lifecycle_state = 'active'
                 LEFT JOIN oci_descriptor_edges edge
                   ON edge.registry_id = manifest.registry_id
                  AND edge.manifest_digest = manifest.digest
                 LEFT JOIN oci_blobs target
                   ON target.registry_id = edge.registry_id
                  AND target.digest = edge.target_digest
                  AND target.lifecycle_state = 'active'
                 WHERE manifest.registry_id = ?1
                 ORDER BY manifest.digest, edge.edge_role, edge.ordinal
                 LIMIT ?2",
                &vals![registry_id, i64::try_from(OCI_GC_MAX_EDGES + 1)?],
            )
            .await?;
        if rows.len() > OCI_GC_MAX_EDGES {
            bail!("OCI descriptor graph exceeds the {OCI_GC_MAX_EDGES}-edge bound");
        }
        let mut forward: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut reverse_referrers: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut declared = BTreeMap::new();
        let mut observed = BTreeMap::<String, usize>::new();
        for row in &rows {
            let manifest = canonical_digest(row.get(0)?)?;
            declared.insert(manifest.clone(), row.get::<i64>(1)?);
            let Some(role) = row.get::<Option<String>>(2)? else {
                continue;
            };
            let target = canonical_digest(
                row.get::<Option<String>>(3)?
                    .context("OCI descriptor edge target is absent")?,
            )?;
            *observed.entry(manifest.clone()).or_default() += 1;
            if row.get::<i64>(4)? == 0 {
                blockers.push(PlanBlocker {
                    kind: "missing_descriptor_target",
                    digest: Some(Sha256Digest::parse(&target)?),
                    detail: format!("manifest {manifest} has a missing/inactive {role} target"),
                });
                continue;
            }
            forward
                .entry(manifest.clone())
                .or_default()
                .push(target.clone());
            if role == "subject" {
                reverse_referrers.entry(target).or_default().push(manifest);
            }
        }
        for (manifest, count) in declared {
            let count = usize::try_from(count).context("negative OCI descriptor count")?;
            if observed.get(&manifest).copied().unwrap_or(0) != count {
                blockers.push(PlanBlocker {
                    kind: "incomplete_descriptor_graph",
                    digest: Some(Sha256Digest::parse(&manifest)?),
                    detail: "manifest descriptor count conflicts with persisted edges".into(),
                });
            }
        }

        let mut live = BTreeSet::new();
        let mut queue = VecDeque::new();
        for root in roots.iter() {
            queue.push_back((root.digest.clone(), 0_usize));
        }
        for digest in grace_roots {
            queue.push_back((digest.clone(), 0_usize));
        }
        while let Some((digest, depth)) = queue.pop_front() {
            if !live.insert(digest.clone()) {
                continue;
            }
            if live.len() > OCI_GC_MAX_OBJECTS.saturating_add(OCI_GC_MAX_EDGES) {
                bail!("OCI live graph exceeds the bounded root-plus-edge frontier");
            }
            if depth > OCI_GC_MAX_DEPTH {
                bail!("OCI live graph exceeds the {OCI_GC_MAX_DEPTH}-level bound");
            }
            if let Some(targets) = forward.get(&digest) {
                for target in targets {
                    queue.push_back((target.clone(), depth + 1));
                }
            }
            if retain_referrers {
                if let Some(referrers) = reverse_referrers.get(&digest) {
                    for referrer in referrers {
                        roots.insert(FrozenRoot {
                            kind: "referrer".into(),
                            digest: referrer.clone(),
                            source_id: digest.clone(),
                            repository_id: None,
                        });
                        queue.push_back((referrer.clone(), depth + 1));
                    }
                }
            }
        }
        Ok(live)
    }

    async fn freeze_oci_gc_actions(
        &self,
        registry_id: i64,
        placements: &[FrozenPlacement],
        candidates: &[FrozenCandidate],
        blockers: &mut Vec<PlanBlocker>,
    ) -> Result<Vec<FrozenAction>> {
        let mut actions = Vec::new();
        for candidate in candidates {
            for placement in placements {
                let inventory = self
                    .backend
                    .query_opt(
                        "SELECT object_digest, observed_hash, byte_size, strong_etag,
                                surface_object_id, catalog_object_resource_version,
                                classification, deleted_at
                         FROM oci_provider_inventory_entries
                         WHERE generation_id = ?1 AND registry_id = ?2
                           AND placement_id = ?3 AND object_key = ?4",
                        &vals![
                            placement.inventory_generation_id,
                            registry_id,
                            placement.placement_id,
                            candidate.object_key
                        ],
                    )
                    .await?;
                let expected_strong_etag = if let Some(row) = inventory.as_ref() {
                    let exact = row.get::<String>(0)? == candidate.digest
                        && row.get::<String>(1)? == candidate.digest
                        && u64::try_from(row.get::<i64>(2)?)? == candidate.byte_size
                        && row.get::<Option<i64>>(4)? == Some(candidate.surface_object_id)
                        && row.get::<Option<i64>>(5)?
                            == Some(candidate.catalog_object_resource_version)
                        && row.get::<String>(6)? == "tracked"
                        && row.get::<Option<i64>>(7)?.is_none();
                    if !exact {
                        blockers.push(PlanBlocker {
                            kind: "provider_inventory_conflict",
                            digest: Some(Sha256Digest::parse(&candidate.digest)?),
                            detail: format!(
                                "placement '{}' inventory conflicts with catalog identity",
                                placement.placement_name
                            ),
                        });
                    }
                    Some(row.get(3)?)
                } else {
                    None
                };
                actions.push(FrozenAction {
                    id: format!("ocigca-{}", Uuid::new_v4().simple()),
                    digest: candidate.digest.clone(),
                    placement_id: placement.placement_id,
                    object_key: candidate.object_key.clone(),
                    expected_hash: candidate.digest.clone(),
                    expected_size: candidate.byte_size,
                    expected_strong_etag,
                    inventory_generation_id: placement.inventory_generation_id.clone(),
                    inventory_entry_present: inventory.is_some(),
                });
            }
        }
        Ok(actions)
    }
}

#[cfg(test)]
mod tests {
    use super::repository_root_source_id;

    #[test]
    fn repository_root_sources_do_not_collide_across_repositories() {
        assert_ne!(
            repository_root_source_id(7, "latest"),
            repository_root_source_id(11, "latest")
        );
        assert_eq!(repository_root_source_id(7, "latest"), "7:latest");
    }
}
