//! Phase 7 authority fences and provider-inventory reconciliation records.
//!
//! Registry purge is deliberately two-stage: the fence first excludes every
//! Hub writer, then provider inventory captured after that fence proves the
//! physical namespace empty. Untracked inventory remains provider evidence;
//! listing it never silently promotes it into the logical OCI catalog.

use anyhow::{bail, Context, Result};
use aos_oci_types::{MediaType, Sha256Digest};
use serde::Serialize;
use uuid::Uuid;

use crate::backend::Statement;
use crate::db::{validate_key_bytes, Database};

/// Durable write fence that precedes final provider-empty inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciRegistryPurgeFenceRecord {
    /// Registry whose Hub writers are excluded.
    pub registry_id: i64,
    /// Authenticated actor that requested purge.
    pub actor_id: String,
    /// Stable response-loss retry key.
    pub idempotency_key: String,
    /// Registry version reviewed by the actor.
    pub registry_resource_version: i64,
    /// Mutation epoch frozen before post-fence enumeration.
    pub captured_mutation_epoch: i64,
    /// `collecting` or `aborted`.
    pub state: String,
    /// Fence acquisition time.
    pub created_at: i64,
    /// Fence cancellation time.
    pub aborted_at: Option<i64>,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
}

/// Exact keyset selector for one immutable inventory head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciUntrackedInventoryCursor {
    /// Complete provider inventory generation bound by the cursor.
    pub generation_id: String,
    /// Last object key returned by the preceding page.
    pub object_key: String,
    /// Registry mutation epoch bound by the page selector.
    pub captured_mutation_epoch: i64,
}

/// One bounded, selector-bound page of untracked provider evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciUntrackedInventoryPage {
    /// Exact current-head entries.
    pub items: Vec<OciUntrackedInventoryRecord>,
    /// Continuation bound to the same registry epoch and inventory order.
    pub next_cursor: Option<OciUntrackedInventoryCursor>,
    /// Registry mutation epoch shared by every returned head.
    pub captured_mutation_epoch: i64,
}

/// One current-head provider object with no matching catalog identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciUntrackedInventoryRecord {
    /// Owning registry.
    pub registry_id: i64,
    /// Exact placement enumerated by the provider.
    pub placement_id: i64,
    /// Complete inventory generation containing the evidence.
    pub inventory_generation_id: String,
    /// Canonical complete-inventory digest.
    pub inventory_digest: Sha256Digest,
    /// Provider observation time.
    pub inventory_observed_at: i64,
    /// Canonical provider key.
    pub object_key: String,
    /// Digest encoded in the canonical key.
    pub object_digest: Sha256Digest,
    /// Hash observed from provider bytes.
    pub observed_hash: Sha256Digest,
    /// Exact provider byte length.
    pub byte_size: u64,
    /// Strong conditional-delete entity tag.
    pub strong_etag: String,
    /// Frozen placement optimistic-concurrency version.
    pub placement_resource_version: i64,
    /// Stable placement name.
    pub placement_name: String,
    /// Exact provider addressing prefix.
    pub placement_prefix: String,
    /// Frozen placement writer-spec version.
    pub placement_write_spec_version: i64,
    /// Frozen placement observation version.
    pub placement_observation_version: i64,
    /// Frozen binding id.
    pub binding_id: i64,
    /// Frozen binding resource version.
    pub binding_resource_version: i64,
    /// Frozen immutable binding writer revision.
    pub binding_write_revision: i64,
    /// Observed delete credential purpose, when the placement uses one.
    pub delete_credential_purpose: Option<String>,
    /// Observed delete credential generation, when the placement uses one.
    pub delete_credential_generation: Option<i64>,
    /// Current capability fingerprint, absent when probing is incomplete.
    pub delete_capability_fingerprint: Option<String>,
    /// Current capability version, absent when probing is incomplete.
    pub delete_capability_resource_version: Option<i64>,
}

/// Reviewed repair behavior for one untracked provider object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OciUntrackedRepairKind {
    /// Schedules exact conditional physical deletion.
    Delete,
    /// Adopts exact provider bytes into the registry-global logical catalog.
    Adopt,
}

impl OciUntrackedRepairKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Delete => "delete",
            Self::Adopt => "adopt",
        }
    }
}

/// Terminal physical or catalog outcome of an untracked-object repair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OciUntrackedRepairOutcome {
    /// Conditional deletion removed the exact provider entity.
    Deleted,
    /// A live exact lookup proved the provider entity was already absent.
    AlreadyAbsent,
    /// Internal reconciliation adopted the exact bytes into catalog authority.
    Adopted,
}

/// Input for creating one actor-bound reviewed repair plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanOciUntrackedRepair {
    /// Owning registry.
    pub registry_id: i64,
    /// Placement containing the untracked key.
    pub placement_id: i64,
    /// Exact current-head inventory generation reviewed by the actor.
    pub inventory_generation_id: String,
    /// Exact canonical provider key.
    pub object_key: String,
    /// Requested repair behavior.
    pub repair_kind: OciUntrackedRepairKind,
    /// Required media type for internal adoption; absent for deletion.
    pub adopt_media_type: Option<MediaType>,
    /// Authenticated actor identity.
    pub actor_id: String,
    /// Stable plan retry key.
    pub idempotency_key: String,
    /// Registry mutation epoch returned by the listing page.
    pub expected_mutation_epoch: i64,
    /// Planning time in Unix seconds.
    pub now: i64,
}

/// Input for applying one exact reviewed repair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOciUntrackedRepair {
    /// Durable plan identity.
    pub plan_id: String,
    /// Authenticated actor that created the plan.
    pub actor_id: String,
    /// Stable apply retry key.
    pub idempotency_key: String,
    /// Exact reviewed confirmation digest.
    pub confirmation_hash: Sha256Digest,
    /// Expected plan optimistic-concurrency version.
    pub expected_resource_version: i64,
    /// Apply time in Unix seconds.
    pub now: i64,
}

/// Durable reviewed plan and operation state for untracked reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciUntrackedRepairPlanRecord {
    /// Stable plan and operation id.
    pub id: String,
    /// Owning registry.
    pub registry_id: i64,
    /// Exact placement.
    pub placement_id: i64,
    /// Frozen placement name.
    pub placement_name: String,
    /// Frozen provider prefix.
    pub placement_prefix: String,
    /// Frozen placement resource version.
    pub placement_resource_version: i64,
    /// Frozen writer-spec version.
    pub placement_write_spec_version: i64,
    /// Frozen ready observation version.
    pub placement_observation_version: i64,
    /// Frozen binding id.
    pub binding_id: i64,
    /// Frozen binding resource version.
    pub binding_resource_version: i64,
    /// Frozen immutable writer revision.
    pub binding_write_revision: i64,
    /// Frozen delete credential purpose.
    pub delete_credential_purpose: Option<String>,
    /// Frozen delete credential generation.
    pub delete_credential_generation: Option<i64>,
    /// Frozen capability semantics fingerprint.
    pub delete_capability_fingerprint: String,
    /// Frozen capability observation version.
    pub delete_capability_resource_version: i64,
    /// Exact complete inventory generation.
    pub inventory_generation_id: String,
    /// Exact complete inventory digest.
    pub inventory_digest: Sha256Digest,
    /// Provider inventory observation time.
    pub inventory_observed_at: i64,
    /// Canonical provider key.
    pub object_key: String,
    /// Digest encoded in the key.
    pub object_digest: Sha256Digest,
    /// Provider-observed content hash.
    pub observed_hash: Sha256Digest,
    /// Exact provider byte length.
    pub byte_size: u64,
    /// Strong conditional entity tag.
    pub strong_etag: String,
    /// Reviewed repair behavior.
    pub repair_kind: OciUntrackedRepairKind,
    /// Internal adoption media type.
    pub adopt_media_type: Option<MediaType>,
    /// Actor that owns the plan.
    pub actor_id: String,
    /// Registry epoch frozen by planning.
    pub captured_mutation_epoch: i64,
    /// Canonical reviewed confirmation digest.
    pub confirmation_hash: Sha256Digest,
    /// Durable operation state.
    pub state: String,
    /// Review expiry.
    pub expires_at: i64,
    /// Creation time.
    pub created_at: i64,
    /// Apply time.
    pub applied_at: Option<i64>,
    /// Terminal time.
    pub finished_at: Option<i64>,
    /// Sanitized terminal failure detail.
    pub last_error: Option<String>,
    /// Exact provider terminal outcome, when absence evidence is committed.
    pub outcome: Option<OciUntrackedRepairOutcome>,
    /// Provider request identity retained for audit.
    pub provider_request_id: Option<String>,
    /// Strong entity tag used by a successful conditional delete.
    pub conditional_etag: Option<String>,
    /// Canonical digest over the complete provider response evidence.
    pub evidence_digest: Option<Sha256Digest>,
    /// Provider absence confirmation time.
    pub confirmed_at: Option<i64>,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UntrackedRepairConfirmation<'a> {
    registry_id: i64,
    placement_id: i64,
    inventory_generation_id: &'a str,
    inventory_digest: &'a str,
    object_key: &'a str,
    object_digest: &'a str,
    observed_hash: &'a str,
    byte_size: u64,
    strong_etag: &'a str,
    repair_kind: OciUntrackedRepairKind,
    adopt_media_type: Option<&'a str>,
    actor_id: &'a str,
    captured_mutation_epoch: i64,
    expires_at: i64,
}

impl Database {
    /// Acquires the durable writer fence required before final purge inventory.
    ///
    /// Exact actor/key retries return the existing fence. The registry must
    /// already be logically empty and have no active OCI or GC work.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input, stale registry state, nonempty OCI
    /// state, an active competing fence, or database failure.
    pub async fn begin_oci_registry_purge_fence(
        &self,
        registry_id: i64,
        expected_registry_resource_version: i64,
        actor_id: &str,
        idempotency_key: &str,
        now: i64,
    ) -> Result<OciRegistryPurgeFenceRecord> {
        validate_key_bytes(actor_id, "OCI purge actor id", 128)?;
        validate_key_bytes(idempotency_key, "OCI purge idempotency key", 128)?;
        if registry_id <= 0 || expected_registry_resource_version < 1 || now <= 0 {
            bail!("OCI registry purge fence identity is invalid");
        }
        if let Some(existing) = self.oci_registry_purge_fence(registry_id).await? {
            if existing.state == "collecting"
                && existing.actor_id == actor_id
                && existing.idempotency_key == idempotency_key
                && existing.registry_resource_version == expected_registry_resource_version
            {
                return Ok(existing);
            }
            if existing.state == "collecting" {
                bail!("OCI registry purge fence conflicts with an existing request");
            }
        }

        self.backend
            .checked_batch(&[
                Statement::new(
                    "INSERT INTO oci_registry_state
                       (registry_id, mutation_epoch, charged_bytes,
                        charged_objects, updated_at)
                     SELECT id, 0, 0, 0, ?2 FROM registries
                     WHERE id = ?1
                     ON CONFLICT(registry_id) DO NOTHING",
                    vals![registry_id, now],
                )
                .unchecked(),
                Statement::new(
                    "DELETE FROM oci_registry_purge_fences
                     WHERE registry_id = ?1 AND state = 'aborted'",
                    vals![registry_id],
                )
                .unchecked(),
                Statement::new(
                    "UPDATE registries SET updated_at = updated_at
                     WHERE id = ?1 AND resource_version = ?2
                       AND NOT EXISTS (SELECT 1 FROM oci_repositories WHERE registry_id = ?1)
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
                    vals![registry_id, expected_registry_resource_version],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO oci_registry_purge_fences
                       (registry_id, actor_id, idempotency_key,
                        registry_resource_version, captured_mutation_epoch,
                        state, created_at, aborted_at, resource_version)
                     SELECT ?1, ?2, ?3, ?4, registry_state.mutation_epoch,
                            'collecting', ?5, NULL, 1
                     FROM oci_registry_state registry_state
                     WHERE registry_state.registry_id = ?1",
                    vals![
                        registry_id,
                        actor_id,
                        idempotency_key,
                        expected_registry_resource_version,
                        now
                    ],
                )
                .expecting(1),
            ])
            .await?;
        self.oci_registry_purge_fence(registry_id)
            .await?
            .context("OCI registry purge fence disappeared after acquisition")
    }

    /// Returns the current purge fence for one registry.
    ///
    /// # Errors
    ///
    /// Returns an error on malformed persisted data or database failure.
    pub async fn oci_registry_purge_fence(
        &self,
        registry_id: i64,
    ) -> Result<Option<OciRegistryPurgeFenceRecord>> {
        self.backend
            .query_opt(
                "SELECT registry_id, actor_id, idempotency_key,
                        registry_resource_version, captured_mutation_epoch,
                        state, created_at, aborted_at, resource_version
                 FROM oci_registry_purge_fences WHERE registry_id = ?1",
                &vals![registry_id],
            )
            .await?
            .map(|row| {
                Ok(OciRegistryPurgeFenceRecord {
                    registry_id: row.get(0)?,
                    actor_id: row.get(1)?,
                    idempotency_key: row.get(2)?,
                    registry_resource_version: row.get(3)?,
                    captured_mutation_epoch: row.get(4)?,
                    state: row.get(5)?,
                    created_at: row.get(6)?,
                    aborted_at: row.get(7)?,
                    resource_version: row.get(8)?,
                })
            })
            .transpose()
    }

    /// Cancels a purge fence so ordinary writers may resume.
    ///
    /// # Errors
    ///
    /// Returns an error for stale ownership/version, invalid input, or database
    /// failure.
    pub async fn abort_oci_registry_purge_fence(
        &self,
        registry_id: i64,
        actor_id: &str,
        expected_resource_version: i64,
        now: i64,
    ) -> Result<OciRegistryPurgeFenceRecord> {
        validate_key_bytes(actor_id, "OCI purge actor id", 128)?;
        if registry_id <= 0 || expected_resource_version < 1 || now <= 0 {
            bail!("OCI registry purge abort identity is invalid");
        }
        self.backend
            .checked_batch(&[Statement::new(
                "UPDATE oci_registry_purge_fences
                 SET state = 'aborted', aborted_at = ?4,
                     resource_version = resource_version + 1
                 WHERE registry_id = ?1 AND actor_id = ?2
                   AND state = 'collecting' AND resource_version = ?3",
                vals![registry_id, actor_id, expected_resource_version, now],
            )
            .expecting(1)])
            .await?;
        self.oci_registry_purge_fence(registry_id)
            .await?
            .context("OCI registry purge fence disappeared after abort")
    }

    /// Lists one bounded page of untracked entries from exact current heads.
    ///
    /// A continuation is generation-bound; if the placement head advances, a
    /// stale cursor returns no rows instead of mixing observations.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid bounds/cursor, malformed persisted evidence,
    /// or database failure.
    pub async fn list_untracked_oci_provider_inventory(
        &self,
        registry_id: i64,
        cursor: Option<&OciUntrackedInventoryCursor>,
        limit: u32,
    ) -> Result<OciUntrackedInventoryPage> {
        if registry_id <= 0 || limit == 0 || limit > super::OCI_GC_MAX_PAGE_SIZE {
            bail!("OCI untracked inventory selector is invalid");
        }
        if let Some(cursor) = cursor {
            validate_key_bytes(&cursor.generation_id, "OCI inventory cursor generation", 64)?;
            validate_key_bytes(&cursor.object_key, "OCI inventory cursor key", 512)?;
            if cursor.captured_mutation_epoch < 0 {
                bail!("OCI inventory cursor epoch is invalid");
            }
        }
        let captured_mutation_epoch: i64 = self
            .backend
            .query_opt(
                "SELECT COALESCE(registry_state.mutation_epoch, 0)
                 FROM registries registry
                 LEFT JOIN oci_registry_state registry_state
                   ON registry_state.registry_id = registry.id
                 WHERE registry.id = ?1",
                &vals![registry_id],
            )
            .await?
            .context("OCI registry does not exist")?
            .get(0)?;
        if let Some(cursor) = cursor {
            if cursor.captured_mutation_epoch != captured_mutation_epoch
                || self
                    .backend
                    .query_opt(
                        "SELECT 1 FROM oci_provider_inventory_heads head
                         JOIN oci_provider_inventory_generations inventory
                           ON inventory.id = head.generation_id
                         WHERE head.registry_id = ?1 AND head.generation_id = ?2
                           AND inventory.captured_mutation_epoch = ?3",
                        &vals![registry_id, cursor.generation_id, captured_mutation_epoch],
                    )
                    .await?
                    .is_none()
            {
                bail!("OCI untracked inventory cursor is stale");
            }
        }
        let rows = self
            .backend
            .query(
                "SELECT entry.registry_id, entry.placement_id, entry.generation_id,
                        inventory.inventory_digest, inventory.observed_at,
                        entry.object_key, entry.object_digest, entry.observed_hash,
                        entry.byte_size, entry.strong_etag,
                        inventory.placement_resource_version,
                        placement.name, placement.prefix,
                        inventory.placement_write_spec_version,
                        inventory.placement_observation_version,
                        inventory.binding_id, inventory.binding_resource_version,
                        inventory.binding_write_revision,
                        capability.delete_credential_purpose,
                        capability.delete_credential_generation,
                        capability.capability_fingerprint, capability.resource_version
                 FROM oci_provider_inventory_entries entry
                 JOIN oci_provider_inventory_heads head
                   ON head.placement_id = entry.placement_id
                  AND head.generation_id = entry.generation_id
                 JOIN oci_provider_inventory_generations inventory
                   ON inventory.id = head.generation_id
                  AND inventory.registry_id = entry.registry_id
                 JOIN surface_placements placement
                   ON placement.id = inventory.placement_id
                  AND placement.registry_id = inventory.registry_id
                 LEFT JOIN oci_conditional_delete_capabilities capability
                   ON capability.binding_id = inventory.binding_id
                  AND capability.binding_write_revision = inventory.binding_write_revision
                 WHERE entry.registry_id = ?1 AND entry.classification = 'untracked'
                   AND entry.deleted_at IS NULL
                   AND (?2 IS NULL OR entry.generation_id > ?2
                     OR (entry.generation_id = ?2 AND entry.object_key > ?3))
                 ORDER BY entry.generation_id, entry.object_key LIMIT ?4",
                &vals![
                    registry_id,
                    cursor.map(|value| value.generation_id.as_str()),
                    cursor.map(|value| value.object_key.as_str()),
                    i64::from(limit) + 1
                ],
            )
            .await?;
        let mut items = rows
            .iter()
            .map(|row| {
                Ok(OciUntrackedInventoryRecord {
                    registry_id: row.get(0)?,
                    placement_id: row.get(1)?,
                    inventory_generation_id: row.get(2)?,
                    inventory_digest: Sha256Digest::parse(&row.get::<String>(3)?)?,
                    inventory_observed_at: row.get(4)?,
                    object_key: row.get(5)?,
                    object_digest: Sha256Digest::parse(&row.get::<String>(6)?)?,
                    observed_hash: Sha256Digest::parse(&row.get::<String>(7)?)?,
                    byte_size: u64::try_from(row.get::<i64>(8)?)
                        .context("untracked OCI inventory size is negative")?,
                    strong_etag: row.get(9)?,
                    placement_resource_version: row.get(10)?,
                    placement_name: row.get(11)?,
                    placement_prefix: row.get(12)?,
                    placement_write_spec_version: row.get(13)?,
                    placement_observation_version: row.get(14)?,
                    binding_id: row.get(15)?,
                    binding_resource_version: row.get(16)?,
                    binding_write_revision: row.get(17)?,
                    delete_credential_purpose: row.get(18)?,
                    delete_credential_generation: row.get(19)?,
                    delete_capability_fingerprint: row.get(20)?,
                    delete_capability_resource_version: row.get(21)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let has_more = items.len() > usize::try_from(limit)?;
        if has_more {
            items.pop();
        }
        let next_cursor = if has_more {
            items.last().map(|item| OciUntrackedInventoryCursor {
                generation_id: item.inventory_generation_id.clone(),
                object_key: item.object_key.clone(),
                captured_mutation_epoch,
            })
        } else {
            None
        };
        Ok(OciUntrackedInventoryPage {
            items,
            next_cursor,
            captured_mutation_epoch,
        })
    }

    /// Creates one reviewed, actor-bound untracked-object repair plan.
    ///
    /// The plan is accepted only from the exact current inventory head and
    /// freezes every non-secret provider access identity needed by execution.
    ///
    /// # Errors
    ///
    /// Returns an error for stale inventory/epoch/topology/capability, invalid
    /// input, idempotency conflict, or database failure.
    pub async fn plan_oci_untracked_repair(
        &self,
        input: &PlanOciUntrackedRepair,
    ) -> Result<OciUntrackedRepairPlanRecord> {
        validate_key_bytes(
            &input.inventory_generation_id,
            "OCI inventory generation",
            64,
        )?;
        validate_key_bytes(&input.object_key, "OCI untracked object key", 512)?;
        validate_key_bytes(&input.actor_id, "OCI repair actor id", 128)?;
        validate_key_bytes(&input.idempotency_key, "OCI repair idempotency key", 128)?;
        if input.registry_id <= 0
            || input.placement_id <= 0
            || input.expected_mutation_epoch < 0
            || input.now <= 0
            || (input.repair_kind == OciUntrackedRepairKind::Delete
                && input.adopt_media_type.is_some())
            || (input.repair_kind == OciUntrackedRepairKind::Adopt
                && input.adopt_media_type.is_none())
        {
            bail!("OCI untracked repair plan identity is invalid");
        }
        let replay_query = format!(
            "{UNTRACKED_REPAIR_COLUMNS}
             WHERE repair.registry_id = ?1 AND repair.actor_id = ?2
               AND repair.plan_idempotency_key = ?3"
        );
        if let Some(existing) = self
            .backend
            .query_opt(
                &replay_query,
                &vals![input.registry_id, input.actor_id, input.idempotency_key],
            )
            .await?
        {
            let existing = row_to_untracked_repair(&existing)?;
            if existing.placement_id == input.placement_id
                && existing.inventory_generation_id == input.inventory_generation_id
                && existing.object_key == input.object_key
                && existing.repair_kind == input.repair_kind
                && existing.adopt_media_type == input.adopt_media_type
                && existing.captured_mutation_epoch == input.expected_mutation_epoch
            {
                return Ok(existing);
            }
            bail!("OCI untracked repair plan idempotency conflict");
        }

        let oldest_capability = input
            .now
            .saturating_sub(super::OCI_GC_MAX_INVENTORY_AGE_SECONDS);
        let row = self
            .backend
            .query_opt(
                "SELECT entry.registry_id, entry.placement_id, entry.generation_id,
                        inventory.inventory_digest, inventory.observed_at,
                        entry.object_key, entry.object_digest, entry.observed_hash,
                        entry.byte_size, entry.strong_etag,
                        placement.name, placement.prefix, placement.resource_version,
                        placement.write_spec_version, observation.observation_version,
                        placement.binding_id, binding.resource_version,
                        inventory.binding_write_revision,
                        capability.delete_credential_purpose,
                        capability.delete_credential_generation,
                        capability.capability_fingerprint, capability.resource_version
                 FROM oci_provider_inventory_entries entry
                 JOIN oci_provider_inventory_heads head
                   ON head.placement_id = entry.placement_id
                  AND head.generation_id = entry.generation_id
                 JOIN oci_provider_inventory_generations inventory
                   ON inventory.id = head.generation_id
                  AND inventory.registry_id = entry.registry_id
                 JOIN oci_registry_state registry_state
                   ON registry_state.registry_id = inventory.registry_id
                 JOIN surface_placements placement
                   ON placement.id = inventory.placement_id
                  AND placement.registry_id = inventory.registry_id
                 JOIN surface_placement_observations observation
                   ON observation.placement_id = placement.id
                 JOIN bindings binding ON binding.id = placement.binding_id
                 JOIN oci_conditional_delete_capabilities capability
                   ON capability.binding_id = inventory.binding_id
                  AND capability.binding_write_revision = inventory.binding_write_revision
                 LEFT JOIN binding_credential_revisions credential
                   ON credential.binding_id = capability.binding_id
                  AND credential.purpose = capability.delete_credential_purpose
                  AND credential.generation = capability.delete_credential_generation
                 WHERE entry.registry_id = ?1 AND entry.placement_id = ?2
                   AND entry.generation_id = ?3 AND entry.object_key = ?4
                   AND entry.classification = 'untracked' AND entry.deleted_at IS NULL
                   AND inventory.state = 'complete' AND inventory.inventory_digest IS NOT NULL
                   AND inventory.captured_mutation_epoch = ?5
                   AND registry_state.mutation_epoch = ?5
                   AND placement.resource_version = inventory.placement_resource_version
                   AND placement.write_spec_version = inventory.placement_write_spec_version
                   AND observation.observation_version >= inventory.placement_observation_version
                   AND observation.state = 'ready' AND observation.completeness = 'complete'
                   AND binding.resource_version = inventory.binding_resource_version
                   AND capability.binding_resource_version = binding.resource_version
                   AND capability.state = 'valid' AND capability.observed_at >= ?6
                   AND ((capability.delete_credential_purpose IS NULL
                         AND capability.delete_credential_generation IS NULL
                         AND binding.kind = 'local_fs')
                     OR credential.validation_state = 'valid')
                   AND NOT EXISTS (SELECT 1 FROM oci_gc_registry_locks registry_lock
                     WHERE registry_lock.registry_id = entry.registry_id)",
                &vals![
                    input.registry_id,
                    input.placement_id,
                    input.inventory_generation_id,
                    input.object_key,
                    input.expected_mutation_epoch,
                    oldest_capability
                ],
            )
            .await?
            .context("untracked provider evidence is no longer repairable")?;

        let inventory_digest_string: String = row.get(3)?;
        let object_digest_string: String = row.get(6)?;
        let observed_hash_string: String = row.get(7)?;
        let byte_size = u64::try_from(row.get::<i64>(8)?)
            .context("untracked provider object size is negative")?;
        let expires_at = input.now.saturating_add(super::OCI_GC_PLAN_TTL_SECONDS);
        let confirmation_hash =
            Sha256Digest::digest(&serde_json::to_vec(&UntrackedRepairConfirmation {
                registry_id: input.registry_id,
                placement_id: input.placement_id,
                inventory_generation_id: &input.inventory_generation_id,
                inventory_digest: &inventory_digest_string,
                object_key: &input.object_key,
                object_digest: &object_digest_string,
                observed_hash: &observed_hash_string,
                byte_size,
                strong_etag: &row.get::<String>(9)?,
                repair_kind: input.repair_kind,
                adopt_media_type: input
                    .adopt_media_type
                    .as_ref()
                    .map(|value| (*value).as_str()),
                actor_id: &input.actor_id,
                captured_mutation_epoch: input.expected_mutation_epoch,
                expires_at,
            })?);
        let id = new_untracked_repair_id();
        self.backend
            .checked_batch(&[Statement::new(
                "INSERT INTO oci_untracked_repair_plans
                   (id, registry_id, placement_id, placement_name, placement_prefix,
                    placement_resource_version, placement_write_spec_version,
                    placement_observation_version, binding_id, binding_resource_version,
                    binding_write_revision, delete_credential_purpose,
                    delete_credential_generation, delete_capability_fingerprint,
                    delete_capability_resource_version, inventory_generation_id,
                    inventory_digest, inventory_observed_at, object_key, object_digest,
                    observed_hash, byte_size, strong_etag, repair_kind, adopt_media_type,
                    actor_id, plan_idempotency_key, apply_idempotency_key,
                    captured_mutation_epoch, confirmation_hash, state, worker_id,
                    claim_token, lease_expires_at, attempt_count, max_attempts,
                    next_attempt_at, response_idempotency_key, created_at, expires_at,
                    applied_at, finished_at, last_error, resource_version)
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                        ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23,
                        ?24, ?25, ?26, ?27, NULL, ?28, ?29, 'planned', NULL, NULL,
                        NULL, 0, 8, ?30, NULL, ?30, ?31, NULL, NULL, NULL, 1
                 WHERE EXISTS (SELECT 1 FROM oci_provider_inventory_heads head
                   JOIN oci_provider_inventory_entries entry
                     ON entry.generation_id = head.generation_id
                    AND entry.placement_id = head.placement_id
                   JOIN oci_registry_state registry_state
                     ON registry_state.registry_id = entry.registry_id
                   WHERE head.generation_id = ?16 AND head.placement_id = ?3
                     AND entry.registry_id = ?2 AND entry.object_key = ?19
                     AND entry.classification = 'untracked' AND entry.deleted_at IS NULL
                     AND registry_state.mutation_epoch = ?28)",
                vals![
                    id,
                    input.registry_id,
                    input.placement_id,
                    row.get::<String>(10)?,
                    row.get::<String>(11)?,
                    row.get::<i64>(12)?,
                    row.get::<i64>(13)?,
                    row.get::<i64>(14)?,
                    row.get::<i64>(15)?,
                    row.get::<i64>(16)?,
                    row.get::<i64>(17)?,
                    row.get::<Option<String>>(18)?,
                    row.get::<Option<i64>>(19)?,
                    row.get::<String>(20)?,
                    row.get::<i64>(21)?,
                    input.inventory_generation_id,
                    inventory_digest_string,
                    row.get::<i64>(4)?,
                    input.object_key,
                    object_digest_string,
                    observed_hash_string,
                    i64::try_from(byte_size)?,
                    row.get::<String>(9)?,
                    input.repair_kind.as_str(),
                    input
                        .adopt_media_type
                        .as_ref()
                        .map(|value| (*value).as_str()),
                    input.actor_id,
                    input.idempotency_key,
                    input.expected_mutation_epoch,
                    confirmation_hash.to_string(),
                    input.now,
                    expires_at
                ],
            )
            .expecting(1)])
            .await?;
        self.oci_untracked_repair_plan_for_actor(&id, &input.actor_id)
            .await?
            .context("OCI untracked repair plan disappeared after creation")
    }

    /// Looks up one reviewed repair only for its authenticated actor.
    ///
    /// # Errors
    ///
    /// Returns an error on malformed persisted data or database failure.
    pub async fn oci_untracked_repair_plan_for_actor(
        &self,
        plan_id: &str,
        actor_id: &str,
    ) -> Result<Option<OciUntrackedRepairPlanRecord>> {
        let query = format!(
            "{UNTRACKED_REPAIR_COLUMNS}
             WHERE repair.id = ?1 AND repair.actor_id = ?2"
        );
        self.backend
            .query_opt(&query, &vals![plan_id, actor_id])
            .await?
            .as_ref()
            .map(row_to_untracked_repair)
            .transpose()
    }

    /// Looks up one repair for internal provider-worker execution.
    pub(super) async fn oci_untracked_repair_plan(
        &self,
        plan_id: &str,
    ) -> Result<Option<OciUntrackedRepairPlanRecord>> {
        let query = format!("{UNTRACKED_REPAIR_COLUMNS} WHERE repair.id = ?1");
        self.backend
            .query_opt(&query, &vals![plan_id])
            .await?
            .as_ref()
            .map(row_to_untracked_repair)
            .transpose()
    }

    /// Applies one reviewed repair with actor, confirmation, CAS, and retry binding.
    ///
    /// Delete plans become durable provider work. Internal adoption is rejected
    /// until its exact quota transaction is selected explicitly by a caller.
    ///
    /// # Errors
    ///
    /// Returns an error for ownership, confirmation, expiry, epoch, inventory,
    /// version, or idempotency mismatch, or database failure.
    pub async fn apply_oci_untracked_repair(
        &self,
        input: &ApplyOciUntrackedRepair,
    ) -> Result<OciUntrackedRepairPlanRecord> {
        validate_key_bytes(&input.plan_id, "OCI repair plan id", 64)?;
        validate_key_bytes(&input.actor_id, "OCI repair actor id", 128)?;
        validate_key_bytes(&input.idempotency_key, "OCI repair apply key", 128)?;
        if input.expected_resource_version < 1 || input.now <= 0 {
            bail!("OCI untracked repair apply identity is invalid");
        }
        let current = self
            .oci_untracked_repair_plan_for_actor(&input.plan_id, &input.actor_id)
            .await?
            .context("OCI untracked repair plan does not exist for this actor")?;
        if current.state != "planned" {
            let replay_key = self
                .backend
                .query_opt(
                    "SELECT apply_idempotency_key FROM oci_untracked_repair_plans
                     WHERE id = ?1 AND actor_id = ?2",
                    &vals![input.plan_id, input.actor_id],
                )
                .await?
                .and_then(|row| row.get::<Option<String>>(0).ok())
                .flatten();
            if replay_key.as_deref() == Some(input.idempotency_key.as_str()) {
                return Ok(current);
            }
            bail!("OCI untracked repair apply idempotency conflict");
        }
        if current.repair_kind == OciUntrackedRepairKind::Adopt {
            bail!("OCI untracked adoption requires the internal quota-authority path");
        }
        self.backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE oci_untracked_repair_plans
                 SET state = 'pending', apply_idempotency_key = ?4, applied_at = ?7,
                     next_attempt_at = ?7, resource_version = resource_version + 1
                 WHERE id = ?1 AND actor_id = ?2 AND state = 'planned'
                   AND resource_version = ?3 AND confirmation_hash = ?5
                   AND expires_at > ?7 AND captured_mutation_epoch = ?6
                   AND EXISTS (SELECT 1 FROM oci_registry_state registry_state
                     WHERE registry_state.registry_id = oci_untracked_repair_plans.registry_id
                       AND registry_state.mutation_epoch = ?6)
                   AND EXISTS (SELECT 1 FROM oci_provider_inventory_heads head
                     JOIN oci_provider_inventory_entries entry
                       ON entry.generation_id = head.generation_id
                      AND entry.placement_id = head.placement_id
                     WHERE head.generation_id =
                             oci_untracked_repair_plans.inventory_generation_id
                       AND head.placement_id = oci_untracked_repair_plans.placement_id
                       AND entry.object_key = oci_untracked_repair_plans.object_key
                       AND entry.classification = 'untracked' AND entry.deleted_at IS NULL)
                   AND EXISTS (SELECT 1 FROM surface_placements placement
                     JOIN surface_placement_observations observation
                       ON observation.placement_id = placement.id
                     JOIN bindings binding ON binding.id = placement.binding_id
                     JOIN oci_conditional_delete_capabilities capability
                       ON capability.binding_id = binding.id
                      AND capability.binding_write_revision =
                        oci_untracked_repair_plans.binding_write_revision
                     LEFT JOIN binding_credential_revisions credential
                       ON credential.binding_id = binding.id
                      AND credential.purpose =
                        oci_untracked_repair_plans.delete_credential_purpose
                      AND credential.generation =
                        oci_untracked_repair_plans.delete_credential_generation
                     LEFT JOIN binding_credential_heads credential_head
                       ON credential_head.binding_id = credential.binding_id
                      AND credential_head.purpose = credential.purpose
                     WHERE placement.id = oci_untracked_repair_plans.placement_id
                       AND placement.registry_id = oci_untracked_repair_plans.registry_id
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
                       AND binding.id = oci_untracked_repair_plans.binding_id
                       AND binding.resource_version =
                         oci_untracked_repair_plans.binding_resource_version
                       AND capability.resource_version =
                         oci_untracked_repair_plans.delete_capability_resource_version
                       AND capability.capability_fingerprint =
                         oci_untracked_repair_plans.delete_capability_fingerprint
                       AND capability.state = 'valid'
                       AND ((oci_untracked_repair_plans.delete_credential_purpose IS NULL
                             AND oci_untracked_repair_plans.delete_credential_generation IS NULL
                             AND binding.kind = 'local_fs')
                         OR (credential.validation_state = 'valid'
                           AND credential_head.current_generation =
                             oci_untracked_repair_plans.delete_credential_generation)))",
                    vals![
                        input.plan_id,
                        input.actor_id,
                        input.expected_resource_version,
                        input.idempotency_key,
                        input.confirmation_hash.to_string(),
                        current.captured_mutation_epoch,
                        input.now
                    ],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO oci_untracked_repair_credential_holds
                       (plan_id, binding_id, purpose, generation)
                     SELECT id, binding_id, delete_credential_purpose,
                            delete_credential_generation
                     FROM oci_untracked_repair_plans
                     WHERE id = ?1 AND actor_id = ?2 AND state = 'pending'
                       AND apply_idempotency_key = ?3
                       AND delete_credential_purpose IS NOT NULL
                     ON CONFLICT(plan_id, binding_id, purpose, generation) DO NOTHING",
                    vals![input.plan_id, input.actor_id, input.idempotency_key],
                )
                .unchecked(),
                Statement::new(
                    "UPDATE oci_untracked_repair_plans
                     SET resource_version = resource_version
                     WHERE id = ?1 AND actor_id = ?2 AND state = 'pending'
                       AND apply_idempotency_key = ?3
                       AND ((delete_credential_purpose IS NULL
                             AND delete_credential_generation IS NULL)
                         OR EXISTS (SELECT 1 FROM oci_untracked_repair_credential_holds hold
                           WHERE hold.plan_id = oci_untracked_repair_plans.id
                             AND hold.binding_id = oci_untracked_repair_plans.binding_id
                             AND hold.purpose =
                               oci_untracked_repair_plans.delete_credential_purpose
                             AND hold.generation =
                               oci_untracked_repair_plans.delete_credential_generation))",
                    vals![input.plan_id, input.actor_id, input.idempotency_key],
                )
                .expecting(1),
            ])
            .await?;
        self.oci_untracked_repair_plan_for_actor(&input.plan_id, &input.actor_id)
            .await?
            .context("OCI untracked repair plan disappeared after apply")
    }
}

/// Returns a fresh random reviewed-plan identity.
pub(super) fn new_untracked_repair_id() -> String {
    Uuid::new_v4().simple().to_string()
}

const UNTRACKED_REPAIR_COLUMNS: &str = "SELECT repair.id, repair.registry_id, repair.placement_id,
            repair.placement_name, repair.placement_prefix,
            repair.placement_resource_version, repair.placement_write_spec_version,
            repair.placement_observation_version, repair.binding_id,
            repair.binding_resource_version, repair.binding_write_revision,
            repair.delete_credential_purpose, repair.delete_credential_generation,
            repair.delete_capability_fingerprint,
            repair.delete_capability_resource_version,
            repair.inventory_generation_id, repair.inventory_digest,
            repair.inventory_observed_at, repair.object_key, repair.object_digest,
            repair.observed_hash, repair.byte_size, repair.strong_etag,
            repair.repair_kind, repair.adopt_media_type, repair.actor_id,
            repair.captured_mutation_epoch, repair.confirmation_hash, repair.state,
            repair.expires_at, repair.created_at, repair.applied_at,
            repair.finished_at, repair.last_error, repair.resource_version,
            evidence.outcome, evidence.provider_request_id,
            evidence.conditional_etag, evidence.evidence_digest,
            evidence.confirmed_at
     FROM oci_untracked_repair_plans repair
     LEFT JOIN oci_untracked_repair_evidence evidence ON evidence.plan_id = repair.id";

fn row_to_untracked_repair(row: &crate::value::Row) -> Result<OciUntrackedRepairPlanRecord> {
    let repair_kind = match row.get::<String>(23)?.as_str() {
        "delete" => OciUntrackedRepairKind::Delete,
        "adopt" => OciUntrackedRepairKind::Adopt,
        _ => bail!("persisted OCI untracked repair kind is invalid"),
    };
    let outcome = match row.get::<Option<String>>(35)?.as_deref() {
        Some("deleted") => Some(OciUntrackedRepairOutcome::Deleted),
        Some("already_absent") => Some(OciUntrackedRepairOutcome::AlreadyAbsent),
        Some("adopted") => Some(OciUntrackedRepairOutcome::Adopted),
        Some(_) => bail!("persisted OCI untracked repair outcome is invalid"),
        None => None,
    };
    Ok(OciUntrackedRepairPlanRecord {
        id: row.get(0)?,
        registry_id: row.get(1)?,
        placement_id: row.get(2)?,
        placement_name: row.get(3)?,
        placement_prefix: row.get(4)?,
        placement_resource_version: row.get(5)?,
        placement_write_spec_version: row.get(6)?,
        placement_observation_version: row.get(7)?,
        binding_id: row.get(8)?,
        binding_resource_version: row.get(9)?,
        binding_write_revision: row.get(10)?,
        delete_credential_purpose: row.get(11)?,
        delete_credential_generation: row.get(12)?,
        delete_capability_fingerprint: row.get(13)?,
        delete_capability_resource_version: row.get(14)?,
        inventory_generation_id: row.get(15)?,
        inventory_digest: Sha256Digest::parse(&row.get::<String>(16)?)?,
        inventory_observed_at: row.get(17)?,
        object_key: row.get(18)?,
        object_digest: Sha256Digest::parse(&row.get::<String>(19)?)?,
        observed_hash: Sha256Digest::parse(&row.get::<String>(20)?)?,
        byte_size: u64::try_from(row.get::<i64>(21)?)
            .context("persisted OCI untracked repair size is negative")?,
        strong_etag: row.get(22)?,
        repair_kind,
        adopt_media_type: row
            .get::<Option<String>>(24)?
            .map(|value| MediaType::parse(&value))
            .transpose()?,
        actor_id: row.get(25)?,
        captured_mutation_epoch: row.get(26)?,
        confirmation_hash: Sha256Digest::parse(&row.get::<String>(27)?)?,
        state: row.get(28)?,
        expires_at: row.get(29)?,
        created_at: row.get(30)?,
        applied_at: row.get(31)?,
        finished_at: row.get(32)?,
        last_error: row.get(33)?,
        outcome,
        provider_request_id: row.get(36)?,
        conditional_etag: row.get(37)?,
        evidence_digest: row
            .get::<Option<String>>(38)?
            .map(|value| Sha256Digest::parse(&value))
            .transpose()?,
        confirmed_at: row.get(39)?,
        resource_version: row.get(34)?,
    })
}
