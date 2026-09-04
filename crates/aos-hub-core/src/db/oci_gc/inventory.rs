//! Exact provider inventory and conditional-delete capability persistence.

use anyhow::{bail, Context, Result};
use aos_oci_types::Sha256Digest;
use serde::Serialize;
use uuid::Uuid;

use super::inventory_model::{
    inventory_entry_statements, validate_capability_input, validate_inventory_page,
};
use super::OCI_GC_MAX_INVENTORY_OBJECTS;
use crate::backend::Statement;
use crate::db::{validate_key_bytes, Database};

/// Observed conditional-delete capability for one immutable binding revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciConditionalDeleteCapabilityRecord {
    /// Binding database id.
    pub binding_id: i64,
    /// Immutable write revision used for exact provider access.
    pub binding_write_revision: i64,
    /// Binding optimistic-concurrency version observed with the capability.
    pub binding_resource_version: i64,
    /// Exact delete credential purpose, absent for credential-free local IO.
    pub delete_credential_purpose: Option<String>,
    /// Exact delete credential generation, absent for credential-free local IO.
    pub delete_credential_generation: Option<i64>,
    /// Controller-derived immutable capability fingerprint.
    pub capability_fingerprint: String,
    /// `valid` or `invalid`.
    pub state: String,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
    /// Observation time in Unix seconds.
    pub observed_at: i64,
}

/// Input for recording an exact conditional-delete capability observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordOciConditionalDeleteCapability {
    /// Binding database id.
    pub binding_id: i64,
    /// Immutable write revision tested by the controller.
    pub binding_write_revision: i64,
    /// Exact binding version tested by the controller.
    pub binding_resource_version: i64,
    /// Delete credential purpose, absent for local filesystem deletion.
    pub delete_credential_purpose: Option<String>,
    /// Delete credential generation, absent for local filesystem deletion.
    pub delete_credential_generation: Option<i64>,
    /// Canonical capability fingerprint.
    pub capability_fingerprint: String,
    /// `valid` only when conditional deletion was positively observed.
    pub state: String,
    /// Expected prior record version, or `None` for first observation.
    pub expected_resource_version: Option<i64>,
    /// Observation time in Unix seconds.
    pub observed_at: i64,
}

/// Durable provider inventory generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciProviderInventoryGenerationRecord {
    /// Stable generation id.
    pub id: String,
    /// Owning registry id.
    pub registry_id: i64,
    /// Enumerated placement id.
    pub placement_id: i64,
    /// Stable controller identity.
    pub collector_id: String,
    /// Opaque current collector lease receipt.
    pub collector_claim_token: String,
    /// Current collector lease expiry for active generations.
    pub collector_lease_expires_at: Option<i64>,
    /// Caller retry identity for beginning exactly one enumeration.
    pub idempotency_key: String,
    /// Registry mutation epoch frozen before provider enumeration.
    pub captured_mutation_epoch: i64,
    /// Exact purge-fence version active when enumeration began, when any.
    pub purge_fence_resource_version: Option<i64>,
    /// Frozen placement resource version.
    pub placement_resource_version: i64,
    /// Frozen placement write-spec version.
    pub placement_write_spec_version: i64,
    /// Frozen ready/complete observation version.
    pub placement_observation_version: i64,
    /// Frozen binding id.
    pub binding_id: i64,
    /// Frozen binding resource version.
    pub binding_resource_version: i64,
    /// Frozen binding write revision.
    pub binding_write_revision: i64,
    /// `collecting`, `sealing`, `complete`, or `failed`.
    pub state: String,
    /// Canonical sorted provider inventory digest, once complete.
    pub inventory_digest: Option<Sha256Digest>,
    /// Enumerated canonical OCI object count.
    pub object_count: u64,
    /// Enumerated byte count.
    pub byte_count: u64,
    /// Enumerated keys with no catalog identity.
    pub untracked_object_count: u64,
    /// Number of provider listing pages durably committed.
    pub checkpoint_ordinal: u64,
    /// Opaque provider cursor for the next page, when another page remains.
    pub provider_cursor: Option<String>,
    /// Greatest provider key covered by the committed listing prefix.
    pub checkpoint_last_key: Option<String>,
    /// Chained digest binding every committed page checkpoint.
    pub checkpoint_digest: Option<Sha256Digest>,
    /// Number of expired collector leases taken over by another receipt.
    pub takeover_count: u64,
    /// Collection start time.
    pub started_at: i64,
    /// Provider observation time, once complete.
    pub observed_at: Option<i64>,
    /// Completion time, once terminal.
    pub completed_at: Option<i64>,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
}

/// Input for beginning one provider enumeration generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginOciProviderInventory {
    /// Owning registry id.
    pub registry_id: i64,
    /// Placement to enumerate.
    pub placement_id: i64,
    /// Expected placement resource version.
    pub expected_placement_resource_version: i64,
    /// Expected ready/complete observation version.
    pub expected_placement_observation_version: i64,
    /// Stable inventory controller identity.
    pub collector_id: String,
    /// Opaque initial collector lease receipt.
    pub collector_claim_token: String,
    /// Initial collector lease duration in seconds.
    pub collector_lease_seconds: i64,
    /// Stable retry identity for response-loss replay.
    pub idempotency_key: String,
    /// Collection start time in Unix seconds.
    pub now: i64,
}

/// One canonical OCI object returned by a complete provider enumeration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OciProviderInventoryEntryInput {
    /// Canonical `oci/blobs/sha256/...` object key.
    pub object_key: String,
    /// Digest encoded by the object key.
    pub object_digest: Sha256Digest,
    /// SHA-256 observed from the exact provider bytes.
    pub observed_hash: Sha256Digest,
    /// Exact provider byte length.
    pub byte_size: u64,
    /// Strong provider entity tag used by conditional deletion.
    pub strong_etag: String,
}

/// One lease-fenced provider listing page and its durable continuation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendOciProviderInventoryPage {
    /// Inventory generation id.
    pub generation_id: String,
    /// Current collector identity.
    pub collector_id: String,
    /// Exact current collector lease receipt.
    pub collector_claim_token: String,
    /// Checkpoint ordinal observed before listing this page.
    pub expected_checkpoint_ordinal: u64,
    /// Provider cursor used to fetch this page.
    pub expected_provider_cursor: Option<String>,
    /// Provider cursor for the next page, or `None` after the terminal page.
    pub next_provider_cursor: Option<String>,
    /// Greatest provider key covered by this page, including non-OCI keys.
    pub last_listed_key: Option<String>,
    /// Canonical OCI objects contained in this provider page.
    pub entries: Vec<OciProviderInventoryEntryInput>,
    /// Checkpoint time in Unix seconds.
    pub now: i64,
    /// Renewed collector lease duration in seconds.
    pub lease_seconds: i64,
}

/// Input sealing a complete provider enumeration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteOciProviderInventory {
    /// Inventory generation id.
    pub generation_id: String,
    /// Exact controller identity that began the generation.
    pub collector_id: String,
    /// Exact current collector lease receipt.
    pub collector_claim_token: String,
    /// Last durable listing-page ordinal observed by the collector.
    pub expected_checkpoint_ordinal: u64,
    /// Time the complete enumeration was observed.
    pub observed_at: i64,
    /// Persistence completion time.
    pub now: i64,
}

/// One registry placement whose exact provider inventory is due.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciProviderInventoryPlacement {
    /// Owning registry id.
    pub registry_id: i64,
    /// Placement id.
    pub placement_id: i64,
    /// Stable placement name.
    pub placement_name: String,
    /// Current placement optimistic-concurrency version.
    pub placement_resource_version: i64,
    /// Current placement writer-spec version.
    pub placement_write_spec_version: i64,
    /// Current ready/complete observation version.
    pub placement_observation_version: i64,
    /// Current binding id.
    pub binding_id: i64,
    /// Current binding resource version.
    pub binding_resource_version: i64,
    /// Current immutable writer revision.
    pub binding_write_revision: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PersistedInventoryDigestEntry {
    object_key: String,
    object_digest: String,
    observed_hash: String,
    byte_size: u64,
    strong_etag: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalInventoryPage<'a> {
    expected_checkpoint_ordinal: u64,
    expected_provider_cursor: Option<&'a str>,
    next_provider_cursor: Option<&'a str>,
    last_listed_key: Option<&'a str>,
    entries: &'a [OciProviderInventoryEntryInput],
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChainedInventoryCheckpoint<'a> {
    previous_digest: Option<&'a str>,
    page_digest: &'a str,
}

impl Database {
    /// Lists ready registry placements whose current delete capability is due.
    ///
    /// At most one deterministic placement is returned for each exact binding
    /// writer revision, because the capability is shared by that immutable
    /// access identity rather than by placement.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid time/limit, malformed persisted data, or
    /// database failure.
    pub async fn list_due_oci_conditional_delete_placements(
        &self,
        now: i64,
        limit: u32,
    ) -> Result<Vec<OciProviderInventoryPlacement>> {
        if now < 0 || limit == 0 || limit > 100 {
            bail!("OCI conditional-delete due selector is invalid");
        }
        let oldest = now.saturating_sub(super::OCI_GC_MAX_INVENTORY_AGE_SECONDS);
        self.backend
            .query(
                "SELECT placement.registry_id, placement.id, placement.name,
                        placement.resource_version, placement.write_spec_version,
                        observation.observation_version, placement.binding_id,
                        binding.resource_version, write_state.current_write_revision
                 FROM surface_placements placement
                 JOIN surface_placement_observations observation
                   ON observation.placement_id = placement.id
                 JOIN bindings binding ON binding.id = placement.binding_id
                 JOIN binding_write_state write_state
                   ON write_state.binding_id = binding.id
                 WHERE placement.registry_id IS NOT NULL
                   AND placement.desired_state <> 'offline'
                   AND observation.state = 'ready'
                   AND observation.completeness = 'complete'
                   AND write_state.current_write_revision IS NOT NULL
                   AND placement.id = (SELECT MIN(candidate.id)
                     FROM surface_placements candidate
                     JOIN surface_placement_observations candidate_observation
                       ON candidate_observation.placement_id = candidate.id
                     WHERE candidate.binding_id = placement.binding_id
                       AND candidate.registry_id IS NOT NULL
                       AND candidate.desired_state <> 'offline'
                       AND candidate_observation.state = 'ready'
                       AND candidate_observation.completeness = 'complete')
                   AND NOT EXISTS (SELECT 1
                     FROM oci_conditional_delete_capabilities capability
                     WHERE capability.binding_id = placement.binding_id
                       AND capability.binding_write_revision =
                         write_state.current_write_revision
                       AND capability.binding_resource_version =
                         binding.resource_version
                       AND ((capability.delete_credential_purpose IS NULL
                            AND capability.delete_credential_generation IS NULL)
                         OR EXISTS (SELECT 1 FROM binding_credential_heads head
                           WHERE head.binding_id = capability.binding_id
                             AND head.purpose = capability.delete_credential_purpose
                             AND head.current_generation =
                               capability.delete_credential_generation))
                       AND capability.observed_at >= ?1)
                 ORDER BY placement.binding_id, write_state.current_write_revision,
                          placement.id LIMIT ?2",
                &vals![oldest, i64::from(limit)],
            )
            .await?
            .iter()
            .map(|row| {
                Ok(OciProviderInventoryPlacement {
                    registry_id: row.get(0)?,
                    placement_id: row.get(1)?,
                    placement_name: row.get(2)?,
                    placement_resource_version: row.get(3)?,
                    placement_write_spec_version: row.get(4)?,
                    placement_observation_version: row.get(5)?,
                    binding_id: row.get(6)?,
                    binding_resource_version: row.get(7)?,
                    binding_write_revision: row.get(8)?,
                })
            })
            .collect()
    }

    /// Lists a bounded set of registry placements whose exact inventory is due.
    ///
    /// Active collecting/sealing generations are excluded and discoverable via
    /// [`Database::active_oci_provider_inventory`] for lease recovery.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid time/limit, malformed persisted data, or
    /// database failure.
    pub async fn list_due_oci_provider_inventory_placements(
        &self,
        now: i64,
        limit: u32,
    ) -> Result<Vec<OciProviderInventoryPlacement>> {
        if now < 0 || limit == 0 || limit > 100 {
            bail!("OCI provider inventory due selector is invalid");
        }
        let oldest = now.saturating_sub(super::OCI_GC_MAX_INVENTORY_AGE_SECONDS);
        self.backend
            .query(
                "SELECT placement.registry_id, placement.id, placement.name,
                        placement.resource_version, placement.write_spec_version,
                        observation.observation_version, placement.binding_id,
                        binding.resource_version, write_state.current_write_revision
                 FROM surface_placements placement
                 JOIN surface_placement_observations observation
                   ON observation.placement_id = placement.id
                 JOIN bindings binding ON binding.id = placement.binding_id
                 JOIN binding_write_state write_state
                   ON write_state.binding_id = binding.id
                 JOIN oci_registry_state registry_state
                   ON registry_state.registry_id = placement.registry_id
                 WHERE placement.registry_id IS NOT NULL
                   AND placement.desired_state <> 'offline'
                   AND observation.state = 'ready'
                   AND observation.completeness = 'complete'
                   AND write_state.current_write_revision IS NOT NULL
                   AND NOT EXISTS (SELECT 1
                     FROM oci_provider_inventory_generations active
                     WHERE active.placement_id = placement.id
                       AND active.state IN('collecting', 'sealing'))
                   AND NOT EXISTS (SELECT 1 FROM oci_provider_inventory_heads head
                     JOIN oci_provider_inventory_generations inventory
                       ON inventory.id = head.generation_id
                     WHERE head.placement_id = placement.id
                       AND inventory.state = 'complete'
                       AND inventory.observed_at >= ?1
                       AND inventory.captured_mutation_epoch = registry_state.mutation_epoch
                       AND inventory.placement_resource_version = placement.resource_version
                       AND inventory.placement_write_spec_version =
                         placement.write_spec_version
                       AND inventory.placement_observation_version =
                         observation.observation_version
                       AND inventory.binding_resource_version = binding.resource_version
                       AND inventory.binding_write_revision =
                         write_state.current_write_revision
                       AND NOT EXISTS (SELECT 1 FROM oci_provider_inventory_entries repaired
                         WHERE repaired.generation_id = inventory.id
                           AND repaired.deleted_at IS NOT NULL)
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
                                    AND failed.started_at > inventory.started_at))))
                 ORDER BY placement.registry_id, placement.name, placement.id
                 LIMIT ?2",
                &vals![oldest, i64::from(limit)],
            )
            .await?
            .iter()
            .map(|row| {
                Ok(OciProviderInventoryPlacement {
                    registry_id: row.get(0)?,
                    placement_id: row.get(1)?,
                    placement_name: row.get(2)?,
                    placement_resource_version: row.get(3)?,
                    placement_write_spec_version: row.get(4)?,
                    placement_observation_version: row.get(5)?,
                    binding_id: row.get(6)?,
                    binding_resource_version: row.get(7)?,
                    binding_write_revision: row.get(8)?,
                })
            })
            .collect()
    }

    /// Lists expired active inventory generations eligible for lease takeover.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid time/limit, malformed persisted data, or
    /// database failure.
    pub async fn list_recoverable_oci_provider_inventories(
        &self,
        now: i64,
        limit: u32,
    ) -> Result<Vec<OciProviderInventoryGenerationRecord>> {
        if now < 0 || limit == 0 || limit > 100 {
            bail!("OCI provider inventory recovery selector is invalid");
        }
        self.backend
            .query(
                "SELECT id, registry_id, placement_id, collector_id,
                        collector_claim_token, collector_lease_expires_at,
                        idempotency_key, captured_mutation_epoch,
                        placement_resource_version, placement_write_spec_version,
                        placement_observation_version, binding_id,
                        binding_resource_version, binding_write_revision, state,
                        inventory_digest, object_count, byte_count,
                        untracked_object_count, checkpoint_ordinal,
                        provider_cursor, checkpoint_last_key, checkpoint_digest,
                        takeover_count,
                        started_at, observed_at,
                        completed_at, resource_version,
                        purge_fence_resource_version
                 FROM oci_provider_inventory_generations
                 WHERE state IN('collecting', 'sealing')
                   AND collector_lease_expires_at <= ?1
                 ORDER BY collector_lease_expires_at, id LIMIT ?2",
                &vals![now, i64::from(limit)],
            )
            .await?
            .iter()
            .map(row_to_inventory_generation)
            .collect()
    }

    /// Records a controller-observed exact conditional-delete capability.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identity, a stale expected version,
    /// mismatched binding/credential identity, or database failure.
    pub async fn record_oci_conditional_delete_capability(
        &self,
        input: &RecordOciConditionalDeleteCapability,
    ) -> Result<OciConditionalDeleteCapabilityRecord> {
        validate_capability_input(input)?;
        let statement = if let Some(expected) = input.expected_resource_version {
            Statement::new(
                "UPDATE oci_conditional_delete_capabilities
                 SET binding_resource_version = ?3,
                     delete_credential_purpose = ?4,
                     delete_credential_generation = ?5,
                     capability_fingerprint = ?6, state = ?7,
                     resource_version = resource_version + 1, observed_at = ?8
                 WHERE binding_id = ?1 AND binding_write_revision = ?2
                   AND resource_version = ?9
                   AND EXISTS (SELECT 1 FROM bindings binding
                     WHERE binding.id = ?1 AND binding.resource_version = ?3)
                   AND EXISTS (SELECT 1 FROM binding_write_revisions revision
                     WHERE revision.binding_id = ?1 AND revision.revision = ?2)
                   AND (?7 = 'invalid'
                     OR (?4 IS NULL AND ?5 IS NULL
                       AND EXISTS (SELECT 1 FROM bindings local_binding
                         WHERE local_binding.id = ?1
                           AND local_binding.kind = 'local_fs'))
                     OR EXISTS (SELECT 1 FROM binding_credential_heads head
                       JOIN binding_credential_revisions credential
                         ON credential.binding_id = head.binding_id
                        AND credential.purpose = head.purpose
                        AND credential.generation = head.current_generation
                       WHERE head.binding_id = ?1 AND head.purpose = ?4
                         AND head.current_generation = ?5
                         AND credential.validation_state = 'valid'))",
                vals![
                    input.binding_id,
                    input.binding_write_revision,
                    input.binding_resource_version,
                    input.delete_credential_purpose,
                    input.delete_credential_generation,
                    input.capability_fingerprint,
                    input.state,
                    input.observed_at,
                    expected
                ],
            )
            .expecting(1)
        } else {
            Statement::new(
                "INSERT INTO oci_conditional_delete_capabilities
                   (binding_id, binding_write_revision, binding_resource_version,
                    delete_credential_purpose, delete_credential_generation,
                    capability_fingerprint, state, resource_version, observed_at)
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8
                 FROM bindings binding JOIN binding_write_revisions revision
                   ON revision.binding_id = binding.id
                  AND revision.revision = ?2
                 WHERE binding.id = ?1 AND binding.resource_version = ?3
                   AND (?7 = 'invalid'
                     OR (?4 IS NULL AND ?5 IS NULL AND binding.kind = 'local_fs')
                     OR EXISTS (SELECT 1 FROM binding_credential_heads head
                       JOIN binding_credential_revisions credential
                         ON credential.binding_id = head.binding_id
                        AND credential.purpose = head.purpose
                        AND credential.generation = head.current_generation
                       WHERE head.binding_id = ?1 AND head.purpose = ?4
                         AND head.current_generation = ?5
                         AND credential.validation_state = 'valid'))
                   AND NOT EXISTS (SELECT 1
                     FROM oci_conditional_delete_capabilities capability
                     WHERE capability.binding_id = ?1
                       AND capability.binding_write_revision = ?2)",
                vals![
                    input.binding_id,
                    input.binding_write_revision,
                    input.binding_resource_version,
                    input.delete_credential_purpose,
                    input.delete_credential_generation,
                    input.capability_fingerprint,
                    input.state,
                    input.observed_at
                ],
            )
            .expecting(1)
        };
        self.backend.checked_batch(&[statement]).await?;
        self.oci_conditional_delete_capability(input.binding_id, input.binding_write_revision)
            .await?
            .context("conditional-delete capability disappeared after persistence")
    }

    /// Returns one exact conditional-delete capability observation.
    ///
    /// # Errors
    ///
    /// Returns an error on malformed persisted data or database failure.
    pub async fn oci_conditional_delete_capability(
        &self,
        binding_id: i64,
        binding_write_revision: i64,
    ) -> Result<Option<OciConditionalDeleteCapabilityRecord>> {
        self.backend
            .query_opt(
                "SELECT binding_id, binding_write_revision,
                        binding_resource_version, delete_credential_purpose,
                        delete_credential_generation, capability_fingerprint,
                        state, resource_version, observed_at
                 FROM oci_conditional_delete_capabilities
                 WHERE binding_id = ?1 AND binding_write_revision = ?2",
                &vals![binding_id, binding_write_revision],
            )
            .await?
            .as_ref()
            .map(row_to_capability)
            .transpose()
    }

    /// Begins a provider-enumerated inventory under exact registry/topology fences.
    ///
    /// # Errors
    ///
    /// Returns an error when the placement is not ready and complete, a
    /// topology/epoch fence is stale, identity is invalid, or persistence fails.
    pub async fn begin_oci_provider_inventory(
        &self,
        input: &BeginOciProviderInventory,
    ) -> Result<OciProviderInventoryGenerationRecord> {
        validate_key_bytes(&input.collector_id, "OCI inventory collector id", 128)?;
        validate_key_bytes(
            &input.idempotency_key,
            "OCI inventory begin idempotency key",
            128,
        )?;
        validate_key_bytes(
            &input.collector_claim_token,
            "OCI inventory collector claim token",
            64,
        )?;
        if input.registry_id <= 0
            || input.placement_id <= 0
            || input.expected_placement_resource_version <= 0
            || input.expected_placement_observation_version <= 0
            || !(1..=3_600).contains(&input.collector_lease_seconds)
            || input.now < 0
        {
            bail!("OCI provider inventory has an invalid fence or time");
        }
        let collector_lease_expires_at = input.now.saturating_add(input.collector_lease_seconds);
        if let Some(existing) = self.oci_provider_inventory_generation_by_key(input).await? {
            return Ok(existing);
        }
        let id = format!("ociinv-{}", Uuid::new_v4().simple());
        let persisted = self
            .backend
            .checked_batch(&[
                Statement::new(
                    "INSERT INTO oci_registry_state
                       (registry_id, mutation_epoch, charged_bytes,
                        charged_objects, updated_at)
                     SELECT ?1, 0, 0, 0, ?9 FROM registries WHERE id = ?1
                     ON CONFLICT(registry_id) DO NOTHING",
                    vals![
                        input.registry_id,
                        input.placement_id,
                        input.expected_placement_resource_version,
                        input.expected_placement_observation_version,
                        input.collector_id,
                        input.idempotency_key,
                        input.collector_claim_token,
                        collector_lease_expires_at,
                        input.now
                    ],
                )
                .unchecked(),
                Statement::new(
                    "INSERT INTO oci_provider_inventory_generations
                       (id, registry_id, placement_id, collector_id,
                        collector_claim_token, collector_lease_expires_at,
                        idempotency_key, source_kind,
                        captured_mutation_epoch, purge_fence_resource_version,
                        placement_resource_version,
                        placement_write_spec_version,
                        placement_observation_version, binding_id,
                        binding_resource_version, binding_write_revision, state,
                        active_slot,
                        inventory_digest, object_count, byte_count,
                        untracked_object_count, checkpoint_ordinal,
                        provider_cursor, checkpoint_last_key, checkpoint_digest,
                        checkpoint_page_digest, started_at, observed_at,
                        completed_at, last_error, resource_version)
                     SELECT ?1, placement.registry_id, placement.id, ?6, ?8, ?9, ?7,
                            'provider_enumeration_v1', registry_state.mutation_epoch,
                            (SELECT resource_version FROM oci_registry_purge_fences purge
                              WHERE purge.registry_id = placement.registry_id
                                AND purge.state = 'collecting'),
                            placement.resource_version, placement.write_spec_version,
                            observation.observation_version, placement.binding_id,
                            binding.resource_version, write_state.current_write_revision,
                            'collecting', 1, NULL, 0, 0, 0, 0,
                            NULL, NULL, NULL, NULL, ?10, NULL, NULL, NULL, 1
                     FROM surface_placements placement
                     JOIN surface_placement_observations observation
                       ON observation.placement_id = placement.id
                     JOIN bindings binding ON binding.id = placement.binding_id
                     JOIN binding_write_state write_state
                       ON write_state.binding_id = binding.id
                     JOIN oci_registry_state registry_state
                       ON registry_state.registry_id = placement.registry_id
                     WHERE placement.id = ?3 AND placement.registry_id = ?2
                       AND placement.resource_version = ?4
                       AND placement.desired_state <> 'offline'
                       AND observation.observation_version = ?5
                       AND observation.state = 'ready'
                       AND observation.completeness = 'complete'
                       AND write_state.current_write_revision IS NOT NULL",
                    vals![
                        id,
                        input.registry_id,
                        input.placement_id,
                        input.expected_placement_resource_version,
                        input.expected_placement_observation_version,
                        input.collector_id,
                        input.idempotency_key,
                        input.collector_claim_token,
                        collector_lease_expires_at,
                        input.now
                    ],
                )
                .expecting(1),
            ])
            .await;
        if let Err(error) = persisted {
            if let Some(existing) = self.oci_provider_inventory_generation_by_key(input).await? {
                return Ok(existing);
            }
            return Err(error);
        }
        self.oci_provider_inventory_generation(&id)
            .await?
            .context("OCI provider inventory disappeared after begin")
    }

    /// Atomically appends one provider page and advances its durable checkpoint.
    ///
    /// A committed page may be replayed exactly after response loss. A new
    /// collector may resume from the returned cursor only after acquiring the
    /// expired generation lease with [`Database::claim_oci_provider_inventory`].
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized, unordered, malformed, conflicting,
    /// or stale page, an expired collector lease, or database failure.
    pub async fn append_oci_provider_inventory_page(
        &self,
        input: &AppendOciProviderInventoryPage,
    ) -> Result<OciProviderInventoryGenerationRecord> {
        validate_inventory_page(input)?;
        let current = self
            .oci_provider_inventory_generation(&input.generation_id)
            .await?
            .context("OCI provider inventory does not exist")?;
        let page_digest = Sha256Digest::digest(&serde_json::to_vec(&CanonicalInventoryPage {
            expected_checkpoint_ordinal: input.expected_checkpoint_ordinal,
            expected_provider_cursor: input.expected_provider_cursor.as_deref(),
            next_provider_cursor: input.next_provider_cursor.as_deref(),
            last_listed_key: input.last_listed_key.as_deref(),
            entries: &input.entries,
        })?);
        if current.checkpoint_ordinal == input.expected_checkpoint_ordinal.saturating_add(1) {
            let replay = self
                .backend
                .query_opt(
                    "SELECT checkpoint_page_digest
                     FROM oci_provider_inventory_generations WHERE id = ?1",
                    &vals![input.generation_id],
                )
                .await?
                .context("OCI provider inventory disappeared during page replay")?;
            if replay.get::<Option<String>>(0)?.as_deref() == Some(&page_digest.to_string()) {
                return Ok(current);
            }
            bail!("OCI provider inventory page replay conflicts");
        }
        if current.state != "collecting"
            || current.collector_id != input.collector_id
            || current.collector_claim_token != input.collector_claim_token
            || current.checkpoint_ordinal != input.expected_checkpoint_ordinal
            || current.provider_cursor != input.expected_provider_cursor
        {
            bail!("OCI provider inventory page checkpoint is stale");
        }
        if current.checkpoint_last_key.as_deref().is_some_and(|last| {
            input
                .last_listed_key
                .as_deref()
                .is_none_or(|next| next <= last)
        }) {
            bail!("OCI provider inventory page does not advance ordered listing progress");
        }

        let page_bytes = input.entries.iter().try_fold(0_u64, |total, entry| {
            total
                .checked_add(entry.byte_size)
                .context("OCI provider inventory checkpoint bytes overflowed")
        })?;
        let checkpoint_ordinal = input
            .expected_checkpoint_ordinal
            .checked_add(1)
            .context("OCI provider inventory checkpoint ordinal overflowed")?;
        let previous_digest = current.checkpoint_digest.map(|digest| digest.to_string());
        let page_digest_string = page_digest.to_string();
        let checkpoint_digest =
            Sha256Digest::digest(&serde_json::to_vec(&ChainedInventoryCheckpoint {
                previous_digest: previous_digest.as_deref(),
                page_digest: &page_digest_string,
            })?);
        let lease_expires_at = input.now.saturating_add(input.lease_seconds);
        let mut statements = inventory_entry_statements(
            &input.generation_id,
            &input.collector_id,
            &input.collector_claim_token,
            input.now,
            &input.entries,
        )?;
        statements.push(
            Statement::new(
                "UPDATE oci_provider_inventory_generations
                 SET checkpoint_ordinal = ?5, provider_cursor = ?6,
                     checkpoint_last_key = ?7, checkpoint_digest = ?8,
                     checkpoint_page_digest = ?9,
                     object_count = object_count + ?10,
                     byte_count = byte_count + ?11,
                     collector_lease_expires_at = ?12,
                     resource_version = resource_version + 1
                 WHERE id = ?1 AND collector_id = ?2
                   AND collector_claim_token = ?3
                   AND collector_lease_expires_at > ?4 AND state = 'collecting'
                   AND checkpoint_ordinal = ?13
                   AND (provider_cursor = ?14
                     OR (provider_cursor IS NULL AND ?14 IS NULL))
                   AND object_count + ?10 <= ?15",
                vals![
                    input.generation_id,
                    input.collector_id,
                    input.collector_claim_token,
                    input.now,
                    i64::try_from(checkpoint_ordinal)?,
                    input.next_provider_cursor,
                    input.last_listed_key,
                    checkpoint_digest.to_string(),
                    page_digest_string,
                    i64::try_from(input.entries.len())?,
                    i64::try_from(page_bytes)?,
                    lease_expires_at,
                    i64::try_from(input.expected_checkpoint_ordinal)?,
                    input.expected_provider_cursor,
                    i64::try_from(OCI_GC_MAX_INVENTORY_OBJECTS)?
                ],
            )
            .expecting(1),
        );
        self.backend.checked_batch(&statements).await?;
        self.oci_provider_inventory_generation(&input.generation_id)
            .await?
            .context("OCI provider inventory disappeared after page checkpoint")
    }

    /// Seals a complete provider enumeration and publishes it as placement head.
    ///
    /// # Errors
    ///
    /// Returns an error when declared counts/digest differ from appended rows,
    /// the registry/topology fence moved, or persistence fails.
    pub async fn complete_oci_provider_inventory(
        &self,
        input: &CompleteOciProviderInventory,
    ) -> Result<OciProviderInventoryGenerationRecord> {
        validate_key_bytes(&input.generation_id, "OCI provider inventory id", 64)?;
        validate_key_bytes(&input.collector_id, "OCI inventory collector id", 128)?;
        validate_key_bytes(
            &input.collector_claim_token,
            "OCI inventory collector claim token",
            64,
        )?;
        if input.observed_at < 0 || input.now < input.observed_at {
            bail!("OCI provider inventory completion time is invalid");
        }
        let affected = self
            .backend
            .execute(
                "UPDATE oci_provider_inventory_generations
                 SET state = 'sealing', resource_version = resource_version + 1
                 WHERE id = ?1 AND collector_id = ?2
                   AND collector_claim_token = ?3
                   AND collector_lease_expires_at > ?4
                   AND checkpoint_ordinal = ?5 AND provider_cursor IS NULL
                   AND state = 'collecting'",
                &vals![
                    input.generation_id,
                    input.collector_id,
                    input.collector_claim_token,
                    input.now,
                    i64::try_from(input.expected_checkpoint_ordinal)?
                ],
            )
            .await?;
        if affected == 0 {
            let current = self
                .oci_provider_inventory_generation(&input.generation_id)
                .await?
                .context("OCI provider inventory does not exist")?;
            if current.collector_id != input.collector_id {
                bail!("OCI provider inventory belongs to another collector");
            }
            if current.collector_claim_token != input.collector_claim_token {
                bail!("OCI provider inventory collector lease is stale");
            }
            if current.state == "complete" {
                if current.checkpoint_ordinal == input.expected_checkpoint_ordinal {
                    return Ok(current);
                }
                bail!("OCI provider inventory completion replay conflicts");
            }
            if current.state != "sealing" {
                bail!("OCI provider inventory is not sealable");
            }
            if current.checkpoint_ordinal != input.expected_checkpoint_ordinal
                || current.provider_cursor.is_some()
            {
                bail!("OCI provider inventory completion checkpoint conflicts");
            }
        }
        let entries = self
            .backend
            .query(
                "SELECT object_key, object_digest, observed_hash, byte_size,
                        strong_etag, classification
                 FROM oci_provider_inventory_entries
                 WHERE generation_id = ?1 ORDER BY object_key LIMIT ?2",
                &vals![
                    input.generation_id,
                    i64::try_from(OCI_GC_MAX_INVENTORY_OBJECTS + 1)?
                ],
            )
            .await?;
        if entries.len() > OCI_GC_MAX_INVENTORY_OBJECTS {
            bail!("OCI provider inventory exceeds the synchronous object bound");
        }
        let mut digest_entries = Vec::with_capacity(entries.len());
        let mut byte_count = 0_u64;
        let mut untracked = 0_u64;
        for row in &entries {
            let byte_size = u64::try_from(row.get::<i64>(3)?)
                .context("persisted OCI provider byte size is negative")?;
            byte_count = byte_count
                .checked_add(byte_size)
                .context("OCI provider inventory byte count overflowed")?;
            untracked += u64::from(row.get::<String>(5)? == "untracked");
            digest_entries.push(PersistedInventoryDigestEntry {
                object_key: row.get(0)?,
                object_digest: row.get(1)?,
                observed_hash: row.get(2)?,
                byte_size,
                strong_etag: row.get(4)?,
            });
        }
        let digest = Sha256Digest::digest(&serde_json::to_vec(&digest_entries)?);
        let object_count = u64::try_from(entries.len()).context("inventory count overflowed")?;
        let object_count_i64 =
            i64::try_from(object_count).context("inventory count exceeds int64")?;
        let byte_count_i64 = i64::try_from(byte_count).context("inventory bytes exceed int64")?;
        let untracked_i64 = i64::try_from(untracked).context("inventory count exceeds int64")?;

        self.backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE oci_provider_inventory_generations
                     SET state = 'complete', active_slot = NULL,
                         collector_lease_expires_at = NULL,
                         inventory_digest = ?3,
                         object_count = ?4, byte_count = ?5,
                         untracked_object_count = ?6, observed_at = ?7,
                         completed_at = ?8, resource_version = resource_version + 1
                     WHERE id = ?1 AND collector_id = ?2
                       AND collector_claim_token = ?9
                       AND collector_lease_expires_at > ?8
                       AND state = 'sealing'
                       AND checkpoint_ordinal = ?10 AND provider_cursor IS NULL
                       AND object_count = ?4 AND byte_count = ?5
                       AND EXISTS (SELECT 1 FROM oci_registry_state registry_state
                         WHERE registry_state.registry_id =
                           oci_provider_inventory_generations.registry_id
                           AND registry_state.mutation_epoch =
                             oci_provider_inventory_generations.captured_mutation_epoch)
                       AND EXISTS (SELECT 1 FROM surface_placements placement
                         JOIN surface_placement_observations observation
                           ON observation.placement_id = placement.id
                         JOIN bindings binding
                           ON binding.id = placement.binding_id
                         JOIN binding_write_state write_state
                           ON write_state.binding_id = binding.id
                         WHERE placement.id =
                           oci_provider_inventory_generations.placement_id
                           AND placement.resource_version =
                             oci_provider_inventory_generations.placement_resource_version
                           AND placement.write_spec_version =
                             oci_provider_inventory_generations.placement_write_spec_version
                           AND observation.observation_version =
                             oci_provider_inventory_generations.placement_observation_version
                           AND observation.state = 'ready'
                           AND observation.completeness = 'complete'
                           AND binding.resource_version =
                             oci_provider_inventory_generations.binding_resource_version
                           AND write_state.current_write_revision =
                             oci_provider_inventory_generations.binding_write_revision)",
                    vals![
                        input.generation_id,
                        input.collector_id,
                        digest.to_string(),
                        object_count_i64,
                        byte_count_i64,
                        untracked_i64,
                        input.observed_at,
                        input.now,
                        input.collector_claim_token,
                        i64::try_from(input.expected_checkpoint_ordinal)?
                    ],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO oci_provider_inventory_heads
                       (placement_id, registry_id, generation_id, updated_at)
                     SELECT placement_id, registry_id, id, ?2
                     FROM oci_provider_inventory_generations
                     WHERE id = ?1 AND state = 'complete'
                     ON CONFLICT(placement_id) DO UPDATE SET
                       registry_id = excluded.registry_id,
                       generation_id = excluded.generation_id,
                       updated_at = excluded.updated_at
                     WHERE (SELECT observed_at
                              FROM oci_provider_inventory_generations
                             WHERE id = oci_provider_inventory_heads.generation_id)
                           < (SELECT observed_at
                                FROM oci_provider_inventory_generations
                               WHERE id = excluded.generation_id)
                        OR ((SELECT observed_at
                               FROM oci_provider_inventory_generations
                              WHERE id = oci_provider_inventory_heads.generation_id)
                            = (SELECT observed_at
                                 FROM oci_provider_inventory_generations
                                WHERE id = excluded.generation_id)
                            AND oci_provider_inventory_heads.generation_id
                              < excluded.generation_id)",
                    vals![input.generation_id, input.now],
                )
                .expecting(1),
            ])
            .await?;
        self.oci_provider_inventory_generation(&input.generation_id)
            .await?
            .context("OCI provider inventory disappeared after completion")
    }

    /// Returns one provider inventory generation.
    ///
    /// # Errors
    ///
    /// Returns an error on malformed persisted data or database failure.
    pub async fn oci_provider_inventory_generation(
        &self,
        generation_id: &str,
    ) -> Result<Option<OciProviderInventoryGenerationRecord>> {
        self.backend
            .query_opt(
                "SELECT id, registry_id, placement_id, collector_id,
                        collector_claim_token, collector_lease_expires_at,
                        idempotency_key,
                        captured_mutation_epoch, placement_resource_version,
                        placement_write_spec_version,
                        placement_observation_version, binding_id,
                        binding_resource_version, binding_write_revision, state,
                        inventory_digest, object_count, byte_count,
                        untracked_object_count, checkpoint_ordinal,
                        provider_cursor, checkpoint_last_key, checkpoint_digest,
                        takeover_count,
                        started_at, observed_at,
                        completed_at, resource_version,
                        purge_fence_resource_version
                 FROM oci_provider_inventory_generations WHERE id = ?1",
                &vals![generation_id],
            )
            .await?
            .as_ref()
            .map(row_to_inventory_generation)
            .transpose()
    }

    /// Returns the complete current inventory head for one placement.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid placement identity, malformed persisted
    /// data, or database failure.
    pub async fn oci_provider_inventory_head(
        &self,
        placement_id: i64,
    ) -> Result<Option<OciProviderInventoryGenerationRecord>> {
        if placement_id <= 0 {
            bail!("OCI provider inventory placement id is invalid");
        }
        self.backend
            .query_opt(
                "SELECT inventory.id, inventory.registry_id, inventory.placement_id,
                        inventory.collector_id, inventory.collector_claim_token,
                        inventory.collector_lease_expires_at, inventory.idempotency_key,
                        inventory.captured_mutation_epoch,
                        inventory.placement_resource_version,
                        inventory.placement_write_spec_version,
                        inventory.placement_observation_version, inventory.binding_id,
                        inventory.binding_resource_version, inventory.binding_write_revision,
                        inventory.state, inventory.inventory_digest,
                        inventory.object_count, inventory.byte_count,
                        inventory.untracked_object_count, inventory.checkpoint_ordinal,
                        inventory.provider_cursor, inventory.checkpoint_last_key,
                        inventory.checkpoint_digest, inventory.takeover_count,
                        inventory.started_at, inventory.observed_at,
                        inventory.completed_at, inventory.resource_version,
                        inventory.purge_fence_resource_version
                 FROM oci_provider_inventory_heads head
                 JOIN oci_provider_inventory_generations inventory
                   ON inventory.id = head.generation_id
                  AND inventory.placement_id = head.placement_id
                 WHERE head.placement_id = ?1 AND inventory.state = 'complete'",
                &vals![placement_id],
            )
            .await?
            .as_ref()
            .map(row_to_inventory_generation)
            .transpose()
    }

    /// Returns the single collecting/sealing inventory for one placement.
    ///
    /// Controllers use this after restart to resume the exact caller-keyed
    /// enumeration or explicitly fail it before starting a replacement.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid placement identity, malformed persisted
    /// data, or database failure.
    pub async fn active_oci_provider_inventory(
        &self,
        placement_id: i64,
    ) -> Result<Option<OciProviderInventoryGenerationRecord>> {
        if placement_id <= 0 {
            bail!("OCI provider inventory placement id is invalid");
        }
        self.backend
            .query_opt(
                "SELECT id, registry_id, placement_id, collector_id,
                        collector_claim_token, collector_lease_expires_at,
                        idempotency_key,
                        captured_mutation_epoch, placement_resource_version,
                        placement_write_spec_version,
                        placement_observation_version, binding_id,
                        binding_resource_version, binding_write_revision, state,
                        inventory_digest, object_count, byte_count,
                        untracked_object_count, checkpoint_ordinal,
                        provider_cursor, checkpoint_last_key, checkpoint_digest,
                        takeover_count,
                        started_at, observed_at,
                        completed_at, resource_version,
                        purge_fence_resource_version
                 FROM oci_provider_inventory_generations
                 WHERE placement_id = ?1 AND state IN('collecting', 'sealing')",
                &vals![placement_id],
            )
            .await?
            .as_ref()
            .map(row_to_inventory_generation)
            .transpose()
    }

    async fn oci_provider_inventory_generation_by_key(
        &self,
        input: &BeginOciProviderInventory,
    ) -> Result<Option<OciProviderInventoryGenerationRecord>> {
        let record = self
            .backend
            .query_opt(
                "SELECT id, registry_id, placement_id, collector_id,
                        collector_claim_token, collector_lease_expires_at,
                        idempotency_key,
                        captured_mutation_epoch, placement_resource_version,
                        placement_write_spec_version,
                        placement_observation_version, binding_id,
                        binding_resource_version, binding_write_revision, state,
                        inventory_digest, object_count, byte_count,
                        untracked_object_count, checkpoint_ordinal,
                        provider_cursor, checkpoint_last_key, checkpoint_digest,
                        takeover_count, started_at, observed_at,
                        completed_at, resource_version,
                        purge_fence_resource_version
                 FROM oci_provider_inventory_generations
                 WHERE registry_id = ?1 AND placement_id = ?2
                   AND collector_id = ?3 AND idempotency_key = ?4",
                &vals![
                    input.registry_id,
                    input.placement_id,
                    input.collector_id,
                    input.idempotency_key
                ],
            )
            .await?
            .as_ref()
            .map(row_to_inventory_generation)
            .transpose()?;
        if let Some(existing) = record.as_ref() {
            if existing.placement_resource_version != input.expected_placement_resource_version
                || existing.placement_observation_version
                    != input.expected_placement_observation_version
            {
                bail!("OCI provider inventory begin idempotency conflict");
            }
        }
        Ok(record)
    }

    /// Acquires, renews, or takes over one active inventory collector lease.
    ///
    /// A different receipt may take over only after expiry. Every append,
    /// seal, and failure transition checks the winning receipt transactionally.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identity/time, a live competing lease,
    /// terminal generation, or database failure.
    pub async fn claim_oci_provider_inventory(
        &self,
        generation_id: &str,
        collector_id: &str,
        collector_claim_token: &str,
        now: i64,
        lease_seconds: i64,
    ) -> Result<OciProviderInventoryGenerationRecord> {
        validate_key_bytes(generation_id, "OCI provider inventory id", 64)?;
        validate_key_bytes(collector_id, "OCI inventory collector id", 128)?;
        validate_key_bytes(
            collector_claim_token,
            "OCI inventory collector claim token",
            64,
        )?;
        if now < 0 || !(1..=3_600).contains(&lease_seconds) {
            bail!("OCI provider inventory collector lease is invalid");
        }
        let lease_expires_at = now.saturating_add(lease_seconds);
        self.backend
            .checked_batch(&[Statement::new(
                "UPDATE oci_provider_inventory_generations
                     SET collector_id = ?2, collector_claim_token = ?3,
                         collector_lease_expires_at = ?5,
                         takeover_count = takeover_count + CASE
                           WHEN collector_id = ?2 AND collector_claim_token = ?3
                           THEN 0 ELSE 1 END,
                         resource_version = resource_version + 1
                     WHERE id = ?1 AND state IN('collecting', 'sealing')
                       AND (collector_lease_expires_at <= ?4
                         OR (collector_id = ?2 AND collector_claim_token = ?3))",
                vals![
                    generation_id,
                    collector_id,
                    collector_claim_token,
                    now,
                    lease_expires_at
                ],
            )
            .expecting(1)])
            .await?;
        self.oci_provider_inventory_generation(generation_id)
            .await?
            .context("OCI provider inventory disappeared after collector claim")
    }

    /// Marks one abandoned collecting/sealing inventory as failed.
    ///
    /// This is the crash-recovery path when the original controller cannot
    /// safely resume and seal the complete provider enumeration.
    ///
    /// # Errors
    ///
    /// Returns an error for actor mismatch, invalid input, a stale version,
    /// a terminal generation, or database failure.
    pub async fn fail_oci_provider_inventory(
        &self,
        generation_id: &str,
        collector_id: &str,
        collector_claim_token: &str,
        expected_resource_version: i64,
        error: &str,
        now: i64,
    ) -> Result<OciProviderInventoryGenerationRecord> {
        validate_key_bytes(generation_id, "OCI provider inventory id", 64)?;
        validate_key_bytes(collector_id, "OCI inventory collector id", 128)?;
        validate_key_bytes(
            collector_claim_token,
            "OCI inventory collector claim token",
            64,
        )?;
        if expected_resource_version <= 0 || now < 0 {
            bail!("OCI provider inventory failure fence is invalid");
        }
        let error = crate::db::sanitize_log_text(error);
        self.backend
            .checked_batch(&[Statement::new(
                "UPDATE oci_provider_inventory_generations
                     SET state = 'failed', active_slot = NULL,
                         collector_lease_expires_at = NULL, last_error = ?5,
                         completed_at = ?6, resource_version = resource_version + 1
                     WHERE id = ?1 AND collector_id = ?2
                       AND collector_claim_token = ?3
                       AND collector_lease_expires_at > ?6
                       AND resource_version = ?4
                       AND state IN('collecting', 'sealing')",
                vals![
                    generation_id,
                    collector_id,
                    collector_claim_token,
                    expected_resource_version,
                    error,
                    now
                ],
            )
            .expecting(1)])
            .await?;
        self.oci_provider_inventory_generation(generation_id)
            .await?
            .context("OCI provider inventory disappeared after failure")
    }
}

fn row_to_capability(row: &crate::value::Row) -> Result<OciConditionalDeleteCapabilityRecord> {
    Ok(OciConditionalDeleteCapabilityRecord {
        binding_id: row.get(0)?,
        binding_write_revision: row.get(1)?,
        binding_resource_version: row.get(2)?,
        delete_credential_purpose: row.get(3)?,
        delete_credential_generation: row.get(4)?,
        capability_fingerprint: row.get(5)?,
        state: row.get(6)?,
        resource_version: row.get(7)?,
        observed_at: row.get(8)?,
    })
}

pub(super) fn row_to_inventory_generation(
    row: &crate::value::Row,
) -> Result<OciProviderInventoryGenerationRecord> {
    Ok(OciProviderInventoryGenerationRecord {
        id: row.get(0)?,
        registry_id: row.get(1)?,
        placement_id: row.get(2)?,
        collector_id: row.get(3)?,
        collector_claim_token: row.get(4)?,
        collector_lease_expires_at: row.get(5)?,
        idempotency_key: row.get(6)?,
        captured_mutation_epoch: row.get(7)?,
        purge_fence_resource_version: row.get(28)?,
        placement_resource_version: row.get(8)?,
        placement_write_spec_version: row.get(9)?,
        placement_observation_version: row.get(10)?,
        binding_id: row.get(11)?,
        binding_resource_version: row.get(12)?,
        binding_write_revision: row.get(13)?,
        state: row.get(14)?,
        inventory_digest: row
            .get::<Option<String>>(15)?
            .map(|value| Sha256Digest::parse(&value))
            .transpose()?,
        object_count: u64::try_from(row.get::<i64>(16)?)
            .context("persisted OCI inventory count is negative")?,
        byte_count: u64::try_from(row.get::<i64>(17)?)
            .context("persisted OCI inventory byte count is negative")?,
        untracked_object_count: u64::try_from(row.get::<i64>(18)?)
            .context("persisted OCI untracked count is negative")?,
        checkpoint_ordinal: u64::try_from(row.get::<i64>(19)?)
            .context("persisted OCI inventory checkpoint ordinal is negative")?,
        provider_cursor: row.get(20)?,
        checkpoint_last_key: row.get(21)?,
        checkpoint_digest: row
            .get::<Option<String>>(22)?
            .map(|value| Sha256Digest::parse(&value))
            .transpose()?,
        takeover_count: u64::try_from(row.get::<i64>(23)?)
            .context("persisted OCI inventory takeover count is negative")?,
        started_at: row.get(24)?,
        observed_at: row.get(25)?,
        completed_at: row.get(26)?,
        resource_version: row.get(27)?,
    })
}
