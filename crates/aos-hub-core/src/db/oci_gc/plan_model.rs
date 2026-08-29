//! Canonical reviewed-plan records, validation, and SQL fence builders.

use anyhow::{bail, Result};
use aos_oci_types::Sha256Digest;
use serde::Serialize;

use super::OCI_GC_MAX_INVENTORY_AGE_SECONDS;
use crate::backend::{CheckedStatement, Statement};
use crate::db::{validate_key_bytes, Database};

/// Input for planning one reviewed OCI retention generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanOciGc {
    /// Registry to collect.
    pub registry_id: i64,
    /// Authenticated actor identity.
    pub actor_id: String,
    /// Actor-scoped retry key.
    pub idempotency_key: String,
    /// Expected retention-policy version; zero means effective defaults.
    pub expected_resource_version: i64,
    /// Planning time in Unix seconds.
    pub now: i64,
}

/// Input for applying a reviewed OCI retention generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOciGc {
    /// Durable generation id.
    pub generation_id: String,
    /// Authenticated actor that created the plan.
    pub actor_id: String,
    /// Actor-scoped apply retry key.
    pub idempotency_key: String,
    /// Exact review confirmation hash.
    pub confirmation_hash: Sha256Digest,
    /// Apply time in Unix seconds.
    pub now: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct EffectivePolicy {
    pub(super) untagged_grace_seconds: u64,
    pub(super) deleted_tag_history_seconds: u64,
    pub(super) recent_manual_tag_revisions: u32,
    pub(super) retain_referrers: bool,
    pub(super) resource_version: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct FrozenRoot {
    pub(super) kind: String,
    pub(super) digest: String,
    pub(super) source_id: String,
    pub(super) repository_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct FrozenPlacement {
    pub(super) placement_id: i64,
    pub(super) placement_name: String,
    pub(super) placement_prefix: String,
    pub(super) placement_resource_version: i64,
    pub(super) placement_write_spec_version: i64,
    pub(super) placement_observation_version: i64,
    pub(super) binding_id: i64,
    pub(super) binding_resource_version: i64,
    pub(super) binding_write_revision: i64,
    pub(super) delete_credential_purpose: Option<String>,
    pub(super) delete_credential_generation: Option<i64>,
    pub(super) delete_capability_fingerprint: String,
    pub(super) delete_capability_resource_version: i64,
    pub(super) delete_capability_observed_at: i64,
    pub(super) inventory_generation_id: String,
    pub(super) inventory_digest: String,
    pub(super) inventory_observed_at: i64,
    pub(super) inventory_object_count: u64,
    pub(super) inventory_byte_size: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct FrozenCandidate {
    pub(super) digest: String,
    pub(super) media_type: String,
    pub(super) byte_size: u64,
    pub(super) object_key: String,
    pub(super) surface_object_id: i64,
    pub(super) catalog_object_resource_version: i64,
    pub(super) repositories: Vec<(i64, String)>,
    pub(super) eligible_at: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct FrozenAction {
    pub(super) id: String,
    pub(super) digest: String,
    pub(super) placement_id: i64,
    pub(super) object_key: String,
    pub(super) expected_hash: String,
    pub(super) expected_size: u64,
    pub(super) expected_strong_etag: Option<String>,
    pub(super) inventory_generation_id: String,
    pub(super) inventory_entry_present: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PlanBlocker {
    pub(super) kind: &'static str,
    pub(super) digest: Option<Sha256Digest>,
    pub(super) detail: String,
}

pub(super) fn canonical_digest(value: String) -> Result<String> {
    Ok(Sha256Digest::parse(&value)?.to_string())
}

pub(super) fn validate_plan_input(input: &PlanOciGc) -> Result<()> {
    if input.registry_id <= 0 || input.expected_resource_version < 0 || input.now < 0 {
        bail!("OCI GC plan has an invalid registry, version, or time");
    }
    validate_key_bytes(&input.actor_id, "OCI GC actor id", 128)?;
    validate_key_bytes(&input.idempotency_key, "OCI GC plan idempotency key", 128)
}

pub(super) fn validate_apply_input(input: &ApplyOciGc) -> Result<()> {
    validate_key_bytes(&input.generation_id, "OCI GC generation id", 64)?;
    validate_key_bytes(&input.actor_id, "OCI GC actor id", 128)?;
    validate_key_bytes(&input.idempotency_key, "OCI GC apply idempotency key", 128)?;
    if input.now < 0 {
        bail!("OCI GC apply time is invalid");
    }
    Ok(())
}

pub(super) fn digest_json(value: &(impl Serialize + ?Sized)) -> Result<Sha256Digest> {
    Ok(Sha256Digest::digest(&serde_json::to_vec(value)?))
}

pub(super) fn policy_guard_statement(
    registry_id: i64,
    policy_resource_version: i64,
) -> CheckedStatement {
    if policy_resource_version == 0 {
        Statement::new(
            "UPDATE oci_registry_state SET updated_at = updated_at
             WHERE registry_id = ?1 AND NOT EXISTS (
               SELECT 1 FROM oci_retention_policies WHERE registry_id = ?1)",
            vals![registry_id],
        )
        .expecting(1)
    } else {
        Statement::new(
            "UPDATE oci_registry_state SET updated_at = updated_at
             WHERE registry_id = ?1 AND EXISTS (
               SELECT 1 FROM oci_retention_policies
               WHERE registry_id = ?1 AND resource_version = ?2)",
            vals![registry_id, policy_resource_version],
        )
        .expecting(1)
    }
}

pub(super) fn oci_gc_snapshot_guard_statement(
    generation_id: &str,
    placement_id: i64,
    now: i64,
) -> CheckedStatement {
    let oldest = now.saturating_sub(OCI_GC_MAX_INVENTORY_AGE_SECONDS);
    Statement::new(
        "UPDATE oci_registry_state SET updated_at = updated_at
         WHERE registry_id = (SELECT registry_id FROM oci_gc_runs WHERE id = ?1)
           AND EXISTS (SELECT 1 FROM oci_gc_placement_snapshots snapshot
             JOIN surface_placements placement
               ON placement.id = snapshot.placement_id
              AND placement.registry_id = snapshot.registry_id
             JOIN surface_placement_observations observation
               ON observation.placement_id = placement.id
             JOIN bindings binding ON binding.id = snapshot.binding_id
             JOIN binding_write_state write_state
               ON write_state.binding_id = binding.id
             JOIN oci_conditional_delete_capabilities capability
               ON capability.binding_id = snapshot.binding_id
              AND capability.binding_write_revision = snapshot.binding_write_revision
             LEFT JOIN binding_credential_revisions delete_credential
               ON delete_credential.binding_id = snapshot.binding_id
              AND delete_credential.purpose = snapshot.delete_credential_purpose
              AND delete_credential.generation = snapshot.delete_credential_generation
             LEFT JOIN binding_credential_heads delete_credential_head
               ON delete_credential_head.binding_id = snapshot.binding_id
              AND delete_credential_head.purpose = snapshot.delete_credential_purpose
              AND delete_credential_head.current_generation =
                snapshot.delete_credential_generation
             JOIN oci_provider_inventory_heads head
               ON head.placement_id = snapshot.placement_id
              AND head.generation_id = snapshot.inventory_generation_id
             JOIN oci_provider_inventory_generations inventory
               ON inventory.id = head.generation_id
             WHERE snapshot.run_id = ?1 AND snapshot.placement_id = ?2
               AND placement.name = snapshot.placement_name
               AND placement.prefix = snapshot.placement_prefix
               AND placement.resource_version = snapshot.placement_resource_version
               AND placement.write_spec_version = snapshot.placement_write_spec_version
               AND placement.desired_state <> 'offline'
               AND observation.observation_version = snapshot.placement_observation_version
               AND observation.state = 'ready'
               AND observation.completeness = 'complete'
               AND placement.binding_id = snapshot.binding_id
               AND binding.resource_version = snapshot.binding_resource_version
               AND write_state.current_write_revision = snapshot.binding_write_revision
               AND capability.state = 'valid'
               AND capability.resource_version >= snapshot.delete_capability_resource_version
               AND capability.capability_fingerprint = snapshot.delete_capability_fingerprint
               AND (capability.delete_credential_purpose = snapshot.delete_credential_purpose
                 OR (capability.delete_credential_purpose IS NULL
                   AND snapshot.delete_credential_purpose IS NULL))
               AND (capability.delete_credential_generation =
                    snapshot.delete_credential_generation
                 OR (capability.delete_credential_generation IS NULL
                   AND snapshot.delete_credential_generation IS NULL))
               AND ((snapshot.delete_credential_purpose IS NULL
                     AND snapshot.delete_credential_generation IS NULL
                     AND binding.kind = 'local_fs')
                 OR (delete_credential.validation_state = 'valid'
                   AND delete_credential_head.current_generation =
                     snapshot.delete_credential_generation))
               AND capability.observed_at >= snapshot.delete_capability_observed_at
               AND inventory.state = 'complete'
               AND inventory.inventory_digest = snapshot.inventory_digest
               AND inventory.observed_at = snapshot.inventory_observed_at
               AND inventory.observed_at >= ?3)",
        vals![generation_id, placement_id, oldest],
    )
    .expecting(1)
}

impl Database {
    pub(super) async fn oci_gc_snapshot_guard_statements(
        &self,
        generation_id: &str,
        now: i64,
    ) -> Result<Vec<CheckedStatement>> {
        let rows = self
            .backend
            .query(
                "SELECT placement_id FROM oci_gc_placement_snapshots
                 WHERE run_id = ?1 ORDER BY placement_id",
                &vals![generation_id],
            )
            .await?;
        rows.iter()
            .map(|row| {
                Ok(oci_gc_snapshot_guard_statement(
                    generation_id,
                    row.get(0)?,
                    now,
                ))
            })
            .collect()
    }
}
