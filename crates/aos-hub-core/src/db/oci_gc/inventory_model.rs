//! Provider-inventory validation and exact replay statement construction.

use anyhow::{bail, Context, Result};

use super::inventory::{
    AppendOciProviderInventoryPage, OciProviderInventoryEntryInput,
    RecordOciConditionalDeleteCapability,
};
use super::{
    OCI_GC_INVENTORY_BATCH_SIZE, OCI_GC_MAX_INVENTORY_KEY_BYTES, OCI_GC_MAX_INVENTORY_OBJECTS,
};
use crate::backend::{CheckedStatement, Statement};
use crate::db::{oci_blob_object_key, validate_key_bytes};

pub(super) fn validate_capability_input(
    input: &RecordOciConditionalDeleteCapability,
) -> Result<()> {
    if input.binding_id <= 0
        || input.binding_write_revision <= 0
        || input.binding_resource_version <= 0
        || input.observed_at < 0
        || !matches!(input.state.as_str(), "valid" | "invalid")
        || input
            .expected_resource_version
            .is_some_and(|version| version <= 0)
    {
        bail!("conditional-delete capability has an invalid version or state");
    }
    validate_key_bytes(
        &input.capability_fingerprint,
        "conditional-delete capability fingerprint",
        128,
    )?;
    match (
        input.delete_credential_purpose.as_deref(),
        input.delete_credential_generation,
    ) {
        (None, None) => {}
        (Some("delete"), Some(generation)) if generation > 0 => {}
        _ => bail!("conditional-delete credential identity is invalid"),
    }
    Ok(())
}

fn validate_inventory_entry(entry: &OciProviderInventoryEntryInput) -> Result<()> {
    if entry.object_key != oci_blob_object_key(entry.object_digest) {
        bail!("OCI provider inventory key conflicts with its digest");
    }
    validate_key_bytes(&entry.object_key, "OCI provider object key", 512)?;
    let canonical = crate::surface_write::strong_if_match_etag(&entry.strong_etag)?;
    validate_key_bytes(&canonical, "OCI provider strong etag", 512)?;
    i64::try_from(entry.byte_size).context("OCI provider inventory byte size exceeds int64")?;
    Ok(())
}

fn validate_inventory_entries(entries: &[OciProviderInventoryEntryInput]) -> Result<()> {
    if entries.len() > OCI_GC_INVENTORY_BATCH_SIZE {
        bail!("OCI provider inventory batch exceeds {OCI_GC_INVENTORY_BATCH_SIZE}");
    }
    let mut previous = None;
    for entry in entries {
        validate_inventory_entry(entry)?;
        if previous.is_some_and(|value: &str| value >= entry.object_key.as_str()) {
            bail!("OCI provider inventory page keys must be unique and ordered");
        }
        previous = Some(entry.object_key.as_str());
    }
    Ok(())
}

pub(super) fn validate_inventory_page(input: &AppendOciProviderInventoryPage) -> Result<()> {
    validate_key_bytes(&input.generation_id, "OCI provider inventory id", 64)?;
    validate_key_bytes(&input.collector_id, "OCI inventory collector id", 128)?;
    validate_key_bytes(
        &input.collector_claim_token,
        "OCI inventory collector claim token",
        64,
    )?;
    if let Some(cursor) = input.expected_provider_cursor.as_deref() {
        validate_key_bytes(cursor, "OCI provider inventory expected cursor", 512)?;
    }
    if let Some(cursor) = input.next_provider_cursor.as_deref() {
        validate_key_bytes(cursor, "OCI provider inventory next cursor", 512)?;
    }
    if let Some(last) = input.last_listed_key.as_deref() {
        validate_key_bytes(last, "OCI provider inventory last listed key", 512)?;
    }
    if input.now < 0
        || !(1..=3_600).contains(&input.lease_seconds)
        || i64::try_from(input.expected_checkpoint_ordinal).is_err()
    {
        bail!("OCI provider inventory page lease or checkpoint is invalid");
    }
    validate_inventory_entries(&input.entries)?;
    if input.entries.last().is_some_and(|entry| {
        input
            .last_listed_key
            .as_deref()
            .is_none_or(|last| entry.object_key.as_str() > last)
    }) {
        bail!("OCI provider inventory page entries exceed its last listed key");
    }
    Ok(())
}

pub(super) fn inventory_entry_statements(
    generation_id: &str,
    collector_id: &str,
    collector_claim_token: &str,
    now: i64,
    entries: &[OciProviderInventoryEntryInput],
) -> Result<Vec<CheckedStatement>> {
    let mut statements = Vec::with_capacity(entries.len() * 2);
    for entry in entries {
        let byte_size = i64::try_from(entry.byte_size)
            .context("OCI provider inventory byte size exceeds int64")?;
        let strong_etag = crate::surface_write::strong_if_match_etag(&entry.strong_etag)?;
        statements.push(
            Statement::new(
                "INSERT INTO oci_provider_inventory_entries
                   (generation_id, registry_id, placement_id, object_key,
                    object_digest, observed_hash, byte_size, strong_etag,
                    surface_object_id, catalog_object_resource_version,
                    classification, deleted_at)
                 SELECT generation.id, generation.registry_id,
                        generation.placement_id, ?3, ?4, ?5, ?6, ?7,
                        object.id, object.resource_version,
                        CASE WHEN object.id IS NULL
                          THEN 'untracked' ELSE 'tracked' END, NULL
                 FROM oci_provider_inventory_generations generation
                 LEFT JOIN surface_objects object
                   ON object.registry_id = generation.registry_id
                  AND object.object_key = ?3
                  AND object.lifecycle_state = 'active'
                 LEFT JOIN oci_blobs stored_blob
                   ON stored_blob.registry_id = generation.registry_id
                  AND stored_blob.surface_object_id = object.id
                  AND stored_blob.digest = ?4
                  AND stored_blob.lifecycle_state = 'active'
                 JOIN oci_registry_state registry_state
                   ON registry_state.registry_id = generation.registry_id
                 WHERE generation.id = ?1 AND generation.collector_id = ?2
                   AND generation.collector_claim_token = ?9
                   AND generation.collector_lease_expires_at > ?10
                   AND generation.state = 'collecting'
                   AND registry_state.mutation_epoch = generation.captured_mutation_epoch
                   AND (SELECT COUNT(*) FROM oci_provider_inventory_entries current
                     WHERE current.generation_id = generation.id) < ?11
                   AND (SELECT COALESCE(SUM(length(current.object_key)), 0)
                     FROM oci_provider_inventory_entries current
                     WHERE current.generation_id = generation.id) + length(?3) <= ?12
                   AND (object.id IS NULL OR (stored_blob.digest IS NOT NULL
                     AND object.content_hash = ?8 AND object.size = ?6))
                 ON CONFLICT(generation_id, object_key) DO NOTHING",
                vals![
                    generation_id,
                    collector_id,
                    entry.object_key,
                    entry.object_digest.to_string(),
                    entry.observed_hash.to_string(),
                    byte_size,
                    strong_etag,
                    entry.object_digest.encoded(),
                    collector_claim_token,
                    now,
                    i64::try_from(OCI_GC_MAX_INVENTORY_OBJECTS)?,
                    i64::try_from(OCI_GC_MAX_INVENTORY_KEY_BYTES)?
                ],
            )
            .unchecked(),
        );
        statements.push(
            Statement::new(
                "UPDATE oci_provider_inventory_entries
                 SET deleted_at = deleted_at
                 WHERE generation_id = ?1 AND object_key = ?3
                   AND object_digest = ?4 AND observed_hash = ?5
                   AND byte_size = ?6 AND strong_etag = ?7
                   AND deleted_at IS NULL
                   AND EXISTS (SELECT 1 FROM oci_provider_inventory_generations generation
                     WHERE generation.id = ?1 AND generation.collector_id = ?2
                       AND generation.collector_claim_token = ?8
                       AND generation.collector_lease_expires_at > ?9
                       AND generation.state = 'collecting')",
                vals![
                    generation_id,
                    collector_id,
                    entry.object_key,
                    entry.object_digest.to_string(),
                    entry.observed_hash.to_string(),
                    byte_size,
                    crate::surface_write::strong_if_match_etag(&entry.strong_etag)?,
                    collector_claim_token,
                    now
                ],
            )
            .expecting(1),
        );
    }
    Ok(statements)
}
