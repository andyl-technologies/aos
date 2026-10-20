//! Bounded cache-upload ticket admission.
//!
//! Bulk clients must not turn one upload inventory into a query/insert/query
//! sequence per object. This module reads every occupied active slot in one
//! query and admits all unoccupied proxy tickets in one checked transaction.
//! The transaction retains the same placement, binding, credential, inventory,
//! deletion, and ownership fences as single-ticket admission.

use std::collections::BTreeSet;

use anyhow::{bail, Result};

use crate::backend::CheckedStatement;
use crate::value::Value;

use super::{row_to_cache_write_ticket, validate_key_bytes, CacheWriteTicketRecord, Database};

/// Maximum proxy upload tickets admitted in one database transaction.
pub const MAX_CACHE_WRITE_TICKET_ADMISSION_BATCH: usize = 256;

/// One requested proxy-upload ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheProxyWriteAdmission {
    /// Client-visible opaque ticket identity.
    pub ticket_id: String,
    /// Cache-relative object key protected by the ticket.
    pub object_key: String,
    /// Exact byte length accepted by the upload endpoint.
    pub declared_size: i64,
}

/// One occupied same-key write slot and whether its topology pins remain current.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheWriteTicketSlot {
    /// Durable ticket currently occupying the cache/key active slot.
    pub ticket: CacheWriteTicketRecord,
    /// Whether the ticket still names the caller's exact reconciled authority.
    pub topology_current: bool,
}

impl Database {
    /// Lists active write slots for a bounded set of cache object keys.
    ///
    /// Stale slots are returned with `topology_current = false` instead of
    /// being hidden. The caller must not reuse them, but must treat them as
    /// occupied until recovery settles their uncertainty.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid or duplicate keys, invalid topology pins,
    /// an oversized batch, malformed durable state, or persistence failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn cache_write_ticket_slots(
        &self,
        cache_id: i64,
        object_keys: &[String],
        placement_id: i64,
        expected_placement_resource_version: i64,
        expected_binding_write_revision: i64,
        expected_write_credential_generation: i64,
        now: i64,
    ) -> Result<Vec<CacheWriteTicketSlot>> {
        if cache_id <= 0
            || placement_id <= 0
            || expected_placement_resource_version <= 0
            || expected_binding_write_revision <= 0
            || expected_write_credential_generation <= 0
            || object_keys.is_empty()
            || object_keys.len() > MAX_CACHE_WRITE_TICKET_ADMISSION_BATCH
        {
            bail!("cache write ticket slot query is invalid");
        }
        let mut unique = BTreeSet::new();
        for object_key in object_keys {
            validate_key_bytes(object_key, "cache object key", 512)?;
            if !unique.insert(object_key.as_str()) {
                bail!("cache write ticket slot keys must be unique");
            }
        }

        let mut params = vals![
            cache_id,
            now,
            placement_id,
            expected_placement_resource_version,
            expected_binding_write_revision,
            expected_write_credential_generation
        ];
        params.extend(object_keys.iter().cloned().map(Value::Text));
        let placeholders = (0..object_keys.len())
            .map(|index| format!("?{}", index + 7))
            .collect::<Vec<_>>()
            .join(", ");
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT ticket.ticket_id, ticket.cache_id, ticket.object_key,
                            ticket.declared_size, ticket.observed_final_size,
                            ticket.uploaded_size, ticket.upload_kind,
                            ticket.placement_id, ticket.placement_resource_version,
                            ticket.placement_write_spec_version, ticket.binding_id,
                            ticket.binding_resource_version, ticket.binding_write_revision,
                            ticket.write_credential_purpose,
                            ticket.write_credential_generation,
                            ticket.presign_credential_purpose,
                            ticket.presign_credential_generation,
                            ticket.starting_inventory_generation,
                            ticket.covered_inventory_generation, ticket.backend_upload_id,
                            ticket.state, ticket.expires_at, ticket.resource_version,
                            ticket.prior_object_size, ticket.prior_object_hash,
                            ticket.prior_object_etag, ticket.intended_object_hash,
                            EXISTS(SELECT 1
                              FROM surface_placement_effective placement
                              JOIN bindings binding ON binding.id = ticket.binding_id
                              JOIN binding_credential_revisions credential
                                ON credential.binding_id = ticket.binding_id
                               AND credential.purpose = ticket.write_credential_purpose
                               AND credential.generation = ticket.write_credential_generation
                              JOIN cache_gc_state cache_state
                                ON cache_state.cache_id = ticket.cache_id
                             WHERE placement.id = ticket.placement_id
                               AND placement.cache_id = ticket.cache_id
                               AND ticket.placement_id = ?3
                               AND ticket.placement_resource_version = ?4
                               AND ticket.binding_write_revision = ?5
                               AND ticket.write_credential_generation = ?6
                               AND ticket.expires_at > ?2
                               AND placement.resource_version
                                 = ticket.placement_resource_version
                               AND placement.write_spec_version
                                 = ticket.placement_write_spec_version
                               AND placement.binding_id = ticket.binding_id
                               AND placement.authority_observed_binding_write_revision
                                 = ticket.binding_write_revision
                               AND placement.effective_write_enabled = 1
                               AND binding.resource_version
                                 = ticket.binding_resource_version
                               AND credential.validation_state = 'valid'
                               AND cache_state.inventory_generation
                                 = ticket.starting_inventory_generation) AS topology_current
                       FROM cache_write_tickets ticket
                      WHERE ticket.cache_id = ?1 AND ticket.active_cache_slot = 1
                        AND ticket.object_key IN ({placeholders})
                      ORDER BY ticket.object_key"
                ),
                &params,
            )
            .await?;
        rows.into_iter()
            .map(|row| {
                let topology_current = row.get::<i64>(27)? != 0;
                Ok(CacheWriteTicketSlot {
                    ticket: row_to_cache_write_ticket(&row)?,
                    topology_current,
                })
            })
            .collect()
    }

    /// Atomically creates a bounded set of observing proxy-write tickets.
    ///
    /// Every ticket shares one already-resolved physical authority snapshot.
    /// Any same-key race, stale topology pin, active inventory, deletion
    /// overlap, or invalid credential rolls the whole admission back.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid or duplicate input, an oversized batch,
    /// stale topology, an occupied write slot, or persistence failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn begin_cache_proxy_write_tickets(
        &self,
        cache_id: i64,
        placement_id: i64,
        expected_placement_resource_version: i64,
        expected_binding_write_revision: i64,
        expected_write_credential_generation: i64,
        quota_org_id: Option<i64>,
        expires_at: i64,
        now: i64,
        admissions: &[CacheProxyWriteAdmission],
    ) -> Result<()> {
        if cache_id <= 0
            || placement_id <= 0
            || expected_placement_resource_version <= 0
            || expected_binding_write_revision <= 0
            || expected_write_credential_generation <= 0
            || expires_at <= now
            || admissions.is_empty()
            || admissions.len() > MAX_CACHE_WRITE_TICKET_ADMISSION_BATCH
        {
            bail!("cache proxy write ticket batch is invalid");
        }
        let mut ticket_ids = BTreeSet::new();
        let mut object_keys = BTreeSet::new();
        for admission in admissions {
            validate_key_bytes(&admission.ticket_id, "cache write ticket id", 64)?;
            validate_key_bytes(&admission.object_key, "cache object key", 512)?;
            if admission.declared_size < 0
                || !ticket_ids.insert(admission.ticket_id.as_str())
                || !object_keys.insert(admission.object_key.as_str())
            {
                bail!("cache proxy write ticket batch contains invalid duplicates");
            }
        }

        let statements = admissions
            .iter()
            .map(|admission| {
                CheckedStatement::exact(
                    "INSERT INTO cache_write_tickets
                         (ticket_id, cache_id, object_key, declared_size, upload_kind,
                          placement_id, placement_resource_version,
                          placement_write_spec_version, binding_id,
                          binding_resource_version, binding_write_revision,
                          write_credential_purpose, write_credential_generation,
                          starting_inventory_generation, quota_org_id,
                          quota_delta_bytes, quota_delta_objects, quota_state,
                          state, active_cache_slot, expires_at, created_at)
                     SELECT ?1, ?2, ?4, ?11, 'single', placement.id,
                            placement.resource_version, placement.write_spec_version,
                            binding.id, binding.resource_version, revision.revision,
                            revision.write_credential_purpose,
                            revision.write_credential_generation,
                            state.inventory_generation, ?5, 0, 0,
                            CASE WHEN ?5 IS NULL THEN 'none' ELSE 'pending' END,
                            'observing', 1, ?8, ?9
                       FROM surface_placement_effective placement
                       JOIN bindings binding ON binding.id = placement.binding_id
                       JOIN binding_write_revisions revision
                         ON revision.binding_id = binding.id
                        AND revision.revision
                          = placement.authority_observed_binding_write_revision
                       JOIN binding_credential_revisions credential
                         ON credential.binding_id = revision.binding_id
                        AND credential.purpose = revision.write_credential_purpose
                        AND credential.generation = revision.write_credential_generation
                       JOIN cache_gc_state state ON state.cache_id = placement.cache_id
                      WHERE placement.id = ?3 AND placement.cache_id = ?2
                        AND placement.resource_version = ?6
                        AND revision.revision = ?7
                        AND revision.write_credential_generation = ?10
                        AND placement.effective_write_enabled = 1
                        AND credential.validation_state = 'valid'
                        AND EXISTS (SELECT 1 FROM binary_caches owner
                          LEFT JOIN orgs org ON org.id = owner.org_id
                          WHERE owner.id = ?2
                            AND (owner.org_id IS NULL OR org.deleted_at IS NULL)
                            AND (owner.org_id = ?5
                              OR (owner.org_id IS NULL AND ?5 IS NULL)))
                        AND NOT EXISTS (SELECT 1
                          FROM cache_inventory_generations inventory
                          WHERE inventory.cache_id = ?2
                            AND inventory.state = 'building')
                        AND NOT EXISTS (SELECT 1 FROM object_deletion_jobs job
                          JOIN surface_objects object
                            ON object.id = job.surface_object_id
                           AND object.cache_id = job.cache_id
                          WHERE job.cache_id = ?2 AND job.active_slot = 1
                            AND object.object_key = ?4)",
                    vals![
                        admission.ticket_id.as_str(),
                        cache_id,
                        placement_id,
                        admission.object_key.as_str(),
                        quota_org_id,
                        expected_placement_resource_version,
                        expected_binding_write_revision,
                        expires_at,
                        now,
                        expected_write_credential_generation,
                        admission.declared_size
                    ],
                    1,
                )
            })
            .collect::<Vec<_>>();
        self.backend.checked_batch(&statements).await
    }
}

#[cfg(all(test, feature = "query-timing", not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::backend::{QueryTimings, SqlxBackend, TimingBackend};
    use crate::db::SurfaceTarget;

    #[tokio::test]
    async fn bulk_proxy_admission_uses_one_query_and_one_checked_batch() {
        let timings = QueryTimings::new();
        let backend = SqlxBackend::connect_sqlite(":memory:").await.unwrap();
        let db = Database::with_backend(Box::new(TimingBackend::new(backend, timings.clone())))
            .await
            .unwrap();
        db.install_write_failure_test_tickets().await.unwrap();
        let placement = db
            .reconciled_surface_writer(SurfaceTarget::BinaryCache(1))
            .await
            .unwrap();
        let admissions = (0..64)
            .map(|index| CacheProxyWriteAdmission {
                ticket_id: format!("bulk-ticket-{index:04}"),
                object_key: format!("nar/bulk-{index:04}.nar"),
                declared_size: index + 1,
            })
            .collect::<Vec<_>>();
        let object_keys = admissions
            .iter()
            .map(|admission| admission.object_key.clone())
            .collect::<Vec<_>>();

        let before = timings.spans().len();
        let slots = db
            .cache_write_ticket_slots(1, &object_keys, placement.id, 1, 1, 1, 50)
            .await
            .unwrap();
        assert!(slots.is_empty());
        db.begin_cache_proxy_write_tickets(1, placement.id, 1, 1, 1, Some(1), 500, 50, &admissions)
            .await
            .unwrap();
        let spans = timings.spans();
        let operations = spans[before..]
            .iter()
            .map(|span| span.op)
            .collect::<Vec<_>>();

        assert_eq!(operations, ["query", "checked_batch"]);
    }
}
