//! Portable row locks for current mirror authority and publication dependencies.
//!
//! Checked no-op writes hold real rows through commit on PostgreSQL. A joined
//! predicate alone would observe a snapshot while a concurrent revocation could
//! complete before publication. Locks use the same entity order for every copy.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, ensure};

use crate::backend::CheckedStatement;
use crate::mirror_work::MirrorOriginal;

use super::{Database, SurfaceObjectRecord};

impl Database {
    pub(super) async fn mirror_authority_locks(
        &self,
        original: &MirrorOriginal,
        publication_id: Option<&str>,
        object: Option<&SurfaceObjectRecord>,
        org_id: Option<i64>,
    ) -> Result<Vec<CheckedStatement>> {
        let mut locks = Vec::new();
        if let Some(org_id) = org_id {
            locks.push(CheckedStatement::exact(
                "UPDATE orgs SET updated_at = updated_at WHERE id = ?1",
                vals![org_id],
                1,
            ));
            // Materializing an absent unlimited cap row prevents a concurrent
            // cap INSERT from slipping behind an absence predicate. Existing
            // configured limits are never overwritten.
            locks.push(CheckedStatement::unchecked(
                "INSERT INTO org_quotas(org_id) VALUES (?1) ON CONFLICT(org_id) DO NOTHING",
                vals![org_id],
            ));
            locks.push(CheckedStatement::exact(
                "UPDATE org_quotas SET max_bytes = max_bytes WHERE org_id = ?1",
                vals![org_id],
                1,
            ));
            locks.push(CheckedStatement::exact(
                "UPDATE org_usage SET updated_at = updated_at WHERE org_id = ?1",
                vals![org_id],
                1,
            ));
        }
        locks.push(CheckedStatement::exact(
            "UPDATE registries SET updated_at = updated_at WHERE id = ?1 AND resource_version = ?2",
            vals![original.registry_id, original.registry_resource_version],
            1,
        ));
        locks.push(CheckedStatement::exact(
            "UPDATE mirror_sources SET resource_version = resource_version
              WHERE registry_id = ?1 AND resource_version = ?2 AND upstream_url = ?3",
            vals![
                original.registry_id,
                original.mirror_resource_version,
                original.upstream_base
            ],
            1,
        ));
        if let Some(publication_id) = publication_id {
            locks.push(CheckedStatement::exact(
                "UPDATE registry_publication_state SET resource_version = resource_version WHERE registry_id = ?1",
                vals![original.registry_id], 1,
            ));
            locks.push(CheckedStatement::exact(
                "UPDATE registry_publications SET mutation_version = mutation_version
                  WHERE publication_id = ?1 AND registry_id = ?2",
                vals![publication_id, original.registry_id],
                1,
            ));
        }
        if let Some(object) = object {
            locks.push(CheckedStatement::exact(
                "UPDATE surface_objects SET updated_at = updated_at
                  WHERE id = ?1 AND resource_version = ?2 AND registry_id = ?3",
                vals![object.id, object.resource_version, original.registry_id],
                1,
            ));
        }

        let mut placements = BTreeSet::from([original.placement_id]);
        if let Some(publication_id) = publication_id {
            let rows = self
                .backend
                .query(
                    "SELECT placement_id FROM registry_publication_placements
                  WHERE publication_id = ?1 AND required = 1 ORDER BY placement_id LIMIT 65",
                    &vals![publication_id],
                )
                .await?;
            ensure!(
                rows.len() <= 64,
                "mirror required placement set exceeds its lock bound"
            );
            for row in rows {
                placements.insert(row.get(0)?);
            }
        }
        let mut bindings = BTreeMap::new();
        let mut placement_rows = Vec::new();
        for placement_id in placements {
            let row = self.backend.query_opt(
                "SELECT placement.binding_id, binding.resource_version, placement.resource_version,
                        placement.write_spec_version, observation.observation_version
                   FROM surface_placements placement JOIN bindings binding ON binding.id = placement.binding_id
                   JOIN surface_placement_observations observation ON observation.placement_id = placement.id
                  WHERE placement.id = ?1 AND placement.registry_id = ?2",
                &vals![placement_id, original.registry_id],
            ).await?.context("mirror required placement authority disappeared")?;
            let binding_id: i64 = row.get(0)?;
            let binding_version: i64 = row.get(1)?;
            bindings.insert(binding_id, binding_version);
            placement_rows.push((
                placement_id,
                row.get::<i64>(2)?,
                row.get::<i64>(3)?,
                row.get::<i64>(4)?,
            ));
        }
        for (binding_id, version) in bindings {
            locks.push(CheckedStatement::exact(
                "UPDATE bindings SET updated_at = updated_at WHERE id = ?1 AND resource_version = ?2",
                vals![binding_id, version], 1,
            ));
        }
        let writer = self
            .reconciled_surface_writer(super::super::SurfaceTarget::Registry(original.registry_id))
            .await?;
        let authority_id = writer
            .write_authority_id
            .context("mirror write authority absent")?;
        let write_revision = writer
            .authority_observed_binding_write_revision
            .context("mirror write revision absent")?;
        locks.extend([
            CheckedStatement::exact(
                "UPDATE binding_credential_heads SET updated_at = updated_at
                  WHERE binding_id = ?1 AND purpose = 'write' AND current_generation =
                    (SELECT write_credential_generation FROM binding_write_revisions
                      WHERE binding_id = ?1 AND revision = ?2)",
                vals![original.binding_id, write_revision],
                1,
            ),
            CheckedStatement::exact(
                "UPDATE binding_credential_revisions SET created_at = created_at
                  WHERE binding_id = ?1 AND purpose = 'write' AND generation =
                    (SELECT write_credential_generation FROM binding_write_revisions
                      WHERE binding_id = ?1 AND revision = ?2)",
                vals![original.binding_id, write_revision],
                1,
            ),
        ]);
        locks.extend([
            CheckedStatement::exact(
                "UPDATE binding_write_state SET updated_at = updated_at
                  WHERE binding_id = ?1 AND current_write_revision = ?2",
                vals![original.binding_id, write_revision], 1,
            ),
            CheckedStatement::exact(
                "UPDATE binding_write_revisions SET created_at = created_at WHERE binding_id = ?1 AND revision = ?2",
                vals![original.binding_id, write_revision], 1,
            ),
            CheckedStatement::exact(
                "UPDATE binding_write_observations SET observation_version = observation_version
                  WHERE binding_id = ?1 AND revision = ?2 AND state = 'valid'",
                vals![original.binding_id, write_revision], 1,
            ),
            CheckedStatement::exact(
                "UPDATE surface_write_authorities SET updated_at = updated_at
                  WHERE id = ?1 AND registry_id = ?2 AND reconciliation_state = 'ready'
                    AND desired_placement_id = ?3 AND observed_placement_id = ?3
                    AND desired_write_spec_version = ?4 AND observed_write_spec_version = ?4
                    AND desired_binding_write_revision = ?5 AND observed_binding_write_revision = ?5",
                vals![authority_id, original.registry_id, original.placement_id, original.write_spec_version, write_revision], 1,
            ),
        ]);
        for (id, version, write_spec, observation) in placement_rows {
            locks.push(CheckedStatement::exact(
                "UPDATE surface_placements SET updated_at = updated_at
                  WHERE id = ?1 AND resource_version = ?2 AND write_spec_version = ?3",
                vals![id, version, write_spec],
                1,
            ));
            locks.push(CheckedStatement::exact(
                "UPDATE surface_placement_observations SET observation_version = observation_version
                  WHERE placement_id = ?1 AND observation_version = ?2",
                vals![id, observation], 1,
            ));
        }
        locks.push(CheckedStatement::exact(
            "UPDATE surface_placement_write_capabilities SET created_at = created_at
              WHERE placement_id = ?1 AND placement_write_spec_version = ?2
                AND binding_id = ?3 AND binding_write_revision = ?4",
            vals![
                original.placement_id,
                original.write_spec_version,
                original.binding_id,
                write_revision
            ],
            1,
        ));
        if let Some(publication_id) =
            publication_id.filter(|_| crate::keymap::is_mutable_path(&original.path))
        {
            locks.extend(self.mirror_dependency_locks(publication_id).await?);
        }
        Ok(locks)
    }

    async fn mirror_dependency_locks(&self, publication_id: &str) -> Result<Vec<CheckedStatement>> {
        let counts = self.backend.query_opt(
            "SELECT (SELECT COUNT(*) FROM registry_publication_objects
                       WHERE publication_id = ?1 AND object_kind = 'immutable'),
                    (SELECT COUNT(*) FROM registry_publication_placements WHERE publication_id = ?1 AND required = 1)",
            &vals![publication_id],
        ).await?.context("mirror publication dependency count disappeared")?;
        let objects: i64 = counts.get(0)?;
        let placements: i64 = counts.get(1)?;
        ensure!(
            objects >= 0 && (1..=64).contains(&placements),
            "mirror dependency set is invalid"
        );
        let copies = objects
            .checked_mul(placements)
            .context("mirror dependency count overflow")?;
        let mut locks = vec![
            CheckedStatement::exact(
                "UPDATE registry_publication_placements SET observed_at = observed_at
                  WHERE publication_id = ?1 AND required = 1",
                vals![publication_id], u64::try_from(placements)?,
            ),
            CheckedStatement::exact(
                "UPDATE registry_publication_objects SET expected_size = expected_size
                  WHERE publication_id = ?1 AND object_kind = 'immutable'",
                vals![publication_id], u64::try_from(objects)?,
            ),
            CheckedStatement::exact(
                "UPDATE registry_publication_manifest_sessions SET resource_version = resource_version
                  WHERE publication_id = ?1 AND state = 'sealed'", vals![publication_id], 1,
            ),
            CheckedStatement::exact(
                "UPDATE surface_objects SET updated_at = updated_at WHERE id IN
                   (SELECT surface_object_id FROM registry_publication_objects
                     WHERE publication_id = ?1 AND object_kind = 'immutable')",
                vals![publication_id], u64::try_from(objects)?,
            ),
        ];
        locks.extend(
            self.direct_publication_provenance_locks(publication_id)
                .await?,
        );
        locks.extend([
            CheckedStatement::exact(
                "UPDATE object_placements SET observed_at = observed_at
                  WHERE surface_object_id IN (SELECT surface_object_id FROM registry_publication_objects
                    WHERE publication_id = ?1 AND object_kind = 'immutable')
                    AND placement_id IN (SELECT placement_id FROM registry_publication_placements
                      WHERE publication_id = ?1 AND required = 1)",
                vals![publication_id], u64::try_from(copies)?,
            ),
            CheckedStatement::exact(
                "UPDATE registry_publication_object_evidence SET observed_at = observed_at
                  WHERE publication_id = ?1 AND surface_object_id IN
                    (SELECT surface_object_id FROM registry_publication_objects
                      WHERE publication_id = ?1 AND object_kind = 'immutable')
                    AND placement_id IN (SELECT placement_id FROM registry_publication_placements
                      WHERE publication_id = ?1 AND required = 1)",
                vals![publication_id], u64::try_from(copies)?,
            ),
        ]);
        Ok(locks)
    }
}
