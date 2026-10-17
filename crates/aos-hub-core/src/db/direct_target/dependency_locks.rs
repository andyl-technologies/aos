//! Target and immutable dependency locks held through direct logical commit.
//!
//! Parent rows precede writer topology. Dependency sets are locked with bounded
//! statement counts, including large sealed manifests, before eligibility runs.

use anyhow::{ensure, Context as _, Result};

use super::super::{Database, DirectSqlOwner, DirectUploadSessionRecord};
use crate::{backend::CheckedStatement, direct_upload::DirectUploadTarget};

impl Database {
    /// Locks the selected cache content and signing revision before metadata eligibility.
    ///
    /// # Errors
    /// Returns an error for SQL failure or a missing selected signing revision.
    pub async fn direct_cache_dependency_locks(
        &self,
        cache_id: i64,
        path: &str,
        signing: Option<&super::super::SigningKeyRecord>,
    ) -> Result<Vec<CheckedStatement>> {
        let mut statements = vec![
            CheckedStatement::unchecked(
                "UPDATE surface_objects SET updated_at = updated_at WHERE cache_id = ?1 AND object_key = ?2",
                vals![cache_id, path],
            ),
            CheckedStatement::unchecked(
                "UPDATE object_placements SET observed_at = observed_at WHERE surface_object_id IN
                  (SELECT id FROM surface_objects WHERE cache_id = ?1 AND object_key = ?2)",
                vals![cache_id, path],
            ),
            CheckedStatement::unchecked(
                "UPDATE signing_key_usages SET updated_at = updated_at WHERE purpose = 'narinfo'
                  AND consumer_stable_id = (SELECT stable_id FROM binary_caches WHERE id = ?1)",
                vals![cache_id],
            ),
        ];
        if let Some(key) = signing {
            statements.push(CheckedStatement::exact(
                "UPDATE signing_key_generations SET created_at = created_at
                  WHERE signing_key_id = ?1 AND generation = ?2 AND public_key_fingerprint = ?3",
                vals![key.stable_id, key.generation, key.public_key_fingerprint],
                1,
            ));
        }
        Ok(statements)
    }

    pub(crate) async fn direct_target_parent_locks(
        &self,
        record: &DirectUploadSessionRecord,
    ) -> Result<Vec<CheckedStatement>> {
        let exact = CheckedStatement::exact;
        Ok(match (&record.owner, &record.admission.intent.target) {
            (DirectSqlOwner::Cache { cache_id, .. }, DirectUploadTarget::CacheObject { .. }) => {
                vec![
                    exact(
                        "UPDATE binary_caches SET updated_at = updated_at WHERE id = ?1",
                        vals![cache_id],
                        1,
                    ),
                    exact(
                        "UPDATE cache_gc_state SET epoch = epoch WHERE cache_id = ?1",
                        vals![cache_id],
                        1,
                    ),
                ]
            }
            (
                DirectSqlOwner::Publication,
                DirectUploadTarget::PublicationObject {
                    publication_id,
                    surface_object_id,
                    ..
                },
            ) => {
                let row = self
                    .backend
                    .query_opt(
                        "SELECT registry_id FROM registry_publications WHERE publication_id = ?1",
                        &vals![publication_id],
                    )
                    .await?
                    .context("direct publication parent disappeared")?;
                let registry: i64 = row.get(0)?;
                vec![
                    exact("UPDATE registries SET updated_at = updated_at WHERE id = ?1", vals![registry], 1),
                    exact("UPDATE registry_publication_state SET resource_version = resource_version WHERE registry_id = ?1", vals![registry], 1),
                    exact("UPDATE registry_publications SET mutation_version = mutation_version WHERE publication_id = ?1 AND registry_id = ?2", vals![publication_id, registry], 1),
                    exact("UPDATE surface_objects SET updated_at = updated_at WHERE id = ?1 AND registry_id = ?2", vals![i64::try_from(surface_object_id.get())?, registry], 1),
                ]
            }
            (DirectSqlOwner::Oci, DirectUploadTarget::OciBlob { upload_id }) => {
                let row = self
                    .backend
                    .query_opt(
                        "SELECT registry_id FROM oci_upload_sessions WHERE id = ?1",
                        &vals![upload_id],
                    )
                    .await?
                    .context("direct OCI parent disappeared")?;
                vec![exact(
                    "UPDATE registries SET updated_at = updated_at WHERE id = ?1",
                    vals![row.get::<i64>(0)?],
                    1,
                )]
            }
            _ => anyhow::bail!("direct original target owner differs"),
        })
    }

    pub(crate) async fn direct_target_dependency_locks(
        &self,
        record: &DirectUploadSessionRecord,
    ) -> Result<Vec<CheckedStatement>> {
        let DirectUploadTarget::PublicationObject {
            publication_id,
            surface_object_id,
            ..
        } = &record.admission.intent.target
        else {
            return Ok(Vec::new());
        };
        let row = self.backend.query_opt(
            "SELECT object_kind FROM registry_publication_objects WHERE publication_id = ?1 AND surface_object_id = ?2",
            &vals![publication_id, i64::try_from(surface_object_id.get())?],
        ).await?.context("direct publication original disappeared")?;
        if row.get::<String>(0)? != "mutable_pointer" {
            return Ok(Vec::new());
        }
        self.direct_publication_dependency_locks(publication_id)
            .await
    }

    /// Locks every required immutable dependency before the pointer eligibility fence.
    ///
    /// The sealed manifest and exact row counts prevent missing rows or concurrent
    /// manifest edits from reducing the dependency set. Eligibility still checks
    /// current content and presence after these locks; a lock is not evidence.
    ///
    /// # Errors
    /// Rejects an absent or invalid manifest, missing dependencies or SQL failure.
    pub async fn direct_publication_dependency_locks(
        &self,
        publication: &str,
    ) -> Result<Vec<CheckedStatement>> {
        let counts = self.backend.query_opt(
            "SELECT (SELECT COUNT(*) FROM registry_publication_objects WHERE publication_id = ?1 AND object_kind = 'immutable'),
                    (SELECT COUNT(*) FROM registry_publication_placements WHERE publication_id = ?1 AND required = 1)",
            &vals![publication],
        ).await?.context("direct publication dependency set disappeared")?;
        let objects: i64 = counts.get(0)?;
        let placements: i64 = counts.get(1)?;
        ensure!(
            objects >= 0 && (1..=64).contains(&placements),
            "direct publication dependency set is invalid"
        );
        let copies = objects
            .checked_mul(placements)
            .context("direct dependency count overflow")?;
        let mut locks = vec![
            CheckedStatement::exact("UPDATE registry_publication_placements SET observed_at = observed_at WHERE publication_id = ?1 AND required = 1", vals![publication], u64::try_from(placements)?),
            CheckedStatement::exact("UPDATE registry_publication_objects SET expected_size = expected_size WHERE publication_id = ?1 AND object_kind = 'immutable'", vals![publication], u64::try_from(objects)?),
            CheckedStatement::exact("UPDATE registry_publication_manifest_sessions SET resource_version = resource_version WHERE publication_id = ?1 AND state = 'sealed'", vals![publication], 1),
            CheckedStatement::exact("UPDATE surface_objects SET updated_at = updated_at WHERE id IN (SELECT surface_object_id FROM registry_publication_objects WHERE publication_id = ?1 AND object_kind = 'immutable')", vals![publication], u64::try_from(objects)?),
        ];
        locks.extend(
            self.direct_publication_provenance_locks(publication)
                .await?,
        );
        locks.extend([
            CheckedStatement::exact("UPDATE object_placements SET observed_at = observed_at WHERE surface_object_id IN (SELECT surface_object_id FROM registry_publication_objects WHERE publication_id = ?1 AND object_kind = 'immutable') AND placement_id IN (SELECT placement_id FROM registry_publication_placements WHERE publication_id = ?1 AND required = 1)", vals![publication], u64::try_from(copies)?),
            CheckedStatement::exact("UPDATE registry_publication_object_evidence SET observed_at = observed_at WHERE publication_id = ?1 AND surface_object_id IN (SELECT surface_object_id FROM registry_publication_objects WHERE publication_id = ?1 AND object_kind = 'immutable') AND placement_id IN (SELECT placement_id FROM registry_publication_placements WHERE publication_id = ?1 AND required = 1)", vals![publication], u64::try_from(copies)?),
            CheckedStatement::exact("UPDATE registry_placement_publication_watermarks SET observed_at = observed_at WHERE placement_id IN (SELECT placement_id FROM registry_publication_placements WHERE publication_id = ?1 AND required = 1)", vals![publication], u64::try_from(placements)?),
        ]);
        Ok(locks)
    }
}
