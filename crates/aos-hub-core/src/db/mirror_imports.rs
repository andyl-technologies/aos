//! Retained mirror originals and positive per-object progress in Native SQL.
//!
//! No lease, expiry or ordinary scheduler failure deletes these records. A
//! Worker guard owns physical uncertainty; SQL advances only exact positive
//! evidence under the current writer, registry and binding fences.

use anyhow::{ensure, Context as _, Result};

use crate::backend::CheckedStatement;
use crate::mirror_work::{digest, MirrorOriginal, MirrorProgress};

use super::{Database, SurfaceTarget};

#[cfg(test)]
pub(crate) mod tests;

/// Holds one validated system-of-record mirror original and its observations.
#[derive(Clone, Debug)]
pub struct MirrorImportRecord {
    /// Complete immutable source and destination selection.
    pub original: MirrorOriginal,
    /// Positive bounded Worker observations, if any.
    pub progress: Option<MirrorProgress>,
    /// Logical phase independent of any scheduler lease.
    pub state: String,
    /// Exact committed original/final evidence digest, if terminal.
    pub commit_digest: Option<String>,
    /// Generation of an atomic catalogue/accounting commit; absent for legacy journals.
    pub publication_commit_version: Option<i64>,
    /// Original SQL admission time.
    pub created_at: i64,
    /// Time of the most recent positive observation.
    pub updated_at: i64,
}

impl MirrorImportRecord {
    /// Decodes and validates one stored row before lifecycle or snapshot use.
    ///
    /// # Errors
    /// Returns an error for a changed original/digest or inconsistent progress.
    #[allow(clippy::too_many_arguments)]
    pub fn decode(
        job_id: &str,
        registry_id: i64,
        original_digest: &str,
        original_json: &str,
        progress_json: Option<&str>,
        state: &str,
        commit_digest: Option<&str>,
        created_at: i64,
        updated_at: i64,
    ) -> Result<Self> {
        ensure!(
            original_json.len() <= 64 * 1024,
            "mirror original exceeds its stored bound"
        );
        ensure!(
            progress_json.is_none_or(|value| value.len() <= 256 * 1024),
            "mirror progress exceeds its stored bound"
        );
        let original: MirrorOriginal = serde_json::from_str(original_json)?;
        original.validate()?;
        ensure!(
            original.job_id == job_id
                && original.registry_id == registry_id
                && digest(&original)? == original_digest
                && serde_json::to_string(&original)? == original_json,
            "stored mirror original changed identity or representation"
        );
        let progress: Option<MirrorProgress> =
            progress_json.map(serde_json::from_str).transpose()?;
        if let Some(progress) = &progress {
            progress.validate(&original)?;
            ensure!(
                Some(serde_json::to_string(progress)?).as_deref() == progress_json,
                "stored mirror progress is noncanonical"
            );
        }
        let expected_state = match progress.as_ref() {
            Some(progress) if progress.destination.is_some() && commit_digest.is_some() => {
                "committed"
            }
            Some(progress) if progress.destination.is_some() => "published",
            Some(progress) if progress.verified.is_some() => "staged_verified",
            _ => "admitted",
        };
        ensure!(
            state == expected_state && created_at > 0 && updated_at >= created_at,
            "stored mirror lifecycle is inconsistent"
        );
        if let Some(commit) = commit_digest {
            ensure!(
                progress
                    .as_ref()
                    .context("mirror commit has no progress")?
                    .commit_digest(&original)?
                    == commit,
                "stored mirror commit changed its positive proof"
            );
        }
        Ok(Self {
            original,
            progress,
            state: state.into(),
            commit_digest: commit_digest.map(str::to_owned),
            publication_commit_version: None,
            created_at,
            updated_at,
        })
    }

    /// Validates generation 6 indexed identity against the complete original.
    ///
    /// # Errors
    /// Returns an error for missing backfill, changed paths/digests or operation.
    pub fn validate_index(
        &self,
        source_path: Option<&str>,
        source_path_digest: Option<&str>,
        copy_operation_id: Option<&str>,
    ) -> Result<()> {
        ensure!(
            source_path == Some(self.original.path.as_str())
                && source_path_digest == Some(self.original.source_path_digest().as_str())
                && copy_operation_id == self.original.copy_operation_id.as_deref(),
            "mirror indexed identity changed its retained original"
        );
        Ok(())
    }

    /// Checks whether a terminal qualifier belongs to the atomic publication contract.
    ///
    /// # Errors
    /// Returns an error for a future version or a qualifier on nonterminal progress.
    pub fn validate_publication_commit_version(&self, version: Option<i64>) -> Result<()> {
        ensure!(
            version.is_none_or(|version| version == 7 && self.state == "committed"),
            "mirror logical publication qualifier differs"
        );
        Ok(())
    }
}

impl Database {
    /// Deletes one exact mirror configuration without recycling parent authority.
    ///
    /// # Errors
    /// Returns an error while an original is retained or the transactional
    /// source/registry generation fence changes during deletion.
    pub(super) async fn delete_mirror_configuration(
        &self,
        registry_id: i64,
        expected_source_version: Option<i64>,
    ) -> Result<bool> {
        let Some(source) = self.registry_mirror(registry_id).await? else {
            return Ok(false);
        };
        if expected_source_version.is_some_and(|version| version != source.resource_version) {
            return Ok(false);
        }
        let registry = self
            .registry_by_id(registry_id)
            .await?
            .context("mirror registry disappeared")?;
        ensure!(
            self.backend
                .query_opt(
                    "SELECT 1 FROM mirror_import_objects WHERE registry_id = ?1 LIMIT 1",
                    &vals![registry_id]
                )
                .await?
                .is_none(),
            "mirror configuration retains an unresolved or unacknowledged original"
        );
        // The parent generation survives deletion/recreation of the source
        // row. Even an admission racing this transaction cannot obtain fresh
        // authority for its older registry pin after this commit.
        self.backend
            .checked_batch(&[
                CheckedStatement::exact(
                    "UPDATE registries SET resource_version = resource_version + 1, updated_at = ?3
                   WHERE id = ?1 AND resource_version = ?2
                     AND NOT EXISTS (SELECT 1 FROM mirror_import_objects WHERE registry_id = ?1)",
                    vals![registry_id, registry.resource_version, super::unix_now()],
                    1,
                ),
                CheckedStatement::exact(
                    "DELETE FROM mirror_sources WHERE registry_id = ?1 AND resource_version = ?2
                   AND NOT EXISTS (SELECT 1 FROM mirror_import_objects WHERE registry_id = ?1)",
                    vals![registry_id, source.resource_version],
                    1,
                ),
            ])
            .await?;
        Ok(true)
    }

    /// Loads an exact mirror original with independently validated progress.
    ///
    /// # Errors
    /// Returns an error for corrupt retained state or SQL failure.
    pub async fn mirror_import(&self, job_id: &str) -> Result<Option<MirrorImportRecord>> {
        self.backend
            .query_opt(
                "SELECT job_id, registry_id, original_digest, original_json, progress_json,
                    state, commit_digest, created_at, updated_at, source_path, source_path_digest, copy_operation_id,
                    publication_commit_version
               FROM mirror_import_objects WHERE job_id = ?1",
                &vals![job_id],
            )
            .await?
            .map(|row| {
                let mut record = MirrorImportRecord::decode(
                    &row.get::<String>(0)?,
                    row.get(1)?,
                    &row.get::<String>(2)?,
                    &row.get::<String>(3)?,
                    row.get::<Option<String>>(4)?.as_deref(),
                    &row.get::<String>(5)?,
                    row.get::<Option<String>>(6)?.as_deref(),
                    row.get(7)?,
                    row.get(8)?,
                )?;
                record.validate_index(
                    row.get::<Option<String>>(9)?.as_deref(),
                    row.get::<Option<String>>(10)?.as_deref(),
                    row.get::<Option<String>>(11)?.as_deref(),
                )?;
                record.publication_commit_version = row.get(12)?;
                record.validate_publication_commit_version(record.publication_commit_version)?;
                Ok(record)
            })
            .transpose()
    }

    /// Loads the single retained business operation for an exact registry path.
    ///
    /// # Errors
    /// Returns an error for a changed index or malformed retained original.
    pub async fn mirror_import_for_path(
        &self,
        registry_id: i64,
        path: &str,
    ) -> Result<Option<MirrorImportRecord>> {
        use sha2::{Digest as _, Sha256};
        let mut hash = Sha256::new();
        hash.update(b"aos.hub.mirror-source-path.v1\0");
        hash.update(path.as_bytes());
        let digest = hex::encode(hash.finalize());
        let row = self
            .backend
            .query_opt(
                "SELECT job_id FROM mirror_import_objects WHERE registry_id = ?1 AND source_path_digest = ?2",
                &vals![registry_id, digest],
            )
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let record = self
            .mirror_import(&row.get::<String>(0)?)
            .await?
            .context("mirror path index lost its original")?;
        ensure!(
            record.original.path == path && record.original.registry_id == registry_id,
            "mirror path index changed exact source identity"
        );
        Ok(Some(record))
    }

    /// Backfills legacy exact path indexes before any initialized DB is exposed.
    ///
    /// Each bounded keyset page is decoded through the historical typed model.
    /// A conflict leaves all originals intact and refuses startup; a restart
    /// repeats only missing metadata indexes, never provider operations.
    pub(super) async fn backfill_mirror_import_index(&self) -> Result<()> {
        let mut cursor = String::new();
        loop {
            let rows = self
                .backend
                .query(
                    "SELECT job_id, registry_id, original_digest, original_json, progress_json, state, commit_digest, created_at, updated_at, copy_operation_id FROM mirror_import_objects WHERE source_path IS NULL AND job_id > ?1 ORDER BY job_id LIMIT 128",
                    &vals![cursor],
                )
                .await?;
            if rows.is_empty() {
                break;
            }
            let mut statements = Vec::with_capacity(rows.len());
            for row in rows {
                let record = MirrorImportRecord::decode(
                    &row.get::<String>(0)?,
                    row.get(1)?,
                    &row.get::<String>(2)?,
                    &row.get::<String>(3)?,
                    row.get::<Option<String>>(4)?.as_deref(),
                    &row.get::<String>(5)?,
                    row.get::<Option<String>>(6)?.as_deref(),
                    row.get(7)?,
                    row.get(8)?,
                )?;
                ensure!(
                    record.original.copy_operation_id.is_none()
                        && row.get::<Option<String>>(9)?.is_none(),
                    "mirror generation 6 operation is missing its atomic source index"
                );
                cursor = record.original.job_id.clone();
                statements.push(CheckedStatement::exact(
                    "UPDATE mirror_import_objects SET source_path = ?2, source_path_digest = ?3, copy_operation_id = ?4 WHERE job_id = ?1 AND original_digest = ?5 AND source_path IS NULL",
                    vals![
                        record.original.job_id,
                        record.original.path,
                        record.original.source_path_digest(),
                        record.original.copy_operation_id,
                        digest(&record.original)?
                    ],
                    1,
                ));
            }
            self.backend.checked_batch(&statements).await?;
        }
        Ok(())
    }

    /// Checks the original against current Native mirror and writer authority.
    ///
    /// # Errors
    /// Returns an error when source configuration or any destination pin changed.
    pub async fn validate_mirror_import_authority(&self, original: &MirrorOriginal) -> Result<()> {
        original.validate()?;
        let registry = self
            .registry_by_id(original.registry_id)
            .await?
            .context("mirror registry disappeared")?;
        let source = self
            .mirror_source(original.registry_id)
            .await?
            .context("mirror source disappeared")?;
        let source_version = self
            .registry_mirror(original.registry_id)
            .await?
            .context("mirror configuration disappeared")?
            .resource_version;
        let writer = self
            .reconciled_surface_writer(SurfaceTarget::Registry(original.registry_id))
            .await?;
        let binding = self
            .binding(writer.binding_id)
            .await?
            .context("mirror binding disappeared")?;
        ensure!(
            registry.resource_version == original.registry_resource_version
                && source_version == original.mirror_resource_version
                && source.upstream_url == original.upstream_base
                && writer.id == original.placement_id
                && writer.resource_version == original.placement_resource_version
                && writer.write_spec_version == original.write_spec_version
                && writer.prefix == original.placement_prefix
                && binding.id == original.binding_id
                && binding.resource_version == original.binding_resource_version
                && binding.kind == "deployment_r2"
                && binding.is_instance_default,
            "mirror original no longer has current Native authority"
        );
        Ok(())
    }

    /// Retains one new original before the first storage effect.
    ///
    /// # Errors
    /// Returns an error for stale authority, substituted identity or SQL failure.
    pub async fn admit_mirror_import(
        &self,
        original: &MirrorOriginal,
        now: i64,
    ) -> Result<MirrorImportRecord> {
        self.validate_mirror_import_authority(original).await?;
        ensure!(
            original.copy_operation_id.is_some(),
            "fresh mirror admission requires a retained Native business operation"
        );
        ensure!(now > 0, "mirror admission time is invalid");
        let original_json = serde_json::to_string(original)?;
        ensure!(
            original_json.len() <= 64 * 1024,
            "mirror original exceeds its bound"
        );
        let original_digest = digest(original)?;
        self.backend.execute(
            "INSERT INTO mirror_import_objects
                 (job_id, registry_id, original_digest, original_json, state, created_at, updated_at, source_path, source_path_digest, copy_operation_id)
             SELECT ?1, ?2, ?3, ?4, 'admitted', ?5, ?5, ?15, ?16, ?17
             WHERE EXISTS (SELECT 1 FROM registries r JOIN mirror_sources m ON m.registry_id = r.id
                           WHERE r.id = ?2 AND r.resource_version = ?6
                             AND m.resource_version = ?7 AND m.upstream_url = ?8)
               AND EXISTS (SELECT 1 FROM surface_placement_effective p JOIN bindings b ON b.id = p.binding_id
                           WHERE p.id = ?9 AND p.registry_id = ?2
                             AND p.resource_version = ?10 AND p.write_spec_version = ?11
                             AND p.prefix = ?12 AND p.effective_write_enabled = 1
                             AND b.id = ?13 AND b.resource_version = ?14
                             AND b.kind = 'deployment_r2' AND b.is_instance_default = 1)
             ON CONFLICT(job_id) DO NOTHING",
            &vals![
                original.job_id,
                original.registry_id,
                original_digest,
                original_json,
                now,
                original.registry_resource_version,
                original.mirror_resource_version,
                original.upstream_base,
                original.placement_id,
                original.placement_resource_version,
                original.write_spec_version,
                original.placement_prefix,
                original.binding_id,
                original.binding_resource_version,
                original.path,
                original.source_path_digest(),
                original.copy_operation_id
            ],
        ).await?;
        let retained = self
            .mirror_import(&original.job_id)
            .await?
            .context("mirror original admission disappeared")?;
        ensure!(
            retained.original == *original,
            "mirror job identity already owns another original"
        );
        Ok(retained)
    }

    /// Advances only positive evidence under an atomic current-writer SQL fence.
    ///
    /// # Errors
    /// Returns an error for changed originals, regressing progress, stale pins or
    /// a concurrent observation. Failure retains the original and guard owner.
    pub async fn record_mirror_import_progress(
        &self,
        original: &MirrorOriginal,
        progress: &MirrorProgress,
        commit: bool,
        now: i64,
    ) -> Result<MirrorImportRecord> {
        progress.validate(original)?;
        let retained = self
            .mirror_import(&original.job_id)
            .await?
            .context("mirror original was not admitted")?;
        ensure!(
            retained.original == *original && now >= retained.updated_at,
            "mirror observation changed original or clock"
        );
        if let Some(prior) = &retained.progress {
            ensure!(
                prior
                    .upstream_etag
                    .as_ref()
                    .is_none_or(|etag| progress.upstream_etag.as_ref() == Some(etag)),
                "mirror observation replaced the original upstream incarnation"
            );
            ensure!(
                progress.stage_parts.starts_with(&prior.stage_parts)
                    && progress
                        .destination_parts
                        .starts_with(&prior.destination_parts)
                    && prior
                        .stage_upload_id
                        .as_ref()
                        .is_none_or(|value| progress.stage_upload_id.as_ref() == Some(value))
                    && prior
                        .stage_object
                        .as_ref()
                        .is_none_or(|value| progress.stage_object.as_ref() == Some(value))
                    && prior
                        .verified
                        .as_ref()
                        .is_none_or(|value| progress.verified.as_ref() == Some(value))
                    && prior
                        .destination_upload_id
                        .as_ref()
                        .is_none_or(|value| progress.destination_upload_id.as_ref() == Some(value))
                    && prior
                        .destination
                        .as_ref()
                        .is_none_or(|value| progress.destination.as_ref() == Some(value)),
                "mirror observation regressed or replaced a positive original"
            );
        }
        let progress_json = serde_json::to_string(progress)?;
        ensure!(
            progress_json.len() <= 256 * 1024,
            "mirror progress exceeds its bound"
        );
        let prior_json = retained
            .progress
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let commit_digest = if commit {
            Some(progress.commit_digest(original)?)
        } else {
            None
        };
        let state = if commit {
            "committed"
        } else if progress.destination.is_some() {
            "published"
        } else if progress.verified.is_some() {
            "staged_verified"
        } else {
            "admitted"
        };
        if retained.state == "committed" {
            ensure!(
                retained.progress.as_ref() == Some(progress)
                    && retained.commit_digest == commit_digest,
                "mirror terminal replay changed its proof"
            );
            return Ok(retained);
        }
        ensure!(
            !commit,
            "mirror final publication requires independent guard proof and atomic catalogue accounting"
        );
        self.validate_mirror_import_authority(original).await?;
        self.backend.checked_batch(&[CheckedStatement::exact(
            "UPDATE mirror_import_objects SET progress_json = ?2, state = ?3,
                    commit_digest = ?4, updated_at = ?5
              WHERE job_id = ?1 AND original_digest = ?6
                AND (progress_json = ?7 OR (progress_json IS NULL AND ?7 IS NULL))
                AND EXISTS (SELECT 1 FROM registries r JOIN mirror_sources m ON m.registry_id = r.id
                            WHERE r.id = mirror_import_objects.registry_id
                              AND r.resource_version = ?8 AND m.resource_version = ?15
                              AND m.upstream_url = ?16)
                AND EXISTS (SELECT 1 FROM surface_placement_effective p JOIN bindings b ON b.id = p.binding_id
                            WHERE p.id = ?9 AND p.registry_id = mirror_import_objects.registry_id
                              AND p.resource_version = ?10 AND p.write_spec_version = ?11
                              AND p.prefix = ?12 AND p.effective_write_enabled = 1
                              AND b.id = ?13 AND b.resource_version = ?14
                              AND b.kind = 'deployment_r2' AND b.is_instance_default = 1)",
            vals![original.job_id, progress_json, state, commit_digest, now, digest(original)?, prior_json,
                original.registry_resource_version, original.placement_id, original.placement_resource_version,
                original.write_spec_version, original.placement_prefix, original.binding_id, original.binding_resource_version,
                original.mirror_resource_version, original.upstream_base],
            1,
        )]).await?;
        self.mirror_import(&original.job_id)
            .await?
            .context("mirror observation disappeared")
    }

    /// Retires one committed SQL original after its exact positive guard ACK.
    ///
    /// The controller calls this only after the acknowledged storage-work
    /// response proves that the guard archived the original and final receipt
    /// before releasing the owner. An absent response, timeout or scheduler
    /// lease never reaches this method. Retained physical receipts outlive the
    /// SQL row; unresolved SQL rows continue to restrict registry deletion.
    ///
    /// # Errors
    /// Returns an error unless the exact original and final proof were committed,
    /// or if another state transition races this exact retirement.
    pub async fn retire_acknowledged_mirror_import(
        &self,
        original: &MirrorOriginal,
        acknowledged_progress: &MirrorProgress,
    ) -> Result<()> {
        let commit = acknowledged_progress.commit_digest(original)?;
        let Some(retained) = self.mirror_import(&original.job_id).await? else {
            return Ok(());
        };
        ensure!(
            retained.original == *original
                && retained.state == "committed"
                && retained.progress.as_ref() == Some(acknowledged_progress)
                && retained.commit_digest.as_ref() == Some(&commit),
            "mirror retirement lacks exact committed guard proof"
        );
        self.backend
            .checked_batch(&[CheckedStatement::exact(
                "DELETE FROM mirror_import_objects WHERE job_id = ?1 AND original_digest = ?2
               AND state = 'committed' AND commit_digest = ?3 AND progress_json = ?4",
                vals![
                    original.job_id,
                    digest(original)?,
                    commit,
                    serde_json::to_string(acknowledged_progress)?
                ],
                1,
            )])
            .await?;
        Ok(())
    }
}
