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
mod tests;

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
            created_at,
            updated_at,
        })
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
                    state, commit_digest, created_at, updated_at
               FROM mirror_import_objects WHERE job_id = ?1",
                &vals![job_id],
            )
            .await?
            .map(|row| {
                MirrorImportRecord::decode(
                    &row.get::<String>(0)?,
                    row.get(1)?,
                    &row.get::<String>(2)?,
                    &row.get::<String>(3)?,
                    row.get::<Option<String>>(4)?.as_deref(),
                    &row.get::<String>(5)?,
                    row.get::<Option<String>>(6)?.as_deref(),
                    row.get(7)?,
                    row.get(8)?,
                )
            })
            .transpose()
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
        ensure!(now > 0, "mirror admission time is invalid");
        let original_json = serde_json::to_string(original)?;
        ensure!(
            original_json.len() <= 64 * 1024,
            "mirror original exceeds its bound"
        );
        let original_digest = digest(original)?;
        self.backend.execute(
            "INSERT INTO mirror_import_objects
                 (job_id, registry_id, original_digest, original_json, state, created_at, updated_at)
             SELECT ?1, ?2, ?3, ?4, 'admitted', ?5, ?5
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
            &vals![original.job_id, original.registry_id, original_digest, original_json, now,
                original.registry_resource_version, original.mirror_resource_version, original.upstream_base,
                original.placement_id, original.placement_resource_version, original.write_spec_version,
                original.placement_prefix, original.binding_id, original.binding_resource_version],
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
