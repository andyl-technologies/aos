//! Atomic logical publication of independently guarded mirror bytes.
//!
//! A positive provider receipt is retained before this transaction. A separate
//! guard-role challenge then proves its exact held final incarnation. Catalogue
//! identity, placement provenance, logical accounting and the terminal original
//! advance together; a failed fence leaves the physical owner held for recovery.

use anyhow::{Context as _, Result, ensure};
use sha2::{Digest as _, Sha256};

use crate::backend::CheckedStatement;
use crate::mirror_guard::VerifiedMirrorGuardProof;
use crate::mirror_work::{MirrorOriginal, MirrorProgress, digest};

use super::{Database, MirrorImportRecord, SurfaceObjectRecord, SurfaceTarget, validate_key_bytes};

mod locks;
mod retirement;

#[cfg(test)]
mod tests;

/// Retains the logical charge independently of placement loss or copy retirement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SurfaceObjectUsageRecord {
    /// Catalogue object whose logical bytes were verified by a registry publisher.
    pub surface_object_id: i64,
    /// Original charged organization, or an unowned registry.
    pub org_id: Option<i64>,
    /// Exact currently charged logical byte length.
    pub accounted_bytes: i64,
    /// Optimistic version of the accounting identity.
    pub resource_version: i64,
    /// Time of the most recent successful accounting transaction.
    pub updated_at: i64,
}

impl SurfaceObjectUsageRecord {
    /// Checks a retained charge without inferring any provider or deletion effect.
    ///
    /// # Errors
    /// Returns an error for malformed identities, negative bytes or invalid clocks.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.surface_object_id > 0
                && self.org_id.is_none_or(|id| id > 0)
                && self.accounted_bytes >= 0
                && self.resource_version > 0
                && self.updated_at > 0,
            "surface object usage is invalid"
        );
        Ok(())
    }
}

impl Database {
    /// Checks current publication eligibility before issuing a new provider effect.
    ///
    /// Full source paths remain retained for recovery, but the existing catalogue
    /// contract admits at most 512 bytes. Mutable dispatch requires current
    /// independently verified immutable-copy pins and a pending pointer watermark.
    /// This method grants no provider permission; the caller issues its fresh,
    /// bounded signed control only after it succeeds.
    ///
    /// # Errors
    /// Returns an error for stale original/progress, ineligible catalogue paths,
    /// missing manifest/barriers, changed writer or database failure.
    pub async fn validate_mirror_publication_dispatch(
        &self,
        original: &MirrorOriginal,
        verified_stage: &MirrorProgress,
        publication_id: Option<&str>,
        now: i64,
    ) -> Result<()> {
        validate_key_bytes(&original.path, "mirror catalogue key", 512)?;
        verified_stage.validate(original)?;
        let verified = verified_stage
            .verified
            .as_ref()
            .context("mirror source is not verified")?;
        let retained = self
            .mirror_import(&original.job_id)
            .await?
            .context("mirror original was not admitted")?;
        ensure!(
            retained.original == *original
                && retained.progress.as_ref() == Some(verified_stage)
                && retained.state != "committed"
                && now >= retained.updated_at,
            "mirror dispatch differs from the retained current original"
        );
        self.validate_mirror_import_authority(original).await?;
        let mutable = crate::keymap::is_mutable_path(&original.path);
        ensure!(
            !mutable || publication_id.is_some(),
            "mutable mirror dispatch requires a manifest"
        );
        let object = self
            .surface_object_named(
                SurfaceTarget::Registry(original.registry_id),
                &original.path,
            )
            .await?;
        if let Some(object) = &object {
            self.verified_registry_object_accounting_eligibility(object.id)
                .await?;
        }
        let org_id = self
            .registry_by_id(original.registry_id)
            .await?
            .context("mirror registry disappeared")?
            .org_id;
        let mut statements = self
            .mirror_authority_locks(original, publication_id, object.as_ref(), org_id)
            .await?;
        if let Some(object) = &object {
            statements.push(Self::verified_registry_object_accounting_fence(
                object.id, org_id,
            ));
        }
        if let Some(publication_id) = publication_id {
            let object = object
                .as_ref()
                .context("mirror dispatch requires its manifest placeholder")?;
            ensure!(
                object.lifecycle_state == "active"
                    && object.object_kind
                        == if mutable {
                            "mutable_pointer"
                        } else {
                            "immutable"
                        },
                "mirror dispatch catalogue role differs"
            );
            statements.extend(
                self.mirror_publication_fences(
                    original,
                    publication_id,
                    object.id,
                    &verified.sha256,
                    i64::try_from(verified.object.size)?,
                    mutable,
                )
                .await?
                .statements,
            );
        }
        statements.push(journal_statement(original, verified_stage, None, now)?);
        self.backend.checked_batch(&statements).await
    }

    /// Checks whether an atomic terminal copy still matches the current catalogue.
    ///
    /// Historical journal-only rows remain available for positive ACK recovery;
    /// they cannot supply current catalogue or accounting authority. This check
    /// performs no provider lookup, backfill or mutation.
    ///
    /// # Errors
    /// Returns an error for malformed progress or a database failure.
    pub async fn mirror_committed_catalogue_matches(
        &self,
        original: &MirrorOriginal,
        progress: &MirrorProgress,
    ) -> Result<bool> {
        let commit = progress.commit_digest(original)?;
        let Some(retained) = self.mirror_import(&original.job_id).await? else {
            return Ok(false);
        };
        if retained.original != *original
            || retained.progress.as_ref() != Some(progress)
            || retained.commit_digest.as_ref() != Some(&commit)
            || retained.publication_commit_version != Some(7)
        {
            return Ok(false);
        }
        let destination = progress
            .destination
            .as_ref()
            .context("mirror final receipt absent")?;
        Ok(self.backend.query_opt(
            "SELECT 1 FROM surface_objects object
             JOIN registries registry ON registry.id = object.registry_id
             JOIN surface_object_usage usage ON usage.surface_object_id = object.id
             JOIN object_placements presence ON presence.surface_object_id = object.id
             JOIN surface_placement_effective placement ON placement.id = presence.placement_id
             JOIN bindings binding ON binding.id = placement.binding_id
             WHERE object.registry_id = ?1 AND object.object_key = ?2 AND object.lifecycle_state = 'active'
               AND object.content_hash = ?3 AND object.size = ?4
               AND usage.accounted_bytes = ?4 AND (usage.org_id = registry.org_id
                 OR (usage.org_id IS NULL AND registry.org_id IS NULL))
               AND presence.placement_id = ?5 AND presence.state = 'present'
               AND presence.observed_hash = ?3 AND presence.observed_size = ?4
               AND presence.etag = ?6 AND presence.provider_version = ?7
               AND presence.catalog_object_resource_version = object.resource_version
               AND presence.observed_placement_resource_version = placement.resource_version
               AND placement.resource_version = ?8 AND placement.write_spec_version = ?9
               AND presence.observed_write_spec_version = placement.write_spec_version
               AND placement.prefix = ?10 AND placement.effective_write_enabled = 1
               AND binding.id = ?11 AND binding.resource_version = ?12
               AND presence.observed_binding_resource_version = binding.resource_version
               AND registry.resource_version = ?13",
            &vals![original.registry_id, original.path, destination.sha256,
                i64::try_from(destination.object.size)?, original.placement_id,
                destination.object.etag, destination.object.provider_version,
                original.placement_resource_version, original.write_spec_version,
                original.placement_prefix, original.binding_id, original.binding_resource_version,
                original.registry_resource_version],
        ).await?.is_some())
    }

    /// Loads a durable logical charge without consulting current placement state.
    ///
    /// # Errors
    /// Returns an error for corrupt accounting identity or a database failure.
    pub async fn surface_object_usage(
        &self,
        surface_object_id: i64,
    ) -> Result<Option<SurfaceObjectUsageRecord>> {
        self.backend
            .query_opt(
                "SELECT org_id, accounted_bytes, resource_version, updated_at
                   FROM surface_object_usage WHERE surface_object_id = ?1",
                &vals![surface_object_id],
            )
            .await?
            .map(|row| {
                let record = SurfaceObjectUsageRecord {
                    surface_object_id,
                    org_id: row.get(0)?,
                    accounted_bytes: row.get(1)?,
                    resource_version: row.get(2)?,
                    updated_at: row.get(3)?,
                };
                record.validate()?;
                Ok(record)
            })
            .transpose()
    }

    /// Commits one exact held mirror publication and its logical charge atomically.
    ///
    /// The complete positive progress must already be retained. Mutable paths
    /// require a sealed publication and every required immutable placement;
    /// standalone immutable objects may be created by this transaction. A
    /// committed exact replay returns its original result without rebilling.
    /// Provider acknowledgement is sent only after this method succeeds.
    ///
    /// # Errors
    /// Returns an error for stale guard proof, changed original or target,
    /// missing publication barriers, quota refusal, concurrent catalogue change
    /// or database failure. Every transaction mutation rolls back together.
    pub async fn commit_mirror_import(
        &self,
        original: &MirrorOriginal,
        progress: &MirrorProgress,
        proof: &VerifiedMirrorGuardProof,
        publication_id: Option<&str>,
        now: i64,
    ) -> Result<MirrorImportRecord> {
        let started = crate::clock::Instant::now();
        let wall_started = super::unix_now();
        let commit_digest = progress.commit_digest(original)?;
        let retained = self
            .mirror_import(&original.job_id)
            .await?
            .context("mirror original was not admitted")?;
        ensure!(
            retained.original == *original && retained.progress.as_ref() == Some(progress),
            "mirror publication lacks its exact retained positive progress"
        );
        if retained.state == "committed" {
            ensure!(
                retained.commit_digest.as_ref() == Some(&commit_digest)
                    && retained.publication_commit_version == Some(7),
                "legacy mirror journal cannot attest an atomic catalogue publication"
            );
            return Ok(retained);
        }
        ensure!(
            retained.state == "published" && now >= retained.updated_at && now > 0,
            "mirror publication is not a current positive original"
        );
        proof.validate_for(original, progress, u64::try_from(now)?)?;
        self.validate_mirror_import_authority(original).await?;

        validate_key_bytes(&original.path, "mirror catalogue key", 512)?;
        let mutable = crate::keymap::is_mutable_path(&original.path);
        ensure!(
            !mutable || publication_id.is_some(),
            "mutable mirror publication requires an explicit manifest"
        );
        let destination = progress
            .destination
            .as_ref()
            .context("mirror final receipt absent")?;
        let hash = &destination.sha256;
        let size = i64::try_from(destination.object.size)?;
        let object = self
            .surface_object_named(
                SurfaceTarget::Registry(original.registry_id),
                &original.path,
            )
            .await?;
        if let Some(object) = &object {
            ensure!(
                object.lifecycle_state == "active"
                    && object.object_kind
                        == if mutable {
                            "mutable_pointer"
                        } else {
                            "immutable"
                        }
                    && (mutable
                        || (object.content_hash.as_ref() == Some(hash)
                            && object.size == Some(size))),
                "mirror catalogue identity differs from the verified bytes"
            );
        } else {
            ensure!(
                !mutable && publication_id.is_none(),
                "manifest mirror publication requires its admitted placeholder"
            );
        }
        let object_id = match &object {
            Some(object) => object.id,
            None => self
                .max_id("surface_objects")
                .await?
                .checked_add(1)
                .context("mirror catalogue id overflow")?,
        };
        let object_version = object.as_ref().map_or(Ok(1), |object| {
            object
                .resource_version
                .checked_add(1)
                .context("mirror catalogue version overflow")
        })?;
        let usage = self.surface_object_usage(object_id).await?;
        let org_id = self
            .registry_by_id(original.registry_id)
            .await?
            .context("mirror registry disappeared")?
            .org_id;
        ensure!(
            usage.as_ref().is_none_or(|usage| usage.org_id == org_id),
            "mirror logical charge changed organization"
        );

        let mut statements = self
            .mirror_authority_locks(original, publication_id, object.as_ref(), org_id)
            .await?;
        if let Some(publication_id) = publication_id {
            let publication = self
                .mirror_publication_fences(original, publication_id, object_id, hash, size, mutable)
                .await?;
            statements.extend(publication.statements);
        }
        statements.push(catalogue_statement(
            original,
            object.as_ref(),
            object_id,
            object_version,
            hash,
            size,
            publication_id,
            now,
        ));
        statements.extend(
            self.verified_registry_object_usage_statements(
                object_id,
                org_id,
                usage.as_ref(),
                size,
                now,
            )
            .await?,
        );

        if let Some(publication_id) = publication_id {
            statements.extend(Self::registry_publication_object_presence_statements(
                publication_id,
                object_id,
                original.placement_id,
                hash,
                size,
                Some(&destination.object.etag),
                now,
                Some((
                    original.placement_resource_version,
                    original.binding_resource_version,
                )),
            )?);
            statements.push(CheckedStatement::exact(
                "UPDATE object_placements SET provider_version = ?3,
                        direct_upload_session_id = NULL,
                        observed_placement_resource_version = ?7,
                        observed_write_spec_version = ?8, observed_binding_resource_version = ?9
                  WHERE surface_object_id = ?1 AND placement_id = ?2
                    AND state = 'present' AND observed_hash = ?4 AND observed_size = ?5
                    AND catalog_object_resource_version = ?6",
                vals![
                    object_id,
                    original.placement_id,
                    destination.object.provider_version,
                    hash,
                    size,
                    object_version,
                    original.placement_resource_version,
                    original.write_spec_version,
                    original.binding_resource_version
                ],
                1,
            ));
        } else {
            statements.push(CheckedStatement::unchecked(
                "DELETE FROM object_placements WHERE surface_object_id = ?1 AND placement_id = ?2",
                vals![object_id, original.placement_id],
            ));
            statements.push(CheckedStatement::exact(
                "INSERT INTO object_placements
                   (surface_object_id, registry_id, cache_id, placement_id, state,
                    observed_hash, observed_size, etag, provider_version,
                    observed_inventory_generation, observed_at, catalog_object_resource_version,
                    observed_placement_resource_version, observed_write_spec_version,
                    observed_binding_resource_version)
                 VALUES (?1, ?2, NULL, ?3, 'present', ?4, ?5, ?6, ?7, ?8, ?9, ?8, ?10, ?11, ?12)",
                vals![
                    object_id,
                    original.registry_id,
                    original.placement_id,
                    hash,
                    size,
                    destination.object.etag,
                    destination.object.provider_version,
                    object_version,
                    now,
                    original.placement_resource_version,
                    original.write_spec_version,
                    original.binding_resource_version
                ],
                1,
            ));
        }
        // Other copies with this exact immutable identity remain usable after
        // the object CAS; mismatched copies retain their older catalogue fence.
        statements.push(CheckedStatement::unchecked(
            "UPDATE object_placements SET catalog_object_resource_version = ?2
              WHERE surface_object_id = ?1 AND state = 'present'
                AND observed_hash = ?3 AND observed_size = ?4",
            vals![object_id, object_version, hash, size],
        ));
        statements.push(journal_statement(
            original,
            progress,
            Some(&commit_digest),
            now,
        )?);

        let wall_latest = super::unix_now();
        ensure!(
            wall_latest >= wall_started,
            "mirror publication clock moved backwards"
        );
        let elapsed = started.elapsed();
        let elapsed_seconds = elapsed
            .as_secs()
            .checked_add(u64::from(elapsed.subsec_nanos() > 0))
            .context("mirror publication elapsed time overflow")?;
        let elapsed_seconds = elapsed_seconds.max(u64::try_from(wall_latest - wall_started)?);
        let latest_now = u64::try_from(now)?
            .checked_add(elapsed_seconds)
            .context("mirror publication clock overflow")?;
        proof.validate_for(original, progress, latest_now)?;
        let remaining = proof.remaining_validity_seconds(latest_now)?;
        // Cancellation leaves an unknown logical outcome until the exact
        // journal is reloaded. It never releases the physical owner or ACKs.
        let transaction = self.backend.checked_batch(&statements);
        let deadline = crate::clock::sleep(std::time::Duration::from_secs(remaining));
        futures_util::pin_mut!(transaction, deadline);
        match futures_util::future::select(transaction, deadline).await {
            futures_util::future::Either::Left((result, _)) => result?,
            futures_util::future::Either::Right(((), _)) => {
                anyhow::bail!(
                    "mirror publication guard deadline elapsed with an unknown SQL outcome"
                );
            }
        }
        self.mirror_import(&original.job_id)
            .await?
            .context("committed mirror original disappeared")
    }

    /// Builds an exact logical charge shared by verified registry publishers.
    ///
    /// The caller holds current organization, quota, usage, registry and catalogue
    /// row locks before these statements, and commits positive receipt/presence
    /// evidence in the same checked batch. A placement observation never supplies
    /// an earlier charge; only the explicit retained ledger does.
    ///
    /// # Errors
    /// Rejects invalid or changed charge ownership, integer overflow, inconsistent
    /// organization totals or a database failure.
    pub(crate) async fn verified_registry_object_usage_statements(
        &self,
        object_id: i64,
        org_id: Option<i64>,
        prior: Option<&SurfaceObjectUsageRecord>,
        size: i64,
        now: i64,
    ) -> Result<Vec<CheckedStatement>> {
        ensure!(
            object_id > 0 && org_id.is_none_or(|id| id > 0) && size >= 0 && now > 0,
            "verified registry logical charge is invalid"
        );
        if let Some(prior) = prior {
            prior.validate()?;
            prior
                .resource_version
                .checked_add(1)
                .context("registry charge revision exhausted")?;
            ensure!(
                prior.surface_object_id == object_id && prior.org_id == org_id,
                "verified registry logical charge changed ownership"
            );
        } else if self.surface_object(object_id).await?.is_some() {
            self.verified_registry_object_accounting_eligibility(object_id)
                .await?;
        }
        let delta_bytes = size
            .checked_sub(prior.map_or(0, |usage| usage.accounted_bytes))
            .context("registry accounting delta overflow")?;
        let delta_objects = i64::from(prior.is_none());
        let mut statements = vec![Self::verified_registry_object_accounting_fence(
            object_id, org_id,
        )];
        if let Some(org_id) = org_id {
            let minimum_bytes = prior
                .map_or(0, |charge| charge.accounted_bytes)
                .max(if delta_bytes < 0 { -delta_bytes } else { 0 });
            let maximum_bytes = i64::MAX - delta_bytes.max(0);
            let minimum_objects = i64::from(prior.is_some());
            let maximum_objects = i64::MAX - delta_objects;
            // Independent objects serialize on the usage row and add their own
            // exact deltas. A pre-read global counter would make valid parallel
            // publications conflict even though their ledgers do not overlap.
            statements.push(CheckedStatement::exact(
                "UPDATE org_usage SET used_bytes = used_bytes + ?2,
                        object_count = object_count + ?3, updated_at = ?4
                  WHERE org_id = ?1 AND used_bytes BETWEEN ?5 AND ?6
                    AND object_count BETWEEN ?8 AND ?7
                    AND used_bytes = CAST(used_bytes AS BIGINT)
                    AND object_count = CAST(object_count AS BIGINT)
                    AND ((SELECT max_bytes FROM org_quotas WHERE org_id = ?1) IS NULL
                      OR used_bytes + ?2 <= (SELECT max_bytes FROM org_quotas WHERE org_id = ?1))
                    AND ((SELECT max_objects FROM org_quotas WHERE org_id = ?1) IS NULL
                      OR object_count + ?3 <= (SELECT max_objects FROM org_quotas WHERE org_id = ?1))",
                vals![
                    org_id,
                    delta_bytes,
                    delta_objects,
                    now,
                    minimum_bytes,
                    maximum_bytes,
                    maximum_objects,
                    minimum_objects
                ],
                1,
            ));
        }
        statements.push(match prior {
            Some(prior) => CheckedStatement::exact(
                "UPDATE surface_object_usage SET accounted_bytes = ?2,
                        resource_version = resource_version + 1, updated_at = ?3
                  WHERE surface_object_id = ?1 AND accounted_bytes = ?4 AND resource_version = ?5
                    AND (org_id = CAST(?6 AS BIGINT) OR (org_id IS NULL AND CAST(?6 AS BIGINT) IS NULL))",
                vals![object_id, size, now, prior.accounted_bytes, prior.resource_version, org_id],
                1,
            ),
            None => CheckedStatement::exact(
                "INSERT INTO surface_object_usage
                   (surface_object_id, org_id, accounted_bytes, resource_version, updated_at)
                 SELECT object.id, ?2, ?3, 1, ?4 FROM surface_objects object
                  WHERE object.id = ?1 AND object.registry_id IS NOT NULL
                    AND object.cache_id IS NULL AND object.accounting_origin_version = 7
                    AND EXISTS (SELECT 1 FROM registries registry
                      WHERE registry.id = object.registry_id
                        AND (registry.org_id = CAST(?2 AS BIGINT)
                          OR (registry.org_id IS NULL AND CAST(?2 AS BIGINT) IS NULL)))",
                vals![object_id, org_id, size, now],
                1,
            ),
        });
        Ok(statements)
    }
}

fn catalogue_statement(
    original: &MirrorOriginal,
    prior: Option<&SurfaceObjectRecord>,
    object_id: i64,
    version: i64,
    hash: &str,
    size: i64,
    publication_id: Option<&str>,
    now: i64,
) -> CheckedStatement {
    match prior {
        Some(prior) => CheckedStatement::exact(
            "UPDATE surface_objects SET content_hash = ?4, size = ?5,
                    mutable_publication_id = CAST(?6 AS VARCHAR), updated_at = ?7, resource_version = ?8
              WHERE id = ?1 AND registry_id = ?2 AND object_key = ?3
                AND resource_version = ?9 AND lifecycle_state = 'active' AND object_kind = ?10",
            vals![object_id, original.registry_id, original.path, hash, size,
                if prior.object_kind == "mutable_pointer" { publication_id } else { None },
                now, version, prior.resource_version, prior.object_kind],
            1,
        ),
        None => CheckedStatement::exact(
            "INSERT INTO surface_objects
               (id, registry_id, cache_id, object_key, object_kind, partition_key,
                content_hash, size, mutable_publication_id, created_at, updated_at,
                resource_version, accounting_origin_version)
             VALUES (?1, ?2, NULL, ?3, 'immutable', ?4, ?5, ?6, NULL, ?7, ?7, 1, 7)",
            vals![object_id, original.registry_id, original.path,
                Sha256::digest(original.path.as_bytes()).to_vec(), hash, size, now],
            1,
        ),
    }
}

fn journal_statement(
    original: &MirrorOriginal,
    progress: &MirrorProgress,
    commit: Option<&str>,
    now: i64,
) -> Result<CheckedStatement> {
    let mutation = if commit.is_some() {
        "state = 'committed', commit_digest = ?2, updated_at = ?3, publication_commit_version = 7"
    } else {
        "updated_at = updated_at"
    };
    Ok(CheckedStatement::exact(
        format!("UPDATE mirror_import_objects SET {mutation}
          WHERE job_id = ?1 AND original_digest = ?4 AND original_json = ?5
            AND ((CAST(?2 AS VARCHAR) IS NULL AND state IN ('staged_verified', 'published'))
              OR (CAST(?2 AS VARCHAR) IS NOT NULL AND state = 'published'))
            AND commit_digest IS NULL AND publication_commit_version IS NULL AND progress_json = ?6
            AND updated_at <= ?3
            AND source_path = ?7 AND source_path_digest = ?8 AND copy_operation_id = ?9
            AND EXISTS (SELECT 1 FROM registries r JOIN mirror_sources m ON m.registry_id = r.id
              WHERE r.id = mirror_import_objects.registry_id AND r.resource_version = ?10
                AND m.resource_version = ?11 AND m.upstream_url = ?12)
            AND EXISTS (SELECT 1 FROM surface_placement_effective p JOIN bindings b ON b.id = p.binding_id
              WHERE p.id = ?13 AND p.registry_id = mirror_import_objects.registry_id
                AND p.resource_version = ?14 AND p.write_spec_version = ?15 AND p.prefix = ?16
                AND p.effective_write_enabled = 1 AND b.id = ?17 AND b.resource_version = ?18
                AND b.kind = 'deployment_r2' AND b.is_instance_default = 1)"),
        vals![original.job_id, commit, now, digest(original)?, serde_json::to_string(original)?,
            serde_json::to_string(progress)?, original.path, original.source_path_digest(),
            original.copy_operation_id, original.registry_resource_version, original.mirror_resource_version,
            original.upstream_base, original.placement_id, original.placement_resource_version,
            original.write_spec_version, original.placement_prefix, original.binding_id,
            original.binding_resource_version],
        1,
    ))
}

struct PublicationFences {
    statements: Vec<CheckedStatement>,
}

impl Database {
    async fn mirror_publication_fences(
        &self,
        original: &MirrorOriginal,
        publication_id: &str,
        object_id: i64,
        hash: &str,
        size: i64,
        mutable: bool,
    ) -> Result<PublicationFences> {
        validate_key_bytes(publication_id, "mirror publication id", 64)?;
        let publication = self
            .backend
            .query_opt(
                "SELECT pub.mutation_version, head.resource_version
               FROM registry_publications pub JOIN registry_publication_state head
                 ON head.registry_id = pub.registry_id
              WHERE pub.publication_id = ?1 AND pub.registry_id = ?2
                AND pub.state IN ('preparing', 'writing_pointers')
                AND (head.current_publication_id = pub.parent_publication_id
                  OR (head.current_publication_id IS NULL AND pub.parent_publication_id IS NULL))",
                &vals![publication_id, original.registry_id],
            )
            .await?
            .context("mirror publication has a stale parent or phase")?;
        let mutation_version: i64 = publication.get(0)?;
        let head_version: i64 = publication.get(1)?;
        let mut statements = vec![CheckedStatement::exact(
            "UPDATE registry_publication_state SET resource_version = resource_version
              WHERE registry_id = ?1 AND resource_version = ?2",
            vals![original.registry_id, head_version],
            1,
        )];
        let phase = if mutable {
            "writing_pointers"
        } else {
            "preparing"
        };
        let barrier = if mutable { IMMUTABLE_BARRIER } else { "1 = 1" };
        statements.push(CheckedStatement::exact(
            format!("UPDATE registry_publications SET mutation_version = mutation_version
              WHERE publication_id = ?1 AND registry_id = ?2 AND mutation_version = ?3
                AND (state = ?4 OR (?4 = 'preparing' AND state = 'writing_pointers'))
                AND EXISTS (SELECT 1 FROM registry_publication_state head WHERE head.registry_id = ?2
                  AND (head.current_publication_id = registry_publications.parent_publication_id
                    OR (head.current_publication_id IS NULL AND registry_publications.parent_publication_id IS NULL)))
                AND EXISTS (SELECT 1 FROM registry_publication_manifest_sessions manifest
                  WHERE manifest.publication_id = ?1 AND manifest.state = 'sealed'
                    AND manifest.manifest_digest = registry_publications.manifest_digest
                    AND manifest.admitted_object_count = manifest.expected_object_count)
                AND EXISTS (SELECT 1 FROM registry_publication_objects declared
                  WHERE declared.publication_id = ?1 AND declared.surface_object_id = ?5
                    AND declared.object_kind = ?6 AND declared.expected_hash = ?7 AND declared.expected_size = ?8)
                AND EXISTS (SELECT 1 FROM registry_publication_placements placement
                  WHERE placement.publication_id = ?1 AND placement.placement_id = ?9 AND placement.required = 1
                    AND (placement.state = ?4 OR (?4 = 'preparing' AND placement.state = 'writing_pointers')))
                AND ({barrier})"),
            vals![publication_id, original.registry_id, mutation_version, phase, object_id,
                if mutable { "mutable_pointer" } else { "immutable" }, hash, size, original.placement_id],
            1,
        ));
        if mutable {
            statements.push(CheckedStatement::exact(
                "UPDATE registry_placement_publication_watermarks SET resource_version = resource_version
                  WHERE placement_id = ?2 AND pending_publication_id = ?1 AND mutable_publication_id IS NULL",
                vals![publication_id, original.placement_id], 1,
            ));
        }
        Ok(PublicationFences { statements })
    }
}

// This is the existing publication barrier, asserted inside the same checked
// transaction as the mutable catalogue and accounting update.
pub(crate) const IMMUTABLE_BARRIER: &str = "
  EXISTS (SELECT 1 FROM registry_publication_placements required
    WHERE required.publication_id = ?1 AND required.required = 1)
  AND NOT EXISTS (
    SELECT 1 FROM registry_publication_objects object
    JOIN registry_publication_placements required
      ON required.publication_id = object.publication_id AND required.required = 1
    WHERE object.publication_id = ?1 AND object.object_kind = 'immutable'
      AND NOT EXISTS (SELECT 1 FROM object_placements presence
        WHERE presence.surface_object_id = object.surface_object_id
          AND presence.placement_id = required.placement_id AND presence.state = 'present'
          AND presence.observed_hash = object.expected_hash AND presence.observed_size = object.expected_size
          AND EXISTS (SELECT 1 FROM surface_objects catalogue
            WHERE catalogue.id = object.surface_object_id AND catalogue.lifecycle_state = 'active'
              AND catalogue.content_hash = object.expected_hash AND catalogue.size = object.expected_size
              AND catalogue.resource_version = presence.catalog_object_resource_version)
          AND (presence.provider_version IS NOT NULL OR EXISTS (
            SELECT 1 FROM direct_upload_sessions source
            JOIN direct_upload_completion_receipts receipt ON receipt.session_id = source.session_id
            WHERE source.session_id = presence.direct_upload_session_id
              AND source.state = 'committed' AND source.surface_object_id = presence.surface_object_id))
          AND presence.etag IS NOT NULL
          AND EXISTS (SELECT 1 FROM surface_placement_effective placement JOIN bindings binding
            ON binding.id = placement.binding_id
            WHERE placement.id = required.placement_id AND placement.registry_id = required.registry_id
              AND placement.state = 'ready' AND placement.completeness = 'complete'
              AND placement.desired_state = 'active'
              AND placement.resource_version = presence.observed_placement_resource_version
              AND placement.write_spec_version = presence.observed_write_spec_version
              AND binding.resource_version = presence.observed_binding_resource_version)
          AND EXISTS (SELECT 1 FROM registry_publication_object_evidence evidence
            WHERE evidence.publication_id = object.publication_id
              AND evidence.surface_object_id = object.surface_object_id
              AND evidence.placement_id = required.placement_id
              AND evidence.observed_hash = presence.observed_hash
              AND evidence.observed_size = presence.observed_size
              AND evidence.strong_etag = presence.etag)))";
