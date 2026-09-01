//! Per-registry leases and generation fences for expensive index builds.
//!
//! The existing `registry_index.generation` row is the atomic visible pointer.
//! This module records the base and intended next generation before provider
//! reads begin, preventing periodic and publication-triggered jobs from walking
//! the same registry concurrently.

use anyhow::{bail, Context as _, Result};

use crate::backend::CheckedStatement;

use super::Database;

/// Outcome of claiming one registry's next index generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryIndexBuildClaim {
    /// The caller owns the exact next generation.
    Acquired {
        /// Random token fencing terminal writes.
        owner_token: String,
        /// Generation visible when the build began.
        base_generation: i64,
        /// Only generation this build may publish.
        target_generation: i64,
    },
    /// Another unexpired build owns this registry.
    Busy,
    /// This exact stable build identity already reached a terminal state.
    AlreadyFinished,
}

impl Database {
    /// Claims one registry's exact next index generation.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identity/timing, a missing registry or
    /// index state, generation overflow, or persistence failure.
    pub async fn claim_registry_index_build(
        &self,
        registry_id: i64,
        build_id: &str,
        now: i64,
        lease_seconds: i64,
    ) -> Result<RegistryIndexBuildClaim> {
        validate_hex(build_id, "registry index build id", &[32, 64])?;
        if registry_id <= 0 || now < 0 || !(1..=900).contains(&lease_seconds) {
            bail!("registry index build claim is invalid");
        }
        let index_status = self
            .index_status(registry_id)
            .await?
            .context("registry has no index state")?;
        let generation = index_status.generation;
        let target_generation = generation
            .checked_add(1)
            .context("registry index generation overflowed")?;
        let lease_expires_at = now
            .checked_add(lease_seconds)
            .context("registry index build lease overflowed")?;
        let owner_token = uuid::Uuid::new_v4().simple().to_string();

        let inserted = self
            .backend
            .execute(
                "INSERT INTO registry_index_build_heads
                   (registry_id, build_id, owner_token, base_generation,
                    target_generation, state, lease_expires_at, started_at,
                    finished_at, content_digest, error, resource_version)
                 SELECT ?1, ?2, ?3, ?4, ?5, 'building', ?6, ?7,
                        NULL, NULL, NULL, 1
                   FROM registries WHERE id = ?1
                 ON CONFLICT(registry_id) DO NOTHING",
                &vals![
                    registry_id,
                    build_id,
                    owner_token,
                    generation,
                    target_generation,
                    lease_expires_at,
                    now
                ],
            )
            .await?;
        if inserted == 1 {
            return Ok(RegistryIndexBuildClaim::Acquired {
                owner_token,
                base_generation: generation,
                target_generation,
            });
        }
        if inserted != 0 {
            bail!("registry index build insert changed an unexpected number of rows");
        }
        let row = self
            .backend
            .query_opt(
                "SELECT build_id, base_generation, target_generation, state,
                        lease_expires_at, resource_version
                   FROM registry_index_build_heads WHERE registry_id = ?1",
                &vals![registry_id],
            )
            .await?
            .context("registry index build head disappeared")?;
        let existing_build_id: String = row.get(0)?;
        let existing_base: i64 = row.get(1)?;
        let existing_target: i64 = row.get(2)?;
        let state: String = row.get(3)?;
        let existing_lease: Option<i64> = row.get(4)?;
        let resource_version: i64 = row.get(5)?;
        if existing_build_id == build_id && matches!(state.as_str(), "published" | "no_change") {
            return Ok(RegistryIndexBuildClaim::AlreadyFinished);
        }
        if existing_build_id == build_id && generation >= existing_target {
            let changed = self
                .backend
                .execute(
                    "UPDATE registry_index_build_heads
                        SET state = 'published', owner_token = NULL,
                            lease_expires_at = NULL, finished_at = ?3,
                            content_digest = ?4, error = NULL,
                            resource_version = resource_version + 1
                      WHERE registry_id = ?1 AND build_id = ?2
                        AND state = 'building' AND target_generation <= ?5",
                    &vals![
                        registry_id,
                        build_id,
                        now,
                        index_status.content_digest,
                        generation
                    ],
                )
                .await?;
            if changed != 1 {
                return Ok(RegistryIndexBuildClaim::Busy);
            }
            return Ok(RegistryIndexBuildClaim::AlreadyFinished);
        }
        if state == "building" && existing_lease.is_some_and(|lease| lease > now) {
            return Ok(RegistryIndexBuildClaim::Busy);
        }

        let (base_generation, target_generation) = if existing_build_id == build_id {
            (existing_base, existing_target)
        } else {
            (generation, target_generation)
        };
        let changed = self
            .backend
            .execute(
                "UPDATE registry_index_build_heads
                    SET build_id = ?2, owner_token = ?3,
                        base_generation = ?4, target_generation = ?5,
                        state = 'building', lease_expires_at = ?6,
                        started_at = ?7, finished_at = NULL,
                        content_digest = NULL, error = NULL,
                        resource_version = resource_version + 1
                  WHERE registry_id = ?1 AND resource_version = ?8
                    AND (state <> 'building' OR lease_expires_at <= ?7)",
                &vals![
                    registry_id,
                    build_id,
                    owner_token,
                    base_generation,
                    target_generation,
                    lease_expires_at,
                    now,
                    resource_version
                ],
            )
            .await?;
        if changed == 0 {
            return Ok(RegistryIndexBuildClaim::Busy);
        }
        if changed != 1 {
            bail!("registry index build claim changed an unexpected number of rows");
        }
        Ok(RegistryIndexBuildClaim::Acquired {
            owner_token,
            base_generation,
            target_generation,
        })
    }

    /// Completes a build against the generation it exclusively claimed.
    ///
    /// A successful no-op is terminal when the visible generation remains at
    /// the base. A publication is terminal only at the exact target.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale claim, unexpected visible generation,
    /// malformed digest, or persistence failure.
    pub async fn complete_registry_index_build(
        &self,
        registry_id: i64,
        build_id: &str,
        owner_token: &str,
        base_generation: i64,
        target_generation: i64,
        actual_generation: i64,
        content_digest: Option<&str>,
        now: i64,
    ) -> Result<()> {
        validate_hex(build_id, "registry index build id", &[32, 64])?;
        validate_hex(owner_token, "registry index build owner token", &[32])?;
        if let Some(digest) = content_digest {
            validate_hex(digest, "registry index content digest", &[64, 128])?;
        }
        let state = if actual_generation == target_generation {
            if content_digest.is_none() {
                bail!("published registry index build requires a content digest");
            }
            "published"
        } else if actual_generation == base_generation {
            "no_change"
        } else {
            bail!("registry index build completed at an unexpected generation");
        };
        self.backend
            .checked_batch(&[CheckedStatement::exact(
                "UPDATE registry_index_build_heads
                    SET state = ?6, owner_token = NULL, lease_expires_at = NULL,
                        finished_at = ?7, content_digest = ?8, error = NULL,
                        resource_version = resource_version + 1
                  WHERE registry_id = ?1 AND build_id = ?2
                    AND owner_token = ?3 AND state = 'building'
                    AND base_generation = ?4 AND target_generation = ?5
                    AND EXISTS (SELECT 1 FROM registry_index current
                      WHERE current.registry_id = ?1
                        AND current.generation = ?9)",
                vals![
                    registry_id,
                    build_id,
                    owner_token,
                    base_generation,
                    target_generation,
                    state,
                    now,
                    content_digest,
                    actual_generation
                ],
                1,
            )])
            .await
    }

    /// Records a failed build and releases its generation lease.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed evidence, a stale claim, or persistence
    /// failure.
    pub async fn fail_registry_index_build(
        &self,
        registry_id: i64,
        build_id: &str,
        owner_token: &str,
        error: &str,
        now: i64,
    ) -> Result<()> {
        validate_hex(build_id, "registry index build id", &[32, 64])?;
        validate_hex(owner_token, "registry index build owner token", &[32])?;
        if error.is_empty() || error.len() > 8_192 || now < 0 {
            bail!("registry index build failure evidence is invalid");
        }
        self.backend
            .checked_batch(&[CheckedStatement::exact(
                "UPDATE registry_index_build_heads
                    SET state = 'failed', owner_token = NULL,
                        lease_expires_at = NULL, finished_at = ?5,
                        content_digest = NULL, error = ?4,
                        resource_version = resource_version + 1
                  WHERE registry_id = ?1 AND build_id = ?2
                    AND owner_token = ?3 AND state = 'building'",
                vals![registry_id, build_id, owner_token, error, now],
                1,
            )])
            .await
    }
}

fn validate_hex(value: &str, label: &str, lengths: &[usize]) -> Result<()> {
    if !lengths.contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} is malformed");
    }
    Ok(())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn registry_builds_exclude_competitors_and_record_noops() {
        let db = Database::open_in_memory().await.unwrap();
        let registry_id = db
            .register_registry("build-lease", &[], false)
            .await
            .unwrap();
        let build = "a".repeat(32);
        let claim = db
            .claim_registry_index_build(registry_id, &build, 100, 60)
            .await
            .unwrap();
        let RegistryIndexBuildClaim::Acquired {
            owner_token,
            base_generation,
            target_generation,
        } = claim
        else {
            panic!("first build did not acquire its generation")
        };
        assert_eq!(
            db.claim_registry_index_build(registry_id, &"b".repeat(32), 101, 60)
                .await
                .unwrap(),
            RegistryIndexBuildClaim::Busy
        );
        db.complete_registry_index_build(
            registry_id,
            &build,
            &owner_token,
            base_generation,
            target_generation,
            base_generation,
            None,
            102,
        )
        .await
        .unwrap();
        assert_eq!(
            db.claim_registry_index_build(registry_id, &build, 103, 60)
                .await
                .unwrap(),
            RegistryIndexBuildClaim::AlreadyFinished
        );
    }

    #[tokio::test]
    async fn failed_stable_build_identity_can_be_retried() {
        let db = Database::open_in_memory().await.unwrap();
        let registry_id = db
            .register_registry("build-retry", &[], false)
            .await
            .unwrap();
        let build = "c".repeat(32);
        let RegistryIndexBuildClaim::Acquired { owner_token, .. } = db
            .claim_registry_index_build(registry_id, &build, 100, 60)
            .await
            .unwrap()
        else {
            panic!("first build did not acquire its generation")
        };
        db.fail_registry_index_build(registry_id, &build, &owner_token, "retryable", 101)
            .await
            .unwrap();

        assert!(matches!(
            db.claim_registry_index_build(registry_id, &build, 102, 60)
                .await
                .unwrap(),
            RegistryIndexBuildClaim::Acquired { .. }
        ));
    }
}
