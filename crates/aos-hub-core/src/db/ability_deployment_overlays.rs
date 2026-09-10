//! Fail-closed enrollment and live package deployment overlay storage.

use anyhow::{ensure, Result};

use super::Database;

/// One current admin-controlled deployment reporter enrollment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbilityDeploymentReporterRecord {
    /// Numeric registry identity owning the reporter slot.
    pub registry_id: i64,
    /// Stable deployment name inside the registry.
    pub deployment: String,
    /// Kind of the bound Hub principal.
    pub principal_kind: String,
    /// Numeric identity of the bound Hub principal.
    pub principal_id: i64,
    /// Human-facing stable reference for the bound principal.
    pub principal_ref: String,
    /// Whether the reporter is currently authorized.
    pub active: bool,
    /// Optimistic concurrency version of the enrollment.
    pub resource_version: u64,
    /// Last accepted reporter sequence, or zero before the first report.
    pub current_sequence: u64,
    /// Reviewed control plan that last changed this enrollment.
    pub last_mutation_plan_id: String,
}

/// One unexpired canonical overlay and its Hub receipt authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredAbilityDeploymentOverlay {
    /// Stable deployment name inside the registry.
    pub deployment: String,
    /// Kind of the principal whose bearer submitted the report.
    pub principal_kind: String,
    /// Numeric identity of the reporting principal.
    pub principal_id: i64,
    /// Human-facing stable reference for the reporting principal.
    pub principal_ref: String,
    /// Current reporter enrollment version.
    pub reporter_resource_version: u64,
    /// Last accepted reporter sequence carried by the canonical overlay.
    pub sequence: u64,
    /// Exact canonical reporter-authored overlay bytes.
    pub canonical_json: Vec<u8>,
    /// Hub wall-clock receipt time.
    pub received_at: i64,
    /// Hub-computed expiry time.
    pub expires_at: i64,
}

impl Database {
    /// Loads one reporter slot, including a revoked slot.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or an invalid stored integer.
    pub async fn ability_deployment_reporter(
        &self,
        registry_id: i64,
        deployment: &str,
    ) -> Result<Option<AbilityDeploymentReporterRecord>> {
        self.backend
            .query_opt(
                "SELECT principal_kind, principal_id, principal_ref, active,
                        resource_version, current_sequence, last_mutation_plan_id
                 FROM ability_deployment_reporters
                 WHERE registry_id = ?1 AND deployment = ?2",
                &vals![registry_id, deployment],
            )
            .await?
            .map(|row| {
                Ok(AbilityDeploymentReporterRecord {
                    registry_id,
                    deployment: deployment.to_string(),
                    principal_kind: row.get(0)?,
                    principal_id: row.get(1)?,
                    principal_ref: row.get(2)?,
                    active: row.get::<i64>(3)? == 1,
                    resource_version: nonnegative_u64(row.get(4)?, "reporter resource version")?,
                    current_sequence: nonnegative_u64(row.get(5)?, "reporter sequence")?,
                    last_mutation_plan_id: row.get(6)?,
                })
            })
            .transpose()
    }

    /// Creates or replaces one reporter enrollment under an exact version CAS.
    ///
    /// Reconfiguration always clears the prior assertion so a changed or
    /// re-enabled principal cannot inherit another enrollment's live state.
    ///
    /// # Errors
    ///
    /// Returns an error when the expected version is stale or a database write
    /// fails.
    pub async fn configure_ability_deployment_reporter(
        &self,
        registry_id: i64,
        deployment: &str,
        principal_kind: &str,
        principal_id: i64,
        principal_ref: &str,
        active: bool,
        expected_resource_version: u64,
        mutation_plan_id: &str,
    ) -> Result<AbilityDeploymentReporterRecord> {
        let current = self
            .ability_deployment_reporter(registry_id, deployment)
            .await?;
        let next_version = expected_resource_version
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("reporter resource version overflow"))?;
        let next_version_i64 = i64::try_from(next_version)?;
        let active_i64 = if active { 1_i64 } else { 0_i64 };

        let affected = if current.is_none() {
            ensure!(
                expected_resource_version == 0,
                "ability deployment reporter resource version is stale"
            );
            self.backend
                .execute(
                    "INSERT INTO ability_deployment_reporters
                     (registry_id, deployment, principal_kind, principal_id, principal_ref,
                      active, resource_version, current_sequence, last_mutation_plan_id)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8)",
                    &vals![
                        registry_id,
                        deployment,
                        principal_kind,
                        principal_id,
                        principal_ref,
                        active_i64,
                        next_version_i64,
                        mutation_plan_id,
                    ],
                )
                .await?
        } else {
            self.backend
                .execute(
                    "UPDATE ability_deployment_reporters
                     SET principal_kind = ?3, principal_id = ?4, principal_ref = ?5,
                         active = ?6, resource_version = ?7, current_sequence = 0,
                         registry_commit = NULL, package_name = NULL, package_version = NULL,
                         platform = NULL, manifest_sha256 = NULL, package_digest = NULL,
                         canonical_json = NULL, reported_at = NULL, received_at = NULL,
                         expires_at = NULL, last_mutation_plan_id = ?9
                     WHERE registry_id = ?1 AND deployment = ?2 AND resource_version = ?8",
                    &vals![
                        registry_id,
                        deployment,
                        principal_kind,
                        principal_id,
                        principal_ref,
                        active_i64,
                        next_version_i64,
                        i64::try_from(expected_resource_version)?,
                        mutation_plan_id,
                    ],
                )
                .await?
        };
        ensure!(
            affected == 1,
            "ability deployment reporter resource version is stale"
        );

        Ok(AbilityDeploymentReporterRecord {
            registry_id,
            deployment: deployment.to_string(),
            principal_kind: principal_kind.to_string(),
            principal_id,
            principal_ref: principal_ref.to_string(),
            active,
            resource_version: next_version,
            current_sequence: 0,
            last_mutation_plan_id: mutation_plan_id.to_string(),
        })
    }

    /// Reports whether one enrollment already reflects an exact reviewed plan.
    ///
    /// This closes the crash window between the enrollment mutation and generic
    /// control-plan completion: a retry can reconstruct and persist the same
    /// response without attempting the resource-version CAS again.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed stored integers.
    #[allow(clippy::too_many_arguments)]
    pub async fn ability_deployment_reporter_matches_plan(
        &self,
        registry_id: i64,
        deployment: &str,
        principal_kind: &str,
        principal_id: i64,
        principal_ref: &str,
        active: bool,
        resource_version: u64,
        mutation_plan_id: &str,
    ) -> Result<bool> {
        let Some(reporter) = self
            .ability_deployment_reporter(registry_id, deployment)
            .await?
        else {
            return Ok(false);
        };

        Ok(reporter.principal_kind == principal_kind
            && reporter.principal_id == principal_id
            && reporter.principal_ref == principal_ref
            && reporter.active == active
            && reporter.resource_version == resource_version
            && reporter.last_mutation_plan_id == mutation_plan_id)
    }

    /// Atomically accepts a newer report from the active bound principal.
    ///
    /// # Errors
    ///
    /// Returns an error for a revoked or changed enrollment, a replayed
    /// sequence, an integer overflow, or a database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn accept_package_ability_deployment_overlay(
        &self,
        registry_id: i64,
        deployment: &str,
        principal_kind: &str,
        principal_id: i64,
        reporter_resource_version: u64,
        sequence: u64,
        registry_commit: &str,
        package_name: &str,
        package_version: &str,
        platform: &str,
        manifest_sha256: &str,
        package_digest: &str,
        canonical_json: &[u8],
        reported_at: u64,
        received_at: i64,
        expires_at: i64,
    ) -> Result<()> {
        let affected = self
            .backend
            .execute(
                "UPDATE ability_deployment_reporters
                 SET current_sequence = ?6, registry_commit = ?7, package_name = ?8,
                     package_version = ?9, platform = ?10, manifest_sha256 = ?11,
                     package_digest = ?12, canonical_json = ?13, reported_at = ?14,
                     received_at = ?15, expires_at = ?16
                 WHERE registry_id = ?1 AND deployment = ?2 AND principal_kind = ?3
                   AND principal_id = ?4 AND resource_version = ?5 AND active = 1
                   AND current_sequence < ?6",
                &vals![
                    registry_id,
                    deployment,
                    principal_kind,
                    principal_id,
                    i64::try_from(reporter_resource_version)?,
                    i64::try_from(sequence)?,
                    registry_commit,
                    package_name,
                    package_version,
                    platform,
                    manifest_sha256,
                    package_digest,
                    canonical_json,
                    i64::try_from(reported_at)?,
                    received_at,
                    expires_at,
                ],
            )
            .await?;
        ensure!(
            affected == 1,
            "reporter enrollment changed, was revoked, or rejected a replayed sequence"
        );
        Ok(())
    }

    /// Loads one exact unexpired overlay while rechecking reporter enrollment.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed stored values.
    #[allow(clippy::too_many_arguments)]
    pub async fn package_ability_deployment_overlay(
        &self,
        registry_id: i64,
        deployment: &str,
        registry_commit: &str,
        package_name: &str,
        package_version: &str,
        platform: &str,
        now: i64,
    ) -> Result<Option<StoredAbilityDeploymentOverlay>> {
        let row = self
            .backend
            .query_opt(
                "SELECT deployment, principal_kind, principal_id, principal_ref,
                        resource_version, current_sequence, canonical_json,
                        received_at, expires_at
                 FROM ability_deployment_reporters
                 WHERE registry_id = ?1 AND deployment = ?2 AND registry_commit = ?3
                   AND package_name = ?4 AND package_version = ?5 AND platform = ?6
                   AND active = 1 AND canonical_json IS NOT NULL AND expires_at > ?7",
                &vals![
                    registry_id,
                    deployment,
                    registry_commit,
                    package_name,
                    package_version,
                    platform,
                    now,
                ],
            )
            .await?;
        row.map(stored_overlay).transpose()
    }

    /// Lists unexpired overlays matching one exact package reference anchor.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed stored values.
    pub async fn package_ability_deployment_overlays(
        &self,
        registry_id: i64,
        registry_commit: &str,
        package_name: &str,
        package_version: &str,
        platform: &str,
        now: i64,
    ) -> Result<Vec<StoredAbilityDeploymentOverlay>> {
        self.backend
            .query(
                "SELECT deployment, principal_kind, principal_id, principal_ref,
                        resource_version, current_sequence, canonical_json,
                        received_at, expires_at
                 FROM ability_deployment_reporters
                 WHERE registry_id = ?1 AND registry_commit = ?2 AND package_name = ?3
                   AND package_version = ?4 AND platform = ?5 AND active = 1
                   AND canonical_json IS NOT NULL AND expires_at > ?6
                 ORDER BY deployment",
                &vals![
                    registry_id,
                    registry_commit,
                    package_name,
                    package_version,
                    platform,
                    now,
                ],
            )
            .await?
            .into_iter()
            .map(stored_overlay)
            .collect()
    }
}

fn stored_overlay(row: crate::value::Row) -> Result<StoredAbilityDeploymentOverlay> {
    Ok(StoredAbilityDeploymentOverlay {
        deployment: row.get(0)?,
        principal_kind: row.get(1)?,
        principal_id: row.get(2)?,
        principal_ref: row.get(3)?,
        reporter_resource_version: nonnegative_u64(row.get(4)?, "reporter resource version")?,
        sequence: nonnegative_u64(row.get(5)?, "reporter sequence")?,
        canonical_json: row.get(6)?,
        received_at: row.get(7)?,
        expires_at: row.get(8)?,
    })
}

fn nonnegative_u64(value: i64, label: &str) -> Result<u64> {
    u64::try_from(value).map_err(|_| anyhow::anyhow!("{label} is negative"))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn fixture() -> (Database, i64, i64) {
        let db = Database::open_in_memory().await.unwrap();
        let org_id = db.create_org("overlay-test", "Overlay Test").await.unwrap();
        let registry_id = db
            .create_managed_registry(org_id, "", "packages", "private", &[], false)
            .await
            .unwrap();
        let user_id = db.create_user("reporter@overlay.test", None).await.unwrap();
        (db, registry_id, user_id)
    }

    #[tokio::test]
    async fn enrollment_sequence_replay_expiry_and_revocation_fail_closed() {
        let (db, registry_id, user_id) = fixture().await;
        let reporter = db
            .configure_ability_deployment_reporter(
                registry_id,
                "production",
                "user",
                user_id,
                "reporter@overlay.test",
                true,
                0,
                "plan-enable-1",
            )
            .await
            .unwrap();
        assert_eq!(reporter.resource_version, 1);
        assert!(reporter.active);
        assert!(db
            .ability_deployment_reporter_matches_plan(
                registry_id,
                "production",
                "user",
                user_id,
                "reporter@overlay.test",
                true,
                1,
                "plan-enable-1",
            )
            .await
            .unwrap());

        db.accept_package_ability_deployment_overlay(
            registry_id,
            "production",
            "user",
            user_id,
            reporter.resource_version,
            1,
            &"a".repeat(64),
            "demo",
            "1.0",
            "x86_64-linux",
            &format!("sha256:{}", "b".repeat(64)),
            &format!("sha256:{}", "c".repeat(64)),
            br#"{"schema":"test"}"#,
            99,
            100,
            110,
        )
        .await
        .unwrap();

        assert!(db
            .ability_deployment_reporter_matches_plan(
                registry_id,
                "production",
                "user",
                user_id,
                "reporter@overlay.test",
                true,
                1,
                "plan-enable-1",
            )
            .await
            .unwrap());

        let fresh = db
            .package_ability_deployment_overlay(
                registry_id,
                "production",
                &"a".repeat(64),
                "demo",
                "1.0",
                "x86_64-linux",
                109,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fresh.canonical_json, br#"{"schema":"test"}"#);

        assert_eq!(fresh.sequence, 1);

        let replay = db
            .accept_package_ability_deployment_overlay(
                registry_id,
                "production",
                "user",
                user_id,
                reporter.resource_version,
                1,
                &"a".repeat(64),
                "demo",
                "1.0",
                "x86_64-linux",
                &format!("sha256:{}", "b".repeat(64)),
                &format!("sha256:{}", "c".repeat(64)),
                br#"{"schema":"replay"}"#,
                100,
                101,
                111,
            )
            .await
            .unwrap_err();
        assert!(replay.to_string().contains("replayed sequence"));

        assert!(db
            .package_ability_deployment_overlay(
                registry_id,
                "production",
                &"a".repeat(64),
                "demo",
                "1.0",
                "x86_64-linux",
                110,
            )
            .await
            .unwrap()
            .is_none());

        let revoked = db
            .configure_ability_deployment_reporter(
                registry_id,
                "production",
                "user",
                user_id,
                "reporter@overlay.test",
                false,
                reporter.resource_version,
                "plan-revoke-2",
            )
            .await
            .unwrap();
        assert_eq!(revoked.resource_version, 2);
        assert!(!revoked.active);
        assert_eq!(revoked.current_sequence, 0);
        assert!(db
            .package_ability_deployment_overlay(
                registry_id,
                "production",
                &"a".repeat(64),
                "demo",
                "1.0",
                "x86_64-linux",
                100,
            )
            .await
            .unwrap()
            .is_none());

        let stale_version = db
            .configure_ability_deployment_reporter(
                registry_id,
                "production",
                "user",
                user_id,
                "reporter@overlay.test",
                true,
                reporter.resource_version,
                "plan-stale",
            )
            .await
            .unwrap_err();
        assert!(stale_version
            .to_string()
            .contains("resource version is stale"));
    }
}
