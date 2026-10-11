//! Current database-backed authority for privately admitted scan jobs.

use anyhow::{ensure, Context as _, Result};
use aos_assessment::result::PackageAssessmentV1;
use aos_assessment_runtime::scan::TaskClaim;

use super::AssessmentAuthority;
use crate::backend::CheckedStatement;
use crate::db::{AssessmentScanRecord, Database};
use crate::domain::Permission;
use crate::value::ToValue as _;
use std::sync::Arc;

/// Rechecks immutable job provenance and current IAM in every runtime mode.
///
/// This host never converts expired credentials into system authority and never
/// substitutes another permission when the assessment role policy is absent.
pub struct DatabaseAssessmentAuthority {
    db: Arc<Database>,
}

impl DatabaseAssessmentAuthority {
    /// Binds the authoritative logical database used by the scan coordinator.
    #[must_use]
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Prepares exact current IAM and private job guards for a checked effect.
    ///
    /// # Errors
    /// Returns an error for absent policy, expired/revoked authority, changed
    /// principal/resource incarnation or an excessive current lock scope.
    pub async fn current_fences(
        &self,
        scan: &AssessmentScanRecord,
    ) -> Result<Vec<CheckedStatement>> {
        let permission = Permission::parse("assessment.scan")
            .context("assessment permission policy is unavailable")?;
        let claims = self.db.assessment_scan_authority(scan).await?;
        let registry = self
            .db
            .registry_by_id(scan.registry_id)
            .await?
            .context("assessment job registry is absent")?;
        ensure!(
            registry.scope_key == scan.request.resource_scope
                && registry.scope_key == scan.request.authorization_partition,
            "assessment job registry incarnation changed"
        );
        if let Some(org) = registry.org_id {
            ensure!(
                self.db.org_is_active(org).await?,
                "assessment job organization is inactive"
            );
        }
        let mut fences = self
            .db
            .assessment_iam_statements(&claims, &registry.scope_key, permission)
            .await?;
        if let Some(service_guards) = self.db.assessment_scan_service_guards(scan).await? {
            fences.extend(service_guards);
        } else if scan.request.trigger == "schedule" {
            let permission = Permission::parse("assessment.schedule.manage")
                .context("assessment schedule permission policy is unavailable")?;
            fences.extend(
                self.db
                    .assessment_iam_statements(&claims, &registry.scope_key, permission)
                    .await?,
            );
        }
        fences.push(self.db.assessment_job_authority_guard(scan).await?);
        fences.extend(
            self.db
                .assessment_publication_fences(
                    scan.registry_id,
                    &registry.scope_key,
                    scan.request.inventory_digest,
                    scan.request.policy_digest,
                )
                .await?,
        );
        ensure!(
            fences.len() <= 32,
            "assessment job authority lock scope exceeds its ceiling"
        );
        Ok(fences)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl AssessmentAuthority for DatabaseAssessmentAuthority {
    async fn source_fences(
        &self,
        scan: &AssessmentScanRecord,
        deadline: &aos_assessment::time::Timestamp,
    ) -> Result<Vec<CheckedStatement>> {
        let mut fences = self.current_fences(scan).await?;
        let clock = self.db.backend.dialect().unix_time_expression();
        fences.push(
            crate::backend::Statement::new(
                format!(
                    "UPDATE assessment_scan_authorities SET admitted_at = admitted_at
             WHERE scan_id = ?1 AND registry_id = ?2 AND expires_at >= ?3
               AND ?3 >= {clock} + 60"
                ),
                vec![
                    scan.scan_id.to_value(),
                    scan.registry_id.to_value(),
                    deadline.unix_seconds().to_value(),
                ],
            )
            .expecting(1),
        );
        ensure!(
            fences.len() <= 32,
            "physical assessment authority exceeds its guard bound"
        );
        Ok(fences)
    }

    async fn source_deadline(
        &self,
        scan: &AssessmentScanRecord,
    ) -> Result<aos_assessment::time::Timestamp> {
        self.db.assessment_scan_authority_deadline(scan).await
    }

    async fn current_fences(&self, scan: &AssessmentScanRecord) -> Result<Vec<CheckedStatement>> {
        DatabaseAssessmentAuthority::current_fences(self, scan).await
    }

    async fn require_current(&self, scan: &AssessmentScanRecord) -> Result<()> {
        self.db
            .backend
            .checked_batch(&self.current_fences(scan).await?)
            .await
    }

    async fn commit_current(
        &self,
        db: &Database,
        scan: &AssessmentScanRecord,
        claim: &TaskClaim,
        assessment: &PackageAssessmentV1,
    ) -> Result<()> {
        db.commit_assessment_evaluation_fenced(
            scan.registry_id,
            claim,
            assessment,
            self.current_fences(scan).await?,
        )
        .await
    }
}
