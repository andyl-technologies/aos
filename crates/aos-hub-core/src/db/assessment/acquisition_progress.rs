//! Claim-fenced acquisition cursors without changing immutable evaluation checkpoints.

use anyhow::{bail, Context as _, Result};
use aos_assessment_runtime::acquisition::AcquisitionCheckpointV1;
use aos_assessment_runtime::scan::TaskClaim;
use aos_contract::Sha256Digest;

use super::scans::claim_values;
use super::AssessmentObjectKind;
use crate::backend::{CheckedStatement, Statement};
use crate::db::Database;

impl Database {
    /// Reads exact acquisition progress under the current logical operation claim.
    ///
    /// # Errors
    /// Returns an error for lost authority, missing immutable custody or invalid scope.
    pub async fn assessment_acquisition_checkpoint(
        &self,
        registry_id: i64,
        claim: &TaskClaim,
    ) -> Result<Option<AcquisitionCheckpointV1>> {
        self.check_assessment_scan_claim(registry_id, claim).await?;
        let row = self.backend.query_opt(
            "SELECT checkpoint_digest FROM assessment_scans WHERE registry_id = ?1 AND scan_id = ?2",
            &vals![@slice registry_id, claim.scan_id],
        ).await?.context("acquisition scan is absent")?;
        let Some(digest) = row.get::<Option<String>>(0)? else {
            return Ok(None);
        };
        let scan = self
            .assessment_scan(registry_id, &claim.scan_id)
            .await?
            .context("acquisition scan is absent")?;
        let bytes = self
            .assessment_object(
                &scan.request.authorization_partition,
                AssessmentObjectKind::AcquisitionCheckpoint,
                Sha256Digest::parse(&digest)?,
            )
            .await?
            .context("acquisition checkpoint custody is absent")?;
        let checkpoint = AcquisitionCheckpointV1::from_slice(&bytes)?;
        let base = self.assessment_evaluation_base(registry_id, claim).await?;
        checkpoint.require_scope(
            &scan.request.authorization_partition,
            &base,
            &scan.request.subjects,
            &scan.request.profiles,
        )?;
        self.check_assessment_scan_claim(registry_id, claim).await?;
        Ok(Some(checkpoint))
    }

    /// Pins one immutable acquisition progress revision while holding current authority.
    ///
    /// This pointer never makes a result, profile head, alert or frozen input eligible.
    /// Final evaluation has separate immutable input and data commitments.
    ///
    /// # Errors
    /// Returns an error for changed scope, active effects, lost authority, excessive
    /// guards or unavailable custody/persistence.
    pub async fn save_assessment_acquisition_checkpoint_fenced(
        &self,
        registry_id: i64,
        claim: &TaskClaim,
        checkpoint: &AcquisitionCheckpointV1,
        authority_fences: &[CheckedStatement],
    ) -> Result<()> {
        if authority_fences.len() > 32 {
            bail!("acquisition progress exceeds its authority bound");
        }
        self.check_assessment_scan_claim(registry_id, claim).await?;
        let scan = self
            .assessment_scan(registry_id, &claim.scan_id)
            .await?
            .context("acquisition scan is absent")?;
        let base = self.assessment_evaluation_base(registry_id, claim).await?;
        checkpoint.require_scope(
            &scan.request.authorization_partition,
            &base,
            &scan.request.subjects,
            &scan.request.profiles,
        )?;
        let now = self.assessment_database_time().await?;
        let digest = checkpoint.digest()?;
        self.put_assessment_object(
            &scan.request.authorization_partition,
            AssessmentObjectKind::AcquisitionCheckpoint,
            digest,
            &checkpoint.encoded()?,
            now.unix_seconds() as i64,
        )
        .await?;
        let mut values = claim_values(registry_id, claim);
        values.extend(vals![digest.to_string(), scan.resource_version]);
        let mut statements = authority_fences.to_vec();
        statements.push(Statement::new(format!(
            "UPDATE assessment_scans SET checkpoint_digest = ?9, resource_version = resource_version + 1
             WHERE {} AND resource_version = ?10 AND evaluation_input_digest IS NULL
               AND NOT EXISTS(SELECT 1 FROM assessment_tasks WHERE scan_id = ?2 AND state = 'leased')",
            self.assessment_claim_guard()), values).expecting(1));
        self.backend.checked_batch(&statements).await
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
pub(super) mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn initial_checkpoint(
        data: &aos_assessment::input::EvaluationData,
        request: &aos_assessment_runtime::scan::ScanRequestV1,
    ) -> Result<AcquisitionCheckpointV1> {
        let jobs = aos_assessment_runtime::acquisition::plan_acquisition(
            data,
            &request.subjects,
            &request.profiles,
        )?;
        AcquisitionCheckpointV1::from_slice(&serde_json::to_vec(&json!({
            "schema":"aos.acquisition-checkpoint/v1", "partition": request.authorization_partition,
            "data":data, "jobs":jobs, "subjects":request.subjects, "profiles":request.profiles,
            "position":0, "diagnostics":[], "source":{
                "initial": jobs[0].operation, "operation":jobs[0].operation,
                "previous":null, "pagePosition":0, "enumerationComplete":false, "recordOffset":0,
                "observations":[], "objects":[], "revisions":{}, "complete":false, "normalizedBytes":0
            }
        }))?)
    }

    #[tokio::test]
    async fn cooperative_progress_preserves_attempts_and_is_distinct_from_frozen_evaluation(
    ) -> Result<()> {
        let (db, registry_id, request) = super::super::scans_tests::setup().await?;
        let scan = db.request_assessment_scan(registry_id, &request).await?;
        let claim = db
            .claim_assessment_scan(registry_id, &scan.scan_id, 90)
            .await?;
        let base = db.assessment_evaluation_base(registry_id, &claim).await?;
        let checkpoint = initial_checkpoint(&base, &request)?;
        db.save_assessment_acquisition_checkpoint_fenced(registry_id, &claim, &checkpoint, &[])
            .await?;
        assert!(db
            .assessment_evaluation_checkpoint(registry_id, &claim)
            .await?
            .is_none());
        db.pause_assessment_scan_fenced(registry_id, &claim, &[])
            .await?;
        assert!(db
            .assessment_scan(registry_id, &scan.scan_id)
            .await?
            .unwrap()
            .failure_code
            .is_none());
        assert!(db
            .assessment_acquisition_checkpoint(registry_id, &claim)
            .await
            .is_err());
        let resumed = db
            .claim_assessment_scan(registry_id, &scan.scan_id, 90)
            .await?;
        assert_eq!(resumed.attempt, claim.attempt);
        assert_ne!(resumed.claim_token, claim.claim_token);
        assert_eq!(
            db.assessment_acquisition_checkpoint(registry_id, &resumed)
                .await?
                .unwrap()
                .digest()?,
            checkpoint.digest()?
        );
        assert_eq!(
            db.assessment_scan(registry_id, &scan.scan_id)
                .await?
                .unwrap()
                .usage
                .provider_requests,
            0
        );
        let current = db
            .assessment_scan(registry_id, &scan.scan_id)
            .await?
            .unwrap();
        db.cancel_assessment_scan(registry_id, &scan.scan_id, current.resource_version)
            .await?;
        assert!(db
            .assessment_acquisition_checkpoint(registry_id, &resumed)
            .await
            .is_err());
        assert!(db
            .save_assessment_acquisition_checkpoint_fenced(registry_id, &resumed, &checkpoint, &[])
            .await
            .is_err());
        Ok(())
    }
}
