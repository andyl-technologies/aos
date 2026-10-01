//! Immutable first destination observations and atomic accounting activation.

use super::*;

impl Database {
    pub(super) async fn load_direct_baselines(
        &self,
        deployment: &str,
        admission: &DirectUploadAdmission,
        complete: Option<&DirectCompleteRequest>,
    ) -> Result<Vec<DirectDestinationBaselineEvidence>> {
        let rows = self.backend.query(
            "SELECT placement_id, complete_operation_id, baseline_digest, evidence_json, activated_at
             FROM direct_upload_baselines WHERE deployment_id = ?1 AND session_id = ?2
             ORDER BY placement_id", &vals![deployment, admission.session_id],
        ).await?;
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        let complete = complete.context("direct baseline Complete original unavailable")?;
        ensure!(
            rows.len() == admission.placements.len(),
            "direct baseline required set changed"
        );
        rows.iter()
            .zip(&admission.placements)
            .map(|(row, placement)| {
                let evidence: DirectDestinationBaselineEvidence = document(&row.get::<String>(3)?)?;
                evidence.validate()?;
                evidence.binding.validate_for(
                    admission,
                    complete,
                    deployment,
                    &placement.protected_profile_digest,
                )?;
                ensure!(
                    evidence.binding.placement == placement.public_ref(deployment)?
                        && row.get::<i64>(0)? == integer(placement.placement_id)?
                        && row.get::<String>(1)? == complete.operation_id
                        && row.get::<String>(2)? == evidence.fingerprint()?
                        && row.get::<i64>(4)? > 0,
                    "direct baseline retained scalar mismatch"
                );
                Ok(evidence)
            })
            .collect()
    }

    /// Retains first destination observations with target accounting activation.
    ///
    /// The configured authority independently verifies each held reservation and
    /// current witness before calling this method. Exact retries supply the same
    /// immutable full set and no activation SQL, preventing duplicate quota.
    ///
    /// # Errors
    /// Returns an error for changed originals, incomplete sets, stale SQL fences
    /// or database failure. No provider work occurs inside this transaction.
    pub async fn retain_direct_baselines(
        &self,
        deployment: &str,
        record: &DirectUploadSessionRecord,
        evidence: &[DirectDestinationBaselineEvidence],
        authority_statements: Vec<CheckedStatement>,
        mut activation_statements: Vec<CheckedStatement>,
        now: i64,
    ) -> Result<()> {
        ensure!(
            record.state == DirectSessionState::StagedVerified
                && evidence.len() == record.admission.placements.len(),
            "direct baseline logical phase or required set mismatch"
        );
        let complete = record
            .complete_intent
            .as_ref()
            .context("direct baseline Complete original unavailable")?;
        for (item, placement) in evidence.iter().zip(&record.admission.placements) {
            item.validate()?;
            item.binding.validate_for(
                &record.admission,
                complete,
                deployment,
                &placement.protected_profile_digest,
            )?;
            ensure!(
                item.binding.placement == placement.public_ref(deployment)?,
                "direct baseline original destination mismatch"
            );
        }
        if !record.baselines.is_empty() {
            ensure!(
                record.baselines == evidence && activation_statements.is_empty(),
                "direct baseline original or accounting replay changed"
            );
            return self
                .direct_batch(record)
                .checked_batch(&[vec![current_guard(record, now)?], authority_statements].concat())
                .await;
        }
        if matches!(record.owner, DirectSqlOwner::Cache { .. }) {
            ensure!(
                activation_statements
                    .iter()
                    .any(|statement| statement.expected_rows == Some(1)),
                "direct cache baseline accounting activation unavailable"
            );
        }
        let mut statements = vec![current_guard(record, now)?];
        statements.extend(authority_statements);
        for item in evidence {
            statements.push(
                Statement::new(
                    "INSERT INTO direct_upload_baselines
                   (deployment_id, session_id, placement_id, complete_operation_id,
                    baseline_digest, evidence_json, activated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    vals![
                        deployment,
                        record.admission.session_id,
                        integer(item.binding.placement.placement_id)?,
                        complete.operation_id,
                        item.fingerprint()?,
                        canonical(item)?,
                        now
                    ],
                )
                .expecting(1),
            );
        }
        statements.append(&mut activation_statements);
        self.direct_batch(record).checked_batch(&statements).await
    }
}
