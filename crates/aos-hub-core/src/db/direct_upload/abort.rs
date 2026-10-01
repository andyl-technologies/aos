//! Original Abort CAS retention and explicit outcome progress without expiry inference.

use super::*;

impl Database {
    pub(super) async fn load_direct_abort(
        &self,
        deployment: &str,
        admission: &DirectUploadAdmission,
    ) -> Result<Option<DirectAbortRequest>> {
        let Some(row) = self.backend.query_opt(
            "SELECT abort.operation_id, abort.expected_resource_version, abort.intent_digest,
                abort.intent_json, abort.admitted_at, abort.terminal_receipt_digest,
                abort.settled_at, session.state
             FROM direct_upload_abort_intents abort JOIN direct_upload_sessions session
               ON session.session_id = abort.session_id AND session.deployment_id = abort.deployment_id
             WHERE abort.deployment_id = ?1 AND abort.session_id = ?2",
            &vals![deployment, admission.session_id],
        ).await? else { return Ok(None); };
        let intent: DirectAbortRequest = document(&row.get::<String>(3)?)?;
        intent.session.validate()?;
        ensure!(
            intent.session.session_id == admission.session_id
                && intent.session.logical_fingerprint == admission.logical_fingerprint
                && valid_direct_digest(&intent.operation_id)
                && integer(intent.expected_resource_version)? > 0
                && row.get::<String>(0)? == intent.operation_id
                && row.get::<i64>(1)? == integer(intent.expected_resource_version)?
                && row.get::<String>(2)? == digest(&intent)?
                && row.get::<i64>(4)? > 0,
            "retained direct abort original mismatch"
        );
        let receipt: Option<String> = row.get(5)?;
        let settled: Option<i64> = row.get(6)?;
        let admitted: i64 = row.get(4)?;
        ensure!(
            receipt.is_some() == settled.is_some()
                && receipt.is_some() == (row.get::<String>(7)? == "aborted")
                && receipt
                    .as_ref()
                    .is_none_or(|digest| valid_direct_digest(digest))
                && settled.is_none_or(|time| time >= admitted),
            "retained direct abort terminal receipt changed"
        );
        Ok(Some(intent))
    }

    /// Freezes the first Abort operation and original CAS before provider abort.
    ///
    /// Unknown effect progress cannot replace this intent or reopen the session.
    /// Current actor and target authorization are checked independently by Native.
    ///
    /// # Errors
    /// Returns an error for changed intent, stale initial CAS, a committed session,
    /// changed physical revisions or database failure. Cleanup may retain an
    /// overdue original without renewing its ordinary upload eligibility.
    pub async fn retain_direct_abort(
        &self,
        deployment: &str,
        intent: &DirectAbortRequest,
        now: i64,
    ) -> Result<DirectUploadSessionRecord> {
        intent.session.validate()?;
        ensure!(
            valid_direct_digest(&intent.operation_id)
                && integer(intent.expected_resource_version)? > 0,
            "invalid direct abort intent"
        );
        let record = self
            .direct_upload_session(deployment, &intent.session.session_id)
            .await?
            .context("direct abort session unavailable")?;
        ensure!(
            record.admission.logical_fingerprint == intent.session.logical_fingerprint,
            "direct abort original session mismatch"
        );
        if let Some(original) = &record.abort_intent {
            ensure!(
                original == intent,
                DirectUploadRefusal {
                    code: DirectItemErrorCode::Conflict
                }
            );
            self.direct_batch(&record)
                .checked_batch(&[current_guard_with_recovery(&record, now, true)?])
                .await?;
            return Ok(record);
        }
        ensure!(
            matches!(
                record.state,
                DirectSessionState::Creating | DirectSessionState::StagedVerified
            ) && record.resource_version == intent.expected_resource_version,
            DirectUploadRefusal {
                code: DirectItemErrorCode::Conflict
            }
        );
        integer(record.resource_version)?
            .checked_add(1)
            .context("direct resource version exhausted")?;
        self.direct_batch(&record)
            .checked_batch(&[
                current_guard_with_recovery(&record, now, true)?,
                Statement::new(
                    "INSERT INTO direct_upload_abort_intents
                   (deployment_id, session_id, operation_id, expected_resource_version,
                    intent_digest, intent_json, admitted_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    vals![
                        deployment,
                        intent.session.session_id,
                        intent.operation_id,
                        integer(intent.expected_resource_version)?,
                        digest(intent)?,
                        canonical(intent)?,
                        now
                    ],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE direct_upload_sessions SET state = 'abort_pending', updated_at = ?4,
                   resource_version = resource_version + 1
                 WHERE deployment_id = ?1 AND session_id = ?2 AND resource_version = ?3
                   AND state IN('admitted', 'staged_verified')",
                    vals![
                        deployment,
                        intent.session.session_id,
                        integer(intent.expected_resource_version)?,
                        now
                    ],
                )
                .expecting(1),
            ])
            .await?;
        self.direct_upload_session(deployment, &intent.session.session_id)
            .await?
            .context("retained direct abort disappeared")
    }

    #[cfg(test)]
    pub(crate) async fn report_direct_abort(
        &self,
        deployment: &str,
        record: &DirectUploadSessionRecord,
        evidence: &DirectAbortEvidence,
        now: i64,
    ) -> Result<()> {
        self.report_direct_abort_checked(deployment, record, evidence, Vec::new(), now)
            .await
    }

    pub(crate) async fn report_direct_abort_checked(
        &self,
        deployment: &str,
        record: &DirectUploadSessionRecord,
        evidence: &DirectAbortEvidence,
        target_statements: Vec<CheckedStatement>,
        now: i64,
    ) -> Result<()> {
        ensure!(
            evidence.outcome == DirectAbortOutcome::Aborted || target_statements.is_empty(),
            "nonterminal abort cannot settle target accounting"
        );
        let intent = record
            .abort_intent
            .as_ref()
            .context("direct abort original unavailable")?;
        ensure!(
            evidence.session == intent.session
                && evidence.operation_id == intent.operation_id
                && (evidence.outcome == DirectAbortOutcome::Aborted)
                    == evidence.receipt_digest.is_some()
                && evidence
                    .receipt_digest
                    .as_ref()
                    .is_none_or(|digest| valid_direct_digest(digest)),
            "direct abort evidence original mismatch"
        );
        let (state, current) = match evidence.outcome {
            DirectAbortOutcome::Pending => ("abort_pending", DirectSessionState::Aborting),
            DirectAbortOutcome::Unknown => ("abort_unknown", DirectSessionState::BlockedUnknown),
            DirectAbortOutcome::Aborted => ("aborted", DirectSessionState::Aborted),
        };
        if record.state == current {
            ensure!(
                target_statements.is_empty(),
                "abort replay cannot repeat settlement"
            );
            if current == DirectSessionState::Aborted {
                let row = self
                    .backend
                    .query_opt(
                        "SELECT terminal_receipt_digest FROM direct_upload_abort_intents
                     WHERE deployment_id = ?1 AND session_id = ?2 AND operation_id = ?3",
                        &vals![deployment, intent.session.session_id, intent.operation_id],
                    )
                    .await?
                    .context("direct abort receipt unavailable")?;
                ensure!(
                    row.get::<Option<String>>(0)? == evidence.receipt_digest,
                    "direct abort terminal receipt changed"
                );
            }
            return Ok(());
        }
        ensure!(
            matches!(
                record.state,
                DirectSessionState::Aborting | DirectSessionState::BlockedUnknown
            ) && !(record.state == DirectSessionState::BlockedUnknown
                && evidence.outcome == DirectAbortOutcome::Pending),
            "direct abort outcome cannot reopen unknown or terminal state"
        );
        integer(record.resource_version)?
            .checked_add(1)
            .context("direct resource version exhausted")?;
        let mut statements = vec![current_guard_with_recovery(record, now, true)?];
        statements.extend(target_statements);
        statements.extend([
            Statement::new(
                "UPDATE direct_upload_abort_intents SET terminal_receipt_digest = CAST(?4 AS VARCHAR),
                   settled_at = CASE WHEN CAST(?4 AS VARCHAR) IS NOT NULL
                     THEN CAST(?5 AS BIGINT) ELSE NULL END
                 WHERE deployment_id = ?1 AND session_id = ?2 AND operation_id = ?3
                   AND terminal_receipt_digest IS NULL",
                vals![
                    deployment,
                    intent.session.session_id,
                    intent.operation_id,
                    evidence.receipt_digest,
                    now
                ],
            )
            .expecting(1),
            Statement::new(
                "UPDATE direct_upload_sessions SET state = ?4, updated_at = ?5,
                   resource_version = resource_version + 1
                 WHERE deployment_id = ?1 AND session_id = ?2 AND resource_version = ?3
                   AND state IN('abort_pending', 'abort_unknown')",
                vals![
                    deployment,
                    intent.session.session_id,
                    integer(record.resource_version)?,
                    state,
                    now
                ],
            )
            .expecting(1),
        ]);
        self.direct_batch(&record).checked_batch(&statements).await
    }
}
