//! Cross-checks retained Complete and receipt rows against the original admission.

use super::*;

impl Database {
    /// Loads and cross-checks all original documents and duplicated SQL pins.
    ///
    /// # Errors
    /// Returns an error for malformed retained originals, scalar inconsistencies,
    /// missing required placements/receipts, or database failure.
    pub async fn direct_upload_session(
        &self,
        deployment: &str,
        session_id: &str,
    ) -> Result<Option<DirectUploadSessionRecord>> {
        ensure!(
            valid_direct_identity(deployment) && valid_direct_identity(session_id),
            "invalid direct session lookup"
        );
        let Some(row) = self
            .backend
            .query_opt(
                "SELECT session_id, deployment_id, principal_id, client_operation_id,
               target_kind, cache_id, cache_identifier, publication_id,
               surface_object_id, oci_upload_id, object_path, owner_scope_key,
               intent_json, admission_json, logical_fingerprint, source_sha256,
               declared_size, part_size, declared_dependency_phase,
               final_dependency_phase, cache_ticket_id, state, expires_at,
               created_at, updated_at, resource_version, completed_at
             FROM direct_upload_sessions WHERE deployment_id = ?1 AND session_id = ?2",
                &vals![deployment, session_id],
            )
            .await?
        else {
            return Ok(None);
        };
        let admission: DirectUploadAdmission = document(&row.get::<String>(13)?)?;
        admission.validate(deployment)?;
        ensure!(
            admission.session_id == session_id
                && row.get::<String>(0)? == session_id
                && row.get::<String>(1)? == deployment
                && row.get::<String>(2)? == admission.principal_id
                && row.get::<String>(3)? == admission.intent.client_operation_id
                && document::<DirectUploadIntent>(&row.get::<String>(12)?)? == admission.intent
                && row.get::<String>(14)? == admission.logical_fingerprint
                && row.get::<String>(15)? == admission.intent.expected_sha256
                && integer(admission.intent.byte_size)? == row.get::<i64>(16)?
                && integer(admission.intent.part_size)? == row.get::<i64>(17)?
                && phase_name(admission.intent.dependency_phase) == row.get::<String>(18)?
                && integer(admission.expires_at)? == row.get::<i64>(22)?,
            "retained direct admission scalar mismatch"
        );
        let owner = load_owner(&row, &admission.intent.target)?;
        let state = match row.get::<String>(21)?.as_str() {
            "admitted" => DirectSessionState::Creating,
            "staged_verified" => DirectSessionState::StagedVerified,
            "committed" => DirectSessionState::Committed,
            "abort_pending" => DirectSessionState::Aborting,
            "abort_unknown" => DirectSessionState::BlockedUnknown,
            "aborted" => DirectSessionState::Aborted,
            _ => anyhow::bail!("invalid retained direct state"),
        };
        let created: i64 = row.get(23)?;
        let version: i64 = row.get(25)?;
        let completed: Option<i64> = row.get(26)?;
        ensure!(
            created > 0
                && integer(admission.expires_at)? > created
                && row.get::<i64>(24)? >= created
                && version > 0
                && (state == DirectSessionState::Committed) == completed.is_some(),
            "invalid retained direct session progress"
        );
        let final_dependency_phase = row
            .get::<Option<String>>(19)?
            .map(|phase| parse_phase(&phase))
            .transpose()?;

        let placements = self
            .backend
            .query(
                "SELECT placement_id, placement_resource_version, write_spec_version,
               binding_id, binding_resource_version, binding_write_revision,
               placement_fingerprint, placement_json
             FROM direct_upload_session_placements
             WHERE deployment_id = ?1 AND session_id = ?2 ORDER BY placement_id",
                &vals![deployment, session_id],
            )
            .await?;
        ensure!(
            placements.len() == admission.placements.len(),
            "retained direct required placement count changed"
        );
        for (row, original) in placements.iter().zip(&admission.placements) {
            ensure!(
                document::<DirectPlacement>(&row.get::<String>(7)?)? == *original
                    && row.get::<String>(6)? == original.fingerprint(deployment)?,
                "retained direct placement original changed"
            );
            for (index, value) in [
                original.placement_id,
                original.placement_resource_version,
                original.write_spec_version,
                original.binding_id,
                original.binding_resource_version,
                original.binding_write_revision,
            ]
            .iter()
            .enumerate()
            {
                ensure!(
                    row.get::<i64>(index)? == integer(*value)?,
                    "retained direct placement scalar changed"
                );
            }
        }

        let complete_intent = self.load_direct_complete(deployment, &admission).await?;
        let abort_intent = self.load_direct_abort(deployment, &admission).await?;
        let baselines = self
            .load_direct_baselines(deployment, &admission, complete_intent.as_ref())
            .await?;
        let stage_evidence = self.load_direct_stage(deployment, &admission).await?;
        let completion_evidence = self.load_direct_completion(deployment, &admission).await?;
        let final_guards = self
            .load_direct_final_guards(
                deployment,
                &admission,
                complete_intent.as_ref(),
                completion_evidence.as_ref(),
            )
            .await?;
        for operation in stage_evidence
            .iter()
            .map(|proof| &proof.operation_id)
            .chain(completion_evidence.iter().map(|proof| &proof.operation_id))
        {
            ensure!(
                complete_intent
                    .as_ref()
                    .is_some_and(|intent| &intent.operation_id == operation),
                "retained direct evidence original operation missing"
            );
        }
        ensure!(
            (state != DirectSessionState::StagedVerified || stage_evidence.is_some())
                && (state != DirectSessionState::Committed || completion_evidence.is_some()),
            "retained direct progress has no original receipt"
        );
        ensure!(
            (stage_evidence.is_some() == final_dependency_phase.is_some())
                && (state != DirectSessionState::Creating || stage_evidence.is_none())
                && (abort_intent.is_some()
                    == matches!(
                        state,
                        DirectSessionState::Aborting
                            | DirectSessionState::BlockedUnknown
                            | DirectSessionState::Aborted
                    )),
            "retained direct intent or stage progress mismatch"
        );
        if state == DirectSessionState::Committed {
            ensure!(
                baselines.len() == admission.placements.len()
                    && final_guards
                        .iter()
                        .map(|guard| &guard.reservation)
                        .eq(baselines.iter().map(|baseline| &baseline.binding)),
                "retained direct final original reservations changed"
            );
        }
        Ok(Some(DirectUploadSessionRecord {
            admission,
            owner_scope_key: row.get(11)?,
            owner,
            state,
            resource_version: WireInteger::new(u64::try_from(version)?),
            final_dependency_phase,
            complete_intent,
            abort_intent,
            baselines,
            stage_evidence,
            completion_evidence,
            final_guards,
        }))
    }

    pub(super) async fn load_direct_final_guards(
        &self,
        deployment: &str,
        admission: &DirectUploadAdmission,
        complete: Option<&DirectCompleteRequest>,
        evidence: Option<&DirectCompletionEvidence>,
    ) -> Result<Vec<DirectFinalGuardRecord>> {
        let Some(evidence) = evidence else {
            return Ok(Vec::new());
        };
        let complete = complete.context("direct final receipt Complete original absent")?;
        let row = self
            .backend
            .query_opt(
                "SELECT final_guards_json, committed_at, resulting_resource_version
             FROM direct_upload_completion_receipts WHERE deployment_id = ?1 AND session_id = ?2",
                &vals![deployment, admission.session_id],
            )
            .await?
            .context("direct final receipts absent")?;
        let guards: Vec<DirectFinalGuardRecord> = document(&row.get::<String>(0)?)?;
        validate_final_guards(admission, complete, evidence, &guards, deployment)?;
        let progress = self
            .backend
            .query_opt(
                "SELECT completed_at, resource_version FROM direct_upload_sessions
             WHERE deployment_id = ?1 AND session_id = ?2 AND state = 'committed'",
                &vals![deployment, admission.session_id],
            )
            .await?
            .context("direct terminal receipt session progress absent")?;
        ensure!(
            progress.get::<i64>(0)? == row.get::<i64>(1)?
                && progress.get::<i64>(1)? == row.get::<i64>(2)?,
            "direct terminal receipt resulting progress changed"
        );
        Ok(guards)
    }

    pub(super) async fn load_direct_complete(
        &self,
        deployment: &str,
        admission: &DirectUploadAdmission,
    ) -> Result<Option<DirectCompleteRequest>> {
        let Some(row) = self.backend.query_opt(
            "SELECT operation_id, expected_resource_version, intent_digest, intent_json, admitted_at
             FROM direct_upload_completion_intents WHERE deployment_id = ?1 AND session_id = ?2",
            &vals![deployment, admission.session_id],
        ).await? else { return Ok(None); };
        let intent: DirectCompleteRequest = document(&row.get::<String>(3)?)?;
        validate_complete(admission, &intent, deployment)?;
        ensure!(
            row.get::<String>(0)? == intent.operation_id
                && row.get::<i64>(1)? == integer(intent.expected_resource_version)?
                && row.get::<String>(2)? == intent.fingerprint()?
                && row.get::<i64>(4)? > 0,
            "retained direct complete scalar mismatch"
        );
        Ok(Some(intent))
    }

    pub(super) async fn load_direct_stage(
        &self,
        deployment: &str,
        admission: &DirectUploadAdmission,
    ) -> Result<Option<DirectVerifiedStageEvidence>> {
        let Some(row) = self.backend.query_opt(
            "SELECT operation_id, logical_fingerprint, evidence_digest, evidence_json, verified_at
             FROM direct_upload_stage_receipts WHERE deployment_id = ?1 AND session_id = ?2",
            &vals![deployment, admission.session_id],
        ).await? else { return Ok(None); };
        let evidence: DirectVerifiedStageEvidence = document(&row.get::<String>(3)?)?;
        evidence.validate_against(admission, deployment)?;
        ensure!(
            row.get::<String>(0)? == evidence.operation_id
                && row.get::<String>(1)? == evidence.logical_fingerprint
                && row.get::<String>(2)? == digest(&evidence)?
                && row.get::<i64>(4)? > 0,
            "retained direct stage scalar mismatch"
        );
        Ok(Some(evidence))
    }

    pub(super) async fn load_direct_completion(
        &self,
        deployment: &str,
        admission: &DirectUploadAdmission,
    ) -> Result<Option<DirectCompletionEvidence>> {
        let Some(row) = self
            .backend
            .query_opt(
                "SELECT operation_id, logical_fingerprint, evidence_digest, evidence_json,
               committed_at, resulting_resource_version
             FROM direct_upload_completion_receipts WHERE deployment_id = ?1 AND session_id = ?2",
                &vals![deployment, admission.session_id],
            )
            .await?
        else {
            return Ok(None);
        };
        let evidence: DirectCompletionEvidence = document(&row.get::<String>(3)?)?;
        evidence.validate_against(admission, deployment)?;
        ensure!(
            row.get::<String>(0)? == evidence.operation_id
                && row.get::<String>(1)? == evidence.logical_fingerprint
                && row.get::<String>(2)? == digest(&evidence)?
                && row.get::<i64>(4)? > 0
                && row.get::<i64>(5)? > 1,
            "retained direct completion scalar mismatch"
        );
        Ok(Some(evidence))
    }
}
