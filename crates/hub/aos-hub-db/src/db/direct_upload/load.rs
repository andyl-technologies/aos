//! Cross-checks retained Complete and receipt rows against the original admission.

use super::*;

mod documents;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;

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
                "SELECT session.session_id, session.deployment_id, session.principal_id, session.client_operation_id,
               session.target_kind, session.cache_id, session.cache_identifier, session.publication_id,
               session.surface_object_id, session.oci_upload_id, session.object_path, session.owner_scope_key,
               session.intent_json, session.admission_json, session.logical_fingerprint, session.source_sha256,
               session.declared_size, session.part_size, session.declared_dependency_phase,
               session.final_dependency_phase, session.cache_ticket_id, session.state, session.expires_at,
               session.created_at, session.updated_at, session.resource_version, session.completed_at,
               complete.operation_id, complete.expected_resource_version, complete.intent_digest,
               complete.intent_json, complete.admitted_at,
               abort.operation_id, abort.expected_resource_version, abort.intent_digest,
               abort.intent_json, abort.admitted_at, abort.terminal_receipt_digest, abort.settled_at, session.state,
               stage.operation_id, stage.logical_fingerprint, stage.evidence_digest, stage.evidence_json, stage.verified_at,
               receipt.operation_id, receipt.logical_fingerprint, receipt.evidence_digest, receipt.evidence_json,
               receipt.committed_at, receipt.resulting_resource_version, receipt.final_guards_json,
               complete.session_id, abort.session_id, stage.session_id, receipt.session_id
             FROM direct_upload_sessions session
             LEFT JOIN direct_upload_completion_intents complete
               ON complete.deployment_id = session.deployment_id AND complete.session_id = session.session_id
             LEFT JOIN direct_upload_abort_intents abort
               ON abort.deployment_id = session.deployment_id AND abort.session_id = session.session_id
             LEFT JOIN direct_upload_stage_receipts stage
               ON stage.deployment_id = session.deployment_id AND stage.session_id = session.session_id
             LEFT JOIN direct_upload_completion_receipts receipt
               ON receipt.deployment_id = session.deployment_id AND receipt.session_id = session.session_id
             WHERE session.deployment_id = ?1 AND session.session_id = ?2",
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

        // Single-row originals share the selected session snapshot. Required
        // placement and baseline sets keep their independent complete readers.
        let retained = documents::RetainedDocuments::from_joined(&row)?;
        let complete_intent =
            documents::complete(retained.complete.as_ref(), deployment, &admission)?;
        let abort_intent = documents::abort(retained.abort.as_ref(), &admission)?;
        let baselines = self
            .load_direct_baselines(deployment, &admission, complete_intent.as_ref())
            .await?;
        let stage_evidence = documents::stage(retained.stage.as_ref(), deployment, &admission)?;
        let completion_evidence =
            documents::completion(retained.completion.as_ref(), deployment, &admission)?;
        let final_guards = documents::final_guards(
            retained.completion.as_ref(),
            &row,
            deployment,
            &admission,
            complete_intent.as_ref(),
            completion_evidence.as_ref(),
        )?;
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
}
