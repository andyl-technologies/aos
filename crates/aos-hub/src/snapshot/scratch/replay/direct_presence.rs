//! Exact retained Direct source links after disposable relational replay.
//!
//! This reconstructs canonical documents only from the session named by each
//! presence row. It never searches for an observationally equal receipt or
//! initializes a live database, backfills originals or grants restored effects.

use aos_hub_core::db::{
    DirectPresenceProvenance, DirectSqlOwner, DirectUploadSessionRecord,
    validate_direct_presence_provenance,
};
use aos_hub_core::direct_upload::{
    DirectCompleteRequest, DirectCompletionEvidence, DirectDependencyPhase,
    DirectDestinationBaselineEvidence, DirectFinalGuardRecord, DirectPlacement, DirectSessionState,
    DirectUploadAdmission, DirectVerifiedStageEvidence, WireInteger, encode_direct_control,
};
use rusqlite::Connection;
use serde::{Serialize, de::DeserializeOwned};

use super::{Failure, MemoryReplay, ScratchResult};

impl MemoryReplay {
    pub(super) fn direct_presence_checks(&self) -> ScratchResult<()> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT presence.surface_object_id, presence.placement_id, presence.direct_upload_session_id,
                    presence.observed_hash, presence.observed_size, presence.etag, presence.provider_version,
                    presence.observed_placement_resource_version, presence.observed_write_spec_version,
                    presence.observed_binding_resource_version, session.deployment_id
               FROM object_placements presence JOIN direct_upload_sessions session
                 ON session.session_id = presence.direct_upload_session_id
              WHERE presence.direct_upload_session_id IS NOT NULL
              ORDER BY presence.surface_object_id, presence.placement_id",
        ).map_err(|error| self.sql_failure(&error, Failure::Constraints))?;
        let mut copies = statement
            .query([])
            .map_err(|error| self.sql_failure(&error, Failure::Constraints))?;
        while let Some(row) = copies
            .next()
            .map_err(|error| self.sql_failure(&error, Failure::Constraints))?
        {
            self.budget.check()?;
            let session_id: String = row.get(2).map_err(|_| Failure::Constraints)?;
            let deployment: String = row.get(10).map_err(|_| Failure::Constraints)?;
            let hash: String = row.get(3).map_err(|_| Failure::Constraints)?;
            let etag: String = row.get(5).map_err(|_| Failure::Constraints)?;
            let provider: Option<String> = row.get(6).map_err(|_| Failure::Constraints)?;
            let record = retained_record(connection, &deployment, &session_id)?;
            validate_direct_presence_provenance(
                &record,
                &DirectPresenceProvenance {
                    deployment_id: &deployment,
                    session_id: &session_id,
                    surface_object_id: row.get(0).map_err(|_| Failure::Constraints)?,
                    placement_id: row.get(1).map_err(|_| Failure::Constraints)?,
                    sha256: &hash,
                    byte_size: row.get(4).map_err(|_| Failure::Constraints)?,
                    etag: &etag,
                    provider_version: provider.as_deref(),
                    placement_resource_version: row.get(7).map_err(|_| Failure::Constraints)?,
                    write_spec_version: row.get(8).map_err(|_| Failure::Constraints)?,
                    binding_resource_version: row.get(9).map_err(|_| Failure::Constraints)?,
                },
            )
            .map_err(|_| Failure::Constraints)?;
        }
        self.budget.check()
    }
}

fn retained_record(
    connection: &Connection,
    deployment: &str,
    session: &str,
) -> ScratchResult<DirectUploadSessionRecord> {
    let (admission, scope, state, version, phase, completed): (String, String, String, i64, String, i64) = connection.query_row(
        "SELECT admission_json, owner_scope_key, state, resource_version, final_dependency_phase, completed_at
           FROM direct_upload_sessions WHERE deployment_id = ?1 AND session_id = ?2",
        [deployment, session],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
    ).map_err(|_| Failure::Constraints)?;
    let admission: DirectUploadAdmission = document(&admission)?;
    admission
        .validate(deployment)
        .map_err(|_| Failure::Constraints)?;
    if admission.session_id != session || state != "committed" || version <= 1 || completed <= 0 {
        return Err(Failure::Constraints);
    }
    let phase = match phase.as_str() {
        "content" => DirectDependencyPhase::Content,
        "leaf_metadata" => DirectDependencyPhase::LeafMetadata,
        "visibility" => DirectDependencyPhase::Visibility,
        _ => return Err(Failure::Constraints),
    };
    let complete: DirectCompleteRequest = document(&text(
        connection,
        "SELECT intent_json FROM direct_upload_completion_intents WHERE deployment_id = ?1 AND session_id = ?2",
        deployment,
        session,
    )?)?;
    let stage: DirectVerifiedStageEvidence = document(&text(
        connection,
        "SELECT evidence_json FROM direct_upload_stage_receipts WHERE deployment_id = ?1 AND session_id = ?2",
        deployment,
        session,
    )?)?;
    stage
        .validate_against(&admission, deployment)
        .map_err(|_| Failure::Constraints)?;
    if stage.operation_id != complete.operation_id {
        return Err(Failure::Constraints);
    }
    let (receipt, guards, receipt_version, committed): (String, String, i64, i64) = connection
        .query_row(
            "SELECT evidence_json, final_guards_json, resulting_resource_version, committed_at
           FROM direct_upload_completion_receipts WHERE deployment_id = ?1 AND session_id = ?2",
            [deployment, session],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| Failure::Constraints)?;
    let evidence: DirectCompletionEvidence = document(&receipt)?;
    let final_guards: Vec<DirectFinalGuardRecord> = document(&guards)?;
    if receipt_version != version || committed != completed {
        return Err(Failure::Constraints);
    }

    let placements = documents::<DirectPlacement>(
        connection,
        "SELECT placement_json FROM direct_upload_session_placements
           WHERE deployment_id = ?1 AND session_id = ?2 ORDER BY placement_id LIMIT 65",
        deployment,
        session,
    )?;
    if placements != admission.placements {
        return Err(Failure::Constraints);
    }
    let baselines = documents::<DirectDestinationBaselineEvidence>(
        connection,
        "SELECT evidence_json FROM direct_upload_baselines
           WHERE deployment_id = ?1 AND session_id = ?2 ORDER BY placement_id LIMIT 65",
        deployment,
        session,
    )?;
    if baselines.len() != placements.len() || final_guards.len() != placements.len()
        || connection.query_row(
            "SELECT COUNT(*) FROM direct_upload_abort_intents WHERE deployment_id = ?1 AND session_id = ?2",
            [deployment, session], |row| row.get::<_, i64>(0),
        ).map_err(|_| Failure::Constraints)? != 0
    {
        return Err(Failure::Constraints);
    }
    for ((baseline, guard), placement) in baselines.iter().zip(&final_guards).zip(&placements) {
        baseline.validate().map_err(|_| Failure::Constraints)?;
        baseline
            .binding
            .validate_for(
                &admission,
                &complete,
                deployment,
                &placement.protected_profile_digest,
            )
            .map_err(|_| Failure::Constraints)?;
        guard
            .validate_for(&admission, &complete, &evidence, deployment)
            .map_err(|_| Failure::Constraints)?;
        if baseline.binding != guard.reservation
            || baseline.binding.placement
                != placement
                    .public_ref(deployment)
                    .map_err(|_| Failure::Constraints)?
        {
            return Err(Failure::Constraints);
        }
    }
    Ok(DirectUploadSessionRecord {
        admission,
        owner_scope_key: scope,
        owner: DirectSqlOwner::Publication,
        state: DirectSessionState::Committed,
        resource_version: WireInteger::new(
            u64::try_from(version).map_err(|_| Failure::Constraints)?,
        ),
        final_dependency_phase: Some(phase),
        complete_intent: Some(complete),
        abort_intent: None,
        baselines,
        stage_evidence: Some(stage),
        completion_evidence: Some(evidence),
        final_guards,
    })
}

fn text(
    connection: &Connection,
    sql: &str,
    deployment: &str,
    session: &str,
) -> ScratchResult<String> {
    connection
        .query_row(sql, [deployment, session], |row| row.get(0))
        .map_err(|_| Failure::Constraints)
}

fn documents<T: DeserializeOwned + Serialize>(
    connection: &Connection,
    sql: &str,
    deployment: &str,
    session: &str,
) -> ScratchResult<Vec<T>> {
    let mut statement = connection.prepare(sql).map_err(|_| Failure::Constraints)?;
    let mut rows = statement
        .query([deployment, session])
        .map_err(|_| Failure::Constraints)?;
    let mut documents = Vec::new();
    while let Some(row) = rows.next().map_err(|_| Failure::Constraints)? {
        documents.push(document(
            &row.get::<_, String>(0).map_err(|_| Failure::Constraints)?,
        )?);
    }
    Ok(documents)
}

fn document<T: DeserializeOwned + Serialize>(text: &str) -> ScratchResult<T> {
    let result: T = serde_json::from_str(text).map_err(|_| Failure::Constraints)?;
    if encode_direct_control(&result).map_err(|_| Failure::Constraints)? != text.as_bytes() {
        return Err(Failure::Constraints);
    }
    Ok(result)
}
