//! Retained Native direct-upload originals and transactional logical progress.
//!
//! Provider sessions and part/grant uncertainty remain outside this database.
//! Every mutation checks the original actor incarnation and exact current SQL
//! placement revisions. A receipt document establishes identity only; the Native
//! service must independently verify its current guard provenance before calling
//! the private stage/commit methods.
//!
//! ```text
//! admitted + immutable Complete -> staged_verified -> atomic target/receipt/commit
//! ```

use anyhow::{ensure, Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::Database;
use crate::backend::{CheckedStatement, Statement};
use crate::direct_upload::*;
use crate::value::Row;

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "direct_upload/tests.rs"]
mod tests;

mod abort;
mod baseline;
mod load;

/// Canonical SQL owner resolved by current target authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectSqlOwner {
    /// Managed cache row and its existing accounting reservation.
    Cache {
        /// Positive canonical cache SQL identity.
        cache_id: i64,
        /// Existing cache ticket retained before admitting provider work.
        ticket_id: String,
    },
    /// Existing publication object; identity comes from the admission target.
    Publication,
    /// Existing OCI upload; identity comes from the admission target.
    Oci,
}

/// Durable original admission and the Native logical progress associated with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectUploadSessionRecord {
    /// Exact immutable original admission, including every required placement.
    pub admission: DirectUploadAdmission,
    /// Stable target authorization scope, never an arbitrary client scope.
    pub owner_scope_key: String,
    /// Canonical SQL owner and existing accounting reservation.
    pub owner: DirectSqlOwner,
    /// Current logical state, separate from provider journal state.
    pub state: DirectSessionState,
    /// Current logical CAS version; part progress does not change it.
    pub resource_version: WireInteger,
    /// Independently classified final dependency phase after verified staging.
    pub final_dependency_phase: Option<DirectDependencyPhase>,
    /// First immutable Complete intent, unchanged as logical progress advances.
    pub complete_intent: Option<DirectCompleteRequest>,
    /// Original immutable Abort operation and CAS, retained before provider effects.
    pub abort_intent: Option<DirectAbortRequest>,
    /// First immutable full destination baseline set and accounting activation.
    pub baselines: Vec<DirectDestinationBaselineEvidence>,
    /// Exact independently verified original stage receipt, when retained.
    pub stage_evidence: Option<DirectVerifiedStageEvidence>,
    /// Exact independently verified terminal receipt; replay performs no provider I/O.
    pub completion_evidence: Option<DirectCompletionEvidence>,
    /// Exact independently verified final reservations and receipts at commit.
    pub final_guards: Vec<DirectFinalGuardRecord>,
}

impl DirectUploadSessionRecord {
    /// Projects authoritative logical metadata without inventing provider progress.
    ///
    /// Outstanding grant accounting belongs to the independent journal and is
    /// conservatively unresolved here even after logical commit.
    ///
    /// # Errors
    /// Returns an error for invalid original placement projections or status.
    pub fn status(&self, deployment: &str) -> Result<DirectSessionStatus> {
        let status = DirectSessionStatus {
            session: DirectSessionRef {
                session_id: self.admission.session_id.clone(),
                logical_fingerprint: self.admission.logical_fingerprint.clone(),
            },
            resource_version: self.resource_version,
            intent: self.admission.intent.clone(),
            placements: self
                .admission
                .placements
                .iter()
                .map(|placement| placement.public_ref(deployment))
                .collect::<Result<Vec<_>>>()?,
            state: self.state,
            parts: Vec::new(),
            next_cursor: None,
            outstanding_grants: true,
        };
        status.validate()?;
        Ok(status)
    }
}

impl Database {
    /// Reserves an original admission and every required placement atomically.
    ///
    /// The caller supplies current target IAM authorization and an already
    /// reserved target accounting owner. Exact retries retain the first horizon;
    /// changed originals cannot allocate another session under the same business ID.
    /// This operation accepts metadata only and invokes no provider.
    ///
    /// # Errors
    /// Returns an error for changed originals, stale owner/placement revisions,
    /// invalid target reservation, or database failure.
    pub async fn admit_direct_upload(
        &self,
        deployment: &str,
        admission: &DirectUploadAdmission,
        owner_scope_key: &str,
        owner: &DirectSqlOwner,
        now: i64,
    ) -> Result<DirectUploadSessionRecord> {
        self.admit_direct_upload_checked(
            deployment,
            admission,
            owner_scope_key,
            owner,
            Vec::new(),
            now,
        )
        .await
    }

    /// Retains original admission with current credential and scoped IAM fences.
    ///
    /// # Errors
    /// Returns an error for revoked authority, changed originals or stale SQL fences.
    pub async fn admit_direct_upload_checked(
        &self,
        deployment: &str,
        admission: &DirectUploadAdmission,
        owner_scope_key: &str,
        owner: &DirectSqlOwner,
        authority_statements: Vec<CheckedStatement>,
        now: i64,
    ) -> Result<DirectUploadSessionRecord> {
        admission.validate(deployment)?;
        ensure!(
            now > 0 && !owner_scope_key.is_empty(),
            "invalid direct admission time or owner"
        );
        if let Some(existing) = self
            .direct_upload_session(deployment, &admission.session_id)
            .await?
        {
            ensure!(
                existing.admission == *admission
                    && existing.owner == *owner
                    && existing.owner_scope_key == owner_scope_key,
                DirectUploadRefusal {
                    code: DirectItemErrorCode::Conflict
                }
            );
            self.direct_batch(&existing)
                .checked_batch(
                    &[
                        vec![current_guard(&existing, now)?],
                        authority_statements.clone(),
                    ]
                    .concat(),
                )
                .await?;
            return Ok(existing);
        }
        ensure!(
            integer(admission.expires_at)? > now,
            "direct admission original horizon expired"
        );
        let (target_kind, cache, cache_identifier, publication, surface, oci, path, ticket) =
            owner_cells(owner, &admission.intent.target)?;
        if let Some(upload_id) = &oci {
            ensure!(
                self.backend
                    .query_opt(
                        "SELECT session_id FROM direct_upload_sessions WHERE oci_upload_id = ?1",
                        &vals![upload_id],
                    )
                    .await?
                    .is_none(),
                DirectUploadRefusal {
                    code: DirectItemErrorCode::Conflict
                }
            );
        }
        let mut statements = vec![Statement::new(
            "INSERT INTO direct_upload_sessions
               (session_id, deployment_id, principal_id, client_operation_id,
                target_kind, cache_id, cache_identifier, publication_id,
                surface_object_id, oci_upload_id, object_path, owner_scope_key,
                intent_json, admission_json, logical_fingerprint, source_sha256,
                declared_size, part_size, declared_dependency_phase, cache_ticket_id,
                state, expires_at, created_at, updated_at, resource_version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, 'admitted', ?21, ?22, ?22, 1)",
            vals![
                admission.session_id,
                deployment,
                admission.principal_id,
                admission.intent.client_operation_id,
                target_kind,
                cache,
                cache_identifier,
                publication,
                surface,
                oci,
                path,
                owner_scope_key,
                canonical(&admission.intent)?,
                canonical(admission)?,
                admission.logical_fingerprint,
                admission.intent.expected_sha256,
                integer(admission.intent.byte_size)?,
                integer(admission.intent.part_size)?,
                phase_name(admission.intent.dependency_phase),
                ticket,
                integer(admission.expires_at)?,
                now
            ],
        )
        .expecting(1)];
        for placement in &admission.placements {
            statements.push(
                Statement::new(
                    "INSERT INTO direct_upload_session_placements
                   (deployment_id, session_id, placement_id, placement_resource_version,
                    write_spec_version, binding_id, binding_resource_version,
                    binding_write_revision, placement_fingerprint, placement_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    vals![
                        deployment,
                        admission.session_id,
                        integer(placement.placement_id)?,
                        integer(placement.placement_resource_version)?,
                        integer(placement.write_spec_version)?,
                        integer(placement.binding_id)?,
                        integer(placement.binding_resource_version)?,
                        integer(placement.binding_write_revision)?,
                        placement.fingerprint(deployment)?,
                        canonical(placement)?
                    ],
                )
                .expecting(1),
            );
        }
        let record = DirectUploadSessionRecord {
            admission: admission.clone(),
            owner_scope_key: owner_scope_key.to_owned(),
            owner: owner.clone(),
            state: DirectSessionState::Creating,
            resource_version: WireInteger::new(1),
            final_dependency_phase: None,
            complete_intent: None,
            abort_intent: None,
            baselines: Vec::new(),
            stage_evidence: None,
            completion_evidence: None,
            final_guards: Vec::new(),
        };
        statements.push(current_guard(&record, now)?);
        statements.extend(authority_statements.clone());
        if let Err(error) = self.direct_batch(&record).checked_batch(&statements).await {
            // A concurrent exact admission may win; a business uniqueness conflict
            // with another session or immutable original remains a hard refusal.
            if let Some(existing) = self
                .direct_upload_session(deployment, &admission.session_id)
                .await?
            {
                if existing.admission == *admission
                    && existing.owner == *owner
                    && existing.owner_scope_key == owner_scope_key
                {
                    self.direct_batch(&existing)
                        .checked_batch(
                            &[
                                vec![current_guard(&existing, now)?],
                                authority_statements.clone(),
                            ]
                            .concat(),
                        )
                        .await?;
                    return Ok(existing);
                }
            }
            return Err(error).context("retaining direct admission");
        }
        Ok(record)
    }

    /// Retains the first complete intent before grants or staging are closed.
    ///
    /// Exact replay retains its original CAS version even after stage progress.
    /// The required manifests must cover the complete admitted placement set.
    ///
    /// # Errors
    /// Returns an error for stale initial CAS, changed first intent, incomplete
    /// destinations, expired authority or database failure.
    pub async fn retain_direct_complete(
        &self,
        deployment: &str,
        session_id: &str,
        intent: &DirectCompleteRequest,
        now: i64,
    ) -> Result<DirectUploadSessionRecord> {
        let record = self
            .direct_upload_session(deployment, session_id)
            .await?
            .context("direct upload session unavailable")?;
        validate_complete(&record.admission, intent, deployment)?;
        if let Some(original) = &record.complete_intent {
            ensure!(
                original == intent,
                DirectUploadRefusal {
                    code: DirectItemErrorCode::Conflict
                }
            );
            self.direct_batch(&record)
                .checked_batch(&[current_guard(&record, now)?])
                .await?;
            return Ok(record);
        }
        ensure!(
            record.state == DirectSessionState::Creating
                && record.resource_version == intent.expected_resource_version,
            DirectUploadRefusal {
                code: DirectItemErrorCode::Conflict
            }
        );
        self.direct_batch(&record)
            .checked_batch(&[
                current_guard(&record, now)?,
                Statement::new(
                    "INSERT INTO direct_upload_completion_intents
                   (deployment_id, session_id, operation_id, expected_resource_version,
                    intent_digest, intent_json, admitted_at)
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7 FROM direct_upload_sessions
                 WHERE deployment_id = ?1 AND session_id = ?2
                   AND resource_version = ?4 AND state = 'admitted' AND expires_at > ?7",
                    vals![
                        deployment,
                        session_id,
                        intent.operation_id,
                        integer(intent.expected_resource_version)?,
                        intent.fingerprint()?,
                        canonical(intent)?,
                        now
                    ],
                )
                .expecting(1),
            ])
            .await?;
        self.direct_upload_session(deployment, session_id)
            .await?
            .context("retained direct complete disappeared")
    }

    /// Reads an exact retained Complete after independent held-positive authorization.
    ///
    /// This path cannot create an intent, extend admission or reserve a destination.
    /// The service must first authenticate fresh positive stage provenance and IAM.
    ///
    /// # Errors
    /// Rejects absent positive originals, changed Complete, current pins or SQL failure.
    pub(crate) async fn retain_direct_positive_complete(
        &self,
        deployment: &str,
        session_id: &str,
        intent: &DirectCompleteRequest,
        now: i64,
    ) -> Result<DirectUploadSessionRecord> {
        let record = self
            .direct_upload_session(deployment, session_id)
            .await?
            .context("direct positive recovery session absent")?;
        validate_complete(&record.admission, intent, deployment)?;
        ensure!(
            record.state == DirectSessionState::StagedVerified
                && record.complete_intent.as_ref() == Some(intent)
                && record.stage_evidence.is_some()
                && record.baselines.len() == record.admission.placements.len(),
            "direct positive recovery original absent or changed"
        );
        self.direct_batch(&record)
            .checked_batch(&[current_guard_with_recovery(&record, now, true)?])
            .await?;
        Ok(record)
    }

    pub(crate) async fn retain_direct_verified_stage(
        &self,
        deployment: &str,
        record: &DirectUploadSessionRecord,
        evidence: &DirectVerifiedStageEvidence,
        phase: DirectDependencyPhase,
        now: i64,
    ) -> Result<()> {
        evidence.validate_against(&record.admission, deployment)?;
        let intent = record
            .complete_intent
            .as_ref()
            .context("direct complete original unavailable")?;
        ensure!(
            intent.operation_id == evidence.operation_id,
            "direct stage original operation mismatch"
        );
        if let Some(original) = &record.stage_evidence {
            ensure!(
                original == evidence && record.final_dependency_phase == Some(phase),
                DirectUploadRefusal {
                    code: DirectItemErrorCode::Conflict
                }
            );
            self.direct_batch(&record)
                .checked_batch(&[current_guard(record, now)?])
                .await?;
            return Ok(());
        }
        ensure!(
            record.state == DirectSessionState::Creating,
            "direct stage progress state mismatch"
        );
        integer(record.resource_version)?
            .checked_add(1)
            .context("direct resource version exhausted")?;
        self.direct_batch(&record)
            .checked_batch(&[
                current_guard(record, now)?,
                Statement::new(
                    "INSERT INTO direct_upload_stage_receipts
                   (deployment_id, session_id, operation_id, logical_fingerprint,
                    evidence_digest, evidence_json, verified_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    vals![
                        deployment,
                        evidence.session_id,
                        evidence.operation_id,
                        evidence.logical_fingerprint,
                        digest(evidence)?,
                        canonical(evidence)?,
                        now
                    ],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE direct_upload_sessions SET state = 'staged_verified',
                   final_dependency_phase = ?4, updated_at = ?5,
                   resource_version = resource_version + 1
                 WHERE deployment_id = ?1 AND session_id = ?2
                   AND resource_version = ?3 AND state = 'admitted' AND expires_at > ?5",
                    vals![
                        deployment,
                        evidence.session_id,
                        integer(record.resource_version)?,
                        phase_name(phase),
                        now
                    ],
                )
                .expecting(1),
            ])
            .await
    }

    pub(crate) async fn commit_direct_upload(
        &self,
        deployment: &str,
        record: &DirectUploadSessionRecord,
        evidence: &DirectCompletionEvidence,
        final_guards: &[DirectFinalGuardRecord],
        mut target_statements: Vec<CheckedStatement>,
        now: i64,
    ) -> Result<()> {
        evidence.validate_against(&record.admission, deployment)?;
        let complete = record
            .complete_intent
            .as_ref()
            .context("direct complete original unavailable")?;
        ensure!(
            complete.operation_id == evidence.operation_id,
            "direct commit original operation mismatch"
        );
        validate_final_guards(
            &record.admission,
            complete,
            evidence,
            final_guards,
            deployment,
        )?;
        if let Some(original) = &record.completion_evidence {
            ensure!(
                original == evidence && record.final_guards == final_guards,
                DirectUploadRefusal {
                    code: DirectItemErrorCode::Conflict
                }
            );
            return Ok(());
        }
        ensure!(
            record.state == DirectSessionState::StagedVerified
                && record.stage_evidence.is_some()
                && !target_statements.is_empty()
                && record.baselines.len() == record.admission.placements.len()
                && target_statements
                    .iter()
                    .any(|statement| statement.expected_rows == Some(1)),
            "direct atomic target commit unavailable"
        );
        for (guard, baseline) in final_guards.iter().zip(&record.baselines) {
            ensure!(
                guard.reservation == baseline.binding,
                "direct final original reservation changed"
            );
        }
        let stage = record
            .stage_evidence
            .as_ref()
            .context("direct stage original unavailable")?;
        ensure!(
            stage.projection == evidence.projection
                && stage.placements.len() == evidence.placements.len(),
            "direct final projection changed"
        );
        for (source, final_object) in stage.placements.iter().zip(&evidence.placements) {
            ensure!(
                source.manifest == final_object.manifest
                    && source.staging_incarnation == final_object.staging_incarnation,
                "direct final original stage changed"
            );
        }

        // Fresh independent final verification settles originals after expiry
        // without authorizing another provider effect.
        let mut statements = self.direct_publication_accounting_prefix(record).await?;
        statements.push(current_guard_with_recovery(record, now, true)?);
        statements.append(&mut target_statements);
        statements.push(Statement::new(
            "INSERT INTO direct_upload_completion_receipts
               (deployment_id, session_id, operation_id, logical_fingerprint,
                evidence_digest, evidence_json, final_guards_json, committed_at, resulting_resource_version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            vals![deployment, evidence.session_id, evidence.operation_id,
                evidence.logical_fingerprint, digest(evidence)?, canonical(evidence)?,
                canonical(&final_guards)?, now,
                integer(record.resource_version)?.checked_add(1)
                    .context("direct resource version exhausted")?],
        ).expecting(1));
        statements.push(
            Statement::new(
                "UPDATE direct_upload_sessions SET state = 'committed', completed_at = ?4,
               updated_at = ?4, resource_version = resource_version + 1
             WHERE deployment_id = ?1 AND session_id = ?2 AND resource_version = ?3
               AND state = 'staged_verified'",
                vals![
                    deployment,
                    evidence.session_id,
                    integer(record.resource_version)?,
                    now
                ],
            )
            .expecting(1),
        );
        self.direct_batch(&record).checked_batch(&statements).await
    }
}

fn validate_final_guards(
    admission: &DirectUploadAdmission,
    complete: &DirectCompleteRequest,
    evidence: &DirectCompletionEvidence,
    guards: &[DirectFinalGuardRecord],
    deployment: &str,
) -> Result<()> {
    ensure!(
        guards.len() == admission.placements.len(),
        "direct final receipt required set changed"
    );
    for (guard, placement) in guards.iter().zip(&admission.placements) {
        guard.validate_for(admission, complete, evidence, deployment)?;
        ensure!(
            guard.selected.manifest.placement == placement.public_ref(deployment)?,
            "direct final receipt destination order changed"
        );
    }
    Ok(())
}

fn current_guard(record: &DirectUploadSessionRecord, now: i64) -> Result<CheckedStatement> {
    current_guard_with_recovery(record, now, false)
}

// Cleanup retains all current actor and topology fences without renewing admission.
fn current_guard_with_recovery(
    record: &DirectUploadSessionRecord,
    now: i64,
    allow_expired_original: bool,
) -> Result<CheckedStatement> {
    ensure!(now > 0, "invalid direct current authorization time");
    let actor = &record.admission.actor_slot;
    let kind = match actor.kind {
        DirectActorKind::User => "user",
        DirectActorKind::ServiceAccount => "service_account",
    };
    Ok(Statement::new(
        "UPDATE direct_upload_sessions SET updated_at = updated_at
         WHERE session_id = ?1 AND logical_fingerprint = ?2 AND (?7 = 1 OR expires_at > ?3)
           AND EXISTS (SELECT 1 FROM authorization_scopes scope
             LEFT JOIN orgs org ON org.id = scope.org_id
             WHERE scope.scope_key = direct_upload_sessions.owner_scope_key
               AND scope.retired_at IS NULL AND (scope.org_id IS NULL OR org.deleted_at IS NULL))
           AND ((?4 = 'user' AND EXISTS (SELECT 1 FROM users owner
             WHERE owner.id = ?5 AND owner.principal_incarnation = ?6 AND owner.deleted_at IS NULL))
             OR (?4 = 'service_account' AND EXISTS (SELECT 1 FROM service_accounts owner
             JOIN orgs org ON org.id = owner.org_id WHERE owner.id = ?5
               AND owner.principal_incarnation = ?6 AND org.deleted_at IS NULL)))
           AND NOT EXISTS (SELECT 1 FROM direct_upload_session_placements original
             WHERE original.session_id = direct_upload_sessions.session_id
               AND NOT EXISTS (SELECT 1 FROM surface_placement_effective placement
                 JOIN bindings binding ON binding.id = placement.binding_id
                 WHERE placement.id = original.placement_id
                   AND placement.resource_version = original.placement_resource_version
                   AND placement.write_spec_version = original.write_spec_version
                   AND placement.binding_id = original.binding_id
                   AND placement.effective_write_enabled = 1
                   AND binding.resource_version = original.binding_resource_version
                   AND placement.authority_observed_binding_write_revision = original.binding_write_revision))",
        vals![record.admission.session_id, record.admission.logical_fingerprint, now,
            kind, integer(actor.numeric_id)?, actor.incarnation,
            allow_expired_original
                || matches!(record.state, DirectSessionState::Committed | DirectSessionState::Aborted)],
    ).expecting(1))
}

fn validate_complete(
    admission: &DirectUploadAdmission,
    intent: &DirectCompleteRequest,
    deployment: &str,
) -> Result<()> {
    intent.fingerprint()?;
    ensure!(
        intent.session.session_id == admission.session_id
            && intent.session.logical_fingerprint == admission.logical_fingerprint
            && intent.manifests.len() == admission.placements.len(),
        "direct complete original required set mismatch"
    );
    for (manifest, placement) in intent.manifests.iter().zip(&admission.placements) {
        ensure!(
            manifest.placement == placement.public_ref(deployment)?
                && manifest.part_count == admission.intent.part_count()?,
            "direct complete original placement mismatch"
        );
    }
    Ok(())
}

fn canonical<T: Serialize>(value: &T) -> Result<String> {
    Ok(String::from_utf8(encode_direct_control(value)?)?)
}

fn document<T: DeserializeOwned + Serialize>(value: &str) -> Result<T> {
    let result = decode_direct_control(value.as_bytes())?;
    ensure!(
        canonical(&result)? == value,
        "noncanonical retained direct document"
    );
    Ok(result)
}

fn digest<T: Serialize>(value: &T) -> Result<String> {
    Ok(hex::encode(Sha256::digest(encode_direct_control(value)?)))
}

fn integer(value: WireInteger) -> Result<i64> {
    Ok(i64::try_from(value.get())?)
}

fn phase_name(phase: DirectDependencyPhase) -> &'static str {
    match phase {
        DirectDependencyPhase::Content => "content",
        DirectDependencyPhase::LeafMetadata => "leaf_metadata",
        DirectDependencyPhase::Visibility => "visibility",
    }
}

fn parse_phase(value: &str) -> Result<DirectDependencyPhase> {
    match value {
        "content" => Ok(DirectDependencyPhase::Content),
        "leaf_metadata" => Ok(DirectDependencyPhase::LeafMetadata),
        "visibility" => Ok(DirectDependencyPhase::Visibility),
        _ => anyhow::bail!("invalid retained direct dependency phase"),
    }
}

type OwnerCells<'a> = (
    &'static str,
    Option<i64>,
    Option<&'a str>,
    Option<&'a str>,
    Option<i64>,
    Option<&'a str>,
    Option<&'a str>,
    Option<&'a str>,
);

fn owner_cells<'a>(
    owner: &'a DirectSqlOwner,
    target: &'a DirectUploadTarget,
) -> Result<OwnerCells<'a>> {
    match (owner, target) {
        (
            DirectSqlOwner::Cache {
                cache_id,
                ticket_id,
            },
            DirectUploadTarget::CacheObject {
                cache_id: identifier,
                path,
            },
        ) => {
            ensure!(
                *cache_id > 0 && valid_direct_identity(ticket_id),
                "invalid direct cache reservation"
            );
            Ok((
                "cache_object",
                Some(*cache_id),
                Some(identifier),
                None,
                None,
                None,
                Some(path),
                Some(ticket_id),
            ))
        }
        (
            DirectSqlOwner::Publication,
            DirectUploadTarget::PublicationObject {
                publication_id,
                surface_object_id,
                path,
            },
        ) => Ok((
            "publication_object",
            None,
            None,
            Some(publication_id),
            Some(integer(*surface_object_id)?),
            None,
            Some(path),
            None,
        )),
        (DirectSqlOwner::Oci, DirectUploadTarget::OciBlob { upload_id }) => Ok((
            "oci_blob",
            None,
            None,
            None,
            None,
            Some(upload_id),
            None,
            None,
        )),
        _ => anyhow::bail!("direct SQL owner target mismatch"),
    }
}

fn load_owner(row: &Row, target: &DirectUploadTarget) -> Result<DirectSqlOwner> {
    let owner = match target {
        DirectUploadTarget::CacheObject { .. } => DirectSqlOwner::Cache {
            cache_id: row.get(5)?,
            ticket_id: row.get(20)?,
        },
        DirectUploadTarget::PublicationObject { .. } => DirectSqlOwner::Publication,
        DirectUploadTarget::OciBlob { .. } => DirectSqlOwner::Oci,
    };
    let (kind, cache, identifier, publication, surface, oci, path, ticket) =
        owner_cells(&owner, target)?;
    ensure!(
        row.get::<String>(4)? == kind
            && row.get::<Option<i64>>(5)? == cache
            && row.get::<Option<String>>(6)?.as_deref() == identifier
            && row.get::<Option<String>>(7)?.as_deref() == publication
            && row.get::<Option<i64>>(8)? == surface
            && row.get::<Option<String>>(9)?.as_deref() == oci
            && row.get::<Option<String>>(10)?.as_deref() == path
            && row.get::<Option<String>>(20)?.as_deref() == ticket,
        "retained direct SQL target mismatch"
    );
    Ok(owner)
}
