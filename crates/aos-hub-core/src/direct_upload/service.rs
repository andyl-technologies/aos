//! Metadata-only logical direct-upload dispatch and retained lifecycle ordering.
//!
//! The configured authority resolves current IAM, topology and independently
//! qualified storage receipts. SQL retains immutable originals before effects;
//! final target statements, receipt and session progress share one transaction.

use std::sync::Arc;

use anyhow::{ensure, Context as _, Result};
use async_trait::async_trait;
use futures_util::{stream, StreamExt};

use crate::auth::jwt::Claims;
use crate::backend::CheckedStatement;
use crate::db::{Database, DirectSqlOwner, DirectUploadSessionRecord};

use super::*;

// Bounds remote authority reads and SQL work while preserving public item order.
const MAX_AUTHORITY_ITEM_CONCURRENCY: usize = 8;

/// Value-free refusal classification shared by configured authorities and SQL.
#[derive(Debug, thiserror::Error)]
#[error("direct logical control refused")]
pub struct DirectUploadRefusal {
    /// Stable public item failure code, without provider or private values.
    pub code: DirectItemErrorCode,
}

/// Server-resolved target reservation and immutable admission.
pub struct ResolvedDirectAdmission {
    /// Complete original admission, including independently pinned profiles.
    pub admission: DirectUploadAdmission,
    /// Current stable target scope used for every later authorization.
    pub owner_scope_key: String,
    /// Existing target accounting reservation retained before provider effects.
    pub owner: DirectSqlOwner,
    /// Current credential and scoped IAM fences executed with retained admission.
    pub authority_statements: Vec<CheckedStatement>,
}

/// Exact metadata phases eligible for held-positive recovery after producer expiry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectPositiveMetadataPhase {
    /// Reads the already retained original Complete without new provider effects.
    Freeze,
    /// Commits exact independently verified final receipts and logical accounting.
    Commit,
}

/// Configured current target and independent receipt authority.
///
/// Every method accepts bounded typed metadata. Implementations must refuse
/// absent qualification and must never replace guard lookup with broker MAC,
/// a client report, provider HEAD, or a structurally valid receipt document.
#[async_trait]
pub trait DirectUploadAuthority: Send + Sync {
    /// Creates isolated discovery state for exactly one logical invocation.
    ///
    /// A prepared profile readback may be shared only within this invocation;
    /// every reuse checks its exact context and current qualification deadline.
    fn invocation(&self) -> Arc<dyn DirectUploadAuthority>;

    /// Observes the current conservative bound from the qualified mutation clock.
    ///
    /// # Errors
    /// Returns an error for unavailable qualification, rollback or clock failure.
    fn current_time(&self) -> Result<i64>;

    /// Resolves current reusable target IAM and independently qualified profiles.
    ///
    /// # Errors
    /// Returns an error for revoked IAM, unavailable profiles or stale topology.
    async fn capabilities(
        &self,
        claims: &Claims,
        target: &DirectCapabilitiesTarget,
        now: i64,
    ) -> Result<DirectUploadCapabilities>;

    /// Resolves current IAM, target reservation, required placements and profiles.
    ///
    /// # Errors
    /// Returns an error for refused IAM, quota, stale topology or qualification.
    async fn resolve_admission(
        &self,
        claims: &Claims,
        context: &DirectRequestContext,
        intent: &DirectUploadIntent,
        now: i64,
    ) -> Result<ResolvedDirectAdmission>;

    /// Checks live target IAM and the original actor for the requested action.
    ///
    /// # Errors
    /// Returns an error for changed target ownership, revoked authority or barriers.
    async fn authorize_session(
        &self,
        claims: &Claims,
        context: &DirectRequestContext,
        record: &DirectUploadSessionRecord,
        action: DirectLogicalAction,
        metadata_phase: Option<DirectPositiveMetadataPhase>,
        now: i64,
    ) -> Result<()>;

    /// Independently verifies immutable stage provenance and classifies semantics.
    ///
    /// # Errors
    /// Returns an error for missing independent provenance or invalid semantics.
    async fn verify_stage(
        &self,
        context: &DirectRequestContext,
        record: &DirectUploadSessionRecord,
        evidence: &DirectVerifiedStageEvidence,
        now: i64,
    ) -> Result<DirectDependencyPhase>;

    /// Activates retained destination baselines and returns fresh permissions.
    ///
    /// # Errors
    /// Returns an error for changed originals, stale guard witnesses or quota.
    async fn baseline_permissions(
        &self,
        claims: &Claims,
        context: &DirectRequestContext,
        record: &DirectUploadSessionRecord,
        evidence: &[DirectDestinationBaselineEvidence],
        witnesses: &[DirectDestinationBaselineWitness],
        settled: &[DirectSettledPlacement],
        now: i64,
    ) -> Result<Vec<DirectDestinationBaselinePermission>>;

    /// Looks up exact current receipts independently and prepares target SQL.
    ///
    /// All target accounting, object presence, links and upload completion must
    /// be returned as checked statements without executing them separately.
    ///
    /// # Errors
    /// Returns an error for unavailable or changed guard receipts and target fences.
    async fn verify_final(
        &self,
        claims: &Claims,
        context: &DirectRequestContext,
        record: &DirectUploadSessionRecord,
        evidence: &DirectCompletionEvidence,
        guards: &[DirectFinalGuardRecord],
        now: i64,
    ) -> Result<Vec<CheckedStatement>>;

    /// Verifies explicit abort progress and builds atomic terminal target settlement.
    ///
    /// # Errors
    /// Returns an error for uncorrelated or unsupported terminal abort evidence.
    async fn verify_abort(
        &self,
        claims: &Claims,
        context: &DirectRequestContext,
        record: &DirectUploadSessionRecord,
        evidence: &DirectAbortEvidence,
        now: i64,
    ) -> Result<Vec<CheckedStatement>>;
}

/// Retained logical service whose configured authority owns current dependencies.
pub struct DirectUploadService {
    db: Arc<Database>,
    authority: Arc<dyn DirectUploadAuthority>,
}

impl DirectUploadService {
    /// Constructs metadata dispatch with an explicitly configured authority.
    #[must_use]
    pub fn new(db: Arc<Database>, authority: Arc<dyn DirectUploadAuthority>) -> Self {
        Self { db, authority }
    }

    /// Discovers current target profiles for the original authenticated actor.
    ///
    /// # Errors
    /// Returns an error for unavailable current identity, target IAM or profiles,
    /// or a reply that changes the exact resolved deployment/actor namespace.
    pub async fn get_capabilities(
        &self,
        claims: &Claims,
        target: &DirectCapabilitiesTarget,
        deployment: &str,
        now: i64,
    ) -> Result<DirectUploadCapabilities> {
        target.validate()?;
        let actor = self
            .db
            .current_authenticated_actor(claims)
            .await?
            .context("direct current authentication unavailable")?;
        let capabilities = self
            .authority
            .invocation()
            .capabilities(claims, target, now)
            .await?;
        capabilities.validate_at_for(target, u64::try_from(now)?)?;
        capabilities.validate_actor_for(deployment, &actor.principal_id(deployment)?)?;
        Ok(capabilities)
    }

    /// Dispatches one authenticated bounded logical envelope with per-item results.
    ///
    /// The transport verifies the domain-separated signature and exact audience
    /// before calling this method. Current token provenance is reloaded here.
    /// Terminal replay returns retained evidence without provider work.
    ///
    /// # Errors
    /// Returns an error for absent current authentication, invalid envelope or time.
    pub async fn dispatch(
        &self,
        claims: &Claims,
        envelope: &DirectLogicalRequestEnvelope,
        now: i64,
    ) -> Result<DirectUploadLogicalReply> {
        ensure!(now > 0, "invalid direct logical current time");
        let context = &envelope.context;
        context.validate(
            &context.deployment_id,
            &context.executor_public_origin,
            u64::try_from(now)?,
        )?;
        envelope.validate_transport(
            &context.public_method,
            &context.public_path,
            &context.public_authority,
            envelope.request.phase(),
        )?;
        let actor = self
            .db
            .current_authenticated_actor(claims)
            .await?
            .context("direct current authentication unavailable")?;
        let principal = actor.principal_id(&context.deployment_id)?;
        let authority = self.authority.invocation();
        let authority = &authority;
        let actor = &actor;
        let principal = &principal;
        let mut reply = DirectUploadLogicalReply {
            admissions: Vec::new(),
            sessions: Vec::new(),
            session_summaries: Vec::new(),
            authorizations: Vec::new(),
            baseline_permissions: Vec::new(),
            errors: Vec::new(),
        };

        match &envelope.request {
            DirectUploadLogicalRequest::Admission { intents } => {
                let work = intents
                    .iter()
                    .map(|intent| async move {
                        let result = async {
                            let resolved = authority
                                .resolve_admission(claims, context, intent, now)
                                .await?;
                            ensure!(
                                !resolved.authority_statements.is_empty()
                                    && resolved.admission.intent == *intent
                                    && &resolved.admission.actor_slot == actor
                                    && &resolved.admission.principal_id == principal,
                                "direct resolved actor or intent mismatch"
                            );
                            let now = self.refresh_time(claims, context, now)?;
                            self.db
                                .admit_direct_upload_checked(
                                    &context.deployment_id,
                                    &resolved.admission,
                                    &resolved.owner_scope_key,
                                    &resolved.owner,
                                    resolved.authority_statements,
                                    now,
                                )
                                .await
                        }
                        .await;
                        (intent, result)
                    })
                    .collect::<Vec<_>>();
                let results = stream::iter(work)
                    .buffered(MAX_AUTHORITY_ITEM_CONCURRENCY)
                    .collect::<Vec<_>>()
                    .await;
                for (intent, result) in results {
                    append_record(
                        &mut reply,
                        &context.deployment_id,
                        &intent.client_operation_id,
                        result,
                    )?;
                }
            }
            DirectUploadLogicalRequest::Authorize {
                action,
                complete_step,
                stage_evidence,
                retained_stage_digests,
                baseline_evidence,
                baseline_witnesses,
                baseline_witness_refs,
                settled_placements,
                sessions,
            } => {
                let expanded_witnesses = baseline_evidence
                    .iter()
                    .zip(baseline_witness_refs)
                    .map(|(baseline, reference)| reference.expand(baseline))
                    .collect::<Result<Vec<_>>>()?;
                let baseline_witnesses = if baseline_witness_refs.is_empty() {
                    baseline_witnesses
                } else {
                    &expanded_witnesses
                };
                let work = sessions
                    .iter()
                    .enumerate()
                    .map(|(index, session)| async move {
                        let result = async {
                            let mut record =
                                self.load_owned(context, &session.session, &actor).await?;
                            authority
                                .authorize_session(
                                    claims,
                                    context,
                                    &record,
                                    *action,
                                    if *complete_step == Some(DirectCompleteStep::Freeze) {
                                        Some(DirectPositiveMetadataPhase::Freeze)
                                    } else {
                                        None
                                    },
                                    now,
                                )
                                .await?;
                            let now = self.refresh_time(claims, context, now)?;
                            match action {
                                DirectLogicalAction::Complete => {
                                    let intent = session
                                        .complete_intent
                                        .as_ref()
                                        .context("direct Complete original absent")?;
                                    record = if *complete_step == Some(DirectCompleteStep::Freeze)
                                        && record.state == DirectSessionState::StagedVerified
                                        && record.baselines.len()
                                            == record.admission.placements.len()
                                    {
                                        self.db
                                            .retain_direct_positive_complete(
                                                &context.deployment_id,
                                                &session.session.session_id,
                                                intent,
                                                now,
                                            )
                                            .await?
                                    } else {
                                        self.db
                                            .retain_direct_complete(
                                                &context.deployment_id,
                                                &session.session.session_id,
                                                intent,
                                                now,
                                            )
                                            .await?
                                    };
                                    if record.state == DirectSessionState::Committed {
                                        return Ok((record, Vec::new()));
                                    }
                                    ensure!(
                                        record.abort_intent.is_none(),
                                        "direct session abort retained"
                                    );
                                    if matches!(
                                        complete_step,
                                        Some(
                                            DirectCompleteStep::Baseline
                                                | DirectCompleteStep::Promote
                                        )
                                    ) {
                                        let evidence = if *complete_step
                                            == Some(DirectCompleteStep::Promote)
                                        {
                                            retained_stage_digests
                                                .get(index)
                                                .context("direct retained stage reference absent")?
                                                .expand(record.stage_evidence.as_ref().context(
                                                    "direct verified retained stage absent",
                                                )?)?
                                        } else {
                                            stage_evidence
                                                .get(index)
                                                .context("direct immutable stage evidence absent")?
                                                .clone()
                                        };
                                        evidence.validate_against(
                                            &record.admission,
                                            &context.deployment_id,
                                        )?;
                                        let phase = authority
                                            .verify_stage(context, &record, &evidence, now)
                                            .await?;
                                        let now = self.refresh_time(claims, context, now)?;
                                        self.db
                                            .retain_direct_verified_stage(
                                                &context.deployment_id,
                                                &record,
                                                &evidence,
                                                phase,
                                                now,
                                            )
                                            .await?;
                                        record = self
                                            .load_owned(context, &session.session, &actor)
                                            .await?;
                                    }
                                    if *complete_step == Some(DirectCompleteStep::Promote) {
                                        let mut baselines = Vec::new();
                                        let mut witnesses = Vec::new();
                                        for (baseline, witness) in
                                            baseline_evidence.iter().zip(baseline_witnesses)
                                        {
                                            if baseline.binding.session == session.session {
                                                baselines.push(baseline.clone());
                                                witnesses.push(witness.clone());
                                            }
                                        }
                                        let settled = settled_placements
                                            .iter()
                                            .filter(|item| {
                                                item.guard.selected.session == session.session
                                            })
                                            .cloned()
                                            .collect::<Vec<_>>();
                                        for item in &settled {
                                            item.guard.validate_placement_for(
                                                &record.admission,
                                                record
                                                    .complete_intent
                                                    .as_ref()
                                                    .context("direct original Complete absent")?,
                                                &item.evidence,
                                                &context.deployment_id,
                                            )?;
                                            let original_stage = record
                                                .stage_evidence
                                                .as_ref()
                                                .context("direct settled original stage absent")?;
                                            let source_matches =
                                                original_stage.placements.iter().any(|original| {
                                                    original.manifest == item.evidence.manifest
                                                        && original.staging_incarnation
                                                            == item.evidence.staging_incarnation
                                                });
                                            ensure!(
                                                source_matches,
                                                "direct settled original source changed"
                                            );
                                        }
                                        let permissions = authority
                                            .baseline_permissions(
                                                claims, context, &record, &baselines, &witnesses,
                                                &settled, now,
                                            )
                                            .await?;
                                        return Ok((record, permissions));
                                    }
                                }
                                DirectLogicalAction::Abort => {
                                    let intent = DirectAbortRequest {
                                        session: session.session.clone(),
                                        operation_id: session.operation_id.clone(),
                                        expected_resource_version: session
                                            .expected_resource_version
                                            .context("direct Abort original CAS absent")?,
                                    };
                                    record = self
                                        .db
                                        .retain_direct_abort(&context.deployment_id, &intent, now)
                                        .await?;
                                }
                                DirectLogicalAction::GrantParts
                                | DirectLogicalAction::ReportParts => {
                                    ensure!(
                                        record.state != DirectSessionState::BlockedUnknown,
                                        DirectUploadRefusal {
                                            code: DirectItemErrorCode::BlockedUnknown
                                        }
                                    );
                                    ensure!(
                                        record.state == DirectSessionState::Creating
                                            && record.complete_intent.is_none()
                                            && record.abort_intent.is_none(),
                                        DirectUploadRefusal {
                                            code: DirectItemErrorCode::Conflict
                                        }
                                    );
                                }
                                DirectLogicalAction::Status => {}
                            }
                            Ok((record, Vec::new()))
                        }
                        .await;
                        (session, result)
                    })
                    .collect::<Vec<_>>();
                let results = stream::iter(work)
                    .buffered(MAX_AUTHORITY_ITEM_CONCURRENCY)
                    .collect::<Vec<_>>()
                    .await;
                for (session, result) in results {
                    match result {
                        Ok((record, permissions)) => {
                            // Freeze returns retained originals. Later complete phases
                            // acknowledge exact authorizations without repeating those
                            // bounded but large admission and manifest snapshots.
                            if !matches!(
                                complete_step,
                                Some(DirectCompleteStep::Baseline | DirectCompleteStep::Promote)
                            ) {
                                if *complete_step == Some(DirectCompleteStep::Freeze) {
                                    let status = record.status(&context.deployment_id)?;
                                    reply.session_summaries.push(DirectLogicalSessionSummary {
                                        session: status.session,
                                        resource_version: status.resource_version,
                                        state: status.state,
                                        outstanding_grants: status.outstanding_grants,
                                    });
                                } else {
                                    reply.sessions.push(record.status(&context.deployment_id)?);
                                }
                                reply.admissions.push(record.admission);
                            }
                            reply.authorizations.push(session.clone());
                            reply.baseline_permissions.extend(permissions);
                        }
                        Err(error) => push_error(&mut reply, &session.session.session_id, &error),
                    }
                }
            }
            DirectUploadLogicalRequest::Commit {
                evidence,
                final_guards: _,
                final_guard_refs,
            } => {
                let work = evidence
                    .iter()
                    .map(|item| async move {
                        let result = async {
                            let session = DirectSessionRef {
                                session_id: item.session_id.clone(),
                                logical_fingerprint: item.logical_fingerprint.clone(),
                            };
                            let record = self.load_owned(context, &session, &actor).await?;
                            authority
                                .authorize_session(
                                    claims,
                                    context,
                                    &record,
                                    DirectLogicalAction::Complete,
                                    Some(DirectPositiveMetadataPhase::Commit),
                                    now,
                                )
                                .await?;
                            let complete = record
                                .complete_intent
                                .as_ref()
                                .context("direct Complete original absent")?;
                            let guards = final_guard_refs
                                .iter()
                                .filter(|reference| reference.session == session)
                                .map(|reference| {
                                    reference.expand(
                                        &record.admission,
                                        complete,
                                        item,
                                        &record.baselines,
                                        &context.deployment_id,
                                    )
                                })
                                .collect::<Result<Vec<_>>>()?;
                            if let Some(original) = &record.completion_evidence {
                                ensure!(
                                    original == item && record.final_guards == guards,
                                    "direct terminal replay changed"
                                );
                                self.refresh_time(claims, context, now)?;
                                return Ok(record);
                            }
                            ensure!(
                                guards.len() == record.admission.placements.len(),
                                "direct final guard required set absent"
                            );
                            for guard in &guards {
                                guard.validate_for(
                                    &record.admission,
                                    complete,
                                    item,
                                    &context.deployment_id,
                                )?;
                            }
                            let statements = authority
                                .verify_final(claims, context, &record, item, &guards, now)
                                .await?;
                            let now = self.refresh_time(claims, context, now)?;
                            let expires_at = context.expires_at.get()
                                .min(u64::try_from(claims.exp)?);
                            let remaining = expires_at.checked_sub(u64::try_from(now)?)
                                .filter(|seconds| *seconds > 0)
                                .context("direct final SQL authority expired")?;
                            // A blocked SQL transaction cannot outlive the exact
                            // lookup or authenticated claims window. Cancellation provides no
                            // settlement assertion; exact retained replay resolves
                            // a possibly committed result after the reply is lost.
                            let transaction = self.db.commit_direct_upload(
                                &context.deployment_id,
                                &record,
                                item,
                                &guards,
                                statements,
                                now,
                            );
                            let deadline = crate::clock::sleep(
                                std::time::Duration::from_secs(remaining),
                            );
                            futures_util::pin_mut!(transaction, deadline);
                            match futures_util::future::select(transaction, deadline).await {
                                futures_util::future::Either::Left((result, _)) => result?,
                                futures_util::future::Either::Right(((), _)) => {
                                    anyhow::bail!("direct final SQL outcome unavailable at authority deadline");
                                }
                            }
                            // Both futures can become ready before a delayed executor
                            // polls select. A SQL result never extends reply authority.
                            let after_commit = self.refresh_time(claims, context, now)?;
                            let committed = self.load_owned(context, &session, &actor).await?;
                            self.refresh_time(claims, context, after_commit)?;
                            Ok(committed)
                        }
                        .await;
                        (item, result)
                    })
                    .collect::<Vec<_>>();
                let results = stream::iter(work)
                    .buffered(MAX_AUTHORITY_ITEM_CONCURRENCY)
                    .collect::<Vec<_>>()
                    .await;
                for (item, result) in results {
                    // A different batch item may have waited after this one loaded
                    // its receipt. Expiry refuses ACK without rewriting SQL outcome.
                    let result = result.and_then(|record| {
                        self.refresh_time(claims, context, now)?;
                        Ok(record)
                    });
                    append_record(&mut reply, &context.deployment_id, &item.session_id, result)?;
                }
            }
            DirectUploadLogicalRequest::AbortReport { outcomes } => {
                let work = outcomes
                    .iter()
                    .map(|item| async move {
                        let result = async {
                            let record = self.load_owned(context, &item.session, &actor).await?;
                            authority
                                .authorize_session(
                                    claims,
                                    context,
                                    &record,
                                    DirectLogicalAction::Abort,
                                    None,
                                    now,
                                )
                                .await?;
                            let target_statements = if record.state == DirectSessionState::Aborted {
                                Vec::new()
                            } else {
                                let statements = authority
                                    .verify_abort(claims, context, &record, item, now)
                                    .await?;
                                ensure!(
                                    (item.outcome == DirectAbortOutcome::Aborted)
                                        == !statements.is_empty(),
                                    "direct abort target settlement plan mismatch"
                                );
                                statements
                            };
                            let now = self.refresh_time(claims, context, now)?;
                            self.db
                                .report_direct_abort_checked(
                                    &context.deployment_id,
                                    &record,
                                    item,
                                    target_statements,
                                    now,
                                )
                                .await?;
                            self.load_owned(context, &item.session, &actor).await
                        }
                        .await;
                        (item, result)
                    })
                    .collect::<Vec<_>>();
                let results = stream::iter(work)
                    .buffered(MAX_AUTHORITY_ITEM_CONCURRENCY)
                    .collect::<Vec<_>>()
                    .await;
                for (item, result) in results {
                    append_record(
                        &mut reply,
                        &context.deployment_id,
                        &item.session.session_id,
                        result,
                    )?;
                }
            }
        }
        reply.validate(&context.deployment_id)?;
        Ok(reply)
    }

    fn refresh_time(
        &self,
        claims: &Claims,
        context: &DirectRequestContext,
        prior: i64,
    ) -> Result<i64> {
        let now = self.authority.current_time()?;
        ensure!(
            now >= prior,
            "direct qualified mutation clock moved backwards"
        );
        context.validate(
            &context.deployment_id,
            &context.executor_public_origin,
            u64::try_from(now)?,
        )?;
        ensure!(
            claims.iat <= now && now < claims.exp,
            DirectUploadRefusal {
                code: DirectItemErrorCode::Denied,
            }
        );
        Ok(now)
    }

    async fn load_owned(
        &self,
        context: &DirectRequestContext,
        session: &DirectSessionRef,
        actor: &DirectActorSlot,
    ) -> Result<DirectUploadSessionRecord> {
        let record = self
            .db
            .direct_upload_session(&context.deployment_id, &session.session_id)
            .await?
            .context("direct original unavailable")?;
        ensure!(
            record.admission.actor_slot == *actor
                && record.admission.logical_fingerprint == session.logical_fingerprint,
            DirectUploadRefusal {
                code: DirectItemErrorCode::Denied
            }
        );
        Ok(record)
    }
}

fn append_record(
    reply: &mut DirectUploadLogicalReply,
    deployment: &str,
    item_id: &str,
    result: Result<DirectUploadSessionRecord>,
) -> Result<()> {
    match result {
        Ok(record) => {
            reply.sessions.push(record.status(deployment)?);
            reply.admissions.push(record.admission);
        }
        Err(error) => push_error(reply, item_id, &error),
    }
    Ok(())
}

fn push_error(reply: &mut DirectUploadLogicalReply, item_id: &str, error: &anyhow::Error) {
    let code = error
        .downcast_ref::<DirectUploadRefusal>()
        .map_or(DirectItemErrorCode::Unavailable, |refusal| refusal.code);
    reply.errors.push(DirectItemError {
        item_id: item_id.to_owned(),
        code,
    });
}
