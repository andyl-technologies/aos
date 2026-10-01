//! Current Native target admission and independently authenticated storage receipts.
//!
//! Native accepts bounded metadata only. Reviewed runtime acceptance, live SQL
//! authority and fresh physical guard readback all precede logical visibility.

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::{
    auth::jwt::{Claims, JwtKeys},
    backend::CheckedStatement,
    db::{Database, DirectSqlOwner, DirectUploadSessionRecord, SurfaceTarget, WriteObjectIdentity},
    direct_upload::*,
    service::RpcService,
    storage_work::StorageWorkKey,
};
use async_trait::async_trait;

mod acceptance;
mod targets;
mod transport;

pub use acceptance::NativeDirectUploadAcceptances;

/// Configured Native runtime using independently accepted protected profiles.
pub struct NativeDirectUploadRuntime {
    origin: String,
    deployment: String,
    storage_key: StorageWorkKey,
    guard_key: StorageWorkKey,
    acceptances: Arc<NativeDirectUploadAcceptances>,
    clock_uncertainty_seconds: u64,
}

enum RuntimeFacts {
    CurrentProducer,
    PositiveMetadataRecovery,
}

impl NativeDirectUploadRuntime {
    /// Constructs a runtime whose independent guard key differs from the broker key.
    ///
    /// # Errors
    /// Returns an error for invalid origin, deployment, missing current acceptance,
    /// incompatible clock qualifications or reused authentication keys.
    pub fn new(
        origin: &str,
        deployment: &str,
        storage_key: &[u8],
        guard_key: &[u8],
        acceptances: NativeDirectUploadAcceptances,
    ) -> Result<Self> {
        Self::configured(
            origin,
            deployment,
            storage_key,
            guard_key,
            acceptances,
            RuntimeFacts::CurrentProducer,
        )
    }

    /// Constructs a runtime retaining reviewed clock and guard facts after expiry.
    ///
    /// The acceptance loader must independently authenticate historical facts.
    /// Provider dispatch still requires current acceptance; recovery authorizes
    /// only exact held-positive metadata with fresh independent guard readback.
    ///
    /// # Errors
    /// Rejects invalid audience, absent reviewed facts, incompatible clock policies
    /// or reused broker/guard authentication keys.
    pub fn new_for_positive_recovery(
        origin: &str,
        deployment: &str,
        storage_key: &[u8],
        guard_key: &[u8],
        acceptances: NativeDirectUploadAcceptances,
    ) -> Result<Self> {
        Self::configured(
            origin,
            deployment,
            storage_key,
            guard_key,
            acceptances,
            RuntimeFacts::PositiveMetadataRecovery,
        )
    }

    fn configured(
        origin: &str,
        deployment: &str,
        storage_key: &[u8],
        guard_key: &[u8],
        acceptances: NativeDirectUploadAcceptances,
        facts: RuntimeFacts,
    ) -> Result<Self> {
        let url = url::Url::parse(origin)?;
        let canonical = url.origin().ascii_serialization();
        ensure!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.path() == "/"
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && valid_direct_identity(deployment)
                && storage_key != guard_key,
            "invalid direct Native runtime configuration"
        );
        let profiles = match facts {
            RuntimeFacts::CurrentProducer => {
                acceptances.profiles(deployment, &canonical, current_time()?)?
            }
            RuntimeFacts::PositiveMetadataRecovery => {
                acceptances.retained_clock_policy(deployment, &canonical)?;
                acceptances.retained_profiles(deployment, &canonical)?
            }
        };
        let mut uncertainties = profiles.iter().map(|profile| match profile {
            DirectProtectedProfile::Managed { profile, .. } => {
                profile.clock_uncertainty_seconds.get()
            }
            DirectProtectedProfile::External { profile, .. } => {
                profile.clock_uncertainty.get() as u64
            }
        });
        let uncertainty = uncertainties
            .next()
            .context("direct acceptance has no clock policy")?;
        ensure!(
            (1..30).contains(&uncertainty) && uncertainties.all(|item| item == uncertainty),
            "direct accepted clock policies differ"
        );
        Ok(Self {
            origin: canonical,
            deployment: deployment.to_owned(),
            storage_key: StorageWorkKey::new(storage_key)?,
            guard_key: StorageWorkKey::new(guard_key)?,
            acceptances: Arc::new(acceptances),
            clock_uncertainty_seconds: uncertainty,
        })
    }
}

impl super::DirectUploadTransportFactory for NativeDirectUploadRuntime {
    fn build(
        &self,
        db: Arc<Database>,
        rpc: Arc<RpcService>,
        jwt_keys: JwtKeys,
        deployment: &str,
    ) -> Result<Arc<super::DirectUploadTransport>> {
        ensure!(
            deployment == self.deployment,
            "direct Native deployment changed"
        );
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()?;
        let authority = NativeDirectUploadAuthority {
            db: Arc::clone(&db),
            rpc,
            origin: self.origin.clone(),
            deployment: self.deployment.clone(),
            storage_key: self.storage_key.clone(),
            guard_key: self.guard_key.clone(),
            acceptances: Arc::clone(&self.acceptances),
            http,
            clock_uncertainty_seconds: self.clock_uncertainty_seconds,
            discovery: Arc::new(tokio::sync::OnceCell::new()),
            lookup_slots: Arc::new(tokio::sync::Semaphore::new(8)),
        };
        Ok(Arc::new(super::DirectUploadTransport::new(
            DirectUploadService::new(db, Arc::new(authority)),
            jwt_keys,
            self.storage_key.clone(),
            self.deployment.clone(),
            self.origin.clone(),
            self.clock_uncertainty_seconds,
        )?))
    }
}

#[derive(Clone)]
struct NativeDirectUploadAuthority {
    db: Arc<Database>,
    rpc: Arc<RpcService>,
    origin: String,
    deployment: String,
    storage_key: StorageWorkKey,
    guard_key: StorageWorkKey,
    acceptances: Arc<NativeDirectUploadAcceptances>,
    http: reqwest::Client,
    discovery: Arc<tokio::sync::OnceCell<transport::VerifiedDiscovery>>,
    lookup_slots: Arc<tokio::sync::Semaphore>,
    clock_uncertainty_seconds: u64,
}

#[async_trait]
impl DirectUploadAuthority for NativeDirectUploadAuthority {
    fn invocation(&self) -> Arc<dyn DirectUploadAuthority> {
        let mut scoped = self.clone();
        scoped.discovery = Arc::new(tokio::sync::OnceCell::new());
        scoped.lookup_slots = Arc::new(tokio::sync::Semaphore::new(8));
        Arc::new(scoped)
    }

    fn current_time(&self) -> Result<i64> {
        Ok(i64::try_from(self.latest_now()?)?)
    }

    async fn capabilities(
        &self,
        claims: &Claims,
        target: &DirectCapabilitiesTarget,
        now: i64,
    ) -> Result<DirectUploadCapabilities> {
        self.resolve_capabilities(claims, target, now).await
    }

    async fn resolve_admission(
        &self,
        claims: &Claims,
        context: &DirectRequestContext,
        intent: &DirectUploadIntent,
        now: i64,
    ) -> Result<ResolvedDirectAdmission> {
        intent.validate()?;
        let actor = self.current_actor(claims).await?;
        let principal = actor.principal_id(&self.deployment)?;
        let session_id = deterministic_business_operation_id(
            &self.deployment,
            &principal,
            &intent.client_operation_id,
        )?;
        if let Some(original) = self
            .db
            .direct_upload_session(&self.deployment, &session_id)
            .await?
        {
            ensure!(
                original.admission.intent == *intent && original.admission.actor_slot == actor,
                "direct original operation conflicts"
            );
            if !matches!(
                original.state,
                DirectSessionState::Committed | DirectSessionState::Aborted
            ) {
                self.current_profiles(context, self.current_time()?).await?;
                self.ensure_new_effect_accounting(intent).await?;
            }
            self.authorize_session(
                claims,
                context,
                &original,
                DirectLogicalAction::Status,
                None,
                now,
            )
            .await?;
            return Ok(ResolvedDirectAdmission {
                authority_statements: self
                    .db
                    .direct_iam_statements(
                        claims,
                        &original.owner_scope_key,
                        target_permission(&original),
                        self.current_time()?,
                    )
                    .await?,
                admission: original.admission,
                owner_scope_key: original.owner_scope_key,
                owner: original.owner,
            });
        }

        self.ensure_new_effect_accounting(intent).await?;
        let mut target = self
            .resolve_target(claims, &actor, intent, false, now)
            .await?;
        let profiles = self.current_profiles(context, now).await?;
        let mut placements = Vec::new();
        for row in &target.placements {
            placements.push(
                self.resolve_placement(row, &target.path, intent, &profiles)
                    .await?,
            );
        }
        ensure!(
            !placements.is_empty() && placements.len() <= MAX_DIRECT_PLACEMENTS,
            "direct target has no bounded required placements"
        );
        ensure!(
            intent.byte_size.get() > 0
                || placements.iter().all(|placement| matches!(
                    placement.physical,
                    DirectPhysicalContext::DeploymentR2 { .. }
                )),
            DirectUploadRefusal {
                code: DirectItemErrorCode::Unsupported
            }
        );
        // Pointer preparation and quota reservation follow the complete physical
        // plan check. External empty puts cannot yet be independently aborted.
        if matches!(target.owner, targets::TargetOwner::Publication) {
            self.current_profiles(context, self.current_time()?).await?;
            let original_plan = placements.clone();
            target = self
                .resolve_target(claims, &actor, intent, true, self.current_time()?)
                .await?;
            placements.clear();
            for row in &target.placements {
                placements.push(
                    self.resolve_placement(row, &target.path, intent, &profiles)
                        .await?,
                );
            }
            ensure!(
                placements == original_plan,
                DirectUploadRefusal {
                    code: DirectItemErrorCode::Conflict
                }
            );
        }
        placements.sort_by_key(|item| item.placement_id);
        ensure!(
            !placements.is_empty() && placements.len() <= MAX_DIRECT_PLACEMENTS,
            "direct target has no bounded required placements"
        );
        let now = self.current_time()?;
        self.current_profiles(context, now).await?;
        let expires_at = WireInteger::new(u64::try_from(
            target.expires_at.min(now.saturating_add(3600)),
        )?);
        let mut admission = DirectUploadAdmission {
            session_id: session_id.clone(),
            principal_id: principal,
            actor_slot: actor,
            intent: intent.clone(),
            logical_fingerprint: String::new(),
            expires_at,
            placements,
        };
        admission.logical_fingerprint = admission.fingerprint(&self.deployment)?;
        let owner = match target.owner {
            targets::TargetOwner::Cache(cache) => {
                ensure!(
                    admission.placements.len() == 1,
                    "cache direct writer must be singular"
                );
                let placement = &admission.placements[0];
                let ticket = if let Some(ticket) = self.db.cache_write_ticket(&session_id).await? {
                    ensure!(
                        ticket.cache_id == cache.id
                            && ticket.object_key == target.path
                            && ticket.declared_size == i64::try_from(intent.byte_size.get())?
                            && ticket.placement_id == i64::try_from(placement.placement_id.get())?,
                        "direct original cache ticket conflicts"
                    );
                    ticket
                } else {
                    let write_revision = self
                        .db
                        .binding_write_revision(
                            i64::try_from(placement.binding_id.get())?,
                            i64::try_from(placement.binding_write_revision.get())?,
                        )
                        .await?
                        .context("direct SQL writer revision absent")?;
                    self.db
                        .begin_cache_write_ticket(
                            &session_id,
                            cache.id,
                            i64::try_from(placement.placement_id.get())?,
                            i64::try_from(placement.placement_resource_version.get())?,
                            i64::try_from(placement.binding_write_revision.get())?,
                            write_revision.write_credential_generation,
                            &target.path,
                            i64::try_from(intent.byte_size.get())?,
                            "single",
                            cache.org_id,
                            0,
                            0,
                            i64::try_from(expires_at.get())?,
                            now,
                            None,
                            None,
                        )
                        .await?
                };
                admission.expires_at = WireInteger::new(u64::try_from(ticket.expires_at)?);
                admission.logical_fingerprint = admission.fingerprint(&self.deployment)?;
                DirectSqlOwner::Cache {
                    cache_id: cache.id,
                    ticket_id: session_id,
                }
            }
            targets::TargetOwner::Publication => DirectSqlOwner::Publication,
            targets::TargetOwner::Oci(upload) => {
                self.db.reserve_direct_oci_source(&upload, now).await?;
                DirectSqlOwner::Oci
            }
        };
        // Revalidate signed owner and IAM after storage discovery/reservation awaits.
        self.resolve_target(claims, &admission.actor_slot, intent, false, now)
            .await?;
        let permission = if matches!(owner, DirectSqlOwner::Cache { .. }) {
            aos_hub_core::domain::Permission::RegistryConfigure
        } else {
            aos_hub_core::domain::Permission::Publish
        };
        let authority_statements = self
            .db
            .direct_iam_statements(claims, &target.scope, permission, self.current_time()?)
            .await?;
        Ok(ResolvedDirectAdmission {
            admission,
            owner_scope_key: target.scope,
            owner,
            authority_statements,
        })
    }

    async fn authorize_session(
        &self,
        claims: &Claims,
        context: &DirectRequestContext,
        record: &DirectUploadSessionRecord,
        action: DirectLogicalAction,
        metadata_phase: Option<DirectPositiveMetadataPhase>,
        now: i64,
    ) -> Result<()> {
        let target = self
            .resolve_target(
                claims,
                &record.admission.actor_slot,
                &record.admission.intent,
                false,
                now,
            )
            .await?;
        ensure!(
            target.scope == record.owner_scope_key,
            "direct original target scope changed"
        );
        if matches!(
            record.state,
            DirectSessionState::Committed | DirectSessionState::Aborted
        ) || matches!(
            action,
            DirectLogicalAction::Status | DirectLogicalAction::Abort
        ) {
            return Ok(());
        }
        let recovering_positive = metadata_phase.is_some()
            && (u64::try_from(now)? >= record.admission.expires_at.get()
                || self
                    .acceptances
                    .profiles(&self.deployment, &self.origin, u64::try_from(now)?)
                    .is_err());
        if metadata_phase.is_none() && action == DirectLogicalAction::Complete {
            self.ensure_new_effect_accounting(&record.admission.intent)
                .await?;
        }
        let profiles = if recovering_positive {
            ensure!(
                action == DirectLogicalAction::Complete
                    && record.state == DirectSessionState::StagedVerified
                    && record.complete_intent.is_some()
                    && record.baselines.len() == record.admission.placements.len(),
                "direct held-positive metadata original absent"
            );
            let stage = record
                .stage_evidence
                .as_ref()
                .context("direct held-positive stage absent")?;
            stage.validate_against(&record.admission, &self.deployment)?;
            self.lookup_stage(context, record, stage, now).await?;
            self.acceptances
                .retained_profiles(&self.deployment, &self.origin)?
        } else {
            ensure!(
                u64::try_from(now)? < record.admission.expires_at.get(),
                "direct original admission expired"
            );
            self.current_profiles(context, now).await?
        };
        ensure!(
            target.placements.len() == record.admission.placements.len(),
            "direct required placement set changed"
        );
        for (row, original) in target.placements.iter().zip(&record.admission.placements) {
            let current = self
                .resolve_placement(row, &target.path, &record.admission.intent, &profiles)
                .await?;
            ensure!(
                current == *original,
                "direct immutable placement or profile changed"
            );
        }
        Ok(())
    }

    async fn verify_stage(
        &self,
        context: &DirectRequestContext,
        record: &DirectUploadSessionRecord,
        evidence: &DirectVerifiedStageEvidence,
        now: i64,
    ) -> Result<DirectDependencyPhase> {
        evidence.validate_against(&record.admission, &self.deployment)?;
        self.lookup_stage(context, record, evidence, now).await?;
        self.classify_stage(record, evidence).await
    }

    async fn baseline_permissions(
        &self,
        claims: &Claims,
        context: &DirectRequestContext,
        record: &DirectUploadSessionRecord,
        evidence: &[DirectDestinationBaselineEvidence],
        witnesses: &[DirectDestinationBaselineWitness],
        settled: &[DirectSettledPlacement],
        now: i64,
    ) -> Result<Vec<DirectDestinationBaselinePermission>> {
        use futures_util::{stream, StreamExt as _, TryStreamExt as _};
        use std::collections::BTreeSet;

        ensure!(
            u64::try_from(now)? < record.admission.expires_at.get(),
            "direct baseline original expired"
        );
        self.ensure_new_effect_accounting(&record.admission.intent)
            .await?;
        self.current_profiles(context, now).await?;
        let complete = record
            .complete_intent
            .as_ref()
            .context("direct Complete original absent")?;
        ensure!(
            evidence.len() == witnesses.len()
                && evidence.len() + settled.len() == record.admission.placements.len(),
            "direct baseline and settled partition differs"
        );
        ensure!(
            settled.is_empty() || record.baselines.len() == record.admission.placements.len(),
            "direct partial promotion has no complete original baseline set"
        );
        let originals = if record.baselines.is_empty() {
            evidence.to_vec()
        } else {
            record.baselines.clone()
        };
        let mut selected = BTreeSet::new();
        let mut permissions = Vec::new();
        for (baseline, witness) in evidence.iter().zip(witnesses) {
            let placement_id = baseline.binding.placement.placement_id;
            let original = record
                .admission
                .placements
                .iter()
                .find(|item| item.placement_id == placement_id)
                .context("direct baseline destination differs")?;
            ensure!(
                selected.insert(placement_id),
                "duplicate direct destination"
            );
            ensure!(
                originals.iter().any(|item| item == baseline),
                "direct retained baseline changed"
            );
            baseline.binding.validate_for(
                &record.admission,
                complete,
                &self.deployment,
                &original.protected_profile_digest,
            )?;
            witness.validate_for(baseline, context, self.latest_now()?)?;
            permissions.push(DirectDestinationBaselinePermission {
                binding: baseline.binding.clone(),
                baseline_digest: baseline.fingerprint()?,
                witness_digest: witness.fingerprint()?,
                request_nonce: context.request_nonce.clone(),
                expires_at: WireInteger::new(
                    context.expires_at.get().min(witness.expires_at.get()).min(
                        self.acceptances.valid_until(
                            &self.deployment,
                            &self.origin,
                            self.latest_now()?,
                        )?,
                    ),
                ),
            });
        }
        for item in settled {
            item.guard.validate_placement_for(
                &record.admission,
                complete,
                &item.evidence,
                &self.deployment,
            )?;
            ensure!(
                selected.insert(item.evidence.placement_id),
                "duplicate direct settled destination"
            );
            ensure!(
                originals
                    .iter()
                    .any(|baseline| baseline.binding == item.guard.reservation),
                "direct settled original reservation changed"
            );
        }
        let baseline_lookups = evidence
            .iter()
            .zip(witnesses)
            .map(|(baseline, witness)| {
                self.lookup_baseline(context, record, baseline, witness, now)
            })
            .collect::<Vec<_>>();
        stream::iter(baseline_lookups)
            .buffer_unordered(8)
            .try_collect::<Vec<_>>()
            .await?;
        let settled_lookups = settled
            .iter()
            .map(|item| self.lookup_final(context, record, &item.guard, now))
            .collect::<Vec<_>>();
        stream::iter(settled_lookups)
            .buffer_unordered(8)
            .try_collect::<Vec<_>>()
            .await?;

        let fresh_now = self.current_time()?;
        context.validate(&self.deployment, &self.origin, u64::try_from(fresh_now)?)?;
        for (baseline, witness) in evidence.iter().zip(witnesses) {
            witness.validate_for(baseline, context, u64::try_from(fresh_now)?)?;
        }
        let activation = if record.baselines.is_empty() {
            self.cache_baseline_activation(record, &originals, fresh_now)
                .await?
        } else {
            Vec::new()
        };
        let mut authority = self
            .db
            .direct_iam_statements(
                claims,
                &record.owner_scope_key,
                target_permission(record),
                fresh_now,
            )
            .await?;
        authority.extend(self.dependency_statements(record).await?);
        let mutation_now = self.current_time()?;
        context.validate(&self.deployment, &self.origin, u64::try_from(mutation_now)?)?;
        self.acceptances
            .profiles(&self.deployment, &self.origin, u64::try_from(mutation_now)?)?;
        for (baseline, witness) in evidence.iter().zip(witnesses) {
            witness.validate_for(baseline, context, u64::try_from(mutation_now)?)?;
        }
        let deadline = witnesses
            .iter()
            .map(|witness| witness.expires_at.get())
            .chain(std::iter::once(context.expires_at.get()))
            .chain(std::iter::once(u64::try_from(claims.exp)?))
            .min()
            .context("direct baseline authority deadline absent")?;
        let remaining = deadline
            .checked_sub(u64::try_from(mutation_now)?)
            .filter(|seconds| *seconds > 0)
            .context("direct baseline SQL authority expired")?;
        tokio::time::timeout(
            Duration::from_secs(remaining),
            self.db.retain_direct_baselines(
                &self.deployment,
                record,
                &originals,
                authority,
                activation,
                mutation_now,
            ),
        )
        .await
        .context("direct baseline SQL outcome unavailable at authority deadline")??;
        Ok(permissions)
    }

    async fn verify_final(
        &self,
        claims: &Claims,
        context: &DirectRequestContext,
        record: &DirectUploadSessionRecord,
        evidence: &DirectCompletionEvidence,
        guards: &[DirectFinalGuardRecord],
        now: i64,
    ) -> Result<Vec<CheckedStatement>> {
        let complete = record
            .complete_intent
            .as_ref()
            .context("direct Complete original absent")?;
        ensure!(
            guards.len() == record.admission.placements.len(),
            "direct final guard set differs"
        );
        for (guard, placement) in guards.iter().zip(&record.admission.placements) {
            guard.validate_for(&record.admission, complete, evidence, &self.deployment)?;
            ensure!(
                guard.reservation.placement.placement_id == placement.placement_id,
                "direct final guard order differs"
            );
        }
        use futures_util::{stream, StreamExt as _, TryStreamExt as _};
        let lookups = guards
            .iter()
            .map(|guard| self.lookup_final(context, record, guard, now))
            .collect::<Vec<_>>();
        stream::iter(lookups)
            .buffer_unordered(8)
            .try_collect::<Vec<_>>()
            .await?;
        let fresh_now = self.current_time()?;
        context.validate(&self.deployment, &self.origin, u64::try_from(fresh_now)?)?;
        let mut statements = self
            .db
            .direct_iam_statements(
                claims,
                &record.owner_scope_key,
                target_permission(record),
                fresh_now,
            )
            .await?;
        statements.extend(self.final_statements(record, evidence, fresh_now).await?);
        Ok(statements)
    }

    async fn verify_abort(
        &self,
        claims: &Claims,
        context: &DirectRequestContext,
        record: &DirectUploadSessionRecord,
        evidence: &DirectAbortEvidence,
        now: i64,
    ) -> Result<Vec<CheckedStatement>> {
        if evidence.outcome != DirectAbortOutcome::Aborted {
            return Ok(Vec::new());
        }
        self.lookup_authority(
            context,
            DirectAuthorityLookupOperation::Abort {
                admission: record.admission.clone(),
                abort: record
                    .abort_intent
                    .clone()
                    .context("direct Abort original absent")?,
                evidence: evidence.clone(),
            },
            now,
        )
        .await?;
        let fresh_now = self.current_time()?;
        context.validate(&self.deployment, &self.origin, u64::try_from(fresh_now)?)?;
        let mut statements = self
            .db
            .direct_iam_statements(
                claims,
                &record.owner_scope_key,
                target_permission(record),
                fresh_now,
            )
            .await?;
        match &record.owner {
            DirectSqlOwner::Cache { ticket_id, .. } => {
                let ticket = self
                    .db
                    .cache_write_ticket(ticket_id)
                    .await?
                    .context("direct cache abort ticket absent")?;
                statements.extend(Database::abort_cache_write_ticket_statements(
                    ticket_id,
                    ticket.resource_version,
                    "aborted",
                    fresh_now,
                )?);
            }
            DirectSqlOwner::Oci => {
                let DirectUploadTarget::OciBlob { upload_id } = &record.admission.intent.target
                else {
                    anyhow::bail!("direct OCI abort original target differs");
                };
                let upload = self
                    .db
                    .direct_oci_upload_for_actor_recovery(
                        &self.deployment,
                        &record.admission.actor_slot,
                        upload_id,
                    )
                    .await?;
                statements.extend(Database::abort_direct_oci_upload_statements(
                    &upload, fresh_now,
                )?);
            }
            DirectSqlOwner::Publication => {}
        }
        Ok(statements)
    }
}

impl NativeDirectUploadAuthority {
    async fn current_actor(&self, claims: &Claims) -> Result<DirectActorSlot> {
        self.db
            .current_authenticated_actor(claims)
            .await?
            .ok_or_else(|| {
                anyhow::Error::new(DirectUploadRefusal {
                    code: DirectItemErrorCode::Denied,
                })
            })
    }

    fn latest_now(&self) -> Result<u64> {
        Ok(current_time()?
            .checked_add(self.clock_uncertainty_seconds)
            .context("direct qualified clock overflow")?)
    }

    async fn cache_baseline_activation(
        &self,
        record: &DirectUploadSessionRecord,
        baselines: &[DirectDestinationBaselineEvidence],
        now: i64,
    ) -> Result<Vec<CheckedStatement>> {
        let DirectSqlOwner::Cache {
            cache_id,
            ticket_id,
        } = &record.owner
        else {
            return Ok(Vec::new());
        };
        let cache = self
            .db
            .binary_cache_by_id(*cache_id)
            .await?
            .context("direct cache disappeared")?;
        let ticket = self
            .db
            .cache_write_ticket(ticket_id)
            .await?
            .context("direct cache ticket disappeared")?;
        ensure!(
            baselines.len() == 1 && ticket.state == "observing",
            "direct cache baseline activation conflicts"
        );
        let prior = match &baselines[0].state {
            DirectDestinationBaselineState::Missing {} => None,
            DirectDestinationBaselineState::Present {
                byte_size,
                sha256,
                etag,
                ..
            } => Some(WriteObjectIdentity {
                size: i64::try_from(byte_size.get())?,
                sha256: sha256.clone(),
                strong_etag: Some(etag.clone()),
            }),
        };
        let delta_bytes = if cache.org_id.is_some() {
            i64::try_from(record.admission.intent.byte_size.get())?
                - prior.as_ref().map_or(0, |item| item.size)
        } else {
            0
        };
        let delta_objects = i64::from(cache.org_id.is_some() && prior.is_none());
        Database::activate_cache_write_ticket_statements(
            ticket_id,
            ticket.resource_version,
            cache.org_id,
            delta_bytes,
            delta_objects,
            prior.as_ref(),
            Some(&record.admission.intent.expected_sha256),
            now,
        )
    }
}

fn current_time() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn target_permission(record: &DirectUploadSessionRecord) -> aos_hub_core::domain::Permission {
    if matches!(record.owner, DirectSqlOwner::Cache { .. }) {
        aos_hub_core::domain::Permission::RegistryConfigure
    } else {
        aos_hub_core::domain::Permission::Publish
    }
}

#[cfg(test)]
mod tests;
