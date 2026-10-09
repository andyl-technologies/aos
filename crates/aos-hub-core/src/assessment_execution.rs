//! Database-backed execution of shared package assessment acquisition and evaluation.
//!
//! Native and Worker hosts supply current authority, scoped evidence custody and
//! provider transport. Hybrid supplies a Worker transport while keeping this
//! coordinator and the durable journal on Native. Placement never substitutes a
//! different parser or matching engine, and no raw source body enters SQL.

use anyhow::{bail, Context as _, Result};
use aos_assessment::input::{FreshnessMode, ScanInputV1};
use aos_assessment::result::PackageAssessmentV1;
use aos_assessment_runtime::acquisition::{acquire, acquire_stale, AcquisitionPort};
use aos_assessment_runtime::ports::{EvidenceStore, ProviderTransport, RuntimeBounds};
use aos_assessment_runtime::provider::{
    CapabilityChallenge, ProviderLimits, ProviderOperation, ProviderPageV1, ProviderWorkPlanV1,
    ProviderWorkResultV1, PROVIDER_WORK_PLAN_V1,
};
use aos_assessment_runtime::scan::TaskClaim;

use crate::db::{AssessmentProviderWork, AssessmentScanRecord, Database};

/// Rechecks a durable operation's current actor and authorization generation.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait AssessmentAuthority: RuntimeBounds {
    /// Requires the current principal, delegated scan scope and resource revision.
    ///
    /// Hosts recheck current membership, token/job delegation and the exact
    /// registry incarnation. Revocation must also advance the resource's SQL
    /// authorization generation so the final checked transaction fences it.
    ///
    /// # Errors
    /// Returns an error for revoked or unavailable authority or a changed scope.
    async fn require_current(&self, scan: &AssessmentScanRecord) -> Result<()>;
}

/// Supplies an installed provider route under independent current source authority.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait AssessmentSourceRoutes: RuntimeBounds {
    /// Resolves the exact installed executor, credential version and global quota.
    ///
    /// Package metadata cannot choose a URL, executor, secret or quota key.
    /// Hybrid implementations return their paired Worker and never fall back
    /// to direct Native acquisition when that executor is unavailable.
    ///
    /// # Errors
    /// Returns an error for missing/revoked routes or source credential authority.
    async fn route(
        &self,
        scan: &AssessmentScanRecord,
        operation: &ProviderOperation,
    ) -> Result<AssessmentSourceRoute>;
}

/// Binds one installed source to its coordinator/executor authentication domain.
#[derive(Clone, Debug)]
pub struct AssessmentSourceRoute {
    /// Installed deployment incarnation.
    pub deployment_id: String,
    /// Installed coordinator service identity.
    pub issuer: String,
    /// Independently paired provider executor identity.
    pub audience: String,
    /// Installed global provider/account budget key.
    pub budget_key: String,
    /// Optional immutable scoped secret version reference, never secret bytes.
    pub credential_ref: Option<String>,
    /// Effective provider effect ceilings, tightened by deployment policy.
    pub limits: ProviderLimits,
}

/// Claims and executes an admitted request through the shared acquisition engine.
///
/// Reads without refresh intent perform no network acquisition. Every physical
/// task consumes SQL quota before dispatch; failed attempts settle without a
/// refund. The evaluator freezes one exact closure and commits through the
/// inventory, policy, authorization, generation, attempt and cancellation fences.
///
/// # Errors
/// Returns an error for unavailable/revoked authority, stale claims, provider
/// admission failure, custody gaps or failed deterministic/final admission checks.
pub async fn run_scan<A, T, E, R>(
    db: &Database,
    registry_id: i64,
    scan_id: &str,
    authority: &A,
    transport: &T,
    evidence: &E,
    routes: &R,
) -> Result<PackageAssessmentV1>
where
    A: AssessmentAuthority,
    T: ProviderTransport,
    E: EvidenceStore,
    R: AssessmentSourceRoutes,
{
    let scan = db
        .assessment_scan(registry_id, scan_id)
        .await?
        .context("assessment scan is absent")?;
    authority.require_current(&scan).await?;
    let claim = db.claim_assessment_scan(registry_id, scan_id, 900).await?;
    let port = DatabaseAcquisition {
        db,
        scan: &scan,
        claim: &claim,
        authority,
        transport,
        routes,
    };
    let mut data = db.assessment_evaluation_base(registry_id, &claim).await?;
    if matches!(
        scan.request.freshness,
        FreshnessMode::Refresh | FreshnessMode::RefreshStale
    ) {
        // Each selected source question is independently admitted. Host caches
        // may provide conditional custody through their issued route/profile;
        // an explicit refresh never bypasses source or operation allowance.
        if scan.request.freshness == FreshnessMode::RefreshStale {
            acquire_stale(
                &port,
                evidence,
                &scan.request.authorization_partition,
                &mut data,
                &scan.request.subjects,
                &scan.request.profiles,
                &db.assessment_database_time().await?,
            )
            .await?;
        } else {
            acquire(
                &port,
                evidence,
                &scan.request.authorization_partition,
                &mut data,
                &scan.request.subjects,
                &scan.request.profiles,
            )
            .await?;
        }
    }
    restore_candidate_history(db, &scan, &mut data).await?;
    authority.require_current(&scan).await?;
    let input = db
        .freeze_assessment_evaluation(registry_id, &claim, &data)
        .await?;
    let result = aos_assessment::evaluator::evaluate(&input, &data)?;
    authority.require_current(&scan).await?;
    db.commit_assessment_evaluation(registry_id, &claim, &result)
        .await?;
    Ok(result)
}

async fn restore_candidate_history(
    db: &Database,
    scan: &AssessmentScanRecord,
    data: &mut aos_assessment::input::EvaluationData,
) -> Result<()> {
    let mut history = data
        .history
        .iter()
        .map(|entry| {
            (
                (
                    entry.provider.clone(),
                    entry.project.clone(),
                    entry.raw_id.clone(),
                ),
                entry.first_observed_at.clone(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    for binding in &mut data.upstream {
        let observation = &mut binding.observation;
        let ids = observation
            .candidates
            .iter()
            .map(|candidate| candidate.raw_id.clone())
            .collect::<Vec<_>>();
        for entry in db
            .assessment_candidate_history(
                &scan.request.authorization_partition,
                &observation.provider,
                &observation.project,
                &ids,
            )
            .await?
        {
            history.insert(
                (entry.provider, entry.project, entry.raw_id),
                entry.first_observed_at,
            );
        }
        for candidate in &mut observation.candidates {
            if let Some(first) = history.get(&(
                observation.provider.clone(),
                observation.project.clone(),
                candidate.raw_id.clone(),
            )) {
                candidate.first_observed_at_unix = first.unix_seconds();
            }
        }
    }
    data.history = history
        .into_iter()
        .map(|((provider, project, raw_id), first_observed_at)| {
            aos_assessment::input::CandidateHistory {
                provider,
                project,
                raw_id,
                first_observed_at,
            }
        })
        .collect();
    Ok(())
}

struct DatabaseAcquisition<'a, A, T, R> {
    db: &'a Database,
    scan: &'a AssessmentScanRecord,
    claim: &'a TaskClaim,
    authority: &'a A,
    transport: &'a T,
    routes: &'a R,
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<A: AssessmentAuthority, T: ProviderTransport, R: AssessmentSourceRoutes> AcquisitionPort
    for DatabaseAcquisition<'_, A, T, R>
{
    async fn invoke(
        &self,
        operation: &ProviderOperation,
        previous: Option<&ProviderPageV1>,
    ) -> Result<ProviderWorkResultV1> {
        self.authority.require_current(self.scan).await?;
        self.db
            .check_assessment_scan_claim(self.scan.registry_id, self.claim)
            .await?;
        let now = self.db.assessment_database_time().await?;
        if now.elapsed_since(&self.scan.created_at)?
            >= u64::from(self.scan.request.limits.wall_seconds)
        {
            bail!("assessment operation wall time is exhausted");
        }
        let route = self.routes.route(self.scan, operation).await?;
        let requests = operation.source_requests()?.len() as u32;
        if requests > route.limits.requests {
            bail!("provider operation exceeds the installed route request allowance");
        }
        let challenge = CapabilityChallenge {
            schema: "aos.provider-capability-challenge/v1".into(),
            deployment_id: route.deployment_id.clone(),
            issuer: route.issuer.clone(),
            audience: route.audience.clone(),
            nonce: uuid::Uuid::new_v4().simple().to_string(),
            issued_at: now.clone(),
            expires_at: aos_assessment::time::Timestamp::from_unix_seconds(
                now.unix_seconds() + 60,
            )?,
        };
        let capabilities = self.transport.capabilities(&challenge).await?;
        capabilities.validate_for(&challenge, &self.db.assessment_database_time().await?)?;
        capabilities.require(operation)?;
        let limits = ProviderLimits {
            requests,
            concurrency: route.limits.concurrency.min(requests),
            ..route.limits
        };
        limits.require_within(&capabilities.limits)?;
        self.authority.require_current(self.scan).await?;
        let reservation = self
            .db
            .reserve_assessment_provider_work(
                self.scan.registry_id,
                self.claim,
                &AssessmentProviderWork {
                    task_id: operation.digest()?.hex(),
                    operation_digest: operation.digest()?,
                    budget_key: route.budget_key,
                    requests,
                    deadline_seconds: 60,
                },
            )
            .await?;
        let plan = ProviderWorkPlanV1 {
            schema: PROVIDER_WORK_PLAN_V1.into(),
            deployment_id: route.deployment_id,
            issuer: route.issuer,
            audience: route.audience,
            plan_id: uuid::Uuid::new_v4().simple().to_string(),
            claim: reservation.claim,
            issued_at: self.db.assessment_database_time().await?,
            expires_at: reservation.budget.deadline.clone(),
            nonce: uuid::Uuid::new_v4().simple().to_string(),
            inventory_digest: self.scan.request.inventory_digest,
            policy_digest: self.scan.request.policy_digest,
            authorization_partition: self.scan.request.authorization_partition.clone(),
            credential_ref: route.credential_ref,
            budget_reservation: reservation.budget,
            cache_ref: None,
            continuation: previous.map(ProviderPageV1::digest).transpose()?,
            continuation_ref: previous.cloned(),
            operation: operation.clone(),
            adapter_version: operation.adapter_version().into(),
            limits,
        };
        self.db
            .admit_assessment_provider_plan(self.scan.registry_id, &plan)
            .await?;
        let physical = self.transport.execute(&plan).await;
        self.authority.require_current(self.scan).await?;
        let result = match physical {
            Ok(result) => result,
            Err(error) => {
                self.db
                    .fail_assessment_provider_work(
                        self.scan.registry_id,
                        &plan.claim,
                        "source-transport-failed",
                    )
                    .await?;
                return Err(error);
            }
        };
        result.validate_for(&plan, &self.db.assessment_database_time().await?)?;
        self.db
            .admit_assessment_provider_result(self.scan.registry_id, &plan, &result)
            .await?;
        Ok(result)
    }
}

/// Reads the exact admitted replay closure independently from physical execution.
///
/// # Errors
/// Returns an error for missing normalized custody or an unpinned operation.
pub async fn frozen_input(db: &Database, registry_id: i64, scan_id: &str) -> Result<ScanInputV1> {
    Ok(db
        .assessment_frozen_evaluation(registry_id, scan_id)
        .await?
        .0)
}
