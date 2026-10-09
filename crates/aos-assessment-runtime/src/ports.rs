//! Runtime ports separating durable logical authority from physical provider effects.
//!
//! These interfaces carry exact immutable references and explicit time. Hybrid
//! supplies a Native journal and Worker transport; other modes supply local
//! adapters. No port introduces a second matching or eligibility algorithm.

use anyhow::Result;
use aos_assessment::input::{EvaluationData, ScanInputV1};
use aos_assessment::result::PackageAssessmentV1;
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;

use crate::provider::{
    CapabilityChallenge, ProviderCapabilitiesV1, ProviderWorkPlanV1, ProviderWorkResultV1,
};
use crate::scan::{ScanRequestV1, TaskClaim};

/// Supplies target-specific thread bounds for runtime effect ports.
///
/// Native servers move futures between threads. Single-threaded Worker ports
/// may hold JavaScript handles and use non-Send futures without changing the
/// shared orchestration or wire contracts.
#[cfg(not(target_arch = "wasm32"))]
pub trait RuntimeBounds: Send + Sync {}

#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync> RuntimeBounds for T {}

/// Supplies the unrestricted marker used by single-threaded Worker ports.
#[cfg(target_arch = "wasm32")]
pub trait RuntimeBounds {}

#[cfg(target_arch = "wasm32")]
impl<T> RuntimeBounds for T {}

/// Reads explicit runtime time without entering deterministic assessment policy.
pub trait Clock: RuntimeBounds {
    /// Returns an exact whole-second UTC timestamp from the runtime clock.
    ///
    /// # Errors
    /// Returns an error if the clock is unavailable or outside the portable range.
    fn now(&self) -> Result<Timestamp>;
}

/// Runs one admitted physical provider invocation under its current capability.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait ProviderTransport: RuntimeBounds {
    /// Returns authenticated installed profiles bound to a fresh paired challenge.
    ///
    /// # Errors
    /// Returns an error for unavailable executors, wrong service pairing,
    /// invalid authentication, expiry or incompatible capability contracts.
    async fn capabilities(&self, challenge: &CapabilityChallenge)
    -> Result<ProviderCapabilitiesV1>;

    /// Executes typed bounded work, preserving cancellation and exact byte receipts.
    ///
    /// # Errors
    /// Returns an error for unsupported capabilities, authentication/expiry,
    /// transport failure, exhausted budgets or unavailable evidence custody.
    async fn execute(&self, plan: &ProviderWorkPlanV1) -> Result<ProviderWorkResultV1>;
}

/// Retains and reads exact immutable evidence in an authorization partition.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait EvidenceStore: RuntimeBounds {
    /// Retains exact bounded bytes under independently admitted write authority.
    ///
    /// # Errors
    /// Returns an error for unavailable/revoked authority, conflicting custody or limits.
    async fn retain(&self, partition: &str, bytes: &[u8]) -> Result<Sha256Digest>;

    /// Reads one exact authorized object without exceeding the caller's byte limit.
    ///
    /// # Errors
    /// Returns an error for missing evidence, hash mismatch, revoked scope or limits.
    async fn read(&self, partition: &str, digest: Sha256Digest, max_bytes: u64) -> Result<Vec<u8>>;
}

/// Owns atomic generations, lease fencing, budgets and assessment/event admission.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait ScanJournal: RuntimeBounds {
    /// Admits a bounded idempotent request and returns its durable operation identity.
    ///
    /// # Errors
    /// Returns an error for changed idempotency content, stale authority or quotas.
    async fn admit(&self, request: &ScanRequestV1) -> Result<String>;

    /// Rechecks the current generation, lease, cancellation and authorization fence.
    ///
    /// # Errors
    /// Returns an error for an expired/superseded claim or unavailable journal.
    async fn check_claim(&self, claim: &TaskClaim) -> Result<()>;

    /// Admits a verified result atomically against the current attempt and budget.
    ///
    /// # Errors
    /// Returns an error for conflicting duplicate content, stale claim or limits.
    async fn admit_observation(
        &self,
        plan: &ProviderWorkPlanV1,
        result: &ProviderWorkResultV1,
    ) -> Result<()>;

    /// Loads all pinned immutable evidence required for deterministic evaluation.
    ///
    /// # Errors
    /// Returns an error for missing/conflicting evidence or invalid authority.
    async fn evaluation_data(&self, claim: &TaskClaim) -> Result<(ScanInputV1, EvaluationData)>;

    /// Commits assessment, profile heads, alert transitions and outbox atomically.
    ///
    /// # Errors
    /// Returns an error for changed generation/inventory/policy/authentication,
    /// cancellation, missing custody or an immutable-content conflict.
    async fn commit(
        &self,
        claim: &TaskClaim,
        input: &ScanInputV1,
        assessment: &PackageAssessmentV1,
    ) -> Result<()>;
}

/// Executes one physical invocation with journal fences on both sides of effects.
///
/// # Errors
/// Returns an error for expired/revoked claims, physical failure, malformed result,
/// lost commit races or unavailable ports. The journal conservatively retains
/// consumed reservation allowance even when a transport attempt times out.
pub async fn execute_provider<J: ScanJournal, T: ProviderTransport, C: Clock>(
    journal: &J,
    transport: &T,
    clock: &C,
    plan: &ProviderWorkPlanV1,
) -> Result<()> {
    plan.validate_at(&clock.now()?)?;
    journal.check_claim(&plan.claim).await?;
    let challenge = CapabilityChallenge {
        schema: "aos.provider-capability-challenge/v1".into(),
        deployment_id: plan.deployment_id.clone(),
        issuer: plan.issuer.clone(),
        audience: plan.audience.clone(),
        nonce: plan.nonce.clone(),
        issued_at: plan.issued_at.clone(),
        expires_at: plan.expires_at.clone(),
    };
    let capabilities = transport.capabilities(&challenge).await?;
    capabilities.validate_for(&challenge, &clock.now()?)?;
    capabilities.require(&plan.operation)?;
    plan.limits.require_within(&capabilities.limits)?;
    let result = transport.execute(plan).await?;
    result.validate_for(plan, &clock.now()?)?;
    journal.check_claim(&plan.claim).await?;
    journal.admit_observation(plan, &result).await
}

/// Evaluates a pinned closure and commits through the same authority in every mode.
///
/// # Errors
/// Returns an error for stale claims, missing/conflicting closure, evaluator limits
/// or loss of the atomic head/event commit fence.
pub async fn evaluate_and_commit<J: ScanJournal>(
    journal: &J,
    claim: &TaskClaim,
) -> Result<PackageAssessmentV1> {
    journal.check_claim(claim).await?;
    let (input, data) = journal.evaluation_data(claim).await?;
    let assessment = aos_assessment::evaluator::evaluate(&input, &data)?;
    journal.commit(claim, &input, &assessment).await?;
    Ok(assessment)
}
