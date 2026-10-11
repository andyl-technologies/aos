//! Process-local provider transport using the shared source executor and custody.

use std::sync::Arc;

use anyhow::{Result, bail};
use aos_assessment_providers::{UPSTREAM_ADAPTER_VERSION, kev, nvd, osv};
use aos_assessment_runtime::ports::{Clock, EvidenceStore, ProviderTransport};
use aos_assessment_runtime::provider::{
    CapabilityChallenge, ProviderCapabilitiesV1, ProviderLimits, ProviderWorkPlanV1,
    ProviderWorkResultV1, execute_source,
};

use crate::{NativeSourceTransport, PhysicalClock, SourceCredentials};

/// Binds a process-local executor to one installed deployment/service pairing.
#[derive(Clone, Debug)]
pub struct NativeExecutorIdentity {
    /// Installed deployment incarnation.
    pub deployment_id: String,
    /// Installed coordinator identity.
    pub issuer: String,
    /// Installed provider executor identity.
    pub audience: String,
    /// Actual executor build identity.
    pub build: String,
}

/// Supplies Native provider effects for an already admitted journal invocation.
///
/// This transport crosses a process-local trust boundary. Remote executors use
/// separately authenticated work protocols; this type is not an HTTP handler.
pub struct NativeProviderExecutor<E> {
    identity: NativeExecutorIdentity,
    source: NativeSourceTransport,
    evidence: Arc<E>,
    limits: ProviderLimits,
    ttl_seconds: u32,
}

impl<E: EvidenceStore> NativeProviderExecutor<E> {
    /// Creates one installed process-local executor with explicit ports and ceilings.
    ///
    /// # Errors
    /// Returns an error for invalid effect limits, source freshness bounds or pairing.
    pub fn new(
        identity: NativeExecutorIdentity,
        credentials: Arc<dyn SourceCredentials>,
        evidence: Arc<E>,
        limits: ProviderLimits,
        ttl_seconds: u32,
    ) -> Result<Self> {
        limits.validate()?;
        if !(1..=86400).contains(&ttl_seconds)
            || [
                &identity.deployment_id,
                &identity.issuer,
                &identity.audience,
                &identity.build,
            ]
            .iter()
            .any(|value| {
                value.is_empty() || value.len() > 128 || value.chars().any(char::is_control)
            })
        {
            bail!("native assessment executor has invalid installed identity or freshness");
        }
        Ok(Self {
            identity,
            source: NativeSourceTransport::new(credentials),
            evidence,
            limits,
            ttl_seconds,
        })
    }

    fn require_pair(&self, deployment: &str, issuer: &str, audience: &str) -> Result<()> {
        if deployment != self.identity.deployment_id
            || issuer != self.identity.issuer
            || audience != self.identity.audience
        {
            bail!("provider work differs from the installed process-local service pairing");
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl<E: EvidenceStore> ProviderTransport for NativeProviderExecutor<E> {
    async fn capabilities(
        &self,
        challenge: &CapabilityChallenge,
    ) -> Result<ProviderCapabilitiesV1> {
        challenge.validate_at(&PhysicalClock.now()?)?;
        self.require_pair(
            &challenge.deployment_id,
            &challenge.issuer,
            &challenge.audience,
        )?;
        let mut adapters = vec![
            UPSTREAM_ADAPTER_VERSION.into(),
            osv::ADAPTER_VERSION.into(),
            nvd::ADAPTER_VERSION.into(),
            kev::ADAPTER_VERSION.into(),
        ];
        adapters.sort();
        adapters.dedup();
        Ok(ProviderCapabilitiesV1 {
            schema: "aos.provider-capabilities/v1".into(),
            challenge: challenge.clone(),
            executor_build: self.identity.build.clone(),
            adapters,
            limits: self.limits.clone(),
        })
    }

    async fn execute(&self, plan: &ProviderWorkPlanV1) -> Result<ProviderWorkResultV1> {
        plan.validate_at(&PhysicalClock.now()?)?;
        self.require_pair(&plan.deployment_id, &plan.issuer, &plan.audience)?;
        plan.limits.require_within(&self.limits)?;
        execute_source(
            &self.source,
            self.evidence.as_ref(),
            &PhysicalClock,
            plan,
            &self.identity.build,
            self.ttl_seconds,
        )
        .await
    }
}
