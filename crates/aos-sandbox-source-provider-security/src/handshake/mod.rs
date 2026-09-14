//! Sealed mutually authenticated hello typestates.

mod provider;
mod root_mount;

pub use provider::CurrentProviderIngressSessionV1;
pub use root_mount::CurrentRootMountSourceProviderSessionV1;

/// Carries an authenticated provider outcome before durable acceptance.
///
/// Construction remains sealed until concrete AOSSPL request evidence exists.
pub struct AuthenticatedProviderOutcomeV1 {
    _private: (),
}

/// Carries a provider outcome after exact AOSSPL persistence.
///
/// Construction remains sealed until the standalone ledger exists.
pub struct CommittedProviderOutcomeV1 {
    _private: (),
}

/// Retains a provider request with live execution and durable reservation authority.
///
/// No constructor exists before concrete AOSSPL reservation receipts exist.
pub struct CurrentProviderRequestV1 {
    _private: (),
}

impl core::fmt::Debug for AuthenticatedProviderOutcomeV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AuthenticatedProviderOutcomeV1([redacted])")
    }
}

impl core::fmt::Debug for CommittedProviderOutcomeV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CommittedProviderOutcomeV1([redacted])")
    }
}

impl core::fmt::Debug for CurrentProviderRequestV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CurrentProviderRequestV1([redacted])")
    }
}

pub(super) enum HandshakeTransitionV1<RetryState, CompleteState> {
    Complete(CompleteState),
    Retry(RetryState),
    Fatal(crate::SourceProviderSecurityError),
}

pub(super) fn current_unix_seconds() -> Result<i64, crate::SourceProviderSecurityError> {
    let value = rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec;
    if value < 0 {
        Err(crate::SourceProviderSecurityError::ExecutionChanged)
    } else {
        Ok(value)
    }
}

pub(super) fn process_identity(
    evidence: &crate::execution::ProcessExecutionEvidenceV1,
) -> Result<
    aos_sandbox_source_provider_protocol::SourceProviderProcessIdentityV1,
    crate::SourceProviderSecurityError,
> {
    let credentials = evidence.credentials();
    aos_sandbox_source_provider_protocol::SourceProviderProcessIdentityV1::new(
        credentials.effective_user_id(),
        credentials.effective_group_id(),
        evidence.tgid(),
        evidence.start_time_ticks(),
        crate::execution::cgroup_object_digest(evidence.cgroup_path_digest()),
        evidence.is_alive()?,
    )
    .map_err(|_| crate::SourceProviderSecurityError::SessionContinuity)
}
