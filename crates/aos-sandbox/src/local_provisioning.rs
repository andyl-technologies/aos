//! Protected controller provisioning of live local holder channels.
//!
//! Trusted administration supplies an authorized principal/runtime assignment
//! and retained execution scope. Current protected policy determines the exact
//! nondelegable publication grant. The capability and issuance evidence commit
//! before either endpoint escapes; restart never reconstructs live sessions.
//! This is not an RPC handler, source admission, or publication permission.
//!
//! Current-runtime issuance instead consumes a sealed observation, derives its
//! holder/assignment scope, and retains the whole proof in the live session.
//! Its version-three audit evidence is distinct from administrative issuance.
//! A capability may outlive its issuance observation: use requires fresh
//! runtime admission, not continued reliance on the historical audit record.

#[cfg(all(test, feature = "kernel-tests"))]
pub(crate) mod tests;

use aos_sandbox_core::ownership_lease::RawPairedClockSample;
use aos_sandbox_core::{
    AuditId, CapabilityDraft, CapabilityRecord, DelegationLimits, Grant, GrantId, Operation,
    OperationSet, ResourceKind, ResourceVector, Revision, RevocationScopeId, Selector,
};
use aos_sandbox_linux::{boot::KernelBootId, cgroup::RetainedCgroupAnchor};

use crate::Journal;
use crate::local_sessions::{
    LocalSessionEndpoint, LocalSessionError, LocalSessionRegistry, LocalSessionScope,
};
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::publisher_authority::{
    IssuanceDecisionMetadataDraftV1, IssuanceDecisionMetadataV1, PublisherAuthorityError,
    PublisherAuthorityLimits, PublisherCapabilityRegistry,
};
use crate::publisher_policy::{PublisherPolicyError, PublisherPolicyLimits, PublisherPolicyStore};

/// Configures trusted local issuance independently of incoming packet contents.
#[derive(Clone, Copy, Debug)]
pub struct LocalProvisioningPolicy {
    /// Maximum requested validity, in seconds, within `1..=3600`.
    pub validity_seconds: u32,
    /// Protected revocation namespace consulted at issuance and on every use.
    pub revocation_scope: RevocationScopeId,
    /// Expected provenance of the trusted paired-clock adapter.
    pub clock_provenance: [u8; 16],
    /// Bounds complete protected capability replay.
    pub authority_limits: PublisherAuthorityLimits,
    /// Bounds complete protected policy replay.
    pub policy_limits: PublisherPolicyLimits,
}

/// Reports fail-closed local channel provisioning failures.
#[derive(Debug, thiserror::Error)]
pub enum LocalProvisioningError {
    /// Trusted configuration is incomplete or outside supported bounds.
    #[error("invalid local provisioning configuration")]
    InvalidConfiguration,
    /// Current protected state does not authorize this exact cache grant.
    #[error("current protected policy does not authorize local publication")]
    PolicyDenied,
    /// Time provenance, boot, validity, or monotonic ordering is invalid.
    #[error("local provisioning clock is unavailable or invalid")]
    Clock,
    /// The retained kernel scope or boot observation failed.
    #[error(transparent)]
    Kernel(#[from] aos_sandbox_linux::Error),
    /// Channel preparation or final execution-scope validation failed.
    #[error(transparent)]
    Session(#[from] LocalSessionError),
    /// Current runtime authority, validity, or retained execution validation failed.
    #[error(transparent)]
    Runtime(#[from] crate::runtime_scope::CurrentRuntimeScopeError),
    /// Protected policy replay or lookup failed.
    #[error(transparent)]
    Policy(#[from] PublisherPolicyError),
    /// Protected issuance or its atomic commit failed.
    #[error(transparent)]
    Authority(#[from] PublisherAuthorityError),
    /// Derived capability invariants were not satisfied.
    #[error("derived local capability is invalid")]
    InvalidCapability,
}

/// Commits issuance while retaining exclusive access to the controller journal.
pub(crate) fn provision<T>(
    journal: &mut Journal,
    sessions: &mut LocalSessionRegistry,
    scope: LocalSessionScope,
    anchor: RetainedCgroupAnchor,
    config: LocalProvisioningPolicy,
    clock: &mut T,
) -> Result<LocalSessionEndpoint, LocalProvisioningError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    validate_config(config)?;
    let prepared = sessions.prepare(scope, anchor)?;
    provision_prepared(journal, prepared, config, clock)
}

/// Derives the local scope from current authority while keeping all execution pins owned.
pub(crate) fn provision_runtime<T>(
    journal: &mut Journal,
    sessions: &mut LocalSessionRegistry,
    runtime: crate::runtime_scope::CurrentRuntimeScope,
    cache_resource: aos_sandbox_core::ResourceId,
    config: LocalProvisioningPolicy,
    clock: &mut T,
) -> Result<LocalSessionEndpoint, LocalProvisioningError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    validate_config(config)?;
    runtime.recheck(journal, clock)?;
    let prepared = sessions.prepare_runtime(runtime, cache_resource)?;
    provision_prepared(journal, prepared, config, clock)
}

fn provision_prepared<T>(
    journal: &mut Journal,
    prepared: crate::local_sessions::PreparedLocalSession<'_>,
    config: LocalProvisioningPolicy,
    clock: &mut T,
) -> Result<LocalSessionEndpoint, LocalProvisioningError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    let scope = *prepared.scope();
    let boot = KernelBootId::current()?.into_bytes();
    let observed = clock().map_err(|_| LocalProvisioningError::Clock)?;
    validate_clock(observed, boot, config.clock_provenance)?;

    // One exclusive journal borrow prevents administration interleaving between
    // these reads and commit. No cached policy snapshot can bypass journal health.
    let (policy, resource, controller, revocation) = {
        let store = PublisherPolicyStore::load(journal, config.policy_limits)?;
        (
            store
                .current_policy(scope.project)?
                .ok_or(LocalProvisioningError::PolicyDenied)?,
            store
                .resource_binding(scope.cache_resource)?
                .ok_or(LocalProvisioningError::PolicyDenied)?,
            store
                .controller_head()?
                .ok_or(LocalProvisioningError::PolicyDenied)?,
            store
                .revocation_head(config.revocation_scope)?
                .ok_or(LocalProvisioningError::PolicyDenied)?,
        )
    };
    let selector = Selector::Resource {
        resource: scope.cache_resource,
    };
    if resource.project() != scope.project
        || resource.cache_domain() != policy.policy().cache_domain()
        || !policy.policy().effective_grants().iter().any(|grant| {
            grant.resource_kind() == ResourceKind::CachePublish
                && grant.operations().contains(Operation::Publish)
                && grant.selector() == &selector
        })
        || observed.wall_seconds() < policy.not_before()
        || observed.wall_seconds() >= policy.expires_at()
    {
        return Err(LocalProvisioningError::PolicyDenied);
    }
    let expires_at = observed
        .wall_seconds()
        .checked_add(i64::from(config.validity_seconds))
        .ok_or(LocalProvisioningError::Clock)?
        .min(policy.expires_at());
    let identity = *prepared.capability_id().as_bytes();
    let decision = AuditId::from_bytes(identity);
    let grant = Grant::new(
        GrantId::from_bytes(identity),
        ResourceKind::CachePublish,
        OperationSet::one(Operation::Publish),
        selector,
        false,
    )
    .map_err(|_| LocalProvisioningError::InvalidCapability)?;
    let capability = CapabilityRecord::issue(CapabilityDraft {
        id: prepared.capability_id(),
        issuer: controller.principal,
        audience: controller.principal,
        holder: scope.holder,
        channel_binding: prepared.channel_binding(),
        root_subject: scope.holder,
        project: scope.project,
        sandbox: Some(scope.sandbox),
        incarnation: Some(scope.incarnation),
        grants: vec![grant],
        policy_digest: policy.descriptor().digest(),
        assignment_epoch: Some(scope.epoch),
        not_before: observed.wall_seconds(),
        expires_at,
        revocation_scope: config.revocation_scope,
        revocation_generation: Revision::new(revocation.generation),
        delegation: DelegationLimits::new(0, 0, ResourceVector::ZERO),
        parent_decision: decision,
    })
    .map_err(|_| LocalProvisioningError::InvalidCapability)?;
    let metadata = IssuanceDecisionMetadataV1::new(IssuanceDecisionMetadataDraftV1 {
        decision_id: decision,
        session_id: *prepared.session_id().as_bytes(),
        boot_id: boot,
        clock_provenance: config.clock_provenance,
        observed_wall_seconds: observed.wall_seconds(),
        observed_boottime_nanoseconds: observed.boottime_nanoseconds(),
        policy_generation: policy.generation(),
        controller_generation: controller.generation,
        cache_resource: scope.cache_resource,
        isolation_policy: resource.isolation_policy(),
    })?;

    prepared.check_pending_anchor()?;
    if let Some(runtime) = prepared.runtime() {
        runtime.recheck(journal, clock)?;
        PublisherCapabilityRegistry::load(journal, config.authority_limits)?
            .install_current_runtime_session(identity, capability, metadata, runtime)?;
    } else {
        PublisherCapabilityRegistry::load(journal, config.authority_limits)?
            .install_local_session_from_trusted_controller(identity, capability, metadata)?;
    }

    // A post-commit failure leaves an auditable but unusable issued record. The
    // preparation guard closes both endpoints and no session is activated.
    if let Some(runtime) = prepared.runtime() {
        runtime.recheck(journal, clock)?;
    }
    let fresh = clock().map_err(|_| LocalProvisioningError::Clock)?;
    validate_clock(fresh, boot, config.clock_provenance)?;
    let maximum_elapsed = u64::try_from(expires_at - observed.wall_seconds())
        .map_err(|_| LocalProvisioningError::Clock)?
        .checked_mul(1_000_000_000)
        .ok_or(LocalProvisioningError::Clock)?;
    let elapsed = fresh
        .boottime_nanoseconds()
        .checked_sub(observed.boottime_nanoseconds())
        .ok_or(LocalProvisioningError::Clock)?;
    if fresh.wall_seconds() < observed.wall_seconds()
        || fresh.wall_seconds() >= expires_at
        || elapsed >= maximum_elapsed
    {
        return Err(LocalProvisioningError::Clock);
    }
    prepared.check_pending_anchor()?;
    if let Some(runtime) = prepared.runtime() {
        runtime.check_validity(fresh)?;
    }
    Ok(prepared.activate())
}

fn validate_config(config: LocalProvisioningPolicy) -> Result<(), LocalProvisioningError> {
    if !(1..=3600).contains(&config.validity_seconds)
        || config.clock_provenance == [0; 16]
        || config.revocation_scope.as_bytes() == &[0; 16]
    {
        return Err(LocalProvisioningError::InvalidConfiguration);
    }
    Ok(())
}

fn validate_clock(
    sample: RawPairedClockSample,
    boot: [u8; 16],
    provenance: [u8; 16],
) -> Result<(), LocalProvisioningError> {
    if sample.host_boot_id() != boot || sample.provenance().as_bytes() != provenance {
        return Err(LocalProvisioningError::Clock);
    }
    Ok(())
}
