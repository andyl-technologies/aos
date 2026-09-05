//! Controller-owned registration of distinct publisher executions and requests.
//!
//! Trusted administration maps a configured service to an exact connected
//! process. Registration commits immutable audit facts before sending a greeting
//! or activating the session. It grants no publication root access, admission,
//! reservation, signing authority, or completion permit. Restart never restores
//! a live execution from its diagnostic PID or cgroup fields.

mod challenge;
pub use challenge::PendingPublisherChallengeReceipt;
pub(crate) use challenge::register_challenge;
mod join;
pub(crate) use join::join_holder_request;
pub use join::{JoinedPublisherRequest, PublisherJoinError, PublisherJoinPolicy};

use aos_sandbox_core::ownership_lease::RawPairedClockSample;
use aos_sandbox_core::{Operation, PublisherInstanceId, ResourceKind, Selector};
use aos_sandbox_linux::{
    boot::KernelBootId, cgroup::RetainedCgroupAnchor, seqpacket::RecordSubjectListener,
};

use crate::publisher_ingress::{
    PublisherExecutionDraftV1, PublisherExecutionRegistrationV1, PublisherIngressError,
    PublisherIngressLimits, PublisherIngressStore,
};
use crate::publisher_policy::{
    PreparedPublisherPolicyRevisionV1, PublisherControllerHeadV1, PublisherPolicyError,
    PublisherPolicyLimits, PublisherPolicyStore, PublisherResourceBindingV1,
};
use crate::publisher_sessions::{
    PublisherSessionError, PublisherSessionRegistry, PublisherSessionScope,
};
use crate::{Journal, JournalError, ProtectedOwnershipClockError};

/// Binds an administratively authorized service identity to its retained scope.
///
/// Constructing this value does not itself authorize the mapping. The trusted
/// controller caller must establish that authorization before registration.
pub struct PublisherServiceRegistration {
    /// Configured principal, node, project, and publication cache resource.
    pub scope: PublisherSessionScope,
    /// Retained exact cgroup for the configured publisher process.
    pub anchor: RetainedCgroupAnchor,
}

/// Configures bounded registration independently of incoming request fields.
#[derive(Clone, Copy, Debug)]
pub struct PublisherControlPolicy {
    /// Expected protected paired-clock adapter identity.
    pub clock_provenance: [u8; 16],
    /// Maximum registration lifetime for a pending challenge, within `1..=300`.
    pub maximum_challenge_seconds: u32,
    /// Complete protected policy replay bounds.
    pub policy_limits: PublisherPolicyLimits,
    /// Complete execution/challenge audit replay and lifetime bounds.
    pub ingress_limits: PublisherIngressLimits,
}

/// Reports registration failures without granting fallback publication authority.
#[derive(Debug, thiserror::Error)]
pub enum PublisherControlError {
    /// The incoming publisher request is malformed or noncanonical.
    #[error(transparent)]
    Request(#[from] aos_sandbox_core::CanonicalCborError),
    /// Trusted registration configuration contains invalid limits or identities.
    #[error("invalid publisher control configuration")]
    InvalidConfiguration,
    /// Current protected policy does not admit the configured cache resource.
    #[error("publisher registration current policy precondition failed")]
    PolicyDenied,
    /// The paired clock is unavailable, inconsistent, expired, or changed provenance.
    #[error("publisher registration clock is unavailable or invalid")]
    Clock,
    /// The kernel boot or execution observation failed.
    #[error(transparent)]
    Kernel(#[from] aos_sandbox_linux::Error),
    /// The accepted process, record subject, or volatile session failed validation.
    #[error(transparent)]
    Session(#[from] PublisherSessionError),
    /// Durable execution/challenge audit validation or commit failed.
    #[error(transparent)]
    Ingress(#[from] PublisherIngressError),
    /// Current protected policy could not be resolved.
    #[error(transparent)]
    Policy(#[from] PublisherPolicyError),
    /// The controller journal is unavailable or poisoned.
    #[error(transparent)]
    Journal(#[from] JournalError),
}

pub(crate) fn register<T>(
    journal: &mut Journal,
    sessions: &mut PublisherSessionRegistry,
    listener: &mut RecordSubjectListener,
    scope: PublisherSessionScope,
    anchor: RetainedCgroupAnchor,
    config: PublisherControlPolicy,
    clock: &mut T,
) -> Result<PublisherExecutionRegistrationV1, PublisherControlError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    validate_config(config)?;
    let mut prepared = sessions.prepare(listener, scope, anchor)?;
    let scope = *prepared.scope();
    let boot = KernelBootId::current()?.into_bytes();
    let observed = clock().map_err(|_| PublisherControlError::Clock)?;
    validate_clock(observed, boot, config.clock_provenance)?;
    let policy = resolve_policy(
        journal,
        scope,
        config.policy_limits,
        observed.wall_seconds(),
    )?;
    let peer = prepared.check_current()?;
    let registration = PublisherExecutionRegistrationV1::new(PublisherExecutionDraftV1 {
        instance: prepared.instance(),
        principal: scope.principal,
        node: scope.node,
        project: scope.project,
        cache_resource: scope.cache_resource,
        cache_domain: policy.resource.cache_domain(),
        isolation_policy: policy.resource.isolation_policy(),
        channel_binding: prepared.channel_binding(),
        boot_id: boot,
        clock_provenance: config.clock_provenance,
        registered_wall_seconds: observed.wall_seconds(),
        registered_boottime_nanoseconds: observed.boottime_nanoseconds(),
        controller_generation: policy.controller.generation,
        policy_generation: policy.revision.generation(),
        policy_digest: policy.revision.descriptor().digest(),
        peer_pid: peer.pid(),
        peer_tgid: peer.thread_group_id(),
        peer_cgroup_id: peer
            .cgroup_id()
            .ok_or(PublisherControlError::PolicyDenied)?,
    })?;
    let installed = PublisherIngressStore::load(journal, config.ingress_limits)?
        .install_execution(*prepared.instance().as_bytes(), registration.clone());
    if let Err(error) = installed {
        // A storage error can leave commit durability indeterminate. Keep the
        // exact execution pin until exit even though no greeting escaped.
        if matches!(&error, PublisherIngressError::Journal(_)) {
            prepared.retire();
        }
        return Err(error.into());
    }

    // Once durable facts exist, failure keeps the old execution pin and service
    // slot retired. Transport closure cannot establish execution quiescence.
    let completion = (|| {
        let fresh = clock().map_err(|_| PublisherControlError::Clock)?;
        validate_clock(fresh, boot, config.clock_provenance)?;
        let remaining_policy_seconds = policy
            .revision
            .expires_at()
            .checked_sub(observed.wall_seconds())
            .and_then(|seconds| u64::try_from(seconds).ok())
            .ok_or(PublisherControlError::Clock)?;
        validate_elapsed(
            observed,
            fresh,
            policy.revision.expires_at(),
            remaining_policy_seconds.min(30),
        )?;
        prepared.check_current()?;
        prepared.send_registration_greeting()?;
        Ok::<(), PublisherControlError>(())
    })();
    if let Err(error) = completion {
        prepared.retire();
        return Err(error);
    }
    prepared.activate();
    Ok(registration)
}

pub(crate) fn release_exited(
    journal: &mut Journal,
    sessions: &mut PublisherSessionRegistry,
    instance: PublisherInstanceId,
) -> Result<PublisherInstanceId, PublisherControlError> {
    journal.ensure_protected_authority()?;
    Ok(sessions.release_retired_after_exit(instance)?)
}

struct ResolvedPolicy {
    revision: PreparedPublisherPolicyRevisionV1,
    resource: PublisherResourceBindingV1,
    controller: PublisherControllerHeadV1,
}

fn resolve_policy(
    journal: &mut Journal,
    scope: PublisherSessionScope,
    limits: PublisherPolicyLimits,
    now: i64,
) -> Result<ResolvedPolicy, PublisherControlError> {
    let store = PublisherPolicyStore::load(journal, limits)?;
    let revision = store
        .current_policy(scope.project)?
        .ok_or(PublisherControlError::PolicyDenied)?;
    let resource = store
        .resource_binding(scope.cache_resource)?
        .ok_or(PublisherControlError::PolicyDenied)?;
    let controller = store
        .controller_head()?
        .ok_or(PublisherControlError::PolicyDenied)?;
    let selector = Selector::Resource {
        resource: scope.cache_resource,
    };
    if resource.project() != scope.project
        || resource.cache_domain() != revision.policy().cache_domain()
        || now < revision.not_before()
        || now >= revision.expires_at()
        || !revision.policy().effective_grants().iter().any(|grant| {
            grant.resource_kind() == ResourceKind::CachePublish
                && grant.operations().contains(Operation::Publish)
                && grant.selector() == &selector
        })
    {
        return Err(PublisherControlError::PolicyDenied);
    }
    Ok(ResolvedPolicy {
        revision,
        resource,
        controller,
    })
}

fn validate_config(config: PublisherControlPolicy) -> Result<(), PublisherControlError> {
    if config.clock_provenance == [0; 16] || !(1..=300).contains(&config.maximum_challenge_seconds)
    {
        return Err(PublisherControlError::InvalidConfiguration);
    }
    Ok(())
}

fn validate_clock(
    sample: RawPairedClockSample,
    boot: [u8; 16],
    provenance: [u8; 16],
) -> Result<(), PublisherControlError> {
    if sample.host_boot_id() != boot || sample.provenance().as_bytes() != provenance {
        return Err(PublisherControlError::Clock);
    }
    Ok(())
}

fn validate_elapsed(
    before: RawPairedClockSample,
    after: RawPairedClockSample,
    expiry: i64,
    maximum_seconds: u64,
) -> Result<(), PublisherControlError> {
    let elapsed = after
        .boottime_nanoseconds()
        .checked_sub(before.boottime_nanoseconds())
        .ok_or(PublisherControlError::Clock)?;
    let ceiling = maximum_seconds
        .checked_mul(1_000_000_000)
        .ok_or(PublisherControlError::Clock)?;
    if after.wall_seconds() < before.wall_seconds()
        || after.wall_seconds() >= expiry
        || elapsed >= ceiling
    {
        return Err(PublisherControlError::Clock);
    }
    Ok(())
}

#[cfg(all(test, feature = "kernel-tests"))]
pub(crate) mod tests;
