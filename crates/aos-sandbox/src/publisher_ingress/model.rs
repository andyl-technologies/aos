//! Validated inert execution and challenge audit facts.

use aos_sandbox_core::model::{CacheDomain, CacheDomainKind};
use aos_sandbox_core::{
    ChannelBinding, NodeId, ObjectDigest, PrincipalId, ProjectId, PublisherAdmissionRequestV1,
    PublisherInstanceId, ResourceId,
};
use serde::{Deserialize, Serialize};

use super::PublisherIngressError;

/// Supplies trusted-controller observations for one publisher execution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublisherExecutionDraftV1 {
    /// Fresh execution identity; never restored as live authority from this record.
    pub instance: PublisherInstanceId,
    /// Configured service principal, not a UID-derived identity.
    pub principal: PrincipalId,
    /// Executing node.
    pub node: NodeId,
    /// Authorized project scope observed at registration.
    pub project: ProjectId,
    /// Immutable logical cache resource.
    pub cache_resource: ResourceId,
    /// Exact project disclosure domain.
    pub cache_domain: CacheDomain,
    /// Resolved isolation-policy commitment.
    pub isolation_policy: ObjectDigest,
    /// Controller-minted publisher channel binding, not holder possession.
    pub channel_binding: ChannelBinding,
    /// Boot identity of the observed process and clock.
    pub boot_id: [u8; 16],
    /// Configured protected clock-reader identity.
    pub clock_provenance: [u8; 16],
    /// Registration Unix second.
    pub registered_wall_seconds: i64,
    /// Registration CLOCK_BOOTTIME nanoseconds.
    pub registered_boottime_nanoseconds: u64,
    /// Observed current controller generation.
    pub controller_generation: u64,
    /// Observed current policy generation.
    pub policy_generation: u64,
    /// Observed immutable policy digest.
    pub policy_digest: ObjectDigest,
    /// Diagnostic PID observed through a retained kernel pidfd.
    pub peer_pid: u32,
    /// Diagnostic thread-group ID; this profile requires its leader.
    pub peer_tgid: u32,
    /// Diagnostic full kernel cgroup ID; never used to reopen an execution.
    pub peer_cgroup_id: u64,
}

/// Retains validated registration facts without authenticating a live publisher.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublisherExecutionRegistrationV1(PublisherExecutionDraftV1);

impl PublisherExecutionRegistrationV1 {
    /// Validates non-sentinel execution facts for the project publisher profile.
    ///
    /// # Errors
    /// Rejects unspecified identities, non-project domains, zero generations,
    /// or missing/non-leader process observations.
    pub fn new(draft: PublisherExecutionDraftV1) -> Result<Self, PublisherIngressError> {
        if [
            draft.instance.as_bytes(),
            draft.principal.as_bytes(),
            draft.node.as_bytes(),
            draft.project.as_bytes(),
            draft.cache_resource.as_bytes(),
            draft.cache_domain.domain_id().as_bytes(),
            &draft.boot_id,
            &draft.clock_provenance,
        ]
        .iter()
        .any(|id| **id == [0; 16])
            || draft.cache_domain.kind() != CacheDomainKind::Project
            || draft.isolation_policy.as_bytes() == &[0; 32]
            || draft.channel_binding.as_bytes() == &[0; 32]
            || draft.policy_digest.as_bytes() == &[0; 32]
            || draft.controller_generation == 0
            || draft.policy_generation == 0
            || draft.peer_pid == 0
            || draft.peer_pid != draft.peer_tgid
            || draft.peer_cgroup_id == 0
        {
            return Err(PublisherIngressError::InvalidFacts);
        }
        Ok(Self(draft))
    }

    /// Borrows immutable audit facts, not a live execution proof.
    #[must_use]
    pub const fn fields(&self) -> &PublisherExecutionDraftV1 {
        &self.0
    }
}

/// Supplies the exact request and trusted time observations for registration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublisherChallengeDraftV1 {
    /// Canonical challenge-bound request; its claims remain untrusted preconditions.
    pub request: PublisherAdmissionRequestV1,
    /// Boot under which the publisher registered this challenge.
    pub boot_id: [u8; 16],
    /// Configured protected clock reader.
    pub clock_provenance: [u8; 16],
    /// Trusted registration Unix second.
    pub registered_wall_seconds: i64,
    /// Trusted registration CLOCK_BOOTTIME nanoseconds.
    pub registered_boottime_nanoseconds: u64,
    /// Exclusive registration expiry, independently clamped by the controller.
    pub expires_wall_seconds: i64,
}

/// Retains a registered challenge without consuming it or authorizing an effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublisherChallengeRegistrationV1(PublisherChallengeDraftV1);

impl PublisherChallengeRegistrationV1 {
    /// Validates the registration interval and its exact request bounds.
    ///
    /// # Errors
    /// Rejects sentinel clock/boot identities or registration outside the
    /// proposed request interval, or an interval longer than 3600 seconds.
    /// The caller must separately clamp policy time.
    pub fn new(draft: PublisherChallengeDraftV1) -> Result<Self, PublisherIngressError> {
        let plan = draft.request.plan().fields();
        if draft.boot_id == [0; 16]
            || draft.clock_provenance == [0; 16]
            || draft.registered_wall_seconds < plan.issued_seconds
            || draft.registered_wall_seconds >= draft.expires_wall_seconds
            || draft.expires_wall_seconds > plan.expires_seconds
            || draft
                .expires_wall_seconds
                .checked_sub(draft.registered_wall_seconds)
                .is_none_or(|duration| duration > 3600)
        {
            return Err(PublisherIngressError::InvalidFacts);
        }
        Ok(Self(draft))
    }

    /// Borrows exact immutable request and time observations.
    #[must_use]
    pub const fn fields(&self) -> &PublisherChallengeDraftV1 {
        &self.0
    }

    pub(super) fn validate_execution(
        &self,
        execution: &PublisherExecutionRegistrationV1,
    ) -> Result<(), PublisherIngressError> {
        let facts = execution.fields();
        let target = &self.0.request.plan().fields().target;
        if target.instance != facts.instance
            || target.principal != facts.principal
            || target.node != facts.node
            || target.project != facts.project
            || target.cache_domain != facts.cache_domain
            || target.isolation_policy != facts.isolation_policy
            || self.0.request.cache_resource() != facts.cache_resource
            || self.0.boot_id != facts.boot_id
            || self.0.clock_provenance != facts.clock_provenance
            || self.0.registered_wall_seconds < facts.registered_wall_seconds
            || self.0.registered_boottime_nanoseconds < facts.registered_boottime_nanoseconds
        {
            return Err(PublisherIngressError::ExecutionMismatch);
        }
        Ok(())
    }
}
