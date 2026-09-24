//! Protected first issuance of a public holder capability.
//!
//! An authenticated public TLS peer establishes holder and certificate-key
//! custody. Trusted controller administration supplies the approved grants;
//! the current protected publisher policy, controller head, project revocation
//! mapping, and time fence independently bound the resulting record. This
//! module registers no route by which a peer can approve its own grants.

use aos_sandbox_core::{
    AuditId, CapabilityDraft, CapabilityId, CapabilityRecord, ChannelBinding, DelegationLimits,
    Grant, PrincipalId, ProjectId, ResourceKind, Revision,
};

use crate::Journal;
use crate::cli_model::authorization_adapter::advance_initial_issuance_time_floor;
use crate::controller::ControllerProtectedClockV1;
use crate::public_api_session::PublicApiPeer;
use crate::publisher_authority::{
    PublisherAuthorityError, PublisherAuthorityLimits, PublisherCapabilityRegistry,
};
use crate::publisher_policy::{PublisherPolicyError, PublisherPolicyLimits, PublisherPolicyStore};

const MAXIMUM_VALIDITY_SECONDS: i64 = 3_600;

/// An explicit grant approval supplied only by trusted controller administration.
///
/// The public holder cannot create this approval through the capability service.
/// Every grant is still checked against the current protected project policy.
pub(crate) struct InitialPublicCapabilityApprovalV1 {
    grants: Vec<Grant>,
    delegation: DelegationLimits,
    validity_seconds: u32,
}

impl InitialPublicCapabilityApprovalV1 {
    /// Records the grant set and validity approved by the trusted controller.
    ///
    /// # Errors
    ///
    /// Rejects an empty grant set or validity outside `1..=3600` seconds.
    pub(crate) fn new(
        grants: Vec<Grant>,
        delegation: DelegationLimits,
        validity_seconds: u32,
    ) -> Result<Self, InitialPublicCapabilityErrorV1> {
        if grants.is_empty() || !(1..=3_600).contains(&validity_seconds) {
            return Err(InitialPublicCapabilityErrorV1::Rejected);
        }
        Ok(Self {
            grants,
            delegation,
            validity_seconds,
        })
    }
}

/// Returns the committed resource identity and secret holder handle.
///
/// The handle is intentionally omitted from `Debug`, audit, and public
/// projections. It may only be delivered on the authenticated holder channel.
pub(crate) struct IssuedPublicCapabilityV1 {
    id: CapabilityId,
    handle: [u8; 32],
}

impl IssuedPublicCapabilityV1 {
    /// Returns the non-authorizing public resource identity.
    #[must_use]
    pub(crate) const fn id(&self) -> CapabilityId {
        self.id
    }

    /// Returns the secret handle for delivery to the authenticated holder.
    #[must_use]
    pub(crate) const fn holder_handle(&self) -> &[u8; 32] {
        &self.handle
    }
}

/// Reports a failed first issuance without exposing a handle.
#[derive(Debug, thiserror::Error)]
pub(crate) enum InitialPublicCapabilityErrorV1 {
    /// Approval or current protected authority did not cover the requested grant.
    #[error("initial public capability issuance rejected")]
    Rejected,
    /// Protected publisher policy could not be validated.
    #[error(transparent)]
    Policy(#[from] PublisherPolicyError),
    /// Protected capability custody or commit failed.
    #[error(transparent)]
    Authority(#[from] PublisherAuthorityError),
}

struct AuthenticatedHolderV1 {
    principal: PrincipalId,
    project: ProjectId,
    key_binding: ChannelBinding,
}

pub(crate) fn issue(
    journal: &mut Journal,
    peer: &PublicApiPeer,
    approval: InitialPublicCapabilityApprovalV1,
) -> Result<IssuedPublicCapabilityV1, InitialPublicCapabilityErrorV1> {
    peer.recheck()
        .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
    let holder = AuthenticatedHolderV1 {
        principal: peer.principal(),
        project: peer.project(),
        key_binding: peer.key_binding(),
    };
    let mut clock = ControllerProtectedClockV1::open_fixed()
        .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
    let observed = clock
        .sample()
        .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
    advance_initial_issuance_time_floor(journal, observed)
        .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;

    let issued = issue_checked(journal, holder, approval, observed.wall_seconds())?;
    peer.recheck()
        .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
    Ok(issued)
}

fn issue_checked(
    journal: &mut Journal,
    holder: AuthenticatedHolderV1,
    approval: InitialPublicCapabilityApprovalV1,
    now: i64,
) -> Result<IssuedPublicCapabilityV1, InitialPublicCapabilityErrorV1> {
    if holder.principal.as_bytes() == &[0; 16]
        || holder.project.as_bytes() == &[0; 16]
        || holder.key_binding.as_bytes() == &[0; 32]
    {
        return Err(InitialPublicCapabilityErrorV1::Rejected);
    }

    // A single exclusive journal owner keeps all current-head checks and the
    // capability commit in one authority cut.
    let (policy, controller, revocation) = {
        let store = PublisherPolicyStore::load(journal, PublisherPolicyLimits::default())?;
        let policy = store
            .current_policy(holder.project)?
            .ok_or(InitialPublicCapabilityErrorV1::Rejected)?;
        let controller = store
            .controller_head()?
            .ok_or(InitialPublicCapabilityErrorV1::Rejected)?;
        let revocation = store
            .project_revocation_head(holder.project)?
            .ok_or(InitialPublicCapabilityErrorV1::Rejected)?;
        (policy, controller, revocation)
    };
    let expires_at = now
        .checked_add(i64::from(approval.validity_seconds))
        .ok_or(InitialPublicCapabilityErrorV1::Rejected)?;
    if now < policy.not_before()
        || expires_at > policy.expires_at()
        || expires_at <= now
        || expires_at - now > MAXIMUM_VALIDITY_SECONDS
        || controller.principal.as_bytes() == &[0; 16]
        || controller.generation == 0
        || revocation.generation() == 0
        || !approval.grants.iter().all(|grant| {
            if grant.id().as_bytes() == &[0; 16] {
                return false;
            }
            let candidates = if grant.delegable() {
                policy.policy().delegable_grants()
            } else {
                policy.policy().effective_grants()
            };
            candidates.iter().any(|candidate| {
                candidate.resource_kind() == grant.resource_kind()
                    && grant.operations().is_subset_of(candidate.operations())
                    && candidate.selector().contains(grant.selector())
                    && (grant.resource_kind() != ResourceKind::CachePublish
                        || matches!(
                            grant.selector(),
                            aos_sandbox_core::Selector::Resource { .. }
                        ))
            })
        })
    {
        return Err(InitialPublicCapabilityErrorV1::Rejected);
    }

    let id = CapabilityId::new();
    let capability = CapabilityRecord::issue(CapabilityDraft {
        id,
        issuer: controller.principal,
        audience: controller.principal,
        holder: holder.principal,
        channel_binding: holder.key_binding,
        root_subject: holder.principal,
        project: holder.project,
        sandbox: None,
        incarnation: None,
        grants: approval.grants,
        policy_digest: policy.descriptor().digest(),
        assignment_epoch: None,
        not_before: now,
        expires_at,
        revocation_scope: revocation.scope(),
        revocation_generation: Revision::new(revocation.generation()),
        delegation: approval.delegation,
        parent_decision: AuditId::from_bytes(*id.as_bytes()),
    })
    .map_err(|_| InitialPublicCapabilityErrorV1::Rejected)?;
    let mut registry =
        PublisherCapabilityRegistry::load(journal, PublisherAuthorityLimits::default())?;
    registry.install_from_trusted_controller(*id.as_bytes(), capability)?;
    let handle = registry.holder_handle(id, holder.principal, holder.key_binding)?;
    Ok(IssuedPublicCapabilityV1 { id, handle })
}

#[cfg(test)]
mod tests;
