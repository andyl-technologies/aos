//! Immutable local identity and operation policy for the campaign listener.
//!
//! Linux peer credentials are mapped by exact effective user/group pair. The
//! process ID is retained only for diagnostics because PID reuse is not a
//! stable authorization identity. Grants are exact operation plus either one
//! canonical campaign name or all names. No policy input enters campaign
//! semantic state or content identity.

use std::collections::{BTreeMap, BTreeSet};

use crucible_campaign::{
    CampaignAuthorizationError, CampaignHash, CampaignName, CampaignPrincipal,
    CampaignPrincipalAuthorizer, CampaignServiceOperation,
};

use crate::{UnixPeerCampaignCredentials, UnixPeerCampaignPrincipalResolver};

/// Maximum exact Unix credential bindings retained by one local policy.
pub const MAX_CAMPAIGN_PEER_BINDINGS: usize = 4_096;
/// Maximum exact operation/campaign grants retained by one local policy.
pub const MAX_CAMPAIGN_ACCESS_GRANTS: usize = 65_536;

/// Stable Unix identity selector used for campaign peer authentication.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixPeerCampaignIdentity {
    user_id: u32,
    group_id: u32,
}

impl UnixPeerCampaignIdentity {
    /// Builds one exact effective user/group selector.
    #[must_use]
    pub const fn new(user_id: u32, group_id: u32) -> Self {
        Self { user_id, group_id }
    }

    /// Returns the required effective user ID.
    #[must_use]
    pub const fn user_id(self) -> u32 {
        self.user_id
    }

    /// Returns the required effective group ID.
    #[must_use]
    pub const fn group_id(self) -> u32 {
        self.group_id
    }
}

/// One exact Unix identity to campaign-principal binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnixPeerCampaignBinding {
    identity: UnixPeerCampaignIdentity,
    principal: CampaignPrincipal,
}

impl UnixPeerCampaignBinding {
    /// Binds one effective Unix identity to one canonical principal.
    #[must_use]
    pub const fn new(identity: UnixPeerCampaignIdentity, principal: CampaignPrincipal) -> Self {
        Self {
            identity,
            principal,
        }
    }

    /// Returns the exact effective Unix identity selector.
    #[must_use]
    pub const fn identity(&self) -> UnixPeerCampaignIdentity {
        self.identity
    }

    /// Returns the operational campaign principal.
    #[must_use]
    pub const fn principal(&self) -> &CampaignPrincipal {
        &self.principal
    }
}

/// Campaign-name scope of one operation grant.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CampaignAccessScope {
    /// Grants the operation for every canonical campaign name.
    AllCampaigns,
    /// Grants the operation for one exact canonical campaign name.
    Campaign(CampaignName),
}

/// One immutable principal/operation/campaign authorization grant.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CampaignAccessGrant {
    principal: CampaignPrincipal,
    operation: CampaignServiceOperation,
    scope: CampaignAccessScope,
}

impl CampaignAccessGrant {
    /// Builds one exact local campaign-service grant.
    #[must_use]
    pub const fn new(
        principal: CampaignPrincipal,
        operation: CampaignServiceOperation,
        scope: CampaignAccessScope,
    ) -> Self {
        Self {
            principal,
            operation,
            scope,
        }
    }

    /// Returns the authenticated principal receiving the grant.
    #[must_use]
    pub const fn principal(&self) -> &CampaignPrincipal {
        &self.principal
    }

    /// Returns the exact service operation receiving the grant.
    #[must_use]
    pub const fn operation(&self) -> CampaignServiceOperation {
        self.operation
    }

    /// Returns the exact-name or all-campaign scope.
    #[must_use]
    pub const fn scope(&self) -> &CampaignAccessScope {
        &self.scope
    }
}

/// Bounded immutable peer and operation policy for a local campaign listener.
pub struct UnixPeerCampaignPolicy {
    principals: BTreeMap<UnixPeerCampaignIdentity, CampaignPrincipal>,
    known_principals: BTreeSet<CampaignPrincipal>,
    grants: BTreeSet<CampaignAccessGrant>,
}

impl UnixPeerCampaignPolicy {
    /// Builds one closed policy from bounded binding and grant iterators.
    ///
    /// Empty inputs form an explicit deny-all policy. Every configured grant
    /// must name a principal reachable through at least one Unix binding.
    ///
    /// # Errors
    ///
    /// Returns [`UnixPeerCampaignPolicyError`] for an oversized input,
    /// duplicate identity or grant, or a grant naming an unreachable
    /// principal.
    pub fn new(
        bindings: impl IntoIterator<Item = UnixPeerCampaignBinding>,
        grants: impl IntoIterator<Item = CampaignAccessGrant>,
    ) -> Result<Self, UnixPeerCampaignPolicyError> {
        let mut principals = BTreeMap::new();
        let mut known_principals = BTreeSet::new();
        for binding in bindings {
            if principals.len() >= MAX_CAMPAIGN_PEER_BINDINGS {
                return Err(UnixPeerCampaignPolicyError::TooManyBindings);
            }
            known_principals.insert(binding.principal.clone());
            if principals
                .insert(binding.identity, binding.principal)
                .is_some()
            {
                return Err(UnixPeerCampaignPolicyError::DuplicateIdentity);
            }
        }

        let mut retained_grants = BTreeSet::new();
        for grant in grants {
            if retained_grants.len() >= MAX_CAMPAIGN_ACCESS_GRANTS {
                return Err(UnixPeerCampaignPolicyError::TooManyGrants);
            }
            if !known_principals.contains(grant.principal()) {
                return Err(UnixPeerCampaignPolicyError::UnknownGrantPrincipal);
            }
            if !retained_grants.insert(grant) {
                return Err(UnixPeerCampaignPolicyError::DuplicateGrant);
            }
        }
        Ok(Self {
            principals,
            known_principals,
            grants: retained_grants,
        })
    }

    /// Returns the exact number of Unix peer bindings.
    #[must_use]
    pub fn binding_count(&self) -> usize {
        self.principals.len()
    }

    /// Returns the exact number of operation/campaign grants.
    #[must_use]
    pub fn grant_count(&self) -> usize {
        self.grants.len()
    }

    fn permits(
        &self,
        principal: &CampaignPrincipal,
        operation: CampaignServiceOperation,
        campaign: &CampaignName,
    ) -> bool {
        if !self.known_principals.contains(principal) {
            return false;
        }
        let all = CampaignAccessGrant::new(
            principal.clone(),
            operation,
            CampaignAccessScope::AllCampaigns,
        );
        let exact = CampaignAccessGrant::new(
            principal.clone(),
            operation,
            CampaignAccessScope::Campaign(campaign.clone()),
        );
        self.grants.contains(&all) || self.grants.contains(&exact)
    }
}

impl UnixPeerCampaignPrincipalResolver for UnixPeerCampaignPolicy {
    fn resolve_campaign_principal(
        &self,
        credentials: UnixPeerCampaignCredentials,
    ) -> Result<CampaignPrincipal, CampaignAuthorizationError> {
        self.principals
            .get(&UnixPeerCampaignIdentity::new(
                credentials.user_id(),
                credentials.group_id(),
            ))
            .cloned()
            .ok_or(CampaignAuthorizationError::Unauthorized)
    }
}

impl CampaignPrincipalAuthorizer for UnixPeerCampaignPolicy {
    fn authorize(
        &self,
        principal: &CampaignPrincipal,
        operation: CampaignServiceOperation,
        campaign: &CampaignName,
        _request_digest: CampaignHash,
    ) -> Result<(), CampaignAuthorizationError> {
        if self.permits(principal, operation, campaign) {
            Ok(())
        } else {
            Err(CampaignAuthorizationError::Unauthorized)
        }
    }
}

/// Invalid immutable campaign-listener policy configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum UnixPeerCampaignPolicyError {
    /// The Unix binding count exceeded its fixed ceiling.
    #[error("campaign peer binding count exceeds 4,096")]
    TooManyBindings,
    /// Two bindings selected the same effective Unix identity.
    #[error("campaign peer policy repeats a Unix identity")]
    DuplicateIdentity,
    /// The grant count exceeded its fixed ceiling.
    #[error("campaign access grant count exceeds 65,536")]
    TooManyGrants,
    /// Two grants named the same principal, operation, and scope.
    #[error("campaign peer policy repeats an access grant")]
    DuplicateGrant,
    /// A grant named no principal reachable through a Unix binding.
    #[error("campaign access grant names an unbound principal")]
    UnknownGrantPrincipal,
}

#[cfg(test)]
mod tests;
