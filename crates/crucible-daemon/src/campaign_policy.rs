//! Immutable local identity and operation policy for the campaign listener.
//!
//! Linux peer credentials are mapped by exact effective user/group pair. The
//! process ID is retained only for diagnostics because PID reuse is not a
//! stable authorization identity. Grants are exact operation plus either one
//! canonical campaign name or all names. No policy input enters campaign
//! semantic state or content identity.

use std::collections::{BTreeMap, BTreeSet};

use crucible_campaign::{
    CampaignAuthorizationError, CampaignCodecError, CampaignHash, CampaignName, CampaignPrincipal,
    CampaignPrincipalAuthorizer, CampaignServiceOperation,
};
use serde::Deserialize;

use crate::{UnixPeerCampaignCredentials, UnixPeerCampaignPrincipalResolver};

/// Maximum exact Unix credential bindings retained by one local policy.
pub const MAX_CAMPAIGN_PEER_BINDINGS: usize = 4_096;
/// Maximum exact operation/campaign grants retained by one local policy.
pub const MAX_CAMPAIGN_ACCESS_GRANTS: usize = 65_536;
/// Maximum encoded deployment-policy bytes accepted before TOML parsing.
pub const MAX_CAMPAIGN_POLICY_BYTES: usize = 1024 * 1024;

/// Stable schema name for the local campaign deployment policy.
pub const CAMPAIGN_POLICY_SCHEMA: &str = "crucible.campaign-local-policy";
/// Current accepted local campaign deployment-policy version.
pub const CAMPAIGN_POLICY_SCHEMA_VERSION: u32 = 1;

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

    /// Parses one strict bounded versioned local deployment policy.
    ///
    /// The TOML document uses this closed shape:
    ///
    /// ```toml
    /// schema = "crucible.campaign-local-policy"
    /// version = 1
    ///
    /// [[bindings]]
    /// user_id = 1000
    /// group_id = 1000
    /// principal = "operator"
    ///
    /// [[grants]]
    /// principal = "operator"
    /// operation = "get-campaign"
    /// campaign = "*"
    /// ```
    ///
    /// A grant campaign of `"*"` selects all canonical campaign names. Every
    /// other value is parsed through [`CampaignName`]. Unknown fields and
    /// operation labels fail closed.
    ///
    /// # Errors
    ///
    /// Returns [`UnixPeerCampaignPolicyLoadError`] for an oversized, non-UTF-8,
    /// malformed, unsupported, noncanonical, ambiguous, or unreachable policy.
    pub fn from_toml_bytes(bytes: &[u8]) -> Result<Self, UnixPeerCampaignPolicyLoadError> {
        if bytes.len() > MAX_CAMPAIGN_POLICY_BYTES {
            return Err(UnixPeerCampaignPolicyLoadError::TooLarge);
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|source| UnixPeerCampaignPolicyLoadError::Utf8 { source })?;
        let document: CampaignPolicyDocument = toml::from_str(text)
            .map_err(|source| UnixPeerCampaignPolicyLoadError::Toml { source })?;
        if document.schema != CAMPAIGN_POLICY_SCHEMA
            || document.version != CAMPAIGN_POLICY_SCHEMA_VERSION
        {
            return Err(UnixPeerCampaignPolicyLoadError::UnsupportedSchema);
        }
        if document.bindings.len() > MAX_CAMPAIGN_PEER_BINDINGS {
            return Err(UnixPeerCampaignPolicyLoadError::Policy(
                UnixPeerCampaignPolicyError::TooManyBindings,
            ));
        }
        if document.grants.len() > MAX_CAMPAIGN_ACCESS_GRANTS {
            return Err(UnixPeerCampaignPolicyLoadError::Policy(
                UnixPeerCampaignPolicyError::TooManyGrants,
            ));
        }

        let mut bindings = Vec::with_capacity(document.bindings.len());
        for binding in document.bindings {
            let principal = CampaignPrincipal::new(binding.principal)
                .map_err(|source| UnixPeerCampaignPolicyLoadError::InvalidPrincipal { source })?;
            bindings.push(UnixPeerCampaignBinding::new(
                UnixPeerCampaignIdentity::new(binding.user_id, binding.group_id),
                principal,
            ));
        }

        let mut grants = Vec::with_capacity(document.grants.len());
        for grant in document.grants {
            let principal = CampaignPrincipal::new(grant.principal)
                .map_err(|source| UnixPeerCampaignPolicyLoadError::InvalidPrincipal { source })?;
            let operation = parse_operation(&grant.operation).ok_or_else(|| {
                UnixPeerCampaignPolicyLoadError::UnknownOperation {
                    operation: grant.operation.clone(),
                }
            })?;
            let scope = if grant.campaign == "*" {
                CampaignAccessScope::AllCampaigns
            } else {
                CampaignAccessScope::Campaign(CampaignName::new(grant.campaign).map_err(
                    |source| UnixPeerCampaignPolicyLoadError::InvalidCampaign { source },
                )?)
            };
            grants.push(CampaignAccessGrant::new(principal, operation, scope));
        }
        Self::new(bindings, grants).map_err(UnixPeerCampaignPolicyLoadError::Policy)
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

    fn permits_all_campaigns(
        &self,
        principal: &CampaignPrincipal,
        operation: CampaignServiceOperation,
    ) -> bool {
        self.known_principals.contains(principal)
            && self.grants.contains(&CampaignAccessGrant::new(
                principal.clone(),
                operation,
                CampaignAccessScope::AllCampaigns,
            ))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CampaignPolicyDocument {
    schema: String,
    version: u32,
    #[serde(default)]
    bindings: Vec<CampaignPolicyBinding>,
    #[serde(default)]
    grants: Vec<CampaignPolicyGrant>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CampaignPolicyBinding {
    user_id: u32,
    group_id: u32,
    principal: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CampaignPolicyGrant {
    principal: String,
    operation: String,
    campaign: String,
}

fn parse_operation(operation: &str) -> Option<CampaignServiceOperation> {
    match operation {
        "list-campaigns" => Some(CampaignServiceOperation::ListCampaigns),
        "create-campaign" => Some(CampaignServiceOperation::CreateCampaign),
        "derive-campaign" => Some(CampaignServiceOperation::DeriveCampaign),
        "get-campaign" => Some(CampaignServiceOperation::GetCampaign),
        "get-campaign-status" => Some(CampaignServiceOperation::GetCampaignStatus),
        "get-campaign-snapshot" => Some(CampaignServiceOperation::GetCampaignSnapshot),
        "watch-campaign" => Some(CampaignServiceOperation::WatchCampaign),
        "query-campaign-graph" => Some(CampaignServiceOperation::QueryCampaignGraph),
        "query-campaign-findings" => Some(CampaignServiceOperation::QueryCampaignFindings),
        "get-campaign-finding-object" => Some(CampaignServiceOperation::GetCampaignFindingObject),
        "explain-campaign-attempt" => Some(CampaignServiceOperation::ExplainCampaignAttempt),
        "get-campaign-planner-rankings" => {
            Some(CampaignServiceOperation::GetCampaignPlannerRankings)
        }
        "get-campaign-graph-object" => Some(CampaignServiceOperation::GetCampaignGraphObject),
        "query-campaign-choices" => Some(CampaignServiceOperation::QueryCampaignChoices),
        "query-campaign-frontier" => Some(CampaignServiceOperation::QueryCampaignFrontier),
        "get-campaign-frontier-object" => Some(CampaignServiceOperation::GetCampaignFrontierObject),
        "get-campaign-choice-object" => Some(CampaignServiceOperation::GetCampaignChoiceObject),
        "apply-campaign-command" => Some(CampaignServiceOperation::ApplyCampaignCommand),
        "pin-campaign" => Some(CampaignServiceOperation::PinCampaign),
        "submit-discovery-request" => Some(CampaignServiceOperation::SubmitDiscoveryRequest),
        "submit-branch-request" => Some(CampaignServiceOperation::SubmitBranchRequest),
        "attach-campaign-runtime" => Some(CampaignServiceOperation::AttachCampaignRuntime),
        _ => None,
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
    fn authorize_all_campaigns(
        &self,
        principal: &CampaignPrincipal,
        operation: CampaignServiceOperation,
        _request_digest: CampaignHash,
    ) -> Result<(), CampaignAuthorizationError> {
        if self.permits_all_campaigns(principal, operation) {
            Ok(())
        } else {
            Err(CampaignAuthorizationError::Unauthorized)
        }
    }

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

/// Failure to parse and validate one local campaign deployment policy.
#[derive(Debug, thiserror::Error)]
pub enum UnixPeerCampaignPolicyLoadError {
    /// Input exceeded the fixed pre-parse byte ceiling.
    #[error("campaign peer policy exceeds 1 MiB")]
    TooLarge,
    /// Input was not UTF-8 TOML text.
    #[error("campaign peer policy is not UTF-8")]
    Utf8 {
        /// Exact UTF-8 decoding failure.
        #[source]
        source: std::str::Utf8Error,
    },
    /// The strict TOML document was malformed or carried an unknown field.
    #[error("campaign peer policy TOML is invalid")]
    Toml {
        /// Exact TOML decoding failure.
        #[source]
        source: toml::de::Error,
    },
    /// The document schema name or version is unsupported.
    #[error("campaign peer policy schema is unsupported")]
    UnsupportedSchema,
    /// A configured principal violated the canonical service grammar.
    #[error("campaign peer policy principal is invalid")]
    InvalidPrincipal {
        /// Exact canonical principal failure.
        #[source]
        source: CampaignCodecError,
    },
    /// A configured campaign scope violated the canonical repository grammar.
    #[error("campaign peer policy campaign scope is invalid")]
    InvalidCampaign {
        /// Exact canonical campaign-name failure.
        #[source]
        source: CampaignCodecError,
    },
    /// A grant named an operation outside the closed v1 vocabulary.
    #[error("campaign peer policy operation `{operation}` is unknown")]
    UnknownOperation {
        /// Exact rejected operation label.
        operation: String,
    },
    /// The decoded bindings or grants violated closed policy invariants.
    #[error(transparent)]
    Policy(UnixPeerCampaignPolicyError),
}

#[cfg(test)]
mod tests;
