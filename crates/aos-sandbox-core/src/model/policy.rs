//! Resolved portable policy and advisory optimization values.
//!
//! A policy is the normalized typed result of policy compilation. It is not
//! source Nix, an ordered allow/deny program, or a backend option bag. Hard
//! grants, view actions, resource enforcement, disclosure, and revocation are
//! represented separately from advisory optimization.

use serde::{Deserialize, Serialize};

use crate::{
    AttachmentSlotId, FeatureRef, Grant, ObjectDescriptor, RelativePath, ResourceId, Selector,
};

use super::{CacheDomain, ResourceProfile, ViewMutation};

/// Reports an invalid normalized policy or optimization value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidPolicyModel {
    /// A set-valued collection is not strictly ordered or contains duplicates.
    #[error("set-valued policy collection must be strictly ordered and unique")]
    SetNotCanonical,
    /// Effective grants repeat an identity or semantic authority tuple.
    #[error("effective grants contain a duplicate identity or semantic grant")]
    DuplicateEffectiveGrant,
    /// A delegable grant is absent from or differs from its effective grant.
    #[error("delegable grants must be an exact delegable subset of effective grants")]
    InvalidDelegableSubset,
    /// A resolved policy retains an inherited resource limit.
    #[error("resolved policy resource limits cannot retain inheritance")]
    UnresolvedLimit,
    /// A policy explanation cites an input not committed by the policy.
    #[error("policy explanation source must occur in input commitments")]
    UnknownExplanationSource,
    /// An optimization list contains a duplicate typed action.
    #[error("optimization entries must be unique")]
    DuplicateOptimization,
}

/// Stores one ordered logical namespace-policy action.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum PolicyViewAction {
    /// Includes a subtree from a preauthorized logical source.
    Include {
        /// Logical source capability resource.
        source: ResourceId,
        /// View-relative subtree prefix.
        prefix: RelativePath,
    },
    /// Excludes one view-relative subtree.
    Exclude {
        /// View-relative subtree prefix.
        prefix: RelativePath,
    },
    /// Attaches a separately authorized source at a declared slot.
    Attach {
        /// Logical source capability resource.
        source: ResourceId,
        /// Broker-owned destination slot.
        destination_slot: AttachmentSlotId,
        /// Maximum mutation semantics of the attachment.
        mode: ViewMutation,
    },
    /// Applies a registered metadata/presentation policy to a subtree.
    Present {
        /// View-relative subtree prefix.
        prefix: RelativePath,
        /// Registered presentation semantics.
        presentation_profile: FeatureRef,
    },
}

/// Selects the required response to a current-policy revocation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RevocationMode {
    /// Denies new operations while existing admitted effects drain.
    DenyNew,
    /// Freezes the payload before the bounded grace period ends.
    Freeze,
    /// Stops the payload before the bounded grace period ends.
    Stop,
}

/// Stores the effective revocation response and grace interval.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationPolicy {
    mode: RevocationMode,
    grace_nanos: u64,
}

impl RevocationPolicy {
    /// Constructs an explicit revocation response.
    #[must_use]
    pub const fn new(mode: RevocationMode, grace_nanos: u64) -> Self {
        Self { mode, grace_nanos }
    }

    /// Returns the required revocation action.
    #[must_use]
    pub const fn mode(self) -> RevocationMode {
        self.mode
    }

    /// Returns the maximum grace interval in nanoseconds.
    #[must_use]
    pub const fn grace_nanos(self) -> u64 {
        self.grace_nanos
    }
}

/// Selects one closed advisory optimization family.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OptimizationKind {
    /// Prefetches structural metadata.
    PrefetchMetadata,
    /// Prefetches immutable content.
    PrefetchContent,
    /// Performs bounded sequential or dependency-aware readahead.
    Readahead,
    /// Retains or eagerly builds a directory lookup index.
    DirectoryIndex,
    /// Prefers a verified passthrough data path.
    Passthrough,
    /// Extends advisory cache/index residency within hard limits.
    Keepalive,
    /// Assigns relative cache replacement weight.
    CacheWeight,
    /// Allows compatible work to share a bounded worker process.
    WorkerPooling,
}

/// Stores one bounded advisory optimization action.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Optimization {
    kind: OptimizationKind,
    target: Selector,
    bounded_value: u64,
}

impl Optimization {
    /// Constructs one advisory action over an already authorized selector.
    #[must_use]
    pub const fn new(kind: OptimizationKind, target: Selector, bounded_value: u64) -> Self {
        Self {
            kind,
            target,
            bounded_value,
        }
    }

    /// Returns the closed optimization family.
    #[must_use]
    pub const fn kind(&self) -> OptimizationKind {
        self.kind
    }

    /// Returns the logical optimization target.
    #[must_use]
    pub const fn target(&self) -> &Selector {
        &self.target
    }

    /// Returns the family-specific bounded advisory value.
    #[must_use]
    pub const fn bounded_value(&self) -> u64 {
        self.bounded_value
    }
}

/// Stores the separately addressed advisory optimization set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct OptimizationProfile(Vec<Optimization>);

impl OptimizationProfile {
    /// Constructs a duplicate-free optimization set.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPolicyModel::DuplicateOptimization`] when two entries
    /// are semantically identical. Canonical wire ordering is enforced by the
    /// portable codec.
    pub fn new(entries: Vec<Optimization>) -> Result<Self, InvalidPolicyModel> {
        for (index, entry) in entries.iter().enumerate() {
            if entries[..index].contains(entry) {
                return Err(InvalidPolicyModel::DuplicateOptimization);
            }
        }
        Ok(Self(entries))
    }

    /// Returns the unique advisory actions.
    #[must_use]
    pub fn entries(&self) -> &[Optimization] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for OptimizationProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(Vec::<Optimization>::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Identifies one closed explanation source category.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExplanationReasonCode {
    /// A node-wide safety or capacity ceiling.
    SiteCeiling,
    /// A project authority or capacity ceiling.
    ProjectCeiling,
    /// A logical ancestor's delegated ceiling.
    AncestorCeiling,
    /// The authenticated caller's grant.
    CallerGrant,
    /// A requested or effective resource limit.
    ResourceLimit,
    /// A cache disclosure-domain restriction.
    DisclosureDomain,
    /// Current revocation policy.
    Revocation,
    /// A required backend semantic or enforcement feature.
    BackendRequirement,
    /// A namespace attachment conflict.
    AttachmentConflict,
    /// A project-environment policy decision.
    EnvironmentPolicy,
    /// Default-deny or default policy behavior.
    Default,
}

/// Stores one bounded normalized policy explanation reason.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExplanationReason {
    code: ExplanationReasonCode,
    source: Option<ObjectDescriptor>,
}

impl ExplanationReason {
    /// Constructs one typed explanation reason.
    #[must_use]
    pub const fn new(code: ExplanationReasonCode, source: Option<ObjectDescriptor>) -> Self {
        Self { code, source }
    }

    /// Returns the closed explanation category.
    #[must_use]
    pub const fn code(&self) -> ExplanationReasonCode {
        self.code
    }

    /// Returns the committed input that caused the decision, when applicable.
    #[must_use]
    pub const fn source(&self) -> Option<&ObjectDescriptor> {
        self.source.as_ref()
    }
}

/// Stores one complete resolved portable policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Policy {
    required_features: Vec<FeatureRef>,
    input_commitments: Vec<ObjectDescriptor>,
    effective_grants: Vec<Grant>,
    delegable_grants: Vec<Grant>,
    limits: ResourceProfile,
    view_actions: Vec<PolicyViewAction>,
    cache_domain: CacheDomain,
    revocation: RevocationPolicy,
    optimization_digest: Option<ObjectDescriptor>,
    explanation_reasons: Vec<ExplanationReason>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyWire {
    required_features: Vec<FeatureRef>,
    input_commitments: Vec<ObjectDescriptor>,
    effective_grants: Vec<Grant>,
    delegable_grants: Vec<Grant>,
    limits: ResourceProfile,
    view_actions: Vec<PolicyViewAction>,
    cache_domain: CacheDomain,
    revocation: RevocationPolicy,
    optimization_digest: Option<ObjectDescriptor>,
    explanation_reasons: Vec<ExplanationReason>,
}

impl<'de> Deserialize<'de> for Policy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = PolicyWire::deserialize(deserializer)?;
        Self::new(
            wire.required_features,
            wire.input_commitments,
            wire.effective_grants,
            wire.delegable_grants,
            wire.limits,
            wire.view_actions,
            wire.cache_domain,
            wire.revocation,
            wire.optimization_digest,
            wire.explanation_reasons,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl Policy {
    /// Constructs a normalized resolved policy and validates its subsets.
    ///
    /// # Errors
    ///
    /// Returns an error for noncanonical feature sets, duplicate grants,
    /// invalid delegable subsets, inherited limits, or explanation sources
    /// outside the committed input sequence.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        required_features: Vec<FeatureRef>,
        input_commitments: Vec<ObjectDescriptor>,
        effective_grants: Vec<Grant>,
        delegable_grants: Vec<Grant>,
        limits: ResourceProfile,
        view_actions: Vec<PolicyViewAction>,
        cache_domain: CacheDomain,
        revocation: RevocationPolicy,
        optimization_digest: Option<ObjectDescriptor>,
        explanation_reasons: Vec<ExplanationReason>,
    ) -> Result<Self, InvalidPolicyModel> {
        if !strictly_increasing(&required_features) {
            return Err(InvalidPolicyModel::SetNotCanonical);
        }
        validate_effective_grants(&effective_grants)?;
        validate_delegable_grants(&effective_grants, &delegable_grants)?;
        if limits.contains_inherited() {
            return Err(InvalidPolicyModel::UnresolvedLimit);
        }
        if explanation_reasons.iter().any(|reason| {
            reason
                .source()
                .is_some_and(|source| !input_commitments.contains(source))
        }) {
            return Err(InvalidPolicyModel::UnknownExplanationSource);
        }

        Ok(Self {
            required_features,
            input_commitments,
            effective_grants,
            delegable_grants,
            limits,
            view_actions,
            cache_domain,
            revocation,
            optimization_digest,
            explanation_reasons,
        })
    }

    /// Returns the exact required feature set.
    #[must_use]
    pub fn required_features(&self) -> &[FeatureRef] {
        &self.required_features
    }

    /// Returns policy inputs in semantic resolution order.
    #[must_use]
    pub fn input_commitments(&self) -> &[ObjectDescriptor] {
        &self.input_commitments
    }

    /// Returns the normalized effective grant set.
    #[must_use]
    pub fn effective_grants(&self) -> &[Grant] {
        &self.effective_grants
    }

    /// Returns the exact subset eligible for further attenuation.
    #[must_use]
    pub fn delegable_grants(&self) -> &[Grant] {
        &self.delegable_grants
    }

    /// Returns fully resolved resource limits.
    #[must_use]
    pub const fn limits(&self) -> &ResourceProfile {
        &self.limits
    }

    /// Returns the ordered namespace construction program.
    #[must_use]
    pub fn view_actions(&self) -> &[PolicyViewAction] {
        &self.view_actions
    }

    /// Returns the maximum permitted cache disclosure domain.
    #[must_use]
    pub const fn cache_domain(&self) -> CacheDomain {
        self.cache_domain
    }

    /// Returns the required current-policy revocation response.
    #[must_use]
    pub const fn revocation(&self) -> RevocationPolicy {
        self.revocation
    }

    /// Returns the separately addressed advisory optimization commitment.
    #[must_use]
    pub const fn optimization_digest(&self) -> Option<&ObjectDescriptor> {
        self.optimization_digest.as_ref()
    }

    /// Returns the bounded normalized explanation table.
    #[must_use]
    pub fn explanation_reasons(&self) -> &[ExplanationReason] {
        &self.explanation_reasons
    }
}

fn validate_effective_grants(grants: &[Grant]) -> Result<(), InvalidPolicyModel> {
    for (index, grant) in grants.iter().enumerate() {
        if grants[..index].iter().any(|prior| {
            prior.id() == grant.id()
                || (prior.resource_kind() == grant.resource_kind()
                    && prior.operations() == grant.operations()
                    && prior.selector() == grant.selector()
                    && prior.delegable() == grant.delegable())
        }) {
            return Err(InvalidPolicyModel::DuplicateEffectiveGrant);
        }
    }
    Ok(())
}

fn validate_delegable_grants(
    effective: &[Grant],
    delegable: &[Grant],
) -> Result<(), InvalidPolicyModel> {
    for (index, grant) in delegable.iter().enumerate() {
        if !grant.delegable()
            || delegable[..index]
                .iter()
                .any(|prior| prior.id() == grant.id() || prior == grant)
            || !effective.iter().any(|candidate| candidate == grant)
        {
            return Err(InvalidPolicyModel::InvalidDelegableSubset);
        }
    }
    Ok(())
}

fn strictly_increasing<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CacheDomainKind, Limit, LimitDimension, LimitValue};
    use crate::{CacheDomainId, GrantId, MediaType, ObjectDigest, Operation, OperationSet};

    fn descriptor(byte: u8) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new("application/vnd.aos.sandbox.policy-input.v1+cbor")
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            ObjectDigest::from_bytes([byte; 32]),
            1,
        )
    }

    fn grant(id: u8, delegable: bool) -> Grant {
        Grant::new(
            GrantId::from_bytes([id; 16]),
            crate::ResourceKind::Tree,
            OperationSet::one(Operation::ContentRead),
            Selector::Tree {
                tree: descriptor(id),
            },
            delegable,
        )
        .unwrap_or_else(|error| panic!("test grant failed: {error}"))
    }

    fn limits() -> ResourceProfile {
        ResourceProfile::new(vec![Limit::new(
            LimitDimension::Memory,
            LimitValue::Bounded(1024),
            FeatureRef::new("aos.sandbox.enforcement.cgroup-v2", 1, 0)
                .unwrap_or_else(|error| panic!("test feature failed: {error}")),
        )])
        .unwrap_or_else(|error| panic!("test limits failed: {error}"))
    }

    fn policy(
        effective: Vec<Grant>,
        delegable: Vec<Grant>,
        reasons: Vec<ExplanationReason>,
    ) -> Result<Policy, InvalidPolicyModel> {
        Policy::new(
            Vec::new(),
            vec![descriptor(9)],
            effective,
            delegable,
            limits(),
            Vec::new(),
            CacheDomain::new(CacheDomainKind::Private, CacheDomainId::from_bytes([3; 16])),
            RevocationPolicy::new(RevocationMode::Freeze, 1_000),
            None,
            reasons,
        )
    }

    #[test]
    fn delegable_grants_are_an_exact_effective_subset() {
        assert_eq!(
            policy(vec![grant(1, false)], vec![grant(1, true)], Vec::new()),
            Err(InvalidPolicyModel::InvalidDelegableSubset)
        );
    }

    #[test]
    fn semantically_duplicate_grants_fail_even_with_new_ids() {
        let first = grant(1, false);
        let second = Grant::new(
            GrantId::from_bytes([2; 16]),
            first.resource_kind(),
            first.operations(),
            first.selector().clone(),
            first.delegable(),
        )
        .unwrap_or_else(|error| panic!("test grant failed: {error}"));

        assert_eq!(
            policy(vec![first, second], Vec::new(), Vec::new()),
            Err(InvalidPolicyModel::DuplicateEffectiveGrant)
        );
    }

    #[test]
    fn resolved_policy_rejects_inherited_limits() {
        let inherited = ResourceProfile::new(vec![Limit::new(
            LimitDimension::Memory,
            LimitValue::Inherited,
            FeatureRef::new("aos.sandbox.enforcement.cgroup-v2", 1, 0)
                .unwrap_or_else(|error| panic!("test feature failed: {error}")),
        )])
        .unwrap_or_else(|error| panic!("test limits failed: {error}"));
        let result = Policy::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            inherited,
            Vec::new(),
            CacheDomain::new(CacheDomainKind::Private, CacheDomainId::from_bytes([3; 16])),
            RevocationPolicy::new(RevocationMode::Stop, 0),
            None,
            Vec::new(),
        );

        assert_eq!(result, Err(InvalidPolicyModel::UnresolvedLimit));
    }

    #[test]
    fn explanations_must_cite_committed_inputs() {
        let reason =
            ExplanationReason::new(ExplanationReasonCode::ProjectCeiling, Some(descriptor(8)));

        assert_eq!(
            policy(Vec::new(), Vec::new(), vec![reason]),
            Err(InvalidPolicyModel::UnknownExplanationSource)
        );
    }

    #[test]
    fn duplicate_optimizations_fail() {
        let optimization = Optimization::new(
            OptimizationKind::PrefetchContent,
            Selector::Resource {
                resource: ResourceId::from_bytes([4; 16]),
            },
            64,
        );

        assert_eq!(
            OptimizationProfile::new(vec![optimization.clone(), optimization]),
            Err(InvalidPolicyModel::DuplicateOptimization)
        );
    }
}
