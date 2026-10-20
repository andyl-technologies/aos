//! Complete portable and controller-accounting resource resolution.
//!
//! The model contains all sixteen portable policy dimensions and all twenty-two
//! controller accounting dimensions. Enforcement is a closed typed registry;
//! arbitrary feature names cannot claim to enforce a limit.

use std::collections::BTreeSet;

use aos_sandbox_model::model::{Limit, LimitDimension, LimitValue, ResourceProfile};
use aos_sandbox_model::{
    FeatureRef, Grant, GrantId, Operation, OperationSet, ResourceCeilings, ResourceDimension,
    ResourceId, ResourceKind, ResourceLimit, Selector,
};
use serde::Serialize;

use super::authority::AuthorityPlanV1;
use super::model::{
    ExplanationDecisionV1, ExplanationEntryV1, ExplanationReasonV1, ExplanationStageV1,
    HardResourcePlanCommitmentV1, InputSourceV1, PolicyCompilerInputV1, PolicyModelError,
    RedactedSubjectV1,
};
use aos_sandbox_protocol::policy_data::digest;

/// Portable dimensions in their exact core registry order.
pub const PORTABLE_LIMIT_DIMENSIONS: [LimitDimension; 16] = [
    LimitDimension::Bytes,
    LimitDimension::Inodes,
    LimitDimension::Processes,
    LimitDimension::Memory,
    LimitDimension::CpuWeight,
    LimitDimension::CpuQuota,
    LimitDimension::IoWeight,
    LimitDimension::IoBandwidth,
    LimitDimension::MountCount,
    LimitDimension::OpenFiles,
    LimitDimension::FuseRequests,
    LimitDimension::FuseMemory,
    LimitDimension::CacheBytes,
    LimitDimension::SnapshotCount,
    LimitDimension::ChildCount,
    LimitDimension::ExecutionCount,
];

/// Identifies one dimension without conflating portable and accounting registries.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum HardResourceKeyV1 {
    /// One portable core-policy limit.
    Portable(LimitDimension),
    /// One controller accounting limit.
    Accounting(ResourceDimension),
}
impl HardResourceKeyV1 {
    /// Returns the enforcement/accounting scope of the dimension.
    #[must_use]
    pub const fn scope(self) -> HardResourceScopeV1 {
        match self {
            Self::Portable(_) => HardResourceScopeV1::PortablePerSandbox,
            Self::Accounting(_) => HardResourceScopeV1::ControllerAccounting,
        }
    }
}

/// Separates payload-local enforcement from controller aggregate accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum HardResourceScopeV1 {
    /// Enforces one resolved portable policy limit for the sandbox.
    PortablePerSandbox,
    /// Accounts one aggregate controller reservation dimension.
    ControllerAccounting,
}

/// Stores explicit unresolved limit semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum HardLimitValueV1 {
    /// Defers to another layer.
    Inherit,
    /// Applies a finite inclusive bound.
    Bounded(u64),
    /// Requests unlimited use under an exact same-layer grant.
    Unlimited(GrantId),
}

/// Selects a registered hard enforcement implementation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum HardEnforcementV1 {
    /// Kernel cgroup-v2 enforcement.
    CgroupV2,
    /// Broker admission and durable ledger enforcement.
    BrokerLedger,
    /// Storage quota and reservation enforcement.
    ZfsQuota,
    /// Bounded shared node residency enforcement.
    NodeBoundedSharedResidency,
    /// Hard-isolated cache residency enforcement.
    HardIsolatedResidency,
    /// Combines payload file-descriptor enforcement with broker accounting.
    CombinedFileDescriptor,
    /// Combines payload memory enforcement with broker reservation accounting.
    CombinedMemoryAccounting,
}

impl HardEnforcementV1 {
    /// Returns the primary registered feature embedded in a core policy limit.
    ///
    /// # Errors
    ///
    /// Returns [`HardResourceModelError::RegisteredFeature`] only if a built-in
    /// feature spelling is rejected by the core feature parser.
    pub fn feature(self) -> Result<FeatureRef, HardResourceModelError> {
        let namespace = self.required_feature_names().first()
            .ok_or(HardResourceModelError::RegisteredFeature)?;
        FeatureRef::new(*namespace, 1, 0).map_err(|_| HardResourceModelError::RegisteredFeature)
    }

    /// Reports whether this exact mechanism implements the dimension in its scope.
    #[must_use]
    pub fn supports(self, key: HardResourceKeyV1) -> bool {
        match key {
            HardResourceKeyV1::Portable(dimension) => match dimension {
                LimitDimension::Bytes | LimitDimension::Inodes | LimitDimension::SnapshotCount => {
                    self == Self::ZfsQuota
                }
                LimitDimension::Processes
                | LimitDimension::Memory
                | LimitDimension::CpuWeight
                | LimitDimension::CpuQuota
                | LimitDimension::IoWeight
                | LimitDimension::IoBandwidth => self == Self::CgroupV2,
                LimitDimension::OpenFiles => self == Self::CombinedFileDescriptor,
                LimitDimension::FuseMemory => self == Self::CombinedMemoryAccounting,
                LimitDimension::CacheBytes => matches!(
                    self,
                    Self::NodeBoundedSharedResidency | Self::HardIsolatedResidency
                ),
                LimitDimension::MountCount
                | LimitDimension::FuseRequests
                | LimitDimension::ChildCount
                | LimitDimension::ExecutionCount => self == Self::BrokerLedger,
            },
            // Controller dimensions are reservation-ledger quantities. Their
            // payload-local mechanisms are represented only by the separate
            // portable dimension, never falsely by ZFS or cgroup here.
            HardResourceKeyV1::Accounting(_) => self == Self::BrokerLedger,
        }
    }

    fn required_feature_names(self) -> &'static [&'static str] {
        match self {
            Self::CgroupV2 => &["aos.sandbox.enforcement.cgroup-v2"],
            Self::BrokerLedger | Self::CombinedFileDescriptor =>
                &["aos.sandbox.enforcement.broker-ledger"],
            Self::ZfsQuota => &["aos.sandbox.enforcement.zfs-quota"],
            Self::NodeBoundedSharedResidency => &["aos.sandbox.residency.node-bounded-shared"],
            Self::HardIsolatedResidency => &["aos.sandbox.residency.hard-isolated"],
            Self::CombinedMemoryAccounting => &["aos.sandbox.enforcement.cgroup-v2",
                "aos.sandbox.enforcement.broker-ledger"],
        }
    }

    fn required_features(self) -> Result<Vec<FeatureRef>, HardResourceModelError> {
        self.required_feature_names().iter().map(|name| FeatureRef::new(*name, 1, 0)
            .map_err(|_| HardResourceModelError::RegisteredFeature)).collect()
    }
}

/// Stores one explicit limit and typed enforcement selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct HardLimitRequestV1 {
    key: HardResourceKeyV1,
    value: HardLimitValueV1,
    enforcement: Option<HardEnforcementV1>,
}

impl HardLimitRequestV1 {
    /// Constructs one limit entry.
    ///
    /// `Inherit` must omit enforcement. Explicit values must name a mechanism
    /// registered for the exact dimension.
    ///
    /// # Errors
    ///
    /// Returns [`HardResourceModelError`] for a value/enforcement mismatch.
    pub fn new(
        key: HardResourceKeyV1,
        value: HardLimitValueV1,
        enforcement: Option<HardEnforcementV1>,
    ) -> Result<Self, HardResourceModelError> {
        match (value, enforcement) {
            (HardLimitValueV1::Inherit, None) => {}
            (HardLimitValueV1::Inherit, Some(_)) | (_, None) => {
                return Err(HardResourceModelError::EnforcementShape);
            }
            (_, Some(mechanism)) if !mechanism.supports(key) => {
                return Err(HardResourceModelError::WrongEnforcement);
            }
            _ => {}
        }
        Ok(Self {
            key,
            value,
            enforcement,
        })
    }

    /// Returns the exact registry and dimension.
    #[must_use]
    pub const fn key(self) -> HardResourceKeyV1 {
        self.key
    }
    /// Returns unresolved value semantics.
    #[must_use]
    pub const fn value(self) -> HardLimitValueV1 {
        self.value
    }
    /// Returns typed enforcement, absent only for inheritance.
    #[must_use]
    pub const fn enforcement(self) -> Option<HardEnforcementV1> {
        self.enforcement
    }
}

/// Stores every portable and accounting dimension in registry order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HardResourceProfileV1 {
    portable: Vec<HardLimitRequestV1>,
    accounting: Vec<HardLimitRequestV1>,
}

impl HardResourceProfileV1 {
    /// Constructs a complete 16-plus-22 dimension input profile.
    ///
    /// # Errors
    ///
    /// Returns [`HardResourceModelError::IncompleteProfile`] unless both
    /// vectors exactly follow their complete registries.
    pub fn new(
        portable: Vec<HardLimitRequestV1>,
        accounting: Vec<HardLimitRequestV1>,
    ) -> Result<Self, HardResourceModelError> {
        let portable_ok = portable.len() == PORTABLE_LIMIT_DIMENSIONS.len()
            && portable
                .iter()
                .zip(PORTABLE_LIMIT_DIMENSIONS)
                .all(|(entry, dimension)| entry.key() == HardResourceKeyV1::Portable(dimension));
        let accounting_ok = accounting.len() == ResourceDimension::COUNT
            && accounting
                .iter()
                .zip(ResourceDimension::ALL)
                .all(|(entry, dimension)| entry.key() == HardResourceKeyV1::Accounting(dimension));
        if !portable_ok || !accounting_ok {
            return Err(HardResourceModelError::IncompleteProfile);
        }
        Ok(Self {
            portable,
            accounting,
        })
    }

    /// Returns all portable entries.
    #[must_use]
    pub fn portable(&self) -> &[HardLimitRequestV1] {
        &self.portable
    }
    /// Returns all twenty-two accounting entries.
    #[must_use]
    pub fn accounting(&self) -> &[HardLimitRequestV1] {
        &self.accounting
    }
    fn entry(&self, key: HardResourceKeyV1) -> Option<HardLimitRequestV1> {
        self.portable
            .iter()
            .chain(&self.accounting)
            .copied()
            .find(|entry| entry.key() == key)
    }
}

/// Bounds new named resource rows and feature/mechanism sets for an inherited request.
///
/// The three profiles are the already decoded node, site and project layers.
/// The selected parentless request inherits every dimension and has no grants,
/// namespace rules, advisory actions or ancestors. Callers must separately
/// establish that closed recipe; this supplier validates no policy authority.
///
/// Every explicit enforcement contributes at most one per-dimension mechanism
/// entry. The actual registered feature roster bounds each of the resource and
/// final compiler feature unions; the selected portable feature contributes at
/// most one per portable dimension to each union. The resolved portable and
/// accounting dimensions are actual semantic rows, not Rust control fields.
/// Overflow returns `None` before allocation.
#[must_use]
pub fn inherited_parentless_resource_namespace_entries_v1(
    profiles: [&HardResourceProfileV1; 3],
) -> Option<u64> {
    let mut mechanisms = 0_u64;
    let mut features = 0_u64;
    for profile in profiles {
        for entry in profile.portable().iter().chain(profile.accounting()) {
            if let Some(mechanism) = entry.enforcement() {
                mechanisms = mechanisms.checked_add(1)?;
                features = features.checked_add(u64::try_from(mechanism.required_feature_names().len()).ok()?)?;
            }
        }
    }
    let explicit = |key| profiles.iter().any(|profile| profile.entry(key)
        .is_some_and(|entry| entry.enforcement().is_some()));
    let portable = PORTABLE_LIMIT_DIMENSIONS.into_iter()
        .filter(|dimension| explicit(HardResourceKeyV1::Portable(*dimension))).count();
    let accounting = ResourceDimension::ALL.into_iter()
        .filter(|dimension| explicit(HardResourceKeyV1::Accounting(*dimension))).count();
    let rows = u64::try_from(portable.checked_add(accounting)?).ok()?;
    rows.checked_add(mechanisms)?.checked_add(features.checked_mul(2)?)?
        .checked_add(u64::try_from(portable).ok()?.checked_mul(2)?)
}

/// Stores a canonical typed backend enforcement set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BackendEnforcementSetV1(Vec<HardEnforcementV1>);
impl BackendEnforcementSetV1 {
    /// Constructs a strictly ordered unique enforcement set.
    ///
    /// # Errors
    ///
    /// Returns [`HardResourceModelError::EnforcementSetNotCanonical`] otherwise.
    pub fn new(values: Vec<HardEnforcementV1>) -> Result<Self, HardResourceModelError> {
        if !values.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(HardResourceModelError::EnforcementSetNotCanonical);
        }
        Ok(Self(values))
    }
    /// Reports whether an exact mechanism is available.
    #[must_use]
    pub fn contains(&self, value: HardEnforcementV1) -> bool {
        self.0.binary_search(&value).is_ok()
    }
}

/// Proves one unlimited assertion without cross-layer GrantId confusion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UnlimitedProvenanceV1 {
    source: InputSourceV1,
    source_commitment: aos_sandbox_model::ObjectDigest,
    key: HardResourceKeyV1,
    grant: GrantId,
    resource_kind: ResourceKind,
    operations: OperationSet,
    selector: Selector,
    grant_semantics: aos_sandbox_model::ObjectDigest,
    predecessor: Option<aos_sandbox_model::ObjectDigest>,
}

/// Records one explicit layer contribution to a resolved hard dimension.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct HardLimitProvenanceV1 {
    source: InputSourceV1,
    source_commitment: aos_sandbox_model::ObjectDigest,
    value: HardLimitValueV1,
    enforcement: HardEnforcementV1,
}
impl HardLimitProvenanceV1 {
    /// Returns the contributing layer.
    #[must_use]
    pub const fn source(self) -> InputSourceV1 {
        self.source
    }
    /// Returns its purpose-separated frozen commitment.
    #[must_use]
    pub const fn source_commitment(self) -> aos_sandbox_model::ObjectDigest {
        self.source_commitment
    }
    /// Returns the exact contributed value.
    #[must_use]
    pub const fn value(self) -> HardLimitValueV1 {
        self.value
    }
    /// Returns the exact contributed enforcement mechanism.
    #[must_use]
    pub const fn enforcement(self) -> HardEnforcementV1 {
        self.enforcement
    }
}

impl UnlimitedProvenanceV1 {
    /// Returns the defining source.
    #[must_use]
    pub const fn source(&self) -> InputSourceV1 {
        self.source
    }
    /// Returns the source commitment preventing cross-layer identity confusion.
    #[must_use]
    pub const fn source_commitment(&self) -> aos_sandbox_model::ObjectDigest {
        self.source_commitment
    }
    /// Returns the exact dimension.
    #[must_use]
    pub const fn key(&self) -> HardResourceKeyV1 {
        self.key
    }
    /// Returns the same-layer grant identity.
    #[must_use]
    pub const fn grant(&self) -> GrantId {
        self.grant
    }
    /// Returns the exact capability kind proved by this link.
    #[must_use]
    pub const fn resource_kind(&self) -> ResourceKind {
        self.resource_kind
    }
    /// Returns the complete required operation set proved by this link.
    #[must_use]
    pub const fn operations(&self) -> OperationSet {
        self.operations
    }
    /// Returns the effective target selector covered by this link.
    #[must_use]
    pub const fn selector(&self) -> &Selector {
        &self.selector
    }
    /// Returns the full semantic-grant digest.
    #[must_use]
    pub const fn grant_semantics(&self) -> aos_sandbox_model::ObjectDigest {
        self.grant_semantics
    }
    /// Returns the prior proof-link digest, if this is not the chain root.
    #[must_use]
    pub const fn predecessor(&self) -> Option<aos_sandbox_model::ObjectDigest> {
        self.predecessor
    }
}

/// Stores a resolved value and complete unlimited provenance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum ResolvedHardLimitValueV1 {
    /// A finite bound.
    Bounded(u64),
    /// Unlimited use with effective request grant and every layer proof.
    Unlimited {
        /// Exact effective request-grant identity.
        effective_grant: GrantId,
        /// Ordered cryptographic proof chain for all Unlimited assertions.
        provenance: Vec<UnlimitedProvenanceV1>,
    },
}

/// Stores one resolved dimension.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResolvedHardLimitV1 {
    key: HardResourceKeyV1,
    value: ResolvedHardLimitValueV1,
    selected_enforcement: HardEnforcementV1,
    required_enforcements: Vec<HardEnforcementV1>,
    decisive_source: InputSourceV1,
    provenance: Vec<HardLimitProvenanceV1>,
    unlimited_chain: Vec<UnlimitedProvenanceV1>,
}
impl ResolvedHardLimitV1 {
    /// Returns the dimension key.
    #[must_use]
    pub const fn key(&self) -> HardResourceKeyV1 {
        self.key
    }
    /// Returns the value and provenance.
    #[must_use]
    pub const fn value(&self) -> &ResolvedHardLimitValueV1 {
        &self.value
    }
    /// Returns the mechanism encoded into portable policy where applicable.
    #[must_use]
    pub const fn selected_enforcement(&self) -> HardEnforcementV1 {
        self.selected_enforcement
    }
    /// Returns every layer-required mechanism.
    #[must_use]
    pub fn required_enforcements(&self) -> &[HardEnforcementV1] {
        &self.required_enforcements
    }
    /// Returns the decisive ceiling source.
    #[must_use]
    pub const fn decisive_source(&self) -> InputSourceV1 {
        self.decisive_source
    }
    /// Returns every explicit layer contribution in semantic input order.
    #[must_use]
    pub fn provenance(&self) -> &[HardLimitProvenanceV1] {
        &self.provenance
    }
    /// Returns every fully verified Unlimited assertion in input order.
    #[must_use]
    pub fn unlimited_chain(&self) -> &[UnlimitedProvenanceV1] {
        &self.unlimited_chain
    }
}

/// Stores all resolved limits and the exact portable core profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HardResourcePlanV1 {
    commitment: HardResourcePlanCommitmentV1,
    portable: Vec<ResolvedHardLimitV1>,
    accounting: Vec<ResolvedHardLimitV1>,
    #[serde(skip)]
    core_profile: ResourceProfile,
    #[serde(skip)]
    accounting_ceilings: ResourceCeilings,
    required_features: Vec<FeatureRef>,
}
impl HardResourcePlanV1 {
    /// Returns the plan commitment.
    #[must_use]
    pub const fn commitment(&self) -> HardResourcePlanCommitmentV1 {
        self.commitment
    }
    /// Returns all sixteen portable limits.
    #[must_use]
    pub fn portable(&self) -> &[ResolvedHardLimitV1] {
        &self.portable
    }
    /// Returns all twenty-two accounting limits.
    #[must_use]
    pub fn accounting(&self) -> &[ResolvedHardLimitV1] {
        &self.accounting
    }
    /// Returns the total-lowered core resource profile.
    #[must_use]
    pub const fn core_profile(&self) -> &ResourceProfile {
        &self.core_profile
    }
    /// Returns the exact twenty-two-dimension accounting ceiling mapping.
    #[must_use]
    pub const fn accounting_ceilings(&self) -> ResourceCeilings {
        self.accounting_ceilings
    }
    /// Returns exact required enforcement features.
    #[must_use]
    pub fn required_features(&self) -> &[FeatureRef] {
        &self.required_features
    }
}

pub(crate) fn compile_resources(
    input: &PolicyCompilerInputV1,
    authority: &AuthorityPlanV1,
) -> Result<
    (
        HardResourcePlanV1,
        Vec<ExplanationEntryV1>,
        Vec<ExplanationEntryV1>,
    ),
    HardResourceCompilationError,
> {
    let portable_keys = PORTABLE_LIMIT_DIMENSIONS.map(HardResourceKeyV1::Portable);
    let accounting_keys = ResourceDimension::ALL.map(HardResourceKeyV1::Accounting);
    let mut resolved = Vec::with_capacity(38);
    let mut provenance_explanation = Vec::with_capacity(38);
    let mut backend_explanation = Vec::new();

    for key in portable_keys.into_iter().chain(accounting_keys) {
        let value = resolve_key(input, authority, key)?;
        provenance_explanation.push(ExplanationEntryV1::new(
            ExplanationStageV1::HardResources,
            ExplanationDecisionV1::Required,
            ExplanationReasonV1::ResourceProvenance,
            value.decisive_source(),
            RedactedSubjectV1::for_value(&value)?,
            value
                .provenance()
                .iter()
                .map(|item| item.source())
                .collect(),
        ));
        for mechanism in value.required_enforcements() {
            if !input.backend().enforcement().contains(*mechanism) {
                return Err(HardResourceCompilationError::EnforcementUnavailable);
            }
            backend_explanation.push(ExplanationEntryV1::new(
                ExplanationStageV1::BackendAdmission,
                ExplanationDecisionV1::Required,
                ExplanationReasonV1::BackendEnforcement,
                InputSourceV1::Backend,
                RedactedSubjectV1::for_value(&(key, mechanism))?,
                Vec::new(),
            ));
        }
        resolved.push(value);
    }

    let portable = resolved[..PORTABLE_LIMIT_DIMENSIONS.len()].to_vec();
    let accounting = resolved[PORTABLE_LIMIT_DIMENSIONS.len()..].to_vec();
    let mut core_limits = Vec::with_capacity(portable.len());
    let mut features = BTreeSet::new();
    for limit in &portable {
        let HardResourceKeyV1::Portable(dimension) = limit.key() else {
            return Err(HardResourceCompilationError::InternalMapping);
        };
        let value = match limit.value() {
            ResolvedHardLimitValueV1::Bounded(value) => LimitValue::Bounded(*value),
            ResolvedHardLimitValueV1::Unlimited {
                effective_grant, ..
            } => LimitValue::Unlimited(*effective_grant),
        };
        let feature = limit.selected_enforcement().feature()?;
        features.insert(feature.clone());
        for mechanism in limit.required_enforcements() {
            features.extend(mechanism.required_features()?);
        }
        core_limits.push(Limit::new(dimension, value, feature));
    }
    for limit in &accounting {
        for mechanism in limit.required_enforcements() {
            features.extend(mechanism.required_features()?);
        }
    }
    let core_profile = ResourceProfile::new(core_limits)
        .map_err(|_| HardResourceCompilationError::InternalMapping)?;
    let accounting_values = accounting
        .iter()
        .map(|limit| match limit.value() {
            ResolvedHardLimitValueV1::Bounded(value) => ResourceLimit::Bounded(*value),
            ResolvedHardLimitValueV1::Unlimited { .. } => ResourceLimit::Unlimited,
        })
        .collect::<Vec<_>>();
    let accounting_array: [ResourceLimit; ResourceDimension::COUNT] = accounting_values
        .try_into()
        .map_err(|_| HardResourceCompilationError::InternalMapping)?;
    let accounting_ceilings = ResourceCeilings::new(accounting_array);
    let required_features = features.into_iter().collect::<Vec<_>>();
    let commitment = HardResourcePlanCommitmentV1::new(
        digest(
            b"aos.sandbox.hard-resource-plan.v2",
            &(&portable, &accounting, &required_features),
        )
        .map_err(crate::PolicyModelError::from)?,
    );
    Ok((
        HardResourcePlanV1 {
            commitment,
            portable,
            accounting,
            core_profile,
            accounting_ceilings,
            required_features,
        },
        provenance_explanation,
        backend_explanation,
    ))
}

fn resolve_key(
    input: &PolicyCompilerInputV1,
    authority: &AuthorityPlanV1,
    key: HardResourceKeyV1,
) -> Result<ResolvedHardLimitV1, HardResourceCompilationError> {
    let mut finite: Option<(u64, InputSourceV1, HardEnforcementV1)> = None;
    let mut proofs: Vec<UnlimitedProvenanceV1> = Vec::new();
    let mut provenance = Vec::new();
    let mut mechanisms = BTreeSet::new();
    let mut request_unlimited = None;
    let effective_selector = Selector::Resource {
        resource: ResourceId::from_bytes(input.sandbox().into_bytes()),
    };
    let unlimited_operations = OperationSet::one(Operation::LifecycleControl);
    for (source, layer, source_commitment) in input.all_layers() {
        let entry = layer
            .resources()
            .entry(key)
            .ok_or(HardResourceCompilationError::InternalMapping)?;
        match (entry.value(), entry.enforcement()) {
            (HardLimitValueV1::Inherit, None) => {}
            (HardLimitValueV1::Bounded(value), Some(mechanism)) => {
                provenance.push(HardLimitProvenanceV1 {
                    source,
                    source_commitment,
                    value: entry.value(),
                    enforcement: mechanism,
                });
                mechanisms.insert(mechanism);
                if finite
                    .as_ref()
                    .is_none_or(|(current, _, _)| value < *current)
                {
                    finite = Some((value, source, mechanism));
                }
            }
            (HardLimitValueV1::Unlimited(grant_id), Some(mechanism)) => {
                provenance.push(HardLimitProvenanceV1 {
                    source,
                    source_commitment,
                    value: entry.value(),
                    enforcement: mechanism,
                });
                mechanisms.insert(mechanism);
                let grant = same_layer_unlimited_grant(
                    layer.grants(),
                    grant_id,
                    &effective_selector,
                    unlimited_operations,
                )
                .ok_or(HardResourceCompilationError::UnlimitedNotAuthorized)?;
                let predecessor = match proofs.last() {
                    Some(prior) => Some(
                        digest(b"aos.sandbox.unlimited-proof-link.v2", prior)
                            .map_err(crate::PolicyModelError::from)?,
                    ),
                    None => None,
                };
                proofs.push(UnlimitedProvenanceV1 {
                    source,
                    source_commitment,
                    key,
                    grant: grant_id,
                    resource_kind: ResourceKind::Sandbox,
                    operations: unlimited_operations,
                    selector: effective_selector.clone(),
                    grant_semantics: digest(b"aos.sandbox.unlimited-grant.v2", grant)
                        .map_err(crate::PolicyModelError::from)?,
                    predecessor,
                });
                if source == InputSourceV1::Request {
                    request_unlimited = Some((grant_id, mechanism));
                }
            }
            _ => return Err(HardResourceCompilationError::InternalMapping),
        }
    }
    if mechanisms.is_empty() {
        return Err(HardResourceCompilationError::UnresolvedLimit);
    }
    let required_enforcements = mechanisms.into_iter().collect::<Vec<_>>();
    if let Some((value, source, mechanism)) = finite {
        return Ok(ResolvedHardLimitV1 {
            key,
            value: ResolvedHardLimitValueV1::Bounded(value),
            selected_enforcement: mechanism,
            required_enforcements,
            decisive_source: source,
            provenance,
            unlimited_chain: proofs,
        });
    }
    let (effective_grant, mechanism) =
        request_unlimited.ok_or(HardResourceCompilationError::UnresolvedLimit)?;
    if !authority.admits_effective_grant(
        effective_grant,
        aos_sandbox_model::ResourceKind::Sandbox,
        unlimited_operations,
        &effective_selector,
    ) {
        return Err(HardResourceCompilationError::UnlimitedNotEffective);
    }
    Ok(ResolvedHardLimitV1 {
        key,
        value: ResolvedHardLimitValueV1::Unlimited {
            effective_grant,
            provenance: proofs.clone(),
        },
        selected_enforcement: mechanism,
        required_enforcements,
        decisive_source: InputSourceV1::Request,
        provenance,
        unlimited_chain: proofs,
    })
}

fn same_layer_unlimited_grant<'a>(
    grants: &'a [Grant],
    identity: GrantId,
    selector: &Selector,
    operations: OperationSet,
) -> Option<&'a Grant> {
    grants.iter().find(|grant| {
        grant.id() == identity
            && grant.resource_kind() == ResourceKind::Sandbox
            && operations.is_subset_of(grant.operations())
            && grant.selector().contains(selector)
    })
}

/// Reports malformed typed resource input.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HardResourceModelError {
    /// Inheritance or explicit enforcement shape is invalid.
    #[error("inherit must omit enforcement and explicit values must name it")]
    EnforcementShape,
    /// A mechanism is not registered for the dimension.
    #[error("hard enforcement mechanism cannot enforce this dimension")]
    WrongEnforcement,
    /// The profile is not the complete 16-plus-22 registry.
    #[error("hard resource profile must contain all 16 portable and 22 accounting dimensions")]
    IncompleteProfile,
    /// Backend mechanisms are not strictly ordered and unique.
    #[error("backend enforcement set is not canonical")]
    EnforcementSetNotCanonical,
    /// A built-in feature spelling was rejected.
    #[error("built-in enforcement feature was rejected")]
    RegisteredFeature,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HardResourceCompilationError {
    UnlimitedNotAuthorized,
    UnlimitedNotEffective,
    UnresolvedLimit,
    EnforcementUnavailable,
    InternalMapping,
    Model(PolicyModelError),
    Resource(HardResourceModelError),
}
impl From<PolicyModelError> for HardResourceCompilationError {
    fn from(value: PolicyModelError) -> Self {
        Self::Model(value)
    }
}
impl From<HardResourceModelError> for HardResourceCompilationError {
    fn from(value: HardResourceModelError) -> Self {
        Self::Resource(value)
    }
}

/// Reports incompatible immutable Spec and resolved portable resource limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("the resolved resource profile is incompatible with the immutable specification")]
pub struct SpecResourceCompatibilityErrorV1;

/// Checks the existing exact sixteen-dimension Spec-to-resolved relation.
///
/// Both profiles must contain all dimensions in registry order and identical
/// enforcement mechanisms. Resolved values must be bounded; requested inherited
/// limits allow that bound, finite requests cap it, and unlimited requests fail.
/// This compares semantic DATA and supplies no resource or compiler authority.
///
/// # Errors
/// Returns [`SpecResourceCompatibilityErrorV1`] on any missing or reordered
/// dimension, enforcement mismatch, unbounded result, unlimited request or
/// resolved value exceeding its finite requested bound.
pub fn require_specification_resource_profile_v1(
    requested: &ResourceProfile, resolved: &ResourceProfile,
) -> Result<(), SpecResourceCompatibilityErrorV1> {
    let requested = requested.limits();
    let resolved = resolved.limits();
    if requested.len() != 16 || resolved.len() != 16 {
        return Err(SpecResourceCompatibilityErrorV1);
    }
    for (index, (requested, resolved)) in requested.iter().zip(resolved).enumerate() {
        let LimitValue::Bounded(actual) = resolved.value() else {
            return Err(SpecResourceCompatibilityErrorV1);
        };
        if requested.dimension() as usize != index
            || requested.dimension() != resolved.dimension()
            || requested.enforcement() != resolved.enforcement()
            || match requested.value() {
                LimitValue::Inherited => false,
                LimitValue::Bounded(limit) => actual > limit,
                LimitValue::Unlimited(_) => true,
            }
        {
            return Err(SpecResourceCompatibilityErrorV1);
        }
    }
    Ok(())
}

#[cfg(test)]
mod specification_resource_compatibility_tests {
    use super::*;
    use std::num::NonZeroU32;
    use aos_sandbox_model::{DecodeLimits, MediaType, ObjectDescriptor, ObjectDigest};
    use aos_sandbox_model::model::{
        IdentityProfile, NetworkKind, NetworkProfile, SandboxSpec, UnmappableIdentityPolicy,
    };

    fn canonical_spec(value: LimitValue, changed: Option<(LimitDimension, LimitValue, HardEnforcementV1)>)
        -> SandboxSpec
    {
        let limits = PORTABLE_LIMIT_DIMENSIONS.into_iter().map(|dimension| {
            let (value, mechanism) = match changed {
                Some((target, value, mechanism)) if target == dimension => (value, mechanism),
                _ => (value, HardEnforcementV1::CgroupV2),
            };
            Limit::new(dimension, value, mechanism.feature().unwrap())
        }).collect();
        let descriptor = |kind| ObjectDescriptor::new(
            MediaType::new(format!("application/vnd.aos.sandbox.{kind}.v1+cbor")).unwrap(),
            ObjectDigest::from_bytes([1; 32]), 1,
        );
        let specification = SandboxSpec::new(
            FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0).unwrap(),
            IdentityProfile::PrivateUserns {
                id_range_size: NonZeroU32::new(65_536).unwrap(),
                unmappable_policy: UnmappableIdentityPolicy::Reject, required_features: Vec::new(),
            },
            ResourceProfile::new(limits).unwrap(), descriptor("environment"), descriptor("view"),
            Vec::new(), NetworkProfile::new(NetworkKind::Isolated, Vec::new(), Vec::new()).unwrap(), Vec::new(),
        ).unwrap();
        let bytes = aos_sandbox_model::format::encode_sandbox_spec(&specification);
        aos_sandbox_model::format::decode_sandbox_spec(&bytes, DecodeLimits::default()).unwrap()
    }

    #[test]
    fn canonical_spec_allows_inherited_or_sufficient_bounded_resolved_limits() {
        let bounded = canonical_spec(LimitValue::Bounded(100), None);
        let inherited = canonical_spec(LimitValue::Inherited, None);
        let actual = canonical_spec(LimitValue::Bounded(90), None);

        assert!(require_specification_resource_profile_v1(bounded.resource_profile(), actual.resource_profile()).is_ok());
        assert!(require_specification_resource_profile_v1(inherited.resource_profile(), actual.resource_profile()).is_ok());
    }

    #[test]
    fn canonical_spec_rejects_underbound_enforcement_mismatch_and_unresolved_result() {
        let requested = canonical_spec(LimitValue::Bounded(100), None);
        let underbound = canonical_spec(LimitValue::Bounded(100), Some((
            LimitDimension::Memory, LimitValue::Bounded(99), HardEnforcementV1::CgroupV2,
        )));
        let mismatch = canonical_spec(LimitValue::Bounded(90), Some((
            LimitDimension::OpenFiles, LimitValue::Bounded(90), HardEnforcementV1::BrokerLedger,
        )));
        let inherited = canonical_spec(LimitValue::Inherited, None);
        let unlimited = canonical_spec(LimitValue::Unlimited(GrantId::from_bytes([4; 16])), None);

        assert!(require_specification_resource_profile_v1(unlimited.resource_profile(), requested.resource_profile()).is_err());
        assert!(require_specification_resource_profile_v1(underbound.resource_profile(), requested.resource_profile()).is_err());
        assert!(require_specification_resource_profile_v1(requested.resource_profile(), mismatch.resource_profile()).is_err());
        assert!(require_specification_resource_profile_v1(requested.resource_profile(), inherited.resource_profile()).is_err());
    }
}


#[cfg(test)]
mod receiving_namespace_tests {
    use super::*;

    fn profile(mechanism: bool) -> HardResourceProfileV1 {
        let portable = PORTABLE_LIMIT_DIMENSIONS.into_iter().map(|dimension| {
            let selected = mechanism && dimension == LimitDimension::FuseMemory;
            HardLimitRequestV1::new(HardResourceKeyV1::Portable(dimension),
                if selected { HardLimitValueV1::Bounded(1024) } else { HardLimitValueV1::Inherit },
                selected.then_some(HardEnforcementV1::CombinedMemoryAccounting)).unwrap()
        }).collect();
        let accounting = ResourceDimension::ALL.into_iter().map(|dimension|
            HardLimitRequestV1::new(HardResourceKeyV1::Accounting(dimension),
                HardLimitValueV1::Inherit, None).unwrap()).collect();
        HardResourceProfileV1::new(portable, accounting).unwrap()
    }

    #[test]
    fn namespace_forecast_counts_actual_semantic_rows_and_registered_feature_roster() {
        let empty = profile(false);
        let memory = profile(true);
        assert_eq!(inherited_parentless_resource_namespace_entries_v1([&empty, &empty, &empty]), Some(0));
        // One real dimension row, one mechanism, two features in each of two
        // compiler unions, and one selected feature in each union.
        assert_eq!(inherited_parentless_resource_namespace_entries_v1([&empty, &memory, &empty]), Some(8));
        // The repeated layer does not invent another semantic dimension row.
        assert_eq!(inherited_parentless_resource_namespace_entries_v1([&memory, &memory, &empty]), Some(13));
    }
}
