//! Fixed-order compilation and total lowering to portable core models.

use std::collections::BTreeSet;

use aos_sandbox_core::format::{descriptor_for_bytes, encode_optimization};
use aos_sandbox_core::model::{
    CacheDomain, CacheDomainKind, ExplanationReason, ExplanationReasonCode, Policy, RevocationMode,
    RevocationPolicy,
};
use aos_sandbox_core::{MediaType, PortableMediaType, validate_required_features};

use super::advisory::{AdvisoryCompilationError, compile_advisory};
use super::authority::{AuthorityCompilationError, compile_authority};
use super::model::{
    CacheDomainInputV1, CompiledPolicyCandidateV1, ExplanationDecisionV1, ExplanationEntryV1,
    ExplanationReasonV1, ExplanationStageV1, InputSourceV1, MAXIMUM_CANONICAL_OBJECT_BYTES,
    PlanExplanationV1, PolicyCompilerInputV1, PolicyModelError, PortablePolicyOutputV1,
    RedactedSubjectV1, RevocationInputV1, StageExplanationV1,
};
use super::namespace::{NamespaceCompilationError, NamespaceRuleV1, compile_namespace};
use super::resources::{HardResourceCompilationError, compile_resources};

/// Pure compiler producing an explicitly nonauthoritative candidate.
#[derive(Clone, Copy, Debug, Default)]
pub struct PolicyCompilerV1;

impl PolicyCompilerV1 {
    /// Runs normalization, authority, namespace, resources, backend admission,
    /// advisory selection, explanation, and canonical lowering in fixed order.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilationError`] for any ambiguity, missing authority,
    /// unresolved value, unavailable hard mechanism, work-cap violation, or
    /// lossy core-model conversion.
    pub fn compile(
        input: PolicyCompilerInputV1,
    ) -> Result<CompiledPolicyCandidateV1, PolicyCompilationError> {
        enforce_work_cap(&input)?;
        let normalize = normalization_explanation(&input)?;

        let (authority, authority_entries) = compile_authority(&input)?;
        let (namespace, namespace_entries) = compile_namespace(&input, &authority)?;
        let (hard, mut resource_entries, mut backend_entries) =
            compile_resources(&input, &authority)?;
        let (advisory, advisory_entries) = compile_advisory(&input, &authority, &namespace)?;

        let mut authority_stage = Vec::new();
        for entry in authority_entries {
            if entry.stage() == ExplanationStageV1::BackendAdmission {
                backend_entries.push(entry);
            } else {
                authority_stage.push(entry);
            }
        }

        let cross_cutting = resolve_cross_cutting(&input)?;
        resource_entries.push(ExplanationEntryV1::new(
            ExplanationStageV1::HardResources,
            if cross_cutting.cache_narrowed {
                ExplanationDecisionV1::Narrowed
            } else {
                ExplanationDecisionV1::Admitted
            },
            ExplanationReasonV1::CacheDomainCeiling,
            InputSourceV1::Compiler,
            RedactedSubjectV1::for_value(&cross_cutting.cache_domain)?,
            cross_cutting.cache_causes.clone(),
        ));
        resource_entries.push(ExplanationEntryV1::new(
            ExplanationStageV1::HardResources,
            if cross_cutting.revocation_narrowed {
                ExplanationDecisionV1::Narrowed
            } else {
                ExplanationDecisionV1::Admitted
            },
            ExplanationReasonV1::RevocationCeiling,
            InputSourceV1::Compiler,
            RedactedSubjectV1::for_value(&cross_cutting.revocation)?,
            cross_cutting.revocation_causes.clone(),
        ));
        let mut required_features = namespace
            .required_features()
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        required_features.extend(hard.required_features().iter().cloned());
        let required_features = required_features.into_iter().collect::<Vec<_>>();
        validate_required_features(&required_features)
            .map_err(|_| PolicyCompilationError::UnknownRequiredFeature)?;
        for feature in &required_features {
            backend_entries.push(ExplanationEntryV1::new(
                ExplanationStageV1::BackendAdmission,
                ExplanationDecisionV1::Required,
                ExplanationReasonV1::BackendFeature,
                InputSourceV1::Backend,
                RedactedSubjectV1::for_value(feature)?,
                Vec::new(),
            ));
        }

        let optimization_bytes = encode_optimization(advisory.core_profile());
        if optimization_bytes.len() > MAXIMUM_CANONICAL_OBJECT_BYTES {
            return Err(PolicyCompilationError::Model(
                PolicyModelError::CanonicalObjectTooLarge,
            ));
        }
        let optimization_media = MediaType::new(PortableMediaType::Optimization.as_str())
            .map_err(|_| PolicyCompilationError::CoreLowering)?;
        let optimization_descriptor = descriptor_for_bytes(optimization_media, &optimization_bytes);
        let effective_grants = authority
            .grants()
            .iter()
            .map(|item| item.grant().clone())
            .collect::<Vec<_>>();
        let delegable_grants = authority.delegable_grants();
        let layer_descriptor_count = input.descriptors().len();
        let mut input_descriptors = input.descriptors();
        input_descriptors.push(input.relation().descriptor().clone());
        input_descriptors.push(input.endpoints().descriptor().clone());
        input_descriptors.push(input.destinations().descriptor().clone());
        input_descriptors.push(input.backend().descriptor().clone());
        // These two derived objects are mandatory policy-construction inputs:
        // the core action list must never detach opaque handles or discard
        // advisory specificity/priority semantics.
        input_descriptors.push(namespace.graph().descriptor().clone());
        input_descriptors.push(advisory.program().descriptor().clone());
        let core_reasons = core_explanation(&input_descriptors, layer_descriptor_count);
        let policy = Policy::new(
            required_features,
            input_descriptors,
            effective_grants,
            delegable_grants,
            hard.core_profile().clone(),
            namespace.core_actions().to_vec(),
            cross_cutting.cache_domain,
            cross_cutting.revocation,
            Some(optimization_descriptor),
            core_reasons,
        )
        .map_err(|_| PolicyCompilationError::CoreLowering)?;
        let portable = PortablePolicyOutputV1::new(
            policy,
            advisory.core_profile().clone(),
            namespace.graph(),
            advisory.program(),
        )?;
        let lowering_entry = ExplanationEntryV1::new(
            ExplanationStageV1::Lowering,
            ExplanationDecisionV1::Frozen,
            ExplanationReasonV1::PortableLowering,
            InputSourceV1::Compiler,
            RedactedSubjectV1::for_value(&(
                portable.policy_descriptor(),
                portable.optimization_descriptor(),
                portable.namespace_graph_descriptor(),
                portable.advisory_program_descriptor(),
            ))?,
            Vec::new(),
        );

        let explanation = PlanExplanationV1::new(vec![
            StageExplanationV1::new(ExplanationStageV1::Normalize, normalize)?,
            StageExplanationV1::new(ExplanationStageV1::Authority, authority_stage)?,
            StageExplanationV1::new(ExplanationStageV1::Namespace, namespace_entries)?,
            StageExplanationV1::new(ExplanationStageV1::HardResources, resource_entries)?,
            StageExplanationV1::new(ExplanationStageV1::BackendAdmission, backend_entries)?,
            StageExplanationV1::new(ExplanationStageV1::Advisory, advisory_entries)?,
            StageExplanationV1::new(ExplanationStageV1::Lowering, vec![lowering_entry])?,
        ])?;
        CompiledPolicyCandidateV1::new(authority, namespace, hard, advisory, portable, explanation)
            .map_err(PolicyCompilationError::Model)
    }
}

fn enforce_work_cap(input: &PolicyCompilerInputV1) -> Result<(), PolicyCompilationError> {
    let request = input.request().layer();
    let (mut ceiling_grants, mut ceiling_namespace, mut ceiling_advisory) = (0_u64, 0_u64, 0_u64);
    for (_, layer, _) in input.ceiling_layers() {
        ceiling_grants = ceiling_grants
            .checked_add(to_work_units(layer.grants().len())?)
            .ok_or(PolicyCompilationError::WorkLimitExceeded)?;
        ceiling_namespace = ceiling_namespace
            .checked_add(to_work_units(layer.namespace_rules().len())?)
            .ok_or(PolicyCompilationError::WorkLimitExceeded)?;
        ceiling_advisory = ceiling_advisory
            .checked_add(to_work_units(layer.advisory_actions().len())?)
            .ok_or(PolicyCompilationError::WorkLimitExceeded)?;
    }
    let namespace_rules = to_work_units(request.namespace_rules().len())?;
    let namespace_edges = request
        .namespace_rules()
        .iter()
        .filter_map(|rule| match rule {
            NamespaceRuleV1::Compose(node) => Some(node.inputs().len()),
            _ => None,
        })
        .try_fold(0_u64, |total, edges| {
            total
                .checked_add(to_work_units(edges)?)
                .ok_or(PolicyCompilationError::WorkLimitExceeded)
        })?;
    let request_grants = to_work_units(request.grants().len())?;
    let request_advisory = to_work_units(request.advisory_actions().len())?;
    let ancestry_layers = to_work_units(input.ancestors().len())?
        .checked_add(4)
        .ok_or(PolicyCompilationError::WorkLimitExceeded)?;
    let layer_bytes = [
        input.node().canonical_bytes().len(),
        input.site().canonical_bytes().len(),
        input.project().canonical_bytes().len(),
        input.request().canonical_bytes().len(),
    ]
    .into_iter()
    .chain(
        input
            .ancestors()
            .iter()
            .map(|ancestor| ancestor.canonical_bytes().len()),
    )
    .try_fold(0_u64, |total, bytes| {
        total
            .checked_add(to_work_units(bytes)?)
            .ok_or(PolicyCompilationError::WorkLimitExceeded)
    })?;
    let endpoints = to_work_units(input.endpoints().entries().len())?;
    let estimated = request_grants
        .checked_mul(ceiling_grants)
        .and_then(|value| value.checked_mul(2))
        .and_then(|value| {
            value.checked_add(request_grants.checked_mul(request_grants)?.checked_mul(3)?)
        })
        .and_then(|value| value.checked_add(namespace_rules.checked_mul(ceiling_namespace)?))
        .and_then(|value| value.checked_add(request_advisory.checked_mul(ceiling_advisory)?))
        .and_then(|value| {
            value.checked_add(
                request_advisory
                    .checked_mul(request_advisory)?
                    .checked_mul(2)?,
            )
        })
        .and_then(|value| {
            value.checked_add(
                namespace_rules
                    .checked_mul(namespace_rules)?
                    .checked_mul(3)?,
            )
        })
        .and_then(|value| value.checked_add(namespace_edges.checked_mul(4)?))
        // Selector/path comparisons can revisit layer bytes once per layer.
        .and_then(|value| value.checked_add(layer_bytes.checked_mul(ancestry_layers)?))
        .and_then(|value| value.checked_add(38_u64.checked_mul(ancestry_layers)?))
        .and_then(|value| value.checked_add(endpoints.checked_mul(request_grants)?))
        .ok_or(PolicyCompilationError::WorkLimitExceeded)?;
    if estimated > input.limits().work() {
        Err(PolicyCompilationError::WorkLimitExceeded)
    } else {
        Ok(())
    }
}

fn to_work_units(value: usize) -> Result<u64, PolicyCompilationError> {
    u64::try_from(value).map_err(|_| PolicyCompilationError::WorkLimitExceeded)
}

fn normalization_explanation(
    input: &PolicyCompilerInputV1,
) -> Result<Vec<ExplanationEntryV1>, PolicyModelError> {
    let descriptors = input.descriptors();
    let descriptor_count = descriptors.len();
    let mut entries = descriptors
        .iter()
        .enumerate()
        .map(|(index, descriptor)| {
            let source = match index {
                0 => InputSourceV1::Node,
                1 => InputSourceV1::Site,
                2 => InputSourceV1::Project,
                value if value + 1 == descriptor_count => InputSourceV1::Request,
                value => InputSourceV1::Ancestor {
                    ordinal: u16::try_from(value - 3)
                        .map_err(|_| PolicyModelError::TooManyAncestors)?,
                },
            };
            Ok(ExplanationEntryV1::new(
                ExplanationStageV1::Normalize,
                ExplanationDecisionV1::Frozen,
                ExplanationReasonV1::InputFrozen,
                source,
                RedactedSubjectV1::for_value(descriptor)?,
                Vec::new(),
            ))
        })
        .collect::<Result<Vec<_>, PolicyModelError>>()?;
    for (source, descriptor) in [
        (InputSourceV1::Catalog, input.relation().descriptor()),
        (InputSourceV1::Catalog, input.endpoints().descriptor()),
        (InputSourceV1::Catalog, input.destinations().descriptor()),
        (InputSourceV1::Backend, input.backend().descriptor()),
    ] {
        entries.push(ExplanationEntryV1::new(
            ExplanationStageV1::Normalize,
            ExplanationDecisionV1::Frozen,
            ExplanationReasonV1::InputFrozen,
            source,
            RedactedSubjectV1::for_value(descriptor)?,
            Vec::new(),
        ));
    }
    Ok(entries)
}

struct CrossCuttingResolutionV1 {
    cache_domain: CacheDomain,
    revocation: RevocationPolicy,
    cache_causes: Vec<InputSourceV1>,
    revocation_causes: Vec<InputSourceV1>,
    cache_narrowed: bool,
    revocation_narrowed: bool,
}
fn resolve_cross_cutting(
    input: &PolicyCompilerInputV1,
) -> Result<CrossCuttingResolutionV1, PolicyCompilationError> {
    let mut cache: Option<CacheDomain> = None;
    let mut revocation: Option<RevocationPolicy> = None;
    let mut cache_inputs = Vec::new();
    let mut revocation_inputs = Vec::new();
    for (source, layer, _) in input.all_layers() {
        if let CacheDomainInputV1::Exact(candidate) = layer.cache_domain() {
            let candidate = candidate.domain();
            cache_inputs.push((source, candidate));
            cache = Some(match cache {
                None => candidate,
                Some(current) => intersect_cache(current, candidate)?,
            });
        }
        if let RevocationInputV1::Exact(candidate) = layer.revocation() {
            revocation_inputs.push((source, candidate));
            revocation = Some(match revocation {
                None => candidate,
                Some(current) => intersect_revocation(current, candidate),
            });
        }
    }
    let cache_domain = cache.ok_or(PolicyCompilationError::UnresolvedCacheDomain)?;
    let revocation = revocation.ok_or(PolicyCompilationError::UnresolvedRevocation)?;
    let cache_causes = cache_inputs
        .iter()
        .filter_map(|(source, candidate)| (*candidate == cache_domain).then_some(*source))
        .collect();
    let revocation_causes = revocation_inputs
        .iter()
        .filter_map(|(source, candidate)| {
            (candidate.mode() == revocation.mode()
                || candidate.grace_nanos() == revocation.grace_nanos())
            .then_some(*source)
        })
        .collect();
    let cache_narrowed = cache_inputs
        .iter()
        .any(|(_, candidate)| *candidate != cache_domain);
    let revocation_narrowed = revocation_inputs
        .iter()
        .any(|(_, candidate)| *candidate != revocation);
    Ok(CrossCuttingResolutionV1 {
        cache_domain,
        revocation,
        cache_causes,
        revocation_causes,
        cache_narrowed,
        revocation_narrowed,
    })
}
fn intersect_cache(
    left: CacheDomain,
    right: CacheDomain,
) -> Result<CacheDomain, PolicyCompilationError> {
    if left.kind() == right.kind() && left.domain_id() != right.domain_id() {
        return Err(PolicyCompilationError::ConflictingCacheDomain);
    }
    let rank = |kind| match kind {
        CacheDomainKind::Private => 0,
        CacheDomainKind::Project => 1,
        CacheDomainKind::TrustDomain => 2,
        CacheDomainKind::Public => 3,
    };
    Ok(if rank(left.kind()) <= rank(right.kind()) {
        left
    } else {
        right
    })
}
fn intersect_revocation(left: RevocationPolicy, right: RevocationPolicy) -> RevocationPolicy {
    let rank = |mode| match mode {
        RevocationMode::DenyNew => 0,
        RevocationMode::Freeze => 1,
        RevocationMode::Stop => 2,
    };
    let mode = if rank(left.mode()) >= rank(right.mode()) {
        left.mode()
    } else {
        right.mode()
    };
    RevocationPolicy::new(mode, left.grace_nanos().min(right.grace_nanos()))
}
fn core_explanation(
    descriptors: &[aos_sandbox_core::ObjectDescriptor],
    layer_descriptor_count: usize,
) -> Vec<ExplanationReason> {
    let mut reasons = descriptors
        .iter()
        .enumerate()
        .map(|(index, descriptor)| {
            let code = match index {
                0 | 1 => ExplanationReasonCode::SiteCeiling,
                2 => ExplanationReasonCode::ProjectCeiling,
                value if value + 1 == layer_descriptor_count => ExplanationReasonCode::CallerGrant,
                value if value < layer_descriptor_count => ExplanationReasonCode::AncestorCeiling,
                value if value == layer_descriptor_count + 2 => {
                    ExplanationReasonCode::AttachmentConflict
                }
                value if value == layer_descriptor_count + 3 => {
                    ExplanationReasonCode::BackendRequirement
                }
                _ => ExplanationReasonCode::EnvironmentPolicy,
            };
            ExplanationReason::new(code, Some(descriptor.clone()))
        })
        .collect::<Vec<_>>();
    reasons.extend([
        ExplanationReason::new(ExplanationReasonCode::ResourceLimit, None),
        ExplanationReason::new(ExplanationReasonCode::DisclosureDomain, None),
        ExplanationReason::new(ExplanationReasonCode::Revocation, None),
        ExplanationReason::new(ExplanationReasonCode::BackendRequirement, None),
    ]);
    reasons
}

/// Reports fail-closed compilation errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PolicyCompilationError {
    /// A model invariant failed.
    #[error("invalid compiler model: {0}")]
    Model(PolicyModelError),
    /// Static worst-case work exceeds the compiler budget.
    #[error("policy compilation exceeds its global work budget")]
    WorkLimitExceeded,
    /// Profile selectors lack a safe base-v1 lattice.
    #[error("profile selector has no safe base-v1 authority lattice")]
    UnsafeSelector,
    /// A sentinel identity was supplied where exact identity is required.
    #[error("sentinel identity is not valid policy input")]
    AmbiguousIdentity,
    /// Effective grant construction failed.
    #[error("authority intersection produced an invalid grant")]
    InvalidGrant,
    /// Authenticated endpoint binding lacks its exact required use operation.
    #[error("endpoint catalog binding is not authorized for its declared use")]
    UnauthorizedEndpointUse,
    /// Namespace ceilings deny a requested rule.
    #[error("namespace rule is absent from a required ceiling")]
    NamespaceCeilingDenied,
    /// Namespace DAG or destination semantics are invalid.
    #[error("namespace DAG, handle, destination, or feature semantics are invalid")]
    NamespaceInvalid,
    /// A mediated service was requested through an ordinary filesystem include.
    #[error("mediated service sources require service attachment, not include")]
    ServiceInclude,
    /// A mediated service attachment attempted to expose executable content.
    #[error("mediated service attachments cannot expose executable content")]
    ServiceExecution,
    /// Executable presentation lacks immutable package-or-tool verification.
    #[error("executable view source is not a verified package or tool")]
    UnverifiedExecutableSource,
    /// Namespace source operations exceed authority.
    #[error("derived namespace source operations exceed authority")]
    UnauthorizedNamespaceSource,
    /// An unlimited claim lacks complete same-layer or effective provenance.
    #[error("unlimited resource claim lacks complete nonconfusable provenance")]
    UnlimitedNotAuthorized,
    /// A hard resource remains unresolved.
    #[error("hard resource remains unresolved")]
    UnresolvedResource,
    /// Typed hard enforcement is unavailable.
    #[error("typed hard enforcement is unavailable")]
    EnforcementUnavailable,
    /// Advisory target does not exactly equal its namespace source or lacks operations.
    #[error("advisory target equivalence or operation proof failed")]
    AdvisoryProofFailed,
    /// Advisory source authority exists but the source is absent from the resulting view.
    #[error("advisory source is not reachable from any included or attached view root")]
    AdvisorySourceNotReachable,
    /// Core policy/optimization construction would be lossy or invalid.
    #[error("portable core lowering failed")]
    CoreLowering,
    /// A required feature is outside the portable registry.
    #[error("required feature is outside the portable registry")]
    UnknownRequiredFeature,
    /// Cache disclosure is unresolved.
    #[error("cache disclosure domain remains unresolved")]
    UnresolvedCacheDomain,
    /// Same-class cache domains conflict.
    #[error("cache disclosure domains conflict")]
    ConflictingCacheDomain,
    /// Revocation behavior is unresolved.
    #[error("revocation behavior remains unresolved")]
    UnresolvedRevocation,
}
impl From<PolicyModelError> for PolicyCompilationError {
    fn from(value: PolicyModelError) -> Self {
        Self::Model(value)
    }
}
impl From<AuthorityCompilationError> for PolicyCompilationError {
    fn from(value: AuthorityCompilationError) -> Self {
        match value {
            AuthorityCompilationError::UnsafeSelector => Self::UnsafeSelector,
            AuthorityCompilationError::AmbiguousIdentity => Self::AmbiguousIdentity,
            AuthorityCompilationError::InvalidGrant => Self::InvalidGrant,
            AuthorityCompilationError::UnauthorizedEndpointUse => Self::UnauthorizedEndpointUse,
            AuthorityCompilationError::Model(error) => Self::Model(error),
        }
    }
}
impl From<NamespaceCompilationError> for PolicyCompilationError {
    fn from(value: NamespaceCompilationError) -> Self {
        match value {
            NamespaceCompilationError::CeilingDenied => Self::NamespaceCeilingDenied,
            NamespaceCompilationError::UnauthorizedSource
            | NamespaceCompilationError::UnauthorizedDestination => {
                Self::UnauthorizedNamespaceSource
            }
            NamespaceCompilationError::ServiceInclude => Self::ServiceInclude,
            NamespaceCompilationError::ServiceExecution => Self::ServiceExecution,
            NamespaceCompilationError::UnverifiedExecutableSource => {
                Self::UnverifiedExecutableSource
            }
            NamespaceCompilationError::Model(error) => Self::Model(error),
            _ => Self::NamespaceInvalid,
        }
    }
}
impl From<HardResourceCompilationError> for PolicyCompilationError {
    fn from(value: HardResourceCompilationError) -> Self {
        match value {
            HardResourceCompilationError::UnlimitedNotAuthorized
            | HardResourceCompilationError::UnlimitedNotEffective => Self::UnlimitedNotAuthorized,
            HardResourceCompilationError::UnresolvedLimit => Self::UnresolvedResource,
            HardResourceCompilationError::EnforcementUnavailable => Self::EnforcementUnavailable,
            HardResourceCompilationError::Model(error) => Self::Model(error),
            _ => Self::CoreLowering,
        }
    }
}
impl From<AdvisoryCompilationError> for PolicyCompilationError {
    fn from(value: AdvisoryCompilationError) -> Self {
        match value {
            AdvisoryCompilationError::Model(error) => Self::Model(error),
            AdvisoryCompilationError::SourceNotReachable => Self::AdvisorySourceNotReachable,
            _ => Self::AdvisoryProofFailed,
        }
    }
}
