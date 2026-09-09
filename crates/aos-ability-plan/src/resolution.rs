//! Authenticated provider candidates and deterministic binding resolution.
//!
//! The policy document is the replayable authority input. A [`BindingSource`]
//! in a binding plan is only a description of the decision after this module
//! has checked the corresponding explicit selection, exact pin, singleton
//! candidate set, or operator order.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use aos_ability_model::document::DocumentError;
use aos_ability_model::identity::compare_request_ids;
use aos_ability_model::{
    ABILITY_LIMITS_V1, AuthorityGrant, Binding, BindingId, BindingPlanDocument, BindingRequest,
    BindingSource, DeploymentObligation, DesiredStateDocument, EnvironmentDocument, InstanceId,
    InterfaceKey, LocalKey, PackageDocument, ProviderImplementationReference, RequestId,
    RequiredFeature, ResourceId, ResourceLifetime, RevisionId, VersionedDocument,
    compare_resource_ids,
};
use aos_ability_validate::{
    BindingValidationInputs, CheckedBindingPlan, PreparedBindingCandidates, ValidationContext,
};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Declares one request-specific provider choice under exact authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BindingCandidate {
    /// Names this candidate uniquely within the policy document.
    pub key: LocalKey,
    /// Identifies the exact request this candidate may satisfy.
    pub request: RequestId,
    /// Identifies the exact public interface supplied.
    pub interface: InterfaceKey,
    /// Identifies the selected provider instance.
    pub provider: InstanceId,
    /// Pins the exact authenticated package supplying this provider.
    pub provider_package: Sha256Digest,
    /// Pins the exact implementation and retained executable artifact.
    pub implementation: ProviderImplementationReference,
    /// Defines authority retained by the caller.
    pub caller_grant: AuthorityGrant,
    /// Defines separate provider implementation authority.
    pub provider_grant: AuthorityGrant,
    /// Lists exact supplied guarantees in canonical order.
    pub guarantees: Vec<aos_ability_model::GuaranteeKey>,
    /// Identifies the policy revision authorizing both grants.
    pub policy_revision: RevisionId,
    /// Bounds the selected binding's resource lifetime.
    pub lifetime: ResourceLifetime,
    /// States whether provider implementation mediation is authorized.
    pub mediation_allowed: bool,
    /// Lists exact resources whose simultaneous selection would conflict.
    pub exclusive_resources: Vec<ResourceId>,
}

/// Selects one exact candidate for a request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateSelection {
    /// Identifies the request being selected.
    pub request: RequestId,
    /// Names the exact candidate.
    pub candidate: LocalKey,
}

/// Replays one retained binding only when its exact provider identity is unchanged.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExistingProviderPin {
    /// Identifies the exact request whose prior selection is retained.
    pub request: RequestId,
    /// Names the authenticated candidate that must still carry this identity.
    pub candidate: LocalKey,
    /// Identifies the previously selected provider instance.
    pub provider: InstanceId,
    /// Identifies the previously selected exact provider package.
    pub provider_package: Sha256Digest,
    /// Identifies the previously selected exact public interface.
    pub interface: InterfaceKey,
    /// Pins the previously selected implementation descriptor and artifact.
    pub implementation: ProviderImplementationReference,
}

/// Gives the operator-authored search order for one request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateOrder {
    /// Identifies the request governed by this order.
    pub request: RequestId,
    /// Lists candidate keys from most to least preferred.
    pub candidates: Vec<LocalKey>,
}

/// Selects one exact provider aggregate for an operator-enabled instance.
///
/// Root selection is separate from request binding because an enabled instance
/// must continue to compose after its final consumer contribution is removed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnabledProviderSelection {
    /// Identifies the exact enabled deployment instance.
    pub instance: InstanceId,
    /// Identifies the public interface whose aggregate is selected.
    pub interface: InterfaceKey,
    /// Pins the exact pure implementation and retained executable artifact.
    pub implementation: ProviderImplementationReference,
    /// Defines the implementation authority held by the root provider.
    pub provider_grant: AuthorityGrant,
    /// Identifies the policy revision authorizing the root provider.
    pub policy_revision: RevisionId,
    /// Bounds the selected provider's resource lifetime.
    pub lifetime: ResourceLifetime,
}

/// Carries authenticated, replayable provider-selection inputs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionPolicyDocument {
    /// Carries `aos.ability.resolution-policy/v1`.
    pub schema: String,
    /// Names required semantics in canonical order.
    pub required_features: Vec<RequiredFeature>,
    /// Commits to the exact normalized desired state.
    pub desired_state: Sha256Digest,
    /// Commits to the exact authenticated environment snapshot.
    pub environment: Sha256Digest,
    /// Identifies the policy revision authorizing every candidate.
    pub policy_revision: RevisionId,
    /// Lists request-specific candidates in canonical key order.
    pub candidates: Vec<BindingCandidate>,
    /// Lists deployment-owned selections in canonical request order.
    pub explicit_bindings: Vec<CandidateSelection>,
    /// Lists exact retained pins in canonical request order.
    pub existing_pins: Vec<ExistingProviderPin>,
    /// Lists operator candidate orders in canonical request order.
    pub operator_orders: Vec<CandidateOrder>,
    /// Selects aggregates for explicitly enabled root instances in canonical order.
    pub enabled_providers: Vec<EnabledProviderSelection>,
    /// Lists explicit external obligations for requests with no local binding.
    pub obligations: Vec<DeploymentObligation>,
}

impl VersionedDocument for ResolutionPolicyDocument {
    const SCHEMA: &'static str = "aos.ability.resolution-policy/v1";

    fn schema(&self) -> &str {
        &self.schema
    }

    fn required_features(&self) -> &[RequiredFeature] {
        &self.required_features
    }
}

/// Bounds candidate search independently of document encoding limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolutionLimits {
    /// Limits candidates considered for any one request.
    pub max_candidates_per_request: u32,
    /// Limits complete candidate combinations examined.
    pub max_backtracks: u64,
    /// Limits retained accepted and rejected decision records.
    pub max_trace_entries: u32,
    /// Limits the aggregate encoded size of retained decision explanations.
    pub max_trace_bytes: u64,
}

impl Default for ResolutionLimits {
    fn default() -> Self {
        Self {
            max_candidates_per_request: 64,
            max_backtracks: u64::from(ABILITY_LIMITS_V1.max_graph_edges),
            max_trace_entries: ABILITY_LIMITS_V1.max_graph_edges,
            max_trace_bytes: ABILITY_LIMITS_V1.max_document_bytes,
        }
    }
}

/// Records one accepted provider decision and its authenticated source.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResolutionDecision {
    /// Identifies the satisfied request.
    pub request: RequestId,
    /// Names the selected policy candidate.
    pub candidate: LocalKey,
    /// Records which precedence rule selected it.
    pub source: BindingSource,
}

/// Records why one candidate was skipped during bounded search.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CandidateRejection {
    /// Identifies the request being resolved.
    pub request: RequestId,
    /// Names the rejected candidate.
    pub candidate: LocalKey,
    /// Describes the first exact constraint that rejected it.
    pub constraint: String,
}

/// Retains a checked plan together with its authenticated decision commitment.
#[derive(Debug)]
pub struct ResolutionOutcome {
    /// Retains the exact authenticated provider-selection input.
    pub policy: ResolutionPolicyDocument,
    /// Identifies the canonical resolution-policy input.
    pub policy_digest: Sha256Digest,
    /// Retains accepted decisions in canonical request order.
    pub decisions: Vec<ResolutionDecision>,
    /// Retains bounded rejected-candidate explanations in encounter order.
    pub rejections: Vec<CandidateRejection>,
    /// Carries the semantically checked binding plan.
    pub checked: CheckedBindingPlan,
}

/// Reports why deterministic provider resolution failed.
#[derive(Debug, Error)]
pub enum ResolutionError {
    /// The authenticated policy document is malformed or inconsistent.
    #[error("invalid resolution policy: {0}")]
    InvalidPolicy(String),
    /// An explicit deployment selection or retained pin is invalid.
    #[error("fixed provider selection `{candidate}` for request is invalid: {constraint}")]
    InvalidFixedSelection {
        /// Names the rejected fixed candidate.
        candidate: LocalKey,
        /// Describes the rejecting constraint.
        constraint: String,
    },
    /// More than one candidate is eligible without an operator order.
    #[error("request has {count} eligible providers and no explicit selection policy")]
    Ambiguous {
        /// Reports the number of eligible candidates.
        count: usize,
    },
    /// No eligible candidate or explicit external obligation satisfies a request.
    #[error("request has no eligible provider or explicit external obligation")]
    NoCandidate,
    /// Bounded deterministic backtracking found no conflict-free selection.
    #[error("provider search exhausted its {attempts} combination limit")]
    SearchExhausted {
        /// Reports the configured search bound.
        attempts: u64,
    },
    /// Resolution explanations exceeded their independent retention budget.
    #[error("resolution decision trace exceeds the configured {limit} limit")]
    TraceLimit {
        /// Names the exceeded trace dimension.
        limit: &'static str,
    },
    /// The selected binding document failed common semantic validation.
    #[error("resolved binding plan failed semantic validation: {0}")]
    Validation(#[from] aos_ability_validate::ValidationErrors),
    /// Every remaining candidate combination failed common semantic validation.
    #[error("candidate-dependent binding validation failed after {attempts} attempts: {source}")]
    CandidateValidation {
        /// Reports candidate combinations consumed by this resolver call.
        attempts: u64,
        /// Retains the final common semantic validation failure.
        source: aos_ability_validate::ValidationErrors,
    },
    /// A canonical input could not be encoded or identified.
    #[error("resolution input cannot be canonically identified: {0}")]
    Encoding(#[from] DocumentError),
}

/// Resolves authenticated candidates without performing external effects.
pub struct Resolver<'a> {
    context: &'a ValidationContext,
    limits: ResolutionLimits,
}

impl<'a> Resolver<'a> {
    /// Creates a resolver under the version-1 default search limits.
    #[must_use]
    pub const fn new(context: &'a ValidationContext) -> Self {
        Self {
            context,
            limits: ResolutionLimits {
                max_candidates_per_request: 64,
                max_backtracks: ABILITY_LIMITS_V1.max_graph_edges as u64,
                max_trace_entries: ABILITY_LIMITS_V1.max_graph_edges,
                max_trace_bytes: ABILITY_LIMITS_V1.max_document_bytes,
            },
        }
    }

    /// Replaces the bounded candidate-search limits.
    ///
    /// # Errors
    ///
    /// Returns an error when a limit is zero or exceeds the version-1 hard
    /// candidate or graph-analysis ceiling.
    pub fn with_limits(mut self, limits: ResolutionLimits) -> Result<Self, ResolutionError> {
        if limits.max_candidates_per_request == 0
            || limits.max_candidates_per_request > 64
            || limits.max_backtracks == 0
            || limits.max_backtracks > u64::from(ABILITY_LIMITS_V1.max_graph_edges)
            || limits.max_trace_entries == 0
            || limits.max_trace_entries > ABILITY_LIMITS_V1.max_graph_edges
            || limits.max_trace_bytes == 0
            || limits.max_trace_bytes > ABILITY_LIMITS_V1.max_document_bytes
        {
            return Err(ResolutionError::InvalidPolicy(
                "resolution limits exceed the version-1 bounded profile".to_string(),
            ));
        }
        self.limits = limits;
        Ok(self)
    }

    /// Resolves, validates, and retains one exact binding plan.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid policy commitments or ordering, an invalid
    /// explicit selection or pin, ambiguity, exhausted bounded search, or a
    /// binding plan rejected by the common semantic validator.
    pub fn resolve(
        &self,
        policy: &ResolutionPolicyDocument,
        desired_state: DesiredStateDocument,
        environment: EnvironmentDocument,
        packages: Vec<PackageDocument>,
    ) -> Result<ResolutionOutcome, ResolutionError> {
        let draft = self.resolve_draft(policy, &desired_state, &environment, &packages)?;

        Ok(ResolutionOutcome {
            policy: policy.clone(),
            policy_digest: draft.policy,
            decisions: draft.decisions,
            rejections: draft.rejections,
            checked: draft.checked,
        })
    }

    pub(crate) fn resolve_draft(
        &self,
        policy: &ResolutionPolicyDocument,
        desired_state: &DesiredStateDocument,
        environment: &EnvironmentDocument,
        packages: &[PackageDocument],
    ) -> Result<ResolutionDraft, ResolutionError> {
        self.resolve_draft_at(policy, desired_state, environment, packages, 0)
    }

    pub(crate) fn resolve_draft_at(
        &self,
        policy: &ResolutionPolicyDocument,
        desired_state: &DesiredStateDocument,
        environment: &EnvironmentDocument,
        packages: &[PackageDocument],
        combination: u64,
    ) -> Result<ResolutionDraft, ResolutionError> {
        let policy_digest = policy.content_digest()?;
        let desired_digest = desired_state.content_digest()?;
        let environment_digest = environment.content_digest()?;
        validate_policy_shape(
            self.context,
            self.limits,
            policy,
            desired_digest,
            environment_digest,
            desired_state,
            environment,
        )?;

        let index =
            ResolutionIndex::new(self.context, policy, desired_state, environment, packages)?;
        let explicit = selection_map(&policy.explicit_bindings);
        let pins: BTreeMap<_, _> = policy
            .existing_pins
            .iter()
            .map(|pin| (pin.request.clone(), pin))
            .collect();
        let orders: BTreeMap<_, _> = policy
            .operator_orders
            .iter()
            .map(|order| (order.request.clone(), order))
            .collect();
        let mut obligations: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for obligation in &policy.obligations {
            obligations
                .entry(obligation.request.clone())
                .or_default()
                .push(obligation.clone());
        }

        let mut request_choices = Vec::new();
        let mut unresolved = Vec::new();
        let mut rejections = Vec::new();
        let mut trace = ResolutionTrace::new(self.limits);
        for request in &desired_state.child_requests {
            let selection = explicit
                .get(&request.id)
                .map(|candidate| (*candidate, BindingSource::Explicit))
                .or_else(|| {
                    pins.get(&request.id)
                        .map(|pin| (&pin.candidate, BindingSource::ExistingPin))
                });

            if let Some((candidate, source)) = selection {
                let choice =
                    index
                        .fixed_choice(request, candidate, source)
                        .map_err(|constraint| ResolutionError::InvalidFixedSelection {
                            candidate: candidate.clone(),
                            constraint,
                        })?;
                if let Some(pin) = pins.get(&request.id)
                    && source == BindingSource::ExistingPin
                    && (choice.binding.provider != pin.provider
                        || choice.binding.provider_package != Some(pin.provider_package)
                        || choice.binding.interface != pin.interface
                        || choice.binding.implementation != pin.implementation)
                {
                    return Err(ResolutionError::InvalidFixedSelection {
                        candidate: candidate.clone(),
                        constraint:
                            "retained pin differs from its exact previous provider identity"
                                .to_string(),
                    });
                }
                request_choices.push(vec![choice]);
                continue;
            }

            let choices = if let Some(order) = orders.get(&request.id) {
                index.ordered_choices(request, order, &mut rejections, &mut trace)?
            } else {
                let eligible = index.sole_eligible_choices(request, &mut rejections, &mut trace)?;
                if eligible.len() > 1 {
                    return Err(ResolutionError::Ambiguous {
                        count: eligible.len(),
                    });
                }
                eligible
            };
            if choices.is_empty() {
                if let Some(request_obligations) = obligations.get(&request.id) {
                    unresolved.extend(request_obligations.iter().cloned());
                    continue;
                }
                return Err(ResolutionError::NoCandidate);
            }
            request_choices.push(choices);
        }

        unresolved.sort_by(|left, right| left.key.cmp(&right.key));
        let required_features: Vec<_> = environment
            .required_features
            .iter()
            .chain(&desired_state.required_features)
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let resources = merged_resources(&environment.resources, &desired_state.resources);
        drop(index);
        let mut cursor = combination;
        let mut aggregate_attempts = 0_u64;
        loop {
            let ConflictFreeSelection {
                selected,
                next_combination,
                retry_rejection,
                attempts,
            } = select_conflict_free(
                &request_choices,
                self.limits.max_backtracks,
                cursor,
                &mut rejections,
                &mut trace,
            )?;
            aggregate_attempts = aggregate_attempts.saturating_add(attempts);
            let mut bindings: Vec<_> = selected
                .iter()
                .map(|choice| choice.binding.clone())
                .collect();
            bindings.sort_by(|left, right| left.id.cmp(&right.id));
            let decisions: Vec<_> = selected
                .iter()
                .map(|choice| ResolutionDecision {
                    request: choice.binding.request.clone(),
                    candidate: choice.candidate.clone(),
                    source: choice.binding.source,
                })
                .collect();
            trace.retain_decisions(&decisions)?;

            let document = BindingPlanDocument {
                schema: BindingPlanDocument::SCHEMA.to_string(),
                required_features: required_features.clone(),
                desired_state: desired_digest,
                environment: environment_digest,
                policy_revision: policy.policy_revision,
                requests: desired_state.child_requests.clone(),
                bindings,
                resources: resources.clone(),
                obligations: unresolved.clone(),
            };
            let checked = self.context.validate_binding_plan(
                document,
                BindingValidationInputs {
                    environment: environment.clone(),
                    desired_state: desired_state.clone(),
                    packages: packages.to_vec(),
                },
            );
            match checked {
                Ok(checked) => {
                    return Ok(ResolutionDraft {
                        policy: policy_digest,
                        decisions,
                        rejections,
                        next_combination,
                        retry_rejection,
                        attempts: aggregate_attempts,
                        checked,
                    });
                }
                Err(error) => {
                    let Some(next) = next_combination else {
                        return Err(ResolutionError::CandidateValidation {
                            attempts: aggregate_attempts,
                            source: error,
                        });
                    };
                    let Some((request, candidate)) = retry_rejection else {
                        return Err(ResolutionError::CandidateValidation {
                            attempts: aggregate_attempts,
                            source: error,
                        });
                    };
                    trace.push_rejection(
                        &mut rejections,
                        CandidateRejection {
                            request,
                            candidate,
                            constraint: bounded_validation_constraint(&error.to_string()),
                        },
                    )?;
                    cursor = next;
                }
            }
        }
    }
}

fn bounded_validation_constraint(message: &str) -> String {
    const MAXIMUM_BYTES: usize = 4 * 1024;
    if message.len() <= MAXIMUM_BYTES {
        return message.to_string();
    }
    let mut boundary = MAXIMUM_BYTES;
    while !message.is_char_boundary(boundary) {
        boundary -= 1;
    }
    message[..boundary].to_string()
}

pub(crate) struct ResolutionDraft {
    pub(crate) policy: Sha256Digest,
    pub(crate) decisions: Vec<ResolutionDecision>,
    pub(crate) rejections: Vec<CandidateRejection>,
    pub(crate) next_combination: Option<u64>,
    pub(crate) retry_rejection: Option<(RequestId, LocalKey)>,
    pub(crate) attempts: u64,
    pub(crate) checked: CheckedBindingPlan,
}

#[derive(Clone)]
struct CandidateChoice {
    candidate: LocalKey,
    binding: Binding,
    exclusive_resources: Vec<ResourceId>,
}

struct ResolutionIndex<'a> {
    policy: &'a ResolutionPolicyDocument,
    candidates: BTreeMap<LocalKey, &'a BindingCandidate>,
    candidates_by_request: BTreeMap<RequestId, Vec<&'a BindingCandidate>>,
    prepared: PreparedBindingCandidates,
    resources: BTreeSet<ResourceId>,
}

impl<'a> ResolutionIndex<'a> {
    fn new(
        context: &'a ValidationContext,
        policy: &'a ResolutionPolicyDocument,
        desired_state: &'a DesiredStateDocument,
        environment: &'a EnvironmentDocument,
        packages: &'a [PackageDocument],
    ) -> Result<Self, ResolutionError> {
        let mut candidates = BTreeMap::new();
        let mut candidates_by_request: BTreeMap<RequestId, Vec<_>> = BTreeMap::new();
        for candidate in &policy.candidates {
            candidates.insert(candidate.key.clone(), candidate);
            candidates_by_request
                .entry(candidate.request.clone())
                .or_default()
                .push(candidate);
        }
        let prepared = context.prepare_binding_candidates(environment, desired_state, packages)?;
        let resources = environment
            .resources
            .iter()
            .chain(&desired_state.resources)
            .map(|revision| revision.resource.clone())
            .collect();

        Ok(Self {
            policy,
            candidates,
            candidates_by_request,
            prepared,
            resources,
        })
    }

    fn fixed_choice(
        &self,
        request: &BindingRequest,
        candidate_key: &LocalKey,
        source: BindingSource,
    ) -> Result<CandidateChoice, String> {
        let candidate = self
            .candidates
            .get(candidate_key)
            .copied()
            .ok_or_else(|| "selection names no authenticated candidate".to_string())?;
        self.choice(request, candidate, source)
    }

    fn ordered_choices(
        &self,
        request: &BindingRequest,
        order: &CandidateOrder,
        rejections: &mut Vec<CandidateRejection>,
        trace: &mut ResolutionTrace,
    ) -> Result<Vec<CandidateChoice>, ResolutionError> {
        let mut choices = Vec::new();
        for candidate_key in &order.candidates {
            let candidate = self.candidates.get(candidate_key).copied().ok_or_else(|| {
                ResolutionError::InvalidPolicy(
                    "operator order names no authenticated candidate".to_string(),
                )
            })?;
            match self.choice(request, candidate, BindingSource::OperatorPolicy) {
                Ok(choice) => choices.push(choice),
                Err(constraint) => trace.push_rejection(
                    rejections,
                    CandidateRejection {
                        request: request.id.clone(),
                        candidate: candidate.key.clone(),
                        constraint,
                    },
                )?,
            }
        }
        Ok(choices)
    }

    fn sole_eligible_choices(
        &self,
        request: &BindingRequest,
        rejections: &mut Vec<CandidateRejection>,
        trace: &mut ResolutionTrace,
    ) -> Result<Vec<CandidateChoice>, ResolutionError> {
        let mut choices = Vec::new();
        for candidate in self
            .candidates_by_request
            .get(&request.id)
            .into_iter()
            .flatten()
        {
            match self.choice(request, candidate, BindingSource::SoleEligible) {
                Ok(choice) => choices.push(choice),
                Err(constraint) => trace.push_rejection(
                    rejections,
                    CandidateRejection {
                        request: request.id.clone(),
                        candidate: candidate.key.clone(),
                        constraint,
                    },
                )?,
            }
        }
        Ok(choices)
    }

    fn choice(
        &self,
        request: &BindingRequest,
        candidate: &BindingCandidate,
        source: BindingSource,
    ) -> Result<CandidateChoice, String> {
        if candidate.request != request.id {
            return Err("candidate belongs to a different request".to_string());
        }
        if candidate.policy_revision != self.policy.policy_revision {
            return Err("candidate uses a different policy revision".to_string());
        }
        if candidate
            .exclusive_resources
            .iter()
            .any(|resource| !self.resources.contains(resource))
        {
            return Err("candidate claims an unknown exclusive resource".to_string());
        }
        let binding = Binding {
            id: BindingId(candidate.key.clone()),
            request: request.id.clone(),
            interface: candidate.interface.clone(),
            provider: candidate.provider.clone(),
            provider_package: Some(candidate.provider_package),
            implementation: candidate.implementation.clone(),
            source,
            caller_grant: candidate.caller_grant.clone(),
            provider_grant: candidate.provider_grant.clone(),
            guarantees: candidate.guarantees.clone(),
            policy_revision: candidate.policy_revision,
            lifetime: candidate.lifetime,
            mediation_allowed: candidate.mediation_allowed,
        };
        self.prepared.validate(&binding).map_err(|error| {
            error.diagnostics().first().map_or_else(
                || error.to_string(),
                |diagnostic| diagnostic.message.clone(),
            )
        })?;

        Ok(CandidateChoice {
            candidate: candidate.key.clone(),
            binding,
            exclusive_resources: candidate.exclusive_resources.clone(),
        })
    }
}

fn validate_policy_shape(
    context: &ValidationContext,
    limits: ResolutionLimits,
    policy: &ResolutionPolicyDocument,
    desired_digest: Sha256Digest,
    environment_digest: Sha256Digest,
    desired_state: &DesiredStateDocument,
    environment: &EnvironmentDocument,
) -> Result<(), ResolutionError> {
    if policy.desired_state != desired_digest || policy.environment != environment_digest {
        return Err(ResolutionError::InvalidPolicy(
            "policy commitments differ from the supplied desired state or environment".to_string(),
        ));
    }
    if policy
        .required_features
        .iter()
        .any(|feature| !context.supported_features().contains(feature))
    {
        return Err(ResolutionError::InvalidPolicy(
            "policy requires unsupported semantics".to_string(),
        ));
    }
    if policy.candidates.len() > ABILITY_LIMITS_V1.max_graph_nodes as usize {
        return Err(ResolutionError::InvalidPolicy(
            "candidate catalog exceeds the version-1 graph-node limit".to_string(),
        ));
    }
    check_strict_order_by(
        &policy.candidates,
        |left, right| left.key.cmp(&right.key),
        "candidate keys",
    )?;
    check_selection_order(&policy.explicit_bindings, "explicit bindings")?;
    check_strict_order_by(
        &policy.existing_pins,
        |left, right| compare_request_ids(&left.request, &right.request),
        "existing pins",
    )?;
    check_strict_order_by(
        &policy.operator_orders,
        |left, right| compare_request_ids(&left.request, &right.request),
        "operator orders",
    )?;
    check_strict_order_by(
        &policy.enabled_providers,
        |left, right| {
            left.instance
                .cmp(&right.instance)
                .then_with(|| left.interface.cmp(&right.interface))
        },
        "enabled provider selections",
    )?;
    check_strict_order_by(
        &policy.obligations,
        |left, right| {
            compare_request_ids(&left.request, &right.request)
                .then_with(|| left.key.cmp(&right.key))
        },
        "resolution obligations",
    )?;

    let requests: BTreeSet<_> = desired_state
        .child_requests
        .iter()
        .map(|request| request.id.clone())
        .collect();
    let mut obligation_keys = BTreeSet::new();
    for obligation in &policy.obligations {
        if !requests.contains(&obligation.request) || !obligation_keys.insert(&obligation.key) {
            return Err(ResolutionError::InvalidPolicy(
                "resolution obligation is duplicated or belongs to an unknown desired request"
                    .to_string(),
            ));
        }
    }
    let mut candidate_counts: BTreeMap<&RequestId, usize> = BTreeMap::new();
    for candidate in &policy.candidates {
        if !requests.contains(&candidate.request) {
            return Err(ResolutionError::InvalidPolicy(
                "candidate belongs to an unknown desired request".to_string(),
            ));
        }
        *candidate_counts.entry(&candidate.request).or_default() += 1;
        if candidate
            .exclusive_resources
            .windows(2)
            .any(|pair| compare_resource_ids(&pair[0], &pair[1]) != Ordering::Less)
        {
            return Err(ResolutionError::InvalidPolicy(
                "candidate exclusive resources are not in strict canonical order".to_string(),
            ));
        }
    }
    if candidate_counts
        .values()
        .any(|count| *count > limits.max_candidates_per_request as usize)
    {
        return Err(ResolutionError::InvalidPolicy(
            "request exceeds the configured candidate limit".to_string(),
        ));
    }
    for order in &policy.operator_orders {
        if !requests.contains(&order.request)
            || order.candidates.is_empty()
            || order.candidates.len() > limits.max_candidates_per_request as usize
            || !strictly_unique(&order.candidates)
        {
            return Err(ResolutionError::InvalidPolicy(
                "operator order is empty, duplicated, unknown, or oversized".to_string(),
            ));
        }
    }
    for selection in &policy.explicit_bindings {
        if !requests.contains(&selection.request) {
            return Err(ResolutionError::InvalidPolicy(
                "selection belongs to an unknown desired request".to_string(),
            ));
        }
    }
    let candidates: BTreeMap<_, _> = policy
        .candidates
        .iter()
        .map(|candidate| (&candidate.key, candidate))
        .collect();
    for pin in &policy.existing_pins {
        let exact = candidates.get(&pin.candidate).is_some_and(|candidate| {
            candidate.request == pin.request
                && candidate.provider == pin.provider
                && candidate.provider_package == pin.provider_package
                && candidate.interface == pin.interface
                && candidate.implementation == pin.implementation
        });
        if !requests.contains(&pin.request) || !exact {
            return Err(ResolutionError::InvalidPolicy(
                "existing pin does not match an exact authenticated candidate identity".to_string(),
            ));
        }
    }
    let enabled_instances: BTreeSet<_> = desired_state
        .instances
        .iter()
        .filter(|instance| instance.enabled)
        .map(|instance| &instance.instance)
        .collect();
    for selection in &policy.enabled_providers {
        if !enabled_instances.contains(&selection.instance)
            || selection.policy_revision != policy.policy_revision
            || selection.provider_grant.principal != selection.instance
        {
            return Err(ResolutionError::InvalidPolicy(
                "enabled provider selection names a disabled instance or uses a different policy revision or principal".to_string(),
            ));
        }
        validate_enabled_provider_grant(selection)?;
    }
    if policy.policy_revision != environment.policy_revision {
        return Err(ResolutionError::InvalidPolicy(
            "resolution policy revision differs from the environment".to_string(),
        ));
    }
    Ok(())
}

fn validate_enabled_provider_grant(
    selection: &EnabledProviderSelection,
) -> Result<(), ResolutionError> {
    if selection
        .provider_grant
        .methods
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
        || !selection.provider_grant.contributions.is_empty()
    {
        return Err(ResolutionError::InvalidPolicy(
            "enabled provider grant methods are noncanonical or grant contribution authority"
                .to_string(),
        ));
    }
    if selection
        .provider_grant
        .resources
        .windows(2)
        .any(|pair| compare_resource_ids(&pair[0].resource, &pair[1].resource) != Ordering::Less)
    {
        return Err(ResolutionError::InvalidPolicy(
            "enabled provider grant resources are not in strict canonical order".to_string(),
        ));
    }
    for permission in &selection.provider_grant.resources {
        if permission.resource.provider != selection.instance
            || permission
                .operations
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(ResolutionError::InvalidPolicy(
                "enabled provider grant leaves its instance or has noncanonical operations"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

struct ConflictFreeSelection {
    selected: Vec<CandidateChoice>,
    next_combination: Option<u64>,
    retry_rejection: Option<(RequestId, LocalKey)>,
    attempts: u64,
}

fn select_conflict_free(
    request_choices: &[Vec<CandidateChoice>],
    max_attempts: u64,
    start: u64,
    rejections: &mut Vec<CandidateRejection>,
    trace: &mut ResolutionTrace,
) -> Result<ConflictFreeSelection, ResolutionError> {
    if request_choices.is_empty() {
        return if start == 0 {
            Ok(ConflictFreeSelection {
                selected: Vec::new(),
                next_combination: None,
                retry_rejection: None,
                attempts: 1,
            })
        } else {
            Err(ResolutionError::SearchExhausted { attempts: 1 })
        };
    }
    let total = request_choices.iter().try_fold(1_u64, |total, choices| {
        total.checked_mul(choices.len() as u64)
    });
    let total = total.unwrap_or(u64::MAX);
    if start >= total || start >= max_attempts {
        return Err(ResolutionError::SearchExhausted {
            attempts: total.min(max_attempts),
        });
    }
    let mut ordinal = start;
    while ordinal < total && ordinal < max_attempts {
        let positions = combination_positions(ordinal, request_choices);
        let selected: Vec<_> = request_choices
            .iter()
            .zip(&positions)
            .map(|(choices, position)| choices[*position].clone())
            .collect();
        if let Some((rejected_index, constraint)) = first_resource_conflict(&selected) {
            let rejected = &selected[rejected_index];
            trace.push_rejection(
                rejections,
                CandidateRejection {
                    request: rejected.binding.request.clone(),
                    candidate: rejected.candidate.clone(),
                    constraint,
                },
            )?;
        } else {
            let next = (ordinal.saturating_add(1) < total
                && ordinal.saturating_add(1) < max_attempts)
                .then_some(ordinal.saturating_add(1));
            let retry_rejection = next.and_then(|next| {
                let next_positions = combination_positions(next, request_choices);
                positions
                    .iter()
                    .zip(&next_positions)
                    .position(|(current, next)| current != next)
                    .map(|index| {
                        (
                            selected[index].binding.request.clone(),
                            selected[index].candidate.clone(),
                        )
                    })
            });
            return Ok(ConflictFreeSelection {
                selected,
                next_combination: next,
                retry_rejection,
                attempts: ordinal.saturating_sub(start).saturating_add(1),
            });
        }
        ordinal = ordinal.saturating_add(1);
    }
    Err(ResolutionError::SearchExhausted {
        attempts: total.min(max_attempts).saturating_sub(start),
    })
}

fn first_resource_conflict(selected: &[CandidateChoice]) -> Option<(usize, String)> {
    let mut claims: BTreeMap<ResourceId, usize> = BTreeMap::new();
    for (selected_index, choice) in selected.iter().enumerate() {
        for resource in &choice.exclusive_resources {
            if claims.insert(resource.clone(), selected_index).is_some() {
                return Some((
                    selected_index,
                    "authenticated exclusive resource claim conflicts with an earlier candidate"
                        .to_string(),
                ));
            }
        }
    }
    None
}

fn combination_positions(ordinal: u64, choices: &[Vec<CandidateChoice>]) -> Vec<usize> {
    let mut remainder = ordinal;
    let mut positions = vec![0; choices.len()];
    for index in (0..choices.len()).rev() {
        let radix = choices[index].len() as u64;
        positions[index] = (remainder % radix) as usize;
        remainder /= radix;
    }
    positions
}

fn merged_resources(
    current: &[aos_ability_model::ResourceRevision],
    desired: &[aos_ability_model::ResourceRevision],
) -> Vec<aos_ability_model::ResourceRevision> {
    let mut resources: BTreeMap<_, _> = current
        .iter()
        .map(|revision| (revision.resource.clone(), revision.clone()))
        .collect();
    resources.extend(
        desired
            .iter()
            .map(|revision| (revision.resource.clone(), revision.clone())),
    );
    resources.into_values().collect()
}

fn selection_map(selections: &[CandidateSelection]) -> BTreeMap<RequestId, &LocalKey> {
    selections
        .iter()
        .map(|selection| (selection.request.clone(), &selection.candidate))
        .collect()
}

fn check_selection_order(
    selections: &[CandidateSelection],
    name: &str,
) -> Result<(), ResolutionError> {
    check_strict_order_by(
        selections,
        |left, right| compare_request_ids(&left.request, &right.request),
        name,
    )
}

fn check_strict_order_by<T>(
    values: &[T],
    compare: impl Fn(&T, &T) -> Ordering,
    name: &str,
) -> Result<(), ResolutionError> {
    if values
        .windows(2)
        .any(|pair| compare(&pair[0], &pair[1]) != Ordering::Less)
    {
        return Err(ResolutionError::InvalidPolicy(format!(
            "{name} are not in strict canonical order"
        )));
    }
    Ok(())
}

fn strictly_unique<T: Ord>(values: &[T]) -> bool {
    let mut seen = BTreeSet::new();
    values.iter().all(|value| seen.insert(value))
}

struct ResolutionTrace {
    limits: ResolutionLimits,
    entries: u32,
    bytes: u64,
}

impl ResolutionTrace {
    const fn new(limits: ResolutionLimits) -> Self {
        Self {
            limits,
            entries: 0,
            bytes: 0,
        }
    }

    fn push_rejection(
        &mut self,
        rejections: &mut Vec<CandidateRejection>,
        rejection: CandidateRejection,
    ) -> Result<(), ResolutionError> {
        self.retain_entry(
            request_size_hint(&rejection.request)
                .saturating_add(rejection.candidate.as_str().len())
                .saturating_add(rejection.constraint.len()),
        )?;
        rejections.push(rejection);
        Ok(())
    }

    fn retain_decisions(
        &mut self,
        decisions: &[ResolutionDecision],
    ) -> Result<(), ResolutionError> {
        for decision in decisions {
            self.retain_entry(
                request_size_hint(&decision.request)
                    .saturating_add(decision.candidate.as_str().len())
                    .saturating_add(1),
            )?;
        }
        Ok(())
    }

    fn retain_entry(&mut self, bytes: usize) -> Result<(), ResolutionError> {
        self.entries = self.entries.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes as u64);
        if self.entries > self.limits.max_trace_entries {
            return Err(ResolutionError::TraceLimit {
                limit: "entry count",
            });
        }
        if self.bytes > self.limits.max_trace_bytes {
            return Err(ResolutionError::TraceLimit {
                limit: "encoded byte",
            });
        }
        Ok(())
    }
}

fn request_size_hint(request: &RequestId) -> usize {
    request.consumer.environment.authority.as_str().len()
        + request.consumer.environment.key.as_str().len()
        + request.consumer.key.as_str().len()
        + request
            .scope
            .as_slice()
            .iter()
            .map(|component| component.as_str().len())
            .sum::<usize>()
        + request.key.as_str().len()
}
