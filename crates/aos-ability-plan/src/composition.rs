//! Bounded recursive evaluation of authenticated pure provider implementations.
//!
//! Every expansion pass is authorized by a separate resolution-policy snapshot
//! committed to the exact desired-state digest for that pass. Provider output
//! can derive declared child requests and desired data, but it cannot create
//! candidates, grants, pins, orders, obligations, or policy commitments.

use aos_ability_model::document::{Contribution, encode_canonical};
use aos_ability_model::{
    ABILITY_LIMITS_V1, AbilityValue, AggregateOutput, Binding, BindingRequest,
    ControllerAssignment, DesiredStateDocument, EnvironmentDocument, InstanceId, InterfaceKey,
    LocalKey, PackageDocument, ProviderImplementationReference, RequestId, ResourceRevision,
    ScopePath, VersionedDocument,
};
use aos_ability_validate::ValidationContext;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

use crate::resolution::{
    CandidateRejection, ResolutionDecision, ResolutionError, ResolutionLimits, ResolutionOutcome,
    ResolutionPolicyDocument, Resolver,
};

mod evaluation;
mod merge;
mod trace;

use evaluation::{
    EvaluationRecorder, PureProviderEvaluationInputs, evaluate_pure_providers,
    validate_desired_activation_modes, validate_desired_outputs, validate_enabled_providers,
};
use merge::merge_fragments;
use trace::TraceBudget;

/// Supplies the checked, bounded input to one pure composition entry point.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionContext {
    /// Carries `aos.ability.composition-context/v1`.
    pub schema: String,
    /// Identifies the provider aggregate evaluated exactly once in this pass.
    pub provider: InstanceId,
    /// Identifies the exact public interface implemented by this aggregate.
    pub interface: InterfaceKey,
    /// Pins the exact implementation selected for evaluation.
    pub implementation: ProviderImplementationReference,
    /// Pins the exact package manifest supplying the pure implementation.
    pub package: Sha256Digest,
    /// Lists all requests currently bound to this provider aggregate.
    pub requests: Vec<BindingRequest>,
    /// Lists the complete canonical current-pass binding set.
    pub bindings: Vec<Binding>,
    /// Lists contributions addressed to this provider without erasing provenance.
    pub contributions: Vec<Contribution>,
    /// Lists the complete current desired resource set.
    pub resources: Vec<ResourceRevision>,
    /// Lists the complete current provider-qualified desired aggregate outputs.
    pub outputs: Vec<AggregateOutput>,
    /// Lists the complete current desired controller assignments.
    pub controllers: Vec<ControllerAssignment>,
}

/// Carries the bounded desired-state fragment returned by a pure provider.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionFragment {
    /// Carries `aos.ability.composition-fragment/v1`.
    pub schema: String,
    /// Lists direct child requests declared by the provider implementation.
    pub requests: Vec<BindingRequest>,
    /// Lists derived contributions while preserving their source request.
    pub contributions: Vec<Contribution>,
    /// Lists provider-owned desired resource revisions.
    pub resources: Vec<ResourceRevision>,
    /// Lists provider-qualified desired aggregate outputs.
    pub outputs: Vec<AggregateOutput>,
    /// Lists lifecycle controllers for the fragment's desired resources.
    pub controllers: Vec<ControllerAssignment>,
}

/// Derives the only child request identity a provider may emit for an alias.
///
/// The child consumer is the selected provider. Its provider-owned scope is
/// the single stable provider instance key, independent of contributor
/// ancestry, and its local key is the exact declared requirement alias.
///
/// # Errors
///
/// Returns an error when appending the provider would exceed the configured
/// version-1 scope depth.
pub fn child_request_id(
    provider: &InstanceId,
    alias: LocalKey,
) -> Result<RequestId, CompositionError> {
    let scope = ScopePath::new(vec![provider.key.clone()]).map_err(|error| {
        CompositionError::InvalidFragment {
            provider: provider.clone(),
            reason: error.to_string(),
        }
    })?;
    Ok(RequestId {
        consumer: provider.clone(),
        scope,
        key: alias,
    })
}

fn validate_child_depth(
    provider: &InstanceId,
    child: &RequestId,
    limits: CompositionLimits,
) -> Result<(), CompositionError> {
    if child.scope.as_slice().len() > limits.max_depth as usize {
        return Err(CompositionError::Limit {
            limit: "composition depth",
        });
    }
    if child.consumer != *provider {
        return Err(CompositionError::InvalidFragment {
            provider: provider.clone(),
            reason: "child request leaves its provider aggregate".to_string(),
        });
    }
    Ok(())
}

/// Evaluates one exact authenticated package entry without external effects.
pub trait CompositionEvaluator {
    /// Evaluates `entry` from `implementation` against one bounded input value.
    ///
    /// # Errors
    ///
    /// Returns an error when the artifact or entry is unavailable, evaluation
    /// exceeds its restricted budget, or the implementation rejects the input.
    fn evaluate(
        &mut self,
        implementation: &ProviderImplementationReference,
        entry: &LocalKey,
        input: &AbilityValue,
    ) -> Result<AbilityValue, EvaluationError>;
}

/// Reports a restricted evaluator failure without coupling adapters to an error crate.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("{message}")]
pub struct EvaluationError {
    message: String,
}

impl EvaluationError {
    /// Creates an evaluator error from a bounded adapter-owned message.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the adapter-owned failure message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Bounds recursive evaluation and retained cross-pass explanations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompositionLimits {
    /// Limits outer resolve/evaluate rounds.
    pub max_rounds: u32,
    /// Limits nested provider scope components.
    pub max_depth: u32,
    /// Limits fragment evaluations across all rounds.
    pub max_evaluations: u32,
    /// Limits aggregate canonical input and output bytes processed by evaluators.
    pub max_evaluation_bytes: u64,
    /// Limits candidate combinations examined across all recursive passes.
    pub max_search_attempts: u64,
    /// Limits retained pass decisions and candidate rejections.
    pub max_trace_entries: u32,
    /// Limits approximate encoded bytes retained by the pass trace.
    pub max_trace_bytes: u64,
}

impl Default for CompositionLimits {
    fn default() -> Self {
        Self {
            max_rounds: 64,
            max_depth: 64,
            max_evaluations: ABILITY_LIMITS_V1.max_graph_nodes,
            max_evaluation_bytes: ABILITY_LIMITS_V1.max_document_bytes,
            max_search_attempts: u64::from(ABILITY_LIMITS_V1.max_graph_edges),
            max_trace_entries: ABILITY_LIMITS_V1.max_graph_edges,
            max_trace_bytes: ABILITY_LIMITS_V1.max_document_bytes,
        }
    }
}

/// Records the authenticated inputs and decisions used in one expansion pass.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionPass {
    /// Gives the zero-based outer round.
    pub round: u32,
    /// Retains the exact bounded desired-state subject of the pass.
    pub desired_state: DesiredStateDocument,
    /// Identifies the exact desired-state subject of the pass.
    pub desired_state_digest: Sha256Digest,
    /// Retains the exact authenticated resolution policy used by the pass.
    pub policy: ResolutionPolicyDocument,
    /// Identifies the exact authenticated resolution policy used by the pass.
    pub policy_digest: Sha256Digest,
    /// Retains selected candidates in canonical request order.
    pub decisions: Vec<ResolutionDecision>,
    /// Retains rejected candidates in deterministic encounter order.
    pub rejections: Vec<CandidateRejection>,
}

/// Records one exact restricted-evaluator exchange, including failed branches.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionEvaluation {
    /// Identifies the provider whose selected implementation was evaluated.
    pub provider: InstanceId,
    /// Pins the exact selected implementation descriptor and artifact.
    pub implementation: ProviderImplementationReference,
    /// Names the exact pure package entry point invoked.
    pub entry: LocalKey,
    /// Retains the canonical checked evaluation context.
    pub input: AbilityValue,
    /// Retains the exact returned value or bounded adapter failure.
    pub result: CompositionEvaluationResult,
}

/// Retains the exact result of one restricted pure evaluation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CompositionEvaluationResult {
    /// The evaluator returned one bounded value for fragment validation.
    Returned {
        /// Carries the exact returned value.
        value: AbilityValue,
    },
    /// The evaluator rejected the selected implementation.
    Failed {
        /// Carries a bounded deterministic adapter message.
        message: String,
    },
}

/// Retains stabilized desired state, replay trace, and its checked binding plan.
#[derive(Debug)]
pub struct CompositionOutcome {
    /// Retains the original normalized desired-state input.
    pub seed: DesiredStateDocument,
    /// Carries the normalized fixed-point desired state.
    pub desired_state: DesiredStateDocument,
    /// Retains the complete canonical authenticated policy set supplied to planning.
    pub policies: Vec<ResolutionPolicyDocument>,
    /// Records every evaluator exchange, including discarded search branches.
    pub evaluations: Vec<CompositionEvaluation>,
    /// Records every authenticated resolution snapshot used in order.
    pub passes: Vec<CompositionPass>,
    /// Carries the final semantically checked provider resolution.
    pub resolution: ResolutionOutcome,
}

/// Reports why pure recursive composition did not reach an authorized fixed point.
#[derive(Debug, Error)]
pub enum CompositionError {
    /// The current pass failed deterministic provider resolution.
    #[error(transparent)]
    Resolution(#[from] ResolutionError),
    /// Orchestration must obtain policy for this exact expanded desired state.
    #[error(
        "authenticated resolution policy is required for expanded desired state {desired_state_digest}"
    )]
    PolicyRequired {
        /// Supplies the exact bounded document to authorize and replay.
        desired_state: Box<DesiredStateDocument>,
        /// Identifies the supplied expanded desired-state document.
        desired_state_digest: Sha256Digest,
        /// Identifies the unchanged authenticated environment snapshot.
        environment: Sha256Digest,
    },
    /// The restricted evaluator rejected an exact pure implementation.
    #[error("pure composition evaluation failed for provider {provider:?}: {source}")]
    Evaluation {
        /// Identifies the provider whose entry failed.
        provider: InstanceId,
        /// Retains the adapter failure.
        source: EvaluationError,
    },
    /// A provider returned a malformed or unauthorized desired-state fragment.
    #[error("invalid composition fragment from provider {provider:?}: {reason}")]
    InvalidFragment {
        /// Identifies the provider that returned the fragment.
        provider: InstanceId,
        /// Describes the first rejected invariant.
        reason: String,
    },
    /// The selected pure implementation could not be recovered from package inputs.
    #[error("selected pure implementation for provider {provider:?} is unavailable")]
    MissingImplementation {
        /// Identifies the selected provider.
        provider: InstanceId,
    },
    /// Expansion revisited an earlier nonfixed desired-state digest.
    #[error("recursive composition oscillated at desired state {desired_state}")]
    Oscillation {
        /// Identifies the repeated desired state.
        desired_state: Sha256Digest,
    },
    /// A configured recursive planning bound was exhausted.
    #[error("recursive composition exceeds the configured {limit} limit")]
    Limit {
        /// Names the exhausted dimension.
        limit: &'static str,
    },
    /// A context, fragment, or desired document failed bounded canonical encoding.
    #[error("composition value cannot be canonically encoded: {0}")]
    Encoding(String),
    /// Final common binding validation rejected the fixed point.
    #[error("composed binding plan failed semantic validation: {0}")]
    Validation(#[from] aos_ability_validate::ValidationErrors),
}

/// Resolves and evaluates pure providers until desired state and bindings stabilize.
pub struct RecursiveComposer<'a> {
    context: &'a ValidationContext,
    resolver: Resolver<'a>,
    limits: CompositionLimits,
}

impl<'a> RecursiveComposer<'a> {
    /// Creates a composer under the version-1 recursive and search limits.
    #[must_use]
    pub const fn new(context: &'a ValidationContext) -> Self {
        Self {
            context,
            resolver: Resolver::new(context),
            limits: CompositionLimits {
                max_rounds: 64,
                max_depth: 64,
                max_evaluations: ABILITY_LIMITS_V1.max_graph_nodes,
                max_evaluation_bytes: ABILITY_LIMITS_V1.max_document_bytes,
                max_search_attempts: ABILITY_LIMITS_V1.max_graph_edges as u64,
                max_trace_entries: ABILITY_LIMITS_V1.max_graph_edges,
                max_trace_bytes: ABILITY_LIMITS_V1.max_document_bytes,
            },
        }
    }

    /// Replaces the bounded recursive-evaluation limits.
    ///
    /// # Errors
    ///
    /// Returns an error when a limit is zero or exceeds the version-1 hard
    /// document, graph, or scope ceiling.
    pub fn with_limits(mut self, limits: CompositionLimits) -> Result<Self, CompositionError> {
        if limits.max_rounds == 0
            || limits.max_rounds > ABILITY_LIMITS_V1.max_graph_nodes
            || limits.max_depth == 0
            || limits.max_depth > 64
            || limits.max_evaluations == 0
            || limits.max_evaluations > ABILITY_LIMITS_V1.max_graph_nodes
            || limits.max_evaluation_bytes == 0
            || limits.max_evaluation_bytes > ABILITY_LIMITS_V1.max_document_bytes
            || limits.max_search_attempts == 0
            || limits.max_search_attempts > u64::from(ABILITY_LIMITS_V1.max_graph_edges)
            || limits.max_trace_entries == 0
            || limits.max_trace_entries > ABILITY_LIMITS_V1.max_graph_edges
            || limits.max_trace_bytes == 0
            || limits.max_trace_bytes > ABILITY_LIMITS_V1.max_document_bytes
        {
            return Err(CompositionError::Limit {
                limit: "version-1 composition profile",
            });
        }
        self.limits = limits;
        Ok(self)
    }

    /// Replaces deterministic provider-search limits used by every pass.
    ///
    /// # Errors
    ///
    /// Returns an error when a search or trace limit is outside the version-1
    /// hard profile.
    pub fn with_resolution_limits(
        mut self,
        limits: ResolutionLimits,
    ) -> Result<Self, CompositionError> {
        self.resolver = self.resolver.with_limits(limits)?;
        Ok(self)
    }

    /// Produces a checked fixed point from explicit authenticated policy snapshots.
    ///
    /// Each snapshot must commit to the exact desired state of the pass where it
    /// is used. A fragment cannot derive authorization. When a newly expanded
    /// desired state has no matching snapshot, [`CompositionError::PolicyRequired`]
    /// returns that exact bounded state so orchestration can authorize and replay it.
    ///
    /// # Errors
    ///
    /// Returns an error for missing policy, invalid resolution, evaluator failure,
    /// undeclared or out-of-scope fragment output, conflicting merged identities,
    /// oscillation, exhausted bounds, or final common validation failure.
    pub fn compose(
        &self,
        policies: &[ResolutionPolicyDocument],
        seed: DesiredStateDocument,
        environment: EnvironmentDocument,
        packages: Vec<PackageDocument>,
        evaluator: &mut impl CompositionEvaluator,
    ) -> Result<CompositionOutcome, CompositionError> {
        let environment_digest = environment
            .content_digest()
            .map_err(|error| CompositionError::Encoding(error.to_string()))?;
        let policy_index = index_policies(policies, environment_digest)?;
        let retained_policies = policy_index.values().copied().cloned().collect();
        let package_index = index_packages(&packages)?;
        let seed_digest = seed
            .content_digest()
            .map_err(|error| CompositionError::Encoding(error.to_string()))?;
        let mut evaluations = 0_u32;
        let mut evaluation_bytes = 0_u64;
        let mut evaluation_trace = Vec::new();
        let mut search_attempts = 0_u64;
        let mut trace_budget = TraceBudget::default();
        let mut cursors = vec![0_u64];
        let mut backtrack_rejections: BTreeMap<(u32, Sha256Digest), Vec<CandidateRejection>> =
            BTreeMap::new();

        'search: loop {
            let mut desired_state = seed.clone();
            let mut desired_digest = seed_digest;
            let mut seen = BTreeSet::new();
            let mut passes = Vec::new();
            let mut frames = Vec::new();

            for round in 0..self.limits.max_rounds {
                if !seen.insert(desired_digest) {
                    let error = CompositionError::Oscillation {
                        desired_state: desired_digest,
                    };
                    if advance_backtrack(&frames, &mut cursors, &mut backtrack_rejections, &error) {
                        continue 'search;
                    }
                    return Err(error);
                }
                let Some(policy) = policy_index.get(&desired_digest).copied() else {
                    return Err(CompositionError::PolicyRequired {
                        desired_state: Box::new(desired_state),
                        desired_state_digest: desired_digest,
                        environment: environment_digest,
                    });
                };
                validate_enabled_providers(
                    self.context,
                    policy,
                    &desired_state,
                    &packages,
                    &package_index,
                )?;
                validate_desired_activation_modes(&desired_state, &packages, &package_index)?;

                let cursor = cursors.get(round as usize).copied().unwrap_or_default();
                let draft = self.resolver.resolve_draft_at(
                    policy,
                    &desired_state,
                    &environment,
                    &packages,
                    cursor,
                );
                let mut draft = match draft {
                    Ok(draft) => draft,
                    Err(error @ ResolutionError::NoCandidate) => {
                        retain_search_attempts(&mut search_attempts, 1, self.limits)?;
                        let error = CompositionError::Resolution(error);
                        if advance_backtrack(
                            &frames,
                            &mut cursors,
                            &mut backtrack_rejections,
                            &error,
                        ) {
                            continue 'search;
                        }
                        return Err(error);
                    }
                    Err(error @ ResolutionError::SearchExhausted { attempts }) => {
                        retain_search_attempts(&mut search_attempts, attempts, self.limits)?;
                        let error = CompositionError::Resolution(error);
                        if advance_backtrack(
                            &frames,
                            &mut cursors,
                            &mut backtrack_rejections,
                            &error,
                        ) {
                            continue 'search;
                        }
                        return Err(error);
                    }
                    Err(error @ ResolutionError::CandidateValidation { attempts, .. }) => {
                        retain_search_attempts(&mut search_attempts, attempts, self.limits)?;
                        let error = CompositionError::Resolution(error);
                        if advance_backtrack(
                            &frames,
                            &mut cursors,
                            &mut backtrack_rejections,
                            &error,
                        ) {
                            continue 'search;
                        }
                        return Err(error);
                    }
                    Err(error) => return Err(CompositionError::Resolution(error)),
                };
                retain_search_attempts(&mut search_attempts, draft.attempts, self.limits)?;
                if let Some(rejections) = backtrack_rejections.get(&(round, desired_digest)) {
                    draft.rejections.extend(rejections.iter().cloned());
                }
                frames.push(BacktrackFrame {
                    round,
                    desired_state: desired_digest,
                    next_combination: draft.next_combination,
                    retry_rejection: draft.retry_rejection.clone(),
                });
                trace_budget.retain(
                    trace::BorrowedCompositionPass {
                        round,
                        desired_state: &desired_state,
                        desired_state_digest: desired_digest,
                        policy,
                        policy_digest: draft.policy,
                        decisions: &draft.decisions,
                        rejections: &draft.rejections,
                    },
                    self.limits,
                )?;

                if let Err(error) = validate_provider_lineage(
                    &desired_state,
                    draft.checked.bindings(),
                    self.limits.max_depth,
                ) {
                    if advance_backtrack(&frames, &mut cursors, &mut backtrack_rejections, &error) {
                        continue 'search;
                    }
                    return Err(error);
                }
                if let Err(error) = validate_desired_outputs(
                    self.context,
                    &desired_state,
                    draft.checked.bindings(),
                    &draft.checked.document().resources,
                    &packages,
                    &package_index,
                    &policy.enabled_providers,
                ) {
                    if advance_backtrack(&frames, &mut cursors, &mut backtrack_rejections, &error) {
                        continue 'search;
                    }
                    return Err(error);
                }
                let pass = CompositionPass {
                    round,
                    desired_state: desired_state.clone(),
                    desired_state_digest: desired_digest,
                    policy: policy.clone(),
                    policy_digest: draft.policy,
                    decisions: draft.decisions.clone(),
                    rejections: draft.rejections.clone(),
                };
                passes.push(pass);

                let fragments = evaluate_pure_providers(
                    PureProviderEvaluationInputs {
                        context: self.context,
                        desired_state: &desired_state,
                        bindings: draft.checked.bindings(),
                        enabled_providers: &policy.enabled_providers,
                        packages: &packages,
                        package_index: &package_index,
                    },
                    EvaluationRecorder {
                        evaluator,
                        evaluations: &mut evaluations,
                        bytes: &mut evaluation_bytes,
                        trace: &mut evaluation_trace,
                    },
                    self.limits,
                );
                let fragments = match fragments {
                    Ok(fragments) => fragments,
                    Err(
                        error @ (CompositionError::Evaluation { .. }
                        | CompositionError::InvalidFragment { .. }
                        | CompositionError::MissingImplementation { .. }),
                    ) => {
                        if advance_backtrack(
                            &frames,
                            &mut cursors,
                            &mut backtrack_rejections,
                            &error,
                        ) {
                            continue 'search;
                        }
                        return Err(error);
                    }
                    Err(error) => return Err(error),
                };
                let expanded = match merge_fragments(&seed, fragments) {
                    Ok(expanded) => expanded,
                    Err(error) => {
                        if advance_backtrack(
                            &frames,
                            &mut cursors,
                            &mut backtrack_rejections,
                            &error,
                        ) {
                            continue 'search;
                        }
                        return Err(error);
                    }
                };
                let expanded_digest = expanded
                    .content_digest()
                    .map_err(|error| CompositionError::Encoding(error.to_string()))?;
                if expanded_digest == desired_digest {
                    let resolution = ResolutionOutcome {
                        policy: policy.clone(),
                        policy_digest: draft.policy,
                        decisions: draft.decisions,
                        rejections: draft.rejections,
                        checked: draft.checked,
                    };
                    return Ok(CompositionOutcome {
                        seed,
                        desired_state,
                        policies: retained_policies,
                        evaluations: evaluation_trace,
                        passes,
                        resolution,
                    });
                }
                if seen.contains(&expanded_digest) {
                    let error = CompositionError::Oscillation {
                        desired_state: expanded_digest,
                    };
                    if advance_backtrack(&frames, &mut cursors, &mut backtrack_rejections, &error) {
                        continue 'search;
                    }
                    return Err(error);
                }
                desired_state = expanded;
                desired_digest = expanded_digest;
                if cursors.len() <= round as usize + 1 {
                    cursors.push(0);
                }
            }

            let error = CompositionError::Limit {
                limit: "outer resolution round",
            };
            if advance_backtrack(&frames, &mut cursors, &mut backtrack_rejections, &error) {
                continue 'search;
            }
            return Err(error);
        }
    }
}

struct BacktrackFrame {
    round: u32,
    desired_state: Sha256Digest,
    next_combination: Option<u64>,
    retry_rejection: Option<(RequestId, LocalKey)>,
}

fn advance_backtrack(
    frames: &[BacktrackFrame],
    cursors: &mut Vec<u64>,
    rejections: &mut BTreeMap<(u32, Sha256Digest), Vec<CandidateRejection>>,
    error: &CompositionError,
) -> bool {
    let Some((index, frame)) = frames
        .iter()
        .enumerate()
        .rev()
        .find(|(_, frame)| frame.next_combination.is_some())
    else {
        return false;
    };
    let Some(next_combination) = frame.next_combination else {
        return false;
    };
    cursors.truncate(index.saturating_add(1));
    if cursors.len() <= index {
        cursors.resize(index.saturating_add(1), 0);
    }
    cursors[index] = next_combination;

    if let Some((request, candidate)) = &frame.retry_rejection {
        rejections
            .entry((frame.round, frame.desired_state))
            .or_default()
            .push(CandidateRejection {
                request: request.clone(),
                candidate: candidate.clone(),
                constraint: bounded_constraint(&error.to_string()),
            });
    }
    true
}

fn bounded_constraint(message: &str) -> String {
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

fn retain_search_attempts(
    retained: &mut u64,
    additional: u64,
    limits: CompositionLimits,
) -> Result<(), CompositionError> {
    *retained = retained
        .checked_add(additional)
        .ok_or(CompositionError::Limit {
            limit: "aggregate candidate search attempt",
        })?;
    if *retained > limits.max_search_attempts {
        return Err(CompositionError::Limit {
            limit: "aggregate candidate search attempt",
        });
    }
    Ok(())
}

fn validate_provider_lineage(
    desired_state: &DesiredStateDocument,
    bindings: &[Binding],
    maximum_depth: u32,
) -> Result<(), CompositionError> {
    let in_scope: BTreeSet<_> = desired_state
        .instances
        .iter()
        .map(|desired| desired.instance.clone())
        .chain(
            desired_state
                .child_requests
                .iter()
                .map(|request| request.id.consumer.clone()),
        )
        .chain(bindings.iter().map(|binding| binding.provider.clone()))
        .collect();
    let mut successors: BTreeMap<InstanceId, BTreeSet<InstanceId>> = in_scope
        .iter()
        .cloned()
        .map(|instance| (instance, BTreeSet::new()))
        .collect();
    let mut indegree: BTreeMap<InstanceId, u32> = in_scope
        .iter()
        .cloned()
        .map(|instance| (instance, 0))
        .collect();
    for binding in bindings {
        let consumer = binding.request.consumer.clone();
        let provider = binding.provider.clone();
        if successors
            .entry(consumer)
            .or_default()
            .insert(provider.clone())
        {
            let degree = indegree.entry(provider).or_default();
            *degree = degree.saturating_add(1);
        }
    }

    let mut ready: BTreeSet<_> = indegree
        .iter()
        .filter_map(|(instance, degree)| (*degree == 0).then_some(instance.clone()))
        .collect();
    let mut depths: BTreeMap<InstanceId, u32> = ready
        .iter()
        .cloned()
        .map(|instance| (instance, 0))
        .collect();
    let mut visited = 0_usize;
    while let Some(instance) = ready.pop_first() {
        visited = visited.saturating_add(1);
        let depth = depths.get(&instance).copied().unwrap_or_default();
        for successor in successors.get(&instance).into_iter().flatten() {
            let successor_depth = depth.saturating_add(1);
            if successor_depth > maximum_depth {
                return Err(CompositionError::InvalidFragment {
                    provider: successor.clone(),
                    reason: "provider dependency lineage exceeds the configured composition depth"
                        .to_string(),
                });
            }
            depths
                .entry(successor.clone())
                .and_modify(|current| *current = (*current).max(successor_depth))
                .or_insert(successor_depth);
            let degree =
                indegree
                    .get_mut(successor)
                    .ok_or_else(|| CompositionError::InvalidFragment {
                        provider: successor.clone(),
                        reason: "provider dependency lineage is internally inconsistent"
                            .to_string(),
                    })?;
            *degree = degree.saturating_sub(1);
            if *degree == 0 {
                ready.insert(successor.clone());
            }
        }
    }
    if visited != indegree.len() {
        let provider = indegree
            .into_iter()
            .find_map(|(instance, degree)| (degree != 0).then_some(instance))
            .or_else(|| bindings.first().map(|binding| binding.provider.clone()))
            .ok_or_else(|| {
                CompositionError::Encoding("empty provider lineage reported a cycle".to_string())
            })?;
        return Err(CompositionError::InvalidFragment {
            provider,
            reason: "provider dependency lineage contains a cycle".to_string(),
        });
    }
    Ok(())
}

fn index_policies(
    policies: &[ResolutionPolicyDocument],
    environment: Sha256Digest,
) -> Result<BTreeMap<Sha256Digest, &ResolutionPolicyDocument>, CompositionError> {
    if policies.len() > ABILITY_LIMITS_V1.max_graph_nodes as usize {
        return Err(CompositionError::Limit {
            limit: "policy snapshot count",
        });
    }
    let mut aggregate_bytes = 0_u64;
    let mut index = BTreeMap::new();
    for policy in policies {
        let bytes = encode_canonical(policy)
            .map_err(|error| CompositionError::Encoding(error.to_string()))?;
        aggregate_bytes =
            aggregate_bytes
                .checked_add(bytes.len() as u64)
                .ok_or(CompositionError::Limit {
                    limit: "policy snapshot aggregate byte",
                })?;
        if aggregate_bytes > ABILITY_LIMITS_V1.max_document_bytes {
            return Err(CompositionError::Limit {
                limit: "policy snapshot aggregate byte",
            });
        }
        if policy.environment != environment {
            return Err(CompositionError::Encoding(
                "policy snapshot commits to a different environment".to_string(),
            ));
        }
        if index.insert(policy.desired_state, policy).is_some() {
            return Err(CompositionError::Encoding(
                "multiple policy snapshots commit to one desired state".to_string(),
            ));
        }
    }
    Ok(index)
}

fn index_packages(
    packages: &[PackageDocument],
) -> Result<BTreeMap<Sha256Digest, usize>, CompositionError> {
    if packages.len() > ABILITY_LIMITS_V1.max_graph_nodes as usize {
        return Err(CompositionError::Limit {
            limit: "package input count",
        });
    }
    let mut aggregate_bytes = 0_u64;
    let mut index = BTreeMap::new();
    for (position, package) in packages.iter().enumerate() {
        let bytes = encode_canonical(package)
            .map_err(|error| CompositionError::Encoding(error.to_string()))?;
        aggregate_bytes =
            aggregate_bytes
                .checked_add(bytes.len() as u64)
                .ok_or(CompositionError::Limit {
                    limit: "package input aggregate byte",
                })?;
        if aggregate_bytes > ABILITY_LIMITS_V1.max_document_bytes {
            return Err(CompositionError::Limit {
                limit: "package input aggregate byte",
            });
        }
        let digest = Sha256Digest::separated(PackageDocument::SCHEMA, bytes);
        if index.insert(digest, position).is_some() {
            return Err(CompositionError::Encoding(
                "duplicate exact package input".to_string(),
            ));
        }
    }
    Ok(index)
}
