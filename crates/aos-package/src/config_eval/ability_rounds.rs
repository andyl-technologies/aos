//! Bounded outer resolution rounds for provider-derived ability requests.
//!
//! One round evaluates the complete standard AOS module fixed point. The
//! evaluation either returns its final manifest or exposes the internal child
//! requests that still need bindings. The resolver selects those bindings and
//! their authenticated provider modules, then the next round reevaluates the
//! complete fixed point from the original module inputs plus that monotone
//! selection state. Child declarations are never copied into the public
//! request graph.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use anyhow::Result;
use aos_ability_model::{
    ABILITY_LIMITS_V1, AbilityValue, ArtifactReference, LocalKey, ModuleLocator,
    RequirementDeclaration,
};
use aos_ability_validate::PackageOutputSelector;
use aos_contract::{Sha256Digest, canonical};
use serde::{Deserialize, Serialize};

use super::PackageOutputs;

/// Carries one provider-derived child request awaiting an outer binding round.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingAbilityRequest {
    /// Identifies the exact selected implementation/provider-instance group.
    pub origin_group: String,
    /// Names the request within its provider module.
    pub local_request_key: String,
    /// Names the selected implementation that emitted the request.
    pub implementation: String,
    /// Names the selected provider instance that emitted the request.
    pub provider_instance: String,
    /// Names the emitting implementation's nested requirement alias.
    pub requirement: String,
    /// Names the package-authored aggregation slot for the child request.
    pub slot: String,
    /// Carries the deterministic globally qualified request key.
    pub request: String,
    /// Retains the exact internally derived request declaration.
    pub declaration: AbilityValue,
}

/// Retains one exact nested requirement activated by provider composition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingAbilityRequirement {
    /// Names the requirement inside the selected implementation.
    pub alias: String,
    /// Names the exact selected implementation that activated it.
    pub implementation: String,
    /// Carries the canonical signed-package requirement contract.
    pub requirement: RequirementDeclaration,
}

/// Carries the unresolved child projection from one complete module evaluation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingAbilityProjection {
    /// Maps each exact qualified request key to its origin and declaration.
    pub requests: BTreeMap<String, PendingAbilityRequest>,
    /// Retains exact nested requirement declarations keyed by derived identity.
    pub requirements: BTreeMap<String, PendingAbilityRequirement>,
    /// Maps each available provider instance to its selected implementation.
    pub provider_instances: BTreeMap<String, PendingProviderInstance>,
}

/// Retains the provider selection relevant to one unresolved child request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingProviderInstance {
    /// Names the exact implementation instantiated by this provider.
    pub implementation: Option<String>,
}

/// Carries the activation authority emitted by the final module fixed point.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AbilityFixedPointProjection {
    /// Retains exact selected bindings after all provider expansion rounds.
    pub bindings: BTreeMap<String, AbilityValue>,
    /// Retains exact desired and published resource projections.
    pub resolved_resources: BTreeMap<String, AbilityValue>,
}

impl AbilityFixedPointProjection {
    fn validate(&self) -> Result<(), AbilityRoundError> {
        if self.bindings.len() as u64 > ABILITY_LIMITS_V1.max_collection_items
            || self.resolved_resources.len() as u64 > ABILITY_LIMITS_V1.max_collection_items
        {
            return Err(AbilityRoundError::Limit {
                limit: "final fixed-point item",
            });
        }
        if self
            .bindings
            .keys()
            .chain(self.resolved_resources.keys())
            .any(|key| key.is_empty() || key.len() as u64 > ABILITY_LIMITS_V1.max_string_bytes)
        {
            return Err(AbilityRoundError::InvalidProjection {
                reason: "final fixed-point key is empty or exceeds its bound".to_string(),
            });
        }

        encoded_digest("aos.ability.fixed-point-projection/v1", self).map(|_| ())
    }
}

/// Returns the manifest and activation authority from one complete round.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteAbilityRound {
    /// Carries the final configuration manifest JSON.
    pub manifest: String,
    /// Carries the exact final module fixed-point projection.
    pub fixed_point: AbilityFixedPointProjection,
}

impl PendingAbilityProjection {
    fn validate(&self) -> Result<(), AbilityRoundError> {
        if self.requests.len() as u64 > ABILITY_LIMITS_V1.max_collection_items {
            return Err(AbilityRoundError::Limit {
                limit: "pending child request count",
            });
        }
        if self.requirements.len() as u64 > ABILITY_LIMITS_V1.max_collection_items
            || self.provider_instances.len() as u64 > ABILITY_LIMITS_V1.max_collection_items
        {
            return Err(AbilityRoundError::Limit {
                limit: "pending child selection input count",
            });
        }
        for (instance, selected) in &self.provider_instances {
            if instance.is_empty()
                || instance.len() as u64 > ABILITY_LIMITS_V1.max_string_bytes
                || selected
                    .implementation
                    .as_ref()
                    .is_some_and(|implementation| {
                        implementation.is_empty()
                            || implementation.len() as u64 > ABILITY_LIMITS_V1.max_string_bytes
                    })
            {
                return Err(AbilityRoundError::InvalidProjection {
                    reason: "provider instance selection is empty or exceeds its bound".to_string(),
                });
            }
        }

        for (key, request) in &self.requests {
            if key != &request.request {
                return Err(AbilityRoundError::InvalidProjection {
                    reason: format!(
                        "pending child request map key {key:?} differs from its request identity {:?}",
                        request.request
                    ),
                });
            }
            for (field, value) in [
                ("origin group", request.origin_group.as_str()),
                ("implementation", request.implementation.as_str()),
                ("provider instance", request.provider_instance.as_str()),
                ("request", request.request.as_str()),
            ] {
                if value.is_empty() || value.len() as u64 > ABILITY_LIMITS_V1.max_string_bytes {
                    return Err(AbilityRoundError::InvalidProjection {
                        reason: format!("pending child {field} is empty or exceeds its bound"),
                    });
                }
            }
            for (field, value) in [
                ("local request key", request.local_request_key.as_str()),
                ("requirement", request.requirement.as_str()),
                ("slot", request.slot.as_str()),
            ] {
                if LocalKey::new(value.to_string()).is_err() {
                    return Err(AbilityRoundError::InvalidProjection {
                        reason: format!("pending child {field} is not a canonical local key"),
                    });
                }
            }
            let declaration = request.declaration.as_json();
            let requirement_key = declaration
                .get("requirement")
                .and_then(|value| value.as_str());
            let consumer = declaration.get("consumer").and_then(|value| value.as_str());
            let Some(requirement) = requirement_key.and_then(|key| self.requirements.get(key))
            else {
                return Err(AbilityRoundError::InvalidProjection {
                    reason: format!(
                        "pending child request {:?} names an absent nested requirement",
                        request.request
                    ),
                });
            };
            if requirement.implementation != request.implementation
                || requirement.alias != request.requirement
                || requirement.requirement.alias.as_str() != request.requirement
                || consumer != Some(request.provider_instance.as_str())
            {
                return Err(AbilityRoundError::InvalidProjection {
                    reason: format!(
                        "pending child request {:?} disagrees with its exact origin or requirement",
                        request.request
                    ),
                });
            }
        }

        encoded_digest("aos.ability.pending-child-projection/v1", self).map(|_| ())
    }
}

/// Carries the exact binding value injected by an outer resolution round.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedAbilityBinding {
    /// Names the binding in the final module option graph.
    pub key: String,
    /// Names the exact pending child request selected by this binding.
    pub request: String,
    /// Names the selected implementation declaration.
    pub implementation: String,
    /// Names the selected provider instance declaration.
    pub provider_instance: String,
    /// Names the authorized aggregation slot.
    pub slot: String,
    /// Supplies the authenticated provider module, when this implementation has one.
    pub provider_module: Option<SelectedProviderModule>,
}

/// Supplies one resolver-authenticated provider module to the standard evaluator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedProviderModule {
    /// Names the package whose implementation selected this module.
    pub package: String,
    /// Retains the exact authenticated package version supplying the module.
    pub version: String,
    /// Locates the module below its exact authenticated artifact root.
    pub locator: ModuleLocator,
    /// Supplies only the package outputs authorized by release dependency metadata.
    pub outputs: PackageOutputs,
    /// Maps reachable symbolic outputs to authenticated artifacts for pure projection.
    pub artifact_locators: BTreeMap<PackageOutputSelector, ArtifactReference>,
}

/// Retains the monotone selections supplied to each complete module evaluation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AbilityRoundSelections {
    pub(super) bindings: BTreeMap<String, SelectedAbilityBinding>,
    pub(super) provider_modules: BTreeMap<String, SelectedProviderModule>,
}

impl AbilityRoundSelections {
    /// Returns selected bindings in deterministic binding-key order.
    #[must_use]
    pub const fn bindings(&self) -> &BTreeMap<String, SelectedAbilityBinding> {
        &self.bindings
    }

    /// Returns authenticated provider modules in deterministic locator order.
    #[must_use]
    pub fn provider_modules(&self) -> impl Iterator<Item = &SelectedProviderModule> {
        self.provider_modules.values()
    }
}

/// Reports one complete standard module fixed-point evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AbilityRoundEvaluation {
    /// The module graph converged and returned its final activation authority.
    Complete(CompleteAbilityRound),
    /// Provider composition exposed unresolved internal child requests.
    Pending(PendingAbilityProjection),
}

/// Evaluates the complete standard module graph for one outer round.
pub trait AbilityRoundEvaluator {
    /// Re-evaluates the original module inputs with the exact accumulated selections.
    ///
    /// Implementations import only [`AbilityRoundSelections::provider_modules`]
    /// and inject only [`AbilityRoundSelections::bindings`]. They must return
    /// the module driver's internal pending projection rather than copying its
    /// requests into public `aos.abilities.requests`.
    ///
    /// # Errors
    ///
    /// Returns an error when the complete module fixed point cannot be evaluated.
    fn evaluate(
        &self,
        round: u32,
        selections: &AbilityRoundSelections,
    ) -> Result<AbilityRoundEvaluation>;
}

/// Selects exact providers for one complete unresolved child projection.
pub trait AbilityRoundResolver {
    /// Returns exactly one binding for every pending request and no other binding.
    ///
    /// # Errors
    ///
    /// Returns an error when an authenticated provider cannot be selected or
    /// its provider-module artifact cannot be materialized.
    fn select(&self, pending: &PendingAbilityProjection) -> Result<Vec<SelectedAbilityBinding>>;
}

/// Records one bounded outer resolution step for deterministic diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbilityRoundTrace {
    /// Gives the zero-based complete-evaluation round.
    pub round: u32,
    /// Identifies the exact pending projection observed in that round.
    pub pending: Sha256Digest,
    /// Lists pending request keys in canonical order.
    pub requests: Vec<String>,
    /// Lists newly selected binding keys in canonical order.
    pub bindings: Vec<String>,
}

/// Returns the converged manifest and the exact outer-resolution trace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbilityRoundOutcome {
    /// Carries the final manifest JSON from the authoritative fixed point.
    pub manifest: String,
    /// Carries exact bindings and resources from the authoritative fixed point.
    pub fixed_point: AbilityFixedPointProjection,
    /// Retains every nonfinal provider-selection round.
    pub trace: Vec<AbilityRoundTrace>,
    /// Retains the exact bindings and modules admitted into the final round.
    pub selections: AbilityRoundSelections,
}

/// Reports why bounded outer ability resolution could not converge.
#[derive(Debug)]
pub enum AbilityRoundError {
    /// The complete standard module evaluation failed.
    Evaluation {
        /// Gives the zero-based outer round.
        round: u32,
        /// Retains the evaluator failure.
        source: anyhow::Error,
    },
    /// Authenticated provider selection or module materialization failed.
    Resolution {
        /// Gives the zero-based outer round.
        round: u32,
        /// Retains the resolver failure.
        source: anyhow::Error,
    },
    /// The evaluator returned malformed or inconsistent pending provenance.
    InvalidProjection {
        /// Describes the first rejected invariant.
        reason: String,
    },
    /// The resolver did not return an exact one-to-one selection.
    InvalidSelection {
        /// Describes the first rejected invariant.
        reason: String,
    },
    /// The immediately preceding unresolved projection recurred unchanged.
    Cycle {
        /// Identifies the repeated pending projection.
        pending: Sha256Digest,
    },
    /// A prior nonadjacent unresolved projection recurred.
    Oscillation {
        /// Identifies the repeated pending projection.
        pending: Sha256Digest,
    },
    /// A version-1 structural or round bound was exhausted.
    Limit {
        /// Names the exhausted dimension.
        limit: &'static str,
    },
}

impl fmt::Display for AbilityRoundError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Evaluation { round, source } => {
                write!(
                    formatter,
                    "ability module evaluation failed in round {round}: {source:#}"
                )
            }
            Self::Resolution { round, source } => write!(
                formatter,
                "ability provider resolution failed in round {round}: {source:#}"
            ),
            Self::InvalidProjection { reason } => {
                write!(formatter, "invalid pending ability projection: {reason}")
            }
            Self::InvalidSelection { reason } => {
                write!(formatter, "invalid ability provider selection: {reason}")
            }
            Self::Cycle { pending } => write!(
                formatter,
                "ability provider expansion cycle repeated pending projection {pending}"
            ),
            Self::Oscillation { pending } => write!(
                formatter,
                "ability provider expansion oscillated at pending projection {pending}"
            ),
            Self::Limit { limit } => write!(
                formatter,
                "ability provider resolution exceeds the configured {limit} limit"
            ),
        }
    }
}

impl std::error::Error for AbilityRoundError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Evaluation { source, .. } | Self::Resolution { source, .. } => {
                Some(source.as_ref())
            }
            _ => None,
        }
    }
}

/// Runs bounded provider selection around repeated complete module evaluations.
///
/// # Errors
///
/// Returns an error for evaluator or resolver failure, malformed pending data,
/// inexact or nonmonotone selection, a cycle or oscillation, or exhaustion of
/// the RFC-0022 version-1 provider-resolution bound.
pub fn resolve_ability_rounds(
    evaluator: &impl AbilityRoundEvaluator,
    resolver: &impl AbilityRoundResolver,
    max_rounds: u32,
) -> Result<AbilityRoundOutcome, AbilityRoundError> {
    if max_rounds == 0 || max_rounds > ABILITY_LIMITS_V1.max_resolver_rounds {
        return Err(AbilityRoundError::Limit {
            limit: "outer resolution round",
        });
    }

    let mut selections = AbilityRoundSelections::default();
    let mut seen = BTreeMap::new();
    let mut trace = Vec::new();

    for round in 0..max_rounds {
        let pending = match evaluator
            .evaluate(round, &selections)
            .map_err(|source| AbilityRoundError::Evaluation { round, source })?
        {
            AbilityRoundEvaluation::Complete(complete) => {
                complete.fixed_point.validate()?;
                return Ok(AbilityRoundOutcome {
                    manifest: complete.manifest,
                    fixed_point: complete.fixed_point,
                    trace,
                    selections,
                });
            }
            AbilityRoundEvaluation::Pending(pending) => pending,
        };

        pending.validate()?;
        if pending.requests.is_empty() {
            return Err(AbilityRoundError::InvalidProjection {
                reason: "a pending round contains no requests".to_string(),
            });
        }
        let digest = encoded_digest("aos.ability.pending-child-projection/v1", &pending)?;
        if let Some(previous_round) = seen.insert(digest, round) {
            return Err(if previous_round + 1 == round {
                AbilityRoundError::Cycle { pending: digest }
            } else {
                AbilityRoundError::Oscillation { pending: digest }
            });
        }
        if round + 1 == max_rounds {
            return Err(AbilityRoundError::Limit {
                limit: "outer resolution round",
            });
        }

        let selected = resolver
            .select(&pending)
            .map_err(|source| AbilityRoundError::Resolution { round, source })?;
        validate_and_extend(&pending, selected, &mut selections)?;

        let requests = pending.requests.keys().cloned().collect();
        let bindings = selections
            .bindings
            .iter()
            .filter_map(|(key, binding)| {
                pending
                    .requests
                    .contains_key(&binding.request)
                    .then(|| key.clone())
            })
            .collect();
        trace.push(AbilityRoundTrace {
            round,
            pending: digest,
            requests,
            bindings,
        });
    }

    Err(AbilityRoundError::Limit {
        limit: "outer resolution round",
    })
}

fn validate_and_extend(
    pending: &PendingAbilityProjection,
    selected: Vec<SelectedAbilityBinding>,
    state: &mut AbilityRoundSelections,
) -> Result<(), AbilityRoundError> {
    let mut by_request = BTreeMap::new();
    let mut binding_keys = BTreeSet::new();
    for binding in selected {
        let Some(pending_request) = pending.requests.get(&binding.request) else {
            return Err(AbilityRoundError::InvalidSelection {
                reason: format!(
                    "binding {:?} selects a request outside the current pending projection",
                    binding.key
                ),
            });
        };
        if binding.key.is_empty()
            || binding.request.is_empty()
            || binding.implementation.is_empty()
            || binding.provider_instance.is_empty()
            || LocalKey::new(binding.slot.clone()).is_err()
        {
            return Err(AbilityRoundError::InvalidSelection {
                reason: "a selected binding contains an empty identity component".to_string(),
            });
        }
        if binding.slot != pending_request.slot {
            return Err(AbilityRoundError::InvalidSelection {
                reason: format!(
                    "binding {:?} changes the package-authored slot for pending request {:?}",
                    binding.key, binding.request
                ),
            });
        }
        if !binding_keys.insert(binding.key.clone()) {
            return Err(AbilityRoundError::InvalidSelection {
                reason: format!("binding key {:?} was selected more than once", binding.key),
            });
        }
        if by_request
            .insert(binding.request.clone(), binding)
            .is_some()
        {
            return Err(AbilityRoundError::InvalidSelection {
                reason: "one pending request received several bindings".to_string(),
            });
        }
    }

    let pending_keys = pending.requests.keys().collect::<BTreeSet<_>>();
    let selected_keys = by_request.keys().collect::<BTreeSet<_>>();
    if pending_keys != selected_keys {
        return Err(AbilityRoundError::InvalidSelection {
            reason: "selected bindings do not exactly cover the current pending requests"
                .to_string(),
        });
    }

    for (_, binding) in by_request {
        if state.bindings.contains_key(&binding.key)
            || state
                .bindings
                .values()
                .any(|existing| existing.request == binding.request)
        {
            return Err(AbilityRoundError::InvalidSelection {
                reason: format!(
                    "selection for pending request {:?} is not a monotone addition",
                    binding.request
                ),
            });
        }
        if let Some(module) = &binding.provider_module {
            if module.package.is_empty() || module.outputs.self_output.is_none() {
                return Err(AbilityRoundError::InvalidSelection {
                    reason: "a selected provider module lacks package provenance or its authenticated self output"
                        .to_string(),
                });
            }
            if module.artifact_locators.values().any(|artifact| {
                artifact.store_path.is_empty()
                    || artifact.store_path.len() as u64 > ABILITY_LIMITS_V1.max_string_bytes
            }) {
                return Err(AbilityRoundError::InvalidSelection {
                    reason: "a selected provider module has an invalid artifact locator"
                        .to_string(),
                });
            }
            let key = selected_module_key(module)?;
            if let Some(existing) = state.provider_modules.get(&key) {
                if existing != module {
                    return Err(AbilityRoundError::InvalidSelection {
                        reason: format!(
                            "selected provider module {key} changed its authenticated outputs"
                        ),
                    });
                }
            } else {
                state.provider_modules.insert(key, module.clone());
            }
        }
        state.bindings.insert(binding.key.clone(), binding);
    }
    if state.bindings.len() as u32 > ABILITY_LIMITS_V1.max_graph_edges {
        return Err(AbilityRoundError::Limit {
            limit: "selected child binding count",
        });
    }

    Ok(())
}

fn selected_module_key(module: &SelectedProviderModule) -> Result<String, AbilityRoundError> {
    Sha256Digest::of_canonical(
        "aos.ability.selected-provider-module/v1",
        &(module.package.as_str(), &module.locator),
    )
    .map(|digest| digest.to_string())
    .map_err(|error| AbilityRoundError::InvalidSelection {
        reason: format!("selected provider module cannot be encoded: {error}"),
    })
}

fn encoded_digest<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<Sha256Digest, AbilityRoundError> {
    let encoded =
        canonical::to_vec(value).map_err(|error| AbilityRoundError::InvalidProjection {
            reason: format!("ability round value cannot be canonically encoded: {error}"),
        })?;
    if encoded.len() as u64 > ABILITY_LIMITS_V1.max_document_bytes {
        return Err(AbilityRoundError::Limit {
            limit: "pending child projection byte",
        });
    }
    Sha256Digest::of_canonical(domain, value).map_err(|error| {
        AbilityRoundError::InvalidProjection {
            reason: error.to_string(),
        }
    })
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::{BTreeMap, VecDeque};

    use anyhow::bail;
    use aos_ability_model::{ArtifactReference, RelativePath, RequirementStrength};

    use super::*;

    struct ScriptedEvaluation {
        script: RefCell<VecDeque<AbilityRoundEvaluation>>,
        seen: RefCell<Vec<AbilityRoundSelections>>,
    }

    impl ScriptedEvaluation {
        fn new(script: Vec<AbilityRoundEvaluation>) -> Self {
            Self {
                script: RefCell::new(script.into()),
                seen: RefCell::new(Vec::new()),
            }
        }
    }

    impl AbilityRoundEvaluator for ScriptedEvaluation {
        fn evaluate(
            &self,
            _round: u32,
            selections: &AbilityRoundSelections,
        ) -> Result<AbilityRoundEvaluation> {
            self.seen.borrow_mut().push(selections.clone());
            self.script
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("evaluation script exhausted"))
        }
    }

    struct ExactResolver;

    impl AbilityRoundResolver for ExactResolver {
        fn select(
            &self,
            pending: &PendingAbilityProjection,
        ) -> Result<Vec<SelectedAbilityBinding>> {
            Ok(pending
                .requests
                .values()
                .map(|request| selected(&request.request, &request.slot))
                .collect())
        }
    }

    struct MissingResolver;

    impl AbilityRoundResolver for MissingResolver {
        fn select(
            &self,
            _pending: &PendingAbilityProjection,
        ) -> Result<Vec<SelectedAbilityBinding>> {
            Ok(Vec::new())
        }
    }

    struct FailingResolver;

    impl AbilityRoundResolver for FailingResolver {
        fn select(
            &self,
            _pending: &PendingAbilityProjection,
        ) -> Result<Vec<SelectedAbilityBinding>> {
            bail!("no authenticated provider")
        }
    }

    fn complete(manifest: &str) -> AbilityRoundEvaluation {
        complete_with_fixed_point(manifest, AbilityFixedPointProjection::default())
    }

    fn complete_with_fixed_point(
        manifest: &str,
        fixed_point: AbilityFixedPointProjection,
    ) -> AbilityRoundEvaluation {
        AbilityRoundEvaluation::Complete(CompleteAbilityRound {
            manifest: manifest.to_string(),
            fixed_point,
        })
    }

    #[test]
    fn complete_first_round_imports_nothing() {
        let evaluator = ScriptedEvaluation::new(vec![complete("{\"manifest\":true}")]);

        let outcome = resolve_ability_rounds(&evaluator, &ExactResolver, 4)
            .expect("an already-complete module graph converges");

        assert!(outcome.trace.is_empty());
        assert!(outcome.selections.bindings().is_empty());
        assert_eq!(
            evaluator.seen.borrow().as_slice(),
            &[AbilityRoundSelections::default()]
        );
    }

    #[test]
    fn complete_round_retains_the_exact_fixed_point_projection() {
        let projection = AbilityFixedPointProjection {
            bindings: BTreeMap::from([(
                "consumer:storage".to_string(),
                AbilityValue::new(serde_json::json!({"implementation": "provider:storage"}))
                    .expect("test binding is bounded"),
            )]),
            resolved_resources: BTreeMap::from([(
                "provider:state".to_string(),
                AbilityValue::new(serde_json::json!({"kind": "aos.storage.instance"}))
                    .expect("test resource is bounded"),
            )]),
        };
        let evaluator = ScriptedEvaluation::new(vec![complete_with_fixed_point(
            "{\"manifest\":true}",
            projection.clone(),
        )]);

        let outcome = resolve_ability_rounds(&evaluator, &ExactResolver, 4)
            .expect("a complete projection is retained");

        assert_eq!(outcome.fixed_point, projection);
    }

    #[test]
    fn complete_round_rejects_an_invalid_fixed_point_key() {
        let projection = AbilityFixedPointProjection {
            bindings: BTreeMap::from([(
                String::new(),
                AbilityValue::new(serde_json::json!(true)).expect("test value is bounded"),
            )]),
            resolved_resources: BTreeMap::new(),
        };
        let evaluator = ScriptedEvaluation::new(vec![complete_with_fixed_point("{}", projection)]);

        let error = resolve_ability_rounds(&evaluator, &ExactResolver, 4)
            .expect_err("invalid final authority must fail before activation");

        assert!(matches!(error, AbilityRoundError::InvalidProjection { .. }));
    }

    #[test]
    fn pending_requests_add_only_their_bindings_and_selected_modules() {
        let evaluator = ScriptedEvaluation::new(vec![
            AbilityRoundEvaluation::Pending(pending(&["child-a", "child-b"])),
            complete("{\"manifest\":true}"),
        ]);

        let outcome = resolve_ability_rounds(&evaluator, &ExactResolver, 4)
            .expect("one provider-selection round converges");

        assert_eq!(outcome.trace.len(), 1);
        assert_eq!(outcome.selections.bindings().len(), 2);
        assert_eq!(outcome.selections.provider_modules().count(), 1);
        let seen = evaluator.seen.borrow();
        assert!(seen[0].bindings().is_empty());
        assert_eq!(seen[1], outcome.selections);
    }

    #[test]
    fn resolver_must_cover_every_current_request_exactly() {
        let evaluator =
            ScriptedEvaluation::new(vec![AbilityRoundEvaluation::Pending(pending(&["child-a"]))]);

        let error = resolve_ability_rounds(&evaluator, &MissingResolver, 4)
            .expect_err("an incomplete selection must fail closed");

        assert!(matches!(error, AbilityRoundError::InvalidSelection { .. }));
    }

    #[test]
    fn resolver_cannot_change_the_package_authored_slot() {
        struct ChangedSlotResolver;

        impl AbilityRoundResolver for ChangedSlotResolver {
            fn select(
                &self,
                pending: &PendingAbilityProjection,
            ) -> Result<Vec<SelectedAbilityBinding>> {
                Ok(pending
                    .requests
                    .keys()
                    .map(|request| selected(request, "changed-slot"))
                    .collect())
            }
        }

        let evaluator =
            ScriptedEvaluation::new(vec![AbilityRoundEvaluation::Pending(pending(&["child-a"]))]);

        let error = resolve_ability_rounds(&evaluator, &ChangedSlotResolver, 4)
            .expect_err("provider selection must retain the child request slot");

        assert!(matches!(error, AbilityRoundError::InvalidSelection { .. }));
    }

    #[test]
    fn resolver_failure_retains_its_round() {
        let evaluator =
            ScriptedEvaluation::new(vec![AbilityRoundEvaluation::Pending(pending(&["child-a"]))]);

        let error = resolve_ability_rounds(&evaluator, &FailingResolver, 4)
            .expect_err("a provider lookup failure is terminal");

        assert!(matches!(
            error,
            AbilityRoundError::Resolution { round: 0, .. }
        ));
    }

    #[test]
    fn immediate_repeat_is_a_cycle() {
        let repeated = pending(&["child-a"]);
        let evaluator = ScriptedEvaluation::new(vec![
            AbilityRoundEvaluation::Pending(repeated.clone()),
            AbilityRoundEvaluation::Pending(repeated),
        ]);

        let error = resolve_ability_rounds(&evaluator, &ExactResolver, 4)
            .expect_err("an unchanged unresolved projection must fail");

        assert!(matches!(error, AbilityRoundError::Cycle { .. }));
    }

    #[test]
    fn nonadjacent_repeat_is_an_oscillation() {
        let first = pending(&["child-a"]);
        let second = pending(&["child-b"]);
        let evaluator = ScriptedEvaluation::new(vec![
            AbilityRoundEvaluation::Pending(first.clone()),
            AbilityRoundEvaluation::Pending(second),
            AbilityRoundEvaluation::Pending(first),
        ]);

        let error = resolve_ability_rounds(&evaluator, &ExactResolver, 4)
            .expect_err("alternating pending projections must fail");

        assert!(matches!(error, AbilityRoundError::Oscillation { .. }));
    }

    #[test]
    fn distinct_expansion_exhausts_the_shared_round_limit() {
        let evaluator = ScriptedEvaluation::new(vec![
            AbilityRoundEvaluation::Pending(pending(&["child-a"])),
            AbilityRoundEvaluation::Pending(pending(&["child-b"])),
        ]);

        let error = resolve_ability_rounds(&evaluator, &ExactResolver, 2)
            .expect_err("a nonconverged final allowed round must fail");

        assert!(matches!(
            error,
            AbilityRoundError::Limit {
                limit: "outer resolution round"
            }
        ));
    }

    #[test]
    fn invalid_requested_round_limit_fails_before_evaluation() {
        let evaluator = ScriptedEvaluation::new(Vec::new());

        assert!(matches!(
            resolve_ability_rounds(&evaluator, &ExactResolver, 0),
            Err(AbilityRoundError::Limit { .. })
        ));
        assert!(matches!(
            resolve_ability_rounds(
                &evaluator,
                &ExactResolver,
                ABILITY_LIMITS_V1.max_resolver_rounds + 1,
            ),
            Err(AbilityRoundError::Limit { .. })
        ));
        assert!(evaluator.seen.borrow().is_empty());
    }

    fn pending(requests: &[&str]) -> PendingAbilityProjection {
        PendingAbilityProjection {
            requests: requests
                .iter()
                .map(|request| {
                    (
                        (*request).to_string(),
                        PendingAbilityRequest {
                            origin_group: "origin".to_string(),
                            local_request_key: (*request).to_string(),
                            implementation: "provider:recursive".to_string(),
                            provider_instance: "provider:instance".to_string(),
                            requirement: "lower".to_string(),
                            slot: "main".to_string(),
                            request: (*request).to_string(),
                            declaration: AbilityValue::new(serde_json::json!({
                                "package": null,
                                "requirement": "derived:lower",
                                "consumer": "provider:instance",
                                "scope": [],
                                "parameters": {"enabled": true},
                            }))
                            .expect("test request declaration is bounded"),
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>(),
            requirements: BTreeMap::from([(
                "derived:lower".to_string(),
                PendingAbilityRequirement {
                    alias: "lower".to_string(),
                    implementation: "provider:recursive".to_string(),
                    requirement: RequirementDeclaration {
                        description: "Describes this child requirement.".to_string(),
                        alias: LocalKey::new("lower".to_string()).expect("test requirement alias"),
                        accepted_interfaces: Vec::new(),
                        methods: Vec::new(),
                        guarantees: Vec::new(),
                        strength: RequirementStrength::Required,
                        fallback: None,
                    },
                },
            )]),
            provider_instances: BTreeMap::from([(
                "provider:instance".to_string(),
                PendingProviderInstance {
                    implementation: Some("provider:recursive".to_string()),
                },
            )]),
        }
    }

    fn selected(request: &str, slot: &str) -> SelectedAbilityBinding {
        SelectedAbilityBinding {
            key: format!("binding-{request}"),
            request: request.to_string(),
            implementation: "lower:implementation".to_string(),
            provider_instance: "lower:instance".to_string(),
            slot: slot.to_string(),
            provider_module: Some(SelectedProviderModule {
                package: "lower".to_string(),
                version: "1.0.0".to_string(),
                locator: ModuleLocator {
                    artifact: ArtifactReference {
                        content: Sha256Digest::of_bytes("provider-module"),
                        store_path: "/nix/store/provider-module".to_string(),
                        nar_hash: Sha256Digest::of_bytes("provider-module-nar"),
                        closure: Sha256Digest::of_bytes("provider-module-closure"),
                    },
                    path: RelativePath::new("provider.nix").expect("test provider module path"),
                },
                outputs: PackageOutputs {
                    self_output: Some("/nix/store/lower".to_string()),
                    dependencies: BTreeMap::new(),
                },
                artifact_locators: BTreeMap::new(),
            }),
        }
    }
}
