//! Provider-authored construction of checked finite effect plans.
//!
//! The transition planner invokes each selected pure implementation exact
//! transition entry against scoped current and desired state, lowers explicit
//! checked-binding boundaries, and validates the complete finite effect graph.
//! This module performs no runtime effects.

mod context;
mod graph;
mod snapshot;

use std::collections::BTreeSet;
use std::io::{self, Write};

use aos_ability_model::{ABILITY_LIMITS_V1, AbilityValue, InstanceId};
use aos_ability_validate::{CheckedEffectPlan, ValidationContext, ValidationErrors};
use serde::Serialize;
use thiserror::Error;

use crate::{CompositionEvaluator, VerifiedPlanningSnapshot};

use context::{
    bounded_evaluation_message, controller_union, encode_ability_value, resource_changes,
    scoped_desired_state, scoped_observations,
};
use graph::{
    AuthoredTransitionFragment, index_packages, merge_fragments, operation_scope,
    package_for_group, pure_transition, transition_groups, validate_fragment,
};

pub use context::{
    ResourceChange, ResourceChangeKind, ScopedDesiredState, ScopedObservations,
    TRANSITION_CONTEXT_SCHEMA, TransitionContext,
};
pub use graph::{
    TRANSITION_FRAGMENT_SCHEMA, TransitionExport, TransitionExportKind, TransitionFragment,
    TransitionImport, TransitionImportDirection, TransitionLink,
};
pub use snapshot::{
    TRANSITION_SNAPSHOT_MAX_BYTES, TRANSITION_SNAPSHOT_SCHEMA, TransitionEvaluation,
    TransitionEvaluationResult, TransitionReplayInputs, TransitionSnapshot,
    TransitionSnapshotError, VerifiedTransitionPlan,
};

/// Supplies the independently verified planning states used for a transition.
pub struct TransitionInputs<'a> {
    /// Supplies the prior verified planning state, absent for first activation.
    ///
    /// This proves prior identity and desired state. It does not keep historical
    /// grants live: teardown effects still require exact bindings authorized by
    /// the desired checked plan.
    pub current: Option<&'a VerifiedPlanningSnapshot>,
}

/// Bounds pure transition evaluation and the merged effect graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionLimits {
    /// Limits selected pure transition entries evaluated once per implementation.
    pub max_evaluations: u32,
    /// Limits aggregate canonical transition context and fragment bytes.
    pub max_evaluation_bytes: u64,
    /// Limits operations, decisions, and merges across the complete plan.
    pub max_graph_nodes: u32,
    /// Limits typed dependency edges across the complete plan.
    pub max_graph_edges: u32,
}

impl Default for TransitionLimits {
    fn default() -> Self {
        Self {
            max_evaluations: ABILITY_LIMITS_V1.max_graph_nodes,
            max_evaluation_bytes: ABILITY_LIMITS_V1.max_document_bytes,
            max_graph_nodes: ABILITY_LIMITS_V1.max_graph_nodes,
            max_graph_edges: ABILITY_LIMITS_V1.max_graph_edges,
        }
    }
}

/// Reports why provider-authored transition construction could not be trusted.
#[derive(Debug, Error)]
pub enum TransitionError {
    /// A retained exact package or pure transition entry is unavailable.
    #[error("pure transition implementation for provider {provider:?} is unavailable")]
    MissingImplementation {
        /// Identifies the selected provider whose implementation is missing.
        provider: InstanceId,
    },
    /// A prior pure provider lacks matching authority in the desired checked plan.
    #[error("teardown authority for prior provider {provider:?} is absent from the desired plan")]
    MissingTeardownAuthority {
        /// Identifies the provider that still needs an authorized transition.
        provider: InstanceId,
    },
    /// A restricted transition constructor rejected its exact input.
    #[error("transition evaluation failed for provider {provider:?}: {message}")]
    Evaluation {
        /// Identifies the provider whose entry failed.
        provider: InstanceId,
        /// Retains the bounded evaluator failure message.
        message: String,
        /// Retains the exact failed evaluator exchange for audit and retry.
        evaluation: Box<TransitionEvaluation>,
    },
    /// A constructor returned malformed or unauthorized graph content.
    #[error("invalid transition fragment from provider {provider:?}: {reason}")]
    InvalidFragment {
        /// Identifies the provider that authored the rejected fragment.
        provider: InstanceId,
        /// Describes the first rejected invariant.
        reason: String,
    },
    /// Transition context or fragment encoding failed.
    #[error("transition encoding failed: {0}")]
    Encoding(String),
    /// Aggregate transition evaluation exceeded a configured bound.
    #[error("transition construction exceeded the {limit} limit")]
    Limit {
        /// Names the exhausted deterministic bound.
        limit: &'static str,
    },
    /// The merged portable graph failed complete semantic validation.
    #[error("constructed effect plan failed semantic validation: {0}")]
    Validation(#[source] ValidationErrors),
}

/// Constructs checked effect plans from successful fixed-point composition.
pub struct TransitionPlanner<'a> {
    context: &'a ValidationContext,
    limits: TransitionLimits,
}

impl<'a> TransitionPlanner<'a> {
    /// Constructs a planner over one validated exact interface catalog.
    #[must_use]
    pub fn new(context: &'a ValidationContext) -> Self {
        Self {
            context,
            limits: TransitionLimits::default(),
        }
    }

    /// Overrides transition evaluation and graph-construction bounds.
    ///
    /// # Errors
    ///
    /// Returns an error if any configured bound is zero or exceeds the shared
    /// version-1 graph ceiling.
    pub fn with_limits(mut self, limits: TransitionLimits) -> Result<Self, TransitionError> {
        if limits.max_evaluations == 0
            || limits.max_evaluation_bytes == 0
            || limits.max_graph_nodes == 0
            || limits.max_graph_edges == 0
            || limits.max_evaluations > ABILITY_LIMITS_V1.max_graph_nodes
            || limits.max_evaluation_bytes > ABILITY_LIMITS_V1.max_document_bytes
            || limits.max_graph_nodes > ABILITY_LIMITS_V1.max_graph_nodes
            || limits.max_graph_edges > ABILITY_LIMITS_V1.max_graph_edges
        {
            return Err(TransitionError::Limit {
                limit: "configured transition",
            });
        }
        self.limits = limits;
        Ok(self)
    }

    /// Evaluates exact pure transition entries and returns a sealed checked plan.
    ///
    /// The outcome must come from successful fixed-point composition against
    /// this exact interface catalog. The evaluator receives only scoped state,
    /// bindings, changes, and the operation-key scope assigned to its provider.
    /// No runtime effect occurs during construction.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing retained implementation, evaluator
    /// failure, malformed or out-of-scope fragment, exhausted aggregate bound,
    /// or any complete effect-plan validation diagnostic.
    pub fn plan(
        &self,
        desired: &VerifiedPlanningSnapshot,
        inputs: TransitionInputs<'_>,
        evaluator: &mut impl CompositionEvaluator,
    ) -> Result<VerifiedTransitionPlan, TransitionError> {
        let (checked_effect, evaluations) = self.construct(desired, &inputs, evaluator)?;
        let snapshot = TransitionSnapshot::from_construction(
            desired,
            inputs.current,
            evaluations,
            &checked_effect,
        )
        .map_err(|error| TransitionError::Encoding(error.to_string()))?;
        let snapshot_digest = snapshot
            .digest()
            .map_err(|error| TransitionError::Encoding(error.to_string()))?;

        Ok(VerifiedTransitionPlan {
            snapshot_digest,
            snapshot,
            checked_effect,
        })
    }

    fn construct(
        &self,
        desired: &VerifiedPlanningSnapshot,
        inputs: &TransitionInputs<'_>,
        evaluator: &mut impl CompositionEvaluator,
    ) -> Result<(CheckedEffectPlan, Vec<TransitionEvaluation>), TransitionError> {
        let outcome = desired.outcome();
        let packages = index_packages(outcome.resolution.checked.packages())?;
        let groups = transition_groups(desired, inputs.current)?;
        let changes = resource_changes(
            outcome
                .resolution
                .checked
                .environment()
                .resources
                .as_slice(),
            outcome
                .resolution
                .checked
                .desired_state()
                .resources
                .as_slice(),
        );
        let controllers = controller_union(outcome);
        let mut budget = TransitionBudget::default();
        let mut fragments = Vec::new();
        let mut evaluations = Vec::new();
        let mut evaluated_packages = BTreeSet::new();

        for group in groups.into_values() {
            budget.begin(self.limits)?;
            let package = package_for_group(&group, &packages)?;
            let Some((implementation, transition_entry)) = pure_transition(&group, package)? else {
                continue;
            };
            let operation_scope = operation_scope(&group.provider, group.reference.descriptor)?;
            let outgoing: Vec<_> = outcome
                .resolution
                .checked
                .bindings()
                .iter()
                .filter(|binding| binding.request.consumer == group.provider)
                .collect();
            let owned_changes: Vec<_> = changes
                .iter()
                .filter(|change| change.resource.provider == group.provider)
                .cloned()
                .collect();
            let owned_controllers: Vec<_> = controllers
                .iter()
                .filter(|assignment| assignment.controller.provider == group.provider)
                .cloned()
                .collect();
            let before = inputs
                .current
                .map(|current| scoped_desired_state(current, &group.provider));
            let after = scoped_desired_state(desired, &group.provider);
            let observations = scoped_observations(desired, &group.provider);
            let context = TransitionContext {
                schema: TRANSITION_CONTEXT_SCHEMA.to_string(),
                desired_planning: desired.snapshot_digest(),
                current_planning: inputs
                    .current
                    .map(VerifiedPlanningSnapshot::snapshot_digest),
                provider: group.provider.clone(),
                interface: implementation.interface.clone(),
                implementation: group.reference.clone(),
                package: group.package,
                operation_scope: operation_scope.clone(),
                before,
                after,
                observations,
                changes: owned_changes,
                controllers: owned_controllers,
            };
            budget.preflight_context(&context, self.limits)?;
            let input = encode_ability_value(&context)?;
            budget.retain_bytes(input.encoded_size(), self.limits)?;
            let output = match evaluator.evaluate(&group.reference, transition_entry, &input) {
                Ok(output) => output,
                Err(source) => {
                    let message = bounded_evaluation_message(&source);
                    let evaluation = TransitionEvaluation {
                        provider: group.provider.clone(),
                        implementation: group.reference.clone(),
                        entry: transition_entry.clone(),
                        input,
                        result: TransitionEvaluationResult::Failed {
                            message: message.clone(),
                        },
                    };
                    return Err(TransitionError::Evaluation {
                        provider: group.provider.clone(),
                        message,
                        evaluation: Box::new(evaluation),
                    });
                }
            };
            let evaluation = TransitionEvaluation {
                provider: group.provider.clone(),
                implementation: group.reference.clone(),
                entry: transition_entry.clone(),
                input,
                result: TransitionEvaluationResult::Returned {
                    value: output.clone(),
                },
            };
            budget.preflight_fragment_value(&output, self.limits)?;
            budget.retain_bytes(output.encoded_size(), self.limits)?;
            let fragment: TransitionFragment =
                serde_json::from_value(output.into_json()).map_err(|error| {
                    TransitionError::InvalidFragment {
                        provider: group.provider.clone(),
                        reason: error.to_string(),
                    }
                })?;
            validate_fragment(
                &group.provider,
                &operation_scope,
                package.activation_mode,
                &outgoing,
                &fragment,
                self.limits,
            )?;
            evaluated_packages.insert(group.package);
            evaluations.push(evaluation);
            fragments.push(AuthoredTransitionFragment {
                provider: group.provider,
                implementation: group.reference,
                operation_scope,
                fragment,
            });
        }

        let document = merge_fragments(
            outcome,
            controllers,
            fragments,
            &packages,
            &evaluated_packages,
            self.limits,
        )?;
        let checked_effect = self
            .context
            .validate_effect_plan(document, outcome.resolution.checked.clone())
            .map_err(TransitionError::Validation)?;

        Ok((checked_effect, evaluations))
    }
}

#[derive(Default)]
struct TransitionBudget {
    evaluations: u32,
    bytes: u64,
}

impl TransitionBudget {
    fn begin(&mut self, limits: TransitionLimits) -> Result<(), TransitionError> {
        self.evaluations = self.evaluations.saturating_add(1);
        if self.evaluations > limits.max_evaluations {
            return Err(TransitionError::Limit {
                limit: "transition evaluation count",
            });
        }
        Ok(())
    }

    fn retain_bytes(
        &mut self,
        encoded_size: Result<u64, aos_ability_model::ValueError>,
        limits: TransitionLimits,
    ) -> Result<(), TransitionError> {
        let bytes = encoded_size.map_err(|error| TransitionError::Encoding(error.to_string()))?;
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or(TransitionError::Limit {
                limit: "aggregate transition evaluation byte",
            })?;
        if self.bytes > limits.max_evaluation_bytes {
            return Err(TransitionError::Limit {
                limit: "aggregate transition evaluation byte",
            });
        }
        Ok(())
    }

    fn preflight_context(
        &self,
        context: &impl Serialize,
        limits: TransitionLimits,
    ) -> Result<(), TransitionError> {
        let remaining =
            limits
                .max_evaluation_bytes
                .checked_sub(self.bytes)
                .ok_or(TransitionError::Limit {
                    limit: "aggregate transition evaluation byte",
                })?;
        let mut writer = EvaluationBoundedWriter::new(remaining);
        serde_json::to_writer(&mut writer, context).map_err(|error| {
            if writer.exceeded {
                TransitionError::Limit {
                    limit: "aggregate transition evaluation byte",
                }
            } else {
                TransitionError::Encoding(error.to_string())
            }
        })
    }

    fn preflight_fragment_value(
        &self,
        value: &AbilityValue,
        limits: TransitionLimits,
    ) -> Result<(), TransitionError> {
        let remaining =
            limits
                .max_evaluation_bytes
                .checked_sub(self.bytes)
                .ok_or(TransitionError::Limit {
                    limit: "aggregate transition evaluation byte",
                })?;
        let mut writer = EvaluationBoundedWriter::new(remaining);
        serde_json::to_writer(&mut writer, value).map_err(|error| {
            if writer.exceeded {
                TransitionError::Limit {
                    limit: "aggregate transition evaluation byte",
                }
            } else {
                TransitionError::Encoding(error.to_string())
            }
        })
    }
}

struct EvaluationBoundedWriter {
    remaining: u64,
    exceeded: bool,
}

impl EvaluationBoundedWriter {
    const fn new(remaining: u64) -> Self {
        Self {
            remaining,
            exceeded: false,
        }
    }
}

impl Write for EvaluationBoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > self.remaining {
            self.exceeded = true;
            return Err(io::Error::other(
                "serialized transition evaluation exceeds its byte limit",
            ));
        }
        self.remaining -= bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
