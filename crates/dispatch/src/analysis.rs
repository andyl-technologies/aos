//! Exact assignment comparison, explanation, and immutable what-if analysis.
//!
//! Explanations are recomputed from a supplied assignment. Saved evaluations and
//! serialized verification flags never acquire local verification authority.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    Assignment, Binding, Evaluation, ModelError, Problem, ValidatedProblem, evaluate, validate,
};

/// Reports the preference of a proposed assignment relative to its baseline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectiveOrdering {
    /// The proposal has a smaller lexicographic minimized objective vector.
    Better,
    /// Both assignments have exactly equal objective vectors.
    Equal,
    /// The proposal has a larger lexicographic minimized objective vector.
    Worse,
}

/// Describes one changed item binding without implying execution authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingChange {
    /// Stable item identifier.
    pub item: String,
    /// Baseline binding.
    pub before: Binding,
    /// Proposed binding.
    pub after: Binding,
}

/// Contains independently calculated evaluations and exact assignment changes.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignmentComparison {
    /// Evaluation of the baseline assignment.
    pub before: Evaluation,
    /// Evaluation of the proposed assignment.
    pub after: Evaluation,
    /// Item changes in stable identifier order.
    pub binding_changes: Vec<BindingChange>,
    /// Objective preference of the proposal; feasibility is reported separately.
    pub objective_ordering: ObjectiveOrdering,
}

/// Contains a recomputed explanation bound to the consumer's observation basis.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Explanation {
    /// Opaque revisions preserved without interpreting their authority.
    pub observation_basis: BTreeMap<String, String>,
    /// The complete assignment being explained.
    pub assignment: Assignment,
    /// Exact loads, named violations, repair debt, and objective contributions.
    pub evaluation: Evaluation,
}

/// Reports one changed semantic input using a JSON Pointer path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelChange {
    /// Escaped JSON Pointer identifying the changed input.
    pub path: String,
    /// Previous value; `None` means the field was absent.
    pub before: Option<serde_json::Value>,
    /// New value; `None` means the field was removed.
    pub after: Option<serde_json::Value>,
}

/// Compares inputs and independently evaluates assignments under their own models.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProblemComparison {
    /// Whether both complete semantic model documents are identical.
    pub same_problem: bool,
    /// Changed model inputs in stable JSON Pointer order.
    pub model_changes: Vec<ModelChange>,
    /// Evaluation under the baseline problem.
    pub before: Evaluation,
    /// Evaluation under the proposed problem.
    pub after: Evaluation,
    /// Preference is provided only for an unchanged problem.
    pub objective_ordering: Option<ObjectiveOrdering>,
}

/// Reports a model evaluation or analysis-document conversion failure.
#[derive(Debug, thiserror::Error)]
pub enum AnalysisError {
    /// The assignment is structurally malformed for its model.
    #[error(transparent)]
    Model(#[from] ModelError),
    /// A model could not be represented as a portable analysis document.
    #[error("cannot encode analysis document")]
    Json(#[from] serde_json::Error),
}

/// Compares complete assignments under one unchanged problem.
///
/// Objective ordering does not override feasibility or repair envelopes. A
/// numerically preferred assignment may still violate a hard requirement.
///
/// # Errors
///
/// Returns an error if either assignment has missing, duplicate, or unknown
/// bindings, or exact evaluation encounters an invalid numeric operation.
pub fn compare(
    problem: &ValidatedProblem,
    before: &Assignment,
    after: &Assignment,
) -> Result<AssignmentComparison, ModelError> {
    let before_evaluation = evaluate(problem, before)?;
    let after_evaluation = evaluate(problem, after)?;
    let mut binding_changes = Vec::new();
    for (item, binding) in &before.bindings {
        let proposed = after.bindings.get(item).ok_or_else(|| {
            ModelError::new(
                format!("assignment.bindings.{item}"),
                "proposed binding is missing",
            )
        })?;
        if binding != proposed {
            binding_changes.push(BindingChange {
                item: item.clone(),
                before: binding.clone(),
                after: proposed.clone(),
            });
        }
    }

    let objective_ordering = objective_ordering(&before_evaluation, &after_evaluation);
    Ok(AssignmentComparison {
        before: before_evaluation,
        after: after_evaluation,
        binding_changes,
        objective_ordering,
    })
}

/// Recomputes a candidate's exact resource and policy explanation.
///
/// # Errors
///
/// Returns an error if the supplied assignment is structurally malformed or
/// evaluation encounters an invalid numeric operation.
pub fn explain(
    problem: &ValidatedProblem,
    assignment: &Assignment,
) -> Result<Explanation, ModelError> {
    Ok(Explanation {
        observation_basis: problem.problem().observation_basis.clone(),
        assignment: assignment.clone(),
        evaluation: evaluate(problem, assignment)?,
    })
}

/// Creates a distinct validated problem without mutating the original snapshot.
///
/// # Errors
///
/// Returns an error if the transformation makes no semantic change or produces
/// invalid model references, accounting, numeric values, or policy parameters.
pub fn what_if(
    original: &ValidatedProblem,
    transform: impl FnOnce(&mut Problem),
) -> Result<ValidatedProblem, ModelError> {
    let mut revised = original.problem().clone();
    transform(&mut revised);
    let revised = validate(revised)?;
    if revised.problem() == original.problem() {
        return Err(ModelError::new(
            "what_if",
            "transformation must change the semantic problem",
        ));
    }
    Ok(revised)
}

/// Reports changed inputs and evaluates each assignment using its own problem.
///
/// Scores from different policies, capacities, observations, or units are not
/// implicitly comparable. The report omits objective preference whenever the
/// complete problem changes, while exposing both evaluations for inspection.
///
/// # Errors
///
/// Returns an error for malformed assignments or failed model serialization.
pub fn compare_problems(
    before_problem: &ValidatedProblem,
    before_assignment: &Assignment,
    after_problem: &ValidatedProblem,
    after_assignment: &Assignment,
) -> Result<ProblemComparison, AnalysisError> {
    let before = evaluate(before_problem, before_assignment)?;
    let after = evaluate(after_problem, after_assignment)?;
    let before_document = serde_json::to_value(before_problem.problem())?;
    let after_document = serde_json::to_value(after_problem.problem())?;
    let mut model_changes = Vec::new();
    diff_documents(
        "",
        Some(&before_document),
        Some(&after_document),
        &mut model_changes,
    );
    let same_problem = model_changes.is_empty();
    let objective_ordering = same_problem.then(|| objective_ordering(&before, &after));

    Ok(ProblemComparison {
        same_problem,
        model_changes,
        before,
        after,
        objective_ordering,
    })
}

fn objective_ordering(before: &Evaluation, after: &Evaluation) -> ObjectiveOrdering {
    match after.objectives.cmp(&before.objectives) {
        std::cmp::Ordering::Less => ObjectiveOrdering::Better,
        std::cmp::Ordering::Equal => ObjectiveOrdering::Equal,
        std::cmp::Ordering::Greater => ObjectiveOrdering::Worse,
    }
}

fn diff_documents(
    path: &str,
    before: Option<&serde_json::Value>,
    after: Option<&serde_json::Value>,
    changes: &mut Vec<ModelChange>,
) {
    if before == after {
        return;
    }
    match (before, after) {
        (Some(serde_json::Value::Object(left)), Some(serde_json::Value::Object(right))) => {
            let keys: BTreeSet<_> = left.keys().chain(right.keys()).collect();
            for key in keys {
                let escaped = key.replace('~', "~0").replace('/', "~1");
                diff_documents(
                    &format!("{path}/{escaped}"),
                    left.get(key),
                    right.get(key),
                    changes,
                );
            }
        }
        _ => changes.push(ModelChange {
            path: path.to_owned(),
            before: before.cloned(),
            after: after.cloned(),
        }),
    }
}
