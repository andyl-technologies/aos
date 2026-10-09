//! Independent exact interpretation of assignments, obligations, and preferences.
//!
//! Evaluations are portable reports, not serialized verification credentials:
//!
//! ```json
//! {"component":{"constraint":"memory","component":"capacity"},"debt":"2","baseline":"2"}
//! ```

use std::collections::{BTreeMap, BTreeSet};

use num_bigint::BigInt;
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::accounting::{Loads, calculate_loads, lookup};
use crate::validation::{check_rational, check_size, require_binding};
use crate::*;

/// One exact per-target resource load in a declared accounting phase.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLoad {
    /// Target identifier.
    pub target: String,
    /// Resource dimension identifier.
    pub dimension: String,
    /// Final or conservative-overlap accounting.
    pub phase: AccountingPhase,
    /// Exact resource aggregate, potentially larger than a 64-bit input.
    pub quantity: Integer,
}

/// A numeric repair component and its independent observation-derived envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentDebt {
    /// Stable constraint and component reference.
    pub component: ComponentId,
    /// Exact remaining debt for this candidate.
    pub debt: Integer,
    /// Maximum permitted debt derived from historical ordinary charges.
    pub baseline: Integer,
}

/// A hard violation or a repair component exceeding its baseline envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Violation {
    /// Stable constraint and component reference.
    pub component: ComponentId,
    /// Exact debt produced by this candidate.
    pub actual_debt: Rational,
    /// Zero for hard constraints, or the independently derived repair baseline.
    pub allowed_debt: Rational,
    /// Whether this failure is a worsened repair obligation.
    pub repair: bool,
    /// A diagnostic description of the obligation.
    pub message: String,
}

/// An independent exact evaluation, available without running an optimizer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evaluation {
    /// Per-target resource loads for both accounting phases.
    pub resource_loads: Vec<ResourceLoad>,
    /// Hard violations and repair-envelope failures; remaining permitted debt is separate.
    pub violations: Vec<Violation>,
    /// Sparse repair components; an omitted valid component has zero debt and baseline.
    /// Nonzero baselines, active scope members, and objective selections are reported.
    pub repair_debt: Vec<ComponentDebt>,
    /// Exact minimized objective values in lexicographic tier order.
    pub objectives: Vec<Rational>,
    /// Raw metric values keyed by globally unique objective-term identifier.
    pub term_values: BTreeMap<String, Rational>,
    /// Signed, weighted, normalized contributions keyed by objective-term identifier.
    pub term_contributions: BTreeMap<String, Rational>,
    /// Exact observed-relative transition category for each changed item.
    pub movements: BTreeMap<String, MovementCategory>,
}

/// The validity class of an independently verified assignment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationClass {
    /// Every hard constraint and every repair obligation has zero debt.
    Feasible,
    /// Every hard constraint holds and permitted repair debt remains.
    Repair,
}

/// An assignment bound to the exact immutable problem evaluated locally.
///
/// Construction is restricted to [`verify`]. Importing serialized data does not
/// establish this type's invariants; the imported assignment must be verified.
#[derive(Clone, Debug)]
pub struct VerifiedAssignment {
    problem: ValidatedProblem,
    assignment: Assignment,
    evaluation: Evaluation,
    classification: VerificationClass,
}

impl VerifiedAssignment {
    /// Returns the accepted complete placement decisions.
    pub fn assignment(&self) -> &Assignment {
        &self.assignment
    }

    /// Returns the independently recomputed exact report.
    pub fn evaluation(&self) -> &Evaluation {
        &self.evaluation
    }

    /// Returns whether the answer is fully feasible or retains permitted repair debt.
    pub fn classification(&self) -> VerificationClass {
        self.classification
    }

    /// Returns the exact immutable semantic problem to which verification is bound.
    pub fn problem(&self) -> &Problem {
        self.problem.problem()
    }

    /// Returns the structurally validated problem and independently derived baselines.
    pub fn validated_problem(&self) -> &ValidatedProblem {
        &self.problem
    }
}

/// A malformed candidate or an independently established constraint failure.
#[derive(Clone, Debug, Error)]
pub enum VerificationError {
    /// The candidate cannot be evaluated under the model's exact contracts.
    #[error(transparent)]
    Model(#[from] ModelError),
    /// The candidate violates hard requirements or repair envelopes.
    #[error("assignment violates hard constraints or repair envelopes")]
    Violations {
        /// The complete exact rejection report.
        evaluation: Box<Evaluation>,
    },
}

/// Evaluates a complete assignment with exact resource and objective arithmetic.
///
/// # Errors
///
/// Returns an error for missing or unknown bindings, undefined demand or costs,
/// or exact arithmetic exceeding the published bound. An ordinary constraint
/// violation is returned in the evaluation rather than as an evaluation error.
pub fn evaluate(
    problem: &ValidatedProblem,
    assignment: &Assignment,
) -> Result<Evaluation, ModelError> {
    validate_assignment(problem.problem(), assignment)?;
    let loads = calculate_loads(problem.problem(), assignment, false)?;
    let components = components_with_loads(problem, assignment, &loads)?;
    let mut repair_debt = Vec::new();
    let mut violations = Vec::new();
    let mut debt_by_id = BTreeMap::new();

    for component in components {
        check_rational(&component.debt, "constraint.debt")?;
        let repair = component.enforcement == Enforcement::Repair;
        let allowed_debt = if repair {
            let baseline = problem.baseline_debt(&component.id).ok_or_else(|| {
                ModelError::new("repair.baseline", "missing independently derived component")
            })?;
            let debt = Integer::from(component.debt.numerator().clone());
            repair_debt.push(ComponentDebt {
                component: component.id.clone(),
                debt,
                baseline: baseline.clone(),
            });
            debt_by_id.insert(component.id.clone(), component.debt.clone());
            Rational::from(baseline.value().clone())
        } else {
            Rational::zero()
        };
        if component.debt > allowed_debt {
            violations.push(Violation {
                component: component.id,
                actual_debt: component.debt,
                allowed_debt,
                repair,
                message: component.message,
            });
        }
    }

    // Explicit references remain inspectable even when a scope member has no load.
    for tier in &problem.problem().objectives {
        for term in &tier.terms {
            if let Metric::RepairDebt { components } = &term.metric {
                for component in components {
                    if !debt_by_id.contains_key(component) {
                        let baseline = problem.baseline_debt(component).ok_or_else(|| {
                            ModelError::new("repair.baseline", "unknown repair component")
                        })?;
                        debt_by_id.insert(component.clone(), Rational::zero());
                        repair_debt.push(ComponentDebt {
                            component: component.clone(),
                            debt: Integer::default(),
                            baseline: baseline.clone(),
                        });
                    }
                }
            }
        }
    }

    let mut resource_loads = Vec::new();
    for phase in [AccountingPhase::Final, AccountingPhase::Overlap] {
        for (target, dimensions) in loads.selected(phase) {
            for (dimension, quantity) in dimensions {
                check_size(quantity, "resource_load")?;
                resource_loads.push(ResourceLoad {
                    target: target.clone(),
                    dimension: dimension.clone(),
                    phase,
                    quantity: quantity.clone().into(),
                });
            }
        }
    }

    let mut objectives = Vec::new();
    let mut term_values = BTreeMap::new();
    let mut term_contributions = BTreeMap::new();
    for tier in &problem.problem().objectives {
        let mut value = Rational::zero();
        for term in &tier.terms {
            let metric = metric_value(problem, assignment, &loads, &debt_by_id, &term.metric)?;
            check_rational(&metric, "objective.metric")?;
            let weighted = (&term.weight * &metric).checked_div(&term.normalizer)?;
            let contribution = match term.direction {
                Direction::Minimize => weighted,
                Direction::Maximize => -&weighted,
            };
            check_rational(&contribution, "objective.contribution")?;
            value = &value + &contribution;
            check_rational(&value, "objective.tier")?;
            term_values.insert(term.id.clone(), metric);
            term_contributions.insert(term.id.clone(), contribution);
        }
        objectives.push(value);
    }

    let mut movements = BTreeMap::new();
    for (item, observation) in &problem.problem().observed {
        if let Some(category) = movement_category(
            &observation.binding,
            lookup(&assignment.bindings, item, "assignment")?,
        ) {
            movements.insert(item.clone(), category);
        }
    }

    Ok(Evaluation {
        resource_loads,
        violations,
        repair_debt,
        objectives,
        term_values,
        term_contributions,
        movements,
    })
}

/// Independently verifies a candidate and binds it to the immutable evaluated problem.
///
/// # Errors
///
/// Returns a model error when exact evaluation fails, or a rejection report
/// when hard constraints or componentwise repair envelopes are violated.
pub fn verify(
    problem: &ValidatedProblem,
    assignment: Assignment,
) -> Result<VerifiedAssignment, VerificationError> {
    let evaluation = evaluate(problem, &assignment)?;
    if !evaluation.violations.is_empty() {
        return Err(VerificationError::Violations {
            evaluation: Box::new(evaluation),
        });
    }

    let classification = if evaluation
        .repair_debt
        .iter()
        .any(|component| !component.debt.is_zero())
    {
        VerificationClass::Repair
    } else {
        VerificationClass::Feasible
    };

    Ok(VerifiedAssignment {
        problem: problem.clone(),
        assignment,
        evaluation,
        classification,
    })
}

pub(crate) struct Component {
    pub(crate) id: ComponentId,
    pub(crate) enforcement: Enforcement,
    pub(crate) debt: Rational,
    pub(crate) message: String,
}

pub(crate) fn constraint_components(
    problem: &ValidatedProblem,
    assignment: &Assignment,
    historical: bool,
) -> Result<Vec<Component>, ModelError> {
    let loads = calculate_loads(problem.problem(), assignment, historical)?;
    components_with_loads(problem, assignment, &loads)
}

fn validate_assignment(problem: &Problem, assignment: &Assignment) -> Result<(), ModelError> {
    if assignment.bindings.len() != problem.items.len() {
        return Err(ModelError::new(
            "assignment.bindings",
            "must bind exactly every item once",
        ));
    }
    for (item, binding) in &assignment.bindings {
        lookup(&problem.items, item, "assignment.bindings")?;
        require_binding(binding, problem, "assignment.bindings")?;
    }

    Ok(())
}

fn components_with_loads(
    problem: &ValidatedProblem,
    assignment: &Assignment,
    loads: &Loads,
) -> Result<Vec<Component>, ModelError> {
    let model = problem.problem();
    let mut components = Vec::new();
    for (id, item) in &model.items {
        let binding = lookup(&assignment.bindings, id, "assignment.bindings")?;
        let eligible = match binding {
            Binding::Target { target } => lookup(&model.domains, &item.domain, "domains")?
                .binary_search(target)
                .is_ok(),
            Binding::Deferred => true,
        };
        components.push(predicate(
            "$eligibility",
            id,
            Enforcement::Hard,
            eligible,
            "item is outside its candidate domain",
        ));
        components.push(predicate(
            "$mandatory",
            id,
            Enforcement::Hard,
            item.deferrable || matches!(binding, Binding::Target { .. }),
            "mandatory item is deferred",
        ));
    }

    for constraint in &model.constraints {
        let enforcement = constraint.enforcement;
        match &constraint.rule {
            ConstraintRule::Eligibility { items, targets } => {
                for item in items {
                    let holds = match lookup(&assignment.bindings, item, "assignment")? {
                        Binding::Target { target } => targets.binary_search(target).is_ok(),
                        Binding::Deferred => true,
                    };
                    components.push(predicate(
                        &constraint.id,
                        item,
                        enforcement,
                        holds,
                        "item is outside explicit eligibility set",
                    ));
                }
            }
            ConstraintRule::FixedPlacement { bindings } => {
                for (item, required) in bindings {
                    components.push(predicate(
                        &constraint.id,
                        item,
                        enforcement,
                        lookup(&assignment.bindings, item, "assignment")? == required,
                        "fixed binding changed",
                    ));
                }
            }
            ConstraintRule::Capacity {
                target_set,
                dimension,
                phase,
                limit,
            } => {
                let load = loads.sum(model, target_set, dimension, *phase)?;
                components.push(bound(
                    &constraint.id,
                    "capacity",
                    enforcement,
                    load,
                    BigInt::from(limit.get()),
                    false,
                    "capacity exceeded",
                ));
            }
            ConstraintRule::Admission {
                group,
                minimum,
                maximum,
            } => {
                let count = admitted_count(model, assignment, group)?;
                components.push(bound(
                    &constraint.id,
                    "minimum",
                    enforcement,
                    count.clone(),
                    BigInt::from(minimum.get()),
                    true,
                    "admitted count below minimum",
                ));
                components.push(bound(
                    &constraint.id,
                    "maximum",
                    enforcement,
                    count,
                    BigInt::from(maximum.get()),
                    false,
                    "admitted count exceeds maximum",
                ));
            }
            ConstraintRule::AtomicAdmission { group } => {
                let size = lookup(&model.groups, group, "groups")?.len();
                let count = admitted_count(model, assignment, group)?;
                components.push(predicate(
                    &constraint.id,
                    "atomic",
                    enforcement,
                    count.is_zero() || count == BigInt::from(size),
                    "group is only partially admitted",
                ));
            }
            ConstraintRule::CoLocation { group, family } => {
                let counts = topology_counts(problem, assignment, group, family)?;
                components.push(predicate(
                    &constraint.id,
                    "co_location",
                    enforcement,
                    counts.values().filter(|count| **count > 0).count() <= 1,
                    "admitted group crosses topology members",
                ));
            }
            ConstraintRule::Spread {
                group,
                family,
                minimum,
                maximum_per_member,
                when_admitted,
            } => {
                let counts = topology_counts(problem, assignment, group, family)?;
                let distinct = BigInt::from(counts.values().filter(|count| **count > 0).count());
                let effective_minimum = if *when_admitted && distinct.is_zero() {
                    0
                } else {
                    minimum.get()
                };
                components.push(bound(
                    &constraint.id,
                    "minimum",
                    enforcement,
                    distinct,
                    BigInt::from(effective_minimum),
                    true,
                    "too few distinct occupied topology members",
                ));
                if let Some(maximum) = maximum_per_member {
                    let mut counts = counts;
                    let first = component_id(&constraint.id, "");
                    for (baseline, _) in problem
                        .baseline
                        .range(first..)
                        .take_while(|(key, _)| key.constraint == constraint.id)
                    {
                        if let Some(member) = baseline.component.strip_prefix("member:") {
                            counts.entry(member.into()).or_default();
                        }
                    }
                    for (member, count) in counts {
                        components.push(bound(
                            &constraint.id,
                            &format!("member:{member}"),
                            enforcement,
                            BigInt::from(count),
                            BigInt::from(maximum.get()),
                            false,
                            "too many group items in topology member",
                        ));
                    }
                }
            }
            ConstraintRule::MovementBudget {
                items,
                costs,
                limit,
            } => {
                let cost = movement_cost(model, assignment, items, costs)?;
                let debt = (&cost - limit).max(Rational::zero());
                components.push(Component {
                    id: component_id(&constraint.id, "movement"),
                    enforcement,
                    debt,
                    message: "movement budget exceeded".into(),
                });
            }
        }
    }

    Ok(components)
}

fn predicate(
    constraint: &str,
    component: &str,
    enforcement: Enforcement,
    holds: bool,
    message: &str,
) -> Component {
    Component {
        id: component_id(constraint, component),
        enforcement,
        debt: Rational::from(u64::from(!holds)),
        message: message.into(),
    }
}

fn bound(
    constraint: &str,
    component: &str,
    enforcement: Enforcement,
    value: BigInt,
    limit: BigInt,
    lower: bool,
    message: &str,
) -> Component {
    let debt = if lower { limit - value } else { value - limit };
    Component {
        id: component_id(constraint, component),
        enforcement,
        debt: debt.max(BigInt::zero()).into(),
        message: message.into(),
    }
}

fn component_id(constraint: &str, component: &str) -> ComponentId {
    ComponentId {
        constraint: constraint.into(),
        component: component.into(),
    }
}

fn admitted_count(
    model: &Problem,
    assignment: &Assignment,
    group: &str,
) -> Result<BigInt, ModelError> {
    let items = lookup(&model.groups, group, "groups")?;
    let mut count = BigInt::zero();
    for item in items {
        if matches!(
            lookup(&assignment.bindings, item, "assignment")?,
            Binding::Target { .. }
        ) {
            count += 1;
        }
    }

    Ok(count)
}

fn topology_counts(
    problem: &ValidatedProblem,
    assignment: &Assignment,
    group: &str,
    family: &str,
) -> Result<BTreeMap<String, usize>, ModelError> {
    let model = problem.problem();
    let mapping = lookup(&problem.topology, family, "topology")?;
    let mut counts = BTreeMap::new();
    for item in lookup(&model.groups, group, "groups")? {
        if let Binding::Target { target } = lookup(&assignment.bindings, item, "assignment")? {
            let member = lookup(mapping, target, "topology.targets")?;
            *counts.entry(member.clone()).or_default() += 1;
        }
    }

    Ok(counts)
}

fn metric_value(
    problem: &ValidatedProblem,
    assignment: &Assignment,
    loads: &Loads,
    debts: &BTreeMap<ComponentId, Rational>,
    metric: &Metric,
) -> Result<Rational, ModelError> {
    let model = problem.problem();
    match metric {
        Metric::AdmittedCount { items } => {
            let mut count = BigInt::zero();
            for item in items {
                if matches!(
                    lookup(&assignment.bindings, item, "assignment")?,
                    Binding::Target { .. }
                ) {
                    count += 1;
                }
            }
            Ok(count.into())
        }
        Metric::AdmittedPriority { priorities } => {
            let mut total = Rational::zero();
            for (item, priority) in priorities {
                if matches!(
                    lookup(&assignment.bindings, item, "assignment")?,
                    Binding::Target { .. }
                ) {
                    total = &total + priority;
                    check_rational(&total, "priority.sum")?;
                }
            }
            Ok(total)
        }
        Metric::AssignmentCost { costs } => {
            let mut total = Rational::zero();
            for (item, values) in costs {
                total = &total
                    + binding_cost(values, lookup(&assignment.bindings, item, "assignment")?)?;
                check_rational(&total, "assignment_cost.sum")?;
            }
            Ok(total)
        }
        Metric::MovementCost { items, costs } => movement_cost(model, assignment, items, costs),
        Metric::UsedTargets { items } => {
            let mut targets = BTreeSet::new();
            for item in items {
                if let Binding::Target { target } =
                    lookup(&assignment.bindings, item, "assignment")?
                {
                    targets.insert(target);
                }
            }
            Ok(BigInt::from(targets.len()).into())
        }
        Metric::RepairDebt { components } => {
            let mut total = Rational::zero();
            for component in components {
                total = &total
                    + debts.get(component).ok_or_else(|| {
                        ModelError::new("metric.repair_debt", "unknown repair component")
                    })?;
                check_rational(&total, "repair_debt.sum")?;
            }
            Ok(total)
        }
        Metric::MaximumUtilization { members } => {
            let values = utilization_values(model, loads, members)?;
            values
                .into_iter()
                .max()
                .ok_or_else(|| ModelError::new("metric.members", "empty utilization selection"))
        }
        Metric::UtilizationRange { members } => {
            let values = utilization_values(model, loads, members)?;
            let maximum = values
                .iter()
                .max()
                .ok_or_else(|| ModelError::new("metric.members", "empty utilization selection"))?;
            let minimum = values
                .iter()
                .min()
                .ok_or_else(|| ModelError::new("metric.members", "empty utilization selection"))?;
            Ok(maximum - minimum)
        }
        Metric::TotalAbsoluteDeviation { members } => {
            let mut total = Rational::zero();
            for selection in members {
                let value = utilization_value(model, loads, &selection.member)?;
                total = &total + &(&value - &selection.reference).abs();
                check_rational(&total, "utilization.deviation")?;
            }
            Ok(total)
        }
    }
}

fn utilization_values(
    model: &Problem,
    loads: &Loads,
    members: &[UtilizationMember],
) -> Result<Vec<Rational>, ModelError> {
    members
        .iter()
        .map(|member| utilization_value(model, loads, member))
        .collect()
}

fn utilization_value(
    model: &Problem,
    loads: &Loads,
    member: &UtilizationMember,
) -> Result<Rational, ModelError> {
    let numerator = loads.sum(model, &member.target_set, &member.dimension, member.phase)?;
    Rational::new(numerator, BigInt::from(member.capacity.get()))
}

fn binding_cost<'a>(
    values: &'a AssignmentCosts,
    binding: &Binding,
) -> Result<&'a Rational, ModelError> {
    match binding {
        Binding::Target { target } => values
            .targets
            .get(target)
            .or(values.default.as_ref())
            .ok_or_else(|| {
                ModelError::new(
                    "costs.targets",
                    format!("undefined cost on target {target:?}"),
                )
            }),
        Binding::Deferred => Ok(&values.deferred),
    }
}

fn movement_category(observed: &ObservedBinding, binding: &Binding) -> Option<MovementCategory> {
    match (observed, binding) {
        (ObservedBinding::Unplaced, Binding::Target { .. }) => Some(MovementCategory::NewPlacement),
        (ObservedBinding::Target { target: source }, Binding::Target { target })
            if source != target =>
        {
            Some(MovementCategory::Relocation)
        }
        (ObservedBinding::Target { .. }, Binding::Deferred) => Some(MovementCategory::Retirement),
        _ => None,
    }
}

fn movement_cost(
    model: &Problem,
    assignment: &Assignment,
    items: &[String],
    costs: &MovementCosts,
) -> Result<Rational, ModelError> {
    let mut total = Rational::zero();
    for item in items {
        let observed = lookup(&model.observed, item, "movement.observed")?;
        let binding = lookup(&assignment.bindings, item, "movement.assignment")?;
        if let Some(category) = movement_category(&observed.binding, binding)
            && costs.categories.contains(&category)
        {
            let values = lookup(&costs.costs, item, "movement.costs")?;
            total = &total + binding_cost(values, binding)?;
            check_rational(&total, "movement.sum")?;
        }
    }

    Ok(total)
}
