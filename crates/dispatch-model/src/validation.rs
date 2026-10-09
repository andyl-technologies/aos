//! Structural validation, normalized finite sets, and immutable problem ownership.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use num_bigint::BigInt;
use num_traits::ToPrimitive;
use thiserror::Error;

use crate::accounting::{lookup, observed_assignment};
use crate::evaluation::constraint_components;
use crate::*;

/// The maximum bit length of each exact evaluation numerator or denominator.
///
/// Exceeding this bound produces numeric exhaustion rather than an approximate
/// objective or feasibility claim. Resource aggregates use the same bound.
pub const MAX_EVALUATION_BITS: u64 = 65_536;

/// The category of a model validation or evaluation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelErrorKind {
    /// An invalid schema value, unresolved reference, or malformed assignment.
    Malformed,
    /// A semantic model version the evaluator does not implement.
    UnsupportedVersion,
    /// Exact arithmetic exceeds the published evaluation bound.
    NumericExhaustion,
}

/// A contextual structural or exact-evaluation error.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("{path}: {message}")]
pub struct ModelError {
    /// Stable distinction between malformed input and unsupported or exhausted evaluation.
    pub kind: ModelErrorKind,
    /// The entity or field whose contract failed.
    pub path: String,
    /// A human-readable explanation without implied feasibility conclusions.
    pub message: String,
}

impl ModelError {
    /// Constructs a malformed-input error with contextual field information.
    pub fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind: ModelErrorKind::Malformed,
            path: path.into(),
            message: message.into(),
        }
    }
}

/// An immutable structurally validated problem and independently derived repair baselines.
#[derive(Clone, Debug)]
pub struct ValidatedProblem {
    pub(crate) problem: Arc<Problem>,
    pub(crate) baseline: BTreeMap<ComponentId, Integer>,
    pub(crate) topology: BTreeMap<String, BTreeMap<String, String>>,
    constraint_index: BTreeMap<String, usize>,
    zero: Integer,
}

impl ValidatedProblem {
    /// Returns the immutable normalized semantic problem.
    pub fn problem(&self) -> &Problem {
        &self.problem
    }

    /// Returns a component's independently derived repair baseline, when repairable.
    pub fn baseline_debt(&self, component: &ComponentId) -> Option<&Integer> {
        if !valid_repair_component(self.problem(), &self.constraint_index, component) {
            return None;
        }
        Some(self.baseline.get(component).unwrap_or(&self.zero))
    }

    /// Returns the historical placement translated to target/deferred bindings.
    ///
    /// The result is a baseline for analysis and may violate mandatory admission
    /// or current eligibility. It is not a verified feasible assignment.
    pub fn observed_assignment(&self) -> Assignment {
        observed_assignment(&self.problem)
    }
}

/// Validates and freezes a portable problem while deriving exact repair baselines.
///
/// Finite set representations are sorted so iteration order does not change
/// semantic identity. Validation does not require a known feasible assignment.
///
/// # Errors
///
/// Returns an error for unsupported versions, duplicate identifiers, invalid
/// numeric inputs, incomplete accounting, unresolved references, invalid scope
/// partitions, unsupported repair policies, or arithmetic exhaustion.
pub fn validate(mut problem: Problem) -> Result<ValidatedProblem, ModelError> {
    if problem.model_version != 1 {
        return Err(ModelError {
            kind: ModelErrorKind::UnsupportedVersion,
            path: "model_version".into(),
            message: "only semantic model version 1 is supported".into(),
        });
    }

    validate_entities(&mut problem)?;
    validate_accounting(&problem)?;
    let topology = build_topology(&mut problem)?;
    validate_constraints(&mut problem)?;

    let constraint_index = problem
        .constraints
        .iter()
        .enumerate()
        .map(|(index, constraint)| (constraint.id.clone(), index))
        .collect();
    validate_objectives(&mut problem, &constraint_index)?;
    let mut validated = ValidatedProblem {
        problem: Arc::new(problem),
        baseline: BTreeMap::new(),
        topology,
        constraint_index,
        zero: Integer::default(),
    };
    let baseline_assignment = validated.observed_assignment();
    let components = constraint_components(&validated, &baseline_assignment, true)?;
    for component in components {
        if component.enforcement == Enforcement::Repair {
            check_rational(&component.debt, "repair.baseline")?;
            // Scope-member obligations are sparse; an omitted valid component is zero.
            if !component.debt.is_zero() || !component.id.component.starts_with("member:") {
                validated
                    .baseline
                    .insert(component.id, component.debt.numerator().clone().into());
            }
        }
    }

    Ok(validated)
}

fn validate_entities(problem: &mut Problem) -> Result<(), ModelError> {
    for (kind, ids) in [
        ("items", problem.items.keys().collect::<Vec<_>>()),
        ("targets", problem.targets.keys().collect()),
        ("dimensions", problem.dimensions.keys().collect()),
        ("domains", problem.domains.keys().collect()),
        ("groups", problem.groups.keys().collect()),
        ("target_sets", problem.target_sets.keys().collect()),
        ("scope_families", problem.scope_families.keys().collect()),
    ] {
        for id in ids {
            require_id(id, kind)?;
        }
    }
    for key in problem.observation_basis.keys() {
        require_id(key, "observation_basis")?;
    }
    for (id, dimension) in &problem.dimensions {
        if dimension.unit.is_empty() || dimension.quantum.get() == 0 {
            return Err(ModelError::new(
                format!("dimensions.{id}"),
                "unit must be nonempty and quantum positive",
            ));
        }
    }

    for (id, values) in &mut problem.domains {
        normalize_set(values, &format!("domains.{id}"))?;
        require_references(values, &problem.targets, "domains")?;
    }
    for (id, values) in &mut problem.groups {
        normalize_set(values, &format!("groups.{id}"))?;
        require_references(values, &problem.items, "groups")?;
    }
    for (id, values) in &mut problem.target_sets {
        normalize_set(values, &format!("target_sets.{id}"))?;
        require_references(values, &problem.targets, "target_sets")?;
    }

    Ok(())
}

fn validate_accounting(problem: &Problem) -> Result<(), ModelError> {
    for (id, target) in &problem.targets {
        require_dimension_keys(
            &target.capacities,
            problem,
            &format!("targets.{id}.capacities"),
        )?;
        require_dimension_keys(
            &target.fixed_load,
            problem,
            &format!("targets.{id}.fixed_load"),
        )?;
    }
    for (id, item) in &problem.items {
        let domain = lookup(&problem.domains, &item.domain, "item.domain")?;
        require_dimension_keys(&item.demands, problem, &format!("items.{id}.demands"))?;
        for demand in item.demands.values() {
            for target in demand.overrides.keys() {
                lookup(&problem.targets, target, "demand.overrides")?;
            }
            if demand.default.is_none() {
                for target in domain {
                    if !demand.overrides.contains_key(target) {
                        return Err(ModelError::new(
                            format!("items.{id}.demands"),
                            format!("no demand defined for eligible target {target:?}"),
                        ));
                    }
                }
            }
        }
    }

    if problem.observed.len() != problem.items.len() {
        return Err(ModelError::new(
            "observed",
            "must contain exactly every item",
        ));
    }
    for (id, observed) in &problem.observed {
        lookup(&problem.items, id, "observed")?;
        require_dimension_keys(&observed.charges, problem, "observed.charges")?;
        match &observed.binding {
            ObservedBinding::Target { target } => {
                lookup(&problem.targets, target, "observed.binding")?;
            }
            ObservedBinding::Unplaced => {
                if observed
                    .charges
                    .values()
                    .any(|quantity| quantity.get() != 0)
                {
                    return Err(ModelError::new(
                        "observed.charges",
                        "unplaced items must have zero ordinary charges",
                    ));
                }
            }
        }
    }

    let mut holding_ids = BTreeSet::new();
    let mut fragments: BTreeMap<(String, String), BigInt> = BTreeMap::new();
    for holding in &problem.holdings {
        require_id(&holding.id, "holdings.id")?;
        if !holding_ids.insert(&holding.id) {
            return Err(ModelError::new(
                "holdings.id",
                "duplicate holding identifier",
            ));
        }
        lookup(&problem.targets, &holding.target, "holding.target")?;
        lookup(&problem.dimensions, &holding.dimension, "holding.dimension")?;
        if let HoldingKind::Ordinary { item } = &holding.kind {
            let observed = lookup(&problem.observed, item, "holding.item")?;
            if !matches!(&observed.binding, ObservedBinding::Target { target } if target == &holding.target)
            {
                return Err(ModelError::new(
                    "holding.target",
                    "ordinary holding must use its item's observed target",
                ));
            }
            *fragments
                .entry((item.clone(), holding.dimension.clone()))
                .or_default() += holding.quantity.get();
        }
    }
    for ((item, dimension), total) in fragments {
        let observed = lookup(&problem.observed, &item, "observed")?;
        let expected = lookup(&observed.charges, &dimension, "observed.charges")?;
        if total != BigInt::from(expected.get()) {
            return Err(ModelError::new(
                "holdings",
                "ordinary fragments must exactly sum to the declared historical charge",
            ));
        }
    }

    Ok(())
}

fn build_topology(
    problem: &mut Problem,
) -> Result<BTreeMap<String, BTreeMap<String, String>>, ModelError> {
    let mut topology = BTreeMap::new();
    for (family, members) in &mut problem.scope_families {
        let mut mapping = BTreeMap::new();
        for (member, targets) in members {
            require_id(member, "scope_families.member")?;
            normalize_set(targets, "scope_families.targets")?;
            require_references(targets, &problem.targets, "scope_families.targets")?;
            for target in targets {
                if mapping.insert(target.clone(), member.clone()).is_some() {
                    return Err(ModelError::new(
                        format!("scope_families.{family}"),
                        "target belongs to multiple members",
                    ));
                }
            }
        }
        if mapping.len() != problem.targets.len() {
            return Err(ModelError::new(
                format!("scope_families.{family}"),
                "family must cover every target exactly once",
            ));
        }
        topology.insert(family.clone(), mapping);
    }

    Ok(topology)
}

fn validate_constraints(problem: &mut Problem) -> Result<(), ModelError> {
    let mut ids = BTreeSet::new();
    let mut constraints = std::mem::take(&mut problem.constraints);
    for constraint in &mut constraints {
        require_id(&constraint.id, "constraints.id")?;
        if constraint.id.starts_with('$') || !ids.insert(constraint.id.clone()) {
            return Err(ModelError::new(
                "constraints.id",
                "identifier is duplicate or uses reserved '$' prefix",
            ));
        }
        if constraint.enforcement == Enforcement::Repair
            && !matches!(
                constraint.rule,
                ConstraintRule::Capacity { .. }
                    | ConstraintRule::Admission { .. }
                    | ConstraintRule::Spread { .. }
            )
        {
            return Err(ModelError::new(
                "constraints.enforcement",
                "only numeric capacity, admission, and spread bounds are repairable",
            ));
        }

        match &mut constraint.rule {
            ConstraintRule::Eligibility { items, targets } => {
                normalize_set(items, "eligibility.items")?;
                normalize_set(targets, "eligibility.targets")?;
                require_references(items, &problem.items, "eligibility.items")?;
                require_references(targets, &problem.targets, "eligibility.targets")?;
            }
            ConstraintRule::FixedPlacement { bindings } => {
                for (item, binding) in bindings {
                    lookup(&problem.items, item, "fixed_placement.bindings")?;
                    require_binding(binding, problem, "fixed_placement.bindings")?;
                }
            }
            ConstraintRule::Capacity {
                target_set,
                dimension,
                ..
            } => {
                lookup(&problem.target_sets, target_set, "capacity.target_set")?;
                lookup(&problem.dimensions, dimension, "capacity.dimension")?;
            }
            ConstraintRule::Admission {
                group,
                minimum,
                maximum,
            } => {
                lookup(&problem.groups, group, "admission.group")?;
                if minimum > maximum {
                    return Err(ModelError::new(
                        "admission",
                        "minimum must not exceed maximum",
                    ));
                }
            }
            ConstraintRule::AtomicAdmission { group } => {
                lookup(&problem.groups, group, "atomic_admission.group")?;
            }
            ConstraintRule::CoLocation { group, family }
            | ConstraintRule::Spread { group, family, .. } => {
                lookup(&problem.groups, group, "topology_constraint.group")?;
                lookup(
                    &problem.scope_families,
                    family,
                    "topology_constraint.family",
                )?;
            }
            ConstraintRule::MovementBudget {
                items,
                costs,
                limit,
            } => {
                normalize_set(items, "movement_budget.items")?;
                validate_movement(items, costs, problem)?;
                input_rational(limit, "movement_budget.limit")?;
                if limit.is_negative() {
                    return Err(ModelError::new(
                        "movement_budget.limit",
                        "must be nonnegative",
                    ));
                }
            }
        }
    }
    constraints.sort_by(|left, right| left.id.cmp(&right.id));
    problem.constraints = constraints;
    problem
        .holdings
        .sort_by(|left, right| left.id.cmp(&right.id));

    Ok(())
}

fn validate_objectives(
    problem: &mut Problem,
    constraint_index: &BTreeMap<String, usize>,
) -> Result<(), ModelError> {
    let mut tiers = std::mem::take(&mut problem.objectives);
    let mut tier_ids = BTreeSet::new();
    let mut term_ids = BTreeSet::new();
    for tier in &mut tiers {
        require_id(&tier.id, "objectives.id")?;
        if !tier_ids.insert(tier.id.clone()) {
            return Err(ModelError::new(
                "objectives.id",
                "duplicate tier identifier",
            ));
        }
        for term in &mut tier.terms {
            require_id(&term.id, "objective.term.id")?;
            if !term_ids.insert(term.id.clone()) {
                return Err(ModelError::new(
                    "objective.term.id",
                    "duplicate term identifier",
                ));
            }
            input_rational(&term.weight, "objective.weight")?;
            input_rational(&term.normalizer, "objective.normalizer")?;
            if term.weight.is_negative()
                || term.normalizer.is_negative()
                || term.normalizer.is_zero()
            {
                return Err(ModelError::new(
                    "objective",
                    "weight must be nonnegative and normalizer strictly positive",
                ));
            }
            validate_metric(&mut term.metric, problem, constraint_index)?;
        }
        tier.terms.sort_by(|left, right| left.id.cmp(&right.id));
    }
    problem.objectives = tiers;

    Ok(())
}

fn validate_metric(
    metric: &mut Metric,
    problem: &Problem,
    constraint_index: &BTreeMap<String, usize>,
) -> Result<(), ModelError> {
    match metric {
        Metric::AdmittedCount { items } | Metric::UsedTargets { items } => {
            normalize_set(items, "metric.items")?;
            require_references(items, &problem.items, "metric.items")?;
        }
        Metric::AdmittedPriority { priorities } => {
            for (item, priority) in priorities {
                lookup(&problem.items, item, "metric.priorities")?;
                input_rational(priority, "metric.priority")?;
                if priority.is_negative() {
                    return Err(ModelError::new("metric.priority", "must be nonnegative"));
                }
            }
        }
        Metric::AssignmentCost { costs } => {
            for (item, values) in costs {
                validate_cost_table(item, values, problem, false, None)?;
            }
        }
        Metric::MovementCost { items, costs } => {
            normalize_set(items, "metric.items")?;
            validate_movement(items, costs, problem)?;
        }
        Metric::RepairDebt { components } => {
            components.sort();
            if components.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err(ModelError::new(
                    "metric.components",
                    "duplicate repair component",
                ));
            }
            let mut unit = None;
            for component in components {
                if !valid_repair_component(problem, constraint_index, component) {
                    return Err(ModelError::new(
                        "metric.components",
                        "unknown or non-repair constraint component",
                    ));
                }
                let component_unit = repair_unit(problem, constraint_index, component)?;
                if unit
                    .as_ref()
                    .is_some_and(|expected| expected != &component_unit)
                {
                    return Err(ModelError::new(
                        "metric.components",
                        "repair components have incompatible units; normalize in separate terms",
                    ));
                }
                unit = Some(component_unit);
            }
        }
        Metric::MaximumUtilization { members } | Metric::UtilizationRange { members } => {
            validate_utilizations(members, problem)?;
        }
        Metric::TotalAbsoluteDeviation { members } => {
            let mut selections = members
                .iter()
                .map(|reference| reference.member.clone())
                .collect::<Vec<_>>();
            validate_utilizations(&mut selections, problem)?;
            for reference in members.iter() {
                input_rational(&reference.reference, "metric.reference")?;
            }
            members.sort_by(|left, right| left.member.id.cmp(&right.member.id));
        }
    }

    Ok(())
}

fn valid_repair_component(
    problem: &Problem,
    constraint_index: &BTreeMap<String, usize>,
    component: &ComponentId,
) -> bool {
    let Some(constraint) = constraint_index
        .get(&component.constraint)
        .and_then(|index| problem.constraints.get(*index))
    else {
        return false;
    };
    if constraint.enforcement != Enforcement::Repair {
        return false;
    }
    match &constraint.rule {
        ConstraintRule::Capacity { .. } => component.component == "capacity",
        ConstraintRule::Admission { .. } => {
            matches!(component.component.as_str(), "minimum" | "maximum")
        }
        ConstraintRule::Spread {
            family,
            maximum_per_member,
            ..
        } => {
            if component.component == "minimum" {
                return true;
            }
            maximum_per_member.is_some()
                && component
                    .component
                    .strip_prefix("member:")
                    .is_some_and(|member| {
                        problem
                            .scope_families
                            .get(family)
                            .is_some_and(|members| members.contains_key(member))
                    })
        }
        _ => false,
    }
}

fn repair_unit(
    problem: &Problem,
    constraint_index: &BTreeMap<String, usize>,
    component: &ComponentId,
) -> Result<String, ModelError> {
    let constraint = constraint_index
        .get(&component.constraint)
        .and_then(|index| problem.constraints.get(*index))
        .ok_or_else(|| ModelError::new("metric.components", "unknown constraint"))?;
    match &constraint.rule {
        ConstraintRule::Capacity { dimension, .. } => Ok(format!("resource:{dimension}")),
        ConstraintRule::Admission { .. } => Ok("items".into()),
        ConstraintRule::Spread { family, .. } if component.component == "minimum" => {
            Ok(format!("scope_members:{family}"))
        }
        ConstraintRule::Spread { .. } => Ok("items".into()),
        _ => Err(ModelError::new(
            "metric.components",
            "constraint has no numeric repair units",
        )),
    }
}

fn validate_utilizations(
    members: &mut [UtilizationMember],
    problem: &Problem,
) -> Result<(), ModelError> {
    if members.is_empty() {
        return Err(ModelError::new(
            "metric.members",
            "utilization selection must be nonempty",
        ));
    }
    let mut ids = BTreeSet::new();
    for member in members.iter() {
        require_id(&member.id, "metric.member.id")?;
        if !ids.insert(&member.id) {
            return Err(ModelError::new(
                "metric.member.id",
                "duplicate utilization member",
            ));
        }
        lookup(
            &problem.target_sets,
            &member.target_set,
            "metric.member.target_set",
        )?;
        lookup(
            &problem.dimensions,
            &member.dimension,
            "metric.member.dimension",
        )?;
        if member.capacity.get() == 0 {
            return Err(ModelError::new(
                "metric.member.capacity",
                "must be positive",
            ));
        }
    }
    members.sort_by(|left, right| left.id.cmp(&right.id));

    Ok(())
}

fn validate_movement(
    items: &[String],
    costs: &mut MovementCosts,
    problem: &Problem,
) -> Result<(), ModelError> {
    require_references(items, &problem.items, "movement.items")?;
    if costs.unit.is_empty() {
        return Err(ModelError::new("movement.unit", "must be nonempty"));
    }
    costs.categories.sort();
    if costs.categories.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ModelError::new("movement.categories", "duplicate category"));
    }
    if costs.costs.len() != items.len() || items.iter().any(|item| !costs.costs.contains_key(item))
    {
        return Err(ModelError::new(
            "movement.costs",
            "cost tables must exactly cover selected items",
        ));
    }
    for (item, values) in &costs.costs {
        validate_cost_table(item, values, problem, true, Some(&costs.categories))?;
    }

    Ok(())
}

fn validate_cost_table(
    item: &str,
    costs: &AssignmentCosts,
    problem: &Problem,
    nonnegative: bool,
    categories: Option<&[MovementCategory]>,
) -> Result<(), ModelError> {
    let spec = lookup(&problem.items, item, "costs.item")?;
    let domain = lookup(&problem.domains, &spec.domain, "costs.domain")?;
    for target in costs.targets.keys() {
        lookup(&problem.targets, target, "costs.targets")?;
    }
    for value in costs
        .targets
        .values()
        .chain(costs.default.iter())
        .chain(std::iter::once(&costs.deferred))
    {
        input_rational(value, "costs.value")?;
        if nonnegative && value.is_negative() {
            return Err(ModelError::new(
                "costs.value",
                "movement cost must be nonnegative",
            ));
        }
    }
    let observed = lookup(&problem.observed, item, "costs.observed")?;
    if costs.default.is_some() {
        return Ok(());
    }
    for target in domain {
        let charged = match categories {
            None => true,
            Some(categories) => match &observed.binding {
                ObservedBinding::Unplaced => categories.contains(&MovementCategory::NewPlacement),
                ObservedBinding::Target { target: source } => {
                    source != target && categories.contains(&MovementCategory::Relocation)
                }
            },
        };
        if charged && !costs.targets.contains_key(target) {
            return Err(ModelError::new(
                "costs.targets",
                format!("no cost for eligible target {target:?}"),
            ));
        }
    }

    Ok(())
}

pub(crate) fn input_rational(value: &Rational, path: &str) -> Result<(), ModelError> {
    if value.numerator().to_i64().is_none() || value.denominator().to_u64().is_none() {
        return Err(ModelError::new(
            path,
            "input rational must have signed 64-bit numerator and positive unsigned 64-bit denominator",
        ));
    }

    Ok(())
}

pub(crate) fn check_size(value: &BigInt, path: &str) -> Result<(), ModelError> {
    if value.bits() > MAX_EVALUATION_BITS {
        return Err(ModelError {
            kind: ModelErrorKind::NumericExhaustion,
            path: path.into(),
            message: format!("exact integer exceeds {MAX_EVALUATION_BITS} bits"),
        });
    }

    Ok(())
}

pub(crate) fn check_rational(value: &Rational, path: &str) -> Result<(), ModelError> {
    check_size(value.numerator(), path)?;
    check_size(value.denominator(), path)
}

pub(crate) fn require_binding(
    binding: &Binding,
    problem: &Problem,
    path: &str,
) -> Result<(), ModelError> {
    if let Binding::Target { target } = binding {
        lookup(&problem.targets, target, path)?;
    }

    Ok(())
}

fn require_dimension_keys<T>(
    values: &BTreeMap<String, T>,
    problem: &Problem,
    path: &str,
) -> Result<(), ModelError> {
    if values.len() != problem.dimensions.len()
        || problem.dimensions.keys().any(|id| !values.contains_key(id))
    {
        return Err(ModelError::new(
            path,
            "must explicitly define exactly every resource dimension",
        ));
    }

    Ok(())
}

fn require_id(id: &str, path: &str) -> Result<(), ModelError> {
    if id.is_empty() {
        return Err(ModelError::new(path, "identifier must be nonempty"));
    }

    Ok(())
}

fn normalize_set(values: &mut [String], path: &str) -> Result<(), ModelError> {
    values.sort();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ModelError::new(path, "duplicate set member"));
    }

    Ok(())
}

fn require_references<T>(
    values: &[String],
    entities: &BTreeMap<String, T>,
    path: &str,
) -> Result<(), ModelError> {
    for value in values {
        lookup(entities, value, path)?;
    }

    Ok(())
}
