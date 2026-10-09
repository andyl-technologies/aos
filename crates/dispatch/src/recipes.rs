//! Inspectable policy expansions for packing, replica spread, and evacuation.
//!
//! Recipes emit ordinary target sets, constraints, and objective tiers. They do
//! not discover topology, assume application policy, or reserve resources. An
//! expansion can be serialized, reviewed, and changed before it is applied:
//!
//! ```json
//! {"target_sets":{},"constraints":[],"objectives":[]}
//! ```

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    AccountingPhase, Binding, Capacity, Constraint, ConstraintRule, Demand, Direction, Enforcement,
    Metric, ModelError, ObjectiveTerm, ObjectiveTier, ObservedBinding, Problem, Quantity, Rational,
};

/// Contains only ordinary model operations produced by a policy recipe.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyExpansion {
    /// Additional named target sets, which may overlap existing sets.
    pub target_sets: BTreeMap<String, Vec<String>>,
    /// Additional requirements with explicit enforcement modes.
    pub constraints: Vec<Constraint>,
    /// Objective tiers appended after existing tiers.
    pub objectives: Vec<ObjectiveTier>,
}

impl PolicyExpansion {
    /// Applies every operation atomically after checking identifier collisions.
    ///
    /// # Errors
    ///
    /// Returns an error when an expansion would duplicate a target set,
    /// constraint, objective tier, or objective term. The problem remains
    /// unchanged on failure. Full structural validation is a separate operation.
    pub fn apply(self, problem: &mut Problem) -> Result<(), ModelError> {
        for id in self.target_sets.keys() {
            if problem.target_sets.contains_key(id) {
                return Err(ModelError::new(
                    format!("target_sets.{id}"),
                    "policy identifier collision",
                ));
            }
        }

        check_identifiers(
            problem
                .constraints
                .iter()
                .map(|constraint| constraint.id.as_str()),
            self.constraints
                .iter()
                .map(|constraint| constraint.id.as_str()),
            "constraints",
        )?;
        check_identifiers(
            problem.objectives.iter().map(|tier| tier.id.as_str()),
            self.objectives.iter().map(|tier| tier.id.as_str()),
            "objectives",
        )?;
        check_identifiers(
            problem
                .objectives
                .iter()
                .flat_map(|tier| tier.terms.iter())
                .map(|term| term.id.as_str()),
            self.objectives
                .iter()
                .flat_map(|tier| tier.terms.iter())
                .map(|term| term.id.as_str()),
            "objective_terms",
        )?;

        problem.target_sets.extend(self.target_sets);
        problem.constraints.extend(self.constraints);
        problem.objectives.extend(self.objectives);
        Ok(())
    }
}

/// Constructs an explicit uniform demand with no target overrides.
pub fn uniform_demand(quantity: u64) -> Demand {
    Demand {
        default: Some(Quantity::new(quantity)),
        overrides: BTreeMap::new(),
    }
}

/// Expands declared finite target capacities into per-target capacity predicates.
///
/// Unbounded target capacities remain explicitly unbounded and produce no finite
/// predicate. This recipe adds no admission or balance objective.
///
/// # Errors
///
/// Returns an error for unknown dimensions, repeated dimensions, or targets that
/// omit a capacity for a selected dimension.
pub fn packing_capacity(
    name: &str,
    problem: &Problem,
    dimensions: &[String],
    phase: AccountingPhase,
    enforcement: Enforcement,
) -> Result<PolicyExpansion, ModelError> {
    let mut selected = BTreeSet::new();
    for dimension in dimensions {
        if !problem.dimensions.contains_key(dimension) || !selected.insert(dimension) {
            return Err(ModelError::new(
                "recipe.dimensions",
                "unknown or repeated dimension",
            ));
        }
    }

    let mut expansion = PolicyExpansion::default();
    for (target_id, target) in &problem.targets {
        let target_set = generated_id(name, "target", &[target_id]);
        let mut constrained = false;
        for dimension in dimensions {
            let capacity = target.capacities.get(dimension).ok_or_else(|| {
                ModelError::new(
                    format!("targets.{target_id}.capacities.{dimension}"),
                    "capacity is missing",
                )
            })?;
            if let Capacity::Finite { limit } = capacity {
                expansion.constraints.push(Constraint {
                    id: generated_id(name, "capacity", &[target_id, dimension]),
                    enforcement,
                    rule: ConstraintRule::Capacity {
                        target_set: target_set.clone(),
                        dimension: dimension.clone(),
                        phase,
                        limit: *limit,
                    },
                });
                constrained = true;
            }
        }

        if constrained {
            expansion
                .target_sets
                .insert(target_set, vec![target_id.clone()]);
        }
    }

    Ok(expansion)
}

/// Requires an explicit replica count and separation across a supplied family.
///
/// Replica items remain distinct placement units. This expansion adds hard
/// admission and spread requirements; it does not infer durability from target
/// identifiers or create a topology family.
pub fn replica_spread(
    name: &str,
    group: impl Into<String>,
    replica_count: u64,
    family: impl Into<String>,
    minimum_domains: u64,
    maximum_per_member: Option<u64>,
) -> PolicyExpansion {
    let group = group.into();
    PolicyExpansion {
        constraints: vec![
            Constraint {
                id: generated_id(name, "admission", &[]),
                enforcement: Enforcement::Hard,
                rule: ConstraintRule::Admission {
                    group: group.clone(),
                    minimum: Quantity::new(replica_count),
                    maximum: Quantity::new(replica_count),
                },
            },
            Constraint {
                id: generated_id(name, "spread", &[]),
                enforcement: Enforcement::Hard,
                rule: ConstraintRule::Spread {
                    group,
                    family: family.into(),
                    minimum: Quantity::new(minimum_domains),
                    maximum_per_member: maximum_per_member.map(Quantity::new),
                    when_admitted: false,
                },
            },
        ],
        ..PolicyExpansion::default()
    }
}

/// Restricts selected items to targets outside an explicit evacuation set.
///
/// Historical targets, charges, and observed holdings remain in the problem.
/// The emitted eligibility predicate intersects each item's existing domain;
/// this recipe neither authorizes migration nor introduces deferral.
///
/// # Errors
///
/// Returns an error for unknown or repeated item or target identifiers.
pub fn evacuate(
    name: &str,
    problem: &Problem,
    items: Vec<String>,
    evacuating_targets: &[String],
) -> Result<PolicyExpansion, ModelError> {
    check_selection(&items, &problem.items, "recipe.items")?;
    check_selection(
        evacuating_targets,
        &problem.targets,
        "recipe.evacuating_targets",
    )?;
    let excluded: BTreeSet<_> = evacuating_targets.iter().collect();
    let targets = problem
        .targets
        .keys()
        .filter(|target| !excluded.contains(target))
        .cloned()
        .collect();

    Ok(PolicyExpansion {
        constraints: vec![Constraint {
            id: generated_id(name, "eligibility", &[]),
            enforcement: Enforcement::Hard,
            rule: ConstraintRule::Eligibility { items, targets },
        }],
        ..PolicyExpansion::default()
    })
}

/// Freezes selected observed bindings as explicit hard placement requirements.
///
/// An unplaced observation becomes `Deferred`. This does not override mandatory
/// admission or eligibility, so freezing can deliberately create an infeasible
/// combination of otherwise valid requirements.
///
/// # Errors
///
/// Returns an error for unknown or repeated items or missing observations.
pub fn freeze_observed(
    name: &str,
    problem: &Problem,
    items: &[String],
) -> Result<PolicyExpansion, ModelError> {
    check_selection(items, &problem.items, "recipe.items")?;
    let mut bindings = BTreeMap::new();
    for item in items {
        let observation = problem
            .observed
            .get(item)
            .ok_or_else(|| ModelError::new(format!("observed.{item}"), "observation is missing"))?;
        let binding = match &observation.binding {
            ObservedBinding::Target { target } => Binding::Target {
                target: target.clone(),
            },
            ObservedBinding::Unplaced => Binding::Deferred,
        };
        bindings.insert(item.clone(), binding);
    }

    Ok(PolicyExpansion {
        constraints: vec![Constraint {
            id: generated_id(name, "fixed", &[]),
            enforcement: Enforcement::Hard,
            rule: ConstraintRule::FixedPlacement { bindings },
        }],
        ..PolicyExpansion::default()
    })
}

/// Appends a tier minimizing destinations used by an explicit item selection.
///
/// Fixed or additional occupancy does not count toward this metric. A preferred
/// plan therefore makes no claim that unused targets can be shut down.
pub fn minimize_used_targets(name: &str, items: Vec<String>) -> PolicyExpansion {
    PolicyExpansion {
        objectives: vec![ObjectiveTier {
            id: generated_id(name, "tier", &[]),
            terms: vec![ObjectiveTerm {
                id: generated_id(name, "used_targets", &[]),
                direction: Direction::Minimize,
                weight: Rational::one(),
                normalizer: Rational::one(),
                metric: Metric::UsedTargets { items },
            }],
        }],
        ..PolicyExpansion::default()
    }
}

fn generated_id(name: &str, operation: &str, identifiers: &[&str]) -> String {
    // Length-prefixing avoids collisions when opaque identifiers contain slashes.
    let mut id = format!("{name}/{operation}");
    for identifier in identifiers {
        id.push_str(&format!("/{}:{identifier}", identifier.len()));
    }
    id
}

fn check_identifiers<'a>(
    existing: impl Iterator<Item = &'a str>,
    incoming: impl Iterator<Item = &'a str>,
    field: &str,
) -> Result<(), ModelError> {
    let mut identifiers: BTreeSet<&str> = existing.collect();
    for id in incoming {
        if !identifiers.insert(id) {
            return Err(ModelError::new(
                format!("{field}.{id}"),
                "policy identifier collision",
            ));
        }
    }
    Ok(())
}

fn check_selection<T>(
    selection: &[String],
    entities: &BTreeMap<String, T>,
    field: &str,
) -> Result<(), ModelError> {
    let mut selected = BTreeSet::new();
    for id in selection {
        if !entities.contains_key(id) || !selected.insert(id) {
            return Err(ModelError::new(field, "unknown or repeated identifier"));
        }
    }
    Ok(())
}
