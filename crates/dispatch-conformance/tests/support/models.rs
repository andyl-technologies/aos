//! Compact public-model fixtures with explicit observations and topology.

use std::collections::BTreeMap;

use dispatch_model::{
    AccountingPhase, Assignment, Binding, Capacity, Constraint, ConstraintRule, Demand, Dimension,
    Enforcement, Item, Observation, ObservedBinding, Problem, Quantity, Rational, Target,
};

/// Constructs an exact fixture fraction.
pub fn rational(numerator: i64, denominator: u64) -> Rational {
    Rational::new(numerator.into(), denominator.into()).expect("valid fixture rational")
}

/// Returns the stable name of a fixture item.
pub fn item(index: usize) -> String {
    format!("item_{index}")
}

/// Returns the stable name of a fixture destination.
pub fn target(index: usize) -> String {
    format!("target_{index}")
}

/// Constructs a two-destination fixture without implied capacity constraints.
pub fn problem(
    demands: &[[u64; 2]],
    deferrable: &[bool],
    observed: &[Option<usize>],
    historical: &[u64],
) -> Problem {
    assert_eq!(demands.len(), deferrable.len());
    assert_eq!(demands.len(), observed.len());
    assert_eq!(demands.len(), historical.len());

    let dimensions = BTreeMap::from([(
        "bytes".into(),
        Dimension {
            unit: "bytes".into(),
            quantum: Quantity::new(1),
        },
    )]);
    let targets = (0..2)
        .map(|index| {
            (
                target(index),
                Target {
                    capacities: BTreeMap::from([(
                        "bytes".into(),
                        Capacity::Finite {
                            limit: Quantity::new(100),
                        },
                    )]),
                    fixed_load: BTreeMap::from([("bytes".into(), Quantity::new(0))]),
                },
            )
        })
        .collect();
    let items = demands
        .iter()
        .enumerate()
        .map(|(index, demand)| {
            (
                item(index),
                Item {
                    domain: "everywhere".into(),
                    deferrable: deferrable[index],
                    demands: BTreeMap::from([(
                        "bytes".into(),
                        Demand {
                            default: None,
                            overrides: BTreeMap::from([
                                (target(0), Quantity::new(demand[0])),
                                (target(1), Quantity::new(demand[1])),
                            ]),
                        },
                    )]),
                },
            )
        })
        .collect();
    let observations = observed
        .iter()
        .enumerate()
        .map(|(index, binding)| {
            (
                item(index),
                Observation {
                    binding: binding.map_or(ObservedBinding::Unplaced, |index| {
                        ObservedBinding::Target {
                            target: target(index),
                        }
                    }),
                    charges: BTreeMap::from([("bytes".into(), Quantity::new(historical[index]))]),
                },
            )
        })
        .collect();

    Problem {
        model_version: 1,
        observation_basis: BTreeMap::from([("revision".into(), "fixture-1".into())]),
        items,
        targets,
        dimensions,
        domains: BTreeMap::from([("everywhere".into(), vec![target(0), target(1)])]),
        groups: BTreeMap::from([("all".into(), (0..demands.len()).map(item).collect())]),
        target_sets: BTreeMap::from([
            ("left".into(), vec![target(0)]),
            ("right".into(), vec![target(1)]),
            ("fleet".into(), vec![target(0), target(1)]),
        ]),
        scope_families: BTreeMap::from([
            (
                "host".into(),
                BTreeMap::from([
                    ("left_host".into(), vec![target(0)]),
                    ("right_host".into(), vec![target(1)]),
                ]),
            ),
            (
                "rack".into(),
                BTreeMap::from([("one_rack".into(), vec![target(0), target(1)])]),
            ),
        ]),
        observed: observations,
        holdings: Vec::new(),
        constraints: Vec::new(),
        objectives: Vec::new(),
    }
}

/// Constructs one complete assignment from deferred-or-target tuple coordinates.
pub fn assignment(choices: &[usize]) -> Assignment {
    Assignment {
        bindings: choices
            .iter()
            .enumerate()
            .map(|(index, choice)| {
                (
                    item(index),
                    if *choice == 0 {
                        Binding::Deferred
                    } else {
                        Binding::Target {
                            target: target(*choice - 1),
                        }
                    },
                )
            })
            .collect(),
    }
}

/// Constructs an explicit singleton capacity predicate.
pub fn capacity(
    id: &str,
    target_set: &str,
    phase: AccountingPhase,
    limit: u64,
    enforcement: Enforcement,
) -> Constraint {
    Constraint {
        id: id.into(),
        enforcement,
        rule: ConstraintRule::Capacity {
            target_set: target_set.into(),
            dimension: "bytes".into(),
            phase,
            limit: Quantity::new(limit),
        },
    }
}
