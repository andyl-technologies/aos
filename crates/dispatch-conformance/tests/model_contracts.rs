//! Exhaustive semantic checks against independent accepted-tuple and charge tables.

#![allow(clippy::expect_used)]

mod support;

use std::collections::{BTreeMap, BTreeSet};

use dispatch_model::{
    AccountingPhase, AssignmentCosts, Binding, ComponentId, Constraint, ConstraintRule, Direction,
    Enforcement, Holding, HoldingKind, Metric, MovementCategory, MovementCosts, ObjectiveTerm,
    ObjectiveTier, Quantity, UtilizationMember, UtilizationReference, evaluate, validate, verify,
};

use support::{models, oracle};

fn domain(values: &[usize]) -> BTreeSet<usize> {
    values.iter().copied().collect()
}

fn bound(coefficients: Vec<Vec<u128>>, constant: u128, limit: u128) -> oracle::Bound {
    oracle::Bound {
        coefficients,
        constant,
        minimum: None,
        maximum: Some(limit),
        lower_allowance: 0,
        upper_allowance: 0,
    }
}

fn assert_exhaustive(problem: dispatch_model::Problem, expected: oracle::Problem) {
    let validated = validate(problem).expect("valid finite fixture");
    for choices in expected.assignments() {
        let answer = expected.classify(&choices);
        let candidate = models::assignment(&choices);
        let verified = verify(&validated, candidate);
        assert_eq!(
            verified.is_ok(),
            answer.accepted,
            "assignment {choices:?}: {verified:?} versus {answer:?}"
        );
        if let Ok(verified) = &verified {
            assert_eq!(
                verified.classification() == dispatch_model::VerificationClass::Repair,
                answer.repair,
                "repair classification for {choices:?}"
            );
        }
        if !answer.objectives.is_empty() {
            let evaluation =
                evaluate(&validated, &models::assignment(&choices)).expect("objective evaluation");
            assert_eq!(evaluation.objectives.len(), answer.objectives.len());
            for (actual, expected) in evaluation.objectives.iter().zip(answer.objectives) {
                assert_eq!(
                    actual,
                    &models::rational(
                        i64::try_from(expected.numerator).expect("small fixture numerator"),
                        u64::try_from(expected.denominator).expect("small fixture denominator"),
                    ),
                    "objective for assignment {choices:?}"
                );
            }
        }
    }
}

#[test]
fn admission_repair_bounds_each_side_against_its_observed_baseline() {
    let mut problem = models::problem(&[[1, 1]; 2], &[true; 2], &[Some(0), None], &[1, 0]);
    problem.constraints.push(Constraint {
        id: "admitted_pair".into(),
        enforcement: Enforcement::Repair,
        rule: ConstraintRule::Admission {
            group: "all".into(),
            minimum: Quantity::new(2),
            maximum: Quantity::new(2),
        },
    });
    assert_exhaustive(
        problem,
        oracle::Problem {
            targets: 2,
            domains: vec![domain(&[0, 1, 2]); 2],
            bounds: vec![oracle::Bound {
                coefficients: vec![vec![0, 1, 1]; 2],
                constant: 0,
                minimum: Some(2),
                maximum: Some(2),
                lower_allowance: 1,
                upper_allowance: 0,
            }],
            relations: Vec::new(),
            objectives: Vec::new(),
        },
    );
}

#[test]
fn exact_signed_weighted_tiers_preserve_lexicographic_order() {
    let mut problem = models::problem(&[[1, 1]; 2], &[true; 2], &[None; 2], &[0; 2]);
    let costs = BTreeMap::from_iter((0..2).map(|index| {
        (
            models::item(index),
            AssignmentCosts {
                default: None,
                targets: BTreeMap::from([
                    (models::target(0), models::rational(2, 1)),
                    (models::target(1), models::rational(7, 1)),
                ]),
                deferred: models::rational(1, 1),
            },
        )
    }));
    problem.objectives = vec![
        ObjectiveTier {
            id: "mixed".into(),
            terms: vec![
                ObjectiveTerm {
                    id: "admission".into(),
                    direction: Direction::Maximize,
                    weight: models::rational(5, 1),
                    normalizer: models::rational(2, 1),
                    metric: Metric::AdmittedCount {
                        items: vec![models::item(0), models::item(1)],
                    },
                },
                ObjectiveTerm {
                    id: "placement_cost".into(),
                    direction: Direction::Minimize,
                    weight: models::rational(3, 1),
                    normalizer: models::rational(2, 1),
                    metric: Metric::AssignmentCost { costs },
                },
            ],
        },
        ObjectiveTier {
            id: "priority".into(),
            terms: vec![ObjectiveTerm {
                id: "priority".into(),
                direction: Direction::Maximize,
                weight: models::rational(1, 1),
                normalizer: models::rational(1, 1),
                metric: Metric::AdmittedPriority {
                    priorities: BTreeMap::from([
                        (models::item(0), models::rational(1, 3)),
                        (models::item(1), models::rational(2, 7)),
                    ]),
                },
            }],
        },
    ];
    let f = oracle::Fraction::new;
    let expected = oracle::Problem {
        targets: 2,
        domains: vec![domain(&[0, 1, 2]); 2],
        bounds: Vec::new(),
        relations: Vec::new(),
        objectives: vec![
            oracle::Objective {
                coefficients: vec![vec![f(3, 2), f(1, 2), f(8, 1)]; 2],
                constant: f(0, 1),
            },
            oracle::Objective {
                coefficients: vec![
                    vec![f(0, 1), f(-1, 3), f(-1, 3)],
                    vec![f(0, 1), f(-2, 7), f(-2, 7)],
                ],
                constant: f(0, 1),
            },
        ],
    };
    let best = expected
        .assignments()
        .into_iter()
        .min_by_key(|choices| expected.classify(choices).objectives)
        .expect("finite oracle optimum");
    assert_eq!(best, vec![1, 1]);
    assert_exhaustive(problem, expected);
}

#[test]
fn movement_budget_and_metric_charge_new_relocation_and_retirement_separately() {
    let mut problem = models::problem(&[[1, 1]; 2], &[true; 2], &[Some(0), None], &[1, 0]);
    let costs = MovementCosts {
        unit: "transfer_units".into(),
        categories: vec![
            MovementCategory::NewPlacement,
            MovementCategory::Relocation,
            MovementCategory::Retirement,
        ],
        costs: BTreeMap::from([
            (
                models::item(0),
                AssignmentCosts {
                    default: None,
                    targets: BTreeMap::from([(models::target(1), models::rational(5, 1))]),
                    deferred: models::rational(9, 1),
                },
            ),
            (
                models::item(1),
                AssignmentCosts {
                    default: None,
                    targets: BTreeMap::from([
                        (models::target(0), models::rational(2, 1)),
                        (models::target(1), models::rational(7, 1)),
                    ]),
                    deferred: models::rational(0, 1),
                },
            ),
        ]),
    };
    problem.constraints.push(Constraint {
        id: "transfer_budget".into(),
        enforcement: Enforcement::Hard,
        rule: ConstraintRule::MovementBudget {
            items: vec![models::item(0), models::item(1)],
            costs: costs.clone(),
            limit: models::rational(6, 1),
        },
    });
    problem.objectives.push(ObjectiveTier {
        id: "movement".into(),
        terms: vec![ObjectiveTerm {
            id: "movement".into(),
            direction: Direction::Minimize,
            weight: models::rational(1, 1),
            normalizer: models::rational(1, 1),
            metric: Metric::MovementCost {
                items: vec![models::item(0), models::item(1)],
                costs,
            },
        }],
    });
    let f = oracle::Fraction::new;
    assert_exhaustive(
        problem,
        oracle::Problem {
            targets: 2,
            domains: vec![domain(&[0, 1, 2]); 2],
            bounds: vec![bound(vec![vec![9, 0, 5], vec![0, 2, 7]], 0, 6)],
            relations: Vec::new(),
            objectives: vec![oracle::Objective {
                coefficients: vec![
                    vec![f(9, 1), f(0, 1), f(5, 1)],
                    vec![f(0, 1), f(2, 1), f(7, 1)],
                ],
                constant: f(0, 1),
            }],
        },
    );
}

#[test]
fn nonlinear_utilization_and_distinct_target_metrics_match_small_exhaustive_tables() {
    let mut problem = models::problem(&[[2, 3], [4, 1]], &[true; 2], &[None; 2], &[0; 2]);
    problem
        .targets
        .get_mut(&models::target(0))
        .expect("left")
        .fixed_load
        .insert("bytes".into(), Quantity::new(1));
    problem
        .targets
        .get_mut(&models::target(1))
        .expect("right")
        .fixed_load
        .insert("bytes".into(), Quantity::new(2));
    let members = vec![
        UtilizationMember {
            id: "left".into(),
            target_set: "left".into(),
            dimension: "bytes".into(),
            phase: AccountingPhase::Final,
            capacity: Quantity::new(3),
        },
        UtilizationMember {
            id: "right".into(),
            target_set: "right".into(),
            dimension: "bytes".into(),
            phase: AccountingPhase::Final,
            capacity: Quantity::new(4),
        },
    ];
    let references = vec![
        UtilizationReference {
            member: members[0].clone(),
            reference: models::rational(1, 2),
        },
        UtilizationReference {
            member: members[1].clone(),
            reference: models::rational(3, 4),
        },
    ];
    problem.objectives.push(ObjectiveTier {
        id: "shape".into(),
        terms: vec![
            (
                "maximum",
                Metric::MaximumUtilization {
                    members: members.clone(),
                },
            ),
            ("range", Metric::UtilizationRange { members }),
            (
                "deviation",
                Metric::TotalAbsoluteDeviation {
                    members: references,
                },
            ),
            (
                "targets",
                Metric::UsedTargets {
                    items: vec![models::item(0), models::item(1)],
                },
            ),
        ]
        .into_iter()
        .map(|(id, metric)| ObjectiveTerm {
            id: id.into(),
            direction: Direction::Minimize,
            weight: models::rational(1, 1),
            normalizer: models::rational(1, 1),
            metric,
        })
        .collect(),
    });
    let validated = validate(problem).expect("nonlinear metric fixture");
    let f = oracle::Fraction::new;
    let left_coefficients = [[0, 2, 0], [0, 4, 0]];
    let right_coefficients = [[0, 0, 3], [0, 0, 1]];
    for first in 0..3 {
        for second in 0..3 {
            let left = f(
                1 + left_coefficients[0][first] + left_coefficients[1][second],
                3,
            );
            let right = f(
                2 + right_coefficients[0][first] + right_coefficients[1][second],
                4,
            );
            let maximum = left.max(right);
            let range = left.plus(right.times(f(-1, 1))).absolute();
            let deviation = left
                .plus(f(-1, 2))
                .absolute()
                .plus(right.plus(f(-3, 4)).absolute());
            let used = BTreeSet::from([first, second])
                .into_iter()
                .filter(|choice| *choice != 0)
                .count();
            let expected = [
                ("maximum", maximum),
                ("range", range),
                ("deviation", deviation),
                ("targets", f(used as i128, 1)),
            ];
            let evaluation = evaluate(&validated, &models::assignment(&[first, second]))
                .expect("metric evaluation");
            let mut sum = f(0, 1);
            for (id, value) in expected {
                let rational = models::rational(
                    i64::try_from(value.numerator).expect("small numerator"),
                    u64::try_from(value.denominator).expect("small denominator"),
                );
                assert_eq!(
                    evaluation.term_values.get(id),
                    Some(&rational),
                    "term {id} choices {first},{second}"
                );
                sum = sum.plus(value);
            }
            assert_eq!(
                evaluation.objectives,
                vec![models::rational(
                    i64::try_from(sum.numerator).expect("small numerator"),
                    u64::try_from(sum.denominator).expect("small denominator")
                )]
            );
        }
    }
}

#[test]
fn repair_debt_metric_uses_historical_charges_without_double_counting_observation() {
    let mut problem = models::problem(&[[4, 8]], &[true], &[Some(0)], &[6]);
    problem.constraints.push(models::capacity(
        "limit",
        "left",
        AccountingPhase::Final,
        3,
        Enforcement::Repair,
    ));
    problem.objectives.push(ObjectiveTier {
        id: "debt".into(),
        terms: vec![ObjectiveTerm {
            id: "debt".into(),
            direction: Direction::Minimize,
            weight: models::rational(1, 1),
            normalizer: models::rational(1, 1),
            metric: Metric::RepairDebt {
                components: vec![ComponentId {
                    constraint: "limit".into(),
                    component: "capacity".into(),
                }],
            },
        }],
    });
    let validated = validate(problem).expect("historical repair baseline");
    for (choice, debt) in [(0, 0), (1, 1), (2, 0)] {
        let evaluation =
            evaluate(&validated, &models::assignment(&[choice])).expect("debt evaluation");
        assert_eq!(evaluation.repair_debt.len(), 1);
        assert_eq!(evaluation.repair_debt[0].baseline.to_string(), "3");
        assert_eq!(evaluation.repair_debt[0].debt.to_string(), debt.to_string());
        assert_eq!(evaluation.objectives, vec![models::rational(debt, 1)]);
    }
}

#[test]
fn malformed_models_and_partial_assignments_fail_closed() {
    let base = models::problem(&[[1, 2]], &[false], &[None], &[0]);
    let mut invalid = Vec::new();

    let mut missing_charge = base.clone();
    missing_charge
        .items
        .get_mut(&models::item(0))
        .expect("item")
        .demands
        .get_mut("bytes")
        .expect("dimension")
        .overrides
        .remove(&models::target(1));
    invalid.push(missing_charge);

    let mut duplicate_scope = base.clone();
    duplicate_scope
        .scope_families
        .get_mut("host")
        .expect("family")
        .get_mut("left_host")
        .expect("member")
        .push(models::target(1));
    invalid.push(duplicate_scope);

    let mut zero_quantum = base.clone();
    zero_quantum
        .dimensions
        .get_mut("bytes")
        .expect("dimension")
        .quantum = Quantity::new(0);
    invalid.push(zero_quantum);

    let mut missing_observation = base.clone();
    missing_observation.observed.clear();
    invalid.push(missing_observation);

    for problem in invalid {
        assert!(validate(problem).is_err());
    }
    let validated = validate(base).expect("valid base");
    assert!(verify(&validated, dispatch_model::Assignment::default()).is_err());
    let mut extra = models::assignment(&[1]);
    extra
        .bindings
        .insert("unknown_item".into(), Binding::Deferred);
    assert!(verify(&validated, extra).is_err());
}

#[test]
fn exhaustive_target_dependent_capacity_eligibility_and_fixed_binding() {
    let mut problem = models::problem(
        &[[2, 4], [3, 1], [1, 2]],
        &[false, true, true],
        &[None, None, None],
        &[0, 0, 0],
    );
    problem.constraints = vec![
        models::capacity(
            "left_limit",
            "left",
            AccountingPhase::Final,
            3,
            Enforcement::Hard,
        ),
        models::capacity(
            "right_limit",
            "right",
            AccountingPhase::Final,
            5,
            Enforcement::Hard,
        ),
        Constraint {
            id: "only_left".into(),
            enforcement: Enforcement::Hard,
            rule: ConstraintRule::Eligibility {
                items: vec![models::item(2)],
                targets: vec![models::target(0)],
            },
        },
        Constraint {
            id: "pin_second".into(),
            enforcement: Enforcement::Hard,
            rule: ConstraintRule::FixedPlacement {
                bindings: BTreeMap::from([(
                    models::item(1),
                    Binding::Target {
                        target: models::target(1),
                    },
                )]),
            },
        },
    ];

    // The independent table charges each choice directly and restricts the
    // pinned coordinate through its domain, rather than reproducing predicates.
    assert_exhaustive(
        problem,
        oracle::Problem {
            targets: 2,
            domains: vec![domain(&[1, 2]), domain(&[2]), domain(&[0, 1])],
            bounds: vec![
                bound(vec![vec![0, 2, 0], vec![0, 3, 0], vec![0, 1, 0]], 0, 3),
                bound(vec![vec![0, 0, 4], vec![0, 0, 1], vec![0, 0, 2]], 0, 5),
            ],
            relations: Vec::new(),
            objectives: Vec::new(),
        },
    );
}

#[test]
fn exhaustive_atomic_and_colocated_admission_uses_exact_allowed_tuples() {
    let mut problem = models::problem(&[[1, 1], [1, 1]], &[true, true], &[None, None], &[0, 0]);
    problem.constraints = vec![
        Constraint {
            id: "gang".into(),
            enforcement: Enforcement::Hard,
            rule: ConstraintRule::AtomicAdmission {
                group: "all".into(),
            },
        },
        Constraint {
            id: "one_host".into(),
            enforcement: Enforcement::Hard,
            rule: ConstraintRule::CoLocation {
                group: "all".into(),
                family: "host".into(),
            },
        },
    ];

    assert_exhaustive(
        problem,
        oracle::Problem {
            targets: 2,
            domains: vec![domain(&[0, 1, 2]); 2],
            bounds: Vec::new(),
            relations: vec![oracle::Relation {
                items: vec![0, 1],
                allowed: BTreeSet::from([vec![0, 0], vec![1, 1], vec![2, 2]]),
            }],
            objectives: Vec::new(),
        },
    );
}

#[test]
fn exhaustive_spread_requires_real_failure_domains_and_explicit_conditional_admission() {
    for when_admitted in [false, true] {
        let mut problem = models::problem(&[[1, 1], [1, 1]], &[true, true], &[None, None], &[0, 0]);
        problem.constraints.push(Constraint {
            id: "separate_hosts".into(),
            enforcement: Enforcement::Hard,
            rule: ConstraintRule::Spread {
                group: "all".into(),
                family: "host".into(),
                minimum: Quantity::new(2),
                maximum_per_member: Some(Quantity::new(1)),
                when_admitted,
            },
        });
        let mut allowed = BTreeSet::from([vec![1, 2], vec![2, 1]]);
        if when_admitted {
            allowed.insert(vec![0, 0]);
        }

        assert_exhaustive(
            problem,
            oracle::Problem {
                targets: 2,
                domains: vec![domain(&[0, 1, 2]); 2],
                bounds: Vec::new(),
                relations: vec![oracle::Relation {
                    items: vec![0, 1],
                    allowed,
                }],
                objectives: Vec::new(),
            },
        );
    }

    let mut same_rack = models::problem(
        &[[1, 1], [1, 1]],
        &[false, false],
        &[Some(0), Some(1)],
        &[1, 1],
    );
    same_rack.constraints.push(Constraint {
        id: "separate_racks".into(),
        enforcement: Enforcement::Hard,
        rule: ConstraintRule::Spread {
            group: "all".into(),
            family: "rack".into(),
            minimum: Quantity::new(2),
            maximum_per_member: None,
            when_admitted: false,
        },
    });
    assert_exhaustive(
        same_rack,
        oracle::Problem {
            targets: 2,
            domains: vec![domain(&[1, 2]); 2],
            bounds: Vec::new(),
            relations: vec![oracle::Relation {
                items: vec![0, 1],
                allowed: BTreeSet::new(),
            }],
            objectives: Vec::new(),
        },
    );
}

#[test]
fn overlapping_atomic_groups_propagate_whole_group_admission() {
    let mut problem = models::problem(&[[1, 1]; 3], &[true; 3], &[None; 3], &[0; 3]);
    problem
        .groups
        .insert("first_pair".into(), vec![models::item(0), models::item(1)]);
    problem
        .groups
        .insert("second_pair".into(), vec![models::item(1), models::item(2)]);
    for group in ["first_pair", "second_pair"] {
        problem.constraints.push(Constraint {
            id: format!("atomic_{group}"),
            enforcement: Enforcement::Hard,
            rule: ConstraintRule::AtomicAdmission {
                group: group.into(),
            },
        });
    }

    let permitted_pairs =
        BTreeSet::from([vec![0, 0], vec![1, 1], vec![1, 2], vec![2, 1], vec![2, 2]]);
    assert_exhaustive(
        problem,
        oracle::Problem {
            targets: 2,
            domains: vec![domain(&[0, 1, 2]); 3],
            bounds: Vec::new(),
            relations: vec![
                oracle::Relation {
                    items: vec![0, 1],
                    allowed: permitted_pairs.clone(),
                },
                oracle::Relation {
                    items: vec![1, 2],
                    allowed: permitted_pairs,
                },
            ],
            objectives: Vec::new(),
        },
    );
}

#[test]
fn capacity_repair_never_transfers_debt_to_a_previously_satisfied_component() {
    let mut problem = models::problem(
        &[[6, 6], [4, 4], [3, 3]],
        &[false; 3],
        &[Some(0), Some(0), Some(1)],
        &[6, 4, 3],
    );
    problem.constraints = vec![
        models::capacity(
            "left",
            "left",
            AccountingPhase::Final,
            8,
            Enforcement::Repair,
        ),
        models::capacity(
            "right",
            "right",
            AccountingPhase::Final,
            8,
            Enforcement::Repair,
        ),
    ];
    let mut left = bound(vec![vec![0, 6, 0], vec![0, 4, 0], vec![0, 3, 0]], 0, 8);
    left.upper_allowance = 2;
    let expected = oracle::Problem {
        targets: 2,
        domains: vec![domain(&[1, 2]); 3],
        bounds: vec![
            left,
            bound(vec![vec![0, 0, 6], vec![0, 0, 4], vec![0, 0, 3]], 0, 8),
        ],
        relations: Vec::new(),
        objectives: Vec::new(),
    };

    assert!(!expected.classify(&[2, 1, 2]).accepted);
    assert!(expected.classify(&[1, 1, 2]).repair);
    assert!(expected.classify(&[1, 2, 2]).accepted);
    assert_exhaustive(problem, expected);
}

#[test]
fn spread_repair_preserves_component_identity_when_moving_debt_between_hosts() {
    let mut problem = models::problem(&[[1, 1]; 2], &[false; 2], &[Some(0), Some(0)], &[1; 2]);
    problem.constraints.push(Constraint {
        id: "replica_domains".into(),
        enforcement: Enforcement::Repair,
        rule: ConstraintRule::Spread {
            group: "all".into(),
            family: "host".into(),
            minimum: Quantity::new(2),
            maximum_per_member: Some(Quantity::new(1)),
            when_admitted: false,
        },
    });
    let mut left = bound(vec![vec![0, 1, 0]; 2], 0, 1);
    left.upper_allowance = 1;
    // Mandatory admission guarantees at least one occupied domain. The observed
    // minimum deficit of one therefore cannot worsen in this fixture. A pair
    // on the previously healthy right host creates a new forbidden component.
    assert_exhaustive(
        problem,
        oracle::Problem {
            targets: 2,
            domains: vec![domain(&[1, 2]); 2],
            bounds: vec![left, bound(vec![vec![0, 0, 1]; 2], 0, 1)],
            relations: Vec::new(),
            objectives: Vec::new(),
        },
    );
}

#[test]
fn observation_charges_and_extra_holdings_have_distinct_final_and_overlap_loads() {
    let mut problem = models::problem(&[[4, 7]], &[true], &[Some(0)], &[6]);
    problem.holdings = vec![
        Holding {
            id: "ordinary_one".into(),
            target: models::target(0),
            dimension: "bytes".into(),
            quantity: Quantity::new(2),
            kind: HoldingKind::Ordinary {
                item: models::item(0),
            },
        },
        Holding {
            id: "ordinary_two".into(),
            target: models::target(0),
            dimension: "bytes".into(),
            quantity: Quantity::new(4),
            kind: HoldingKind::Ordinary {
                item: models::item(0),
            },
        },
        Holding {
            id: "retained_copy".into(),
            target: models::target(1),
            dimension: "bytes".into(),
            quantity: Quantity::new(3),
            kind: HoldingKind::Additional {
                retained_at_final: true,
            },
        },
        Holding {
            id: "temporary_copy".into(),
            target: models::target(0),
            dimension: "bytes".into(),
            quantity: Quantity::new(2),
            kind: HoldingKind::Additional {
                retained_at_final: false,
            },
        },
    ];
    problem
        .targets
        .get_mut(&models::target(0))
        .expect("left target")
        .fixed_load
        .insert("bytes".into(), Quantity::new(1));
    let validated = validate(problem).expect("valid historical accounting");

    // These columns are stated fixture facts, including deferred retirement.
    let expected = [
        ([1_u128, 3], [9_u128, 3]),
        ([5, 3], [9, 3]),
        ([1, 10], [9, 10]),
    ];
    for (choice, (final_load, overlap_load)) in expected.iter().enumerate() {
        let evaluation =
            evaluate(&validated, &models::assignment(&[choice])).expect("evaluated accounting");
        for (phase, loads) in [
            (AccountingPhase::Final, final_load),
            (AccountingPhase::Overlap, overlap_load),
        ] {
            for (index, load) in loads.iter().enumerate() {
                let actual = evaluation
                    .resource_loads
                    .iter()
                    .find(|entry| {
                        entry.target == models::target(index)
                            && entry.dimension == "bytes"
                            && entry.phase == phase
                    })
                    .expect("complete load record");
                assert_eq!(
                    actual.quantity.to_string(),
                    load.to_string(),
                    "choice {choice}, phase {phase:?}, target {index}"
                );
            }
        }
    }
}

#[test]
fn overlap_capacity_rejects_in_place_growth_and_source_plus_destination_peak() {
    let mut problem = models::problem(&[[12, 7]], &[true], &[Some(0)], &[6]);
    problem.constraints = vec![
        models::capacity(
            "steady",
            "fleet",
            AccountingPhase::Final,
            14,
            Enforcement::Hard,
        ),
        models::capacity(
            "peak",
            "fleet",
            AccountingPhase::Overlap,
            10,
            Enforcement::Hard,
        ),
    ];
    // Retirement still retains the observed six units during transition. A
    // same-target resize peaks at twelve; relocation peaks at six plus seven.
    assert_exhaustive(
        problem,
        oracle::Problem {
            targets: 2,
            domains: vec![domain(&[0, 1, 2])],
            bounds: vec![
                bound(vec![vec![0, 12, 7]], 0, 14),
                bound(vec![vec![6, 12, 13]], 0, 10),
            ],
            relations: Vec::new(),
            objectives: Vec::new(),
        },
    );
}

#[test]
fn wide_aggregate_and_small_demand_never_wrap_or_disappear() {
    let mut problem = models::problem(
        &[[u64::MAX, u64::MAX], [1, 1]],
        &[false, false],
        &[Some(0), Some(0)],
        &[u64::MAX, 1],
    );
    problem.constraints.push(models::capacity(
        "ceiling",
        "left",
        AccountingPhase::Final,
        u64::MAX,
        Enforcement::Hard,
    ));
    let validated = validate(problem).expect("valid wide aggregate inputs");
    let candidate = models::assignment(&[1, 1]);
    let evaluation = evaluate(&validated, &candidate).expect("exact wide aggregate");
    let load = evaluation
        .resource_loads
        .iter()
        .find(|entry| entry.target == models::target(0) && entry.phase == AccountingPhase::Final)
        .expect("left final load");

    assert_eq!(load.quantity.to_string(), "18446744073709551616");
    assert!(verify(&validated, candidate).is_err());
}
