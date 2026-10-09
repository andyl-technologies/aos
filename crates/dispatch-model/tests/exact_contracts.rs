//! Exact numeric, accounting, validation, and immutable-verification contracts.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use dispatch_model::*;
use num_bigint::BigInt;

fn quantity(value: u64) -> Quantity {
    Quantity::new(value)
}

fn ratio(numerator: i64, denominator: u64) -> Rational {
    Rational::new(BigInt::from(numerator), BigInt::from(denominator)).unwrap()
}

fn fixture() -> Problem {
    let dimensions = BTreeMap::from([(
        "memory".into(),
        Dimension {
            unit: "bytes".into(),
            quantum: quantity(1),
        },
    )]);
    let target = Target {
        capacities: BTreeMap::from([("memory".into(), Capacity::Finite { limit: quantity(8) })]),
        fixed_load: BTreeMap::from([("memory".into(), quantity(0))]),
    };
    let mut problem = Problem {
        model_version: 1,
        dimensions,
        targets: BTreeMap::from([("A".into(), target.clone()), ("B".into(), target)]),
        domains: BTreeMap::from([("all".into(), vec!["A".into(), "B".into()])]),
        target_sets: BTreeMap::from([
            ("A".into(), vec!["A".into()]),
            ("B".into(), vec!["B".into()]),
        ]),
        scope_families: BTreeMap::from([(
            "host".into(),
            BTreeMap::from([
                ("A".into(), vec!["A".into()]),
                ("B".into(), vec!["B".into()]),
            ]),
        )]),
        ..Problem::default()
    };
    for (item, demand, source) in [("x", 6, "A"), ("y", 4, "A"), ("z", 3, "B")] {
        problem.items.insert(
            item.into(),
            Item {
                domain: "all".into(),
                deferrable: false,
                demands: BTreeMap::from([(
                    "memory".into(),
                    Demand {
                        default: Some(quantity(demand)),
                        overrides: BTreeMap::new(),
                    },
                )]),
            },
        );
        problem.observed.insert(
            item.into(),
            Observation {
                binding: ObservedBinding::Target {
                    target: source.into(),
                },
                charges: BTreeMap::from([("memory".into(), quantity(demand))]),
            },
        );
    }
    problem
        .groups
        .insert("all".into(), vec!["x".into(), "y".into(), "z".into()]);
    for target in ["A", "B"] {
        problem.constraints.push(Constraint {
            id: target.into(),
            enforcement: Enforcement::Repair,
            rule: ConstraintRule::Capacity {
                target_set: target.into(),
                dimension: "memory".into(),
                phase: AccountingPhase::Final,
                limit: quantity(8),
            },
        });
    }

    problem
}

fn assignment(x: &str, y: &str, z: &str) -> Assignment {
    Assignment {
        bindings: [("x", x), ("y", y), ("z", z)]
            .into_iter()
            .map(|(item, target)| {
                (
                    item.into(),
                    Binding::Target {
                        target: target.into(),
                    },
                )
            })
            .collect(),
    }
}

fn load(evaluation: &Evaluation, target: &str, phase: AccountingPhase) -> BigInt {
    evaluation
        .resource_loads
        .iter()
        .find(|load| load.target == target && load.phase == phase)
        .unwrap()
        .quantity
        .value()
        .clone()
}

#[test]
fn resource_inputs_require_canonical_decimal_strings() {
    for malformed in [
        "1",
        "-1",
        "\"01\"",
        "\"+1\"",
        "\" 1\"",
        "\"18446744073709551616\"",
    ] {
        assert!(
            serde_json::from_str::<Quantity>(malformed).is_err(),
            "{malformed}"
        );
    }
    assert_eq!(
        serde_json::from_str::<Quantity>("\"18446744073709551615\"")
            .unwrap()
            .get(),
        u64::MAX
    );
    assert_eq!(
        serde_json::to_string(&quantity(u64::MAX)).unwrap(),
        "\"18446744073709551615\""
    );
}

#[test]
fn rational_wire_rejects_unreduced_or_noncanonical_values() {
    for malformed in [
        r#"{"numerator":"2","denominator":"4"}"#,
        r#"{"numerator":"0","denominator":"2"}"#,
        r#"{"numerator":"-0","denominator":"1"}"#,
        r#"{"numerator":"1","denominator":"0"}"#,
        r#"{"numerator":"1","denominator":"-2"}"#,
        r#"{"numerator":"+1","denominator":"2"}"#,
        r#"{"numerator":1,"denominator":"2"}"#,
    ] {
        assert!(
            serde_json::from_str::<Rational>(malformed).is_err(),
            "{malformed}"
        );
    }
    assert_eq!(
        serde_json::to_string(&ratio(-7, 8)).unwrap(),
        r#"{"numerator":"-7","denominator":"8"}"#
    );
}

#[test]
fn rational_comparison_preserves_differences_beyond_double_precision() {
    let smaller = Rational::from(9_007_199_254_740_992_i64);
    let larger = Rational::from(9_007_199_254_740_993_i64);
    assert!(smaller < larger);
    assert_eq!(&larger - &smaller, Rational::one());
    assert_eq!(ratio(6, 8), ratio(3, 4));
    assert!(Rational::one().checked_div(&Rational::zero()).is_err());
}

#[test]
fn duplicate_assignment_map_keys_are_rejected() {
    let duplicate = r#"{"bindings":{"x":{"kind":"target","target":"A"},"x":{"kind":"deferred"}}}"#;
    assert!(serde_json::from_str::<Assignment>(duplicate).is_err());
}

#[test]
fn unknown_policy_fields_and_tags_are_rejected() {
    assert!(
        serde_json::from_str::<Binding>(r#"{"kind":"target","target":"A","lease":"token"}"#)
            .is_err()
    );
    assert!(serde_json::from_str::<Binding>(r#"{"kind":"arbitrary_callback"}"#).is_err());
}

#[test]
fn model_version_is_a_decimal_string_and_set_order_is_normalized() {
    let mut first = fixture();
    let encoded = serde_json::to_value(&first).unwrap();
    assert_eq!(encoded["model_version"], "1");
    first.domains.get_mut("all").unwrap().reverse();
    first.groups.get_mut("all").unwrap().reverse();
    first.constraints.reverse();

    assert_eq!(
        validate(first).unwrap().problem(),
        validate(fixture()).unwrap().problem()
    );
}

#[test]
fn componentwise_repair_rejects_a_new_violation_despite_lower_total_debt() {
    let problem = validate(fixture()).unwrap();
    let result = evaluate(&problem, &assignment("B", "A", "B")).unwrap();

    assert_eq!(result.violations.len(), 1);
    let failure = &result.violations[0];
    assert_eq!(failure.component.constraint, "B");
    assert_eq!(failure.actual_debt, Rational::one());
    assert_eq!(failure.allowed_debt, Rational::zero());
    assert!(failure.repair);
    assert!(verify(&problem, assignment("B", "A", "B")).is_err());
}

#[test]
fn repair_and_feasible_answers_have_distinct_verification_classes() {
    let problem = validate(fixture()).unwrap();
    let current = verify(&problem, assignment("A", "A", "B")).unwrap();
    let repaired = verify(&problem, assignment("A", "B", "B")).unwrap();

    assert_eq!(current.classification(), VerificationClass::Repair);
    assert_eq!(repaired.classification(), VerificationClass::Feasible);
    assert_eq!(
        load(repaired.evaluation(), "A", AccountingPhase::Final),
        BigInt::from(6)
    );
    assert_eq!(
        load(repaired.evaluation(), "B", AccountingPhase::Final),
        BigInt::from(7)
    );
}

#[test]
fn historic_source_charges_do_not_change_when_proposed_demand_changes() {
    let mut raw = fixture();
    raw.items
        .get_mut("x")
        .unwrap()
        .demands
        .get_mut("memory")
        .unwrap()
        .default = Some(quantity(2));
    let problem = validate(raw).unwrap();
    let debt = problem
        .baseline_debt(&ComponentId {
            constraint: "A".into(),
            component: "capacity".into(),
        })
        .unwrap();
    assert_eq!(debt.value(), &BigInt::from(2));

    let result = evaluate(&problem, &assignment("A", "A", "B")).unwrap();
    assert_eq!(load(&result, "A", AccountingPhase::Final), BigInt::from(6));
    assert_eq!(
        load(&result, "A", AccountingPhase::Overlap),
        BigInt::from(10)
    );
}

#[test]
fn final_and_overlap_have_distinct_additional_holding_rules() {
    let mut raw = fixture();
    raw.holdings = vec![
        Holding {
            id: "temporary".into(),
            target: "B".into(),
            dimension: "memory".into(),
            quantity: quantity(1),
            kind: HoldingKind::Additional {
                retained_at_final: false,
            },
        },
        Holding {
            id: "retained".into(),
            target: "A".into(),
            dimension: "memory".into(),
            quantity: quantity(2),
            kind: HoldingKind::Additional {
                retained_at_final: true,
            },
        },
    ];
    let result = evaluate(&validate(raw).unwrap(), &assignment("A", "B", "B")).unwrap();

    assert_eq!(load(&result, "A", AccountingPhase::Final), BigInt::from(8));
    assert_eq!(load(&result, "B", AccountingPhase::Final), BigInt::from(7));
    assert_eq!(
        load(&result, "A", AccountingPhase::Overlap),
        BigInt::from(12)
    );
    assert_eq!(
        load(&result, "B", AccountingPhase::Overlap),
        BigInt::from(8)
    );
}

#[test]
fn ordinary_holding_fragments_are_not_double_charged() {
    let mut raw = fixture();
    for (id, amount) in [("first", 2), ("second", 4)] {
        raw.holdings.push(Holding {
            id: id.into(),
            target: "A".into(),
            dimension: "memory".into(),
            quantity: quantity(amount),
            kind: HoldingKind::Ordinary { item: "x".into() },
        });
    }
    let result = evaluate(&validate(raw.clone()).unwrap(), &assignment("A", "A", "B")).unwrap();
    assert_eq!(
        load(&result, "A", AccountingPhase::Overlap),
        BigInt::from(10)
    );

    raw.holdings[0].quantity = quantity(3);
    assert!(validate(raw).is_err());
}

#[test]
fn source_holds_remain_when_historical_target_becomes_ineligible() {
    let mut raw = fixture();
    raw.domains.insert("only_B".into(), vec!["B".into()]);
    raw.items.get_mut("x").unwrap().domain = "only_B".into();
    let result = evaluate(&validate(raw).unwrap(), &assignment("B", "A", "B")).unwrap();

    assert_eq!(
        load(&result, "A", AccountingPhase::Overlap),
        BigInt::from(10)
    );
    assert_eq!(
        load(&result, "B", AccountingPhase::Overlap),
        BigInt::from(9)
    );
}

#[test]
fn aggregate_resource_loads_can_exceed_unsigned_64_bit_inputs() {
    let mut raw = fixture();
    for item in raw.items.values_mut() {
        item.demands.get_mut("memory").unwrap().default = Some(quantity(u64::MAX));
    }
    let result = evaluate(&validate(raw).unwrap(), &assignment("A", "A", "A")).unwrap();

    assert_eq!(
        load(&result, "A", AccountingPhase::Final),
        BigInt::from(u64::MAX) * 3
    );
}

#[test]
fn validated_and_verified_objects_are_immune_to_later_input_mutation() {
    let mut raw = fixture();
    let problem = validate(raw.clone()).unwrap();
    let accepted = verify(&problem, assignment("A", "B", "B")).unwrap();
    raw.items.clear();
    raw.targets.clear();

    assert_eq!(accepted.problem().items.len(), 3);
    assert_eq!(accepted.assignment().bindings.len(), 3);
    assert_eq!(accepted.validated_problem().problem(), problem.problem());
}

#[test]
fn malformed_accounting_and_scope_partitions_are_rejected() {
    let mut missing = fixture();
    missing.targets.get_mut("A").unwrap().fixed_load.clear();
    assert!(validate(missing).is_err());

    let mut overlapping = fixture();
    overlapping
        .scope_families
        .get_mut("host")
        .unwrap()
        .get_mut("B")
        .unwrap()
        .push("A".into());
    assert!(validate(overlapping).is_err());

    let mut uncovered = fixture();
    uncovered
        .scope_families
        .get_mut("host")
        .unwrap()
        .remove("B");
    assert!(validate(uncovered).is_err());

    let mut duplicate = fixture();
    duplicate.domains.get_mut("all").unwrap().push("A".into());
    assert!(validate(duplicate).is_err());
}

#[test]
fn repair_cannot_soften_nonnumeric_constraints() {
    let mut raw = fixture();
    raw.constraints.push(Constraint {
        id: "atomic".into(),
        enforcement: Enforcement::Repair,
        rule: ConstraintRule::AtomicAdmission {
            group: "all".into(),
        },
    });
    assert!(validate(raw).is_err());
}

#[test]
fn contradictory_fixed_binding_remains_a_valid_but_infeasible_problem() {
    let mut raw = fixture();
    raw.constraints.push(Constraint {
        id: "fixed".into(),
        enforcement: Enforcement::Hard,
        rule: ConstraintRule::FixedPlacement {
            bindings: BTreeMap::from([("x".into(), Binding::Deferred)]),
        },
    });
    let problem = validate(raw).unwrap();

    assert!(verify(&problem, assignment("A", "B", "B")).is_err());
    let mut deferred = assignment("A", "B", "B");
    deferred.bindings.insert("x".into(), Binding::Deferred);
    let evaluation = evaluate(&problem, &deferred).unwrap();
    assert!(
        evaluation
            .violations
            .iter()
            .any(|failure| failure.component.constraint == "$mandatory")
    );
}

#[test]
fn weighted_tier_values_preserve_orientation_and_normalization() {
    let mut raw = fixture();
    raw.objectives.push(ObjectiveTier {
        id: "preference".into(),
        terms: vec![
            ObjectiveTerm {
                id: "admission".into(),
                direction: Direction::Maximize,
                weight: ratio(3, 2),
                normalizer: Rational::from(2_u64),
                metric: Metric::AdmittedCount {
                    items: vec!["x".into(), "y".into()],
                },
            },
            ObjectiveTerm {
                id: "hosts".into(),
                direction: Direction::Minimize,
                weight: Rational::one(),
                normalizer: Rational::one(),
                metric: Metric::UsedTargets {
                    items: vec!["x".into(), "y".into()],
                },
            },
        ],
    });
    let evaluation = evaluate(&validate(raw).unwrap(), &assignment("A", "B", "B")).unwrap();

    assert_eq!(evaluation.term_values["admission"], Rational::from(2_u64));
    assert_eq!(evaluation.term_contributions["admission"], ratio(-3, 2));
    assert_eq!(evaluation.objectives, vec![ratio(1, 2)]);
}

#[test]
fn objective_inputs_reject_oversized_coefficients_but_outputs_remain_exact() {
    let mut raw = fixture();
    raw.objectives.push(ObjectiveTier {
        id: "huge".into(),
        terms: vec![ObjectiveTerm {
            id: "huge".into(),
            direction: Direction::Minimize,
            weight: Rational::from(BigInt::from(u64::MAX)),
            normalizer: Rational::one(),
            metric: Metric::AdmittedCount {
                items: vec!["x".into()],
            },
        }],
    });
    assert!(validate(raw).is_err());
    let integer = Integer::from(BigInt::from(u64::MAX) * 3);
    assert_eq!(
        serde_json::from_str::<Integer>(&serde_json::to_string(&integer).unwrap()).unwrap(),
        integer
    );
}

#[test]
fn utilization_requires_positive_explicit_denominators_and_nonempty_members() {
    let mut raw = fixture();
    raw.objectives.push(ObjectiveTier {
        id: "empty".into(),
        terms: vec![ObjectiveTerm {
            id: "empty".into(),
            direction: Direction::Minimize,
            weight: Rational::one(),
            normalizer: Rational::one(),
            metric: Metric::MaximumUtilization { members: vec![] },
        }],
    });
    assert!(validate(raw).is_err());
}

#[test]
fn mixed_unit_repair_debt_requires_separate_normalized_terms() {
    let mut raw = fixture();
    raw.constraints.push(Constraint {
        id: "count".into(),
        enforcement: Enforcement::Repair,
        rule: ConstraintRule::Admission {
            group: "all".into(),
            minimum: quantity(3),
            maximum: quantity(3),
        },
    });
    raw.objectives.push(ObjectiveTier {
        id: "mixed".into(),
        terms: vec![ObjectiveTerm {
            id: "mixed".into(),
            direction: Direction::Minimize,
            weight: Rational::one(),
            normalizer: Rational::one(),
            metric: Metric::RepairDebt {
                components: vec![
                    ComponentId {
                        constraint: "A".into(),
                        component: "capacity".into(),
                    },
                    ComponentId {
                        constraint: "count".into(),
                        component: "minimum".into(),
                    },
                ],
            },
        }],
    });
    assert!(validate(raw).is_err());
}

#[test]
fn sparse_spread_components_have_zero_defaults_without_weakening_repair() {
    let mut raw = fixture();
    raw.constraints.clear();
    raw.constraints.push(Constraint {
        id: "spread".into(),
        enforcement: Enforcement::Repair,
        rule: ConstraintRule::Spread {
            group: "all".into(),
            family: "host".into(),
            minimum: quantity(1),
            maximum_per_member: Some(quantity(1)),
            when_admitted: false,
        },
    });
    let problem = validate(raw).unwrap();
    let initially_clean = ComponentId {
        constraint: "spread".into(),
        component: "member:B".into(),
    };
    assert_eq!(
        problem.baseline_debt(&initially_clean).unwrap().value(),
        &BigInt::from(0)
    );

    let evaluation = evaluate(&problem, &assignment("B", "B", "B")).unwrap();
    assert!(
        evaluation
            .violations
            .iter()
            .any(|violation| violation.component == initially_clean)
    );
    let evacuated = ComponentId {
        constraint: "spread".into(),
        component: "member:A".into(),
    };
    let remaining = evaluation
        .repair_debt
        .iter()
        .find(|debt| debt.component == evacuated)
        .unwrap();
    assert_eq!(remaining.debt.value(), &BigInt::from(0));
    assert_eq!(remaining.baseline.value(), &BigInt::from(1));
}

#[test]
fn explicit_zero_scope_debt_selections_are_reported_and_evaluated() {
    let mut raw = fixture();
    raw.constraints.clear();
    raw.constraints.push(Constraint {
        id: "spread".into(),
        enforcement: Enforcement::Repair,
        rule: ConstraintRule::Spread {
            group: "all".into(),
            family: "host".into(),
            minimum: quantity(1),
            maximum_per_member: Some(quantity(4)),
            when_admitted: false,
        },
    });
    let component = ComponentId {
        constraint: "spread".into(),
        component: "member:B".into(),
    };
    raw.objectives.push(ObjectiveTier {
        id: "zero".into(),
        terms: vec![ObjectiveTerm {
            id: "zero".into(),
            direction: Direction::Minimize,
            weight: Rational::one(),
            normalizer: Rational::one(),
            metric: Metric::RepairDebt {
                components: vec![component.clone()],
            },
        }],
    });
    let evaluation = evaluate(&validate(raw).unwrap(), &assignment("A", "A", "A")).unwrap();

    assert_eq!(evaluation.objectives, vec![Rational::zero()]);
    let debt = evaluation
        .repair_debt
        .iter()
        .find(|debt| debt.component == component)
        .unwrap();
    assert!(debt.debt.is_zero());
    assert!(debt.baseline.is_zero());
}

#[test]
fn scope_reports_do_not_expand_every_group_against_every_target() {
    let targets = (0..1_000)
        .map(|index| {
            (
                format!("host-{index}"),
                Target {
                    capacities: BTreeMap::new(),
                    fixed_load: BTreeMap::new(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let host_ids = targets.keys().cloned().collect::<Vec<_>>();
    let family = host_ids
        .iter()
        .map(|target| (target.clone(), vec![target.clone()]))
        .collect();
    let raw = Problem {
        model_version: 1,
        targets,
        domains: BTreeMap::from([("all".into(), host_ids)]),
        items: BTreeMap::from([(
            "item".into(),
            Item {
                domain: "all".into(),
                deferrable: false,
                demands: BTreeMap::new(),
            },
        )]),
        observed: BTreeMap::from([(
            "item".into(),
            Observation {
                binding: ObservedBinding::Target {
                    target: "host-0".into(),
                },
                charges: BTreeMap::new(),
            },
        )]),
        groups: BTreeMap::from([("group".into(), vec!["item".into()])]),
        scope_families: BTreeMap::from([("host".into(), family)]),
        constraints: vec![Constraint {
            id: "spread".into(),
            enforcement: Enforcement::Repair,
            rule: ConstraintRule::Spread {
                group: "group".into(),
                family: "host".into(),
                minimum: quantity(1),
                maximum_per_member: Some(quantity(1)),
                when_admitted: false,
            },
        }],
        ..Problem::default()
    };
    let problem = validate(raw).unwrap();
    let candidate = Assignment {
        bindings: BTreeMap::from([(
            "item".into(),
            Binding::Target {
                target: "host-1".into(),
            },
        )]),
    };
    let evaluation = evaluate(&problem, &candidate).unwrap();

    assert!(evaluation.violations.is_empty());
    assert_eq!(evaluation.repair_debt.len(), 2);
    let dormant = ComponentId {
        constraint: "spread".into(),
        component: "member:host-999".into(),
    };
    assert!(problem.baseline_debt(&dormant).unwrap().is_zero());
}
