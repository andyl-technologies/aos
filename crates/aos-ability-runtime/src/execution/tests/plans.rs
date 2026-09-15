//! Checked-plan builders shared by runtime integration scenarios.

use super::*;

pub(super) fn checked_dependent_plan() -> aos_ability_validate::CheckedEffectPlan {
    let mut fixture = plan_fixture();
    let producer = fixture.effect_plan.operations[0].clone();
    let mut consumer = producer.clone();
    consumer.key = scoped("consume");
    consumer.inputs = ValueExpression::OperationResult {
        reference: result_reference(&producer.key),
    };
    fixture.effect_plan.operations = vec![consumer, producer.clone()];
    fixture
        .effect_plan
        .operations
        .sort_by(|left, right| compare_operation_keys(&left.key, &right.key));
    fixture.effect_plan.edges = vec![DependencyEdge {
        from: PlanNodeKey::Operation { key: producer.key },
        to: PlanNodeKey::Operation {
            key: scoped("consume"),
        },
        kind: DependencyKind::Data,
    }];
    fixture.refresh_commitments();
    fixture
        .validate()
        .expect("dependent runtime fixture must pass production validation")
}

pub(super) fn checked_compensatable_dependent_plan() -> aos_ability_validate::CheckedEffectPlan {
    let mut fixture = recovery_plan_fixture(0);
    let mut producer = fixture.effect_plan.operations[0].clone();
    producer.recovery.retry = RetryPolicy::Disabled;
    producer.recovery.compensate = Some(MethodReference {
        interface: producer.interface.clone(),
        method: producer.method.clone(),
    });
    let mut consumer = producer.clone();
    consumer.key = scoped("consume");
    consumer.recovery.compensate = None;
    consumer.inputs = ValueExpression::OperationResult {
        reference: result_reference(&producer.key),
    };
    fixture.effect_plan.operations = vec![consumer, producer.clone()];
    fixture
        .effect_plan
        .operations
        .sort_by(|left, right| compare_operation_keys(&left.key, &right.key));
    fixture.effect_plan.edges = vec![DependencyEdge {
        from: PlanNodeKey::Operation { key: producer.key },
        to: PlanNodeKey::Operation {
            key: scoped("consume"),
        },
        kind: DependencyKind::Data,
    }];
    fixture.refresh_commitments();
    fixture
        .validate()
        .expect("compensatable dependent fixture must pass production validation")
}

pub(super) fn checked_failure_then_ordering_plan() -> aos_ability_validate::CheckedEffectPlan {
    let mut fixture = plan_fixture();
    let template = fixture.effect_plan.operations[0].clone();
    fixture.effect_plan.operations = ["after", "blocked", "first"]
        .map(|name| {
            let mut operation = template.clone();
            operation.key = scoped(name);
            operation
        })
        .into();
    fixture.effect_plan.edges = vec![
        DependencyEdge {
            from: PlanNodeKey::Operation {
                key: scoped("first"),
            },
            to: PlanNodeKey::Operation {
                key: scoped("blocked"),
            },
            kind: DependencyKind::RequiredSuccess,
        },
        DependencyEdge {
            from: PlanNodeKey::Operation {
                key: scoped("blocked"),
            },
            to: PlanNodeKey::Operation {
                key: scoped("after"),
            },
            kind: DependencyKind::OrderingOnly,
        },
    ];
    fixture.effect_plan.edges.sort_by(compare_edges);
    fixture.refresh_commitments();
    fixture
        .validate()
        .expect("failure-ordering runtime fixture must pass production validation")
}

pub(super) fn checked_deep_dependent_plan(
    length: usize,
) -> aos_ability_validate::CheckedEffectPlan {
    let mut fixture = plan_fixture();
    let template = fixture.effect_plan.operations[0].clone();
    let keys = (0..length)
        .map(|index| scoped(&format!("step-{index:05}")))
        .collect::<Vec<_>>();

    fixture.effect_plan.operations = keys
        .iter()
        .map(|key| {
            let mut operation = template.clone();
            operation.key = key.clone();
            operation
        })
        .collect();
    fixture.effect_plan.edges = keys
        .windows(2)
        .map(|pair| DependencyEdge {
            from: PlanNodeKey::Operation {
                key: pair[0].clone(),
            },
            to: PlanNodeKey::Operation {
                key: pair[1].clone(),
            },
            kind: DependencyKind::RequiredSuccess,
        })
        .collect();
    fixture.refresh_commitments();
    fixture
        .validate()
        .expect("deep runtime fixture must pass production validation")
}

pub(super) fn checked_two_resource_plan() -> aos_ability_validate::CheckedEffectPlan {
    let mut fixture = plan_fixture();
    let mut extra_revision = fixture.effect_plan.current_revisions[0].clone();
    extra_revision.resource.key = key("secondary");
    extra_revision.revision = RevisionId(Sha256Digest::of_bytes("secondary-resource"));
    let extra_resource = extra_revision.resource.clone();
    fixture
        .binding_inputs
        .environment
        .resources
        .push(extra_revision.clone());
    fixture
        .binding_inputs
        .environment
        .resources
        .sort_by(|left, right| left.resource.cmp(&right.resource));
    fixture
        .binding_inputs
        .desired_state
        .resources
        .push(extra_revision.clone());
    fixture
        .binding_inputs
        .desired_state
        .resources
        .sort_by(|left, right| left.resource.cmp(&right.resource));
    fixture.binding_plan.resources.push(extra_revision.clone());
    fixture
        .binding_plan
        .resources
        .sort_by(|left, right| left.resource.cmp(&right.resource));
    fixture.binding_plan.bindings[0]
        .caller_grant
        .resources
        .push(ResourcePermission {
            resource: extra_resource.clone(),
            access: AccessMode::Read,
            operations: vec![key("observe")],
        });
    fixture.binding_plan.bindings[0]
        .caller_grant
        .resources
        .sort_by(|left, right| left.resource.cmp(&right.resource));
    fixture.effect_plan.operations[0]
        .accesses
        .push(ResourceAccess {
            resource: extra_resource,
            mode: AccessMode::Read,
        });
    fixture.effect_plan.operations[0]
        .accesses
        .sort_by(|left, right| left.resource.cmp(&right.resource));
    fixture
        .effect_plan
        .current_revisions
        .push(extra_revision.clone());
    fixture
        .effect_plan
        .current_revisions
        .sort_by(|left, right| left.resource.cmp(&right.resource));
    fixture.effect_plan.desired_revisions.push(extra_revision);
    fixture
        .effect_plan
        .desired_revisions
        .sort_by(|left, right| left.resource.cmp(&right.resource));
    fixture.refresh_commitments();
    fixture
        .validate()
        .expect("multi-resource runtime fixture must pass production validation")
}

pub(super) fn recovery_plan_fixture(
    backoff_millis: u64,
) -> aos_ability_validate::test_support::PlanFixture {
    let mut fixture = plan_fixture();
    fixture.interfaces[0]
        .interface
        .methods
        .get_mut(&key("observe"))
        .expect("fixture observe method")
        .outcome
        .indeterminate = IndeterminateSemantics::Reconcile;
    let operation = &mut fixture.effect_plan.operations[0];
    operation.recovery.retry = RetryPolicy::Bounded {
        max_attempts: NonZeroU32::new(2).expect("positive test retry count"),
        backoff_millis,
    };
    operation.recovery.reconcile = Some(MethodReference {
        interface: operation.interface.clone(),
        method: operation.method.clone(),
    });
    fixture.refresh_interface();
    fixture
}

pub(super) fn checked_recovery_plan() -> aos_ability_validate::CheckedEffectPlan {
    recovery_plan_fixture(0)
        .validate()
        .expect("reconcilable runtime fixture must pass production validation")
}

pub(super) fn checked_cancellation_plan() -> aos_ability_validate::CheckedEffectPlan {
    let mut fixture = recovery_plan_fixture(0);
    let operation = &mut fixture.effect_plan.operations[0];
    operation.recovery.cancel = Some(MethodReference {
        interface: operation.interface.clone(),
        method: operation.method.clone(),
    });
    fixture.refresh_interface();
    fixture
        .validate()
        .expect("cancellation runtime fixture must pass production validation")
}

pub(super) fn checked_terminal_compensation_plan() -> aos_ability_validate::CheckedEffectPlan {
    let mut fixture = recovery_plan_fixture(0);
    let operation = &mut fixture.effect_plan.operations[0];
    operation.recovery.retry = RetryPolicy::Disabled;
    operation.recovery.compensate = Some(MethodReference {
        interface: operation.interface.clone(),
        method: operation.method.clone(),
    });
    fixture.refresh_commitments();
    fixture
        .validate()
        .expect("terminal compensation fixture must pass production validation")
}

pub(super) fn branch_plan_fixture() -> aos_ability_validate::test_support::PlanFixture {
    let mut fixture = plan_fixture();
    let producer = fixture.effect_plan.operations[0].clone();
    let decision_key = scoped("choose");
    let false_key = key("false");
    let true_key = key("true");
    let mut false_operation = producer.clone();
    false_operation.key = scoped("false-step");
    false_operation.branch_context = vec![BranchMembership {
        decision: decision_key.clone(),
        alternative: false_key.clone(),
    }];
    let mut true_operation = producer.clone();
    true_operation.key = scoped("true-step");
    true_operation.branch_context = vec![BranchMembership {
        decision: decision_key.clone(),
        alternative: true_key.clone(),
    }];
    fixture.effect_plan.operations = vec![false_operation, producer.clone(), true_operation];
    fixture
        .effect_plan
        .operations
        .sort_by(|left, right| compare_operation_keys(&left.key, &right.key));
    fixture.effect_plan.decisions = vec![DecisionNode {
        key: decision_key.clone(),
        branch_context: Vec::new(),
        selector: DecisionSelector {
            result: result_reference(&producer.key),
            tag_field: None,
        },
        alternatives: vec![
            DecisionAlternative {
                key: false_key,
                predicate: DecisionPredicate::Boolean { value: false },
            },
            DecisionAlternative {
                key: true_key,
                predicate: DecisionPredicate::Boolean { value: true },
            },
        ],
    }];
    fixture.effect_plan.edges = vec![
        DependencyEdge {
            from: PlanNodeKey::Decision {
                key: decision_key.clone(),
            },
            to: PlanNodeKey::Operation {
                key: scoped("false-step"),
            },
            kind: DependencyKind::BranchGuard,
        },
        DependencyEdge {
            from: PlanNodeKey::Decision {
                key: decision_key.clone(),
            },
            to: PlanNodeKey::Operation {
                key: scoped("true-step"),
            },
            kind: DependencyKind::BranchGuard,
        },
        DependencyEdge {
            from: PlanNodeKey::Operation { key: producer.key },
            to: PlanNodeKey::Decision { key: decision_key },
            kind: DependencyKind::Data,
        },
    ];
    fixture.effect_plan.edges.sort_by(compare_edges);
    fixture.refresh_commitments();
    fixture
}

pub(super) fn checked_branch_plan() -> aos_ability_validate::CheckedEffectPlan {
    branch_plan_fixture()
        .validate()
        .expect("conditional runtime fixture must pass production validation")
}

pub(super) fn checked_failed_decision_ordering_plan() -> aos_ability_validate::CheckedEffectPlan {
    let mut fixture = branch_plan_fixture();
    let mut after_decision = fixture.effect_plan.operations[0].clone();
    after_decision.key = scoped("after-decision");
    after_decision.branch_context.clear();
    fixture.effect_plan.operations.push(after_decision);
    fixture
        .effect_plan
        .operations
        .sort_by(|left, right| compare_operation_keys(&left.key, &right.key));
    fixture.effect_plan.edges.push(DependencyEdge {
        from: PlanNodeKey::Decision {
            key: scoped("choose"),
        },
        to: PlanNodeKey::Operation {
            key: scoped("after-decision"),
        },
        kind: DependencyKind::OrderingOnly,
    });
    fixture.effect_plan.edges.sort_by(compare_edges);
    fixture.refresh_commitments();
    fixture
        .validate()
        .expect("failed-decision ordering fixture must pass production validation")
}

pub(super) fn checked_merge_plan() -> aos_ability_validate::CheckedEffectPlan {
    let mut fixture = branch_plan_fixture();
    let template = fixture.effect_plan.operations[0].clone();
    let mut consumer = template;
    consumer.key = scoped("consume");
    consumer.branch_context.clear();
    consumer.inputs = ValueExpression::OperationResult {
        reference: OperationResultReference {
            producer: ResultProducerKey::Merge {
                key: scoped("selected"),
            },
            output: key("ready"),
        },
    };
    fixture.effect_plan.operations.push(consumer);
    fixture
        .effect_plan
        .operations
        .sort_by(|left, right| compare_operation_keys(&left.key, &right.key));
    let descriptor = fixture.interfaces[0]
        .interface
        .methods
        .get(&key("observe"))
        .and_then(|method| method.outputs.get(&key("ready")))
        .cloned()
        .expect("fixture readiness output");
    fixture.effect_plan.merges = vec![MergeNode {
        key: scoped("selected"),
        decision: scoped("choose"),
        branch_context: Vec::new(),
        outputs: BTreeMap::from([(
            key("ready"),
            MergedOutput {
                descriptor,
                alternatives: BTreeMap::from([
                    (key("false"), result_reference(&scoped("false-step"))),
                    (key("true"), result_reference(&scoped("true-step"))),
                ]),
            },
        )]),
    }];
    fixture.effect_plan.edges.extend([
        DependencyEdge {
            from: PlanNodeKey::Operation {
                key: scoped("false-step"),
            },
            to: PlanNodeKey::Merge {
                key: scoped("selected"),
            },
            kind: DependencyKind::BranchMerge,
        },
        DependencyEdge {
            from: PlanNodeKey::Operation {
                key: scoped("true-step"),
            },
            to: PlanNodeKey::Merge {
                key: scoped("selected"),
            },
            kind: DependencyKind::BranchMerge,
        },
        DependencyEdge {
            from: PlanNodeKey::Merge {
                key: scoped("selected"),
            },
            to: PlanNodeKey::Operation {
                key: scoped("consume"),
            },
            kind: DependencyKind::Data,
        },
    ]);
    fixture.effect_plan.edges.sort_by(compare_edges);
    fixture.refresh_commitments();
    fixture
        .validate()
        .expect("merged runtime fixture must pass production validation")
}

pub(super) fn result_reference(producer: &ScopedOperationKey) -> OperationResultReference {
    OperationResultReference {
        producer: ResultProducerKey::Operation {
            key: producer.clone(),
        },
        output: key("ready"),
    }
}

pub(super) fn scoped(value: &str) -> ScopedOperationKey {
    ScopedOperationKey {
        scope: aos_ability_model::ScopePath::root(),
        key: key(value),
    }
}
