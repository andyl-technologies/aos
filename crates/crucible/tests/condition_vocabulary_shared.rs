//! Checks T-TRIG-2 shared condition vocabulary between assertions and triggers.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use crucible::{
    Action, AssertionDef, AssertionId, Condition, ConditionEvaluationPass, ConditionLeaf,
    ConditionLeafOracle, Event, EventGraph, EventGraphState, EventId, Icount, MarkerId, NodeId,
    NodeTemplate, Predicate, Properties, Property, ReachabilityExpectation, ReachableDisposition,
    ReadyPoint, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
};

#[test]
fn predicate_used_by_assertion_is_the_trigger_condition_type() {
    let condition: Condition = Predicate::all_of(vec![
        Predicate::named("cluster-ready"),
        Predicate::not(Predicate::guest_marker(MarkerId::from_name("unsafe-path"))),
    ]);
    let assertion = AssertionDef {
        id: AssertionId::from_name("cluster-ready-eventually"),
        message: String::from("cluster becomes ready"),
        property: Property::Sometimes {
            predicate: condition.clone(),
        },
    };
    let event = Event::once(
        EventId::from_name("inject-after-ready"),
        Some(condition.clone()),
        Action::Log {
            level: crucible::LogLevel::Info,
            message: String::from("shared condition fired"),
        },
    );
    let world = world_with_white_box_guest();
    let graph = EventGraph::new_with_assertions_for_world(vec![event], [], &world)
        .expect("shared condition event graph should build");

    assert_eq!(assertion_predicate(&assertion), Some(&condition));
    assert_eq!(graph.events()[0].trigger.as_ref(), Some(&condition));
}

#[test]
fn trigger_and_assertion_evaluation_use_the_same_predicate_function() {
    let condition = Predicate::any_of(vec![
        Predicate::named("quorum-ready"),
        Predicate::not(Predicate::named("leader-missing")),
    ]);
    let assertion = AssertionDef {
        id: AssertionId::from_name("quorum-or-leader"),
        message: String::from("quorum or leader observed"),
        property: Property::Reachable {
            predicate: condition.clone(),
            expectation: ReachabilityExpectation::Reachable {
                on_unreached: ReachableDisposition::Fail,
            },
        },
    };
    let graph = EventGraph::new(vec![Event::once(
        EventId::from_name("pass-on-quorum-or-leader"),
        Some(condition.clone()),
        Action::Pass,
    )])
    .expect("shared condition event graph should build");
    let mut state = EventGraphState::new();
    let assertion_truth = evaluator(7, &["quorum-ready"]).evaluate_assertion_condition(
        assertion_predicate(&assertion).expect("assertion carries predicate"),
    );
    let trigger_firings =
        support::evaluate_graph(&graph, &mut state, evaluator(7, &["quorum-ready"]));

    assert!(assertion_truth);
    assert_eq!(trigger_firings.len(), 1);
    assert_eq!(
        trigger_firings[0].event(),
        &EventId::from_name("pass-on-quorum-or-leader")
    );
}

#[test]
fn eventually_trigger_and_property_predicates_are_trigger_usable() {
    let trigger = Predicate::named("request-started");
    let property = Predicate::named("response-committed");
    let assertion = AssertionDef {
        id: AssertionId::from_name("response-after-request"),
        message: String::from("response follows request"),
        property: Property::Eventually {
            trigger: trigger.clone(),
            property: property.clone(),
            deadline: crucible::VirtualTime { ticks: 20 },
        },
    };
    let graph = EventGraph::new(vec![
        Event::once(
            EventId::from_name("trace-request-start"),
            Some(trigger.clone()),
            Action::Log {
                level: crucible::LogLevel::Info,
                message: String::from("request started"),
            },
        ),
        Event::once(
            EventId::from_name("pass-on-response"),
            Some(property.clone()),
            Action::Pass,
        ),
    ])
    .expect("eventually predicates should be trigger-usable");
    let assertion_predicates = assertion_predicates(&assertion);

    assert_eq!(assertion_predicates, vec![&trigger, &property]);
    assert_eq!(graph.events()[0].trigger.as_ref(), Some(&trigger));
    assert_eq!(graph.events()[1].trigger.as_ref(), Some(&property));
}

#[test]
fn properties_accept_the_same_compound_condition_shape_as_triggers() {
    let condition = Predicate::all_of(vec![
        Predicate::named("disk-idle"),
        Predicate::not(Predicate::named("network-partitioned")),
    ]);
    let world = crucible::World::from_nodes(Vec::new()).expect("empty world should build");
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![AssertionDef {
            id: AssertionId::from_name("settled"),
            message: String::from("system settled"),
            property: Property::AfterQuiescence {
                predicate: condition.clone(),
            },
        }],
    )
    .expect("node-free predicates should validate for an empty world");
    let graph = EventGraph::new(vec![Event::once(
        EventId::from_name("save-on-settled"),
        Some(condition.clone()),
        Action::CreateSavepoint {
            label: Some(String::from("settled")),
        },
    )])
    .expect("shared condition event graph should build");

    assert_eq!(
        properties.assertions()[0].property_predicate(),
        Some(&condition)
    );
    assert_eq!(graph.events()[0].trigger.as_ref(), Some(&condition));
}

trait AssertionPredicate {
    fn property_predicate(&self) -> Option<&Predicate>;
}

impl AssertionPredicate for AssertionDef {
    fn property_predicate(&self) -> Option<&Predicate> {
        assertion_predicate(self)
    }
}

fn assertion_predicate(assertion: &AssertionDef) -> Option<&Predicate> {
    match &assertion.property {
        Property::Always { predicate }
        | Property::Sometimes { predicate }
        | Property::AfterQuiescence { predicate }
        | Property::Reachable { predicate, .. } => Some(predicate),
        Property::Eventually { .. } => None,
    }
}

fn assertion_predicates(assertion: &AssertionDef) -> Vec<&Predicate> {
    match &assertion.property {
        Property::Always { predicate }
        | Property::Sometimes { predicate }
        | Property::AfterQuiescence { predicate }
        | Property::Reachable { predicate, .. } => vec![predicate],
        Property::Eventually {
            trigger, property, ..
        } => vec![trigger, property],
    }
}

fn evaluator<'a>(ticks: u64, true_names: &'a [&'a str]) -> ConditionEvaluationPass<TrueNames<'a>> {
    support::evaluation_at(ticks, TrueNames { true_names })
}

struct TrueNames<'a> {
    true_names: &'a [&'a str],
}

impl ConditionLeafOracle for TrueNames<'_> {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { name, .. } => self.true_names.contains(&name),
            ConditionLeaf::GuestMarker { marker } => {
                self.true_names.contains(&marker.name.as_str())
            }
        }
    }
}

fn world_with_white_box_guest() -> World {
    World::from_nodes(vec![WorldNode {
        id: NodeId {
            name: String::from("guest"),
        },
        arch: VmArchitecture::X86_64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
    .expect("white-box shared-vocabulary world should build")
}
