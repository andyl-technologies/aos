//! World, plan, property, and random-fault validation/canonicalization.

use super::*;
pub(super) fn validate_world_nodes(nodes: &[WorldNode]) -> Result<(), EngineError> {
    let mut seen = BTreeSet::new();
    for node in nodes {
        if !seen.insert(node.id.clone()) {
            return Err(EngineError::DuplicateWorldNodeId {
                node: node.id.clone(),
            });
        }
        if matches!(node.ready_point, ReadyPoint::AgentSignal) && !node.white_box.is_enabled() {
            return Err(EngineError::WhiteBoxReadyPointWithoutOptIn {
                node: node.id.clone(),
            });
        }
        match &node.ready_point {
            ReadyPoint::NetworkIdle { window } if window.nanos == 0 => {
                return Err(EngineError::ReadyPointNetworkIdleWindowZero {
                    node: node.id.clone(),
                });
            }
            ReadyPoint::ConsoleMarker { marker } if marker.is_empty() => {
                return Err(EngineError::ReadyPointConsoleMarkerEmpty {
                    node: node.id.clone(),
                });
            }
            ReadyPoint::FixedIcount { .. }
            | ReadyPoint::NetworkIdle { .. }
            | ReadyPoint::ConsoleMarker { .. }
            | ReadyPoint::AgentSignal => {}
        }
        if node.smp_vcpus == 0 {
            return Err(EngineError::WorldNodeSmpVcpuCountZero {
                node: node.id.clone(),
            });
        }
        if node.memory_mib < MIN_WORLD_MEMORY_MIB {
            return Err(EngineError::WorldNodeMemoryMibZero {
                node: node.id.clone(),
            });
        }
        if node.icount_shift > MAX_WORLD_ICOUNT_SHIFT {
            return Err(EngineError::WorldNodeIcountShiftTooLarge {
                node: node.id.clone(),
                shift: node.icount_shift,
                maximum: MAX_WORLD_ICOUNT_SHIFT,
            });
        }
        validate_world_node_workload(node)?;
        validate_world_node_workload_seed(node)?;
        validate_world_node_workload_scalar_parameters(node)?;
        validate_world_node_workload_config_tree(node)?;
        validate_world_node_workload_pattern(node)?;
        validate_world_node_workload_spike_mode(node)?;
        validate_world_node_workload_pattern_consistency(node)?;
        validate_world_node_workload_time_source(node)?;
        validate_world_node_workload_time_source_consistency(node)?;
    }

    Ok(())
}

pub(super) fn validate_world_node_workload(node: &WorldNode) -> Result<(), EngineError> {
    let mut selected = false;
    for token in node.cmdline.split_whitespace() {
        let Some(value) = token.strip_prefix(WORKLOAD_SCENARIO_PARAMETER_PREFIX) else {
            continue;
        };
        if selected {
            return Err(EngineError::WorldNodeDuplicateWorkload {
                node: node.id.clone(),
            });
        }
        if GuestWorkloadBinary::from_scenario_parameter_value(value).is_none() {
            return Err(EngineError::WorldNodeUnsupportedWorkload {
                node: node.id.clone(),
                value: value.to_owned(),
            });
        }
        selected = true;
    }
    Ok(())
}

pub(super) fn validate_world_node_workload_seed(node: &WorldNode) -> Result<(), EngineError> {
    let mut selected = false;
    for token in node.cmdline.split_whitespace() {
        let Some(value) = token.strip_prefix(WORKLOAD_SEED_SCENARIO_PARAMETER_PREFIX) else {
            continue;
        };
        if selected {
            return Err(EngineError::WorldNodeDuplicateWorkloadSeed {
                node: node.id.clone(),
            });
        }
        if GuestWorkloadSeed::from_scenario_parameter_value(value).is_none() {
            return Err(EngineError::WorldNodeInvalidWorkloadSeed {
                node: node.id.clone(),
                value: value.to_owned(),
            });
        }
        selected = true;
    }
    Ok(())
}

pub(super) fn validate_world_node_workload_scalar_parameters(
    node: &WorldNode,
) -> Result<(), EngineError> {
    let mut selected = BTreeSet::new();
    for token in node.cmdline.split_whitespace() {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        let Some(parameter) = GuestWorkloadParameterKey::from_cmdline_key(key) else {
            continue;
        };
        if !selected.insert(parameter) {
            return Err(EngineError::WorldNodeDuplicateWorkloadParameter {
                node: node.id.clone(),
                parameter: parameter.cmdline_key().to_owned(),
            });
        }
        if !valid_guest_workload_parameter_value(value) {
            return Err(EngineError::WorldNodeInvalidWorkloadParameterValue {
                node: node.id.clone(),
                parameter: parameter.cmdline_key().to_owned(),
                value: value.to_owned(),
            });
        }
    }
    Ok(())
}

pub(super) fn validate_world_node_workload_config_tree(
    node: &WorldNode,
) -> Result<(), EngineError> {
    let mut selected = false;
    for token in node.cmdline.split_whitespace() {
        let Some(value) = token.strip_prefix(WORKLOAD_CONFIG_TREE_SCENARIO_PARAMETER_PREFIX) else {
            continue;
        };
        if selected {
            return Err(EngineError::WorldNodeDuplicateWorkloadConfigTree {
                node: node.id.clone(),
            });
        }
        let Some(config) = GuestWorkloadConfigTreeRef::from_scenario_parameter_value(value) else {
            return Err(EngineError::WorldNodeUnsupportedWorkloadConfigTree {
                node: node.id.clone(),
                value: value.to_owned(),
            });
        };
        if config.delivery() == GuestWorkloadConfigTreeDelivery::ReadOnlyRootfs {
            match node.root_image {
                Some(root_image) if root_image == config.export() => {}
                Some(root_image) => {
                    return Err(
                        EngineError::WorldNodeWorkloadConfigTreeRootfsMismatchedRootImage {
                            node: node.id.clone(),
                            export: config.export(),
                            root_image,
                        },
                    );
                }
                None => {
                    return Err(
                        EngineError::WorldNodeWorkloadConfigTreeRootfsMissingRootImage {
                            node: node.id.clone(),
                            export: config.export(),
                        },
                    );
                }
            }
        }
        selected = true;
    }
    Ok(())
}

pub(super) fn validate_world_node_workload_pattern(node: &WorldNode) -> Result<(), EngineError> {
    let mut selected = false;
    for token in node.cmdline.split_whitespace() {
        let Some(value) = token.strip_prefix(WORKLOAD_LOAD_PATTERN_SCENARIO_PARAMETER_PREFIX)
        else {
            continue;
        };
        if selected {
            return Err(EngineError::WorldNodeDuplicateWorkloadPattern {
                node: node.id.clone(),
            });
        }
        if GuestWorkloadPattern::from_scenario_parameter_value(value).is_none() {
            return Err(EngineError::WorldNodeUnsupportedWorkloadPattern {
                node: node.id.clone(),
                value: value.to_owned(),
            });
        }
        selected = true;
    }
    Ok(())
}

pub(super) fn validate_world_node_workload_spike_mode(node: &WorldNode) -> Result<(), EngineError> {
    let mut selected = false;
    for token in node.cmdline.split_whitespace() {
        let Some(value) = token.strip_prefix(WORKLOAD_SPIKE_MODE_SCENARIO_PARAMETER_PREFIX) else {
            continue;
        };
        if selected {
            return Err(EngineError::WorldNodeDuplicateWorkloadSpikeMode {
                node: node.id.clone(),
            });
        }
        if GuestWorkloadSpikeMode::from_scenario_parameter_value(value).is_none() {
            return Err(EngineError::WorldNodeUnsupportedWorkloadSpikeMode {
                node: node.id.clone(),
                value: value.to_owned(),
            });
        }
        selected = true;
    }
    Ok(())
}

pub(super) fn validate_world_node_workload_pattern_consistency(
    node: &WorldNode,
) -> Result<(), EngineError> {
    let pattern = GuestWorkloadPattern::from_cmdline(&node.cmdline);
    let spike_mode = GuestWorkloadSpikeMode::from_cmdline(&node.cmdline);

    match (pattern, spike_mode) {
        (Some(GuestWorkloadPattern::Spike), None) => {
            Err(EngineError::WorldNodeWorkloadSpikePatternMissingMode {
                node: node.id.clone(),
            })
        }
        (Some(GuestWorkloadPattern::Spike), Some(_)) | (_, None) => Ok(()),
        (_, Some(_)) => Err(EngineError::WorldNodeWorkloadSpikeModeWithoutSpikePattern {
            node: node.id.clone(),
        }),
    }
}

pub(super) fn validate_world_node_workload_time_source(
    node: &WorldNode,
) -> Result<(), EngineError> {
    let mut selected = false;
    for token in node.cmdline.split_whitespace() {
        let Some(value) = token.strip_prefix(WORKLOAD_TIME_SOURCE_SCENARIO_PARAMETER_PREFIX) else {
            continue;
        };
        if selected {
            return Err(EngineError::WorldNodeDuplicateWorkloadTimeSource {
                node: node.id.clone(),
            });
        }
        if GuestWorkloadTimeSource::from_scenario_parameter_value(value).is_none() {
            return Err(EngineError::WorldNodeUnsupportedWorkloadTimeSource {
                node: node.id.clone(),
                value: value.to_owned(),
            });
        }
        selected = true;
    }
    Ok(())
}

pub(super) fn validate_world_node_workload_time_source_consistency(
    node: &WorldNode,
) -> Result<(), EngineError> {
    let pattern = GuestWorkloadPattern::from_cmdline(&node.cmdline);
    let time_source = GuestWorkloadTimeSource::from_cmdline(&node.cmdline);

    match (pattern, time_source) {
        (
            Some(GuestWorkloadPattern::Spike | GuestWorkloadPattern::CardinalityGrowth),
            Some(GuestWorkloadTimeSource::VirtualTime),
        ) => Ok(()),
        (Some(GuestWorkloadPattern::Spike | GuestWorkloadPattern::CardinalityGrowth), None) => Err(
            EngineError::WorldNodeWorkloadTimeVaryingPatternMissingVirtualTimeSource {
                node: node.id.clone(),
            },
        ),
        (_, Some(_)) => Err(
            EngineError::WorldNodeWorkloadTimeSourceWithoutTimeVaryingPattern {
                node: node.id.clone(),
            },
        ),
        (_, None) => Ok(()),
    }
}

pub(super) fn validate_world_links_for_node_defs(
    topology_nodes: &[WorldNodeDef],
    links: &[LinkDef],
) -> Result<(), EngineError> {
    let node_ids = topology_nodes
        .iter()
        .map(WorldNodeDef::id)
        .collect::<BTreeSet<_>>();
    let vm_ids = topology_nodes
        .iter()
        .filter_map(|node| match node {
            WorldNodeDef::Vm(node) => Some(&node.id),
            WorldNodeDef::Io(_) => None,
        })
        .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    for link in links {
        let (left, right) = link.endpoints();
        if left == right {
            return Err(EngineError::WorldLinkSelfLoop { node: left.clone() });
        }
        if !node_ids.contains(left) {
            return Err(EngineError::WorldLinkUnknownNode {
                link: link.clone(),
                node: left.clone(),
            });
        }
        if !node_ids.contains(right) {
            return Err(EngineError::WorldLinkUnknownNode {
                link: link.clone(),
                node: right.clone(),
            });
        }
        if !vm_ids.contains(left) {
            return Err(EngineError::WorldLinkNonVmEndpoint {
                link: link.clone(),
                node: left.clone(),
            });
        }
        if !vm_ids.contains(right) {
            return Err(EngineError::WorldLinkNonVmEndpoint {
                link: link.clone(),
                node: right.clone(),
            });
        }
        validate_link_transport(link)?;
        if !seen.insert((left.clone(), right.clone())) {
            return Err(EngineError::DuplicateWorldLink { link: link.clone() });
        }
    }

    for node in topology_nodes.iter().filter_map(|node| match node {
        WorldNodeDef::Vm(node) => Some(node),
        WorldNodeDef::Io(_) => None,
    }) {
        if matches!(node.ready_point, ReadyPoint::NetworkIdle { .. })
            && !links.iter().any(|link| {
                let (left, right) = link.endpoints();
                left == &node.id || right == &node.id
            })
        {
            return Err(EngineError::ReadyPointNetworkIdleWithoutLinks {
                node: node.id.clone(),
            });
        }
    }

    Ok(())
}

pub(super) fn validate_world_node_defs(nodes: &[WorldNodeDef]) -> Result<(), EngineError> {
    let vm_ids = nodes
        .iter()
        .filter_map(|node| match node {
            WorldNodeDef::Vm(node) => Some(&node.id),
            WorldNodeDef::Io(_) => None,
        })
        .collect::<BTreeSet<_>>();
    let mut node_ids = BTreeSet::new();
    let mut device_ids = BTreeSet::new();
    for node in nodes {
        if !node_ids.insert(node.id().clone()) {
            return Err(EngineError::DuplicateWorldNodeId {
                node: node.id().clone(),
            });
        }
        let WorldNodeDef::Io(node) = node else {
            continue;
        };
        if !vm_ids.contains(&node.owner) {
            return Err(EngineError::WorldIoNodeUnknownOwner {
                node: node.id.clone(),
                owner: node.owner.clone(),
            });
        }
        if node.core.shift_bits >= 64 {
            return Err(EngineError::WorldIoNodeClockShiftTooLarge {
                node: node.id.clone(),
                shift: node.core.shift_bits,
            });
        }
        let device = node.device_id();
        if !device_ids.insert(device.clone()) {
            return Err(EngineError::DuplicateWorldDeviceId { device });
        }
    }
    Ok(())
}

pub(super) fn validate_event_graph_plan(
    world: &World,
    assertions: impl IntoIterator<Item = AssertionId>,
    graph: EventGraph,
) -> Result<EventGraph, EventGraphError> {
    EventGraph::new_with_assertions_for_world(graph.events().to_vec(), assertions, world)
}

pub(super) fn event_graph_plan_error(error: EventGraphError) -> EngineError {
    scenario_serialization_error(format!("event graph plan validation failed: {error}"))
}

pub(super) fn validate_properties_for_world(
    world: &World,
    assertions: &[AssertionDef],
) -> Result<(), EngineError> {
    let node_ids = world.nodes.iter().map(|node| &node.id).collect();
    let white_box_node_ids = world
        .nodes
        .iter()
        .filter(|node| node.white_box == WhiteBoxPolicy::Enabled)
        .map(|node| &node.id)
        .collect();
    let mut assertion_ids = BTreeSet::new();

    for assertion in assertions {
        if !assertion_ids.insert(assertion.id.clone()) {
            return Err(EngineError::PropertyDuplicateAssertionId {
                id: assertion.id.clone(),
            });
        }
    }

    for assertion in assertions {
        validate_property_for_world(
            &assertion.property,
            &node_ids,
            &assertion_ids,
            &white_box_node_ids,
        )?;
    }

    Ok(())
}

pub(super) fn resolve_assertions_dsl_for_context(
    world: &World,
    _plan: &Plan,
    assertions: &[AssertionDef],
) -> Vec<AssertionDef> {
    assertions
        .iter()
        .map(|assertion| AssertionDef {
            id: assertion.id.clone(),
            message: assertion.message.clone(),
            property: resolve_property_dsl_for_context(&assertion.property, world),
        })
        .collect()
}

pub(super) fn resolve_properties_dsl_for_context(
    world: &World,
    plan: &Plan,
    properties: &Properties,
) -> Result<Properties, EngineError> {
    Properties::from_assertions_for_world_and_plan(world, plan, properties.assertions().to_vec())
}

pub(super) fn resolve_property_dsl_for_context(property: &Property, world: &World) -> Property {
    match property {
        Property::Always { predicate } => Property::Always {
            predicate: resolve_predicate_dsl_for_context(predicate, world),
        },
        Property::Sometimes { predicate } => Property::Sometimes {
            predicate: resolve_predicate_dsl_for_context(predicate, world),
        },
        Property::Eventually {
            trigger,
            property,
            deadline,
        } => Property::Eventually {
            trigger: resolve_predicate_dsl_for_context(trigger, world),
            property: resolve_predicate_dsl_for_context(property, world),
            deadline: *deadline,
        },
        Property::AfterQuiescence { predicate } => Property::AfterQuiescence {
            predicate: resolve_predicate_dsl_for_context(predicate, world),
        },
        Property::Reachable {
            predicate,
            expectation,
        } => Property::Reachable {
            predicate: resolve_predicate_dsl_for_context(predicate, world),
            expectation: *expectation,
        },
    }
}

pub(super) fn resolve_event_graph_dsl_for_world(world: &World, graph: &EventGraph) -> EventGraph {
    EventGraph::from_unchecked_events_for_model(
        graph
            .events()
            .iter()
            .map(|event| Event {
                id: event.id.clone(),
                trigger: event
                    .trigger
                    .as_ref()
                    .map(|trigger| resolve_predicate_dsl_for_context(trigger, world)),
                action: event.action.clone(),
                policy: event.policy,
            })
            .collect(),
    )
}

pub(super) fn resolve_predicate_dsl_for_context(predicate: &Predicate, world: &World) -> Predicate {
    match predicate {
        Predicate::Named { name, nodes } if nodes.is_empty() => {
            resolve_named_predicate_dsl_for_context(name, world)
                .unwrap_or_else(|| predicate.clone())
        }
        Predicate::AllOf { predicates } => Predicate::all_of(
            predicates
                .iter()
                .map(|predicate| resolve_predicate_dsl_for_context(predicate, world))
                .collect(),
        ),
        Predicate::AnyOf { predicates } => Predicate::any_of(
            predicates
                .iter()
                .map(|predicate| resolve_predicate_dsl_for_context(predicate, world))
                .collect(),
        ),
        Predicate::Once { predicate } => {
            Predicate::once(resolve_predicate_dsl_for_context(predicate, world))
        }
        Predicate::Not { predicate } => {
            Predicate::not(resolve_predicate_dsl_for_context(predicate, world))
        }
        Predicate::At { .. }
        | Predicate::After { .. }
        | Predicate::Timer { .. }
        | Predicate::NetworkMatch { .. }
        | Predicate::ConsoleMatch { .. }
        | Predicate::CoveragePoint { .. }
        | Predicate::MemoryPredicate { .. }
        | Predicate::IoPattern { .. }
        | Predicate::NodeState { .. }
        | Predicate::AssertionState { .. }
        | Predicate::Quiescent
        | Predicate::Named { .. }
        | Predicate::GuestMarker { .. } => predicate.clone(),
    }
}

pub(super) fn resolve_named_predicate_dsl_for_context(
    name: &str,
    world: &World,
) -> Option<Predicate> {
    match name {
        "no_crashed_nodes" => {
            Some(not_any_or_true(world.vm_nodes().iter().map(|node| {
                Predicate::node_state(node.id.clone(), NodeLifecycle::Crashed)
            })))
        }
        "quiescent" => Some(Predicate::quiescent()),
        _ => name
            .strip_prefix("node_alive:")
            .map(|node| Predicate::not(node_crashed_predicate(node)))
            .or_else(|| {
                name.strip_prefix("node_crashed:")
                    .map(|node| Predicate::once(node_crashed_predicate(node)))
            }),
    }
}

pub(super) fn node_crashed_predicate(node: &str) -> Predicate {
    Predicate::node_state(
        NodeId {
            name: node.to_owned(),
        },
        NodeLifecycle::Crashed,
    )
}

pub(super) fn not_any_or_true(predicates: impl IntoIterator<Item = Predicate>) -> Predicate {
    let predicates = predicates.into_iter().collect::<Vec<_>>();
    if predicates.is_empty() {
        dsl_true_predicate()
    } else {
        Predicate::not(Predicate::any_of(predicates))
    }
}

pub(super) fn dsl_true_predicate() -> Predicate {
    Predicate::any_of(vec![
        Predicate::quiescent(),
        Predicate::not(Predicate::quiescent()),
    ])
}

pub(super) fn validate_property_for_world(
    property: &Property,
    node_ids: &BTreeSet<&NodeId>,
    assertion_ids: &BTreeSet<AssertionId>,
    white_box_node_ids: &BTreeSet<&NodeId>,
) -> Result<(), EngineError> {
    match property {
        Property::Always { predicate }
        | Property::Sometimes { predicate }
        | Property::AfterQuiescence { predicate }
        | Property::Reachable { predicate, .. } => validate_property_predicate_for_world(
            predicate,
            node_ids,
            assertion_ids,
            white_box_node_ids,
        ),
        Property::Eventually {
            trigger, property, ..
        } => {
            validate_property_predicate_for_world(
                trigger,
                node_ids,
                assertion_ids,
                white_box_node_ids,
            )?;
            validate_property_predicate_for_world(
                property,
                node_ids,
                assertion_ids,
                white_box_node_ids,
            )
        }
    }
}

pub(super) fn validate_property_predicate_for_world(
    predicate: &Predicate,
    node_ids: &BTreeSet<&NodeId>,
    assertion_ids: &BTreeSet<AssertionId>,
    white_box_node_ids: &BTreeSet<&NodeId>,
) -> Result<(), EngineError> {
    match predicate {
        Predicate::At { .. } | Predicate::NetworkMatch { .. } | Predicate::Quiescent => Ok(()),
        Predicate::After { .. } => Err(EngineError::PropertyPredicateTriggerOnly { kind: "after" }),
        Predicate::Timer { .. } => Err(EngineError::PropertyPredicateTriggerOnly { kind: "timer" }),
        Predicate::ConsoleMatch { node, regex } => {
            validate_property_node(node, node_ids)?;
            validate_property_regex(regex)
        }
        Predicate::CoveragePoint { node, .. }
        | Predicate::MemoryPredicate { node, .. }
        | Predicate::IoPattern { node, .. }
        | Predicate::NodeState { node, .. } => validate_property_node(node, node_ids),
        Predicate::AssertionState { name, .. } => {
            if assertion_ids.contains(name) {
                Ok(())
            } else {
                Err(EngineError::PropertyPredicateUnknownAssertion {
                    assertion: name.clone(),
                })
            }
        }
        Predicate::Named { nodes, .. } => {
            for node in nodes {
                validate_property_node(node, node_ids)?;
            }
            Ok(())
        }
        Predicate::GuestMarker { marker } => {
            if white_box_node_ids.is_empty() {
                Err(
                    EngineError::PropertyPredicateGuestMarkerRequiresWhiteBoxOptIn {
                        marker: marker.clone(),
                    },
                )
            } else {
                Ok(())
            }
        }
        Predicate::AllOf { predicates } => validate_compound_predicate(
            "all-of",
            predicates,
            node_ids,
            assertion_ids,
            white_box_node_ids,
        ),
        Predicate::AnyOf { predicates } => validate_compound_predicate(
            "any-of",
            predicates,
            node_ids,
            assertion_ids,
            white_box_node_ids,
        ),
        Predicate::Once { predicate } | Predicate::Not { predicate } => {
            validate_property_predicate_for_world(
                predicate,
                node_ids,
                assertion_ids,
                white_box_node_ids,
            )
        }
    }
}

pub(super) fn validate_compound_predicate(
    kind: &'static str,
    predicates: &[Predicate],
    node_ids: &BTreeSet<&NodeId>,
    assertion_ids: &BTreeSet<AssertionId>,
    white_box_node_ids: &BTreeSet<&NodeId>,
) -> Result<(), EngineError> {
    if predicates.is_empty() {
        return Err(EngineError::PropertyPredicateEmptyCompound { kind });
    }

    for predicate in predicates {
        validate_property_predicate_for_world(
            predicate,
            node_ids,
            assertion_ids,
            white_box_node_ids,
        )?;
    }

    Ok(())
}

pub(super) fn validate_property_node(
    node: &NodeId,
    node_ids: &BTreeSet<&NodeId>,
) -> Result<(), EngineError> {
    if node_ids.contains(node) {
        Ok(())
    } else {
        Err(EngineError::PropertyPredicateUnknownNode { node: node.clone() })
    }
}

pub(super) fn validate_property_regex(regex: &RegexProgram) -> Result<(), EngineError> {
    regex::bytes::Regex::new(&regex.pattern)
        .map(|_| ())
        .map_err(|source| EngineError::PropertyPredicateInvalidRegex {
            pattern: regex.pattern.clone(),
            reason: source.to_string(),
        })
}

pub(super) fn canonical_assertions(assertions: &[AssertionDef]) -> Vec<AssertionDef> {
    let mut assertions = assertions
        .iter()
        .map(canonical_assertion)
        .collect::<Vec<_>>();
    assertions.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| assertion_material(left).cmp(&assertion_material(right)))
    });
    assertions
}

pub(super) fn canonical_assertion(assertion: &AssertionDef) -> AssertionDef {
    AssertionDef {
        id: assertion.id.clone(),
        message: assertion.message.clone(),
        property: canonical_property(&assertion.property),
    }
}

pub(super) fn canonical_property(property: &Property) -> Property {
    match property {
        Property::Always { predicate } => Property::Always {
            predicate: canonical_predicate(predicate),
        },
        Property::Sometimes { predicate } => Property::Sometimes {
            predicate: canonical_predicate(predicate),
        },
        Property::Eventually {
            trigger,
            property,
            deadline,
        } => Property::Eventually {
            trigger: canonical_predicate(trigger),
            property: canonical_predicate(property),
            deadline: *deadline,
        },
        Property::AfterQuiescence { predicate } => Property::AfterQuiescence {
            predicate: canonical_predicate(predicate),
        },
        Property::Reachable {
            predicate,
            expectation,
        } => Property::Reachable {
            predicate: canonical_predicate(predicate),
            expectation: *expectation,
        },
    }
}

pub(super) fn canonical_predicate(predicate: &Predicate) -> Predicate {
    match predicate {
        Predicate::At { at } => Predicate::At { at: *at },
        Predicate::After { duration, of } => Predicate::After {
            duration: *duration,
            of: of.clone(),
        },
        Predicate::Timer { name } => Predicate::Timer { name: name.clone() },
        Predicate::NetworkMatch { link, predicate } => Predicate::NetworkMatch {
            link: link.clone(),
            predicate: predicate.clone(),
        },
        Predicate::ConsoleMatch { node, regex } => Predicate::ConsoleMatch {
            node: node.clone(),
            regex: regex.clone(),
        },
        Predicate::CoveragePoint { node, point } => Predicate::CoveragePoint {
            node: node.clone(),
            point: point.clone(),
        },
        Predicate::MemoryPredicate {
            node,
            place,
            cmp,
            value,
        } => Predicate::MemoryPredicate {
            node: node.clone(),
            place: place.clone(),
            cmp: *cmp,
            value: *value,
        },
        Predicate::IoPattern { node, kind } => Predicate::IoPattern {
            node: node.clone(),
            kind: *kind,
        },
        Predicate::NodeState { node, state } => Predicate::NodeState {
            node: node.clone(),
            state: *state,
        },
        Predicate::AssertionState { name, state } => Predicate::AssertionState {
            name: name.clone(),
            state: *state,
        },
        Predicate::Quiescent => Predicate::Quiescent,
        Predicate::Named { name, nodes } => Predicate::Named {
            name: name.clone(),
            nodes: nodes.clone(),
        },
        Predicate::GuestMarker { marker } => Predicate::GuestMarker {
            marker: marker.clone(),
        },
        Predicate::AllOf { predicates } => Predicate::AllOf {
            predicates: canonical_predicate_set(predicates),
        },
        Predicate::AnyOf { predicates } => Predicate::AnyOf {
            predicates: canonical_predicate_set(predicates),
        },
        Predicate::Once { predicate } => Predicate::Once {
            predicate: Box::new(canonical_predicate(predicate)),
        },
        Predicate::Not { predicate } => Predicate::Not {
            predicate: Box::new(canonical_predicate(predicate)),
        },
    }
}

pub(super) fn canonical_predicate_set(predicates: &[Predicate]) -> Vec<Predicate> {
    let mut predicates = predicates
        .iter()
        .map(canonical_predicate)
        .collect::<Vec<_>>();
    predicates.sort_by_key(predicate_material);
    predicates
}
