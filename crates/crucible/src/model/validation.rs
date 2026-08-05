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

pub(super) fn validate_plan_entries_for_world(
    world: &World,
    entries: &[PlanEntry],
) -> Result<(), EngineError> {
    let node_ids = world
        .nodes
        .iter()
        .map(|node| &node.id)
        .collect::<BTreeSet<_>>();
    let link_ids = world
        .links
        .iter()
        .map(|link| {
            let (left, right) = link.endpoints();
            (left.clone(), right.clone())
        })
        .collect::<BTreeSet<_>>();
    let taxonomy_link_ids = world_link_id_set(world);
    let device_kinds = world_device_kind_map(world);
    let mut activated_tags = BTreeMap::<FaultTag, Vec<VirtualTime>>::new();
    for entry in entries {
        if let PlanEntry::Activate { at, tag, .. } = entry {
            activated_tags.entry(tag.clone()).or_default().push(*at);
        }
    }

    for entry in entries {
        match entry {
            PlanEntry::Activate { at, fault, .. } => {
                validate_membership_fault_for_world(
                    *at,
                    fault,
                    &node_ids,
                    &link_ids,
                    &taxonomy_link_ids,
                    &device_kinds,
                )?;
            }
            PlanEntry::Heal { tag, .. } => {
                validate_plan_heal(tag, entry, &activated_tags)?;
            }
        }
    }

    Ok(())
}

pub(super) fn validate_fault_plan_entries_for_world(
    world: &World,
    entries: &[FaultPlanEntry],
) -> Result<(), EngineError> {
    let node_ids = world_node_id_set(world);
    let link_ids = world_link_id_set(world);
    let device_kinds = world_device_kind_map(world);
    let mut activated_tags = BTreeMap::<FaultTag, Vec<VirtualTime>>::new();
    for entry in entries {
        match entry {
            FaultPlanEntry::At {
                at, duration, tag, ..
            } => {
                let Some(_) = at.ticks.checked_add(duration.nanos()) else {
                    return Err(EngineError::PlanFaultDurationOverflow {
                        tag: tag.clone(),
                        at: *at,
                        duration: *duration,
                    });
                };
                activated_tags.entry(tag.clone()).or_default().push(*at);
            }
            FaultPlanEntry::PermanentAt { at, tag, .. } => {
                activated_tags.entry(tag.clone()).or_default().push(*at);
            }
            FaultPlanEntry::Heal { .. } => {}
        }
    }

    for entry in entries {
        match entry {
            FaultPlanEntry::At { fault, .. } | FaultPlanEntry::PermanentAt { fault, .. } => {
                validate_fault_for_world(fault, &node_ids, &link_ids, &device_kinds)?;
            }
            FaultPlanEntry::Heal { at, tag } => {
                validate_fault_plan_heal(tag, *at, &activated_tags)?;
            }
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

pub(super) fn validate_membership_fault_for_world(
    at: VirtualTime,
    fault: &MembershipFault,
    node_ids: &BTreeSet<&NodeId>,
    link_ids: &BTreeSet<(NodeId, NodeId)>,
    taxonomy_link_ids: &BTreeSet<LinkId>,
    device_kinds: &BTreeMap<DeviceId, WorldDeviceKind>,
) -> Result<(), EngineError> {
    match fault {
        MembershipFault::Crash { node, .. } | MembershipFault::Isolate { node } => {
            validate_plan_node(node, node_ids)
        }
        MembershipFault::NotYetJoined { node } => {
            validate_plan_node(node, node_ids)?;
            if at != VirtualTime::default() {
                return Err(EngineError::PlanNotYetJoinedAfterStart {
                    node: node.clone(),
                    at,
                });
            }
            Ok(())
        }
        MembershipFault::Partition {
            endpoint_a,
            endpoint_b,
            ..
        } => {
            validate_plan_node(endpoint_a, node_ids)?;
            validate_plan_node(endpoint_b, node_ids)?;
            let link = canonical_link_endpoint_pair(endpoint_a, endpoint_b);
            if !link_ids.contains(&link) {
                return Err(EngineError::PlanFaultUnknownLink {
                    endpoint_a: endpoint_a.clone(),
                    endpoint_b: endpoint_b.clone(),
                });
            }
            Ok(())
        }
        MembershipFault::Taxonomy { fault } => {
            validate_fault_for_world(fault, node_ids, taxonomy_link_ids, device_kinds)
        }
    }
}

pub(super) fn validate_fault_plan_heal(
    tag: &FaultTag,
    heal_at: VirtualTime,
    activated_tags: &BTreeMap<FaultTag, Vec<VirtualTime>>,
) -> Result<(), EngineError> {
    let Some(activation_times) = activated_tags.get(tag) else {
        return Err(EngineError::PlanHealUnknownTag { tag: tag.clone() });
    };
    if activation_times
        .iter()
        .copied()
        .any(|activate_at| activate_at <= heal_at)
    {
        return Ok(());
    }

    if let Some(activate_at) = activation_times.iter().copied().min() {
        return Err(EngineError::PlanHealBeforeActivate {
            tag: tag.clone(),
            activate_at,
            heal_at,
        });
    }
    Err(EngineError::PlanHealUnknownTag { tag: tag.clone() })
}

pub(super) fn validate_fault_for_world(
    fault: &Fault,
    node_ids: &BTreeSet<&NodeId>,
    link_ids: &BTreeSet<LinkId>,
    device_kinds: &BTreeMap<DeviceId, WorldDeviceKind>,
) -> Result<(), EngineError> {
    match fault {
        Fault::Network(fault) => validate_network_fault_for_world(fault, link_ids),
        Fault::Node(fault) => validate_node_fault_for_world(fault, node_ids),
        Fault::Block(fault) => validate_fault_device_for_world(
            block_fault_device(fault),
            WorldDeviceKind::Block,
            device_kinds,
        ),
        Fault::NineP(fault) => validate_fault_device_for_world(
            ninep_fault_device(fault),
            WorldDeviceKind::NineP,
            device_kinds,
        ),
    }
}

pub(super) fn validate_fault_device_for_world(
    device: &DeviceId,
    expected: WorldDeviceKind,
    device_kinds: &BTreeMap<DeviceId, WorldDeviceKind>,
) -> Result<(), EngineError> {
    let Some(actual) = device_kinds.get(device).copied() else {
        return Err(EngineError::PlanFaultUnknownDevice {
            device: device.clone(),
        });
    };
    if actual != expected {
        return Err(EngineError::PlanFaultDeviceKindMismatch {
            device: device.clone(),
            expected,
            actual,
        });
    }
    Ok(())
}

pub(super) fn validate_network_fault_for_world(
    fault: &NetworkFault,
    link_ids: &BTreeSet<LinkId>,
) -> Result<(), EngineError> {
    let link = network_fault_link(fault);
    if link_ids.contains(link) {
        Ok(())
    } else {
        Err(EngineError::PlanFaultUnknownLinkId { link: link.clone() })
    }
}

pub(super) fn validate_node_fault_for_world(
    fault: &NodeFault,
    node_ids: &BTreeSet<&NodeId>,
) -> Result<(), EngineError> {
    validate_plan_node(node_fault_node(fault), node_ids)
}

pub(super) fn network_fault_link(fault: &NetworkFault) -> &LinkId {
    match fault {
        NetworkFault::Partition { link, .. }
        | NetworkFault::Loss { link, .. }
        | NetworkFault::Reorder { link, .. }
        | NetworkFault::Duplicate { link, .. }
        | NetworkFault::Corruption { link, .. }
        | NetworkFault::Bandwidth { link, .. }
        | NetworkFault::LatencyBump { link, .. } => link,
    }
}

pub(super) fn node_fault_node(fault: &NodeFault) -> &NodeId {
    match fault {
        NodeFault::Crash { node, .. }
        | NodeFault::Slow { node, .. }
        | NodeFault::ClockSkew { node, .. } => node,
    }
}

pub(super) fn block_fault_device(fault: &BlockFault) -> &DeviceId {
    match fault {
        BlockFault::Latency { device, .. }
        | BlockFault::Failure { device, .. }
        | BlockFault::Reorder { device, .. }
        | BlockFault::Duplicate { device, .. }
        | BlockFault::Corruption { device, .. }
        | BlockFault::Bandwidth { device, .. } => device,
    }
}

pub(super) fn ninep_fault_device(fault: &NinePFault) -> &DeviceId {
    match fault {
        NinePFault::Latency { device, .. }
        | NinePFault::Failure { device, .. }
        | NinePFault::Reorder { device, .. }
        | NinePFault::Duplicate { device, .. }
        | NinePFault::Corruption { device, .. }
        | NinePFault::Bandwidth { device, .. } => device,
    }
}

pub(super) fn world_node_id_set(world: &World) -> BTreeSet<&NodeId> {
    world.nodes.iter().map(|node| &node.id).collect()
}

pub(super) fn world_link_id_set(world: &World) -> BTreeSet<LinkId> {
    let mut links = BTreeSet::new();
    let mut legacy_counts = BTreeMap::new();
    for link in &world.links {
        links.insert(random_fault_link_id(link));
        let legacy = legacy_link_id_for_world_link(link);
        let count = legacy_counts.entry(legacy).or_insert(0_usize);
        *count = count.saturating_add(1);
    }
    for (legacy, count) in legacy_counts {
        if count == 1 {
            links.insert(legacy);
        }
    }
    links
}

pub(super) fn world_device_kind_map(world: &World) -> BTreeMap<DeviceId, WorldDeviceKind> {
    world
        .io_nodes()
        .map(|node| (node.device_id(), node.kind.family()))
        .collect()
}

pub(super) fn link_id_for_canonical_endpoint_pair(
    endpoint_a: &NodeId,
    endpoint_b: &NodeId,
) -> LinkId {
    LinkId::from_name(format!(
        "link_endpoint_a_len={}\nlink_endpoint_a={}\nlink_endpoint_b_len={}\nlink_endpoint_b={}",
        endpoint_a.name.len(),
        endpoint_a.name,
        endpoint_b.name.len(),
        endpoint_b.name
    ))
}

pub(super) fn legacy_link_id_for_world_link(link: &LinkDef) -> LinkId {
    let (endpoint_a, endpoint_b) = link.endpoints();
    LinkId::from_name(format!("{}--{}", endpoint_a.name, endpoint_b.name))
}

pub(super) fn validate_random_fault_config(config: &RandomFaultConfig) -> Result<(), EngineError> {
    let bounds = config.bounds;
    if config.fault_slots == 0 {
        return Ok(());
    }
    if config.duration.nanos() == 0 {
        return Err(EngineError::RandomFaultConfigInvalid {
            reason: "run duration must be nonzero when fault slots are requested",
        });
    }
    if bounds.min_duration.nanos() == 0 {
        return Err(EngineError::RandomFaultConfigInvalid {
            reason: "minimum generated fault duration must be nonzero",
        });
    }
    if bounds.min_duration > bounds.max_duration {
        return Err(EngineError::RandomFaultConfigInvalid {
            reason: "minimum generated fault duration exceeds maximum",
        });
    }
    if bounds.min_duration > config.duration {
        return Err(EngineError::RandomFaultConfigInvalid {
            reason: "minimum generated fault duration exceeds run duration",
        });
    }
    if bounds.min_rate > bounds.max_rate {
        return Err(EngineError::RandomFaultConfigInvalid {
            reason: "minimum generated fault rate exceeds maximum",
        });
    }
    if bounds.min_latency > bounds.max_latency {
        return Err(EngineError::RandomFaultConfigInvalid {
            reason: "minimum generated latency exceeds maximum",
        });
    }
    if bounds.min_reorder_window > bounds.max_reorder_window {
        return Err(EngineError::RandomFaultConfigInvalid {
            reason: "minimum generated reorder window exceeds maximum",
        });
    }
    if bounds.min_duplicate_gap > bounds.max_duplicate_gap {
        return Err(EngineError::RandomFaultConfigInvalid {
            reason: "minimum generated duplicate gap exceeds maximum",
        });
    }
    if bounds.min_bandwidth > bounds.max_bandwidth {
        return Err(EngineError::RandomFaultConfigInvalid {
            reason: "minimum generated bandwidth exceeds maximum",
        });
    }
    if bounds.min_slowdown > bounds.max_slowdown {
        return Err(EngineError::RandomFaultConfigInvalid {
            reason: "minimum generated slowdown exceeds maximum",
        });
    }
    if bounds.min_clock_skew > bounds.max_clock_skew {
        return Err(EngineError::RandomFaultConfigInvalid {
            reason: "minimum generated clock skew exceeds maximum",
        });
    }
    if bounds.min_corruption_bits > bounds.max_corruption_bits {
        return Err(EngineError::RandomFaultConfigInvalid {
            reason: "minimum generated corruption bit count exceeds maximum",
        });
    }
    if bounds.min_truncation_bytes > bounds.max_truncation_bytes {
        return Err(EngineError::RandomFaultConfigInvalid {
            reason: "minimum generated truncation byte count exceeds maximum",
        });
    }
    Ok(())
}

pub(super) fn random_fault_nodes(world: &World) -> Vec<NodeId> {
    world_participants(world)
}

pub(super) fn random_fault_links(world: &World) -> Vec<LinkId> {
    canonical_world_links(world.links())
        .into_iter()
        .map(|link| random_fault_link_id(&link))
        .collect()
}

pub(super) fn random_fault_link_id(link: &LinkDef) -> LinkId {
    LinkId::from_name(world_link_stream_name(link))
}

pub(super) fn random_fault_devices(world: &World, kind: WorldDeviceKind) -> Vec<DeviceId> {
    world
        .io_nodes()
        .filter(|node| node.kind.family() == kind)
        .map(WorldIoNode::device_id)
        .collect()
}

pub(super) fn eligible_random_fault_kinds(
    weights: &FaultWeights,
    has_nodes: bool,
    has_links: bool,
    has_block_devices: bool,
    has_ninep_devices: bool,
) -> Vec<(RandomFaultKind, u32)> {
    let mut kinds = Vec::new();
    if has_links {
        push_weighted_random_fault_kind(&mut kinds, RandomFaultKind::Partition, weights.partition);
        push_weighted_random_fault_kind(
            &mut kinds,
            RandomFaultKind::MessageLoss,
            weights.message_loss,
        );
        push_weighted_random_fault_kind(&mut kinds, RandomFaultKind::Reorder, weights.reorder);
        push_weighted_random_fault_kind(&mut kinds, RandomFaultKind::Duplicate, weights.duplicate);
        push_weighted_random_fault_kind(
            &mut kinds,
            RandomFaultKind::Corruption,
            weights.corruption,
        );
        push_weighted_random_fault_kind(
            &mut kinds,
            RandomFaultKind::BandwidthLimit,
            weights.bandwidth_limit,
        );
        push_weighted_random_fault_kind(
            &mut kinds,
            RandomFaultKind::LatencyBump,
            weights.latency_bump,
        );
    }
    if has_nodes {
        push_weighted_random_fault_kind(&mut kinds, RandomFaultKind::Crash, weights.crash);
        push_weighted_random_fault_kind(&mut kinds, RandomFaultKind::Slow, weights.slow);
        push_weighted_random_fault_kind(&mut kinds, RandomFaultKind::ClockSkew, weights.clock_skew);
    }
    if has_block_devices {
        push_weighted_random_fault_kind(
            &mut kinds,
            RandomFaultKind::BlockLatency,
            weights.block_latency,
        );
        push_weighted_random_fault_kind(
            &mut kinds,
            RandomFaultKind::BlockFailure,
            weights.block_failure,
        );
        push_weighted_random_fault_kind(
            &mut kinds,
            RandomFaultKind::BlockReorder,
            weights.block_reorder,
        );
    }
    if has_ninep_devices {
        push_weighted_random_fault_kind(
            &mut kinds,
            RandomFaultKind::NinePLatency,
            weights.ninep_latency,
        );
        push_weighted_random_fault_kind(
            &mut kinds,
            RandomFaultKind::NinePFailure,
            weights.ninep_failure,
        );
    }
    kinds
}

pub(super) fn push_weighted_random_fault_kind(
    kinds: &mut Vec<(RandomFaultKind, u32)>,
    kind: RandomFaultKind,
    weight: u32,
) {
    if weight != 0 {
        kinds.push((kind, weight));
    }
}

pub(super) fn draw_random_fault_start(
    stream: &mut DecisionStream,
    config: &RandomFaultConfig,
) -> Result<u64, EngineError> {
    let max_start = config
        .duration
        .nanos()
        .saturating_sub(config.bounds.min_duration.nanos());
    draw_u64_inclusive(stream, 0, max_start)
}

pub(super) fn draw_random_fault_duration(
    stream: &mut DecisionStream,
    config: &RandomFaultConfig,
    start: u64,
) -> Result<FaultDuration, EngineError> {
    let remaining = config.duration.nanos().saturating_sub(start);
    let max_duration = config.bounds.max_duration.nanos().min(remaining);
    draw_fault_duration_inclusive(stream, config.bounds.min_duration.nanos(), max_duration)
}

pub(super) fn draw_random_fault_kind(
    stream: &mut DecisionStream,
    kinds: &[(RandomFaultKind, u32)],
) -> Result<RandomFaultKind, EngineError> {
    let total = kinds
        .iter()
        .try_fold(0_u64, |sum, (_kind, weight)| {
            sum.checked_add(u64::from(*weight))
        })
        .ok_or(EngineError::RandomFaultConfigInvalid {
            reason: "random fault weights overflowed",
        })?;
    let mut draw = draw_bounded_u64(stream, total)?;
    for (kind, weight) in kinds {
        let weight = u64::from(*weight);
        if draw < weight {
            return Ok(*kind);
        }
        draw -= weight;
    }
    Err(EngineError::RandomFaultConfigInvalid {
        reason: "random fault weighted draw had no selected kind",
    })
}

pub(super) fn draw_random_fault(
    stream: &mut DecisionStream,
    config: &RandomFaultConfig,
    kind: RandomFaultKind,
    nodes: &[NodeId],
    links: &[LinkId],
    block_devices: &[DeviceId],
    ninep_devices: &[DeviceId],
) -> Result<Fault, EngineError> {
    match kind {
        RandomFaultKind::Partition => Ok(Fault::Network(NetworkFault::Partition {
            link: draw_link_target(stream, links)?,
            direction: draw_partition_direction(stream)?,
        })),
        RandomFaultKind::MessageLoss => Ok(Fault::Network(NetworkFault::Loss {
            link: draw_link_target(stream, links)?,
            rate: draw_fault_rate(stream, config.bounds)?,
        })),
        RandomFaultKind::Reorder => Ok(Fault::Network(NetworkFault::Reorder {
            link: draw_link_target(stream, links)?,
            window: draw_fault_duration_inclusive(
                stream,
                config.bounds.min_reorder_window.nanos(),
                config.bounds.max_reorder_window.nanos(),
            )?,
        })),
        RandomFaultKind::Duplicate => Ok(Fault::Network(NetworkFault::Duplicate {
            link: draw_link_target(stream, links)?,
            rate: draw_fault_rate(stream, config.bounds)?,
            gap: draw_fault_duration_inclusive(
                stream,
                config.bounds.min_duplicate_gap.nanos(),
                config.bounds.max_duplicate_gap.nanos(),
            )?,
        })),
        RandomFaultKind::Corruption => Ok(Fault::Network(NetworkFault::Corruption {
            link: draw_link_target(stream, links)?,
            kind: draw_network_corruption_fault(stream, config.bounds)?,
        })),
        RandomFaultKind::BandwidthLimit => Ok(Fault::Network(NetworkFault::Bandwidth {
            link: draw_link_target(stream, links)?,
            limit: draw_bandwidth_limit(stream, config.bounds)?,
        })),
        RandomFaultKind::LatencyBump => Ok(Fault::Network(NetworkFault::LatencyBump {
            link: draw_link_target(stream, links)?,
            extra: draw_fault_duration_inclusive(
                stream,
                config.bounds.min_latency.nanos(),
                config.bounds.max_latency.nanos(),
            )?,
        })),
        RandomFaultKind::Crash => Ok(Fault::Node(NodeFault::Crash {
            node: draw_node_target(stream, nodes)?,
            restart: draw_restart_policy(stream)?,
        })),
        RandomFaultKind::Slow => Ok(Fault::Node(NodeFault::Slow {
            node: draw_node_target(stream, nodes)?,
            factor: draw_slowdown_factor(stream, config.bounds)?,
        })),
        RandomFaultKind::ClockSkew => Ok(Fault::Node(NodeFault::ClockSkew {
            node: draw_node_target(stream, nodes)?,
            offset: draw_clock_skew(stream, config.bounds)?,
        })),
        RandomFaultKind::BlockLatency => Ok(Fault::Block(BlockFault::Latency {
            device: draw_device_target(stream, block_devices)?,
            extra: draw_latency_duration(stream, config.bounds)?,
            jitter: draw_latency_duration(stream, config.bounds)?,
        })),
        RandomFaultKind::BlockFailure => Ok(Fault::Block(BlockFault::Failure {
            device: draw_device_target(stream, block_devices)?,
            rate: draw_fault_rate(stream, config.bounds)?,
            mode: draw_io_failure_mode(stream)?,
        })),
        RandomFaultKind::BlockReorder => Ok(Fault::Block(BlockFault::Reorder {
            device: draw_device_target(stream, block_devices)?,
            window: draw_reorder_window(stream, config.bounds)?,
        })),
        RandomFaultKind::NinePLatency => Ok(Fault::NineP(NinePFault::Latency {
            device: draw_device_target(stream, ninep_devices)?,
            extra: draw_latency_duration(stream, config.bounds)?,
            jitter: draw_latency_duration(stream, config.bounds)?,
        })),
        RandomFaultKind::NinePFailure => Ok(Fault::NineP(NinePFault::Failure {
            device: draw_device_target(stream, ninep_devices)?,
            rate: draw_fault_rate(stream, config.bounds)?,
            errno: NinePErrno::EIO,
        })),
    }
}

pub(super) fn draw_node_target(
    stream: &mut DecisionStream,
    nodes: &[NodeId],
) -> Result<NodeId, EngineError> {
    let index = draw_index(stream, nodes.len())?;
    Ok(nodes[index].clone())
}

pub(super) fn draw_link_target(
    stream: &mut DecisionStream,
    links: &[LinkId],
) -> Result<LinkId, EngineError> {
    let index = draw_index(stream, links.len())?;
    Ok(links[index].clone())
}

pub(super) fn draw_device_target(
    stream: &mut DecisionStream,
    devices: &[DeviceId],
) -> Result<DeviceId, EngineError> {
    let index = draw_index(stream, devices.len())?;
    Ok(devices[index].clone())
}

pub(super) fn draw_index(stream: &mut DecisionStream, len: usize) -> Result<usize, EngineError> {
    if len == 0 {
        return Err(EngineError::RandomFaultConfigInvalid {
            reason: "random fault target set is empty",
        });
    }
    Ok(draw_bounded_u64(stream, len as u64)? as usize)
}

pub(super) fn draw_partition_direction(
    stream: &mut DecisionStream,
) -> Result<PartitionDirection, EngineError> {
    match draw_bounded_u64(stream, 3)? {
        0 => Ok(PartitionDirection::Bidirectional),
        1 => Ok(PartitionDirection::EndpointAToEndpointB),
        _ => Ok(PartitionDirection::EndpointBToEndpointA),
    }
}

pub(super) fn draw_restart_policy(
    stream: &mut DecisionStream,
) -> Result<RestartPolicy, EngineError> {
    match draw_bounded_u64(stream, 3)? {
        0 => Ok(RestartPolicy::FromReadyPoint),
        1 => Ok(RestartPolicy::FromLastCheckpoint),
        _ => Ok(RestartPolicy::StayDown),
    }
}

pub(super) fn draw_io_failure_mode(
    stream: &mut DecisionStream,
) -> Result<IoFailureMode, EngineError> {
    match draw_bounded_u64(stream, 2)? {
        0 => Ok(IoFailureMode::ErrorStatus),
        _ => Ok(IoFailureMode::Drop),
    }
}

pub(super) fn draw_latency_duration(
    stream: &mut DecisionStream,
    bounds: SeverityBounds,
) -> Result<FaultDuration, EngineError> {
    draw_fault_duration_inclusive(
        stream,
        bounds.min_latency.nanos(),
        bounds.max_latency.nanos(),
    )
}

pub(super) fn draw_reorder_window(
    stream: &mut DecisionStream,
    bounds: SeverityBounds,
) -> Result<FaultDuration, EngineError> {
    draw_fault_duration_inclusive(
        stream,
        bounds.min_reorder_window.nanos(),
        bounds.max_reorder_window.nanos(),
    )
}

pub(super) fn draw_network_corruption_fault(
    stream: &mut DecisionStream,
    bounds: SeverityBounds,
) -> Result<NetworkCorruptionFault, EngineError> {
    let rate = draw_fault_rate(stream, bounds)?;
    match draw_bounded_u64(stream, 3)? {
        0 => Ok(NetworkCorruptionFault::BitFlip {
            rate,
            max_bits: draw_u32_inclusive(
                stream,
                bounds.min_corruption_bits,
                bounds.max_corruption_bits,
            )?,
        }),
        1 => Ok(NetworkCorruptionFault::FieldMutation { rate }),
        _ => Ok(NetworkCorruptionFault::Truncation {
            rate,
            max_bytes: draw_u64_inclusive(
                stream,
                bounds.min_truncation_bytes,
                bounds.max_truncation_bytes,
            )?,
        }),
    }
}

pub(super) fn draw_fault_rate(
    stream: &mut DecisionStream,
    bounds: SeverityBounds,
) -> Result<FaultRateBasisPoints, EngineError> {
    FaultRateBasisPoints::from_basis_points(draw_u32_inclusive(
        stream,
        u32::from(bounds.min_rate.basis_points()),
        u32::from(bounds.max_rate.basis_points()),
    )?)
}

pub(super) fn draw_bandwidth_limit(
    stream: &mut DecisionStream,
    bounds: SeverityBounds,
) -> Result<FaultBandwidthBitsPerSecond, EngineError> {
    FaultBandwidthBitsPerSecond::new(draw_u64_inclusive(
        stream,
        bounds.min_bandwidth.bits_per_second(),
        bounds.max_bandwidth.bits_per_second(),
    )?)
}

pub(super) fn draw_slowdown_factor(
    stream: &mut DecisionStream,
    bounds: SeverityBounds,
) -> Result<FaultSlowdownFactorBasisPoints, EngineError> {
    FaultSlowdownFactorBasisPoints::from_basis_points(draw_u32_inclusive(
        stream,
        bounds.min_slowdown.basis_points(),
        bounds.max_slowdown.basis_points(),
    )?)
}

pub(super) fn draw_clock_skew(
    stream: &mut DecisionStream,
    bounds: SeverityBounds,
) -> Result<SimOffset, EngineError> {
    Ok(SimOffset {
        nanos: draw_i64_inclusive(
            stream,
            bounds.min_clock_skew.nanos,
            bounds.max_clock_skew.nanos,
        )?,
    })
}

pub(super) fn draw_fault_duration_inclusive(
    stream: &mut DecisionStream,
    min: u64,
    max: u64,
) -> Result<FaultDuration, EngineError> {
    Ok(FaultDuration::from_nanos(draw_u64_inclusive(
        stream, min, max,
    )?))
}

pub(super) fn draw_u32_inclusive(
    stream: &mut DecisionStream,
    min: u32,
    max: u32,
) -> Result<u32, EngineError> {
    Ok(draw_u64_inclusive(stream, u64::from(min), u64::from(max))? as u32)
}

pub(super) fn draw_u64_inclusive(
    stream: &mut DecisionStream,
    min: u64,
    max: u64,
) -> Result<u64, EngineError> {
    if min > max {
        return Err(EngineError::RandomFaultConfigInvalid {
            reason: "random fault integer draw range is empty",
        });
    }
    let span = max
        .checked_sub(min)
        .and_then(|delta| delta.checked_add(1))
        .ok_or(EngineError::RandomFaultConfigInvalid {
            reason: "random fault integer draw range overflows",
        })?;
    Ok(min + draw_bounded_u64(stream, span)?)
}

pub(super) fn draw_i64_inclusive(
    stream: &mut DecisionStream,
    min: i64,
    max: i64,
) -> Result<i64, EngineError> {
    if min > max {
        return Err(EngineError::RandomFaultConfigInvalid {
            reason: "random fault signed draw range is empty",
        });
    }
    let span = i128::from(max) - i128::from(min) + 1;
    if span <= 0 || span > i128::from(u64::MAX) {
        return Err(EngineError::RandomFaultConfigInvalid {
            reason: "random fault signed draw range overflows",
        });
    }
    Ok((i128::from(min) + i128::from(draw_bounded_u64(stream, span as u64)?)) as i64)
}

pub(super) fn draw_bounded_u64(
    stream: &mut DecisionStream,
    upper_exclusive: u64,
) -> Result<u64, EngineError> {
    draw_bounded_u64_from(upper_exclusive, || stream.next_u64())
}

/// Reduces an arbitrary deterministic `u64` draw source without modulo bias.
pub(super) fn draw_bounded_u64_from(
    upper_exclusive: u64,
    mut next_u64: impl FnMut() -> u64,
) -> Result<u64, EngineError> {
    if upper_exclusive == 0 {
        return Err(EngineError::RandomFaultConfigInvalid {
            reason: "random fault bounded draw upper bound is zero",
        });
    }
    // `threshold = 2^64 mod upper_exclusive`. Values below it are the short
    // prefix that would make `% upper_exclusive` favor low residues. Retrying
    // locally preserves the documented logical draw order: a bounded field is
    // completely resolved before the generator advances to the next field.
    let threshold = upper_exclusive.wrapping_neg() % upper_exclusive;
    loop {
        let draw = next_u64();
        if draw >= threshold {
            return Ok(draw % upper_exclusive);
        }
    }
}

pub(super) fn prune_random_fault_candidates(
    candidates: Vec<RandomFaultCandidate>,
    caps: FaultCaps,
) -> Vec<RandomFaultCandidate> {
    let mut kept = Vec::new();
    let mut partitions = 0_u32;
    let mut crashes = 0_u32;

    for candidate in candidates {
        if candidate.kind.is_partition() && partitions >= caps.max_partitions {
            continue;
        }
        if candidate.kind.is_crash() && crashes >= caps.max_crashes {
            continue;
        }
        if random_fault_candidate_exceeds_concurrency(&kept, &candidate, caps.max_concurrent_faults)
        {
            continue;
        }
        if candidate.kind.is_partition() {
            partitions = partitions.saturating_add(1);
        }
        if candidate.kind.is_crash() {
            crashes = crashes.saturating_add(1);
        }
        kept.push(candidate);
    }
    kept
}

pub(super) fn random_fault_candidate_exceeds_concurrency(
    kept: &[RandomFaultCandidate],
    candidate: &RandomFaultCandidate,
    cap: u32,
) -> bool {
    if cap == u32::MAX {
        return false;
    }
    let cap = cap as usize;
    let mut points = vec![candidate.start];
    for retained in kept {
        if random_fault_intervals_overlap(retained, candidate)
            && candidate.start <= retained.start
            && retained.start < candidate.end
        {
            points.push(retained.start);
        }
    }
    points.into_iter().any(|point| {
        let active_retained = kept
            .iter()
            .filter(|retained| retained.start <= point && point < retained.end)
            .count();
        active_retained.saturating_add(1) > cap
    })
}

pub(super) fn random_fault_intervals_overlap(
    left: &RandomFaultCandidate,
    right: &RandomFaultCandidate,
) -> bool {
    left.start < right.end && right.start < left.end
}

impl RandomFaultKind {
    fn is_partition(self) -> bool {
        matches!(self, Self::Partition)
    }

    fn is_crash(self) -> bool {
        matches!(self, Self::Crash)
    }
}

pub(super) fn random_fault_config_material(config: &RandomFaultConfig, world: &World) -> String {
    format!(
        "world_ref={}\nfault_slots={}\nduration_nanos={}\n{}\n{}\n{}",
        content_hash_hex(canonical_world_identity(world)),
        config.fault_slots,
        config.duration.nanos(),
        random_fault_weights_material(config.weights),
        random_fault_bounds_material(config.bounds),
        seed_material(config.seed)
    )
}

pub(super) fn random_fault_weights_material(weights: FaultWeights) -> String {
    format!(
        "weights.partition={}\nweights.message_loss={}\nweights.reorder={}\nweights.duplicate={}\nweights.corruption={}\nweights.bandwidth_limit={}\nweights.latency_bump={}\nweights.crash={}\nweights.slow={}\nweights.clock_skew={}\nweights.block_latency={}\nweights.block_failure={}\nweights.block_reorder={}\nweights.ninep_latency={}\nweights.ninep_failure={}",
        weights.partition,
        weights.message_loss,
        weights.reorder,
        weights.duplicate,
        weights.corruption,
        weights.bandwidth_limit,
        weights.latency_bump,
        weights.crash,
        weights.slow,
        weights.clock_skew,
        weights.block_latency,
        weights.block_failure,
        weights.block_reorder,
        weights.ninep_latency,
        weights.ninep_failure
    )
}

pub(super) fn random_fault_bounds_material(bounds: SeverityBounds) -> String {
    format!(
        "bounds.min_duration_nanos={}\nbounds.max_duration_nanos={}\nbounds.min_rate_basis_points={}\nbounds.max_rate_basis_points={}\nbounds.min_latency_nanos={}\nbounds.max_latency_nanos={}\nbounds.min_reorder_window_nanos={}\nbounds.max_reorder_window_nanos={}\nbounds.min_duplicate_gap_nanos={}\nbounds.max_duplicate_gap_nanos={}\nbounds.min_bandwidth_bits_per_second={}\nbounds.max_bandwidth_bits_per_second={}\nbounds.min_slowdown_basis_points={}\nbounds.max_slowdown_basis_points={}\nbounds.min_clock_skew_nanos={}\nbounds.max_clock_skew_nanos={}\nbounds.min_corruption_bits={}\nbounds.max_corruption_bits={}\nbounds.min_truncation_bytes={}\nbounds.max_truncation_bytes={}",
        bounds.min_duration.nanos(),
        bounds.max_duration.nanos(),
        bounds.min_rate.basis_points(),
        bounds.max_rate.basis_points(),
        bounds.min_latency.nanos(),
        bounds.max_latency.nanos(),
        bounds.min_reorder_window.nanos(),
        bounds.max_reorder_window.nanos(),
        bounds.min_duplicate_gap.nanos(),
        bounds.max_duplicate_gap.nanos(),
        bounds.min_bandwidth.bits_per_second(),
        bounds.max_bandwidth.bits_per_second(),
        bounds.min_slowdown.basis_points(),
        bounds.max_slowdown.basis_points(),
        bounds.min_clock_skew.nanos,
        bounds.max_clock_skew.nanos,
        bounds.min_corruption_bits,
        bounds.max_corruption_bits,
        bounds.min_truncation_bytes,
        bounds.max_truncation_bytes
    )
}

pub(super) fn validate_plan_heal(
    tag: &FaultTag,
    entry: &PlanEntry,
    activated_tags: &BTreeMap<FaultTag, Vec<VirtualTime>>,
) -> Result<(), EngineError> {
    let PlanEntry::Heal { at: heal_at, .. } = entry else {
        return Ok(());
    };
    let Some(activation_times) = activated_tags.get(tag) else {
        return Err(EngineError::PlanHealUnknownTag { tag: tag.clone() });
    };
    if activation_times
        .iter()
        .copied()
        .any(|activate_at| activate_at < *heal_at)
    {
        return Ok(());
    }

    if let Some(activate_at) = activation_times.iter().copied().min() {
        return Err(EngineError::PlanHealBeforeActivate {
            tag: tag.clone(),
            activate_at,
            heal_at: *heal_at,
        });
    }
    Err(EngineError::PlanHealUnknownTag { tag: tag.clone() })
}

pub(super) fn validate_plan_node(
    node: &NodeId,
    node_ids: &BTreeSet<&NodeId>,
) -> Result<(), EngineError> {
    if node_ids.contains(node) {
        Ok(())
    } else {
        Err(EngineError::PlanFaultUnknownNode { node: node.clone() })
    }
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
    plan: &Plan,
    assertions: &[AssertionDef],
) -> Vec<AssertionDef> {
    let fault_tags = plan_declared_fault_tags(plan);
    assertions
        .iter()
        .map(|assertion| AssertionDef {
            id: assertion.id.clone(),
            message: assertion.message.clone(),
            property: resolve_property_dsl_for_context(&assertion.property, world, &fault_tags),
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

pub(super) fn resolve_property_dsl_for_context(
    property: &Property,
    world: &World,
    fault_tags: &BTreeSet<FaultTag>,
) -> Property {
    match property {
        Property::Always { predicate } => Property::Always {
            predicate: resolve_predicate_dsl_for_context(predicate, world, fault_tags),
        },
        Property::Sometimes { predicate } => Property::Sometimes {
            predicate: resolve_predicate_dsl_for_context(predicate, world, fault_tags),
        },
        Property::Eventually {
            trigger,
            property,
            deadline,
        } => Property::Eventually {
            trigger: resolve_predicate_dsl_for_context(trigger, world, fault_tags),
            property: resolve_predicate_dsl_for_context(property, world, fault_tags),
            deadline: *deadline,
        },
        Property::AfterQuiescence { predicate } => Property::AfterQuiescence {
            predicate: resolve_predicate_dsl_for_context(predicate, world, fault_tags),
        },
        Property::Reachable {
            predicate,
            expectation,
        } => Property::Reachable {
            predicate: resolve_predicate_dsl_for_context(predicate, world, fault_tags),
            expectation: *expectation,
        },
    }
}

pub(super) fn resolve_event_graph_dsl_for_world(world: &World, graph: &EventGraph) -> EventGraph {
    let fault_tags = event_graph_declared_fault_tags(graph.events());
    EventGraph::from_unchecked_events_for_model(
        graph
            .events()
            .iter()
            .map(|event| Event {
                id: event.id.clone(),
                trigger: event
                    .trigger
                    .as_ref()
                    .map(|trigger| resolve_predicate_dsl_for_context(trigger, world, &fault_tags)),
                action: event.action.clone(),
                policy: event.policy,
            })
            .collect(),
    )
}

pub(super) fn resolve_predicate_dsl_for_context(
    predicate: &Predicate,
    world: &World,
    fault_tags: &BTreeSet<FaultTag>,
) -> Predicate {
    match predicate {
        Predicate::Named { name, nodes } if nodes.is_empty() => {
            resolve_named_predicate_dsl_for_context(name, world, fault_tags)
                .unwrap_or_else(|| predicate.clone())
        }
        Predicate::AllOf { predicates } => Predicate::all_of(
            predicates
                .iter()
                .map(|predicate| resolve_predicate_dsl_for_context(predicate, world, fault_tags))
                .collect(),
        ),
        Predicate::AnyOf { predicates } => Predicate::any_of(
            predicates
                .iter()
                .map(|predicate| resolve_predicate_dsl_for_context(predicate, world, fault_tags))
                .collect(),
        ),
        Predicate::Once { predicate } => Predicate::once(resolve_predicate_dsl_for_context(
            predicate, world, fault_tags,
        )),
        Predicate::Not { predicate } => Predicate::not(resolve_predicate_dsl_for_context(
            predicate, world, fault_tags,
        )),
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
        | Predicate::FaultActive { .. }
        | Predicate::Named { .. }
        | Predicate::GuestMarker { .. } => predicate.clone(),
    }
}

pub(super) fn resolve_named_predicate_dsl_for_context(
    name: &str,
    world: &World,
    fault_tags: &BTreeSet<FaultTag>,
) -> Option<Predicate> {
    match name {
        "no_crashed_nodes" => {
            Some(not_any_or_true(world.vm_nodes().iter().map(|node| {
                Predicate::node_state(node.id.clone(), NodeLifecycle::Crashed)
            })))
        }
        "quiescent" => Some(Predicate::quiescent()),
        "no_active_faults" => Some(not_any_or_true(
            fault_tags.iter().cloned().map(Predicate::fault_active),
        )),
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

pub(super) fn plan_declared_fault_tags(plan: &Plan) -> BTreeSet<FaultTag> {
    match &plan.kind {
        PlanKind::ScheduledEntries { entries } => entries
            .iter()
            .filter_map(|entry| match entry {
                PlanEntry::Activate { tag, .. } => Some(tag.clone()),
                PlanEntry::Heal { .. } => None,
            })
            .collect(),
        PlanKind::EventGraph { graph } => event_graph_declared_fault_tags(graph.events()),
    }
}

pub(super) fn event_graph_declared_fault_tags(events: &[Event]) -> BTreeSet<FaultTag> {
    let mut tags = BTreeSet::new();
    for event in events {
        collect_action_declared_fault_tags(&event.action, &mut tags);
    }
    tags
}

pub(super) fn collect_action_declared_fault_tags(action: &Action, tags: &mut BTreeSet<FaultTag>) {
    match action {
        Action::InjectFault { tag, .. } => {
            tags.insert(tag.clone());
        }
        Action::Group(actions) => {
            for action in actions {
                collect_action_declared_fault_tags(action, tags);
            }
        }
        Action::HealFault { .. }
        | Action::ArmTimer { .. }
        | Action::CancelTimer { .. }
        | Action::StartNode { .. }
        | Action::StopNode { .. }
        | Action::CreateSavepoint { .. }
        | Action::Fork { .. }
        | Action::Pass
        | Action::Fail { .. }
        | Action::Log { .. } => {}
    }
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
        Predicate::At { .. }
        | Predicate::NetworkMatch { .. }
        | Predicate::Quiescent
        | Predicate::FaultActive { .. } => Ok(()),
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

pub(super) fn canonical_link_endpoint_pair(left: &NodeId, right: &NodeId) -> (NodeId, NodeId) {
    if left <= right {
        (left.clone(), right.clone())
    } else {
        (right.clone(), left.clone())
    }
}

pub(super) fn canonical_plan_entries(entries: &[PlanEntry]) -> Vec<PlanEntry> {
    let mut entries = entries.iter().map(canonical_plan_entry).collect::<Vec<_>>();
    entries.sort_by(plan_entry_cmp);
    entries
}

pub(super) fn canonical_fault_plan_entries(entries: &[FaultPlanEntry]) -> Vec<FaultPlanEntry> {
    let mut entries = entries
        .iter()
        .map(canonical_fault_plan_entry)
        .collect::<Vec<_>>();
    entries.sort_by(fault_plan_entry_cmp);
    entries
}

pub(super) fn canonical_plan_entry(entry: &PlanEntry) -> PlanEntry {
    match entry {
        PlanEntry::Activate { at, tag, fault } => PlanEntry::Activate {
            at: *at,
            tag: tag.clone(),
            fault: canonical_membership_fault(fault),
        },
        PlanEntry::Heal { at, tag } => PlanEntry::Heal {
            at: *at,
            tag: tag.clone(),
        },
    }
}

pub(super) fn canonical_fault_plan_entry(entry: &FaultPlanEntry) -> FaultPlanEntry {
    match entry {
        FaultPlanEntry::At {
            at,
            duration,
            tag,
            fault,
        } => FaultPlanEntry::At {
            at: *at,
            duration: *duration,
            tag: tag.clone(),
            fault: fault.clone(),
        },
        FaultPlanEntry::PermanentAt { at, tag, fault } => FaultPlanEntry::PermanentAt {
            at: *at,
            tag: tag.clone(),
            fault: fault.clone(),
        },
        FaultPlanEntry::Heal { at, tag } => FaultPlanEntry::Heal {
            at: *at,
            tag: tag.clone(),
        },
    }
}

pub(super) fn canonical_membership_fault(fault: &MembershipFault) -> MembershipFault {
    match fault {
        MembershipFault::Crash { node, restart } => MembershipFault::Crash {
            node: node.clone(),
            restart: *restart,
        },
        MembershipFault::Partition {
            endpoint_a,
            endpoint_b,
            direction,
        } => {
            let canonical = canonical_partition_fault(endpoint_a, endpoint_b, *direction);
            MembershipFault::Partition {
                endpoint_a: canonical.endpoint_a,
                endpoint_b: canonical.endpoint_b,
                direction: canonical.direction,
            }
        }
        MembershipFault::Isolate { node } => MembershipFault::Isolate { node: node.clone() },
        MembershipFault::NotYetJoined { node } => {
            MembershipFault::NotYetJoined { node: node.clone() }
        }
        MembershipFault::Taxonomy { fault } => MembershipFault::Taxonomy {
            fault: fault.clone(),
        },
    }
}

pub(super) fn inverted_partition_direction(direction: PartitionDirection) -> PartitionDirection {
    match direction {
        PartitionDirection::Bidirectional => PartitionDirection::Bidirectional,
        PartitionDirection::EndpointAToEndpointB => PartitionDirection::EndpointBToEndpointA,
        PartitionDirection::EndpointBToEndpointA => PartitionDirection::EndpointAToEndpointB,
    }
}

pub(super) fn plan_entry_cmp(left: &PlanEntry, right: &PlanEntry) -> std::cmp::Ordering {
    plan_entry_time(left)
        .cmp(&plan_entry_time(right))
        .then_with(|| plan_entry_kind_order(left).cmp(&plan_entry_kind_order(right)))
        .then_with(|| plan_entry_material(left).cmp(&plan_entry_material(right)))
}

pub(super) fn fault_plan_entry_cmp(
    left: &FaultPlanEntry,
    right: &FaultPlanEntry,
) -> std::cmp::Ordering {
    fault_plan_entry_time(left)
        .cmp(&fault_plan_entry_time(right))
        .then_with(|| fault_plan_entry_kind_order(left).cmp(&fault_plan_entry_kind_order(right)))
        .then_with(|| left.cmp(right))
}

pub(super) fn plan_entry_time(entry: &PlanEntry) -> VirtualTime {
    match entry {
        PlanEntry::Activate { at, .. } | PlanEntry::Heal { at, .. } => *at,
    }
}

pub(super) fn fault_plan_entry_time(entry: &FaultPlanEntry) -> VirtualTime {
    match entry {
        FaultPlanEntry::At { at, .. }
        | FaultPlanEntry::PermanentAt { at, .. }
        | FaultPlanEntry::Heal { at, .. } => *at,
    }
}

pub(super) fn plan_entry_kind_order(entry: &PlanEntry) -> u8 {
    match entry {
        PlanEntry::Activate { .. } => 0,
        PlanEntry::Heal { .. } => 1,
    }
}

pub(super) fn fault_plan_entry_kind_order(entry: &FaultPlanEntry) -> u8 {
    match entry {
        FaultPlanEntry::At { .. } => 0,
        FaultPlanEntry::PermanentAt { .. } => 1,
        FaultPlanEntry::Heal { .. } => 2,
    }
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
        Predicate::FaultActive { tag } => Predicate::FaultActive { tag: tag.clone() },
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
