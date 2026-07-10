// Canonical binary plan, action, fault, and predicate codec.
fn collection_count_from_raw(label: &'static str, count: u64) -> Result<usize, EngineError> {
    let count = usize::try_from(count)
        .map_err(|_| scenario_serialization_error("binary count does not fit usize"))?;
    if count > MAX_SCENARIO_BINARY_COLLECTION_ITEMS {
        Err(scenario_serialization_error(format!(
            "{label} count exceeds serialized collection limit"
        )))
    } else {
        Ok(count)
    }
}

fn event_graph_assertion_references(events: &[Event]) -> Vec<AssertionId> {
    let mut assertions = BTreeSet::new();
    for event in events {
        if let Some(trigger) = &event.trigger {
            collect_predicate_assertion_references(trigger, &mut assertions);
        }
    }
    assertions.into_iter().collect()
}

fn collect_predicate_assertion_references(
    predicate: &Predicate,
    assertions: &mut BTreeSet<AssertionId>,
) {
    match predicate {
        Predicate::AssertionState { name, .. } => {
            assertions.insert(name.clone());
        }
        Predicate::AllOf { predicates } | Predicate::AnyOf { predicates } => {
            for predicate in predicates {
                collect_predicate_assertion_references(predicate, assertions);
            }
        }
        Predicate::Once { predicate } | Predicate::Not { predicate } => {
            collect_predicate_assertion_references(predicate, assertions);
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
        | Predicate::Quiescent
        | Predicate::FaultActive { .. }
        | Predicate::Named { .. }
        | Predicate::GuestMarker { .. } => {}
    }
}

fn write_plan_entry_binary(entry: &PlanEntry, writer: &mut ScenarioBinaryWriter) {
    match entry {
        PlanEntry::Activate { at, tag, fault } => {
            writer.write_u8(0);
            writer.write_u64(at.ticks);
            writer.write_string(&tag.name);
            write_membership_fault_binary(fault, writer);
        }
        PlanEntry::Heal { at, tag } => {
            writer.write_u8(1);
            writer.write_u64(at.ticks);
            writer.write_string(&tag.name);
        }
    }
}

fn read_plan_entry_binary(reader: &mut ScenarioBinaryReader<'_>) -> Result<PlanEntry, EngineError> {
    match reader.read_u8()? {
        0 => Ok(PlanEntry::Activate {
            at: VirtualTime {
                ticks: reader.read_u64()?,
            },
            tag: FaultTag {
                name: reader.read_string()?,
            },
            fault: read_membership_fault_binary(reader)?,
        }),
        1 => Ok(PlanEntry::Heal {
            at: VirtualTime {
                ticks: reader.read_u64()?,
            },
            tag: FaultTag {
                name: reader.read_string()?,
            },
        }),
        _ => Err(scenario_serialization_error("invalid plan-entry tag")),
    }
}

fn write_fault_plan_entry_binary(entry: &FaultPlanEntry, writer: &mut ScenarioBinaryWriter) {
    match entry {
        FaultPlanEntry::At {
            at,
            duration,
            tag,
            fault,
        } => {
            writer.write_u8(0);
            writer.write_u64(at.ticks);
            writer.write_u64(duration.nanos());
            writer.write_string(&tag.name);
            write_fault_binary(fault, writer);
        }
        FaultPlanEntry::PermanentAt { at, tag, fault } => {
            writer.write_u8(1);
            writer.write_u64(at.ticks);
            writer.write_string(&tag.name);
            write_fault_binary(fault, writer);
        }
        FaultPlanEntry::Heal { at, tag } => {
            writer.write_u8(2);
            writer.write_u64(at.ticks);
            writer.write_string(&tag.name);
        }
    }
}

fn read_fault_plan_entry_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<FaultPlanEntry, EngineError> {
    match reader.read_u8()? {
        0 => Ok(FaultPlanEntry::At {
            at: VirtualTime {
                ticks: reader.read_u64()?,
            },
            duration: FaultDuration::from_nanos(reader.read_u64()?),
            tag: FaultTag {
                name: reader.read_string()?,
            },
            fault: read_fault_binary(reader)?,
        }),
        1 => Ok(FaultPlanEntry::PermanentAt {
            at: VirtualTime {
                ticks: reader.read_u64()?,
            },
            tag: FaultTag {
                name: reader.read_string()?,
            },
            fault: read_fault_binary(reader)?,
        }),
        2 => Ok(FaultPlanEntry::Heal {
            at: VirtualTime {
                ticks: reader.read_u64()?,
            },
            tag: FaultTag {
                name: reader.read_string()?,
            },
        }),
        _ => Err(scenario_serialization_error("invalid fault-plan-entry tag")),
    }
}

fn write_event_binary(event: &Event, writer: &mut ScenarioBinaryWriter) {
    writer.write_string(&event.id.name);
    match &event.trigger {
        Some(trigger) => {
            writer.write_u8(1);
            write_predicate_binary(trigger, writer);
        }
        None => writer.write_u8(0),
    }
    write_action_binary(&event.action, writer);
    writer.write_u8(match event.policy {
        FirePolicy::Once => 0,
        FirePolicy::Repeatable => 1,
    });
}

fn read_event_binary(reader: &mut ScenarioBinaryReader<'_>) -> Result<Event, EngineError> {
    let id = EventId {
        name: reader.read_string()?,
    };
    let trigger = match reader.read_u8()? {
        0 => None,
        1 => Some(read_predicate_binary(reader)?),
        _ => return Err(scenario_serialization_error("invalid event trigger tag")),
    };
    let action = read_action_binary(reader)?;
    let policy = match reader.read_u8()? {
        0 => FirePolicy::Once,
        1 => FirePolicy::Repeatable,
        _ => return Err(scenario_serialization_error("invalid fire-policy tag")),
    };
    Ok(Event {
        id,
        trigger,
        action,
        policy,
    })
}

fn write_action_binary(action: &Action, writer: &mut ScenarioBinaryWriter) {
    match action {
        Action::InjectFault { tag, fault } => {
            writer.write_u8(0);
            writer.write_string(&tag.name);
            write_membership_fault_binary(fault, writer);
        }
        Action::HealFault { tag } => {
            writer.write_u8(1);
            writer.write_string(&tag.name);
        }
        Action::ArmTimer { name, after } => {
            writer.write_u8(2);
            writer.write_string(&name.name);
            writer.write_u64(after.nanos);
        }
        Action::CancelTimer { name } => {
            writer.write_u8(3);
            writer.write_string(&name.name);
        }
        Action::StartNode { node } => {
            writer.write_u8(4);
            writer.write_string(&node.name);
        }
        Action::StopNode { node } => {
            writer.write_u8(5);
            writer.write_string(&node.name);
        }
        Action::CreateSavepoint { label } => {
            writer.write_u8(6);
            write_optional_string_binary(label.as_deref(), writer);
        }
        Action::Fork { label } => {
            writer.write_u8(7);
            write_optional_string_binary(label.as_deref(), writer);
        }
        Action::Pass => writer.write_u8(8),
        Action::Fail { reason } => {
            writer.write_u8(9);
            writer.write_string(reason);
        }
        Action::Log { level, message } => {
            writer.write_u8(10);
            write_log_level_binary(*level, writer);
            writer.write_string(message);
        }
        Action::Group(actions) => {
            writer.write_u8(11);
            writer.write_count(actions.len());
            for action in actions {
                write_action_binary(action, writer);
            }
        }
    }
}

fn read_action_binary(reader: &mut ScenarioBinaryReader<'_>) -> Result<Action, EngineError> {
    match reader.read_u8()? {
        0 => Ok(Action::InjectFault {
            tag: FaultTag {
                name: reader.read_string()?,
            },
            fault: read_membership_fault_binary(reader)?,
        }),
        1 => Ok(Action::HealFault {
            tag: FaultTag {
                name: reader.read_string()?,
            },
        }),
        2 => Ok(Action::ArmTimer {
            name: TimerId {
                name: reader.read_string()?,
            },
            after: SimDuration {
                nanos: reader.read_u64()?,
            },
        }),
        3 => Ok(Action::CancelTimer {
            name: TimerId {
                name: reader.read_string()?,
            },
        }),
        4 => Ok(Action::StartNode {
            node: NodeId {
                name: reader.read_string()?,
            },
        }),
        5 => Ok(Action::StopNode {
            node: NodeId {
                name: reader.read_string()?,
            },
        }),
        6 => Ok(Action::CreateSavepoint {
            label: read_optional_string_binary(reader)?,
        }),
        7 => Ok(Action::Fork {
            label: read_optional_string_binary(reader)?,
        }),
        8 => Ok(Action::Pass),
        9 => Ok(Action::Fail {
            reason: reader.read_string()?,
        }),
        10 => Ok(Action::Log {
            level: read_log_level_binary(reader)?,
            message: reader.read_string()?,
        }),
        11 => {
            let count = reader.read_collection_count("action.group")?;
            let mut actions = Vec::with_capacity(count);
            for _ in 0..count {
                actions.push(read_action_binary(reader)?);
            }
            Ok(Action::Group(actions))
        }
        _ => Err(scenario_serialization_error("invalid action tag")),
    }
}

fn write_control_operation_kind_binary(
    kind: &ControlOperationKind,
    writer: &mut ScenarioBinaryWriter,
) {
    match kind {
        ControlOperationKind::Pause => writer.write_u8(0),
        ControlOperationKind::Resume => writer.write_u8(1),
        ControlOperationKind::Step => writer.write_u8(2),
        ControlOperationKind::Snapshot => writer.write_u8(3),
        ControlOperationKind::Fork => writer.write_u8(4),
        ControlOperationKind::Inject => writer.write_u8(5),
        ControlOperationKind::InjectFault { tag, fault } => {
            writer.write_u8(6);
            writer.write_string(&tag.name);
            write_fault_binary(fault, writer);
        }
        ControlOperationKind::HealFault { tag } => {
            writer.write_u8(7);
            writer.write_string(&tag.name);
        }
        ControlOperationKind::Query => writer.write_u8(8),
    }
}

fn read_control_operation_kind_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<ControlOperationKind, EngineError> {
    match reader.read_u8()? {
        0 => Ok(ControlOperationKind::Pause),
        1 => Ok(ControlOperationKind::Resume),
        2 => Ok(ControlOperationKind::Step),
        3 => Ok(ControlOperationKind::Snapshot),
        4 => Ok(ControlOperationKind::Fork),
        5 => Ok(ControlOperationKind::Inject),
        6 => Ok(ControlOperationKind::InjectFault {
            tag: FaultTag {
                name: reader.read_string()?,
            },
            fault: read_fault_binary(reader)?,
        }),
        7 => Ok(ControlOperationKind::HealFault {
            tag: FaultTag {
                name: reader.read_string()?,
            },
        }),
        8 => Ok(ControlOperationKind::Query),
        _ => Err(scenario_serialization_error(
            "invalid control-operation-kind tag",
        )),
    }
}

fn write_optional_string_binary(value: Option<&str>, writer: &mut ScenarioBinaryWriter) {
    match value {
        Some(value) => {
            writer.write_u8(1);
            writer.write_string(value);
        }
        None => writer.write_u8(0),
    }
}

fn read_optional_string_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<Option<String>, EngineError> {
    match reader.read_u8()? {
        0 => Ok(None),
        1 => Ok(Some(reader.read_string()?)),
        _ => Err(scenario_serialization_error(
            "invalid optional string presence tag",
        )),
    }
}

fn write_log_level_binary(level: LogLevel, writer: &mut ScenarioBinaryWriter) {
    writer.write_u8(match level {
        LogLevel::Debug => 0,
        LogLevel::Info => 1,
        LogLevel::Warn => 2,
        LogLevel::Error => 3,
    });
}

fn read_log_level_binary(reader: &mut ScenarioBinaryReader<'_>) -> Result<LogLevel, EngineError> {
    match reader.read_u8()? {
        0 => Ok(LogLevel::Debug),
        1 => Ok(LogLevel::Info),
        2 => Ok(LogLevel::Warn),
        3 => Ok(LogLevel::Error),
        _ => Err(scenario_serialization_error("invalid log-level tag")),
    }
}

fn write_membership_fault_binary(fault: &MembershipFault, writer: &mut ScenarioBinaryWriter) {
    match fault {
        MembershipFault::Crash { node, restart } => {
            writer.write_u8(0);
            writer.write_string(&node.name);
            writer.write_u8(match restart {
                RestartPolicy::FromReadyPoint => 0,
                RestartPolicy::FromLastCheckpoint => 1,
                RestartPolicy::StayDown => 2,
            });
        }
        MembershipFault::Partition {
            endpoint_a,
            endpoint_b,
            direction,
        } => {
            writer.write_u8(1);
            writer.write_string(&endpoint_a.name);
            writer.write_string(&endpoint_b.name);
            writer.write_u8(match direction {
                PartitionDirection::Bidirectional => 0,
                PartitionDirection::EndpointAToEndpointB => 1,
                PartitionDirection::EndpointBToEndpointA => 2,
            });
        }
        MembershipFault::Isolate { node } => {
            writer.write_u8(2);
            writer.write_string(&node.name);
        }
        MembershipFault::NotYetJoined { node } => {
            writer.write_u8(3);
            writer.write_string(&node.name);
        }
        MembershipFault::Taxonomy { fault } => {
            writer.write_u8(4);
            write_fault_binary(fault, writer);
        }
    }
}

fn read_membership_fault_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<MembershipFault, EngineError> {
    match reader.read_u8()? {
        0 => {
            let node = NodeId {
                name: reader.read_string()?,
            };
            let restart = match reader.read_u8()? {
                0 => RestartPolicy::FromReadyPoint,
                1 => RestartPolicy::FromLastCheckpoint,
                2 => RestartPolicy::StayDown,
                _ => return Err(scenario_serialization_error("invalid restart-policy tag")),
            };
            Ok(MembershipFault::Crash { node, restart })
        }
        1 => {
            let endpoint_a = NodeId {
                name: reader.read_string()?,
            };
            let endpoint_b = NodeId {
                name: reader.read_string()?,
            };
            let direction = match reader.read_u8()? {
                0 => PartitionDirection::Bidirectional,
                1 => PartitionDirection::EndpointAToEndpointB,
                2 => PartitionDirection::EndpointBToEndpointA,
                _ => {
                    return Err(scenario_serialization_error(
                        "invalid partition-direction tag",
                    ));
                }
            };
            Ok(MembershipFault::Partition {
                endpoint_a,
                endpoint_b,
                direction,
            })
        }
        2 => Ok(MembershipFault::Isolate {
            node: NodeId {
                name: reader.read_string()?,
            },
        }),
        3 => Ok(MembershipFault::NotYetJoined {
            node: NodeId {
                name: reader.read_string()?,
            },
        }),
        4 => Ok(MembershipFault::Taxonomy {
            fault: read_fault_binary(reader)?,
        }),
        _ => Err(scenario_serialization_error("invalid membership-fault tag")),
    }
}

fn write_fault_binary(fault: &Fault, writer: &mut ScenarioBinaryWriter) {
    match fault {
        Fault::Network(fault) => {
            writer.write_u8(0);
            write_network_fault_binary(fault, writer);
        }
        Fault::Node(fault) => {
            writer.write_u8(1);
            write_node_fault_binary(fault, writer);
        }
        Fault::Block(fault) => {
            writer.write_u8(2);
            write_block_fault_binary(fault, writer);
        }
        Fault::NineP(fault) => {
            writer.write_u8(3);
            write_ninep_fault_binary(fault, writer);
        }
    }
}

fn read_fault_binary(reader: &mut ScenarioBinaryReader<'_>) -> Result<Fault, EngineError> {
    match reader.read_u8()? {
        0 => Ok(Fault::Network(read_network_fault_binary(reader)?)),
        1 => Ok(Fault::Node(read_node_fault_binary(reader)?)),
        2 => Ok(Fault::Block(read_block_fault_binary(reader)?)),
        3 => Ok(Fault::NineP(read_ninep_fault_binary(reader)?)),
        _ => Err(scenario_serialization_error("invalid fault tag")),
    }
}

fn write_network_fault_binary(fault: &NetworkFault, writer: &mut ScenarioBinaryWriter) {
    match fault {
        NetworkFault::Partition { link, direction } => {
            writer.write_u8(0);
            writer.write_string(&link.name);
            write_partition_direction_binary(*direction, writer);
        }
        NetworkFault::Loss { link, rate } => {
            writer.write_u8(1);
            writer.write_string(&link.name);
            writer.write_u32(u32::from(rate.basis_points()));
        }
        NetworkFault::Reorder { link, window } => {
            writer.write_u8(2);
            writer.write_string(&link.name);
            writer.write_u64(window.nanos());
        }
        NetworkFault::Duplicate { link, rate, gap } => {
            writer.write_u8(3);
            writer.write_string(&link.name);
            writer.write_u32(u32::from(rate.basis_points()));
            writer.write_u64(gap.nanos());
        }
        NetworkFault::Corruption { link, kind } => {
            writer.write_u8(4);
            writer.write_string(&link.name);
            write_network_corruption_fault_binary(kind, writer);
        }
        NetworkFault::Bandwidth { link, limit } => {
            writer.write_u8(5);
            writer.write_string(&link.name);
            writer.write_u64(limit.bits_per_second());
        }
        NetworkFault::LatencyBump { link, extra } => {
            writer.write_u8(6);
            writer.write_string(&link.name);
            writer.write_u64(extra.nanos());
        }
    }
}

fn read_network_fault_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<NetworkFault, EngineError> {
    match reader.read_u8()? {
        0 => Ok(NetworkFault::Partition {
            link: read_link_id_binary(reader)?,
            direction: read_partition_direction_binary(reader)?,
        }),
        1 => Ok(NetworkFault::Loss {
            link: read_link_id_binary(reader)?,
            rate: FaultRateBasisPoints::from_basis_points(reader.read_u32()?)?,
        }),
        2 => Ok(NetworkFault::Reorder {
            link: read_link_id_binary(reader)?,
            window: FaultDuration::from_nanos(reader.read_u64()?),
        }),
        3 => Ok(NetworkFault::Duplicate {
            link: read_link_id_binary(reader)?,
            rate: FaultRateBasisPoints::from_basis_points(reader.read_u32()?)?,
            gap: FaultDuration::from_nanos(reader.read_u64()?),
        }),
        4 => Ok(NetworkFault::Corruption {
            link: read_link_id_binary(reader)?,
            kind: read_network_corruption_fault_binary(reader)?,
        }),
        5 => Ok(NetworkFault::Bandwidth {
            link: read_link_id_binary(reader)?,
            limit: FaultBandwidthBitsPerSecond::new(reader.read_u64()?)?,
        }),
        6 => Ok(NetworkFault::LatencyBump {
            link: read_link_id_binary(reader)?,
            extra: FaultDuration::from_nanos(reader.read_u64()?),
        }),
        _ => Err(scenario_serialization_error("invalid network-fault tag")),
    }
}

fn write_network_corruption_fault_binary(
    fault: &NetworkCorruptionFault,
    writer: &mut ScenarioBinaryWriter,
) {
    match fault {
        NetworkCorruptionFault::BitFlip { rate, max_bits } => {
            writer.write_u8(0);
            writer.write_u32(u32::from(rate.basis_points()));
            writer.write_u32(*max_bits);
        }
        NetworkCorruptionFault::FieldMutation { rate } => {
            writer.write_u8(1);
            writer.write_u32(u32::from(rate.basis_points()));
        }
        NetworkCorruptionFault::Truncation { rate, max_bytes } => {
            writer.write_u8(2);
            writer.write_u32(u32::from(rate.basis_points()));
            writer.write_u64(*max_bytes);
        }
    }
}

fn read_network_corruption_fault_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<NetworkCorruptionFault, EngineError> {
    match reader.read_u8()? {
        0 => Ok(NetworkCorruptionFault::BitFlip {
            rate: FaultRateBasisPoints::from_basis_points(reader.read_u32()?)?,
            max_bits: reader.read_u32()?,
        }),
        1 => Ok(NetworkCorruptionFault::FieldMutation {
            rate: FaultRateBasisPoints::from_basis_points(reader.read_u32()?)?,
        }),
        2 => Ok(NetworkCorruptionFault::Truncation {
            rate: FaultRateBasisPoints::from_basis_points(reader.read_u32()?)?,
            max_bytes: reader.read_u64()?,
        }),
        _ => Err(scenario_serialization_error(
            "invalid network-corruption-fault tag",
        )),
    }
}

fn write_node_fault_binary(fault: &NodeFault, writer: &mut ScenarioBinaryWriter) {
    match fault {
        NodeFault::Crash { node, restart } => {
            writer.write_u8(0);
            writer.write_string(&node.name);
            write_restart_policy_binary(*restart, writer);
        }
        NodeFault::Slow { node, factor } => {
            writer.write_u8(1);
            writer.write_string(&node.name);
            writer.write_u32(factor.basis_points());
        }
        NodeFault::ClockSkew { node, offset } => {
            writer.write_u8(2);
            writer.write_string(&node.name);
            writer.write_i64(offset.nanos);
        }
    }
}

fn read_node_fault_binary(reader: &mut ScenarioBinaryReader<'_>) -> Result<NodeFault, EngineError> {
    match reader.read_u8()? {
        0 => Ok(NodeFault::Crash {
            node: read_node_id_binary(reader)?,
            restart: read_restart_policy_binary(reader)?,
        }),
        1 => Ok(NodeFault::Slow {
            node: read_node_id_binary(reader)?,
            factor: FaultSlowdownFactorBasisPoints::from_basis_points(reader.read_u32()?)?,
        }),
        2 => Ok(NodeFault::ClockSkew {
            node: read_node_id_binary(reader)?,
            offset: SimOffset {
                nanos: reader.read_i64()?,
            },
        }),
        _ => Err(scenario_serialization_error("invalid node-fault tag")),
    }
}

fn write_block_fault_binary(fault: &BlockFault, writer: &mut ScenarioBinaryWriter) {
    match fault {
        BlockFault::Latency {
            device,
            extra,
            jitter,
        } => {
            writer.write_u8(0);
            writer.write_string(&device.name);
            writer.write_u64(extra.nanos());
            writer.write_u64(jitter.nanos());
        }
        BlockFault::Failure { device, rate, mode } => {
            writer.write_u8(1);
            writer.write_string(&device.name);
            writer.write_u32(u32::from(rate.basis_points()));
            write_io_failure_mode_binary(*mode, writer);
        }
        BlockFault::Reorder { device, window } => {
            writer.write_u8(2);
            writer.write_string(&device.name);
            writer.write_u64(window.nanos());
        }
        BlockFault::Duplicate { device, rate, gap } => {
            writer.write_u8(3);
            writer.write_string(&device.name);
            writer.write_u32(u32::from(rate.basis_points()));
            writer.write_u64(gap.nanos());
        }
        BlockFault::Corruption {
            device,
            rate,
            bit_flips,
        } => {
            writer.write_u8(4);
            writer.write_string(&device.name);
            writer.write_u32(u32::from(rate.basis_points()));
            writer.write_u32(*bit_flips);
        }
        BlockFault::Bandwidth { device, limit } => {
            writer.write_u8(5);
            writer.write_string(&device.name);
            writer.write_u64(limit.bits_per_second());
        }
    }
}

fn read_block_fault_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<BlockFault, EngineError> {
    match reader.read_u8()? {
        0 => Ok(BlockFault::Latency {
            device: read_device_id_binary(reader)?,
            extra: FaultDuration::from_nanos(reader.read_u64()?),
            jitter: FaultDuration::from_nanos(reader.read_u64()?),
        }),
        1 => Ok(BlockFault::Failure {
            device: read_device_id_binary(reader)?,
            rate: FaultRateBasisPoints::from_basis_points(reader.read_u32()?)?,
            mode: read_io_failure_mode_binary(reader)?,
        }),
        2 => Ok(BlockFault::Reorder {
            device: read_device_id_binary(reader)?,
            window: FaultDuration::from_nanos(reader.read_u64()?),
        }),
        3 => Ok(BlockFault::Duplicate {
            device: read_device_id_binary(reader)?,
            rate: FaultRateBasisPoints::from_basis_points(reader.read_u32()?)?,
            gap: FaultDuration::from_nanos(reader.read_u64()?),
        }),
        4 => Ok(BlockFault::Corruption {
            device: read_device_id_binary(reader)?,
            rate: FaultRateBasisPoints::from_basis_points(reader.read_u32()?)?,
            bit_flips: reader.read_u32()?,
        }),
        5 => Ok(BlockFault::Bandwidth {
            device: read_device_id_binary(reader)?,
            limit: FaultBandwidthBitsPerSecond::new(reader.read_u64()?)?,
        }),
        _ => Err(scenario_serialization_error("invalid block-fault tag")),
    }
}

fn write_ninep_fault_binary(fault: &NinePFault, writer: &mut ScenarioBinaryWriter) {
    match fault {
        NinePFault::Latency {
            device,
            extra,
            jitter,
        } => {
            writer.write_u8(0);
            writer.write_string(&device.name);
            writer.write_u64(extra.nanos());
            writer.write_u64(jitter.nanos());
        }
        NinePFault::Failure {
            device,
            rate,
            errno,
        } => {
            writer.write_u8(1);
            writer.write_string(&device.name);
            writer.write_u32(u32::from(rate.basis_points()));
            writer.write_i64(i64::from(errno.code()));
        }
        NinePFault::Reorder { device, window } => {
            writer.write_u8(2);
            writer.write_string(&device.name);
            writer.write_u64(window.nanos());
        }
        NinePFault::Duplicate { device, rate, gap } => {
            writer.write_u8(3);
            writer.write_string(&device.name);
            writer.write_u32(u32::from(rate.basis_points()));
            writer.write_u64(gap.nanos());
        }
        NinePFault::Corruption {
            device,
            rate,
            bit_flips,
        } => {
            writer.write_u8(4);
            writer.write_string(&device.name);
            writer.write_u32(u32::from(rate.basis_points()));
            writer.write_u32(*bit_flips);
        }
        NinePFault::Bandwidth { device, limit } => {
            writer.write_u8(5);
            writer.write_string(&device.name);
            writer.write_u64(limit.bits_per_second());
        }
    }
}

fn read_ninep_fault_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<NinePFault, EngineError> {
    match reader.read_u8()? {
        0 => Ok(NinePFault::Latency {
            device: read_device_id_binary(reader)?,
            extra: FaultDuration::from_nanos(reader.read_u64()?),
            jitter: FaultDuration::from_nanos(reader.read_u64()?),
        }),
        1 => {
            let device = read_device_id_binary(reader)?;
            let rate = FaultRateBasisPoints::from_basis_points(reader.read_u32()?)?;
            let errno_code = i32::try_from(reader.read_i64()?)
                .map_err(|_error| scenario_serialization_error("9p errno code does not fit i32"))?;
            Ok(NinePFault::Failure {
                device,
                rate,
                errno: NinePErrno::from_code(errno_code)?,
            })
        }
        2 => Ok(NinePFault::Reorder {
            device: read_device_id_binary(reader)?,
            window: FaultDuration::from_nanos(reader.read_u64()?),
        }),
        3 => Ok(NinePFault::Duplicate {
            device: read_device_id_binary(reader)?,
            rate: FaultRateBasisPoints::from_basis_points(reader.read_u32()?)?,
            gap: FaultDuration::from_nanos(reader.read_u64()?),
        }),
        4 => Ok(NinePFault::Corruption {
            device: read_device_id_binary(reader)?,
            rate: FaultRateBasisPoints::from_basis_points(reader.read_u32()?)?,
            bit_flips: reader.read_u32()?,
        }),
        5 => Ok(NinePFault::Bandwidth {
            device: read_device_id_binary(reader)?,
            limit: FaultBandwidthBitsPerSecond::new(reader.read_u64()?)?,
        }),
        _ => Err(scenario_serialization_error("invalid 9p-fault tag")),
    }
}

fn write_restart_policy_binary(policy: RestartPolicy, writer: &mut ScenarioBinaryWriter) {
    writer.write_u8(match policy {
        RestartPolicy::FromReadyPoint => 0,
        RestartPolicy::FromLastCheckpoint => 1,
        RestartPolicy::StayDown => 2,
    });
}

fn read_restart_policy_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<RestartPolicy, EngineError> {
    match reader.read_u8()? {
        0 => Ok(RestartPolicy::FromReadyPoint),
        1 => Ok(RestartPolicy::FromLastCheckpoint),
        2 => Ok(RestartPolicy::StayDown),
        _ => Err(scenario_serialization_error("invalid restart-policy tag")),
    }
}

fn write_partition_direction_binary(
    direction: PartitionDirection,
    writer: &mut ScenarioBinaryWriter,
) {
    writer.write_u8(match direction {
        PartitionDirection::Bidirectional => 0,
        PartitionDirection::EndpointAToEndpointB => 1,
        PartitionDirection::EndpointBToEndpointA => 2,
    });
}

fn read_partition_direction_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<PartitionDirection, EngineError> {
    match reader.read_u8()? {
        0 => Ok(PartitionDirection::Bidirectional),
        1 => Ok(PartitionDirection::EndpointAToEndpointB),
        2 => Ok(PartitionDirection::EndpointBToEndpointA),
        _ => Err(scenario_serialization_error(
            "invalid partition-direction tag",
        )),
    }
}

fn write_io_failure_mode_binary(mode: IoFailureMode, writer: &mut ScenarioBinaryWriter) {
    writer.write_u8(match mode {
        IoFailureMode::Drop => 0,
        IoFailureMode::ErrorStatus => 1,
    });
}

fn read_io_failure_mode_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<IoFailureMode, EngineError> {
    match reader.read_u8()? {
        0 => Ok(IoFailureMode::Drop),
        1 => Ok(IoFailureMode::ErrorStatus),
        _ => Err(scenario_serialization_error("invalid I/O failure-mode tag")),
    }
}

fn read_node_id_binary(reader: &mut ScenarioBinaryReader<'_>) -> Result<NodeId, EngineError> {
    Ok(NodeId {
        name: reader.read_string()?,
    })
}

fn read_link_id_binary(reader: &mut ScenarioBinaryReader<'_>) -> Result<LinkId, EngineError> {
    Ok(LinkId {
        name: reader.read_string()?,
    })
}

fn read_device_id_binary(reader: &mut ScenarioBinaryReader<'_>) -> Result<DeviceId, EngineError> {
    Ok(DeviceId {
        name: reader.read_string()?,
    })
}

fn write_properties_binary(properties: &Properties, writer: &mut ScenarioBinaryWriter) {
    writer.write_hash(properties.content_hash());
    writer.write_count(properties.assertions().len());
    for assertion in properties.assertions() {
        write_assertion_binary(assertion, writer);
    }
}

fn read_properties_binary(
    world: &World,
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<Properties, EngineError> {
    let id = reader.read_hash()?;
    let count = reader.read_collection_count("properties.assertion")?;
    let mut assertions = Vec::with_capacity(count);
    for _ in 0..count {
        assertions.push(read_assertion_binary(reader)?);
    }
    let properties = Properties::from_assertions_for_world(world, assertions)?;
    validate_serialized_id("properties", id, properties.content_hash())?;
    Ok(properties)
}

fn write_assertion_binary(assertion: &AssertionDef, writer: &mut ScenarioBinaryWriter) {
    writer.write_string(&assertion.id.name);
    writer.write_string(&assertion.message);
    write_property_binary(&assertion.property, writer);
}

fn read_assertion_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<AssertionDef, EngineError> {
    Ok(AssertionDef {
        id: AssertionId {
            name: reader.read_string()?,
        },
        message: reader.read_string()?,
        property: read_property_binary(reader)?,
    })
}

fn write_property_binary(property: &Property, writer: &mut ScenarioBinaryWriter) {
    match property {
        Property::Always { predicate } => {
            writer.write_u8(property.kind().binary_tag());
            write_predicate_binary(predicate, writer);
        }
        Property::Sometimes { predicate } => {
            writer.write_u8(property.kind().binary_tag());
            write_predicate_binary(predicate, writer);
        }
        Property::Eventually {
            trigger,
            property,
            deadline,
        } => {
            writer.write_u8(PropertyKind::Eventually.binary_tag());
            write_predicate_binary(trigger, writer);
            write_predicate_binary(property, writer);
            writer.write_u64(deadline.ticks);
        }
        Property::AfterQuiescence { predicate } => {
            writer.write_u8(property.kind().binary_tag());
            write_predicate_binary(predicate, writer);
        }
        Property::Reachable {
            predicate,
            expectation,
        } => {
            writer.write_u8(property.kind().binary_tag());
            write_predicate_binary(predicate, writer);
            write_reachability_expectation_binary(*expectation, writer);
        }
    }
}

fn read_property_binary(reader: &mut ScenarioBinaryReader<'_>) -> Result<Property, EngineError> {
    match PropertyKind::from_binary_tag(reader.read_u8()?) {
        Some(PropertyKind::Always) => Ok(Property::Always {
            predicate: read_predicate_binary(reader)?,
        }),
        Some(PropertyKind::Sometimes) => Ok(Property::Sometimes {
            predicate: read_predicate_binary(reader)?,
        }),
        Some(PropertyKind::Eventually) => Ok(Property::Eventually {
            trigger: read_predicate_binary(reader)?,
            property: read_predicate_binary(reader)?,
            deadline: VirtualTime {
                ticks: reader.read_u64()?,
            },
        }),
        Some(PropertyKind::AfterQuiescence) => Ok(Property::AfterQuiescence {
            predicate: read_predicate_binary(reader)?,
        }),
        Some(PropertyKind::Reachable) => Ok(Property::Reachable {
            predicate: read_predicate_binary(reader)?,
            expectation: read_reachability_expectation_binary(reader)?,
        }),
        None => Err(scenario_serialization_error("invalid property tag")),
    }
}

fn write_predicate_binary(predicate: &Predicate, writer: &mut ScenarioBinaryWriter) {
    match predicate {
        Predicate::At { at } => {
            writer.write_u8(6);
            writer.write_u64(at.ticks);
        }
        Predicate::After { duration, of } => {
            writer.write_u8(7);
            writer.write_u64(duration.nanos);
            writer.write_string(&of.name);
        }
        Predicate::Timer { name } => {
            writer.write_u8(8);
            writer.write_string(&name.name);
        }
        Predicate::NetworkMatch { link, predicate } => {
            writer.write_u8(9);
            match link {
                Some(link) => {
                    writer.write_u8(1);
                    writer.write_string(&link.name);
                }
                None => writer.write_u8(0),
            }
            write_frame_predicate_binary(predicate, writer);
        }
        Predicate::ConsoleMatch { node, regex } => {
            writer.write_u8(10);
            writer.write_string(&node.name);
            writer.write_string(&regex.pattern);
        }
        Predicate::CoveragePoint { node, point } => {
            writer.write_u8(13);
            writer.write_string(&node.name);
            write_code_point_binary(point, writer);
        }
        Predicate::MemoryPredicate {
            node,
            place,
            cmp,
            value,
        } => {
            writer.write_u8(14);
            writer.write_string(&node.name);
            write_mem_place_binary(place, writer);
            write_memory_cmp_binary(*cmp, writer);
            writer.write_u64(*value);
        }
        Predicate::IoPattern { node, kind } => {
            writer.write_u8(11);
            writer.write_string(&node.name);
            write_io_event_kind_binary(*kind, writer);
        }
        Predicate::NodeState { node, state } => {
            writer.write_u8(12);
            writer.write_string(&node.name);
            write_node_lifecycle_binary(*state, writer);
        }
        Predicate::AssertionState { name, state } => {
            writer.write_u8(15);
            writer.write_string(&name.name);
            write_assertion_phase_binary(*state, writer);
        }
        Predicate::Quiescent => {
            writer.write_u8(16);
        }
        Predicate::FaultActive { tag } => {
            writer.write_u8(17);
            writer.write_string(&tag.name);
        }
        Predicate::Named { name, nodes } => {
            writer.write_u8(0);
            writer.write_string(name);
            writer.write_count(nodes.len());
            for node in nodes {
                writer.write_string(&node.name);
            }
        }
        Predicate::GuestMarker { marker } => {
            writer.write_u8(1);
            writer.write_string(&marker.name);
        }
        Predicate::AllOf { predicates } => {
            writer.write_u8(2);
            writer.write_count(predicates.len());
            for predicate in predicates {
                write_predicate_binary(predicate, writer);
            }
        }
        Predicate::AnyOf { predicates } => {
            writer.write_u8(3);
            writer.write_count(predicates.len());
            for predicate in predicates {
                write_predicate_binary(predicate, writer);
            }
        }
        Predicate::Once { predicate } => {
            writer.write_u8(4);
            write_predicate_binary(predicate, writer);
        }
        Predicate::Not { predicate } => {
            writer.write_u8(5);
            write_predicate_binary(predicate, writer);
        }
    }
}

fn read_predicate_binary(reader: &mut ScenarioBinaryReader<'_>) -> Result<Predicate, EngineError> {
    match reader.read_u8()? {
        0 => {
            let name = reader.read_string()?;
            let count = reader.read_collection_count("predicate.node")?;
            let mut nodes = Vec::with_capacity(count);
            for _ in 0..count {
                nodes.push(NodeId {
                    name: reader.read_string()?,
                });
            }
            Ok(Predicate::Named { name, nodes })
        }
        1 => Ok(Predicate::GuestMarker {
            marker: MarkerId {
                name: reader.read_string()?,
            },
        }),
        2 => {
            let count = reader.read_collection_count("predicate.all_of")?;
            let mut predicates = Vec::with_capacity(count);
            for _ in 0..count {
                predicates.push(read_predicate_binary(reader)?);
            }
            Ok(Predicate::AllOf { predicates })
        }
        3 => {
            let count = reader.read_collection_count("predicate.any_of")?;
            let mut predicates = Vec::with_capacity(count);
            for _ in 0..count {
                predicates.push(read_predicate_binary(reader)?);
            }
            Ok(Predicate::AnyOf { predicates })
        }
        4 => Ok(Predicate::Once {
            predicate: Box::new(read_predicate_binary(reader)?),
        }),
        5 => Ok(Predicate::Not {
            predicate: Box::new(read_predicate_binary(reader)?),
        }),
        6 => Ok(Predicate::At {
            at: VirtualTime {
                ticks: reader.read_u64()?,
            },
        }),
        7 => Ok(Predicate::After {
            duration: SimDuration {
                nanos: reader.read_u64()?,
            },
            of: EventId {
                name: reader.read_string()?,
            },
        }),
        8 => Ok(Predicate::Timer {
            name: TimerId {
                name: reader.read_string()?,
            },
        }),
        9 => {
            let link = match reader.read_u8()? {
                0 => None,
                1 => Some(LinkId {
                    name: reader.read_string()?,
                }),
                _ => {
                    return Err(scenario_serialization_error(
                        "invalid network-match link presence tag",
                    ));
                }
            };
            Ok(Predicate::NetworkMatch {
                link,
                predicate: read_frame_predicate_binary(reader)?,
            })
        }
        10 => Ok(Predicate::ConsoleMatch {
            node: NodeId {
                name: reader.read_string()?,
            },
            regex: RegexProgram {
                pattern: reader.read_string()?,
            },
        }),
        13 => Ok(Predicate::CoveragePoint {
            node: NodeId {
                name: reader.read_string()?,
            },
            point: read_code_point_binary(reader)?,
        }),
        14 => Ok(Predicate::MemoryPredicate {
            node: NodeId {
                name: reader.read_string()?,
            },
            place: read_mem_place_binary(reader)?,
            cmp: read_memory_cmp_binary(reader)?,
            value: reader.read_u64()?,
        }),
        11 => Ok(Predicate::IoPattern {
            node: NodeId {
                name: reader.read_string()?,
            },
            kind: read_io_event_kind_binary(reader)?,
        }),
        12 => Ok(Predicate::NodeState {
            node: NodeId {
                name: reader.read_string()?,
            },
            state: read_node_lifecycle_binary(reader)?,
        }),
        15 => Ok(Predicate::AssertionState {
            name: AssertionId {
                name: reader.read_string()?,
            },
            state: read_assertion_phase_binary(reader)?,
        }),
        16 => Ok(Predicate::Quiescent),
        17 => Ok(Predicate::FaultActive {
            tag: FaultTag {
                name: reader.read_string()?,
            },
        }),
        _ => Err(scenario_serialization_error("invalid predicate tag")),
    }
}

fn write_frame_predicate_binary(predicate: &FramePredicate, writer: &mut ScenarioBinaryWriter) {
    match predicate {
        FramePredicate::Any => writer.write_u8(0),
        FramePredicate::Exact(bytes) => {
            writer.write_u8(1);
            writer.write_binary_blob(bytes);
        }
        FramePredicate::Contains(bytes) => {
            writer.write_u8(2);
            writer.write_binary_blob(bytes);
        }
        FramePredicate::Prefix(bytes) => {
            writer.write_u8(3);
            writer.write_binary_blob(bytes);
        }
    }
}

fn read_frame_predicate_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<FramePredicate, EngineError> {
    match reader.read_u8()? {
        0 => Ok(FramePredicate::Any),
        1 => Ok(FramePredicate::Exact(
            reader.read_binary_blob("frame exact bytes")?.to_vec(),
        )),
        2 => Ok(FramePredicate::Contains(
            reader.read_binary_blob("frame contains bytes")?.to_vec(),
        )),
        3 => Ok(FramePredicate::Prefix(
            reader.read_binary_blob("frame prefix bytes")?.to_vec(),
        )),
        _ => Err(scenario_serialization_error("invalid frame predicate tag")),
    }
}

fn write_code_point_binary(point: &CodePoint, writer: &mut ScenarioBinaryWriter) {
    match point {
        CodePoint::GuestAddress { address } => {
            writer.write_u8(0);
            writer.write_u64(*address);
        }
        CodePoint::Symbol { name } => {
            writer.write_u8(1);
            writer.write_string(name);
        }
    }
}

fn read_code_point_binary(reader: &mut ScenarioBinaryReader<'_>) -> Result<CodePoint, EngineError> {
    match reader.read_u8()? {
        0 => Ok(CodePoint::GuestAddress {
            address: reader.read_u64()?,
        }),
        1 => Ok(CodePoint::Symbol {
            name: reader.read_string()?,
        }),
        _ => Err(scenario_serialization_error("invalid code point tag")),
    }
}

fn write_mem_place_binary(place: &MemPlace, writer: &mut ScenarioBinaryWriter) {
    match place {
        MemPlace::PhysicalAddress { address, width } => {
            writer.write_u8(0);
            writer.write_u64(*address);
            write_memory_width_binary(*width, writer);
        }
        MemPlace::VirtualAddress { address, width } => {
            writer.write_u8(1);
            writer.write_u64(*address);
            write_memory_width_binary(*width, writer);
        }
        MemPlace::Symbol { name, width } => {
            writer.write_u8(2);
            writer.write_string(name);
            write_memory_width_binary(*width, writer);
        }
        MemPlace::Register { name, width } => {
            writer.write_u8(3);
            writer.write_string(name);
            write_memory_width_binary(*width, writer);
        }
    }
}

fn read_mem_place_binary(reader: &mut ScenarioBinaryReader<'_>) -> Result<MemPlace, EngineError> {
    match reader.read_u8()? {
        0 => Ok(MemPlace::PhysicalAddress {
            address: reader.read_u64()?,
            width: read_memory_width_binary(reader)?,
        }),
        1 => Ok(MemPlace::VirtualAddress {
            address: reader.read_u64()?,
            width: read_memory_width_binary(reader)?,
        }),
        2 => Ok(MemPlace::Symbol {
            name: reader.read_string()?,
            width: read_memory_width_binary(reader)?,
        }),
        3 => Ok(MemPlace::Register {
            name: reader.read_string()?,
            width: read_memory_width_binary(reader)?,
        }),
        _ => Err(scenario_serialization_error("invalid memory place tag")),
    }
}

fn write_memory_width_binary(width: MemoryWidth, writer: &mut ScenarioBinaryWriter) {
    writer.write_u8(match width {
        MemoryWidth::U8 => 0,
        MemoryWidth::U16 => 1,
        MemoryWidth::U32 => 2,
        MemoryWidth::U64 => 3,
    });
}

fn read_memory_width_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<MemoryWidth, EngineError> {
    match reader.read_u8()? {
        0 => Ok(MemoryWidth::U8),
        1 => Ok(MemoryWidth::U16),
        2 => Ok(MemoryWidth::U32),
        3 => Ok(MemoryWidth::U64),
        _ => Err(scenario_serialization_error("invalid memory width tag")),
    }
}

fn write_memory_cmp_binary(cmp: MemoryCmp, writer: &mut ScenarioBinaryWriter) {
    writer.write_u8(match cmp {
        MemoryCmp::Eq => 0,
        MemoryCmp::Ne => 1,
        MemoryCmp::Lt => 2,
        MemoryCmp::Le => 3,
        MemoryCmp::Gt => 4,
        MemoryCmp::Ge => 5,
    });
}

fn read_memory_cmp_binary(reader: &mut ScenarioBinaryReader<'_>) -> Result<MemoryCmp, EngineError> {
    match reader.read_u8()? {
        0 => Ok(MemoryCmp::Eq),
        1 => Ok(MemoryCmp::Ne),
        2 => Ok(MemoryCmp::Lt),
        3 => Ok(MemoryCmp::Le),
        4 => Ok(MemoryCmp::Gt),
        5 => Ok(MemoryCmp::Ge),
        _ => Err(scenario_serialization_error(
            "invalid memory comparison tag",
        )),
    }
}

fn write_io_event_kind_binary(kind: IoEventKind, writer: &mut ScenarioBinaryWriter) {
    writer.write_u8(match kind {
        IoEventKind::Any => 0,
        IoEventKind::BlockRead => 1,
        IoEventKind::BlockWrite => 2,
        IoEventKind::Fsync => 3,
        IoEventKind::NineP => 4,
        IoEventKind::Network => 5,
    });
}

fn read_io_event_kind_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<IoEventKind, EngineError> {
    match reader.read_u8()? {
        0 => Ok(IoEventKind::Any),
        1 => Ok(IoEventKind::BlockRead),
        2 => Ok(IoEventKind::BlockWrite),
        3 => Ok(IoEventKind::Fsync),
        4 => Ok(IoEventKind::NineP),
        5 => Ok(IoEventKind::Network),
        _ => Err(scenario_serialization_error("invalid I/O event kind tag")),
    }
}

fn write_node_lifecycle_binary(state: NodeLifecycle, writer: &mut ScenarioBinaryWriter) {
    writer.write_u8(match state {
        NodeLifecycle::Started => 0,
        NodeLifecycle::Crashed => 1,
        NodeLifecycle::Exited => 2,
        NodeLifecycle::Hung => 3,
    });
}

fn read_node_lifecycle_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<NodeLifecycle, EngineError> {
    match reader.read_u8()? {
        0 => Ok(NodeLifecycle::Started),
        1 => Ok(NodeLifecycle::Crashed),
        2 => Ok(NodeLifecycle::Exited),
        3 => Ok(NodeLifecycle::Hung),
        _ => Err(scenario_serialization_error("invalid node lifecycle tag")),
    }
}

fn write_assertion_phase_binary(state: AssertionPhase, writer: &mut ScenarioBinaryWriter) {
    writer.write_u8(match state {
        AssertionPhase::Satisfied => 0,
        AssertionPhase::Violated => 1,
    });
}

fn read_assertion_phase_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<AssertionPhase, EngineError> {
    match reader.read_u8()? {
        0 => Ok(AssertionPhase::Satisfied),
        1 => Ok(AssertionPhase::Violated),
        _ => Err(scenario_serialization_error("invalid assertion phase tag")),
    }
}

fn write_reachability_expectation_binary(
    expectation: ReachabilityExpectation,
    writer: &mut ScenarioBinaryWriter,
) {
    match expectation {
        ReachabilityExpectation::Reachable { on_unreached } => {
            writer.write_u8(0);
            writer.write_u8(match on_unreached {
                ReachableDisposition::Warn => 0,
                ReachableDisposition::Fail => 1,
            });
        }
        ReachabilityExpectation::Unreachable => writer.write_u8(1),
    }
}

fn read_reachability_expectation_binary(
    reader: &mut ScenarioBinaryReader<'_>,
) -> Result<ReachabilityExpectation, EngineError> {
    match reader.read_u8()? {
        0 => {
            let on_unreached = match reader.read_u8()? {
                0 => ReachableDisposition::Warn,
                1 => ReachableDisposition::Fail,
                _ => {
                    return Err(scenario_serialization_error(
                        "invalid reachable-disposition tag",
                    ));
                }
            };
            Ok(ReachabilityExpectation::Reachable { on_unreached })
        }
        1 => Ok(ReachabilityExpectation::Unreachable),
        _ => Err(scenario_serialization_error(
            "invalid reachability-expectation tag",
        )),
    }
}
