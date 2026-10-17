//! Admitted event references, dependency indexes and reachability validation.

use super::*;

pub(super) fn admit_error_names(names: &[&str]) -> Result<(), EventGraphError> {
    for name in names {
        crate::owned_decode::charge_array::<u8>(name.len())
            .map_err(EventGraphError::OriginalAdmission)?;
    }
    Ok(())
}

/// Event graph construction errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventGraphError {
    /// Original artifact resource authority refused an allocation.
    OriginalAdmission(crate::owned_decode::DecodeAdmissionError),
    /// Two events declared the same stable id.
    DuplicateEventId {
        /// Duplicated event id.
        event: EventId,
    },
    /// An entrypoint attempted to fire more than once.
    RepeatableEntrypoint {
        /// Invalid entrypoint event id.
        event: EventId,
    },
    /// An `After` predicate references no declared event.
    UnknownEventReference {
        /// Event containing the invalid reference.
        event: EventId,
        /// Referenced event id.
        reference: EventId,
    },
    /// A `Timer` predicate references no timer that can be armed.
    UnknownTimerReference {
        /// Event containing the invalid timer reference.
        event: EventId,
        /// Referenced timer id.
        timer: TimerId,
    },
    /// An `AssertionState` predicate references no declared assertion.
    UnknownAssertionReference {
        /// Event containing the invalid assertion reference.
        event: EventId,
        /// Referenced assertion id.
        assertion: AssertionId,
    },
    /// An `AllOf` or `AnyOf` predicate has no children.
    EmptyCompound {
        /// Event containing the empty compound.
        event: EventId,
        /// Stable compound predicate kind.
        kind: &'static str,
    },
    /// A `GuestMarker` trigger was used without any white-box-enabled node.
    GuestMarkerWithoutWhiteBoxOptIn {
        /// Event containing the guest-marker trigger.
        event: EventId,
        /// Referenced guest marker.
        marker: MarkerId,
    },
    /// A topology-bearing node reference was used without a world.
    NodeReferenceRequiresWorld {
        /// Event containing the invalid reference.
        event: EventId,
        /// Referenced node id.
        node: NodeId,
    },
    /// A topology-bearing link reference was used without a world.
    LinkReferenceRequiresWorld {
        /// Event containing the invalid reference.
        event: EventId,
        /// Referenced link id.
        link: LinkId,
    },
    /// A topology-bearing node reference names no world participant.
    UnknownNodeReference {
        /// Event containing the invalid reference.
        event: EventId,
        /// Referenced node id.
        node: NodeId,
    },
    /// A topology-bearing link reference names no world link.
    UnknownLinkReference {
        /// Event containing the invalid reference.
        event: EventId,
        /// Referenced link id.
        link: LinkId,
    },
    /// A topology-bearing device reference names no declared world device.
    UnknownDeviceReference {
        /// Event containing the invalid reference.
        event: EventId,
        /// Referenced device id.
        device: DeviceId,
    },
    /// A taxonomy fault targets a declared device from the wrong I/O family.
    DeviceKindMismatch {
        /// Event containing the invalid reference.
        event: EventId,
        /// Referenced device id.
        device: DeviceId,
        /// Device family required by the taxonomy fault.
        expected: WorldDeviceKind,
        /// Device family declared by the world.
        actual: WorldDeviceKind,
    },
    /// A `StartNode` or `StopNode` action was used without a world.
    NodeScheduleTargetRequiresWorld {
        /// Event containing the invalid action.
        event: EventId,
        /// Referenced node id.
        node: NodeId,
    },
    /// A `StartNode` or `StopNode` action references no world participant.
    UndeclaredNodeScheduleTarget {
        /// Event containing the invalid action.
        event: EventId,
        /// Referenced node id.
        node: NodeId,
    },
    /// A `StartNode` or `StopNode` action references no baked node.
    UnbakedNodeScheduleTarget {
        /// Event containing the invalid action.
        event: EventId,
        /// Referenced node id.
        node: NodeId,
    },
    /// Non-repeatable events contain a dependency cycle.
    NonRepeatableCycle {
        /// Participating event ids in deterministic DFS order.
        events: Vec<EventId>,
    },
    /// An event cannot be reached from any graph entrypoint.
    UnreachableEvent {
        /// Unreachable event id.
        event: EventId,
    },
    /// A console-match predicate contains an invalid regex program.
    InvalidRegex {
        /// Event containing the invalid regex.
        event: EventId,
        /// Regex pattern that failed validation.
        pattern: String,
        /// Stable validation failure text from the regex compiler.
        reason: String,
    },
}

impl fmt::Display for EventGraphError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OriginalAdmission(source) => {
                write!(formatter, "event graph resource admission: {source}")
            }
            Self::DuplicateEventId { event } => {
                write!(
                    formatter,
                    "event graph contains duplicate event `{}`",
                    event.name
                )
            }
            Self::RepeatableEntrypoint { event } => {
                write!(
                    formatter,
                    "event graph entrypoint `{}` cannot be repeatable",
                    event.name
                )
            }
            Self::UnknownEventReference { event, reference } => {
                write!(
                    formatter,
                    "event `{}` references unknown event `{}`",
                    event.name, reference.name
                )
            }
            Self::UnknownTimerReference { event, timer } => {
                write!(
                    formatter,
                    "event `{}` references unknown timer `{}`",
                    event.name, timer.name
                )
            }
            Self::UnknownAssertionReference { event, assertion } => {
                write!(
                    formatter,
                    "event `{}` references unknown assertion `{}`",
                    event.name, assertion.name
                )
            }
            Self::EmptyCompound { event, kind } => {
                write!(
                    formatter,
                    "event `{}` contains empty compound predicate `{kind}`",
                    event.name
                )
            }
            Self::GuestMarkerWithoutWhiteBoxOptIn { event, marker } => {
                write!(
                    formatter,
                    "event `{}` uses guest marker `{}` without a white-box-enabled node",
                    event.name, marker.name
                )
            }
            Self::NodeReferenceRequiresWorld { event, node } => {
                write!(
                    formatter,
                    "event `{}` references node `{}` without a world",
                    event.name, node.name
                )
            }
            Self::LinkReferenceRequiresWorld { event, link } => {
                write!(
                    formatter,
                    "event `{}` references link `{}` without a world",
                    event.name, link.name
                )
            }
            Self::UnknownNodeReference { event, node } => {
                write!(
                    formatter,
                    "event `{}` references unknown node `{}`",
                    event.name, node.name
                )
            }
            Self::UnknownLinkReference { event, link } => {
                write!(
                    formatter,
                    "event `{}` references unknown link `{}`",
                    event.name, link.name
                )
            }
            Self::UnknownDeviceReference { event, device } => {
                write!(
                    formatter,
                    "event `{}` references unknown device `{}`",
                    event.name, device.name
                )
            }
            Self::DeviceKindMismatch {
                event,
                device,
                expected,
                actual,
            } => {
                write!(
                    formatter,
                    "event `{}` uses {} device `{}` as a {} device",
                    event.name,
                    world_device_kind_name(*actual),
                    device.name,
                    world_device_kind_name(*expected)
                )
            }
            Self::NodeScheduleTargetRequiresWorld { event, node } => {
                write!(
                    formatter,
                    "event `{}` schedules node `{}` without a world",
                    event.name, node.name
                )
            }
            Self::UndeclaredNodeScheduleTarget { event, node } => {
                write!(
                    formatter,
                    "event `{}` schedules undeclared node `{}`",
                    event.name, node.name
                )
            }
            Self::UnbakedNodeScheduleTarget { event, node } => {
                write!(
                    formatter,
                    "event `{}` schedules unbaked node `{}`",
                    event.name, node.name
                )
            }
            Self::NonRepeatableCycle { events } => {
                formatter.write_str("event graph contains non-repeatable dependency cycle `")?;
                for (index, event) in events.iter().enumerate() {
                    if index != 0 {
                        formatter.write_str(" -> ")?;
                    }
                    formatter.write_str(&event.name)?;
                }
                formatter.write_str("`")
            }
            Self::UnreachableEvent { event } => {
                write!(formatter, "event `{}` is unreachable", event.name)
            }
            Self::InvalidRegex { event, reason, .. } => {
                write!(
                    formatter,
                    "event `{}` has invalid regex: {reason}",
                    event.name
                )
            }
        }
    }
}

impl Error for EventGraphError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::OriginalAdmission(source) => Some(source),
            _ => None,
        }
    }
}

pub(super) fn admit_tree<K, V>(name_bytes: usize) -> Result<(), EventGraphError> {
    crate::owned_decode::charge_btree_entry::<K, V>()
        .and_then(|()| crate::owned_decode::charge_array::<u8>(name_bytes))
        .map_err(EventGraphError::OriginalAdmission)
}

#[derive(Clone, Debug)]
pub(super) struct EventGraphTopology {
    nodes: BTreeSet<NodeId>,
    links: BTreeSet<LinkId>,
}

impl EventGraphTopology {
    pub(super) fn from_world(world: &World) -> Result<Self, EventGraphError> {
        let mut nodes = BTreeSet::new();
        for node in world.vm_nodes().iter() {
            admit_tree::<NodeId, ()>(node.id.name.len())?;
            nodes.insert(node.id.clone());
        }
        let mut links = BTreeSet::new();
        for link in world.links() {
            let (left, right) = link.endpoints();
            let length =
                "link_endpoint_a_len=\nlink_endpoint_a=\nlink_endpoint_b_len=\nlink_endpoint_b="
                    .len()
                    + decimal_length(left.name.len())
                    + left.name.len()
                    + decimal_length(right.name.len())
                    + right.name.len();
            admit_tree::<LinkId, ()>(length)?;
            let mut name = String::new();
            name.try_reserve_exact(length).map_err(|source| {
                EventGraphError::OriginalAdmission(crate::owned_decode::DecodeAdmissionError::new(
                    source,
                ))
            })?;
            fmt::Write::write_fmt(&mut name, format_args!(
                "link_endpoint_a_len={}\nlink_endpoint_a={}\nlink_endpoint_b_len={}\nlink_endpoint_b={}",
                left.name.len(), left.name, right.name.len(), right.name,
            )).map_err(|source| {
                EventGraphError::OriginalAdmission(crate::owned_decode::DecodeAdmissionError::new(source))
            })?;
            links.insert(LinkId::from_name(name));
        }
        Ok(Self { nodes, links })
    }
}

fn decimal_length(value: usize) -> usize {
    if value == 0 {
        1
    } else {
        value.ilog10() as usize + 1
    }
}

pub(super) fn world_device_kind_name(kind: WorldDeviceKind) -> &'static str {
    match kind {
        WorldDeviceKind::Block => "block",
        WorldDeviceKind::NineP => "9p",
    }
}

pub(super) fn armed_timer_names(events: &[Event]) -> Result<BTreeSet<TimerId>, EventGraphError> {
    let mut timers = BTreeSet::new();
    for event in events {
        collect_timer_names(&event.action, &mut timers)?;
    }
    Ok(timers)
}

pub(super) fn collect_timer_names(
    action: &Action,
    timers: &mut BTreeSet<TimerId>,
) -> Result<(), EventGraphError> {
    match action {
        Action::ArmTimer { name, .. } => {
            if !timers.contains(name) {
                admit_tree::<TimerId, ()>(name.name.len())?;
                timers.insert(name.clone());
            }
        }
        Action::Group(actions) => {
            for action in actions {
                collect_timer_names(action, timers)?;
            }
        }
        Action::CancelTimer { .. }
        | Action::StartNode { .. }
        | Action::StopNode { .. }
        | Action::CreateSavepoint { .. }
        | Action::Fork { .. }
        | Action::Pass
        | Action::Fail { .. }
        | Action::Log { .. } => {}
    }
    Ok(())
}

pub(super) fn validate_action_references(
    event: &Event,
    action: &Action,
    world: Option<&World>,
) -> Result<(), EventGraphError> {
    match action {
        Action::StartNode { node } | Action::StopNode { node } => {
            let Some(world) = world else {
                admit_error_names(&[&event.id.name, &node.name])?;
                return Err(EventGraphError::NodeScheduleTargetRequiresWorld {
                    event: event.id.clone(),
                    node: node.clone(),
                });
            };
            if !world.vm_nodes().iter().any(|declared| &declared.id == node) {
                admit_error_names(&[&event.id.name, &node.name])?;
                return Err(EventGraphError::UndeclaredNodeScheduleTarget {
                    event: event.id.clone(),
                    node: node.clone(),
                });
            }
            Ok(())
        }
        Action::Group(actions) => {
            for action in actions {
                validate_action_references(event, action, world)?;
            }
            Ok(())
        }
        Action::ArmTimer { .. }
        | Action::CancelTimer { .. }
        | Action::CreateSavepoint { .. }
        | Action::Fork { .. }
        | Action::Pass
        | Action::Fail { .. }
        | Action::Log { .. } => Ok(()),
    }
}

pub(super) fn validate_condition_references(
    event: &Event,
    condition: &Condition,
    event_ids: &BTreeSet<EventId>,
    timer_names: &BTreeSet<TimerId>,
    assertion_ids: &BTreeSet<AssertionId>,
    white_box_nodes: &BTreeSet<NodeId>,
    topology: Option<&EventGraphTopology>,
) -> Result<(), EventGraphError> {
    match condition {
        Condition::After { of, .. } => {
            if event_ids.contains(of) {
                Ok(())
            } else {
                admit_error_names(&[&event.id.name, &of.name])?;
                Err(EventGraphError::UnknownEventReference {
                    event: event.id.clone(),
                    reference: of.clone(),
                })
            }
        }
        Condition::Timer { name } => {
            if timer_names.contains(name) {
                Ok(())
            } else {
                admit_error_names(&[&event.id.name, &name.name])?;
                Err(EventGraphError::UnknownTimerReference {
                    event: event.id.clone(),
                    timer: name.clone(),
                })
            }
        }
        Condition::NetworkMatch { link, .. } => match link {
            Some(link) => validate_link_reference(event, link, topology),
            None => Ok(()),
        },
        Condition::ConsoleMatch { node, regex } => {
            validate_node_reference(event, node, topology)?;
            validate_condition_regex(event, regex)
        }
        Condition::CoveragePoint { node, .. }
        | Condition::MemoryPredicate { node, .. }
        | Condition::IoPattern { node, .. }
        | Condition::NodeState { node, .. } => validate_node_reference(event, node, topology),
        Condition::Named { nodes, .. } => {
            for node in nodes {
                validate_node_reference(event, node, topology)?;
            }
            Ok(())
        }
        Condition::AssertionState { name, .. } => {
            if assertion_ids.contains(name) {
                Ok(())
            } else {
                admit_error_names(&[&event.id.name, &name.name])?;
                Err(EventGraphError::UnknownAssertionReference {
                    event: event.id.clone(),
                    assertion: name.clone(),
                })
            }
        }
        Condition::GuestMarker { marker } => {
            if white_box_nodes.is_empty() {
                admit_error_names(&[&event.id.name, &marker.name])?;
                Err(EventGraphError::GuestMarkerWithoutWhiteBoxOptIn {
                    event: event.id.clone(),
                    marker: marker.clone(),
                })
            } else {
                Ok(())
            }
        }
        Condition::AllOf { predicates } => validate_compound_condition_references(
            event,
            "all-of",
            predicates,
            event_ids,
            timer_names,
            assertion_ids,
            white_box_nodes,
            topology,
        ),
        Condition::AnyOf { predicates } => validate_compound_condition_references(
            event,
            "any-of",
            predicates,
            event_ids,
            timer_names,
            assertion_ids,
            white_box_nodes,
            topology,
        ),
        Condition::Once { predicate } | Condition::Not { predicate } => {
            validate_condition_references(
                event,
                predicate,
                event_ids,
                timer_names,
                assertion_ids,
                white_box_nodes,
                topology,
            )
        }
        Condition::At { .. } | Condition::Quiescent => Ok(()),
    }
}

// crucible-lint: allow rust-allow -- condition validation receives the complete set of independently typed symbol tables.
#[allow(
    clippy::too_many_arguments,
    reason = "the condition validator receives the complete set of independently typed symbol tables"
)]
pub(super) fn validate_compound_condition_references(
    event: &Event,
    kind: &'static str,
    predicates: &[Condition],
    event_ids: &BTreeSet<EventId>,
    timer_names: &BTreeSet<TimerId>,
    assertion_ids: &BTreeSet<AssertionId>,
    white_box_nodes: &BTreeSet<NodeId>,
    topology: Option<&EventGraphTopology>,
) -> Result<(), EventGraphError> {
    if predicates.is_empty() {
        admit_error_names(&[&event.id.name])?;
        return Err(EventGraphError::EmptyCompound {
            event: event.id.clone(),
            kind,
        });
    }

    for predicate in predicates {
        validate_condition_references(
            event,
            predicate,
            event_ids,
            timer_names,
            assertion_ids,
            white_box_nodes,
            topology,
        )?;
    }

    Ok(())
}

pub(super) fn validate_node_reference(
    event: &Event,
    node: &NodeId,
    topology: Option<&EventGraphTopology>,
) -> Result<(), EventGraphError> {
    let Some(topology) = topology else {
        admit_error_names(&[&event.id.name, &node.name])?;
        return Err(EventGraphError::NodeReferenceRequiresWorld {
            event: event.id.clone(),
            node: node.clone(),
        });
    };
    if topology.nodes.contains(node) {
        Ok(())
    } else {
        admit_error_names(&[&event.id.name, &node.name])?;
        Err(EventGraphError::UnknownNodeReference {
            event: event.id.clone(),
            node: node.clone(),
        })
    }
}

pub(super) fn validate_link_reference(
    event: &Event,
    link: &LinkId,
    topology: Option<&EventGraphTopology>,
) -> Result<(), EventGraphError> {
    let Some(topology) = topology else {
        admit_error_names(&[&event.id.name, &link.name])?;
        return Err(EventGraphError::LinkReferenceRequiresWorld {
            event: event.id.clone(),
            link: link.clone(),
        });
    };
    if topology.links.contains(link) {
        Ok(())
    } else {
        admit_error_names(&[&event.id.name, &link.name])?;
        Err(EventGraphError::UnknownLinkReference {
            event: event.id.clone(),
            link: link.clone(),
        })
    }
}

pub(super) fn validate_condition_regex(
    event: &Event,
    regex: &RegexProgram,
) -> Result<(), EventGraphError> {
    match regex.compiled() {
        Ok(_) => Ok(()),
        Err(crate::predicate_regex::PredicateRegexError::Admission(source)) => {
            Err(EventGraphError::OriginalAdmission(source))
        }
        Err(source) => {
            let reason = crate::owned_decode::display_string(&source)
                .map_err(EventGraphError::OriginalAdmission)?;
            admit_error_names(&[&event.id.name, regex.pattern()])?;
            Err(EventGraphError::InvalidRegex {
                event: event.id.clone(),
                pattern: regex.pattern().to_owned(),
                reason,
            })
        }
    }
}

pub(super) fn validate_event_graph_dependencies(
    events: &[Event],
    timer_names: &BTreeSet<TimerId>,
) -> Result<(), EventGraphError> {
    let armers = timer_armers(events)?;
    validate_non_repeatable_cycles(events, &armers)?;
    validate_event_reachability(events, timer_names, &armers)
}

pub(super) fn timer_armers(
    events: &[Event],
) -> Result<BTreeMap<TimerId, BTreeSet<EventId>>, EventGraphError> {
    let mut armers = BTreeMap::new();
    for event in events {
        collect_timer_armers(&event.action, &event.id, &mut armers)?;
    }
    Ok(armers)
}

pub(super) fn collect_timer_armers(
    action: &Action,
    event: &EventId,
    armers: &mut BTreeMap<TimerId, BTreeSet<EventId>>,
) -> Result<(), EventGraphError> {
    match action {
        Action::ArmTimer { name, .. } => {
            if !armers.contains_key(name) {
                admit_tree::<TimerId, BTreeSet<EventId>>(name.name.len())?;
                armers.insert(name.clone(), BTreeSet::new());
            }
            if let Some(events) = armers.get_mut(name)
                && !events.contains(event)
            {
                admit_tree::<EventId, ()>(event.name.len())?;
                events.insert(event.clone());
            }
        }
        Action::Group(actions) => {
            for action in actions {
                collect_timer_armers(action, event, armers)?;
            }
        }
        Action::CancelTimer { .. }
        | Action::StartNode { .. }
        | Action::StopNode { .. }
        | Action::CreateSavepoint { .. }
        | Action::Fork { .. }
        | Action::Pass
        | Action::Fail { .. }
        | Action::Log { .. } => {}
    }
    Ok(())
}

pub(super) fn validate_non_repeatable_cycles(
    events: &[Event],
    armers: &BTreeMap<TimerId, BTreeSet<EventId>>,
) -> Result<(), EventGraphError> {
    let mut policies = BTreeMap::new();
    for event in events {
        admit_tree::<&EventId, FirePolicy>(0)?;
        policies.insert(&event.id, event.policy);
    }
    let mut graph = BTreeMap::<EventId, BTreeSet<EventId>>::new();
    for event in events {
        if event.policy == FirePolicy::Repeatable {
            continue;
        }
        let mut dependencies = event
            .trigger
            .as_ref()
            .map(|condition| hard_event_dependencies(condition, armers))
            .transpose()?
            .unwrap_or_default();
        dependencies.retain(|dependency| policies.get(dependency) != Some(&FirePolicy::Repeatable));
        admit_tree::<EventId, BTreeSet<EventId>>(event.id.name.len())?;
        graph.insert(event.id.clone(), dependencies);
    }

    let mut marks = BTreeMap::<EventId, DfsMark>::new();
    crate::owned_decode::charge_array::<EventId>(events.len())
        .map_err(EventGraphError::OriginalAdmission)?;
    let mut stack = Vec::new();
    stack.try_reserve_exact(events.len()).map_err(|source| {
        EventGraphError::OriginalAdmission(crate::owned_decode::DecodeAdmissionError::new(source))
    })?;
    for event in events {
        if event.policy != FirePolicy::Repeatable {
            visit_non_repeatable_event(&event.id, &graph, &mut marks, &mut stack)?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DfsMark {
    Gray,
    Black,
}

pub(super) fn visit_non_repeatable_event(
    event: &EventId,
    graph: &BTreeMap<EventId, BTreeSet<EventId>>,
    marks: &mut BTreeMap<EventId, DfsMark>,
    stack: &mut Vec<EventId>,
) -> Result<(), EventGraphError> {
    match marks.get(event) {
        Some(DfsMark::Black) => return Ok(()),
        Some(DfsMark::Gray) => {
            let start = stack
                .iter()
                .position(|stacked| stacked == event)
                .unwrap_or(0);
            crate::owned_decode::charge_array::<EventId>(stack.len() - start + 1)
                .map_err(EventGraphError::OriginalAdmission)?;
            for id in stack[start..].iter().chain(std::iter::once(event)) {
                crate::owned_decode::charge_array::<u8>(id.name.len())
                    .map_err(EventGraphError::OriginalAdmission)?;
            }
            let mut cycle = Vec::new();
            cycle
                .try_reserve_exact(stack.len() - start + 1)
                .map_err(|source| {
                    EventGraphError::OriginalAdmission(
                        crate::owned_decode::DecodeAdmissionError::new(source),
                    )
                })?;
            cycle.extend(stack[start..].iter().cloned());
            cycle.push(event.clone());
            return Err(EventGraphError::NonRepeatableCycle { events: cycle });
        }
        None => {}
    }

    admit_tree::<EventId, DfsMark>(event.name.len())?;
    marks.insert(event.clone(), DfsMark::Gray);
    crate::owned_decode::charge_array::<u8>(event.name.len())
        .map_err(EventGraphError::OriginalAdmission)?;
    stack.push(event.clone());
    if let Some(dependencies) = graph.get(event) {
        for dependency in dependencies {
            if graph.contains_key(dependency) {
                visit_non_repeatable_event(dependency, graph, marks, stack)?;
            }
        }
    }
    stack.pop();
    if let Some(mark) = marks.get_mut(event) {
        *mark = DfsMark::Black;
    }
    Ok(())
}

pub(super) fn hard_event_dependencies(
    condition: &Condition,
    armers: &BTreeMap<TimerId, BTreeSet<EventId>>,
) -> Result<BTreeSet<EventId>, EventGraphError> {
    let mut dependencies = BTreeSet::new();
    match condition {
        Condition::After { of, .. } => {
            insert_dependency(&mut dependencies, of)?;
        }
        Condition::Timer { name } => {
            if let Some(events) = armers.get(name).filter(|events| events.len() == 1) {
                for event in events {
                    insert_dependency(&mut dependencies, event)?;
                }
            }
        }
        Condition::AllOf { predicates } => {
            for predicate in predicates {
                for event in hard_event_dependencies(predicate, armers)? {
                    if !dependencies.contains(&event) {
                        admit_tree::<EventId, ()>(0)?;
                        dependencies.insert(event);
                    }
                }
            }
        }
        Condition::AnyOf { predicates } => {
            let mut predicates = predicates.iter();
            if let Some(first) = predicates.next() {
                dependencies = hard_event_dependencies(first, armers)?;
                for predicate in predicates {
                    let other = hard_event_dependencies(predicate, armers)?;
                    dependencies.retain(|event| other.contains(event));
                }
            }
        }
        Condition::Once { predicate } => return hard_event_dependencies(predicate, armers),
        Condition::Not { .. }
        | Condition::At { .. }
        | Condition::NetworkMatch { .. }
        | Condition::ConsoleMatch { .. }
        | Condition::CoveragePoint { .. }
        | Condition::MemoryPredicate { .. }
        | Condition::IoPattern { .. }
        | Condition::NodeState { .. }
        | Condition::AssertionState { .. }
        | Condition::Quiescent
        | Condition::Named { .. }
        | Condition::GuestMarker { .. } => {}
    }
    Ok(dependencies)
}

fn insert_dependency(set: &mut BTreeSet<EventId>, event: &EventId) -> Result<(), EventGraphError> {
    if !set.contains(event) {
        admit_tree::<EventId, ()>(event.name.len())?;
        set.insert(event.clone());
    }
    Ok(())
}

pub(super) fn validate_event_reachability(
    events: &[Event],
    timer_names: &BTreeSet<TimerId>,
    armers: &BTreeMap<TimerId, BTreeSet<EventId>>,
) -> Result<(), EventGraphError> {
    let mut reachable = BTreeSet::<&EventId>::new();
    loop {
        let mut changed = false;
        for event in events {
            if reachable.contains(&event.id) {
                continue;
            }
            if event.trigger.as_ref().is_none_or(|condition| {
                dependencies_are_reachable(condition, timer_names, armers, &reachable)
            }) {
                admit_tree::<&EventId, ()>(0)?;
                reachable.insert(&event.id);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    for event in events {
        if !reachable.contains(&event.id) {
            admit_error_names(&[&event.id.name])?;
            return Err(EventGraphError::UnreachableEvent {
                event: event.id.clone(),
            });
        }
    }
    Ok(())
}

// This is the same monotone reachability predicate as the former disjunctive
// dependency expansion. Evaluating the authored tree directly avoids building
// its potentially exponential Cartesian product of dependency alternatives.
fn dependencies_are_reachable(
    condition: &Condition,
    timer_names: &BTreeSet<TimerId>,
    armers: &BTreeMap<TimerId, BTreeSet<EventId>>,
    reachable: &BTreeSet<&EventId>,
) -> bool {
    match condition {
        Condition::After { of, .. } => reachable.contains(of),
        Condition::Timer { name } => {
            timer_names.contains(name)
                && armers
                    .get(name)
                    .is_some_and(|events| events.iter().any(|event| reachable.contains(event)))
        }
        Condition::AllOf { predicates } => predicates
            .iter()
            .all(|condition| dependencies_are_reachable(condition, timer_names, armers, reachable)),
        Condition::AnyOf { predicates } => predicates
            .iter()
            .any(|condition| dependencies_are_reachable(condition, timer_names, armers, reachable)),
        Condition::Once { predicate } => {
            dependencies_are_reachable(predicate, timer_names, armers, reachable)
        }
        Condition::Not { .. }
        | Condition::At { .. }
        | Condition::NetworkMatch { .. }
        | Condition::ConsoleMatch { .. }
        | Condition::CoveragePoint { .. }
        | Condition::MemoryPredicate { .. }
        | Condition::IoPattern { .. }
        | Condition::NodeState { .. }
        | Condition::AssertionState { .. }
        | Condition::Quiescent
        | Condition::Named { .. }
        | Condition::GuestMarker { .. } => true,
    }
}

#[cfg(test)]
#[path = "admission_tests.rs"]
mod admission_tests;
