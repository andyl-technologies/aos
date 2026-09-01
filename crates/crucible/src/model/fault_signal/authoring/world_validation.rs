//! World, telemetry, target, and authored-row validation.

use super::*;

pub(super) fn validate_world_signal_references(
    nodes: &[SignalNode],
    world: &World,
) -> Result<(), FaultSignalAuthoringError> {
    for node in nodes {
        match &node.kind {
            SignalNodeKind::Source(SignalSourceSpecification::Telemetry {
                adapter,
                target,
                field,
                ..
            }) => validate_telemetry_reference(adapter, target, field, world)?,
            SignalNodeKind::Source(source) => {
                for coordinate in source_coordinates(source) {
                    validate_coordinate_reference(coordinate, world)?;
                }
            }
            SignalNodeKind::Pure(PureSignalSpecification::SampleHold { epoch, .. }) => {
                validate_coordinate_reference(epoch, world)?;
            }
            SignalNodeKind::Constant { .. }
            | SignalNodeKind::Pure(_)
            | SignalNodeKind::Stateful { .. } => {}
        }
    }
    Ok(())
}

pub(super) fn source_coordinates(source: &SignalSourceSpecification) -> Vec<&SignalCoordinate> {
    match source {
        SignalSourceSpecification::Step { points, .. } => {
            points.iter().map(|point| &point.coordinate).collect()
        }
        SignalSourceSpecification::Pulse { start, .. } => vec![start],
        SignalSourceSpecification::PeriodicPulse { epoch, .. }
        | SignalSourceSpecification::Triangle { epoch, .. }
        | SignalSourceSpecification::Sawtooth { epoch, .. } => vec![epoch],
        SignalSourceSpecification::Ramp { start, end, .. } => vec![start, end],
        SignalSourceSpecification::EventSequence { events } => {
            events.iter().map(|event| &event.coordinate).collect()
        }
        _ => Vec::new(),
    }
}

pub(super) fn validate_coordinate_reference(
    coordinate: &SignalCoordinate,
    world: &World,
) -> Result<(), FaultSignalAuthoringError> {
    match coordinate {
        SignalCoordinate::NodeCounter { node, .. } => {
            if world
                .vm_nodes()
                .iter()
                .any(|candidate| candidate.id.name == node.as_str())
            {
                Ok(())
            } else {
                Err(FaultSignalAuthoringError::UnknownWorldTarget {
                    kind: String::from("node_counter"),
                    id: node.to_string(),
                })
            }
        }
        SignalCoordinate::Operation {
            adapter, target, ..
        }
        | SignalCoordinate::State {
            adapter, target, ..
        } => validate_adapter_target(adapter, target, world),
        SignalCoordinate::Event { parent, .. } => validate_coordinate_reference(parent, world),
        SignalCoordinate::VirtualTime { .. } | SignalCoordinate::Spatial { .. } => Ok(()),
    }
}

pub(super) fn validate_telemetry_reference(
    adapter: &SignalId,
    target: &SignalId,
    field: &SignalId,
    world: &World,
) -> Result<(), FaultSignalAuthoringError> {
    validate_adapter_target(adapter, target, world)?;
    let allowed = match adapter.as_str() {
        "network" => &[
            "availability",
            "latency-nanos",
            "queue-depth",
            "rate-bps",
            "loss-millionths",
            "signal-strength-mdbm",
            "sinr-mdb",
            "serving-attachment",
        ][..],
        "storage" => &[
            "availability",
            "queue-depth",
            "latency-nanos",
            "bytes-per-second",
            "iops",
            "wear-cycles",
            "media-errors",
            "cache-bytes",
        ][..],
        "node" => &[
            "lifecycle-state",
            "vcpu-service-millionths",
            "memory-errors",
            "clock-offset-nanos",
            "temperature-millicelsius",
        ][..],
        _ => {
            return Err(FaultSignalAuthoringError::UnsupportedAdapter(
                adapter.to_string(),
            ));
        }
    };
    if allowed.contains(&field.as_str()) {
        Ok(())
    } else {
        Err(FaultSignalAuthoringError::UnknownTelemetryField {
            adapter: adapter.to_string(),
            field: field.to_string(),
        })
    }
}

pub(super) fn validate_adapter_target(
    adapter: &SignalId,
    target: &SignalId,
    world: &World,
) -> Result<(), FaultSignalAuthoringError> {
    let found = match adapter.as_str() {
        "node" => world
            .vm_nodes()
            .iter()
            .any(|node| node.id.name == target.as_str()),
        "storage" => world.io_nodes().any(|node| node.id.name == target.as_str()),
        "network" => world.links().iter().any(|link| {
            link.fault_segment_id()
                .is_ok_and(|id| id.as_str() == target.as_str())
        }),
        _ => {
            return Err(FaultSignalAuthoringError::UnsupportedAdapter(
                adapter.to_string(),
            ));
        }
    };
    if found {
        Ok(())
    } else {
        Err(FaultSignalAuthoringError::UnknownWorldTarget {
            kind: adapter.to_string(),
            id: target.to_string(),
        })
    }
}

pub(super) fn validate_authoring_row_bounds(
    signals: &[toml::Value],
    bindings: &[toml::Value],
    limits: FaultResourceLimits,
) -> Result<(), FaultSignalAuthoringError> {
    limits
        .validate()
        .map_err(FaultSignalAuthoringError::ResourceLimit)?;
    let signal_limit = usize::try_from(limits.signal_nodes)
        .unwrap_or(usize::MAX)
        .min(HARD_SIGNAL_NODE_LIMIT as usize);
    if signals.len() > signal_limit {
        return Err(FaultSignalAuthoringError::CollectionLimit {
            field: "signal",
            actual: signals.len(),
            limit: signal_limit,
        });
    }
    let binding_limit = usize::try_from(limits.bindings)
        .unwrap_or(usize::MAX)
        .min(HARD_FAULT_BINDING_LIMIT);
    if bindings.len() > binding_limit {
        return Err(FaultSignalAuthoringError::CollectionLimit {
            field: "fault_binding",
            actual: bindings.len(),
            limit: binding_limit,
        });
    }
    for signal in signals {
        let row = signal
            .as_table()
            .ok_or(FaultSignalAuthoringError::ExpectedTable("signal"))?;
        check_array_bound(
            row,
            "inputs",
            usize::try_from(limits.signal_inputs_per_node)
                .unwrap_or(usize::MAX)
                .min(usize::from(HARD_SIGNAL_INPUTS_PER_NODE_LIMIT)),
        )?;
        for field in ["points", "events", "entries", "transitions", "states"] {
            check_array_bound(
                row,
                field,
                usize::try_from(limits.lookup_points_per_node)
                    .unwrap_or(usize::MAX)
                    .min(HARD_SIGNAL_LOOKUP_POINTS_PER_NODE_LIMIT as usize),
            )?;
        }
    }
    for binding in bindings {
        let row = binding
            .as_table()
            .ok_or(FaultSignalAuthoringError::ExpectedTable("fault binding"))?;
        check_array_bound(
            row,
            "signals",
            usize::try_from(limits.signals_per_binding)
                .unwrap_or(usize::MAX)
                .min(HARD_BINDING_SIGNAL_INPUT_LIMIT),
        )?;
        for table_field in [
            "selector",
            "mapping",
            "search_policy",
            "transition_declaration",
        ] {
            if let Some(table) = row.get(table_field).and_then(toml::Value::as_table) {
                for field in [
                    "targets",
                    "resolved_targets",
                    "initial_targets",
                    "points",
                    "candidates",
                    "point_indices",
                    "transition",
                ] {
                    let limit = if matches!(field, "candidates" | "point_indices") {
                        usize::try_from(limits.search_candidates_per_choice)
                            .unwrap_or(usize::MAX)
                            .min(HARD_SEARCH_CANDIDATE_LIMIT)
                    } else {
                        usize::try_from(limits.resolved_targets_per_binding)
                            .unwrap_or(usize::MAX)
                            .min(HARD_BINDING_TARGET_LIMIT)
                    };
                    check_array_bound(table, field, limit)?;
                }
            }
        }
    }
    Ok(())
}

pub(super) fn check_array_bound(
    table: &toml::map::Map<String, toml::Value>,
    field: &'static str,
    limit: usize,
) -> Result<(), FaultSignalAuthoringError> {
    if let Some(values) = table.get(field).and_then(toml::Value::as_array)
        && values.len() > limit
    {
        return Err(FaultSignalAuthoringError::CollectionLimit {
            field,
            actual: values.len(),
            limit,
        });
    }
    Ok(())
}

pub(super) fn declared_signal_shapes(
    rows: &[toml::Value],
) -> Result<BTreeMap<SignalId, SignalShape>, FaultSignalAuthoringError> {
    let mut shapes = BTreeMap::new();
    for row in rows {
        let row = row
            .as_table()
            .ok_or(FaultSignalAuthoringError::ExpectedTable("signal"))?;
        let id: SignalId = row
            .get("id")
            .cloned()
            .ok_or(FaultSignalAuthoringError::MissingField("id"))
            .and_then(|value| from_toml_value(value).map_err(Into::into))?;
        let value_type = row
            .get("value_type")
            .and_then(toml::Value::as_str)
            .ok_or(FaultSignalAuthoringError::InvalidField("value_type"))
            .and_then(parse_value_type)?;
        let unit = row
            .get("unit")
            .cloned()
            .ok_or(FaultSignalAuthoringError::MissingField("unit"))
            .and_then(|value| from_toml_value(value).map_err(Into::into))?;
        let scale = match row.get("scale_decimal_exponent") {
            None => 0,
            Some(toml::Value::Integer(value)) => i8::try_from(*value)
                .map_err(|_| FaultSignalAuthoringError::InvalidField("scale_decimal_exponent"))?,
            Some(_) => {
                return Err(FaultSignalAuthoringError::InvalidField(
                    "scale_decimal_exponent",
                ));
            }
        };
        let shape = SignalShape::new(value_type, unit, scale)?;
        if shapes.insert(id.clone(), shape).is_some() {
            return Err(FaultSignalAuthoringError::DuplicateSignalId(id.to_string()));
        }
    }
    Ok(shapes)
}
