//! Strict, flat TOML authoring projection for signal programs and bindings.
//!
//! Persistence uses [`FaultSignalPlanWire`], which deliberately mirrors the
//! internal typed contracts. The user-facing scenario format is different: it
//! presents one flat `[[plan.signal]]` graph and flat mapping, selector, and
//! effect tables. This module is the only conversion boundary between those
//! representations. Every decoded row is rebuilt through the ordinary typed
//! constructors; no authored identity or cached validation result is trusted.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::model::{
    World, WorldFaultTargetRef, WorldIoNodeKind, WorldNetworkPathHop, format_content_hash_ref,
};

use super::*;

/// Canonical TOML projection of one complete fault-signal layer.
pub(crate) struct FaultSignalAuthoringRows {
    /// Exact signal semantic version.
    pub(crate) semantic_version: u16,
    /// One scenario-owned resource declaration for the flat signal graph.
    pub(crate) resource_limits: SignalResourceLimits,
    /// Flat signal rows in canonical graph order.
    pub(crate) signals: Vec<toml::Value>,
    /// Flat binding rows in canonical binding-ID order.
    pub(crate) bindings: Vec<toml::Value>,
}

impl FaultSignalAuthoringRows {
    /// Projects a validated plan into the strict public authoring grammar.
    ///
    /// # Errors
    ///
    /// Returns [`FaultSignalAuthoringError`] when an internal typed value cannot
    /// be represented, or when a plan contains multiple independently bounded
    /// programs. Public scenario TOML owns one flat graph; multi-program wire
    /// layouts remain valid only as an internal persistence representation.
    pub(crate) fn from_plan(plan: &FaultSignalPlan) -> Result<Self, FaultSignalAuthoringError> {
        let (nodes, exports, limits) = match plan.programs() {
            [] => (Vec::new(), BTreeSet::new(), SignalResourceLimits::default()),
            [program] => (
                program.nodes().to_vec(),
                program.exported_outputs().iter().cloned().collect(),
                program.limits(),
            ),
            programs => {
                return Err(FaultSignalAuthoringError::MultiplePrograms {
                    actual: programs.len(),
                });
            }
        };
        Ok(Self {
            semantic_version: FAULT_SIGNAL_PLAN_WIRE_VERSION,
            resource_limits: limits,
            signals: nodes
                .iter()
                .map(|node| signal_to_toml(node, exports.contains(&node.id)))
                .collect::<Result<Vec<_>, _>>()?,
            bindings: plan
                .bindings()
                .iter()
                .map(|binding| binding_to_toml(&FaultBindingWire::from_binding(binding)))
                .collect::<Result<Vec<_>, _>>()?,
        })
    }

    /// Parses and admits the strict public authoring grammar.
    ///
    /// # Errors
    ///
    /// Returns [`FaultSignalAuthoringError`] for an unsupported semantic
    /// version, malformed or unknown fields, invalid graph, invalid binding, or
    /// final plan admission failure.
    pub(crate) fn admit(self, world: &World) -> Result<FaultSignalPlan, FaultSignalAuthoringError> {
        if self.semantic_version != FAULT_SIGNAL_PLAN_WIRE_VERSION {
            return Err(FaultSignalAuthoringError::Version {
                expected: FAULT_SIGNAL_PLAN_WIRE_VERSION,
                actual: self.semantic_version,
            });
        }
        validate_authoring_row_bounds(&self.signals, &self.bindings, self.resource_limits)?;
        if self.signals.is_empty() {
            if self.bindings.is_empty() {
                if self.resource_limits != SignalResourceLimits::default() {
                    return Err(FaultSignalAuthoringError::NonCanonicalEmptyLimits);
                }
                return Ok(FaultSignalPlan::empty());
            }
            return Err(FaultSignalAuthoringError::BindingsWithoutSignals);
        }

        let declared_shapes = declared_signal_shapes(&self.signals)?;
        let parsed = self
            .signals
            .into_iter()
            .map(|row| signal_from_toml(row, &declared_shapes))
            .collect::<Result<Vec<_>, _>>()?;
        let (nodes, exports): (Vec<_>, Vec<_>) = parsed
            .into_iter()
            .map(|(node, exported)| {
                let export = exported.then(|| node.id.clone());
                (node, export)
            })
            .unzip();
        let exports = exports.into_iter().flatten().collect();
        validate_world_signal_references(&nodes, world)?;
        let program = SignalProgram::new(nodes, exports, self.resource_limits)
            .map_err(FaultSignalAuthoringError::Program)?;
        let bindings = self
            .bindings
            .into_iter()
            .map(|row| binding_from_toml(row, &program, world))
            .collect::<Result<Vec<_>, _>>()?;
        FaultSignalPlan::new(vec![program], bindings).map_err(FaultSignalAuthoringError::Plan)
    }
}

fn validate_world_signal_references(
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

fn source_coordinates(source: &SignalSourceSpecification) -> Vec<&SignalCoordinate> {
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

fn validate_coordinate_reference(
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

fn validate_telemetry_reference(
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

fn validate_adapter_target(
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

fn validate_authoring_row_bounds(
    signals: &[toml::Value],
    bindings: &[toml::Value],
    limits: SignalResourceLimits,
) -> Result<(), FaultSignalAuthoringError> {
    let signal_limit = usize::try_from(limits.nodes)
        .unwrap_or(usize::MAX)
        .min(HARD_SIGNAL_NODE_LIMIT as usize);
    if signals.len() > signal_limit {
        return Err(FaultSignalAuthoringError::CollectionLimit {
            field: "signal",
            actual: signals.len(),
            limit: signal_limit,
        });
    }
    if bindings.len() > HARD_FAULT_BINDING_LIMIT {
        return Err(FaultSignalAuthoringError::CollectionLimit {
            field: "fault_binding",
            actual: bindings.len(),
            limit: HARD_FAULT_BINDING_LIMIT,
        });
    }
    for signal in signals {
        let row = signal
            .as_table()
            .ok_or(FaultSignalAuthoringError::ExpectedTable("signal"))?;
        check_array_bound(
            row,
            "inputs",
            usize::from(limits.inputs_per_node).min(usize::from(HARD_SIGNAL_INPUTS_PER_NODE_LIMIT)),
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
        check_array_bound(row, "signals", HARD_BINDING_SIGNAL_INPUT_LIMIT)?;
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
                        HARD_SEARCH_CANDIDATE_LIMIT
                    } else {
                        HARD_BINDING_TARGET_LIMIT
                    };
                    check_array_bound(table, field, limit)?;
                }
            }
        }
    }
    Ok(())
}

fn check_array_bound(
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

fn declared_signal_shapes(
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

fn signal_to_toml(
    node: &SignalNode,
    exported: bool,
) -> Result<toml::Value, FaultSignalAuthoringError> {
    let mut row = toml::map::Map::new();
    insert(&mut row, "id", &node.id)?;
    insert(&mut row, "domain", &node.domain)?;
    row.insert(String::from("exported"), toml::Value::Boolean(exported));
    row.insert(
        String::from("value_type"),
        toml::Value::String(value_type_string(&node.output.value_type)),
    );
    insert(&mut row, "unit", &node.output.unit)?;
    row.insert(
        String::from("scale_decimal_exponent"),
        toml::Value::Integer(i64::from(node.output.scale_decimal_exponent)),
    );
    if !node.inputs.is_empty() {
        insert(&mut row, "inputs", &node.inputs)?;
    }

    match &node.kind {
        SignalNodeKind::Constant { value } => {
            row.insert(
                String::from("kind"),
                toml::Value::String(String::from("constant")),
            );
            row.insert(String::from("value"), authored_signal_value(value)?);
        }
        SignalNodeKind::Source(specification) => {
            merge_tagged(&mut row, to_toml_value(specification)?)?;
            flatten_source_fields(&mut row, specification, node.domain)?;
        }
        SignalNodeKind::Pure(specification) => {
            let (kind, parameters) = pure_parts(specification)?;
            row.insert(String::from("kind"), toml::Value::String(kind));
            merge_parameters(&mut row, parameters)?;
            flatten_pure_fields(&mut row, specification)?;
        }
        SignalNodeKind::Stateful {
            specification,
            state_bytes,
        } => {
            merge_tagged(&mut row, to_toml_value(specification)?)?;
            flatten_stateful_fields(&mut row, specification)?;
            row.insert(String::from("state_bytes"), authored_u64(*state_bytes));
        }
    }
    Ok(toml::Value::Table(row))
}

fn flatten_pure_fields(
    row: &mut toml::map::Map<String, toml::Value>,
    specification: &PureSignalSpecification,
) -> Result<(), FaultSignalAuthoringError> {
    match specification {
        PureSignalSpecification::Clamp {
            minimum, maximum, ..
        } => {
            replace_signal_value(row, "minimum", minimum)?;
            replace_signal_value(row, "maximum", maximum)?;
        }
        PureSignalSpecification::LookupStep {
            points,
            before,
            after,
        } => {
            row.insert(String::from("points"), authored_value_pairs(points)?);
            flatten_boundary(row, "before", before)?;
            flatten_boundary(row, "after", after)?;
        }
        PureSignalSpecification::PiecewiseLinear { points, .. } => {
            row.insert(String::from("points"), authored_value_pairs(points)?);
        }
        PureSignalSpecification::EnumMap { entries } => {
            row.insert(
                String::from("entries"),
                toml::Value::Array(
                    entries
                        .iter()
                        .map(|(variant, output)| {
                            let mut entry = toml::map::Map::new();
                            insert(&mut entry, "variant", variant)?;
                            entry.insert(String::from("output"), authored_signal_value(output)?);
                            Ok(toml::Value::Table(entry))
                        })
                        .collect::<Result<Vec<_>, FaultSignalAuthoringError>>()?,
                ),
            );
        }
        _ => {}
    }
    Ok(())
}

fn flatten_stateful_fields(
    row: &mut toml::map::Map<String, toml::Value>,
    specification: &StatefulSignalSpecification,
) -> Result<(), FaultSignalAuthoringError> {
    match specification {
        StatefulSignalSpecification::Hysteresis {
            set_when,
            clear_when,
            ..
        } => {
            replace_signal_value(row, "set_when", set_when)?;
            replace_signal_value(row, "clear_when", clear_when)?;
        }
        StatefulSignalSpecification::Debounce { initial, .. }
        | StatefulSignalSpecification::Integrator { initial, .. }
        | StatefulSignalSpecification::LeakyIntegrator { initial, .. } => {
            replace_signal_value(row, "initial", initial)?;
        }
        _ => {}
    }
    Ok(())
}

fn authored_value_pairs(
    points: &[(SignalValue, SignalValue)],
) -> Result<toml::Value, FaultSignalAuthoringError> {
    Ok(toml::Value::Array(
        points
            .iter()
            .map(|(input, output)| {
                let mut point = toml::map::Map::new();
                point.insert(String::from("input"), authored_signal_value(input)?);
                point.insert(String::from("output"), authored_signal_value(output)?);
                Ok(toml::Value::Table(point))
            })
            .collect::<Result<Vec<_>, FaultSignalAuthoringError>>()?,
    ))
}

fn expand_pure_fields(
    kind: &str,
    row: &mut toml::map::Map<String, toml::Value>,
    inputs: &[SignalId],
    shapes: &BTreeMap<SignalId, SignalShape>,
    output: &SignalShape,
) -> Result<(), FaultSignalAuthoringError> {
    let input_type = first_input_type(inputs, shapes)?;
    match kind {
        "clamp" => {
            expand_signal_value(row, "minimum", input_type)?;
            expand_signal_value(row, "maximum", input_type)?;
        }
        "lookup_step" | "piecewise_linear" => {
            expand_value_pairs(row, input_type, &output.value_type)?;
            if kind == "lookup_step" {
                expand_boundary(row, "before", &output.value_type)?;
                expand_boundary(row, "after", &output.value_type)?;
            }
        }
        "enum_map" => {
            let SignalValueType::Enum(schema) = input_type else {
                return Err(FaultSignalAuthoringError::InvalidField("inputs"));
            };
            let toml::Value::Array(entries) = take_value(row, "entries")? else {
                return Err(FaultSignalAuthoringError::InvalidField("entries"));
            };
            let entries = entries
                .into_iter()
                .map(|entry| {
                    let mut entry = table(entry, "enum map entry")?;
                    let variant: SignalId = take_typed(&mut entry, "variant")?;
                    let output = parse_authored_signal_value(
                        take_value(&mut entry, "output")?,
                        &output.value_type,
                    )?;
                    ensure_empty(&entry, "enum map entry")?;
                    Ok((variant, output))
                })
                .collect::<Result<Vec<_>, FaultSignalAuthoringError>>()?;
            let _ = schema;
            row.insert(String::from("entries"), to_toml_value(&entries)?);
        }
        _ => {}
    }
    Ok(())
}

fn expand_stateful_fields(
    kind: &str,
    row: &mut toml::map::Map<String, toml::Value>,
    inputs: &[SignalId],
    shapes: &BTreeMap<SignalId, SignalShape>,
    output: &SignalShape,
) -> Result<(), FaultSignalAuthoringError> {
    match kind {
        "hysteresis" => {
            let input_type = first_input_type(inputs, shapes)?;
            expand_signal_value(row, "set_when", input_type)?;
            expand_signal_value(row, "clear_when", input_type)?;
        }
        "debounce" | "integrator" | "leaky_integrator" => {
            expand_signal_value(row, "initial", &output.value_type)?;
        }
        _ => {}
    }
    Ok(())
}

fn first_input_type<'a>(
    inputs: &[SignalId],
    shapes: &'a BTreeMap<SignalId, SignalShape>,
) -> Result<&'a SignalValueType, FaultSignalAuthoringError> {
    let input = inputs
        .first()
        .ok_or(FaultSignalAuthoringError::MissingField("inputs"))?;
    shapes
        .get(input)
        .map(|shape| &shape.value_type)
        .ok_or_else(|| FaultSignalAuthoringError::UnknownSignal(input.to_string()))
}

fn expand_value_pairs(
    row: &mut toml::map::Map<String, toml::Value>,
    input_type: &SignalValueType,
    output_type: &SignalValueType,
) -> Result<(), FaultSignalAuthoringError> {
    let toml::Value::Array(points) = take_value(row, "points")? else {
        return Err(FaultSignalAuthoringError::InvalidField("points"));
    };
    let points = points
        .into_iter()
        .map(|point| {
            let mut point = table(point, "mapping point")?;
            let input = parse_authored_signal_value(take_value(&mut point, "input")?, input_type)?;
            let output =
                parse_authored_signal_value(take_value(&mut point, "output")?, output_type)?;
            ensure_empty(&point, "mapping point")?;
            Ok((input, output))
        })
        .collect::<Result<Vec<_>, FaultSignalAuthoringError>>()?;
    row.insert(String::from("points"), to_toml_value(&points)?);
    Ok(())
}

fn signal_from_toml(
    row: toml::Value,
    declared_shapes: &BTreeMap<SignalId, SignalShape>,
) -> Result<(SignalNode, bool), FaultSignalAuthoringError> {
    let mut row = table(row, "signal")?;
    let id = take_typed(&mut row, "id")?;
    let kind = take_string(&mut row, "kind")?;
    let domain = take_typed(&mut row, "domain")?;
    let exported = take_optional_typed(&mut row, "exported")?.unwrap_or(true);
    let value_type = parse_value_type(&take_string(&mut row, "value_type")?)?;
    let unit = take_typed(&mut row, "unit")?;
    let scale_decimal_exponent = match row.remove("scale_decimal_exponent") {
        Some(toml::Value::Integer(value)) => i8::try_from(value)
            .map_err(|_| FaultSignalAuthoringError::InvalidField("scale_decimal_exponent"))?,
        Some(_) => {
            return Err(FaultSignalAuthoringError::InvalidField(
                "scale_decimal_exponent",
            ));
        }
        None => 0,
    };
    let output = SignalShape::new(value_type, unit, scale_decimal_exponent)
        .map_err(FaultSignalAuthoringError::Program)?;
    let inputs: Vec<SignalId> = take_optional_typed(&mut row, "inputs")?.unwrap_or_default();
    let state_bytes = take_optional_typed::<u64>(&mut row, "state_bytes")?;

    let node_kind = if kind == "constant" {
        if state_bytes.is_some() {
            return Err(FaultSignalAuthoringError::UnexpectedField("state_bytes"));
        }
        let value = row
            .remove("value")
            .ok_or(FaultSignalAuthoringError::MissingField("value"))?;
        ensure_empty(&row, "signal")?;
        SignalNodeKind::Constant {
            value: parse_authored_signal_value(value, &output.value_type)?,
        }
    } else if parse_enum_string::<SignalSourceKind>(&kind).is_ok() {
        if state_bytes.is_some() {
            return Err(FaultSignalAuthoringError::UnexpectedField("state_bytes"));
        }
        expand_source_fields(&kind, &mut row, domain, &output.value_type)?;
        SignalNodeKind::Source(source_from_parts(&kind, row)?)
    } else if parse_enum_string::<StatefulSignalOperator>(&kind).is_ok() {
        let state_bytes =
            state_bytes.ok_or(FaultSignalAuthoringError::MissingField("state_bytes"))?;
        expand_stateful_fields(&kind, &mut row, &inputs, declared_shapes, &output)?;
        SignalNodeKind::Stateful {
            specification: tagged_from_parts(&kind, row)?,
            state_bytes,
        }
    } else if parse_enum_string::<PureSignalOperator>(&kind).is_ok() {
        if state_bytes.is_some() {
            return Err(FaultSignalAuthoringError::UnexpectedField("state_bytes"));
        }
        expand_pure_fields(&kind, &mut row, &inputs, declared_shapes, &output)?;
        SignalNodeKind::Pure(pure_from_parts(&kind, row)?)
    } else {
        return Err(FaultSignalAuthoringError::UnknownKind(kind));
    };
    Ok((
        SignalNode {
            id,
            domain,
            output,
            inputs,
            kind: node_kind,
        },
        exported,
    ))
}

fn flatten_source_fields(
    row: &mut toml::map::Map<String, toml::Value>,
    specification: &SignalSourceSpecification,
    domain: SignalDomain,
) -> Result<(), FaultSignalAuthoringError> {
    match specification {
        SignalSourceSpecification::Step { points, before } => {
            row.insert(
                String::from("points"),
                authored_points(points, domain, "value")?,
            );
            flatten_boundary(row, "before", before)?;
        }
        SignalSourceSpecification::Pulse {
            start,
            inactive,
            active,
            ..
        } => {
            replace_coordinate(row, "start", start, domain)?;
            replace_signal_value(row, "inactive", inactive)?;
            replace_signal_value(row, "active", active)?;
        }
        SignalSourceSpecification::PeriodicPulse {
            epoch,
            inactive,
            active,
            ..
        } => {
            replace_coordinate(row, "epoch", epoch, domain)?;
            replace_signal_value(row, "inactive", inactive)?;
            replace_signal_value(row, "active", active)?;
        }
        SignalSourceSpecification::Ramp {
            start,
            end,
            start_value,
            end_value,
            ..
        } => {
            replace_coordinate(row, "start", start, domain)?;
            replace_coordinate(row, "end", end, domain)?;
            replace_signal_value(row, "start_value", start_value)?;
            replace_signal_value(row, "end_value", end_value)?;
        }
        SignalSourceSpecification::Triangle {
            epoch,
            minimum,
            maximum,
            ..
        }
        | SignalSourceSpecification::Sawtooth {
            epoch,
            minimum,
            maximum,
            ..
        } => {
            replace_coordinate(row, "epoch", epoch, domain)?;
            replace_signal_value(row, "minimum", minimum)?;
            replace_signal_value(row, "maximum", maximum)?;
        }
        SignalSourceSpecification::EventSequence { events } => {
            row.insert(
                String::from("events"),
                authored_points(events, domain, "payload")?,
            );
        }
        SignalSourceSpecification::Trace {
            interpolation,
            before,
            after,
            time_mapping,
            ..
        } => {
            flatten_interpolation(row, *interpolation)?;
            flatten_boundary(row, "before", before)?;
            flatten_boundary(row, "after", after)?;
            if let Some(mapping) = time_mapping {
                row.insert(
                    String::from("time_mapping"),
                    authored_time_mapping(*mapping)?,
                );
            }
        }
        SignalSourceSpecification::PointSet {
            interpolation,
            outside,
            ..
        }
        | SignalSourceSpecification::RegularGrid {
            interpolation,
            outside,
            ..
        }
        | SignalSourceSpecification::TiledGrid {
            interpolation,
            outside,
            ..
        } => {
            flatten_interpolation(row, *interpolation)?;
            flatten_boundary(row, "outside", outside)?;
        }
        SignalSourceSpecification::PathProfile {
            interpolation,
            before,
            after,
            ..
        } => {
            flatten_interpolation(row, *interpolation)?;
            flatten_boundary(row, "before", before)?;
            flatten_boundary(row, "after", after)?;
        }
        _ => {}
    }
    rename_field(row, "origin_mm", "origin")?;
    rename_field(row, "cell_size_mm", "cell_size")?;
    rename_field(row, "tile_size_mm", "tile_size")?;
    rename_field(row, "quantization_mm", "quantization")?;
    rename_field(row, "correlation_mm", "correlation")?;
    Ok(())
}

fn expand_source_fields(
    kind: &str,
    row: &mut toml::map::Map<String, toml::Value>,
    domain: SignalDomain,
    value_type: &SignalValueType,
) -> Result<(), FaultSignalAuthoringError> {
    match kind {
        "step" => {
            expand_points(row, "points", domain, value_type, "value")?;
            row.entry(String::from("before"))
                .or_insert_with(|| toml::Value::String(String::from("error")));
            expand_boundary(row, "before", value_type)?;
        }
        "pulse" => {
            expand_coordinate(row, "start", domain)?;
            expand_signal_value(row, "inactive", value_type)?;
            expand_signal_value(row, "active", value_type)?;
        }
        "periodic_pulse" => {
            expand_coordinate(row, "epoch", domain)?;
            expand_signal_value(row, "inactive", value_type)?;
            expand_signal_value(row, "active", value_type)?;
        }
        "ramp" => {
            expand_coordinate(row, "start", domain)?;
            expand_coordinate(row, "end", domain)?;
            expand_signal_value(row, "start_value", value_type)?;
            expand_signal_value(row, "end_value", value_type)?;
        }
        "triangle" | "sawtooth" => {
            expand_coordinate(row, "epoch", domain)?;
            expand_signal_value(row, "minimum", value_type)?;
            expand_signal_value(row, "maximum", value_type)?;
        }
        "event_sequence" => expand_points(row, "events", domain, value_type, "payload")?,
        "trace" => {
            expand_interpolation(row)?;
            expand_boundary(row, "before", value_type)?;
            expand_boundary(row, "after", value_type)?;
            if let Some(mapping) = row.remove("time_mapping") {
                row.insert(
                    String::from("time_mapping"),
                    to_toml_value(&parse_time_mapping(mapping)?)?,
                );
            }
        }
        "point_set" | "regular_grid" | "tiled_grid" => {
            expand_interpolation(row)?;
            expand_boundary(row, "outside", value_type)?;
        }
        "path_profile" => {
            expand_interpolation(row)?;
            expand_boundary(row, "before", value_type)?;
            expand_boundary(row, "after", value_type)?;
        }
        _ => {}
    }
    rename_field(row, "origin", "origin_mm")?;
    rename_field(row, "cell_size", "cell_size_mm")?;
    rename_field(row, "tile_size", "tile_size_mm")?;
    rename_field(row, "quantization", "quantization_mm")?;
    rename_field(row, "correlation", "correlation_mm")?;
    Ok(())
}

fn flatten_interpolation(
    row: &mut toml::map::Map<String, toml::Value>,
    interpolation: SignalInterpolation,
) -> Result<(), FaultSignalAuthoringError> {
    let (kind, arithmetic) = match interpolation {
        SignalInterpolation::Exact => ("exact", None),
        SignalInterpolation::HoldPrevious => ("hold_previous", None),
        SignalInterpolation::Nearest => ("nearest", None),
        SignalInterpolation::Linear { rounding, overflow } => {
            ("linear", Some((rounding, overflow)))
        }
    };
    insert_string(row, "interpolation", kind);
    if let Some((rounding, overflow)) = arithmetic {
        insert(row, "rounding", &rounding)?;
        insert(row, "overflow", &overflow)?;
    }
    Ok(())
}

fn expand_interpolation(
    row: &mut toml::map::Map<String, toml::Value>,
) -> Result<(), FaultSignalAuthoringError> {
    let kind = take_string(row, "interpolation")?;
    let interpolation = match kind.as_str() {
        "exact" => SignalInterpolation::Exact,
        "hold_previous" => SignalInterpolation::HoldPrevious,
        "nearest" => SignalInterpolation::Nearest,
        "linear" => SignalInterpolation::Linear {
            rounding: take_typed(row, "rounding")?,
            overflow: take_typed(row, "overflow")?,
        },
        _ => return Err(FaultSignalAuthoringError::UnknownKind(kind)),
    };
    row.insert(
        String::from("interpolation"),
        to_toml_value(&interpolation)?,
    );
    Ok(())
}

fn flatten_boundary(
    row: &mut toml::map::Map<String, toml::Value>,
    field: &'static str,
    behavior: &SignalBoundaryBehavior,
) -> Result<(), FaultSignalAuthoringError> {
    let kind = match behavior {
        SignalBoundaryBehavior::Error => "error",
        SignalBoundaryBehavior::Hold => "hold",
        SignalBoundaryBehavior::Constant(value) => {
            row.insert(format!("{field}_value"), authored_signal_value(value)?);
            "constant"
        }
        SignalBoundaryBehavior::Repeat => "repeat",
        SignalBoundaryBehavior::Inactive => "inactive",
    };
    insert_string(row, field, kind);
    Ok(())
}

fn expand_boundary(
    row: &mut toml::map::Map<String, toml::Value>,
    field: &'static str,
    value_type: &SignalValueType,
) -> Result<(), FaultSignalAuthoringError> {
    let kind = take_string(row, field)?;
    let behavior = match kind.as_str() {
        "error" => SignalBoundaryBehavior::Error,
        "hold" => SignalBoundaryBehavior::Hold,
        "constant" => {
            let value_field = match field {
                "before" => "before_value",
                "after" => "after_value",
                "outside" => "outside_value",
                _ => return Err(FaultSignalAuthoringError::InvalidField(field)),
            };
            SignalBoundaryBehavior::Constant(parse_authored_signal_value(
                take_value(row, value_field)?,
                value_type,
            )?)
        }
        "repeat" => SignalBoundaryBehavior::Repeat,
        "inactive" => SignalBoundaryBehavior::Inactive,
        _ => return Err(FaultSignalAuthoringError::UnknownKind(kind)),
    };
    row.insert(String::from(field), to_toml_value(&behavior)?);
    Ok(())
}

fn authored_time_mapping(
    mapping: TraceTimeMapping,
) -> Result<toml::Value, FaultSignalAuthoringError> {
    let mut value = toml::map::Map::new();
    value.insert(
        String::from("source_epoch"),
        toml::Value::Integer(mapping.source_epoch),
    );
    value.insert(
        String::from("virtual_epoch_nanos"),
        authored_u64(mapping.virtual_epoch_nanos),
    );
    value.insert(
        String::from("numerator"),
        toml::Value::Integer(mapping.scale.numerator()),
    );
    value.insert(
        String::from("denominator"),
        authored_u64(mapping.scale.denominator()),
    );
    insert(&mut value, "rounding", &mapping.rounding)?;
    Ok(toml::Value::Table(value))
}

fn parse_time_mapping(value: toml::Value) -> Result<TraceTimeMapping, FaultSignalAuthoringError> {
    let mut value = table(value, "trace time mapping")?;
    let mapping = TraceTimeMapping {
        source_epoch: take_typed(&mut value, "source_epoch")?,
        virtual_epoch_nanos: take_typed(&mut value, "virtual_epoch_nanos")?,
        scale: ExactRatio::new(
            take_typed(&mut value, "numerator")?,
            take_typed(&mut value, "denominator")?,
        )?,
        rounding: take_typed(&mut value, "rounding")?,
    };
    ensure_empty(&value, "trace time mapping")?;
    Ok(mapping)
}

fn rename_field(
    row: &mut toml::map::Map<String, toml::Value>,
    from: &'static str,
    to: &'static str,
) -> Result<(), FaultSignalAuthoringError> {
    if let Some(value) = row.remove(from)
        && row.insert(String::from(to), value).is_some()
    {
        return Err(FaultSignalAuthoringError::DuplicateProjectedField(
            String::from(to),
        ));
    }
    Ok(())
}

fn replace_signal_value(
    row: &mut toml::map::Map<String, toml::Value>,
    field: &'static str,
    value: &SignalValue,
) -> Result<(), FaultSignalAuthoringError> {
    row.insert(String::from(field), authored_signal_value(value)?);
    Ok(())
}

fn expand_signal_value(
    row: &mut toml::map::Map<String, toml::Value>,
    field: &'static str,
    value_type: &SignalValueType,
) -> Result<(), FaultSignalAuthoringError> {
    let value = take_value(row, field)?;
    row.insert(
        String::from(field),
        to_toml_value(&parse_authored_signal_value(value, value_type)?)?,
    );
    Ok(())
}

fn replace_coordinate(
    row: &mut toml::map::Map<String, toml::Value>,
    field: &'static str,
    coordinate: &SignalCoordinate,
    domain: SignalDomain,
) -> Result<(), FaultSignalAuthoringError> {
    row.insert(
        String::from(field),
        authored_coordinate(coordinate, domain)?,
    );
    Ok(())
}

fn expand_coordinate(
    row: &mut toml::map::Map<String, toml::Value>,
    field: &'static str,
    domain: SignalDomain,
) -> Result<(), FaultSignalAuthoringError> {
    let coordinate = parse_authored_coordinate(take_value(row, field)?, domain)?;
    row.insert(String::from(field), to_toml_value(&coordinate)?);
    Ok(())
}

fn authored_points(
    points: &[SignalPoint],
    domain: SignalDomain,
    value_field: &'static str,
) -> Result<toml::Value, FaultSignalAuthoringError> {
    Ok(toml::Value::Array(
        points
            .iter()
            .map(|point| {
                let mut row = toml::map::Map::new();
                row.insert(
                    String::from("coordinate"),
                    authored_coordinate(&point.coordinate, domain)?,
                );
                row.insert(String::from("sequence"), authored_u64(point.sequence));
                row.insert(
                    String::from(value_field),
                    authored_signal_value(&point.value)?,
                );
                Ok(toml::Value::Table(row))
            })
            .collect::<Result<Vec<_>, FaultSignalAuthoringError>>()?,
    ))
}

fn expand_points(
    row: &mut toml::map::Map<String, toml::Value>,
    field: &'static str,
    domain: SignalDomain,
    value_type: &SignalValueType,
    value_field: &'static str,
) -> Result<(), FaultSignalAuthoringError> {
    let toml::Value::Array(points) = take_value(row, field)? else {
        return Err(FaultSignalAuthoringError::InvalidField(field));
    };
    let points = points
        .into_iter()
        .map(|point| {
            let mut point = table(point, "signal point")?;
            let coordinate =
                parse_authored_coordinate(take_value(&mut point, "coordinate")?, domain)?;
            let sequence: u64 = take_typed(&mut point, "sequence")?;
            let value =
                parse_authored_signal_value(take_value(&mut point, value_field)?, value_type)?;
            ensure_empty(&point, "signal point")?;
            to_toml_value(&SignalPoint {
                coordinate,
                sequence,
                value,
            })
            .map_err(Into::into)
        })
        .collect::<Result<Vec<_>, FaultSignalAuthoringError>>()?;
    row.insert(String::from(field), toml::Value::Array(points));
    Ok(())
}

fn authored_coordinate(
    coordinate: &SignalCoordinate,
    domain: SignalDomain,
) -> Result<toml::Value, FaultSignalAuthoringError> {
    let actual_domain = coordinate_domain(coordinate);
    if actual_domain != domain {
        return Err(FaultSignalAuthoringError::CoordinateDomainMismatch);
    }
    let mut tagged = table(flatten_tagged(to_toml_value(coordinate)?)?, "coordinate")?;
    tagged.remove("kind");
    Ok(toml::Value::Table(tagged))
}

fn parse_authored_coordinate(
    value: toml::Value,
    domain: SignalDomain,
) -> Result<SignalCoordinate, FaultSignalAuthoringError> {
    let parameters = table(value, "coordinate")?;
    let kind = enum_string(&domain)?;
    tagged_from_parts(&kind, parameters)
}

const fn coordinate_domain(coordinate: &SignalCoordinate) -> SignalDomain {
    match coordinate {
        SignalCoordinate::VirtualTime { .. } => SignalDomain::VirtualTime,
        SignalCoordinate::NodeCounter { .. } => SignalDomain::NodeCounter,
        SignalCoordinate::Operation { .. } => SignalDomain::Operation,
        SignalCoordinate::Spatial { .. } => SignalDomain::Spatial,
        SignalCoordinate::Event { .. } => SignalDomain::Event,
        SignalCoordinate::State { .. } => SignalDomain::State,
    }
}

fn pure_parts(
    specification: &PureSignalSpecification,
) -> Result<(String, toml::map::Map<String, toml::Value>), FaultSignalAuthoringError> {
    let mut tagged = table(to_toml_value(specification)?, "pure signal")?;
    let wrapper = take_string(&mut tagged, "kind")?;
    let mut parameters = take_optional_table(&mut tagged, "parameters")?.unwrap_or_default();
    ensure_empty(&tagged, "pure signal")?;
    let kind = match wrapper.as_str() {
        "simple" | "ratio_arithmetic" | "window" => {
            let operator: PureSignalOperator = take_typed(&mut parameters, "operator")?;
            enum_string(&operator)?
        }
        other => other.to_owned(),
    };
    Ok((kind, parameters))
}

fn pure_from_parts(
    kind: &str,
    mut parameters: toml::map::Map<String, toml::Value>,
) -> Result<PureSignalSpecification, FaultSignalAuthoringError> {
    let operator = parse_enum_string::<PureSignalOperator>(kind)?;
    let wrapper = match operator {
        PureSignalOperator::MultiplyRatio | PureSignalOperator::DivideRatio => "ratio_arithmetic",
        PureSignalOperator::WindowMin
        | PureSignalOperator::WindowMax
        | PureSignalOperator::WindowMean => "window",
        PureSignalOperator::Clamp => "clamp",
        PureSignalOperator::LookupStep => "lookup_step",
        PureSignalOperator::PiecewiseLinear => "piecewise_linear",
        PureSignalOperator::EnumMap => "enum_map",
        PureSignalOperator::UnitConvert => "unit_convert",
        PureSignalOperator::Delay => "delay",
        PureSignalOperator::SampleHold => "sample_hold",
        PureSignalOperator::Distance => "distance",
        PureSignalOperator::ZoneContains => "zone_contains",
        PureSignalOperator::FieldSample => "field_sample",
        PureSignalOperator::OrientationDelta => "orientation_delta",
        PureSignalOperator::MergeEvents => "merge_events",
        PureSignalOperator::GateEvents => "gate_events",
        _ => "simple",
    };
    if matches!(wrapper, "simple" | "ratio_arithmetic" | "window") {
        parameters.insert(String::from("operator"), to_toml_value(&operator)?);
    }
    if matches!(
        wrapper,
        "simple" | "ratio_arithmetic" | "clamp" | "piecewise_linear" | "unit_convert" | "window"
    ) && !parameters.contains_key("overflow")
    {
        parameters.insert(
            String::from("overflow"),
            to_toml_value(&SignalOverflow::Error)?,
        );
    }
    tagged_from_parts(wrapper, parameters)
}

fn source_from_parts(
    kind: &str,
    mut parameters: toml::map::Map<String, toml::Value>,
) -> Result<SignalSourceSpecification, FaultSignalAuthoringError> {
    match kind {
        "step" if !parameters.contains_key("before") => {
            parameters.insert(
                String::from("before"),
                to_toml_value(&SignalBoundaryBehavior::Error)?,
            );
        }
        "periodic_pulse" | "triangle" | "sawtooth" if !parameters.contains_key("phase") => {
            parameters.insert(String::from("phase"), toml::Value::Integer(0));
        }
        "telemetry" if !parameters.contains_key("boundary_delay") => {
            parameters.insert(String::from("boundary_delay"), toml::Value::Integer(1));
        }
        _ => {}
    }
    tagged_from_parts(kind, parameters)
}

fn authored_signal_value(value: &SignalValue) -> Result<toml::Value, FaultSignalAuthoringError> {
    Ok(match value {
        SignalValue::Bool(value) => toml::Value::Boolean(*value),
        SignalValue::I64(value) => toml::Value::Integer(*value),
        SignalValue::U64(value)
        | SignalValue::DurationNanos(value)
        | SignalValue::RatePerSecond(value) => authored_u64(*value),
        SignalValue::ProbabilityMillionths(value) => toml::Value::Integer(i64::from(*value)),
        SignalValue::Ratio(value) => to_toml_value(value)?,
        SignalValue::Enum { variant, .. } => to_toml_value(variant)?,
        SignalValue::Event { payload, .. } | SignalValue::Bytes(payload) => {
            toml::Value::String(hex_bytes(payload))
        }
        SignalValue::Vector2(values) | SignalValue::Vector3(values) => toml::Value::Array(
            values
                .iter()
                .map(authored_signal_value)
                .collect::<Result<Vec<_>, _>>()?,
        ),
    })
}

fn parse_authored_signal_value(
    value: toml::Value,
    value_type: &SignalValueType,
) -> Result<SignalValue, FaultSignalAuthoringError> {
    Ok(match value_type {
        SignalValueType::Bool => SignalValue::Bool(from_toml_value(value)?),
        SignalValueType::I64 => SignalValue::I64(from_toml_value(value)?),
        SignalValueType::U64 => SignalValue::U64(from_toml_value(value)?),
        SignalValueType::Ratio => SignalValue::Ratio(from_toml_value(value)?),
        SignalValueType::DurationNanos => SignalValue::DurationNanos(from_toml_value(value)?),
        SignalValueType::RatePerSecond => SignalValue::RatePerSecond(from_toml_value(value)?),
        SignalValueType::ProbabilityMillionths => {
            SignalValue::ProbabilityMillionths(from_toml_value(value)?)
        }
        SignalValueType::Enum(schema) => SignalValue::Enum {
            schema: schema.clone(),
            variant: from_toml_value(value)?,
        },
        SignalValueType::Event(schema) => SignalValue::Event {
            schema: schema.clone(),
            payload: parse_hex_value(value)?,
        },
        SignalValueType::Vector2(element) => SignalValue::Vector2(parse_vector(value, element, 2)?),
        SignalValueType::Vector3(element) => SignalValue::Vector3(parse_vector(value, element, 3)?),
        SignalValueType::Bytes => SignalValue::Bytes(parse_hex_value(value)?),
    })
}

fn parse_vector(
    value: toml::Value,
    element: &SignalValueType,
    expected: usize,
) -> Result<Vec<SignalValue>, FaultSignalAuthoringError> {
    let toml::Value::Array(values) = value else {
        return Err(FaultSignalAuthoringError::InvalidField("value"));
    };
    if values.len() != expected {
        return Err(FaultSignalAuthoringError::InvalidField("value"));
    }
    values
        .into_iter()
        .map(|value| parse_authored_signal_value(value, element))
        .collect()
}

fn binding_to_toml(wire: &FaultBindingWire) -> Result<toml::Value, FaultSignalAuthoringError> {
    let mut row = toml::map::Map::new();
    insert(&mut row, "id", &wire.id)?;
    insert(&mut row, "signals", &wire.signals)?;
    encode_sampling(&mut row, &wire.sampling)?;
    row.insert(String::from("mapping"), mapping_to_toml(&wire.mapping)?);
    row.insert(String::from("selector"), selector_to_toml(&wire.selector)?);
    insert(&mut row, "phases", &wire.phases)?;
    row.insert(String::from("effect"), effect_to_toml(&wire.effect)?);
    if let Some(filter) = &wire.opportunity_filter {
        row.insert(String::from("opportunity_filter"), to_toml_value(filter)?);
    }
    encode_search(&mut row, &wire.search)?;
    row.insert(
        String::from("observability"),
        to_toml_value(&wire.observability)?,
    );
    if let Some(declaration) = &wire.transition_declaration {
        row.insert(
            String::from("transition_declaration"),
            to_toml_value(declaration)?,
        );
    }
    if let Some(declaration) = &wire.service_declaration {
        row.insert(
            String::from("service_declaration"),
            to_toml_value(declaration)?,
        );
    }
    Ok(toml::Value::Table(row))
}

fn binding_from_toml(
    row: toml::Value,
    program: &SignalProgram,
    world: &World,
) -> Result<FaultBinding, FaultSignalAuthoringError> {
    let mut row = table(row, "fault binding")?;
    let id = take_typed(&mut row, "id")?;
    let signals = match (row.remove("signal"), row.remove("signals")) {
        (Some(_), Some(_)) => return Err(FaultSignalAuthoringError::ConflictingSignalFields),
        (Some(value), None) => vec![from_toml_value(value)?],
        (None, Some(value)) => from_toml_value(value)?,
        (None, None) => return Err(FaultSignalAuthoringError::MissingField("signals")),
    };
    let sampling = decode_sampling(&mut row)?;
    let mapping = decode_mapping(take_value(&mut row, "mapping")?, &signals, program)?;
    let selector = selector_from_toml(take_value(&mut row, "selector")?, world)?;
    let effect = effect_from_toml(take_value(&mut row, "effect")?, &mapping, &sampling)?;
    let phases = take_optional_typed(&mut row, "phases")?.unwrap_or_else(|| {
        effect
            .specification
            .kind()
            .descriptor()
            .phases
            .iter()
            .copied()
            .collect()
    });
    let opportunity_filter = take_optional_typed(&mut row, "opportunity_filter")?;
    let search = decode_search(&mut row)?;
    let observability = take_optional_typed(&mut row, "observability")?.unwrap_or_default();
    let transition_declaration = take_optional_typed(&mut row, "transition_declaration")?;
    let service_declaration = take_optional_typed(&mut row, "service_declaration")?;
    ensure_empty(&row, "fault binding")?;
    FaultBindingWire {
        id,
        program: program.id(),
        signals,
        sampling,
        mapping,
        selector,
        phases,
        effect,
        opportunity_filter,
        search,
        observability,
        transition_declaration,
        service_declaration,
    }
    .admit(program)
    .map_err(FaultSignalAuthoringError::Wire)
}

fn encode_sampling(
    row: &mut toml::map::Map<String, toml::Value>,
    sampling: &BindingSampling,
) -> Result<(), FaultSignalAuthoringError> {
    match sampling {
        BindingSampling::AtBoundary => insert_string(row, "sampling", "at_boundary"),
        BindingSampling::AtOpportunity => insert_string(row, "sampling", "at_opportunity"),
        BindingSampling::AtChange => insert_string(row, "sampling", "at_change"),
        BindingSampling::CadenceNanos(value) => {
            insert_string(row, "sampling", "cadence_nanos");
            row.insert(String::from("cadence_nanos"), to_toml_value(value)?);
        }
        BindingSampling::AtEvent(parent) => {
            insert_string(row, "sampling", "at_event");
            row.insert(
                String::from("event_parent"),
                flatten_tagged(to_toml_value(parent)?)?,
            );
        }
    }
    Ok(())
}

fn decode_sampling(
    row: &mut toml::map::Map<String, toml::Value>,
) -> Result<BindingSampling, FaultSignalAuthoringError> {
    let Some(value) = row.remove("sampling") else {
        return Ok(BindingSampling::AtBoundary);
    };
    let toml::Value::String(value) = value else {
        return Err(FaultSignalAuthoringError::InvalidField("sampling"));
    };
    match value.as_str() {
        "at_boundary" => Ok(BindingSampling::AtBoundary),
        "at_opportunity" => Ok(BindingSampling::AtOpportunity),
        "at_change" => Ok(BindingSampling::AtChange),
        "cadence_nanos" => Ok(BindingSampling::CadenceNanos(take_typed(
            row,
            "cadence_nanos",
        )?)),
        "at_event" => Ok(BindingSampling::AtEvent(tagged_from_flat(take_value(
            row,
            "event_parent",
        )?)?)),
        kind => Err(FaultSignalAuthoringError::UnknownKind(kind.to_owned())),
    }
}

fn encode_search(
    row: &mut toml::map::Map<String, toml::Value>,
    search: &BindingSearchPolicy,
) -> Result<(), FaultSignalAuthoringError> {
    let mut flattened = table(flatten_tagged(to_toml_value(search)?)?, "search")?;
    let kind = take_string(&mut flattened, "kind")?;
    if let BindingSearchPolicy::BranchParameter { candidates, .. } = search {
        flattened.insert(
            String::from("candidates"),
            toml::Value::Array(
                candidates
                    .iter()
                    .map(authored_signal_value)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        );
    }
    row.insert(String::from("search"), toml::Value::String(kind));
    if !flattened.is_empty() {
        row.insert(String::from("search_policy"), toml::Value::Table(flattened));
    }
    Ok(())
}

fn decode_search(
    row: &mut toml::map::Map<String, toml::Value>,
) -> Result<BindingSearchPolicy, FaultSignalAuthoringError> {
    let Some(value) = row.remove("search") else {
        return Ok(BindingSearchPolicy::Fixed);
    };
    let toml::Value::String(kind) = value else {
        return Err(FaultSignalAuthoringError::InvalidField("search"));
    };
    let mut parameters = take_optional_table(row, "search_policy")?.unwrap_or_default();
    if kind == "branch_parameter" {
        let parameter: MappedEffectParameter = parameters
            .get("parameter")
            .cloned()
            .ok_or(FaultSignalAuthoringError::MissingField("parameter"))
            .and_then(|value| from_toml_value(value).map_err(Into::into))?;
        let toml::Value::Array(candidates) = take_value(&mut parameters, "candidates")? else {
            return Err(FaultSignalAuthoringError::InvalidField("candidates"));
        };
        let value_type = mapped_parameter_value_type(parameter);
        let candidates = candidates
            .into_iter()
            .map(|candidate| parse_authored_signal_value(candidate, &value_type))
            .collect::<Result<Vec<_>, _>>()?;
        parameters.insert(String::from("candidates"), to_toml_value(&candidates)?);
    }
    tagged_from_parts(&kind, parameters)
}

fn mapping_to_toml(mapping: &BindingMapping) -> Result<toml::Value, FaultSignalAuthoringError> {
    let mut value = table(flatten_tagged(to_toml_value(mapping)?)?, "mapping")?;
    match mapping {
        BindingMapping::Threshold {
            threshold,
            clear_threshold,
            ..
        } => {
            replace_signal_value(&mut value, "threshold", threshold)?;
            if let Some(clear_threshold) = clear_threshold {
                replace_signal_value(&mut value, "clear_threshold", clear_threshold)?;
            }
        }
        BindingMapping::PiecewiseParameter { points, .. } => {
            value.insert(
                String::from("points"),
                toml::Value::Array(
                    points
                        .iter()
                        .map(|point| {
                            let mut value = toml::map::Map::new();
                            value.insert(
                                String::from("input"),
                                authored_signal_value(&point.input)?,
                            );
                            value.insert(
                                String::from("output"),
                                authored_signal_value(&point.output)?,
                            );
                            Ok(toml::Value::Table(value))
                        })
                        .collect::<Result<Vec<_>, FaultSignalAuthoringError>>()?,
                ),
            );
        }
        _ => {}
    }
    Ok(toml::Value::Table(value))
}

fn decode_mapping(
    value: toml::Value,
    signals: &[SignalId],
    program: &SignalProgram,
) -> Result<BindingMapping, FaultSignalAuthoringError> {
    let mut value = table(value, "mapping")?;
    let kind = take_string(&mut value, "kind")?;
    match kind.as_str() {
        "active_when_true" => {
            value
                .entry(String::from("invert"))
                .or_insert(toml::Value::Boolean(false));
        }
        "threshold" => {
            if let Some(residence) = value.remove("minimum_active_nanos") {
                if value
                    .insert(String::from("residence_nanos"), residence)
                    .is_some()
                {
                    return Err(FaultSignalAuthoringError::DuplicateProjectedField(
                        String::from("residence_nanos"),
                    ));
                }
            }
            value
                .entry(String::from("residence_nanos"))
                .or_insert(toml::Value::Integer(0));
            let input_type = binding_first_input_type(signals, program)?;
            expand_signal_value(&mut value, "threshold", input_type)?;
            if value.contains_key("clear_threshold") {
                expand_signal_value(&mut value, "clear_threshold", input_type)?;
            }
        }
        "piecewise_parameter" => {
            let parameter: MappedEffectParameter = value
                .get("parameter")
                .cloned()
                .ok_or(FaultSignalAuthoringError::MissingField("parameter"))
                .and_then(|value| from_toml_value(value).map_err(Into::into))?;
            let input_type = binding_first_input_type(signals, program)?;
            expand_binding_map_points(
                &mut value,
                input_type,
                &mapped_parameter_value_type(parameter),
            )?;
        }
        _ => {}
    }
    tagged_from_parts(&kind, value)
}

fn binding_first_input_type<'a>(
    signals: &[SignalId],
    program: &'a SignalProgram,
) -> Result<&'a SignalValueType, FaultSignalAuthoringError> {
    let signal = signals
        .first()
        .ok_or(FaultSignalAuthoringError::MissingField("signals"))?;
    program
        .exported_shape(signal)
        .map(|shape| &shape.value_type)
        .ok_or_else(|| FaultSignalAuthoringError::UnknownSignal(signal.to_string()))
}

fn mapped_parameter_value_type(parameter: MappedEffectParameter) -> SignalValueType {
    match parameter {
        MappedEffectParameter::Probability => SignalValueType::ProbabilityMillionths,
        MappedEffectParameter::DurationNanos => SignalValueType::DurationNanos,
        MappedEffectParameter::BitsPerSecond
        | MappedEffectParameter::BytesPerSecond
        | MappedEffectParameter::OperationsPerSecond
        | MappedEffectParameter::UnsignedCount => SignalValueType::U64,
        MappedEffectParameter::CapacityRatio => SignalValueType::Ratio,
        MappedEffectParameter::SignedOffset => SignalValueType::I64,
    }
}

fn expand_binding_map_points(
    value: &mut toml::map::Map<String, toml::Value>,
    input_type: &SignalValueType,
    output_type: &SignalValueType,
) -> Result<(), FaultSignalAuthoringError> {
    let toml::Value::Array(points) = take_value(value, "points")? else {
        return Err(FaultSignalAuthoringError::InvalidField("points"));
    };
    let points = points
        .into_iter()
        .map(|point| {
            let mut point = table(point, "binding map point")?;
            let input = parse_authored_signal_value(take_value(&mut point, "input")?, input_type)?;
            let output =
                parse_authored_signal_value(take_value(&mut point, "output")?, output_type)?;
            ensure_empty(&point, "binding map point")?;
            Ok(BindingMapPoint { input, output })
        })
        .collect::<Result<Vec<_>, FaultSignalAuthoringError>>()?;
    value.insert(String::from("points"), to_toml_value(&points)?);
    Ok(())
}

fn selector_to_toml(selector: &TargetSelector) -> Result<toml::Value, FaultSignalAuthoringError> {
    match selector {
        TargetSelector::Exact(targets) => {
            let [target] = targets.targets() else {
                return Err(FaultSignalAuthoringError::InvalidSelector);
            };
            let mut value = table(flatten_tagged(to_toml_value(target)?)?, "selector")?;
            if targets.allow_empty() {
                value.insert(String::from("allow_empty"), toml::Value::Boolean(true));
            }
            Ok(toml::Value::Table(value))
        }
        TargetSelector::TargetSet(targets) => {
            if let [
                ResolvedFaultTarget::NetworkSegment {
                    segment: first,
                    direction: FaultDirection::AToB,
                },
                ResolvedFaultTarget::NetworkSegment {
                    segment: second,
                    direction: FaultDirection::BToA,
                },
            ] = targets.targets()
                && first == second
            {
                let mut value = toml::map::Map::new();
                insert_string(&mut value, "kind", "network_segment");
                insert(&mut value, "segment", first)?;
                insert_string(&mut value, "direction", "both");
                if targets.allow_empty() {
                    value.insert(String::from("allow_empty"), toml::Value::Boolean(true));
                }
                return Ok(toml::Value::Table(value));
            }
            let values = targets
                .targets()
                .iter()
                .map(|target| flatten_tagged(to_toml_value(target)?))
                .collect::<Result<Vec<_>, FaultSignalAuthoringError>>()?;
            let mut value = toml::map::Map::new();
            insert_string(&mut value, "kind", "target_set");
            value.insert(String::from("targets"), toml::Value::Array(values));
            value.insert(
                String::from("allow_empty"),
                toml::Value::Boolean(targets.allow_empty()),
            );
            Ok(toml::Value::Table(value))
        }
        TargetSelector::FaultDomain { domain, .. } => {
            let mut value = toml::map::Map::new();
            insert_string(&mut value, "kind", "fault_domain");
            insert(&mut value, "domain", domain)?;
            Ok(toml::Value::Table(value))
        }
        TargetSelector::DynamicPath {
            path,
            membership_semantic_version,
            ..
        } => {
            let mut value = toml::map::Map::new();
            insert_string(&mut value, "kind", "dynamic_path");
            insert(&mut value, "path", path)?;
            value.insert(
                String::from("membership_semantic_version"),
                toml::Value::Integer(i64::from(*membership_semantic_version)),
            );
            Ok(toml::Value::Table(value))
        }
    }
}

fn selector_from_toml(
    value: toml::Value,
    world: &World,
) -> Result<TargetSelector, FaultSignalAuthoringError> {
    let mut value = table(value, "selector")?;
    let kind = take_string(&mut value, "kind")?;
    match kind.as_str() {
        "target_set" => {
            let targets = take_flat_targets(&mut value, "targets", world)?;
            let allow_empty = take_optional_typed(&mut value, "allow_empty")?.unwrap_or(false);
            ensure_empty(&value, "selector")?;
            Ok(TargetSelector::TargetSet(
                ResolvedTargetSet::new(targets, allow_empty)
                    .map_err(|_| FaultSignalAuthoringError::InvalidSelector)?,
            ))
        }
        "fault_domain" => {
            let domain: FaultObjectId = take_typed(&mut value, "domain")?;
            ensure_empty(&value, "selector")?;
            let declaration = world
                .fault_topology()
                .fault_domains
                .iter()
                .find(|candidate| candidate.id.as_str() == domain.as_str())
                .ok_or_else(|| FaultSignalAuthoringError::UnknownWorldTarget {
                    kind: String::from("fault_domain"),
                    id: domain.to_string(),
                })?;
            let targets = declaration
                .targets
                .iter()
                .map(|target| resolve_world_target_ref(target, world))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(TargetSelector::FaultDomain {
                domain,
                resolved: ResolvedTargetSet::new(targets, false)
                    .map_err(|_| FaultSignalAuthoringError::InvalidSelector)?,
            })
        }
        "dynamic_path" => {
            let path: FaultObjectId = take_typed(&mut value, "path")?;
            let membership_semantic_version =
                take_typed(&mut value, "membership_semantic_version")?;
            ensure_empty(&value, "selector")?;
            let declaration = world
                .fault_topology()
                .network_paths
                .iter()
                .find(|candidate| candidate.id.as_str() == path.as_str())
                .ok_or_else(|| FaultSignalAuthoringError::UnknownWorldTarget {
                    kind: String::from("dynamic_path"),
                    id: path.to_string(),
                })?;
            let targets = declaration
                .hops
                .iter()
                .map(|hop| match hop {
                    WorldNetworkPathHop::Segment { segment, direction } => {
                        Ok(ResolvedFaultTarget::NetworkSegment {
                            segment: fault_object_id(segment)?,
                            direction: *direction,
                        })
                    }
                    WorldNetworkPathHop::Forwarder { forwarder } => {
                        Ok(ResolvedFaultTarget::NetworkForwarder {
                            forwarder: fault_object_id(forwarder)?,
                        })
                    }
                })
                .collect::<Result<Vec<_>, FaultSignalAuthoringError>>()?;
            Ok(TargetSelector::DynamicPath {
                path,
                initial: ResolvedTargetSet::new(targets, false)
                    .map_err(|_| FaultSignalAuthoringError::InvalidSelector)?,
                membership_semantic_version,
            })
        }
        _ => {
            let allow_empty = take_optional_typed(&mut value, "allow_empty")?.unwrap_or(false);
            value.insert(String::from("kind"), toml::Value::String(kind));
            let targets = resolve_authored_target(toml::Value::Table(value), world)?;
            let resolved = ResolvedTargetSet::new(targets, allow_empty)
                .map_err(|_| FaultSignalAuthoringError::InvalidSelector)?;
            if resolved.targets().len() == 1 {
                Ok(TargetSelector::Exact(resolved))
            } else {
                Ok(TargetSelector::TargetSet(resolved))
            }
        }
    }
}

fn fault_object_id(id: &SignalId) -> Result<FaultObjectId, FaultSignalAuthoringError> {
    FaultObjectId::parse(id.as_str()).map_err(|_| FaultSignalAuthoringError::InvalidSelector)
}

fn resolve_world_target_ref(
    target: &WorldFaultTargetRef,
    world: &World,
) -> Result<ResolvedFaultTarget, FaultSignalAuthoringError> {
    let topology = world.fault_topology();
    Ok(match target {
        WorldFaultTargetRef::NetworkInterface { interface } => {
            let declaration = topology
                .network_interfaces
                .iter()
                .find(|candidate| &candidate.id == interface)
                .ok_or(FaultSignalAuthoringError::InvalidSelector)?;
            ResolvedFaultTarget::NetworkInterface {
                endpoint: fault_object_id(&declaration.endpoint)?,
                interface: fault_object_id(interface)?,
            }
        }
        WorldFaultTargetRef::NetworkSegment { segment, direction } => {
            ResolvedFaultTarget::NetworkSegment {
                segment: fault_object_id(segment)?,
                direction: *direction,
            }
        }
        WorldFaultTargetRef::NetworkMedium { medium } => {
            let declaration = topology
                .network_media
                .iter()
                .find(|candidate| &candidate.id == medium)
                .ok_or(FaultSignalAuthoringError::InvalidSelector)?;
            let resource = declaration
                .resources
                .first()
                .ok_or(FaultSignalAuthoringError::InvalidSelector)?;
            ResolvedFaultTarget::NetworkMedium {
                medium: fault_object_id(medium)?,
                resource: fault_object_id(resource)?,
            }
        }
        WorldFaultTargetRef::NetworkForwarder { forwarder } => {
            ResolvedFaultTarget::NetworkForwarder {
                forwarder: fault_object_id(forwarder)?,
            }
        }
        WorldFaultTargetRef::NetworkQueue { queue } => {
            let declaration = topology
                .network_queues
                .iter()
                .find(|candidate| &candidate.id == queue)
                .ok_or(FaultSignalAuthoringError::InvalidSelector)?;
            ResolvedFaultTarget::NetworkQueue {
                owner: fault_object_id(&declaration.owner)?,
                queue: fault_object_id(queue)?,
            }
        }
        WorldFaultTargetRef::NetworkPath { path } => ResolvedFaultTarget::NetworkPath {
            path_version: fault_object_id(path)?,
            direction: FaultDirection::AToB,
        },
        WorldFaultTargetRef::NetworkAttachment { attachment } => {
            let declaration = topology
                .network_attachments
                .iter()
                .find(|candidate| &candidate.id == attachment)
                .ok_or(FaultSignalAuthoringError::InvalidSelector)?;
            let interface = topology
                .network_interfaces
                .iter()
                .find(|candidate| candidate.id == declaration.interface)
                .ok_or(FaultSignalAuthoringError::InvalidSelector)?;
            ResolvedFaultTarget::NetworkAttachment {
                endpoint: fault_object_id(&interface.endpoint)?,
                interface: fault_object_id(&interface.id)?,
                attachment: fault_object_id(attachment)?,
            }
        }
        WorldFaultTargetRef::NetworkContact { plan, contact } => {
            let declaration = topology
                .network_contact_plans
                .iter()
                .find(|candidate| &candidate.id == plan)
                .ok_or(FaultSignalAuthoringError::InvalidSelector)?;
            ResolvedFaultTarget::NetworkContact {
                endpoint_a: fault_object_id(&declaration.endpoint_a)?,
                endpoint_b: fault_object_id(&declaration.endpoint_b)?,
                contact: fault_object_id(contact)?,
            }
        }
        WorldFaultTargetRef::BlockDevice { device } => {
            let node = world
                .io_nodes()
                .find(|node| node.id.name == device.as_str())
                .ok_or(FaultSignalAuthoringError::InvalidSelector)?;
            ResolvedFaultTarget::BlockDevice {
                device: node.fault_target_hash(),
            }
        }
        WorldFaultTargetRef::NinePDevice { device } => {
            let node = world
                .io_nodes()
                .find(|node| node.id.name == device.as_str())
                .ok_or(FaultSignalAuthoringError::InvalidSelector)?;
            ResolvedFaultTarget::NinePDevice {
                device: node.fault_target_hash(),
            }
        }
        WorldFaultTargetRef::Node { node } => ResolvedFaultTarget::Node {
            node: fault_object_id(node)?,
        },
    })
}

fn take_flat_targets(
    table: &mut toml::map::Map<String, toml::Value>,
    field: &'static str,
    world: &World,
) -> Result<Vec<ResolvedFaultTarget>, FaultSignalAuthoringError> {
    let value = take_value(table, field)?;
    let toml::Value::Array(values) = value else {
        return Err(FaultSignalAuthoringError::InvalidField(field));
    };
    values
        .into_iter()
        .map(|value| resolve_authored_target(value, world))
        .collect::<Result<Vec<_>, _>>()
        .map(|targets| targets.into_iter().flatten().collect())
}

fn resolve_authored_target(
    value: toml::Value,
    world: &World,
) -> Result<Vec<ResolvedFaultTarget>, FaultSignalAuthoringError> {
    let mut value = table(value, "selector target")?;
    let kind = take_string(&mut value, "kind")?;
    match kind.as_str() {
        "network_interface" => {
            let endpoint: FaultObjectId = take_typed(&mut value, "endpoint")?;
            let interface: FaultObjectId = take_typed(&mut value, "interface")?;
            ensure_empty(&value, "network interface selector")?;
            let exists = world
                .fault_topology()
                .network_interfaces
                .iter()
                .any(|candidate| {
                    candidate.id.as_str() == interface.as_str()
                        && candidate.endpoint.as_str() == endpoint.as_str()
                });
            if !exists {
                return Err(FaultSignalAuthoringError::UnknownWorldTarget {
                    kind,
                    id: interface.to_string(),
                });
            }
            Ok(vec![ResolvedFaultTarget::NetworkInterface {
                endpoint,
                interface,
            }])
        }
        "network_segment" => {
            let segment: FaultObjectId = take_typed(&mut value, "segment")?;
            let direction = take_string(&mut value, "direction")?;
            ensure_empty(&value, "network_segment selector")?;
            let exists = world
                .fault_topology()
                .network_segments
                .iter()
                .any(|candidate| candidate.id.as_str() == segment.as_str());
            if !exists {
                return Err(FaultSignalAuthoringError::UnknownWorldTarget {
                    kind,
                    id: segment.to_string(),
                });
            }
            let directions = match direction.as_str() {
                "a_to_b" => vec![FaultDirection::AToB],
                "b_to_a" => vec![FaultDirection::BToA],
                "both" => vec![FaultDirection::AToB, FaultDirection::BToA],
                _ => return Err(FaultSignalAuthoringError::UnknownKind(direction)),
            };
            Ok(directions
                .into_iter()
                .map(|direction| ResolvedFaultTarget::NetworkSegment {
                    segment: segment.clone(),
                    direction,
                })
                .collect())
        }
        "network_medium" => {
            let medium: FaultObjectId = take_typed(&mut value, "medium")?;
            let resource: FaultObjectId = take_typed(&mut value, "resource")?;
            ensure_empty(&value, "network medium selector")?;
            let exists = world
                .fault_topology()
                .network_media
                .iter()
                .any(|candidate| {
                    candidate.id.as_str() == medium.as_str()
                        && candidate
                            .resources
                            .iter()
                            .any(|item| item.as_str() == resource.as_str())
                });
            if !exists {
                return Err(FaultSignalAuthoringError::UnknownWorldTarget {
                    kind,
                    id: format!("{medium}:{resource}"),
                });
            }
            Ok(vec![ResolvedFaultTarget::NetworkMedium {
                medium,
                resource,
            }])
        }
        "network_queue" => {
            let owner: FaultObjectId = take_typed(&mut value, "owner")?;
            let queue: FaultObjectId = take_typed(&mut value, "queue")?;
            ensure_empty(&value, "network queue selector")?;
            let exists = world
                .fault_topology()
                .network_queues
                .iter()
                .any(|candidate| {
                    candidate.id.as_str() == queue.as_str()
                        && candidate.owner.as_str() == owner.as_str()
                });
            if !exists {
                return Err(FaultSignalAuthoringError::UnknownWorldTarget {
                    kind,
                    id: queue.to_string(),
                });
            }
            Ok(vec![ResolvedFaultTarget::NetworkQueue { owner, queue }])
        }
        "network_forwarder" => {
            let forwarder: FaultObjectId = take_typed(&mut value, "forwarder")?;
            ensure_empty(&value, "network forwarder selector")?;
            let exists = world
                .fault_topology()
                .network_forwarders
                .iter()
                .any(|candidate| candidate.id.as_str() == forwarder.as_str());
            if !exists {
                return Err(FaultSignalAuthoringError::UnknownWorldTarget {
                    kind,
                    id: forwarder.to_string(),
                });
            }
            Ok(vec![ResolvedFaultTarget::NetworkForwarder { forwarder }])
        }
        "network_path" => {
            let path_version: FaultObjectId = take_typed(&mut value, "path_version")?;
            let direction: FaultDirection = take_typed(&mut value, "direction")?;
            ensure_empty(&value, "network path selector")?;
            let exists = world
                .fault_topology()
                .network_paths
                .iter()
                .any(|candidate| candidate.id.as_str() == path_version.as_str());
            if !exists {
                return Err(FaultSignalAuthoringError::UnknownWorldTarget {
                    kind,
                    id: path_version.to_string(),
                });
            }
            Ok(vec![ResolvedFaultTarget::NetworkPath {
                path_version,
                direction,
            }])
        }
        "network_attachment" => {
            let endpoint: FaultObjectId = take_typed(&mut value, "endpoint")?;
            let interface: FaultObjectId = take_typed(&mut value, "interface")?;
            let attachment: FaultObjectId = take_typed(&mut value, "attachment")?;
            ensure_empty(&value, "network attachment selector")?;
            let topology = world.fault_topology();
            let exists = topology.network_attachments.iter().any(|candidate| {
                candidate.id.as_str() == attachment.as_str()
                    && candidate.interface.as_str() == interface.as_str()
            }) && topology.network_interfaces.iter().any(|candidate| {
                candidate.id.as_str() == interface.as_str()
                    && candidate.endpoint.as_str() == endpoint.as_str()
            });
            if !exists {
                return Err(FaultSignalAuthoringError::UnknownWorldTarget {
                    kind,
                    id: attachment.to_string(),
                });
            }
            Ok(vec![ResolvedFaultTarget::NetworkAttachment {
                endpoint,
                interface,
                attachment,
            }])
        }
        "network_contact" => {
            let endpoint_a: FaultObjectId = take_typed(&mut value, "endpoint_a")?;
            let endpoint_b: FaultObjectId = take_typed(&mut value, "endpoint_b")?;
            let contact: FaultObjectId = take_typed(&mut value, "contact")?;
            ensure_empty(&value, "network contact selector")?;
            let exists = world
                .fault_topology()
                .network_contact_plans
                .iter()
                .any(|plan| {
                    plan.endpoint_a.as_str() == endpoint_a.as_str()
                        && plan.endpoint_b.as_str() == endpoint_b.as_str()
                        && plan
                            .contacts
                            .iter()
                            .any(|candidate| candidate.id.as_str() == contact.as_str())
                });
            if !exists {
                return Err(FaultSignalAuthoringError::UnknownWorldTarget {
                    kind,
                    id: contact.to_string(),
                });
            }
            Ok(vec![ResolvedFaultTarget::NetworkContact {
                endpoint_a,
                endpoint_b,
                contact,
            }])
        }
        "block_device" | "nine_p_device" => {
            let device = take_string(&mut value, "device")?;
            ensure_empty(&value, "storage device selector")?;
            let matched = world.io_nodes().find(|node| {
                let kind_matches = matches!(
                    (&node.kind, kind.as_str()),
                    (WorldIoNodeKind::Block { .. }, "block_device")
                        | (WorldIoNodeKind::NineP { .. }, "nine_p_device")
                );
                kind_matches
                    && (node.id.name == device
                        || format_content_hash_ref(node.fault_target_hash()) == device)
            });
            let node = matched.ok_or_else(|| FaultSignalAuthoringError::UnknownWorldTarget {
                kind: kind.clone(),
                id: device,
            })?;
            let target = if kind == "block_device" {
                ResolvedFaultTarget::BlockDevice {
                    device: node.fault_target_hash(),
                }
            } else {
                ResolvedFaultTarget::NinePDevice {
                    device: node.fault_target_hash(),
                }
            };
            Ok(vec![target])
        }
        "node" => {
            let node: FaultObjectId = take_typed(&mut value, "node")?;
            ensure_empty(&value, "node selector")?;
            if !world
                .vm_nodes()
                .iter()
                .any(|candidate| candidate.id.name == node.as_str())
            {
                return Err(FaultSignalAuthoringError::UnknownWorldTarget {
                    kind,
                    id: node.to_string(),
                });
            }
            Ok(vec![ResolvedFaultTarget::Node { node }])
        }
        "vcpu" => {
            let node: FaultObjectId = take_typed(&mut value, "node")?;
            let vcpu = take_typed(&mut value, "vcpu")?;
            ensure_empty(&value, "vcpu selector")?;
            let valid = world.vm_nodes().iter().any(|candidate| {
                candidate.id.name == node.as_str() && u32::from(candidate.smp_vcpus) > vcpu
            });
            if !valid {
                return Err(FaultSignalAuthoringError::UnknownWorldTarget {
                    kind,
                    id: format!("{}:{vcpu}", node.as_str()),
                });
            }
            Ok(vec![ResolvedFaultTarget::Vcpu { node, vcpu }])
        }
        _ => Err(FaultSignalAuthoringError::UnknownKind(kind)),
    }
}

fn effect_to_toml(effect: &EffectRequestWire) -> Result<toml::Value, FaultSignalAuthoringError> {
    let specification = table(
        to_toml_value(&effect.specification)?,
        "effect specification",
    )?;
    let mut specification = specification;
    let adapter = take_string(&mut specification, "adapter")?;
    let parameters = take_value(&mut specification, "parameters")?;
    ensure_empty(&specification, "effect specification")?;
    let mut parameters = table(flatten_tagged(parameters)?, "effect parameters")?;
    let effect_kind = take_string(&mut parameters, "kind")?;
    let mut result = toml::map::Map::new();
    result.insert(
        String::from("kind"),
        toml::Value::String(format!("{adapter}.{effect_kind}")),
    );
    result.insert(
        String::from("semantic_version"),
        toml::Value::Integer(i64::from(effect.semantic_version)),
    );
    insert(&mut result, "lifetime", &effect.lifetime)?;
    merge_parameters(&mut result, parameters)?;
    Ok(toml::Value::Table(result))
}

fn effect_from_toml(
    value: toml::Value,
    mapping: &BindingMapping,
    sampling: &BindingSampling,
) -> Result<EffectRequestWire, FaultSignalAuthoringError> {
    let mut value = table(value, "effect")?;
    let kind = take_string(&mut value, "kind")?;
    let (adapter, effect_kind) = kind
        .split_once('.')
        .ok_or_else(|| FaultSignalAuthoringError::UnknownKind(kind.clone()))?;
    if adapter.is_empty() || effect_kind.is_empty() || effect_kind.contains('.') {
        return Err(FaultSignalAuthoringError::UnknownKind(kind));
    }
    let semantic_version = take_typed(&mut value, "semantic_version")?;
    let authored_lifetime = take_optional_typed(&mut value, "lifetime")?;
    let specification: EffectSpecification = from_toml_value(toml::Value::Table(
        [
            (
                String::from("adapter"),
                toml::Value::String(adapter.to_owned()),
            ),
            (String::from("parameters"), tagged_value(effect_kind, value)),
        ]
        .into_iter()
        .collect(),
    ))?;
    let lifetime = authored_lifetime
        .unwrap_or_else(|| default_effect_lifetime(mapping, sampling, specification.kind()));
    Ok(EffectRequestWire {
        semantic_version,
        lifetime,
        specification,
    })
}

fn default_effect_lifetime(
    mapping: &BindingMapping,
    sampling: &BindingSampling,
    kind: EffectKind,
) -> EffectLifetime {
    let preferred = match mapping {
        BindingMapping::Hazard => EffectLifetime::Opportunity,
        BindingMapping::ImpulseOnEvent => EffectLifetime::Impulse,
        BindingMapping::StateTransition { .. } => EffectLifetime::StateMachine,
        BindingMapping::MapParameter { .. } | BindingMapping::PiecewiseParameter { .. }
            if matches!(
                sampling,
                BindingSampling::AtOpportunity | BindingSampling::AtEvent(_)
            ) =>
        {
            EffectLifetime::Opportunity
        }
        _ => EffectLifetime::Persistent,
    };
    if kind.descriptor().lifetimes.contains(&preferred) {
        preferred
    } else {
        kind.descriptor().lifetimes[0]
    }
}

fn merge_tagged(
    destination: &mut toml::map::Map<String, toml::Value>,
    tagged: toml::Value,
) -> Result<(), FaultSignalAuthoringError> {
    let flattened = table(flatten_tagged(tagged)?, "tagged value")?;
    merge_parameters(destination, flattened)
}

fn flatten_tagged(value: toml::Value) -> Result<toml::Value, FaultSignalAuthoringError> {
    let mut tagged = table(value, "tagged value")?;
    let kind = take_string(&mut tagged, "kind")?;
    let parameters = take_optional_table(&mut tagged, "parameters")?.unwrap_or_default();
    ensure_empty(&tagged, "tagged value")?;
    let mut result = toml::map::Map::new();
    result.insert(String::from("kind"), toml::Value::String(kind));
    merge_parameters(&mut result, parameters)?;
    Ok(toml::Value::Table(result))
}

fn tagged_from_flat<T: DeserializeOwned>(
    value: toml::Value,
) -> Result<T, FaultSignalAuthoringError> {
    let mut value = table(value, "tagged value")?;
    let kind = take_string(&mut value, "kind")?;
    tagged_from_parts(&kind, value)
}

fn tagged_from_parts<T: DeserializeOwned>(
    kind: &str,
    parameters: toml::map::Map<String, toml::Value>,
) -> Result<T, FaultSignalAuthoringError> {
    from_toml_value(tagged_value(kind, parameters)).map_err(Into::into)
}

fn tagged_value(kind: &str, parameters: toml::map::Map<String, toml::Value>) -> toml::Value {
    let mut tagged = toml::map::Map::new();
    tagged.insert(String::from("kind"), toml::Value::String(kind.to_owned()));
    if !parameters.is_empty() {
        tagged.insert(String::from("parameters"), toml::Value::Table(parameters));
    }
    toml::Value::Table(tagged)
}

fn merge_parameters(
    destination: &mut toml::map::Map<String, toml::Value>,
    parameters: toml::map::Map<String, toml::Value>,
) -> Result<(), FaultSignalAuthoringError> {
    for (key, value) in parameters {
        if destination.insert(key.clone(), value).is_some() {
            return Err(FaultSignalAuthoringError::DuplicateProjectedField(key));
        }
    }
    Ok(())
}

fn insert<T: Serialize>(
    table: &mut toml::map::Map<String, toml::Value>,
    field: &'static str,
    value: &T,
) -> Result<(), FaultSignalAuthoringError> {
    table.insert(String::from(field), to_toml_value(value)?);
    Ok(())
}

fn insert_string(
    table: &mut toml::map::Map<String, toml::Value>,
    field: &'static str,
    value: &'static str,
) {
    table.insert(
        String::from(field),
        toml::Value::String(String::from(value)),
    );
}

fn take_value(
    table: &mut toml::map::Map<String, toml::Value>,
    field: &'static str,
) -> Result<toml::Value, FaultSignalAuthoringError> {
    table
        .remove(field)
        .ok_or(FaultSignalAuthoringError::MissingField(field))
}

fn take_string(
    table: &mut toml::map::Map<String, toml::Value>,
    field: &'static str,
) -> Result<String, FaultSignalAuthoringError> {
    match take_value(table, field)? {
        toml::Value::String(value) => Ok(value),
        _ => Err(FaultSignalAuthoringError::InvalidField(field)),
    }
}

fn take_typed<T: DeserializeOwned>(
    table: &mut toml::map::Map<String, toml::Value>,
    field: &'static str,
) -> Result<T, FaultSignalAuthoringError> {
    from_toml_value(take_value(table, field)?).map_err(Into::into)
}

fn take_optional_typed<T: DeserializeOwned>(
    table: &mut toml::map::Map<String, toml::Value>,
    field: &'static str,
) -> Result<Option<T>, FaultSignalAuthoringError> {
    table
        .remove(field)
        .map(from_toml_value)
        .transpose()
        .map_err(Into::into)
}

fn take_optional_table(
    values: &mut toml::map::Map<String, toml::Value>,
    field: &'static str,
) -> Result<Option<toml::map::Map<String, toml::Value>>, FaultSignalAuthoringError> {
    values
        .remove(field)
        .map(|value| table(value, field))
        .transpose()
}

fn table(
    value: toml::Value,
    context: &'static str,
) -> Result<toml::map::Map<String, toml::Value>, FaultSignalAuthoringError> {
    match value {
        toml::Value::Table(value) => Ok(value),
        _ => Err(FaultSignalAuthoringError::ExpectedTable(context)),
    }
}

fn ensure_empty(
    table: &toml::map::Map<String, toml::Value>,
    context: &'static str,
) -> Result<(), FaultSignalAuthoringError> {
    if let Some(field) = table.keys().next() {
        Err(FaultSignalAuthoringError::UnknownField {
            context,
            field: field.clone(),
        })
    } else {
        Ok(())
    }
}

fn authored_u64(value: u64) -> toml::Value {
    if let Ok(value) = i64::try_from(value) {
        toml::Value::Integer(value)
    } else {
        toml::Value::String(format!("u64:{value}"))
    }
}

fn enum_string<T: Serialize>(value: &T) -> Result<String, FaultSignalAuthoringError> {
    match to_toml_value(value)? {
        toml::Value::String(value) => Ok(value),
        _ => Err(FaultSignalAuthoringError::InvalidEnum),
    }
}

fn parse_enum_string<T: DeserializeOwned>(value: &str) -> Result<T, FaultSignalAuthoringError> {
    from_toml_value(toml::Value::String(value.to_owned())).map_err(Into::into)
}

fn value_type_string(value: &SignalValueType) -> String {
    match value {
        SignalValueType::Bool => String::from("bool"),
        SignalValueType::I64 => String::from("i64"),
        SignalValueType::U64 => String::from("u64"),
        SignalValueType::Ratio => String::from("ratio"),
        SignalValueType::DurationNanos => String::from("duration_nanos"),
        SignalValueType::RatePerSecond => String::from("rate_per_second"),
        SignalValueType::ProbabilityMillionths => String::from("probability_millionths"),
        SignalValueType::Enum(schema) => format!("enum:{}", schema.as_str()),
        SignalValueType::Event(schema) => format!("event:{}", schema.as_str()),
        SignalValueType::Vector2(element) => format!("vector2:{}", value_type_string(element)),
        SignalValueType::Vector3(element) => format!("vector3:{}", value_type_string(element)),
        SignalValueType::Bytes => String::from("bytes"),
    }
}

fn parse_value_type(value: &str) -> Result<SignalValueType, FaultSignalAuthoringError> {
    match value {
        "bool" => Ok(SignalValueType::Bool),
        "i64" => Ok(SignalValueType::I64),
        "u64" => Ok(SignalValueType::U64),
        "ratio" => Ok(SignalValueType::Ratio),
        "duration_nanos" => Ok(SignalValueType::DurationNanos),
        "rate_per_second" => Ok(SignalValueType::RatePerSecond),
        "probability_millionths" => Ok(SignalValueType::ProbabilityMillionths),
        "bytes" => Ok(SignalValueType::Bytes),
        _ => {
            let (kind, parameter) = value
                .split_once(':')
                .ok_or_else(|| FaultSignalAuthoringError::InvalidValueType(value.to_owned()))?;
            match kind {
                "enum" => Ok(SignalValueType::Enum(SignalId::parse(parameter)?)),
                "event" => Ok(SignalValueType::Event(SignalId::parse(parameter)?)),
                "vector2" => Ok(SignalValueType::Vector2(Box::new(parse_value_type(
                    parameter,
                )?))),
                "vector3" => Ok(SignalValueType::Vector3(Box::new(parse_value_type(
                    parameter,
                )?))),
                _ => Err(FaultSignalAuthoringError::InvalidValueType(
                    value.to_owned(),
                )),
            }
        }
    }
}

fn hex_bytes(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn parse_hex_value(value: toml::Value) -> Result<Vec<u8>, FaultSignalAuthoringError> {
    let toml::Value::String(value) = value else {
        return Err(FaultSignalAuthoringError::InvalidField("value"));
    };
    if value.len() % 2 != 0
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(FaultSignalAuthoringError::InvalidHex);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_digit(pair[0])?;
            let low = hex_digit(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_digit(value: u8) -> Result<u8, FaultSignalAuthoringError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(FaultSignalAuthoringError::InvalidHex),
    }
}

/// Failure to project or admit the public fault-signal authoring grammar.
#[derive(Debug)]
pub(crate) enum FaultSignalAuthoringError {
    /// Public TOML cannot encode multiple independently bounded graphs.
    MultiplePrograms {
        /// Submitted program count.
        actual: usize,
    },
    /// The fault-signal semantic version is not implemented.
    Version {
        /// Exact implemented version.
        expected: u16,
        /// Authored version.
        actual: u16,
    },
    /// Bindings were authored without a signal graph.
    BindingsWithoutSignals,
    /// An empty graph attempted to assign unused non-default resource limits.
    NonCanonicalEmptyLimits,
    /// A required field was omitted.
    MissingField(&'static str),
    /// A field had the wrong TOML representation.
    InvalidField(&'static str),
    /// A field is not legal in this selected variant.
    UnexpectedField(&'static str),
    /// A selected table contains an unknown field.
    UnknownField {
        /// Owning table.
        context: &'static str,
        /// Unknown field name.
        field: String,
    },
    /// A closed variant name is unknown.
    UnknownKind(String),
    /// A value-type spelling is unknown or malformed.
    InvalidValueType(String),
    /// A tagged value was not a table.
    ExpectedTable(&'static str),
    /// Flattening would overwrite a common field.
    DuplicateProjectedField(String),
    /// `signal` and `signals` were both supplied.
    ConflictingSignalFields,
    /// A selector did not reconstruct a valid homogeneous target set.
    InvalidSelector,
    /// A closed enum did not serialize as its canonical string.
    InvalidEnum,
    /// A byte or event payload was not canonical lowercase even-length hex.
    InvalidHex,
    /// A source coordinate does not belong to its node's declared domain.
    CoordinateDomainMismatch,
    /// A public authoring collection exceeds its configured or hard ceiling.
    CollectionLimit {
        /// Field containing the collection.
        field: &'static str,
        /// Submitted element count.
        actual: usize,
        /// Effective ceiling.
        limit: usize,
    },
    /// An authored selector does not resolve to a declared world target.
    UnknownWorldTarget {
        /// Authored selector kind.
        kind: String,
        /// Authored target identity.
        id: String,
    },
    /// A telemetry or coordinate adapter is outside the executable registry.
    UnsupportedAdapter(String),
    /// A telemetry field is absent from the selected adapter registry.
    UnknownTelemetryField {
        /// Executable adapter name.
        adapter: String,
        /// Rejected field name.
        field: String,
    },
    /// Two authored signal rows reuse one graph identity.
    DuplicateSignalId(String),
    /// An operator or binding references an absent signal row.
    UnknownSignal(String),
    /// JSON/TOML exact-integer conversion failed.
    Toml(FaultSignalTomlWireError),
    /// An identity failed its closed grammar.
    Contract(FaultContractError),
    /// Signal graph admission failed.
    Program(SignalProgramError),
    /// Binding wire admission failed.
    Wire(FaultSignalWireError),
    /// Complete fault plan admission failed.
    Plan(FaultSignalPlanError),
}

impl fmt::Display for FaultSignalAuthoringError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("fault signal authoring admission failed: ")?;
        match self {
            Self::MultiplePrograms { actual } => write!(
                formatter,
                "public TOML requires one flat signal graph, found {actual} programs"
            ),
            Self::Version { expected, actual } => write!(
                formatter,
                "semantic version {actual} does not match implemented version {expected}"
            ),
            Self::BindingsWithoutSignals => formatter.write_str("bindings require signals"),
            Self::NonCanonicalEmptyLimits => {
                formatter.write_str("an empty signal graph requires default resource limits")
            }
            Self::MissingField(field) => write!(formatter, "missing required field `{field}`"),
            Self::InvalidField(field) => write!(formatter, "invalid field `{field}`"),
            Self::UnexpectedField(field) => write!(formatter, "unexpected field `{field}`"),
            Self::UnknownField { context, field } => {
                write!(formatter, "unknown {context} field `{field}`")
            }
            Self::UnknownKind(kind) => write!(formatter, "unknown closed kind `{kind}`"),
            Self::InvalidValueType(value) => write!(formatter, "invalid value type `{value}`"),
            Self::ExpectedTable(context) => write!(formatter, "{context} must be a table"),
            Self::DuplicateProjectedField(field) => {
                write!(
                    formatter,
                    "projected field `{field}` conflicts with a common field"
                )
            }
            Self::ConflictingSignalFields => {
                formatter.write_str("`signal` and `signals` are mutually exclusive")
            }
            Self::InvalidSelector => formatter.write_str("selector target set is invalid"),
            Self::InvalidEnum => formatter.write_str("closed enum is not a canonical string"),
            Self::InvalidHex => formatter.write_str("payload is not canonical lowercase hex"),
            Self::CoordinateDomainMismatch => {
                formatter.write_str("source coordinate does not match the signal domain")
            }
            Self::CollectionLimit {
                field,
                actual,
                limit,
            } => write!(
                formatter,
                "collection `{field}` contains {actual} items, limit is {limit}"
            ),
            Self::UnknownWorldTarget { kind, id } => {
                write!(
                    formatter,
                    "{kind} selector target `{id}` is absent from the world"
                )
            }
            Self::UnsupportedAdapter(adapter) => {
                write!(
                    formatter,
                    "adapter `{adapter}` is not executable in schema v2"
                )
            }
            Self::UnknownTelemetryField { adapter, field } => {
                write!(
                    formatter,
                    "telemetry field `{field}` is unknown for `{adapter}`"
                )
            }
            Self::DuplicateSignalId(id) => write!(formatter, "duplicate signal ID `{id}`"),
            Self::UnknownSignal(id) => write!(formatter, "unknown signal ID `{id}`"),
            Self::Toml(error) => error.fmt(formatter),
            Self::Contract(error) => error.fmt(formatter),
            Self::Program(error) => error.fmt(formatter),
            Self::Wire(error) => error.fmt(formatter),
            Self::Plan(error) => error.fmt(formatter),
        }
    }
}

impl Error for FaultSignalAuthoringError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Toml(error) => Some(error),
            Self::Contract(error) => Some(error),
            Self::Program(error) => Some(error),
            Self::Wire(error) => Some(error),
            Self::Plan(error) => Some(error),
            _ => None,
        }
    }
}

impl From<FaultSignalTomlWireError> for FaultSignalAuthoringError {
    fn from(value: FaultSignalTomlWireError) -> Self {
        Self::Toml(value)
    }
}

impl From<FaultContractError> for FaultSignalAuthoringError {
    fn from(value: FaultContractError) -> Self {
        Self::Contract(value)
    }
}

impl From<SignalProgramError> for FaultSignalAuthoringError {
    fn from(value: SignalProgramError) -> Self {
        Self::Program(value)
    }
}
