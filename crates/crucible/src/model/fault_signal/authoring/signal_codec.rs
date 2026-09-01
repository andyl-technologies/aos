//! Signal-node authoring projection and strict TOML decoding.

use super::*;

pub(super) fn signal_to_toml(
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

pub(super) fn flatten_pure_fields(
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

pub(super) fn flatten_stateful_fields(
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

pub(super) fn authored_value_pairs(
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

pub(super) fn expand_pure_fields(
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

pub(super) fn expand_stateful_fields(
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

pub(super) fn first_input_type<'a>(
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

pub(super) fn expand_value_pairs(
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

pub(super) fn signal_from_toml(
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

pub(super) fn flatten_source_fields(
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

pub(super) fn expand_source_fields(
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

pub(super) fn flatten_interpolation(
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

pub(super) fn expand_interpolation(
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

pub(super) fn flatten_boundary(
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

pub(super) fn expand_boundary(
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

pub(super) fn authored_time_mapping(
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

pub(super) fn parse_time_mapping(
    value: toml::Value,
) -> Result<TraceTimeMapping, FaultSignalAuthoringError> {
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

pub(super) fn rename_field(
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

pub(super) fn replace_signal_value(
    row: &mut toml::map::Map<String, toml::Value>,
    field: &'static str,
    value: &SignalValue,
) -> Result<(), FaultSignalAuthoringError> {
    row.insert(String::from(field), authored_signal_value(value)?);
    Ok(())
}

pub(super) fn expand_signal_value(
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

pub(super) fn replace_coordinate(
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

pub(super) fn expand_coordinate(
    row: &mut toml::map::Map<String, toml::Value>,
    field: &'static str,
    domain: SignalDomain,
) -> Result<(), FaultSignalAuthoringError> {
    let coordinate = parse_authored_coordinate(take_value(row, field)?, domain)?;
    row.insert(String::from(field), to_toml_value(&coordinate)?);
    Ok(())
}

pub(super) fn authored_points(
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

pub(super) fn expand_points(
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

pub(super) fn authored_coordinate(
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

pub(super) fn parse_authored_coordinate(
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

pub(super) fn pure_parts(
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

pub(super) fn pure_from_parts(
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

pub(super) fn source_from_parts(
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

pub(super) fn authored_signal_value(
    value: &SignalValue,
) -> Result<toml::Value, FaultSignalAuthoringError> {
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

pub(super) fn parse_authored_signal_value(
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
        SignalValueType::Vector2(element) => {
            SignalValue::Vector2(parse_vector(value, *element, 2)?)
        }
        SignalValueType::Vector3(element) => {
            SignalValue::Vector3(parse_vector(value, *element, 3)?)
        }
        SignalValueType::Bytes => SignalValue::Bytes(parse_hex_value(value)?),
    })
}

pub(super) fn parse_vector(
    value: toml::Value,
    element: SignalVectorElementType,
    expected: usize,
) -> Result<Vec<SignalValue>, FaultSignalAuthoringError> {
    let toml::Value::Array(values) = value else {
        return Err(FaultSignalAuthoringError::InvalidField("value"));
    };
    if values.len() != expected {
        return Err(FaultSignalAuthoringError::InvalidField("value"));
    }
    let element = element.value_type();
    values
        .into_iter()
        .map(|value| parse_authored_signal_value(value, &element))
        .collect()
}
