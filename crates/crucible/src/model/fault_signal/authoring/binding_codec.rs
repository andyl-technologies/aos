//! Binding, sampling, mapping, and selector authoring codecs.

use super::*;

pub(super) fn binding_to_toml(
    wire: &FaultBindingWire,
) -> Result<toml::Value, FaultSignalAuthoringError> {
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

pub(super) fn binding_from_toml(
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

pub(super) fn encode_sampling(
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

pub(super) fn decode_sampling(
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

pub(super) fn encode_search(
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

pub(super) fn decode_search(
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

pub(super) fn mapping_to_toml(
    mapping: &BindingMapping,
) -> Result<toml::Value, FaultSignalAuthoringError> {
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

pub(super) fn decode_mapping(
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
            if let Some(residence) = value.remove("minimum_active_nanos")
                && value
                    .insert(String::from("residence_nanos"), residence)
                    .is_some()
            {
                return Err(FaultSignalAuthoringError::DuplicateProjectedField(
                    String::from("residence_nanos"),
                ));
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

pub(super) fn binding_first_input_type<'a>(
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

pub(super) fn mapped_parameter_value_type(parameter: MappedEffectParameter) -> SignalValueType {
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

pub(super) fn expand_binding_map_points(
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

pub(super) fn selector_to_toml(
    selector: &TargetSelector,
) -> Result<toml::Value, FaultSignalAuthoringError> {
    match selector {
        TargetSelector::Exact(targets) => {
            let [target] = targets.targets() else {
                return Err(FaultSignalAuthoringError::InvalidSelector);
            };
            let mut value = table(resolved_target_to_authored_toml(target)?, "selector")?;
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
                .map(resolved_target_to_authored_toml)
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

pub(super) fn resolved_target_to_authored_toml(
    target: &ResolvedFaultTarget,
) -> Result<toml::Value, FaultSignalAuthoringError> {
    let mut value = table(flatten_tagged(to_toml_value(target)?)?, "selector target")?;
    match target {
        ResolvedFaultTarget::BlockDevice { device }
        | ResolvedFaultTarget::NinePDevice { device } => {
            value.insert(
                String::from("device"),
                toml::Value::String(format_content_hash_ref(*device)),
            );
        }
        ResolvedFaultTarget::BlockRange { device, .. } => {
            value.insert(
                String::from("device"),
                toml::Value::String(format_content_hash_ref(*device)),
            );
        }
        _ => {}
    }
    Ok(toml::Value::Table(value))
}

pub(super) fn selector_from_toml(
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
                    WorldNetworkPathHop::Queue { queue } => {
                        let declaration = world
                            .fault_topology()
                            .network_queues
                            .iter()
                            .find(|candidate| &candidate.id == queue)
                            .ok_or(FaultSignalAuthoringError::InvalidSelector)?;
                        Ok(ResolvedFaultTarget::NetworkQueue {
                            owner: fault_object_id(&declaration.owner)?,
                            queue: fault_object_id(queue)?,
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

pub(in crate::model::fault_signal) fn validate_selector_for_world(
    selector: &TargetSelector,
    world: &World,
) -> Result<(), FaultSignalAuthoringError> {
    let encoded = selector_to_toml(selector)?;
    let resolved = selector_from_toml(encoded, world)?;
    if &resolved == selector {
        Ok(())
    } else {
        Err(FaultSignalAuthoringError::InvalidSelector)
    }
}
