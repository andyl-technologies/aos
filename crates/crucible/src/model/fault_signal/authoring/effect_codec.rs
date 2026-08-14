//! Effect projection and shared strict TOML value helpers.

use super::*;

#[cfg(test)]
use super::binding_codec::resolved_target_to_authored_toml;

pub(super) fn effect_to_toml(
    effect: &EffectRequestWire,
) -> Result<toml::Value, FaultSignalAuthoringError> {
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

pub(super) fn effect_from_toml(
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

pub(super) fn default_effect_lifetime(
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

pub(super) fn merge_tagged(
    destination: &mut toml::map::Map<String, toml::Value>,
    tagged: toml::Value,
) -> Result<(), FaultSignalAuthoringError> {
    let flattened = table(flatten_tagged(tagged)?, "tagged value")?;
    merge_parameters(destination, flattened)
}

pub(super) fn flatten_tagged(value: toml::Value) -> Result<toml::Value, FaultSignalAuthoringError> {
    let mut tagged = table(value, "tagged value")?;
    let kind = take_string(&mut tagged, "kind")?;
    let parameters = take_optional_table(&mut tagged, "parameters")?.unwrap_or_default();
    ensure_empty(&tagged, "tagged value")?;
    let mut result = toml::map::Map::new();
    result.insert(String::from("kind"), toml::Value::String(kind));
    merge_parameters(&mut result, parameters)?;
    Ok(toml::Value::Table(result))
}

pub(super) fn tagged_from_flat<T: DeserializeOwned>(
    value: toml::Value,
) -> Result<T, FaultSignalAuthoringError> {
    let mut value = table(value, "tagged value")?;
    let kind = take_string(&mut value, "kind")?;
    tagged_from_parts(&kind, value)
}

pub(super) fn tagged_from_parts<T: DeserializeOwned>(
    kind: &str,
    parameters: toml::map::Map<String, toml::Value>,
) -> Result<T, FaultSignalAuthoringError> {
    from_toml_value(tagged_value(kind, parameters)).map_err(Into::into)
}

pub(super) fn tagged_value(
    kind: &str,
    parameters: toml::map::Map<String, toml::Value>,
) -> toml::Value {
    let mut tagged = toml::map::Map::new();
    tagged.insert(String::from("kind"), toml::Value::String(kind.to_owned()));
    if !parameters.is_empty() {
        tagged.insert(String::from("parameters"), toml::Value::Table(parameters));
    }
    toml::Value::Table(tagged)
}

pub(super) fn merge_parameters(
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

pub(super) fn insert<T: Serialize>(
    table: &mut toml::map::Map<String, toml::Value>,
    field: &'static str,
    value: &T,
) -> Result<(), FaultSignalAuthoringError> {
    table.insert(String::from(field), to_toml_value(value)?);
    Ok(())
}

pub(super) fn insert_string(
    table: &mut toml::map::Map<String, toml::Value>,
    field: &'static str,
    value: &'static str,
) {
    table.insert(
        String::from(field),
        toml::Value::String(String::from(value)),
    );
}

pub(super) fn take_value(
    table: &mut toml::map::Map<String, toml::Value>,
    field: &'static str,
) -> Result<toml::Value, FaultSignalAuthoringError> {
    table
        .remove(field)
        .ok_or(FaultSignalAuthoringError::MissingField(field))
}

pub(super) fn take_string(
    table: &mut toml::map::Map<String, toml::Value>,
    field: &'static str,
) -> Result<String, FaultSignalAuthoringError> {
    match take_value(table, field)? {
        toml::Value::String(value) => Ok(value),
        _ => Err(FaultSignalAuthoringError::InvalidField(field)),
    }
}

pub(super) fn take_typed<T: DeserializeOwned>(
    table: &mut toml::map::Map<String, toml::Value>,
    field: &'static str,
) -> Result<T, FaultSignalAuthoringError> {
    from_toml_value(take_value(table, field)?).map_err(Into::into)
}

pub(super) fn take_optional_typed<T: DeserializeOwned>(
    table: &mut toml::map::Map<String, toml::Value>,
    field: &'static str,
) -> Result<Option<T>, FaultSignalAuthoringError> {
    table
        .remove(field)
        .map(from_toml_value)
        .transpose()
        .map_err(Into::into)
}

pub(super) fn take_optional_table(
    values: &mut toml::map::Map<String, toml::Value>,
    field: &'static str,
) -> Result<Option<toml::map::Map<String, toml::Value>>, FaultSignalAuthoringError> {
    values
        .remove(field)
        .map(|value| table(value, field))
        .transpose()
}

pub(super) fn table(
    value: toml::Value,
    context: &'static str,
) -> Result<toml::map::Map<String, toml::Value>, FaultSignalAuthoringError> {
    match value {
        toml::Value::Table(value) => Ok(value),
        _ => Err(FaultSignalAuthoringError::ExpectedTable(context)),
    }
}

pub(super) fn ensure_empty(
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

pub(super) fn authored_u64(value: u64) -> toml::Value {
    if let Ok(value) = i64::try_from(value) {
        toml::Value::Integer(value)
    } else {
        toml::Value::String(format!("u64:{value}"))
    }
}

pub(super) fn enum_string<T: Serialize>(value: &T) -> Result<String, FaultSignalAuthoringError> {
    match to_toml_value(value)? {
        toml::Value::String(value) => Ok(value),
        _ => Err(FaultSignalAuthoringError::InvalidEnum),
    }
}

pub(super) fn parse_enum_string<T: DeserializeOwned>(
    value: &str,
) -> Result<T, FaultSignalAuthoringError> {
    from_toml_value(toml::Value::String(value.to_owned())).map_err(Into::into)
}

pub(super) fn value_type_string(value: &SignalValueType) -> String {
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

pub(super) fn parse_value_type(value: &str) -> Result<SignalValueType, FaultSignalAuthoringError> {
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

pub(super) fn hex_bytes(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

pub(super) fn parse_hex_value(value: toml::Value) -> Result<Vec<u8>, FaultSignalAuthoringError> {
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

pub(super) fn hex_digit(value: u8) -> Result<u8, FaultSignalAuthoringError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(FaultSignalAuthoringError::InvalidHex),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Icount, LinkDef, NodeId, ReadyPoint, VmArchitecture, WhiteBoxPolicy, WorldNode,
    };

    fn authored_test_world() -> World {
        let nodes = ["left", "right"].map(|name| WorldNode {
            id: NodeId {
                name: String::from(name),
            },
            arch: VmArchitecture::X86_64,
            memory_mib: 128,
            cmdline: String::new(),
            ready_point: ReadyPoint::FixedIcount {
                icount: Icount { retired: 0 },
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: 1,
            icount_shift: 0,
            kernel: None,
            root_image: None,
            initrd: None,
        });
        let link = LinkDef::new(nodes[0].id.clone(), nodes[1].id.clone())
            .unwrap_or_else(|error| panic!("test link should be valid: {error}"));
        World::from_nodes_and_links(nodes.to_vec(), vec![link])
            .unwrap_or_else(|error| panic!("test world should be valid: {error}"))
    }

    #[test]
    fn content_addressed_targets_use_the_public_hash_reference_syntax() {
        let device = ContentHash::from_bytes(b"authored-device");
        let expected = toml::Value::String(format_content_hash_ref(device));
        let targets = [
            ResolvedFaultTarget::BlockDevice { device },
            ResolvedFaultTarget::NinePDevice { device },
            ResolvedFaultTarget::BlockRange {
                device,
                start_byte: 512,
                length_bytes: 4_096,
            },
        ];

        for target in targets {
            let value = resolved_target_to_authored_toml(&target)
                .unwrap_or_else(|error| panic!("target should serialize: {error}"));
            let table = value
                .as_table()
                .unwrap_or_else(|| panic!("resolved target should be an authored table"));
            assert_eq!(table.get("device"), Some(&expected));
        }
    }

    #[test]
    fn node_selector_accepts_a_declared_vm_without_optional_capability_rows() {
        let mut selector = toml::map::Map::new();
        selector.insert(
            String::from("kind"),
            toml::Value::String(String::from("node")),
        );
        selector.insert(
            String::from("node"),
            toml::Value::String(String::from("left")),
        );

        let resolved =
            resolve_authored_target(toml::Value::Table(selector), &authored_test_world())
                .unwrap_or_else(|error| panic!("declared VM node should resolve: {error}"));
        assert_eq!(
            resolved,
            vec![ResolvedFaultTarget::Node {
                node: FaultObjectId::parse("left")
                    .unwrap_or_else(|error| panic!("test node ID should be valid: {error}")),
            }]
        );
    }
}
