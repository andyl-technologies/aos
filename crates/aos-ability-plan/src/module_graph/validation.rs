//! Structural and semantic validation of module-generated activation graphs.

use std::collections::BTreeSet;
use std::path::{Component, Path};

use anyhow::{Context, Result, bail, ensure};
use aos_ability_model::{ABILITY_LIMITS_V1, AbilityValue, OptionType};
use aos_contract::Sha256Digest;
use serde_json::Value;

use super::{Handler, ModuleGraph, OutputReference, identity_key};

pub(super) fn check_hashes(raw: &Value) -> Result<()> {
    let nodes = raw
        .get("nodes")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("activation graph has no node map"))?;
    for (key, node) in nodes {
        let identity: Vec<String> = serde_json::from_value(node["identity"].clone())?;
        ensure!(
            identity_key(&identity)? == *key,
            "effect key does not match its logical identity"
        );
        let mut semantic = node
            .as_object()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("effect must be an object"))?;
        let revision = semantic.remove("revision");
        semantic.remove("dependencies");
        semantic.remove("inputs");
        let expected = Sha256Digest::of_bytes(serde_json::to_vec(&semantic)?).hex();
        ensure!(
            revision.as_ref().and_then(Value::as_str) == Some(expected.as_str()),
            "effect revision does not match its content"
        );
    }
    Ok(())
}

pub(super) fn check_graph(graph: &ModuleGraph) -> Result<()> {
    ensure!(
        graph.schema == "aos.activation.graph",
        "unsupported activation graph format"
    );
    ensure!(
        graph.nodes.len() <= ABILITY_LIMITS_V1.max_graph_nodes as usize,
        "too many activation effects"
    );
    let all: BTreeSet<_> = graph.nodes.keys().cloned().collect();
    let order: BTreeSet<_> = graph.order.iter().cloned().collect();
    ensure!(
        all == order && order.len() == graph.order.len(),
        "execution order must contain every node exactly once"
    );
    let mut completed = BTreeSet::new();

    for key in &graph.order {
        let node = &graph.nodes[key];
        ensure!(
            node.identity.len() >= 3 && node.identity.iter().all(|part| !part.is_empty()),
            "invalid effect identity"
        );
        ensure!(
            (1..=3_600_000).contains(&node.timeout_ms),
            "invalid handler timeout"
        );
        check_type(&node.input_type)?;
        for schema in node.results.values() {
            check_type(schema)?;
        }

        let mut dependencies = BTreeSet::new();
        check_input(&node.input, &node.input_type, graph, &mut dependencies)
            .with_context(|| format!("input of effect {:?}", node.identity))?;
        for reference in &node.after {
            dependencies.insert(check_reference(reference, graph)?);
        }

        match &node.handler {
            Handler::Process {
                artifact,
                executable,
            } => {
                let Some(relative) = artifact.strip_prefix("/nix/store/") else {
                    bail!("handler artifact is not a store output");
                };
                ensure!(
                    !relative.is_empty() && !relative.contains('/'),
                    "handler artifact must be a store root"
                );
                let (digest, name) = relative
                    .split_once('-')
                    .ok_or_else(|| anyhow::anyhow!("handler artifact has no store digest"))?;
                ensure!(
                    digest.len() == 32
                        && digest
                            .bytes()
                            .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte)),
                    "invalid handler store digest"
                );
                ensure!(
                    !name.is_empty()
                        && name
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"+-._?=".contains(&byte)),
                    "invalid handler store name"
                );
                let executable_path = Path::new(executable);
                ensure!(
                    executable_path.starts_with(artifact) && executable_path != Path::new(artifact),
                    "handler executable is outside its artifact"
                );
                ensure!(
                    executable_path
                        .components()
                        .all(|part| !matches!(part, Component::ParentDir | Component::CurDir)),
                    "handler executable contains traversal components"
                );
            }
            Handler::Composition { children, exports } => {
                ensure!(
                    !children.is_empty(),
                    "composed handler has no child effects"
                );
                ensure!(
                    exports.keys().eq(node.results.keys()),
                    "composed handler result set differs from its contract"
                );
                for child in children {
                    let child_node = graph
                        .nodes
                        .get(child)
                        .ok_or_else(|| anyhow::anyhow!("absent child effect"))?;
                    ensure!(
                        child_node.lifetime >= node.lifetime,
                        "composed child does not outlive its parent"
                    );
                    dependencies.insert(child.clone());
                }
                for (name, reference) in exports {
                    ensure!(
                        reference.schema == node.results[name],
                        "composed output has incompatible type"
                    );
                    dependencies.insert(check_reference(reference, graph)?);
                }
            }
        }

        let declared: BTreeSet<_> = node.dependencies.iter().cloned().collect();
        ensure!(
            dependencies == declared && declared.len() == node.dependencies.len(),
            "effect dependencies do not match its typed references"
        );
        ensure!(
            dependencies
                .iter()
                .all(|dependency| completed.contains(dependency)),
            "execution order violates a dependency or contains a cycle"
        );
        completed.insert(key.clone());
    }
    Ok(())
}

fn check_type(schema: &OptionType) -> Result<()> {
    ensure!(
        schema.is_within_limits(&ABILITY_LIMITS_V1) && !schema.contains_opaque(),
        "effect type is not portable or exceeds its bounds"
    );
    fn portable(value: &Value) -> bool {
        match value {
            Value::Object(fields) => {
                !(fields.get("kind").and_then(Value::as_str) == Some("string")
                    && fields.get("pattern").is_some_and(|value| !value.is_null()))
                    && fields.values().all(portable)
            }
            Value::Array(values) => values.iter().all(portable),
            _ => true,
        }
    }
    ensure!(
        portable(&serde_json::to_value(schema)?),
        "string pattern has no portable activation validator"
    );
    Ok(())
}

fn check_reference(reference: &OutputReference, graph: &ModuleGraph) -> Result<String> {
    ensure!(
        reference.marker == "aos-effect-output",
        "invalid output reference marker"
    );
    let key = identity_key(&reference.identity)?;
    let producer = graph
        .nodes
        .get(&key)
        .ok_or_else(|| anyhow::anyhow!("absent deferred output producer"))?;
    ensure!(
        producer.results.get(&reference.output) == Some(&reference.schema),
        "deferred output type does not match its producer"
    );
    Ok(key)
}

pub(super) fn check_concrete(value: &Value, expected: &OptionType) -> Result<()> {
    let graph = ModuleGraph {
        schema: "aos.activation.graph".into(),
        nodes: Default::default(),
        order: Vec::new(),
    };
    check_input(value, expected, &graph, &mut BTreeSet::new())
}

fn check_input(
    value: &Value,
    expected: &OptionType,
    graph: &ModuleGraph,
    dependencies: &mut BTreeSet<String>,
) -> Result<()> {
    if value.get("_type").and_then(Value::as_str) == Some("aos-effect-output") {
        let reference: OutputReference = serde_json::from_value(value.clone())?;
        ensure!(
            reference_fits(&reference.schema, expected),
            "deferred input type does not match its consumer"
        );
        dependencies.insert(check_reference(&reference, graph)?);
        return Ok(());
    }

    match (expected, value) {
        (OptionType::Json, Value::Object(values)) => {
            for value in values.values() {
                check_input(value, expected, graph, dependencies)?;
            }
        }
        (OptionType::Json, Value::Array(values)) => {
            for value in values {
                check_input(value, expected, graph, dependencies)?;
            }
        }
        (OptionType::Submodule { fields, open }, Value::Object(values)) => {
            ensure!(
                *open || values.len() == fields.len(),
                "record field count {} does not match its contract ({})",
                values.len(),
                fields.len()
            );
            for (name, schema) in fields {
                let field = values
                    .get(name)
                    .ok_or_else(|| anyhow::anyhow!("missing input field {name}"))?;
                check_input(field, schema, graph, dependencies)
                    .with_context(|| format!("field {name}"))?;
            }
        }
        (OptionType::AttrsOf { value: schema, .. }, Value::Object(values)) => {
            for value in values.values() {
                check_input(value, schema, graph, dependencies)?;
            }
        }
        (
            OptionType::Map {
                key,
                value: schema,
                max_entries,
            },
            Value::Object(values),
        ) => {
            ensure!(
                values.len() as u64 <= *max_entries && values.keys().all(|name| key.admits(name)),
                "input map keys or cardinality violate its contract"
            );
            for value in values.values() {
                check_input(value, schema, graph, dependencies)?;
            }
        }
        (OptionType::TaggedUnion { tag, variants }, Value::Object(values)) => {
            let tag = values
                .get(tag.as_str())
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("union discriminator must be a literal string"))?;
            let variant = variants
                .iter()
                .find(|(name, _)| name.as_str() == tag)
                .map(|(_, variant)| variant)
                .ok_or_else(|| anyhow::anyhow!("unknown union discriminator"))?;
            check_input(value, variant, graph, dependencies)?;
        }
        (
            OptionType::Record {
                fields,
                optional_fields,
            },
            Value::Object(values),
        ) => {
            ensure!(
                values
                    .keys()
                    .all(|name| fields.keys().any(|key| key.as_str() == name)),
                "unknown input record field"
            );
            for (name, schema) in fields {
                if let Some(value) = values.get(name.as_str()) {
                    check_input(value, schema, graph, dependencies)?;
                } else {
                    ensure!(
                        optional_fields.contains(name),
                        "missing required input record field"
                    );
                }
            }
        }
        (
            OptionType::DocumentRecord {
                fields,
                optional_fields,
                key_max_length,
            },
            Value::Object(values),
        ) => {
            ensure!(
                values
                    .keys()
                    .all(|name| name.len() as u64 <= *key_max_length && fields.contains_key(name)),
                "unknown input document field"
            );
            for (name, schema) in fields {
                if let Some(value) = values.get(name) {
                    check_input(value, schema, graph, dependencies)?;
                } else {
                    ensure!(
                        optional_fields.contains(name),
                        "missing required input document field"
                    );
                }
            }
        }
        (OptionType::OneOf { alternatives }, value) => {
            check_alternatives(value, alternatives, false, graph, dependencies)?;
        }
        (OptionType::DisjointUnion { variants }, value) => {
            check_alternatives(value, variants, true, graph, dependencies)?;
        }
        (OptionType::Set { element }, Value::Array(values)) => {
            for value in values {
                check_input(value, element, graph, dependencies)?;
            }
        }
        (OptionType::Refined { value: base, .. }, value) => {
            check_input(value, base, graph, dependencies)?;
        }
        (
            OptionType::List {
                element, max_items, ..
            },
            Value::Array(values),
        ) => {
            ensure!(
                max_items.is_none_or(|maximum| values.len() as u64 <= maximum),
                "input list exceeds its bound"
            );
            for value in values {
                check_input(value, element, graph, dependencies)?;
            }
        }
        (
            OptionType::Nullable { value: schema } | OptionType::Optional { value: schema },
            value,
        ) if !value.is_null() => {
            check_input(value, schema, graph, dependencies)?;
        }
        _ => ensure!(
            expected.admits(&AbilityValue::new(value.clone())?),
            "literal input has the wrong type"
        ),
    }
    // Validate all concrete constraints before any execution. Constraints that
    // depend on deferred values are checked after substitution by Effect::check_input.
    if !contains_reference(value) {
        ensure!(
            expected.admits(&AbilityValue::new(value.clone())?),
            "literal input violates its constraints"
        );
    }
    Ok(())
}

fn check_alternatives(
    value: &Value,
    variants: &[OptionType],
    disjoint: bool,
    graph: &ModuleGraph,
    dependencies: &mut BTreeSet<String>,
) -> Result<()> {
    let mut matching = Vec::new();
    for variant in variants {
        let mut candidate = BTreeSet::new();
        if check_input(value, variant, graph, &mut candidate).is_ok() {
            matching.push(candidate);
            if !disjoint {
                break;
            }
        }
    }
    ensure!(
        !matching.is_empty() && (!disjoint || matching.len() == 1),
        "input does not match its union contract"
    );
    for candidate in matching {
        dependencies.extend(candidate);
    }
    Ok(())
}

fn contains_reference(value: &Value) -> bool {
    if value.get("_type").and_then(Value::as_str) == Some("aos-effect-output") {
        return true;
    }
    match value {
        Value::Object(values) => values.values().any(contains_reference),
        Value::Array(values) => values.iter().any(contains_reference),
        _ => false,
    }
}

fn reference_fits(actual: &OptionType, expected: &OptionType) -> bool {
    actual == expected
        || match expected {
            OptionType::Json => !actual.contains_opaque(),
            OptionType::Nullable { value } | OptionType::Optional { value } => {
                reference_fits(actual, value)
            }
            OptionType::OneOf { alternatives } => alternatives
                .iter()
                .any(|variant| reference_fits(actual, variant)),
            _ => false,
        }
}

#[cfg(test)]
mod tests;
