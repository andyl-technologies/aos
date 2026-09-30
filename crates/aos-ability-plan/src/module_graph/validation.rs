//! Structural and semantic validation of module-generated activation graphs.

use std::collections::BTreeSet;
use std::path::{Component, Path};

use anyhow::{Result, bail, ensure};
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
        check_input(&node.input, &node.input_type, graph, &mut dependencies)?;
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

fn check_input(
    value: &Value,
    expected: &OptionType,
    graph: &ModuleGraph,
    dependencies: &mut BTreeSet<String>,
) -> Result<()> {
    if value.get("_type").and_then(Value::as_str) == Some("aos-effect-output") {
        let reference: OutputReference = serde_json::from_value(value.clone())?;
        ensure!(
            &reference.schema == expected,
            "deferred input type does not match its consumer"
        );
        dependencies.insert(check_reference(&reference, graph)?);
        return Ok(());
    }

    match (expected, value) {
        (OptionType::Submodule { fields, open }, Value::Object(values)) => {
            ensure!(
                *open || values.len() == fields.len(),
                "input record fields do not match its contract"
            );
            for (name, schema) in fields {
                let field = values
                    .get(name)
                    .ok_or_else(|| anyhow::anyhow!("missing input field {name}"))?;
                check_input(field, schema, graph, dependencies)?;
            }
        }
        (OptionType::AttrsOf { value: schema, .. }, Value::Object(values)) => {
            for value in values.values() {
                check_input(value, schema, graph, dependencies)?;
            }
        }
        (OptionType::List { element, .. }, Value::Array(values)) => {
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
    Ok(())
}
