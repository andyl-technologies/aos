//! Admission regressions for native graph wire data and dependency topology.

use serde_json::{Value, json};

use super::*;

fn effect(name: &str) -> Value {
    json!({
        "identity":["test","echo",name], "owner":"@environment",
        "input":{}, "inputs":{}, "input_type":{"kind":"submodule","fields":{}},
        "after":[], "results":{"value":{"kind":"string"}},
        "handler":{"kind":"process",
            "artifact":"/nix/store/00000000000000000000000000000000-handler",
            "executable":"/nix/store/00000000000000000000000000000000-handler/bin/run"},
        "dependencies":[], "lifetime":"instance", "timeout_ms":1000
    })
}

fn key(effect: &Value) -> String {
    identity_key(&serde_json::from_value::<Vec<String>>(effect["identity"].clone()).unwrap())
        .unwrap()
}

fn reference(effect: &Value) -> Value {
    json!({"_type":"aos-effect-output", "identity":effect["identity"],
        "output":"value", "schema":{"kind":"string"}})
}

fn document(effects: Vec<Value>) -> Value {
    let mut nodes = serde_json::Map::new();
    let mut order = Vec::new();
    for mut effect in effects {
        let mut semantic = effect.as_object().unwrap().clone();
        for ignored in ["revision", "dependencies", "inputs"] {
            semantic.remove(ignored);
        }
        effect["revision"] = Sha256Digest::of_bytes(serde_json::to_vec(&semantic).unwrap())
            .hex()
            .into();
        let identity = key(&effect);
        order.push(identity.clone());
        nodes.insert(identity, effect);
    }
    json!({"schema":"aos.activation.graph", "nodes":nodes, "order":order})
}

fn decode(document: &Value) -> Result<CheckedModuleGraph> {
    CheckedModuleGraph::decode(&serde_json::to_vec(document).unwrap())
}

#[test]
fn rejects_forged_identity_revision_and_unknown_fields() {
    let valid = document(vec![effect("first")]);
    assert!(decode(&valid).is_ok());
    let identity = valid["order"][0].as_str().unwrap();

    let mut forged = valid.clone();
    forged["nodes"][identity]["identity"][2] = "other".into();
    assert!(decode(&forged).is_err());

    forged = valid.clone();
    forged["nodes"][identity]["timeout_ms"] = 2000.into();
    assert!(decode(&forged).is_err());

    let mut extended = effect("first");
    extended["legacy_binding"] = json!({});
    assert!(decode(&document(vec![extended])).is_err());
}

#[test]
fn descriptions_do_not_change_semantic_revisions() {
    let before = document(vec![effect("first")]);
    let mut after = before.clone();
    let identity = before["order"][0].as_str().unwrap();
    after["nodes"][identity]["inputs"] = json!({"message":{
        "description":"A documentation-only edit", "type":{"kind":"string"}
    }});

    assert!(decode(&after).is_ok());
    assert_eq!(
        before["nodes"][identity]["revision"],
        after["nodes"][identity]["revision"]
    );
}

#[test]
fn order_and_edges_must_match_actual_references() {
    let producer = effect("producer");
    let mut consumer = effect("consumer");
    consumer["after"] = json!([reference(&producer)]);
    consumer["dependencies"] = json!([key(&producer)]);
    let valid = document(vec![producer.clone(), consumer.clone()]);
    assert!(decode(&valid).is_ok());

    assert!(decode(&document(vec![consumer.clone(), producer.clone()])).is_err());
    consumer["dependencies"] = json!([]);
    assert!(decode(&document(vec![producer.clone(), consumer.clone()])).is_err());
    consumer["dependencies"] = json!([key(&producer), key(&producer)]);
    assert!(decode(&document(vec![producer, consumer])).is_err());

    let mut duplicate = valid;
    let repeated = duplicate["order"][0].clone();
    duplicate["order"].as_array_mut().unwrap().push(repeated);
    assert!(decode(&duplicate).is_err());
}

#[test]
fn cycles_and_unbound_outputs_are_rejected() {
    let mut first = effect("first");
    let mut second = effect("second");
    first["after"] = json!([reference(&second)]);
    first["dependencies"] = json!([key(&second)]);
    second["after"] = json!([reference(&first)]);
    second["dependencies"] = json!([key(&first)]);

    assert!(decode(&document(vec![first.clone(), second])).is_err());
    assert!(decode(&document(vec![first.clone()])).is_err());
    first["after"][0]["output"] = "undeclared".into();
    assert!(decode(&document(vec![effect("second"), first])).is_err());
}

#[test]
fn handler_must_be_inside_its_immutable_artifact() {
    for executable in [
        "/usr/bin/run",
        "/nix/store/00000000000000000000000000000000-handler-other/bin/run",
        "/nix/store/00000000000000000000000000000000-handler/../other/bin/run",
    ] {
        let mut invalid = effect("first");
        invalid["handler"]["executable"] = executable.into();
        assert!(decode(&document(vec![invalid])).is_err());
    }
}

#[test]
fn references_cannot_change_the_declared_producer_type() {
    let producer = effect("producer");
    let mut consumer = effect("consumer");
    consumer["input_type"] = json!({"kind":"submodule","fields":{"value":{"kind":"string"}}});
    consumer["input"] = json!({"value":reference(&producer)});
    consumer["dependencies"] = json!([key(&producer)]);
    assert!(decode(&document(vec![producer.clone(), consumer.clone()])).is_ok());

    consumer["input"]["value"]["schema"] = json!({"kind":"integer"});
    assert!(decode(&document(vec![producer, consumer])).is_err());
}

#[test]
fn composed_children_must_outlive_their_parent() {
    let mut child = effect("child");
    let mut parent = effect("parent");
    parent["handler"] = json!({"kind":"composition", "children":[key(&child)],
        "exports":{"value":reference(&child)}});
    parent["dependencies"] = json!([key(&child)]);
    assert!(decode(&document(vec![child.clone(), parent.clone()])).is_ok());

    child["lifetime"] = "transaction".into();
    assert!(decode(&document(vec![child, parent])).is_err());
}

#[test]
fn explicit_retirement_rejects_duplicate_empty_and_configured_identities() {
    let configured = effect("active");
    let configured_id = key(&configured);
    let graph = decode(&document(vec![configured])).unwrap();
    let retired = "retained-instance".to_string();

    assert_eq!(
        check_retirement(&graph, &[retired.clone()]).unwrap(),
        BTreeSet::from([retired.clone()])
    );
    assert!(check_retirement(&graph, &[retired.clone(), retired]).is_err());
    assert!(check_retirement(&graph, &[String::new()]).is_err());
    assert!(check_retirement(&graph, &[configured_id]).is_err());
}

#[test]
fn resolves_canonical_sets_by_returned_values_without_reordering_lists() {
    let first = effect("alpha");
    let second = effect("omega");
    let mut consumer = effect("consumer");
    let set_type = json!({"kind":"list", "element":{"kind":"string"},
        "max_items":8, "unique":true, "canonical_order":true});
    let list_type = json!({"kind":"list", "element":{"kind":"string"}});
    consumer["input_type"] = json!({"kind":"submodule", "fields":{
        "dependencies":set_type, "commands":list_type
    }});
    consumer["input"] = json!({
        "dependencies":[reference(&first), reference(&second)],
        "commands":[reference(&first), reference(&second)]
    });
    consumer["dependencies"] = json!([key(&first), key(&second)]);
    let consumer_key = key(&consumer);
    let checked = decode(&document(vec![first.clone(), second.clone(), consumer])).unwrap();
    let selected = &checked.graph().nodes[&consumer_key];
    let mut results = BTreeMap::from([
        (key(&first), json!({"value":"zulu.target"})),
        (key(&second), json!({"value":"alpha.target"})),
    ]);

    let input = selected.resolve_input(&results).unwrap();
    assert_eq!(
        input["dependencies"],
        json!(["alpha.target", "zulu.target"])
    );
    assert_eq!(input["commands"], json!(["zulu.target", "alpha.target"]));

    results.insert(key(&second), json!({"value":"zulu.target"}));
    let input = selected.resolve_input(&results).unwrap();
    assert_eq!(input["dependencies"], json!(["zulu.target"]));
    assert_eq!(input["commands"], json!(["zulu.target", "zulu.target"]));
    assert!(
        selected
            .check_input(&json!({
                "dependencies":["zulu.target", "alpha.target"], "commands":[]
            }))
            .is_err()
    );
}

#[test]
fn contract_errors_locate_nested_values_without_disclosing_them() {
    let mut declaration = effect("metadata");
    let record = json!({"kind":"submodule", "fields":{
        "facts":{"kind":"submodule", "fields":{"name":{"kind":"string"}}}
    }});
    declaration["input_type"] = record.clone();
    declaration["input"] = json!({"facts":{"name":"valid"}});
    declaration["results"]["value"] = record;
    let node_key = key(&declaration);
    let checked = decode(&document(vec![declaration])).unwrap();
    let node = &checked.graph().nodes[&node_key];
    let invalid = json!({"facts":{"name":"private-value", "extra":"private-extra"}});

    let input_error = format!("{:#}", node.check_input(&invalid).unwrap_err());
    let result_error = format!(
        "{:#}",
        node.check_results(&json!({"value":invalid})).unwrap_err()
    );

    assert!(input_error.contains("input of effect"));
    assert!(result_error.contains("result value of effect"));
    for error in [input_error, result_error] {
        assert!(error.contains("metadata"));
        assert!(error.contains("field facts"));
        assert!(error.contains("record field count 2"));
        assert!(!error.contains("private-value"));
        assert!(!error.contains("private-extra"));
    }
}
