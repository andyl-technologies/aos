//! Runtime contract checks for merged records, refinements, and deferred leaves.

use serde_json::json;

use super::*;

fn schema(value: Value) -> OptionType {
    serde_json::from_value(value).unwrap()
}

#[test]
fn concrete_records_require_fields_and_check_present_optional_values() {
    let submodule = schema(json!({
        "kind":"submodule", "fields":{"name":{"kind":"string"}}
    }));
    assert!(check_concrete(&json!({"name":"ok"}), &submodule).is_ok());
    assert!(check_concrete(&json!({}), &submodule).is_err());

    let optional = schema(json!({
        "kind":"document-record", "key_max_length":32,
        "fields":{"name":{"kind":"string"}}, "optional_fields":["name"]
    }));
    assert!(check_concrete(&json!({}), &optional).is_ok());
    assert!(check_concrete(&json!({"name":42}), &optional).is_err());
    assert!(!optional.admits(&AbilityValue::new(json!({"name":42})).unwrap()));
}

#[test]
fn merged_record_refinements_reject_overlapping_values() {
    let policy = schema(json!({
        "kind":"refined",
        "value":{"kind":"submodule","fields":{
            "allow":{"kind":"list","element":{"kind":"string"}},
            "deny":{"kind":"list","element":{"kind":"string"}}
        }},
        "constraints":[{"kind":"disjoint-at","left":["allow"],"right":["deny"]}]
    }));
    assert!(check_type(&policy).is_ok());
    assert!(check_concrete(&json!({"allow":["read"],"deny":["write"]}), &policy).is_ok());
    assert!(check_concrete(&json!({"allow":["read"],"deny":["read"]}), &policy).is_err());
}

#[test]
fn json_preserves_nested_deferred_dependencies_and_rechecks_values() {
    let identity = vec!["test".into(), "producer".into(), "path".into()];
    let key = identity_key(&identity).unwrap();
    let text = schema(json!({"kind":"string"}));
    let producer = serde_json::from_value(json!({
        "owner":"test", "identity":identity, "input":{}, "inputs":{},
        "input_type":{"kind":"submodule","fields":{}}, "after":[],
        "results":{"path":text}, "handler":{"kind":"process",
            "artifact":"/nix/store/00000000000000000000000000000000-handler",
            "executable":"/nix/store/00000000000000000000000000000000-handler/bin/run"},
        "dependencies":[],"revision":"unused","lifetime":"instance","timeout_ms":1000
    }))
    .unwrap();
    let graph = ModuleGraph {
        schema: "aos.activation.graph".into(),
        nodes: [(key.clone(), producer)].into(),
        order: vec![key.clone()],
    };
    let reference =
        json!({"_type":"aos-effect-output","identity":identity,"output":"path","schema":text});
    let value = json!({"nested":[true, reference]});
    let mut dependencies = BTreeSet::new();

    check_input(&value, &OptionType::Json, &graph, &mut dependencies).unwrap();
    assert_eq!(dependencies, [key.clone()].into());
    assert!(check_concrete(&value, &OptionType::Json).is_err());
    let resolved =
        crate::module_graph::resolve(&value, &[(key, json!({"path":"/state"}))].into()).unwrap();
    assert!(check_concrete(&resolved, &OptionType::Json).is_ok());
    assert_eq!(resolved, json!({"nested":[true,"/state"]}));
}

#[test]
fn nullable_references_preserve_the_producer_type() {
    let text = schema(json!({"kind":"string"}));
    let nullable = OptionType::Nullable {
        value: Box::new(text.clone()),
    };
    assert!(reference_fits(&text, &nullable));
    assert!(!reference_fits(&OptionType::Bool, &nullable));
}
