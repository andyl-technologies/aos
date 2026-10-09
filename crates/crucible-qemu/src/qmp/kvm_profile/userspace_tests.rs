//! Partial inventory wire models; these cases do not execute or qualify KVM.

// crucible-lint: allow rust-allow -- closed model response assertions deliberately panic on failure.
#![allow(clippy::unwrap_used)]

use super::*;
use serde_json::json;

fn inventory() -> serde_json::Value {
    json!({
        "schema-version": 1, "capacity": 2, "revision": 7, "faulted": false,
        "exits": [{
            "vcpu-index": 0, "kernel-vcpu-id": 42, "exit-sequence": 1, "consumed-sequence": 0,
            "exit-reason": 2, "phase": "pending", "opaque-effects": false,
            "uncertain-effects": false,
        }],
        "device-closure": false, "input-custody": false,
        "output-custody": false, "profile-qualified": false,
    })
}

#[test]
fn query_is_disjoint_and_cannot_run_or_clear_an_original_response() {
    let command = QmpCommand::KvmUserspaceExits;
    assert_eq!(command.kind(), QmpCommandKind::KvmUserspaceExits);
    assert_eq!(
        command.request(),
        json!({"execute":"x-crucible-kvm-userspace-exits"})
    );
    assert!(
        parse_userspace_inventory(&inventory())
            .unwrap()
            .requires_retained_exit_custody()
    );
}

#[test]
fn unknown_completion_and_opaque_history_remain_in_custody() {
    let mut value = inventory();
    value["exits"][0]["phase"] = json!("unknown");
    value["exits"][0]["uncertain-effects"] = json!(true);
    assert!(
        parse_userspace_inventory(&value)
            .unwrap()
            .requires_retained_exit_custody()
    );
    value["exits"][0]["consumed-sequence"] = json!(1);
    value["exits"][0]["phase"] = json!("ready");
    assert!(
        parse_userspace_inventory(&value)
            .unwrap()
            .requires_retained_exit_custody()
    );
    value["exits"][0]["uncertain-effects"] = json!(false);
    assert!(
        !parse_userspace_inventory(&value)
            .unwrap()
            .requires_retained_exit_custody()
    );
    value["exits"][0]["opaque-effects"] = json!(true);
    assert!(
        parse_userspace_inventory(&value)
            .unwrap()
            .requires_retained_exit_custody()
    );
    value["exits"][0]["opaque-effects"] = json!(false);
    value["faulted"] = json!(true);
    assert!(
        parse_userspace_inventory(&value)
            .unwrap()
            .requires_retained_exit_custody()
    );
}

#[test]
fn complete_domain_and_unknown_schema_claims_are_refused() {
    for field in [
        "device-closure",
        "input-custody",
        "output-custody",
        "profile-qualified",
    ] {
        let mut value = inventory();
        value[field] = json!(true);
        assert!(parse_userspace_inventory(&value).is_err(), "{field}");
    }
    let mut value = inventory();
    value["schema-version"] = json!(3);
    assert!(parse_userspace_inventory(&value).is_err());
    value = inventory();
    value["invented-native-stop"] = json!(true);
    assert!(parse_userspace_inventory(&value).is_err());
}

#[test]
fn original_response_and_roster_inconsistencies_are_refused() {
    for patch in [
        json!({"consumed-sequence":2}),
        json!({"exit-sequence":2}),
        json!({"phase":"ready"}),
        json!({"exit-reason":5}),
        json!({"vcpu-index":2}),
        json!({"phase":"unsupported"}),
        json!({"phase":"invented"}),
        json!({"unknown-field":true}),
    ] {
        let mut value = inventory();
        for (key, replacement) in patch.as_object().unwrap() {
            value["exits"][0][key] = replacement.clone();
        }
        assert!(parse_userspace_inventory(&value).is_err(), "{patch}");
    }
    let mut value = inventory();
    let duplicate = value["exits"][0].clone();
    value["exits"].as_array_mut().unwrap().push(duplicate);
    assert!(parse_userspace_inventory(&value).is_err());
    value["exits"][1]["vcpu-index"] = json!(1);
    assert!(parse_userspace_inventory(&value).is_err());
    value["exits"][1]["kernel-vcpu-id"] = json!(43);
    assert!(parse_userspace_inventory(&value).is_ok());
    value["exits"].as_array_mut().unwrap().swap(0, 1);
    assert!(parse_userspace_inventory(&value).is_err());
}

#[test]
fn finite_preallocated_roster_limits_are_preserved() {
    for capacity in [0, 4097] {
        let mut value = inventory();
        value["capacity"] = json!(capacity);
        assert!(parse_userspace_inventory(&value).is_err());
    }
    let mut value = inventory();
    value["exits"] = json!(vec![value["exits"][0].clone(); 4097]);
    assert!(parse_userspace_inventory(&value).is_err());
    value = inventory();
    value["revision"] = json!(0);
    assert!(parse_userspace_inventory(&value).is_err());
}
