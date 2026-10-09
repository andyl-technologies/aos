//! Exercises release-owned structural compatibility and exact review exceptions.

use super::*;

fn fixture() -> Value {
    let source = |owner: &str| json!({"owner":owner,"file":"module.nix","priority":100,"provenance":"package"});
    json!({
        "schema":"aos.module.documentation", "scope":["package","interfaces"],
        "system":"x86_64-linux", "packages":[{"name":"interfaces","version":"1.0.0"}],
        "osRelease":{"name":"aos","version":"1.0.0"},
        "options":[{"path":["settings","message"],"owner":"interfaces",
            "description":"Message settings", "type":{"kind":"string"},
            "visibility":"public", "readOnly":false,"extensible":false,"hasDefault":true}],
        "abilities":{"echo":{"run":{
            "input":{},"result":{},
            "inputType":{"kind":"submodule","fields":{"message":{"kind":"string"}},"open":false},
            "inputDefaults":[["message"]],
            "resultType":{"kind":"submodule","fields":{"value":{"kind":"string"}},"open":false},
            "handlerAvailable":false,"configuredEffects":[],
            "sources":{"input":[source("interfaces")],"result":[source("interfaces")],
                "handler":[],"effects":[]}
        }}}
    })
}

fn document(value: &Value) -> RuntimeDocument {
    RuntimeDocument::from_json(&serde_json::to_vec(value).unwrap()).unwrap()
}

fn check(before: &Value, after: &Value) -> CompatibilityReport {
    check_compatibility(
        &document(before),
        &document(after),
        &ReleaseOwner::Package("interfaces".into()),
        &[],
    )
    .unwrap()
}

fn operation(value: &mut Value) -> &mut Value {
    &mut value["abilities"]["echo"]["run"]
}

#[test]
fn new_input_fields_require_defaults() {
    let before = fixture();
    let mut after = before.clone();
    operation(&mut after)["inputType"]["fields"]["enabled"] = json!({"kind":"bool"});
    let report = check(&before, &after);
    assert!(!report.compatible);
    assert_eq!(report.changes.len(), 1);
    assert_eq!(report.changes[0].reason, "required input field added");
    assert_eq!(report.changes[0].path.last().unwrap(), "enabled");

    operation(&mut after)["inputDefaults"] = json!([["message"], ["enabled"]]);
    assert!(check(&before, &after).compatible);
}

#[test]
fn removed_inputs_defaults_and_changed_refinements_require_review() {
    let before = fixture();
    let mut removed = before.clone();
    operation(&mut removed)["inputType"]["fields"] = json!({});
    assert!(
        check(&before, &removed)
            .changes
            .iter()
            .any(|change| change.reason == "field removed")
    );

    let mut default_removed = before.clone();
    operation(&mut default_removed)["inputDefaults"] = json!([]);
    let report = check(&before, &default_removed);
    assert!(!report.compatible);
    assert_eq!(report.changes[0].reason, "input default removed");

    let mut refinement = before.clone();
    operation(&mut refinement)["inputType"]["fields"]["message"] =
        json!({"kind":"string","max_length":8});
    assert!(!check(&before, &refinement).compatible);
}

#[test]
fn closed_result_additions_require_review_but_open_result_additions_are_safe() {
    let before = fixture();
    let mut after = before.clone();
    operation(&mut after)["resultType"]["fields"]["extra"] = json!({"kind":"bool"});
    let report = check(&before, &after);
    assert!(!report.compatible);
    assert_eq!(
        report.changes[0].reason,
        "field added to closed result record"
    );

    let mut before = before;
    operation(&mut before)["resultType"]["open"] = json!(true);
    operation(&mut after)["resultType"]["open"] = json!(true);
    assert!(check(&before, &after).compatible);
}

#[test]
fn removed_operations_require_review_and_new_operations_are_safe() {
    let before = fixture();
    let mut removed = before.clone();
    removed["abilities"]["echo"] = json!({});
    let report = check(&before, &removed);
    assert!(!report.compatible);
    assert_eq!(
        report.changes[0].reason,
        "operation removed from release owner"
    );

    let mut added = before.clone();
    added["abilities"]["echo"]["extra"] = before["abilities"]["echo"]["run"].clone();
    assert!(check(&before, &added).compatible);
}

#[test]
fn package_checks_exclude_other_owners_hidden_options_and_handler_only_ownership() {
    let mut before = fixture();
    before["options"][0]["owner"] = json!("another-package");
    let sources = &mut operation(&mut before)["sources"];
    sources["input"][0]["owner"] = json!("another-package");
    sources["result"][0]["owner"] = json!("another-package");
    sources["handler"] =
        json!([{"owner":"interfaces","file":"handler.nix","priority":100,"provenance":"package"}]);
    let mut after = before.clone();
    after["options"] = json!([]);
    after["abilities"] = json!({});
    assert!(check(&before, &after).compatible);

    let mut before = fixture();
    before["options"][0]["visibility"] = json!("hidden");
    let mut after = before.clone();
    after["options"] = json!([]);
    assert!(check(&before, &after).compatible);
}

#[test]
fn os_checks_only_base_owned_interfaces() {
    let mut before = fixture();
    before["options"][0]["owner"] = json!("@base");
    let mut after = before.clone();
    after["options"] = json!([]);
    assert!(check(&before, &after).compatible);
    let report = check_compatibility(
        &document(&before),
        &document(&after),
        &ReleaseOwner::Os,
        &[],
    )
    .unwrap();
    assert!(!report.compatible);
    assert_eq!(report.changes[0].reason, "public option removed");
}

#[test]
fn changed_opaque_types_require_review() {
    let mut before = fixture();
    before["options"][0]["type"] = json!({"kind":"opaque","signature":"provider-v1"});
    let mut after = before.clone();
    after["options"][0]["type"]["signature"] = json!("provider-v2");
    let report = check(&before, &after);
    assert!(!report.compatible);
    assert!(report.changes[0].reason.contains("requires review"));
}

#[test]
fn prose_handler_selection_and_default_order_do_not_change_interface_snapshot() {
    let mut before = fixture();
    operation(&mut before)["inputType"]["fields"]["enabled"] = json!({"kind":"bool"});
    operation(&mut before)["inputDefaults"] = json!([["message"], ["enabled"]]);
    let mut after = before.clone();
    after["options"][0]["description"] = json!("Revised description");
    operation(&mut after)["handlerAvailable"] = json!(true);
    operation(&mut after)["configuredEffects"] = json!(["configured"]);
    assert!(check(&before, &after).compatible);

    after["options"] = json!([]);
    let original = check(&before, &after);
    let mut prose = after.clone();
    operation(&mut prose)["sources"]["input"][0]["file"] = json!("renamed.nix");
    operation(&mut prose)["inputDefaults"] = json!([["enabled"], ["message"]]);
    assert_eq!(original.changes[0].id, check(&before, &prose).changes[0].id);
}

#[test]
fn option_addition_with_default_is_safe_and_default_removal_is_not() {
    let before = fixture();
    let mut after = before.clone();
    let mut added = after["options"][0].clone();
    added["path"] = json!(["settings", "extra"]);
    after["options"].as_array_mut().unwrap().push(added);
    assert!(check(&before, &after).compatible);

    after["options"][1]["hasDefault"] = json!(false);
    assert_eq!(
        check(&before, &after).changes[0].reason,
        "required input option added"
    );
    let mut after = before.clone();
    after["options"][0]["hasDefault"] = json!(false);
    assert_eq!(
        check(&before, &after).changes[0].reason,
        "input default removed"
    );
}

#[test]
fn crossing_previous_compatibility_range_acknowledges_breaks_without_hiding_diagnostics() {
    let before = fixture();
    let mut after = before.clone();
    after["options"] = json!([]);
    after["packages"][0]["version"] = json!("2.0.0");
    let report = check(&before, &after);
    assert!(report.compatible);
    assert!(report.compatibility_boundary);
    assert_eq!(report.changes.len(), 1);
    assert!(!report.changes[0].waived);
}

#[test]
fn exceptions_are_bound_to_exact_structural_snapshots_and_release_versions() {
    let before = fixture();
    let mut after = before.clone();
    after["options"] = json!([]);
    let report = check(&before, &after);
    let exception = CompatibilityException {
        id: report.changes[0].id.clone(),
        reason: "Approved removal of obsolete setting".into(),
    };
    let owner = ReleaseOwner::Package("interfaces".into());
    let waived = check_compatibility(
        &document(&before),
        &document(&after),
        &owner,
        std::slice::from_ref(&exception),
    )
    .unwrap();
    assert!(waived.compatible);
    assert!(waived.changes[0].waived);

    let mut changed = after.clone();
    operation(&mut changed)["resultType"]["fields"]["extra"] = json!({"kind":"bool"});
    assert!(
        check_compatibility(
            &document(&before),
            &document(&changed),
            &owner,
            std::slice::from_ref(&exception)
        )
        .is_err()
    );
    after["packages"][0]["version"] = json!("1.1.0");
    assert!(
        check_compatibility(&document(&before), &document(&after), &owner, &[exception]).is_err()
    );
}

#[test]
fn invalid_exceptions_and_release_mismatches_fail_closed() {
    let before = fixture();
    let mut after = before.clone();
    after["options"] = json!([]);
    let id = check(&before, &after).changes[0].id.clone();
    let owner = ReleaseOwner::Package("interfaces".into());
    for exceptions in [
        vec![CompatibilityException {
            id: id.clone(),
            reason: " ".into(),
        }],
        vec![
            CompatibilityException {
                id: id.clone(),
                reason: "Reviewed".into()
            };
            2
        ],
        vec![CompatibilityException {
            id: "sha256:stale".into(),
            reason: "Reviewed".into(),
        }],
    ] {
        assert!(
            check_compatibility(&document(&before), &document(&after), &owner, &exceptions)
                .is_err()
        );
    }

    let mut after = before.clone();
    after["system"] = json!("aarch64-linux");
    assert!(check_compatibility(&document(&before), &document(&after), &owner, &[]).is_err());
    after = before.clone();
    after["packages"][0]["version"] = json!("0.9.0");
    assert!(check_compatibility(&document(&before), &document(&after), &owner, &[]).is_err());
    after = before.clone();
    after["osRelease"]["name"] = json!("another-os");
    assert!(
        check_compatibility(
            &document(&before),
            &document(&after),
            &ReleaseOwner::Os,
            &[]
        )
        .is_err()
    );
    after.as_object_mut().unwrap().remove("osRelease");
    assert!(
        check_compatibility(
            &document(&before),
            &document(&after),
            &ReleaseOwner::Os,
            &[]
        )
        .is_err()
    );
}

#[test]
fn duplicate_owner_identities_and_public_paths_are_rejected() {
    let before = fixture();
    let owner = ReleaseOwner::Package("interfaces".into());
    let mut after = before.clone();
    let identity = after["packages"][0].clone();
    after["packages"].as_array_mut().unwrap().push(identity);
    assert!(check_compatibility(&document(&before), &document(&after), &owner, &[]).is_err());

    let mut after = before.clone();
    let option = after["options"][0].clone();
    after["options"].as_array_mut().unwrap().push(option);
    assert!(check_compatibility(&document(&before), &document(&after), &owner, &[]).is_err());
}

#[test]
fn build_metadata_does_not_change_release_precedence() {
    let mut before = fixture();
    before["packages"][0]["version"] = json!("1.0.0+z");
    let mut after = before.clone();
    after["packages"][0]["version"] = json!("1.0.0+a");
    assert!(check(&before, &after).compatible);
}

#[test]
fn captured_tilde_policy_allows_breaks_at_minor_boundary_only() {
    let mut before = fixture();
    before["packages"][0]["version"] = json!("7.4.2");
    before["packages"][0]["versionRequirement"] = json!("~7.4.2");
    let mut after = before.clone();
    after["options"] = json!([]);
    after["packages"][0]["version"] = json!("7.4.3");
    after["packages"][0]["versionRequirement"] = json!("~7.4.3");
    let inside = check(&before, &after);
    assert!(!inside.compatible);
    assert!(!inside.compatibility_boundary);

    after["packages"][0]["version"] = json!("7.5.0");
    after["packages"][0]["versionRequirement"] = json!("~7.5.0");
    let outside = check(&before, &after);
    assert!(outside.compatible);
    assert!(outside.compatibility_boundary);
    assert_eq!(outside.changes.len(), 1);
}

#[test]
fn caret_zero_versions_preserve_minor_and_patch_compatibility_boundaries() {
    for (previous, inside, outside) in [
        ("0.4.2", "0.4.3", "0.5.0"),
        ("0.0.2", "0.0.2+rebuilt", "0.0.3"),
    ] {
        let mut before = fixture();
        before["packages"][0]["version"] = json!(previous);
        let mut after = before.clone();
        after["options"] = json!([]);
        after["packages"][0]["version"] = json!(inside);
        assert!(!check(&before, &after).compatible);
        after["packages"][0]["version"] = json!(outside);
        assert!(check(&before, &after).compatibility_boundary);
    }
}

#[test]
fn next_release_policy_cannot_relax_previous_consumers_range() {
    let mut before = fixture();
    before["packages"][0]["version"] = json!("7.4.2");
    before["packages"][0]["versionRequirement"] = json!("^7.4.2");
    let mut after = before.clone();
    after["options"] = json!([]);
    after["packages"][0]["version"] = json!("7.5.0");
    after["packages"][0]["versionRequirement"] = json!("=7.5.0");
    let report = check(&before, &after);
    assert!(!report.compatible);
    assert!(!report.compatibility_boundary);
}

#[test]
fn exact_policy_pins_semantic_version_without_pinning_build_artifact() {
    let mut before = fixture();
    before["packages"][0]["version"] = json!("7.4.2+old");
    before["packages"][0]["versionRequirement"] = json!("=7.4.2+old");
    let mut after = before.clone();
    after["options"] = json!([]);
    after["packages"][0]["version"] = json!("7.4.2+new");
    after["packages"][0]["versionRequirement"] = json!("=7.4.2+new");
    assert!(!check(&before, &after).compatibility_boundary);
    after["packages"][0]["version"] = json!("7.4.3");
    after["packages"][0]["versionRequirement"] = json!("=7.4.3");
    assert!(check(&before, &after).compatibility_boundary);
}

#[test]
fn os_zero_versions_use_caret_semantics_without_package_policy() {
    let mut before = fixture();
    before["options"][0]["owner"] = json!("@base");
    before["osRelease"]["version"] = json!("0.4.2");
    let mut after = before.clone();
    after["options"] = json!([]);
    after["osRelease"]["version"] = json!("0.5.0");
    let report = check_compatibility(
        &document(&before),
        &document(&after),
        &ReleaseOwner::Os,
        &[],
    )
    .unwrap();
    assert!(report.compatible);
    assert!(report.compatibility_boundary);
}

#[test]
fn captured_previous_policy_is_part_of_exception_snapshot() {
    let mut before = fixture();
    before["packages"][0]["versionRequirement"] = json!("^1.0.0");
    let mut after = before.clone();
    after["options"] = json!([]);
    let exception = CompatibilityException {
        id: check(&before, &after).changes[0].id.clone(),
        reason: "Approved for this exact release policy".into(),
    };
    before["packages"][0]["versionRequirement"] = json!("~1.0.0");
    assert!(
        check_compatibility(
            &document(&before),
            &document(&after),
            &ReleaseOwner::Package("interfaces".into()),
            &[exception]
        )
        .is_err()
    );
}
