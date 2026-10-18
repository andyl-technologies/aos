//! Process tests for the release-owner structural compatibility gate.

use serde_json::{Value, json};
use std::path::Path;
use std::process::{Command, Output};

fn reference(version: &str) -> Value {
    json!({
        "schema": "aos.module.documentation",
        "scope": ["package", "sample"],
        "system": "x86_64-linux",
        "packages": [{"name": "sample", "version": version}],
        "options": [{
            "path": ["aos", "sample", "enable"],
            "owner": "sample",
            "description": "Enable the sample feature.",
            "type": {"kind": "bool"},
            "visibility": "public",
            "readOnly": false,
            "extensible": false
        }],
        "abilities": {}
    })
}

fn write(directory: &Path, name: &str, document: &Value) {
    std::fs::write(directory.join(name), serde_json::to_vec(document).unwrap()).unwrap();
}

fn run(directory: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_aos"))
        .args(arguments)
        .current_dir(directory)
        .env_clear()
        .env("HOME", directory)
        .output()
        .unwrap()
}

fn check(directory: &Path, extra: &[&str]) -> Output {
    let mut arguments = vec![
        "--json",
        "ability",
        "check-compat",
        "before.json",
        "after.json",
        "--owner",
        "sample",
    ];
    arguments.extend(extra);
    run(directory, &arguments)
}

#[test]
fn compatible_prose_change_emits_one_json_report() {
    let directory = tempfile::tempdir().unwrap();
    let mut after = reference("1.1.0");
    after["options"][0]["description"] = json!("Updated explanation.");
    write(directory.path(), "before.json", &reference("1.0.0"));
    write(directory.path(), "after.json", &after);

    let output = check(directory.path(), &[]);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["compatible"], true);
    assert_eq!(report["compatibility_boundary"], false);
    assert_eq!(report["changes"], json!([]));
}

#[test]
fn incompatible_removal_emits_report_and_nonzero_status_without_second_json() {
    let directory = tempfile::tempdir().unwrap();
    let mut after = reference("1.1.0");
    after["options"] = json!([]);
    write(directory.path(), "before.json", &reference("1.0.0"));
    write(directory.path(), "after.json", &after);

    let output = check(directory.path(), &[]);

    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["compatible"], false);
    assert_eq!(report["changes"].as_array().unwrap().len(), 1);
    assert_eq!(report["changes"][0]["waived"], false);
    assert!(
        report["changes"][0]["reason"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty())
    );
    assert_eq!(
        report["changes"][0]["path"],
        json!(["aos", "sample", "enable"])
    );
}

#[test]
fn major_package_release_accepts_structural_removal() {
    let directory = tempfile::tempdir().unwrap();
    let mut after = reference("2.0.0");
    after["options"] = json!([]);
    write(directory.path(), "before.json", &reference("1.0.0"));
    write(directory.path(), "after.json", &after);

    let output = check(directory.path(), &[]);

    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["compatible"], true);
    assert_eq!(report["compatibility_boundary"], true);
}

#[test]
fn os_selection_uses_the_os_release_instead_of_package_versions() {
    let directory = tempfile::tempdir().unwrap();
    let mut before = reference("7.0.0");
    before["scope"] = json!(["profile", "system"]);
    before["osRelease"] = json!({"name": "aos", "version": "1.0.0"});
    before["options"][0]["owner"] = json!("@base");
    let mut after = before.clone();
    after["osRelease"]["version"] = json!("2.0.0");
    after["options"] = json!([]);
    write(directory.path(), "before.json", &before);
    write(directory.path(), "after.json", &after);

    let output = run(
        directory.path(),
        &[
            "--json",
            "ability",
            "check-compat",
            "before.json",
            "after.json",
            "--os",
        ],
    );

    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["compatible"], true);
    assert_eq!(report["compatibility_boundary"], true);
}

#[test]
fn previous_tilde_requirement_accepts_a_breaking_minor_release() {
    let directory = tempfile::tempdir().unwrap();
    let mut before = reference("1.0.0");
    before["packages"][0]["versionRequirement"] = json!("~1.0.0");
    let mut after = reference("1.1.0");
    after["options"] = json!([]);
    write(directory.path(), "before.json", &before);
    write(directory.path(), "after.json", &after);

    let output = check(directory.path(), &[]);

    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["compatible"], true);
    assert_eq!(report["compatibility_boundary"], true);
    assert_eq!(report["changes"].as_array().unwrap().len(), 1);
}

#[test]
fn next_release_policy_cannot_relax_previous_consumers_requirement() {
    let directory = tempfile::tempdir().unwrap();
    let mut before = reference("1.0.0");
    before["packages"][0]["versionRequirement"] = json!("^1.0.0");
    let mut after = reference("1.1.0");
    after["packages"][0]["versionRequirement"] = json!("=1.1.0");
    after["options"] = json!([]);
    write(directory.path(), "before.json", &before);
    write(directory.path(), "after.json", &after);

    let output = check(directory.path(), &[]);

    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["compatible"], false);
    assert_eq!(report["compatibility_boundary"], false);
}

#[test]
fn exact_reasoned_exception_waives_only_the_identified_change() {
    let directory = tempfile::tempdir().unwrap();
    let mut after = reference("1.1.0");
    after["options"] = json!([]);
    write(directory.path(), "before.json", &reference("1.0.0"));
    write(directory.path(), "after.json", &after);
    let rejected: Value = serde_json::from_slice(&check(directory.path(), &[]).stdout).unwrap();
    let id = rejected["changes"][0]["id"].as_str().unwrap();
    write(
        directory.path(),
        "exceptions.json",
        &json!([{"id": id, "reason": "The removed option has no supported consumers."}]),
    );

    let output = check(directory.path(), &["--exceptions", "exceptions.json"]);

    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["compatible"], true);
    assert_eq!(report["changes"][0]["waived"], true);

    write(directory.path(), "after.json", &reference("1.1.0"));
    assert!(
        !check(directory.path(), &["--exceptions", "exceptions.json"])
            .status
            .success()
    );
}

#[test]
fn human_diagnostics_include_exact_change_id_and_path() {
    let directory = tempfile::tempdir().unwrap();
    let mut after = reference("1.1.0");
    after["options"] = json!([]);
    write(directory.path(), "before.json", &reference("1.0.0"));
    write(directory.path(), "after.json", &after);
    let report: Value = serde_json::from_slice(&check(directory.path(), &[]).stdout).unwrap();

    let output = run(
        directory.path(),
        &[
            "ability",
            "check-compat",
            "before.json",
            "after.json",
            "--owner",
            "sample",
        ],
    );

    assert!(!output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Incompatible release interface"));
    assert!(text.contains(report["changes"][0]["id"].as_str().unwrap()));
    assert!(text.contains("\"aos\".\"sample\".\"enable\""));
}

#[test]
fn release_owner_selection_is_required_and_mutually_exclusive() {
    let directory = tempfile::tempdir().unwrap();

    for extra in [vec![], vec!["--owner", "sample", "--os"]] {
        let mut arguments = vec!["ability", "check-compat", "before.json", "after.json"];
        arguments.extend(extra);
        let output = run(directory.path(), &arguments);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn oversized_exception_file_is_rejected_before_comparison() {
    let directory = tempfile::tempdir().unwrap();
    write(directory.path(), "before.json", &reference("1.0.0"));
    write(directory.path(), "after.json", &reference("1.1.0"));
    std::fs::File::create(directory.path().join("exceptions.json"))
        .unwrap()
        .set_len(64 * 1024 + 1)
        .unwrap();

    let output = check(directory.path(), &["--exceptions", "exceptions.json"]);

    assert!(!output.status.success());
    let error: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(error["error"].as_str().unwrap().contains("byte limit"));
}
