//! Process tests for native declarations and desired transaction inspection.

use aos_contract::Sha256Digest;
use serde_json::{Value, json};
use std::path::Path;
use std::process::{Command, Output};

fn reference(description: &str) -> Value {
    json!({"schema":"aos.module.documentation","scope":["package","sample"],"system":"x86_64-linux",
        "packages":[{"name":"sample","version":"1"}],"options":[{"path":["aos","sample","enable"],"owner":"sample","description":description,
            "type":{"kind":"bool"},"visibility":"public","readOnly":false,"extensible":false}],"abilities":{}})
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

#[test]
fn native_json_mode_and_html_use_the_shared_reference_reader() {
    let directory = tempfile::tempdir().unwrap();
    let document = reference("Enable <sample>.");
    std::fs::write(
        directory.path().join("options.json"),
        serde_json::to_vec(&document).unwrap(),
    )
    .unwrap();

    let output = run(
        directory.path(),
        &["--json", "ability", "inspect", "options.json"],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        document
    );
    let html = run(
        directory.path(),
        &["ability", "inspect", "options.json", "--format", "html"],
    );
    assert!(html.status.success());
    assert!(
        String::from_utf8(html.stdout)
            .unwrap()
            .contains("&lt;sample&gt;")
    );
}

#[test]
fn exact_digest_check_precedes_native_rendering() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("options.json"),
        serde_json::to_vec(&reference("sample")).unwrap(),
    )
    .unwrap();
    let digest = Sha256Digest::of_bytes("different bytes").to_string();

    let output = run(
        directory.path(),
        &[
            "ability",
            "inspect",
            "options.json",
            "--expected-digest",
            &digest,
        ],
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("independent digest")
    );
}

#[test]
fn native_comparison_excludes_prose_and_preserves_literal_path_segments() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("before.json"),
        serde_json::to_vec(&reference("before")).unwrap(),
    )
    .unwrap();
    std::fs::write(
        directory.path().join("prose.json"),
        serde_json::to_vec(&reference("after")).unwrap(),
    )
    .unwrap();
    let prose = run(
        directory.path(),
        &["ability", "compare", "before.json", "prose.json"],
    );
    assert!(prose.status.success());
    let prose_comparison: Value = serde_json::from_slice(&prose.stdout).unwrap();
    assert_eq!(prose_comparison["options"]["added"], json!([]));
    assert_eq!(prose_comparison["options"]["removed"], json!([]));
    assert_eq!(prose_comparison["options"]["changed"], json!([]));

    let mut after = reference("after");
    after["packages"][0]["version"] = json!("2");
    after["options"][0]["path"] = json!(["aos", "sample.enable"]);
    std::fs::write(
        directory.path().join("after.json"),
        serde_json::to_vec(&after).unwrap(),
    )
    .unwrap();

    let output = run(
        directory.path(),
        &["ability", "compare", "before.json", "after.json"],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let comparison: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        comparison["options"]["added"],
        json!([["aos", "sample.enable"]])
    );
    assert_eq!(
        comparison["options"]["removed"],
        json!([["aos", "sample", "enable"]])
    );
}

#[test]
fn diagnostic_requires_a_committed_native_profile() {
    let directory = tempfile::tempdir().unwrap();
    let output = run(directory.path(), &["ability", "diagnostic", ".", "1"]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("committed profile deployment journals are absent or incomplete")
    );
}

#[test]
fn retired_provider_plan_input_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("old.json"),
        br#"{"schema":"aos.ability-inspection-bundle/v1"}"#,
    )
    .unwrap();
    let output = run(directory.path(), &["ability", "inspect", "old.json"]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn journal_inspection_is_checked_and_read_only() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("activation.journal");
    let activation = aos_ability_runtime::activation::Activation::open(
        &path,
        aos_ability_runtime::journal::JournalLimits::default(),
    )
    .unwrap();
    drop(activation);
    let before = std::fs::read(&path).unwrap();

    let output = run(
        directory.path(),
        &[
            "ability",
            "journal",
            "activation.journal",
            "--format",
            "json",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let inspection: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(inspection["schema"], "aos.activation.inspection");
    assert_eq!(inspection["liveStateVerified"], false);
    assert_eq!(inspection["records"], json!([]));
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
