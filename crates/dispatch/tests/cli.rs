//! Checks machine-readable commands and stable failure categories end to end.

#![cfg(feature = "cli")]
#![allow(clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples/fixtures")
        .join(name)
}

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_dispatch"))
}

#[test]
fn compare_emits_one_json_document_with_meaningful_changes() {
    let output = command()
        .arg("compare")
        .arg("--problem")
        .arg(fixture("packing.problem.json"))
        .arg("--before")
        .arg(fixture("packing.before.json"))
        .arg("--after")
        .arg(fixture("packing.after.json"))
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let comparison: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(comparison["objective_ordering"], "better");
    assert_eq!(comparison["binding_changes"][0]["item"], "y");
}

#[test]
fn malformed_json_has_input_exit_status_and_separate_diagnostics() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("malformed.json");
    std::fs::write(&input, b"{").unwrap();

    let output = command()
        .arg("validate")
        .arg("--problem")
        .arg(&input)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let diagnostic: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(diagnostic["error"]["category"], "invalid_input");
}

#[test]
fn duplicate_keys_are_rejected_instead_of_overwritten() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("duplicate.json");
    std::fs::write(&input, b"{\"model_version\":\"1\",\"model_version\":\"1\"}").unwrap();

    let output = command()
        .arg("validate")
        .arg("--problem")
        .arg(&input)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let diagnostic: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert!(
        diagnostic["error"]["message"]
            .as_str()
            .unwrap()
            .contains("duplicate")
    );
}

#[test]
fn output_file_keeps_stdout_empty_and_contains_validated_model() {
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("validated.json");

    let output = command()
        .arg("validate")
        .arg("--problem")
        .arg(fixture("packing.problem.json"))
        .arg("--output")
        .arg(&destination)
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    let model: dispatch::Problem =
        serde_json::from_slice(&std::fs::read(destination).unwrap()).unwrap();
    assert_eq!(model.model_version, 1);
    assert_eq!(model.items.len(), 2);
}

#[test]
fn input_bound_is_checked_before_decoding() {
    let output = command()
        .arg("validate")
        .arg("--max-input-bytes")
        .arg("8")
        .arg("--problem")
        .arg(fixture("packing.problem.json"))
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}

#[test]
fn solve_requires_explicit_profile_and_executable_selection() {
    let output = command()
        .env_remove("DISPATCH_WORKER")
        .env_remove("DISPATCH_BACKEND")
        .arg("solve")
        .arg("--problem")
        .arg(fixture("packing.problem.json"))
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}

#[test]
fn unsupported_model_version_has_a_capability_exit_status() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("future.json");
    let mut problem: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture("packing.problem.json")).unwrap()).unwrap();
    problem["model_version"] = serde_json::Value::String("2".into());
    std::fs::write(&input, serde_json::to_vec(&problem).unwrap()).unwrap();

    let output = command()
        .arg("validate")
        .arg("--problem")
        .arg(&input)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3));
    let diagnostic: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(diagnostic["error"]["category"], "unsupported");
}

#[test]
fn evaluation_reports_constraint_failure_and_verification_rejects_it() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("limited.json");
    let mut problem: dispatch::Problem =
        serde_json::from_slice(&std::fs::read(fixture("packing.problem.json")).unwrap()).unwrap();
    if let dispatch::ConstraintRule::Capacity { limit, .. } = &mut problem.constraints[0].rule {
        *limit = dispatch::Quantity::new(1);
    }
    std::fs::write(&input, serde_json::to_vec(&problem).unwrap()).unwrap();

    let evaluation = command()
        .arg("evaluate")
        .arg("--problem")
        .arg(&input)
        .arg("--assignment")
        .arg(fixture("packing.after.json"))
        .output()
        .unwrap();
    let verification = command()
        .arg("verify")
        .arg("--problem")
        .arg(&input)
        .arg("--assignment")
        .arg(fixture("packing.after.json"))
        .output()
        .unwrap();

    assert!(evaluation.status.success());
    let evaluation: dispatch::Evaluation = serde_json::from_slice(&evaluation.stdout).unwrap();
    assert_eq!(evaluation.violations[0].component.constraint, "capacity-A");
    assert_eq!(verification.status.code(), Some(6));
    let verification: serde_json::Value = serde_json::from_slice(&verification.stdout).unwrap();
    assert_eq!(verification["accepted"], false);
    assert_eq!(verification["classification"], serde_json::Value::Null);
}

#[test]
fn request_export_round_trips_exact_options_without_execution_configuration() {
    let output = command()
        .arg("request")
        .arg("--problem")
        .arg(fixture("packing.problem.json"))
        .arg("--deadline-ms")
        .arg("1234")
        .arg("--threads")
        .arg("2")
        .arg("--seed")
        .arg("18446744073709551615")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let request: dispatch::SolveRequest = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(request.options.wall_time_millis.get(), 1234);
    assert_eq!(request.options.threads.get(), 2);
    assert_eq!(request.options.seed.unwrap().get(), u64::MAX);
    assert_eq!(request.backend, "rebalancer");
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["request_version"], "1");
    assert_eq!(document["options"]["threads"], "2");
    assert!(document.get("runner").is_none());
    assert!(document.get("executable").is_none());
}

#[test]
fn request_import_rejects_search_overrides_before_starting_workers() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("request.json");
    let exported = command()
        .arg("request")
        .arg("--problem")
        .arg(fixture("packing.problem.json"))
        .arg("--output")
        .arg(&input)
        .output()
        .unwrap();
    assert!(exported.status.success());

    let output = command()
        .arg("solve")
        .arg("--request")
        .arg(&input)
        .arg("--profile")
        .arg("warm")
        .arg("--runner")
        .arg("unavailable-worker")
        .arg("--backend")
        .arg("unavailable-backend")
        .arg("--threads")
        .arg("2")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let diagnostic: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert!(
        diagnostic["error"]["message"]
            .as_str()
            .unwrap()
            .contains("cannot override")
    );
}

#[test]
fn unsupported_request_controls_are_rejected_before_execution() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("request.json");
    let problem: dispatch::Problem =
        serde_json::from_slice(&std::fs::read(fixture("packing.problem.json")).unwrap()).unwrap();
    let options = dispatch::SearchRequestOptions {
        memory_bytes: dispatch::Quantity::new(4096),
        ..dispatch::SearchRequestOptions::default()
    };
    let request = dispatch::SolveRequest::new(problem, options, None);
    std::fs::write(&input, serde_json::to_vec(&request).unwrap()).unwrap();

    let output = command()
        .arg("solve")
        .arg("--request")
        .arg(&input)
        .arg("--profile")
        .arg("fresh")
        .arg("--runner")
        .arg("unavailable-worker")
        .arg("--backend")
        .arg("unavailable-backend")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    let diagnostic: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(diagnostic["error"]["category"], "unsupported");
}

#[test]
fn exported_hint_preserves_the_observed_movement_baseline() {
    let output = command()
        .arg("request")
        .arg("--problem")
        .arg(fixture("packing.problem.json"))
        .arg("--hint")
        .arg(fixture("packing.after.json"))
        .output()
        .unwrap();

    assert!(output.status.success());
    let request: dispatch::SolveRequest = serde_json::from_slice(&output.stdout).unwrap();
    let original: dispatch::Problem =
        serde_json::from_slice(&std::fs::read(fixture("packing.problem.json")).unwrap()).unwrap();
    let hint: dispatch::Assignment =
        serde_json::from_slice(&std::fs::read(fixture("packing.after.json")).unwrap()).unwrap();

    assert_eq!(request.problem.observed, original.observed);
    assert_eq!(request.hint, Some(hint));
}

#[test]
fn unsupported_request_version_is_rejected_before_worker_startup() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("future-request.json");
    let problem: dispatch::Problem =
        serde_json::from_slice(&std::fs::read(fixture("packing.problem.json")).unwrap()).unwrap();
    let mut request =
        dispatch::SolveRequest::new(problem, dispatch::SearchRequestOptions::default(), None);
    request.request_version = dispatch::Quantity::new(2);
    std::fs::write(&input, serde_json::to_vec(&request).unwrap()).unwrap();

    let output = command()
        .arg("solve")
        .arg("--request")
        .arg(&input)
        .arg("--profile")
        .arg("fresh")
        .arg("--runner")
        .arg("unavailable-worker")
        .arg("--backend")
        .arg("unavailable-backend")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    let diagnostic: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(diagnostic["error"]["category"], "unsupported");
}
