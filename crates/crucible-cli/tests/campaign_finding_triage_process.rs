//! Executable-process acceptance for authenticated campaign Finding triage.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde::Deserialize;
use serde_json::Value;
use tempfile::TempDir;

#[derive(Deserialize)]
struct FindingTriageFixtureReport {
    schema: String,
    findings: PathBuf,
    store: PathBuf,
    proof_mutation: PathBuf,
    payload_mutation: PathBuf,
    original_artifact: String,
    minimized_artifact: String,
}

#[test]
fn public_cli_authenticates_and_triages_campaign_finding_v4() -> Result<(), Box<dyn Error>> {
    let temporary = TempDir::new()?;
    let fixture_directory = temporary.path().join("fixture");
    let generated = Command::new(env!("CARGO_BIN_EXE_crucible"))
        .args(["--format", "jsonl", "campaign", "fixture", "finding-triage"])
        .arg("--output")
        .arg(&fixture_directory)
        .output()?;
    assert_success("generate campaign Finding fixture", &generated);
    let fixture: FindingTriageFixtureReport = serde_json::from_slice(&generated.stdout)?;
    assert_eq!(
        fixture.schema,
        "crucible.cli.campaign-finding-triage-fixture.v1"
    );

    let artifact_directory = temporary.path().join("artifacts");
    let report_directory = temporary.path().join("reports");
    let triaged = run_triage(
        &fixture.store,
        &artifact_directory,
        &report_directory,
        &fixture.findings,
    )?;
    assert_success("triage authenticated campaign Finding", &triaged);
    let stdout = String::from_utf8(triaged.stdout)?;
    for expected in [
        "findings_count=1",
        "policy=exact",
        "minimize=all",
        "clusters=1",
    ] {
        assert!(
            stdout.contains(expected),
            "triage stdout is missing `{expected}`: {stdout}"
        );
    }

    let report: Value =
        serde_json::from_slice(&fs::read(report_directory.join("triage-report.jsonl"))?)?;
    assert_eq!(report["policy"], "exact");
    assert_eq!(report["member_count"], 1);
    assert_eq!(
        report["member_hashes"][0],
        format!("blake3:{}", fixture.original_artifact)
    );
    assert_eq!(
        report["minimal_representative"],
        format!("blake3:{}", fixture.minimized_artifact)
    );

    let proof_failure = run_triage(
        &fixture.store,
        &temporary.path().join("proof-artifacts"),
        &temporary.path().join("proof-reports"),
        &fixture.proof_mutation,
    )?;
    assert_failure_contains(
        "cross-principal proof mutation",
        &proof_failure,
        "object proof was rejected: campaign service protocol or response validation failed",
    );

    let payload_failure = run_triage(
        &fixture.store,
        &temporary.path().join("payload-artifacts"),
        &temporary.path().join("payload-reports"),
        &fixture.payload_mutation,
    )?;
    assert_failure_contains(
        "projected assertion mutation",
        &payload_failure,
        "discovery signature does not match recorded evidence",
    );
    assert_ne!(proof_failure.stderr, payload_failure.stderr);

    Ok(())
}

fn run_triage(
    store: &Path,
    artifact_directory: &Path,
    report_directory: &Path,
    findings: &Path,
) -> Result<Output, std::io::Error> {
    Command::new(env!("CARGO_BIN_EXE_crucible"))
        .arg("--store")
        .arg(store)
        .arg("--artifact-dir")
        .arg(artifact_directory)
        .args(["--format", "jsonl", "triage"])
        .arg(findings)
        .args(["--policy", "exact", "--minimize", "all", "--report"])
        .arg(report_directory)
        .arg("--recompute-signatures")
        .output()
}

fn assert_success(operation: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{operation} failed; stdout=`{}` stderr=`{}`",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_failure_contains(operation: &str, output: &Output, expected: &str) {
    assert!(
        !output.status.success(),
        "{operation} unexpectedly succeeded; stdout=`{}`",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(expected),
        "{operation} produced another failure; expected `{expected}`, got `{stderr}`"
    );
}
