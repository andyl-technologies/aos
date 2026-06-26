//! Implements the harness-level mock `gate:e2e-determinism`.

#![forbid(unsafe_code)]

use std::error::Error;

use crucible_harness::adversarial::canonical_host_adversary_matrix;
use crucible_harness::e2e::{
    E2eDecision, E2eGateError, E2eNode, canonical_mock_build_identity,
    representative_mock_e2e_artifact, reproduce_mock_e2e_artifact, run_mock_e2e_determinism_gate,
};

#[test]
fn gate_e2e_determinism_runs_fault_injected_multi_vm_artifact_under_adversarial_profiles()
-> Result<(), Box<dyn Error>> {
    let artifact = representative_mock_e2e_artifact();
    let profiles = canonical_host_adversary_matrix();
    let report =
        run_mock_e2e_determinism_gate(&artifact, profiles, &canonical_mock_build_identity())?;

    assert_eq!(artifact.scenario.nodes.len(), 3);
    assert_eq!(artifact.scenario.faults.len(), 1);
    assert_eq!(report.runs.len(), profiles.len());
    assert_eq!(report.runs[0].profile, "quiet-single-core");
    assert!(
        artifact
            .schedule
            .decisions
            .iter()
            .any(|decision| matches!(decision, E2eDecision::Fault { fired: true, .. }))
    );

    for run in &report.runs[1..] {
        assert_eq!(run.canonical_log, report.runs[0].canonical_log);
        assert_eq!(run.final_fingerprint, report.runs[0].final_fingerprint);
        assert_eq!(run.artifact_digest, report.runs[0].artifact_digest);
    }

    assert_eq!(
        report.reproduced.canonical_log,
        report.runs[0].canonical_log
    );
    assert_eq!(
        report.reproduced.final_fingerprint,
        report.runs[0].final_fingerprint
    );
    assert_eq!(
        report.reproduced.artifact_digest,
        report.runs[0].artifact_digest
    );

    Ok(())
}

#[test]
fn gate_e2e_determinism_rejects_build_identity_drift() {
    let mut artifact = representative_mock_e2e_artifact();
    artifact.build_identity.backend_build_id = String::from("different-mock-backend");

    let error = match run_mock_e2e_determinism_gate(
        &artifact,
        canonical_host_adversary_matrix(),
        &canonical_mock_build_identity(),
    ) {
        Ok(_) => panic!("build identity drift must fail e2e reproduction"),
        Err(error) => error,
    };

    assert!(matches!(error, E2eGateError::BuildIdentityMismatch { .. }));
}

#[test]
fn gate_e2e_determinism_rejects_non_fault_injected_scenario() {
    let mut artifact = representative_mock_e2e_artifact();
    artifact.scenario.faults.clear();

    let error = match run_mock_e2e_determinism_gate(
        &artifact,
        canonical_host_adversary_matrix(),
        &canonical_mock_build_identity(),
    ) {
        Ok(_) => panic!("scenario without configured faults must fail e2e gate"),
        Err(error) => error,
    };

    assert!(matches!(error, E2eGateError::MissingFault { .. }));
}

#[test]
fn gate_e2e_determinism_rejects_unknown_fault_target() {
    let mut artifact = representative_mock_e2e_artifact();
    artifact.scenario.faults[0].target = String::from("missing-link");

    let error = match run_mock_e2e_determinism_gate(
        &artifact,
        canonical_host_adversary_matrix(),
        &canonical_mock_build_identity(),
    ) {
        Ok(_) => panic!("fault target drift must fail e2e gate validation"),
        Err(error) => error,
    };

    assert!(matches!(error, E2eGateError::UnknownFaultTarget { .. }));
}

#[test]
fn gate_e2e_determinism_reproduction_changes_when_schedule_drifts() -> Result<(), Box<dyn Error>> {
    let artifact = representative_mock_e2e_artifact();
    let baseline = reproduce_mock_e2e_artifact(&artifact, &canonical_mock_build_identity())?;
    let mut drifted = artifact.clone();
    drifted.schedule.decisions.swap(1, 2);
    let candidate = reproduce_mock_e2e_artifact(&drifted, &canonical_mock_build_identity())?;

    assert_ne!(candidate.artifact_digest, baseline.artifact_digest);
    assert_ne!(candidate.canonical_log, baseline.canonical_log);
    assert_ne!(candidate.final_fingerprint, baseline.final_fingerprint);

    Ok(())
}

#[test]
fn gate_e2e_determinism_canonical_artifact_encoding_is_length_prefixed()
-> Result<(), Box<dyn Error>> {
    let mut left = representative_mock_e2e_artifact();
    left.scenario.nodes.push(E2eNode {
        name: String::from("aux|left"),
        role: String::from("role"),
    });
    let mut right = representative_mock_e2e_artifact();
    right.scenario.nodes.push(E2eNode {
        name: String::from("aux"),
        role: String::from("left|role"),
    });

    let left_run = reproduce_mock_e2e_artifact(&left, &canonical_mock_build_identity())?;
    let right_run = reproduce_mock_e2e_artifact(&right, &canonical_mock_build_identity())?;

    assert_ne!(left_run.artifact_digest, right_run.artifact_digest);
    assert_ne!(left_run.final_fingerprint, right_run.final_fingerprint);

    Ok(())
}
