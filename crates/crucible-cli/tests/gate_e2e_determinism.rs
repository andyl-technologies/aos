//! CLI-owned final acceptance target for `gate:e2e-determinism`.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::error::Error;

use crucible_harness::adversarial::{HostAdversaryProfile, canonical_host_adversary_matrix};
use crucible_harness::e2e::{
    E2eFaultKind, E2eGateError, E2ePropertyKind, canonical_mock_build_identity,
    representative_mock_e2e_artifact, reproduce_mock_e2e_artifact_on_profile,
    run_mock_e2e_determinism_gate,
};

#[test]
fn gate_e2e_determinism_cli_target_runs_final_acceptance_artifact() -> Result<(), Box<dyn Error>> {
    let artifact = representative_mock_e2e_artifact();
    let profiles = canonical_host_adversary_matrix();
    let report =
        run_mock_e2e_determinism_gate(&artifact, profiles, &canonical_mock_build_identity())?;

    assert_eq!(artifact.scenario.nodes.len(), 3);
    assert_eq!(artifact.scenario.io_subnodes.len(), 2);
    for required_kind in [
        E2eFaultKind::Partition,
        E2eFaultKind::Loss,
        E2eFaultKind::Latency,
        E2eFaultKind::Crash,
    ] {
        assert!(
            artifact
                .scenario
                .faults
                .iter()
                .any(|fault| fault.kind == required_kind)
        );
    }
    for required_kind in [
        E2ePropertyKind::Always,
        E2ePropertyKind::Eventually,
        E2ePropertyKind::Sometimes,
    ] {
        assert!(
            artifact
                .scenario
                .properties
                .iter()
                .any(|property| property.kind == required_kind)
        );
    }

    assert_eq!(report.runs.len(), profiles.len());
    let baseline = &report.runs[0];
    for run in &report.runs[1..] {
        assert_eq!(run.canonical_log, baseline.canonical_log);
        assert_eq!(run.final_fingerprint, baseline.final_fingerprint);
        assert_eq!(run.artifact_digest, baseline.artifact_digest);
    }
    assert_eq!(report.reproduced.canonical_log, baseline.canonical_log);
    assert_eq!(
        report.reproduced.final_fingerprint,
        baseline.final_fingerprint
    );
    assert_eq!(report.reproduced.artifact_digest, baseline.artifact_digest);

    assert!(report.cross_machine_reproductions.len() >= 2);
    for run in &report.cross_machine_reproductions {
        assert_ne!(run.profile, baseline.profile);
        assert_eq!(run.canonical_log, baseline.canonical_log);
        assert_eq!(run.final_fingerprint, baseline.final_fingerprint);
        assert_eq!(run.artifact_digest, baseline.artifact_digest);
    }

    Ok(())
}

#[test]
fn gate_e2e_determinism_cli_target_replays_from_artifact_on_different_machine_profile()
-> Result<(), Box<dyn Error>> {
    let artifact = representative_mock_e2e_artifact();
    let baseline = reproduce_mock_e2e_artifact_on_profile(
        &artifact,
        HostAdversaryProfile::quiet_single_core(),
        &canonical_mock_build_identity(),
    )?;
    let reproduced = reproduce_mock_e2e_artifact_on_profile(
        &artifact,
        HostAdversaryProfile::loaded_many_core(),
        &canonical_mock_build_identity(),
    )?;

    assert_ne!(reproduced.profile, baseline.profile);
    assert_eq!(reproduced.canonical_log, baseline.canonical_log);
    assert_eq!(reproduced.final_fingerprint, baseline.final_fingerprint);
    assert_eq!(reproduced.artifact_digest, baseline.artifact_digest);

    Ok(())
}

#[test]
fn gate_e2e_determinism_cli_target_rejects_build_identity_drift() {
    let mut artifact = representative_mock_e2e_artifact();
    artifact.build_identity.backend_build_id = String::from("different-cli-backend");

    let error = match run_mock_e2e_determinism_gate(
        &artifact,
        canonical_host_adversary_matrix(),
        &canonical_mock_build_identity(),
    ) {
        Ok(_) => panic!("build identity drift must fail the CLI e2e gate"),
        Err(error) => error,
    };

    assert!(matches!(error, E2eGateError::BuildIdentityMismatch { .. }));
}

#[test]
fn gate_e2e_determinism_cli_target_requires_cross_machine_reproduction() {
    let artifact = representative_mock_e2e_artifact();
    let profiles = [HostAdversaryProfile::quiet_single_core()];

    let error =
        match run_mock_e2e_determinism_gate(&artifact, &profiles, &canonical_mock_build_identity())
        {
            Ok(_) => panic!("the CLI e2e gate must require a different machine profile"),
            Err(error) => error,
        };

    assert!(matches!(
        error,
        E2eGateError::MissingDifferentMachineProfile
    ));
}
