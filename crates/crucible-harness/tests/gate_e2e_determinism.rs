//! Implements the harness-level mock `gate:e2e-determinism`.

#![forbid(unsafe_code)]

use std::error::Error;

use crucible_harness::adversarial::{HostAdversaryProfile, canonical_host_adversary_matrix};
use crucible_harness::e2e::{
    E2eDecision, E2eFaultKind, E2eGateError, E2eNode, E2ePropertyKind,
    canonical_mock_build_identity, representative_mock_e2e_artifact, reproduce_mock_e2e_artifact,
    run_mock_e2e_determinism_gate,
};

#[test]
fn gate_e2e_determinism_runs_fault_injected_multi_vm_artifact_under_adversarial_profiles()
-> Result<(), Box<dyn Error>> {
    let artifact = representative_mock_e2e_artifact();
    let profiles = canonical_host_adversary_matrix();
    let report =
        run_mock_e2e_determinism_gate(&artifact, profiles, &canonical_mock_build_identity())?;

    assert_eq!(artifact.scenario.nodes.len(), 3);
    assert_eq!(artifact.scenario.io_subnodes.len(), 2);
    assert_eq!(artifact.scenario.faults.len(), 4);
    assert!(
        [
            E2eFaultKind::Partition,
            E2eFaultKind::Loss,
            E2eFaultKind::Latency,
            E2eFaultKind::Crash,
        ]
        .iter()
        .all(|kind| artifact
            .scenario
            .faults
            .iter()
            .any(|fault| fault.kind == *kind))
    );
    assert!(
        [
            E2ePropertyKind::Always,
            E2ePropertyKind::Eventually,
            E2ePropertyKind::Sometimes,
        ]
        .iter()
        .all(|kind| artifact
            .scenario
            .properties
            .iter()
            .any(|property| property.kind == *kind))
    );
    assert_eq!(report.runs.len(), profiles.len());
    assert_eq!(report.runs[0].profile, "quiet-single-core");
    assert!(
        artifact
            .schedule
            .decisions
            .iter()
            .any(|decision| matches!(decision, E2eDecision::Fault { fired: true, .. }))
    );
    assert!(
        artifact
            .schedule
            .decisions
            .iter()
            .any(|decision| matches!(decision, E2eDecision::IoCompletion { .. }))
    );
    assert!(artifact.schedule.decisions.iter().any(|decision| matches!(
        decision,
        E2eDecision::PropertyObservation {
            satisfied: true,
            ..
        }
    )));

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
    assert!(report.cross_machine_reproductions.len() >= 2);
    for run in &report.cross_machine_reproductions {
        assert_ne!(run.profile, report.runs[0].profile);
        assert_eq!(run.canonical_log, report.runs[0].canonical_log);
        assert_eq!(run.final_fingerprint, report.runs[0].final_fingerprint);
        assert_eq!(run.artifact_digest, report.runs[0].artifact_digest);
    }

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
fn gate_e2e_determinism_rejects_scenario_without_io_subnodes() {
    let mut artifact = representative_mock_e2e_artifact();
    artifact.scenario.io_subnodes.clear();

    let error = match run_mock_e2e_determinism_gate(
        &artifact,
        canonical_host_adversary_matrix(),
        &canonical_mock_build_identity(),
    ) {
        Ok(_) => panic!("scenario without I/O sub-nodes must fail e2e gate"),
        Err(error) => error,
    };

    assert!(matches!(error, E2eGateError::MissingIoSubnode { .. }));
}

#[test]
fn gate_e2e_determinism_rejects_unused_io_subnodes() {
    let mut artifact = representative_mock_e2e_artifact();
    artifact
        .schedule
        .decisions
        .retain(|decision| !matches!(decision, E2eDecision::IoCompletion { .. }));

    let error = match run_mock_e2e_determinism_gate(
        &artifact,
        canonical_host_adversary_matrix(),
        &canonical_mock_build_identity(),
    ) {
        Ok(_) => panic!("scenario with unused I/O sub-nodes must fail e2e gate"),
        Err(error) => error,
    };

    assert!(matches!(error, E2eGateError::MissingIoCompletion { .. }));
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
fn gate_e2e_determinism_rejects_missing_property_observation() {
    let mut artifact = representative_mock_e2e_artifact();
    artifact
        .schedule
        .decisions
        .retain(|decision| !matches!(decision, E2eDecision::PropertyObservation { .. }));

    let error = match run_mock_e2e_determinism_gate(
        &artifact,
        canonical_host_adversary_matrix(),
        &canonical_mock_build_identity(),
    ) {
        Ok(_) => panic!("unobserved properties must fail e2e gate validation"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        E2eGateError::MissingSatisfiedProperty { .. }
    ));
}

#[test]
fn gate_e2e_determinism_rejects_false_always_property_observation() {
    let mut artifact = representative_mock_e2e_artifact();
    artifact
        .schedule
        .decisions
        .push(E2eDecision::PropertyObservation {
            at_tick: 48,
            property: String::from("no-past-delivery"),
            satisfied: false,
        });

    let error = match run_mock_e2e_determinism_gate(
        &artifact,
        canonical_host_adversary_matrix(),
        &canonical_mock_build_identity(),
    ) {
        Ok(_) => panic!("false always-property observation must fail e2e gate validation"),
        Err(error) => error,
    };

    assert!(matches!(error, E2eGateError::FailedAlwaysProperty { .. }));
}

#[test]
fn gate_e2e_determinism_accepts_machine_profile_that_changes_only_scheduling() {
    let artifact = representative_mock_e2e_artifact();
    let profiles = [
        HostAdversaryProfile::quiet_single_core(),
        HostAdversaryProfile::loaded_single_core(),
    ];

    let report =
        match run_mock_e2e_determinism_gate(&artifact, &profiles, &canonical_mock_build_identity())
        {
            Ok(report) => report,
            Err(error) => {
                panic!("task-order/load/skew drift is a different machine profile: {error}")
            }
        };

    assert_eq!(report.cross_machine_reproductions.len(), 1);
    assert_eq!(
        report.cross_machine_reproductions[0].profile,
        "loaded-single-core"
    );
}

#[test]
fn gate_e2e_determinism_requires_cross_machine_reproduction_profile() {
    let artifact = representative_mock_e2e_artifact();
    let profiles = [HostAdversaryProfile::quiet_single_core()];

    let error =
        match run_mock_e2e_determinism_gate(&artifact, &profiles, &canonical_mock_build_identity())
        {
            Ok(_) => panic!("e2e gate must require a different machine reproduction profile"),
            Err(error) => error,
        };

    assert!(matches!(
        error,
        E2eGateError::MissingDifferentMachineProfile
    ));
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
