//! Native candidate CLI refusal with genuine kernel probing and no qualification.

#![cfg(target_os = "linux")]
// crucible-lint: allow rust-allow -- native caller setup and refusal assertions deliberately panic on failure.
// crucible-lint: allow panic-shortcut -- These node kvm process tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{path::PathBuf, process::Command};

#[test]
fn kvm_candidate_help_exposes_local_policy_without_an_execution_override() {
    let output = Command::new(env!("CARGO_BIN_EXE_crucible"))
        .args(["node", "kvm-prepare", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("--policy"));
    assert!(!help.contains("--qualified"));
    assert!(!help.contains("--allow-tcg"));
}

#[test]
fn kvm_candidate_cli_refuses_unknown_qualification_switch_before_native_effects() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.json");
    std::fs::write(&path, br#"{"profile_qualified":true}"#).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_crucible"))
        .args(["node", "kvm-prepare", "--policy"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("PreparationRefused"), "{error}");
    assert!(!error.contains("EnvironmentUnavailable"), "{error}");
}

#[test]
#[ignore = "requires independently measured CRUCIBLE_KVM_CANDIDATE_POLICY; tests native availability refusal, not KVM qualification"]
fn actual_installed_native_candidate_refusal_is_distinct_from_hardware_qualification() {
    let policy = PathBuf::from(
        std::env::var("CRUCIBLE_KVM_CANDIDATE_POLICY")
            .expect("independently installed source-built KVM candidate policy"),
    );
    let bytes = std::fs::read(&policy).unwrap();
    let candidate = crucible_daemon::node_observed_executor::load_installed_kvm_candidate(&bytes)
        .expect("actual measured source-built QEMU/kernel candidate");
    assert_eq!(candidate.artifact_identities().count(), 3);

    let output = Command::new(env!("CARGO_BIN_EXE_crucible"))
        .args(["node", "kvm-prepare", "--policy"])
        .arg(&policy)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).unwrap();
    if !std::path::Path::new("/dev/kvm").exists() {
        assert!(error.contains("EnvironmentUnavailable"), "{error}");
        assert!(
            error.contains("native KVM device is unavailable"),
            "{error}"
        );
    } else {
        assert!(
            error.contains("EnvironmentUnavailable") || error.contains("mediation is incomplete"),
            "{error}"
        );
    }
    assert!(output.stdout.is_empty());
}
