//! Checks the QEMU exact-snapshot completeness policy.

#![forbid(unsafe_code)]

use crucible::ContentHash;
use crucible_qemu::{
    QEMU_SAVEVM_COMPLETENESS_CHECK, QemuLoadvmCommandPurpose, QemuReplayOracleValidation,
    QemuSavevmCompletenessPolicy, QemuSavevmPolicyError,
};

#[test]
fn complete_policy_authorizes_probe_and_runtime_loadvm() {
    let policy = QemuSavevmCompletenessPolicy::complete();

    assert_eq!(
        QEMU_SAVEVM_COMPLETENESS_CHECK,
        "checks.crucible.phase2.qemuExactSnapshotRestore"
    );
    assert_eq!(
        policy.authorize_loadvm_probe().purpose(),
        QemuLoadvmCommandPurpose::SnapshotCompletenessProbe
    );
    assert_eq!(
        policy.authorize_loadvm_runtime().purpose(),
        QemuLoadvmCommandPurpose::RuntimeRealization
    );
}

#[test]
fn complete_policy_requires_matching_replay_oracle_evidence() {
    let policy = QemuSavevmCompletenessPolicy::complete();
    let runtime_hash = content_hash_with_byte(0x11);

    assert_eq!(
        policy.accept_loadvm_realized_runtime(QemuReplayOracleValidation::NotRun),
        Err(QemuSavevmPolicyError::ReplayOracleValidationRequired)
    );
    let admission = policy
        .accept_loadvm_realized_runtime(QemuReplayOracleValidation::Match { runtime_hash })
        .unwrap_or_else(|error| panic!("matching replay evidence should be admitted: {error}"));
    assert_eq!(admission.runtime_hash(), runtime_hash);
}

fn content_hash_with_byte(byte: u8) -> ContentHash {
    ContentHash { bytes: [byte; 32] }
}
