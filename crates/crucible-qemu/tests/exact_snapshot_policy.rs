//! Checks the QEMU exact-snapshot completeness policy.

#![forbid(unsafe_code)]

use crucible::ContentHash;
use crucible_qemu::{
    QEMU_EXACT_SNAPSHOT_RESTORE_CHECK, QemuExactSnapshotPolicy, QemuExactSnapshotPolicyError,
    QemuLoadvmCommandPurpose, QemuReplayOracleValidation,
};

#[test]
fn production_policy_authorizes_probe_and_runtime_loadvm() {
    let policy = QemuExactSnapshotPolicy::production();

    assert_eq!(
        QEMU_EXACT_SNAPSHOT_RESTORE_CHECK,
        "checks.crucible.phase2.qemuExactSnapshotRestore"
    );
    assert_eq!(
        policy.authorize_loadvm_probe().purpose(),
        QemuLoadvmCommandPurpose::ReplayOracleProbe
    );
}

#[test]
fn production_policy_requires_matching_replay_oracle_evidence() {
    let policy = QemuExactSnapshotPolicy::production();
    let runtime_hash = content_hash_with_byte(0x11);

    assert_eq!(
        policy.accept_loadvm_realized_runtime(QemuReplayOracleValidation::NotRun),
        Err(QemuExactSnapshotPolicyError::ReplayOracleValidationRequired)
    );
    let admission = policy
        .accept_loadvm_realized_runtime(QemuReplayOracleValidation::Match { runtime_hash })
        .unwrap_or_else(|error| panic!("matching replay evidence should be admitted: {error}"));
    assert_eq!(admission.runtime_hash(), runtime_hash);
}

fn content_hash_with_byte(byte: u8) -> ContentHash {
    ContentHash { bytes: [byte; 32] }
}
