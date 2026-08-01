//! Checks the conservative QEMU `savevm` fallback policy.

#![forbid(unsafe_code)]

use crucible::ContentHash;
use crucible_qemu::{
    QEMU_SAVEVM_FALLBACK_MARKER, QEMU_SAVEVM_PHASE0_S3_CHECK, QemuLoadvmCommandPurpose,
    QemuReplayOracleValidation, QemuSavevmCompletenessPolicy, QemuSavevmCompletenessStatus,
    QemuSavevmFallback, QemuSavevmPolicyError, QemuVmRealizationBranch,
};

#[test]
fn phase0_s3_policy_defaults_to_thin_replay_fallback() {
    let policy = QemuSavevmCompletenessPolicy::phase0_fallback();

    assert_eq!(
        QEMU_SAVEVM_PHASE0_S3_CHECK,
        "checks.crucible.phase0.s3SavevmLoadvm"
    );
    assert_eq!(
        policy.status(),
        QemuSavevmCompletenessStatus::PassWithFallback
    );
    assert_eq!(policy.fallback(), QemuSavevmFallback::ThinReplayUntilFullS3);
    assert_eq!(policy.fallback().marker(), QEMU_SAVEVM_FALLBACK_MARKER);
    assert_eq!(
        policy.default_realization_branch(),
        QemuVmRealizationBranch::ThinReplay
    );
    assert!(policy.thin_checkpoint_default());
    assert!(!policy.fat_snapshot_default());
    assert!(!policy.loadvm_branch_enabled());
    assert!(!policy.full_fat_checkpoint_complete());
    assert!(policy.oracle_validation_required_for_loadvm());
}

#[test]
fn phase0_policy_authorizes_only_probe_loadvm_commands() {
    let policy = QemuSavevmCompletenessPolicy::default();
    let authorization = policy.authorize_loadvm_probe();

    assert_eq!(
        authorization.purpose(),
        QemuLoadvmCommandPurpose::SnapshotCompletenessProbe
    );
    match policy.authorize_loadvm_runtime() {
        Ok(_) => panic!("phase0 fallback policy must not authorize runtime loadvm"),
        Err(QemuSavevmPolicyError::LoadvmBranchDisabled { fallback }) => {
            assert_eq!(fallback, QemuSavevmFallback::ThinReplayUntilFullS3);
        }
        Err(other) => panic!("expected disabled runtime loadvm branch, got {other:?}"),
    }
}

#[test]
fn default_policy_rejects_loadvm_even_with_matching_oracle_evidence() {
    let policy = QemuSavevmCompletenessPolicy::default();
    let validation = QemuReplayOracleValidation::Match {
        runtime_hash: content_hash_with_byte(0x11),
    };

    match policy.accept_loadvm_realized_runtime(validation) {
        Ok(_) => panic!("phase0 fallback policy must not enable loadvm"),
        Err(QemuSavevmPolicyError::LoadvmBranchDisabled { fallback }) => {
            assert_eq!(fallback, QemuSavevmFallback::ThinReplayUntilFullS3);
        }
        Err(other) => panic!("expected disabled loadvm branch, got {other:?}"),
    }
}

fn content_hash_with_byte(byte: u8) -> ContentHash {
    ContentHash { bytes: [byte; 32] }
}
