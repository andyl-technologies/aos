//! QEMU `savevm` completeness fallback policy.
//!
//! RFC-0010 QEMU-21/QEMU-22 allow a `loadvm`-realized runtime only after the
//! replay oracle proves that the restored fat checkpoint is content-equal to
//! its thin replay derivation. The Phase 0 S3 result is currently "pass with
//! fallback", so the default policy keeps thin replay as the realization path
//! and leaves the fat `loadvm` branch disabled.

use crucible::ContentHash;
use thiserror::Error;

/// Phase 0 check that adopted the conservative `savevm` fallback policy.
pub const QEMU_SAVEVM_PHASE0_S3_CHECK: &str = "checks.crucible.phase0.s3SavevmLoadvm";

/// Stable result marker for the conservative realization fallback.
pub const QEMU_SAVEVM_FALLBACK_MARKER: &str = "thin_replay_until_full_s3";

/// Default policy for using QEMU `savevm`/`loadvm` in Crucible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuSavevmCompletenessPolicy {
    status: QemuSavevmCompletenessStatus,
    fallback: QemuSavevmFallback,
    default_realization_branch: QemuVmRealizationBranch,
    thin_checkpoint_default: bool,
    fat_snapshot_default: bool,
    loadvm_branch_enabled: bool,
    full_fat_checkpoint_complete: bool,
    oracle_validation_required_for_loadvm: bool,
}

impl QemuSavevmCompletenessPolicy {
    /// Returns the conservative policy adopted by the Phase 0 S3 spike.
    #[must_use]
    pub const fn phase0_fallback() -> Self {
        Self {
            status: QemuSavevmCompletenessStatus::PassWithFallback,
            fallback: QemuSavevmFallback::ThinReplayUntilFullS3,
            default_realization_branch: QemuVmRealizationBranch::ThinReplay,
            thin_checkpoint_default: true,
            fat_snapshot_default: false,
            loadvm_branch_enabled: false,
            full_fat_checkpoint_complete: false,
            oracle_validation_required_for_loadvm: true,
        }
    }

    /// Returns the spike status that backs this policy.
    #[must_use]
    pub const fn status(self) -> QemuSavevmCompletenessStatus {
        self.status
    }

    /// Returns the fallback selected for runtime realization.
    #[must_use]
    pub const fn fallback(self) -> QemuSavevmFallback {
        self.fallback
    }

    /// Returns the default runtime-realization branch.
    #[must_use]
    pub const fn default_realization_branch(self) -> QemuVmRealizationBranch {
        self.default_realization_branch
    }

    /// Returns whether thin checkpoint replay is the default realization path.
    #[must_use]
    pub const fn thin_checkpoint_default(self) -> bool {
        self.thin_checkpoint_default
    }

    /// Returns whether fat snapshots are the default realization path.
    #[must_use]
    pub const fn fat_snapshot_default(self) -> bool {
        self.fat_snapshot_default
    }

    /// Returns whether the fat `loadvm` branch may be used by default.
    #[must_use]
    pub const fn loadvm_branch_enabled(self) -> bool {
        self.loadvm_branch_enabled
    }

    /// Returns whether the full fat-checkpoint replay-oracle proof is complete.
    #[must_use]
    pub const fn full_fat_checkpoint_complete(self) -> bool {
        self.full_fat_checkpoint_complete
    }

    /// Returns whether every `loadvm` runtime must be replay-oracle validated.
    #[must_use]
    pub const fn oracle_validation_required_for_loadvm(self) -> bool {
        self.oracle_validation_required_for_loadvm
    }

    /// Attempts to accept a `loadvm`-realized runtime under this policy.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSavevmPolicyError::LoadvmBranchDisabled`] while the Phase 0
    /// fallback is active. Once a future full S3 gate enables `loadvm`, this
    /// method also returns replay-oracle validation errors.
    pub fn accept_loadvm_realized_runtime(
        self,
        validation: QemuReplayOracleValidation,
    ) -> Result<QemuLoadvmRealizationAdmission, QemuSavevmPolicyError> {
        if !self.loadvm_branch_enabled {
            return Err(QemuSavevmPolicyError::LoadvmBranchDisabled {
                fallback: self.fallback,
            });
        }

        validate_loadvm_realized_runtime(validation)
    }

    /// Authorizes the low-level QMP `loadvm` command for snapshot-completeness probes.
    ///
    /// This authorization is only for running the S3-style probe that compares a
    /// loaded VMState suffix to thin replay. It is not runtime-realization
    /// admission and does not enable the production `loadvm` branch.
    #[must_use]
    pub const fn authorize_loadvm_probe(self) -> QemuLoadvmCommandAuthorization {
        QemuLoadvmCommandAuthorization {
            purpose: QemuLoadvmCommandPurpose::SnapshotCompletenessProbe,
        }
    }

    /// Attempts to authorize the low-level QMP `loadvm` command for runtime realization.
    ///
    /// # Errors
    ///
    /// Returns [`QemuSavevmPolicyError::LoadvmBranchDisabled`] while the Phase 0
    /// fallback is active.
    pub fn authorize_loadvm_runtime(
        self,
    ) -> Result<QemuLoadvmCommandAuthorization, QemuSavevmPolicyError> {
        if !self.loadvm_branch_enabled {
            return Err(QemuSavevmPolicyError::LoadvmBranchDisabled {
                fallback: self.fallback,
            });
        }

        Ok(QemuLoadvmCommandAuthorization {
            purpose: QemuLoadvmCommandPurpose::RuntimeRealization,
        })
    }

    /// Authorizes QMP `loadvm` for the trusted baked-genesis ready-point snapshot.
    ///
    /// This authorization is deliberately separate from the exact fat-checkpoint
    /// runtime branch: it only loads a baked genesis snapshot produced by
    /// `bake`, so it remains available while arbitrary exact snapshot `loadvm`
    /// is disabled by the Phase 0 fallback policy.
    #[must_use]
    pub const fn authorize_baked_genesis_runtime(self) -> QemuLoadvmCommandAuthorization {
        QemuLoadvmCommandAuthorization {
            purpose: QemuLoadvmCommandPurpose::BakedGenesisRealization,
        }
    }
}

impl Default for QemuSavevmCompletenessPolicy {
    fn default() -> Self {
        Self::phase0_fallback()
    }
}

/// Validates a crate-observed `loadvm` runtime against its thin replay derivation.
///
/// # Errors
///
/// Returns [`QemuSavevmPolicyError::ReplayOracleValidationRequired`] when the
/// replay oracle was not run, or [`QemuSavevmPolicyError::ReplayOracleMismatch`]
/// when the fat and thin fingerprints differ.
pub(crate) fn validate_loadvm_realized_runtime(
    validation: QemuReplayOracleValidation,
) -> Result<QemuLoadvmRealizationAdmission, QemuSavevmPolicyError> {
    match validation {
        QemuReplayOracleValidation::NotRun => {
            Err(QemuSavevmPolicyError::ReplayOracleValidationRequired)
        }
        QemuReplayOracleValidation::Mismatch {
            fat_hash,
            thin_hash,
        } => Err(QemuSavevmPolicyError::ReplayOracleMismatch {
            fat_hash,
            thin_hash,
        }),
        QemuReplayOracleValidation::Match { runtime_hash } => {
            Ok(QemuLoadvmRealizationAdmission { runtime_hash })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loadvm_runtime_requires_replay_oracle_validation() {
        assert_eq!(
            validate_loadvm_realized_runtime(QemuReplayOracleValidation::NotRun),
            Err(QemuSavevmPolicyError::ReplayOracleValidationRequired)
        );
    }

    #[test]
    fn loadvm_runtime_rejects_replay_oracle_mismatch() {
        let fat_hash = content_hash_with_byte(0xfa);
        let thin_hash = content_hash_with_byte(0x7a);

        assert_eq!(
            validate_loadvm_realized_runtime(QemuReplayOracleValidation::Mismatch {
                fat_hash,
                thin_hash,
            }),
            Err(QemuSavevmPolicyError::ReplayOracleMismatch {
                fat_hash,
                thin_hash,
            })
        );
    }

    #[test]
    fn loadvm_runtime_accepts_matching_replay_oracle_evidence() {
        let runtime_hash = content_hash_with_byte(0x42);
        let admission =
            validate_loadvm_realized_runtime(QemuReplayOracleValidation::Match { runtime_hash })
                .unwrap_or_else(|error| {
                    panic!("matching replay oracle should be accepted: {error}")
                });

        assert_eq!(admission.runtime_hash(), runtime_hash);
    }

    #[test]
    fn fallback_policy_authorizes_baked_genesis_without_enabling_exact_loadvm() {
        let policy = QemuSavevmCompletenessPolicy::phase0_fallback();

        assert_eq!(
            policy.authorize_baked_genesis_runtime().purpose(),
            QemuLoadvmCommandPurpose::BakedGenesisRealization
        );
        assert!(matches!(
            policy.authorize_loadvm_runtime(),
            Err(QemuSavevmPolicyError::LoadvmBranchDisabled { .. })
        ));
    }

    fn content_hash_with_byte(byte: u8) -> ContentHash {
        ContentHash { bytes: [byte; 32] }
    }
}

/// Current completeness status of QEMU `savevm`/`loadvm`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuSavevmCompletenessStatus {
    /// The spike passed only by adopting thin replay as the default fallback.
    PassWithFallback,
}

/// Runtime fallback selected until full S3 replay-oracle coverage is green.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuSavevmFallback {
    /// Realize checkpoints by replaying from genesis or a verified ancestor.
    ThinReplayUntilFullS3,
}

impl QemuSavevmFallback {
    /// Returns the stable result marker emitted by the Phase 0 S3 check.
    #[must_use]
    pub const fn marker(self) -> &'static str {
        match self {
            Self::ThinReplayUntilFullS3 => QEMU_SAVEVM_FALLBACK_MARKER,
        }
    }
}

/// QEMU runtime realization branch selected for a checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuVmRealizationBranch {
    /// Replay the suffix from genesis or from a verified ancestor checkpoint.
    ThinReplay,
}

/// Purpose for an authorized low-level QMP `loadvm` command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuLoadvmCommandPurpose {
    /// Realize the trusted baked ready-point snapshot for a world's genesis.
    BakedGenesisRealization,
    /// Run the S3-style snapshot-completeness probe without admitting a runtime.
    SnapshotCompletenessProbe,
    /// Realize a production runtime from a fat snapshot.
    RuntimeRealization,
}

/// Authorization token required to issue the low-level QMP `loadvm` command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuLoadvmCommandAuthorization {
    purpose: QemuLoadvmCommandPurpose,
}

impl QemuLoadvmCommandAuthorization {
    /// Returns the purpose for the authorized command.
    #[must_use]
    pub const fn purpose(self) -> QemuLoadvmCommandPurpose {
        self.purpose
    }

    /// Returns a runtime-realization authorization for crate-internal tests.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn runtime_realization_for_test() -> Self {
        Self {
            purpose: QemuLoadvmCommandPurpose::RuntimeRealization,
        }
    }

    /// Returns a baked-genesis realization authorization for crate-internal tests.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn baked_genesis_realization_for_test() -> Self {
        Self {
            purpose: QemuLoadvmCommandPurpose::BakedGenesisRealization,
        }
    }
}

/// Replay-oracle evidence for a `loadvm`-realized runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuReplayOracleValidation {
    /// No replay-oracle comparison was run.
    NotRun,
    /// The `loadvm` runtime and its thin replay derivation diverged.
    Mismatch {
        /// Fingerprint of the `loadvm`-realized fat runtime.
        fat_hash: ContentHash,
        /// Fingerprint of the thin replay runtime.
        thin_hash: ContentHash,
    },
    /// The `loadvm` runtime matched its thin replay derivation.
    Match {
        /// Shared fingerprint proven by the replay oracle.
        runtime_hash: ContentHash,
    },
}

/// Admission result for a replay-oracle-validated `loadvm` runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuLoadvmRealizationAdmission {
    /// Shared runtime fingerprint proven by fat/thin replay-oracle equality.
    runtime_hash: ContentHash,
}

impl QemuLoadvmRealizationAdmission {
    /// Returns the runtime fingerprint proven by fat/thin replay-oracle equality.
    #[must_use]
    pub const fn runtime_hash(self) -> ContentHash {
        self.runtime_hash
    }

    /// Creates an admission token for tests that exercise downstream policy consumers.
    #[cfg(test)]
    pub(crate) const fn for_test(runtime_hash: ContentHash) -> Self {
        Self { runtime_hash }
    }
}

/// Policy errors for QEMU `savevm`/`loadvm` realization.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum QemuSavevmPolicyError {
    /// The default policy leaves `loadvm` disabled until full S3 coverage is green.
    #[error("QEMU loadvm branch is disabled; fallback={fallback:?}")]
    LoadvmBranchDisabled {
        /// Fallback that must be used instead.
        fallback: QemuSavevmFallback,
    },
    /// The replay oracle was not run for a `loadvm` runtime.
    #[error("QEMU loadvm realization requires replay-oracle validation")]
    ReplayOracleValidationRequired,
    /// The fat `loadvm` runtime diverged from its thin replay derivation.
    #[error("QEMU loadvm replay oracle mismatch: fat={fat_hash:?} thin={thin_hash:?}")]
    ReplayOracleMismatch {
        /// Fingerprint of the `loadvm`-realized fat runtime.
        fat_hash: ContentHash,
        /// Fingerprint of the thin replay runtime.
        thin_hash: ContentHash,
    },
}
